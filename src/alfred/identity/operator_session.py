"""Operator-session model, file persistence, machine-id, and resolver (#153).

This module is the trust boundary for CLI operator attribution. An
operator runs ``alfred login`` to mint a session token persisted at
``~/.config/alfred/session`` (mode 0600); every operator-attributed CLI
command thereafter resolves that file -> a canonical ``User.id`` and
stamps it onto the audit row. The defences layered here:

* **HKDF domain separation** (sec-3): the master ``audit.hash_pepper``
  is expanded into two distinct subkeys so a leaked token-hash cannot be
  replayed as a machine-id-hash.
* **TOCTOU-safe load** (sec-2): parent-dir-fd fstat + ``openat`` +
  ``O_NOFOLLOW`` so a rename-into-dir or symlink swap is refused.
* **SecretStr persistence** (sec-1): the in-memory model redacts the
  token in logs; explicit serialise/deserialise helpers round-trip the
  raw value so the next load's HMAC lookup hits the DB row.
* **Log-injection defence** (sec-4): the self-claimed ``user_id`` in a
  planted file is validated against a strict character class BEFORE any
  audit emit.

Naming: the Pydantic FILE model here is ``OperatorSessionFile``. The
SQLAlchemy ORM row (``operator_sessions`` table) is
``alfred.memory.models.OperatorSession`` — referenced as
``models.OperatorSession`` to keep the distinction unambiguous.

The ``OperatorResolverProtocol`` (``alfred.supervisor.protocols``,
async ``resolve() -> str``) is THE operator-session resolver — it was
shipped + consumed in PR-S4-1 and is reused verbatim here (lower-churn
than introducing a competing ``OperatorSessionResolver`` name).
``DefaultOperatorSessionResolver`` below is the production implementation.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sys
import tempfile
from asyncio import create_subprocess_exec
from asyncio import subprocess as asubprocess
from datetime import datetime, timedelta
from pathlib import Path
from typing import Annotated, Final, Literal, Protocol, runtime_checkable

import structlog
from pydantic import (
    BaseModel,
    ConfigDict,
    SecretStr,
    StringConstraints,
    ValidationError,
    model_validator,
)

from alfred.errors import AlfredError
from alfred.i18n import t
from alfred.security._hkdf import hkdf_expand

_log = structlog.get_logger(__name__)

# ``O_NOFOLLOW`` / ``O_DIRECTORY`` are POSIX-only; on Windows they are
# absent and the open-time symlink/dir refusal is not enforced (Windows
# operators are directed at the WSL2 path — PR-S4-10). Falling back to 0
# keeps the module importable on Windows CI runners.
_O_NOFOLLOW: Final = getattr(os, "O_NOFOLLOW", 0)
_O_DIRECTORY: Final = getattr(os, "O_DIRECTORY", 0)

# Upper bound on the session-file size. A legitimate file is a few hundred
# bytes; the cap refuses a planted multi-megabyte file before it is parsed
# (DoS + memory-pressure defence at the trust boundary).
_MAX_FILE_BYTES: Final = 64 * 1024

# ---------------------------------------------------------------------------
# Constants (lifetime-pin closure 13)
# ---------------------------------------------------------------------------

_TOKEN_BYTES: Final = 32  # 32 random bytes; base64url-encoded -> ~43 chars
_HASH_LEN: Final = 64  # full HMAC-SHA256 hex output (256 bits) — no truncation

_DEFAULT_EXPIRES_IN: Final = timedelta(hours=12)
_MIN_EXPIRES_IN: Final = timedelta(hours=1)
_MAX_EXPIRES_IN: Final = timedelta(days=7)

# HKDF domain-separation labels (sec-3). Versioned so a future rotation of
# the derivation scheme can coexist with v1 sessions during migration.
_TOKEN_HASH_INFO: Final = b"operator_session.token_hash.v1"
_MACHINE_ID_HASH_INFO: Final = b"operator_session.machine_id_hash.v1"
_SUBKEY_LEN: Final = 32

# The file's ``host`` is echoed verbatim into the ``host_mismatch`` audit row
# (``subject["host"]``). A planted file could otherwise carry an unbounded /
# arbitrary-charset string into the log. Cap it at the RFC 1035 hostname
# ceiling (253 chars) and a hostname charset (alnum + ``-`` + ``.``), mirroring
# the ``user_id`` int-coercion defence (sec-4). Non-conforming hosts are
# refused at parse → ``OperatorSessionMalformed`` (file-less refused row).
_Hostname = Annotated[
    str,
    StringConstraints(min_length=1, max_length=253, pattern=r"^[A-Za-z0-9.\-]+$"),
]

# ``machine_id_hash`` is echoed verbatim into the ``machine_mismatch`` audit row
# (``subject["machine_id_hash"]``) on the parsed-file refusal branch. CR-227
# round-3 finding 2: a length-only constraint let a planted file carry ANY
# 64-char string (newlines, control bytes, log-injection payloads) into the
# forensic row. The value is HMAC-SHA256 hex by construction, so pin the exact
# shape — lowercase hex, exactly 64 chars — at PARSE time. A non-hex value is a
# malformed file → ``OperatorSessionMalformed`` → ``planted_file_invalid``
# file-less row (no attacker bytes reach the log), mirroring the ``host`` /
# ``user_id`` defences (sec-4).
_MachineIdHash = Annotated[
    str,
    StringConstraints(pattern=rf"^[0-9a-f]{{{_HASH_LEN}}}$"),
]


def derive_token_hash_subkey(pepper: bytes) -> bytes:
    """HKDF-Expand the master pepper into the token-hash subkey (sec-3)."""
    return hkdf_expand(prk=pepper, info=_TOKEN_HASH_INFO, length=_SUBKEY_LEN)


def derive_machine_id_hash_subkey(pepper: bytes) -> bytes:
    """HKDF-Expand the master pepper into the machine-id-hash subkey (sec-3)."""
    return hkdf_expand(prk=pepper, info=_MACHINE_ID_HASH_INFO, length=_SUBKEY_LEN)


# ---------------------------------------------------------------------------
# Exception hierarchy
# ---------------------------------------------------------------------------


class OperatorSessionError(AlfredError):
    """Root of the operator-session refusal hierarchy.

    Every refusal path raises a concrete subclass so the CLI top-level
    dispatch can map each to a localised stderr message + a typed audit
    ``reason`` without string-matching.
    """


class OperatorSessionMissing(OperatorSessionError):  # noqa: N818 -- name pinned by PR-S4-5 plan + audit reason vocab
    """No session file at the expected path."""


class OperatorSessionMalformed(OperatorSessionError):  # noqa: N818 -- name pinned by PR-S4-5 plan + audit reason vocab
    """The session file exists but did not parse as an OperatorSessionFile."""


class OperatorSessionBadFileMode(OperatorSessionError):  # noqa: N818 -- name pinned by PR-S4-5 plan + audit reason vocab
    """The session file's mode is broader than 0600 (or open was refused)."""


class OperatorSessionBadFileOwner(OperatorSessionError):  # noqa: N818 -- name pinned by PR-S4-5 plan + audit reason vocab
    """The session file is not owned by the calling uid/gid."""


class OperatorSessionParentDirInsecure(OperatorSessionError):  # noqa: N818 -- name pinned by PR-S4-5 plan + audit reason vocab
    """The parent directory is group/other-accessible (mode & 0o077)."""


class OperatorSessionParentDirNotOwned(OperatorSessionError):  # noqa: N818 -- name pinned by PR-S4-5 plan + audit reason vocab
    """The parent directory is not owned by the calling euid."""


class OperatorSessionExpired(OperatorSessionError):  # noqa: N818 -- name pinned by PR-S4-5 plan + audit reason vocab
    """The session's expires_at is in the past."""


class OperatorSessionRevoked(OperatorSessionError):  # noqa: N818 -- name pinned by PR-S4-5 plan + audit reason vocab
    """The session row carries a non-null revoked_at."""


class OperatorSessionHostMismatch(OperatorSessionError):  # noqa: N818 -- name pinned by PR-S4-5 plan + audit reason vocab
    """The session was created on a different host (hostname changed)."""


class OperatorSessionMachineIdMismatch(OperatorSessionError):  # noqa: N818 -- name pinned by PR-S4-5 plan + audit reason vocab
    """The live machine-id hash does not match the session's (replay)."""


class OperatorSessionTokenUnknown(OperatorSessionError):  # noqa: N818 -- name pinned by PR-S4-5 plan + audit reason vocab
    """No matching, non-revoked operator_sessions row for the token hash."""


class OperatorSessionTokenUserMismatch(OperatorSessionError):  # noqa: N818 -- name pinned by PR-S4-5 plan + audit reason vocab
    """Valid token, but the file's user_id disagrees with the DB row.

    Token is authoritative (closure 11); a planted file claiming a
    different operator than the token's DB owner is refused.
    """


class OperatorSessionUserRevoked(OperatorSessionError):  # noqa: N818 -- name pinned by PR-S4-5 plan + audit reason vocab
    """The bound User row is soft-deleted (deleted_at set)."""


class OperatorSessionTimeout(OperatorSessionError):  # noqa: N818 -- name pinned by PR-S4-5 plan + audit reason vocab
    """The resolver exceeded its 250ms hard timeout (err-008)."""


class OperatorSessionNoMachineId(OperatorSessionError):  # noqa: N818 -- name pinned by PR-S4-5 plan + audit reason vocab
    """The per-OS machine-id source was unreadable."""


class OperatorSessionPepperMisconfigured(OperatorSessionError):  # noqa: N818 -- name pinned by PR-S4-5 plan + audit reason vocab
    """The ``audit.hash_pepper`` broker secret is too short / misconfigured.

    CR-227 round-3 finding 1 (KEYSTONE audit-gap): ``hkdf_expand`` raises a
    bare ``ValueError`` for a pepper shorter than 32 bytes (the SHA-256
    PRK floor). Without this typed subclass that error would escape
    ``resolve()`` UNTYPED — skipping BOTH the ``OPERATOR_SESSION_REFUSED``
    audit row (hard rule #7: every refusal lands exactly one row) AND the
    CLI refusal UX (raw traceback to the operator). The resolver wraps the
    pepper read + every HKDF-backed derivation in this subclass so a
    misconfigured pepper is recorded with the closed-vocab reason
    ``pepper_misconfigured`` and rendered as an actionable refusal.
    """


# ---------------------------------------------------------------------------
# §5.1 OperatorSessionFile Pydantic model
# ---------------------------------------------------------------------------


class OperatorSessionFile(BaseModel):
    """Persisted operator-session record (the on-disk file body).

    The token field is the verbatim base64url token minted at login. The
    file's 0600 mode is the host-side defence; the daemon-side defence is
    the matching ``token_hash`` row in ``operator_sessions`` on the
    ``uq_operator_sessions_token_hash`` unique index.

    ``machine_id_hash`` is ``HMAC-SHA256(machine_id_subkey, raw_machine_id)``
    as full 64-char hex. The raw machine-id is NEVER serialised.

    ``user_id`` is the canonical autoincrement ``User.id`` (int) — the FK
    target of ``operator_sessions.user_id``.
    """

    schema_version: Literal[1]
    user_id: int
    token: SecretStr
    issued_at: datetime
    expires_at: datetime
    host: _Hostname
    machine_id_hash: _MachineIdHash

    model_config = ConfigDict(frozen=True, extra="forbid")

    @model_validator(mode="after")
    def _expiry_after_issue(self) -> OperatorSessionFile:
        if self.expires_at <= self.issued_at:
            msg = "expires_at must be strictly after issued_at"
            raise ValueError(msg)
        return self


# ---------------------------------------------------------------------------
# §5.2 File persistence — explicit SecretStr round-trip (sec-1 closure)
# ---------------------------------------------------------------------------


def _serialize_to_file_bytes(session: OperatorSessionFile) -> bytes:
    """Serialise to bytes with the RAW token (sec-1).

    ``SecretStr.model_dump_json()`` writes ``"**********"`` for the token,
    so a naive dump would persist a file whose next load misses the DB
    row. We dump the model excluding the token, then splice the raw token
    string in explicitly via ``get_secret_value()``.
    """
    payload = session.model_dump(mode="json", exclude={"token"})
    payload["token"] = session.token.get_secret_value()
    return json.dumps(payload, separators=(",", ":")).encode("utf-8")


def _deserialize_from_file_bytes(raw: bytes) -> OperatorSessionFile:
    """Parse file bytes back into an OperatorSessionFile.

    The raw token string is re-wrapped in ``SecretStr`` by Pydantic's
    field coercion. Raises ``OperatorSessionMalformed`` on any parse or
    validation failure so the caller maps a single audit reason.
    """
    try:
        return OperatorSessionFile.model_validate_json(raw)
    except (ValidationError, ValueError) as exc:
        raise OperatorSessionMalformed(str(exc)) from exc


def _validate_parent_dir(parent_fd: int, parent: Path) -> None:
    """Refuse a group/other-accessible or non-euid-owned parent dir (sec-2)."""
    parent_stat = os.fstat(parent_fd)
    if parent_stat.st_mode & 0o077:
        raise OperatorSessionParentDirInsecure(
            f"{parent}: mode {parent_stat.st_mode & 0o777:#o} is group/other-accessible",
        )
    if hasattr(os, "geteuid") and parent_stat.st_uid != os.geteuid():
        raise OperatorSessionParentDirNotOwned(
            f"{parent}: owned by uid {parent_stat.st_uid}, not euid {os.geteuid()}",
        )


def _validate_file_stat(session_fd: int, path: Path) -> None:
    """Refuse a file whose mode != 0600 or owner != caller uid/gid (sec-2)."""
    stat = os.fstat(session_fd)
    if (stat.st_mode & 0o777) != 0o600:
        raise OperatorSessionBadFileMode(
            f"{path}: mode {stat.st_mode & 0o777:#o} is not 0o600",
        )
    if hasattr(os, "getuid") and (stat.st_uid != os.getuid() or stat.st_gid != os.getgid()):
        raise OperatorSessionBadFileOwner(
            f"{path}: owned by uid={stat.st_uid} gid={stat.st_gid}, "
            f"not uid={os.getuid()} gid={os.getgid()}",
        )


def load_session_file(path: Path) -> OperatorSessionFile:
    """TOCTOU-safe session-file load (sec-2 closure).

    Discipline:

    1. ``os.open(parent, O_RDONLY | O_DIRECTORY)`` — pin the parent dir by
       FD, then fstat it: refuse if group/other-accessible
       (``st_mode & 0o077``) or not owned by ``geteuid()``.
    2. ``os.openat(parent_fd, "session", O_RDONLY | O_NOFOLLOW)`` — reach
       the file relative to the pinned dir FD; ``O_NOFOLLOW`` refuses a
       symlink at open time. Because the dir is pinned, a rename-into-dir
       swap after step 1 cannot redirect the open.
    3. ``os.fstat(session_fd)`` — validate mode 0600 + owner on the OPEN
       FD (not via ``os.stat(path)``), closing the stat-then-open window.
    4. Only after both fstat validations pass do we read + parse.

    Raises:
        OperatorSessionMissing: file (or its parent dir) does not exist.
        OperatorSessionParentDirInsecure / NotOwned: parent dir refused.
        OperatorSessionBadFileMode: symlink, wrong mode, or open refused.
        OperatorSessionBadFileOwner: uid/gid mismatch.
        OperatorSessionMalformed: bytes did not parse as a session file.
    """
    parent = path.parent
    try:
        parent_fd = os.open(parent, os.O_RDONLY | _O_DIRECTORY)
    except FileNotFoundError as exc:
        raise OperatorSessionMissing(str(parent)) from exc
    try:
        _validate_parent_dir(parent_fd, parent)
        try:
            session_fd = os.open(
                path.name,
                os.O_RDONLY | _O_NOFOLLOW,
                dir_fd=parent_fd,
            )
        except FileNotFoundError as exc:
            raise OperatorSessionMissing(str(path)) from exc
        except OSError as exc:
            # O_NOFOLLOW on a symlink raises ELOOP (errno differs per OS).
            # Surface as bad-file-mode so the audit reason maps cleanly.
            raise OperatorSessionBadFileMode(
                f"{path}: open refused (errno {exc.errno})",
            ) from exc
        try:
            _validate_file_stat(session_fd, path)
            raw = os.read(session_fd, _MAX_FILE_BYTES + 1)
        finally:
            os.close(session_fd)
    finally:
        os.close(parent_fd)

    if len(raw) > _MAX_FILE_BYTES:
        raise OperatorSessionMalformed(f"{path}: session file exceeds {_MAX_FILE_BYTES} bytes")
    return _deserialize_from_file_bytes(raw)


def write_session_file(path: Path, session: OperatorSessionFile) -> None:
    """Write the session file with a 0700 parent dir + 0600 file (sec-2).

    Creates ``~/.config/alfred/`` with mode 0700 if absent; refuses if an
    existing dir is broader than 0700. The file is written 0600 from the
    start via an ``O_CREAT | O_EXCL``-then-atomic-rename dance under a
    tightened umask so there is no post-write ``chmod`` TOCTOU window.
    """
    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    # POSIX hosts always expose geteuid; the guard's false arm is only taken
    # on Windows, where directory mode bits do not carry the same meaning.
    if hasattr(os, "geteuid"):  # pragma: no branch
        parent_stat = parent.stat()
        if parent_stat.st_mode & 0o077:
            raise OperatorSessionParentDirInsecure(
                f"{parent}: existing mode {parent_stat.st_mode & 0o777:#o} is broader than 0o700",
            )

    body = _serialize_to_file_bytes(session)
    # CR-227 round-2 finding 2: a UNIQUE temp name (``mkstemp`` in the same
    # dir) so a leftover ``.session.<...>.tmp`` from a crashed or concurrent
    # write can never make ``O_CREAT | O_EXCL`` fail and lock out all future
    # logins. ``mkstemp`` creates the file 0600 with ``O_EXCL`` on a random
    # name (no symlink to follow — it is a fresh create), preserving the
    # 0600-from-the-start + atomic-rename guarantee. The temp is cleaned up
    # on any failure so a partial write never accumulates an orphan.
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=parent)
    tmp = Path(tmp_name)
    try:
        try:
            os.write(fd, body)
            os.fsync(fd)
        finally:
            os.close(fd)
        tmp.replace(path)
    except BaseException:
        # Any failure (write, fsync, or rename) must leave no temp orphan —
        # an accumulating ``.session.*.tmp`` would defeat the unique-name fix
        # over time and clutter the 0700 config dir.
        tmp.unlink(missing_ok=True)
        raise


# ---------------------------------------------------------------------------
# §5.3 Per-OS machine-id providers (sec-006)
# ---------------------------------------------------------------------------


@runtime_checkable
class MachineIdProvider(Protocol):
    """Read the raw, system-owned machine-id bytes.

    Implementations raise ``OperatorSessionNoMachineId`` on any read
    failure. The raw bytes are HMAC-hashed before storage — they never
    leave this module verbatim.
    """

    async def read_raw(self) -> bytes: ...


class LinuxMachineIdProvider:
    """``/etc/machine-id`` then ``/var/lib/dbus/machine-id`` fallback.

    Reads a ~32-byte file synchronously inside ``async def`` — bounded
    cost, so a ``to_thread`` wrapper would be overkill. The paths are
    injectable so tests substitute a temp dir.
    """

    def __init__(
        self,
        *,
        primary: Path = Path("/etc/machine-id"),
        fallback: Path = Path("/var/lib/dbus/machine-id"),
    ) -> None:
        self._primary = primary
        self._fallback = fallback

    async def read_raw(self) -> bytes:
        for path in (self._primary, self._fallback):
            try:
                raw = path.read_bytes().strip()
            except OSError:
                continue
            # CR-227 round-2 finding 3: an empty/whitespace source is treated
            # as UNREADABLE — never hashed. Hashing ``b""`` would yield a
            # machine-id-hash that is CONSTANT across every host with an empty
            # or unreadable source, defeating the replay protection the
            # machine-id binding exists to provide. Fall through to the next
            # source; if all are empty/unreadable we RAISE (refuse), so the
            # resolver records a ``machine_id_unavailable`` refusal rather than
            # validating a forgeable constant binding.
            if raw:
                return raw
        raise OperatorSessionNoMachineId("linux: no readable machine-id source")


class MacosMachineIdProvider:
    """``ioreg`` IOPlatformUUID, cached at ``/var/db/alfred/machine-id``.

    The cache is read first; a miss spawns ``ioreg`` once and writes the
    cache. In production the install step (PR-S4-7 macOS runbook)
    pre-populates the cache so the spawn is a first-boot-only path.
    """

    def __init__(self, *, cache: Path = Path("/var/db/alfred/machine-id")) -> None:
        self._cache = cache

    async def read_raw(self) -> bytes:
        try:
            cached = self._cache.read_bytes().strip()
        except OSError:
            cached = b""
        if cached:
            return cached

        proc = await create_subprocess_exec(
            "ioreg",
            "-rd1",
            "-c",
            "IOPlatformExpertDevice",
            stdout=asubprocess.PIPE,
            stderr=asubprocess.DEVNULL,
        )
        stdout, _ = await proc.communicate()
        if proc.returncode != 0:
            raise OperatorSessionNoMachineId("macos: ioreg exited non-zero")
        for line in stdout.splitlines():
            if b"IOPlatformUUID" in line:
                _, _, val = line.partition(b"=")
                uuid = val.strip().strip(b'"').strip()
                self._write_cache_best_effort(uuid)
                return uuid
        raise OperatorSessionNoMachineId("macos: IOPlatformUUID not found in ioreg output")

    def _write_cache_best_effort(self, uuid: bytes) -> None:
        """Cache the resolved UUID; never fail login on a cache-write error.

        CR-227 round-2 finding 4: a read-only ``/var/db`` or a permission
        denial on the cache dir must NOT propagate and break ``alfred login``.
        The cache is a first-boot optimisation (avoids a repeat ``ioreg``
        spawn); the in-memory value is authoritative for THIS resolution. On
        ``OSError`` we log (operator-visible via ``t()``) and continue.
        """
        try:
            self._cache.parent.mkdir(parents=True, exist_ok=True)
            self._cache.write_bytes(uuid)
        except OSError as exc:
            _log.warning(
                t("operator_session.machine_id.cache_write_failed", path=str(self._cache)),
                error=str(exc),
            )


class WindowsMachineIdProvider:
    """``HKLM\\SOFTWARE\\Microsoft\\Cryptography\\MachineGuid``.

    Lazy-imports ``winreg`` so the module stays importable on Linux/macOS
    CI runners.
    """

    async def read_raw(self) -> bytes:
        try:
            import winreg  # type: ignore[import-not-found, unused-ignore]
        except ImportError as exc:
            # The only arm reachable on non-Windows CI — exercised in tests.
            raise OperatorSessionNoMachineId("windows: winreg unavailable") from exc
        try:  # pragma: no cover - windows-only (winreg absent on CI runners)
            with winreg.OpenKey(  # type: ignore[attr-defined, unused-ignore]
                winreg.HKEY_LOCAL_MACHINE,  # type: ignore[attr-defined, unused-ignore]
                r"SOFTWARE\Microsoft\Cryptography",
            ) as key:
                guid, _ = winreg.QueryValueEx(key, "MachineGuid")  # type: ignore[attr-defined, unused-ignore]
                return str(guid).encode("utf-8")
        except OSError as exc:  # pragma: no cover - windows-only
            raise OperatorSessionNoMachineId("windows: MachineGuid unreadable") from exc


def select_machine_id_provider() -> MachineIdProvider:
    """Return the concrete provider for the running OS.

    ``sys.platform`` is read into a local so mypy does not statically
    narrow away the non-host branches (the function must dispatch
    correctly on every supported OS, not just the build host's).
    """
    platform: str = sys.platform
    if platform == "linux":
        return LinuxMachineIdProvider()
    if platform == "darwin":
        return MacosMachineIdProvider()
    if platform == "win32":  # pragma: no cover - windows-only selector arm
        return WindowsMachineIdProvider()
    raise OperatorSessionNoMachineId(f"unsupported platform: {platform}")


async def compute_machine_id_hash(*, provider: MachineIdProvider, pepper: bytes) -> str:
    """``HMAC-SHA256(machine_id_subkey, raw_machine_id)`` as 64-char hex.

    Uses the HKDF-derived machine-id subkey (sec-3), NOT the master
    pepper, so the hash cannot be cross-replayed as a token hash.
    Rotating the master pepper invalidates the hash (documented trade-off
    per spec §8.10 — operators re-login).
    """
    raw = await provider.read_raw()
    subkey = derive_machine_id_hash_subkey(pepper)
    return hmac.new(subkey, raw, hashlib.sha256).hexdigest()


def compute_token_hash(*, token: str, pepper: bytes) -> str:
    """``HMAC-SHA256(token_subkey, token)`` as 64-char hex (sec-3).

    The ``operator_sessions.token_hash`` column stores this; the resolver
    recomputes it from the session-file token to look up the row.
    """
    subkey = derive_token_hash_subkey(pepper)
    return hmac.new(subkey, token.encode("utf-8"), hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------------
# §10 Hookpoints (operator.session.*) — carrier_tier=T1
# ---------------------------------------------------------------------------

OPERATOR_SESSION_CREATED_HOOKPOINT: Final = "operator.session.created"
OPERATOR_SESSION_REVOKED_HOOKPOINT: Final = "operator.session.revoked"
OPERATOR_SESSION_REFUSED_HOOKPOINT: Final = "operator.session.refused"

_OPERATOR_SESSION_HOOKPOINTS: Final = (
    OPERATOR_SESSION_CREATED_HOOKPOINT,
    OPERATOR_SESSION_REVOKED_HOOKPOINT,
    OPERATOR_SESSION_REFUSED_HOOKPOINT,
)


def declare_hookpoints(registry: object | None = None) -> None:
    """Register the three operator-session hookpoints (spec §10).

    Each is ``subscribable_tiers=SYSTEM_ONLY_TIERS``, ``fail_closed=True``,
    ``carrier_tier=T1`` — the session-lifecycle events carry
    operator-attributable (T1) content (the ``user_id``, ``host``,
    ``machine_id_hash``). No subscribers exist at this layer in Slice 4;
    the hookpoints exist for future Slice-5+ consumers (step-up auth,
    federated-session sync).

    Called at module import (bottom of this file) so the manifest
    sync-test reaches it by importing the subsystem, mirroring
    ``alfred.cli.daemon.declare_hookpoints``. Idempotent on equal metadata
    via the registry's standard re-declaration guard.

    ``register_hookpoint`` REQUIRES ``carrier_tier=`` (PR-S4-3 AST guard);
    every call below populates it.
    """
    from alfred.hooks import SYSTEM_ONLY_TIERS, get_registry
    from alfred.hooks.registry import HookRegistry
    from alfred.security.tiers import T1

    if registry is None:
        reg: HookRegistry = get_registry()
    elif isinstance(registry, HookRegistry):
        reg = registry
    else:
        raise TypeError(
            f"declare_hookpoints(registry=) expects a HookRegistry or None, "
            f"got {type(registry).__name__}",
        )
    for name in _OPERATOR_SESSION_HOOKPOINTS:
        reg.register_hookpoint(
            name=name,
            subscribable_tiers=SYSTEM_ONLY_TIERS,
            refusable_tiers=frozenset(),
            fail_closed=True,
            carrier_tier=T1,
        )


__all__ = [
    "OPERATOR_SESSION_CREATED_HOOKPOINT",
    "OPERATOR_SESSION_REFUSED_HOOKPOINT",
    "OPERATOR_SESSION_REVOKED_HOOKPOINT",
    "LinuxMachineIdProvider",
    "MachineIdProvider",
    "MacosMachineIdProvider",
    "OperatorSessionBadFileMode",
    "OperatorSessionBadFileOwner",
    "OperatorSessionError",
    "OperatorSessionExpired",
    "OperatorSessionFile",
    "OperatorSessionHostMismatch",
    "OperatorSessionMachineIdMismatch",
    "OperatorSessionMalformed",
    "OperatorSessionMissing",
    "OperatorSessionNoMachineId",
    "OperatorSessionParentDirInsecure",
    "OperatorSessionParentDirNotOwned",
    "OperatorSessionPepperMisconfigured",
    "OperatorSessionRevoked",
    "OperatorSessionTimeout",
    "OperatorSessionTokenUnknown",
    "OperatorSessionTokenUserMismatch",
    "OperatorSessionUserRevoked",
    "WindowsMachineIdProvider",
    "compute_machine_id_hash",
    "compute_token_hash",
    "declare_hookpoints",
    "derive_machine_id_hash_subkey",
    "derive_token_hash_subkey",
    "load_session_file",
    "select_machine_id_provider",
    "write_session_file",
]


# Module-import registration so the manifest sync-test reaches these by
# importing the subsystem (mirrors alfred.cli.daemon + alfred.policies.watcher).
declare_hookpoints()
