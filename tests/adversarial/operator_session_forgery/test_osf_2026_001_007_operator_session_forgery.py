"""Executable assertions for the PR-S4-5 operator-session-forgery corpus (#153).

Each test drives the corresponding ``osf-2026-00N`` attack against the real
``DefaultOperatorSessionResolver`` (or the TOCTOU-safe ``load_session_file``)
and proves the defence fires with the expected typed exception + audit reason.

* osf-001 forged_session_file — valid-looking file, no DB row -> token_unknown.
* osf-002 replayed_session_from_other_host — file host != live host -> host_mismatch.
* osf-003 replayed_session_from_other_machine — machine-id-hash differs -> machine_mismatch.
* osf-004 stat_then_open_toctou_race — open-then-fstat sees the original inode.
* osf-005 symlink_to_attacker_owned_file — O_NOFOLLOW refuses at open ->
  resolver emits a file-less ``bad_file_mode`` refused row (hard rule #7).
* osf-006 token_user_mismatch — valid token, mismatched file user_id -> token_user_mismatch.
* osf-007 planted_user_id_log_injection — non-int user_id refused at parse ->
  resolver emits a file-less ``planted_file_invalid`` refused row (hard rule #7).

Every file-load refusal (osf-005/007 + the bad-mode case) is driven through
the real ``DefaultOperatorSessionResolver`` so the test proves the refusal
lands EXACTLY ONE ``OPERATOR_SESSION_REFUSED`` audit row with the right
closed-vocab reason — not merely that the typed exception was raised. The
file-less rows carry ``attempted_user_id=None`` (no attacker bytes from an
unparsed/insecure file reach the audit log).
"""

from __future__ import annotations

import hashlib
import hmac
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from pydantic import SecretStr

from alfred.identity._resolver import DefaultOperatorSessionResolver
from alfred.identity.operator_session import (
    OperatorSessionBadFileMode,
    OperatorSessionFile,
    OperatorSessionHostMismatch,
    OperatorSessionMachineIdMismatch,
    OperatorSessionMalformed,
    OperatorSessionMissing,
    OperatorSessionTokenUnknown,
    OperatorSessionTokenUserMismatch,
    derive_machine_id_hash_subkey,
    load_session_file,
    write_session_file,
)


def _live_machine_hash() -> str:
    """The machine-id hash the resolver computes for ``_Machine``'s raw bytes."""
    subkey = derive_machine_id_hash_subkey(_PEPPER.encode())
    return hmac.new(subkey, b"machine-raw", hashlib.sha256).hexdigest()


_PEPPER = "0" * 64
_HOST = "victim-host"
_TOKEN = "valid-token"  # noqa: S105 -- corpus fixture token, not a real credential


class _Broker:
    def get(self, name: str) -> str:
        assert name == "audit.hash_pepper"
        return _PEPPER


class _Machine:
    def __init__(self, raw: bytes = b"machine-raw") -> None:
        self._raw = raw

    async def read_raw(self) -> bytes:
        return self._raw


class _Audit:
    def __init__(self) -> None:
        self.reasons: list[str] = []
        self.subjects: list[dict[str, Any]] = []

    async def append_schema(self, **kwargs: Any) -> None:
        self.reasons.append(kwargs["subject"]["reason"])
        self.subjects.append(kwargs["subject"])


class _Hooks:
    async def __call__(self, *_a: Any, **_k: Any) -> None:
        return None


def _scope(rows: list[tuple[int, datetime | None]] | None) -> Any:
    class _Session:
        async def execute(self, *_a: Any, **_k: Any) -> Any:
            class _R:
                def first(self) -> tuple[int, datetime | None] | None:
                    return rows[0] if rows else None

            return _R()

    @asynccontextmanager
    async def _s() -> Any:
        yield _Session()

    return _s


def _write(
    tmp_path: Path,
    *,
    user_id: int = 7,
    host: str = _HOST,
    machine_hash: str | None = None,
    expires_delta: timedelta = timedelta(hours=12),
) -> Path:
    parent = tmp_path / ".config" / "alfred"
    parent.mkdir(parents=True, exist_ok=True)
    parent.chmod(0o700)
    path = parent / "session"
    now = datetime.now(UTC)
    expires_at = now + expires_delta
    if machine_hash is None:
        machine_hash = _live_machine_hash()
    write_session_file(
        path,
        OperatorSessionFile(
            schema_version=1,
            user_id=user_id,
            token=SecretStr(_TOKEN),
            issued_at=expires_at - timedelta(minutes=1),
            expires_at=expires_at,
            host=host,
            machine_id_hash=machine_hash,
        ),
    )
    return path


def _resolver(
    path: Path, rows: list[tuple[int, datetime | None]] | None, *, audit: _Audit, host: str = _HOST
) -> DefaultOperatorSessionResolver:
    return DefaultOperatorSessionResolver(
        session_scope=_scope(rows),
        secret_broker=_Broker(),
        machine_id_provider=_Machine(),
        audit_writer=audit,
        hook_dispatcher=_Hooks(),
        host=host,
        session_file_path=path,
    )


async def test_osf_001_forged_session_file_token_unknown(tmp_path: Path) -> None:
    path = _write(tmp_path)
    audit = _Audit()
    resolver = _resolver(path, rows=None, audit=audit)  # no DB row
    with pytest.raises(OperatorSessionTokenUnknown):
        await resolver.resolve()
    assert audit.reasons[-1] == "token_unknown"


async def test_osf_002_replayed_from_other_host(tmp_path: Path) -> None:
    path = _write(tmp_path, host="host-a")
    audit = _Audit()
    resolver = _resolver(path, rows=[(7, None)], audit=audit, host="host-b")
    with pytest.raises(OperatorSessionHostMismatch):
        await resolver.resolve()
    assert audit.reasons[-1] == "host_mismatch"


async def test_osf_003_replayed_from_other_machine(tmp_path: Path) -> None:
    path = _write(tmp_path, machine_hash="f" * 64)
    audit = _Audit()
    resolver = _resolver(path, rows=[(7, None)], audit=audit)
    with pytest.raises(OperatorSessionMachineIdMismatch):
        await resolver.resolve()
    assert audit.reasons[-1] == "machine_mismatch"


def test_osf_004_stat_then_open_toctou_race(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """open-then-fstat: a mid-load inode swap is invisible at the FD level.

    Models the real race: the attacker swaps the path to a DIFFERENT-content
    inode AFTER the loader has opened (and fstat-validated) the FD but BEFORE
    the read. Because the loader reads from the already-open FD — which still
    points at the original, now-unlinked inode — the attacker's content is
    never observed. A vulnerable stat-then-RE-OPEN loader would instead read
    the swapped bytes, so this assertion genuinely distinguishes the two
    (the prior version re-wrote IDENTICAL bytes and proved nothing).
    """
    path = _write(tmp_path)
    original = load_session_file(path)

    import alfred.identity.operator_session as _osmod

    real_read = _osmod.os.read
    swapped = {"done": False}

    def _swap_then_read(fd: int, n: int) -> bytes:
        if not swapped["done"]:
            swapped["done"] = True
            # Replace the PATH with a new inode carrying attacker bytes. The
            # loader's open FD still references the original inode.
            path.unlink()
            path.write_bytes(b'{"attacker": "swapped-content-different-bytes"}')
            path.chmod(0o600)
        return real_read(fd, n)

    monkeypatch.setattr(_osmod.os, "read", _swap_then_read)

    result = load_session_file(path)
    assert swapped["done"] is True  # the swap fired mid-load
    assert result == original  # ...and the original-inode content still won


def test_osf_005_symlink_to_attacker_file_refused(tmp_path: Path) -> None:
    target = tmp_path / "attacker-session"
    target.write_bytes(b"{}")
    target.chmod(0o600)
    parent = tmp_path / ".config" / "alfred"
    parent.mkdir(parents=True)
    parent.chmod(0o700)
    link = parent / "session"
    link.symlink_to(target)
    with pytest.raises(OperatorSessionBadFileMode):
        load_session_file(link)


async def test_osf_005_symlink_refusal_emits_fileless_audit_row(tmp_path: Path) -> None:
    """O_NOFOLLOW refusal must land a file-less ``bad_file_mode`` row (hard rule #7).

    The previous resolver raised ``OperatorSessionBadFileMode`` from the FIRST
    statement of ``_resolve_inner``, BEFORE any ``_emit_refused`` — so a
    symlink-swap attack produced NO audit row. This asserts the file-less emit
    path now fires exactly one row with the right reason + null self-claimed
    fields.
    """
    target = tmp_path / "attacker-session"
    target.write_bytes(b"{}")
    target.chmod(0o600)
    parent = tmp_path / ".config" / "alfred"
    parent.mkdir(parents=True)
    parent.chmod(0o700)
    link = parent / "session"
    link.symlink_to(target)
    audit = _Audit()
    resolver = _resolver(link, rows=[(7, None)], audit=audit)
    with pytest.raises(OperatorSessionBadFileMode):
        await resolver.resolve()
    assert audit.reasons == ["bad_file_mode"]
    assert audit.subjects[-1]["attempted_user_id"] is None
    assert audit.subjects[-1]["host"] is None
    assert audit.subjects[-1]["machine_id_hash"] is None


async def test_osf_005b_bad_mode_refusal_emits_fileless_audit_row(tmp_path: Path) -> None:
    """A real file with a broadened mode (0644) lands a ``bad_file_mode`` row."""
    path = _write(tmp_path)
    path.chmod(0o644)
    audit = _Audit()
    resolver = _resolver(path, rows=[(7, None)], audit=audit)
    with pytest.raises(OperatorSessionBadFileMode):
        await resolver.resolve()
    assert audit.reasons == ["bad_file_mode"]


async def test_osf_missing_file_emits_fileless_session_missing_row(tmp_path: Path) -> None:
    """No session file at all lands exactly one ``session_missing`` row."""
    parent = tmp_path / ".config" / "alfred"
    parent.mkdir(parents=True)
    parent.chmod(0o700)
    path = parent / "session"  # never created
    audit = _Audit()
    resolver = _resolver(path, rows=[(7, None)], audit=audit)
    with pytest.raises(OperatorSessionMissing):
        await resolver.resolve()
    assert audit.reasons == ["session_missing"]


async def test_osf_006_token_user_mismatch(tmp_path: Path) -> None:
    """Valid token, file claims user 7, DB row owns user 9 -> token authoritative."""
    path = _write(tmp_path, user_id=7)
    audit = _Audit()
    resolver = _resolver(path, rows=[(9, None)], audit=audit)
    with pytest.raises(OperatorSessionTokenUserMismatch):
        await resolver.resolve()
    assert audit.reasons[-1] == "token_user_mismatch"


def _write_planted_malformed(tmp_path: Path) -> Path:
    """Plant a file whose ``user_id`` carries log-injection bytes.

    The int coercion rejects it at ``model_validate`` time -> Malformed.
    """
    parent = tmp_path / ".config" / "alfred"
    parent.mkdir(parents=True)
    parent.chmod(0o700)
    path = parent / "session"
    path.write_bytes(
        b'{"schema_version":1,"user_id":"7\\n[CRITICAL] forged","token":"x",'
        b'"issued_at":"2026-06-08T00:00:00+00:00",'
        b'"expires_at":"2026-06-08T12:00:00+00:00",'
        b'"host":"h","machine_id_hash":"' + b"a" * 64 + b'"}'
    )
    path.chmod(0o600)
    return path


def test_osf_007_planted_user_id_log_injection_refused_at_parse(tmp_path: Path) -> None:
    """A non-int user_id (arbitrary bytes) is refused at parse."""
    path = _write_planted_malformed(tmp_path)
    with pytest.raises(OperatorSessionMalformed):
        load_session_file(path)


async def test_osf_007_planted_malformed_emits_fileless_audit_row(tmp_path: Path) -> None:
    """The planted-malformed refusal lands a ``planted_file_invalid`` row.

    The injection bytes never reach the audit log: the file does not parse,
    so the file-less row carries ``attempted_user_id=None`` — the closed-vocab
    ``reason`` is the only forensic signal (hard rule #7 + sec-4).
    """
    path = _write_planted_malformed(tmp_path)
    audit = _Audit()
    resolver = _resolver(path, rows=[(7, None)], audit=audit)
    with pytest.raises(OperatorSessionMalformed):
        await resolver.resolve()
    assert audit.reasons == ["planted_file_invalid"]
    assert audit.subjects[-1]["attempted_user_id"] is None
