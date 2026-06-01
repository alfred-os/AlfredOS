"""Secret broker for AlfredOS (env-backed in Slice 1; file-backed in Slice 2).

The broker is the sole legitimate consumer of ``ALFRED_*`` environment variables
for any secret listed in :data:`SUPPORTED_SECRETS`. Every other module reads
secrets via :meth:`SecretBroker.get`. This invariant is enforced by the AST-scan
test :mod:`tests.unit.security.test_no_direct_env_reads` — see CLAUDE.md
security hard rule #6 ("Secrets live in the broker, not in env vars accessible
to plugins.") and ADR-0012.

Path resolution pipeline (matches spec §2 — verbatim so the layering is
auditable from ``pydoc alfred.security.secrets``):

================ ===================================== ========================
 Layer            Setting                                Resolves to
================ ===================================== ========================
 Host default     ``Settings.secrets_file`` (Pydantic)   ``~/.config/alfred/secrets.toml``
 Container        ``ALFRED_SECRETS_FILE`` env var        ``/etc/alfred/secrets.toml``
 Override         constructor ``secrets_file=`` kwarg    Any caller-supplied path
 Enforcement      ``require_file=True``                  Init-time fail-closed
================ ===================================== ========================

Precedence: constructor arg wins → then ``ALFRED_SECRETS_FILE`` env var → then
``Settings.secrets_file`` Pydantic default. The constructor resolves the path
once and caches it.

Precedence rules at :meth:`get` (ADR-0012):

* For names in :data:`_PREFER_FILE` (Slice-2+ secrets like ``discord_bot_token``)
  the file wins; env is only consulted if the file is absent or doesn't contain
  the key.
* For Slice-1 keys (``deepseek_api_key``, ``anthropic_api_key``) env wins for
  backward compatibility; the file is consulted only as a fallback. This is
  intentional — operators in Slice 1 set these via ``.env`` files; flipping
  them to file-prefer would change deployment behaviour silently.

The privileged LLM never reads env vars or files directly. All secret access
goes through this broker, which substitutes values at the tool-call boundary
in later slices.
"""

from __future__ import annotations

import os
import re
import stat
import tomllib
from collections.abc import Mapping
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING, Final

import structlog

from alfred.errors import AlfredError
from alfred.i18n import t

if TYPE_CHECKING:
    from alfred.config.settings import Settings

_log = structlog.get_logger(__name__)

# Slice 1 + Slice 2 supported secrets. Extend as new providers and integrations
# land. Anything added here must also be either (a) read-only from env (slice-1
# behaviour) or (b) added to :data:`_PREFER_FILE` (file-prefer behaviour).
SUPPORTED_SECRETS: frozenset[str] = frozenset(
    {
        "deepseek_api_key",
        "anthropic_api_key",
        "discord_bot_token",
    }
)

# Secrets whose file value wins over env. Strict subset of SUPPORTED_SECRETS —
# the AST-scan test asserts the subset invariant so a future drift (adding
# a key here without registering it in SUPPORTED_SECRETS) fails CI loudly.
_PREFER_FILE: frozenset[str] = frozenset({"discord_bot_token"})

# Bound on the redactor's alternation regex size. Past this point we log one
# WARN and fall back to redacting only the 256 longest values (highest-
# information-content secrets — the rationale is recorded in :meth:`redact`'s
# docstring and ADR-0012). The cap exists because a runaway secret-set —
# either an operator misconfiguration or a future incident where secrets
# accumulate without rotation — would otherwise expand into a multi-megabyte
# compiled pattern. perf-006.
MAX_REDACTOR_PATTERNS: Final[int] = 256

# Defends against pathological symlink loops in the .git parent walk. Five
# levels covers the typical "/", "/home", "/home/user", "~/.config",
# "~/.config/alfred" depth; twelve gives us double headroom and still bounds
# wall-time.
_GIT_WALK_MAX_DEPTH: Final[int] = 12

# Pattern for ``ALFRED_<UPPERSECRET>`` env var name to secret-name mapping.
# Used by the AST-scan test (imported via ``SUPPORTED_SECRETS``).
_ENV_PREFIX = "ALFRED_"

# Cumulative count of redactor pattern overflow events across the process.
# Tests assert this; production wiring to Prometheus lands in Slice 3 (an ADR
# is required to introduce ``prometheus_client``; the seam is here so that
# wiring is a single edit later).
alfred_redactor_pattern_overflow_total: int = 0


class UnknownSecretError(KeyError):
    """Raised when a caller asks for a secret name that is not registered."""


class SecretBrokerConfigError(AlfredError):
    """Base class for SecretBroker configuration failures at construction.

    Subclasses carry the offending ``path`` so the CLI top-level dispatch can
    catch ``SecretBrokerConfigError`` once and route error-message i18n on the
    concrete subtype.
    """

    __slots__ = ("path",)

    def __init__(self, message: str, *, path: Path) -> None:
        super().__init__(message)
        self.path = path

    def __repr__(self) -> str:
        return f"{type(self).__name__}(path={self.path!s})"


class SecretBrokerPermissionsError(SecretBrokerConfigError):
    """Secrets file has insecure permissions or sits inside a worktree.

    The ``mode`` field carries the offending POSIX mode bits as an int (render
    as ``oct(mode)``). For the ``.git``-in-parent location-rejection branch the
    sentinel ``mode=0`` is used — there's no perm-bits failure, the file lives
    in the wrong place; the i18n template branches on ``mode == 0`` to render
    the location-specific message (decision 3.2 in the plan: reuse this class
    rather than add a fourth i18n key).
    """

    __slots__ = ("mode", "parent")

    def __init__(
        self,
        message: str,
        *,
        path: Path,
        mode: int,
        parent: Path | None = None,
    ) -> None:
        super().__init__(message, path=path)
        self.mode = mode
        self.parent = parent

    def __repr__(self) -> str:
        return f"SecretBrokerPermissionsError(path={self.path!s}, mode={oct(self.mode)})"


class SecretBrokerFileMissingError(SecretBrokerConfigError):
    """``require_file=True`` was set but the resolved secrets file does not exist."""

    __slots__ = ()


class SecretBrokerNotAFileError(SecretBrokerConfigError):
    """Resolved secrets-file path exists but is not a regular file.

    Typically this means Docker auto-created a bind-mount directory at the path
    before the host file existed — the remediation is in the i18n template
    (run ``bin/alfred-setup.sh``).
    """

    __slots__ = ()


def _resolve_secrets_path(
    constructor_arg: Path | None,
    env: Mapping[str, str],
    settings_default: Path | None,
) -> Path | None:
    """Return the resolved secrets-file path, honouring the layered precedence.

    Pure function (no I/O) — caller is responsible for any subsequent stat or
    open.

    Order: constructor arg wins → then ``ALFRED_SECRETS_FILE`` env var → then
    Settings default. Returns ``None`` if all three are unset, signalling
    "no file backend; env-only" to the constructor.
    """
    if constructor_arg is not None:
        return constructor_arg
    env_value = env.get("ALFRED_SECRETS_FILE")
    if env_value:
        return Path(env_value)
    return settings_default


def _walk_for_git_parent(path: Path, max_depth: int = _GIT_WALK_MAX_DEPTH) -> Path | None:
    """Return the first ancestor of ``path`` containing a ``.git`` dir, or None.

    The bound on ``max_depth`` defends against pathological symlink loops.
    Stops at the filesystem root. Iterative (not recursive) for clarity.
    """
    current = path.parent
    for _ in range(max_depth):
        if (current / ".git").is_dir():
            return current
        parent = current.parent
        if parent == current:
            # Hit filesystem root.
            return None
        current = parent
    return None


def _validate_secrets_file_security(path: Path) -> None:
    """Fail-closed permissions check for the secrets file.

    Order of checks (intentional — earliest failures are the most severe):

    1. Not a symlink (rejects symlink-attack via lstat, never follows).
    2. Owned by the invoking user (``st_uid == os.getuid()``).
    3. Not a regular file → :class:`SecretBrokerNotAFileError`.
    4. No group/world bits on the file itself (``st_mode & 0o077 == 0``).
    5. Parent directory not group/world-writable (``& 0o022 == 0``).

    POSIX ACLs are NOT checked — defense-in-depth at the host level is the
    documented gap in ADR-0012. The mode-bits check catches the common
    misconfiguration (``chmod 644`` on a new file) without spelunking into
    extended attributes.
    """
    lstat_result = path.lstat()
    if stat.S_ISLNK(lstat_result.st_mode):
        raise SecretBrokerPermissionsError(
            t(
                "secrets.file_perms_too_open",
                path=str(path),
                octal_mode=oct(lstat_result.st_mode & 0o777),
                parent=str(path.parent),
            ),
            path=path,
            mode=lstat_result.st_mode,
        )
    if lstat_result.st_uid != os.getuid():
        raise SecretBrokerPermissionsError(
            t(
                "secrets.file_perms_too_open",
                path=str(path),
                octal_mode=oct(lstat_result.st_mode & 0o777),
                parent=str(path.parent),
            ),
            path=path,
            mode=lstat_result.st_mode & 0o777,
        )
    if not stat.S_ISREG(lstat_result.st_mode):
        raise SecretBrokerNotAFileError(
            t("secrets.path_is_directory", path=str(path)),
            path=path,
        )
    if lstat_result.st_mode & 0o077 != 0:
        raise SecretBrokerPermissionsError(
            t(
                "secrets.file_perms_too_open",
                path=str(path),
                octal_mode=oct(lstat_result.st_mode & 0o777),
                parent=str(path.parent),
            ),
            path=path,
            mode=lstat_result.st_mode & 0o777,
        )
    parent_stat = path.parent.stat()
    if parent_stat.st_mode & 0o022 != 0:
        raise SecretBrokerPermissionsError(
            t(
                "secrets.file_perms_too_open",
                path=str(path),
                octal_mode=oct(parent_stat.st_mode & 0o777),
                parent=str(path.parent),
            ),
            path=path,
            mode=parent_stat.st_mode & 0o777,
            parent=path.parent,
        )


def _load_toml_file(path: Path) -> Mapping[str, str]:
    """Parse ``path`` as TOML and return a read-only string→string mapping.

    Non-string values and nested tables are silently dropped — the secrets
    file is a flat table of names to opaque strings. Tolerating unknown keys
    is deliberate: a typo doesn't fail the broker; it just doesn't satisfy
    any :meth:`get` call.
    """
    with path.open("rb") as fh:
        data = tomllib.load(fh)
    flat: dict[str, str] = {}
    for key, value in data.items():
        if isinstance(value, str):
            flat[key] = value
    return MappingProxyType(flat)


class SecretBroker:
    """Reads secrets from environment variables and/or a TOML file.

    Slice-1 callers passing no kwargs see the env-only behaviour. Slice-2
    callers pass ``secrets_file=Path(...)`` (or set ``ALFRED_SECRETS_FILE``,
    or rely on the ``Settings.secrets_file`` default) to enable the file
    backend.

    The constructor is **fail-closed** at the trust boundary. If the resolved
    file exists, permissions are validated immediately; if ``require_file=True``
    is set and the file is missing, the constructor raises rather than letting
    the failure surface three layers downstream as a misleading ``LoginFailure``
    or ``UnknownSecretError``.
    """

    def __init__(
        self,
        *,
        env: Mapping[str, str] | None = None,
        secrets_file: Path | None = None,
        require_file: bool = False,
        allow_inside_git_worktree: bool = False,
        settings_default: Path | None = None,
    ) -> None:
        # Inject env for tests; default to os.environ so callers don't have to.
        self._env: Mapping[str, str] = dict(env) if env is not None else dict(os.environ)
        self._secrets_file_path: Path | None = _resolve_secrets_path(
            secrets_file, self._env, settings_default
        )
        self._file_secrets: Mapping[str, str] = MappingProxyType({})
        self._allow_inside_git_worktree = allow_inside_git_worktree

        # Redactor cache state (perf-006). Version counter bumps whenever the
        # set of live secrets could change; the cache is rebuilt lazily on
        # the next redact() call. _overflow_warned is one-shot per broker
        # instance — we do NOT want to spam the log if every redact() call
        # exceeds the cap.
        self._redactor_version: int = 0
        self._redactor_cache: tuple[int, re.Pattern[str], Mapping[str, str]] | None = None
        self._overflow_warned: bool = False

        if self._secrets_file_path is None:
            if require_file:
                raise SecretBrokerFileMissingError(
                    t(
                        "secrets.file_missing_required",
                        path="<unset>",
                    ),
                    path=Path("<unset>"),
                )
            return

        if not self._secrets_file_path.exists():
            if require_file:
                raise SecretBrokerFileMissingError(
                    t(
                        "secrets.file_missing_required",
                        path=str(self._secrets_file_path),
                    ),
                    path=self._secrets_file_path,
                )
            # require_file=False + missing file: proceed with env-only backend.
            return

        if not allow_inside_git_worktree:
            git_parent = _walk_for_git_parent(self._secrets_file_path)
            if git_parent is not None:
                raise SecretBrokerPermissionsError(
                    t(
                        "secrets.file_perms_too_open",
                        path=str(self._secrets_file_path),
                        octal_mode="0",
                        parent=str(git_parent),
                    ),
                    path=self._secrets_file_path,
                    mode=0,
                    parent=git_parent,
                )

        _validate_secrets_file_security(self._secrets_file_path)
        self._file_secrets = _load_toml_file(self._secrets_file_path)

    @classmethod
    def from_settings(cls, settings: Settings) -> SecretBroker:
        """Build a broker primed from a Settings instance.

        Reads ``settings.secrets_file`` (Pydantic default) and passes it as
        the ``settings_default`` layer of the path-resolution pipeline. The
        env var and constructor override still take precedence.
        """
        raw = getattr(settings, "secrets_file", None)
        # Defensive: only honour Path-like values. MagicMock from
        # tests/unit/security/test_secrets.py::test_from_settings_constructs_broker
        # would otherwise hit the .git-walk path with a nonsense path.
        settings_default = raw if isinstance(raw, Path) else None
        return cls(settings_default=settings_default)

    def get(self, name: str) -> str:
        if name not in SUPPORTED_SECRETS:
            raise UnknownSecretError(name)
        env_name = f"{_ENV_PREFIX}{name.upper()}"
        env_value = self._env.get(env_name) or None
        file_value = self._file_secrets.get(name) or None

        if name in _PREFER_FILE:
            value = file_value if file_value is not None else env_value
        else:
            value = env_value if env_value is not None else file_value

        if value is None or value == "":
            raise UnknownSecretError(f"{name} (env {env_name}, file key '{name}') is not set")
        return value

    def has(self, name: str) -> bool:
        """Return True iff `name` is a registered secret with a non-empty value.

        Used by the CLI to decide whether to wire up optional providers
        (e.g. Anthropic fallback) without forcing a try/except dance.
        """
        if name not in SUPPORTED_SECRETS:
            return False
        try:
            self.get(name)
        except UnknownSecretError:
            return False
        return True

    def known(self) -> list[str]:
        """Return the names of registered secrets that currently have a value.

        Names only — callers that need the values use `_known_with_values()`
        or `get()`. Keeping the public surface name-only prevents accidental
        leakage of values into logs by anyone iterating `known()`.
        """
        return [name for name, _ in self._known_with_values()]

    def _known_with_values(self) -> list[tuple[str, str]]:
        """Return (name, value) pairs for registered secrets with non-empty values.

        Single source of truth for "which secrets are live right now" — used by
        :meth:`known` (which drops the values) and :meth:`redact` (which needs
        both). Sorting by name keeps :meth:`known` ordering deterministic for
        callers.
        """
        pairs: list[tuple[str, str]] = []
        for name in sorted(SUPPORTED_SECRETS):
            try:
                value = self.get(name)
            except UnknownSecretError:
                continue
            # get() already raises UnknownSecretError for empty/None values, so
            # value is always truthy here. The explicit pair-list build is kept
            # for shape symmetry with the slice-1 invariant.
            pairs.append((name, value))
        return pairs

    def _bump_redactor_version(self) -> None:
        """Invalidate the cached compiled redactor regex.

        Called when the set of live secrets could have changed. In Slice 2 the
        SUPPORTED_SECRETS set is module-constant and the env/file backends are
        constructor-frozen, so this method is only invoked by tests. Slice 3+
        (when secrets become mutable at runtime) will call it from any path
        that adds/removes a secret.
        """
        self._redactor_version += 1

    def redact(self, text: str) -> str:
        """Replace any known secret value inside `text` with `[REDACTED:<name>]`.

        Pairs are processed in descending-length order so a longer secret
        whose suffix happens to be another live secret is fully redacted
        before the shorter one runs — otherwise the inner replacement would
        consume the shared prefix and leak the longer secret's tail bytes
        (PRD §7.1 ordering invariant).

        Caching (perf-006): the compiled alternation regex is cached on the
        broker instance and reused across calls. The cache is invalidated by
        :meth:`_bump_redactor_version`. Overflow handling: if more than
        :data:`MAX_REDACTOR_PATTERNS` distinct values are live, the longest
        256 are kept and one structlog WARN is emitted per broker instance
        (one-shot, not per call). The selection rule favours the longest
        values — the highest-information-content secrets — because a short
        tail value is far lower leakage risk than a long one. ADR-0012
        records the rationale.
        """
        cache = self._redactor_cache
        if cache is None or cache[0] != self._redactor_version:
            pairs = sorted(
                self._known_with_values(),
                key=lambda item: len(item[1]),
                reverse=True,
            )

            if len(pairs) > MAX_REDACTOR_PATTERNS:
                if not self._overflow_warned:
                    self._overflow_warned = True
                    global alfred_redactor_pattern_overflow_total
                    alfred_redactor_pattern_overflow_total += 1
                    _log.warning(
                        "redactor.pattern_overflow",
                        total_patterns=len(pairs),
                        cap=MAX_REDACTOR_PATTERNS,
                    )
                pairs = pairs[:MAX_REDACTOR_PATTERNS]

            value_to_name = {value: name for name, value in pairs}
            if pairs:
                pattern = re.compile("|".join(re.escape(value) for _, value in pairs))
            else:
                # Empty pattern would match every position — use a sentinel
                # that never matches so the substitution is a no-op.
                pattern = re.compile(r"(?!x)x")
            self._redactor_cache = (
                self._redactor_version,
                pattern,
                MappingProxyType(value_to_name),
            )
            cache = self._redactor_cache

        _version, pattern, name_map = cache
        if not name_map:
            return text
        return pattern.sub(
            lambda m: f"[REDACTED:{name_map[m.group(0)]}]",
            text,
        )

    def reload(self) -> None:
        """Re-read the secrets file and bump the redactor cache version.

        Public seam so tests (and Slice-3+ runtime mutators) can force a
        refresh without reconstructing the broker. Permission re-validation
        runs again — a file that flipped to insecure mode bits between
        construction and reload is fail-closed at reload time.
        """
        if self._secrets_file_path is None or not self._secrets_file_path.exists():
            self._file_secrets = MappingProxyType({})
        else:
            try:
                _validate_secrets_file_security(self._secrets_file_path)
                self._file_secrets = _load_toml_file(self._secrets_file_path)
            except FileNotFoundError:  # pragma: no cover
                # TOCTOU: file disappeared between exists() and lstat() —
                # treat as missing rather than propagating the race.
                #
                # Coverage rationale: this branch fires only when the
                # filesystem races between the ``exists()`` probe on the
                # line above and the ``lstat()`` inside
                # ``_validate_secrets_file_security``. The window is
                # microseconds and the race is non-deterministic — there
                # is no way to reliably trigger it from a unit test
                # without monkey-patching ``_validate_secrets_file_security``
                # itself, which would only test the patch, not the real
                # behaviour. The fail-closed semantics (empty mapping +
                # cache version bump) ARE asserted by
                # ``test_reload_handles_now_missing_file`` via the
                # ``exists() == False`` arm above; this except-branch is
                # the defensive equivalent for the same outcome.
                # PR #99 added the TOCTOU guard; PR #134 documents the
                # pragma per the spec §11a 100% trust-boundary gate.
                self._file_secrets = MappingProxyType({})
        self._bump_redactor_version()
