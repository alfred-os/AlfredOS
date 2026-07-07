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
import subprocess
import tomllib
from collections.abc import Mapping
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING, Final, Literal

import structlog

from alfred.errors import AlfredError
from alfred.i18n import t

if TYPE_CHECKING:
    from alfred.security._config_protocols import SecretBrokerConfig

_log = structlog.get_logger(__name__)

# Slice 1 + Slice 2 supported secrets. Extend as new providers and integrations
# land. Anything added here must also be either (a) read-only from env (slice-1
# behaviour) or (b) added to :data:`_PREFER_FILE` (file-prefer behaviour).
SUPPORTED_SECRETS: frozenset[str] = frozenset(
    {
        "deepseek_api_key",
        "anthropic_api_key",
        "discord_bot_token",
        # Slice-4 PR-S4-0b Component H: master HMAC pepper used by
        # PR-S4-5 operator-session token_hash + machine_id_hash,
        # PR-S4-8/9 comms platform_user_id_hash + verification_phrase_hash,
        # and PR-S4-0b migration 0012-0015's CHECK regex pins. The
        # ``bin/alfred-setup.sh`` script seeds this on first boot via
        # ``openssl rand -hex 32``; rotation invalidates cross-row
        # correlation (spec §8.10) so the bootstrap is idempotent.
        "audit.hash_pepper",
        # Slice-4 PR-S4-11c-2b: the quarantined-LLM child's provider API key,
        # delivered over fd 3 to the bwrap-sandboxed child (NEVER read from the
        # child's own env). The daemon resolves it via this id and hands it to
        # ``spawn_quarantine_child_io``. The 2b deterministic-echo child reads +
        # scrubs + discards it (no LLM call yet), so an UNSET key currently falls
        # back to a documented placeholder with a loud boot warning; PR-S4-11c-2c
        # (the real LLM client) flips unset -> refuse-boot once the child actually
        # calls the provider. ``config/routing.yaml``'s ``[quarantine] secret_id``
        # pins this same id (test_routing_yaml_quarantine_block).
        "quarantine_provider_api_key",
    }
)

# Secrets whose file value wins over env. Strict subset of SUPPORTED_SECRETS —
# the AST-scan test asserts the subset invariant so a future drift (adding
# a key here without registering it in SUPPORTED_SECRETS) fails CI loudly.
_PREFER_FILE: frozenset[str] = frozenset({"discord_bot_token", "quarantine_provider_api_key"})

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

# ``{{secret:<name>}}`` placeholder resolved by ``SecretBroker.substitute`` at the
# tool-call boundary (HARD rule #6). The inner group is deliberately permissive
# (any non-brace run) so a MALFORMED name is caught and refused rather than passed
# through literally; the strict name charset is validated separately.
_SECRET_PLACEHOLDER: Final = re.compile(r"\{\{secret:([^{}]*)\}\}")
_VALID_SECRET_NAME: Final = re.compile(r"\A[a-z0-9_.]+\Z")

# Cumulative count of redactor pattern overflow events across the process.
# Tests assert this; production wiring to Prometheus lands in Slice 3 (an ADR
# is required to introduce ``prometheus_client``; the seam is here so that
# wiring is a single edit later).
alfred_redactor_pattern_overflow_total: int = 0


class UnknownSecretError(KeyError):
    """Raised when a caller asks for a secret name that is not registered."""


class SecretSubstitutionNotAllowed(AlfredError):  # noqa: N818 -- name pinned by #339 PR4b-broker Task 1 interface spec
    """A ``{{secret:<name>}}`` reference that is not permitted in this context.

    Confused-deputy defence (mirrors
    :class:`alfred.comms_mcp.adapter_credential_resolver.CoreAdapterCredentialResolver`'s
    closed ``_ADAPTER_SECRET_ALLOWLIST``): the referenced name is off the caller's
    closed ``allowed_secrets`` set, or is malformed. Carries the (possibly
    attacker-influenced) ``ref`` for internal correlation ONLY — the message is a
    FIXED string, and callers audit the closed ``secret_substitution_refused``
    token, never the raw ``ref`` (no unbounded attacker text into audit/logs).
    """

    __slots__ = ("ref",)

    def __init__(self, ref: str) -> None:
        super().__init__("secret reference not permitted")
        self.ref = ref


class SecretBrokerConfigError(AlfredError):
    """Base class for SecretBroker configuration failures at construction.

    Subclasses carry the offending ``path``. The realized handlers
    (``build_broker_or_die`` on the CLI, the daemon boot ``_refuse_boot`` path)
    catch this base class ONCE and echo ``str(exc)`` — the concrete subtype
    renders its own i18n message at raise time, so the dispatch never
    re-branches on the subtype (#370 item 4: docstring reconciled to the
    realized #368 behaviour). The subtype still carries the structured ``path``
    for audit/forensics.
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
    in the wrong place. The exception CLASS is reused for API/dispatch
    compatibility (callers catch one type across both failure shapes), but the
    rendered message comes from the dedicated ``secrets.file_in_git_repo``
    catalog entry (#363 blocker 2) — NOT the perms-template — so the operator
    sees the accurate "wrong location" remedy instead of a misleading `chmod`
    instruction.
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


class SecretBrokerMalformedError(SecretBrokerConfigError):
    """The resolved secrets file exists and is readable but is not valid TOML.

    #370 item 1: a valid-perms file with broken TOML raises
    :class:`tomllib.TOMLDecodeError` from :func:`_load_toml_file`. Wrapping it
    at the construction boundary in this typed subtype means the #368 boot/CLI
    handlers catch it via the ``SecretBrokerConfigError`` base and refuse
    fail-closed with an operator message, instead of surfacing a raw
    ``TOMLDecodeError`` traceback. Distinct from
    :class:`SecretBrokerUnreadableError` (an I/O failure) so the operator gets
    the right remediation: fix the file's TOML syntax, not its access.
    """

    __slots__ = ()


class SecretBrokerUnreadableError(SecretBrokerConfigError):
    """An ``OSError`` escaped while reading/stat-ing the resolved secrets file.

    #370 item 1: an ``OSError`` raised by the stat/lstat in
    :func:`_validate_secrets_file_security` or the ``open`` in
    :func:`_load_toml_file` (a TOCTOU race, ``PermissionError``, etc.) at
    construction. Wrapping it in this typed subtype means the #368 boot/CLI
    handlers catch it via the ``SecretBrokerConfigError`` base and refuse
    fail-closed, instead of surfacing a raw ``OSError`` traceback. Distinct from
    :class:`SecretBrokerMalformedError` (bad content) so the operator gets the
    right remediation: fix the file's access/ownership, not its syntax.

    Scope note: only OSErrors from the validate/load step are wrapped. An
    ``OSError`` from the earlier ``exists()`` probe (e.g. an EACCES search on the
    parent on some platforms) sits before this ``try`` and is out of scope — the
    boundary this leaf guards is the validate/load pair, not the existence check.
    """

    __slots__ = ()


_SecretsLayer = Literal["constructor", "env", "settings_default"] | None


def _resolve_secrets_path(
    constructor_arg: Path | None,
    env: Mapping[str, str],
    settings_default: Path | None,
) -> tuple[Path | None, _SecretsLayer]:
    """Return ``(path, layer)`` honouring the layered precedence.

    Pure function (no I/O) — caller is responsible for any subsequent stat or
    open.

    Order: constructor arg wins → then ``ALFRED_SECRETS_FILE`` env var → then
    Settings default. ``path`` is ``None`` if all three are unset (env-only
    backend). ``layer`` names which layer produced the path
    (``"constructor"`` / ``"env"`` / ``"settings_default"``) and is ``None``
    iff ``path`` is ``None``. #366 uses ``layer`` to apply the gitignore-aware
    ``.git``-walk narrowing to the ``settings_default`` (XDG default) layer
    only — the kwarg / ``ALFRED_SECRETS_FILE`` layers keep the full
    always-refuse walk.
    """
    if constructor_arg is not None:
        return constructor_arg, "constructor"
    env_value = env.get("ALFRED_SECRETS_FILE")
    if env_value:
        return Path(env_value), "env"
    if settings_default is not None:
        return settings_default, "settings_default"
    return None, None


def _walk_for_git_parent(path: Path, max_depth: int = _GIT_WALK_MAX_DEPTH) -> Path | None:
    """Return the first ancestor of ``path`` containing a ``.git`` marker, or None.

    ``.git`` is matched by EXISTENCE, not directory-ness (#383): a git secondary
    worktree or submodule has a ``.git`` *file* (a ``gitdir:`` pointer), not a
    directory, and a secret dropped inside one is just as committable — so the
    accidental-commit refusal must catch it too. ``git check-ignore`` (the #366
    gitignore-aware narrowing) resolves worktrees natively, so the layer-3
    narrowing composes correctly here.

    The bound on ``max_depth`` defends against pathological symlink loops.
    Stops at the filesystem root. Iterative (not recursive) for clarity.
    """
    current = path.parent
    for _ in range(max_depth):
        if (current / ".git").exists():
            return current
        parent = current.parent
        if parent == current:
            # Hit filesystem root.
            return None
        current = parent
    return None


_GIT_CHECK_IGNORE_TIMEOUT_S: Final[float] = 5.0


def _secret_is_gitignored(repo: Path, secrets_path: Path) -> bool:
    """Return True iff ``secrets_path`` is git-ignored within ``repo`` (#366).

    Authoritative: shells out to ``git check-ignore`` (honours nested
    ``.gitignore``, ``.git/info/exclude``, ``core.excludesFile``). A hand-rolled
    ``.gitignore`` parser is deliberately NOT used — a false "ignored" verdict
    would let a committable secret boot (a security hole). Fail-closed: returns
    False (→ the caller REFUSES) if git is absent, errors, or times out.

    No ``shell=True`` (args as a list — no injection); ``--`` guards a path that
    starts with ``-``; git chatter is captured (``capture_output``), never
    echoed; ``timeout``-bounded so a hung git cannot hang boot. Exit 0 = ignored;
    1 = not ignored; 128 = fatal (not a repo, etc.) → treated as not-ignored.
    """
    try:
        # ruff S603/S607: fixed-literal git argv, no shell, no untrusted input —
        # ``repo`` + ``secrets_path`` are operator-config paths (not T3 content),
        # ``--`` guards a leading-dash path, and PATH-resolved ``git`` is the
        # standard invocation (its absolute path is platform-variable). The
        # suppression is scoped inline (NOT a per-file ignore) so a future
        # subprocess in this security-critical module is still flagged.
        result = subprocess.run(  # noqa: S603
            ["git", "-C", str(repo), "check-ignore", "--quiet", "--", str(secrets_path)],  # noqa: S607
            capture_output=True,
            timeout=_GIT_CHECK_IGNORE_TIMEOUT_S,
            check=False,
        )
    except subprocess.TimeoutExpired:
        # Fail-closed, but LOUD (CLAUDE.md hard rule #7): a silent False here would
        # surface as the generic "gitignore/move it" refusal with no hint git
        # itself hung — misdirecting an operator who DID gitignore the secret.
        _log.warning("secrets.gitignore_check_failed", reason="timeout", repo=str(repo))
        return False
    except OSError as exc:
        # git binary absent (FileNotFoundError) or another I/O failure invoking it.
        _log.warning(
            "secrets.gitignore_check_failed",
            reason="git_unavailable",
            detail=exc.strerror or type(exc).__name__,
            repo=str(repo),
        )
        return False
    if result.returncode == 0:
        return True
    if result.returncode != 1:
        # exit 128 (fatal — not a repo, bad object, …) is distinct from a clean
        # exit-1 "not ignored"; the latter is the normal refuse (the caller's
        # refusal message covers it), so only the anomalous exit is logged.
        _log.warning(
            "secrets.gitignore_check_failed",
            reason="git_error",
            returncode=result.returncode,
            repo=str(repo),
        )
    return False


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
        self._secrets_file_path: Path | None
        self._secrets_path_layer: _SecretsLayer
        self._secrets_file_path, self._secrets_path_layer = _resolve_secrets_path(
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
                is_layer3 = self._secrets_path_layer == "settings_default"
                if is_layer3 and _secret_is_gitignored(git_parent, self._secrets_file_path):
                    # #366: the layer-3 canonical XDG default whose secret is
                    # AUTHORITATIVELY gitignored — safe from accidental
                    # ``git add -A``. Proceed, but WARN (defence-in-depth): a
                    # future ``git add -f`` or a ``.gitignore`` edit could still
                    # commit it. Only the settings-default layer reaches this
                    # branch; kwarg / ALFRED_SECRETS_FILE keep the full
                    # always-refuse walk (the operator explicitly named the path,
                    # where a repo-clone drop is the real threat). Fail-closed: a
                    # non-ignored secret, or git absent/error/timeout, falls to
                    # the refusal below (``_secret_is_gitignored`` returns False).
                    _log.warning(
                        "secrets.file_in_git_repo_but_ignored",
                        path=str(self._secrets_file_path),
                        parent=str(git_parent),
                        residual_risk=(
                            "gitignored now; a `git add -f` or a .gitignore edit "
                            "could still commit it"
                        ),
                    )
                else:
                    # Branch the message by layer so each literal msgid is
                    # extracted (pybabel takes the FIRST arg of ``t()`` as a
                    # literal): the layer-3 refusal names the gitignore remedy
                    # this narrowing enables; the kwarg / ALFRED_SECRETS_FILE
                    # refusal does NOT (gitignoring an explicitly-named path does
                    # not help — the operator chose that location).
                    if is_layer3:
                        message = t(
                            "secrets.file_in_git_repo_layer3",
                            path=str(self._secrets_file_path),
                            parent=str(git_parent),
                        )
                    else:
                        message = t(
                            "secrets.file_in_git_repo",
                            path=str(self._secrets_file_path),
                            parent=str(git_parent),
                        )
                    raise SecretBrokerPermissionsError(
                        message,
                        path=self._secrets_file_path,
                        mode=0,
                        parent=git_parent,
                    )

        # #370 item 1: convert the two raw exceptions the validate/load step can
        # still leak — malformed TOML and an escaping OSError — into typed
        # SecretBrokerConfigError subtypes at this boundary, so the #368 boot/CLI
        # handlers catch them via the base and refuse fail-closed instead of a
        # raw traceback. The already-typed SecretBrokerConfigError leaves raised
        # by _validate_secrets_file_security are neither TOMLDecodeError nor
        # OSError, so they propagate untouched.
        try:
            _validate_secrets_file_security(self._secrets_file_path)
            self._file_secrets = _load_toml_file(self._secrets_file_path)
        except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
            # UnicodeDecodeError: ``tomllib.load`` decodes the file as UTF-8
            # before parsing, so a corrupt / binary / wrong-encoding secrets
            # file raises UnicodeDecodeError (a ValueError, NOT a TOMLDecodeError
            # and NOT an OSError) — invalid encoding is malformed content, so it
            # maps to the same "fix the file" remediation.
            #
            # Defense-in-depth (secret broker, hard rule #1): do NOT echo
            # str(exc) from a secrets-file PARSE failure into the operator
            # message. The redactor is not built at a construction failure, so
            # any echoed detail would be UN-redacted. tomllib's message is
            # empirically content-free today (a fixed vocabulary + integer
            # line/column, never a `doc` slice) and UnicodeDecodeError echoes the
            # raw offending byte, but structured position attrs are not portable
            # pre-3.14, so we refuse to render free-form exception text from the
            # secrets file at all. `from exc` preserves the cause for a developer
            # debugger; tracebacks print only str(), not the parser's `doc`.
            raise SecretBrokerMalformedError(
                t("secrets.file_malformed", path=str(self._secrets_file_path)),
                path=self._secrets_file_path,
            ) from exc
        except OSError as exc:
            # Echo only the OS-provided ``strerror`` (a fixed errno description
            # such as "Permission denied" — never file content or the path),
            # not str(exc) (which appends the filename). Same redactor-inactive
            # reasoning as above.
            raise SecretBrokerUnreadableError(
                t(
                    "secrets.file_unreadable",
                    path=str(self._secrets_file_path),
                    reason=exc.strerror or type(exc).__name__,
                ),
                path=self._secrets_file_path,
            ) from exc

    @classmethod
    def from_settings(cls, config: SecretBrokerConfig) -> SecretBroker:
        """Build a broker primed from a config object (#351 DIP narrowing).

        Reads ``config.secrets_file`` (ADR-0012 layer-3 host default) and passes it as the
        ``settings_default`` layer. The constructor override + ``ALFRED_SECRETS_FILE`` env var
        still take precedence. Narrowed to :class:`SecretBrokerConfig` rather than the full
        ``Settings`` — a plain stub exposing only ``secrets_file`` satisfies this seam.
        """
        return cls(settings_default=config.secrets_file)

    @property
    def secrets_file_path(self) -> Path | None:
        """The resolved secrets-file path, or ``None`` for the env-only backend.

        Read-only view of the layer the constructor resolved (constructor arg →
        ``ALFRED_SECRETS_FILE`` → the ``Settings`` host default). ``None`` only
        when all three layers are unset. Exposed so ``alfred status`` can report
        WHERE the broker looks for file-backed secrets (#370 item 3) — this is a
        filesystem path, never a secret value. It reflects the resolved path even
        when the file does not exist (a default daemon resolves the
        ``~/.config/alfred/secrets.toml`` XDG default and falls back to env-only
        if it is absent).
        """
        return self._secrets_file_path

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

    def substitute(self, text: str, *, allowed_secrets: frozenset[str]) -> str:
        """Replace every ``{{secret:<name>}}`` placeholder in ``text`` with the real
        secret value.

        ``<name>`` MUST match ``[a-z0-9_.]+``, be in ``allowed_secrets`` (the caller's
        closed, context-specific allowlist), AND resolve via :meth:`get` (i.e. be in
        ``SUPPORTED_SECRETS`` and provisioned). A ``text`` with no placeholder is
        returned byte-for-byte unchanged.

        This method resolves placeholders ONLY. It assumes ``text`` is already
        DLP-clean of RAW secret values (ADR-0017: DLP scans the placeholder frame
        BEFORE substitution) and does not itself detect raw secrets.

        Raises:
            SecretSubstitutionNotAllowed: ``<name>`` is malformed or off-allowlist
                (confused-deputy defence; never a broker passthrough of an
                attacker-named secret).
            UnknownSecretError: ``<name>`` is allowlisted but not a known/provisioned
                secret (delegated from :meth:`get`).
        """
        # perf-001: the overwhelming majority of calls carry no placeholder at
        # all (e.g. every clean header value) — skip the regex substitution
        # entirely rather than running ``re.sub`` over text with nothing to
        # replace. ``"{{secret:"`` is the fixed literal prefix every valid (or
        # malformed) placeholder starts with, so this is a safe, byte-for-byte
        # early return, not a heuristic that could miss a real placeholder.
        if "{{secret:" not in text:
            return text

        def _replace(match: re.Match[str]) -> str:
            ref = match.group(1)
            if not _VALID_SECRET_NAME.match(ref) or ref not in allowed_secrets:
                raise SecretSubstitutionNotAllowed(ref)
            return self.get(ref)

        return _SECRET_PLACEHOLDER.sub(_replace, text)

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
            except FileNotFoundError:
                # TOCTOU: file disappeared between exists() and lstat() —
                # treat as missing rather than propagating the race.
                #
                # CR-142 round-3 sec-003: the pragma was removed in
                # favour of deterministic fault injection. The branch
                # is exercised by
                # ``test_reload_toctou_filenotfound_fails_closed_to_empty``
                # which monkey-patches ``_validate_secrets_file_security``
                # to raise after the ``exists()`` probe — proving the
                # fail-closed semantics (empty mapping + cache version
                # bump) hold even when the filesystem races with us.
                # PR #99 added the TOCTOU guard; CR-142 round-3 added
                # the corresponding adversarial coverage so the spec
                # §11a 100% trust-boundary gate is met on substance,
                # not via a pragma.
                self._file_secrets = MappingProxyType({})
            except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
                # Mirror __init__'s typed load boundary on the reload seam
                # (#370, CR #379): a runtime reload of a now-malformed / non-UTF-8
                # file fails LOUD with the same typed subtype instead of a raw
                # traceback. The assignment never completed, so ``_file_secrets``
                # keeps its last-good value and the redactor cache is NOT bumped
                # (the ``_bump_redactor_version()`` below is skipped by the
                # raise) — fail-closed to the prior secrets. FileNotFoundError is
                # handled above (TOCTOU-as-missing); it is an OSError subclass so
                # its arm MUST precede the generic ``except OSError`` below. No
                # str(exc) echoed (see __init__ raise-site comments).
                raise SecretBrokerMalformedError(
                    t("secrets.file_malformed", path=str(self._secrets_file_path)),
                    path=self._secrets_file_path,
                ) from exc
            except OSError as exc:
                raise SecretBrokerUnreadableError(
                    t(
                        "secrets.file_unreadable",
                        path=str(self._secrets_file_path),
                        reason=exc.strerror or type(exc).__name__,
                    ),
                    path=self._secrets_file_path,
                ) from exc
        self._bump_redactor_version()
