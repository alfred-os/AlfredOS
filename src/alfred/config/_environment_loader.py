"""Three-layer resolver for ``Settings.environment`` (#469 Blocker 1, ADR-0053).

The single canonical precedence chain, top-down:

1. ``ALFRED_ENVIRONMENT`` env var (highest).
2. ``/etc/alfred/environment`` file (middle; trimmed).
3. ``.env`` file, parsed via ``python-dotenv``'s ``dotenv_values`` with
   ``interpolate=False`` — chosen to eliminate a ``$VAR`` injection vector, not
   because it mirrors pydantic's own ``.env`` handling (lowest; gap-fill only).

**Short-circuit on a typo'd higher source [D3].** The highest source that is SET
decides. If that source's value is not in the Literal triple
(``development``/``production``/``test``), the resolver returns ``UNRECOGNISED``
(echoing the typo) and does **not** silently fall through to a valid lower source —
this prevents a downgrade-via-typo, e.g. a root typo in ``/etc`` letting a
``.env=development`` win instead. A source that is unset (absent or blank/whitespace)
is skipped, not a short-circuit.

**Fail-closed on an unreadable ``/etc`` [err-01].** A present-but-unreadable
``/etc/alfred/environment`` (``PermissionError``/``IsADirectoryError``/``OSError``)
returns ``EnvironmentSource.UNREADABLE`` immediately — it never falls through to
``.env``. Only a genuinely *absent* file (``FileNotFoundError``) is skipped.

**``.env`` read failures are treated as absent [err-02/err-03].** ``PermissionError``,
``OSError``, ``IsADirectoryError``, ``FileNotFoundError`` and ``UnicodeDecodeError`` on
the ``.env`` read are all caught and treated as "this source is unset" — a
mode-misconfigured or malformed ``.env`` must never crash boot with a raw, un-audited
traceback (CLAUDE.md hard rule 7). ``.env`` can never participate in a two-source
``conflict`` — it is the lowest, gap-fill-only layer; ``conflict`` is computed solely
against the validated ``/etc`` value.

``consult_dotenv=False`` lets a caller (the launcher, per [D1]) opt out of the
``.env`` layer entirely rather than treat it as absent-but-consulted — this is what
makes an escape-hatch gate fail-closed against a CWD ``.env`` trying to unlock a
permissive mode.

This module is isolated so ``Settings.__init__`` can call it without pulling in the
audit/typer/cli graph at module-load time (perf-001 discipline from Slice-3). It
performs FILE-ONLY ops — no Postgres, no network — so the model validator stays cheap
and deterministic.
"""

from __future__ import annotations

import enum
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from dotenv import dotenv_values

_VALID_VALUES: Final[frozenset[str]] = frozenset({"development", "production", "test"})
_DEFAULT_ETC_PATH: Final[Path] = Path("/etc/alfred/environment")
# CWD-relative — matches pydantic-settings' `env_file` default resolution.
_DEFAULT_DOTENV_PATH: Final[Path] = Path(".env")


class EnvironmentSource(enum.Enum):
    """Which source produced the final value (or why there is none)."""

    ENV_VAR = "env_var"
    ETC_FILE = "etc_file"
    DOTENV = "dotenv"
    NONE = "none"
    UNRECOGNISED = "unrecognised"
    UNREADABLE = "unreadable"


@dataclass(frozen=True, slots=True)
class EnvironmentLoadResult:
    """Outcome of the three-layer environment lookup.

    Attributes:
        value: The resolved environment value, or ``None`` if no source
            supplied a recognised value. Always one of the Literal triple
            when not ``None``.
        source: Which source produced ``value`` (or, for the no-value
            cases, why there is none — ``NONE``, ``UNRECOGNISED``, or
            ``UNREADABLE``).
        conflict: ``True`` iff the env var AND ``/etc`` are both set and
            disagree. ``.env`` can never participate in a conflict — it is
            the lowest, gap-fill-only layer.
        conflicting_file_value: When ``conflict`` is ``True``, the
            validated ``/etc`` value (the env-var value is in ``value``).
        unrecognised_value: When ``source`` is ``UNRECOGNISED``, the raw
            string that failed Literal validation. Carried so the
            caller's refusal message can echo what the operator typed.
    """

    value: str | None
    source: EnvironmentSource
    conflict: bool = False
    conflicting_file_value: str | None = None
    unrecognised_value: str | None = None


def _norm(raw: str | None) -> str | None:
    """Normalize a raw source value: strip, then blank/whitespace-only -> ``None``.

    core-plan-01: an empty or whitespace-only value must be SKIPPED like an unset
    source, never returned as ``UNRECOGNISED("")`` — applied identically at all three
    read sites so precedence never depends on which layer happened to be blank.
    """
    return (raw.strip() or None) if raw is not None else None


@dataclass(frozen=True, slots=True)
class _EtcRead:
    """Internal: the normalized /etc value, plus whether the read failed closed."""

    value: str | None
    unreadable: bool


def _read_etc(etc_path: Path) -> _EtcRead:
    """Read + normalize the ``/etc`` source, distinguishing absent from unreadable.

    A genuinely absent file (``FileNotFoundError``) is skipped like any unset source.
    A *present* file this process cannot read (``PermissionError``/
    ``IsADirectoryError``/generic ``OSError``) fails closed [err-01] — the caller must
    never silently fall through to ``.env`` on a mode-misconfigured ``/etc``.
    """
    try:
        return _EtcRead(_norm(etc_path.read_text(encoding="utf-8")), unreadable=False)
    except FileNotFoundError:
        return _EtcRead(None, unreadable=False)
    except (PermissionError, IsADirectoryError, OSError):
        return _EtcRead(None, unreadable=True)


def _read_dotenv(dotenv_path: Path) -> str | None:
    """Read + normalize the ``.env`` source. Any read failure is treated as absent.

    ``interpolate=False`` eliminates a ``$VAR`` injection vector (ADR-0053) — it is
    not chosen to mirror pydantic's own ``.env`` parsing, which defaults to
    ``interpolate=True``.
    """
    try:
        values = dotenv_values(dotenv_path, interpolate=False)
    except (FileNotFoundError, PermissionError, IsADirectoryError, OSError, UnicodeDecodeError):
        return None
    return _norm(values.get("ALFRED_ENVIRONMENT"))


def resolve_environment(
    *,
    etc_path: Path | None = None,
    dotenv_path: Path | None = None,
    consult_dotenv: bool = True,
) -> EnvironmentLoadResult:
    """Resolve ``Settings.environment`` via env-var > /etc file > .env precedence.

    Args:
        etc_path: Override for the ``/etc`` source. Tests pass a ``tmp_path`` so the
            suite never touches ``/etc/alfred/environment`` on a developer machine.
            ``None`` (the default) reads the module-level ``_DEFAULT_ETC_PATH`` AT
            CALL TIME so a test that monkeypatches that module attribute takes effect
            (a bound parameter default would freeze the value at import time).
        dotenv_path: Override for the ``.env`` source, resolved AT CALL TIME the same
            way as ``etc_path``. ``None`` reads the module-level
            ``_DEFAULT_DOTENV_PATH`` (CWD-relative, matching pydantic-settings'
            ``env_file`` default).
        consult_dotenv: When ``False``, the ``.env`` layer is skipped entirely rather
            than read-and-found-absent — the launcher path [D1] uses this so a CWD
            ``.env`` can never unlock a fail-closed escape-hatch gate.

    Returns:
        :class:`EnvironmentLoadResult` describing the resolved value, the source that
        produced it, and any env-var/``/etc`` conflict the caller must audit.
    """
    if etc_path is None:
        etc_path = _DEFAULT_ETC_PATH
    if dotenv_path is None:
        dotenv_path = _DEFAULT_DOTENV_PATH

    # CR #7: normalize every source identically — strip + blank-skip — so a
    # whitespace-only difference between sources never registers as a spurious
    # source conflict or a spurious UNRECOGNISED.
    env_raw = _norm(os.environ.get("ALFRED_ENVIRONMENT"))
    etc = _read_etc(etc_path)
    if etc.unreadable:
        # err-01: a present-but-unreadable /etc fails closed. Never fall through to
        # a lower source — a mode-misconfigured /etc must not silently downgrade.
        return EnvironmentLoadResult(value=None, source=EnvironmentSource.UNREADABLE)
    dotenv_raw = _read_dotenv(dotenv_path) if consult_dotenv else None

    for raw, source in (
        (env_raw, EnvironmentSource.ENV_VAR),
        (etc.value, EnvironmentSource.ETC_FILE),
        (dotenv_raw, EnvironmentSource.DOTENV),
    ):
        if raw is None:
            continue
        if raw not in _VALID_VALUES:
            # [D3]: the highest SET source decides. A typo here short-circuits —
            # it does not silently fall through to a valid lower source.
            return EnvironmentLoadResult(
                value=None,
                source=EnvironmentSource.UNRECOGNISED,
                unrecognised_value=raw,
            )
        # Conflict is scoped to the env-var-vs-/etc pair, computed on the
        # VALIDATED /etc value — .env is the lowest, gap-fill-only layer and can
        # never participate in a conflict.
        conflict = (
            source is EnvironmentSource.ENV_VAR and etc.value is not None and etc.value != raw
        )
        return EnvironmentLoadResult(
            value=raw,
            source=source,
            conflict=conflict,
            conflicting_file_value=etc.value if conflict else None,
        )

    return EnvironmentLoadResult(value=None, source=EnvironmentSource.NONE)
