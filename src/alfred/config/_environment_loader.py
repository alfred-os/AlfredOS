"""Dual-source loader for ``Settings.environment`` (#174 PR-S4-1).

Spec §7.3 — ``Settings.environment`` is mandatory and dual-sourced with
deterministic precedence:

1. ``ALFRED_ENVIRONMENT`` env var (primary; wins on conflict).
2. ``/etc/alfred/environment`` file (fallback; trimmed).
3. Disagreement emits ``daemon.boot.environment_source_conflict``
   (caller's responsibility — this loader returns the ``conflict`` flag).
4. Neither set → caller refuses to boot with
   ``failure_reason="environment_not_set"``.

This module is isolated so ``Settings.__init__`` can call it without
pulling in the audit/typer/cli graph at module-load time (perf-001
discipline from Slice-3). It performs FILE-ONLY ops — no Postgres, no
network — so the model validator stays cheap and deterministic.
"""

from __future__ import annotations

import enum
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Final

_VALID_VALUES: Final[frozenset[str]] = frozenset({"development", "production", "test"})
_DEFAULT_ETC_PATH: Final[Path] = Path("/etc/alfred/environment")


class EnvironmentSource(enum.Enum):
    """Which source produced the final value (or why there is none)."""

    ENV_VAR = "env_var"
    ETC_FILE = "etc_file"
    NONE = "none"
    UNRECOGNISED = "unrecognised"


@dataclass(frozen=True, slots=True)
class EnvironmentLoadResult:
    """Outcome of the dual-source environment lookup.

    Attributes:
        value: The resolved environment value, or ``None`` if neither
            source supplied a recognised value. Always one of the
            Literal triple when not ``None``.
        source: Which source produced ``value``.
        conflict: ``True`` iff both sources are set AND disagree.
        conflicting_file_value: When ``conflict`` is ``True``, the value
            the file held (the env-var value is in ``value``).
        unrecognised_value: When ``source`` is ``UNRECOGNISED``, the raw
            string that failed Literal validation. Carried so the
            caller's refusal message can echo what the operator typed.
    """

    value: str | None
    source: EnvironmentSource
    conflict: bool = False
    conflicting_file_value: str | None = None
    unrecognised_value: str | None = None


def load_environment(*, etc_path: Path = _DEFAULT_ETC_PATH) -> EnvironmentLoadResult:
    """Resolve ``Settings.environment`` via env-var > /etc file precedence.

    Args:
        etc_path: Override for the file source. Tests pass a ``tmp_path``
            so the suite never touches ``/etc/alfred/environment`` on a
            developer machine. Production callers pass the default.

    Returns:
        :class:`EnvironmentLoadResult` describing the resolved value, the
        source that produced it, and any conflict the daemon must audit.
    """
    env_raw = os.environ.get("ALFRED_ENVIRONMENT")
    file_raw: str | None = None
    try:
        file_raw = etc_path.read_text(encoding="utf-8").strip()
    except (FileNotFoundError, PermissionError, IsADirectoryError):
        # Either the file is absent (developer machine) or unreadable
        # (mode-misconfigured /etc — operator concern). The caller's
        # refusal path handles "neither source set"; we just return.
        file_raw = None
    except OSError:
        # Any other filesystem error: treat as unreadable. Loud failure
        # is the caller's job; the loader stays narrow.
        file_raw = None

    # Validate each candidate against the Literal triple.
    env_value = env_raw if env_raw in _VALID_VALUES else None
    file_value = file_raw if file_raw in _VALID_VALUES else None

    if env_value is not None:
        conflict = file_value is not None and file_value != env_value
        return EnvironmentLoadResult(
            value=env_value,
            source=EnvironmentSource.ENV_VAR,
            conflict=conflict,
            conflicting_file_value=file_value if conflict else None,
        )
    if file_value is not None:
        return EnvironmentLoadResult(
            value=file_value,
            source=EnvironmentSource.ETC_FILE,
        )
    # Neither resolved. Distinguish "totally missing" from "set but
    # unrecognised" so the refusal message can echo what the operator
    # typed in the latter case.
    if env_raw is not None and env_raw not in _VALID_VALUES:
        return EnvironmentLoadResult(
            value=None,
            source=EnvironmentSource.UNRECOGNISED,
            unrecognised_value=env_raw,
        )
    if file_raw is not None and file_raw not in _VALID_VALUES:
        return EnvironmentLoadResult(
            value=None,
            source=EnvironmentSource.UNRECOGNISED,
            unrecognised_value=file_raw,
        )
    return EnvironmentLoadResult(value=None, source=EnvironmentSource.NONE)
