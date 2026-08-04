"""Import-time CPython floor guard (#568, ADR-0061).

`pyproject.toml` declares a SERIES-level `requires-python = ">=3.14"` because
Dependabot cannot resolve a patch-level specifier — a `>=3.14.6` floor there
silently killed dependency-graph submission, Dependabot security updates and the
weekly pip updater for 44 days. The declared floor and the enforced floor
therefore diverge on purpose, and this module is where the real one lives.

i18n EXEMPTION (CLAUDE.md i18n rule #1). This message is deliberately NOT routed
through `t()`. The commonly-cited justification — that calling `t()` here would
be circular — is FALSE and was refuted by execution: `alfred.i18n` is
stdlib-only and imports no `alfred` module. The real reasons:

  * `t()` silently DROPS kwargs when the msgid is missing, so an absent or
    uncompiled catalog renders a bare key with NO version numbers — and for a
    floor guard the versions are the entire payload.
  * `import alfred.i18n` costs a measured 29.7 ms on EVERY `import alfred.*`
    and lands inside the ADR-0030-bounded quarantine-child import closure.

The LAST line of the message is a bare closed-vocabulary key rather than prose:
`bin/alfred-plugin-launcher.sh` captures only the final stderr line and writes
its classification into the signed `supervisor.plugin.sandbox_refused` audit
row. Prose there is recorded as `reason_unclassified`.
"""

from __future__ import annotations

import sys
from typing import Final

from alfred.errors import AlfredError

#: The ENFORCED floor. gh-105936 breaks `@dataclass(frozen=True, slots=True)`
#: `__setattr__` on 3.14.0-3.14.4 (measured on 3.14.0 and 3.14.4; fixed in 3.14.5
#: by CPython GH-144021 via GH-148469 — `_frozen_get_del_attr` ->
#: `_frozen_set_del_attr`, `cls` -> `__class__`). Long-standing, NOT a 3.14
#: regression. Held
#: at 3.14.6 rather than the true 3.14.5 boundary because 3.14.6 is
#: `.python-version` and the only patch any CI lane exercises — supported ==
#: tested, with no untested band.
FLOOR: Final[tuple[int, int, int]] = (3, 14, 6)

#: Closed-vocabulary key; twin of the `interpreter_below_floor` member of
#: `SANDBOX_REFUSED_REASONS` in `alfred.audit.audit_row_schemas`.
REFUSAL_KEY: Final[str] = "daemon.boot.interpreter_below_floor"

_DECLARED_SPECIFIER: Final[str] = ">=3.14"


class UnsupportedPythonError(AlfredError, RuntimeError):
    """The running interpreter is below the enforced AlfredOS floor."""


def enforce(version: tuple[int, int, int]) -> None:
    """Refuse ``version`` when it is below :data:`FLOOR`.

    Pure by design: takes the version rather than reading ``sys.version_info``,
    so the refusal path is executable in a test. The call site is covered
    separately — a pure function nothing calls is not a guard.
    """
    if version >= FLOOR:
        return
    required = ".".join(str(part) for part in FLOOR)
    found = ".".join(str(part) for part in version)
    raise UnsupportedPythonError(
        f"AlfredOS requires CPython >= {required} — this interpreter is {found} "
        f"({sys.executable}).\n"
        f"\n"
        f"Why: CPython 3.14.0-3.14.4 generate a broken __setattr__ for\n"
        f"@dataclass(frozen=True, slots=True) (gh-105936) — an unknown-attribute\n"
        f"assignment raises TypeError instead of FrozenInstanceError. AlfredOS has\n"
        f"36+ such frozen types, including trust-boundary types, so the failure is\n"
        f"silent rather than loud. Fixed upstream in 3.14.5; the floor is held at\n"
        f"{required} because that is the only patch CI exercises.\n"
        f"\n"
        f"Not caught at install time on purpose: pyproject.toml declares\n"
        f'"{_DECLARED_SPECIFIER}" (series-level) because Dependabot cannot parse a\n'
        f"patch-level requires-python and silently stops submitting the dependency\n"
        f"graph and opening security PRs (#568).\n"
        f"\n"
        f"Fix: uv python install && uv sync\n"
        f"{REFUSAL_KEY}"
    )


def enforce_implementation(implementation: str) -> None:
    """Refuse any Python implementation other than CPython.

    Pure by design, same rationale as :func:`enforce`: takes the implementation
    name rather than reading ``sys.implementation.name`` directly, so the
    refusal path is executable in a test. The call site is covered separately
    — a pure function nothing calls is not a guard.

    gh-105936 (see :data:`FLOOR`'s docstring) is a CPython-specific
    ``dataclasses`` code-generation defect. ``enforce()`` alone only compares
    version tuples, so an interpreter that satisfies :data:`FLOOR` but is not
    CPython — PyPy, for example — would pass it while never having the defect
    this module exists to guard against, and would be silently treated as
    covered. This function is the other half of the claim :func:`enforce`'s
    message makes ("AlfredOS requires CPython >= ...").

    Reuses :data:`REFUSAL_KEY` rather than minting a second closed-vocabulary
    key: from the launcher's and the audit row's point of view, "wrong
    interpreter" and "right interpreter, wrong version" are the same refusal
    class with the same operator remedy (install a supported CPython), so a
    second reserved reason would add a vocabulary entry — and a matching
    launcher case arm — for a distinction the audit trail has no use for.
    """
    if implementation == "cpython":
        return
    raise UnsupportedPythonError(
        f"AlfredOS requires CPython — this interpreter is {implementation} "
        f"({sys.executable}).\n"
        f"\n"
        f"Why: gh-105936, the defect this module's version floor exists to guard\n"
        f"against, is a CPython dataclasses code-generation bug. It says nothing\n"
        f"about {implementation}, so an interpreter that happens to satisfy the\n"
        f"version floor would be silently treated as covered when it is not.\n"
        f"\n"
        f"Fix: run AlfredOS under CPython.\n"
        f"{REFUSAL_KEY}"
    )
