"""AST guard — every register_hookpoint(...) call site MUST pass carrier_tier=.

PR-S4-3 Component B (rev-009 closure). Walks ``src/alfred/`` and
``plugins/`` at test time, collects every call expression whose
``func.attr == "register_hookpoint"`` or ``func.id == "register_hookpoint"``,
and refuses any call missing the ``carrier_tier`` keyword.

Lints downstream PR hookpoint registrations during ``make check`` so a
missing ``carrier_tier`` surfaces at PR-author time, not at runtime
first-import time. PR-S4-3 ships this guard as the *static* leg of
the contract; the *runtime* leg lives in
``HookRegistry.register_hookpoint`` (Component A). Both layers ship
in this PR.

Per rev-009 round-3 closure, this gate is what makes PR-S4-3 the
ancestor of every other hookpoint-registering PR: downstream PRs that
register a new hookpoint without ``carrier_tier=`` fail this test and
must update the call site before merging.
"""

from __future__ import annotations

import ast
from collections.abc import Iterator
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
SCAN_DIRS = (REPO_ROOT / "src" / "alfred", REPO_ROOT / "plugins")


def _iter_python_files() -> Iterator[Path]:
    for root in SCAN_DIRS:
        if not root.exists():
            continue
        yield from root.rglob("*.py")


def _find_register_hookpoint_calls(tree: ast.AST) -> list[ast.Call]:
    """Walk ``tree`` and yield every ``register_hookpoint(...)`` call.

    Matches both attribute-style (``registry.register_hookpoint(...)``)
    and free-function-style (``register_hookpoint(...)``) — the
    registry module itself uses the latter via re-export. Definition
    sites (the actual ``def register_hookpoint(...):`` in the
    registry module) are NOT calls and never match here.
    """
    out: list[ast.Call] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if (isinstance(func, ast.Attribute) and func.attr == "register_hookpoint") or (
            isinstance(func, ast.Name) and func.id == "register_hookpoint"
        ):
            out.append(node)
    return out


def _is_passing_carrier_tier(call: ast.Call) -> bool:
    """Return True iff ``call`` passes ``carrier_tier=`` (kw OR **expansion)."""
    for kw in call.keywords:
        if kw.arg == "carrier_tier":
            return True
        if kw.arg is None:
            # ``**kwargs`` expansion — assume it carries carrier_tier.
            # Concrete kwargs-passing sites are rare in this codebase
            # (a tuple-driven loop in supervisor/core.py uses positional
            # passing) and the runtime register_hookpoint signature
            # gate catches a missing carrier_tier value at register
            # time regardless. The AST guard is a static convenience —
            # it ELEVATES the runtime gate to PR-author time for the
            # common direct-kwarg shape; ``**kwargs`` is permitted as
            # the runtime escape valve.
            return True
    return False


def test_every_register_hookpoint_call_passes_carrier_tier() -> None:
    """Every ``register_hookpoint(...)`` call passes ``carrier_tier=``.

    Failure surface lists the offending ``file:line`` pairs so the
    PR-author sees exactly which call sites need migration. Empty
    list → guard satisfied. Non-empty → AssertionError with the
    list of offending sites.
    """
    offenders: list[str] = []
    for path in _iter_python_files():
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except SyntaxError:
            # A file in src/ that the test runner cannot parse is a
            # bigger problem than this guard. Skip rather than mask
            # the real failure here; the broader ``make check`` lint
            # gate surfaces it.
            continue
        for call in _find_register_hookpoint_calls(tree):
            if not _is_passing_carrier_tier(call):
                rel = path.relative_to(REPO_ROOT)
                offenders.append(f"{rel}:{call.lineno}")
    assert not offenders, (
        "register_hookpoint(...) calls missing carrier_tier=:\n"
        + "\n".join(f"  - {o}" for o in offenders)
        + "\n\nPR-S4-3 (#170) requires every hookpoint declaration to "
        "set carrier_tier= explicitly. Set it to the appropriate "
        "TrustTier subclass (T0 for system-internal, T1 for operator, "
        "T2/T3 for ingestion paths)."
    )
