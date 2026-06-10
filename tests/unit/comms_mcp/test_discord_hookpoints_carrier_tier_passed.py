"""AST guard: Discord hookpoint registrations pass the required kwargs (A3, #206).

PR-S4-3 (ADR-0022) makes ``carrier_tier=`` a required-by-AST-guard kwarg on every
``register_hookpoint`` call. This test mirrors that contract for the two PR-S4-9
Discord hookpoints: it parses ``discord_hookpoints.py``, finds every
``register_hookpoint(...)`` call, and asserts each carries ``carrier_tier=`` AND
``subscribable_tiers=`` AND ``fail_closed=``, with the exact values spec'd.

The functional registration is also exercised (declaring against a fresh registry
and reading back the stored metadata) so a refactor that silently drops a kwarg
fails both the static and the dynamic check.
"""

from __future__ import annotations

import ast
from pathlib import Path

from alfred.comms_mcp.discord_hookpoints import declare_hookpoints
from alfred.hooks.registry import SYSTEM_OPERATOR_TIERS, HookRegistry, _DenyAllGate
from alfred.security.tiers import T0, T3

_SRC = (
    Path(__file__).resolve().parents[3] / "src" / "alfred" / "comms_mcp" / "discord_hookpoints.py"
)

_BINDING = "comms.adapter.binding_requested"
_RATE_LIMIT = "comms.adapter.rate_limit_signal"


def _module_str_constants(tree: ast.Module) -> dict[str, str]:
    """Module-level ``NAME = "literal"`` assignments (the hookpoint-name consts)."""
    table: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
            if (
                isinstance(target, ast.Name)
                and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)
            ):
                table[target.id] = node.value.value
    return table


_TREE = ast.parse(_SRC.read_text(encoding="utf-8"))
_CONSTS = _module_str_constants(_TREE)


def _register_calls() -> list[ast.Call]:
    calls: list[ast.Call] = []
    for node in ast.walk(_TREE):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "register_hookpoint"
        ):
            calls.append(node)
    return calls


def _kwarg(call: ast.Call, name: str) -> ast.expr:
    for kw in call.keywords:
        if kw.arg == name:
            return kw.value
    raise AssertionError(f"register_hookpoint call missing {name}= kwarg")


def _const_name(value: ast.expr) -> str:
    if isinstance(value, ast.Constant) and isinstance(value.value, str):
        return value.value
    if isinstance(value, ast.Name) and value.id in _CONSTS:
        return _CONSTS[value.id]
    raise AssertionError(f"expected a string constant or known const, got {ast.dump(value)}")


def test_two_register_calls_present() -> None:
    calls = _register_calls()
    names = {_const_name(_kwarg(c, "name")) for c in calls}
    assert names == {_BINDING, _RATE_LIMIT}


def test_every_call_passes_required_kwargs() -> None:
    for call in _register_calls():
        for required in ("carrier_tier", "subscribable_tiers", "fail_closed"):
            _kwarg(call, required)  # raises if absent


def _call_for(name: str) -> ast.Call:
    for call in _register_calls():
        if _const_name(_kwarg(call, "name")) == name:
            return call
    raise AssertionError(f"no register_hookpoint call for {name!r}")


def test_binding_requested_kwargs() -> None:
    call = _call_for(_BINDING)
    assert isinstance(_kwarg(call, "carrier_tier"), ast.Name)
    assert _kwarg(call, "carrier_tier").id == "T3"  # type: ignore[attr-defined]
    assert _kwarg(call, "subscribable_tiers").id == "SYSTEM_OPERATOR_TIERS"  # type: ignore[attr-defined]
    fail_closed = _kwarg(call, "fail_closed")
    assert isinstance(fail_closed, ast.Constant) and fail_closed.value is False


def test_rate_limit_signal_kwargs() -> None:
    call = _call_for(_RATE_LIMIT)
    assert _kwarg(call, "carrier_tier").id == "T0"  # type: ignore[attr-defined]
    assert _kwarg(call, "subscribable_tiers").id == "SYSTEM_OPERATOR_TIERS"  # type: ignore[attr-defined]
    fail_closed = _kwarg(call, "fail_closed")
    assert isinstance(fail_closed, ast.Constant) and fail_closed.value is False


def test_functional_registration_stores_expected_metadata() -> None:
    registry = HookRegistry(gate=_DenyAllGate())
    declare_hookpoints(registry)

    binding = registry._hookpoints[_BINDING]
    assert binding.carrier_tier is T3
    assert binding.subscribable_tiers == SYSTEM_OPERATOR_TIERS
    assert binding.fail_closed is False

    rate_limit = registry._hookpoints[_RATE_LIMIT]
    assert rate_limit.carrier_tier is T0
    assert rate_limit.subscribable_tiers == SYSTEM_OPERATOR_TIERS
    assert rate_limit.fail_closed is False
