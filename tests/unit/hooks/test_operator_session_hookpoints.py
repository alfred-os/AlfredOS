"""``operator.session.{created,revoked,refused}`` hookpoint registration (Task 20).

Spec §10: each is ``subscribable_tiers=SYSTEM_ONLY_TIERS``,
``fail_closed=True``, ``carrier_tier=T1`` (operator-attributable). The
registration is driven by ``operator_session.declare_hookpoints`` at
module import (mirroring ``alfred.cli.daemon``), so the manifest
sync-test reaches it by importing the subsystem.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from alfred.hooks import SYSTEM_ONLY_TIERS, get_registry
from alfred.identity.operator_session import declare_hookpoints
from alfred.security.tiers import T1

_NAMES = (
    "operator.session.created",
    "operator.session.revoked",
    "operator.session.refused",
)


@pytest.fixture(autouse=True)
def _declared() -> None:
    declare_hookpoints(get_registry())


@pytest.mark.parametrize("name", _NAMES)
def test_hookpoint_registered_with_t1_carrier(name: str) -> None:
    meta = get_registry()._hookpoints[name]
    assert meta.subscribable_tiers == SYSTEM_ONLY_TIERS
    assert meta.fail_closed is True
    assert meta.carrier_tier is T1


def test_declare_hookpoints_is_idempotent() -> None:
    # A second declaration with identical metadata must not raise.
    declare_hookpoints(get_registry())
    for name in _NAMES:
        assert name in get_registry()._hookpoints


def test_declare_hookpoints_rejects_wrong_typed_registry() -> None:
    """A non-HookRegistry, non-None arg is a caller bug -> TypeError."""
    with pytest.raises(TypeError, match="HookRegistry or None"):
        declare_hookpoints(registry="not-a-registry")  # type: ignore[arg-type]


def test_every_register_hookpoint_call_passes_carrier_tier() -> None:
    """PR-S4-3 AST guard parity: no register_hookpoint omits carrier_tier=."""
    src = Path("src/alfred/identity/operator_session.py").read_text()
    tree = ast.parse(src)
    offenders: list[int] = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "register_hookpoint"
        ):
            kwargs = {kw.arg for kw in node.keywords}
            if "carrier_tier" not in kwargs:
                offenders.append(node.lineno)
    assert not offenders, f"register_hookpoint without carrier_tier= at lines {offenders}"
