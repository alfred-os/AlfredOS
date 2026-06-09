"""Task 48 — comms hookpoint registrations (PR-S4-8, #152).

Two hookpoints register here:

* ``comms.inbound.t3_promoted`` — ``carrier_tier=T3``, ``fail_closed=True``,
  ``allow_error_substitution=False``. Quarantined (T3) subscribers are refused:
  the subscribable tiers are the system + operator vocab tokens only
  (``"system"`` / ``"operator"`` — the T0/T1 equivalents), never ``"user-plugin"``.
* ``comms.adapter.crashed`` — ``carrier_tier=T0``, ``fail_closed=True``.

Reality note: the registry's ``carrier_tier`` is the :class:`TrustTier` *class*
(``T3`` / ``T0``), not a string, and subscribable tiers use the
``"system"``/``"operator"``/``"user-plugin"`` vocabulary, not ``"T0"``/``"T1"``.
The plan's pseudocode used string tiers; this test pins the REAL API.
"""

from __future__ import annotations

from alfred.comms_mcp.hookpoints import declare_hookpoints
from alfred.hooks import get_registry
from alfred.hooks.registry import HookRegistry
from alfred.security.tiers import T0, T3
from tests.helpers.gates import make_permissive_fixture_gate


def _registry() -> HookRegistry:
    return HookRegistry(gate=make_permissive_fixture_gate(), strict_declarations=False)


def test_t3_promoted_hookpoint_carrier_tier_t3() -> None:
    registry = _registry()
    declare_hookpoints(registry)
    meta = registry.hookpoint_meta("comms.inbound.t3_promoted")
    assert meta is not None
    assert meta.carrier_tier is T3
    assert meta.fail_closed is True
    assert meta.allow_error_substitution is False
    # Quarantined subscribers (user-plugin tier) refused; system + operator only.
    assert meta.subscribable_tiers == frozenset({"system", "operator"})
    assert "user-plugin" not in meta.subscribable_tiers


def test_crashed_hookpoint_carrier_tier_t0() -> None:
    registry = _registry()
    declare_hookpoints(registry)
    meta = registry.hookpoint_meta("comms.adapter.crashed")
    assert meta is not None
    assert meta.carrier_tier is T0
    assert meta.fail_closed is True


def test_declare_hookpoints_is_idempotent() -> None:
    registry = _registry()
    declare_hookpoints(registry)
    # A second identical declaration must not raise (re-import / reload safety).
    declare_hookpoints(registry)


def test_declare_hookpoints_defaults_to_process_singleton() -> None:
    # Calling with no registry targets the process singleton.
    declare_hookpoints()
    meta = get_registry().hookpoint_meta("comms.inbound.t3_promoted")
    assert meta is not None
