"""Task 48 — comms hookpoint registrations (PR-S4-8, #152, spec §10).

Two hookpoints register here, with the spec §10 table posture (the single
source of truth — they DIVERGE in tier-set and fail-closed):

* ``comms.inbound.t3_promoted`` — ``carrier_tier=T3``, ``fail_closed=True``,
  ``allow_error_substitution=False``. The T3 carrier narrows subscription to the
  **system tier only** (``{"system"}``) — neither operators nor untrusted
  ``user-plugin`` subscribers may observe a T3-carrying promotion event.
* ``comms.adapter.crashed`` — ``carrier_tier=T0``, ``fail_closed=False`` (an
  observation-only crash event must not fail-close the originating action),
  subscribable by system + operator only (NOT ``user-plugin`` — an untrusted
  plugin must not observe crashes).

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
    # Spec §10: T3 carrier -> system tier ONLY. Operators AND quarantined
    # (user-plugin) subscribers are both refused.
    assert meta.subscribable_tiers == frozenset({"system"})
    assert "operator" not in meta.subscribable_tiers
    assert "user-plugin" not in meta.subscribable_tiers


def test_crashed_hookpoint_carrier_tier_t0() -> None:
    registry = _registry()
    declare_hookpoints(registry)
    meta = registry.hookpoint_meta("comms.adapter.crashed")
    assert meta is not None
    assert meta.carrier_tier is T0
    # Spec §10: observation-only crash event -> fail_closed=False, system +
    # operator only (an untrusted user-plugin must NOT observe crashes).
    assert meta.fail_closed is False
    assert meta.subscribable_tiers == frozenset({"system", "operator"})
    assert "user-plugin" not in meta.subscribable_tiers


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
