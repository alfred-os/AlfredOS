"""Coverage + invariant guard for the fail-closed bootstrap gate.

PR-S3-7 Task 12 deleted ``DevGate`` from ``src/`` and replaced the
:func:`alfred.hooks.registry.get_registry` lazy-fallback with a private
``_DenyAllGate``. The fallback used to fail OPEN (the Slice-2.5
``DevGate`` granted unconditionally); after the flag-day removal it
fails CLOSED — every check denies.

The class is private (a leading underscore), production code never
imports it, and the only legitimate construction path is the
lazy-fallback inside :func:`get_registry` when bootstrap hasn't yet
installed a :class:`RealGate`. These tests pin the fail-closed
semantics at 100% line+branch coverage so a future refactor that
accidentally re-introduces a fail-open default in this code path is
caught at the cheapest possible level.

CLAUDE.md hard rule #7: silent failures in security paths are
release-blockers. ``_DenyAllGate`` is the loud-failure equivalent for
the bootstrap-not-yet-run code path — deny, never authorize.
"""

from __future__ import annotations

from alfred.hooks.registry import _DenyAllGate


def test_deny_all_gate_check_denies_unconditionally() -> None:
    """:meth:`_DenyAllGate.check` returns ``False`` for any args.

    The bootstrap-fallback gate must NEVER authorise a tier-gated
    capability. Returning ``True`` here would silently authorise a
    dispatch before the production :class:`RealGate` is installed —
    a fail-open regression that this test pins against.
    """
    gate = _DenyAllGate()

    assert (
        gate.check(
            plugin_id="any.plugin",
            hookpoint="any.hookpoint",
            requested_tier="T0",
        )
        is False
    )
    assert (
        gate.check(
            plugin_id="other.plugin",
            hookpoint="other.hookpoint",
            requested_tier="T3",
        )
        is False
    )


def test_deny_all_gate_check_plugin_load_denies_unconditionally() -> None:
    """:meth:`_DenyAllGate.check_plugin_load` denies every plugin.

    Plugin-load denial is structurally identical to dispatch denial:
    no manifest tier authorises a load until a real gate is installed.
    """
    gate = _DenyAllGate()

    assert gate.check_plugin_load(plugin_id="any.plugin", manifest_tier="T0") is False
    assert gate.check_plugin_load(plugin_id="other.plugin", manifest_tier="T3") is False


def test_deny_all_gate_check_content_clearance_denies_unconditionally() -> None:
    """:meth:`_DenyAllGate.check_content_clearance` denies every read.

    Content-tier clearance is the third capability check the gate
    Protocol expects. The fail-closed default must apply here too —
    quarantined T3 content never reaches a subscriber via the
    bootstrap-fallback gate.
    """
    gate = _DenyAllGate()

    assert (
        gate.check_content_clearance(
            plugin_id="any.plugin",
            hookpoint="any.hookpoint",
            content_tier="T0",
        )
        is False
    )
    assert (
        gate.check_content_clearance(
            plugin_id="other.plugin",
            hookpoint="other.hookpoint",
            content_tier="T3",
        )
        is False
    )


def test_deny_all_gate_is_frozen_slots_dataclass() -> None:
    """:class:`_DenyAllGate` is ``@dataclass(frozen=True, slots=True)``.

    Frozen + slots is the immutability contract: no instance state, no
    setattr, no per-instance dict. A future refactor that adds mutable
    state to the bootstrap-fallback gate would be a security smell —
    the gate's only job is to deny; it has no business holding state.
    """
    gate = _DenyAllGate()

    # slots=True: instance has no __dict__.
    assert not hasattr(gate, "__dict__")
    # frozen=True: __setattr__ raises.
    import dataclasses

    assert dataclasses.is_dataclass(gate)
    # CR-156 round-5: the prior pin (is_dataclass + zero fields) would
    # still pass if a future refactor dropped ``frozen=True`` while
    # keeping ``slots=True``. Assert frozen + slots directly so the
    # immutability contract is the thing under test, not a downstream
    # symptom of it.
    assert type(gate).__dataclass_params__.frozen is True
    assert hasattr(type(gate), "__slots__")
    fields = dataclasses.fields(gate)
    assert fields == ()  # zero state — pure denial.
