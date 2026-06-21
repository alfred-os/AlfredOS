"""G6-5 Task 6 (#288): the gateway builds a BINDING ingress leg per hosted adapter.

Before G6-5 the gateway had ONE leg — the non-binding TUI dial-in (unbounded tokens /
in-flight / frame size so the interactive path is never throttled). G6-5 hosts a real
Discord adapter, so each spawned ``adapter_id`` gets its OWN ``GatewayLeg`` with a
BINDING ``PerAdapterIngressGate`` (finite rate / burst / in-flight / max-frame-bytes,
L1: explicit module-level ``Final`` constants — the Discord manifest carries no rate
fields; manifest-sourced caps are a deferred follow-up). The TUI leg keeps its
non-binding config, and the K4 forged-``adapter_id`` refusal still holds for the
multi-leg router.
"""

from __future__ import annotations

import asyncio

from alfred.gateway.client_listener import GatewayClientListener
from alfred.gateway.core_link import GatewayCoreLink
from alfred.gateway.ingress_gate import IngressDecision
from alfred.gateway.leg_router import LegRouter, RouteOutcome
from alfred.gateway.process import (
    _ADAPTER_LEG_BURST,
    _ADAPTER_LEG_MAX_FRAME_BYTES,
    _ADAPTER_LEG_MAX_INFLIGHT,
    _NON_BINDING_COUNT,
    _NON_BINDING_MAX_FRAME_BYTES,
    GatewayProcess,
    build_adapter_leg,
    build_tui_leg,
    wire_leg_scheduler,
)


def _make_core_link() -> GatewayCoreLink:
    return GatewayCoreLink(client_listener=GatewayClientListener())


def test_adapter_leg_has_a_binding_ingress_gate() -> None:
    """A Discord leg's ingress gate enforces finite rate / in-flight / size (L1).

    The binding caps are STRICTLY below the TUI non-binding sentinels, so a frame above
    ``_ADAPTER_LEG_MAX_FRAME_BYTES`` is OVERSIZED and the in-flight cap is exhaustible —
    neither of which can happen on the non-binding TUI gate.
    """
    leg = build_adapter_leg("discord")

    # The binding caps are genuinely below the non-binding sentinels.
    assert _ADAPTER_LEG_MAX_FRAME_BYTES < _NON_BINDING_MAX_FRAME_BYTES
    assert _ADAPTER_LEG_MAX_INFLIGHT < _NON_BINDING_COUNT
    assert _ADAPTER_LEG_BURST < _NON_BINDING_COUNT

    # A frame above the binding size cap is refused OVERSIZED.
    oversized = leg.try_admit(frame_bytes=_ADAPTER_LEG_MAX_FRAME_BYTES + 1)
    assert oversized.decision is IngressDecision.OVERSIZED

    # The volumetric caps are finite + exhaustible: draining the bucket / filling the
    # in-flight cap eventually refuses with a THROTTLE (rate or in-flight) — neither of
    # which the non-binding TUI gate (1e9 tokens / in-flight) can ever hit. We admit well
    # past both finite caps and assert a refusal lands.
    decisions = [
        leg.try_admit(frame_bytes=1).decision
        for _ in range(_ADAPTER_LEG_BURST + _ADAPTER_LEG_MAX_INFLIGHT + 1)
    ]
    assert IngressDecision.ADMITTED in decisions  # a fresh leg may burst
    throttles = {IngressDecision.THROTTLED_RATE, IngressDecision.THROTTLED_INFLIGHT}
    assert throttles & set(decisions)  # a finite cap refused (binding, unlike the TUI gate)


def test_tui_leg_remains_non_binding() -> None:
    """The TUI leg is UNCHANGED — its gate admits an adapter-oversized frame fine."""
    tui = build_tui_leg()
    # A frame far larger than the adapter binding cap still admits on the TUI gate.
    result = tui.try_admit(frame_bytes=_ADAPTER_LEG_MAX_FRAME_BYTES + 1)
    assert result.decision is IngressDecision.ADMITTED


def test_process_registers_a_binding_leg_per_adapter_id() -> None:
    """The process builds + registers one binding leg per configured ``adapter_id``.

    The scheduler ends up holding the TUI leg AND the Discord leg, so a frame routed to
    ``discord`` enqueues, and the K4 forged-id refusal still holds for the multi-leg
    router.
    """
    process = GatewayProcess(shutdown_event=asyncio.Event(), adapter_ids=["discord"])
    core_link = _make_core_link()
    tui_leg = build_tui_leg()
    scheduler = wire_leg_scheduler(core_link, tui_leg)
    process._register_adapter_legs(scheduler)

    assert scheduler.registered_adapters == frozenset({"tui", "discord"})

    router = LegRouter(scheduler)
    # A registered adapter routes.
    assert router.route("discord", b"opaque") is RouteOutcome.ROUTED
    # K4: a forged/unknown adapter id is REFUSED, never default-routed (multi-leg).
    assert router.route("not-a-leg", b"forged") is RouteOutcome.REFUSED_UNKNOWN_ADAPTER


def test_both_legs_reaped_on_scheduler_close() -> None:
    """Every registered leg (TUI + adapter) is torn down on the scheduler ``aclose`` reap."""
    process = GatewayProcess(shutdown_event=asyncio.Event(), adapter_ids=["discord"])
    core_link = _make_core_link()
    tui_leg = build_tui_leg()
    scheduler = wire_leg_scheduler(core_link, tui_leg)
    process._register_adapter_legs(scheduler)

    assert scheduler.registered_adapters == frozenset({"tui", "discord"})
    scheduler.aclose()
    # Both legs torn down — the scheduler holds nothing.
    assert scheduler.registered_adapters == frozenset()


def test_empty_adapter_set_registers_only_the_tui_leg() -> None:
    """No configured adapters -> only the TUI leg (behaviour-preserving for G5)."""
    process = GatewayProcess(shutdown_event=asyncio.Event())
    core_link = _make_core_link()
    tui_leg = build_tui_leg()
    scheduler = wire_leg_scheduler(core_link, tui_leg)
    process._register_adapter_legs(scheduler)

    assert scheduler.registered_adapters == frozenset({"tui"})
