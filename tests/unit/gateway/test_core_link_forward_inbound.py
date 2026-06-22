"""``GatewayCoreLink.forward_adapter_inbound`` — the leg-payload forward carrier (G6-7-3).

FORK-B: a hosted adapter child's ``inbound.message`` body is forwarded to the core by
wrapping it (BYTE-FOR-BYTE) in a :class:`GatewayAdapterInboundEnvelope`, serializing the
WHOLE envelope to leg-payload bytes, and routing it through the LegRouter the link holds.
The forward never inspects the body; the envelope ``adapter_id`` is the SPAWN-BINDING id
passed by the caller (SEC-309-1), never read from the body. Leg-full / global-cap errors
SURFACE to the caller (the disposition owns back-pressure) — they are NOT swallowed here.

SEC-309-2 byte-stability is asserted at the LEG-PAYLOAD layer: the serialized payload's
``body`` member is byte-identical to the source body and survives a ReplayBuffer round-trip
so ``reparse_forwarded_inbound`` reconstructs an EQUAL ``InboundMessageNotification``.
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime

import pytest

from alfred.comms_mcp.inbound_reparse import reparse_forwarded_inbound
from alfred.comms_mcp.protocol import (
    GATEWAY_ADAPTER_INBOUND,
    GatewayAdapterInboundEnvelope,
    InboundMessageNotification,
)
from alfred.gateway.core_link import ForwardLegUnavailableError, GatewayCoreLink
from alfred.gateway.gateway_leg import GatewayLeg
from alfred.gateway.global_replay_cap import GlobalReplayCap
from alfred.gateway.ingress_gate import PerAdapterIngressGate
from alfred.gateway.leg_router import LegRouter, RouteOutcome
from alfred.gateway.leg_scheduler import GatewayLegScheduler, LegQueueFullError
from alfred.gateway.replay_buffer import ReplayBuffer, ReplayBufferError

pytestmark = pytest.mark.asyncio


class _RecordingClientListener:
    transport = None

    async def accept(self) -> None:
        return None

    async def aclose(self) -> None:
        return None


class _RecordingLegRouter:
    """A LegRouter stand-in recording every (adapter_id, payload) route.

    ``raise_on_route`` lets a test drive the leg-full / global-cap surface so the
    forward's error-propagation contract (FORK-B: surface, never swallow) is pinned.
    """

    def __init__(self, *, raise_on_route: BaseException | None = None) -> None:
        self.routes: list[tuple[str, bytes]] = []
        self._raise = raise_on_route

    def route(self, adapter_id: str, payload: bytes) -> RouteOutcome:
        if self._raise is not None:
            raise self._raise
        self.routes.append((adapter_id, payload))
        return RouteOutcome.ROUTED


def _link() -> GatewayCoreLink:
    return GatewayCoreLink(client_listener=_RecordingClientListener())  # type: ignore[arg-type]


class _RecordingCoreLink:
    """A minimal core-link the scheduler can be constructed over (no drain is run)."""

    def __init__(self) -> None:
        self._gate = asyncio.Event()
        self._gate.set()

    def core_cumulative_ack(self) -> int:
        return 0

    @property
    def replay_pending_gate(self) -> asyncio.Event:
        return self._gate

    async def escalate_if_breaker_tripped(self, leg: GatewayLeg) -> None:
        return None

    async def write_leg_unit(self, adapter_id: str, payload: bytes, *, seq: int, ack: int) -> None:
        return None


def _forward_leg(adapter_id: str, cap: GlobalReplayCap) -> GatewayLeg:
    return GatewayLeg(
        adapter_id=adapter_id,
        buffer=ReplayBuffer(max_frames=1000, max_bytes=1_000_000, ttl_seconds=30.0),
        ingress_gate=PerAdapterIngressGate(
            adapter_id,
            sustained_rate_per_s=1000.0,
            burst=1000,
            max_inflight=1000,
            ttl_seconds=30.0,
            max_frame_bytes=1_000_000,
            now=lambda: 0.0,
        ),
        global_cap=cap,
        now=lambda: 0.0,
    )


def _inbound_body(*, adapter_id: str = "discord", inbound_id: str = "frame-1") -> str:
    notification = InboundMessageNotification(
        adapter_id=adapter_id,  # type: ignore[arg-type]
        inbound_id=inbound_id,
        platform_user_id="discord:42",
        body={"content": "hello"},
        sub_payload_refs=(),
        received_at=datetime(2026, 6, 10, tzinfo=UTC),
        addressing_signal="dm",
    )
    return notification.model_dump_json()


async def test_forward_builds_envelope_from_spawn_binding_routes_to_leg() -> None:
    router = _RecordingLegRouter()
    link = _link()
    link.set_leg_router(router)  # type: ignore[arg-type]
    body = _inbound_body()

    await link.forward_adapter_inbound("discord", body)

    assert len(router.routes) == 1
    routed_adapter, routed_payload = router.routes[0]
    assert routed_adapter == "discord"
    # The leg payload is the serialized WHOLE envelope (method + adapter_id + body).
    # The serialize keeps the str body VERBATIM — assert on the raw JSON, where the body
    # member is the source string byte-for-byte (the re-parsed model coerces the bytes|str
    # union to bytes, so compare the encoded body content, not the model field type).
    parsed = json.loads(routed_payload)
    assert parsed["adapter_id"] == "discord"
    assert parsed["body"] == body  # str body kept verbatim through serialize
    # The re-parsed envelope's body is byte-identical to the source body.
    envelope = GatewayAdapterInboundEnvelope.model_validate_json(routed_payload)
    assert envelope.adapter_id == "discord"
    envelope_body = envelope.body.encode() if isinstance(envelope.body, str) else envelope.body
    assert envelope_body == body.encode()


async def test_forward_uses_binding_id_not_body_id() -> None:
    # SEC-309-1: a MISMATCHED body adapter_id must NOT override the spawn-binding id.
    router = _RecordingLegRouter()
    link = _link()
    link.set_leg_router(router)  # type: ignore[arg-type]
    body = _inbound_body(adapter_id="tui")  # body claims a DIFFERENT adapter

    await link.forward_adapter_inbound("discord", body)  # spawn binding = discord

    _routed_adapter, routed_payload = router.routes[0]
    envelope = GatewayAdapterInboundEnvelope.model_validate_json(routed_payload)
    # The envelope carries the BINDING value, never the body's claimed id.
    assert envelope.adapter_id == "discord"


async def test_forward_byte_stable_through_replay_buffer_roundtrip() -> None:
    # SEC-309-2 at the LEG-PAYLOAD layer: serialize -> ReplayBuffer store -> replay -> parse
    # -> the body is unchanged AND reparse reconstructs an EQUAL notification.
    router = _RecordingLegRouter()
    link = _link()
    link.set_leg_router(router)  # type: ignore[arg-type]
    body = _inbound_body()
    await link.forward_adapter_inbound("discord", body)
    _adapter, payload = router.routes[0]

    buffer = ReplayBuffer()
    buffer.append(seq=0, payload=payload, now=0.0)
    replayed = buffer.unacked_frames()
    assert len(replayed) == 1
    assert replayed[0].payload == payload  # byte-identical through the buffer

    envelope = GatewayAdapterInboundEnvelope.model_validate_json(replayed[0].payload)
    reconstructed = reparse_forwarded_inbound(envelope)
    expected = InboundMessageNotification.model_validate_json(body)
    assert reconstructed == expected


async def test_forward_surfaces_leg_queue_full_to_caller() -> None:
    router = _RecordingLegRouter(raise_on_route=LegQueueFullError("full"))
    link = _link()
    link.set_leg_router(router)  # type: ignore[arg-type]
    with pytest.raises(LegQueueFullError):
        await link.forward_adapter_inbound("discord", _inbound_body())


async def test_forward_surfaces_replay_buffer_error_to_caller() -> None:
    router = _RecordingLegRouter(raise_on_route=ReplayBufferError("cap"))
    link = _link()
    link.set_leg_router(router)  # type: ignore[arg-type]
    with pytest.raises(ReplayBufferError):
        await link.forward_adapter_inbound("discord", _inbound_body())


class _RefusingLegRouter:
    """A LegRouter stand-in that REFUSES every route (the unknown/gone-leg outcome).

    ``route`` RETURNS (never raises) :data:`RouteOutcome.REFUSED_UNKNOWN_ADAPTER` — the K4
    contract — so the forward must INSPECT the outcome and raise (FOLD-1 / ERR-309-1).
    """

    def __init__(self) -> None:
        self.routes: list[tuple[str, bytes]] = []

    def route(self, adapter_id: str, payload: bytes) -> RouteOutcome:
        self.routes.append((adapter_id, payload))
        return RouteOutcome.REFUSED_UNKNOWN_ADAPTER


async def test_forward_raises_leg_unavailable_when_router_refuses() -> None:
    # FOLD-1 (ERR-309-1): the router RETURNS REFUSED_UNKNOWN_ADAPTER (it does not raise) when
    # the adapter_id names no registered leg. The forward MUST inspect that outcome and raise
    # ForwardLegUnavailableError — never DISCARD it (discarding it would let the disposition
    # falsely log forward_accepted on a LOST frame, hard rule #7 silent-loss).
    router = _RefusingLegRouter()
    link = _link()
    link.set_leg_router(router)  # type: ignore[arg-type]
    with pytest.raises(ForwardLegUnavailableError):
        await link.forward_adapter_inbound("discord", _inbound_body())


async def test_forward_raises_leg_unavailable_against_deregistered_leg() -> None:
    # FOLD-1 reachable path: a REAL LegRouter over a REAL scheduler whose leg was registered
    # then DEREGISTERED (the scheduler's isolation arm tears a leg down). The router now refuses
    # the (gone) leg's adapter_id -> the forward raises ForwardLegUnavailableError.
    scheduler = GatewayLegScheduler(_RecordingCoreLink(), max_per_leg_queue_bytes=1_000_000)  # type: ignore[arg-type]
    cap = GlobalReplayCap(max_total_bytes=10_000_000)
    scheduler.register_leg(_forward_leg("discord", cap))
    scheduler.deregister_leg("discord")  # the isolation arm tore the leg down
    assert "discord" not in scheduler.registered_adapters
    link = _link()
    link.set_leg_router(LegRouter(scheduler))
    with pytest.raises(ForwardLegUnavailableError):
        await link.forward_adapter_inbound("discord", _inbound_body())


async def test_forward_requires_a_wired_leg_router() -> None:
    link = _link()  # no set_leg_router
    with pytest.raises(AssertionError):
        await link.forward_adapter_inbound("discord", _inbound_body())


async def test_forward_method_constant_is_gateway_adapter_inbound() -> None:
    # The envelope's wire method is the shared constant the core's _route_notification keys on.
    assert GATEWAY_ADAPTER_INBOUND == "gateway.adapter.inbound"
