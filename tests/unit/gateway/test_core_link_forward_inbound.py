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

import json
from datetime import UTC, datetime

import pytest

from alfred.comms_mcp.inbound_reparse import reparse_forwarded_inbound
from alfred.comms_mcp.protocol import (
    GATEWAY_ADAPTER_INBOUND,
    GatewayAdapterInboundEnvelope,
    InboundMessageNotification,
)
from alfred.gateway.core_link import GatewayCoreLink
from alfred.gateway.leg_router import RouteOutcome
from alfred.gateway.leg_scheduler import LegQueueFullError
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


async def test_forward_requires_a_wired_leg_router() -> None:
    link = _link()  # no set_leg_router
    with pytest.raises(AssertionError):
        await link.forward_adapter_inbound("discord", _inbound_body())


async def test_forward_method_constant_is_gateway_adapter_inbound() -> None:
    # The envelope's wire method is the shared constant the core's _route_notification keys on.
    assert GATEWAY_ADAPTER_INBOUND == "gateway.adapter.inbound"
