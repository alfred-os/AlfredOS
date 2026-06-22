"""End-to-end forward through the PRODUCTION assembly path (Spec B G6-7-3, #309).

The "component-complete != runtime-wired" guard. A forwarded inbound MUST reach the
per-adapter leg as a ``gateway.adapter.inbound`` unit THROUGH the production wiring —
the ``adapter_runner_factory`` the gateway process builds + the supervised pump that
drives ``runner.pump()`` — not just via an isolated runner. The core-side receive is
G6-7-4 (no collaborators yet), so the forwarded frame LANDS as a leg unit and STOPS.

This drives the REAL ``GatewayProcess`` factory closure + a fake adapter child whose
stdout scripts one ``inbound.message``, and asserts the frame reached the leg via the
core link's ``forward_adapter_inbound`` (the production forward target).
"""

from __future__ import annotations

import asyncio

import pytest

from alfred.comms_mcp.protocol import GatewayAdapterInboundEnvelope
from alfred.gateway.client_listener import GatewayClientListener
from alfred.gateway.core_link import GatewayCoreLink
from alfred.gateway.process import GatewayProcess, wire_leg_scheduler

pytestmark = pytest.mark.asyncio

_ADAPTER_ID = "discord"

_HANDSHAKE_OK = {"jsonrpc": "2.0", "id": 0, "result": {"ok": True, "plugin_version": "0.1.0"}}


class _FakeChildTransport:
    """A transport scripting a child's stdout: a handshake ack then one inbound frame."""

    def __init__(self, inbound: list[object]) -> None:
        self._inbound = inbound
        self.sent: list[object] = []
        self.spawned = False
        self.closed = False

    async def spawn(self) -> None:
        self.spawned = True

    async def send(self, frame: object) -> None:
        self.sent.append(frame)

    async def read_frame(self) -> object | None:
        if not self._inbound:
            return None
        return self._inbound.pop(0)

    async def close(self) -> None:
        self.closed = True

    def enable_seq_ack(self) -> None:
        return None


def _inbound_params() -> dict[str, object]:
    return {
        "adapter_id": _ADAPTER_ID,
        "inbound_id": "frame-assembly-1",
        "platform_user_id": "discord:42",
        "body": {"content": "hello from the wire"},
        "sub_payload_refs": [],
        "received_at": "2026-06-10T00:00:00+00:00",
        "addressing_signal": "dm",
    }


async def test_forward_runner_factory_lands_inbound_as_leg_unit() -> None:
    # Build the PRODUCTION wiring: a core link, the scheduler/router, the discord leg,
    # and the gateway's REAL forward-runner factory (the closure that binds
    # forward=core_link.forward_adapter_inbound + the per-adapter back-pressure gate).
    process = GatewayProcess(shutdown_event=asyncio.Event(), adapter_ids=[_ADAPTER_ID])
    core_link = GatewayCoreLink(client_listener=GatewayClientListener())
    tui_leg = process._build_tui_leg()
    scheduler = wire_leg_scheduler(core_link, tui_leg)
    process._register_adapter_legs(scheduler)

    factory = process._build_adapter_runner_factory(core_link, scheduler)

    transport = _FakeChildTransport(
        [
            dict(_HANDSHAKE_OK),
            {"jsonrpc": "2.0", "method": "inbound.message", "params": _inbound_params()},
        ]
    )
    runner = factory(transport=transport, adapter_id=_ADAPTER_ID)

    # Drive the production runner lifetime: handshake (no gate — session-less) then pump
    # (the supervised steady state). The pump dispatches the inbound via the forward
    # disposition -> core_link.forward_adapter_inbound -> the LegRouter -> the discord leg.
    await runner.start_and_handshake()
    await runner.pump()

    # The frame LANDED on the discord leg's scheduler queue (it STOPS there — G6-7-4 owns
    # the core-side receive/dispatch). Drain one frame off the leg to observe it.
    await scheduler._drain_one_round()
    # The leg's buffer now holds the forwarded envelope; assert via the un-acked frame.
    leg = scheduler.leg(_ADAPTER_ID)
    frames = leg.unacked_frames()  # tuple[(seq, payload), ...]
    assert len(frames) == 1
    _seq, payload = frames[0]
    envelope = GatewayAdapterInboundEnvelope.model_validate_json(payload)
    assert envelope.adapter_id == _ADAPTER_ID
    # Byte-stable: the envelope body re-parses to the forwarded inbound params.
    import json

    body = envelope.body.decode() if isinstance(envelope.body, bytes) else envelope.body
    assert json.loads(body) == _inbound_params()


async def test_forward_runner_factory_registers_back_pressure_gate() -> None:
    # The factory MUST register the per-adapter gate with the scheduler, else a full leg
    # could not resume the reader (the back-pressure loop would be one-directional).
    process = GatewayProcess(shutdown_event=asyncio.Event(), adapter_ids=[_ADAPTER_ID])
    core_link = GatewayCoreLink(client_listener=GatewayClientListener())
    tui_leg = process._build_tui_leg()
    scheduler = wire_leg_scheduler(core_link, tui_leg)
    process._register_adapter_legs(scheduler)

    factory = process._build_adapter_runner_factory(core_link, scheduler)
    transport = _FakeChildTransport([dict(_HANDSHAKE_OK)])
    factory(transport=transport, adapter_id=_ADAPTER_ID)

    # Assert the gate THE FACTORY registered is present + non-None (do NOT overwrite it —
    # overwriting would let this test pass even if the factory stopped registering its own
    # gate). The scheduler exposes no public read accessor, so read the registry directly:
    # the entry exists iff the factory wired the per-adapter back-pressure gate, so the
    # test FAILS the moment the factory stops registering it.
    registered_gate = scheduler._back_pressure_gates.get(_ADAPTER_ID)
    assert registered_gate is not None
    assert isinstance(registered_gate, asyncio.Event)


async def test_default_process_uses_real_forward_factory_not_unwired() -> None:
    # A process configured with adapter_ids but NO injected runner factory must build the
    # REAL forward factory at run-wiring time (NOT keep the fail-loud _unwired default) —
    # the production-unwired trap guard.
    process = GatewayProcess(shutdown_event=asyncio.Event(), adapter_ids=[_ADAPTER_ID])
    core_link = GatewayCoreLink(client_listener=GatewayClientListener())
    tui_leg = process._build_tui_leg()
    scheduler = wire_leg_scheduler(core_link, tui_leg)
    process._register_adapter_legs(scheduler)
    supervisor = process._build_adapter_supervisor(core_link, scheduler)
    # The supervisor's child factory holds the REAL forward runner factory (not unwired):
    # constructing a runner over a fake transport returns a forward runner, never raising
    # the GatewayAdapterSpawnError the unwired default raises.
    runner = supervisor._factory._runner_factory(  # type: ignore[attr-defined]
        transport=_FakeChildTransport([]), adapter_id=_ADAPTER_ID
    )
    assert hasattr(runner, "pump")
    assert hasattr(runner, "start_and_handshake")
