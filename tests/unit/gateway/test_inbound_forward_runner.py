"""``GatewayForwardDisposition`` + ``GatewayInboundForwardRunner`` (Spec B G6-7-3, #309).

The session-LESS gateway forward path. The disposition (§3.1 four-notification table)
routes a hosted adapter child's ``inbound.message`` to ``core_link.forward_adapter_inbound``
(BYTE-FOR-BYTE, opaque) and LOUD-AUDITED-drops every other child notification (no core route
exists for them; blind-forwarding ``binding_request`` would be an audit-write DoS amplifier).
The runner is a thin session-less ``CommsPluginRunner`` construction with the forward
disposition + an optional back-pressure gate.

Security must-fix coverage:
* SEC-309-1 spawn-binding-origin: the forwarded adapter_id is the CONSTRUCTION value, even
  when the body carries a MISMATCHED / garbage / absent id.
* Payload-blindness: the disposition never ``json.loads`` / inspects the body — it serializes
  the already-parsed ``params`` blob and forwards it.
* The unknown-method loud-audited drop is an explicit row.
* The disposition NEVER raises (fire-and-forget contract), even on a forward fault.
"""

from __future__ import annotations

import asyncio
import json

import pytest
import structlog

from alfred.gateway.inbound_forward_runner import (
    GatewayForwardDisposition,
    GatewayInboundForwardRunner,
)
from alfred.gateway.leg_scheduler import LegQueueFullError
from alfred.gateway.replay_buffer import ReplayBufferError

pytestmark = pytest.mark.asyncio

_ADAPTER_ID = "discord"


class _RecordingForward:
    """Records every (adapter_id, body) forward; optionally raises to drive back-pressure."""

    def __init__(self, *, raise_on_forward: BaseException | None = None) -> None:
        self.forwards: list[tuple[str, str]] = []
        self._raise = raise_on_forward

    async def __call__(self, adapter_id: str, body: str) -> None:
        if self._raise is not None:
            raise self._raise
        self.forwards.append((adapter_id, body))


def _inbound_params(*, adapter_id: str = _ADAPTER_ID) -> dict[str, object]:
    return {
        "adapter_id": adapter_id,
        "inbound_id": "frame-1",
        "platform_user_id": "discord:42",
        "body": {"content": "hello"},
        "sub_payload_refs": [],
        "received_at": "2026-06-10T00:00:00+00:00",
        "addressing_signal": "dm",
    }


def _disposition(
    forward: _RecordingForward, *, gate: asyncio.Event | None = None
) -> GatewayForwardDisposition:
    return GatewayForwardDisposition(
        adapter_id=_ADAPTER_ID, forward=forward, back_pressure_gate=gate
    )


# ---------------------------------------------------------------------------
# §3.1 four-notification table
# ---------------------------------------------------------------------------


async def test_inbound_message_forwards_serialized_params() -> None:
    forward = _RecordingForward()
    disposition = _disposition(forward)
    params = _inbound_params()

    await disposition.dispatch("inbound.message", params)

    assert len(forward.forwards) == 1
    adapter_id, body = forward.forwards[0]
    assert adapter_id == _ADAPTER_ID
    # The body is the serialized already-parsed params blob (a JSON str).
    assert json.loads(body) == params


async def test_inbound_message_uses_binding_adapter_id_not_body() -> None:
    # SEC-309-1: a MISMATCHED body adapter_id must NOT change the forwarded id.
    forward = _RecordingForward()
    disposition = _disposition(forward)

    await disposition.dispatch("inbound.message", _inbound_params(adapter_id="tui"))

    adapter_id, _body = forward.forwards[0]
    assert adapter_id == _ADAPTER_ID  # the construction (spawn-binding) value


async def test_inbound_message_garbage_id_still_uses_binding() -> None:
    # SEC-309-1: a body with NO adapter_id (or a non-str) still forwards under the binding.
    forward = _RecordingForward()
    disposition = _disposition(forward)
    params = {"no_adapter_id_here": True}

    await disposition.dispatch("inbound.message", params)

    adapter_id, body = forward.forwards[0]
    assert adapter_id == _ADAPTER_ID
    assert json.loads(body) == params


async def test_rate_limit_signal_loud_audited_drop() -> None:
    forward = _RecordingForward()
    disposition = _disposition(forward)
    with structlog.testing.capture_logs() as logs:
        await disposition.dispatch("adapter.rate_limit_signal", {"retry_after_seconds": 5})
    assert forward.forwards == []  # NOT forwarded (no core route)
    events = {row["event"] for row in logs}
    assert "gateway.adapter.rate_limit_signal.dropped" in events


async def test_binding_request_loud_audited_drop() -> None:
    forward = _RecordingForward()
    disposition = _disposition(forward)
    with structlog.testing.capture_logs() as logs:
        await disposition.dispatch("adapter.binding_request", {"platform_user_id": "x"})
    assert forward.forwards == []  # NOT forwarded (audit-write DoS amplifier)
    events = {row["event"] for row in logs}
    assert "gateway.adapter.binding_request.dropped" in events


async def test_unknown_method_loud_audited_drop() -> None:
    forward = _RecordingForward()
    disposition = _disposition(forward)
    with structlog.testing.capture_logs() as logs:
        await disposition.dispatch("totally.unknown.method", {"x": 1})
    assert forward.forwards == []
    events = {row["event"] for row in logs}
    assert "gateway.adapter.inbound.unknown_method_dropped" in events


# ---------------------------------------------------------------------------
# Payload-blindness + never-raise + back-pressure
# ---------------------------------------------------------------------------


async def test_disposition_never_json_loads_the_body(monkeypatch: pytest.MonkeyPatch) -> None:
    # Payload-blindness spy: the gateway serializes the already-parsed params; it never
    # json.loads / re-parses the body. Patch json.loads to explode if called.
    import alfred.gateway.inbound_forward_runner as module

    def _boom(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("the gateway must not json.loads the body")

    monkeypatch.setattr(module.json, "loads", _boom)
    forward = _RecordingForward()
    disposition = _disposition(forward)
    await disposition.dispatch("inbound.message", _inbound_params())
    assert len(forward.forwards) == 1


async def test_forward_fault_engages_back_pressure_never_raises() -> None:
    gate = asyncio.Event()
    gate.set()
    for exc in (LegQueueFullError("full"), ReplayBufferError("cap")):
        gate.set()
        forward = _RecordingForward(raise_on_forward=exc)
        disposition = _disposition(forward, gate=gate)
        with structlog.testing.capture_logs() as logs:
            # MUST NOT raise (fire-and-forget contract).
            await disposition.dispatch("inbound.message", _inbound_params())
        assert not gate.is_set()  # back-pressure engaged (gate cleared)
        events = {row["event"] for row in logs}
        assert "gateway.adapter.inbound.backpressure_engaged" in events


async def test_forward_accepted_emits_structlog() -> None:
    forward = _RecordingForward()
    disposition = _disposition(forward)
    with structlog.testing.capture_logs() as logs:
        await disposition.dispatch("inbound.message", _inbound_params())
    events = {row["event"] for row in logs}
    assert "gateway.adapter.inbound.forward_accepted" in events


# ---------------------------------------------------------------------------
# GatewayInboundForwardRunner (thin session-less construction)
# ---------------------------------------------------------------------------


_HANDSHAKE_OK = {
    "jsonrpc": "2.0",
    "id": 0,
    "result": {"ok": True, "plugin_version": "0.1.0"},
}


class _FakeTransport:
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
        item = self._inbound.pop(0)
        return item() if callable(item) else item

    async def close(self) -> None:
        self.closed = True

    def enable_seq_ack(self) -> None:
        return None


async def test_runner_forwards_inbound_with_no_session() -> None:
    forward = _RecordingForward()
    transport = _FakeTransport(
        [
            dict(_HANDSHAKE_OK),
            {"jsonrpc": "2.0", "method": "inbound.message", "params": _inbound_params()},
        ]
    )
    runner = GatewayInboundForwardRunner(
        transport=transport,  # type: ignore[arg-type]
        adapter_id=_ADAPTER_ID,
        forward=forward,
    )

    await runner.run()

    assert transport.spawned and transport.closed
    assert len(forward.forwards) == 1
    adapter_id, body = forward.forwards[0]
    assert adapter_id == _ADAPTER_ID
    assert json.loads(body) == _inbound_params()


async def test_runner_exposes_start_and_handshake_and_pump() -> None:
    forward = _RecordingForward()
    transport = _FakeTransport([dict(_HANDSHAKE_OK)])
    runner = GatewayInboundForwardRunner(
        transport=transport,  # type: ignore[arg-type]
        adapter_id=_ADAPTER_ID,
        forward=forward,
    )
    await runner.start_and_handshake()
    assert transport.spawned is True
    await runner.pump()  # clean EOF
    assert transport.closed is True
