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

from alfred.gateway.core_link import ForwardLegUnavailableError
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


class _FullThenAcceptForward:
    """Raises ``exc`` on the FIRST forward (leg full), accepts every later forward.

    Drives the no-drop retry path: the disposition must clear the gate + park on it,
    and after a simulated scheduler drain (the test SETS the gate) re-forward the SAME
    body — proving the triggering frame is never dropped.
    """

    def __init__(self, *, exc: BaseException) -> None:
        self.forwards: list[tuple[str, str]] = []
        self._exc = exc
        self.attempts = 0

    async def __call__(self, adapter_id: str, body: str) -> None:
        self.attempts += 1
        if self.attempts == 1:
            raise self._exc
        self.forwards.append((adapter_id, body))


class _AlwaysFullForward:
    """Every forward raises ``exc`` (a permanently-full leg) — drives the shutdown path."""

    def __init__(self, *, exc: BaseException) -> None:
        self.forwards: list[tuple[str, str]] = []
        self._exc = exc
        self.attempts = 0

    async def __call__(self, adapter_id: str, body: str) -> None:
        self.attempts += 1
        raise self._exc


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
    forward: object,
    *,
    gate: asyncio.Event | None = None,
    shutdown_event: asyncio.Event | None = None,
) -> GatewayForwardDisposition:
    return GatewayForwardDisposition(
        adapter_id=_ADAPTER_ID,
        forward=forward,  # type: ignore[arg-type]
        back_pressure_gate=gate,
        shutdown_event=shutdown_event,
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


@pytest.mark.parametrize("exc", [LegQueueFullError("full"), ReplayBufferError("cap")])
async def test_forward_fault_retries_after_drain_never_drops(exc: BaseException) -> None:
    # ADR-0039 invariant: a leg-full is BACK-PRESSURE, not drop. The first forward hits a
    # full leg; the disposition clears the gate (pause) + PARKS on it, NEVER returning
    # until the leg drains. A concurrent "scheduler drain" SETS the gate; the disposition
    # then re-forwards the SAME body — proving the triggering frame is never dropped.
    gate = asyncio.Event()
    gate.set()
    forward = _FullThenAcceptForward(exc=exc)
    disposition = _disposition(forward, gate=gate, shutdown_event=asyncio.Event())
    params = _inbound_params()

    with structlog.testing.capture_logs() as logs:
        dispatch = asyncio.ensure_future(disposition.dispatch("inbound.message", params))
        # Let the first (full) forward run + the disposition park on the cleared gate.
        await asyncio.sleep(0)
        assert not gate.is_set()  # back-pressure engaged
        assert forward.forwards == []  # NOT yet delivered (held, not dropped)
        assert not dispatch.done()  # the disposition is PARKED, not returned (no drop)
        # The scheduler drained a frame off the leg -> SET the gate (resume).
        gate.set()
        await dispatch  # MUST NOT raise (fire-and-forget contract)

    # The SAME triggering frame was re-forwarded after the drain (no-drop).
    assert len(forward.forwards) == 1
    adapter_id, body = forward.forwards[0]
    assert adapter_id == _ADAPTER_ID
    assert json.loads(body) == params
    events = [row["event"] for row in logs]
    assert "gateway.adapter.inbound.backpressure_engaged" in events
    assert "gateway.adapter.inbound.backpressure_released" in events
    # FOLD-2 (DEVEX-309-1) + FOLD-6: the back-pressure rows carry the closed-vocab reason
    # distinguishing per-leg saturation (leg_full) from whole-gateway over-budget (global_cap),
    # and each carries the adapter_id — assert the FIELDS, not just the event name.
    expected_reason = "leg_full" if isinstance(exc, LegQueueFullError) else "global_cap"
    engaged = next(r for r in logs if r["event"] == "gateway.adapter.inbound.backpressure_engaged")
    released = next(
        r for r in logs if r["event"] == "gateway.adapter.inbound.backpressure_released"
    )
    assert engaged["adapter_id"] == _ADAPTER_ID
    assert engaged["reason"] == expected_reason
    assert released["adapter_id"] == _ADAPTER_ID
    assert released["reason"] == expected_reason


async def test_forward_fault_retries_with_gate_but_no_shutdown_event() -> None:
    # A gate wired but NO shutdown_event (defensive): the park is a plain ``gate.wait()``
    # (always resumes). The first forward is full; after the drain SETS the gate the SAME
    # body re-forwards — proving no-drop even without a shutdown_event.
    gate = asyncio.Event()
    gate.set()
    forward = _FullThenAcceptForward(exc=LegQueueFullError("full"))
    disposition = _disposition(forward, gate=gate, shutdown_event=None)
    params = _inbound_params()

    dispatch = asyncio.ensure_future(disposition.dispatch("inbound.message", params))
    await asyncio.sleep(0)
    assert not gate.is_set()  # back-pressure engaged
    assert not dispatch.done()  # parked on the plain gate.wait()
    gate.set()  # scheduler drained -> resume
    await dispatch

    assert len(forward.forwards) == 1
    assert json.loads(forward.forwards[0][1]) == params


async def test_forward_fault_shutdown_ends_retry_promptly() -> None:
    # A permanently-full leg + a SET shutdown_event must end the retry-wait promptly (no
    # wedge). The frame may be dropped ONLY on the shutdown path (we are tearing down).
    gate = asyncio.Event()  # never set -> the leg never drains
    shutdown_event = asyncio.Event()
    forward = _AlwaysFullForward(exc=LegQueueFullError("full"))
    disposition = _disposition(forward, gate=gate, shutdown_event=shutdown_event)

    with structlog.testing.capture_logs() as logs:
        dispatch = asyncio.ensure_future(disposition.dispatch("inbound.message", _inbound_params()))
        await asyncio.sleep(0)
        assert not dispatch.done()  # parked on the never-draining gate
        shutdown_event.set()  # shutdown wins the park
        await asyncio.wait_for(dispatch, timeout=1.0)  # ends promptly, never raises

    assert forward.forwards == []  # dropped on the shutdown path (acceptable)
    events = [row["event"] for row in logs]
    assert "gateway.adapter.inbound.backpressure_engaged" in events
    assert "gateway.adapter.inbound.backpressure_shutdown_drop" in events


async def test_forward_fault_park_cancels_cleanly() -> None:
    # A force-cancel (supervisor drain-timeout escalation) of a parked disposition unwinds
    # cleanly: the CancelledError propagates (never swallowed) and nothing is delivered.
    gate = asyncio.Event()  # never set
    forward = _AlwaysFullForward(exc=LegQueueFullError("full"))
    disposition = _disposition(forward, gate=gate, shutdown_event=asyncio.Event())

    dispatch = asyncio.ensure_future(disposition.dispatch("inbound.message", _inbound_params()))
    await asyncio.sleep(0)
    assert not dispatch.done()
    dispatch.cancel()
    with pytest.raises(asyncio.CancelledError):
        await dispatch
    assert forward.forwards == []


async def test_forward_fault_with_no_gate_drops_loud_with_reason_never_raises() -> None:
    # No back-pressure gate wired (defensive): there is NOTHING to park on, so a full-leg
    # fault is a real DROP — DEVEX-309-2 gives it a DISTINCT ``forward_dropped`` event (NOT
    # the ``backpressure_engaged`` row that implies a HOLD), and never raises. FOLD-6:
    # assert the row carries the expected adapter_id + reason, not just the event name.
    forward = _RecordingForward(raise_on_forward=LegQueueFullError("full"))
    disposition = _disposition(forward, gate=None)
    with structlog.testing.capture_logs() as logs:
        await disposition.dispatch("inbound.message", _inbound_params())
    dropped = [row for row in logs if row["event"] == "gateway.adapter.inbound.forward_dropped"]
    assert len(dropped) == 1
    assert dropped[0]["adapter_id"] == _ADAPTER_ID
    assert dropped[0]["reason"] == "leg_full"
    # The HOLD event must NOT appear — a no-gate fault is a drop, not back-pressure.
    assert "gateway.adapter.inbound.backpressure_engaged" not in {row["event"] for row in logs}


async def test_forward_fault_no_gate_global_cap_reason() -> None:
    # DEVEX-309-1: the no-gate drop distinguishes the global-cap cause (ReplayBufferError)
    # from the per-leg-full cause via the closed-vocab reason field.
    forward = _RecordingForward(raise_on_forward=ReplayBufferError("cap"))
    disposition = _disposition(forward, gate=None)
    with structlog.testing.capture_logs() as logs:
        await disposition.dispatch("inbound.message", _inbound_params())
    dropped = [row for row in logs if row["event"] == "gateway.adapter.inbound.forward_dropped"]
    assert len(dropped) == 1
    assert dropped[0]["reason"] == "global_cap"


async def test_forward_accepted_emits_structlog() -> None:
    forward = _RecordingForward()
    disposition = _disposition(forward)
    with structlog.testing.capture_logs() as logs:
        await disposition.dispatch("inbound.message", _inbound_params())
    events = {row["event"] for row in logs}
    assert "gateway.adapter.inbound.forward_accepted" in events


class _CountingForward:
    """Records attempts; raises ``exc`` on every call (drives the terminal-drop path)."""

    def __init__(self, *, exc: BaseException) -> None:
        self.attempts = 0
        self._exc = exc

    async def __call__(self, adapter_id: str, body: str) -> None:
        self.attempts += 1
        raise self._exc


async def test_leg_unavailable_is_loud_terminal_drop_no_retry_no_accept() -> None:
    # FOLD-1 (ERR-309-1): the forward raises ForwardLegUnavailableError (the router refused —
    # the leg is unregistered/gone). This is NOT back-pressure: the disposition LOUD-TERMINAL
    # drops the frame (leg_unavailable_drop), does NOT retry, does NOT log forward_accepted,
    # and never raises. A gate IS wired to prove the drop does NOT touch the back-pressure
    # path (the gate stays SET — never cleared).
    gate = asyncio.Event()
    gate.set()
    forward = _CountingForward(exc=ForwardLegUnavailableError("no leg"))
    disposition = _disposition(forward, gate=gate, shutdown_event=asyncio.Event())
    with structlog.testing.capture_logs() as logs:
        await disposition.dispatch("inbound.message", _inbound_params())  # must NOT raise
    # Exactly ONE forward attempt — no retry against a gone leg.
    assert forward.attempts == 1
    # The gate was NEVER cleared — the terminal drop is not a back-pressure engage.
    assert gate.is_set()
    events = [row["event"] for row in logs]
    drops = [r for r in logs if r["event"] == "gateway.adapter.inbound.leg_unavailable_drop"]
    assert len(drops) == 1
    assert drops[0]["adapter_id"] == _ADAPTER_ID  # FOLD-6: assert the field, not just the event
    # The frame was LOST — it must NOT be reported as accepted (the load-bearing silent-loss fix).
    assert "gateway.adapter.inbound.forward_accepted" not in events
    assert "gateway.adapter.inbound.backpressure_engaged" not in events


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


class _OrderTrackingTransport:
    """A transport that RECORDS each ``read_frame`` so a test can prove the reader paused.

    ``read_log`` appends the index of every frame read; under back-pressure the reader
    must NOT read the next frame until the in-flight one is forwarded (synchronous-in-reader
    routing — no read-ahead).
    """

    def __init__(self, inbound: list[object]) -> None:
        self._inbound = list(inbound)
        self.read_log: list[int] = []
        self._read_index = 0
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
        self.read_log.append(self._read_index)
        self._read_index += 1
        return item() if callable(item) else item

    async def close(self) -> None:
        self.closed = True

    def enable_seq_ack(self) -> None:
        return None


async def test_runner_no_read_ahead_and_in_order_under_back_pressure() -> None:
    # The end-to-end no-drop + order-preserved property: two inbound frames, the FIRST
    # leg-full. Synchronous-in-reader routing means the reader does NOT read frame 2 until
    # frame 1 is forwarded; after the drain the SAME first frame forwards, THEN frame 2 —
    # in source order, none dropped.
    gate = asyncio.Event()
    gate.set()
    forward = _FullThenAcceptForward(exc=LegQueueFullError("full"))
    params_a = _inbound_params()
    params_b = _inbound_params(adapter_id="discord")
    params_b["inbound_id"] = "frame-2"
    transport = _OrderTrackingTransport(
        [
            dict(_HANDSHAKE_OK),
            {"jsonrpc": "2.0", "method": "inbound.message", "params": params_a},
            {"jsonrpc": "2.0", "method": "inbound.message", "params": params_b},
        ]
    )
    runner = GatewayInboundForwardRunner(
        transport=transport,  # type: ignore[arg-type]
        adapter_id=_ADAPTER_ID,
        forward=forward,
        back_pressure_gate=gate,
        shutdown_event=asyncio.Event(),
    )
    await runner.start_and_handshake()
    assert transport.read_log == [0]  # the handshake ack consumed read #0
    pump = asyncio.ensure_future(runner.pump())
    # Drive the loop: the reader reads frame A (read #1), forwards it (full -> the
    # disposition parks on the cleared gate). It must NOT read frame B ahead.
    for _ in range(6):
        await asyncio.sleep(0)
    assert forward.forwards == []  # frame A held, not dropped
    assert not pump.done()  # parked inside the synchronous forward, not returned
    assert not gate.is_set()  # back-pressure engaged
    # The handshake read (0) + frame A (1) only — frame B NOT read ahead.
    assert transport.read_log == [0, 1]
    # Drain: SET the gate -> frame A re-forwards, then frame B forwards.
    gate.set()
    await asyncio.wait_for(pump, timeout=1.0)

    assert [json.loads(b) for _a, b in forward.forwards] == [params_a, params_b]
    assert transport.closed is True


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
