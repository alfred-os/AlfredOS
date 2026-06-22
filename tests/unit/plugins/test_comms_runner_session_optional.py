"""``CommsPluginRunner`` session-Optional + back-pressure gate (Spec B G6-7-3, #309).

FORK-A: the gateway forward-runner constructs a session-LESS ``CommsPluginRunner``
(``session=None``) with an injected forward disposition — the gateway has NO
capability gate (it is core-side by design). FORK-C: an optional
``back_pressure_gate`` lets the forward disposition PAUSE the reader on a full leg.

These cases drive the runner with a fake transport (no subprocess) and assert:

* the daemon path (session present) is BYTE-FOR-BYTE unchanged — ``_handshake``
  still runs ``_on_handshake_complete``, a transport crash still synthesizes the
  session-bound ``adapter.crashed`` route;
* the gateway path (``session=None``) SKIPS the gate, LOUD-LOGS a transport crash
  instead of routing it, and GUARDS ``_request_restart``;
* the back-pressure gate pauses the pump before the next read and shutdown wins a
  permanently-cleared gate;
* a ``session=None`` runner with NO disposition injected is a loud programming error.
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
import structlog

from alfred.plugins.comms_runner import CommsPluginRunner

pytestmark = pytest.mark.asyncio

_ADAPTER_ID = "discord"

_HANDSHAKE_OK: Mapping[str, object] = {
    "jsonrpc": "2.0",
    "id": 0,
    "result": {"ok": True, "plugin_version": "0.1.0"},
}


class _FakeTransport:
    """In-memory frame queue standing in for the stdio transport."""

    def __init__(self, inbound: list[Any]) -> None:
        self._inbound = inbound
        self.sent: list[Mapping[str, object]] = []
        self.spawned = False
        self.closed = False
        self.seq_ack_enabled = False

    async def spawn(self) -> None:
        self.spawned = True

    async def send(self, frame: Mapping[str, object]) -> None:
        self.sent.append(frame)

    async def read_frame(self) -> Mapping[str, object] | None:
        if not self._inbound:
            return None
        item = self._inbound.pop(0)
        if callable(item):
            return item()  # type: ignore[no-any-return]
        return item

    async def close(self) -> None:
        self.closed = True

    def enable_seq_ack(self) -> None:
        self.seq_ack_enabled = True


class _RecordingDisposition:
    """An :class:`InboundDisposition` that records every dispatched notification."""

    def __init__(self) -> None:
        self.dispatched: list[tuple[str, object, int | None]] = []

    async def dispatch(self, method: str, params: object, *, wire_seq: int | None = None) -> None:
        self.dispatched.append((method, params, wire_seq))


def _inbound_frame() -> Mapping[str, object]:
    return {
        "jsonrpc": "2.0",
        "method": "inbound.message",
        "params": {
            "adapter_id": _ADAPTER_ID,
            "inbound_id": "frame-1",
            "platform_user_id": "discord:42",
            "body": {"content": "hello"},
            "sub_payload_refs": [],
            "received_at": "2026-06-10T00:00:00+00:00",
            "addressing_signal": "dm",
        },
    }


# ---------------------------------------------------------------------------
# FORK-A SEC MUST-FIX #3: the DAEMON path (session present) is byte-for-byte
# unchanged — None is ONLY the gateway construction site.
# ---------------------------------------------------------------------------


def _daemon_session() -> MagicMock:
    """A session whose handshake-complete + post-handshake arms record their calls."""
    session = MagicMock()
    session._on_handshake_complete = AsyncMock()
    session._on_post_handshake_method = AsyncMock()
    session._supervisor = MagicMock(request_plugin_restart=AsyncMock())
    return session


async def test_daemon_path_handshake_complete_and_crash_synth_still_fire() -> None:
    # session PRESENT, no disposition injected -> the daemon's SessionDispatchDisposition
    # is built and the session-touch sites must fire exactly as pre-G6-7-3.
    session = _daemon_session()

    def _crash() -> Mapping[str, object]:
        raise BrokenPipeError("pipe gone")

    transport = _FakeTransport([dict(_HANDSHAKE_OK), _crash])
    runner = CommsPluginRunner(
        session=session,
        transport=transport,  # type: ignore[arg-type]
        adapter_id=_ADAPTER_ID,
    )

    await runner.run()

    # The capability gate (handshake-complete) ran on the session present path.
    session._on_handshake_complete.assert_awaited_once()
    # The transport crash synthesized a SESSION-BOUND adapter.crashed route (NOT the
    # gateway's session-less loud-log path).
    crash_calls = [
        call
        for call in session._on_post_handshake_method.await_args_list
        if call.args and call.args[0] == "adapter.crashed"
    ]
    assert len(crash_calls) == 1
    assert crash_calls[0].args[1]["adapter_id"] == _ADAPTER_ID


# ---------------------------------------------------------------------------
# Gateway path: session=None
# ---------------------------------------------------------------------------


async def test_session_none_handshake_skips_gate_and_dispatches() -> None:
    disposition = _RecordingDisposition()
    transport = _FakeTransport([dict(_HANDSHAKE_OK), _inbound_frame()])
    runner = CommsPluginRunner(
        session=None,
        transport=transport,  # type: ignore[arg-type]
        adapter_id=_ADAPTER_ID,
        inbound_disposition=disposition,
    )

    # No session => no AlfredPluginSession._on_handshake_complete to call; the
    # handshake must still send lifecycle.start, read the ack, and NOT raise.
    await runner.run()

    assert transport.spawned is True
    assert transport.closed is True
    # The lifecycle.start request was sent.
    assert any(f.get("method") == "lifecycle.start" for f in transport.sent)
    # The notification reached the injected disposition (no session involved).
    assert disposition.dispatched == [("inbound.message", _inbound_frame()["params"], None)]


async def test_session_none_transport_crash_loud_logs_no_route() -> None:
    disposition = _RecordingDisposition()

    def _crash() -> Mapping[str, object]:
        raise BrokenPipeError("pipe gone")

    transport = _FakeTransport([dict(_HANDSHAKE_OK), _crash])
    runner = CommsPluginRunner(
        session=None,
        transport=transport,  # type: ignore[arg-type]
        adapter_id=_ADAPTER_ID,
        inbound_disposition=disposition,
    )

    logs: list[Any] = []
    with structlog.testing.capture_logs() as captured:
        await runner.run()
        logs = captured

    # The crash ended the pump (transport closed), did NOT reach the disposition,
    # and emitted the gateway's session-less loud crash log (no session route).
    assert transport.closed is True
    assert disposition.dispatched == []
    events = {row["event"] for row in logs}
    assert "comms.runner.transport_crash_no_session" in events


async def test_session_none_request_restart_guarded() -> None:
    disposition = _RecordingDisposition()
    transport = _FakeTransport([dict(_HANDSHAKE_OK)])
    runner = CommsPluginRunner(
        session=None,
        transport=transport,  # type: ignore[arg-type]
        adapter_id=_ADAPTER_ID,
        inbound_disposition=disposition,
    )

    logs: list[Any] = []
    with structlog.testing.capture_logs() as captured:
        # Directly drive the restart-request arm: with no session there is no
        # supervisor, so it must loud-log and return rather than NPE.
        await runner._request_restart(reason="malformed_frame")
        logs = captured

    events = {row["event"] for row in logs}
    assert "comms.runner.restart_request_no_session" in events


async def test_session_none_without_disposition_is_loud_programming_error() -> None:
    transport = _FakeTransport([])
    with pytest.raises(ValueError, match="session=None requires an inbound_disposition"):
        CommsPluginRunner(
            session=None,
            transport=transport,  # type: ignore[arg-type]
            adapter_id=_ADAPTER_ID,
        )


# ---------------------------------------------------------------------------
# Back-pressure gate (FORK-C)
# ---------------------------------------------------------------------------


class _GateClearingTransport(_FakeTransport):
    """A transport that CLEARS the gate the moment it yields the first inbound frame.

    Models FORK-C's contract DETERMINISTICALLY: back-pressure engages (the gate is
    cleared) synchronously with the read of frame 1, so the pump — which awaits the
    gate at the TOP of the next loop, BEFORE the next ``read_frame`` — provably parks
    before reading frame 2 (no fire-and-forget dispatch race in the assertion).
    """

    def __init__(self, inbound: list[Any], *, gate: asyncio.Event) -> None:
        super().__init__(inbound)
        self._gate = gate
        self.reads = 0

    async def read_frame(self) -> Mapping[str, object] | None:
        frame = await super().read_frame()
        # The first inbound frame (read #2 — read #1 was the handshake ack, consumed by
        # _handshake before the pump) engages back-pressure.
        self.reads += 1
        if self.reads == 2:
            self._gate.clear()
        return frame


async def test_back_pressure_gate_pauses_pump_then_resumes() -> None:
    gate = asyncio.Event()
    gate.set()  # start open
    disposition = _RecordingDisposition()

    transport = _GateClearingTransport(
        [dict(_HANDSHAKE_OK), _inbound_frame(), _inbound_frame()], gate=gate
    )
    runner = CommsPluginRunner(
        session=None,
        transport=transport,  # type: ignore[arg-type]
        adapter_id=_ADAPTER_ID,
        inbound_disposition=disposition,
        back_pressure_gate=gate,
    )

    await runner.start_and_handshake()
    assert transport.reads == 1  # the handshake consumed the ack frame
    pump = asyncio.ensure_future(runner.pump())
    # Drive the loop: the pump reads frame 1 (clearing the gate), then parks at the top
    # of the next loop before reading frame 2.
    for _ in range(6):
        await asyncio.sleep(0)
    assert transport.reads == 2  # frame 1 read; frame 2 NOT yet read (parked on gate)
    assert not pump.done()
    assert not gate.is_set()  # back-pressure engaged
    # Release back-pressure (scheduler drained): the pump drains frame 2, then EOFs.
    gate.set()
    await asyncio.wait_for(pump, timeout=1.0)
    assert transport.reads == 4  # frame 2 + the EOF read
    assert len(disposition.dispatched) == 2


async def test_back_pressure_gate_shutdown_wins_a_cleared_gate() -> None:
    disposition = _RecordingDisposition()
    gate = asyncio.Event()
    gate.clear()  # permanently engaged
    shutdown = asyncio.Event()

    transport = _FakeTransport([dict(_HANDSHAKE_OK), _inbound_frame()])
    runner = CommsPluginRunner(
        session=None,
        transport=transport,  # type: ignore[arg-type]
        adapter_id=_ADAPTER_ID,
        inbound_disposition=disposition,
        back_pressure_gate=gate,
        shutdown_event=shutdown,
    )

    await runner.start_and_handshake()
    pump = asyncio.ensure_future(runner.pump())
    await asyncio.sleep(0)
    # The pump is parked on the cleared gate. A shutdown must win it (no wedge).
    shutdown.set()
    await asyncio.wait_for(pump, timeout=1.0)
    assert transport.closed is True


async def test_back_pressure_gate_force_cancel_during_pause_unwinds() -> None:
    disposition = _RecordingDisposition()
    gate = asyncio.Event()
    gate.clear()

    transport = _FakeTransport([dict(_HANDSHAKE_OK), _inbound_frame()])
    runner = CommsPluginRunner(
        session=None,
        transport=transport,  # type: ignore[arg-type]
        adapter_id=_ADAPTER_ID,
        inbound_disposition=disposition,
        back_pressure_gate=gate,
    )

    await runner.start_and_handshake()
    pump = asyncio.ensure_future(runner.pump())
    await asyncio.sleep(0)
    pump.cancel()
    with pytest.raises(asyncio.CancelledError):
        await pump
    assert transport.closed is True
