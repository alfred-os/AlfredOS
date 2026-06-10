"""``CommsPluginRunner`` — handshake + single-reader pump (PR-S4-11a Wave 1).

The runner is the imperative shell that owns ``(session, transport, adapter_id)``
and drives the conversation: spawn -> handshake (gate check) -> single-reader
pump -> clean teardown. The session stays a pure state machine; the runner does
the I/O sequencing.

These cases use a FAKE transport (an in-memory frame queue, no subprocess) and a
REAL :meth:`AlfredPluginSession.for_comms_adapter` session with RECORDING handlers
and a permissive FIXTURE gate (``tests.helpers.gates.make_permissive_fixture_gate``
— never an always-allow shim; CLAUDE.md rule #2).
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from alfred.comms_mcp.handlers import (
    BindingHandler,
    CrashHandler,
    RateLimitHandler,
)
from alfred.plugins.comms_runner import CommsPluginRunner
from alfred.plugins.comms_stdio_transport import CommsProtocolError
from alfred.plugins.errors import PluginError
from alfred.plugins.session import AlfredPluginSession
from tests.helpers.gates import make_deny_all_gate, make_permissive_fixture_gate

pytestmark = pytest.mark.asyncio

_ADAPTER_ID = "alfred_comms_test"

_MANIFEST = """
[alfred]
manifest_version = 1

[plugin]
id = "alfred_comms_test"
subscriber_tier = "user-plugin"
sandbox_profile = "user-plugin"

[sandbox]
kind = "none"
"""

# A well-formed lifecycle.start success response the reference plugin emits.
_HANDSHAKE_OK: Mapping[str, object] = {
    "jsonrpc": "2.0",
    "id": 0,
    "result": {"ok": True, "plugin_version": "0.1.0"},
}


class _FakeTransport:
    """In-memory frame queue standing in for :class:`CommsStdioTransport`.

    ``inbound`` is the script of frames :meth:`read_frame` yields in order; a
    callable entry is invoked (to raise / inspect) instead of returned. ``None``
    yields a clean EOF. ``sent`` records every :meth:`send`. ``closed`` flips on
    :meth:`close`.
    """

    def __init__(self, inbound: list[Any]) -> None:
        self._inbound = inbound
        self.sent: list[Mapping[str, object]] = []
        self.spawned = False
        self.closed = False

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


class _RecordingHandler:
    """Records every notification it processes; optionally raises once."""

    def __init__(self, *, raise_on_first: BaseException | None = None) -> None:
        self.processed: list[object] = []
        self._raise = raise_on_first

    async def process(self, notification: object) -> None:
        self.processed.append(notification)
        if self._raise is not None:
            exc, self._raise = self._raise, None
            raise exc


def _audit() -> MagicMock:
    writer = MagicMock()
    writer.append_schema = AsyncMock()
    return writer


async def _make_session(
    *,
    gate: Any,
    transport: Any,
    inbound_handler: Any,
    binding_handler: Any | None = None,
    rate_limit_handler: Any | None = None,
    crash_handler: Any | None = None,
    supervisor: Any | None = None,
) -> AlfredPluginSession:
    return await AlfredPluginSession.for_comms_adapter(
        adapter_id=_ADAPTER_ID,
        manifest_raw=_MANIFEST,
        audit_writer=_audit(),
        gate=gate,
        supervisor=supervisor if supervisor is not None else MagicMock(),
        inbound_handler=inbound_handler,
        binding_handler=binding_handler or MagicMock(spec=BindingHandler),
        rate_limit_handler=rate_limit_handler or MagicMock(spec=RateLimitHandler),
        crash_handler=crash_handler or MagicMock(spec=CrashHandler),
        transport=transport,  # type: ignore[arg-type]
    )


def _inbound_frame() -> Mapping[str, object]:
    return {
        "jsonrpc": "2.0",
        "method": "inbound.message",
        "params": {
            "adapter_id": _ADAPTER_ID,
            "platform_user_id": "discord:42",
            "body": {"content": "hello"},
            "sub_payload_refs": [],
            "received_at": "2026-06-10T00:00:00+00:00",
            "addressing_signal": "dm",
        },
    }


# ---------------------------------------------------------------------------
# Handshake-then-pump ordering
# ---------------------------------------------------------------------------


async def test_handshake_runs_before_pump_then_clean_eof_ends_run() -> None:
    inbound_handler = _RecordingHandler()
    transport = _FakeTransport([dict(_HANDSHAKE_OK), _inbound_frame()])
    session = await _make_session(
        gate=make_permissive_fixture_gate(),
        transport=transport,
        inbound_handler=inbound_handler,
    )
    runner = CommsPluginRunner(session=session, transport=transport, adapter_id=_ADAPTER_ID)

    # The real InboundHandler routes to process_inbound_message; here we wired a
    # recording stand-in so we assert the pump reached it. Patch the session's
    # inbound handler to the recorder.
    session._inbound_handler = inbound_handler  # type: ignore[assignment]

    await runner.run()

    assert transport.spawned is True
    # lifecycle.start was sent before any frame was read (handshake first).
    assert transport.sent[0]["method"] == "lifecycle.start"
    assert session._handshake_complete is True
    # The notification frame after the handshake reached the recording handler.
    assert len(inbound_handler.processed) == 1
    assert transport.closed is True


# ---------------------------------------------------------------------------
# Gate denial tears down without pumping
# ---------------------------------------------------------------------------


async def test_gate_denial_tears_down_without_pumping() -> None:
    inbound_handler = _RecordingHandler()
    # A notification follows the handshake; the pump must NEVER reach it because
    # the gate denies at handshake.
    transport = _FakeTransport([dict(_HANDSHAKE_OK), _inbound_frame()])
    session = await _make_session(
        gate=make_deny_all_gate(),
        transport=transport,
        inbound_handler=inbound_handler,
    )
    session._inbound_handler = inbound_handler  # type: ignore[assignment]
    runner = CommsPluginRunner(session=session, transport=transport, adapter_id=_ADAPTER_ID)

    with pytest.raises(PluginError):
        await runner.run()

    assert session._handshake_complete is False
    assert inbound_handler.processed == []  # pump never ran
    assert transport.closed is True  # teardown still closed the transport


# ---------------------------------------------------------------------------
# Notification routing
# ---------------------------------------------------------------------------


async def test_notification_routes_to_recording_handler() -> None:
    inbound_handler = _RecordingHandler()
    transport = _FakeTransport([dict(_HANDSHAKE_OK), _inbound_frame()])
    session = await _make_session(
        gate=make_permissive_fixture_gate(),
        transport=transport,
        inbound_handler=inbound_handler,
    )
    session._inbound_handler = inbound_handler  # type: ignore[assignment]
    runner = CommsPluginRunner(session=session, transport=transport, adapter_id=_ADAPTER_ID)

    await runner.run()

    assert len(inbound_handler.processed) == 1


# ---------------------------------------------------------------------------
# Malformed frame -> restart request, NOT a crash route
# ---------------------------------------------------------------------------


async def test_malformed_frame_requests_restart() -> None:
    supervisor = MagicMock()
    supervisor.request_plugin_restart = AsyncMock()
    supervisor.trip_breaker = AsyncMock()

    def _raise_malformed() -> Mapping[str, object]:
        raise CommsProtocolError("bad wire")

    transport = _FakeTransport([dict(_HANDSHAKE_OK), _raise_malformed])
    session = await _make_session(
        gate=make_permissive_fixture_gate(),
        transport=transport,
        inbound_handler=_RecordingHandler(),
        supervisor=supervisor,
    )
    runner = CommsPluginRunner(session=session, transport=transport, adapter_id=_ADAPTER_ID)

    await runner.run()

    supervisor.request_plugin_restart.assert_awaited_once()
    _, kwargs = supervisor.request_plugin_restart.call_args
    assert kwargs["adapter_id"] == _ADAPTER_ID
    assert transport.closed is True


# ---------------------------------------------------------------------------
# Crash mid-read -> adapter.crashed routed to the crash handler
# ---------------------------------------------------------------------------


async def test_crash_mid_read_routes_adapter_crashed() -> None:
    crash_handler = _RecordingHandler()

    def _broken_pipe() -> Mapping[str, object]:
        raise BrokenPipeError("child died")

    transport = _FakeTransport([dict(_HANDSHAKE_OK), _broken_pipe])
    session = await _make_session(
        gate=make_permissive_fixture_gate(),
        transport=transport,
        inbound_handler=_RecordingHandler(),
        crash_handler=crash_handler,
    )
    session._crash_handler = crash_handler  # type: ignore[assignment]
    runner = CommsPluginRunner(session=session, transport=transport, adapter_id=_ADAPTER_ID)

    await runner.run()

    assert len(crash_handler.processed) == 1
    notification = crash_handler.processed[0]
    # The synthesized crash carries closed-vocab detail, never raw bytes.
    assert notification.adapter_id == _ADAPTER_ID  # type: ignore[attr-defined]
    assert "child died" not in notification.detail  # type: ignore[attr-defined]
    assert transport.closed is True


# ---------------------------------------------------------------------------
# Handler exception -> reader survives + continues
# ---------------------------------------------------------------------------


async def test_handler_exception_reader_survives_and_continues() -> None:
    # The first inbound frame's handler raises; the reader must log + continue to
    # the second frame, then end on clean EOF.
    inbound_handler = _RecordingHandler(raise_on_first=RuntimeError("handler boom"))
    transport = _FakeTransport([dict(_HANDSHAKE_OK), _inbound_frame(), _inbound_frame()])
    session = await _make_session(
        gate=make_permissive_fixture_gate(),
        transport=transport,
        inbound_handler=inbound_handler,
    )
    session._inbound_handler = inbound_handler  # type: ignore[assignment]
    runner = CommsPluginRunner(session=session, transport=transport, adapter_id=_ADAPTER_ID)

    await runner.run()

    # Both frames reached the handler — the reader survived the first failure.
    assert len(inbound_handler.processed) == 2
    assert transport.closed is True


# ---------------------------------------------------------------------------
# Response frame post-handshake (no method) is logged + ignored in 11a
# ---------------------------------------------------------------------------


async def test_post_handshake_response_frame_is_ignored() -> None:
    inbound_handler = _RecordingHandler()
    # A stray response frame (no "method") after the handshake — 11a logs + skips.
    stray_response: Mapping[str, object] = {"jsonrpc": "2.0", "id": 99, "result": {"ok": True}}
    transport = _FakeTransport([dict(_HANDSHAKE_OK), stray_response, _inbound_frame()])
    session = await _make_session(
        gate=make_permissive_fixture_gate(),
        transport=transport,
        inbound_handler=inbound_handler,
    )
    session._inbound_handler = inbound_handler  # type: ignore[assignment]
    runner = CommsPluginRunner(session=session, transport=transport, adapter_id=_ADAPTER_ID)

    await runner.run()

    # The stray response was ignored; only the real notification was routed.
    assert len(inbound_handler.processed) == 1


# ---------------------------------------------------------------------------
# Handshake that never acks (clean EOF before the response) tears down
# ---------------------------------------------------------------------------


async def test_handshake_ack_not_ok_tears_down() -> None:
    # The plugin answers lifecycle.start but reports ok=false.
    not_ok: Mapping[str, object] = {"jsonrpc": "2.0", "id": 0, "result": {"ok": False}}
    transport = _FakeTransport([not_ok, _inbound_frame()])
    session = await _make_session(
        gate=make_permissive_fixture_gate(),
        transport=transport,
        inbound_handler=_RecordingHandler(),
    )
    runner = CommsPluginRunner(session=session, transport=transport, adapter_id=_ADAPTER_ID)

    with pytest.raises(PluginError):
        await runner.run()

    assert session._handshake_complete is False
    assert transport.closed is True


async def test_handshake_ignores_non_matching_frame_before_ack() -> None:
    # A stray frame with a different id arrives before the matching ack; the
    # handshake loop ignores it and keeps reading for the real ack.
    stray: Mapping[str, object] = {"jsonrpc": "2.0", "id": 999, "result": {"ok": True}}
    inbound_handler = _RecordingHandler()
    transport = _FakeTransport([stray, dict(_HANDSHAKE_OK), _inbound_frame()])
    session = await _make_session(
        gate=make_permissive_fixture_gate(),
        transport=transport,
        inbound_handler=inbound_handler,
    )
    session._inbound_handler = inbound_handler  # type: ignore[assignment]
    runner = CommsPluginRunner(session=session, transport=transport, adapter_id=_ADAPTER_ID)

    await runner.run()

    assert session._handshake_complete is True
    assert len(inbound_handler.processed) == 1


async def test_crash_route_swallows_a_failing_crash_handler() -> None:
    # The crash handler itself raises while handling the synthesized crash; the
    # runner must swallow it (the plugin is already crashing) and end cleanly.
    crash_handler = _RecordingHandler(raise_on_first=RuntimeError("crash handler boom"))

    def _broken_pipe() -> Mapping[str, object]:
        raise BrokenPipeError("child died")

    transport = _FakeTransport([dict(_HANDSHAKE_OK), _broken_pipe])
    session = await _make_session(
        gate=make_permissive_fixture_gate(),
        transport=transport,
        inbound_handler=_RecordingHandler(),
        crash_handler=crash_handler,
    )
    session._crash_handler = crash_handler  # type: ignore[assignment]
    runner = CommsPluginRunner(session=session, transport=transport, adapter_id=_ADAPTER_ID)

    # No exception escapes — the failing crash handler is swallowed.
    await runner.run()

    assert len(crash_handler.processed) == 1
    assert transport.closed is True


async def test_malformed_frame_without_supervisor_is_noop_restart() -> None:
    # A comms session always has a supervisor, but the restart helper guards on
    # ``supervisor is None`` defensively. Drive that branch by nulling it.
    def _raise_malformed() -> Mapping[str, object]:
        raise CommsProtocolError("bad wire")

    transport = _FakeTransport([dict(_HANDSHAKE_OK), _raise_malformed])
    session = await _make_session(
        gate=make_permissive_fixture_gate(),
        transport=transport,
        inbound_handler=_RecordingHandler(),
    )
    session._supervisor = None  # type: ignore[assignment]
    runner = CommsPluginRunner(session=session, transport=transport, adapter_id=_ADAPTER_ID)

    # No supervisor to ask — the runner ends cleanly without raising.
    await runner.run()

    assert transport.closed is True


async def test_handshake_eof_before_ack_tears_down() -> None:
    # The plugin closes its stdout before answering lifecycle.start.
    transport = _FakeTransport([])  # read_frame -> None immediately
    session = await _make_session(
        gate=make_permissive_fixture_gate(),
        transport=transport,
        inbound_handler=_RecordingHandler(),
    )
    runner = CommsPluginRunner(session=session, transport=transport, adapter_id=_ADAPTER_ID)

    with pytest.raises(PluginError):
        await runner.run()

    assert session._handshake_complete is False
    assert transport.closed is True


# ---------------------------------------------------------------------------
# Wave 1 (#237): send_request + pending-response correlation
# ---------------------------------------------------------------------------


class _QueueTransport:
    """A transport whose ``read_frame`` blocks on an :class:`asyncio.Queue`.

    Unlike :class:`_FakeTransport` (a static script), this lets a concurrently
    running pump pick up a response frame the test pushes AFTER an in-flight
    :meth:`CommsPluginRunner.send_request` has registered its pending future —
    the request/response interleave the single-reader rule forces. Pushing a
    callable runs it (to raise inside ``read_frame``); pushing ``None`` is a
    clean EOF; otherwise the mapping is yielded verbatim.
    """

    def __init__(self) -> None:
        self._queue: asyncio.Queue[Any] = asyncio.Queue()
        self.sent: list[Mapping[str, object]] = []
        self.spawned = False
        self.closed = False

    async def spawn(self) -> None:
        self.spawned = True

    async def send(self, frame: Mapping[str, object]) -> None:
        self.sent.append(frame)

    async def read_frame(self) -> Mapping[str, object] | None:
        item = await self._queue.get()
        if callable(item):
            return item()  # type: ignore[no-any-return]
        return item

    async def close(self) -> None:
        self.closed = True

    def push(self, item: Any) -> None:
        self._queue.put_nowait(item)


async def _handshook_runner(
    transport: _QueueTransport,
) -> tuple[CommsPluginRunner, asyncio.Task[None]]:
    """Build a runner, drive it past the handshake, and return it + its run task.

    The run task is left pumping on the (initially empty) queue so a test can
    push response / notification / EOF frames into it on demand.
    """
    session = await _make_session(
        gate=make_permissive_fixture_gate(),
        transport=transport,
        inbound_handler=_RecordingHandler(),
    )
    runner = CommsPluginRunner(session=session, transport=transport, adapter_id=_ADAPTER_ID)
    transport.push(dict(_HANDSHAKE_OK))
    run_task = asyncio.create_task(runner.run())
    # Spin until the handshake has completed and the pump is awaiting a frame.
    for _ in range(100):
        await asyncio.sleep(0)
        if session._handshake_complete:
            break
    assert session._handshake_complete is True
    return runner, run_task


async def _wait_for_method_frame(transport: _QueueTransport, method: str) -> Mapping[str, object]:
    for _ in range(100):
        await asyncio.sleep(0)
        for frame in transport.sent:
            if frame.get("method") == method:
                return frame
    raise AssertionError(f"request frame for {method!r} never emitted")


async def _wait_for_request_frame(transport: _QueueTransport) -> Mapping[str, object]:
    return await _wait_for_method_frame(transport, "outbound.message")


async def _wait_for_health_frame(transport: _QueueTransport) -> Mapping[str, object]:
    return await _wait_for_method_frame(transport, "adapter.health")


async def test_send_request_resolves_on_matching_id_response() -> None:
    transport = _QueueTransport()
    runner, run_task = await _handshook_runner(transport)

    request = asyncio.create_task(
        runner.send_request("outbound.message", {"adapter_id": _ADAPTER_ID, "body": "ack"})
    )
    sent = await _wait_for_request_frame(transport)
    req_id = sent["id"]
    assert req_id != 0  # 0 is reserved for lifecycle.start

    transport.push({"jsonrpc": "2.0", "id": req_id, "result": {"platform_message_id": "msg-1"}})
    result = await request
    assert result == {"platform_message_id": "msg-1"}

    transport.push(None)  # clean EOF ends the pump
    await run_task
    assert transport.closed is True


async def test_send_request_unknown_id_response_is_ignored() -> None:
    transport = _QueueTransport()
    runner, run_task = await _handshook_runner(transport)

    request = asyncio.create_task(
        runner.send_request("outbound.message", {"adapter_id": _ADAPTER_ID}, timeout=5.0)
    )
    sent = await _wait_for_request_frame(transport)
    req_id = sent["id"]

    # A response with a DIFFERENT id must not resolve the pending future.
    transport.push({"jsonrpc": "2.0", "id": req_id + 999, "result": {"stray": True}})
    await asyncio.sleep(0)
    assert not request.done()

    # The matching id then resolves it.
    transport.push({"jsonrpc": "2.0", "id": req_id, "result": {"ok": True}})
    assert await request == {"ok": True}

    transport.push(None)
    await run_task


async def test_send_request_timeout_raises_plugin_error_and_cleans_up() -> None:
    transport = _QueueTransport()
    runner, run_task = await _handshook_runner(transport)

    with pytest.raises(PluginError):
        await runner.send_request("outbound.message", {"adapter_id": _ADAPTER_ID}, timeout=0.01)

    # The pending entry was popped on timeout — no leak.
    assert runner._pending == {}

    transport.push(None)
    await run_task


async def test_eof_fails_outstanding_pending_futures_loudly() -> None:
    transport = _QueueTransport()
    runner, run_task = await _handshook_runner(transport)

    request = asyncio.create_task(
        runner.send_request("outbound.message", {"adapter_id": _ADAPTER_ID}, timeout=5.0)
    )
    await _wait_for_request_frame(transport)

    # Clean EOF while a request is in flight must fail the awaiter loudly.
    transport.push(None)
    with pytest.raises(PluginError):
        await request
    await run_task
    assert runner._pending == {}


async def test_transport_crash_fails_outstanding_pending_futures_loudly() -> None:
    transport = _QueueTransport()
    runner, run_task = await _handshook_runner(transport)

    request = asyncio.create_task(
        runner.send_request("outbound.message", {"adapter_id": _ADAPTER_ID}, timeout=5.0)
    )
    await _wait_for_request_frame(transport)

    def _broken_pipe() -> Mapping[str, object]:
        raise BrokenPipeError("child died")

    transport.push(_broken_pipe)
    with pytest.raises(PluginError):
        await request
    await run_task
    assert runner._pending == {}


async def test_response_for_cancelled_request_is_dropped() -> None:
    # An awaiting send_request task is cancelled (CancelledError, NOT TimeoutError),
    # so its done-but-cancelled Future lingers in the pending map. A later response
    # with that id must be dropped, not crash the pump on a re-resolution attempt.
    transport = _QueueTransport()
    runner, run_task = await _handshook_runner(transport)

    request = asyncio.create_task(
        runner.send_request("outbound.message", {"adapter_id": _ADAPTER_ID}, timeout=5.0)
    )
    sent = await _wait_for_request_frame(transport)
    req_id = sent["id"]

    request.cancel()
    with pytest.raises(asyncio.CancelledError):
        await request
    # The cancelled (done) future is still registered under its id.
    assert req_id in runner._pending

    # The late response hits the future.done() guard and is dropped cleanly.
    transport.push({"jsonrpc": "2.0", "id": req_id, "result": {"late": True}})
    await asyncio.sleep(0)

    transport.push(None)
    await run_task


async def test_fail_all_pending_skips_already_done_future() -> None:
    # A done-but-cancelled future lingering in the pending map must be SKIPPED by
    # the EOF drain (set_exception on a done future would raise InvalidStateError).
    transport = _QueueTransport()
    runner, run_task = await _handshook_runner(transport)

    request = asyncio.create_task(
        runner.send_request("outbound.message", {"adapter_id": _ADAPTER_ID}, timeout=5.0)
    )
    await _wait_for_request_frame(transport)

    request.cancel()
    with pytest.raises(asyncio.CancelledError):
        await request

    # Clean EOF drains the map; the already-cancelled future is skipped, not
    # re-failed, and the pump ends cleanly.
    transport.push(None)
    await run_task
    assert runner._pending == {}


# ---------------------------------------------------------------------------
# PR-S4-11b Wave 4: run() splits into start_and_handshake() + pump()
# ---------------------------------------------------------------------------


async def test_start_and_handshake_spawns_and_completes_without_pumping() -> None:
    """``start_and_handshake`` spawns + runs the handshake but never pumps.

    The daemon boot path awaits this FIRST so a broken adapter's spawn/handshake
    failure refuses the boot, BEFORE the long-lived pump is committed to the
    supervisor TaskGroup. A notification scripted after the handshake must NOT be
    consumed by ``start_and_handshake`` — only :meth:`pump` reads notifications.
    """
    inbound_handler = _RecordingHandler()
    transport = _FakeTransport([dict(_HANDSHAKE_OK), _inbound_frame()])
    session = await _make_session(
        gate=make_permissive_fixture_gate(),
        transport=transport,
        inbound_handler=inbound_handler,
    )
    session._inbound_handler = inbound_handler  # type: ignore[assignment]
    runner = CommsPluginRunner(session=session, transport=transport, adapter_id=_ADAPTER_ID)

    await runner.start_and_handshake()

    assert transport.spawned is True
    assert transport.sent[0]["method"] == "lifecycle.start"
    assert session._handshake_complete is True
    # The pump never ran, so the scripted inbound notification was not consumed.
    assert inbound_handler.processed == []
    assert transport.closed is False


async def test_start_and_handshake_raises_on_not_ok_without_closing() -> None:
    """A not-ok handshake raises :class:`PluginError` out of ``start_and_handshake``.

    The daemon maps this raise onto ``_refuse_boot``. Teardown (transport close)
    is the daemon's job on the refusal path / the ``run`` composition's
    ``finally`` — ``start_and_handshake`` itself does not own the close.
    """
    transport = _FakeTransport([{"jsonrpc": "2.0", "id": 0, "result": {"ok": False}}])
    session = await _make_session(
        gate=make_permissive_fixture_gate(),
        transport=transport,
        inbound_handler=_RecordingHandler(),
    )
    runner = CommsPluginRunner(session=session, transport=transport, adapter_id=_ADAPTER_ID)

    with pytest.raises(PluginError):
        await runner.start_and_handshake()


async def test_pump_then_clean_eof_after_separate_handshake() -> None:
    """After a separate ``start_and_handshake``, ``pump`` consumes notifications.

    Proves the daemon's two-phase call shape (``start_and_handshake`` then
    ``register_plugin_task(runner.pump())``) routes notifications identically to
    the merged ``run``.
    """
    inbound_handler = _RecordingHandler()
    transport = _FakeTransport([dict(_HANDSHAKE_OK), _inbound_frame()])
    session = await _make_session(
        gate=make_permissive_fixture_gate(),
        transport=transport,
        inbound_handler=inbound_handler,
    )
    session._inbound_handler = inbound_handler  # type: ignore[assignment]
    runner = CommsPluginRunner(session=session, transport=transport, adapter_id=_ADAPTER_ID)

    await runner.start_and_handshake()
    await runner.pump()

    assert len(inbound_handler.processed) == 1
    # pump's own teardown closes the transport (it owns the steady-state lifetime).
    assert transport.closed is True


# ---------------------------------------------------------------------------
# PR-S4-11b DEFECT 1: pump() observes the supervisor shutdown signal so a
# graceful drain exits promptly instead of force-cancelling after 10s.
# ---------------------------------------------------------------------------


async def test_pump_returns_promptly_when_shutdown_event_set() -> None:
    """A set shutdown_event ends the pump even though ``read_frame`` is blocked.

    The production force-cancel bug: the pump loops on ``read_frame()`` which
    never returns on its own, so the supervisor's graceful-drain budget always
    expires and force-cancels. Wiring the supervisor's shutdown ``Event`` into
    the runner lets the pump race ``read_frame()`` against ``shutdown_event``
    and return promptly on shutdown — a clean stop, no frame loss (we are
    shutting down), transport closed via the existing ``finally``.
    """
    transport = _QueueTransport()  # read_frame blocks on an empty queue
    shutdown_event = asyncio.Event()
    session = await _make_session(
        gate=make_permissive_fixture_gate(),
        transport=transport,
        inbound_handler=_RecordingHandler(),
    )
    runner = CommsPluginRunner(
        session=session,
        transport=transport,
        adapter_id=_ADAPTER_ID,
        shutdown_event=shutdown_event,
    )
    transport.push(dict(_HANDSHAKE_OK))
    await runner.start_and_handshake()

    pump_task = asyncio.create_task(runner.pump())
    # The pump is now blocked on read_frame (empty queue). Signal shutdown.
    await asyncio.sleep(0)
    assert not pump_task.done()
    shutdown_event.set()

    # The pump must end promptly — not hang on the blocked read_frame.
    await asyncio.wait_for(pump_task, timeout=1.0)
    assert transport.closed is True
    assert runner._pending == {}


async def test_pump_drains_in_flight_request_on_shutdown() -> None:
    """A shutdown while a send_request is in flight fails the awaiter loudly.

    Shutting down mid-conversation must not leave a ``send_request`` awaiter
    hung — the existing teardown drain (``_fail_all_pending``) covers the
    shutdown exit the same way it covers EOF / crash.
    """
    transport = _QueueTransport()
    shutdown_event = asyncio.Event()
    session = await _make_session(
        gate=make_permissive_fixture_gate(),
        transport=transport,
        inbound_handler=_RecordingHandler(),
    )
    runner = CommsPluginRunner(
        session=session,
        transport=transport,
        adapter_id=_ADAPTER_ID,
        shutdown_event=shutdown_event,
    )
    transport.push(dict(_HANDSHAKE_OK))
    await runner.start_and_handshake()

    pump_task = asyncio.create_task(runner.pump())
    request = asyncio.create_task(
        runner.send_request("outbound.message", {"adapter_id": _ADAPTER_ID}, timeout=5.0)
    )
    await _wait_for_request_frame(transport)

    shutdown_event.set()
    with pytest.raises(PluginError):
        await request
    await asyncio.wait_for(pump_task, timeout=1.0)
    assert transport.closed is True
    assert runner._pending == {}


async def test_pump_already_set_shutdown_event_does_not_read() -> None:
    """A shutdown_event already set before pump() starts ends it without reading.

    Edge: the supervisor's drain may set the event before the pump task is even
    scheduled. The pump must observe it on the first loop iteration and return
    without consuming a frame.
    """
    transport = _QueueTransport()
    shutdown_event = asyncio.Event()
    session = await _make_session(
        gate=make_permissive_fixture_gate(),
        transport=transport,
        inbound_handler=_RecordingHandler(),
    )
    runner = CommsPluginRunner(
        session=session,
        transport=transport,
        adapter_id=_ADAPTER_ID,
        shutdown_event=shutdown_event,
    )
    transport.push(dict(_HANDSHAKE_OK))
    await runner.start_and_handshake()

    # A notification is queued, but shutdown is already set: it must NOT be read.
    transport.push(_inbound_frame())
    shutdown_event.set()
    await asyncio.wait_for(runner.pump(), timeout=1.0)
    assert transport.closed is True


async def test_pump_with_shutdown_event_routes_frames_then_eof() -> None:
    """With shutdown_event wired but unset, frames route normally and EOF ends.

    Covers the read-won-the-race arm: the race resolves on the read side, the
    frame flows into the dispatcher exactly as a bare ``read_frame`` await would,
    and a clean EOF still terminates the pump. The shutdown plumbing is inert
    while the event stays unset.
    """
    inbound_handler = _RecordingHandler()
    transport = _QueueTransport()
    shutdown_event = asyncio.Event()  # never set in this test
    session = await _make_session(
        gate=make_permissive_fixture_gate(),
        transport=transport,
        inbound_handler=inbound_handler,
    )
    session._inbound_handler = inbound_handler  # type: ignore[assignment]
    runner = CommsPluginRunner(
        session=session,
        transport=transport,
        adapter_id=_ADAPTER_ID,
        shutdown_event=shutdown_event,
    )
    transport.push(dict(_HANDSHAKE_OK))
    await runner.start_and_handshake()

    transport.push(_inbound_frame())
    transport.push(None)  # clean EOF
    await asyncio.wait_for(runner.pump(), timeout=1.0)

    assert len(inbound_handler.processed) == 1
    assert transport.closed is True


async def test_pump_force_cancel_during_race_tears_transport_down() -> None:
    """A force-cancel while the pump races read-vs-shutdown still closes cleanly.

    Covers the cancellation arm of the read/shutdown race (the supervisor's
    drain-timeout force-cancel escalation): the in-flight ``asyncio.wait`` is
    cancelled, both child tasks are cancelled (no leak), the CancelledError
    propagates, and the pump's ``finally`` still closes the transport
    (cancellation-safety, CLAUDE.md hard rule #7).
    """
    transport = _QueueTransport()  # read_frame blocks on an empty queue
    shutdown_event = asyncio.Event()  # left unset: the read side blocks
    session = await _make_session(
        gate=make_permissive_fixture_gate(),
        transport=transport,
        inbound_handler=_RecordingHandler(),
    )
    runner = CommsPluginRunner(
        session=session,
        transport=transport,
        adapter_id=_ADAPTER_ID,
        shutdown_event=shutdown_event,
    )
    transport.push(dict(_HANDSHAKE_OK))
    await runner.start_and_handshake()

    pump_task = asyncio.create_task(runner.pump())
    await asyncio.sleep(0)  # let the pump enter the read/shutdown race
    assert not pump_task.done()

    pump_task.cancel()  # the supervisor's force-cancel escalation
    with pytest.raises(asyncio.CancelledError):
        await pump_task
    assert transport.closed is True
    assert runner._pending == {}


async def test_pump_without_shutdown_event_still_pumps_to_eof() -> None:
    """Omitting shutdown_event preserves the legacy EOF-terminated pump.

    The substrate / legacy callers construct the runner with no shutdown event;
    they must keep ending on clean EOF exactly as before (back-compat for the
    optional kwarg).
    """
    inbound_handler = _RecordingHandler()
    transport = _FakeTransport([dict(_HANDSHAKE_OK), _inbound_frame()])
    session = await _make_session(
        gate=make_permissive_fixture_gate(),
        transport=transport,
        inbound_handler=inbound_handler,
    )
    session._inbound_handler = inbound_handler  # type: ignore[assignment]
    runner = CommsPluginRunner(session=session, transport=transport, adapter_id=_ADAPTER_ID)

    await runner.run()

    assert len(inbound_handler.processed) == 1
    assert transport.closed is True


async def test_send_request_send_failure_pops_pending_and_fails_awaiter() -> None:
    """FIX 3: a send() that raises must not leak the pending entry.

    ``send_request`` registers the future in ``_pending`` BEFORE awaiting the
    transport send. If the send raises (broken pipe), the prior code left the
    future stranded in ``_pending`` — a leak plus a never-resolved awaiter (the
    timeout-cleanup + EOF drain are both skipped, the send never reached the
    wire). The fix pops the entry and fails the future before re-raising.
    """
    transport = _QueueTransport()
    runner, run_task = await _handshook_runner(transport)

    async def _boom_send(_frame: Mapping[str, object]) -> None:
        raise BrokenPipeError("write end closed")

    transport.send = _boom_send  # type: ignore[method-assign]

    with pytest.raises(BrokenPipeError):
        await runner.send_request("outbound.message", {"adapter_id": _ADAPTER_ID})

    # No leak: the pending map is empty, so the pump's drain has nothing to fail
    # and no late response could resolve a Future no one awaits.
    assert runner._pending == {}

    transport.push(None)
    await run_task


async def test_correlated_error_frame_fails_request_loudly() -> None:
    """FIX 4: a JSON-RPC error frame must FAIL the awaiter, not resolve to {}.

    The pump correlated every matching-id response to ``frame["result"]`` (or
    ``{}``), silently turning a plugin ``{"error": {...}}`` into a successful
    empty result. The fix fails the pending future with a PluginError carrying
    no raw wire bytes.
    """
    transport = _QueueTransport()
    runner, run_task = await _handshook_runner(transport)

    request = asyncio.create_task(
        runner.send_request("outbound.message", {"adapter_id": _ADAPTER_ID}, timeout=5.0)
    )
    sent = await _wait_for_request_frame(transport)
    req_id = sent["id"]

    transport.push(
        {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32000, "message": "plugin sad"}}
    )
    with pytest.raises(PluginError) as exc_info:
        await request
    # No raw wire bytes (closed-vocab i18n message): the plugin's error text
    # must never leak into the host-side error string (spec §5.6).
    assert "plugin sad" not in str(exc_info.value)

    transport.push(None)
    await run_task
    assert runner._pending == {}


async def test_correlated_response_without_result_fails_loudly() -> None:
    """FIX 4: a malformed response (no result, no error) fails loudly, not {}.

    A frame correlated by id but carrying NEITHER ``result`` NOR ``error`` is a
    protocol violation; resolving it to a silent ``{}`` would let a malformed
    plugin masquerade a failure as a successful empty ack.
    """
    transport = _QueueTransport()
    runner, run_task = await _handshook_runner(transport)

    request = asyncio.create_task(
        runner.send_request("outbound.message", {"adapter_id": _ADAPTER_ID}, timeout=5.0)
    )
    sent = await _wait_for_request_frame(transport)
    req_id = sent["id"]

    # No "result" and no "error" key — malformed.
    transport.push({"jsonrpc": "2.0", "id": req_id})
    with pytest.raises(PluginError):
        await request

    transport.push(None)
    await run_task
    assert runner._pending == {}


# ---------------------------------------------------------------------------
# PR-S4-11b concurrency fix: a notification handler that itself issues a
# host -> plugin ``send_request`` must NOT deadlock the single reader on its own
# response. Pre-fix the pump ``await``ed the whole dispatch inline, so the reader
# could never read+resolve the outbound ack the in-flight dispatch was awaiting:
# ``send_request`` timed out every turn and any concurrent request flaked. The
# fix dispatches notifications as bounded background tasks so the reader stays
# free to resolve response frames while a dispatch is in flight.
# ---------------------------------------------------------------------------


class _ReentrantOutboundHandler:
    """An inbound handler that, on ``process``, issues a host -> plugin request.

    Models the production reentrancy: ``InboundMessageHandler.process`` ->
    ``CommsInboundOrchestratorAdapter.dispatch`` -> ``send_outbound`` ->
    ``runner.send_request("outbound.message", ...)``. The handler awaits the
    response — which only the runner's single reader can resolve — so the reader
    MUST stay free while this dispatch is in flight or the request deadlocks.
    """

    def __init__(self, *, runner_box: dict[str, CommsPluginRunner]) -> None:
        self._runner_box = runner_box
        self.processed: list[object] = []
        self.outbound_result: Mapping[str, object] | None = None

    async def process(self, notification: object) -> None:
        self.processed.append(notification)
        runner = self._runner_box["runner"]
        self.outbound_result = await runner.send_request(
            "outbound.message",
            {"adapter_id": _ADAPTER_ID, "target_platform_id": "discord:42", "body": {}},
        )


async def test_reentrant_outbound_in_handler_does_not_deadlock_reader() -> None:
    """A notification whose handler ``send_request``s resolves, not times out.

    This is the load-bearing regression for the PR-S4-11b deadlock. The reader
    reads the ``inbound.message`` notification and (post-fix) dispatches it as a
    task while it KEEPS READING. The handler's reentrant ``send_request`` registers
    a pending future; the reader then reads the NEXT frame — the matching
    ``outbound.message`` response — and resolves that future. Pre-fix the reader
    was blocked inside the inline dispatch, the response was never read, and the
    handler's ``send_request`` timed out (the deadlock the e2e flake exposed).
    """
    transport = _QueueTransport()
    runner_box: dict[str, CommsPluginRunner] = {}
    handler = _ReentrantOutboundHandler(runner_box=runner_box)
    session = await _make_session(
        gate=make_permissive_fixture_gate(),
        transport=transport,
        inbound_handler=handler,
    )
    session._inbound_handler = handler  # type: ignore[assignment]
    runner = CommsPluginRunner(session=session, transport=transport, adapter_id=_ADAPTER_ID)
    runner_box["runner"] = runner

    transport.push(dict(_HANDSHAKE_OK))
    run_task = asyncio.create_task(runner.run())
    for _ in range(100):
        await asyncio.sleep(0)
        if session._handshake_complete:
            break
    assert session._handshake_complete is True

    # Feed the inbound notification; its handler will issue an outbound request.
    transport.push(_inbound_frame())

    # Wait for the handler to have emitted its outbound.message request frame.
    sent = await asyncio.wait_for(_wait_for_request_frame(transport), timeout=1.0)
    req_id = sent["id"]

    # The plugin answers the outbound request. The reader — which post-fix is NOT
    # blocked inside the handler dispatch — must read + resolve it, unblocking the
    # handler. Pre-fix the reader is stuck and this response is never consumed.
    transport.push({"jsonrpc": "2.0", "id": req_id, "result": {"platform_message_id": "m-1"}})

    # The whole turn completes within a tight bound (no 30s send_request timeout).
    async def _await_handled() -> None:
        for _ in range(1000):
            await asyncio.sleep(0)
            if handler.outbound_result is not None:
                return
        raise AssertionError("handler outbound never resolved (reader deadlocked)")

    await asyncio.wait_for(_await_handled(), timeout=1.0)
    assert handler.outbound_result == {"platform_message_id": "m-1"}
    assert len(handler.processed) == 1

    transport.push(None)  # clean EOF ends the pump
    await asyncio.wait_for(run_task, timeout=1.0)
    assert transport.closed is True
    assert runner._pending == {}


async def test_pump_drains_in_flight_dispatch_tasks_on_eof() -> None:
    """A dispatch task still running at EOF is awaited (not leaked) by teardown.

    The reader spawns notification dispatch as background tasks; the pump must
    drain them on exit so no task leaks past ``pump`` and the transport close in
    the ``finally`` does not race a still-running handler. Here the handler blocks
    on an event the test controls: EOF arrives while the dispatch is mid-flight,
    and ``pump`` must await the in-flight task before returning.
    """
    transport = _QueueTransport()
    gate_event = asyncio.Event()
    released: list[str] = []

    class _BlockingHandler:
        async def process(self, notification: object) -> None:
            await gate_event.wait()
            released.append("done")

    handler = _BlockingHandler()
    session = await _make_session(
        gate=make_permissive_fixture_gate(),
        transport=transport,
        inbound_handler=handler,
    )
    session._inbound_handler = handler  # type: ignore[assignment]
    runner = CommsPluginRunner(session=session, transport=transport, adapter_id=_ADAPTER_ID)

    transport.push(dict(_HANDSHAKE_OK))
    run_task = asyncio.create_task(runner.run())
    for _ in range(100):
        await asyncio.sleep(0)
        if session._handshake_complete:
            break

    transport.push(_inbound_frame())  # spawns a dispatch task that blocks
    # Let the reader pick up the notification + spawn the dispatch task.
    for _ in range(50):
        await asyncio.sleep(0)
        if runner._inflight:
            break
    assert runner._inflight, "dispatch task was not tracked in-flight"

    transport.push(None)  # clean EOF — the pump must DRAIN the in-flight task
    await asyncio.sleep(0)
    assert not run_task.done(), "pump returned before draining the in-flight dispatch"

    gate_event.set()  # release the blocked handler
    await asyncio.wait_for(run_task, timeout=1.0)
    assert released == ["done"]
    assert runner._inflight == set()
    assert transport.closed is True


async def test_pump_cancels_in_flight_dispatch_tasks_on_force_cancel() -> None:
    """A force-cancel of the pump cancels in-flight dispatch tasks (no leak).

    The supervisor's drain-timeout escalation cancels the pump task. Any dispatch
    task still running must be cancelled by the teardown so it does not outlive
    the pump; the transport is still closed in the ``finally``.
    """
    transport = _QueueTransport()
    never = asyncio.Event()  # never set: the handler blocks forever

    class _ForeverHandler:
        async def process(self, notification: object) -> None:
            await never.wait()

    handler = _ForeverHandler()
    session = await _make_session(
        gate=make_permissive_fixture_gate(),
        transport=transport,
        inbound_handler=handler,
    )
    session._inbound_handler = handler  # type: ignore[assignment]
    runner = CommsPluginRunner(session=session, transport=transport, adapter_id=_ADAPTER_ID)

    transport.push(dict(_HANDSHAKE_OK))
    run_task = asyncio.create_task(runner.run())
    for _ in range(100):
        await asyncio.sleep(0)
        if session._handshake_complete:
            break

    transport.push(_inbound_frame())
    for _ in range(50):
        await asyncio.sleep(0)
        if runner._inflight:
            break
    inflight = set(runner._inflight)
    assert inflight, "dispatch task was not tracked in-flight"

    run_task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await run_task
    # The dispatch task was cancelled by teardown, not leaked.
    assert all(task.cancelled() for task in inflight)
    assert runner._inflight == set()
    assert transport.closed is True


async def test_concurrent_request_resolves_while_dispatch_in_flight() -> None:
    """A concurrent ``send_request`` resolves even while a dispatch is in flight.

    The e2e flake's second symptom: an ``adapter.health`` request issued while an
    inbound dispatch is mid-flight must NOT be starved. The reader resolves BOTH
    responses regardless of order because dispatch no longer blocks it.
    """
    transport = _QueueTransport()
    gate_event = asyncio.Event()

    class _BlockingHandler:
        async def process(self, notification: object) -> None:
            await gate_event.wait()

    handler = _BlockingHandler()
    session = await _make_session(
        gate=make_permissive_fixture_gate(),
        transport=transport,
        inbound_handler=handler,
    )
    session._inbound_handler = handler  # type: ignore[assignment]
    runner = CommsPluginRunner(session=session, transport=transport, adapter_id=_ADAPTER_ID)

    transport.push(dict(_HANDSHAKE_OK))
    run_task = asyncio.create_task(runner.run())
    for _ in range(100):
        await asyncio.sleep(0)
        if session._handshake_complete:
            break

    # An inbound notification whose handler blocks (occupies a dispatch task).
    transport.push(_inbound_frame())
    for _ in range(50):
        await asyncio.sleep(0)
        if runner._inflight:
            break
    assert runner._inflight

    # A concurrent host -> plugin request while the dispatch is blocked.
    health = asyncio.create_task(runner.send_request("adapter.health", {}, timeout=5.0))
    sent = await asyncio.wait_for(_wait_for_health_frame(transport), timeout=1.0)
    req_id = sent["id"]
    transport.push({"jsonrpc": "2.0", "id": req_id, "result": {"queue_depth": 3}})

    # The concurrent request resolves even though the dispatch is still blocked.
    assert await asyncio.wait_for(health, timeout=1.0) == {"queue_depth": 3}

    gate_event.set()  # release the dispatch
    transport.push(None)
    await asyncio.wait_for(run_task, timeout=1.0)
    assert runner._pending == {}
    assert runner._inflight == set()


async def test_notification_cap_applies_backpressure_then_drains() -> None:
    """At the in-flight cap, the next notification intake waits for capacity.

    Drives the ``_await_notification_capacity`` loop: with ``max_in_flight=1`` and
    a handler that blocks, the reader spawns the first dispatch task, then the
    SECOND notification's intake must block until the first frees a slot. Releasing
    the first lets the second run; both are processed (no frame dropped).
    """
    transport = _QueueTransport()
    gate_events = [asyncio.Event(), asyncio.Event()]
    processed: list[int] = []

    class _GatedHandler:
        def __init__(self) -> None:
            self._n = 0

        async def process(self, notification: object) -> None:
            idx = self._n
            self._n += 1
            await gate_events[idx].wait()
            processed.append(idx)

    handler = _GatedHandler()
    session = await _make_session(
        gate=make_permissive_fixture_gate(),
        transport=transport,
        inbound_handler=handler,
    )
    session._inbound_handler = handler  # type: ignore[assignment]
    runner = CommsPluginRunner(
        session=session,
        transport=transport,
        adapter_id=_ADAPTER_ID,
        max_in_flight_notifications=1,
    )

    transport.push(dict(_HANDSHAKE_OK))
    run_task = asyncio.create_task(runner.run())
    for _ in range(100):
        await asyncio.sleep(0)
        if session._handshake_complete:
            break

    transport.push(_inbound_frame())  # first dispatch task — fills the cap
    transport.push(_inbound_frame())  # second — its intake must block on capacity
    for _ in range(50):
        await asyncio.sleep(0)
        if len(runner._inflight) == 1:
            break
    # The cap is 1, so exactly one dispatch task is tracked; the reader is parked
    # in _await_notification_capacity for the second frame.
    assert len(runner._inflight) == 1

    gate_events[0].set()  # release the first; a slot frees, the second spawns
    for _ in range(50):
        await asyncio.sleep(0)
        if processed == [0] and len(runner._inflight) == 1:
            break
    assert processed == [0]
    assert len(runner._inflight) == 1  # the second is now in flight

    gate_events[1].set()
    transport.push(None)
    await asyncio.wait_for(run_task, timeout=1.0)
    assert processed == [0, 1]
    assert runner._inflight == set()


async def test_send_request_after_reader_stopped_fails_fast() -> None:
    """A reentrant ``send_request`` issued after the reader stopped fails fast.

    Closes the teardown race: a dispatch task that calls back into
    ``send_request`` while the pump is draining (reader gone) must not register a
    pending future no reader can resolve — it raises :class:`PluginError`
    immediately instead of hanging the drain.
    """
    transport = _QueueTransport()
    runner, run_task = await _handshook_runner(transport)

    # Simulate the reader having exited (the pump sets this before draining).
    runner._reader_stopped = True
    with pytest.raises(PluginError):
        await runner.send_request("outbound.message", {"adapter_id": _ADAPTER_ID})
    # No future was registered — nothing to leak.
    assert runner._pending == {}

    runner._reader_stopped = False
    transport.push(None)
    await run_task


async def test_run_still_composes_start_and_handshake_then_pump() -> None:
    """``run()`` is preserved as ``start_and_handshake()`` + ``pump()``.

    The substrate integration test still drives ``run()``; this asserts the
    composition so the merged entry point keeps behaving identically.
    """
    inbound_handler = _RecordingHandler()
    transport = _FakeTransport([dict(_HANDSHAKE_OK), _inbound_frame()])
    session = await _make_session(
        gate=make_permissive_fixture_gate(),
        transport=transport,
        inbound_handler=inbound_handler,
    )
    session._inbound_handler = inbound_handler  # type: ignore[assignment]
    runner = CommsPluginRunner(session=session, transport=transport, adapter_id=_ADAPTER_ID)

    calls: list[str] = []
    original_handshake = runner.start_and_handshake
    original_pump = runner.pump

    async def _tracked_handshake() -> None:
        calls.append("start_and_handshake")
        await original_handshake()

    async def _tracked_pump() -> None:
        calls.append("pump")
        await original_pump()

    runner.start_and_handshake = _tracked_handshake  # type: ignore[method-assign]
    runner.pump = _tracked_pump  # type: ignore[method-assign]

    await runner.run()

    assert calls == ["start_and_handshake", "pump"]
    assert len(inbound_handler.processed) == 1
    assert transport.closed is True
