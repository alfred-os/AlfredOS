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
