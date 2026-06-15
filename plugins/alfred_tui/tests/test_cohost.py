"""Co-host harness: Textual app + socket serve loop on one loop (ADR-0031 PR-2).

The TUI is the PLUGIN end of the wire: it ANSWERS the daemon's
``lifecycle.start`` / ``adapter.health`` / ``outbound.message`` requests via
``TuiServer.dispatch`` and EMITS ``inbound.message`` notifications. These cases
drive the serve loop with an in-memory frame-queue transport double and the
co-host lifecycle with a controllable app double — no terminal mounted (the
session/dispatch seam is the unit boundary, mirroring ``test_server_methods`` /
``test_render_wiring``).
"""

from __future__ import annotations

import asyncio
from typing import Any
from uuid import uuid4

import pytest
from alfred_tui.cohost import _make_socket_inbound_sink, _serve_wire, run_cohosted
from alfred_tui.server import TuiServer
from alfred_tui.session import TuiSession

from alfred.comms_mcp.errors import DaemonUnavailableError
from alfred.comms_mcp.protocol import OutboundMessageRequest
from alfred.plugins.comms_socket_transport import CommsPeerAuthError
from alfred.security.dlp import OutboundDlp, ScannedOutboundBody

pytestmark = pytest.mark.asyncio


def _scanned(text: str) -> ScannedOutboundBody:
    class _StubBroker:
        def redact(self, value: str) -> str:
            return value

    def _audit(*, event: str, subject: object) -> None: ...

    return OutboundDlp(broker=_StubBroker(), audit=_audit).scan_for_outbound(text)


class _FakeTransport:
    """In-memory frame-queue carrier double driving the wire serve loop.

    ``read_frame`` pops queued inbound (host -> plugin request) frames in order,
    returning ``None`` (clean EOF) once drained. ``send`` records every frame the
    plugin writes back (responses + ``inbound.message`` notifications).
    """

    def __init__(self, inbound: list[dict[str, Any]] | None = None) -> None:
        self._inbound: list[dict[str, Any] | None] = list(inbound or [])
        # A trailing EOF so a drained queue ends the pump rather than hanging.
        self._inbound.append(None)
        self.sent: list[dict[str, Any]] = []
        self.closed = False

    async def read_frame(self) -> dict[str, Any] | None:
        if not self._inbound:
            return None
        return self._inbound.pop(0)

    async def send(self, frame: Any) -> None:
        self.sent.append(dict(frame))

    async def close(self) -> None:
        self.closed = True


async def test_inbound_sink_writes_an_inbound_message_frame_to_the_transport() -> None:
    """A keystroke-batch flush produces one ``inbound.message`` frame on the wire."""
    transport = _FakeTransport()
    session = TuiSession(notify=_make_socket_inbound_sink(transport))
    await session.start(adapter_id="tui")
    await session.consume_user_input("hello daemon")
    await session.flush_keystroke_batch()

    assert len(transport.sent) == 1
    frame = transport.sent[0]
    assert frame["method"] == "inbound.message"
    assert frame["params"]["body"]["content"] == "hello daemon"


async def test_serve_loop_dispatches_lifecycle_start_and_responds_ok() -> None:
    """A ``lifecycle.start`` request is answered ``ok=True`` over the wire."""
    transport = _FakeTransport(
        inbound=[
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "lifecycle.start",
                "params": {
                    "adapter_id": "tui",
                    "credentials_ref": "n/a",
                    "policies_snapshot_hash": "deadbeef",
                },
            }
        ]
    )
    session = TuiSession()
    server = TuiServer(session=session)
    await _serve_wire(transport, server)

    assert len(transport.sent) == 1
    assert transport.sent[0]["id"] == 1
    assert transport.sent[0]["result"]["ok"] is True


async def test_serve_loop_routes_outbound_dm_into_render_outbound() -> None:
    """An ``outbound.message`` dm reaches ``session.render_outbound``."""
    rendered: list[str] = []
    session = TuiSession()
    session.set_render_hook(rendered.append)

    req = OutboundMessageRequest(
        adapter_id="tui",
        idempotency_key=uuid4(),
        target_platform_id="local-operator",
        body=_scanned("ack"),
        attachments_refs=(),
        addressing_mode="dm",
    )
    transport = _FakeTransport(
        inbound=[
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "outbound.message",
                "params": req.model_dump(mode="json"),
            }
        ]
    )
    server = TuiServer(session=session)
    await _serve_wire(transport, server)

    assert rendered == ["ack"]
    assert transport.sent[0]["result"]["outcome"] == "delivered"


async def test_serve_loop_refuses_non_dm_addressing_after_carrier_flip() -> None:
    """Out-of-scope refusal: a non-dm outbound still returns the typed terminal failure."""
    req = OutboundMessageRequest(
        adapter_id="tui",
        idempotency_key=uuid4(),
        target_platform_id="local-operator",
        body=_scanned("nope"),
        attachments_refs=(),
        addressing_mode="channel",
    )
    transport = _FakeTransport(
        inbound=[
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "outbound.message",
                "params": req.model_dump(mode="json"),
            }
        ]
    )
    server = TuiServer(session=TuiSession())
    await _serve_wire(transport, server)

    assert transport.sent[0]["result"]["outcome"] == "terminal_failure"
    assert transport.sent[0]["result"]["error_class"] == "tui_addressing_mode_not_supported"


async def test_serve_loop_ends_on_clean_eof_without_sending() -> None:
    """A clean EOF (empty queue) ends the pump with no response frames."""
    transport = _FakeTransport(inbound=[])
    await _serve_wire(transport, TuiServer(session=TuiSession()))
    assert transport.sent == []


async def test_serve_loop_handles_consecutive_requests() -> None:
    """The pump loops back after each response (two requests -> two responses)."""
    health = {"method": "adapter.health", "params": {"adapter_id": "tui"}}
    transport = _FakeTransport(
        inbound=[
            {"jsonrpc": "2.0", "id": 1, **health},
            {"jsonrpc": "2.0", "id": 2, **health},
        ]
    )
    await _serve_wire(transport, TuiServer(session=TuiSession()))
    assert [f["id"] for f in transport.sent] == [1, 2]


async def test_serve_loop_ignores_unknown_idless_notification_writes_nothing() -> None:
    """Spec A G3-2 (#237): a ``daemon.lifecycle.*`` notification is ignored, no reply.

    Drive the REAL ``_serve_wire`` loop with a daemon-broadcast ``ready``
    notification (NO ``id``). ``dispatch`` returns ``None`` and ``_serve_wire`` skips
    the write — so NO bytes go back. The fix targets the production receive loop, not
    just ``dispatch``: a bare ``transport.send(None)`` would write a malformed
    ``null`` frame (architect C-2).
    """
    transport = _FakeTransport(
        inbound=[
            {
                "jsonrpc": "2.0",
                "method": "daemon.lifecycle.ready",
                "params": {"epoch": "a" * 32},
            }
        ]
    )
    await _serve_wire(transport, TuiServer(session=TuiSession()))
    # No reply written for an id-less notification (no ``null`` frame, no error frame).
    assert transport.sent == []


async def test_serve_loop_still_replies_to_a_following_request() -> None:
    """A notification is skipped but a subsequent request is still answered.

    Guards that the ``response is None`` skip does not break the loop for the next
    real request (the lifecycle frame interleaves with the normal request stream).
    """
    transport = _FakeTransport(
        inbound=[
            {
                "jsonrpc": "2.0",
                "method": "daemon.lifecycle.going_down",
                "params": {"reason": "shutdown"},
            },
            {
                "jsonrpc": "2.0",
                "id": 9,
                "method": "adapter.health",
                "params": {"adapter_id": "tui"},
            },
        ]
    )
    await _serve_wire(transport, TuiServer(session=TuiSession()))
    assert [f.get("id") for f in transport.sent] == [9]


# ---------------------------------------------------------------------------
# Gateway ``link.*`` control frames -> banner callback (Spec A G5 / ADR-0031).
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "method",
    ["link.reconnecting", "link.restored", "link.unavailable"],
)
async def test_serve_loop_routes_link_control_frame_to_banner_callback(method: str) -> None:
    """A gateway ``link.*`` id-less frame invokes ``on_link_state`` (not ``dispatch``).

    The gateway sends id-less ``link.reconnecting`` / ``link.restored`` /
    ``link.unavailable`` STATE signals when the core link gaps/restores. The pump
    routes them to the banner callback via a NARROW allowlist BEFORE
    ``server.dispatch`` — they are client-terminal (no relay/ack). The server is a
    spy that fails the test if ``dispatch`` is ever reached for one.
    """
    states: list[str] = []

    async def _record(state: str) -> None:
        states.append(state)

    class _SpyServer:
        async def dispatch(self, request: dict[str, Any]) -> dict[str, Any] | None:
            raise AssertionError(f"link.* frame must not reach dispatch: {request!r}")

    transport = _FakeTransport(inbound=[{"jsonrpc": "2.0", "method": method, "params": {}}])
    await _serve_wire(transport, _SpyServer(), on_link_state=_record)  # type: ignore[arg-type]

    assert states == [method]
    assert transport.sent == []  # client-terminal: no reply/ack written back


async def test_serve_loop_request_still_routes_to_dispatch_with_link_callback() -> None:
    """A daemon REQUEST still routes through ``server.dispatch`` + a response is sent.

    The ``link.*`` allowlist must not touch the normal request path: an
    ``outbound.message`` dm still reaches ``dispatch`` and its response goes back —
    even when an ``on_link_state`` callback is wired in.
    """
    states: list[str] = []

    async def _record(state: str) -> None:
        states.append(state)

    session = TuiSession()
    session.set_render_hook(lambda _text: None)
    req = OutboundMessageRequest(
        adapter_id="tui",
        idempotency_key=uuid4(),
        target_platform_id="local-operator",
        body=_scanned("ack"),
        attachments_refs=(),
        addressing_mode="dm",
    )
    transport = _FakeTransport(
        inbound=[
            {
                "jsonrpc": "2.0",
                "id": 5,
                "method": "outbound.message",
                "params": req.model_dump(mode="json"),
            }
        ]
    )
    server = TuiServer(session=session)
    await _serve_wire(transport, server, on_link_state=_record)

    assert states == []  # a request is NOT a link-state signal
    assert transport.sent[0]["id"] == 5
    assert transport.sent[0]["result"]["outcome"] == "delivered"


async def test_serve_loop_daemon_lifecycle_notification_is_not_a_banner() -> None:
    """An id-less ``daemon.lifecycle.*`` notification keeps the EXISTING skip path.

    The allowlist is NARROW: only ``link.*`` becomes a banner. A daemon-lifecycle
    broadcast (also id-less, unknown method) still falls through to
    ``dispatch`` -> ``None`` -> skip — it does NOT invoke ``on_link_state``.
    """
    states: list[str] = []

    async def _record(state: str) -> None:
        states.append(state)

    transport = _FakeTransport(
        inbound=[
            {
                "jsonrpc": "2.0",
                "method": "daemon.lifecycle.ready",
                "params": {"epoch": "a" * 32},
            }
        ]
    )
    await _serve_wire(transport, TuiServer(session=TuiSession()), on_link_state=_record)

    assert states == []  # NOT a banner — the existing dispatch->None skip handled it
    assert transport.sent == []


async def test_serve_loop_arbitrary_unknown_idless_notification_is_not_a_banner() -> None:
    """An arbitrary unknown id-less notification is NOT a banner either (narrow allowlist)."""
    states: list[str] = []

    async def _record(state: str) -> None:
        states.append(state)

    transport = _FakeTransport(
        inbound=[{"jsonrpc": "2.0", "method": "some.unknown.notification", "params": {}}]
    )
    await _serve_wire(transport, TuiServer(session=TuiSession()), on_link_state=_record)

    assert states == []
    assert transport.sent == []


async def test_serve_loop_id_bearing_link_frame_is_not_silently_dropped() -> None:
    """An id-BEARING ``link.*`` frame is a wire-contract violation — NOT silently dropped.

    ``link.*`` are spec'd id-LESS pure-STATE notifications. A frame that carries an
    ``id`` AND a ``link.*`` method violates that contract: if the pump took the banner
    branch on the METHOD alone, it would invoke the banner + ``continue`` WITHOUT
    answering the ``id`` — a silent drop of an id-bearing frame (CLAUDE.md hard rule
    #7). FIX 2 gates the banner branch on ``"id" not in frame``, so an id-bearing
    ``link.*`` falls through to ``dispatch`` instead: it does NOT paint the banner, and
    the daemon's ``id`` IS answered (here, a ``Method not found`` for the unknown
    method). The frame is handled, never swallowed.
    """
    states: list[str] = []

    async def _record(state: str) -> None:
        states.append(state)

    transport = _FakeTransport(
        inbound=[{"jsonrpc": "2.0", "id": 9, "method": "link.reconnecting", "params": {}}]
    )
    await _serve_wire(transport, TuiServer(session=TuiSession()), on_link_state=_record)

    # NOT a banner — the id-bearing frame bypassed the banner allowlist.
    assert states == []
    # The id was ANSWERED (not silently dropped): dispatch wrote a response keyed on
    # the request id. ``link.reconnecting`` is an unknown plugin method, so the reply
    # is a JSON-RPC ``Method not found`` error — but the point is the id got a reply.
    assert len(transport.sent) == 1
    assert transport.sent[0]["id"] == 9
    assert transport.sent[0]["error"]["code"] == -32601  # Method not found


async def test_link_methods_are_absent_from_the_plugin_method_set() -> None:
    """``link.*`` is NOT in the plugin's closed method set (it is client-terminal).

    The ``link.*`` frames are routed by the pump's allowlist, never dispatched, so
    they must not be added to ``TuiServer.list_methods()`` — that set stays the four
    host->plugin request methods.
    """
    methods = TuiServer(session=TuiSession()).list_methods()
    assert "link.reconnecting" not in methods
    assert "link.restored" not in methods
    assert "link.unavailable" not in methods


# ---------------------------------------------------------------------------
# Co-host lifecycle — controllable app double.
# ---------------------------------------------------------------------------


class _FakeApp:
    """App double whose ``run_async`` blocks until ``finish()`` or ``exit()``.

    ``exit`` is Textual's graceful-shutdown analog: the co-host calls it when the wire
    ends so the app task resolves cleanly. It records the call (``exited``) and unblocks
    ``run_async`` exactly like ``finish``.
    """

    def __init__(self, session: TuiSession) -> None:
        self.session = session
        self._done = asyncio.Event()
        self.ran = False
        self.exited = False

    async def run_async(self) -> None:
        self.ran = True
        await self._done.wait()

    def finish(self) -> None:
        self._done.set()

    def exit(self) -> None:
        self.exited = True
        self._done.set()


class _CrashingApp:
    """App double whose ``run_async`` blocks forever (so the wire crash wins)."""

    def __init__(self, session: TuiSession) -> None:
        self.session = session

    async def run_async(self) -> None:
        await asyncio.Event().wait()  # never resolves

    def exit(self) -> None:  # pragma: no cover - the crash path raises before exit
        ...


async def test_cohost_app_quit_cancels_wire_and_closes_transport() -> None:
    """Operator quit: the app task ends -> wire task cancelled + transport closed."""
    # A wire that never EOFs on its own (so only the app-quit path can end it).
    transport = _BlockingReadTransport()
    fake_app_holder: dict[str, _FakeApp] = {}

    def _build(session: TuiSession) -> _FakeApp:
        app = _FakeApp(session)
        fake_app_holder["app"] = app
        return app

    async def _dial(_adapter_id: str) -> Any:
        return transport

    cohost_task = asyncio.ensure_future(
        run_cohosted(adapter_id="tui", dial=_dial, build_app_fn=_build)  # type: ignore[arg-type]
    )
    # Let the group spin up, then quit the app.
    await asyncio.sleep(0)
    await asyncio.sleep(0)
    assert fake_app_holder["app"].ran is True
    fake_app_holder["app"].finish()

    rc = await asyncio.wait_for(cohost_task, timeout=2.0)
    assert rc == 0
    assert transport.closed is True


async def test_cohost_wire_eof_shuts_down_app() -> None:
    """Clean EOF first (graceful daemon stop): the wire ends -> the app is shut down.

    The daemon closes the socket while the operator's app is still running. The wire
    pump returns on the clean EOF, and the SYMMETRIC teardown arm gracefully exits the
    app (``app.exit()`` -> ``run_async()`` resolves) so the operator is not stranded in
    a live UI with a dead wire. ``rc == 0`` and the transport is reaped.
    """
    transport = _FakeTransport(inbound=[])  # drains immediately to a clean EOF
    fake_app_holder: dict[str, _FakeApp] = {}

    def _build(session: TuiSession) -> _FakeApp:
        app = _FakeApp(session)
        fake_app_holder["app"] = app
        return app

    async def _dial(_adapter_id: str) -> Any:
        return transport

    rc = await asyncio.wait_for(
        run_cohosted(adapter_id="tui", dial=_dial, build_app_fn=_build),  # type: ignore[arg-type]
        timeout=2.0,
    )
    assert rc == 0
    assert fake_app_holder["app"].exited is True
    assert transport.closed is True


async def test_cohost_wire_crash_cancels_app_and_raises_loud() -> None:
    """Daemon died / malformed frame: the wire crash tears the app down + raises."""

    class _BoomError(RuntimeError):
        pass

    class _CrashOnReadTransport:
        def __init__(self) -> None:
            self.closed = False

        async def read_frame(self) -> Any:
            raise _BoomError("daemon socket died")

        async def send(self, frame: Any) -> None: ...

        async def close(self) -> None:
            self.closed = True

    transport = _CrashOnReadTransport()

    async def _dial(_adapter_id: str) -> Any:
        return transport

    with pytest.raises(BaseExceptionGroup) as excinfo:
        await asyncio.wait_for(
            run_cohosted(
                adapter_id="tui",
                dial=_dial,  # type: ignore[arg-type]
                build_app_fn=_CrashingApp,  # type: ignore[arg-type]
            ),
            timeout=2.0,
        )
    # The crash is surfaced LOUD (not swallowed), and the transport is reaped.
    assert any(isinstance(e, _BoomError) for e in excinfo.value.exceptions)
    assert transport.closed is True


async def test_cohost_dial_failure_wraps_oserror_as_daemon_unavailable() -> None:
    """A daemon-absent dial (OSError) is wrapped as DaemonUnavailableError before the group.

    ``run_cohosted`` wraps ONLY the dial's OSError so ``_chat_main`` maps THIS typed
    condition (not a stray post-dial OSError) to the daemon-required message + exit 3.
    The original OSError is preserved as ``__cause__`` for diagnosability.
    """

    async def _dial(_adapter_id: str) -> Any:
        raise ConnectionRefusedError("no daemon")

    with pytest.raises(DaemonUnavailableError) as excinfo:
        await run_cohosted(adapter_id="tui", dial=_dial, build_app_fn=_FakeApp)  # type: ignore[arg-type]
    assert isinstance(excinfo.value.__cause__, ConnectionRefusedError)


async def test_cohost_dial_peer_auth_failure_wraps_as_daemon_unavailable() -> None:
    """A dial that the SO_PEERCRED backstop refuses surfaces as daemon-unavailable.

    ``CommsPeerAuthError`` is a ``CommsProtocolError``/``AlfredError`` (NOT an
    ``OSError``), so a planted-inode / uid-squat / wider-perm misconfig dial would
    otherwise escape ``run_cohosted`` as a raw traceback. The co-host wraps it as
    :class:`DaemonUnavailableError` — a same-uid socket the dialer cannot
    peer-authenticate IS "no usable daemon socket" — so ``_chat_main`` maps it to the
    one clean daemon-required message + exit 3. The original is preserved as
    ``__cause__`` for diagnosability.
    """

    async def _dial(_adapter_id: str) -> Any:
        raise CommsPeerAuthError("dialed socket uid mismatch")

    with pytest.raises(DaemonUnavailableError) as excinfo:
        await run_cohosted(adapter_id="tui", dial=_dial, build_app_fn=_FakeApp)  # type: ignore[arg-type]
    assert isinstance(excinfo.value.__cause__, CommsPeerAuthError)


class _BlockingReadTransport:
    """A carrier whose ``read_frame`` blocks forever (only app-quit ends the pump)."""

    def __init__(self) -> None:
        self.closed = False

    async def read_frame(self) -> Any:
        await asyncio.Event().wait()  # never resolves

    async def send(self, frame: Any) -> None: ...

    async def close(self) -> None:
        self.closed = True
