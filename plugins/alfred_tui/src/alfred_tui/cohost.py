"""Co-host harness: one asyncio program runs Textual + the socket wire (ADR-0031).

PR-S4-237-2 (#237) flips ``alfred chat`` to **Shape A**: the foreground TUI runs
IN ITS OWN process (no launcher subprocess) as one asyncio program co-hosting two
long-lived tasks — the Textual app and a socket-carried serve loop — under a single
:class:`asyncio.TaskGroup`.

**The TUI is the PLUGIN end of the wire.** Over the socket, the DAEMON runs the
host-side :class:`alfred.plugins.comms_runner.CommsPluginRunner` (it SENDS
``lifecycle.start`` / ``outbound.message`` *requests* and RECEIVES
``inbound.message`` *notifications*). So this side ANSWERS those requests via
:meth:`alfred_tui.server.TuiServer.dispatch` and EMITS ``inbound.message``
notifications — exactly what the daemon-spawned stdio carrier did, only the carrier
is now the dialed socket. This side does NOT use ``CommsPluginRunner``.

**Why one loop.** Textual's blocking ``App.run()`` would own the loop; the wire task
could never run. The co-host uses Textual's async entry ``App.run_async()`` (a
coroutine) so Textual co-exists on the same running loop as the wire's ``read_frame``
pump. Both halves are await-dense and I/O-bound, so neither starves the other. The
wire pump reads the SOCKET ``StreamReader`` — never stdin (Textual owns the PTY).

**Teardown (CLAUDE.md hard rule #7) — SYMMETRIC.** Either half ending tears the other
down, so the operator never sees a live half-dead session:
- App ends (operator quits) → the wire task is cancelled and the transport closed.
- Wire crashes (daemon died / malformed frame) → the ``TaskGroup`` cancels the app
  task and re-raises LOUD; the operator sees a failure, never a silent hang.
- Wire ends on a CLEAN EOF (the daemon closed the socket — the likely path on a
  graceful ``alfred daemon stop``) → the app is shut down GRACEFULLY via Textual's
  ``app.exit()`` (resolving ``run_async()``), so the operator sees "daemon
  disconnected" rather than a live UI whose keystrokes silently go nowhere.

No leaked task or fd on any path.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import Any, Final, Protocol

import structlog

from alfred.comms_mcp.errors import DaemonUnavailableError
from alfred.comms_mcp.protocol import (
    LINK_RECONNECTING,
    LINK_RESTORED,
    LINK_UNAVAILABLE,
    TURN_FAILED,
    InboundMessageNotification,
    TurnFailedNotification,
    TurnFailureStage,
)
from alfred.plugins.comms_socket_transport import (
    CommsPeerAuthError,
    CommsSocketTransport,
    dial_comms_socket,
)
from alfred_tui.render import build_app
from alfred_tui.server import TuiServer
from alfred_tui.session import TuiSession

_log = structlog.get_logger(__name__)

# Plugin -> host notification method name (mirrors ``alfred_tui.server._NOTIFY_INBOUND``;
# the ADR-0024 method name appears LITERALLY on the wire).
_NOTIFY_INBOUND: Final[str] = "inbound.message"


class _AppLike(Protocol):
    """The structural seam the co-host needs from the Textual app.

    Binding to a Protocol (not the concrete :class:`alfred_tui.textual.app.AlfredTuiApp`)
    keeps the co-host's task lifecycle testable with a recording double whose
    ``run_async`` resolves on command — no terminal mounted.

    ``exit`` is Textual's graceful shutdown: it resolves the pending ``run_async()``
    so the app task completes cleanly (the co-host calls it when the wire ends so the
    operator is not left in a live UI with a dead wire).
    """

    async def run_async(self) -> Any: ...

    def exit(self) -> None: ...

    def set_link_state(self, method: str) -> None:
        """Paint/clear the reconnect banner from a gateway ``link.*`` state method.

        A SYNCHRONOUS reactive set (the app mutates a Textual ``reactive``); the
        co-host calls it on the SAME loop as ``run_async()`` (one ``TaskGroup``),
        so there is no ``call_from_thread`` hop (M1).
        """
        ...

    def set_turn_failed(self, stage: TurnFailureStage) -> None:
        """Render/clear turn-failure feedback from a core ``turn.failed`` stage (#593).

        Protocol member only — Task 14 implements the real body on
        :class:`alfred_tui.textual.app.AlfredTuiApp`. Declared here so the co-host's
        wiring (and this task's tests) have a structural target to bind against
        before that lands.
        """
        ...


class _TransportLike(Protocol):
    """The three-awaitable carrier seam the wire serve loop drives (no ``spawn`` —
    the connection is already dialed).

    A subset of :class:`alfred.plugins.comms_runner._CommsTransportLike` (which also
    declares ``spawn`` for the daemon-spawned stdio carrier); here the socket is
    already connected, so a test can drive the loop with an in-memory frame-queue
    double over just ``send`` / ``read_frame`` / ``close``.
    """

    async def send(self, frame: Any) -> None: ...

    async def read_frame(self) -> Any: ...

    async def close(self) -> None: ...


type _Dial = Callable[[str], Awaitable[CommsSocketTransport]]
type _BuildApp = Callable[[TuiSession], _AppLike]

# A narrow allowlist of the gateway's client-TERMINAL link-state control frames
# (Spec A G3-3a / ADR-0031). These id-less notifications carry NO payload and NO
# ``adapter_id`` — they are pure STATE signals the pump routes to a banner callback
# the TUI renders via its own localized ``t("tui.banner.*")`` (``run_cohosted``
# wires it to ``AlfredTuiApp.set_link_state``). They are NOT relayed/dispatched/
# acked, and are NOT in ``TuiServer``'s method set.
_LINK_STATE_METHODS: Final[frozenset[str]] = frozenset(
    {LINK_RECONNECTING, LINK_RESTORED, LINK_UNAVAILABLE}
)

# The banner callback the pump invokes with the link-state METHOD string. Kept a
# bare ``str`` (the wire method) — the pump only routes the STATE; the banner TEXT
# (and its ``t()`` localization) is the app's job (``AlfredTuiApp.set_link_state``).
type _OnLinkState = Callable[[str], Awaitable[None]]


async def _noop_link_state(_state: str) -> None:
    """Default ``on_link_state``: drop the signal (no banner consumer wired yet).

    Keeps every existing caller behaviour-identical — a ``link.*`` frame is still
    recognised as client-terminal (never relayed/dispatched), it simply has no
    visible effect until the TUI wires a real banner callback.
    """


# The core's client-TERMINAL turn-state control frame (#593). Kept in its OWN
# branch rather than folded into `_LINK_STATE_METHODS`: this frame carries a
# PAYLOAD (the closed `stage` Literal) the pump must Pydantic-validate, whereas
# a `link.*` frame is method-only.
type _OnTurnFailed = Callable[[TurnFailureStage], Awaitable[None]]


async def _noop_turn_failed(_stage: TurnFailureStage) -> None:
    """Default: drop the signal (no turn-state consumer wired)."""


def _make_socket_inbound_sink(
    transport: _TransportLike,
) -> Callable[[InboundMessageNotification], Awaitable[None]]:
    """Build the session's inbound sink: write one ``inbound.message`` frame to the wire.

    Replaces the daemon-spawned stdio sink (``alfred_tui.server._stdout_inbound_sink``)
    — the carrier is now the dialed socket, so the operator's keystroke-batch
    notification crosses to the daemon over ``transport.send`` instead of stdout. The
    body is the SAME ``InboundMessageNotification`` shape the host scanner reads; the
    transport is a dumb carrier (no trust tagging here — T3 tagging happens host-side
    in ``process_inbound_message`` on receipt).
    """

    async def _sink(note: InboundMessageNotification) -> None:
        await transport.send(
            {
                "jsonrpc": "2.0",
                "method": _NOTIFY_INBOUND,
                "params": note.model_dump(mode="json"),
            }
        )

    return _sink


async def _serve_wire(
    transport: _TransportLike,
    server: TuiServer,
    *,
    on_link_state: _OnLinkState = _noop_link_state,
    on_turn_failed: _OnTurnFailed = _noop_turn_failed,
) -> None:
    """Read request frames off the socket, dispatch them, write responses back.

    The daemon-side runner SENDS ``lifecycle.start`` / ``adapter.health`` /
    ``outbound.message`` requests; this loop routes each through
    :meth:`TuiServer.dispatch` and writes the response frame back over the same
    carrier. Ends on a clean EOF (the daemon closed the socket — the likely path on
    a graceful ``alfred daemon stop``). A malformed frame raises ``CommsProtocolError``
    out of ``read_frame`` — propagated LOUD so the co-host's ``TaskGroup`` tears the
    app down rather than limping on a corrupt wire.

    The gateway's client-TERMINAL ``link.*`` control frames (Spec A G3-3a / ADR-0031)
    are routed by a NARROW ALLOWLIST *before* ``dispatch``: a frame whose ``method``
    is one of :data:`_LINK_STATE_METHODS` AND that carries NO ``id`` invokes
    ``on_link_state`` (the banner callback) and is NOT relayed/dispatched/acked. The
    allowlist is deliberately narrow on the METHOD — NOT a catch-all on "id-less": an
    id-less ``daemon.lifecycle.*`` (or any other unknown notification) is NOT a link
    signal and still falls through to the existing dispatch->``None`` skip below.

    ``link.*`` frames are spec'd id-LESS (pure STATE notifications). An id-BEARING
    ``link.*`` is a wire-contract violation: taking the banner branch for it would
    invoke the banner and ``continue`` WITHOUT answering the ``id`` — a silent drop of
    an id-bearing frame. So the banner branch is gated on ``"id" not in frame``; an
    id-bearing ``link.*`` is logged LOUD (``gateway.cohost.id_bearing_link_frame``) and
    falls through to the normal ``dispatch`` path (which answers/handles the ``id``)
    rather than being silently swallowed (CLAUDE.md hard rule #7).

    The core's client-TERMINAL ``turn.failed`` control frame (#593) is routed in its
    OWN branch, immediately after the ``link.*`` allowlist and before ``dispatch``:
    unlike ``link.*`` (method-only), this frame carries a PAYLOAD (the closed
    ``stage`` Literal) that must be Pydantic-validated. An id-bearing ``turn.failed``
    is the same wire-contract violation as an id-bearing ``link.*`` frame and is
    handled identically — logged LOUD and left to fall through to ``dispatch``
    rather than silently answered-and-dropped.

    ``server.dispatch`` returns a response frame for a well-formed REQUEST, but
    ``None`` for an id-less NOTIFICATION with an unknown method (Spec A G3-2 #237: the
    daemon now broadcasts ``daemon.lifecycle.*`` notifications onto this wire). So the
    response is sent ONLY when it is not ``None`` — a bare ``transport.send(None)``
    would write a malformed ``null`` frame back (architect C-2).
    """
    while True:
        frame = await transport.read_frame()
        if frame is None:
            # Clean EOF — the daemon closed the wire (e.g. graceful daemon stop). End
            # the pump; the caller's ``wire_task`` done-callback then gracefully exits
            # the app so the operator sees "daemon disconnected", not a silent hang.
            _log.info("comms.tui.wire_eof")
            return
        frame_dict = dict(frame)
        method = frame_dict.get("method")
        if isinstance(method, str) and method in _LINK_STATE_METHODS:
            if "id" in frame_dict:
                # Wire-contract violation: ``link.*`` is spec'd id-LESS. Taking the
                # banner branch here would invoke the banner + ``continue`` WITHOUT
                # answering the ``id`` — a SILENT drop of an id-bearing frame. Log
                # LOUD and fall through to ``dispatch`` (which answers/handles the
                # ``id``) instead of swallowing it (CLAUDE.md hard rule #7).
                _log.warning("gateway.cohost.id_bearing_link_frame", method=method)
            else:
                # Gateway link-state control frame — route to the banner callback and
                # STOP (client-terminal: never relayed/dispatched/acked). The narrow
                # method allowlist keeps a daemon.lifecycle.* / unknown notification on
                # the dispatch->``None`` skip path below.
                _log.info("comms.tui.link_state", state=method)
                await on_link_state(method)
                continue
        if method == TURN_FAILED:
            if "id" in frame_dict:
                # Same wire-contract violation shape as an id-bearing `link.*`
                # frame: taking this branch would `continue` WITHOUT answering
                # the id. Log LOUD and fall through to `dispatch` instead.
                _log.warning("comms.tui.id_bearing_turn_frame", method=method)
            else:
                # Validate AT THE WIRE: a forged/typo'd stage is a loud
                # ValidationError here, propagated exactly like a malformed frame
                # out of `read_frame` — never a silently-unrendered turn state.
                # The frame comes from the same-uid peer-authed core, so a bad
                # stage is a code defect, not something to swallow.
                note = TurnFailedNotification.model_validate(frame_dict.get("params") or {})
                _log.info("comms.tui.turn_failed", stage=note.stage)
                await on_turn_failed(note.stage)
                continue
        response = await server.dispatch(frame_dict)
        if response is not None:
            # An id-less notification (unknown method) dispatches to ``None`` — skip
            # the write so no malformed ``null`` reply goes back (architect C-2).
            await transport.send(response)


async def run_cohosted(
    *,
    adapter_id: str,
    dial: _Dial = dial_comms_socket,
    build_app_fn: _BuildApp = build_app,
    on_link_state: _OnLinkState = _noop_link_state,
    on_turn_failed: _OnTurnFailed = _noop_turn_failed,
) -> int:
    """Dial the daemon and co-host the Textual app + the socket serve loop.

    One asyncio program, one loop, two long-lived tasks under a single
    :class:`asyncio.TaskGroup`. Returns ``0`` on a clean operator quit.

    The ``dial`` / ``build_app_fn`` seams default to the production
    :func:`alfred.plugins.comms_socket_transport.dial_comms_socket` /
    :func:`alfred_tui.render.build_app`; tests inject in-memory doubles.

    ``on_link_state`` is the banner callback the wire pump invokes with a gateway
    ``link.*`` state method (Spec A G5 / ADR-0031). When a caller leaves it at the
    :func:`_noop_link_state` default (production), the co-host wires it to the
    constructed app's ``set_link_state`` so a ``link.*`` frame paints/clears the
    TUI's reconnect banner — a SAME-LOOP async call into a synchronous reactive set
    (M1: the pump and ``app.run_async()`` share one ``TaskGroup``/loop, so no
    ``call_from_thread``). A test may inject its own recording callback to keep the
    app/pump seam isolated.

    ``on_turn_failed`` is the parallel callback the wire pump invokes with a core
    ``turn.failed`` stage (#593). Wired IDENTICALLY to ``on_link_state``: left at the
    :func:`_noop_turn_failed` default (production), the co-host routes it to the
    constructed app's ``set_turn_failed``; a test may inject its own recording
    callback to keep the app/pump seam isolated.

    Construction order breaks the session<->app render-hook cycle: the session is
    built FIRST with the socket inbound sink, then ``build_app_fn`` cross-wires the
    app's ``write_outbound`` back as the session render hook. The dial happens before
    the ``TaskGroup`` so a daemon-absent failure raises out of HERE. The dial's
    ``OSError`` (no daemon reachable) AND its :class:`CommsPeerAuthError` (a same-uid
    socket the dialer cannot peer-authenticate — a planted-inode / uid-squat /
    wider-perm misconfig the dial-side ``SO_PEERCRED`` backstop refuses) are both
    wrapped as :class:`DaemonUnavailableError` (mapped by ``_chat_main`` to the
    daemon-required operator message + exit 3): an unauthenticable socket is, from the
    operator's seat, "no usable daemon socket". A stray post-dial ``OSError`` (PTY
    ioctl / broken render pipe) is NOT wrapped and surfaces LOUD rather than being
    mislabelled "daemon required".

    Teardown (CLAUDE.md hard rule #7) is SYMMETRIC: each half ending tears the other
    down. App ends (operator quit) → the wire task is cancelled. Wire ends — whether
    it crashed (``TaskGroup`` cancels the app + re-raises LOUD) or returned on a CLEAN
    EOF (daemon closed the socket) → the app is shut down GRACEFULLY via Textual's
    ``app.exit()``, so a graceful daemon stop surfaces as "daemon disconnected" rather
    than a live UI with a silently dead wire. The transport is closed on every path.
    """
    try:
        transport = await dial(adapter_id)
    except (OSError, CommsPeerAuthError) as exc:
        # The dial — and ONLY the dial — failing means no USABLE daemon socket is
        # reachable: either an OSError family member (no daemon listening) OR a
        # CommsPeerAuthError (a same-uid socket the dial-side SO_PEERCRED backstop
        # refused — a planted-inode / uid-squat / wider-perm misconfig). Wrap both so
        # ``_chat_main`` maps THIS typed condition (not a stray post-dial OSError) to
        # the daemon-required message + exit 3 — one clean operator line, no traceback.
        raise DaemonUnavailableError(adapter_id) from exc
    session = TuiSession(notify=_make_socket_inbound_sink(transport))
    app = build_app_fn(session)
    server = TuiServer(session=session)

    # Default wiring (production): route a gateway ``link.*`` state to the app's
    # banner. ``set_link_state`` is a SYNCHRONOUS reactive set on THIS loop (M1) — no
    # ``call_from_thread`` hop. A test that injected its own callback keeps it.
    link_state_cb: _OnLinkState = on_link_state
    if link_state_cb is _noop_link_state:

        async def _paint_banner(method: str) -> None:
            app.set_link_state(method)

        link_state_cb = _paint_banner

    # Default wiring (production): route a core ``turn.failed`` stage to the app's
    # turn-failure feedback. Same shape as the banner wiring above — a test that
    # injected its own callback keeps it.
    turn_failed_cb: _OnTurnFailed = on_turn_failed
    if turn_failed_cb is _noop_turn_failed:

        async def _render_turn_failed(stage: TurnFailureStage) -> None:
            app.set_turn_failed(stage)

        turn_failed_cb = _render_turn_failed

    try:
        async with asyncio.TaskGroup() as tg:
            app_task = tg.create_task(app.run_async())
            wire_task = tg.create_task(
                _serve_wire(
                    transport,
                    server,
                    on_link_state=link_state_cb,
                    on_turn_failed=turn_failed_cb,
                )
            )

            # The app task owns the lifecycle: when the operator quits, end the wire
            # pump too (it would otherwise block forever on the daemon's socket).
            app_task.add_done_callback(lambda _t: wire_task.cancel())

            # SYMMETRIC arm: when the wire ends — clean EOF (daemon closed the socket)
            # INCLUDED — gracefully exit the app so the operator is not stranded in a
            # live UI with a dead wire. ``app.exit()`` resolves ``run_async()``; guard
            # against a double-exit if the app already finished (then this is a no-op).
            wire_task.add_done_callback(lambda _t: app.exit() if not app_task.done() else None)
    finally:
        # Reap the carrier on EVERY exit path — clean quit, wire crash, or cancel —
        # so no fd leaks. ``close`` is idempotent.
        await transport.close()
    return 0


__all__ = ["run_cohosted"]
