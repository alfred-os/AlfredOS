"""``CommsPluginRunner`` — handshake + single-reader pump for a comms plugin.

PR-S4-11a Wave 1 (#237). The imperative shell that drives one comms-plugin
subprocess end to end: spawn the transport, run the ``lifecycle.start`` handshake
(which gates the capability check), then run the SINGLE-READER pump that fans
every plugin -> host notification into the session dispatcher, and finally tear
the transport down cleanly so a supervisor ``TaskGroup`` cancellation does not
leak a subprocess.

The session (:class:`alfred.plugins.session.AlfredPluginSession`) stays a pure
state machine — it owns the per-adapter dispatch semaphore, the err-007 breaker
counter, and every audit emit. The runner owns the I/O sequencing and the LOUD
error arms (CLAUDE.md hard rule #7):

* **Broken pipe / unexpected EOF mid-conversation** -> synthesize a closed-vocab
  ``adapter.crashed`` notification and route it through the session so the
  CrashHandler emits its audit row and the breaker can trip. The raw exception
  text is NEVER carried into the synthesized ``detail`` (spec §5.6).
* **Malformed frame** (:class:`CommsProtocolError`) -> log loudly + request a
  plugin restart via the supervisor. The wire is unusable, but the plugin is not
  (yet) known-crashed.
* **Handler exception** propagating from the session dispatch arm ->
  CATCH-AND-CONTINUE. The session already emitted ``COMMS_HANDLER_FAILED`` and
  owns the breaker threshold; the reader must survive a single handler failure
  (matching the session docstring: "the original exception propagates to the
  reader, which logs + continues").

**Single reader, non-blocking dispatch.** Once :meth:`run` owns the reader,
NOTHING else reads the stream — the handshake also reads via
:meth:`_CommsTransportLike.read_frame`, but strictly before the pump starts. The
reader must STAY FREE to read+resolve response frames while a notification's
handler is in flight, because a comms handler is REENTRANT: an ``inbound.message``
dispatch calls back into :meth:`send_request` (``InboundMessageHandler.process`` ->
``CommsInboundOrchestratorAdapter.dispatch`` -> ``outbound.message`` request) whose
response only the reader can resolve. So the pump dispatches each NOTIFICATION as
a tracked background task (:attr:`_inflight`) and keeps reading; a RESPONSE frame
is resolved inline by the reader. If the reader instead ``await``-ed the whole
dispatch (the pre-fix 11a shape), it would deadlock on its own outbound ack: the
in-flight ``send_request`` would time out every turn and any concurrent request
would stall. The session's per-adapter dispatch semaphore (entered INSIDE the
dispatch task) bounds concurrent handler execution; the reader never blocks on it.
Per-message independence means strict in-order processing is NOT required — the
inbound trust-boundary path produces an independent t3 row + ack per message — so
semaphore-bounded concurrency across notifications is correct.
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from contextlib import suppress
from typing import TYPE_CHECKING, Final, Protocol, runtime_checkable

import structlog

from alfred.i18n import t
from alfred.plugins.comms_seq_codec import SEQ_VERSION
from alfred.plugins.comms_stdio_transport import CommsProtocolError
from alfred.plugins.errors import PluginError

if TYPE_CHECKING:
    from alfred.plugins.session import AlfredPluginSession, _SupervisorLike

log = structlog.get_logger(__name__)

# The JSON-RPC id the runner stamps on its single ``lifecycle.start`` request.
# The handshake is one round-trip, so a constant id is sufficient — the runner
# matches the response by this id before the pump begins.
_LIFECYCLE_START_ID: Final[int] = 0

# The first id :meth:`CommsPluginRunner.send_request` allocates. 0 belongs to the
# lifecycle handshake (:data:`_LIFECYCLE_START_ID`); outbound request ids start at
# 1 so a response can never be mistaken for the handshake ack.
_FIRST_REQUEST_ID: Final[int] = 1

# Default per-request response deadline (seconds). An outbound request that the
# plugin never answers must not hang the host forever; :meth:`send_request`
# raises :class:`PluginError` once this elapses and drops the pending future.
_SEND_REQUEST_TIMEOUT_SECONDS: Final[float] = 30.0

# Mirrors ``Settings.comms_max_in_flight_notifications`` /
# ``session._DEFAULT_MAX_IN_FLIGHT`` (Field default 32). Caps the number of
# notification-dispatch tasks the pump tracks concurrently (see :meth:`_pump`).
# The daemon passes the live setting so the runner's task cap matches the
# session's dispatch-semaphore cap.
_DEFAULT_MAX_IN_FLIGHT_NOTIFICATIONS: Final[int] = 32

# Closed-vocabulary error_class + detail for the host-synthesized crash route.
# A broken pipe / mid-read EOF is a TRANSPORT-level crash; the runner names it
# from this closed vocab so a raw exception string (which could echo wire bytes)
# never reaches the CrashHandler's audit row.
_TRANSPORT_CRASH_ERROR_CLASS: Final[str] = "CommsTransportClosed"
_TRANSPORT_CRASH_DETAIL: Final[str] = "comms transport closed mid-conversation"

# Closed-vocab restart reason for a malformed-frame wire violation.
_MALFORMED_FRAME_RESTART_REASON: Final[str] = "malformed_frame"

# The transport-crash exception family the pump's read arm already handles. When
# a shutdown wins the race against an in-flight ``read_frame`` (PR-S4-11b DEFECT
# 1), we cancel + await that read and suppress these so a plugin that crashed
# right as we shut down does not raise out of the shutdown path — we are tearing
# the adapter down regardless.
_TRANSPORT_READ_EXCEPTIONS: Final[tuple[type[BaseException], ...]] = (
    BrokenPipeError,
    ConnectionResetError,
    asyncio.IncompleteReadError,
    EOFError,
    CommsProtocolError,
)


class _ShutdownSignalled(Exception):  # noqa: N818 — internal control signal, not an error
    """Internal control-flow signal: the supervisor shutdown event fired.

    Raised out of :meth:`CommsPluginRunner._read_frame_or_shutdown` when the
    shutdown wait wins its race against ``read_frame``. The pump catches it and
    returns; the ``finally`` in :meth:`CommsPluginRunner.pump` closes the
    transport. Never escapes the runner.
    """


@runtime_checkable
class _CommsTransportLike(Protocol):
    """Structural seam for the transport the runner drives.

    The runner binds to this shape rather than the concrete
    :class:`alfred.plugins.comms_stdio_transport.CommsStdioTransport` so a test
    can drive it with an in-memory frame queue and so the runner never reaches
    for transport internals beyond these four awaitables + the sync seq/ack flip.

    ``enable_seq_ack`` (Spec A G2 / ADR-0032) is a SYNC flip (it only sets a bool),
    not an awaitable like the other four. The runner calls it as a TYPED method
    after the ``lifecycle.start`` handshake negotiates ``AlfredSeqAck/1`` — never
    via ``getattr`` duck-typing — so every transport (and test fake) implements it.
    """

    async def spawn(self) -> None: ...

    async def send(self, frame: Mapping[str, object]) -> None: ...

    async def read_frame(self) -> Mapping[str, object] | None: ...

    async def close(self) -> None: ...

    def enable_seq_ack(self) -> None: ...


class CommsPluginRunner:
    """Owns ``(session, transport, adapter_id)`` and drives one comms plugin.

    Construct one per comms adapter; :meth:`run` is the single entry point and
    runs until the plugin's stdout reaches a clean EOF (or a fatal handshake
    failure). The runner is the imperative shell; the session is the state
    machine.
    """

    def __init__(
        self,
        *,
        session: AlfredPluginSession,
        transport: _CommsTransportLike,
        adapter_id: str,
        shutdown_event: asyncio.Event | None = None,
        max_in_flight_notifications: int = _DEFAULT_MAX_IN_FLIGHT_NOTIFICATIONS,
        boot_epoch: str | None = None,
    ) -> None:
        self._session = session
        self._transport = transport
        self._adapter_id = adapter_id
        # Spec A G3-2 (#237) — architect H-2: the non-secret per-boot epoch the
        # runner threads into the ``lifecycle.start`` handshake params alongside
        # ``seq_ack``. The G3-3 gateway reconciles core-liveness from the HANDSHAKE
        # epoch (the boot-``ready`` broadcast reaches zero senders in the normal
        # case — the socket peer connects on-demand later), so without this the
        # gateway has no epoch to bind its retained high-water to. ``None`` (the
        # stdio, daemon-spawned adapters) omits the key — the wire stays plain.
        self._boot_epoch = boot_epoch
        # PR-S4-11b DEFECT 1: the supervisor's graceful-drain signal. When the
        # daemon wires this (the supervisor's own ``_shutdown_event`` via
        # ``Supervisor.shutdown_event``), :meth:`pump` races ``read_frame`` against
        # it and returns PROMPTLY on a clean stop — instead of blocking forever on
        # an idle plugin's stream until the supervisor's drain budget expires and
        # force-cancels the pump (which recorded ``cancelled_with_errors``). A
        # graceful stop drops no frames: we are shutting the adapter down. ``None``
        # (legacy / substrate callers) preserves the EOF-only pump exactly.
        self._shutdown_event = shutdown_event
        # Outbound request/response correlation (Wave 1, #237). The transport has
        # no ``request()`` by design — the single-reader rule means only the pump
        # reads, so the runner OWNS the pending map: ``send_request`` registers a
        # Future under a fresh id; the pump resolves it when the matching response
        # frame arrives. Every error/close path drains this map so no awaiter ever
        # hangs (CLAUDE.md hard rule #7).
        self._pending: dict[int, asyncio.Future[Mapping[str, object]]] = {}
        self._next_request_id = _FIRST_REQUEST_ID
        # PR-S4-11b concurrency fix: notification dispatch runs as tracked
        # background tasks so the single reader never blocks on a reentrant
        # handler's ``send_request`` (see the module docstring). The set is the
        # drain/cancel surface for teardown — every spawned dispatch task lives
        # here until it completes (a done-callback discards it). Concurrent
        # handler EXECUTION is bounded by the session's per-adapter dispatch
        # semaphore (entered inside the dispatch); ``_max_in_flight`` caps the
        # number of tracked tasks the reader spawns before applying backpressure.
        self._inflight: set[asyncio.Task[None]] = set()
        self._max_in_flight = max_in_flight_notifications
        # Set once the reader loop has exited (any terminal arm) so a still-running
        # dispatch task's late reentrant ``send_request`` fails FAST instead of
        # registering a pending future no reader will ever resolve — which would
        # hang the teardown drain. Closes the post-snapshot race between a dispatch
        # task issuing a request and the pump's terminal ``_fail_all_pending``.
        self._reader_stopped = False
        # Spec A G2 (#237): whether the lifecycle.start handshake negotiated the
        # out-of-band seq/ack header. Flipped True only when BOTH the host
        # advertised it AND the plugin echoed it; drives transport.enable_seq_ack.
        self._seq_ack_negotiated = False

    async def send_request(
        self,
        method: str,
        params: Mapping[str, object],
        *,
        timeout: float = _SEND_REQUEST_TIMEOUT_SECONDS,
    ) -> Mapping[str, object]:
        """Send a host -> plugin JSON-RPC request and await its correlated result.

        Allocates a monotonic id, registers a pending Future, emits the request on
        the transport, and awaits the response the pump correlates back by id. The
        pump resolves the Future with the response frame's ``result`` mapping. On
        timeout the pending entry is dropped and :class:`PluginError` is raised so
        the caller never blocks on a plugin that goes silent. A transport
        crash / EOF while the request is in flight fails the Future loudly (see
        :meth:`_fail_all_pending`), surfacing as :class:`PluginError` here too.

        The runner is the SINGLE reader: ``send_request`` never reads the
        transport itself — it only ``send``s and awaits the Future the pump
        completes. Calling it before :meth:`run` has entered the pump is a
        programming error (no reader to resolve the Future); production wires it
        only after the readiness handshake.
        """
        if self._reader_stopped:
            # The reader has exited — no response can ever be read again, so a new
            # request would register a future that hangs the teardown drain. Fail
            # fast + loud rather than block forever (CLAUDE.md hard rule #7). This
            # is the late-dispatch reentrancy window: a handler that calls back in
            # while the pump is tearing down.
            log.warning(
                "comms.runner.send_request_after_reader_stopped",
                adapter_id=self._adapter_id,
                request_method=method,
            )
            raise PluginError(t("comms.runner.request_aborted", adapter_id=self._adapter_id))
        request_id = self._next_request_id
        self._next_request_id += 1
        loop = asyncio.get_running_loop()
        future: asyncio.Future[Mapping[str, object]] = loop.create_future()
        self._pending[request_id] = future
        # FIX 3 (PR-S4-11b review): the future is registered BEFORE the send so
        # the pump can correlate a response that races back. If the send itself
        # raises (broken pipe), the future would otherwise be stranded in
        # ``_pending`` — a leak whose awaiter never resolves (the timeout cleanup
        # + the pump's EOF/crash drain are both bypassed because the request never
        # reached the wire). Pop the entry + cancel the (un-awaited) future, then
        # re-raise so the caller sees the transport error loudly.
        try:
            await self._transport.send(
                {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}
            )
        except BaseException:
            self._pending.pop(request_id, None)
            future.cancel()
            raise
        try:
            return await asyncio.wait_for(future, timeout)
        except TimeoutError as exc:
            # Drop the orphaned pending entry so a late response cannot resolve a
            # Future no one awaits, and surface the timeout loudly.
            self._pending.pop(request_id, None)
            log.error(
                "comms.runner.send_request_timeout",
                adapter_id=self._adapter_id,
                request_method=method,
            )
            raise PluginError(
                t("comms.runner.request_timeout", adapter_id=self._adapter_id, method=method)
            ) from exc

    async def send_notification(self, method: str, params: Mapping[str, object]) -> None:
        """Send an id-less JSON-RPC NOTIFICATION (no response awaited).

        Unlike :meth:`send_request`, a notification carries NO ``id`` and registers
        NO pending future — the core announces lifecycle state
        (``daemon.lifecycle.ready`` / ``daemon.lifecycle.going_down``, Spec A G3-2)
        that the peer consumes without acking at the JSON-RPC layer. Writes through
        the single-writer-locked ``transport.send`` (C2) so it cannot interleave a
        concurrent ``send_request`` frame — the boot coroutine's lifecycle-send is a
        SECOND writer racing the pump's reentrant outbound acks. On a negotiated
        ``AlfredSeqAck/1`` wire the notification still occupies a seq slot (architect
        H-3): it rides IN-BAND in the seq stream, out-of-band only in JSON-RPC
        semantics; the gateway ``decode_seq_frame``s it then routes by ``method``.
        """
        await self._transport.send({"jsonrpc": "2.0", "method": method, "params": dict(params)})

    async def run(self) -> None:
        """Spawn, handshake, pump, then tear down — the full adapter lifecycle.

        Kept as the composition of :meth:`start_and_handshake` and :meth:`pump`
        (PR-S4-11b Wave 4) so the substrate integration test still drives one
        merged entry point. The daemon boot path instead calls the two halves
        separately: ``await start_and_handshake()`` (so a spawn/handshake failure
        REFUSES the boot before the long-lived pump is committed to the
        supervisor TaskGroup), then ``register_plugin_task(runner.pump())``.

        Raises :class:`PluginError` if the capability gate denies the load or the
        plugin never acknowledges the handshake; in both cases the transport is
        still closed (the ``finally`` in each half) so no subprocess leaks. On a
        clean run the method returns when the pump sees EOF.
        """
        await self.start_and_handshake()
        await self.pump()

    async def start_and_handshake(self) -> None:
        """Spawn the subprocess + run the readiness handshake — the boot half.

        The daemon awaits this BEFORE registering the long-lived pump so a broken
        adapter (spawn failure, gate denial, or a not-ok / absent handshake ack)
        raises :class:`PluginError` and the boot path can refuse fail-closed
        (CLAUDE.md hard rule #7) rather than park with a dead plugin.

        On SUCCESS the transport stays OPEN: ownership of the steady-state
        lifetime passes to :meth:`pump`, which closes it on EOF / crash / cancel.
        On FAILURE (any raise from spawn or the handshake) the transport is closed
        here so a half-spawned subprocess never leaks before the caller's refusal
        path runs; the pending-request map is drained for symmetry with
        :meth:`pump`'s teardown (it is empty this early, but the drain is cheap
        and keeps the invariant that no awaiter survives a teardown).
        """
        try:
            await self._transport.spawn()
            await self._handshake()
        except BaseException:
            self._fail_all_pending(reason="comms.runner.handshake_teardown")
            await self._transport.close()
            raise

    async def pump(self) -> None:
        """Run the single-reader pump until EOF, then tear the transport down.

        The steady-state half: owns the transport lifetime once
        :meth:`start_and_handshake` has handed off. The daemon schedules this as a
        supervised TaskGroup task; a supervisor cancellation funnels through the
        ``finally`` so the subprocess never leaks and no ``send_request`` awaiter
        is left hung.
        """
        try:
            await self._pump()
        except BaseException:
            # A force-cancel (supervisor drain-timeout escalation) or any other
            # raise tearing the pump down: the reader is gone, so a draining task's
            # late ``send_request`` must fail fast (flag) rather than hang. CANCEL
            # in-flight dispatch tasks so none outlives the pump (cancellation-
            # safety, CLAUDE.md hard rule #7). The ``finally`` still fails pending
            # request futures + closes the transport.
            self._reader_stopped = True
            await self._cancel_inflight_dispatches()
            raise
        else:
            # Clean exit (EOF / shutdown / malformed / crash arms all RETURN): the
            # reader is gone, so flag it (a draining task's late reentrant
            # ``send_request`` fails fast instead of hanging the drain), then DRAIN
            # the still-running dispatch tasks so none leaks and the transport close
            # below does not race a live handler. Each task already swallows a
            # single handler failure, so the drain is best-effort.
            self._reader_stopped = True
            await self._drain_inflight_dispatches()
        finally:
            # Fail any still-outstanding request Future loudly before the
            # transport goes away — a supervisor TaskGroup cancellation must not
            # leave an awaiter hung (the pump's own error arms drain on the
            # EOF/crash paths; this is the catch-all for cancellation).
            self._fail_all_pending(reason="comms.runner.pump_teardown")
            # Always close — a supervisor TaskGroup cancellation or a clean EOF
            # both funnel here so the subprocess never leaks.
            await self._transport.close()

    async def _handshake(self) -> None:
        """Send ``lifecycle.start``, await the matching ack, run the gate check.

        Reads frames (single reader, before the pump) until the frame whose
        ``id`` matches the request arrives. A clean EOF before the ack, or an ack
        whose ``result.ok`` is falsy, is a fatal handshake failure
        (:class:`PluginError`). On success, ``session._on_handshake_complete``
        runs the capability gate + emits ``plugin.lifecycle.loaded``; a gate
        denial raises :class:`PluginError` out of the session, unwinding ``run``
        WITHOUT entering the pump.
        """
        params: dict[str, object] = {
            "adapter_id": self._adapter_id,
            # Spec A G2 (#237): advertise out-of-band seq/ack support. A plugin
            # that speaks it echoes the same field in its result; a plugin that
            # does not omits it and the wire stays plain.
            "seq_ack": {"version": SEQ_VERSION},
        }
        # Spec A G3-2 (#237) — architect H-2: carry the non-secret boot epoch so
        # the G3-3 gateway reconciles core-liveness from the HANDSHAKE (the
        # boot-``ready`` broadcast reaches zero senders normally). Omitted when
        # unset (the stdio adapters) so the wire stays the pre-G3-2 shape.
        if self._boot_epoch is not None:
            params["epoch"] = self._boot_epoch
        await self._transport.send(
            {
                "jsonrpc": "2.0",
                "id": _LIFECYCLE_START_ID,
                "method": "lifecycle.start",
                "params": params,
            }
        )
        while True:
            frame = await self._transport.read_frame()
            if frame is None:
                log.error(
                    "comms.runner.handshake_eof",
                    adapter_id=self._adapter_id,
                )
                raise PluginError(t("comms.runner.handshake_failed", adapter_id=self._adapter_id))
            if frame.get("id") == _LIFECYCLE_START_ID:
                result = frame.get("result")
                if not (isinstance(result, Mapping) and result.get("ok")):
                    log.error(
                        "comms.runner.handshake_not_ok",
                        adapter_id=self._adapter_id,
                    )
                    raise PluginError(
                        t("comms.runner.handshake_failed", adapter_id=self._adapter_id)
                    )
                seq_ack = result.get("seq_ack")
                if isinstance(seq_ack, Mapping) and seq_ack.get("version") == SEQ_VERSION:
                    # Both peers speak the wire version — enable the header. The
                    # transport now frames every subsequent send with seq/ack and
                    # strips the header on read. A plugin that omitted the echo
                    # leaves this False and the wire stays plain ADR-0025. The flip
                    # is a TYPED call on the _CommsTransportLike seam (architect F4)
                    # — no getattr duck-typing.
                    self._seq_ack_negotiated = True
                    self._transport.enable_seq_ack()
                break
            # A non-matching frame before the ack is not expected on a conformant
            # wire (the plugin answers lifecycle.start before emitting anything
            # else); warn rather than debug so a plugin that front-runs the ack is
            # visible to an operator. The frame is dropped — the runner keeps
            # reading for the ack.
            log.warning(
                "comms.runner.pre_handshake_frame_ignored",
                adapter_id=self._adapter_id,
            )
        # Gate check + plugin.lifecycle.loaded emit. Raises PluginError on denial,
        # which propagates through run()'s finally (transport.close()).
        await self._session._on_handshake_complete()

    async def _pump(self) -> None:
        """Single-reader loop: read a frame, route it, survive a handler failure.

        Ends on clean EOF (``read_frame`` -> ``None``). A response frame (no
        ``method``) is logged + ignored in 11a (no request/response correlation
        yet). A notification is routed through ``_on_post_handshake_method``,
        which respects the session's per-adapter semaphore. Error arms are loud
        per :meth:`run`'s contract.
        """
        while True:
            # PR-S4-11b DEFECT 1: observe the supervisor shutdown signal so a
            # graceful stop ends the pump promptly. Checked at the TOP of each
            # iteration (cheap, lets an already-set event short-circuit before a
            # blocking read) AND raced against the read below (so a shutdown that
            # arrives WHILE we are blocked on ``read_frame`` still ends us). The
            # ``finally`` in :meth:`pump` closes the transport on this exit, same
            # as the EOF/crash arms — no frame loss, we are shutting down.
            if self._shutdown_event is not None and self._shutdown_event.is_set():
                log.info("comms.runner.shutdown_signalled", adapter_id=self._adapter_id)
                return
            try:
                frame = await self._read_frame_or_shutdown()
            except _ShutdownSignalled:
                log.info("comms.runner.shutdown_signalled", adapter_id=self._adapter_id)
                return
            except CommsProtocolError:
                # Malformed wire frame: loud + restart request. The wire is
                # unusable; let the supervisor cycle the subprocess. Drain any
                # in-flight request Future so its awaiter does not hang on a wire
                # that is no longer readable.
                log.warning(
                    "comms.runner.malformed_frame",
                    adapter_id=self._adapter_id,
                )
                self._fail_all_pending(reason="comms.runner.malformed_frame")
                await self._request_restart(reason=_MALFORMED_FRAME_RESTART_REASON)
                return
            except (BrokenPipeError, ConnectionResetError, asyncio.IncompleteReadError, EOFError):
                # Broken pipe / unexpected EOF mid-conversation: the plugin
                # crashed. Route a closed-vocab adapter.crashed so the breaker
                # can trip; never carry the raw exception text. Fail every pending
                # request Future loudly — the plugin will never answer.
                self._fail_all_pending(reason="comms.runner.transport_crash")
                await self._route_transport_crash()
                return

            if frame is None:
                # Clean EOF — the plugin closed stdout. End the pump. Any request
                # still awaiting a response will now never get one, so fail it
                # loudly rather than leaving the awaiter hung.
                log.info("comms.runner.clean_eof", adapter_id=self._adapter_id)
                self._fail_all_pending(reason="comms.runner.clean_eof")
                return

            method = frame.get("method")
            if method is None:
                # A response frame (no ``method``). If its id matches an in-flight
                # request, resolve that Future with the response ``result``
                # envelope (the reference plugin answers ``outbound.message`` with
                # ``{"result": {...}}``). An unknown id is a stray response with no
                # awaiter — log + ignore rather than route an unroutable frame.
                #
                # CRITICAL (PR-S4-11b deadlock fix): responses are resolved INLINE
                # by the reader and are NEVER gated by the notification cap below,
                # so a reentrant handler's outbound ack is always read while its
                # dispatch task is in flight. This is what keeps the single reader
                # from deadlocking on its own ``send_request``.
                self._resolve_pending(frame)
                continue

            # A NOTIFICATION. Dispatch it as a tracked background task and KEEP
            # READING — the reader must stay free to resolve the response a
            # reentrant handler's ``send_request`` awaits (module docstring).
            self._spawn_notification_dispatch(str(method), frame.get("params"))
            # Backpressure into the pipe: cap the number of in-flight dispatch
            # tasks. Only the NEXT notification intake is gated — responses are
            # resolved above WITHOUT a cap check — so an in-flight dispatch's
            # outbound ack is still read+resolved while we wait here. The session's
            # per-adapter semaphore bounds concurrent handler bodies; this caps the
            # tracked-task set so a notification flood cannot grow it unbounded.
            await self._await_notification_capacity()

    async def _read_frame_or_shutdown(self) -> Mapping[str, object] | None:
        """Read the next frame, but abort the read if shutdown is signalled.

        PR-S4-11b DEFECT 1. With no shutdown event wired (legacy / substrate
        callers) this is a bare ``read_frame`` await — identical to the prior
        behaviour. With one wired, the read races ``shutdown_event.wait()`` via
        ``FIRST_COMPLETED``: if the read wins, its frame (or EOF/raise) flows on
        exactly as before; if shutdown wins, the in-flight read task is cancelled
        (so a blocking ``read_frame`` does not leak) and :class:`_ShutdownSignalled`
        is raised so the pump returns and its ``finally`` closes the transport.

        A read that completes with an EXCEPTION (``CommsProtocolError`` / a
        transport crash) is re-raised here so the pump's existing error arms still
        fire — shutdown does not mask a crash that already landed.
        """
        if self._shutdown_event is None:
            return await self._transport.read_frame()

        read_task: asyncio.Task[Mapping[str, object] | None] = asyncio.ensure_future(
            self._transport.read_frame()
        )
        shutdown_task: asyncio.Task[bool] = asyncio.ensure_future(self._shutdown_event.wait())
        try:
            done, _pending = await asyncio.wait(
                {read_task, shutdown_task}, return_when=asyncio.FIRST_COMPLETED
            )
        except asyncio.CancelledError:
            # A force-cancel (the supervisor's drain-timeout escalation) tearing
            # down the pump: cancel both children so neither leaks, then let the
            # CancelledError propagate — the ``finally`` in :meth:`pump` still
            # closes the transport (cancellation-safety, CLAUDE.md hard rule #7).
            read_task.cancel()
            shutdown_task.cancel()
            raise
        if read_task in done:
            # The read won the race — cancel the (still-pending) shutdown waiter
            # and surface the read's result/exception exactly as a bare await would.
            shutdown_task.cancel()
            return read_task.result()
        # Shutdown won: cancel the in-flight blocking read so it does not leak,
        # await its cancellation, then signal the pump to exit.
        read_task.cancel()
        with suppress(asyncio.CancelledError, *_TRANSPORT_READ_EXCEPTIONS):
            await read_task
        raise _ShutdownSignalled

    def _spawn_notification_dispatch(self, method: str, params: object) -> None:
        """Schedule one notification's dispatch as a tracked background task.

        The task runs :meth:`_route_notification` (which already swallows a single
        handler failure — err-007 catch-and-continue). It is added to
        :attr:`_inflight` and removed by a done-callback when it completes, so the
        set is the live drain/cancel surface :meth:`pump` uses on teardown. The
        reader does NOT await the task — that is the whole point: keep reading so a
        reentrant ``send_request`` response is resolved while the dispatch runs.
        """
        task: asyncio.Task[None] = asyncio.ensure_future(self._route_notification(method, params))
        self._inflight.add(task)
        task.add_done_callback(self._inflight.discard)

    async def _await_notification_capacity(self) -> None:
        """Block notification intake while the in-flight task set is at the cap.

        Backpressure into the pipe (spec): a notification storm cannot grow the
        tracked-task set past :attr:`_max_in_flight`. Only the NEXT notification
        read is delayed — :meth:`_pump` resolves RESPONSE frames inline WITHOUT
        calling this, so an in-flight dispatch's outbound ack is still read while
        we wait. Returns immediately when below the cap (the common case — the
        steady-state inbound pattern is one ack per message, far below the
        default cap of 32).
        """
        while len(self._inflight) >= self._max_in_flight:
            await asyncio.wait(self._inflight, return_when=asyncio.FIRST_COMPLETED)

    async def _drain_inflight_dispatches(self) -> None:
        """Await every in-flight dispatch task so none leaks past :meth:`pump`.

        Called on a CLEAN pump exit (EOF / shutdown / malformed / crash). Each
        dispatch task body is :meth:`_route_notification`, which swallows any
        single handler ``Exception`` (err-007 catch-and-continue) — so a task
        cannot raise an application error here. ``return_exceptions=True`` keeps a
        stray ``BaseException`` (e.g. a cancellation racing the drain) from masking
        the teardown. Snapshots the set first because the done-callback mutates
        :attr:`_inflight` as tasks complete.
        """
        if not self._inflight:
            return
        pending = list(self._inflight)
        await asyncio.gather(*pending, return_exceptions=True)

    async def _cancel_inflight_dispatches(self) -> None:
        """Cancel + await every in-flight dispatch task (force-cancel teardown).

        Called when :meth:`pump` is itself force-cancelled (the supervisor's
        drain-timeout escalation): the dispatch tasks must not outlive the pump.
        Cancel each, then await its cancellation so no task leaks; suppress the
        ``CancelledError`` each raises (we are tearing down).
        """
        if not self._inflight:
            return
        pending = list(self._inflight)
        for task in pending:
            task.cancel()
        with suppress(asyncio.CancelledError):
            await asyncio.gather(*pending, return_exceptions=True)

    def _resolve_pending(self, frame: Mapping[str, object]) -> None:
        """Resolve (or FAIL) the pending request Future this response frame matches.

        The response carries no ``method``; its ``id`` correlates it to a prior
        :meth:`send_request`. An unknown id has no awaiter — it is a stray
        response, so log + ignore.

        FIX 4 (PR-S4-11b review): a correlated frame is resolved with its
        ``result`` mapping ONLY on the success shape. A frame carrying a
        JSON-RPC ``error`` member — or one carrying NEITHER ``result`` NOR
        ``error`` (a malformed response) — FAILS the future with a closed-vocab
        :class:`PluginError` instead of silently resolving to ``{}``. The prior
        code turned a plugin error frame into a successful empty result, masking
        an application-level failure as a clean ack. The raw wire ``error``
        payload is NEVER carried into the host-side message (spec §5.6 — no T3
        bytes in operational errors).
        """
        frame_id = frame.get("id")
        future = self._pending.pop(frame_id, None) if isinstance(frame_id, int) else None
        if future is None:
            log.debug(
                "comms.runner.response_frame_ignored",
                adapter_id=self._adapter_id,
            )
            return
        if future.done():
            # Already failed/cancelled (e.g. a timeout that lost the id race);
            # nothing to resolve.
            return
        if "error" in frame or "result" not in frame:
            # An error frame (or a malformed one missing both members) is an
            # application-level failure — fail loudly with a closed-vocab message
            # that never echoes the raw wire payload.
            log.warning(
                "comms.runner.response_error_frame",
                adapter_id=self._adapter_id,
                has_error="error" in frame,
            )
            future.set_exception(
                PluginError(t("comms.runner.response_error", adapter_id=self._adapter_id))
            )
            return
        result = frame.get("result")
        future.set_result(result if isinstance(result, Mapping) else {})

    def _fail_all_pending(self, *, reason: str) -> None:
        """Fail every outstanding request Future loudly (CLAUDE.md hard rule #7).

        Called on every terminal pump arm (clean EOF, transport crash, malformed
        frame) and in :meth:`run`'s teardown so no ``send_request`` awaiter can
        hang once the wire is gone. Idempotent: futures already resolved or
        cancelled are skipped, and the map is cleared so a second call is a no-op.
        """
        if not self._pending:
            return
        pending = self._pending
        self._pending = {}
        log.warning(
            "comms.runner.pending_requests_aborted",
            adapter_id=self._adapter_id,
            reason=reason,
            pending_count=len(pending),
        )
        for future in pending.values():
            if not future.done():
                future.set_exception(
                    PluginError(t("comms.runner.request_aborted", adapter_id=self._adapter_id))
                )

    async def _route_notification(self, method: str, params: object) -> None:
        """Fan one notification into the session; survive a single handler failure.

        The session's dispatch arm RE-RAISES a handler exception (err-007 — it has
        already emitted ``COMMS_HANDLER_FAILED`` + counted toward the breaker). The
        runner catches it here and continues to the next frame, matching the
        session docstring's "the reader logs + continues" contract.
        """
        params_mapping = params if isinstance(params, Mapping) else None
        try:
            await self._session._on_post_handshake_method(method, params_mapping)
        except Exception:
            # Catch-and-continue: the session already audited + counted this
            # failure. The reader must survive so a single bad handler does not
            # silence the whole adapter (err-007 invariant).
            log.warning(
                "comms.runner.handler_failed_continuing",
                adapter_id=self._adapter_id,
                notification_method=method,
            )

    async def _route_transport_crash(self) -> None:
        """Synthesize a closed-vocab ``adapter.crashed`` and route it to the session.

        Routing through ``_on_post_handshake_method`` (not the handler directly)
        reuses the session's validated dispatch arm: the CrashHandler emits its
        audit row and the err-007 breaker counter advances. A handler failure on
        THIS path is swallowed too — the plugin is already crashing, so a failing
        crash handler must not mask the original crash.
        """
        log.warning(
            "comms.runner.transport_crash",
            adapter_id=self._adapter_id,
        )
        crash_params: Mapping[str, object] = {
            "adapter_id": self._adapter_id,
            "error_class": _TRANSPORT_CRASH_ERROR_CLASS,
            "detail": _TRANSPORT_CRASH_DETAIL,
        }
        try:
            await self._session._on_post_handshake_method("adapter.crashed", crash_params)
        except Exception:
            log.warning(
                "comms.runner.crash_route_failed",
                adapter_id=self._adapter_id,
            )

    async def _request_restart(self, *, reason: str) -> None:
        """Ask the supervisor to restart the adapter, if one is wired."""
        supervisor: _SupervisorLike | None = self._session._supervisor
        if supervisor is not None:
            await supervisor.request_plugin_restart(adapter_id=self._adapter_id, reason=reason)


__all__ = [
    "CommsPluginRunner",
]
