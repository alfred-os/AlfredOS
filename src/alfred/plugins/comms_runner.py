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

**Single reader.** Once :meth:`run` owns the reader, NOTHING else reads the
stream — the handshake also reads via :meth:`_CommsTransportLike.read_frame`, but
strictly before the pump starts. The ``await`` chain through the session's
per-adapter semaphore is what applies backpressure into the pipe: no frame is
dropped, and frames are processed strictly sequentially in 11a.
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from typing import TYPE_CHECKING, Final, Protocol, runtime_checkable

import structlog

from alfred.i18n import t
from alfred.plugins.comms_stdio_transport import CommsProtocolError
from alfred.plugins.errors import PluginError

if TYPE_CHECKING:
    from alfred.plugins.session import AlfredPluginSession, _SupervisorLike

log = structlog.get_logger(__name__)

# The JSON-RPC id the runner stamps on its single ``lifecycle.start`` request.
# The handshake is one round-trip, so a constant id is sufficient — the runner
# matches the response by this id before the pump begins.
_LIFECYCLE_START_ID: Final[int] = 0

# Closed-vocabulary error_class + detail for the host-synthesized crash route.
# A broken pipe / mid-read EOF is a TRANSPORT-level crash; the runner names it
# from this closed vocab so a raw exception string (which could echo wire bytes)
# never reaches the CrashHandler's audit row.
_TRANSPORT_CRASH_ERROR_CLASS: Final[str] = "CommsTransportClosed"
_TRANSPORT_CRASH_DETAIL: Final[str] = "comms transport closed mid-conversation"

# Closed-vocab restart reason for a malformed-frame wire violation.
_MALFORMED_FRAME_RESTART_REASON: Final[str] = "malformed_frame"


@runtime_checkable
class _CommsTransportLike(Protocol):
    """Structural seam for the transport the runner drives.

    The runner binds to this shape rather than the concrete
    :class:`alfred.plugins.comms_stdio_transport.CommsStdioTransport` so a test
    can drive it with an in-memory frame queue and so the runner never reaches
    for transport internals beyond these four awaitables.
    """

    async def spawn(self) -> None: ...

    async def send(self, frame: Mapping[str, object]) -> None: ...

    async def read_frame(self) -> Mapping[str, object] | None: ...

    async def close(self) -> None: ...


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
    ) -> None:
        self._session = session
        self._transport = transport
        self._adapter_id = adapter_id

    async def run(self) -> None:
        """Spawn, handshake, pump, then tear down — the full adapter lifecycle.

        Raises :class:`PluginError` if the capability gate denies the load or the
        plugin never acknowledges the handshake; in both cases the transport is
        still closed (the ``finally``) so no subprocess leaks. On a clean run the
        method returns when the pump sees EOF.
        """
        try:
            await self._transport.spawn()
            await self._handshake()
            await self._pump()
        finally:
            # Always close — a supervisor TaskGroup cancellation, a gate denial,
            # or a clean EOF all funnel here so the subprocess never leaks.
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
        await self._transport.send(
            {
                "jsonrpc": "2.0",
                "id": _LIFECYCLE_START_ID,
                "method": "lifecycle.start",
                "params": {"adapter_id": self._adapter_id},
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
            try:
                frame = await self._transport.read_frame()
            except CommsProtocolError:
                # Malformed wire frame: loud + restart request. The wire is
                # unusable; let the supervisor cycle the subprocess.
                log.warning(
                    "comms.runner.malformed_frame",
                    adapter_id=self._adapter_id,
                )
                await self._request_restart(reason=_MALFORMED_FRAME_RESTART_REASON)
                return
            except (BrokenPipeError, ConnectionResetError, asyncio.IncompleteReadError, EOFError):
                # Broken pipe / unexpected EOF mid-conversation: the plugin
                # crashed. Route a closed-vocab adapter.crashed so the breaker
                # can trip; never carry the raw exception text.
                await self._route_transport_crash()
                return

            if frame is None:
                # Clean EOF — the plugin closed stdout. End the pump.
                log.info("comms.runner.clean_eof", adapter_id=self._adapter_id)
                return

            method = frame.get("method")
            if method is None:
                # A response frame with no method — in 11a there is no in-flight
                # request to correlate it to (the handshake already completed), so
                # log + ignore rather than route an unroutable frame.
                log.debug(
                    "comms.runner.response_frame_ignored",
                    adapter_id=self._adapter_id,
                )
                continue

            await self._route_notification(str(method), frame.get("params"))

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
