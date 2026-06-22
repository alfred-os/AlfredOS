"""The gateway's session-LESS inbound forward path (Spec B G6-7-3, #309 / ADR-0039).

The gateway HOSTS a comms-adapter child (e.g. Discord) but is connectivity-free at its
core: it does NOT dispatch the child's ``inbound.message`` into a local
:class:`alfred.plugins.session.AlfredPluginSession` (the daemon does that). Instead it
FORWARDS the opaque body to the core over a per-adapter ADR-0031 leg, where the core
re-parses + dispatches it (G6-7-4). This module is the forward half:

* :class:`GatewayForwardDisposition` implements the G6-7-2
  :class:`alfred.plugins.inbound_disposition.InboundDisposition` Protocol — the §3.1
  four-notification table. ``inbound.message`` -> ``core_link.forward_adapter_inbound``;
  ``adapter.rate_limit_signal`` / ``adapter.binding_request`` / any other method -> a
  LOUD-AUDITED gateway-local DROP (no core route exists for them; blind-forwarding a
  ``binding_request`` would be an audit-write DoS amplifier). Every arm NEVER raises
  (fire-and-forget — the pump schedules ``dispatch`` and never retrieves the result).

* :class:`GatewayInboundForwardRunner` is a thin session-LESS construction of
  :class:`alfred.plugins.comms_runner.CommsPluginRunner` (``session=None``, FORK-A) with
  the forward disposition + an optional back-pressure gate (FORK-C), exposing
  ``start_and_handshake`` / ``pump`` / ``run`` for the factory + supervised pump.

**SEC-309-1 (hard).** The disposition gets ``adapter_id`` from CONSTRUCTION (the gateway's
per-child spawn binding) and passes it to ``forward`` — it NEVER reads the id from
``params`` / the body. A forged/mismatched body id cannot change where the frame routes.

**Payload-blind (hard rule #5).** The disposition serializes the ALREADY-PARSED ``params``
blob (the transport parsed the frame) to a JSON ``str`` and forwards it; it never
``json.loads`` / inspects the body. ``json.dumps`` is the chosen deterministic serializer
(``ensure_ascii=False`` keeps the byte run faithful for non-ASCII content; sort_keys is
NOT set so the producer's key order is preserved — the core re-parses the body, so the
exact key order is immaterial, but we never reorder/mutate the producer's blob).

**Back-pressure = no-drop RETRY (FORK-C / ADR-0039 invariant).** A leg-full (a full but
REGISTERED leg) is BACK-PRESSURE, not drop: "no path silently loses an inbound." On a
``LegQueueFullError`` / ``ReplayBufferError`` from the forward, the disposition CLEARS
the shared gate (pause the child-stdio reader), logs ``backpressure_engaged`` (carrying a
closed-vocab ``reason`` — ``leg_full`` vs ``global_cap``, DEVEX-309-1), then
PARKS — ``await``-ing the gate (raced against ``shutdown_event`` so shutdown wins) — and
on resume logs ``backpressure_released`` and RE-FORWARDS THE SAME body, looping until the
forward succeeds or shutdown ends it. The scheduler SETS the gate after it drains a frame
off the leg (resume). Because the gateway pump routes this notification SYNCHRONOUSLY (the
reader ``await``s the dispatch, NOT fire-and-forget — there is no reentrant ``send_request``
on the forward path), the reader is naturally paused while a frame is being (re)forwarded:
no-drop, in-order, and no read-ahead all fall out by construction. Dropping the held frame
is acceptable ONLY on the shutdown path (we are tearing down) — logged
``backpressure_shutdown_drop`` (never silent, hard rule #7). The gate + shutdown_event are
forward-runner collaborators, NOT part of the ``InboundDisposition`` Protocol.

**Leg-unavailable = LOUD TERMINAL drop (ERR-309-1).** DISTINCT from back-pressure: a
:class:`alfred.gateway.core_link.ForwardLegUnavailableError` (the LegRouter refused —
the spawn-binding ``adapter_id`` names NO registered leg, e.g. the scheduler's isolation
arm deregistered it while a forward was parked on back-pressure) is an UNREGISTERED / gone
leg. A forward can never reach it, so retrying is futile — the disposition LOUD-TERMINAL
drops the frame (``leg_unavailable_drop``), never logging ``forward_accepted`` on a LOST
frame. This is the load-bearing silent-loss fix (hard rule #7).
"""

from __future__ import annotations

import asyncio
import json
from contextlib import suppress
from typing import TYPE_CHECKING, Final, Protocol, runtime_checkable

import structlog

from alfred.gateway.core_link import ForwardLegUnavailableError
from alfred.gateway.leg_scheduler import LegQueueFullError
from alfred.gateway.replay_buffer import ReplayBufferError
from alfred.plugins.comms_runner import CommsPluginRunner

if TYPE_CHECKING:
    from alfred.plugins.comms_runner import _CommsTransportLike

log = structlog.get_logger(__name__)

# The child notification methods the gateway sees off the wire (mirrors the session's
# closed set, alfred/plugins/session.py). Only ``inbound.message`` has a core forward
# target; the other two have NO gateway-side route and are loud-audited drops.
_INBOUND_MESSAGE: Final[str] = "inbound.message"
_RATE_LIMIT_SIGNAL: Final[str] = "adapter.rate_limit_signal"
_BINDING_REQUEST: Final[str] = "adapter.binding_request"

# DEVEX-309-1: the back-pressure except arm catches BOTH a per-leg queue-budget overflow
# (``LegQueueFullError``) and a global-cap overflow (``ReplayBufferError``) — different
# remediations (one leg saturated vs whole-gateway over budget). A closed-vocab ``reason``
# on the back-pressure / drop rows lets an operator tell them apart (mirrors the
# ``reason=``-on-structlog convention, e.g. ``gateway.ingress.slot_evicted reason=...``).
_BACK_PRESSURE_LEG_FULL: Final[str] = "leg_full"
_BACK_PRESSURE_GLOBAL_CAP: Final[str] = "global_cap"


@runtime_checkable
class _ForwardCallable(Protocol):
    """The injected forward sink — satisfied by ``core_link.forward_adapter_inbound``.

    The disposition does NOT own the core link; the runner factory binds the link's
    method here so the disposition stays free of the link's construction deps. ``body``
    is the serialized (opaque) child params; ``adapter_id`` is the spawn binding.
    """

    async def __call__(self, adapter_id: str, body: str) -> None: ...


class GatewayForwardDisposition:
    """The §3.1 four-notification table: forward ``inbound.message``, loud-drop the rest.

    Implements :class:`alfred.plugins.inbound_disposition.InboundDisposition`. NEVER
    raises (fire-and-forget). SEC-309-1: ``adapter_id`` is the construction (spawn-binding)
    value, never read from the body.
    """

    def __init__(
        self,
        *,
        adapter_id: str,
        forward: _ForwardCallable,
        back_pressure_gate: asyncio.Event | None = None,
        shutdown_event: asyncio.Event | None = None,
    ) -> None:
        self._adapter_id = adapter_id
        self._forward = forward
        self._back_pressure_gate = back_pressure_gate
        # ADR-0039: the no-drop retry PARKS on the gate; a SET shutdown_event must win that
        # park so a permanently-full leg during shutdown cannot wedge the reader (the held
        # frame is then dropped on the shutdown path — acceptable while tearing down).
        self._shutdown_event = shutdown_event

    async def dispatch(self, method: str, params: object, *, wire_seq: int | None = None) -> None:
        """Route ONE child notification per the §3.1 table; NEVER raise.

        ``wire_seq`` is host-authoritative leg-carrier metadata the FORWARD does not carry
        (the core rebinds the real leg seq out-of-band, per ``reparse_forwarded_inbound``);
        it is accepted to satisfy the Protocol and intentionally ignored on the gateway
        forward path (a body-smuggled value would be scrubbed core-side regardless).
        """
        del wire_seq  # the forward carries no seq; the core rebinds the real leg seq
        if method == _INBOUND_MESSAGE:
            await self._forward_inbound(params)
            return
        if method == _RATE_LIMIT_SIGNAL:
            # No core route for a hosted-adapter rate-limit signal exists yet — a loud
            # audited gateway-local drop (never a silent skip, hard rule #7).
            log.warning(
                "gateway.adapter.rate_limit_signal.dropped",
                adapter_id=self._adapter_id,
            )
            return
        if method == _BINDING_REQUEST:
            # Blind-forwarding a binding request would be an audit-write DoS amplifier
            # (its core receiver is audit-only and un-rate-limited) — loud audited drop.
            log.warning(
                "gateway.adapter.binding_request.dropped",
                adapter_id=self._adapter_id,
            )
            return
        # Any other / unknown method: a loud audited drop (never a silent skip).
        log.warning(
            "gateway.adapter.inbound.unknown_method_dropped",
            adapter_id=self._adapter_id,
            notification_method=method,
        )

    async def _forward_inbound(self, params: object) -> None:
        """Serialize the already-parsed ``params`` blob + forward it; RETRY on back-pressure.

        Payload-blind: the params arrive ALREADY PARSED (the transport parsed the frame).
        We serialize them ONCE to an opaque JSON ``str`` and hand the SAME body to the
        forward sink — we never ``json.loads`` / read a field (SEC-309-1 / hard rule #5).
        The body's BYTE CONTENT is stable through serialize -> ReplayBuffer -> core re-parse
        (SEC-309-2); a ``str`` body re-validates core-side as ``bytes`` (the wire model's
        ``bytes | str`` union coerces it) — content preserved, the type flips.
        ``adapter_id`` is the construction (spawn-binding) value.

        ADR-0039 invariant (no-drop): on a full but REGISTERED leg (:class:`LegQueueFullError`
        — the live synchronous raise — or :class:`ReplayBufferError` — the global-cap defensive
        catch) ENGAGE back-pressure (clear the gate, carrying the closed-vocab ``reason``), PARK
        on the gate until the scheduler drains (sets it), then RE-FORWARD THE SAME body —
        looping until the forward succeeds. The triggering frame is held, never dropped. Because
        the gateway pump routes this SYNCHRONOUSLY, the reader is paused for the duration, so no
        later frame is read ahead and source order is preserved. NEVER raises (fire-and-forget);
        a ``shutdown`` wins the park and drops the held frame (acceptable while tearing down).

        ERR-309-1 TERMINAL DROP: a :class:`ForwardLegUnavailableError` is an UNREGISTERED / gone
        leg (the router refused), NOT back-pressure. Retrying a gone leg is futile — so this is a
        LOUD TERMINAL drop (``leg_unavailable_drop``), no retry, no ``forward_accepted``. DISTINCT
        from the full-but-registered back-pressure path above.

        With NO gate wired (defensive — the gate is optional, the loud row is not) there is
        nothing to park on, so a full-leg fault is a single loud-audited DROP — logged
        ``forward_dropped`` (a real drop, not a back-pressure HOLD).
        """
        body = json.dumps(params, ensure_ascii=False)
        while True:
            try:
                await self._forward(self._adapter_id, body)
            except ForwardLegUnavailableError:
                # ERR-309-1: the leg is unregistered / gone (the router refused) — a forward
                # can NEVER be delivered to it, so retrying is futile. LOUD TERMINAL drop
                # (hard rule #7: never silent, never a false ``forward_accepted``). The K4
                # ``record_unknown_adapter_refusal`` audit row already fired core-side.
                #
                # FOLLOW-UP (lifecycle, later slice): an isolated discord leg is registered
                # at BOOT (not per-spawn), so a deregistered leg leaves that adapter
                # inbound-dark until process restart — there is no leg re-registration here.
                # Out of scope for G6-7-3; tracked separately. Do NOT attempt re-registration.
                log.warning(
                    "gateway.adapter.inbound.leg_unavailable_drop",
                    adapter_id=self._adapter_id,
                )
                return
            except (LegQueueFullError, ReplayBufferError) as exc:
                # A full but REGISTERED leg: pause the reader (clear the gate) so the child's
                # stdout back-pressures the platform. The scheduler SETS the gate on its next
                # drain (resume), and we RE-FORWARD the same body (no-drop, hard rule #7).
                # DEVEX-309-1: distinguish per-leg saturation from whole-gateway over-budget.
                reason = (
                    _BACK_PRESSURE_LEG_FULL
                    if isinstance(exc, LegQueueFullError)
                    else _BACK_PRESSURE_GLOBAL_CAP
                )
                if self._back_pressure_gate is None:
                    # No gate to park on (defensive): this arm DROPS the frame (there is
                    # nothing to hold it on) — a real drop, NOT a back-pressure HOLD, so it
                    # gets its own greppable event (DEVEX-309-2), never the shared
                    # ``backpressure_engaged`` row.
                    log.warning(
                        "gateway.adapter.inbound.forward_dropped",
                        adapter_id=self._adapter_id,
                        reason=reason,
                    )
                    return
                self._back_pressure_gate.clear()
                log.warning(
                    "gateway.adapter.inbound.backpressure_engaged",
                    adapter_id=self._adapter_id,
                    reason=reason,
                )
                if not await self._await_resume_or_shutdown(self._back_pressure_gate):
                    # Shutdown won the park: drop the held frame (we are tearing down) —
                    # LOUD (never silent), the one acceptable drop on the no-drop path.
                    log.warning(
                        "gateway.adapter.inbound.backpressure_shutdown_drop",
                        adapter_id=self._adapter_id,
                    )
                    return
                log.warning(
                    "gateway.adapter.inbound.backpressure_released",
                    adapter_id=self._adapter_id,
                    reason=reason,
                )
                continue
            log.debug("gateway.adapter.inbound.forward_accepted", adapter_id=self._adapter_id)
            return

    async def _await_resume_or_shutdown(self, gate: asyncio.Event) -> bool:
        """Park until the scheduler-drain SETS ``gate`` (resume); shutdown wins (ADR-0039).

        Returns ``True`` to RESUME (re-forward the held frame), ``False`` if a shutdown won
        the park (drop the held frame on the teardown path). With NO ``shutdown_event``
        wired this is a plain ``await gate.wait()`` (always resumes). With one wired, the
        gate-wait races ``shutdown_event.wait()`` (FIRST_COMPLETED) so a permanently-full
        leg during shutdown cannot wedge the reader. CANCELLATION-SAFE: a force-cancel of a
        parked disposition cancels both child waits and re-raises (CLAUDE.md hard rule #7) —
        the pump's ``finally`` still closes the transport.
        """
        if self._shutdown_event is None:
            await gate.wait()
            return True
        gate_task: asyncio.Task[bool] = asyncio.ensure_future(gate.wait())
        shutdown_task: asyncio.Task[bool] = asyncio.ensure_future(self._shutdown_event.wait())
        try:
            done, _pending = await asyncio.wait(
                {gate_task, shutdown_task}, return_when=asyncio.FIRST_COMPLETED
            )
        except asyncio.CancelledError:
            gate_task.cancel()
            shutdown_task.cancel()
            # Await the cancelled children before re-raising so neither leaks a transient
            # pending-task warning under aggressive teardown (matches the
            # ``_read_frame_or_shutdown`` discipline; the win/lose arms already await-suppress).
            with suppress(asyncio.CancelledError):
                await asyncio.gather(gate_task, shutdown_task, return_exceptions=True)
            raise
        if shutdown_task in done:
            gate_task.cancel()
            with suppress(asyncio.CancelledError):
                await gate_task
            return False
        shutdown_task.cancel()
        with suppress(asyncio.CancelledError):
            await shutdown_task
        return True


class GatewayInboundForwardRunner:
    """A session-LESS :class:`CommsPluginRunner` that FORWARDS a hosted child's inbound.

    FORK-A: constructs the runner with ``session=None`` (the gateway has no capability
    gate — it is core-side by design) + the :class:`GatewayForwardDisposition` + an
    optional back-pressure gate (FORK-C). Exposes ``start_and_handshake`` (the factory
    awaits it to bring the child to ``up``), ``pump`` (the supervised steady state), and
    ``run`` (their composition).
    """

    def __init__(
        self,
        *,
        transport: _CommsTransportLike,
        adapter_id: str,
        forward: _ForwardCallable,
        shutdown_event: asyncio.Event | None = None,
        boot_epoch: str | None = None,
        back_pressure_gate: asyncio.Event | None = None,
    ) -> None:
        disposition = GatewayForwardDisposition(
            adapter_id=adapter_id,
            forward=forward,
            back_pressure_gate=back_pressure_gate,
            # ADR-0039: the disposition's no-drop RETRY parks on the gate; the runner's
            # shutdown_event must win that park so a permanently-full leg during shutdown
            # cannot wedge the synchronously-routed reader (the held frame is dropped on
            # the teardown path — the one acceptable drop on the no-drop path).
            shutdown_event=shutdown_event,
        )
        self._runner = CommsPluginRunner(
            session=None,
            transport=transport,
            adapter_id=adapter_id,
            shutdown_event=shutdown_event,
            boot_epoch=boot_epoch,
            inbound_disposition=disposition,
            back_pressure_gate=back_pressure_gate,
        )

    async def start_and_handshake(self) -> None:
        """Spawn + run the readiness handshake (no capability gate — session-less)."""
        await self._runner.start_and_handshake()

    async def pump(self) -> None:
        """Run the single-reader pump until EOF / crash / shutdown, then tear down."""
        await self._runner.pump()

    async def run(self) -> None:
        """Spawn, handshake, pump, tear down — the full session-less forward lifecycle."""
        await self._runner.run()


__all__ = [
    "GatewayForwardDisposition",
    "GatewayInboundForwardRunner",
]
