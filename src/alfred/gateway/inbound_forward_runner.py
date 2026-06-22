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

**Back-pressure (FORK-C).** On a ``LegQueueFullError`` / ``ReplayBufferError`` from the
forward, the disposition CLEARS the shared gate (pause the child-stdio reader) so the
in-flight frame is NOT dropped (hard rule #7); the scheduler SETS it on the next drain
(resume). The structlog ``backpressure_engaged`` row makes the pause observable (never
silent). The gate is a forward-runner collaborator, NOT part of ``InboundDisposition``.
"""

from __future__ import annotations

import asyncio
import json
from typing import TYPE_CHECKING, Final, Protocol, runtime_checkable

import structlog

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
    ) -> None:
        self._adapter_id = adapter_id
        self._forward = forward
        self._back_pressure_gate = back_pressure_gate

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
        """Serialize the already-parsed ``params`` blob + forward it; engage back-pressure.

        Payload-blind: the params arrive ALREADY PARSED (the transport parsed the frame).
        We serialize them to an opaque JSON ``str`` and hand them to the forward sink — we
        never ``json.loads`` / read a field (SEC-309-1 / hard rule #5). ``adapter_id`` is
        the construction (spawn-binding) value.

        On a full leg (:class:`LegQueueFullError` — the live synchronous raise — or
        :class:`ReplayBufferError` — the global-cap defensive catch) ENGAGE back-pressure
        (clear the gate) so the reader pauses BEFORE the next frame and the in-flight frame
        is not dropped. NEVER raises (fire-and-forget).
        """
        body = json.dumps(params, ensure_ascii=False)
        try:
            await self._forward(self._adapter_id, body)
        except (LegQueueFullError, ReplayBufferError):
            # The leg is full: pause the reader (clear the gate) so the child's stdout
            # back-pressures the platform without losing the in-flight frame (hard rule #7).
            # The scheduler SETS the gate on its next drain (resume).
            if self._back_pressure_gate is not None:
                self._back_pressure_gate.clear()
            log.warning(
                "gateway.adapter.inbound.backpressure_engaged",
                adapter_id=self._adapter_id,
            )
            return
        log.debug("gateway.adapter.inbound.forward_accepted", adapter_id=self._adapter_id)


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
