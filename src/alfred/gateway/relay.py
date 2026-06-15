"""``GatewayRelay`` — the gateway's two-direction opaque payload relay (Spec A G3-3b-2).

The relay is the engine that joins the gateway's two legs into a resumable front door
(ADR-0032 / #237). It owns NO socket of its own: it is handed a live
:class:`GatewayCoreLink` (the core-facing half — dial + handshake + supervised pump +
reconnect) and a client transport (the accepted TUI connection), and it wires them so an
opaque payload flows end-to-end byte-for-byte in BOTH directions:

* **core -> client** IS :meth:`GatewayCoreLink.run` (the merged supervised pump). The
  relay binds that pump's ``payload_relay`` sink to :meth:`_send_to_client`, so every
  opaque payload the core leg forwards (a frame that is NOT a consumed ``daemon.lifecycle.*``
  control frame) is written down to the client. The reconnect/backoff/lifecycle-signal
  machinery all lives in the core-link — the relay rides it.
* **client -> core** is :meth:`_client_to_core_pump`: a second pump that reads the
  client transport's raw units and calls :meth:`GatewayCoreLink.relay_to_core`, doing
  ZERO body parse on that leg (a PURE opaque forward — security H3; the client leg never
  inspects the payload, the core re-parses).

**Production wire (the leg asymmetry).** The core leg is seq/ack-ENABLED (the daemon's
``CommsPluginRunner`` negotiates ``AlfredSeqAck/1`` in the handshake); the client (TUI)
leg is PLAIN — the real ``alfred chat`` never negotiates seq/ack. So on the production
shape the client-send carries ``ack=0`` (the plain transport ignores it and emits a
plain ADR-0025 line) and the client-leg receive ack is moot. A seq-enabled-client variant
is forward-looking (G4/G5): the relay maintains a SEPARATE client-receive tracker so the
client-leg ack is RESEQUENCED — the gateway's own client-side cumulative ack, never the
core-leg seq passed through. Which mode is live is learned from the client handshake and
passed in as ``client_seq_enabled``.

**Payload-blind (CLAUDE.md hard rule #5).** The relay NEVER ``json.loads`` a payload
body. The ONLY method-peek in the whole gateway is the core-link's lifecycle router
(:meth:`GatewayCoreLink._route_unit`), which peeks the method to CONSUME the two
lifecycle control frames; everything else — including the entire client->core leg — is
forwarded as opaque bytes. The inner JSON-RPC ``id`` the runner correlates on lives
inside that opaque run and survives end-to-end.

**Loud drops, no buffering (CLAUDE.md hard rule #7; G4 owns buffering).** A dead client
(broken pipe) on the core->client sink is a LOUD drop that does NOT raise into the core
pump (the client hung up — the core leg keeps running). A gapped core on the client->core
leg is a LOUD drop in :meth:`GatewayCoreLink.relay_to_core` (never buffered). The dropped
unit is the peer's to re-request once the leg is back — a G4 ReplayBuffer concern, not
this carrier's to hold.
"""

from __future__ import annotations

import asyncio
import json  # noqa: F401 — imported so the H3 zero-parse test can spy on this module's json.loads

import structlog

from alfred.gateway._seq_tracker import BoundedSeqAckTracker
from alfred.gateway.core_link import GatewayCoreLink, _CommsTransportLike
from alfred.plugins.comms_wire import CommsProtocolError

log = structlog.get_logger(__name__)


class GatewayRelay:
    """Joins a :class:`GatewayCoreLink` and a client transport into a two-way relay.

    Construct one per accepted client. :meth:`run` drives both pumps concurrently; the
    relay ends when the core pump returns (shutdown) — the client pump is reaped with it.
    """

    def __init__(
        self,
        *,
        core_link: GatewayCoreLink,
        client_transport: _CommsTransportLike,
        client_seq_enabled: bool,
    ) -> None:
        self._core_link = core_link
        self._client_transport = client_transport
        # Whether the client leg negotiated seq/ack at its handshake. PRODUCTION is
        # FALSE (the real TUI is a plain ADR-0025 peer); a seq-enabled client is the
        # forward-looking G4/G5 variant. When FALSE the client-send carries ack=0 and
        # the client-receive tracker is never consulted.
        self._client_seq_enabled = client_seq_enabled
        # The client-leg RECEIVE tracker — used ONLY when the client leg is seq-enabled.
        # It is the gateway's OWN client-side cumulative ack: the client-leg ack the
        # relay emits is RESEQUENCED from this tracker, NEVER the core-leg seq passed
        # through. Bounded (like the core tracker) so an always-up gateway cannot be
        # memory-DoS'd by an every-other-seq client stream.
        self._client_tracker = BoundedSeqAckTracker()
        # Wire the core pump's sink to our client-send half. The core-link's run() reads
        # raw units, consumes lifecycle frames, and forwards every opaque payload to this
        # callable — so binding it here is what turns the core-link's pump into the
        # core->client direction of the relay. The sink slot is the core-link's
        # ``_payload_relay`` (the ctor param the pump dispatches on); binding it AFTER
        # construction (rather than threading it through the ctor) keeps the relay the
        # one place that knows both legs — the core-link stays leg-agnostic.
        self._core_link._payload_relay = self._send_to_client

    async def run(self) -> None:
        """Drive both pumps concurrently; end when the core pump (shutdown) returns.

        The core->client direction IS ``core_link.run()`` (the supervised pump that owns
        dial + handshake + reconnect + the lifecycle control signal). The client->core
        direction is :meth:`_client_to_core_pump`. They run in an
        :class:`asyncio.TaskGroup`:

        * On CLIENT EOF the client pump returns; the relay then waits on the core pump,
          which ends on shutdown (the held-client-across-core-gaps posture — a closed
          client does not tear the core leg, but with no client there is nothing to relay
          to, so the relay simply rides the core pump to its shutdown).
        * On SHUTDOWN ``core_link.run()`` returns; the group then CANCELS the still-running
          client pump (a client read blocked forever must be cancellable on shutdown) and
          the TaskGroup awaits its cancellation. The cancel is clean — the client pump's
          read is interruptible.

        Reaping is the TaskGroup's job (it awaits both children) plus each pump's own
        ``finally``; the core-link closes its transport in ``run``'s finally.
        """
        async with asyncio.TaskGroup() as group:
            core_task = group.create_task(self._core_link.run())
            client_task = group.create_task(self._client_to_core_pump())
            # When the core pump returns (shutdown), cancel the client pump so a client
            # read blocked forever on shutdown does not wedge the group. A client pump
            # that already returned (client EOF) makes this cancel a harmless no-op.
            core_task.add_done_callback(lambda _t: client_task.cancel())

    async def _send_to_client(self, payload: bytes) -> None:
        """Write an opaque core-originated payload down to the client; loud-drop a hangup.

        The core pump's ``payload_relay`` sink. Writes the opaque ``payload`` to the
        client transport carrying the client-leg ack: the RESEQUENCED client-receive
        cumulative ack when the client leg is seq-enabled, else ``0`` (the plain client
        transport ignores ``ack`` and emits a plain ADR-0025 line).

        **Loud drop, never raise into the core pump (CLAUDE.md hard rule #7).** Any
        send-path fault is a LOUD drop — the core leg must keep running (it is held
        across client churn just as it is held across core churn), so raising here would
        crash the core pump for a client-side fault, which is wrong. The widened family:
        transport-died (:class:`BrokenPipeError` / :class:`ConnectionResetError`),
        encode-failed (:class:`ValueError` from :func:`encode_seq_frame` send-seq
        decimal-width exhaustion, or :class:`CommsProtocolError` from an over-bound
        reframe), or a write to a client transport ``close()``d mid-reconnect-swap
        (:class:`RuntimeError` "unable to perform operation on closed transport").

        The seq-enabled ack is FLOORED to ``0`` (mirroring :meth:`GatewayCoreLink.relay_to_core`):
        the client tracker's ``-1`` ("nothing acked yet") is the wire's ``a=0`` placeholder,
        and an un-floored ``-1`` would crash :func:`encode_seq_frame` on the first
        core->client unit sent before the client leg has delivered a seq.
        """
        ack = max(self._client_tracker.cumulative_ack(), 0) if self._client_seq_enabled else 0
        try:
            await self._client_transport.send_payload_unit(payload, ack=ack)
        except (
            BrokenPipeError,
            ConnectionResetError,
            RuntimeError,
            ValueError,
            CommsProtocolError,
        ) as exc:
            log.warning("gateway.relay.client_send_dropped", error=repr(exc))

    async def _client_to_core_pump(self) -> None:
        """Read client units and forward them to the core leg — ZERO body parse (H3).

        The client->core direction. Loops reading the client transport's raw units; a
        ``None`` read is a clean client EOF that returns the pump. Otherwise: if the
        client leg is seq-enabled and the unit carries a ``seq``, advance the client
        receive tracker (so the client-leg ack the relay emits stays current); then
        forward the OPAQUE payload to :meth:`GatewayCoreLink.relay_to_core` — which
        carries the core-leg cumulative ack and loud-drops on a gapped core.

        **Pure opaque forward (security H3 / CLAUDE.md hard rule #5).** This leg NEVER
        ``json.loads`` the payload: the gateway is a T1 carrier and the client->core body
        is forwarded byte-for-byte for the core to re-parse. The lifecycle method-peek
        lives ONLY on the core->client leg (the core-link's router); the client leg has
        no lifecycle frames to consume.

        Cancellation-safe: when the core pump returns on shutdown the group cancels this
        task, interrupting a blocked client read — the read is cancellable, so the cancel
        propagates cleanly (no leaked read, no swallowed cancel).

        **Client-leg fault isolation (CLAUDE.md hard rule #7).** A malformed/torn client
        frame (:meth:`read_payload_unit` raising :class:`CommsProtocolError` or a
        transport-tear), or a negative client seq (:meth:`observe` raising
        :class:`ValueError`), is the CLIENT leg's fault — not the core leg's. It must NOT
        escape this pump and abort the whole :class:`asyncio.TaskGroup` (tearing the core
        pump down with it) as an un-triaged crash. We LOUD-LOG it and RETURN: the client
        leg is unusable, so the client->core direction ends cleanly; the TaskGroup then
        reaps the core pump via its normal done-callback — a handled stop, not an
        unhandled ``ExceptionGroup``. A clean client EOF (``read_payload_unit() -> None``)
        stays the existing quiet return.
        """
        while True:
            try:
                frame = await self._client_transport.read_payload_unit()
                if frame is None:
                    # Clean client EOF — the operator closed ``alfred chat``. Return the
                    # pump; the relay rides the core pump to its shutdown.
                    return
                if self._client_seq_enabled and frame.seq is not None:
                    self._client_tracker.observe(frame.seq)
            except (
                CommsProtocolError,
                BrokenPipeError,
                ConnectionResetError,
                asyncio.IncompleteReadError,
                EOFError,
                ValueError,
            ) as exc:
                # A torn/malformed client frame or a negative client seq: the client leg
                # is unusable. Loud (hard rule #7), then end THIS direction cleanly so the
                # fault does not crash the core pump's TaskGroup.
                log.warning("gateway.relay.client_read_failed", error=repr(exc))
                return
            await self._core_link.relay_to_core(frame.payload)


__all__ = ["GatewayRelay"]
