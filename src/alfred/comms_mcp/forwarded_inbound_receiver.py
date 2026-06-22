"""The core-side receive trust boundary for a gateway-forwarded inbound (G6-7-4, #309).

ADR-0039 (option 1). The gateway is the network-facing front door; it spawns and
supervises the hosted adapter children (Discord, ...) and forwards each child's
``inbound.message`` to the connectivity-free CORE as a JSON-RPC
``gateway.adapter.inbound`` notification whose ``params`` is a
:class:`~alfred.comms_mcp.protocol.GatewayAdapterInboundEnvelope`
(``{adapter_id, body}``). The opaque T3 ``body`` is the child's inbound ``params``
serialized verbatim; the gateway NEVER parses it (hard rule #5).

THIS module is the core-side receiver that turns that envelope back into a
dispatched inbound. It is the highest-value trust seam in the system: untrusted T3
crossing from the network-facing gateway into the trusted core. Its job, in order:

1. **K4 admission** — the ENVELOPE ``adapter_id`` (the gateway spawn-binding routing
   key, SEC-309-1 — NEVER the body) must name a registered per-adapter collaborator
   set. An unregistered adapter is a loud refusal, never default-routed.
2. **Re-parse** — :func:`~alfred.comms_mcp.inbound_reparse.reparse_forwarded_inbound`
   is the SOLE body parser (core-side, the trusted boundary). The receiver itself
   NEVER ``json.loads`` the body (SEC-309-1). Re-parse enforces the §3.3 F3
   mitigation (envelope==body ``adapter_id`` equality) and scrubs any body-smuggled
   ``wire_seq`` to ``None``.
3. **wire_seq rebind** — the REAL leg-carrier ``wire_seq`` (out-of-band header the
   core read off its OWN wire) is rebound onto the notification, replacing the
   re-parse's scrubbed ``None`` — never a body-derived value (ADR-0032).
4. **Dispatch on the DISPATCHED edge** — through ``process_inbound_message`` with
   the per-``adapter_id`` collaborator set and ``commit_at_dispatch_edge=True`` (the
   G0 ``commit_once`` + the durable-intake ``observe`` move to AFTER a successful
   dispatch, so a dispatch failure leaves the frame un-committed/un-observed and the
   forwarding leg replays it — ADR-0039 item 4).

TERMINAL DROPS — drain after the signed audit (ARCH-309-3 / hard rule #7). Each of
the three terminal dispositions (unknown adapter / envelope-body mismatch /
malformed body) writes ONE SIGNED audit row carrying ONLY the closed-vocab ENVELOPE
``adapter_id`` + a fixed closed-vocab reason code (NEVER ``str(exc)`` / the raw T3
body — the leak-safe structural summary goes to a structlog ``.warning`` only), THEN
``observe``\\s the leg ``wire_seq`` to DRAIN it. Draining is non-optional: an
un-observed drop on a live contiguous-seq leg wedges the high-water and the gateway
replays it forever. The drain happens ONLY AFTER the audit row WROTE — an
audit-write failure PROPAGATES out of :meth:`~GatewayForwardedInboundReceiver.receive`
(Task 4's disposition arm escalates it as a non-skippable security event) and the
frame is left un-drained so it is NOT silently dropped without a record.

FAIL-LOUD on misconfig. :class:`~alfred.comms_mcp.errors.PromoterRequiredError` (a
boot/wiring fault ``process_inbound_message`` raises) is NOT caught — it propagates.

RUNS CORE-SIDE ONLY. The carrier (the gateway leg) is payload-BLIND; only the core
re-parses the body. The receiver is a per-boot SINGLETON; its ack tracker is bound
PER accepted connection via :meth:`~GatewayForwardedInboundReceiver.set_ack_tracker`.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING

import structlog

from alfred.audit import audit_row_schemas
from alfred.comms_mcp.errors import (
    InboundBodyMalformedError,
    InboundEnvelopeBodyMismatchError,
)
from alfred.comms_mcp.inbound import (
    _AckTrackerLike,
    _AuditWriterLike,
    _BurstLimiterLike,
    _IdentityResolverLike,
    _InboundIdempotencyStoreLike,
    _OrchestratorLike,
    _PreResolutionLimiter,
    _SecretBrokerLike,
    _SubPayloadPromoterLike,
    process_inbound_message,
)
from alfred.comms_mcp.inbound_reparse import reparse_forwarded_inbound
from alfred.comms_mcp.protocol import GatewayAdapterInboundEnvelope

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

_log = structlog.get_logger(__name__)

# Closed-vocab reason discriminators for the three terminal drops. Bound to
# constants so the emit sites and the audit-row vocabulary cannot drift.
_REASON_UNKNOWN_ADAPTER = "unknown_adapter"
_REASON_ENVELOPE_BODY_MISMATCH = "envelope_body_mismatch"
_REASON_BODY_MALFORMED = "body_malformed"


@dataclass(frozen=True, slots=True)
class _ForwardedCollaborators:
    """The per-``adapter_id`` collaborator set the dispatched-edge pipeline needs.

    One entry per registered (gateway-forwarded) adapter kind. Every field mirrors
    the matching ``process_inbound_message`` parameter; the receiver threads them
    through unchanged. ``pre_resolution_limiter`` MUST be a LONG-LIVED instance per
    adapter (sec-003) so the coarse per-``(adapter_id, platform_user_id_hash)`` DoS
    budget accumulates across the flood of inbounds a single platform user can send
    — the registry holds exactly one per adapter for the receiver's whole lifetime.

    ``resolver_bridge`` is the host-side identity resolver (named ``resolver_bridge``
    because the daemon wiring bridges the sync ORM resolver into the async
    :class:`~alfred.comms_mcp.inbound._IdentityResolverLike` surface).
    """

    sub_payload_promoter: _SubPayloadPromoterLike
    resolver_bridge: _IdentityResolverLike
    orchestrator: _OrchestratorLike
    burst_limiter: _BurstLimiterLike
    secret_broker: _SecretBrokerLike
    pre_resolution_limiter: _PreResolutionLimiter


class GatewayForwardedInboundReceiver:
    """Turns a ``gateway.adapter.inbound`` envelope into a dispatched core inbound.

    Per-boot singleton (one per core). The per-connection ack tracker is bound after
    each accepted gateway connection via :meth:`set_ack_tracker`; the receiver itself
    outlives any single connection.
    """

    def __init__(
        self,
        *,
        registry: Mapping[str, _ForwardedCollaborators],
        idempotency_store: _InboundIdempotencyStoreLike,
        audit_writer: _AuditWriterLike,
        dispatch: Callable[..., Awaitable[None]] = process_inbound_message,
    ) -> None:
        self._registry = registry
        self._idempotency_store = idempotency_store
        self._audit_writer = audit_writer
        self._dispatch = dispatch
        # Per-connection mutable slot. The receiver is a per-boot singleton; the
        # tracker is bound per accepted connection (None until set — an un-set
        # tracker makes the drain a no-op, which is correct for an un-sequenced leg).
        self._ack_tracker: _AckTrackerLike | None = None

    def set_ack_tracker(self, ack_tracker: _AckTrackerLike) -> None:
        """Bind the per-connection durable-intake ack tracker (post-handshake)."""
        self._ack_tracker = ack_tracker

    async def receive(self, *, params: object, wire_seq: int | None) -> None:
        """Admit, re-parse, rebind, and dispatch one forwarded inbound.

        On a terminal drop (unknown adapter / envelope-body mismatch / malformed
        body) writes the signed audit row, drains the leg ``wire_seq``, and returns
        — never raises for a drop. An audit-write failure on a drop PROPAGATES (the
        frame is left un-drained so the drop is never un-recorded). A
        ``ValidationError`` from the off-vocab envelope ``adapter_id`` surfaces loud
        at the wire; :class:`PromoterRequiredError` from the dispatch propagates.
        """
        # The off-vocab envelope ``adapter_id`` fails the closed-vocab AdapterId
        # validator HERE — a loud ValidationError at the wire, before any logic.
        envelope = GatewayAdapterInboundEnvelope.model_validate(params)

        # K4 admission. Route on the ENVELOPE ``adapter_id`` (the gateway
        # spawn-binding key, SEC-309-1) — NEVER the body. An unregistered adapter is
        # refused on the registry miss ALONE, BEFORE any body parse (so the receiver
        # never ``json.loads`` the body itself).
        if envelope.adapter_id not in self._registry:
            await self._audit_drop(
                adapter_id=envelope.adapter_id,
                reason=_REASON_UNKNOWN_ADAPTER,
                result="refused",
            )
            self._drain(wire_seq)
            return

        # The SOLE body parser is core-side. It enforces the §3.3 F3 equality check
        # (envelope==body adapter_id) and scrubs any body-smuggled wire_seq → None.
        try:
            notification = reparse_forwarded_inbound(envelope)
        except InboundEnvelopeBodyMismatchError:
            await self._audit_drop(
                adapter_id=envelope.adapter_id,
                reason=_REASON_ENVELOPE_BODY_MISMATCH,
                result="refused",
            )
            self._drain(wire_seq)
            return
        except InboundBodyMalformedError as exc:
            # The structural summary is LEAK-SAFE (closed structural shape, no T3 —
            # see inbound_reparse._structural_summary) so it may aid an operator in
            # a structlog line, but it NEVER lands on the signed row (spec §3.3).
            _log.warning(
                "comms.forwarded_inbound.body_malformed",
                adapter_id=envelope.adapter_id,
                structural_summary=str(exc),
            )
            await self._audit_drop(
                adapter_id=envelope.adapter_id,
                reason=_REASON_BODY_MALFORMED,
                result="dropped",
            )
            self._drain(wire_seq)
            return

        # Rebind the REAL leg-carrier wire_seq (the re-parse scrubbed the
        # body-derived value to None; ADR-0032 rebinds the host-authoritative seq
        # out-of-band here). model_copy is frozen-safe and re-runs no validation.
        notification = notification.model_copy(update={"wire_seq": wire_seq})

        collab = self._registry[envelope.adapter_id]
        await self._dispatch(
            notification,
            identity_resolver=collab.resolver_bridge,
            orchestrator=collab.orchestrator,
            burst_limiter=collab.burst_limiter,
            audit_writer=self._audit_writer,
            secret_broker=collab.secret_broker,
            pre_resolution_limiter=collab.pre_resolution_limiter,
            sub_payload_promoter=collab.sub_payload_promoter,
            idempotency_store=self._idempotency_store,
            ack_tracker=self._ack_tracker,
            commit_at_dispatch_edge=True,
        )

    def _drain(self, wire_seq: int | None) -> None:
        """ACK the leg ``wire_seq`` to drain a terminal drop (ARCH-309-3).

        Called ONLY after the drop's signed audit row WROTE — the audit helper
        raises BEFORE the caller reaches here on a write failure, so a failed audit
        never drains an un-recorded drop. A None tracker (no connection bound yet)
        or a None ``wire_seq`` (un-sequenced leg) makes this a no-op.
        """
        if self._ack_tracker is not None and wire_seq is not None:
            self._ack_tracker.observe(wire_seq)

    async def _audit_drop(self, *, adapter_id: str, reason: str, result: str) -> None:
        """Write the ONE signed, content-free row for a terminal drop.

        Carries ONLY the closed-vocab ENVELOPE ``adapter_id`` (the routing key, never
        the body — SEC-309-1), the fixed closed-vocab ``reason`` discriminator, and
        the observation time. NO raw T3 body, NO ``inbound_id`` (the body may not have
        re-parsed), NO ``str(exc)`` (spec §3.3). REUSES an in-domain ``result`` value
        (``refused`` for the K4/forge refusals, ``dropped`` for the malformed-body
        drain) so no migration is needed. An ``append_schema`` write failure
        PROPAGATES — the caller does NOT catch it, so the drain is short-circuited and
        Task 4's disposition arm escalates the non-skippable audit-write fault.
        """
        await self._audit_writer.append_schema(
            fields=audit_row_schemas.COMMS_FORWARDED_INBOUND_DROPPED_FIELDS,
            schema_name="COMMS_FORWARDED_INBOUND_DROPPED_FIELDS",
            event="comms.forwarded_inbound.dropped",
            actor_user_id=None,
            subject={
                "adapter_id": adapter_id,
                "reason": reason,
                "observed_at": datetime.now(UTC).isoformat(),
            },
            trust_tier_of_trigger="T3",
            result=result,
            cost_estimate_usd=0.0,
            # sec-010: trace_id is a persisted, indexed column — the ENVELOPE
            # adapter_id (closed-vocab, non-secret) is the only safe correlation
            # token here (a drop carries no resolved user / inbound_id to hash).
            trace_id=adapter_id,
        )


__all__ = ["GatewayForwardedInboundReceiver", "_ForwardedCollaborators"]
