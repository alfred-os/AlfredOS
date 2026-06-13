"""Plugin -> host notification handlers (PR-S4-8, #152).

The four handler **protocols** (``InboundHandler``, ``BindingHandler``,
``RateLimitHandler``, ``CrashHandler``) define the structural contract the
session dispatcher (Wave 3 ``_on_post_handshake_method`` extension) fans out to;
each declares ``async def process(self, notification) -> None``. The concrete
classes implement them:

* :class:`InboundMessageHandler` -> :func:`process_inbound_message`.
* :class:`BindingRequestHandler` -> emits ``COMMS_BINDING_REQUESTED_FIELDS``
  for a first-contact platform user (the out-of-band verification-phrase
  delivery is Slice-5 scope).
* :class:`PlatformRateLimitHandler` -> comms-001 round-2 contract: emit
  ``COMMS_RATE_LIMIT_SIGNAL_FIELDS`` and, when the platform's ``retry_after``
  exceeds the global-exhaustion threshold, trip the comms-adapter breaker.
* :class:`AdapterCrashHandler` -> emits ``COMMS_ADAPTER_CRASHED_FIELDS`` and
  fires the ``comms.adapter.crashed`` hookpoint.

Wire-shape reconciliation (foundation gap). The shipped Wave-1
:class:`alfred.comms_mcp.protocol.RateLimitSignal` carries
``(adapter_id, retry_after_seconds, platform_endpoint)`` — NOT the plan's
``(scope, scope_key, retry_after_ms)`` shape. This handler implements comms-001
against the REAL shipped shape: the global-exhaustion breaker trip fires when
``retry_after_seconds`` exceeds :data:`_GLOBAL_EXHAUSTION_THRESHOLD_SECONDS`
(the 30s round-2 threshold, re-expressed in seconds). When PR-S4-9 lands the
scoped signal, the scope discriminator can be threaded through additively.

The breaker trip + hookpoint fire are injected structural dependencies
(:class:`_BreakerTripperLike`, :class:`_HookInvokerLike`) because the Slice-3
:class:`alfred.supervisor.breaker.CircuitBreaker` exposes ``record_failure`` /
internal ``_trip``, not a public ``trip(reason=...)`` (arch-004 confirmed). The
comms host (Wave 3) wires the concrete tripper / invoker; keeping them behind a
seam means the handler defines the contract without fabricating a non-existent
supervisor method.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Protocol, runtime_checkable

import structlog

from alfred.audit import audit_row_schemas
from alfred.comms_mcp import audit_hash
from alfred.comms_mcp.inbound import (
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
from alfred.security.dlp import redact_secret_shapes

if TYPE_CHECKING:
    from alfred.comms_mcp.protocol import (
        BindingRequestNotification,
        CrashedNotification,
        InboundMessageNotification,
        RateLimitSignal,
    )

_log = structlog.get_logger(__name__)

# comms-001 round-2: a platform-reported retry-after beyond this threshold is
# treated as global exhaustion and trips the comms-adapter breaker. The plan's
# threshold was 30000ms; the shipped signal is in seconds, so 30s here.
_GLOBAL_EXHAUSTION_THRESHOLD_SECONDS = 30

# Closed-vocab reason for the comms-adapter breaker trip on global exhaustion.
_RATE_LIMIT_EXHAUSTED_REASON = "comms.rate_limit.exhausted"

# Closed-vocab reason bucket for an adapter self-reported crash. The open-vocab
# Python exception type lands on ``error_class``; ``reason`` is the SLO bucket.
_CRASH_REASON_SELF_REPORTED = "adapter_self_reported"

# Bound on the redacted crash detail carried into the audit row.
_MAX_CRASH_DETAIL_LEN = 256


# ---------------------------------------------------------------------------
# Handler protocols (structural contract for the session dispatcher)
# ---------------------------------------------------------------------------


@runtime_checkable
class InboundHandler(Protocol):
    """Handles ``inbound.message`` notifications."""

    async def process(self, notification: InboundMessageNotification) -> None: ...


@runtime_checkable
class BindingHandler(Protocol):
    """Handles ``adapter.binding_request`` notifications."""

    async def process(self, notification: BindingRequestNotification) -> None: ...


@runtime_checkable
class RateLimitHandler(Protocol):
    """Handles ``adapter.rate_limit_signal`` notifications."""

    async def process(self, notification: RateLimitSignal) -> None: ...


@runtime_checkable
class CrashHandler(Protocol):
    """Handles ``adapter.crashed`` notifications."""

    async def process(self, notification: CrashedNotification) -> None: ...


# ---------------------------------------------------------------------------
# Injected structural dependencies for the rate-limit / crash handlers
# ---------------------------------------------------------------------------


@runtime_checkable
class _BreakerTripperLike(Protocol):
    """Trips the comms-adapter breaker (Wave-3 supervisor wiring provides it)."""

    async def trip_comms_breaker(self, *, adapter_id: str, reason: str) -> None: ...


@runtime_checkable
class _HookInvokerLike(Protocol):
    """Fires the ``comms.adapter.crashed`` hookpoint (Wave-3 wiring provides it)."""

    async def fire_adapter_crashed(self, *, adapter_id: str, error_class: str) -> None: ...


# ---------------------------------------------------------------------------
# Concrete handlers
# ---------------------------------------------------------------------------


class InboundMessageHandler:
    """Routes ``inbound.message`` through :func:`process_inbound_message`.

    sec-003: the handler is the long-lived host object that the session
    dispatcher fans ``inbound.message`` notifications out to, so it OWNS the
    persistent :class:`_PreResolutionLimiter`. A fresh limiter per message would
    reset the coarse per-``(adapter_id, platform_user_id_hash)`` budget every
    time and make the pre-resolution DoS gate a no-op in production; holding it
    on the handler is what lets the budget actually accumulate across the flood
    of messages a single platform user can send.
    """

    def __init__(
        self,
        *,
        identity_resolver: _IdentityResolverLike,
        orchestrator: _OrchestratorLike,
        burst_limiter: _BurstLimiterLike,
        audit_writer: _AuditWriterLike,
        secret_broker: _SecretBrokerLike,
        pre_resolution_limiter: _PreResolutionLimiter | None = None,
        sub_payload_promoter: _SubPayloadPromoterLike | None = None,
        idempotency_store: _InboundIdempotencyStoreLike | None = None,
    ) -> None:
        self._identity_resolver = identity_resolver
        self._orchestrator = orchestrator
        self._burst_limiter = burst_limiter
        self._audit_writer = audit_writer
        self._secret_broker = secret_broker
        # H1: wire the authoritative comms hash recipe to the process broker at
        # the host CONSTRUCTION seam, so it is LIVE before the first inbound
        # (the per-message ``set_broker`` in process_inbound_message is the cheap
        # idempotent safety net, not the only wiring point).
        audit_hash.set_broker(secret_broker)
        # P1: per-adapter sub-payload promoter (None → inert for the reference
        # plugin's empty required-classifier set). Forwarded on every process call.
        self._sub_payload_promoter = sub_payload_promoter
        # G0 (Spec A): the durable accept-once store. None → idempotency inert
        # (pre-G0 unit callers); production injects a PostgresInboundIdempotencyStore.
        self._idempotency_store = idempotency_store
        # Persistent across every ``process`` call (sec-003). Tests may inject a
        # pre-loaded limiter to drive the cap deterministically; production
        # leaves it defaulted so the handler mints exactly one and keeps it.
        self._pre_resolution_limiter = (
            pre_resolution_limiter
            if pre_resolution_limiter is not None
            else _PreResolutionLimiter()
        )

    async def process(self, notification: InboundMessageNotification) -> None:
        await process_inbound_message(
            notification,
            identity_resolver=self._identity_resolver,
            orchestrator=self._orchestrator,
            burst_limiter=self._burst_limiter,
            audit_writer=self._audit_writer,
            secret_broker=self._secret_broker,
            pre_resolution_limiter=self._pre_resolution_limiter,
            sub_payload_promoter=self._sub_payload_promoter,
            idempotency_store=self._idempotency_store,
        )


class BindingRequestHandler:
    """Emits ``COMMS_BINDING_REQUESTED_FIELDS`` for a first-contact user.

    Both the platform user id and the plugin-supplied verification phrase are
    peppered-hashed before they reach the audit row (sec-010) — the raw phrase
    is never echoed. The out-of-band phrase delivery (the actual binding UX) is
    Slice-5 scope.
    """

    def __init__(self, *, audit_writer: _AuditWriterLike, secret_broker: _SecretBrokerLike) -> None:
        self._audit_writer = audit_writer
        self._secret_broker = secret_broker
        # H1: wire the authoritative comms hash recipe at construction (live
        # before the first binding row); the per-call set_broker is the cheap
        # idempotent safety net.
        audit_hash.set_broker(secret_broker)

    async def process(self, notification: BindingRequestNotification) -> None:
        # Wire the authoritative comms hash recipe (closure comms-1) to this
        # handler's broker; idempotent on the same broker object. The
        # verification-phrase and platform-user-id hashes use per-field domain
        # separation so a phrase digest can never collide with a user-id digest.
        audit_hash.set_broker(self._secret_broker)
        await self._audit_writer.append_schema(
            fields=audit_row_schemas.COMMS_BINDING_REQUESTED_FIELDS,
            schema_name="COMMS_BINDING_REQUESTED_FIELDS",
            event="comms.binding.requested",
            actor_user_id=None,
            subject={
                "adapter_id": notification.adapter_id,
                "platform_user_id_hash": audit_hash.hash_platform_user_id(
                    notification.platform_user_id
                ),
                "verification_phrase_hash": audit_hash.hash_verification_phrase(
                    notification.verification_phrase
                ),
                "requested_at": datetime.now(UTC).isoformat(),
                "language": "en-US",
            },
            trust_tier_of_trigger="T3",
            result="binding_requested",
            cost_estimate_usd=0.0,
            trace_id=uuid.uuid4().hex,
            language="en-US",
        )


class PlatformRateLimitHandler:
    """comms-001: emits the rate-limit audit row + trips on global exhaustion."""

    def __init__(
        self,
        *,
        breaker_tripper: _BreakerTripperLike,
        audit_writer: _AuditWriterLike,
    ) -> None:
        self._breaker_tripper = breaker_tripper
        self._audit_writer = audit_writer

    async def process(self, notification: RateLimitSignal) -> None:
        await self._audit_writer.append_schema(
            fields=audit_row_schemas.COMMS_RATE_LIMIT_SIGNAL_FIELDS,
            schema_name="COMMS_RATE_LIMIT_SIGNAL_FIELDS",
            event="comms.rate_limit.signal_received",
            actor_user_id=None,
            subject={
                "adapter_id": notification.adapter_id,
                "platform_endpoint": notification.platform_endpoint,
                "retry_after_seconds": notification.retry_after_seconds,
                "signalled_at": datetime.now(UTC).isoformat(),
            },
            trust_tier_of_trigger="T3",
            result="rate_limited",
            cost_estimate_usd=0.0,
            trace_id=notification.adapter_id,
        )
        if notification.retry_after_seconds > _GLOBAL_EXHAUSTION_THRESHOLD_SECONDS:
            await self._breaker_tripper.trip_comms_breaker(
                adapter_id=notification.adapter_id,
                reason=_RATE_LIMIT_EXHAUSTED_REASON,
            )


class AdapterCrashHandler:
    """Emits ``COMMS_ADAPTER_CRASHED_FIELDS`` + fires ``comms.adapter.crashed``."""

    def __init__(self, *, audit_writer: _AuditWriterLike, hook_invoker: _HookInvokerLike) -> None:
        self._audit_writer = audit_writer
        self._hook_invoker = hook_invoker

    async def process(self, notification: CrashedNotification) -> None:
        await self._audit_writer.append_schema(
            fields=audit_row_schemas.COMMS_ADAPTER_CRASHED_FIELDS,
            schema_name="COMMS_ADAPTER_CRASHED_FIELDS",
            event="comms.adapter.crashed",
            actor_user_id=None,
            subject={
                "adapter_id": notification.adapter_id,
                "error_class": notification.error_class,
                "reason": _CRASH_REASON_SELF_REPORTED,
                # The plugin is UNTRUSTED (T3): its claim to have redacted
                # ``detail`` cannot be trusted, and the CrashedNotification
                # docstring says the host re-scrubs. Re-run the secret-shape
                # redactor host-side BEFORE bounding the length, so a leaked
                # ``sk-…``-shaped token never reaches the audit log
                # (CLAUDE.md hard rule 1).
                "detail_redacted": redact_secret_shapes(notification.detail)[
                    :_MAX_CRASH_DETAIL_LEN
                ],
                "crashed_at": datetime.now(UTC).isoformat(),
            },
            # Provenance (PRD §7.1): the row is TRIGGERED by an UNTRUSTED plugin
            # self-reporting a crash, so the trigger tier is T3 — same as the
            # sibling binding / rate-limit rows, which are also plugin-triggered.
            # Tagging it T0 would misrepresent an untrusted plugin's self-report
            # as a trusted system trigger. (The ``comms.adapter.crashed``
            # HOOKPOINT keeps ``carrier_tier=T0`` per spec §10 — carrier_tier is
            # the surrounding host-daemon action's tier, a distinct concept from
            # this trigger-provenance field.)
            trust_tier_of_trigger="T3",
            result="crashed",
            cost_estimate_usd=0.0,
            trace_id=notification.adapter_id,
        )
        await self._hook_invoker.fire_adapter_crashed(
            adapter_id=notification.adapter_id,
            error_class=notification.error_class,
        )


__all__ = [
    "AdapterCrashHandler",
    "BindingHandler",
    "BindingRequestHandler",
    "CrashHandler",
    "InboundHandler",
    "InboundMessageHandler",
    "PlatformRateLimitHandler",
    "RateLimitHandler",
]
