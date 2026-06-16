"""Host-side ``process_inbound_message`` entrypoint (PR-S4-8, #152).

The single chokepoint through which a plugin-reported inbound platform message
crosses the comms trust boundary. It enforces the **load-bearing order**
(spec §8.2):

    resolution -> burst-limit acquire -> quarantined_extract -> ingest -> dispatch

Each step gates the next:

* **resolution** — :meth:`_IdentityResolverLike.resolve` runs host-side. A
  ``None`` result (first-contact / unbound platform user) emits
  ``COMMS_BINDING_REQUESTED_FIELDS`` and returns early — NO extract, NO ingest,
  NO dispatch. The binding flow's out-of-band verification-phrase delivery is
  Slice-5 scope; this PR emits an internally-generated placeholder phrase hash.
* **burst-limit acquire** — :meth:`BurstLimiter.acquire` caps sub-second bursts
  per ``(canonical_user_id, persona)``. A ``Dropped`` result returns early
  before the (expensive) quarantined extract — the bucket refuses to call the
  extractor when empty (sec-003 / spec §8.2).
* **quarantined_extract** — :meth:`Orchestrator.quarantined_extract` funnels the
  T3 body into the quarantined extractor with ``source_tier="T3"`` hard-coded.
  No path promotes a comms inbound body to T2 (sec-001 round-3).
* **ingest + dispatch** — the structured (T3-derived) result is ingested then
  dispatched to the orchestrator's per-turn machinery.

Identity invariant (spec §8.2 last paragraph). The canonical ``user_id`` never
crosses the stdio boundary outward — it is resolved host-side and stays
host-side. Every audit row carries the **peppered hash** of the
``platform_user_id`` (sec-010), never the raw value; the pepper is sourced from
:meth:`SecretBroker.get` for ``audit.hash_pepper``.

Pre-resolution DoS guard (sec-003 round-2). :class:`_PreResolutionLimiter` is a
coarse per-``(adapter_id, platform_user_id_hash)`` limiter that runs BEFORE the
resolver so an unbound-user flood cannot drive unbounded resolver lookups. The
cheap pre-check :func:`_inbound_message_cheap_validate` rejects empty / oversized
payloads before any expensive work (perf-003).
"""

from __future__ import annotations

import time
import uuid
from collections import OrderedDict
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Literal, Protocol, runtime_checkable

import structlog

from alfred.audit import audit_row_schemas
from alfred.comms_mcp import audit_hash, observability
from alfred.comms_mcp.classifier_registry import REQUIRED_CLASSIFIERS_BY_KIND
from alfred.comms_mcp.errors import PromoterRequiredError

if TYPE_CHECKING:
    from alfred.comms_mcp.protocol import InboundMessageNotification
    from alfred.comms_mcp.sub_payload_promotion import PromotedBody
    from alfred.orchestrator.burst_limiter import Acquired, Dropped
    from alfred.security.quarantine import ExtractionResult

_log = structlog.get_logger(__name__)

# Cheap pre-check bounds (perf-003). The body's plain-text field can be large
# for rich platforms, but the cheap gate only checks the raw notification's
# top-level identifiers; the body itself is validated by Pydantic AFTER the
# burst gate so the validation cost is not paid for dropped messages.
_MAX_PLATFORM_USER_ID_LEN = 512

# Pre-resolution coarse limiter defaults (sec-003 round-2). Keyed on the
# peppered ``(adapter_id, platform_user_id_hash)`` so cardinality stays bounded
# and the raw id is never a dict key.
_PRE_RESOLUTION_LIMIT_PER_MINUTE = 50
_PRE_RESOLUTION_WINDOW_SECONDS = 60.0
_PRE_RESOLUTION_MAX_TRACKED_KEYS = 10_000

# Placeholder verification phrase for the first-contact binding row. The real
# out-of-band phrase delivery is Slice-5 scope; this PR emits a host-generated
# random phrase whose peppered hash anchors the audit row.
_PERSONA_DEFAULT = "alfred"


@dataclass(frozen=True, slots=True)
class ResolvedInbound:
    """Host-side identity resolution result for an inbound comms message.

    Carries exactly what the downstream steps need — the canonical user id, the
    addressed persona, the user's BCP-47 language, and the adapter id — and
    nothing that should cross the stdio boundary outward. The real
    :class:`alfred.identity.resolver.IdentityResolver` is sync and returns a
    ``User``; the comms host (Wave 3) bridges that into this frozen value so the
    inbound entrypoint stays decoupled from the ORM and the canonical id is the
    only identity token it handles.
    """

    canonical_user_id: str
    persona: str
    language: str
    adapter_id: str


@runtime_checkable
class _IdentityResolverLike(Protocol):
    """Structural type for the host-side comms identity resolver."""

    async def resolve(
        self, *, adapter_id: str, platform_user_id: str
    ) -> ResolvedInbound | None: ...


@runtime_checkable
class _OrchestratorLike(Protocol):
    """Structural type for the orchestrator surface the inbound path uses."""

    async def quarantined_extract(
        self,
        body: bytes | str | Mapping[str, object],
        *,
        canonical_user_id: str,
        source_tier: Literal["T3"],
    ) -> ExtractionResult: ...

    async def ingest(self, **kwargs: Any) -> object: ...

    async def dispatch(self, ingested: object) -> None: ...


@runtime_checkable
class _BurstLimiterLike(Protocol):
    """Structural type for the per-(user, persona) burst limiter."""

    async def acquire(
        self,
        *,
        canonical_user_id: str,
        persona: str,
        adapter_id: str = ...,
        language: str = ...,
    ) -> Acquired | Dropped: ...


@runtime_checkable
class _AuditWriterLike(Protocol):
    """Structural type for the audit-row sink."""

    async def append_schema(self, **kwargs: Any) -> None: ...

    async def append(self, **kwargs: Any) -> None: ...


@runtime_checkable
class _SecretBrokerLike(Protocol):
    """Structural type for the secret broker (``audit.hash_pepper`` source)."""

    def get(self, name: str) -> str: ...


@runtime_checkable
class _InboundIdempotencyStoreLike(Protocol):
    """Structural type for the durable accept-once commit (Spec A / G0)."""

    async def commit_once(self, *, inbound_id: str, adapter_id: str) -> bool: ...


@runtime_checkable
class _AckTrackerLike(Protocol):
    """Structural type for the host durable-intake ack tracker (Spec A / G4b-2a-pre).

    The daemon's per-connection ``BoundedSeqAckTracker`` (reused from the gateway —
    ``gateway/_seq_tracker.py``); this module binds to its SHAPE (``observe``) so it
    stays decoupled from the gateway package. ``observe`` is pure-CPU (no ``await``),
    so the ``commit_once``->``observe`` pair is atomic w.r.t. the single-threaded
    event loop and needs no lock under the runner's concurrent dispatch fan-out.
    """

    def observe(self, seq: int) -> None: ...


@runtime_checkable
class _SubPayloadPromoterLike(Protocol):
    """Structural type for the host-side sub-payload promoter (P1).

    Runs BEFORE ``quarantined_extract`` to replace every recognised sub-payload
    in the (T3) body with a single-use ``ContentHandle`` reference so the
    privileged orchestrator never sees raw sub-payload bytes. A ``None`` promoter
    means promotion is inert (reference plugin / empty required-classifier set).
    """

    async def promote(self, body: Mapping[str, object]) -> PromotedBody: ...


def _inbound_message_cheap_validate(*, platform_user_id: object, body: object) -> bool:
    """Cheap pre-check before any expensive work (perf-003).

    Validates only that ``platform_user_id`` is a non-empty, bounded string and
    that ``body`` is a mapping carrying something. Returns ``False`` to refuse
    immediately — no Pydantic, no resolver, no semaphore. Full
    :class:`InboundMessageNotification` validation runs later, after the burst
    gate, so the validation cost is not paid for dropped messages.
    """
    if not isinstance(platform_user_id, str):
        return False
    if not platform_user_id or len(platform_user_id) > _MAX_PLATFORM_USER_ID_LEN:
        return False
    # An empty mapping carries no body — refuse it at the cheap gate rather than
    # paying for Pydantic validation + resolver lookup on content-free traffic
    # (perf-003 / CR #232 follow-up). ``bool({})`` is ``False``.
    return isinstance(body, Mapping) and bool(body)


class _PreResolutionLimiter:
    """Coarse per-``(adapter_id, platform_user_id_hash)`` sliding-window limiter.

    Runs BEFORE :meth:`_IdentityResolverLike.resolve` (sec-003 round-2 closure)
    so an unbound-user flood cannot drive unbounded resolver lookups. Keyed on
    the peppered hash — the raw ``platform_user_id`` is never a dict key, and the
    LRU cap bounds memory against an adversary cycling distinct ids.
    """

    def __init__(
        self,
        *,
        limit_per_minute: int = _PRE_RESOLUTION_LIMIT_PER_MINUTE,
        window_seconds: float = _PRE_RESOLUTION_WINDOW_SECONDS,
        max_tracked_keys: int = _PRE_RESOLUTION_MAX_TRACKED_KEYS,
        monotonic: Any = time.monotonic,
    ) -> None:
        self._limit = limit_per_minute
        self._window = window_seconds
        self._max_tracked = max_tracked_keys
        self._monotonic = monotonic
        # key -> list of monotonic timestamps within the window.
        self._hits: OrderedDict[tuple[str, str], list[float]] = OrderedDict()

    def check_and_record(self, *, adapter_id: str, platform_user_id_hash: str) -> bool:
        """Record a hit; return ``True`` if within budget, ``False`` if capped."""
        key = (adapter_id, platform_user_id_hash)
        now = self._monotonic()
        cutoff = now - self._window
        timestamps = self._hits.get(key)
        if timestamps is None:
            timestamps = []
            self._hits[key] = timestamps
            self._evict_if_needed()
        else:
            self._hits.move_to_end(key)
        # Age out timestamps older than the window.
        fresh = [ts for ts in timestamps if ts > cutoff]
        if len(fresh) >= self._limit:
            self._hits[key] = fresh
            return False
        fresh.append(now)
        self._hits[key] = fresh
        return True

    def _evict_if_needed(self) -> None:
        while len(self._hits) > self._max_tracked:
            self._hits.popitem(last=False)


async def _emit_binding_request(
    notification: InboundMessageNotification,
    *,
    audit_writer: _AuditWriterLike,
    language: str,
) -> None:
    """Emit ``COMMS_BINDING_REQUESTED_FIELDS`` for a first-contact inbound.

    The ``platform_user_id`` and the host-generated verification phrase are both
    hashed via the authoritative comms ``audit_hash`` recipe (HKDF subkey +
    per-field domain separation, closure comms-1) before they land on the row
    (sec-010) — so ``hash(phrase)`` can never collide with ``hash(user_id)``. The
    phrase itself is a placeholder for the Slice-5 out-of-band binding flow; its
    hash anchors the audit row so a later flow can correlate the binding attempt
    without ever storing the raw phrase.
    """
    phrase = uuid.uuid4().hex
    platform_user_id_hash = audit_hash.hash_platform_user_id(notification.platform_user_id)
    await audit_writer.append_schema(
        fields=audit_row_schemas.COMMS_BINDING_REQUESTED_FIELDS,
        schema_name="COMMS_BINDING_REQUESTED_FIELDS",
        event="comms.binding.requested",
        actor_user_id=None,
        subject={
            "adapter_id": notification.adapter_id,
            "platform_user_id_hash": platform_user_id_hash,
            "verification_phrase_hash": audit_hash.hash_verification_phrase(phrase),
            "requested_at": datetime.now(UTC).isoformat(),
            "language": language,
        },
        trust_tier_of_trigger="T3",
        result="binding_requested",
        cost_estimate_usd=0.0,
        # sec-010: trace_id is a persisted, indexed String(64) column — it must
        # carry the peppered hash, NEVER the raw platform_user_id.
        trace_id=platform_user_id_hash,
        language=language,
    )


async def _emit_t3_promotion(
    notification: InboundMessageNotification,
    *,
    resolved: ResolvedInbound,
    inbound_message_id: str,
    sub_payload_kinds: frozenset[str],
    audit_writer: _AuditWriterLike,
) -> None:
    """Emit ``COMMS_INBOUND_T3_PROMOTION_FIELDS`` after a successful extract."""
    await audit_writer.append_schema(
        fields=audit_row_schemas.COMMS_INBOUND_T3_PROMOTION_FIELDS,
        schema_name="COMMS_INBOUND_T3_PROMOTION_FIELDS",
        event="comms.inbound.t3_promoted",
        actor_user_id=resolved.canonical_user_id,
        subject={
            "adapter_id": notification.adapter_id,
            "inbound_message_id": inbound_message_id,
            "platform_user_id_hash": audit_hash.hash_platform_user_id(
                notification.platform_user_id
            ),
            "canonical_user_id": resolved.canonical_user_id,
            # JSONB-serializable: a frozenset is not JSON-encodable, so the
            # audit row carries a sorted list. Determinism keeps the row stable
            # across runs for forensic diffing.
            "sub_payload_kinds": sorted(sub_payload_kinds),
            "language": resolved.language,
            "addressing_signal": notification.addressing_signal,
        },
        trust_tier_of_trigger="T3",
        result="promoted",
        cost_estimate_usd=0.0,
        trace_id=inbound_message_id,
        language=resolved.language,
    )


async def _emit_promoter_required(
    notification: InboundMessageNotification,
    *,
    audit_writer: _AuditWriterLike,
) -> None:
    """Emit the M2 fail-closed handler-failure row before raising.

    Uses ``COMMS_HANDLER_FAILED_FIELDS`` with the closed-vocab
    ``reason="promoter_required"`` so an operator sees a loud, structured refusal
    (no platform bytes — ``detail_redacted`` carries only the adapter kind).
    """
    await audit_writer.append_schema(
        fields=audit_row_schemas.COMMS_HANDLER_FAILED_FIELDS,
        schema_name="COMMS_HANDLER_FAILED_FIELDS",
        event="comms.inbound.promoter_required",
        actor_user_id=None,
        subject={
            "adapter_id": notification.adapter_id,
            "notification_method": "inbound.message",
            "handler_class": "process_inbound_message",
            "error_class": "PromoterRequiredError",
            "reason": "promoter_required",
            "detail_redacted": (
                f"adapter_kind {notification.adapter_id!r} requires a sub_payload_promoter"
            ),
            "failed_at": datetime.now(UTC).isoformat(),
        },
        trust_tier_of_trigger="T3",
        result="refused",
        cost_estimate_usd=0.0,
        trace_id=notification.adapter_id,
    )


async def _emit_idempotency_replay_observed(
    notification: InboundMessageNotification,
    *,
    audit_writer: _AuditWriterLike,
) -> None:
    """Emit the content-free replay-observed row when the commit-once loses.

    A replay short-circuit is a side-effecting DROP, so it must be visible in the
    SIGNED audit log — not just a structlog line. The row carries ONLY the
    adapter id, the PEPPERED HASH of the wire ``inbound_id`` (never the raw
    string — sec-010), and the observation time. ``result="dropped"`` reuses the
    existing comms drop result value (no new migration).
    """
    await audit_writer.append_schema(
        fields=audit_row_schemas.COMMS_INBOUND_IDEMPOTENCY_REPLAY_FIELDS,
        schema_name="COMMS_INBOUND_IDEMPOTENCY_REPLAY_FIELDS",
        event="comms.inbound.idempotency.replay_observed",
        actor_user_id=None,
        subject={
            "adapter_id": notification.adapter_id,
            "inbound_id_hash": audit_hash.hash_inbound_id(notification.inbound_id),
            "observed_at": datetime.now(UTC).isoformat(),
        },
        trust_tier_of_trigger="T3",
        result="dropped",
        cost_estimate_usd=0.0,
        # sec-010: trace_id is a persisted, indexed column — it carries the
        # peppered hash of inbound_id, NEVER the raw wire string.
        trace_id=audit_hash.hash_inbound_id(notification.inbound_id),
    )


async def process_inbound_message(
    notification: InboundMessageNotification,
    *,
    identity_resolver: _IdentityResolverLike,
    orchestrator: _OrchestratorLike,
    burst_limiter: _BurstLimiterLike,
    audit_writer: _AuditWriterLike,
    secret_broker: _SecretBrokerLike,
    pre_resolution_limiter: _PreResolutionLimiter | None = None,
    sub_payload_promoter: _SubPayloadPromoterLike | None = None,
    idempotency_store: _InboundIdempotencyStoreLike | None = None,
    ack_tracker: _AckTrackerLike | None = None,
) -> None:
    """Route one inbound comms notification through the trust boundary.

    Enforces the load-bearing order (resolution -> burst-gate ->
    quarantined_extract -> ingest -> dispatch). See the module docstring for the
    per-step contract. ``None`` resolution short-circuits to the binding flow;
    a ``Dropped`` burst result short-circuits before the extractor; every audit
    row carries peppered hashes (sec-010).

    ``pre_resolution_limiter`` (sec-003) MUST be a long-lived instance for the
    coarse per-``(adapter_id, platform_user_id_hash)`` DoS budget to accumulate
    across messages. The production caller — :class:`.handlers.InboundMessageHandler`
    — owns exactly one and threads it on every call. The ``None`` default mints a
    single-shot limiter for unit tests that drive ONE message; passing ``None``
    from a hot loop would reset the budget every message and silently disable the
    gate, so no long-lived caller should rely on the default.
    """
    # Cheap pre-check BEFORE any expensive work (perf-003). The notification is
    # already a validated Pydantic model here, but the cheap gate is the
    # structural seam the (Wave-3) raw-dict dispatcher consults before
    # constructing the model — pinned here against the model's own fields so the
    # invariant is covered by this module's tests.
    if not _inbound_message_cheap_validate(
        platform_user_id=notification.platform_user_id, body=notification.body
    ):
        _log.warning(
            "comms.inbound.cheap_validate_refused",
            adapter_id=notification.adapter_id,
        )
        return

    # M2 fail-closed guard: an adapter kind whose required-classifier set is
    # non-empty (e.g. "discord") MUST receive a non-None promoter. Without one,
    # promotion silently does not happen and the host falls back to trusting the
    # wire-asserted ``sub_payload_refs`` — the exact untrusted-input-trust the
    # required classifier set exists to prevent. Refuse loudly (audit + raise)
    # rather than processing the message, so a misconfigured wiring fails closed.
    if sub_payload_promoter is None and REQUIRED_CLASSIFIERS_BY_KIND.get(
        notification.adapter_id, frozenset()
    ):
        await _emit_promoter_required(notification, audit_writer=audit_writer)
        _log.error(
            "comms.inbound.promoter_required",
            adapter_id=notification.adapter_id,
        )
        msg = (
            f"adapter_kind {notification.adapter_id!r} has a non-empty required-classifier "
            "set but no sub_payload_promoter was wired; refusing to process inbound "
            "without host-side sub-payload promotion"
        )
        raise PromoterRequiredError(msg)

    # Spec A decision 4 (G0): durable accept-once commit on the COMPOSITE
    # (adapter_id, inbound_id), BEFORE any per-message side effect (limiter budget
    # / resolve / binding / extract / audit / ingest / dispatch). A replayed frame
    # (gateway buffer replay after a core restart, or an adapter retry) hits the
    # existing row and short-circuits here so NONE of the side effects re-run —
    # including the unbound-first-contact binding branch, idempotent on the same
    # id by construction. Structural refusals (cheap-validate, promoter-required)
    # stay AHEAD of this so a misconfig fails loud and never consumes an
    # idempotency row. Placed BEFORE the pre-resolution DoS limiter so a replay
    # never re-charges the coarse budget (which would defeat G0). ``None`` store =
    # pre-G0 unit callers; production always injects. A DB error in commit_once
    # PROPAGATES (the store fails loud — hard rule #7); it is not caught here.
    if idempotency_store is not None:
        if not await idempotency_store.commit_once(
            inbound_id=notification.inbound_id,
            adapter_id=notification.adapter_id,
        ):
            # REPLAY branch (commit_once == False) — UNCHANGED. The replay DROP is a
            # side effect → it is AUDITED (signed log), not just logged. Wire the
            # broker so hash_inbound_id can derive the comms subkey.
            audit_hash.set_broker(secret_broker)
            await _emit_idempotency_replay_observed(notification, audit_writer=audit_writer)
            _log.info(
                "comms.inbound.idempotency.replay_short_circuit",
                adapter_id=notification.adapter_id,
            )
            return
        # DURABLE accept (commit_once == True): advance the host durable-intake ack
        # (Spec A G4b-2a-pre / ADR-0032 — F2/F4). The ack means "highest CONTIGUOUS
        # seq the core has DURABLY accepted", so it advances ONLY here — never on the
        # replay branch above, never on the structural refusals ahead of this gate,
        # never on the None-store fallthrough below. ``observe`` is pure-CPU (no
        # ``await``), so the commit_once->observe pair is atomic w.r.t. the single
        # event loop under the runner's concurrent dispatch — no lock needed, and the
        # contiguous high-water is correct regardless of dispatch order. ``wire_seq``
        # is the VALIDATED model field (Task 1's ``ge=0`` validator already ran), so
        # a forged negative can never reach ``observe`` (which would raise).
        if ack_tracker is not None and notification.wire_seq is not None:
            ack_tracker.observe(notification.wire_seq)
    # None-store path (pre-G0 unit callers) falls through UNCHANGED to the rest of
    # the pipeline — it advances no ack (no durable accept was adjudicated).

    # Wire the authoritative comms hash recipe (closure comms-1) to this call's
    # broker. ``set_broker`` is idempotent on the same broker object, so this is
    # cheap to call every message while keeping the dependency explicit (no hidden
    # global construction). All identity hashing below — and in handlers.py —
    # routes through the ONE HKDF + per-field-domain-separation recipe.
    audit_hash.set_broker(secret_broker)
    platform_user_id_hash = audit_hash.hash_platform_user_id(notification.platform_user_id)

    # Pre-resolution coarse limiter (sec-003) — runs BEFORE the resolver. The
    # production caller (InboundMessageHandler) always injects its persistent
    # instance so the budget accumulates; the ``None`` fallback mints a
    # single-shot limiter only for unit tests that drive exactly one message.
    limiter = (
        pre_resolution_limiter if pre_resolution_limiter is not None else _PreResolutionLimiter()
    )
    if not limiter.check_and_record(
        adapter_id=notification.adapter_id,
        platform_user_id_hash=platform_user_id_hash,
    ):
        await _emit_budget_capped_pre_resolution(
            notification,
            platform_user_id_hash=platform_user_id_hash,
            audit_writer=audit_writer,
        )
        return

    # 1) Resolution — host-side, first.
    resolved = await identity_resolver.resolve(
        adapter_id=notification.adapter_id,
        platform_user_id=notification.platform_user_id,
    )
    if resolved is None:
        await _emit_binding_request(
            notification,
            audit_writer=audit_writer,
            language="en-US",
        )
        return

    # 2) Burst-limit acquire — BEFORE the extractor (the bucket refuses to call
    # quarantined_extract when empty).
    acquired = await burst_limiter.acquire(
        canonical_user_id=resolved.canonical_user_id,
        persona=resolved.persona,
        adapter_id=resolved.adapter_id,
        language=resolved.language,
    )
    # ``Dropped`` carries no ``tokens_remaining``; branch by attribute presence
    # without importing the concrete class at runtime (kept TYPE_CHECKING-only).
    if not hasattr(acquired, "tokens_remaining"):
        return

    # Task 62: observe the backpressure wait the message incurred at the limiter.
    observability.record_burst_limiter_wait_seconds(getattr(acquired, "waited_seconds", 0.0))

    # 3a) Sub-payload promotion (P1, #206) — runs BEFORE the extract so the
    # privileged orchestrator never sees raw sub-payload bytes. The promoter
    # host-classifies the body, writes each recognised sub-payload to the content
    # store under a host-minted handle id, and rewrites the body field to a
    # single-use ``ContentHandle`` reference. The HOST-classified kinds (not the
    # plugin-asserted ``notification.sub_payload_refs`` off the UNTRUSTED wire)
    # are authoritative for the audit row. A ``None`` promoter leaves the body
    # verbatim and falls back to the wire-asserted kinds (reference plugin /
    # empty required-classifier set) — closes the #233 scanner-wiring seam for
    # adapters with a non-empty classifier set.
    if sub_payload_promoter is not None:
        promoted = await sub_payload_promoter.promote(notification.body)
        extract_body: Mapping[str, object] = promoted.body
        sub_payload_kinds = promoted.sub_payload_kinds
    else:
        extract_body = notification.body
        sub_payload_kinds = frozenset(notification.sub_payload_refs)

    # 3b) Quarantined extract — T3 hard-coded; no silent promotion. Receives the
    # PROMOTED body (raw sub-payloads already swapped for handle references).
    extracted = await orchestrator.quarantined_extract(
        extract_body,
        canonical_user_id=resolved.canonical_user_id,
        source_tier="T3",
    )

    inbound_message_id = uuid.uuid4().hex

    # 4) Observability — the T3 promotion row.
    await _emit_t3_promotion(
        notification,
        resolved=resolved,
        inbound_message_id=inbound_message_id,
        sub_payload_kinds=sub_payload_kinds,
        audit_writer=audit_writer,
    )

    # 5) Ingest then 6) dispatch.
    ingested = await orchestrator.ingest(
        notification=notification,
        extracted=extracted,
        canonical_user_id=resolved.canonical_user_id,
        addressing_signal=notification.addressing_signal,
        language=resolved.language,
    )
    await orchestrator.dispatch(ingested)


async def _emit_budget_capped_pre_resolution(
    notification: InboundMessageNotification,
    *,
    platform_user_id_hash: str,
    audit_writer: _AuditWriterLike,
) -> None:
    """Emit the pre-resolution budget-capped row (sec-003).

    Uses ``COMMS_INBOUND_BUDGET_CAPPED_FIELDS`` with ``dropped=True`` — the
    pre-resolution refusal is a hard drop (the resolver is never consulted). The
    canonical user id is unknown at this phase (resolution has not run), so the
    peppered ``platform_user_id_hash`` stands in for ``canonical_user_id`` to
    keep the row's key-set symmetric while never carrying the raw id.
    """
    await audit_writer.append_schema(
        fields=audit_row_schemas.COMMS_INBOUND_BUDGET_CAPPED_FIELDS,
        schema_name="COMMS_INBOUND_BUDGET_CAPPED_FIELDS",
        event="comms.inbound.budget_capped",
        actor_user_id=None,
        subject={
            "adapter_id": notification.adapter_id,
            "canonical_user_id": platform_user_id_hash,
            "persona": _PERSONA_DEFAULT,
            "tokens_available": 0.0,
            "wait_seconds": 0.0,
            "dropped": True,
            "observed_at": datetime.now(UTC).isoformat(),
            "language": "en-US",
        },
        trust_tier_of_trigger="T3",
        result="dropped",
        cost_estimate_usd=0.0,
        trace_id=platform_user_id_hash,
        language="en-US",
    )


__all__ = [
    "ResolvedInbound",
    "process_inbound_message",
]
