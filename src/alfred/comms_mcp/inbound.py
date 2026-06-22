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
from alfred.comms_mcp.errors import ForwardedInboundAuditWriteError, PromoterRequiredError

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

    # Non-mutating read (Spec B G6-7-4 Task 1) — the dispatched-edge forwarded
    # path consults it BEFORE dispatch to short-circuit a replay (a row already
    # durable) without re-dispatching, then drains the seq tail.
    async def has_committed(self, *, inbound_id: str, adapter_id: str) -> bool: ...


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


def _drain_forwarded_seq(ack_tracker: _AckTrackerLike | None, wire_seq: int | None) -> None:
    """Observe-only drain of a forwarded leg ``wire_seq`` (Spec B G6-7-4, #309).

    Mirrors :meth:`GatewayForwardedInboundReceiver._drain` (2nd-duplication factor).
    A deterministic mid-pipeline refusal on the FORWARDED (dispatched-edge) path
    refuses identically on every replay; if it never ``observe``\\d the seq, the
    leg's contiguous high-water would wedge and the gateway would replay it
    forever. This advances the high-water so the dispatched tail can trim — WITHOUT
    a ``commit_once`` (the refusal is not a durable accept, just a drain). A ``None``
    tracker (no connection bound yet) or a ``None`` ``wire_seq`` (un-sequenced leg)
    makes this a no-op. ``observe`` is pure-CPU (no ``await``).
    """
    if ack_tracker is not None and wire_seq is not None:
        ack_tracker.observe(wire_seq)


async def _emit_burst_dropped_at_edge(
    notification: InboundMessageNotification,
    *,
    resolved: ResolvedInbound,
    audit_writer: _AuditWriterLike,
) -> None:
    """Emit the FORWARDED-path burst-drop row (Spec B G6-7-4, #309).

    The burst ``Dropped`` arm has no signed audit trail on the DIRECT path (it just
    returns). On the forwarded dispatched edge a silent drop that is then drained
    would be an un-recorded side-effecting DROP — a hard-rule-#7 hole. So the
    FORWARDED path (and only it — gated under ``commit_at_dispatch_edge`` at the call
    site) emits a content-free row BEFORE the drain. Reuses the budget-capped field
    set + the in-domain ``result="dropped"`` value (no new migration). The canonical
    user id IS known here (resolution ran), so it anchors the row; the body / user
    text never lands on it.
    """
    await audit_writer.append_schema(
        fields=audit_row_schemas.COMMS_INBOUND_BUDGET_CAPPED_FIELDS,
        schema_name="COMMS_INBOUND_BUDGET_CAPPED_FIELDS",
        event="comms.inbound.burst_dropped",
        actor_user_id=resolved.canonical_user_id,
        subject={
            "adapter_id": notification.adapter_id,
            "canonical_user_id": resolved.canonical_user_id,
            "persona": resolved.persona,
            "tokens_available": 0.0,
            "wait_seconds": 0.0,
            "dropped": True,
            "observed_at": datetime.now(UTC).isoformat(),
            "language": resolved.language,
        },
        trust_tier_of_trigger="T3",
        result="dropped",
        cost_estimate_usd=0.0,
        trace_id=resolved.canonical_user_id,
        language=resolved.language,
    )


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


async def _emit_dispatch_failed(
    notification: InboundMessageNotification,
    *,
    audit_writer: _AuditWriterLike,
) -> None:
    """Emit the content-free dispatch_failed row on the dispatched edge.

    Spec B G6-7-4 / ADR-0039 item 4. A dispatch failure on the FORWARDED path is a
    visible, recoverable event: the frame is deliberately left NOT committed and
    NOT observed so the forwarding leg replays it. That decision is a SIGNED
    audit-log fact — a distinct closed-vocab ``result="dispatch_failed"`` row
    (never the ``"dropped"`` replay value, so the two are distinguishable in the
    log). The row is content-free: ONLY the adapter id, the PEPPERED HASH of the
    wire ``inbound_id`` (never the raw string — sec-010), and the observation time.
    NO raw T3 body, no user text. An audit-write failure here PROPAGATES (the
    caller does not swallow it).
    """
    await audit_writer.append_schema(
        fields=audit_row_schemas.COMMS_INBOUND_DISPATCH_FAILED_FIELDS,
        schema_name="COMMS_INBOUND_DISPATCH_FAILED_FIELDS",
        event="comms.inbound.dispatch_failed",
        actor_user_id=None,
        subject={
            "adapter_id": notification.adapter_id,
            "inbound_id_hash": audit_hash.hash_inbound_id(notification.inbound_id),
            "observed_at": datetime.now(UTC).isoformat(),
        },
        trust_tier_of_trigger="T3",
        result="dispatch_failed",
        cost_estimate_usd=0.0,
        # sec-010: trace_id is a persisted, indexed column — peppered hash, never
        # the raw wire inbound_id.
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
    commit_at_dispatch_edge: bool = False,
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
    #
    # Spec B G6-7-4 (ADR-0039 item 4): the FORWARDED path
    # (``commit_at_dispatch_edge=True``) does NOT commit/observe at receipt — that
    # moves to AFTER a successful dispatch (the "dispatched edge"), so a dispatch
    # failure leaves the seq un-observed and the leg replays it. At receipt the
    # forwarded path only needs the replay short-circuit: a row already durable
    # (``has_committed`` — Task 1's non-mutating read) is DRAINED here (advance the
    # contiguous high-water so its dispatched tail can trim) and short-circuited
    # WITHOUT re-dispatch. The DIRECT TUI/daemon path (``False``, the default) keeps
    # the original receipt-time ``commit_once`` + ``observe`` UNCHANGED, lifted
    # verbatim under the ``elif`` guard — its logic and the None-store fall-through
    # are byte-for-byte the prior behaviour.
    if commit_at_dispatch_edge:
        if idempotency_store is not None and await idempotency_store.has_committed(
            inbound_id=notification.inbound_id,
            adapter_id=notification.adapter_id,
        ):
            audit_hash.set_broker(secret_broker)
            # Spec B G6-7-4 (#309): the forwarded-path replay-observed audit row is a
            # SIGNED security fact. Wrap a write failure in the typed
            # ForwardedInboundAuditWriteError marker AT THE WRITE SITE so the
            # disposition escalates LOUD (restart) — never the leg-replay path a raw
            # SQLAlchemyError takes. A failed audit short-circuits BEFORE the drain
            # observe, so a replay is never ACKed without its signed record.
            try:
                await _emit_idempotency_replay_observed(notification, audit_writer=audit_writer)
            except Exception as exc:
                raise ForwardedInboundAuditWriteError(
                    "forwarded-inbound replay-observed audit write failed"
                ) from exc
            if ack_tracker is not None and notification.wire_seq is not None:
                ack_tracker.observe(notification.wire_seq)
            _log.info(
                "comms.inbound.idempotency.replay_short_circuit",
                adapter_id=notification.adapter_id,
            )
            return
    elif idempotency_store is not None:
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
        # Spec B G6-7-4 (#309): on the FORWARDED dispatched edge this deterministic
        # refusal repeats identically every replay; drain the seq (observe-only, NO
        # commit_once) AFTER the signed row wrote so the leg's high-water advances and
        # the gateway stops replaying it (ARCH-309-3 audit-before-drain). Gated under
        # commit_at_dispatch_edge so the DIRECT path is byte-for-byte unchanged.
        if commit_at_dispatch_edge:
            _drain_forwarded_seq(ack_tracker, notification.wire_seq)
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
        # Spec B G6-7-4 (#309): an unbound first-contact refuses identically on every
        # forwarded replay; drain the seq (observe-only, NO commit_once) AFTER the
        # signed binding row wrote (ARCH-309-3 audit-before-drain). Gated under
        # commit_at_dispatch_edge so the DIRECT path is byte-for-byte unchanged.
        if commit_at_dispatch_edge:
            _drain_forwarded_seq(ack_tracker, notification.wire_seq)
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
        # Spec B G6-7-4 (#309): the burst-drop arm is SILENT on the DIRECT path (it
        # just returns — the BurstLimiter writes no row). On the FORWARDED dispatched
        # edge a silent drop that is then drained would be an un-recorded
        # side-effecting DROP (hard rule #7). So the forwarded path FIRST emits a
        # content-free signed row (in-domain result="dropped", no migration), THEN
        # drains the seq (observe-only, NO commit_once) so the leg's high-water
        # advances. Both are gated under commit_at_dispatch_edge so the DIRECT path
        # stays byte-for-byte (no new emit, no drain).
        if commit_at_dispatch_edge:
            await _emit_burst_dropped_at_edge(
                notification,
                resolved=resolved,
                audit_writer=audit_writer,
            )
            _drain_forwarded_seq(ack_tracker, notification.wire_seq)
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

    # 4) Observability — the T3 promotion row. INTENTIONALLY NOT wrapped in
    # ForwardedInboundAuditWriteError (unlike replay_observed / dispatch_failed):
    # this emit precedes commit_once + observe, so a raw audit-write failure here
    # propagates with NOTHING committed or observed → the leg replays (re-charging
    # quarantined_extract, bounded by G6-7-5). The typed-marker escalation is reserved
    # for audit failures adjacent to an irreversible drain/commit; escalating a
    # replayable pre-commit emit would cause a restart-storm on a transient audit blip.
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
    if commit_at_dispatch_edge:
        # Dispatched edge (ADR-0039 item 4): commit + observe AFTER a successful
        # dispatch, so a dispatch failure leaves the frame NOT committed / NOT
        # observed and the forwarding leg replays it → the core re-dispatches.
        try:
            await orchestrator.dispatch(ingested)
        except Exception as exc:
            # Fail-loud (hard rule #7): emit the distinct closed-vocab
            # dispatch_failed row and re-raise. NOT committed, NOT observed. The
            # bound on this replay (poison ceiling / dead-letter) is G6-7-5. An
            # audit-write failure here PROPAGATES — it is not nested-swallowed.
            # ``Exception`` (not ``BaseException``) so cancellation tears down
            # cleanly rather than being audited as a dispatch fault.
            #
            # Spec B G6-7-4 (#309): the dispatch_failed row is a SIGNED security fact.
            # A write failure here is wrapped in the typed
            # ForwardedInboundAuditWriteError marker AT THE WRITE SITE so the
            # disposition escalates LOUD (restart) — distinct from the original dispatch
            # ``exc`` (whose recovery is leg replay, re-raised below when the audit
            # succeeds). The wrapped audit fault replaces the re-raise: it is the
            # non-skippable signal that takes precedence over the replayable dispatch
            # fault.
            #
            # Carry the exception CLASS NAME (never ``str(exc)`` — that could embed raw
            # T3) on the structlog line so a replay-storm is triageable by fault kind.
            _log.warning(
                "comms.inbound.dispatch_failed",
                adapter_id=notification.adapter_id,
                error_class=type(exc).__name__,
            )
            audit_hash.set_broker(secret_broker)
            try:
                await _emit_dispatch_failed(notification, audit_writer=audit_writer)
            except Exception as audit_exc:
                raise ForwardedInboundAuditWriteError(
                    "forwarded-inbound dispatch_failed audit write failed"
                ) from audit_exc
            raise
        if idempotency_store is not None:
            # The bool result is intentionally DISCARDED: on the dispatched edge a
            # dispatch SUCCEEDED, but a concurrent replay of the same frame (the
            # bounded at-least-once race ADR-0039 item 4 accepts, ceilinged by G6-7-5)
            # may have already won commit_once. Either outcome — fresh durable accept
            # (True) or already-committed (False) — is benign here: the side effect
            # (dispatch) ran exactly as intended and the seq is observed below. The
            # row's existence, not the winner, is what the replay short-circuit reads.
            await idempotency_store.commit_once(
                inbound_id=notification.inbound_id,
                adapter_id=notification.adapter_id,
            )
            # ADR-0039 item 4: the G0 commit and the durable-intake observe move
            # TOGETHER. The observe lives INSIDE the commit_once guard so it can
            # NEVER advance the ACK high-water without a durable commit — observing
            # a frame that was never committed would let a crash-then-replay re-run
            # the side effect past an ACK that claimed it durable.
            if ack_tracker is not None and notification.wire_seq is not None:
                ack_tracker.observe(notification.wire_seq)
    else:
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
