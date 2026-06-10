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

import hashlib
import hmac
import time
import uuid
from collections import OrderedDict
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Literal, Protocol, runtime_checkable

import structlog

from alfred.audit import audit_row_schemas
from alfred.comms_mcp import observability

if TYPE_CHECKING:
    from alfred.comms_mcp.protocol import InboundMessageNotification
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


def _peppered_hash(raw: str, *, pepper: str) -> str:
    """Return the 32-hex-char HMAC-SHA256 of ``raw`` keyed on ``pepper``.

    sec-010: the raw ``platform_user_id`` (and the binding verification phrase)
    never land in an audit row — only this peppered, truncated digest does. The
    pepper is ``audit.hash_pepper`` from the secret broker; HMAC (not a plain
    salted hash) binds the digest to the secret so an attacker cannot reproduce
    it without the pepper, and the 32-char truncation keeps the row compact
    while leaving 128 bits of collision resistance.
    """
    return hmac.new(
        key=pepper.encode(),
        msg=raw.encode(),
        digestmod=hashlib.sha256,
    ).hexdigest()[:32]


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
    pepper: str,
    language: str,
) -> None:
    """Emit ``COMMS_BINDING_REQUESTED_FIELDS`` for a first-contact inbound.

    The ``platform_user_id`` and the host-generated verification phrase are both
    peppered-hashed before they land on the row (sec-010). The phrase itself is
    a placeholder for the Slice-5 out-of-band binding flow; its hash anchors the
    audit row so a later flow can correlate the binding attempt without ever
    storing the raw phrase.
    """
    phrase = uuid.uuid4().hex
    platform_user_id_hash = _peppered_hash(notification.platform_user_id, pepper=pepper)
    await audit_writer.append_schema(
        fields=audit_row_schemas.COMMS_BINDING_REQUESTED_FIELDS,
        schema_name="COMMS_BINDING_REQUESTED_FIELDS",
        event="comms.binding.requested",
        actor_user_id=None,
        subject={
            "adapter_id": notification.adapter_id,
            "platform_user_id_hash": platform_user_id_hash,
            "verification_phrase_hash": _peppered_hash(phrase, pepper=pepper),
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
    pepper: str,
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
            "platform_user_id_hash": _peppered_hash(notification.platform_user_id, pepper=pepper),
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


async def process_inbound_message(
    notification: InboundMessageNotification,
    *,
    identity_resolver: _IdentityResolverLike,
    orchestrator: _OrchestratorLike,
    burst_limiter: _BurstLimiterLike,
    audit_writer: _AuditWriterLike,
    secret_broker: _SecretBrokerLike,
    pre_resolution_limiter: _PreResolutionLimiter | None = None,
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

    pepper = secret_broker.get("audit.hash_pepper")
    platform_user_id_hash = _peppered_hash(notification.platform_user_id, pepper=pepper)

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
            pepper=pepper,
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

    # 3) Quarantined extract — T3 hard-coded; no silent promotion.
    extracted = await orchestrator.quarantined_extract(
        notification.body,
        canonical_user_id=resolved.canonical_user_id,
        source_tier="T3",
    )

    inbound_message_id = uuid.uuid4().hex
    # PROVENANCE CAVEAT + SCANNER-WIRING SEAM (TODO PR-S4-9). These kinds are
    # taken straight off the UNTRUSTED wire (``notification.sub_payload_refs``) —
    # they are PLUGIN-ASSERTED, not yet host-classified. ``InboundContentScanner``
    # is built + tested but has no caller here: for the reference plugin the
    # required-classifier set is empty, so scanning is inert. PR-S4-9 (which adds
    # the non-empty Discord classifier set) MUST wire the scanner in BEFORE that
    # set is non-empty, or unclassified T3 sub-payloads would be admitted on the
    # plugin's word. Tracked in the PR-S4-9 follow-up issue (#233).
    sub_payload_kinds = frozenset(notification.sub_payload_refs)

    # 4) Observability — the T3 promotion row.
    await _emit_t3_promotion(
        notification,
        resolved=resolved,
        inbound_message_id=inbound_message_id,
        sub_payload_kinds=sub_payload_kinds,
        audit_writer=audit_writer,
        pepper=pepper,
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
