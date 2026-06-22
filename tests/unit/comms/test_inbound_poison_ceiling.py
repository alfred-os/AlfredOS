"""Forwarded post-extract poison ceiling + dead-letter (Spec B G6-7-5, #309).

ADR-0039 item 4b — the keystone trust-boundary bound. The forwarded
dispatched-edge path (``commit_at_dispatch_edge=True``) deliberately leaves a
failed frame NOT committed / NOT observed so the forwarding leg replays it
(G6-7-4). Without a bound, a frame whose post-extract region ALWAYS fails (a
poison message) re-charges the quarantined extractor on every reconnect forever
(PERF-309-1). This module's bound is two co-operating writes against the durable
``ForwardedDispatchAttemptStore``:

* a READ of ``attempt_count`` BEFORE ``quarantined_extract`` — placed AFTER the
  pre-resolution DoS limiter (sec C-1) so an attacker-chosen distinct-id flood is
  shed before it can grow the ledger; ``>= ceiling`` short-circuits to a
  content-free ``comms.inbound.poisoned`` dead-letter row + observe-only drain;
* an ``increment`` ON ENTRY to the post-extract region (right after a successful
  extract) so EVERY un-draining downstream failure — promotion-emit, ingest,
  dispatch — is ceilinged, not just dispatch (sec C-2). increment-before-audit so
  a flaky audit backend can never under-count a poison frame past the ceiling.

ALL three code changes are gated under ``commit_at_dispatch_edge and
attempt_store is not None`` so the DIRECT TUI/daemon path is byte-for-byte
unchanged. These tests drive ``process_inbound_message`` directly with the shared
spies plus a fake attempt store that carries a real monotone counter.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from alfred.comms_mcp import audit_hash
from alfred.comms_mcp.errors import ForwardedInboundAuditWriteError
from alfred.comms_mcp.inbound import (
    _FORWARDED_DISPATCH_ATTEMPT_CEILING,
    _PreResolutionLimiter,
    process_inbound_message,
)
from alfred.orchestrator.burst_limiter import Dropped
from tests.unit.comms_mcp._inbound_spies import (
    SpyAuditWriter,
    SpyBurstLimiter,
    SpyIdentityResolver,
    SpyOrchestrator,
    SpySecretBroker,
    make_notification,
    make_resolved,
)

pytestmark = pytest.mark.asyncio


class _FakeAttemptStore:
    """A durable forwarded-dispatch attempt ledger backed by a real counter.

    Keyed on the COMPOSITE ``(adapter_id, inbound_id)`` so the tests exercise the
    SAME key isolation the Postgres store has. ``increment`` advances the count
    and returns the post-write value; ``attempt_count`` is the non-mutating read
    (0 if absent). Both record their calls so a test can assert the gate
    placement (never called on the direct path, never called for a pre-resolution
    shed). Either method can be scripted to raise to drive the fail-loud paths.
    """

    def __init__(
        self,
        *,
        raise_on_increment: BaseException | None = None,
        raise_on_attempt_count: BaseException | None = None,
    ) -> None:
        self._counts: dict[tuple[str, str], int] = {}
        self._raise_on_increment = raise_on_increment
        self._raise_on_attempt_count = raise_on_attempt_count
        self.increment_calls: list[tuple[str, str]] = []
        self.attempt_count_calls: list[tuple[str, str]] = []

    async def increment(self, *, adapter_id: str, inbound_id: str) -> int:
        self.increment_calls.append((adapter_id, inbound_id))
        if self._raise_on_increment is not None:
            raise self._raise_on_increment
        key = (adapter_id, inbound_id)
        self._counts[key] = self._counts.get(key, 0) + 1
        return self._counts[key]

    async def attempt_count(self, *, adapter_id: str, inbound_id: str) -> int:
        self.attempt_count_calls.append((adapter_id, inbound_id))
        if self._raise_on_attempt_count is not None:
            raise self._raise_on_attempt_count
        return self._counts.get((adapter_id, inbound_id), 0)


class _SpyAckTracker:
    """Records ``observe`` calls (the forwarded drain)."""

    def __init__(self) -> None:
        self.observed: list[int] = []

    def observe(self, seq: int) -> None:
        self.observed.append(seq)


class _RaisingDispatchOrchestrator(SpyOrchestrator):
    """A spy orchestrator whose ``dispatch`` raises after recording the call."""

    async def dispatch(self, ingested: object) -> None:
        self.call_order.append("dispatch")
        self.dispatch_calls += 1
        raise RuntimeError("dispatch boom")


class _RaisingIngestOrchestrator(SpyOrchestrator):
    """A spy orchestrator whose ``ingest`` raises after recording the call."""

    async def ingest(self, **kwargs: Any) -> object:
        self.call_order.append("ingest")
        self.ingest_calls += 1
        raise RuntimeError("ingest boom")


class _RaisingPoisonedAuditWriter(SpyAuditWriter):
    """A spy audit writer that raises on the ``poisoned`` row only."""

    async def append_schema(self, *, event: str, **kwargs: Any) -> None:
        if event == "comms.inbound.poisoned":
            raise RuntimeError("poison audit sink down")
        await super().append_schema(event=event, **kwargs)


class _RaisingPromotionAuditWriter(SpyAuditWriter):
    """A spy audit writer that raises on the t3_promoted row only."""

    async def append_schema(self, *, event: str, **kwargs: Any) -> None:
        if event == "comms.inbound.t3_promoted":
            raise RuntimeError("promotion audit sink down")
        await super().append_schema(event=event, **kwargs)


def _capped_pre_resolution_limiter() -> _PreResolutionLimiter:
    """A pre-resolution limiter whose budget is ALREADY exhausted (limit 0)."""
    return _PreResolutionLimiter(limit_per_minute=0)


# --------------------------------------------------------------------------- #
# A — EXACT cost bound: extractor charged at most CEILING times across replays
# --------------------------------------------------------------------------- #
async def test_exact_cost_bound_extractor_charged_ceiling_times() -> None:
    # A deterministically-failing dispatch replayed (ceiling + 1) times charges
    # quarantined_extract EXACTLY ``ceiling`` times: the on-entry increment counts
    # each of the first ``ceiling`` attempts, then the (ceiling+1)-th call reads
    # ``attempts >= ceiling`` BEFORE the extract and dead-letters.
    ceiling = _FORWARDED_DISPATCH_ATTEMPT_CEILING
    store = _FakeAttemptStore()
    tracker = _SpyAckTracker()
    audit = SpyAuditWriter()
    orch = _RaisingDispatchOrchestrator()

    async def _one_replay() -> None:
        await process_inbound_message(
            make_notification(inbound_id="poison-frame", wire_seq=7),
            identity_resolver=SpyIdentityResolver(returns=make_resolved()),
            orchestrator=orch,
            burst_limiter=SpyBurstLimiter(),
            audit_writer=audit,
            secret_broker=SpySecretBroker(),
            attempt_store=store,
            ack_tracker=tracker,
            commit_at_dispatch_edge=True,
        )

    # The first ``ceiling`` replays each fail dispatch loud (no drain) — they
    # increment and re-raise the dispatch RuntimeError.
    for _ in range(ceiling):
        with pytest.raises(RuntimeError, match="dispatch boom"):
            await _one_replay()

    # The (ceiling+1)-th replay: attempt_count == ceiling >= ceiling → poisoned.
    await _one_replay()

    # The extractor was charged EXACTLY ``ceiling`` times across the ceiling+1 calls.
    assert orch.quarantined_extract_calls == ceiling
    # The final call emitted a single poisoned dead-letter row and drained once.
    poisoned = audit.rows_with_schema("COMMS_INBOUND_POISONED_FIELDS")
    assert len(poisoned) == 1
    assert poisoned[0]["event"] == "comms.inbound.poisoned"
    assert poisoned[0]["result"] == "poisoned"
    assert poisoned[0]["attempt_count"] == ceiling
    assert tracker.observed == [7]


# --------------------------------------------------------------------------- #
# B — UNDER-CEILING dispatch failure: increments once, re-raises, no drain,
#     dispatch_failed row content UNCHANGED (no attempt_count key)
# --------------------------------------------------------------------------- #
async def test_under_ceiling_dispatch_failure_increments_and_reraises() -> None:
    store = _FakeAttemptStore()
    tracker = _SpyAckTracker()
    audit = SpyAuditWriter()
    orch = _RaisingDispatchOrchestrator()
    with pytest.raises(RuntimeError, match="dispatch boom"):
        await process_inbound_message(
            make_notification(inbound_id="frame-under", wire_seq=9),
            identity_resolver=SpyIdentityResolver(returns=make_resolved()),
            orchestrator=orch,
            burst_limiter=SpyBurstLimiter(),
            audit_writer=audit,
            secret_broker=SpySecretBroker(),
            attempt_store=store,
            ack_tracker=tracker,
            commit_at_dispatch_edge=True,
        )
    # The on-entry increment ran exactly once (this attempt counted).
    assert store.increment_calls == [("alfred_comms_test", "frame-under")]
    # Under the ceiling: the frame is NOT drained — the leg will replay it.
    assert tracker.observed == []
    # The dispatch_failed row is content-IDENTICAL to G6-7-4: no attempt_count key.
    rows = audit.rows_with_schema("COMMS_INBOUND_DISPATCH_FAILED_FIELDS")
    assert len(rows) == 1
    assert "attempt_count" not in rows[0]
    assert audit.rows_with_schema("COMMS_INBOUND_POISONED_FIELDS") == []


# --------------------------------------------------------------------------- #
# C — WHOLE-REGION bound (sec C-2): ingest AND promotion-emit failures both
#     increment the ledger (the on-entry increment ran before them) + propagate
# --------------------------------------------------------------------------- #
async def test_ingest_failure_increments_and_propagates() -> None:
    store = _FakeAttemptStore()
    tracker = _SpyAckTracker()
    audit = SpyAuditWriter()
    orch = _RaisingIngestOrchestrator()
    with pytest.raises(RuntimeError, match="ingest boom"):
        await process_inbound_message(
            make_notification(inbound_id="frame-ingest", wire_seq=10),
            identity_resolver=SpyIdentityResolver(returns=make_resolved()),
            orchestrator=orch,
            burst_limiter=SpyBurstLimiter(),
            audit_writer=audit,
            secret_broker=SpySecretBroker(),
            attempt_store=store,
            ack_tracker=tracker,
            commit_at_dispatch_edge=True,
        )
    # The on-entry increment (after extract, before promotion/ingest) ran — so an
    # ingest failure is ceilinged, not just dispatch (sec C-2).
    assert store.increment_calls == [("alfred_comms_test", "frame-ingest")]
    assert tracker.observed == []


async def test_promotion_emit_failure_increments_and_propagates() -> None:
    store = _FakeAttemptStore()
    tracker = _SpyAckTracker()
    audit = _RaisingPromotionAuditWriter()
    with pytest.raises(RuntimeError, match="promotion audit sink down"):
        await process_inbound_message(
            make_notification(inbound_id="frame-promote", wire_seq=11),
            identity_resolver=SpyIdentityResolver(returns=make_resolved()),
            orchestrator=SpyOrchestrator(),
            burst_limiter=SpyBurstLimiter(),
            audit_writer=audit,
            secret_broker=SpySecretBroker(),
            attempt_store=store,
            ack_tracker=tracker,
            commit_at_dispatch_edge=True,
        )
    # The increment runs BEFORE the promotion emit, so even a promotion-emit
    # failure replay is bounded by the ceiling (sec C-2).
    assert store.increment_calls == [("alfred_comms_test", "frame-promote")]
    assert tracker.observed == []


# --------------------------------------------------------------------------- #
# D — POISON-EMIT audit-write failure: typed marker, frame NOT drained
# --------------------------------------------------------------------------- #
async def test_poison_emit_audit_write_failure_propagates_and_does_not_drain() -> None:
    store = _FakeAttemptStore()
    # Arm the ledger above the ceiling so the READ short-circuits to poisoned.
    for _ in range(_FORWARDED_DISPATCH_ATTEMPT_CEILING):
        await store.increment(adapter_id="alfred_comms_test", inbound_id="frame-poison-audit")
    tracker = _SpyAckTracker()
    audit = _RaisingPoisonedAuditWriter()
    with pytest.raises(ForwardedInboundAuditWriteError) as excinfo:
        await process_inbound_message(
            make_notification(inbound_id="frame-poison-audit", wire_seq=12),
            identity_resolver=SpyIdentityResolver(returns=make_resolved()),
            orchestrator=SpyOrchestrator(),
            burst_limiter=SpyBurstLimiter(),
            audit_writer=audit,
            secret_broker=SpySecretBroker(),
            attempt_store=store,
            ack_tracker=tracker,
            commit_at_dispatch_edge=True,
        )
    assert isinstance(excinfo.value.__cause__, RuntimeError)
    assert str(excinfo.value.__cause__) == "poison audit sink down"
    # Audit-before-drain: a failed poisoned write leaves the frame UNDRAINED.
    assert tracker.observed == []


# --------------------------------------------------------------------------- #
# E — attempt_count DB error on the READ propagates loud; not poisoned, not drained
# --------------------------------------------------------------------------- #
async def test_attempt_count_read_db_error_propagates() -> None:
    store = _FakeAttemptStore(raise_on_attempt_count=RuntimeError("read down"))
    tracker = _SpyAckTracker()
    audit = SpyAuditWriter()
    with pytest.raises(RuntimeError, match="read down"):
        await process_inbound_message(
            make_notification(inbound_id="frame-read-err", wire_seq=13),
            identity_resolver=SpyIdentityResolver(returns=make_resolved()),
            orchestrator=SpyOrchestrator(),
            burst_limiter=SpyBurstLimiter(),
            audit_writer=audit,
            secret_broker=SpySecretBroker(),
            attempt_store=store,
            ack_tracker=tracker,
            commit_at_dispatch_edge=True,
        )
    # The read raised BEFORE extract — not poisoned, not drained, leg replays.
    assert audit.rows_with_schema("COMMS_INBOUND_POISONED_FIELDS") == []
    assert tracker.observed == []


# --------------------------------------------------------------------------- #
# E' — increment DB error in the post-extract region propagates as a leg replay;
#      no dispatch_failed / poisoned masking; not drained
# --------------------------------------------------------------------------- #
async def test_increment_db_error_propagates_as_replay() -> None:
    store = _FakeAttemptStore(raise_on_increment=RuntimeError("increment down"))
    tracker = _SpyAckTracker()
    audit = SpyAuditWriter()
    orch = SpyOrchestrator()
    with pytest.raises(RuntimeError, match="increment down"):
        await process_inbound_message(
            make_notification(inbound_id="frame-inc-err", wire_seq=14),
            identity_resolver=SpyIdentityResolver(returns=make_resolved()),
            orchestrator=orch,
            burst_limiter=SpyBurstLimiter(),
            audit_writer=audit,
            secret_broker=SpySecretBroker(),
            attempt_store=store,
            ack_tracker=tracker,
            commit_at_dispatch_edge=True,
        )
    # The increment is post-extract but pre-dispatch — the raw error surfaces with
    # no dispatch_failed/poisoned row masking it, and dispatch never ran.
    assert orch.dispatch_calls == 0
    assert audit.rows_with_schema("COMMS_INBOUND_DISPATCH_FAILED_FIELDS") == []
    assert audit.rows_with_schema("COMMS_INBOUND_POISONED_FIELDS") == []
    assert tracker.observed == []


# --------------------------------------------------------------------------- #
# F — READ placement (sec C-1): a pre-resolution-shed frame never touches the
#     ledger (neither attempt_count nor increment) and drains as before
# --------------------------------------------------------------------------- #
async def test_pre_resolution_shed_never_touches_ledger() -> None:
    store = _FakeAttemptStore()
    tracker = _SpyAckTracker()
    audit = SpyAuditWriter()
    await process_inbound_message(
        make_notification(inbound_id="frame-flood", wire_seq=15),
        identity_resolver=SpyIdentityResolver(returns=make_resolved()),
        orchestrator=SpyOrchestrator(),
        burst_limiter=SpyBurstLimiter(),
        audit_writer=audit,
        secret_broker=SpySecretBroker(),
        pre_resolution_limiter=_capped_pre_resolution_limiter(),
        attempt_store=store,
        ack_tracker=tracker,
        commit_at_dispatch_edge=True,
    )
    # The flood is shed at the DoS limiter BEFORE the ceiling read (sec C-1) so a
    # distinct-id flood can never grow the ledger.
    assert store.attempt_count_calls == []
    assert store.increment_calls == []
    # It still drains as the G6-7-4 budget-capped shed does.
    assert len(audit.rows_with_schema("COMMS_INBOUND_BUDGET_CAPPED_FIELDS")) == 1
    assert tracker.observed == [15]


# --------------------------------------------------------------------------- #
# F' — BURST-drop (post-resolution) skips increment: a forwarded frame the burst
#      limiter Drops drains as the G6-7-4 burst-dropped shed does, and never
#      INCREMENTS the ledger (a read-only attempt_count probe is allowed)
# --------------------------------------------------------------------------- #
async def test_burst_drop_skips_increment() -> None:
    store = _FakeAttemptStore()
    tracker = _SpyAckTracker()
    audit = SpyAuditWriter()
    dropped = SpyBurstLimiter(
        result=Dropped(waited_seconds=0.0, bucket_empty_since=datetime.now(UTC))
    )
    await process_inbound_message(
        make_notification(inbound_id="frame-burst", wire_seq=20),
        identity_resolver=SpyIdentityResolver(returns=make_resolved()),
        orchestrator=SpyOrchestrator(),
        burst_limiter=dropped,
        audit_writer=audit,
        secret_broker=SpySecretBroker(),
        attempt_store=store,
        ack_tracker=tracker,
        commit_at_dispatch_edge=True,
    )
    # The post-resolution burst-drop returns BEFORE the on-entry increment, so the
    # ledger is never INCREMENTED — a Dropped frame does not re-charge the count
    # (the read-only attempt_count probe before the extract is harmless).
    assert store.increment_calls == []
    # It still drains as the G6-7-4 burst-dropped shed does (observe-only, one row).
    assert len(audit.rows_with_schema("COMMS_INBOUND_BUDGET_CAPPED_FIELDS")) == 1
    assert audit.rows_with_schema("COMMS_INBOUND_POISONED_FIELDS") == []
    assert tracker.observed == [20]


# --------------------------------------------------------------------------- #
# G — DIRECT path unchanged: edge=False + attempt_store set → ledger untouched
# --------------------------------------------------------------------------- #
async def test_direct_path_never_touches_ledger() -> None:
    store = _FakeAttemptStore()
    orch = SpyOrchestrator()
    await process_inbound_message(
        make_notification(inbound_id="frame-direct", wire_seq=16),
        identity_resolver=SpyIdentityResolver(returns=make_resolved()),
        orchestrator=orch,
        burst_limiter=SpyBurstLimiter(),
        audit_writer=SpyAuditWriter(),
        secret_broker=SpySecretBroker(),
        attempt_store=store,
        # default commit_at_dispatch_edge=False
    )
    assert store.attempt_count_calls == []
    assert store.increment_calls == []
    # The direct pipeline still ran to dispatch unchanged.
    assert orch.dispatch_calls == 1


# --------------------------------------------------------------------------- #
# H — None attempt_store on the forwarded path → ceiling disabled, falls through
#     to the prior G6-7-4 dispatch-failure behaviour (re-raise, no poison, no row)
# --------------------------------------------------------------------------- #
async def test_none_attempt_store_falls_through_to_g674_behaviour() -> None:
    tracker = _SpyAckTracker()
    audit = SpyAuditWriter()
    orch = _RaisingDispatchOrchestrator()
    with pytest.raises(RuntimeError, match="dispatch boom"):
        await process_inbound_message(
            make_notification(inbound_id="frame-no-store", wire_seq=17),
            identity_resolver=SpyIdentityResolver(returns=make_resolved()),
            orchestrator=orch,
            burst_limiter=SpyBurstLimiter(),
            audit_writer=audit,
            secret_broker=SpySecretBroker(),
            attempt_store=None,
            ack_tracker=tracker,
            commit_at_dispatch_edge=True,
        )
    # No ceiling: the G6-7-4 dispatch_failed row + re-raise, no poison, no drain.
    assert len(audit.rows_with_schema("COMMS_INBOUND_DISPATCH_FAILED_FIELDS")) == 1
    assert audit.rows_with_schema("COMMS_INBOUND_POISONED_FIELDS") == []
    assert tracker.observed == []


# --------------------------------------------------------------------------- #
# I — the poisoned row's inbound_id is a real PEPPERED hash, never the raw string
# --------------------------------------------------------------------------- #
async def test_poisoned_row_inbound_id_is_peppered_hash() -> None:
    store = _FakeAttemptStore()
    for _ in range(_FORWARDED_DISPATCH_ATTEMPT_CEILING):
        await store.increment(adapter_id="alfred_comms_test", inbound_id="frame-secret-id")
    tracker = _SpyAckTracker()
    audit = SpyAuditWriter()
    await process_inbound_message(
        make_notification(inbound_id="frame-secret-id", wire_seq=18),
        identity_resolver=SpyIdentityResolver(returns=make_resolved()),
        orchestrator=SpyOrchestrator(),
        burst_limiter=SpyBurstLimiter(),
        audit_writer=audit,
        secret_broker=SpySecretBroker(),
        attempt_store=store,
        ack_tracker=tracker,
        commit_at_dispatch_edge=True,
    )
    rows = audit.rows_with_schema("COMMS_INBOUND_POISONED_FIELDS")
    assert len(rows) == 1
    row = rows[0]
    assert row["inbound_id_hash"] == audit_hash.hash_inbound_id("frame-secret-id")
    # sec-010: trace_id carries the peppered hash too; the raw id never lands.
    assert row["trace_id"] == audit_hash.hash_inbound_id("frame-secret-id")
    assert row["trust_tier_of_trigger"] == "T3"
    assert "frame-secret-id" not in str(row)
