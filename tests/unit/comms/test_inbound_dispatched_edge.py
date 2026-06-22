"""Dispatched-edge commit/observe mode for the forwarded inbound path (Spec B G6-7-4).

ADR-0039 item 4. A gateway-FORWARDED inbound is dispatched core-side through
:func:`process_inbound_message`. For that path the durable accept (the G0
``commit_once``) and the durable-intake ack (``observe``) move from RECEIPT-time
(the top of the pipeline) to the ``dispatched edge`` — AFTER a successful
``orchestrator.dispatch``. The semantic invariant: a dispatch failure leaves the
seq UN-observed and the row UN-committed, so the forwarding leg replays the frame
→ the core re-dispatches it. ``commit_at_dispatch_edge=True`` selects this mode.

The DIRECT TUI/daemon path (``commit_at_dispatch_edge=False``, the default) is
BYTE-FOR-BYTE behaviour-identical to today: receipt-time ``commit_once`` +
``observe``, the replay short-circuit, and the None-store fall-through all
unchanged. ``has_committed`` (Task 1's non-mutating read) is consulted ONLY on
the forwarded path, for the replay short-circuit.

Call ORDER is the load-bearing property: each spy appends to a shared ``order``
list so the tests can assert ``dispatch`` precedes both ``commit_once`` and
``observe`` on the dispatched edge.
"""

from __future__ import annotations

from typing import Any

import pytest

from alfred.comms_mcp import audit_hash
from alfred.comms_mcp.errors import ForwardedInboundAuditWriteError
from alfred.comms_mcp.inbound import _PreResolutionLimiter, process_inbound_message
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


class _OrderedStore:
    """A commit_once / has_committed store that records call order.

    ``has_committed`` reports whether the COMPOSITE ``(adapter_id, inbound_id)``
    is already durable — the dispatched-edge replay short-circuit reads it before
    deciding to dispatch. ``commit_once`` marks the key durable and returns
    ``True`` on the first call (a fresh durable accept), ``False`` on a replay.
    """

    def __init__(self, *, already: bool = False) -> None:
        self._committed: set[tuple[str, str]] = set()
        self._already = already
        self.order: list[str] = []
        self.has_committed_calls: list[tuple[str, str]] = []
        self.commit_once_calls: list[tuple[str, str]] = []

    def _bind_order(self, order: list[str]) -> _OrderedStore:
        self.order = order
        return self

    async def has_committed(self, *, inbound_id: str, adapter_id: str) -> bool:
        self.order.append("has_committed")
        self.has_committed_calls.append((inbound_id, adapter_id))
        return self._already or (adapter_id, inbound_id) in self._committed

    async def commit_once(self, *, inbound_id: str, adapter_id: str) -> bool:
        self.order.append("commit_once")
        self.commit_once_calls.append((inbound_id, adapter_id))
        key = (adapter_id, inbound_id)
        if key in self._committed:
            return False
        self._committed.add(key)
        return True


class _OrderedAckTracker:
    """Records ``observe`` order + the seq it was handed."""

    def __init__(self, *, order: list[str]) -> None:
        self.order = order
        self.observed: list[int] = []

    def observe(self, seq: int) -> None:
        self.order.append("observe")
        self.observed.append(seq)


class _RaisingDispatchOrchestrator(SpyOrchestrator):
    """A spy orchestrator whose ``dispatch`` raises after recording the call."""

    async def dispatch(self, ingested: object) -> None:
        self.call_order.append("dispatch")
        self.dispatch_calls += 1
        raise RuntimeError("dispatch boom")


class _RaisingAuditWriter(SpyAuditWriter):
    """A spy audit writer that raises on the ``dispatch_failed`` row only."""

    async def append_schema(self, *, event: str, **kwargs: Any) -> None:
        if event == "comms.inbound.dispatch_failed":
            raise RuntimeError("audit sink down")
        await super().append_schema(event=event, **kwargs)


class _RaisingReplayObservedAuditWriter(SpyAuditWriter):
    """A spy audit writer that raises on the ``replay_observed`` row only."""

    async def append_schema(self, *, event: str, **kwargs: Any) -> None:
        if event == "comms.inbound.idempotency.replay_observed":
            raise RuntimeError("replay audit sink down")
        await super().append_schema(event=event, **kwargs)


# --------------------------------------------------------------------------- #
# 1 — SUCCESS: edge mode commits + observes AFTER dispatch
# --------------------------------------------------------------------------- #
async def test_dispatched_edge_commits_and_observes_after_dispatch() -> None:
    order: list[str] = []
    store = _OrderedStore()._bind_order(order)
    tracker = _OrderedAckTracker(order=order)
    orch = SpyOrchestrator(call_order=order)
    await process_inbound_message(
        make_notification(inbound_id="frame-1", wire_seq=7),
        identity_resolver=SpyIdentityResolver(returns=make_resolved()),
        orchestrator=orch,
        burst_limiter=SpyBurstLimiter(call_order=order),
        audit_writer=SpyAuditWriter(),
        secret_broker=SpySecretBroker(),
        idempotency_store=store,
        ack_tracker=tracker,
        commit_at_dispatch_edge=True,
    )
    # has_committed read BEFORE dispatch; commit_once + observe AFTER dispatch.
    assert store.has_committed_calls == [("frame-1", "alfred_comms_test")]
    assert store.commit_once_calls == [("frame-1", "alfred_comms_test")]
    assert tracker.observed == [7]
    assert order.index("has_committed") < order.index("dispatch")
    assert order.index("dispatch") < order.index("commit_once")
    assert order.index("dispatch") < order.index("observe")


# --------------------------------------------------------------------------- #
# 2 — REPLAY: has_committed True => no dispatch, no commit, drain the tail
# --------------------------------------------------------------------------- #
async def test_dispatched_edge_replay_short_circuits_but_still_observes() -> None:
    order: list[str] = []
    store = _OrderedStore(already=True)._bind_order(order)
    tracker = _OrderedAckTracker(order=order)
    orch = SpyOrchestrator(call_order=order)
    audit = SpyAuditWriter()
    await process_inbound_message(
        make_notification(inbound_id="frame-dup", wire_seq=3),
        identity_resolver=SpyIdentityResolver(returns=make_resolved()),
        orchestrator=orch,
        burst_limiter=SpyBurstLimiter(call_order=order),
        audit_writer=audit,
        secret_broker=SpySecretBroker(),
        idempotency_store=store,
        ack_tracker=tracker,
        commit_at_dispatch_edge=True,
    )
    # No dispatch, no commit_once — a replay is a clean DROP.
    assert orch.dispatch_calls == 0
    assert store.commit_once_calls == []
    # But the seq IS observed — the replay must still drain the contiguous tail so
    # the leg can trim, and a content-free replay_observed row is emitted.
    assert tracker.observed == [3]
    rows = audit.rows_with_schema("COMMS_INBOUND_IDEMPOTENCY_REPLAY_FIELDS")
    assert len(rows) == 1
    assert rows[0]["inbound_id_hash"] == audit_hash.hash_inbound_id("frame-dup")
    assert "frame-dup" not in str(rows[0])


async def test_dispatched_edge_replay_with_no_seq_skips_observe() -> None:
    # A forwarded replay carrying no wire_seq (and/or no tracker) still emits the
    # replay_observed row and short-circuits, but the observe-branch falls through
    # cleanly — nothing to drain.
    order: list[str] = []
    store = _OrderedStore(already=True)._bind_order(order)
    audit = SpyAuditWriter()
    await process_inbound_message(
        make_notification(inbound_id="frame-dup-noseq", wire_seq=None),
        identity_resolver=SpyIdentityResolver(returns=make_resolved()),
        orchestrator=SpyOrchestrator(call_order=order),
        burst_limiter=SpyBurstLimiter(call_order=order),
        audit_writer=audit,
        secret_broker=SpySecretBroker(),
        idempotency_store=store,
        ack_tracker=None,
        commit_at_dispatch_edge=True,
    )
    assert store.commit_once_calls == []
    assert "observe" not in order
    assert len(audit.rows_with_schema("COMMS_INBOUND_IDEMPOTENCY_REPLAY_FIELDS")) == 1


# --------------------------------------------------------------------------- #
# 3 — DISPATCH FAILURE: no commit, no observe, dispatch_failed row, raises
# --------------------------------------------------------------------------- #
async def test_dispatched_edge_dispatch_failure_audits_and_propagates() -> None:
    order: list[str] = []
    store = _OrderedStore()._bind_order(order)
    tracker = _OrderedAckTracker(order=order)
    orch = _RaisingDispatchOrchestrator(call_order=order)
    audit = SpyAuditWriter()
    with pytest.raises(RuntimeError, match="dispatch boom"):
        await process_inbound_message(
            make_notification(inbound_id="frame-fail", wire_seq=9),
            identity_resolver=SpyIdentityResolver(returns=make_resolved()),
            orchestrator=orch,
            burst_limiter=SpyBurstLimiter(call_order=order),
            audit_writer=audit,
            secret_broker=SpySecretBroker(),
            idempotency_store=store,
            ack_tracker=tracker,
            commit_at_dispatch_edge=True,
        )
    # NOT committed, NOT observed — the leg will replay it.
    assert store.commit_once_calls == []
    assert tracker.observed == []
    # A distinct closed-vocab dispatch_failed row was emitted.
    rows = audit.rows_with_schema("COMMS_INBOUND_DISPATCH_FAILED_FIELDS")
    assert len(rows) == 1
    row = rows[0]
    assert row["event"] == "comms.inbound.dispatch_failed"
    assert row["result"] == "dispatch_failed"
    assert row["trust_tier_of_trigger"] == "T3"
    # Content-free: the peppered hash of inbound_id, never the raw string nor body.
    assert row["inbound_id_hash"] == audit_hash.hash_inbound_id("frame-fail")
    assert "frame-fail" not in str(row)
    assert "hello" not in str(row)


# --------------------------------------------------------------------------- #
# 4 — DIRECT PATH UNCHANGED: receipt-time commit + observe, no edge behaviour
# --------------------------------------------------------------------------- #
async def test_direct_path_commits_at_receipt_before_pipeline() -> None:
    order: list[str] = []
    store = _OrderedStore()._bind_order(order)
    tracker = _OrderedAckTracker(order=order)
    orch = SpyOrchestrator(call_order=order)
    await process_inbound_message(
        make_notification(inbound_id="frame-direct", wire_seq=2),
        identity_resolver=SpyIdentityResolver(returns=make_resolved()),
        orchestrator=orch,
        burst_limiter=SpyBurstLimiter(call_order=order),
        audit_writer=SpyAuditWriter(),
        secret_broker=SpySecretBroker(),
        idempotency_store=store,
        ack_tracker=tracker,
        # default commit_at_dispatch_edge=False
    )
    # commit_once + observe happen at RECEIPT, BEFORE the pipeline (burst/dispatch).
    assert store.commit_once_calls == [("frame-direct", "alfred_comms_test")]
    assert tracker.observed == [2]
    assert order.index("commit_once") < order.index("dispatch")
    assert order.index("observe") < order.index("dispatch")


async def test_direct_path_replay_emits_row_and_does_not_observe() -> None:
    # A direct-path replay (commit_once loses) emits replay_observed and does NOT
    # observe — receipt-time ack advances only on the commit-WON branch.
    order: list[str] = []
    store = _OrderedStore()._bind_order(order)
    # Pre-commit the key so commit_once loses on this call.
    store._committed.add(("alfred_comms_test", "frame-seen"))
    tracker = _OrderedAckTracker(order=order)
    orch = SpyOrchestrator(call_order=order)
    audit = SpyAuditWriter()
    await process_inbound_message(
        make_notification(inbound_id="frame-seen", wire_seq=4),
        identity_resolver=SpyIdentityResolver(returns=make_resolved()),
        orchestrator=orch,
        burst_limiter=SpyBurstLimiter(call_order=order),
        audit_writer=audit,
        secret_broker=SpySecretBroker(),
        idempotency_store=store,
        ack_tracker=tracker,
    )
    assert orch.dispatch_calls == 0
    assert tracker.observed == []  # replay branch never observes
    assert len(audit.rows_with_schema("COMMS_INBOUND_IDEMPOTENCY_REPLAY_FIELDS")) == 1


async def test_direct_path_none_store_falls_through() -> None:
    order: list[str] = []
    orch = SpyOrchestrator(call_order=order)
    await process_inbound_message(
        make_notification(inbound_id="frame-none", wire_seq=1),
        identity_resolver=SpyIdentityResolver(returns=make_resolved()),
        orchestrator=orch,
        burst_limiter=SpyBurstLimiter(call_order=order),
        audit_writer=SpyAuditWriter(),
        secret_broker=SpySecretBroker(),
        idempotency_store=None,
    )
    assert orch.dispatch_calls == 1  # pipeline runs unchanged with no store


# --------------------------------------------------------------------------- #
# 5 — has_committed is NEVER called on the direct path
# --------------------------------------------------------------------------- #
async def test_direct_path_never_reads_has_committed() -> None:
    order: list[str] = []
    store = _OrderedStore()._bind_order(order)
    await process_inbound_message(
        make_notification(inbound_id="frame-x", wire_seq=0),
        identity_resolver=SpyIdentityResolver(returns=make_resolved()),
        orchestrator=SpyOrchestrator(call_order=order),
        burst_limiter=SpyBurstLimiter(call_order=order),
        audit_writer=SpyAuditWriter(),
        secret_broker=SpySecretBroker(),
        idempotency_store=store,
    )
    assert store.has_committed_calls == []


async def test_dispatched_edge_none_store_falls_through_without_has_committed() -> None:
    # edge=True + store=None: no has_committed call, pipeline proceeds, dispatch runs.
    order: list[str] = []
    orch = SpyOrchestrator(call_order=order)
    await process_inbound_message(
        make_notification(inbound_id="frame-edge-none", wire_seq=5),
        identity_resolver=SpyIdentityResolver(returns=make_resolved()),
        orchestrator=orch,
        burst_limiter=SpyBurstLimiter(call_order=order),
        audit_writer=SpyAuditWriter(),
        secret_broker=SpySecretBroker(),
        idempotency_store=None,
        commit_at_dispatch_edge=True,
    )
    assert orch.dispatch_calls == 1
    assert "has_committed" not in order


async def test_dispatched_edge_none_wire_seq_does_not_observe() -> None:
    # edge=True, commit wins, but no seq to observe.
    order: list[str] = []
    store = _OrderedStore()._bind_order(order)
    tracker = _OrderedAckTracker(order=order)
    await process_inbound_message(
        make_notification(inbound_id="frame-noseq", wire_seq=None),
        identity_resolver=SpyIdentityResolver(returns=make_resolved()),
        orchestrator=SpyOrchestrator(call_order=order),
        burst_limiter=SpyBurstLimiter(call_order=order),
        audit_writer=SpyAuditWriter(),
        secret_broker=SpySecretBroker(),
        idempotency_store=store,
        ack_tracker=tracker,
        commit_at_dispatch_edge=True,
    )
    assert store.commit_once_calls == [("frame-noseq", "alfred_comms_test")]
    assert tracker.observed == []  # nothing to observe


# --------------------------------------------------------------------------- #
# 6 — AUDIT-WRITE FAILURE on dispatch_failed propagates loud; not committed
# --------------------------------------------------------------------------- #
async def test_dispatch_failed_audit_write_failure_propagates() -> None:
    order: list[str] = []
    store = _OrderedStore()._bind_order(order)
    tracker = _OrderedAckTracker(order=order)
    orch = _RaisingDispatchOrchestrator(call_order=order)
    audit = _RaisingAuditWriter()
    # The dispatch_failed audit-write failure (not the dispatch RuntimeError) surfaces
    # loud, wrapped in the typed ForwardedInboundAuditWriteError marker AT THE WRITE SITE
    # so the disposition escalates a restart (Spec B G6-7-4); the raw backend error is
    # chained as its __cause__.
    with pytest.raises(ForwardedInboundAuditWriteError) as excinfo:
        await process_inbound_message(
            make_notification(inbound_id="frame-audit-fail", wire_seq=6),
            identity_resolver=SpyIdentityResolver(returns=make_resolved()),
            orchestrator=orch,
            burst_limiter=SpyBurstLimiter(call_order=order),
            audit_writer=audit,
            secret_broker=SpySecretBroker(),
            idempotency_store=store,
            ack_tracker=tracker,
            commit_at_dispatch_edge=True,
        )
    assert isinstance(excinfo.value.__cause__, RuntimeError)
    assert str(excinfo.value.__cause__) == "audit sink down"
    # The frame is NOT committed and NOT observed — the leg will replay it.
    assert store.commit_once_calls == []
    assert tracker.observed == []


# --------------------------------------------------------------------------- #
# 7 — AUDIT-WRITE FAILURE on the forwarded replay-observed row -> typed marker;
#     no drain (the replay is never ACKed without its signed record)
# --------------------------------------------------------------------------- #
async def test_forwarded_replay_observed_audit_write_failure_propagates() -> None:
    order: list[str] = []
    store = _OrderedStore(already=True)._bind_order(order)
    tracker = _OrderedAckTracker(order=order)
    audit = _RaisingReplayObservedAuditWriter()
    # The forwarded-path replay-observed audit-write failure surfaces loud, wrapped in
    # the typed ForwardedInboundAuditWriteError marker AT THE WRITE SITE so the
    # disposition escalates a restart (Spec B G6-7-4); the raw backend error chains as
    # its __cause__. The drain ``observe`` is SHORT-CIRCUITED — never ACK a replay that
    # was not signed-audited.
    with pytest.raises(ForwardedInboundAuditWriteError) as excinfo:
        await process_inbound_message(
            make_notification(inbound_id="frame-replay-audit-fail", wire_seq=8),
            identity_resolver=SpyIdentityResolver(returns=make_resolved()),
            orchestrator=SpyOrchestrator(call_order=order),
            burst_limiter=SpyBurstLimiter(call_order=order),
            audit_writer=audit,
            secret_broker=SpySecretBroker(),
            idempotency_store=store,
            ack_tracker=tracker,
            commit_at_dispatch_edge=True,
        )
    assert isinstance(excinfo.value.__cause__, RuntimeError)
    assert str(excinfo.value.__cause__) == "replay audit sink down"
    # The drain was short-circuited: a replay is never ACKed without its signed record.
    assert tracker.observed == []


# --------------------------------------------------------------------------- #
# 8 — DETERMINISTIC MID-PIPELINE REFUSALS drain under edge mode (FIX 1, #309)
#
# The three deterministic refusals (pre-resolution budget cap / unbound
# first-contact / burst Dropped) refuse identically on every replay. On the
# forwarded dispatched edge they MUST observe-only DRAIN (NO commit_once) AFTER
# their signed row, else the contiguous high-water wedges → infinite replay.
# --------------------------------------------------------------------------- #
def _capped_pre_resolution_limiter() -> _PreResolutionLimiter:
    """A pre-resolution limiter whose budget is ALREADY exhausted (limit 0)."""
    return _PreResolutionLimiter(limit_per_minute=0)


async def test_edge_budget_cap_audits_then_drains_no_commit() -> None:
    order: list[str] = []
    store = _OrderedStore()._bind_order(order)
    tracker = _OrderedAckTracker(order=order)
    orch = SpyOrchestrator(call_order=order)
    audit = SpyAuditWriter()
    await process_inbound_message(
        make_notification(inbound_id="frame-cap", wire_seq=11),
        identity_resolver=SpyIdentityResolver(returns=make_resolved()),
        orchestrator=orch,
        burst_limiter=SpyBurstLimiter(call_order=order),
        audit_writer=audit,
        secret_broker=SpySecretBroker(),
        pre_resolution_limiter=_capped_pre_resolution_limiter(),
        idempotency_store=store,
        ack_tracker=tracker,
        commit_at_dispatch_edge=True,
    )
    # (a) the signed budget-capped row wrote.
    rows = audit.rows_with_schema("COMMS_INBOUND_BUDGET_CAPPED_FIELDS")
    assert len(rows) == 1
    assert rows[0]["result"] == "dropped"
    # (b) observe called exactly once; (c) commit_once NOT called.
    assert tracker.observed == [11]
    assert store.commit_once_calls == []
    # Refused before resolution → no dispatch.
    assert orch.dispatch_calls == 0


async def test_edge_binding_request_audits_then_drains_no_commit() -> None:
    order: list[str] = []
    store = _OrderedStore()._bind_order(order)
    tracker = _OrderedAckTracker(order=order)
    orch = SpyOrchestrator(call_order=order)
    audit = SpyAuditWriter()
    await process_inbound_message(
        make_notification(inbound_id="frame-bind", wire_seq=12),
        identity_resolver=SpyIdentityResolver(returns=None),  # unbound first-contact
        orchestrator=orch,
        burst_limiter=SpyBurstLimiter(call_order=order),
        audit_writer=audit,
        secret_broker=SpySecretBroker(),
        idempotency_store=store,
        ack_tracker=tracker,
        commit_at_dispatch_edge=True,
    )
    rows = audit.rows_with_schema("COMMS_BINDING_REQUESTED_FIELDS")
    assert len(rows) == 1
    assert tracker.observed == [12]
    assert store.commit_once_calls == []
    assert orch.dispatch_calls == 0


async def test_edge_burst_dropped_audits_then_drains_no_commit() -> None:
    from datetime import UTC, datetime

    order: list[str] = []
    store = _OrderedStore()._bind_order(order)
    tracker = _OrderedAckTracker(order=order)
    orch = SpyOrchestrator(call_order=order)
    audit = SpyAuditWriter()
    dropped = Dropped(waited_seconds=0.0, bucket_empty_since=datetime.now(UTC))
    await process_inbound_message(
        make_notification(inbound_id="frame-burst", wire_seq=13),
        identity_resolver=SpyIdentityResolver(returns=make_resolved()),
        orchestrator=orch,
        burst_limiter=SpyBurstLimiter(call_order=order, result=dropped),
        audit_writer=audit,
        secret_broker=SpySecretBroker(),
        idempotency_store=store,
        ack_tracker=tracker,
        commit_at_dispatch_edge=True,
    )
    # The burst-drop arm is SILENT on the direct path; the forwarded edge emits a
    # NEW content-free signed row (reusing the budget-capped field set, result=dropped).
    rows = audit.rows_with_schema("COMMS_INBOUND_BUDGET_CAPPED_FIELDS")
    assert len(rows) == 1
    assert rows[0]["event"] == "comms.inbound.burst_dropped"
    assert rows[0]["result"] == "dropped"
    assert rows[0]["canonical_user_id"] == make_resolved().canonical_user_id
    # No raw body / user text on the row.
    assert "hello" not in str(rows[0])
    assert tracker.observed == [13]
    assert store.commit_once_calls == []
    assert orch.dispatch_calls == 0


# --------------------------------------------------------------------------- #
# 9 — DIRECT-PATH REGRESSION: the new edge-only drains are NOT reached
#     (byte-for-byte unchanged refusals).
# --------------------------------------------------------------------------- #
async def test_direct_budget_cap_does_not_observe_or_emit_new_row() -> None:
    order: list[str] = []
    tracker = _OrderedAckTracker(order=order)
    audit = SpyAuditWriter()
    await process_inbound_message(
        make_notification(inbound_id="frame-cap-direct", wire_seq=21),
        identity_resolver=SpyIdentityResolver(returns=make_resolved()),
        orchestrator=SpyOrchestrator(call_order=order),
        burst_limiter=SpyBurstLimiter(call_order=order),
        audit_writer=audit,
        secret_broker=SpySecretBroker(),
        pre_resolution_limiter=_capped_pre_resolution_limiter(),
        idempotency_store=None,
        ack_tracker=tracker,
        # default commit_at_dispatch_edge=False
    )
    # The budget-capped row still wrote (unchanged), but NO drain on the direct path.
    assert len(audit.rows_with_schema("COMMS_INBOUND_BUDGET_CAPPED_FIELDS")) == 1
    assert tracker.observed == []


async def test_direct_binding_request_does_not_observe() -> None:
    order: list[str] = []
    tracker = _OrderedAckTracker(order=order)
    audit = SpyAuditWriter()
    await process_inbound_message(
        make_notification(inbound_id="frame-bind-direct", wire_seq=22),
        identity_resolver=SpyIdentityResolver(returns=None),
        orchestrator=SpyOrchestrator(call_order=order),
        burst_limiter=SpyBurstLimiter(call_order=order),
        audit_writer=audit,
        secret_broker=SpySecretBroker(),
        idempotency_store=None,
        ack_tracker=tracker,
    )
    assert len(audit.rows_with_schema("COMMS_BINDING_REQUESTED_FIELDS")) == 1
    assert tracker.observed == []


async def test_edge_budget_cap_drain_is_noop_when_no_wire_seq() -> None:
    # edge=True but the leg is un-sequenced (wire_seq=None): the row still writes and
    # _drain_forwarded_seq is invoked, but its observe branch is a NO-OP (nothing to
    # drain). Covers the drain helper's False (fall-through) branch.
    order: list[str] = []
    tracker = _OrderedAckTracker(order=order)
    audit = SpyAuditWriter()
    await process_inbound_message(
        make_notification(inbound_id="frame-cap-noseq", wire_seq=None),
        identity_resolver=SpyIdentityResolver(returns=make_resolved()),
        orchestrator=SpyOrchestrator(call_order=order),
        burst_limiter=SpyBurstLimiter(call_order=order),
        audit_writer=audit,
        secret_broker=SpySecretBroker(),
        pre_resolution_limiter=_capped_pre_resolution_limiter(),
        idempotency_store=None,
        ack_tracker=tracker,
        commit_at_dispatch_edge=True,
    )
    assert len(audit.rows_with_schema("COMMS_INBOUND_BUDGET_CAPPED_FIELDS")) == 1
    assert tracker.observed == []  # un-sequenced leg → drain no-op


async def test_direct_burst_dropped_stays_silent_and_does_not_observe() -> None:
    from datetime import UTC, datetime

    order: list[str] = []
    tracker = _OrderedAckTracker(order=order)
    audit = SpyAuditWriter()
    dropped = Dropped(waited_seconds=0.0, bucket_empty_since=datetime.now(UTC))
    await process_inbound_message(
        make_notification(inbound_id="frame-burst-direct", wire_seq=23),
        identity_resolver=SpyIdentityResolver(returns=make_resolved()),
        orchestrator=SpyOrchestrator(call_order=order),
        burst_limiter=SpyBurstLimiter(call_order=order, result=dropped),
        audit_writer=audit,
        secret_broker=SpySecretBroker(),
        idempotency_store=None,
        ack_tracker=tracker,
    )
    # Direct path: the burst-drop arm writes NO row and does NOT observe (byte-for-byte).
    assert audit.rows_with_schema("COMMS_INBOUND_BUDGET_CAPPED_FIELDS") == []
    assert tracker.observed == []
