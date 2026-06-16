"""Host durable-intake ack tracker advanced ONLY on the G0 ``commit_once`` (G4b-2a-pre).

Spec A G4b-2a-pre / ADR-0032 (#237). ``process_inbound_message`` ``observe``s the
inbound ``wire_seq`` on the host-side ``BoundedSeqAckTracker`` ONLY when the durable
``commit_once`` returns ``True`` (a fresh durable accept). It does NOT advance on:

* the REPLAY branch (``commit_once == False``) — the gateway must not trim a frame
  the core merely re-saw;
* a structural refusal AHEAD of the gate (cheap-validate, promoter-required) — the
  message was never durably accepted;
* ``wire_seq is None`` (stdio / un-sequenced) — nothing to observe;
* ``ack_tracker is None`` (pre-G0 unit caller) — the path is unchanged.

The ack then means "highest CONTIGUOUS seq the core has DURABLY accepted" and is
correct under the runner's out-of-order concurrent dispatch (``observe`` is
order-insensitive within its window).
"""

from __future__ import annotations

import pytest

from alfred.comms_mcp.errors import PromoterRequiredError
from alfred.comms_mcp.inbound import process_inbound_message
from alfred.gateway._seq_tracker import BoundedSeqAckTracker
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


class _FakeStore:
    """A commit_once store: returns ``won`` for ids NOT yet committed.

    ``won=True`` admits every id once (a fresh durable accept); a second call for
    the SAME id returns ``False`` (the replay branch). ``won=False`` always loses
    (every call is a replay).
    """

    def __init__(self, *, won: bool) -> None:
        self._won = won
        self._committed: set[str] = set()
        self.calls: list[tuple[str, str]] = []

    async def commit_once(self, *, inbound_id: str, adapter_id: str) -> bool:
        self.calls.append((inbound_id, adapter_id))
        if not self._won:
            return False
        if inbound_id in self._committed:
            return False
        self._committed.add(inbound_id)
        return True


async def _run(
    *,
    store: _FakeStore,
    tracker: BoundedSeqAckTracker | None,
    inbound_id: str,
    wire_seq: int | None,
    promoter: object | None = None,
    adapter_id: str = "alfred_comms_test",
    body: dict[str, object] | None = None,
) -> None:
    await process_inbound_message(
        make_notification(
            inbound_id=inbound_id,
            adapter_id=adapter_id,
            wire_seq=wire_seq,
            body=body,
        ),
        identity_resolver=SpyIdentityResolver(returns=make_resolved()),
        orchestrator=SpyOrchestrator(),
        burst_limiter=SpyBurstLimiter(),
        audit_writer=SpyAuditWriter(),
        secret_broker=SpySecretBroker(),
        idempotency_store=store,
        sub_payload_promoter=promoter,  # type: ignore[arg-type]
        ack_tracker=tracker,
    )


async def test_contiguous_commits_advance_the_ack() -> None:
    store = _FakeStore(won=True)
    tracker = BoundedSeqAckTracker()
    for seq in (0, 1, 2):
        await _run(store=store, tracker=tracker, inbound_id=f"frame-{seq}", wire_seq=seq)
    assert tracker.cumulative_ack() == 2


async def test_replay_does_not_advance_the_ack() -> None:
    # A REPLAYED inbound_id (commit_once -> False) carrying a FRESH wire seq must
    # not advance: it returns at the replay branch, never reaching ``observe``.
    store = _FakeStore(won=True)
    tracker = BoundedSeqAckTracker()
    await _run(store=store, tracker=tracker, inbound_id="frame-A", wire_seq=0)
    assert tracker.cumulative_ack() == 0
    # Same id, a fresh seq=1 — the store loses (replay); the ack must stay at 0.
    await _run(store=store, tracker=tracker, inbound_id="frame-A", wire_seq=1)
    assert tracker.cumulative_ack() == 0


async def test_gap_stalls_then_fills_under_out_of_order_dispatch() -> None:
    # Feed 0, 1, 3 (the runner dispatches concurrently, so 2 lands AFTER 3). The
    # ack stalls at 1 until 2 commits, then jumps to 3 — the contiguous property.
    store = _FakeStore(won=True)
    tracker = BoundedSeqAckTracker()
    await _run(store=store, tracker=tracker, inbound_id="frame-0", wire_seq=0)
    await _run(store=store, tracker=tracker, inbound_id="frame-1", wire_seq=1)
    await _run(store=store, tracker=tracker, inbound_id="frame-3", wire_seq=3)
    assert tracker.cumulative_ack() == 1  # 2 not yet seen
    await _run(store=store, tracker=tracker, inbound_id="frame-2", wire_seq=2)
    assert tracker.cumulative_ack() == 3  # the hole filled; high-water jumps


async def test_promoter_required_refusal_does_not_advance() -> None:
    # A structural refusal AHEAD of the G0 gate (promoter-required for a
    # classifier-bearing adapter) raises before commit_once — the ack is untouched.
    store = _FakeStore(won=True)
    tracker = BoundedSeqAckTracker()
    with pytest.raises(PromoterRequiredError):
        await _run(
            store=store,
            tracker=tracker,
            inbound_id="frame-discord",
            wire_seq=0,
            adapter_id="discord",
            promoter=None,
        )
    assert tracker.cumulative_ack() == -1
    assert store.calls == []  # the gate was never even reached


async def test_cheap_validate_refusal_does_not_advance() -> None:
    # An empty body fails the cheap pre-check BEFORE the gate; no observe, no commit.
    store = _FakeStore(won=True)
    tracker = BoundedSeqAckTracker()
    await _run(store=store, tracker=tracker, inbound_id="frame-empty", wire_seq=0, body={})
    assert tracker.cumulative_ack() == -1
    assert store.calls == []


async def test_none_wire_seq_is_a_safe_no_op() -> None:
    # stdio / un-sequenced frame: commit_once wins but there is no seq to observe.
    store = _FakeStore(won=True)
    tracker = BoundedSeqAckTracker()
    await _run(store=store, tracker=tracker, inbound_id="frame-stdio", wire_seq=None)
    assert store.calls == [("frame-stdio", "alfred_comms_test")]  # committed
    assert tracker.cumulative_ack() == -1  # but nothing observed


async def test_none_tracker_leaves_pipeline_unchanged() -> None:
    # The pre-G0 unit caller passes no tracker; the path runs as before.
    store = _FakeStore(won=True)
    await _run(store=store, tracker=None, inbound_id="frame-x", wire_seq=5)
    assert store.calls == [("frame-x", "alfred_comms_test")]


async def test_none_store_does_not_advance_and_still_dispatches() -> None:
    # A None store (pre-G0 caller) never calls observe but MUST still fall through
    # to the rest of the pipeline (F2.1 None-store fallthrough).
    tracker = BoundedSeqAckTracker()
    orch = SpyOrchestrator()
    await process_inbound_message(
        make_notification(inbound_id="frame-y", wire_seq=3),
        identity_resolver=SpyIdentityResolver(returns=make_resolved()),
        orchestrator=orch,
        burst_limiter=SpyBurstLimiter(),
        audit_writer=SpyAuditWriter(),
        secret_broker=SpySecretBroker(),
        idempotency_store=None,
        ack_tracker=tracker,
    )
    assert tracker.cumulative_ack() == -1  # no store => no durable-accept observe
    assert orch.dispatch_calls == 1  # pipeline still ran
