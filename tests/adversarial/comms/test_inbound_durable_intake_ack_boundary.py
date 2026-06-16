"""Adversarial: the host durable-intake ack advances ONLY on a durable commit.

**Threat model** (Spec A G4b-2a-pre / ADR-0032, #237 — the daemon's durable-intake
ack feeds the gateway's ReplayBuffer ``trim_to_ack`` in G4b-2a). The ack is the
core's signal of "highest CONTIGUOUS client->core wire seq I have DURABLY intaken";
the gateway trims its replay buffer up to it. Two ways an adversary could corrupt
that trim (a liveness / possible-INPUT-LOSS concern on the resume path) — both must
be defended at the host:

* **(a) forged / out-of-window seq** — a ``wire_seq`` far beyond the contiguous
  high-water (a same-uid impostor on the seq-enabled socket leg forging a giant seq,
  or a badly-reordered stream) must NOT advance the ack. ``BoundedSeqAckTracker``
  rejects any seq more than ``_MAX_OOO_GAP`` beyond the high-water LOUD
  (``gateway.relay.seq_out_of_window``) and does not admit it — bounding the
  out-of-order memory surface (hard rule #7: no silent drop) AND keeping the ack
  honest. Proven END-TO-END through ``process_inbound_message`` (the real G0 path),
  not just the tracker in isolation.

* **(b) replay-after-commit** — a REPLAYED ``inbound_id`` (the gateway buffer
  replaying after a core restart, or an adapter retry) carrying a FRESH wire seq must
  NOT double-advance the ack: the G0 ``commit_once`` loses (the row already exists),
  the pipeline short-circuits at the replay branch BEFORE ``observe``, and the
  existing signed ``comms.inbound.idempotency.replay_observed`` row is the evidence
  (NO new audit reason). This is the exactly-once-vs-ack-monotonicity property: the
  ack reflects DURABLE intake, so a re-seen frame the core already took never moves
  it. If it did, the gateway would trim a frame it must keep available for replay.

**Trust impact (F3).** A forged in-window seq could corrupt ONLY the gateway's
buffer-trim liveness (a resume-path concern), NEVER the durable ``commit_once``
exactly-once guarantee (that is the in-payload ``inbound_id``, untouched here).
``_MAX_OOO_GAP`` bounds the memory-DoS; out-of-window is loud. Standalone
adversarial module (a wire-seq integrity property, not a corpus content payload).
"""

from __future__ import annotations

import pytest
import structlog.testing

from alfred.comms_mcp import audit_hash
from alfred.comms_mcp.inbound import process_inbound_message
from alfred.gateway._seq_tracker import _MAX_OOO_GAP, BoundedSeqAckTracker
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
    """commit_once: wins once per inbound_id (durable accept), loses on re-see (replay)."""

    def __init__(self) -> None:
        self._committed: set[str] = set()
        self.calls: list[tuple[str, str]] = []

    async def commit_once(self, *, inbound_id: str, adapter_id: str) -> bool:
        self.calls.append((inbound_id, adapter_id))
        if inbound_id in self._committed:
            return False
        self._committed.add(inbound_id)
        return True


async def _process(
    *,
    store: _FakeStore,
    tracker: BoundedSeqAckTracker,
    inbound_id: str,
    wire_seq: int,
    audit: SpyAuditWriter | None = None,
) -> None:
    await process_inbound_message(
        make_notification(inbound_id=inbound_id, wire_seq=wire_seq),
        identity_resolver=SpyIdentityResolver(returns=make_resolved()),
        orchestrator=SpyOrchestrator(),
        burst_limiter=SpyBurstLimiter(),
        audit_writer=audit if audit is not None else SpyAuditWriter(),
        secret_broker=SpySecretBroker(),
        idempotency_store=store,
        ack_tracker=tracker,
    )


async def test_forged_out_of_window_seq_does_not_advance_the_ack() -> None:
    store = _FakeStore()
    tracker = BoundedSeqAckTracker()
    # Establish a contiguous high-water at 0.
    await _process(store=store, tracker=tracker, inbound_id="frame-0", wire_seq=0)
    assert tracker.cumulative_ack() == 0

    forged = _MAX_OOO_GAP + 1  # strictly beyond high-water (0) + _MAX_OOO_GAP
    with structlog.testing.capture_logs() as logs:
        await _process(store=store, tracker=tracker, inbound_id="frame-forged", wire_seq=forged)

    # The forged seq was REFUSED loud and NOT admitted — the ack is unchanged.
    assert tracker.cumulative_ack() == 0
    events = [entry["event"] for entry in logs]
    assert "gateway.relay.seq_out_of_window" in events
    # The G0 commit DID run for the (distinct) inbound_id — the durable exactly-once
    # guarantee is untouched; only the ack-trim was (correctly) refused the advance.
    assert ("frame-forged", "alfred_comms_test") in store.calls


async def test_replay_after_commit_does_not_double_advance_the_ack() -> None:
    store = _FakeStore()
    tracker = BoundedSeqAckTracker()
    audit = SpyAuditWriter()

    # First delivery: durable accept at seq 0 → ack advances to 0.
    await _process(store=store, tracker=tracker, inbound_id="frame-A", wire_seq=0, audit=audit)
    assert tracker.cumulative_ack() == 0

    # The gateway replays frame-A after a restart, this time stamping a FRESH wire seq
    # (the buffer re-mints the seq on the new connection). commit_once LOSES (the row
    # exists), so the pipeline short-circuits BEFORE observe — the ack does not move.
    await _process(store=store, tracker=tracker, inbound_id="frame-A", wire_seq=99, audit=audit)
    assert tracker.cumulative_ack() == 0  # NOT advanced to 99 — exactly-once vs ack

    # The evidence is the existing signed replay-observed row (NO new audit reason),
    # carrying the peppered hash of the replayed inbound_id (never the raw string).
    rows = audit.rows_with_schema("COMMS_INBOUND_IDEMPOTENCY_REPLAY_FIELDS")
    assert len(rows) == 1
    assert rows[0]["inbound_id_hash"] == audit_hash.hash_inbound_id("frame-A")
    assert rows[0]["result"] == "dropped"
