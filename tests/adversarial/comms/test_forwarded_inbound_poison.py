"""Adversarial: the forwarded-inbound POISON CEILING trust boundary (Spec B G6-7-5).

**Threat model** (ADR-0039 item 4b / #309 / §3.3). The ``alfred-gateway`` forwards a
hosted adapter child's ``inbound.message`` to the connectivity-free CORE as a JSON-RPC
``gateway.adapter.inbound`` notification. The core dispatches it on the DISPATCHED edge
(``commit_at_dispatch_edge=True``): a dispatch failure deliberately leaves the frame NOT
committed / NOT observed so the forwarding leg replays it (G6-7-4). Without a bound a
frame whose post-extract region ALWAYS fails (a POISON message) re-charges the
quarantined extractor on every reconnect forever (PERF-309-1). G6-7-5 lands the ceiling:

* a READ of ``attempt_count`` BEFORE ``quarantined_extract`` — placed AFTER the
  pre-resolution DoS limiter (sec C-1) so an attacker-chosen distinct-``inbound_id``
  flood is shed before it can grow the ledger; ``>= N`` short-circuits to a content-free
  ``comms.inbound.poisoned`` dead-letter row + an observe-only drain;
* an ``increment`` ON ENTRY to the post-extract region (right after a successful extract)
  so EVERY un-draining downstream failure — promotion-emit, ingest, dispatch — is
  ceilinged (sec C-2), increment-before-audit so a flaky audit backend can never
  under-count a poison frame past the ceiling.

These are the ADVERSARIAL companions to the unit suite
(``tests/unit/comms/test_inbound_poison_ceiling.py``) — they drive the property the
attacker actually exercises and prove the bound holds end-to-end, including the
no-T3-leak invariant on the dead-letter row. They mirror the G6-7-4 admission
companions' harness (``test_forwarded_inbound_admission.py``): a REAL
``GatewayForwardedInboundReceiver`` over the REAL ``process_inbound_message`` pipeline
with deps mocked (no Postgres), plus a real ``BoundedSeqAckTracker`` where the high-water
RELEASE property is load-bearing, and a real composite-keyed in-memory attempt ledger
where the cross-adapter isolation property is load-bearing.

The eight levers:

1. **Poison e2e** — N failing replays charge the extractor EXACTLY N times; the (N+1)-th
   is a dead-letter + a single drain whose ``observe`` RELEASES the stalled contiguous
   high-water (a real ``BoundedSeqAckTracker``'s ``cumulative_ack`` advances past the
   poison seq so the dispatched tail can trim).
2. **Distinct-id flood is DoS-gated (sec C-1)** — a flood of distinct attacker-chosen
   ``inbound_id``\\s under ONE ``(adapter_id, platform_user_id_hash)`` is shed by the
   pre-resolution limiter; the ledger is NEVER read/grown past the DoS budget.
3. **Deliberate shed is NOT poison (item 4)** — a budget-capped / burst-dropped forwarded
   frame drains single-shot and the ledger is byte-for-byte UNTOUCHED; replay never poisons.
4. **receive_fault is NOT ceilinged (item 5)** — an off-vocab/unparseable envelope drains
   on the FIRST occurrence and never touches the attempt store; no ``poisoned`` row ever.
5. **poison-then-receive_fault interleave** — a frame that fails dispatch k<N times, then
   surfaces as a receive_fault drop, drains single-shot with no double-count, no
   cross-path poison.
6. **Cross-adapter isolation (composite key)** — a ``discord`` frame failing dispatch never
   advances the ``tui`` counter (a real composite-keyed ledger proves it at the key).
7. **Concurrent replay at ceiling (sec H3, "at least N")** — two concurrent copies of an
   at-ceiling frame produce >=1 ``poisoned`` row, the high-water advances once-effectively
   (idempotent ``observe``), never dispatched.
8. **Canary absence (sec-010)** — a high-entropy secret in the T3 body AND a high-entropy
   ``inbound_id`` never appear (raw) in the ``poisoned`` row's fields OR in any structlog
   record — only the peppered hash.

NON-ROOT, no-Postgres, in-process. Standalone adversarial module — a receive-boundary
COST-bound property, not a corpus content payload.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
import structlog.testing

from alfred.comms_mcp import audit_hash
from alfred.comms_mcp.forwarded_inbound_receiver import (
    GatewayForwardedInboundReceiver,
    _ForwardedCollaborators,
)
from alfred.comms_mcp.inbound import (
    _FORWARDED_DISPATCH_ATTEMPT_CEILING,
    _PreResolutionLimiter,
)
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

# The admitted reference kind — EMPTY required-classifier set, so a ``None`` promoter is
# correct and the real ``process_inbound_message`` runs plain-text (no M2 trip). Mirrors
# the G6-7-4 admission companions.
_ADAPTER_ID = "alfred_comms_test"

# The ceiling under test (5). Bound to the production constant so a config change can
# never silently weaken these adversarial bounds without re-surfacing here.
_CEILING = _FORWARDED_DISPATCH_ATTEMPT_CEILING

# A high-entropy synthetic canary planted in the T3 body / inbound_id of the
# poison-leak case. NOT a real secret — but distinctive so a partial leak (a fragment)
# is still caught by the substring scan. Assembled to be plainly synthetic.
_CANARY = "CANARY-9d2e7a4f1b6c3e8a-POISON-TRIPWIRE-do-not-log-этот-секрет"


# --------------------------------------------------------------------------- #
# Stateful fakes — a REAL composite-keyed attempt ledger + a recording ack
# tracker, so the cost-bound / isolation / drain properties are non-vacuous.
# --------------------------------------------------------------------------- #


class _InMemoryAttemptStore:
    """A durable forwarded-dispatch attempt ledger backed by a REAL monotone counter.

    Keyed on the COMPOSITE ``(adapter_id, inbound_id)`` — the SAME isolation the
    Postgres :class:`PostgresForwardedDispatchAttemptStore` has — so the cross-adapter
    isolation case (6) is proven at the ledger, not stubbed. ``increment`` advances and
    returns the post-write count; ``attempt_count`` is the non-mutating read (0 absent).
    Both record their composite-key calls so a test can assert the gate placement (never
    touched on a pre-resolution shed / the direct path).
    """

    def __init__(self) -> None:
        self._counts: dict[tuple[str, str], int] = {}
        self.increment_calls: list[tuple[str, str]] = []
        self.attempt_count_calls: list[tuple[str, str]] = []

    async def increment(self, *, adapter_id: str, inbound_id: str) -> int:
        self.increment_calls.append((adapter_id, inbound_id))
        key = (adapter_id, inbound_id)
        self._counts[key] = self._counts.get(key, 0) + 1
        return self._counts[key]

    async def attempt_count(self, *, adapter_id: str, inbound_id: str) -> int:
        self.attempt_count_calls.append((adapter_id, inbound_id))
        return self._counts.get((adapter_id, inbound_id), 0)

    def count(self, *, adapter_id: str, inbound_id: str) -> int:
        """Test-only direct read (never goes through the recorded surface)."""
        return self._counts.get((adapter_id, inbound_id), 0)


class _SpyAckTracker:
    """Records ``observe`` so drain occurrence is assertable (idempotent re-observe)."""

    def __init__(self) -> None:
        self.observed: list[int] = []

    def observe(self, seq: int) -> None:
        self.observed.append(seq)


class _NeverCommittedStore:
    """A store whose key is never durable — the dispatched path reads, never short-circuits."""

    async def commit_once(self, *, inbound_id: str, adapter_id: str) -> bool:
        return True

    async def has_committed(self, *, inbound_id: str, adapter_id: str) -> bool:
        return False


class _AlwaysFailOrchestrator(SpyOrchestrator):
    """``dispatch`` ALWAYS raises — a deterministically-failing (poison) frame."""

    async def dispatch(self, ingested: object) -> None:
        self.call_order.append("dispatch")
        self.dispatch_calls += 1
        raise RuntimeError("poison frame")


def _collaborators(
    *,
    orchestrator: SpyOrchestrator | None = None,
    pre_resolution_limiter: _PreResolutionLimiter | None = None,
) -> _ForwardedCollaborators:
    """The K4-admitted collaborator set for ``_ADAPTER_ID`` (the real pipeline runs)."""
    return _ForwardedCollaborators(
        sub_payload_promoter=None,  # type: ignore[arg-type]
        resolver_bridge=SpyIdentityResolver(returns=make_resolved(adapter_id=_ADAPTER_ID)),
        orchestrator=orchestrator if orchestrator is not None else SpyOrchestrator(),
        burst_limiter=SpyBurstLimiter(),
        secret_broker=SpySecretBroker(),
        # ONE long-lived limiter per adapter (sec-003) so the DoS budget accumulates
        # across the flood — load-bearing for case 2.
        pre_resolution_limiter=(
            pre_resolution_limiter
            if pre_resolution_limiter is not None
            else _PreResolutionLimiter()
        ),
    )


def _build_receiver(
    *,
    audit_writer: Any,
    attempt_store: Any,
    ack_tracker: _SpyAckTracker | BoundedSeqAckTracker | None = None,
    orchestrator: SpyOrchestrator | None = None,
    pre_resolution_limiter: _PreResolutionLimiter | None = None,
    registry: dict[str, _ForwardedCollaborators] | None = None,
) -> GatewayForwardedInboundReceiver:
    """A REAL receiver over the REAL dispatched-edge pipeline (deps mocked, no DB).

    The receiver always threads ``attempt_store`` + ``commit_at_dispatch_edge=True`` into
    ``process_inbound_message``, so these cases exercise the REAL item-4b ceiling.
    """
    receiver = GatewayForwardedInboundReceiver(
        registry=registry
        if registry is not None
        else {
            _ADAPTER_ID: _collaborators(
                orchestrator=orchestrator, pre_resolution_limiter=pre_resolution_limiter
            )
        },
        idempotency_store=_NeverCommittedStore(),
        attempt_store=attempt_store,
        audit_writer=audit_writer,
    )
    if ack_tracker is not None:
        receiver.set_ack_tracker(ack_tracker)
    return receiver


def _envelope_params(*, adapter_id: str = _ADAPTER_ID, body: str) -> dict[str, Any]:
    """The wire ``params`` of a ``gateway.adapter.inbound`` notification frame."""
    return {"adapter_id": adapter_id, "body": body}


def _body(
    *,
    adapter_id: str = _ADAPTER_ID,
    inbound_id: str,
    content: str = "hello there",
) -> str:
    """A well-formed ``InboundMessageNotification`` body serialized to a JSON str."""
    notification = make_notification(
        adapter_id=adapter_id, inbound_id=inbound_id, body={"content": content}
    )
    dumped: str = notification.model_dump_json()
    return dumped


@pytest.fixture(autouse=True)
def _reset_audit_hash() -> Any:
    """Isolate the module-level comms audit-hash broker between tests."""
    audit_hash.reset_for_test()
    yield
    audit_hash.reset_for_test()


# --------------------------------------------------------------------------- #
# 1 — Poison e2e: N failing replays → N extracts; the (N+1)-th dead-letters,
#     drains ONCE, and that drain RELEASES the stalled contiguous high-water.
# --------------------------------------------------------------------------- #


async def test_poison_e2e_dead_letters_and_releases_stalled_high_water() -> None:
    """A deterministically-failing forwarded frame is ceilinged + frees the high-water.

    Property proven: a poison frame whose dispatch ALWAYS raises charges
    ``quarantined_extract`` EXACTLY ``N`` times across ``N+1`` replays sharing ONE durable
    ledger; the (N+1)-th replay is a single content-free ``comms.inbound.poisoned``
    dead-letter row + a single drain ``observe(poison_seq)``. The un-observed→observed
    transition RELEASES the stalled contiguous high-water — a REAL ``BoundedSeqAckTracker``
    whose ``cumulative_ack`` is wedged at the gap below the poison seq advances PAST the
    poison seq once it drains, so a dispatched tail can finally trim (the gateway stops
    replaying the whole window).
    """
    store = _InMemoryAttemptStore()
    tracker = BoundedSeqAckTracker()
    audit = SpyAuditWriter()
    orch = _AlwaysFailOrchestrator()
    receiver = _build_receiver(
        audit_writer=audit, attempt_store=store, ack_tracker=tracker, orchestrator=orch
    )
    body = _body(inbound_id="poison-frame")

    # The poison frame rides on leg seq 1. Seq 0 is a healthy frame that already
    # drained, so the contiguous high-water sits at 0 and is WEDGED at the gap (1) the
    # poison frame leaves un-observed on every failing replay.
    tracker.observe(0)
    assert tracker.cumulative_ack() == 0

    # The first N replays each fail dispatch LOUD (no drain): each increments the durable
    # ledger and re-raises. The high-water stays wedged at 0 (seq 1 never observed).
    for _ in range(_CEILING):
        with pytest.raises(RuntimeError, match="poison frame"):
            await receiver.receive(params=_envelope_params(body=body), wire_seq=1)
        assert tracker.cumulative_ack() == 0  # still wedged — poison seq un-observed

    # The (N+1)-th replay: attempt_count == N >= N → poisoned, NO extract, drain.
    await receiver.receive(params=_envelope_params(body=body), wire_seq=1)

    # The extractor was charged EXACTLY N times across the N+1 deliveries.
    assert orch.quarantined_extract_calls == _CEILING
    assert orch.dispatch_calls == _CEILING  # the (N+1)-th never reached dispatch
    # Exactly one terminal dead-letter row, carrying the bounded attempt_count.
    poisoned = audit.rows_with_schema("COMMS_INBOUND_POISONED_FIELDS")
    assert len(poisoned) == 1
    assert poisoned[0]["event"] == "comms.inbound.poisoned"
    assert poisoned[0]["result"] == "poisoned"
    assert poisoned[0]["attempt_count"] == _CEILING
    # The drain RELEASED the wedge: the contiguous high-water advanced past the poison seq.
    assert tracker.cumulative_ack() == 1


# --------------------------------------------------------------------------- #
# 2 — Distinct-id flood is DoS-gated (sec C-1): the ledger is never grown past
#     the pre-resolution budget — the flood is shed BEFORE the ceiling read.
# --------------------------------------------------------------------------- #


async def test_distinct_inbound_id_flood_is_dos_gated_before_ledger() -> None:
    """A distinct-``inbound_id`` flood under ONE user is shed before it can grow the ledger.

    Property proven (sec C-1): the ceiling READ is placed AFTER the pre-resolution DoS
    limiter, which is keyed on ``(adapter_id, platform_user_id_hash)`` — NOT on
    ``inbound_id``. So an attacker cycling distinct ``inbound_id``\\s under ONE platform
    user shares ONE budget; once the budget is exhausted EVERY further distinct id is shed
    WITHOUT touching the attempt store. The ledger therefore cannot be grown past the DoS
    budget (the dead-letter ledger is not itself an amplification surface).
    """
    budget = 3
    store = _InMemoryAttemptStore()
    tracker = _SpyAckTracker()
    audit = SpyAuditWriter()
    # An always-fail orchestrator so any frame that DID reach dispatch would increment —
    # making a ledger touch past the budget unmistakable.
    orch = _AlwaysFailOrchestrator()
    limiter = _PreResolutionLimiter(limit_per_minute=budget)
    receiver = _build_receiver(
        audit_writer=audit,
        attempt_store=store,
        ack_tracker=tracker,
        orchestrator=orch,
        pre_resolution_limiter=limiter,
    )

    # Drive 4*budget distinct inbound_ids — all the SAME platform user (make_notification's
    # default platform_user_id), so they all share the one limiter key.
    flood = budget * 4
    seen_poison: list[BaseException] = []
    for i in range(flood):
        body = _body(inbound_id=f"flood-{i}")
        try:
            await receiver.receive(params=_envelope_params(body=body), wire_seq=i)
        except RuntimeError as exc:  # the within-budget ones fail dispatch loud
            seen_poison.append(exc)

    # Exactly ``budget`` frames got past the limiter (they failed dispatch loud and each
    # incremented the ledger ONCE); the remaining flood-budget were shed at the limiter.
    assert len(seen_poison) == budget
    # The ledger was touched at most ``budget`` times — NEVER grown past the DoS budget.
    assert len(store.increment_calls) == budget
    assert len(store.attempt_count_calls) == budget
    # The shed frames drained as budget-capped drops (sec C-1) — they are not poison.
    capped = audit.rows_with_schema("COMMS_INBOUND_BUDGET_CAPPED_FIELDS")
    assert len(capped) == flood - budget
    assert audit.rows_with_schema("COMMS_INBOUND_POISONED_FIELDS") == []


# --------------------------------------------------------------------------- #
# 3 — Deliberate shed is NOT poison (item 4): budget-cap + burst-drop both drain
#     single-shot and leave the ledger byte-for-byte UNTOUCHED; replay never poisons.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "arm",
    [
        pytest.param("budget_cap", id="budget_cap"),
        pytest.param("burst_drop", id="burst_drop"),
    ],
)
async def test_deliberate_shed_drains_single_shot_ledger_untouched(arm: str) -> None:
    """A budget-capped / burst-dropped frame drains single-shot — the ledger never GROWS.

    Property proven (item 4): a DELIBERATE shed is not a post-extract failure, so it is
    NEVER ceilinged — the load-bearing invariant is that NO shed ever calls ``increment``
    (the only ledger GROWTH op), so re-shedding can never accumulate toward the poison
    ceiling. The two shed arms sit on opposite sides of the ceiling READ, which the bound
    deliberately places AFTER the pre-resolution DoS limiter but BEFORE resolution/extract:

    * budget_cap (pre-resolution) is shed BEFORE the ceiling read → the ledger is
      byte-for-byte UNTOUCHED (no ``attempt_count``, no ``increment``);
    * burst_drop (post-resolution, pre-extract) is shed AFTER the harmless read-only
      ``attempt_count`` probe but BEFORE the extract — so it reads the count (read-only,
      no growth) yet NEVER ``increment``\\s.

    Replaying the SAME shed frame several times never produces a ``poisoned`` row (a shed
    frame is not poison, and no shed grows the ledger).
    """
    from datetime import UTC, datetime

    from alfred.orchestrator.burst_limiter import Dropped

    store = _InMemoryAttemptStore()
    tracker = _SpyAckTracker()
    audit = SpyAuditWriter()

    if arm == "budget_cap":
        # An already-exhausted pre-resolution budget sheds before the ledger read.
        limiter = _PreResolutionLimiter(limit_per_minute=0)
        collab = _collaborators(pre_resolution_limiter=limiter)
    else:
        # burst-drop: an admitting pre-resolution limiter, but a burst limiter that
        # returns ``Dropped`` (the bucket emptied) — drops after resolution, before extract.
        # ``_ForwardedCollaborators`` is frozen+slots, so build it directly with the drop
        # limiter rather than mutating a field after construction.
        dropping_burst = SpyBurstLimiter(
            result=Dropped(waited_seconds=0.0, bucket_empty_since=datetime.now(UTC))
        )
        collab = _ForwardedCollaborators(
            sub_payload_promoter=None,  # type: ignore[arg-type]
            resolver_bridge=SpyIdentityResolver(returns=make_resolved(adapter_id=_ADAPTER_ID)),
            orchestrator=SpyOrchestrator(),
            burst_limiter=dropping_burst,
            secret_broker=SpySecretBroker(),
            pre_resolution_limiter=_PreResolutionLimiter(),
        )

    receiver = _build_receiver(
        audit_writer=audit,
        attempt_store=store,
        ack_tracker=tracker,
        registry={_ADAPTER_ID: collab},
    )
    body = _body(inbound_id="deliberate-shed")

    # Replay the SAME shed frame several times — each drains single-shot.
    for seq in range(3):
        await receiver.receive(params=_envelope_params(body=body), wire_seq=seq)

    # The ledger never GREW — a deliberate shed never ``increment``\\s (the only growth op),
    # so re-shedding can never accumulate toward the ceiling.
    assert store.increment_calls == []
    # Each replay drained its own seq (the gateway high-water advances, no wedge).
    assert tracker.observed == [0, 1, 2]
    # No frame ever poisoned, regardless of how often it was re-shed.
    assert audit.rows_with_schema("COMMS_INBOUND_POISONED_FIELDS") == []
    if arm == "burst_drop":
        # burst_drop is shed AFTER the harmless read-only ceiling probe but BEFORE extract,
        # so it reads ``attempt_count`` (read-only — never grows the ledger).
        assert store.attempt_count_calls == [(_ADAPTER_ID, "deliberate-shed")] * 3
        # The burst-drop arm wrote the forwarded-path burst_dropped rows (one per replay).
        burst_rows = [
            r
            for r in audit.rows_with_schema("COMMS_INBOUND_BUDGET_CAPPED_FIELDS")
            if r["event"] == "comms.inbound.burst_dropped"
        ]
        assert len(burst_rows) == 3
    else:
        # budget_cap is shed BEFORE the ceiling read — the ledger is byte-for-byte untouched.
        assert store.attempt_count_calls == []
        capped = audit.rows_with_schema("COMMS_INBOUND_BUDGET_CAPPED_FIELDS")
        assert len(capped) == 3


# --------------------------------------------------------------------------- #
# 4 — receive_fault is NOT ceilinged (item 5): an off-vocab envelope drains on
#     the FIRST occurrence and never touches the attempt store.
# --------------------------------------------------------------------------- #


async def test_receive_fault_is_not_ceilinged_and_never_touches_ledger() -> None:
    """An off-vocab envelope is a single-shot receive_fault drop — never poison.

    Property proven (item 5): the ADMISSION region (K4 / re-parse / receive_fault) is
    NEVER ceilinged — admission drops drain single-shot. An off-vocab envelope
    ``adapter_id`` fails the closed ``AdapterId`` validator inside ``model_validate``,
    becomes a ``receive_fault`` terminal drop on the FIRST occurrence (the dispatch
    pipeline — and the attempt store with it — is never reached), and replaying it never
    produces a ``poisoned`` row nor touches the ledger.
    """
    store = _InMemoryAttemptStore()
    tracker = _SpyAckTracker()
    audit = SpyAuditWriter()
    receiver = _build_receiver(audit_writer=audit, attempt_store=store, ack_tracker=tracker)

    # An off-vocab kind that fails the AdapterId validator → receive_fault. Replay it.
    for seq in range(3):
        await receiver.receive(
            params={"adapter_id": "forged-off-vocab-kind", "body": "never-parsed"},
            wire_seq=seq,
        )

    rows = audit.rows_with_schema("COMMS_FORWARDED_INBOUND_DROPPED_FIELDS")
    assert len(rows) == 3
    assert all(r["reason"] == "receive_fault" for r in rows)
    # The dispatch pipeline (and the ledger) was NEVER reached — admission drops single-shot.
    assert store.attempt_count_calls == []
    assert store.increment_calls == []
    # No poison row EVER — a receive_fault is not a post-extract failure.
    assert audit.rows_with_schema("COMMS_INBOUND_POISONED_FIELDS") == []
    # Each occurrence drained its own seq (no wedge).
    assert tracker.observed == [0, 1, 2]


# --------------------------------------------------------------------------- #
# 5 — poison-then-receive_fault interleave: a frame fails dispatch k<N times
#     (ledger at k), then surfaces as a receive_fault drop → single-shot, no
#     double-count, no cross-path poison.
# --------------------------------------------------------------------------- #


async def test_poison_then_receive_fault_interleave_no_double_count() -> None:
    """A frame that fails dispatch k<N times then surfaces malformed drops single-shot.

    Property proven: the dispatch (ceilinged) path and the admission (single-shot) path
    are distinct. A frame whose dispatched replays fail k<N times leaves the ledger at k;
    if a LATER replay surfaces as an admission-region drop (here a malformed body — the
    same inbound re-delivered with a corrupted body) it drains single-shot via the
    admission path WITHOUT incrementing the ledger again (no double-count) and without
    ever emitting a poison row (the two paths never cross-contaminate).
    """
    k = _CEILING - 2
    store = _InMemoryAttemptStore()
    tracker = _SpyAckTracker()
    audit = SpyAuditWriter()
    orch = _AlwaysFailOrchestrator()
    receiver = _build_receiver(
        audit_writer=audit, attempt_store=store, ack_tracker=tracker, orchestrator=orch
    )
    good_body = _body(inbound_id="interleave-frame")

    # k dispatched replays, each fails LOUD and increments the ledger to k.
    for seq in range(k):
        with pytest.raises(RuntimeError, match="poison frame"):
            await receiver.receive(params=_envelope_params(body=good_body), wire_seq=seq)
    assert store.count(adapter_id=_ADAPTER_ID, inbound_id="interleave-frame") == k

    # The NEXT replay surfaces with a malformed (non-JSON) body → admission-region drop.
    await receiver.receive(params=_envelope_params(body="{not-valid-json"), wire_seq=k)

    # The malformed drop drained single-shot via the admission path: the ledger is STILL
    # at k (no double-count), and the admission drop is a body_malformed row, not poison.
    assert store.count(adapter_id=_ADAPTER_ID, inbound_id="interleave-frame") == k
    assert len(store.increment_calls) == k  # only the k dispatched failures incremented
    drop_rows = audit.rows_with_schema("COMMS_FORWARDED_INBOUND_DROPPED_FIELDS")
    assert len(drop_rows) == 1
    assert drop_rows[0]["reason"] == "body_malformed"
    assert audit.rows_with_schema("COMMS_INBOUND_POISONED_FIELDS") == []
    assert tracker.observed == [k]  # the malformed replay drained its own seq


# --------------------------------------------------------------------------- #
# 6 — Cross-adapter isolation (composite key): a "discord" frame failing dispatch
#     never advances the "tui" counter.
# --------------------------------------------------------------------------- #


async def test_cross_adapter_isolation_composite_key() -> None:
    """A failing adapter-A frame never advances adapter-B's counter (composite key).

    Property proven: the ledger key is the COMPOSITE ``(adapter_id, inbound_id)``, so each
    adapter's free-form ``inbound_id`` namespace is isolated — load-bearing because K4
    admission mints ``adapter_id`` from the un-forgeable spawn binding, so one adapter
    cannot poison or reset another adapter's counter by colliding on a shared
    ``inbound_id``. Here two REGISTERED adapters (both empty-required-classifier kinds, so
    the real pipeline runs plain-text) share the SAME ``inbound_id`` and the SAME real
    ledger; ``alfred_comms_test``'s dispatch always fails, ``tui``'s succeeds — the
    ``tui`` namespace is untouched by the other's failures. Proven at the ledger keys.
    """
    adapter_a = _ADAPTER_ID  # alfred_comms_test — empty classifier set, dispatch fails
    adapter_b = "tui"  # also empty classifier set, dispatch succeeds
    shared_inbound_id = "collision-id"
    store = _InMemoryAttemptStore()
    audit = SpyAuditWriter()
    registry = {
        adapter_a: _ForwardedCollaborators(
            sub_payload_promoter=None,  # type: ignore[arg-type]
            resolver_bridge=SpyIdentityResolver(returns=make_resolved(adapter_id=adapter_a)),
            orchestrator=_AlwaysFailOrchestrator(),
            burst_limiter=SpyBurstLimiter(),
            secret_broker=SpySecretBroker(),
            pre_resolution_limiter=_PreResolutionLimiter(),
        ),
        adapter_b: _ForwardedCollaborators(
            sub_payload_promoter=None,  # type: ignore[arg-type]
            resolver_bridge=SpyIdentityResolver(returns=make_resolved(adapter_id=adapter_b)),
            orchestrator=SpyOrchestrator(),
            burst_limiter=SpyBurstLimiter(),
            secret_broker=SpySecretBroker(),
            pre_resolution_limiter=_PreResolutionLimiter(),
        ),
    }
    receiver = _build_receiver(
        audit_writer=audit,
        attempt_store=store,
        ack_tracker=_SpyAckTracker(),
        registry=registry,
    )

    # adapter_a fails dispatch ``_CEILING`` times → its counter climbs to _CEILING.
    a_body = _body(adapter_id=adapter_a, inbound_id=shared_inbound_id)
    for seq in range(_CEILING):
        with pytest.raises(RuntimeError, match="poison frame"):
            await receiver.receive(
                params=_envelope_params(adapter_id=adapter_a, body=a_body), wire_seq=seq
            )

    # A single SUCCESSFUL adapter_b frame with the SAME inbound_id dispatches cleanly.
    b_body = _body(adapter_id=adapter_b, inbound_id=shared_inbound_id)
    await receiver.receive(params=_envelope_params(adapter_id=adapter_b, body=b_body), wire_seq=100)

    # The composite key isolates the two namespaces: adapter_a's counter climbed; adapter_b
    # is untouched by adapter_a's failures (a successful dispatch increments once on entry
    # to the post-extract region, then succeeds — so adapter_b's count is exactly 1).
    assert store.count(adapter_id=adapter_a, inbound_id=shared_inbound_id) == _CEILING
    assert store.count(adapter_id=adapter_b, inbound_id=shared_inbound_id) == 1
    # No cross-contamination: adapter_a never advanced adapter_b's counter past its own entry.
    assert store.count(adapter_id=adapter_b, inbound_id=shared_inbound_id) != _CEILING


# --------------------------------------------------------------------------- #
# 7 — Concurrent replay at ceiling (sec H3, "at least N"): two concurrent copies
#     of an at-ceiling frame → >=1 poisoned row, idempotent observe, never dispatched.
# --------------------------------------------------------------------------- #


async def test_concurrent_replay_at_ceiling_at_least_once_idempotent() -> None:
    """Two concurrent copies of an at-ceiling frame: >=1 poisoned row, idempotent observe.

    Property proven (sec H3, the at-least-once race ADR-0039 item 4 accepts): when the
    ledger is ALREADY at the ceiling, two concurrent copies of the same poison frame both
    read ``attempts >= N`` → at least one (here both) dead-letter, never dispatch, and the
    drain ``observe`` is IDEMPOTENT — a real ``BoundedSeqAckTracker`` advances the
    contiguous high-water once-effectively no matter how many times the SAME poison seq is
    observed. The invariant under concurrency: NO dispatch, the high-water advances exactly
    once-effectively, and at least one signed dead-letter is written.
    """
    store = _InMemoryAttemptStore()
    # Arm the ledger AT the ceiling so the READ short-circuits to poisoned for both copies.
    for _ in range(_CEILING):
        await store.increment(adapter_id=_ADAPTER_ID, inbound_id="concurrent-poison")
    tracker = BoundedSeqAckTracker()
    audit = SpyAuditWriter()
    orch = _AlwaysFailOrchestrator()
    receiver = _build_receiver(
        audit_writer=audit, attempt_store=store, ack_tracker=tracker, orchestrator=orch
    )
    body = _body(inbound_id="concurrent-poison")

    # Seed the healthy contiguous prefix 0..6 (already-drained tail) so the high-water sits
    # at 6 — the poison frame rides seq 7, the next contiguous step. The ``BoundedSeqAckTracker``
    # advances over an unbroken 0.. run, so a lone seq-7 with a gap below would NOT advance;
    # the realistic resume scenario is a contiguous tail with the poison at its head.
    for s in range(7):
        tracker.observe(s)
    assert tracker.cumulative_ack() == 6  # wedged at 6 until seq 7 drains

    # Two CONCURRENT copies of the at-ceiling frame on the SAME poison seq (7).
    await asyncio.gather(
        receiver.receive(params=_envelope_params(body=body), wire_seq=7),
        receiver.receive(params=_envelope_params(body=body), wire_seq=7),
    )

    # NEVER dispatched (both short-circuited at the poison READ before extract/dispatch).
    assert orch.dispatch_calls == 0
    assert orch.quarantined_extract_calls == 0
    # At least one signed dead-letter row (the at-least-once contract — here both copies).
    poisoned = audit.rows_with_schema("COMMS_INBOUND_POISONED_FIELDS")
    assert len(poisoned) >= 1
    # The high-water advanced ONCE-EFFECTIVELY despite the duplicate observe (idempotent).
    assert tracker.cumulative_ack() == 7


# --------------------------------------------------------------------------- #
# 8 — Canary absence (sec-010): a high-entropy secret in the T3 body AND a
#     high-entropy inbound_id never appear (raw) on the poisoned row or any log.
# --------------------------------------------------------------------------- #


async def test_poisoned_row_no_t3_or_inbound_id_leak() -> None:
    """The dead-letter row leaks neither the T3 body secret nor the raw inbound_id.

    Property proven (sec-010 / spec §3.3): the terminal ``comms.inbound.poisoned`` row is
    content-free. A high-entropy secret embedded in the T3 body AND a high-entropy
    ``inbound_id`` MUST NOT appear (raw) on ANY field of the signed row NOR on ANY captured
    structlog record — only the PEPPERED hash of the ``inbound_id`` (which equals neither
    the raw id nor the canary). Mirrors the G6-7-4 canary-absence test.
    """
    secret_inbound_id = f"inbound-{_CANARY}"
    store = _InMemoryAttemptStore()
    # Arm the ledger at the ceiling so the next delivery short-circuits to poisoned.
    for _ in range(_CEILING):
        await store.increment(adapter_id=_ADAPTER_ID, inbound_id=secret_inbound_id)
    tracker = _SpyAckTracker()
    audit = SpyAuditWriter()
    receiver = _build_receiver(audit_writer=audit, attempt_store=store, ack_tracker=tracker)
    # The body carries the canary as T3 content; the inbound_id carries it too.
    body = _body(inbound_id=secret_inbound_id, content=f"secret {_CANARY} payload")

    with structlog.testing.capture_logs() as logs:
        await receiver.receive(params=_envelope_params(body=body), wire_seq=42)

    rows = audit.rows_with_schema("COMMS_INBOUND_POISONED_FIELDS")
    assert len(rows) == 1
    row = rows[0]
    # The row carries the PEPPERED hash of the inbound_id — never the raw id / canary.
    assert row["inbound_id_hash"] == audit_hash.hash_inbound_id(secret_inbound_id)
    assert row["trace_id"] == audit_hash.hash_inbound_id(secret_inbound_id)
    assert row["trust_tier_of_trigger"] == "T3"
    # CANARY-ABSENCE: no fragment of the canary on ANY field of ANY signed audit row...
    for audit_row in audit.schema_rows:
        assert _CANARY not in str(audit_row)
        assert "CANARY" not in str(audit_row)
    # ...nor on ANY captured structlog line (the content-free dead-letter only).
    for entry in logs:
        assert _CANARY not in str(entry)
        assert "CANARY" not in str(entry)
    assert tracker.observed == [42]  # drained
