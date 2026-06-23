"""Integration: the N=5 forwarded poison ceiling COMPOSED with real Postgres (G6-7-6).

**Threat model** (ADR-0039 item 4b / #309 / §3.3). The ``alfred-gateway`` forwards a
hosted adapter child's ``inbound.message`` to the connectivity-free CORE on the
DISPATCHED edge (``commit_at_dispatch_edge=True``): a dispatch failure deliberately
leaves the frame NOT committed / NOT observed so the forwarding leg replays it. A POISON
frame whose post-extract region ALWAYS fails would re-charge the quarantined extractor on
every reconnect forever (PERF-309-1) without the ceiling. G6-7-5 landed the ceiling and
proved it three ways:

* the unit suite (``tests/unit/comms/test_inbound_poison_ceiling.py``) pins the branch;
* the store-primitive integration tests pin each Postgres store IN ISOLATION;
* the adversarial suite (``tests/adversarial/comms/test_forwarded_inbound_poison.py``)
  drives the attacker's property end-to-end — but over IN-MEMORY fakes for both stores.

NONE of those proves the COMPOSITION through the real receiver + the real
``process_inbound_message(commit_at_dispatch_edge=True)`` + the real
``PostgresForwardedDispatchAttemptStore`` + the real ``PostgresInboundIdempotencyStore`` +
the real Postgres ``AuditWriter``. THIS test is the G6-7-6 A2 closer: it lifts the
adversarial poison-e2e harness (``test_poison_e2e_dead_letters_and_releases_stalled_high_water``)
and swaps the in-memory fakes for the REAL durable Postgres stores, so the bound is shown
to hold against the genuine atomic-upsert ledger, the genuine commit-once idempotency
store, and a genuine signed ``audit_log`` row read back over SQL.

The reference adapter kind is the plain-text ``alfred_comms_test`` (EMPTY required-classifier
set → a ``None`` promoter is correct and the real plain-text pipeline runs with no M2 trip).
A2 proves the LEDGER composition, NOT the discord sub-payload promotion (that is a sibling
test's job).

Needs Docker (a Postgres testcontainer via the integration ``postgres_url`` fixture). The
ONLY non-production seam is ``_AlwaysFailOrchestrator.dispatch`` raising on the post-extract
tail — extract + ingest SUCCEED, so ``orch.quarantined_extract_calls == N`` proves the
extractor really ran the ceiling's worth of times before the bound short-circuited it.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager

import pytest
from sqlalchemy import Engine, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from alfred.audit.log import AuditWriter
from alfred.comms_mcp import audit_hash
from alfred.comms_mcp.forwarded_inbound_receiver import GatewayForwardedInboundReceiver
from alfred.comms_mcp.inbound import _FORWARDED_DISPATCH_ATTEMPT_CEILING
from alfred.gateway._seq_tracker import BoundedSeqAckTracker
from alfred.memory.forwarded_dispatch_attempts import PostgresForwardedDispatchAttemptStore
from alfred.memory.inbound_idempotency import PostgresInboundIdempotencyStore
from alfred.memory.models import Base

# Lift the adversarial poison harness verbatim — the SAME shared spies, the SAME local
# always-fail orchestrator (dispatch raises on the post-extract tail), and the SAME
# ``_collaborators`` / ``_body`` / ``_envelope_params`` helpers — so the ONLY difference
# between this composition and the adversarial proof is real-Postgres-vs-in-memory stores.
from tests.adversarial.comms.test_forwarded_inbound_poison import (
    _ADAPTER_ID,
    _AlwaysFailOrchestrator,
    _body,
    _collaborators,
    _envelope_params,
)

pytestmark = pytest.mark.integration

# A discriminating inbound id so a content-free-leak regression surfaces as a raw id on
# the signed row rather than passing by luck.
_INBOUND_ID = "poison-compose-001"

# The ceiling under test (5). Bound to the production constant so a config change can never
# silently weaken this composition bound without re-surfacing here.
_CEILING = _FORWARDED_DISPATCH_ATTEMPT_CEILING

# ``_body``'s default content string — asserted ABSENT from the signed poison row (sec-004:
# the dead-letter row is content-free; the T3 body never lands on it).
_BODY_CONTENT = "hello there"


@pytest.fixture(autouse=True)
def _reset_audit_hash() -> Iterator[None]:
    """Isolate the module-level comms audit-hash broker/subkey between tests."""
    audit_hash.reset_for_test()
    yield
    audit_hash.reset_for_test()


@asynccontextmanager
async def _real_stores(
    postgres_url: str,
) -> AsyncIterator[
    tuple[
        PostgresForwardedDispatchAttemptStore,
        PostgresInboundIdempotencyStore,
        AuditWriter,
    ]
]:
    """Create the schema and yield the three REAL Postgres stores.

    All three share ONE ``session_scope`` (one transaction-per-call ``async with`` over a
    shared ``async_sessionmaker``) — exactly the "pre-built durable writer injected from
    the boot graph" shape the daemon wires. A test reads the signed ``audit_log`` row back
    over the conftest's ``postgres_engine`` (a disposed sync ``Engine`` on the same
    container).
    """
    engine = create_async_engine(postgres_url, future=True)
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        sm = async_sessionmaker(bind=engine, expire_on_commit=False)

        @asynccontextmanager
        async def session_scope() -> AsyncIterator[AsyncSession]:
            async with sm() as session, session.begin():
                yield session

        attempt_store = PostgresForwardedDispatchAttemptStore(session_scope=session_scope)
        idem_store = PostgresInboundIdempotencyStore(session_scope=session_scope)
        yield attempt_store, idem_store, AuditWriter(session_factory=session_scope)
    finally:
        await engine.dispose()


def _fetch_audit_rows(sync_engine: Engine, *, event: str) -> list[dict[str, object]]:
    """Return every ``audit_log`` row for ``event`` (subject + trace_id + result).

    ``subject`` is the JSON column carrying the poison row's content-free payload
    (``adapter_id``, the PEPPERED ``inbound_id_hash``, ``attempt_count``, ``observed_at``).
    There is NO raw-body column — the read mirrors ``_fetch_t3_promotion_rows``.
    """
    with sync_engine.connect() as conn:
        result = conn.execute(
            text("SELECT subject, trace_id, result, event FROM audit_log WHERE event = :event"),
            {"event": event},
        )
        return [dict(row._mapping) for row in result]


async def test_poison_ceiling_bounds_extract_to_N_against_real_postgres(  # noqa: N802 -- the N is the ceiling, load-bearing emphasis
    postgres_url: str,
    postgres_engine: Engine,
) -> None:
    """A deterministically-failing forwarded frame is ceilinged against REAL Postgres.

    Property proven (the adversarial poison-e2e, now composed with the durable stores): a
    poison frame whose dispatch ALWAYS raises charges ``quarantined_extract`` EXACTLY ``N``
    times across ``N+1`` replays sharing ONE real ``PostgresForwardedDispatchAttemptStore``;
    the (N+1)-th replay reads ``attempt_count >= N`` and short-circuits to a single
    content-free ``comms.inbound.poisoned`` dead-letter row (a genuine signed ``audit_log``
    row, read back over SQL) + a single drain ``observe(poison_seq)`` that RELEASES the
    stalled contiguous high-water of a REAL ``BoundedSeqAckTracker``. The poison row leaks
    neither the raw ``inbound_id`` nor the T3 body (sec-004), and the G0 idempotency store
    was NEVER committed on the poison path (sec-007).
    """
    async with _real_stores(postgres_url) as (attempt_store, idem_store, audit):
        orch = _AlwaysFailOrchestrator()
        tracker = BoundedSeqAckTracker()
        receiver = GatewayForwardedInboundReceiver(
            registry={_ADAPTER_ID: _collaborators(orchestrator=orch)},
            idempotency_store=idem_store,
            attempt_store=attempt_store,
            audit_writer=audit,
        )
        receiver.set_ack_tracker(tracker)
        params = _envelope_params(body=_body(inbound_id=_INBOUND_ID))

        # The poison frame rides leg seq 1; seq 0 is a healthy frame that already drained,
        # so the contiguous high-water sits at 0 and is WEDGED at the gap (1) the poison
        # frame leaves un-observed on every failing replay.
        tracker.observe(0)
        assert tracker.cumulative_ack() == 0

        # The first N replays each fail dispatch LOUD (a bare await would throw on delivery
        # #1) → each increments the durable ledger and re-raises. The high-water stays
        # wedged at 0 because the poison seq (1) is never observed.
        for _ in range(_CEILING):
            with pytest.raises(RuntimeError, match="poison frame"):
                await receiver.receive(params=params, wire_seq=1)
            assert tracker.cumulative_ack() == 0  # still wedged — poison seq un-observed

        # The (N+1)-th replay: attempt_count == N >= N → poisoned, NO extract, drain.
        await receiver.receive(params=params, wire_seq=1)

        # The extractor was charged EXACTLY N times across the N+1 deliveries; the
        # (N+1)-th never reached dispatch. Ingest SUCCEEDED on every one of those N
        # replays (only ``_AlwaysFailOrchestrator.dispatch`` raises), so the post-extract
        # tail — promotion → ingest → dispatch — genuinely ran to the dispatch edge each
        # time, not a gate/extractor stub.
        assert orch.quarantined_extract_calls == _CEILING
        assert orch.ingest_calls == _CEILING
        assert orch.dispatch_calls == _CEILING
        # This drive is strictly SEQUENTIAL (one in-flight replay at a time), so the durable
        # ledger holds EXACTLY N: deliveries 1..N each increment on entry to the post-extract
        # region; the (N+1)-th reads ``attempt_count == N``, poisons, and never increments.
        # The production AT-LEAST-N semantics (a concurrent racing replay can only OVER-count,
        # never under-count) are proven by the concurrent-replay adversarial test — here the
        # exact count is the tighter, correct assertion.
        assert (
            await attempt_store.attempt_count(adapter_id=_ADAPTER_ID, inbound_id=_INBOUND_ID)
            == _CEILING
        )

        # Exactly one genuine signed poison row in the real audit_log, with result=poisoned.
        rows = _fetch_audit_rows(postgres_engine, event="comms.inbound.poisoned")
        assert len(rows) == 1, rows
        assert rows[0]["result"] == "poisoned"

        # sec-004 content-free: the row carries the PEPPERED inbound_id hash only — never the
        # raw id nor any T3 body byte. Scan the WHOLE serialized row (subject JSON included).
        row_blob = json.dumps(rows[0], default=str)
        assert _INBOUND_ID not in row_blob
        assert _BODY_CONTENT not in row_blob

        # sec-007: the G0 commit-once store was NEVER committed on the poison path (a poison
        # frame must stay un-committed — only a SUCCESSFUL dispatch commits).
        assert (
            await idem_store.has_committed(adapter_id=_ADAPTER_ID, inbound_id=_INBOUND_ID) is False
        )

        # The drain RELEASED the wedge: the contiguous high-water advanced past the poison seq.
        assert tracker.cumulative_ack() == 1
