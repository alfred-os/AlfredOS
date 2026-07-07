"""EgressIdempotencyStore against real Postgres: tri-state intent, integrity, TTL.

The tri-state ledger (Spec C §5, G7-2a) is the at-most-once guard for
side-effecting tool egress. Its race-free ``INSERT … ON CONFLICT (egress_id) DO
NOTHING RETURNING`` semantics and the commit-then-fire / replay contract can only
be proven against a real Postgres — SQLite cannot express the
exactly-one-winner-under-concurrency property. This testcontainers suite migrates
to head (incl. 0023) and exercises the full DAO contract:

* fresh commit -> ``committed_no_response`` intent (IntentFresh);
* record_response -> ``committed_with_response``;
* duplicate same-hash + recorded -> IntentReplayComplete(stored T2, language);
* duplicate same-hash + not-yet-recorded -> IntentInDoubt;
* duplicate DIFFERENT-hash -> EgressIdIntegrityError (a non-deterministic re-run);
* 8 concurrent commits on the same id -> exactly one IntentFresh winner;
* record_response is idempotent on an already-recorded row (MEM-3);
* record_response on an unknown id fails loud;
* prune_expired sweeps a back-dated row (the TTL retention path).
"""

from __future__ import annotations

import asyncio
import datetime as dt
from collections.abc import AsyncIterator

import pytest
import sqlalchemy as sa
from alembic import command, config
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from alfred.egress.egress_id import EgressIdIntegrityError
from alfred.memory.db import session_scope
from alfred.memory.egress_idempotency import (
    EgressLedgerStateError,
    IntentFresh,
    IntentInDoubt,
    IntentReplayComplete,
    PostgresEgressIdempotencyStore,
)

pytestmark = pytest.mark.integration

_HASH_A = "a" * 64
_HASH_B = "b" * 64


@pytest.fixture
def migrated_url(postgres_url: str, monkeypatch: pytest.MonkeyPatch) -> str:
    monkeypatch.setenv("ALFRED_DATABASE_URL", postgres_url)
    cfg = config.Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", postgres_url)
    command.upgrade(cfg, "head")  # head includes 0023
    return postgres_url


@pytest.fixture
async def store(migrated_url: str) -> AsyncIterator[PostgresEgressIdempotencyStore]:
    engine = create_async_engine(migrated_url, future=True)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        yield PostgresEgressIdempotencyStore(session_scope=lambda: session_scope(factory))
    finally:
        await engine.dispose()


async def _commit(
    store: PostgresEgressIdempotencyStore,
    *,
    egress_id: str,
    body_hash: str = _HASH_A,
    call_index: int = 0,
) -> IntentFresh | IntentReplayComplete | IntentInDoubt:
    return await store.commit_intent(
        egress_id=egress_id,
        adapter_id="discord",
        inbound_id="msg-1",
        session_id="sess-1",
        call_index=call_index,
        body_hash=body_hash,
    )


async def _state_of(migrated_url: str, egress_id: str) -> str | None:
    engine = create_async_engine(migrated_url, future=True)
    try:
        async with engine.connect() as conn:
            return await conn.scalar(
                sa.text("SELECT state FROM egress_idempotency WHERE egress_id = :e"),
                {"e": egress_id},
            )
    finally:
        await engine.dispose()


async def test_fresh_commit_creates_no_response_intent(
    store: PostgresEgressIdempotencyStore, migrated_url: str
) -> None:
    result = await _commit(store, egress_id="eg-fresh")
    assert isinstance(result, IntentFresh)
    assert await _state_of(migrated_url, "eg-fresh") == "committed_no_response"


async def test_record_response_transitions_to_with_response(
    store: PostgresEgressIdempotencyStore, migrated_url: str
) -> None:
    await _commit(store, egress_id="eg-rec")
    await store.record_response(egress_id="eg-rec", response="extracted-t2", language="en")
    assert await _state_of(migrated_url, "eg-rec") == "committed_with_response"


async def test_duplicate_recorded_replays_stored_t2(
    store: PostgresEgressIdempotencyStore,
) -> None:
    await _commit(store, egress_id="eg-replay")
    await store.record_response(egress_id="eg-replay", response="the-t2", language="fr")
    again = await _commit(store, egress_id="eg-replay")
    assert isinstance(again, IntentReplayComplete)
    assert again.response == "the-t2"
    assert again.language == "fr"


async def test_duplicate_before_response_is_in_doubt(
    store: PostgresEgressIdempotencyStore,
) -> None:
    await _commit(store, egress_id="eg-doubt")
    again = await _commit(store, egress_id="eg-doubt")
    assert isinstance(again, IntentInDoubt)


async def test_duplicate_different_hash_raises_integrity(
    store: PostgresEgressIdempotencyStore,
) -> None:
    await _commit(store, egress_id="eg-int", body_hash=_HASH_A)
    with pytest.raises(EgressIdIntegrityError):
        await _commit(store, egress_id="eg-int", body_hash=_HASH_B)


async def test_concurrent_commits_exactly_one_fresh(
    store: PostgresEgressIdempotencyStore,
) -> None:
    # The single-statement INSERT … ON CONFLICT DO NOTHING RETURNING is race-free,
    # and ON CONFLICT blocks the loser until the winner commits — so the loser's
    # subsequent SELECT sees the committed_no_response row (IntentInDoubt).
    results = await asyncio.gather(*(_commit(store, egress_id="eg-race") for _ in range(8)))
    assert sum(isinstance(r, IntentFresh) for r in results) == 1
    assert sum(isinstance(r, IntentInDoubt) for r in results) == 7


async def test_record_response_idempotent_on_already_recorded(
    store: PostgresEgressIdempotencyStore, migrated_url: str
) -> None:
    # MEM-3: a second record_response on an already-committed_with_response row is
    # a no-op, not a raise (a Spec-A replay can re-enter this path) — AND it must not
    # overwrite the stored payload (the egress-id pins one logical call to one T2).
    await _commit(store, egress_id="eg-idem")
    await store.record_response(egress_id="eg-idem", response="first", language="en")
    await store.record_response(egress_id="eg-idem", response="second", language="fr")
    assert await _state_of(migrated_url, "eg-idem") == "committed_with_response"
    # The replay returns the FIRST stored response/language — the second call dropped.
    replay = await _commit(store, egress_id="eg-idem")
    assert isinstance(replay, IntentReplayComplete)
    assert replay.response == "first"
    assert replay.language == "en"


async def test_record_response_unknown_id_raises(
    store: PostgresEgressIdempotencyStore,
) -> None:
    with pytest.raises(EgressLedgerStateError):
        await store.record_response(egress_id="eg-nonexistent", response="x", language="en")


async def test_prune_expired_sweeps_only_backdated_rows(
    store: PostgresEgressIdempotencyStore, migrated_url: str
) -> None:
    # Prove prune respects the committed_at cutoff (not "delete everything"): one row is
    # backdated past the window, one stays fresh, and a cutoff between them removes ONLY
    # the stale row. Backdate via a direct UPDATE since committed_at is server-defaulted.
    await _commit(store, egress_id="eg-stale")
    await _commit(store, egress_id="eg-fresh")
    engine = create_async_engine(migrated_url, future=True)
    try:
        async with engine.begin() as conn:
            await conn.execute(
                sa.text(
                    "UPDATE egress_idempotency SET committed_at = now() - interval '10 days' "
                    "WHERE egress_id = 'eg-stale'"
                )
            )
    finally:
        await engine.dispose()
    cutoff = dt.datetime.now(dt.UTC) - dt.timedelta(days=1)
    deleted = await store.prune_expired(older_than=cutoff)
    assert deleted == 1
    assert await _state_of(migrated_url, "eg-stale") is None
    assert await _state_of(migrated_url, "eg-fresh") == "committed_no_response"


async def test_prune_expired_returns_zero_when_nothing_expired(
    store: PostgresEgressIdempotencyStore, migrated_url: str
) -> None:
    # The no-op path: a cutoff in the past matches no row, so prune returns 0 and the
    # fresh row survives — proving the count contract, not just the delete-1 case.
    await _commit(store, egress_id="eg-young")
    past = dt.datetime.now(dt.UTC) - dt.timedelta(days=1)
    assert await store.prune_expired(older_than=past) == 0
    assert await _state_of(migrated_url, "eg-young") == "committed_no_response"


async def test_get_state_reflects_ledger_lifecycle(store: PostgresEgressIdempotencyStore) -> None:
    # A pure read of the ledger's tri-state lifecycle (#347 blocker 2's post-timeout
    # audit path): no row -> None, fresh commit -> committed_no_response (the
    # in-doubt state), record_response -> committed_with_response. Unlike
    # commit_intent, get_state never inserts and cannot re-fire a side effect.
    egress_id = "a" * 64
    assert await store.get_state(egress_id=egress_id) is None
    result = await _commit(store, egress_id=egress_id)
    assert isinstance(result, IntentFresh)
    assert await store.get_state(egress_id=egress_id) == "committed_no_response"
    await store.record_response(egress_id=egress_id, response="ok", language="en")
    assert await store.get_state(egress_id=egress_id) == "committed_with_response"


async def test_check_constraint_rejects_no_response_row_with_a_response(
    migrated_url: str,
) -> None:
    # The state<->response invariant is what justifies the DAO casting row.response to
    # str on the committed_with_response branch. Prove Postgres ENFORCES it (not just
    # that the constraint exists by name): a committed_no_response row carrying a
    # non-NULL response must be rejected at write time.
    engine = create_async_engine(migrated_url, future=True)
    try:
        # connect() (not begin()) so the immediate CHECK violation surfaces on execute
        # and no commit is attempted on the aborted transaction. pytest.raises is a SYNC
        # context manager wrapping the single await.
        async with engine.connect() as conn:
            with pytest.raises(sa.exc.IntegrityError):
                await conn.execute(
                    sa.text(
                        "INSERT INTO egress_idempotency "
                        "(egress_id, adapter_id, inbound_id, session_id, call_index, "
                        "body_hash, state, response) "
                        "VALUES ('eg-bad', 'discord', 'msg-1', 'sess-1', 0, :h, "
                        "'committed_no_response', 'leaked-t2')"
                    ),
                    {"h": _HASH_A},
                )
    finally:
        await engine.dispose()
