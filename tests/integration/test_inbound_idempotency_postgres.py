"""InboundIdempotencyStore against real Postgres: first-wins / replay-noop / concurrent-one.

The genuine ``ON CONFLICT (adapter_id, inbound_id) DO NOTHING RETURNING`` race
semantics can only be proven against a real Postgres — SQLite cannot express the
exactly-one-winner-under-concurrency property. This testcontainers suite migrates
to head (incl. migration 0018) and exercises the store's full contract:

* first-commit-wins;
* replay-is-noop on the SAME composite key;
* exactly-one-winner across 8 CONCURRENT commits on the same key (the race-free
  ``RETURNING`` claim);
* the COMPOSITE key isolates each adapter's id namespace (same id, two adapters,
  both win — the denial-of-delivery the composite key exists to prevent);
* the distinct-id flood drives one ledger row per distinct id (resolved
  open-question: G0 does NOT cap this — the downstream pre-resolution DoS limiter
  caps a per-user flood; the ledger's job is correctness, not rate-limiting).
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator

import pytest
import sqlalchemy as sa
from alembic import command, config
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from alfred.memory.db import session_scope
from alfred.memory.inbound_idempotency import PostgresInboundIdempotencyStore

pytestmark = pytest.mark.integration


@pytest.fixture
def migrated_url(postgres_url: str, monkeypatch: pytest.MonkeyPatch) -> str:
    monkeypatch.setenv("ALFRED_DATABASE_URL", postgres_url)
    cfg = config.Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", postgres_url)
    command.upgrade(cfg, "head")  # head includes 0018
    return postgres_url


@pytest.fixture
async def store(migrated_url: str) -> AsyncIterator[PostgresInboundIdempotencyStore]:
    engine = create_async_engine(migrated_url, future=True)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        yield PostgresInboundIdempotencyStore(session_scope=lambda: session_scope(factory))
    finally:
        await engine.dispose()


async def test_first_commit_wins(store: PostgresInboundIdempotencyStore) -> None:
    assert await store.commit_once(inbound_id="frame-1", adapter_id="tui") is True


async def test_replay_is_noop_duplicate(store: PostgresInboundIdempotencyStore) -> None:
    assert await store.commit_once(inbound_id="frame-2", adapter_id="tui") is True
    assert await store.commit_once(inbound_id="frame-2", adapter_id="tui") is False


async def test_concurrent_commits_exactly_one_winner(
    store: PostgresInboundIdempotencyStore,
) -> None:
    # The same COMPOSITE key under 8 concurrent commits: the single-statement
    # ``INSERT … ON CONFLICT DO NOTHING RETURNING`` is race-free, so exactly one
    # caller sees the RETURNING row (won=True) and the other 7 see no row.
    results = await asyncio.gather(
        *(store.commit_once(inbound_id="frame-3", adapter_id="tui") for _ in range(8))
    )
    assert sum(results) == 1  # exactly one True across 8 concurrent commits


async def test_same_id_different_adapters_both_win(
    store: PostgresInboundIdempotencyStore,
) -> None:
    # The COMPOSITE key isolates each adapter's namespace: the SAME inbound_id
    # under two DIFFERENT adapters is two distinct rows — neither drops the other
    # (the denial-of-delivery the composite key exists to prevent).
    assert await store.commit_once(inbound_id="shared-id", adapter_id="tui") is True
    assert await store.commit_once(inbound_id="shared-id", adapter_id="discord") is True
    # …and each is still individually idempotent on its own adapter.
    assert await store.commit_once(inbound_id="shared-id", adapter_id="tui") is False


async def test_distinct_id_flood_writes_one_row_per_distinct_id(
    store: PostgresInboundIdempotencyStore, migrated_url: str
) -> None:
    # A flood of DISTINCT ids drives one Postgres write per frame (resolved
    # open-question): N distinct ids => N winners (N ledger rows). G0 does NOT
    # cap this — the coarse pre-resolution DoS limiter (downstream, per
    # (adapter_id, platform_user_id_hash)) is what caps a distinct-id flood in
    # the real pipeline; the ledger's job is correctness, not rate-limiting.
    # Documented + a tracked committed_at-based prune follow-up (see plan note).
    results = [
        await store.commit_once(inbound_id=f"flood-{i}", adapter_id="tui") for i in range(50)
    ]
    assert all(results)  # every distinct id is a fresh winner…
    # …and PROVE the N rows actually landed. ``won=True`` alone does not show the
    # row persisted — a broken RETURNING/commit could report a win with no durable
    # row. Count directly against the ledger (per-test container, so the only
    # ``tui`` rows are this flood's). The composite key isolates ``tui`` already.
    engine = create_async_engine(migrated_url, future=True)
    try:
        async with engine.connect() as conn:
            count = await conn.scalar(
                sa.text("SELECT count(*) FROM inbound_idempotency WHERE adapter_id = :a"),
                {"a": "tui"},
            )
    finally:
        await engine.dispose()
    assert count == 50
