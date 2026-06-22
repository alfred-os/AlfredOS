"""ForwardedDispatchAttemptStore against real Postgres: monotone / absent-zero / isolation / race.

The genuine ``ON CONFLICT (adapter_id, inbound_id) DO UPDATE … RETURNING`` atomic
increment can only be proven against a real Postgres — SQLite cannot express the
serialised-monotone-count-under-concurrency property. This testcontainers suite
migrates to head (incl. migration 0020) and exercises the store's full contract:

* a fresh key increments 1 → 2 → 3 (monotone);
* ``attempt_count`` reads 0 for an absent key, then the live value after increments;
* the COMPOSITE key isolates each adapter's id namespace (incrementing one
  ``(adapter_id, inbound_id)`` never perturbs a sibling key);
* concurrent increments on one key settle to a correct monotone count (the atomic
  single-statement UPSERT serialises — no lost updates).
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator

import pytest
from alembic import command, config
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from alfred.memory.db import session_scope
from alfred.memory.forwarded_dispatch_attempts import PostgresForwardedDispatchAttemptStore

pytestmark = pytest.mark.integration


@pytest.fixture
def migrated_url(postgres_url: str, monkeypatch: pytest.MonkeyPatch) -> str:
    monkeypatch.setenv("ALFRED_DATABASE_URL", postgres_url)
    cfg = config.Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", postgres_url)
    command.upgrade(cfg, "head")  # head includes 0020
    return postgres_url


@pytest.fixture
async def store(migrated_url: str) -> AsyncIterator[PostgresForwardedDispatchAttemptStore]:
    engine = create_async_engine(migrated_url, future=True)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        yield PostgresForwardedDispatchAttemptStore(session_scope=lambda: session_scope(factory))
    finally:
        await engine.dispose()


async def test_increment_is_monotone_from_absent(
    store: PostgresForwardedDispatchAttemptStore,
) -> None:
    assert await store.increment(adapter_id="discord", inbound_id="m1") == 1
    assert await store.increment(adapter_id="discord", inbound_id="m1") == 2
    assert await store.increment(adapter_id="discord", inbound_id="m1") == 3


async def test_attempt_count_zero_then_tracks_increments(
    store: PostgresForwardedDispatchAttemptStore,
) -> None:
    # Absent key reads 0 (non-mutating — no row arms the counter).
    assert await store.attempt_count(adapter_id="discord", inbound_id="m2") == 0
    assert await store.increment(adapter_id="discord", inbound_id="m2") == 1
    assert await store.attempt_count(adapter_id="discord", inbound_id="m2") == 1
    await store.increment(adapter_id="discord", inbound_id="m2")
    assert await store.attempt_count(adapter_id="discord", inbound_id="m2") == 2


async def test_composite_key_namespaces_are_isolated(
    store: PostgresForwardedDispatchAttemptStore,
) -> None:
    # Incrementing ("discord","m1") must not perturb a different adapter on the
    # SAME inbound_id, nor the same adapter on a different inbound_id.
    await store.increment(adapter_id="discord", inbound_id="m1")
    await store.increment(adapter_id="discord", inbound_id="m1")
    assert await store.attempt_count(adapter_id="discord", inbound_id="m1") == 2
    assert await store.attempt_count(adapter_id="tui", inbound_id="m1") == 0
    assert await store.attempt_count(adapter_id="discord", inbound_id="m2") == 0


async def test_concurrent_increments_settle_monotone(
    store: PostgresForwardedDispatchAttemptStore,
) -> None:
    # 8 concurrent increments on one key: the single-statement atomic UPSERT
    # serialises, so the final count is exactly 8 (no lost updates) and the eight
    # returned counts are precisely {1..8}.
    results = await asyncio.gather(
        *(store.increment(adapter_id="discord", inbound_id="race") for _ in range(8))
    )
    assert sorted(results) == list(range(1, 9))
    assert await store.attempt_count(adapter_id="discord", inbound_id="race") == 8
