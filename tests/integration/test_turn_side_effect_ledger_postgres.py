"""Real-Postgres integration tests for PostgresTurnSideEffectLedger.

Tests the genuine "INSERT ... ON CONFLICT ... WHERE ... RETURNING"
at-most-once property that can only be proven against real Postgres.
SQLite cannot express the serialised-exactly-once-under-concurrency
guarantee. Exercises first-apply, already-applied, isolation,
and concurrent-race semantics.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator

import pytest
from alembic import command, config
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from alfred.memory.db import session_scope
from alfred.memory.turn_side_effects import PostgresTurnSideEffectLedger

pytestmark = pytest.mark.integration

_ADAPTER = "discord"


@pytest.fixture
def migrated_url(postgres_url: str, monkeypatch: pytest.MonkeyPatch) -> str:
    monkeypatch.setenv("ALFRED_DATABASE_URL", postgres_url)
    cfg = config.Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", postgres_url)
    command.upgrade(cfg, "head")  # head includes 0025
    return postgres_url


@pytest.fixture
async def ledger(migrated_url: str) -> AsyncIterator[PostgresTurnSideEffectLedger]:
    engine = create_async_engine(migrated_url, future=True)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        yield PostgresTurnSideEffectLedger(session_scope=lambda: session_scope(factory))
    finally:
        await engine.dispose()


async def test_first_apply_proceeds_each_gate(ledger: PostgresTurnSideEffectLedger) -> None:
    assert await ledger.try_apply_user_turn(adapter_id=_ADAPTER, inbound_id="m1") is True
    assert await ledger.try_apply_assistant_turn(adapter_id=_ADAPTER, inbound_id="m1") is True


async def test_second_apply_skips_each_gate(ledger: PostgresTurnSideEffectLedger) -> None:
    assert await ledger.try_apply_user_turn(adapter_id=_ADAPTER, inbound_id="m2") is True
    assert await ledger.try_apply_user_turn(adapter_id=_ADAPTER, inbound_id="m2") is False
    assert await ledger.try_apply_assistant_turn(adapter_id=_ADAPTER, inbound_id="m2") is True
    assert await ledger.try_apply_assistant_turn(adapter_id=_ADAPTER, inbound_id="m2") is False


async def test_gates_are_independent_columns_on_one_row(
    ledger: PostgresTurnSideEffectLedger,
) -> None:
    # Applying assistant_turn does not pre-empt the OTHER gate on the same row.
    assert await ledger.try_apply_assistant_turn(adapter_id=_ADAPTER, inbound_id="m3") is True
    assert await ledger.try_apply_user_turn(adapter_id=_ADAPTER, inbound_id="m3") is True


async def test_inbound_id_namespaces_are_isolated(
    ledger: PostgresTurnSideEffectLedger,
) -> None:
    assert await ledger.try_apply_user_turn(adapter_id=_ADAPTER, inbound_id="m4") is True
    # Different inbound_id, not skipped.
    assert await ledger.try_apply_user_turn(adapter_id=_ADAPTER, inbound_id="m5") is True


async def test_adapter_id_namespaces_are_isolated_on_the_same_inbound_id(
    ledger: PostgresTurnSideEffectLedger,
) -> None:
    # Two DIFFERENT adapters minting the SAME inbound_id string must not collide.
    assert await ledger.try_apply_user_turn(adapter_id="discord", inbound_id="shared-id") is True
    assert await ledger.try_apply_user_turn(adapter_id="tui", inbound_id="shared-id") is True


async def test_concurrent_first_applies_settle_to_exactly_one_winner(
    ledger: PostgresTurnSideEffectLedger,
) -> None:
    # 8 concurrent try_apply_user_turn calls on ONE key: the atomic UPSERT
    # serialises, so exactly one True and seven False — never two winners.
    results = await asyncio.gather(
        *(ledger.try_apply_user_turn(adapter_id=_ADAPTER, inbound_id="race") for _ in range(8))
    )
    assert sorted(results) == [False] * 7 + [True]
