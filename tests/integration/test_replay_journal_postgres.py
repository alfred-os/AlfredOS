"""PostgresReplayJournal against real Postgres: append/read ordering + isolation."""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest
from alembic import command, config
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from alfred.memory.db import session_scope
from alfred.memory.replay_journal import JournalEntry, PostgresReplayJournal
from alfred.providers.base import ToolCall

pytestmark = pytest.mark.integration

_ADAPTER = "discord"


@pytest.fixture
def migrated_url(postgres_url: str, monkeypatch: pytest.MonkeyPatch) -> str:
    monkeypatch.setenv("ALFRED_DATABASE_URL", postgres_url)
    cfg = config.Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", postgres_url)
    command.upgrade(cfg, "head")  # head includes 0026
    return postgres_url


@pytest.fixture
async def journal(migrated_url: str) -> AsyncIterator[PostgresReplayJournal]:
    engine = create_async_engine(migrated_url, future=True)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        yield PostgresReplayJournal(session_scope=lambda: session_scope(factory))
    finally:
        await engine.dispose()


async def test_read_empty_for_absent_inbound_id(journal: PostgresReplayJournal) -> None:
    assert await journal.read(adapter_id=_ADAPTER, inbound_id="never-seen") == ()


async def test_append_batch_then_read_round_trips(journal: PostgresReplayJournal) -> None:
    call = ToolCall(id="tc-1", name="web.fetch", arguments={"url": "https://example.invalid"})
    await journal.append_batch(adapter_id=_ADAPTER, inbound_id="m1", iteration=0, calls=[(0, call)])
    entries = await journal.read(adapter_id=_ADAPTER, inbound_id="m1")
    assert entries == (JournalEntry(call_index=0, iteration=0, tool_call=call),)


async def test_append_batch_writes_every_call_of_one_iteration_in_one_call(
    journal: PostgresReplayJournal,
) -> None:
    """The core-001 real-Postgres proof: a multi-call iteration round-trips as ONE batch write."""
    call_a = ToolCall(id="tc-a", name="clock.now", arguments={})
    call_b = ToolCall(id="tc-b", name="clock.now", arguments={})
    await journal.append_batch(
        adapter_id=_ADAPTER, inbound_id="m1b", iteration=0, calls=[(0, call_a), (1, call_b)]
    )
    entries = await journal.read(adapter_id=_ADAPTER, inbound_id="m1b")
    assert entries == (
        JournalEntry(call_index=0, iteration=0, tool_call=call_a),
        JournalEntry(call_index=1, iteration=0, tool_call=call_b),
    )


async def test_read_orders_by_call_index_regardless_of_insert_order(
    journal: PostgresReplayJournal,
) -> None:
    call_a = ToolCall(id="tc-a", name="clock.now", arguments={})
    call_b = ToolCall(id="tc-b", name="clock.now", arguments={})
    call_c = ToolCall(id="tc-c", name="clock.now", arguments={})
    # Insert out of order: iteration 1's batch first, iteration 0's second.
    await journal.append_batch(
        adapter_id=_ADAPTER, inbound_id="m2", iteration=1, calls=[(2, call_c)]
    )
    await journal.append_batch(
        adapter_id=_ADAPTER, inbound_id="m2", iteration=0, calls=[(0, call_a), (1, call_b)]
    )

    entries = await journal.read(adapter_id=_ADAPTER, inbound_id="m2")
    assert [e.call_index for e in entries] == [0, 1, 2]
    assert [e.tool_call.id for e in entries] == ["tc-a", "tc-b", "tc-c"]


async def test_inbound_id_namespaces_are_isolated(journal: PostgresReplayJournal) -> None:
    call = ToolCall(id="tc-1", name="clock.now", arguments={})
    await journal.append_batch(adapter_id=_ADAPTER, inbound_id="m3", iteration=0, calls=[(0, call)])
    assert await journal.read(adapter_id=_ADAPTER, inbound_id="m4") == ()


async def test_adapter_id_namespaces_are_isolated_on_the_same_inbound_id(
    journal: PostgresReplayJournal,
) -> None:
    # Two DIFFERENT adapters minting the SAME inbound_id string must not collide.
    call_discord = ToolCall(id="tc-discord", name="clock.now", arguments={})
    call_tui = ToolCall(id="tc-tui", name="clock.now", arguments={})
    await journal.append_batch(
        adapter_id="discord", inbound_id="shared-id", iteration=0, calls=[(0, call_discord)]
    )
    await journal.append_batch(
        adapter_id="tui", inbound_id="shared-id", iteration=0, calls=[(0, call_tui)]
    )

    discord_entries = await journal.read(adapter_id="discord", inbound_id="shared-id")
    tui_entries = await journal.read(adapter_id="tui", inbound_id="shared-id")
    assert discord_entries == (JournalEntry(call_index=0, iteration=0, tool_call=call_discord),)
    assert tui_entries == (JournalEntry(call_index=0, iteration=0, tool_call=call_tui),)


async def test_arguments_round_trip_through_json_serialization(
    journal: PostgresReplayJournal,
) -> None:
    call = ToolCall(
        id="tc-1",
        name="web.fetch",
        arguments={"url": "https://example.invalid", "nested": {"a": 1, "b": [1, 2, 3]}},
    )
    await journal.append_batch(adapter_id=_ADAPTER, inbound_id="m5", iteration=0, calls=[(0, call)])
    entries = await journal.read(adapter_id=_ADAPTER, inbound_id="m5")
    assert entries[0].tool_call.arguments == call.arguments
