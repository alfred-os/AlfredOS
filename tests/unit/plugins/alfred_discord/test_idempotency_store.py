"""SQLite-backed outbound idempotency store (Task F1, PR-S4-9 #206).

The store is the single-use ledger that makes outbound delivery idempotent
*across a plugin restart*: a redelivered ``outbound.message`` carrying the same
host-minted ``idempotency_key`` must NOT hit Discord a second time. Because a
plugin can crash and respawn between the first send and the host's redelivery,
the ledger is on-disk SQLite (not in-memory) and survives the subprocess
lifetime.

Behaviour pinned here:

1. ``record`` then ``lookup`` round-trips the recorded ``platform_message_id``.
2. A second ``record`` for the same key with a DIFFERENT message id is a loud
   conflict (``IdempotencyConflictError``) — never a silent overwrite.
3. Restart survival: close + reopen at the same path still ``lookup``\\s the id.
4. TTL expiry: a record older than ``ttl_hours`` is pruned by
   ``vacuum_expired`` and then ``lookup``\\s as ``None``.
5. Concurrent same-key ``record`` race: exactly one wins, one raises.
6. WAL journal mode is enabled (concurrent reader/writer correctness).
"""

from __future__ import annotations

import asyncio
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from plugins.alfred_discord.idempotency_store import (
    IdempotencyConflictError,
    IdempotencyStore,
)


def _store(tmp_path: Path) -> IdempotencyStore:
    return IdempotencyStore(db_path=tmp_path / "idempotency.db")


def test_record_then_lookup_round_trips(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.record("key-1", "platform-42")
    assert store.lookup("key-1") == "platform-42"


def test_lookup_unknown_key_returns_none(tmp_path: Path) -> None:
    store = _store(tmp_path)
    assert store.lookup("never-seen") is None


def test_second_record_different_id_raises_conflict(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.record("key-1", "platform-42")
    with pytest.raises(IdempotencyConflictError):
        store.record("key-1", "platform-99")


def test_second_record_same_id_is_idempotent_noop(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.record("key-1", "platform-42")
    # Same id replayed: no conflict — the ledger already holds this exact fact.
    store.record("key-1", "platform-42")
    assert store.lookup("key-1") == "platform-42"


def test_record_survives_restart(tmp_path: Path) -> None:
    first = _store(tmp_path)
    first.record("key-1", "platform-42")
    first.close()

    reopened = _store(tmp_path)
    assert reopened.lookup("key-1") == "platform-42"


def test_ttl_expiry_vacuum_prunes_old_records(tmp_path: Path) -> None:
    store = IdempotencyStore(db_path=tmp_path / "idempotency.db", ttl_hours=24)
    stale = datetime.now(UTC) - timedelta(hours=25)
    store.record("old-key", "platform-1", recorded_at=stale)
    store.record("fresh-key", "platform-2")

    store.vacuum_expired()

    assert store.lookup("old-key") is None
    assert store.lookup("fresh-key") == "platform-2"


async def test_concurrent_same_key_record_exactly_one_wins(tmp_path: Path) -> None:
    store = _store(tmp_path)

    async def _record(msg_id: str) -> str | None:
        try:
            await asyncio.to_thread(store.record, "race-key", msg_id)
            return None
        except IdempotencyConflictError:
            return "conflict"

    async with asyncio.TaskGroup() as tg:
        t1 = tg.create_task(_record("platform-A"))
        t2 = tg.create_task(_record("platform-B"))

    outcomes = [t1.result(), t2.result()]
    # Exactly one of the two distinct ids wins; the loser raises a conflict.
    assert outcomes.count("conflict") == 1
    assert store.lookup("race-key") in {"platform-A", "platform-B"}


def test_wal_journal_mode_enabled(tmp_path: Path) -> None:
    db_path = tmp_path / "idempotency.db"
    store = IdempotencyStore(db_path=db_path)
    store.record("key-1", "platform-42")
    # Inspect the journal mode directly via a fresh raw connection.
    with sqlite3.connect(db_path) as conn:
        (mode,) = conn.execute("PRAGMA journal_mode").fetchone()
    assert mode.lower() == "wal"
