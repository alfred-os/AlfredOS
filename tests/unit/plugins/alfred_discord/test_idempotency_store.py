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
import contextlib
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from plugins.alfred_discord.idempotency_store import (
    IdempotencyConflictError,
    IdempotencyStore,
)

_DB_NAME = "idempotency.db"


def _store(tmp_path: Path, *, ttl_hours: int | None = None) -> IdempotencyStore:
    """The store under test — USE IT AS A CONTEXT MANAGER.

    `IdempotencyStore` is itself a context manager (`__enter__`/`__exit__` ->
    `close()`), so `with _store(tmp_path) as store:` runs the PRODUCTION reaper
    rather than a test-local reimplementation of it. Constructing one without a
    `with` leaks the sqlite connection until GC — the defect #559 closes.

    `ttl_hours=None` means the store's own default, so the default is not
    restated here and cannot drift from production.
    """
    db_path = tmp_path / _DB_NAME
    if ttl_hours is None:
        return IdempotencyStore(db_path=db_path)
    return IdempotencyStore(db_path=db_path, ttl_hours=ttl_hours)


def test_record_then_lookup_round_trips(tmp_path: Path) -> None:
    with _store(tmp_path) as store:
        store.record("key-1", "platform-42")
        assert store.lookup("key-1") == "platform-42"


def test_lookup_unknown_key_returns_none(tmp_path: Path) -> None:
    with _store(tmp_path) as store:
        assert store.lookup("never-seen") is None


def test_second_record_different_id_raises_conflict(tmp_path: Path) -> None:
    with _store(tmp_path) as store:
        store.record("key-1", "platform-42")
        with pytest.raises(IdempotencyConflictError):
            store.record("key-1", "platform-99")


def test_second_record_same_id_is_idempotent_noop(tmp_path: Path) -> None:
    with _store(tmp_path) as store:
        store.record("key-1", "platform-42")
        # Same id replayed: no conflict — the ledger already holds this exact fact.
        store.record("key-1", "platform-42")
        assert store.lookup("key-1") == "platform-42"


def test_record_survives_restart(tmp_path: Path) -> None:
    with _store(tmp_path) as first:
        first.record("key-1", "platform-42")

    # The point of this test is that the data outlives the CONNECTION, so the
    # first store must be fully closed before the second opens — that is what
    # the with-block above guarantees.
    with _store(tmp_path) as reopened:
        assert reopened.lookup("key-1") == "platform-42"


def test_ttl_expiry_vacuum_prunes_old_records(tmp_path: Path) -> None:
    with _store(tmp_path, ttl_hours=24) as store:
        stale = datetime.now(UTC) - timedelta(hours=25)
        store.record("old-key", "platform-1", recorded_at=stale)
        store.record("fresh-key", "platform-2")

        # L2: ``vacuum_expired`` returns the pruned-row count, read INSIDE the
        # write-lock + transaction block so a concurrent writer cannot perturb
        # the reported figure after the lock releases.
        pruned = store.vacuum_expired()

        assert pruned == 1
        assert store.lookup("old-key") is None
        assert store.lookup("fresh-key") == "platform-2"


async def test_concurrent_same_key_record_exactly_one_wins(tmp_path: Path) -> None:
    with _store(tmp_path) as store:

        async def _record(msg_id: str) -> str | None:
            try:
                await asyncio.to_thread(store.record, "race-key", msg_id)
                return None
            except IdempotencyConflictError:
                return "conflict"

        # `gather`, not `TaskGroup`: on an UNEXPECTED exception a TaskGroup
        # cancels its sibling, but cancelling an `asyncio.to_thread` await does
        # not stop the OS thread — it would run on into the `close()` this
        # with-block is about to perform and die with "Cannot operate on a
        # closed database", burying the original failure. `return_exceptions`
        # keeps both threads joined before teardown without weakening the race.
        outcomes = await asyncio.gather(
            _record("platform-A"), _record("platform-B"), return_exceptions=True
        )

        unexpected = [o for o in outcomes if isinstance(o, BaseException)]
        assert not unexpected, f"unexpected exception from a racer: {unexpected}"
        # Exactly one of the two distinct ids wins; the loser raises a conflict.
        assert outcomes.count("conflict") == 1
        assert store.lookup("race-key") in {"platform-A", "platform-B"}


def test_wal_journal_mode_enabled(tmp_path: Path) -> None:
    db_path = tmp_path / _DB_NAME
    with _store(tmp_path) as store:
        store.record("key-1", "platform-42")

    # Inspect the journal mode directly via a fresh raw connection.
    # `with sqlite3.connect(...)` COMMITS but does not CLOSE — the classic
    # trap. `closing()` is what actually releases the handle.
    with contextlib.closing(sqlite3.connect(db_path)) as conn:
        (mode,) = conn.execute("PRAGMA journal_mode").fetchone()
    assert mode.lower() == "wal"
