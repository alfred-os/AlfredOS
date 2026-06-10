"""On-disk outbound idempotency ledger (Task F1, PR-S4-9 #206).

:class:`IdempotencyStore` is the single-use ledger that dedupes outbound delivery
across a plugin **crash + respawn within one sandbox lifetime**. The host mints
an ``idempotency_key`` (a ``UUID``) per ``outbound.message`` request; if the
plugin crashes between a successful Discord send and the host's redelivery, the
respawned plugin must *not* hit Discord again. An in-memory dedup set would forget
across the subprocess boundary, so the ledger is on-disk SQLite.

Storage location (M1 sandbox reconciliation). Under the real bwrap sandbox the
ONLY writable surface is the ephemeral tmpfs the policy mounts at
``/run/alfred/discord`` (``config/sandbox/discord-adapter.linux.bwrap.policy``);
every other path is read-only. :func:`server.idempotency_db_path` resolves the db
under that tmpfs. Because the tmpfs is fresh per sandbox launch and discarded on
sandbox exit, the ledger survives a **crash-respawn of the plugin process inside
a live sandbox** (the host re-execs the plugin into the same tmpfs) but NOT a
full sandbox teardown / daemon restart — which is exactly the redelivery window
the host's outbound queue can re-fire into. A daemon restart re-mints fresh keys,
so a forgotten ledger across that boundary cannot double-send.

Design notes:

* **WAL journal mode** is set on first connection so a concurrent reader does
  not block a writer (the outbound handler may ``lookup`` while another coroutine
  ``record``\\s).
* **Conflict is loud.** A second ``record`` for the same key with a *different*
  ``platform_message_id`` raises :class:`IdempotencyConflictError` rather than
  silently overwriting — a key collision across two distinct sends is a host bug
  the plugin must surface, not paper over. A second ``record`` with the *same*
  id is an idempotent no-op (the safe redelivery-after-record case).
* **TTL pruning** is explicit (``vacuum_expired``), not lazy-on-read: a key past
  ``ttl_hours`` is removed so the ledger does not grow without bound. The host's
  outbound queue never legitimately redelivers a >24h-old key, so pruning is
  safe.

This module holds no global state; the connection is owned per instance.
"""

from __future__ import annotations

import sqlite3
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import TracebackType
from typing import Final, Self

from alfred.errors import AlfredError

_DEFAULT_TTL_HOURS: Final[int] = 24

_SCHEMA: Final[str] = """
CREATE TABLE IF NOT EXISTS outbound_idempotency (
    idempotency_key     TEXT PRIMARY KEY,
    platform_message_id TEXT NOT NULL,
    recorded_at         TEXT NOT NULL
)
"""


class IdempotencyConflictError(AlfredError):
    """A second ``record`` for an existing key carried a different message id.

    Distinct from an idempotent replay (same key + same id, a no-op): a *different*
    id under the same key means two distinct sends collided on one idempotency
    key — a host-side bug the plugin refuses to mask with a silent overwrite.
    """


class IdempotencyStore:
    """SQLite-backed, restart-survivable outbound dedup ledger."""

    def __init__(self, *, db_path: Path, ttl_hours: int = _DEFAULT_TTL_HOURS) -> None:
        """Open (creating if absent) the ledger at ``db_path``.

        Args:
            db_path: On-disk SQLite path. Parent directories are created.
            ttl_hours: Records older than this are pruned by ``vacuum_expired``.
        """
        self._db_path = db_path
        self._ttl = timedelta(hours=ttl_hours)
        db_path.parent.mkdir(parents=True, exist_ok=True)
        # ``check_same_thread=False`` lets ``asyncio.to_thread`` workers share the
        # connection; SQLite serialises writes internally and WAL keeps readers
        # non-blocking. The store's own callers never share a cursor.
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(_SCHEMA)
        self._conn.commit()
        # The connection is shared across ``asyncio.to_thread`` workers; sqlite's
        # connection-level transaction state is not safe for concurrent ``with
        # conn`` blocks, so a write lock serialises record/vacuum at the Python
        # level. Reads under WAL stay non-blocking and need no lock.
        self._write_lock = threading.Lock()

    def record(
        self, key: str, platform_message_id: str, *, recorded_at: datetime | None = None
    ) -> None:
        """Record ``key -> platform_message_id``; raise on a conflicting redo.

        An ``INSERT ... ON CONFLICT DO NOTHING`` followed by a ``RETURNING``-shape
        check makes the write atomic against a concurrent same-key insert: the
        loser's row is untouched, so its stored id is compared against the one it
        tried to write. Same id → idempotent no-op; different id → conflict.
        """
        when = (recorded_at or datetime.now(UTC)).isoformat()
        with self._write_lock, self._conn:  # serialise writers; commit/rollback txn
            cursor = self._conn.execute(
                """
                INSERT INTO outbound_idempotency (idempotency_key, platform_message_id, recorded_at)
                VALUES (?, ?, ?)
                ON CONFLICT(idempotency_key) DO NOTHING
                """,
                (key, platform_message_id, when),
            )
            if cursor.rowcount == 1:
                return  # fresh insert won the race
            # Row already existed (this insert was a no-op): compare the stored id.
            existing = self._lookup_locked(key)
            if existing != platform_message_id:
                msg = f"idempotency key {key!r} already bound to a different message id"
                raise IdempotencyConflictError(msg)

    def lookup(self, key: str) -> str | None:
        """Return the recorded ``platform_message_id`` for ``key``, or ``None``."""
        return self._lookup_locked(key)

    def _lookup_locked(self, key: str) -> str | None:
        row = self._conn.execute(
            "SELECT platform_message_id FROM outbound_idempotency WHERE idempotency_key = ?",
            (key,),
        ).fetchone()
        return None if row is None else str(row[0])

    def vacuum_expired(self, *, now: datetime | None = None) -> int:
        """Delete records older than ``ttl_hours``; return the pruned row count."""
        cutoff = ((now or datetime.now(UTC)) - self._ttl).isoformat()
        with self._write_lock, self._conn:
            cursor = self._conn.execute(
                "DELETE FROM outbound_idempotency WHERE recorded_at < ?",
                (cutoff,),
            )
            # L2: read ``rowcount`` INSIDE the lock + transaction block. A
            # concurrent ``record``/``vacuum_expired`` on the shared connection
            # could mutate the cursor's reported rowcount once the ``with`` block
            # has released the lock; capturing it here keeps the pruned count
            # consistent with the DELETE this call actually performed.
            pruned = cursor.rowcount
        return pruned

    def close(self) -> None:
        """Close the underlying connection (flushes WAL to the main db)."""
        self._conn.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()


__all__ = ["IdempotencyConflictError", "IdempotencyStore"]
