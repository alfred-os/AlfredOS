"""Durable forwarded-dispatch attempt ledger (Spec B G6-7-5).

The forwarded dispatched-edge path
(:func:`alfred.comms_mcp.inbound.process_inbound_message` with
``commit_at_dispatch_edge=True``, ADR-0039 item 4) leaves a failed frame NOT
committed / NOT observed so the forwarding leg replays it. That replay must be
BOUNDED — otherwise a frame whose dispatch can never succeed (a poison message)
replays forever. This store is the durable per-``(adapter_id, inbound_id)``
attempt counter that supplies the bound.

It is durable-across-restart on purpose (ADR-0039 item 4b): the forwarded
dispatched-edge replay happens ACROSS core restarts — an in-memory counter would
reset to zero exactly when the bound is needed (a crash-loop on a poison frame
would re-arm the replay every boot), so the count lives in Postgres.

The atomicity contract is a single ``INSERT … ON CONFLICT (adapter_id,
inbound_id) DO UPDATE SET attempt_count = attempt_count + 1 … RETURNING
attempt_count`` — one statement inserts ``attempt_count = 1`` on the first
failure or increments on conflict, with NO read-then-write window, so concurrent
increments on the same key serialise to a correct monotone count.

A genuine DB failure (``SQLAlchemyError``) PROPAGATES — it is never caught and
collapsed into a count. The replay bound is a safety limit, so a failed write
must fail LOUD (CLAUDE.md hard rule #7) rather than silently forge a low count
(which would re-arm the replay it exists to cap).

The key is COMPOSITE so each adapter's free-form ``inbound_id`` namespace is
isolated — load-bearing ONLY because upstream K4 admission mints ``adapter_id``
from the un-forgeable spawn binding, so one adapter cannot poison or reset
another adapter's attempt counter by colliding on a shared ``inbound_id``.

This module is a pure primitive: it logs NOTHING. The poisoned-exhausted
observability + audit row is owned by the comms boundary that consumes the
count.
"""

from __future__ import annotations

from collections.abc import Callable
from contextlib import AbstractAsyncContextManager
from typing import Protocol, runtime_checkable

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession

__all__ = [
    "ForwardedDispatchAttemptStore",
    "PostgresForwardedDispatchAttemptStore",
]

# Single source of truth for the atomic increment. ``first_failed_at`` is set by
# the column ``server_default now()`` on the fresh insert and never touched on
# conflict (it stays the FIRST failure's timestamp); ``last_failed_at`` is moved
# to ``now()`` on every increment so a retention sweep can prune by recency.
# ``RETURNING attempt_count`` yields the post-write count in both branches, so
# the caller never read-then-writes.
_INCREMENT_SQL = sa.text(
    "INSERT INTO forwarded_dispatch_attempts (adapter_id, inbound_id, attempt_count) "
    "VALUES (:adapter_id, :inbound_id, 1) "
    "ON CONFLICT (adapter_id, inbound_id) DO UPDATE SET "
    "attempt_count = forwarded_dispatch_attempts.attempt_count + 1, last_failed_at = now() "
    "RETURNING attempt_count"
)

# Non-mutating probe on the same COMPOSITE key. Yields the current count IFF a
# row exists; zero rows otherwise (the caller maps that to 0). It NEVER inserts —
# arming the counter stays the sole job of ``_INCREMENT_SQL``.
_ATTEMPT_COUNT_SQL = sa.text(
    "SELECT attempt_count FROM forwarded_dispatch_attempts "
    "WHERE adapter_id = :adapter_id AND inbound_id = :inbound_id"
)


@runtime_checkable
class ForwardedDispatchAttemptStore(Protocol):
    """Durable per-``(adapter_id, inbound_id)`` forwarded-dispatch attempt counter."""

    async def increment(self, *, adapter_id: str, inbound_id: str) -> int:
        """Atomically record one more failed forwarded dispatch; return the new count.

        Inserts ``attempt_count = 1`` on the first failure or increments on
        conflict, in a single statement (no read-then-write window). Returns the
        post-write ``attempt_count``. Raises ``SQLAlchemyError`` only on a genuine
        DB failure (fail-loud — CLAUDE.md hard rule #7; never swallowed into a
        count).
        """
        ...

    async def attempt_count(self, *, adapter_id: str, inbound_id: str) -> int:
        """Non-mutating: the current attempt count, or 0 if no row exists.

        Raises ``SQLAlchemyError`` only on a genuine DB failure (fail-loud; never
        swallowed into a 0).
        """
        ...


class PostgresForwardedDispatchAttemptStore:
    """Postgres-backed :class:`ForwardedDispatchAttemptStore`.

    Owns its transactional ``session_scope`` (the daemon-built
    ``build_session_scope(settings)`` callable) — the same "pre-built durable
    writer injected from the boot graph" shape ``audit_writer`` and the sibling
    ``PostgresInboundIdempotencyStore`` use, so the inbound path never handles a
    raw DB session.
    """

    def __init__(
        self,
        *,
        session_scope: Callable[[], AbstractAsyncContextManager[AsyncSession]],
    ) -> None:
        self._session_scope = session_scope

    async def increment(self, *, adapter_id: str, inbound_id: str) -> int:
        async with self._session_scope() as session:
            result = await session.execute(
                _INCREMENT_SQL,
                {"adapter_id": adapter_id, "inbound_id": inbound_id},
            )
            return int(result.scalar_one())

    async def attempt_count(self, *, adapter_id: str, inbound_id: str) -> int:
        async with self._session_scope() as session:
            result = await session.execute(
                _ATTEMPT_COUNT_SQL,
                {"adapter_id": adapter_id, "inbound_id": inbound_id},
            )
            value = result.scalar_one_or_none()
            return int(value) if value is not None else 0
