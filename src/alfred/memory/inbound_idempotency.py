"""Durable inbound accept-once store (Spec A / G0).

The commit-once primitive the Comms-Resume Gateway needs: the core records
"this inbound was accepted exactly once" keyed on a durable wire ``inbound_id``
BEFORE any side effect runs. A replayed frame short-circuits.

The atomicity contract is a single ``INSERT … ON CONFLICT (adapter_id,
inbound_id) DO NOTHING RETURNING inbound_id`` — Postgres returns a row IFF this
caller won the insert; an existing row yields no rows. There is NO read-then-
write window, so two concurrent commits on the same ``(adapter_id, inbound_id)``
produce exactly one winner. The key is COMPOSITE so each adapter's free-form
``inbound_id`` namespace is isolated (one adapter's id reuse cannot drop
another adapter's distinct message).

A genuine DB failure (``SQLAlchemyError``) PROPAGATES — it is never caught and
collapsed into a won/replay bool. The commit-once decision is part of the
inbound trust boundary, so a failed commit must fail LOUD (CLAUDE.md hard rule
#7), letting the caller's handler-failure path audit + surface it rather than
silently process or silently drop the message.
"""

from __future__ import annotations

from collections.abc import Callable
from contextlib import AbstractAsyncContextManager
from typing import Protocol, runtime_checkable

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession

# Single source of truth for the commit-once SQL. ``committed_at`` is filled by
# the column ``server_default now()`` so it is never named here. ``RETURNING``
# yields a row only on a fresh insert; ON CONFLICT DO NOTHING suppresses the
# duplicate, returning zero rows — the value that tells the caller "replay".
_COMMIT_ONCE_SQL = sa.text(
    "INSERT INTO inbound_idempotency (inbound_id, adapter_id) "
    "VALUES (:inbound_id, :adapter_id) "
    "ON CONFLICT (adapter_id, inbound_id) DO NOTHING "
    "RETURNING inbound_id"
)


@runtime_checkable
class InboundIdempotencyStore(Protocol):
    """Durable accept-once commit on a wire ``inbound_id`` (Spec A decision 4)."""

    async def commit_once(self, *, inbound_id: str, adapter_id: str) -> bool:
        """Atomically record ``inbound_id`` as accepted.

        The accept-once is keyed on the COMPOSITE ``(adapter_id, inbound_id)`` so
        each adapter's free-form id namespace is isolated. Returns ``True`` if
        THIS call won the insert (the inbound is new — the caller proceeds with
        side effects), ``False`` if a row already existed (a replay/retry — the
        caller short-circuits). Never raises on a duplicate; raises
        ``SQLAlchemyError`` only on a genuine DB failure (fail-loud at the
        boundary — CLAUDE.md hard rule #7; the error propagates, it is never
        swallowed into a won/replay bool).
        """
        ...


class PostgresInboundIdempotencyStore:
    """Postgres-backed :class:`InboundIdempotencyStore`.

    Owns its transactional ``session_scope`` (the daemon-built
    ``build_session_scope(settings)`` callable) — the same "pre-built durable
    writer injected from the boot graph" shape ``audit_writer`` uses, so
    ``process_inbound_message`` never handles a raw DB session.
    """

    def __init__(
        self,
        *,
        session_scope: Callable[[], AbstractAsyncContextManager[AsyncSession]],
    ) -> None:
        self._session_scope = session_scope

    async def commit_once(self, *, inbound_id: str, adapter_id: str) -> bool:
        # The store stays a pure primitive: it returns the won/replay decision and
        # logs NOTHING. The replay-observed observability line is owned by the comms
        # BOUNDARY guard (``process_inbound_message``), which holds the trust-boundary
        # event — so a single replay emits exactly one structlog line, not two.
        async with self._session_scope() as session:
            result = await session.execute(
                _COMMIT_ONCE_SQL,
                {"inbound_id": inbound_id, "adapter_id": adapter_id},
            )
            return result.scalar_one_or_none() is not None
