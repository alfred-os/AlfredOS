"""Storage backend Protocol + :class:`PostgresBackend` for :class:`RealGate`.

Spec §8.1 (Fork 7): hot-path capability checks consult Postgres for
millisecond-latency answers. The ``plugin_grants`` and
``capability_gate_sync`` tables are defined in migrations
``0008_plugin_grants`` and ``0009_capability_gate_sync`` (PR-S3-0b);
the SQLAlchemy ORM models :class:`alfred.memory.models.PluginGrant` and
:class:`alfred.memory.models.CapabilityGateSyncRow` live alongside the
rest of the memory subsystem.

This module follows the sec-007 extension: it does NOT ``import os``.
``ALFRED_ENV`` selection (RealGate vs DevGate) lives in
:mod:`alfred.bootstrap.gate_factory` (a forthcoming PR-S3-2 task); the
DSN string is injected via dependency injection through the constructor.

The Postgres I/O surface uses SQLAlchemy 2.0 ``async_sessionmaker`` and
parameterised text queries — the schema is rigid enough (and the query
set small enough) that the typed-Core / ORM machinery would buy little
over the explicit ``sa.text`` form. Future PRs can lift to ORM if the
query shape becomes dynamic.

Hard invariants pinned by ``tests/unit/security/capability_gate/test_storage_backend.py``:

* :class:`StorageBackend` is ``@runtime_checkable``; concrete backends
  satisfy it structurally without subclassing.
* :class:`PostgresBackend` rejects an empty constructor (no
  ``session_factory`` AND no ``dsn``) with :class:`ValueError`.
* :meth:`PostgresBackend.upsert_grant` uses ``ON CONFLICT (plugin_id,
  hookpoint, subscriber_tier)`` — matches migration 0008's
  ``uq_plugin_grants_plugin_hook_tier`` UNIQUE constraint (mem-003).
* :meth:`PostgresBackend.revoke_grant` filters by all three key columns
  in the DELETE WHERE clause.
* :meth:`PostgresBackend.get_sync_hash` returns ``None`` on an unseeded
  table.
"""

from __future__ import annotations

import datetime as dt
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Protocol, runtime_checkable

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from alfred.security.capability_gate.policy import GrantRow


@runtime_checkable
class StorageBackend(Protocol):
    """Structural Protocol for the :class:`RealGate` backing store.

    :class:`PostgresBackend` is the production implementation. Test
    doubles (and future backends — Redis-cached projection, in-memory
    for the dev gate fixture, etc.) implement this Protocol so
    :class:`RealGate` can compose with any backend without subclassing.

    The Protocol is ``@runtime_checkable`` so dispatcher code can
    ``isinstance``-narrow at runtime — same posture as
    :class:`alfred.hooks.capability.CapabilityGate`.
    """

    async def ping(self) -> None:
        """Raise on connectivity failure; return ``None`` on success.

        Used by the heartbeat task (spec §8.1) to detect backing-store
        outages. A raised exception trips the missed-heartbeat counter;
        crossing the 60s threshold flips the gate to fail-closed.
        """
        ...

    async def load_grants(self) -> frozenset[GrantRow]:
        """Load all active grants. Returns an empty ``frozenset`` if none."""
        ...

    async def upsert_grant(self, grant: GrantRow) -> None:
        """Insert or update one grant row.

        The unique key is ``(plugin_id, hookpoint, subscriber_tier)``;
        ``content_tier`` and ``proposal_branch`` are updated on conflict.
        """
        ...

    async def revoke_grant(
        self,
        *,
        plugin_id: str,
        hookpoint: str,
        subscriber_tier: str,
    ) -> None:
        """Remove a single grant. No-op if not present (idempotent)."""
        ...

    async def get_sync_hash(self) -> str | None:
        """Return the last-recorded state.git commit hash, or ``None`` if unseeded."""
        ...

    async def set_sync_hash(self, commit_hash: str) -> None:
        """Record the state.git commit hash after a successful rebuild."""
        ...


class PostgresBackend:
    """Production :class:`StorageBackend` backed by Postgres.

    Operates on ``plugin_grants`` (migration 0008) for the grant rows
    and ``capability_gate_sync`` (migration 0009) for the rebuild-hash
    sync marker. Rebuilding is idempotent: :meth:`upsert_grant` and
    :meth:`set_sync_hash` are called atomically from
    :meth:`RealGate._apply_grants` when the state.git HEAD differs from
    the cached hash.

    Construction:

    * ``session_factory`` — a pre-built
      :class:`sqlalchemy.ext.asyncio.async_sessionmaker`; preferred when
      the surrounding app already manages the engine (production path).
    * ``dsn`` — a connection URL; the backend builds its own engine and
      sessionmaker. Convenience shortcut for tests that don't have a
      pre-built factory.

    Constructing with neither raises :class:`ValueError` — CLAUDE.md
    hard rule #7 (no silent failures) — a backend with no session
    factory cannot answer any of its Protocol methods.
    """

    def __init__(
        self,
        *,
        session_factory: async_sessionmaker[AsyncSession] | None = None,
        dsn: str | None = None,
    ) -> None:
        if session_factory is not None:
            self._session_factory = session_factory
        elif dsn is not None:
            engine = create_async_engine(dsn, echo=False)
            self._session_factory = async_sessionmaker(engine, expire_on_commit=False)
        else:
            msg = "PostgresBackend requires either session_factory or dsn; neither was provided"
            raise ValueError(msg)

    @asynccontextmanager
    async def _session(self) -> AsyncIterator[AsyncSession]:
        """Open a session inside a ``BEGIN`` block (per-call transaction).

        Every backend method runs inside its own transaction so a
        failed write does not leave a half-applied state. The
        :func:`asynccontextmanager` decorator gives us ``async with``
        semantics over the two-level (factory + begin) nesting.
        """
        async with (
            self._session_factory() as session,
            session.begin(),
        ):
            yield session

    async def ping(self) -> None:
        """Issue ``SELECT 1`` against the backing store."""
        async with self._session() as session:
            await session.execute(sa.text("SELECT 1"))

    async def load_grants(self) -> frozenset[GrantRow]:
        """Load every active grant from ``plugin_grants`` as :class:`GrantRow`.

        Filters by ``state = 'approved'``. The closed-domain CHECK admits
        ``'requested' | 'approved' | 'denied' | 'revoked'``; only
        ``'approved'`` rows authorise hot-path dispatch. ``'requested'``
        rows are pending reviewer review; ``'denied'`` / ``'revoked'``
        are historical attribution kept for audit-graph traversal.
        Letting any non-approved row leak into the in-memory policy would
        be a silent privilege escalation — CLAUDE.md hard rule #7.
        """
        async with self._session() as session:
            result = await session.execute(
                sa.text(
                    "SELECT plugin_id, subscriber_tier, hookpoint, "
                    "content_tier, proposal_branch "
                    "FROM plugin_grants WHERE state = 'approved'"
                )
            )
            rows = result.fetchall()
        return frozenset(
            GrantRow(
                plugin_id=r.plugin_id,
                subscriber_tier=r.subscriber_tier,
                hookpoint=r.hookpoint,
                content_tier=r.content_tier,
                proposal_branch=r.proposal_branch,
            )
            for r in rows
        )

    async def upsert_grant(self, grant: GrantRow) -> None:
        """Insert one grant or update on the (plugin_id, hookpoint, subscriber_tier) conflict.

        The ON CONFLICT target matches migration 0008's
        ``uq_plugin_grants_plugin_hook_tier`` UNIQUE constraint exactly;
        the mem-003 comment in that migration documents the contract.

        NOT NULL columns from migration 0008 — ``id``, ``created_at``,
        ``correlation_id``, ``state`` — are populated here at the SQL
        layer rather than at the :class:`GrantRow` boundary. Rationale:
        :class:`GrantRow` models the state.git source-of-truth shape;
        these four columns are persistence-layer attribution that lives
        in Postgres but not in the state.git proposal tree. Generating
        them here keeps the policy-layer immutable model lean.

        State semantics: every row written via this method represents an
        approved-and-merged grant (the reviewer-agent's
        ``state.git → main`` merge triggered the rebuild calling this
        path). The closed-domain CHECK in migration 0008 admits
        ``'approved'`` for that lifecycle position. ``'requested'`` rows
        come from the proposal flow (PR-S3-2 :mod:`proposals` writes to
        state.git, NOT this table); ``'denied'`` / ``'revoked'`` come
        from the reviewer-agent's tooling in a later PR.

        ``correlation_id`` is freshly minted per row — one rebuild
        operation upserts N grants and emits one audit row per upsert,
        each with its own correlation. The forensic graph follows the
        per-grant correlation upstream to the per-rebuild trace via
        ``state_git_commit_hash`` (populated by ``set_sync_hash``).
        """
        now = dt.datetime.now(dt.UTC)
        async with self._session() as session:
            await session.execute(
                sa.text(
                    "INSERT INTO plugin_grants "
                    "(id, created_at, plugin_id, subscriber_tier, hookpoint, "
                    "content_tier, proposal_branch, correlation_id, state) "
                    "VALUES (:id, :created_at, :plugin_id, :subscriber_tier, "
                    ":hookpoint, :content_tier, :proposal_branch, "
                    ":correlation_id, :state) "
                    "ON CONFLICT (plugin_id, hookpoint, subscriber_tier) "
                    "DO UPDATE SET content_tier = EXCLUDED.content_tier, "
                    "proposal_branch = EXCLUDED.proposal_branch"
                ),
                {
                    "id": uuid.uuid4(),
                    "created_at": now,
                    "plugin_id": grant.plugin_id,
                    "subscriber_tier": grant.subscriber_tier,
                    "hookpoint": grant.hookpoint,
                    "content_tier": grant.content_tier,
                    "proposal_branch": grant.proposal_branch,
                    "correlation_id": str(uuid.uuid4()),
                    "state": "approved",
                },
            )

    async def revoke_grant(
        self,
        *,
        plugin_id: str,
        hookpoint: str,
        subscriber_tier: str,
    ) -> None:
        """Delete one grant; idempotent (no error if absent)."""
        async with self._session() as session:
            await session.execute(
                sa.text(
                    "DELETE FROM plugin_grants "
                    "WHERE plugin_id = :plugin_id "
                    "AND hookpoint = :hookpoint "
                    "AND subscriber_tier = :subscriber_tier"
                ),
                {
                    "plugin_id": plugin_id,
                    "hookpoint": hookpoint,
                    "subscriber_tier": subscriber_tier,
                },
            )

    async def get_sync_hash(self) -> str | None:
        """Return the most recently recorded state.git HEAD hash, or ``None``."""
        async with self._session() as session:
            result = await session.execute(
                sa.text("SELECT commit_hash FROM capability_gate_sync ORDER BY id DESC LIMIT 1")
            )
            row = result.fetchone()
        if row is None:
            return None
        commit_hash: str = row.commit_hash
        return commit_hash

    async def set_sync_hash(self, commit_hash: str) -> None:
        """Upsert the singleton commit-hash marker (migration 0009).

        mem-004: the table's INTEGER PK has ``CHECK (id = 1)`` enforcing
        the singleton-row contract. The INSERT explicitly supplies
        ``id = 1``; the ``ON CONFLICT (id) DO UPDATE`` then updates the
        same row in place when called multiple times during a process
        lifetime (one set per state.git rebuild).
        """
        async with self._session() as session:
            await session.execute(
                sa.text(
                    "INSERT INTO capability_gate_sync (id, commit_hash) "
                    "VALUES (1, :commit_hash) "
                    "ON CONFLICT (id) DO UPDATE SET "
                    "commit_hash = EXCLUDED.commit_hash"
                ),
                {"commit_hash": commit_hash},
            )
