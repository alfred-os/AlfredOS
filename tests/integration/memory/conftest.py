"""Shared per-test Postgres fixtures for the episodic-memory integration tier.

Promoted out of ``test_episodic_hooks_poc.py`` once the second consumer
(Task 8's no-recursion / fresh-session assertions) needed the same
container + engine + per-test session shape. Per the plan-reviewer's
second-consumer threshold: two consumers is the bar at which a fixture
moves to ``conftest.py``; below that it lives inline so the reader sees
the setup at the test site.

What this conftest owns:

* :func:`pg_engine` — a per-test :class:`~sqlalchemy.ext.asyncio.AsyncEngine`
  bound to a fresh :class:`~testcontainers.postgres.PostgresContainer`
  with the full :class:`alfred.memory.models.Base` schema applied. ~5 s
  container startup is the price of per-test isolation; the
  byte-identity baseline test exists precisely to catch the kind of
  cross-test leak this discipline prevents.
* :func:`session_factory` — a zero-arg async-cm factory returning FRESH
  sessions bound to ``pg_engine``. Shaped exactly like
  :func:`alfred.memory.db.build_session_scope`'s output so a real
  :class:`alfred.audit.log.AuditWriter` can consume it verbatim. The
  freshness is load-bearing for Task 8's test (b) — Decision 3.6 /
  memB-1 — where the turn session is intentionally poisoned by a
  CHECK-constraint violation and the audit row's persistence depends
  on its own fresh session, NOT the poisoned turn session.
* :func:`session` — the "turn" :class:`AsyncSession` bound to the same
  engine. This is the session :class:`alfred.memory.episodic.EpisodicMemory`
  drives during the test. Distinct instance from any session the
  ``AuditWriter`` opens via ``session_factory`` — i.e. an
  ``InvalidRequestError`` on this session does NOT block the audit
  writer.

The trio shares ONE engine per test so the same Postgres container
serves both the turn session and the audit writer's fresh sessions —
that's how the test reproduces the production wiring where
``alfred.memory.db.build_session_scope`` and the orchestrator's per-turn
session live in the same process against the same DB but on independent
session lifecycles.

Conventions: real Postgres via testcontainers (alfred-memory-engineer
quality bar — write paths get real DB, not in-memory fakes);
``expire_on_commit=False`` on the per-test session so a post-commit
attribute read does not trigger a surprise SELECT.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager

import pytest
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from testcontainers.postgres import PostgresContainer

from alfred.memory.models import Base


@pytest.fixture
async def pg_engine() -> AsyncIterator[AsyncEngine]:
    """Yield a per-test async engine bound to a fresh Postgres container.

    The container is per-test (not per-module) for the same reason the
    inline fixture in the original byte-identity test was per-test: a
    leak across tests on the byte-identity baseline OR on the
    no-recursion bound is exactly the kind of bug the integration tier
    exists to catch. Modules sharing a container would let a stale row
    inflate the ``audit_log`` row count and silently break Task 8's
    EXACT-count assertion.

    ``create_all`` (rather than ``alembic upgrade``) keeps the baseline
    immune to migration-shape drift; the migration-specific integration
    tests cover that axis separately.
    """
    with PostgresContainer("postgres:18") as pg:
        url = pg.get_connection_url().replace("psycopg2", "asyncpg")
        engine = create_async_engine(url)
        try:
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            yield engine
        finally:
            await engine.dispose()


@pytest.fixture
async def session_factory(
    pg_engine: AsyncEngine,
) -> Callable[[], AbstractAsyncContextManager[AsyncSession]]:
    """Return a zero-arg async-cm factory yielding FRESH sessions per call.

    Shape mirrors :func:`alfred.memory.db.build_session_scope` so an
    :class:`alfred.audit.log.AuditWriter` constructed against this
    factory exercises the production fresh-session-per-append contract
    verbatim. Each ``async with session_factory() as session: ...`` opens
    a new ``AsyncSession`` (and commits inside the writer's own ``append``
    implementation), so two emits → two fresh sessions — the Decision 3.6
    / memB-1 invariant.
    """
    sm = async_sessionmaker(bind=pg_engine, expire_on_commit=False)

    @asynccontextmanager
    async def _scope() -> AsyncIterator[AsyncSession]:
        async with sm() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    return _scope


@pytest.fixture
async def session(pg_engine: AsyncEngine) -> AsyncIterator[AsyncSession]:
    """Yield a per-test "turn" :class:`AsyncSession` bound to ``pg_engine``.

    This is the session :class:`alfred.memory.episodic.EpisodicMemory`
    drives during the test — the equivalent of the orchestrator's
    per-turn session in production. Distinct from any session the
    :class:`alfred.audit.log.AuditWriter` opens via :func:`session_factory`,
    which is the WHOLE POINT of the fresh-session-per-emit invariant:
    when this turn session is poisoned by an ``IntegrityError``, the
    audit writer can still persist its fault row through an independent
    session on the same engine.

    ``expire_on_commit=False`` so tests can read attributes off the
    returned ORM instance after a ``session.commit()`` without
    triggering a surprise refresh; the readback path uses explicit
    ``select(...)`` queries, but the flag avoids the SELECT-after-commit
    a future refactor might introduce.
    """
    sm = async_sessionmaker(bind=pg_engine, expire_on_commit=False)
    async with sm() as s:
        yield s
