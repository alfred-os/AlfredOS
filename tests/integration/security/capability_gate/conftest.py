"""Shared fixtures for ``tests/integration/security/capability_gate/``.

CR-139 finding #8: ``test_hybrid_storage_roundtrip.py`` and
``test_grant_lifecycle_e2e.py`` previously duplicated the Alembic /
backend wiring. Centralising here keeps both suites pinned to one
fixture contract — drift in the trust-boundary integration setup
would otherwise be invisible until a CR pass surfaces it.

Fixtures provided:

* :func:`alembic_cfg` — :class:`alembic.config.Config` pointed at the
  per-test container's ``postgres_url``, with the env-var and
  ``sqlalchemy.url`` both set so the migration env covers either code
  path.
* :func:`migrated_postgres` — upgrades the per-test container to HEAD
  (covers ``plugin_grants`` from 0008 and ``capability_gate_sync``
  from 0009) and returns the URL.
* :func:`make_audit_sink` — factory producing a Protocol-compatible
  audit sink double; the real :class:`AuditWriter` is exercised by
  ``test_audit_persistence.py``.
* :func:`backend_against` — async context manager yielding
  ``(PostgresBackend, async_sessionmaker)`` against the supplied URL.
  Returned as a callable so each test can build multiple backends
  inside one ``async with`` block (the proposal → apply → check
  sequence builds two backends against the same DB to simulate a
  cross-process roundtrip).

Both helper factories are exposed as fixtures so individual tests can
opt in without inheriting the full Postgres dependency stack.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from alembic import command, config
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from alfred.security.capability_gate.backend import PostgresBackend


@pytest.fixture
def alembic_cfg(
    postgres_url: str,
    monkeypatch: pytest.MonkeyPatch,
) -> config.Config:
    """Alembic Config pointed at the per-test container.

    Sets both the env-var and Config ``sqlalchemy.url`` so the migration
    env covers either code path; production reads
    ``ALFRED_DATABASE_URL`` from the env, tests can also pass the URL
    directly to :func:`alembic.command.upgrade` via the Config.
    """
    monkeypatch.setenv("ALFRED_DATABASE_URL", postgres_url)
    cfg = config.Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", postgres_url)
    return cfg


@pytest.fixture
def migrated_postgres(
    alembic_cfg: config.Config,
    postgres_url: str,
) -> str:
    """Upgrade the per-test container to HEAD before any backend operation.

    HEAD lands at migration 0009 today; the fixture stays HEAD-relative
    so a future migration that touches ``plugin_grants`` or
    ``capability_gate_sync`` is still exercised end-to-end. Returns the
    URL unchanged so downstream fixtures / tests can compose.
    """
    command.upgrade(alembic_cfg, "head")
    return postgres_url


@pytest.fixture
def make_audit_sink() -> Callable[[], Any]:
    """Factory producing a Protocol-compatible audit sink double.

    Returned as a callable rather than a sink instance so each test
    can build a fresh sink per call site — useful when a single test
    drives multiple gate constructions and wants to assert per-sink.

    The real :class:`AuditWriter` is exercised by
    ``test_audit_persistence.py``; here we want a structural seam
    that the proposal-flow + gate emit paths can call and we can
    assert on the call shape post-hoc.
    """

    def _factory() -> Any:
        sink = MagicMock()
        sink.append_schema = AsyncMock(return_value=None)
        return sink

    return _factory


@pytest.fixture
def backend_against() -> Callable[
    [str],
    Any,
]:
    """Return an async context manager yielding ``(PostgresBackend, factory)``.

    Disposing the engine on exit prevents open-connection leakage
    across nested ``async with`` blocks in the same test — critical
    for the proposal → apply → check sequence which builds two
    backends against the same DB to simulate the cross-process
    roundtrip.

    Returned as a callable so tests can write::

        async with backend_against(migrated_postgres) as (backend, _factory):
            ...
    """

    @asynccontextmanager
    async def _builder(
        postgres_url: str,
    ) -> AsyncIterator[tuple[PostgresBackend, async_sessionmaker[AsyncSession]]]:
        engine = create_async_engine(postgres_url, future=True)
        factory = async_sessionmaker(engine, expire_on_commit=False)
        backend = PostgresBackend(session_factory=factory)
        try:
            yield backend, factory
        finally:
            await engine.dispose()

    return _builder
