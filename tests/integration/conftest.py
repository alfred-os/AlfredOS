"""Integration-test fixtures shared across ``tests/integration/``.

Spins up a single Postgres testcontainer per test function (cheap enough at
~5s startup; isolates each migration scenario from siblings) and yields the
URL + a sync ``Engine``.

Sync because Alembic's command-line helpers (``alembic.command.upgrade`` etc.)
operate on a sync connection. The production ``env.py`` runs async via
``async_engine_from_config`` + ``run_sync``, which means ``command.upgrade``
*itself* uses asyncpg under the hood — but the tests want plain
``with engine.begin() as conn: conn.execute(text(...))`` to assert
post-migration state, which is sync-shaped and natural with a sync engine.
``psycopg2-binary`` is dev-only; the runtime never sees it.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from sqlalchemy import Engine, create_engine
from testcontainers.postgres import PostgresContainer


@pytest.fixture
def postgres_url() -> Iterator[str]:
    """Yield a fresh Postgres container's connection URL for one test.

    testcontainers' default URL is ``postgresql+psycopg2://…``. We rewrite
    to ``postgresql+asyncpg://…`` because that's what the migration
    ``env.py`` expects to consume from ``ALFRED_DATABASE_URL`` (it builds an
    async engine). Tests that need a sync handle use ``postgres_engine``
    below, which builds its own psycopg2-backed engine from the raw URL.
    """
    with PostgresContainer("postgres:16") as pg:
        url = pg.get_connection_url().replace("psycopg2", "asyncpg")
        yield url


@pytest.fixture
def postgres_engine(postgres_url: str) -> Iterator[Engine]:
    """Yield a sync SQLAlchemy Engine bound to the per-test Postgres container.

    Rewrites the asyncpg URL back to psycopg2 for the sync engine — the
    migration env consumes ``postgres_url`` (asyncpg), the tests use this
    sync engine for inspecting / inserting rows around the migration calls.
    """
    sync_url = postgres_url.replace("asyncpg", "psycopg2")
    engine = create_engine(sync_url, future=True)
    try:
        yield engine
    finally:
        engine.dispose()
