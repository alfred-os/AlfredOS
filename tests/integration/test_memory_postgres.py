"""Integration test: schema migrates cleanly against real Postgres."""

from __future__ import annotations

import pytest
from sqlalchemy import inspect
from sqlalchemy.ext.asyncio import create_async_engine
from testcontainers.postgres import PostgresContainer

from alfred.memory.models import Base


@pytest.mark.integration
async def test_schema_creates_episodes_and_audit_log() -> None:
    with PostgresContainer("postgres:16") as pg:
        url = pg.get_connection_url().replace("psycopg2", "asyncpg")
        engine = create_async_engine(url, future=True)
        # try/finally so engine.dispose() always runs, even if create_all or
        # inspection raises. Otherwise a failing schema change leaks a
        # connection pool to whichever container the test runner reuses
        # next, and the failure cascade hides the real assertion.
        try:
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
                tables = await conn.run_sync(lambda c: inspect(c).get_table_names())
        finally:
            await engine.dispose()
        assert "episodes" in tables
        assert "audit_log" in tables
