"""#410 PR1: integration engines are pool-starved BY DEFAULT.

With pool_size=2 / max_overflow=0 / pool_timeout=5 on every shared
integration engine, any test that reintroduces hold-and-wait (holding one
connection while demanding another beyond the pool) fails LOUDLY with a
SQLAlchemy TimeoutError within seconds — every boot-graph integration test
becomes an incidental deadlock detector. The opt-out is a standard pytest
fixture override at a narrower scope, demonstrated below.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.exc import TimeoutError as SaTimeoutError
from sqlalchemy.ext.asyncio import AsyncEngine

pytestmark = pytest.mark.integration


async def test_default_integration_pool_is_the_starvation_shape(
    pg_engine: AsyncEngine,
) -> None:
    assert pg_engine.pool.size() == 2


async def test_third_concurrent_hold_fails_loud_within_pool_timeout(
    pg_engine: AsyncEngine,
) -> None:
    conn_a = await pg_engine.connect()
    conn_b = await pg_engine.connect()
    try:
        await conn_a.execute(text("SELECT 1"))
        await conn_b.execute(text("SELECT 1"))
        with pytest.raises(SaTimeoutError):
            async with asyncio.timeout(30):  # the pool_timeout (5s) fires well inside
                conn_c = await pg_engine.connect()
                await conn_c.close()  # pragma: no cover — checkout must have raised
    finally:
        await conn_a.close()
        await conn_b.close()


class TestOptOut:
    """The documented opt-out: override the fixture at a narrower scope."""

    @pytest.fixture
    def integration_pool_kwargs(self) -> dict[str, Any]:
        return {"pool_size": 5, "max_overflow": 0, "pool_timeout": 10}

    async def test_override_reaches_the_engine(self, pg_engine: AsyncEngine) -> None:
        assert pg_engine.pool.size() == 5
