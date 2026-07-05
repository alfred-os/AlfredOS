"""Integration test: 3 quarantined-LLM crashes within 5 min trip the breaker to OPEN.

Spec §10.2 + §10.6. Uses testcontainers for real Postgres so the
DB-side state-persistence round-trip is exercised against the actual
engine that ships in production (not an in-memory fake).

Three scenarios pinned end-to-end:

1. **Trip + persist**. Three ``record_failure`` calls inside the
   failure window transition CLOSED → OPEN, the new state is persisted
   via ``save_to_db``, a fresh ``CircuitBreaker`` then loaded with
   ``last_trip_at`` < 1h ago stays OPEN, and a fourth dispatch raises
   :class:`QuarantinedUnavailable` from ``assert_available``. This is
   the headline contract spec §10.2 expects from the supervised
   quarantined-LLM (PR-S3-3b §10.6 — flap protection on rolling
   restarts).
2. **Re-arm window**. Loading 2h after the trip transitions the breaker
   to HALF_OPEN automatically. The 1h re-arm window is the spec §10.6
   default; the re-arm path is the only safe way to return from OPEN
   without operator intervention.
3. **Operator reset persists**. ``reset()`` flips OPEN→CLOSED;
   ``save_to_db`` persists; a fresh breaker loads CLOSED and preserves
   ``trip_count`` (cumulative audit counter — see ``reset()`` docstring
   on why it is not zeroed on operator override).

Per the integration tier's discipline (CLAUDE.md hard rule:
"Integration tests use real Postgres ... via testcontainers; LLM
responses are recorded fixtures except in tests/smoke/"), the breaker's
``save_to_db`` / ``load_from_db`` paths run against the real engine.
The session_scope on the breaker stays ``None`` because the test owns
the session directly — production wires the orchestrator's
``build_session_scope`` factory in.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import AsyncIterator

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from testcontainers.postgres import PostgresContainer

from alfred.memory.models import Base
from alfred.supervisor.breaker import BreakerState, CircuitBreaker
from alfred.supervisor.errors import QuarantinedUnavailable

pytestmark = pytest.mark.integration


@pytest.fixture
async def async_session() -> AsyncIterator[AsyncSession]:
    """Yield a per-test ``AsyncSession`` bound to a fresh Postgres container.

    Per-test (not per-module) container: each scenario gets a clean
    ``circuit_breakers`` table so a previous test's persisted state
    cannot leak into the next test's load path. The 5s container startup
    is the price of isolation — without it, the load-back assertions
    here would silently green on the prior test's row.

    ``Base.metadata.create_all`` rather than alembic upgrade for the same
    reason ``memory/conftest.py`` does it: this test is about the breaker
    contract, not migration shape. The migration-specific integration
    test (``test_migration_0010_round_trip.py``) covers the alembic axis
    separately.
    """
    with PostgresContainer("postgres:18") as pg:
        url = pg.get_connection_url().replace("psycopg2", "asyncpg")
        engine = create_async_engine(url, echo=False)
        try:
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            sm = async_sessionmaker(bind=engine, expire_on_commit=False)
            async with sm() as session:
                yield session
        finally:
            await engine.dispose()


async def test_three_failures_trip_and_persist(async_session: AsyncSession) -> None:
    """Three failures inside the window trip the breaker and persist OPEN state.

    The fourth ``assert_available`` call raises ``QuarantinedUnavailable``
    immediately on the freshly-loaded breaker — the operator-facing
    contract that "a tripped breaker stays tripped across a restart"
    (spec §10.6).
    """
    cb = CircuitBreaker(component_id="quarantined-llm", session_scope=None)
    base = dt.datetime(2026, 1, 1, 12, 0, 0, tzinfo=dt.UTC)
    for i in range(3):
        cb.record_failure(
            "SubprocessExitedError",
            now=base + dt.timedelta(seconds=i * 60),
        )
    assert cb.state == BreakerState.OPEN
    assert cb.trip_count == 1

    await cb.save_to_db(async_session)
    await async_session.commit()

    # Fresh breaker simulates a restart; load 30 min after the trip so
    # the re-arm window has NOT elapsed and OPEN persists.
    cb2 = CircuitBreaker(component_id="quarantined-llm", session_scope=None)
    await cb2.load_from_db(async_session, now=base + dt.timedelta(minutes=30))
    assert cb2.state == BreakerState.OPEN
    assert cb2.trip_count == 1

    with pytest.raises(QuarantinedUnavailable):
        cb2.assert_available()


async def test_restart_after_1h_rearms_breaker(async_session: AsyncSession) -> None:
    """Loading 2h after a trip transitions OPEN → HALF_OPEN automatically.

    Pins ``load_from_db``'s spec §10.6 re-arm arm: the re-arm window has
    elapsed by the time the supervisor loads, so the next probe dispatch
    is allowed through (HALF_OPEN is intentionally permissive — see
    ``assert_available`` docstring).
    """
    cb = CircuitBreaker(component_id="quarantined-llm-b", session_scope=None)
    base = dt.datetime(2026, 1, 1, 12, 0, 0, tzinfo=dt.UTC)
    for i in range(3):
        cb.record_failure(
            "SubprocessExitedError",
            now=base + dt.timedelta(seconds=i * 60),
        )
    await cb.save_to_db(async_session)
    await async_session.commit()

    cb2 = CircuitBreaker(component_id="quarantined-llm-b", session_scope=None)
    await cb2.load_from_db(async_session, now=base + dt.timedelta(hours=2))
    assert cb2.state == BreakerState.HALF_OPEN


async def test_supervisor_reset_persists_and_preserves_trip_count(
    async_session: AsyncSession,
) -> None:
    """Operator-triggered reset flips OPEN → CLOSED and is preserved on reload.

    ``trip_count`` survives the reset (cumulative audit counter —
    operators rely on it to see "this component has tripped N times
    across its lifetime" on the dashboard).
    """
    cb = CircuitBreaker(component_id="quarantined-llm-c", session_scope=None)
    cb.state = BreakerState.OPEN
    cb.trip_count = 2
    cb.last_trip_at = dt.datetime(2026, 1, 1, 12, 0, 0, tzinfo=dt.UTC)
    await cb.save_to_db(async_session)
    await async_session.commit()

    cb.reset()
    await cb.save_to_db(async_session)
    await async_session.commit()

    cb2 = CircuitBreaker(component_id="quarantined-llm-c", session_scope=None)
    await cb2.load_from_db(async_session)
    assert cb2.state == BreakerState.CLOSED
    assert cb2.trip_count == 2  # cumulative — preserved across reset
