"""Burst-limiter hard-drop emits comms.inbound.dropped against real Postgres (Task 55).

Drives the REAL :class:`BurstLimiter` through a real :class:`AuditWriter` backed
by a Postgres testcontainer. A deterministic injected clock makes the projected
wait exceed ``drop_after_seconds`` so the hard-drop path fires without sleeping
35 wall-clock seconds:

* a burst drains the bucket -> ``COMMS_INBOUND_BUDGET_CAPPED`` rows accumulate;
* once the projected wait exceeds the drop ceiling the acquire returns
  ``Dropped`` with ``dropped=True`` and a ``comms.inbound.dropped`` audit row;
* the limiter keeps accepting traffic afterward (no wedge).

The drop trigger is ``wait_seconds > drop_after_seconds``; with
``refill_seconds=60`` a single-token deficit projects a 60s wait, exceeding the
30s ceiling, so the bucket-empty drop fires deterministically.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from alfred.audit.log import AuditWriter
from alfred.memory.models import AuditEntry, Base
from alfred.orchestrator.burst_limiter import Acquired, BurstLimiter, Dropped

pytestmark = pytest.mark.integration


class _FakeClock:
    """A monotonic clock the test advances by hand (no wall sleeping)."""

    def __init__(self) -> None:
        self._t = 0.0

    def __call__(self) -> float:
        return self._t

    def advance(self, seconds: float) -> None:
        self._t += seconds


async def _noop_sleep(_seconds: float) -> None:
    return None


async def _rows_with_event(sm: async_sessionmaker[AsyncSession], event: str) -> list[AuditEntry]:
    async with sm() as session:
        result = await session.execute(select(AuditEntry).where(AuditEntry.event == event))
        return list(result.scalars().all())


async def test_burst_drains_then_drops_then_recovers(postgres_url: str) -> None:
    engine = create_async_engine(postgres_url, future=True)
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        sm = async_sessionmaker(bind=engine, expire_on_commit=False)

        @asynccontextmanager
        async def session_scope() -> AsyncIterator[AsyncSession]:
            async with sm() as session, session.begin():
                yield session

        audit = AuditWriter(session_factory=session_scope)
        clock = _FakeClock()
        limiter = BurstLimiter(
            capacity_tokens=3,
            refill_seconds=60.0,
            drop_after_seconds=30.0,
            audit_writer=audit,
            monotonic=clock,
            sleep=_noop_sleep,
        )

        # Drain the 3-token capacity — all fast-path acquires.
        for _ in range(3):
            result = await limiter.acquire(canonical_user_id="alice", persona="alfred")
            assert isinstance(result, Acquired)
            assert result.waited_seconds == 0.0

        # The 4th acquire: the bucket is empty, the projected wait (60s) exceeds
        # the 30s drop ceiling -> hard drop.
        dropped = await limiter.acquire(canonical_user_id="alice", persona="alfred")
        assert isinstance(dropped, Dropped)

        # A comms.inbound.dropped audit row + a budget_capped(dropped=True) row.
        dropped_rows = await _rows_with_event(sm, "comms.inbound.dropped")
        assert len(dropped_rows) == 1
        assert dropped_rows[0].result == "dropped"

        capped_rows = await _rows_with_event(sm, "comms.inbound.budget_capped")
        assert any(r.subject.get("dropped") is True for r in capped_rows)

        # After enough refill time the limiter recovers — no wedge.
        clock.advance(120.0)  # 2 tokens refilled at 60s each
        recovered = await limiter.acquire(canonical_user_id="alice", persona="alfred")
        assert isinstance(recovered, Acquired)

        # A different user's bucket is independent — never depleted by alice.
        other = await limiter.acquire(canonical_user_id="bob", persona="alfred")
        assert isinstance(other, Acquired)
    finally:
        await engine.dispose()
