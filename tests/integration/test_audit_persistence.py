"""Integration: audit rows survive caller-transaction rollback.

Regression coverage for CLAUDE.md hard rule #7 ("no silent failures in
security paths"). The orchestrator opens a per-turn user-content transaction
and rolls it back on any exception. The audit writer MUST use its own
session/transaction so its row survives the caller's rollback — otherwise a
failed turn (provider error, budget block) leaves no trace, which is the
exact silent-security-failure the rule forbids.

These tests construct the **real** ``AuditWriter`` against a Postgres
testcontainer, drive failing turns through the **real** ``Orchestrator``,
and assert that the audit table holds exactly the expected row after the
caller's rollback fired.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from testcontainers.postgres import PostgresContainer

from alfred.audit.log import AuditWriter
from alfred.budget.guard import BudgetGuard
from alfred.memory.models import AuditEntry, Base
from alfred.memory.working import WorkingMemory
from alfred.orchestrator.core import Orchestrator


@pytest.mark.integration
async def test_provider_failure_audit_row_survives_rollback() -> None:
    """A provider exception triggers the orchestrator's outer rollback. The
    audit row must still be present because the writer uses its own session.
    """
    with PostgresContainer("postgres:16") as pg:
        url = pg.get_connection_url().replace("psycopg2", "asyncpg")
        engine = create_async_engine(url, future=True)
        try:
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)

            sm = async_sessionmaker(bind=engine, expire_on_commit=False)

            @asynccontextmanager
            async def session_scope() -> AsyncIterator[AsyncSession]:
                # session.begin() commits on clean exit, rolls back on
                # exception. Matches production session_scope semantics so
                # the regression coverage is faithful.
                async with sm() as session, session.begin():
                    yield session

            # Real AuditWriter wired through session_scope — owns its own txn.
            audit = AuditWriter(session_factory=session_scope)

            router = MagicMock()
            router.complete = AsyncMock(side_effect=RuntimeError("upstream 503"))

            budget = BudgetGuard(daily_usd=1.0, per_call_max_usd=0.10)
            working = WorkingMemory()

            orch = Orchestrator(
                operator_name="operator",
                operator_language="en-US",
                session_scope=session_scope,
                working=working,
                router=router,
                budget=budget,
                audit_factory=lambda _f: audit,
            )

            with pytest.raises(RuntimeError, match="upstream 503"):
                await orch.handle_user_message("hi")

            # Open a separate session to read what survived.
            async with sm() as session:
                rows = (await session.execute(select(AuditEntry))).scalars().all()
                assert len(rows) == 1, (
                    "audit row was rolled back with the caller's txn — "
                    "AuditWriter is sharing the session, violating hard rule #7"
                )
                assert rows[0].result == "provider_failed"
                assert rows[0].event == "orchestrator.turn"
                assert rows[0].trust_tier_of_trigger == "T2"
                assert rows[0].subject["error_type"] == "RuntimeError"
        finally:
            await engine.dispose()


@pytest.mark.integration
async def test_budget_block_audit_row_survives_rollback() -> None:
    """Budget pre-check refusal also raises BudgetError, also triggers the
    outer rollback. Same invariant: the audit row must survive.
    """
    with PostgresContainer("postgres:16") as pg:
        url = pg.get_connection_url().replace("psycopg2", "asyncpg")
        engine = create_async_engine(url, future=True)
        try:
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)

            sm = async_sessionmaker(bind=engine, expire_on_commit=False)

            @asynccontextmanager
            async def session_scope() -> AsyncIterator[AsyncSession]:
                async with sm() as session, session.begin():
                    yield session

            audit = AuditWriter(session_factory=session_scope)

            # Budget guard with a cap so low that any pre-check estimate trips.
            # estimate_for() returns the request's token-derived estimate; a
            # per-call cap of 0 forces ``would_exceed`` to fire even on a
            # one-byte request. daily_usd=0 doubles up the constraint.
            budget = MagicMock()
            budget.estimate_for = MagicMock(return_value=99.0)
            budget.would_exceed = MagicMock(return_value=True)

            router = MagicMock()
            router.complete = AsyncMock()

            working = WorkingMemory()

            orch = Orchestrator(
                operator_name="operator",
                operator_language="en-US",
                session_scope=session_scope,
                working=working,
                router=router,
                budget=budget,
                audit_factory=lambda _f: audit,
            )

            # BudgetError subclasses RuntimeError; match its message instead.
            from alfred.budget.guard import BudgetError

            with pytest.raises(BudgetError, match="pre-check refused"):
                await orch.handle_user_message("this would be expensive")

            async with sm() as session:
                rows = (await session.execute(select(AuditEntry))).scalars().all()
                assert len(rows) == 1
                assert rows[0].result == "budget_blocked"
                assert rows[0].cost_actual_usd == 0.0
                assert rows[0].subject["phase"] == "budget_pre_check"

            # Provider was never called.
            router.complete.assert_not_awaited()
        finally:
            await engine.dispose()
