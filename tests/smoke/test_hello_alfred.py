"""End-to-end smoke test for Slice 1.

Boots a Postgres testcontainer, runs migrations via the real ``alembic
upgrade head`` command (NOT ``Base.metadata.create_all`` — using alembic is
load-bearing: a divergence between the ORM models and ``0001_initial.py``
fails this test), instantiates the full orchestrator with a mocked provider
router, drives one user turn, and asserts:

  * the orchestrator returns the assistant content
  * the ``episodes`` table received two rows (user + assistant)
  * the ``audit_log`` table received one row with ``result="success"``
  * both episodes + the audit row carry the operator's BCP-47 ``language``
  * the actual cost was reconciled into ``cost_actual_usd``

Runs in CI on every PR; never calls real LLM APIs.

Alembic config note
-------------------
``alembic/env.py`` reads its URL from ``Settings().database_url`` rather than
from ``alembic.ini``'s ``sqlalchemy.url``. So passing
``alembic_cfg.set_main_option("sqlalchemy.url", ...)`` would be silently
ignored. The smoke test overrides ``ALFRED_DATABASE_URL`` (and
``ALFRED_DEEPSEEK_API_KEY``, which ``Settings`` requires) via ``monkeypatch``
for the duration of the test instead. asyncpg is fine here — env.py uses
``async_engine_from_config`` for online migrations, which expects an async
driver URL.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from testcontainers.postgres import PostgresContainer

from alfred.budget.guard import BudgetGuard
from alfred.memory.models import AuditEntry, Episode
from alfred.memory.working import WorkingMemory
from alfred.orchestrator.core import Orchestrator
from alfred.providers.base import CompletionResponse


@pytest.mark.smoke
async def test_alfred_handles_one_turn_end_to_end(monkeypatch: pytest.MonkeyPatch) -> None:
    """One full turn through real Postgres + real migrations."""
    with PostgresContainer("postgres:16") as pg:
        # testcontainers returns a psycopg2 URL by default; convert to asyncpg
        # for SQLAlchemy's async engine, and override the Settings env vars
        # alembic/env.py reads from (env.py uses Settings().database_url, not
        # alembic.ini's sqlalchemy.url — see module docstring).
        async_url = pg.get_connection_url().replace("psycopg2", "asyncpg")
        monkeypatch.setenv("ALFRED_DATABASE_URL", async_url)
        monkeypatch.setenv(
            "ALFRED_DEEPSEEK_API_KEY",
            "not-a-real-secret-smoke-test-placeholder",
        )

        # Run migrations via the real alembic command. ``alembic.command.upgrade``
        # is itself sync, but env.py's online runner calls ``asyncio.run()`` —
        # which raises RuntimeError when invoked from inside pytest-asyncio's
        # already-running event loop. Run the whole alembic call on a worker
        # thread so it gets its own loop. Using the real CLI behaviour here is
        # load-bearing: it catches ORM-vs-migration drift the integration test
        # (which uses ``Base.metadata.create_all``) cannot.
        alembic_cfg = Config("alembic.ini")
        await asyncio.to_thread(command.upgrade, alembic_cfg, "head")

        engine = create_async_engine(async_url, future=True)
        sm = async_sessionmaker(bind=engine, expire_on_commit=False)

        @asynccontextmanager
        async def session_scope() -> AsyncIterator[AsyncSession]:
            # session.begin() commits on clean exit, rollbacks on exception.
            # Load-bearing: the orchestrator does not call commit itself —
            # it relies on the scope to persist writes.
            async with sm() as session, session.begin():
                yield session

        working = WorkingMemory()
        # Budget headroom comfortably exceeds the mocked cost so the pre-check
        # passes and no overrun-result branch fires.
        budget = BudgetGuard(daily_usd=1.0, per_call_max_usd=0.10)

        router = MagicMock()
        router.complete = AsyncMock(
            return_value=CompletionResponse(
                content="Good evening, operator.",
                tokens_in=12,
                tokens_out=5,
                cost_usd=0.00001,
                model="deepseek-chat",
            )
        )

        orch = Orchestrator(
            operator_name="operator",
            operator_language="en-US",
            session_scope=session_scope,
            working=working,
            router=router,
            budget=budget,
        )

        try:
            response = await orch.handle_user_message("hi alfred")
            assert response == "Good evening, operator."

            # Re-open a fresh session to verify what was persisted — using the
            # same session_scope would leak the orchestrator's commit context
            # and read its own pending writes.
            async with sm() as session:
                ep_rows = (await session.execute(select(Episode))).scalars().all()
                assert len(ep_rows) == 2, "expected user + assistant episodes"
                assert {r.role for r in ep_rows} == {"user", "assistant"}
                assert all(ep.language == "en-US" for ep in ep_rows), (
                    "all episodes must carry the operator's BCP-47 language tag "
                    "(CLAUDE.md i18n rule #3)"
                )

                audit_rows = (await session.execute(select(AuditEntry))).scalars().all()
                assert len(audit_rows) == 1, "expected exactly one audit entry per turn"
                entry = audit_rows[0]
                assert entry.result == "success"
                assert entry.language == "en-US"
                assert entry.cost_actual_usd == 0.00001
                assert entry.event == "orchestrator.turn"
                # User input was tagged T2 at the orchestrator boundary.
                assert entry.trust_tier_of_trigger == "T2"
        finally:
            await engine.dispose()
