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
from sqlalchemy import create_engine, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import sessionmaker
from testcontainers.postgres import PostgresContainer

from alfred.budget.guard import BudgetGuard
from alfred.identity import (
    IdentityResolver,
    IdentityVersionCounter,
    Platform,
    _NullRateLimiter,
)
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
        # (which uses ``Base.metadata.create_all``) cannot. Migration 0004
        # backfills the operator + ``(tui, operator_name)`` binding so the
        # IdentityResolver call below resolves on a fresh stack.
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

        # Resolve the canonical operator slug via IdentityResolver. The CLI's
        # ``_chat_main`` (T15) does exactly this at startup; the smoke test
        # mirrors that wiring so the slug propagated into episode + audit
        # rows matches what production writes. We can't reuse the async
        # engine for the sync resolver, so build a sync engine against the
        # SAME testcontainer URL (psycopg driver). Both engines target the
        # same DB; the orchestrator writes through the async path and the
        # resolver reads through the sync path.
        sync_url = async_url.replace("+asyncpg", "+psycopg")
        sync_engine = create_engine(sync_url, future=True)
        sync_factory = sessionmaker(sync_engine, expire_on_commit=False, future=True)
        resolver = IdentityResolver(
            session_factory=sync_factory,
            version_counter=IdentityVersionCounter(),
            rate_limiter=_NullRateLimiter(),
        )
        operator = await asyncio.to_thread(resolver.resolve, Platform.TUI, "operator")
        assert operator is not None, (
            "migration 0004 must backfill (tui, ALFRED_OPERATOR_NAME='operator') "
            "binding — the smoke env defaults to operator_name='operator'"
        )

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
            operator_name=operator.slug,
            operator_language=operator.language,
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
                assert all(ep.language == operator.language for ep in ep_rows), (
                    "all episodes must carry the operator's BCP-47 language tag "
                    "(CLAUDE.md i18n rule #3)"
                )
                # Slice-2 identity: every episode carries the canonical slug
                # and the active persona id (T15 — migration 0004 added the
                # per-row column and the orchestrator pins ``"alfred"``).
                assert all(ep.user_id == operator.slug for ep in ep_rows)
                assert all(ep.persona_id == "alfred" for ep in ep_rows)

                audit_rows = (await session.execute(select(AuditEntry))).scalars().all()
                assert len(audit_rows) == 1, "expected exactly one audit entry per turn"
                entry = audit_rows[0]
                assert entry.result == "success"
                assert entry.language == operator.language
                assert entry.actor_user_id == operator.slug
                assert entry.persona_id == "alfred"
                # Float equality is fragile across SQL round-trip + Decimal
                # coercion; use approx with a tight relative tolerance.
                assert entry.cost_actual_usd == pytest.approx(0.00001, rel=1e-9)
                assert entry.event == "orchestrator.turn"
                # User input was tagged T2 at the orchestrator boundary.
                assert entry.trust_tier_of_trigger == "T2"
        finally:
            sync_engine.dispose()
            await engine.dispose()
