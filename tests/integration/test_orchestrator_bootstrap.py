"""Integration: ``build_orchestrator`` assembles a real, drivable orchestrator.

PR-S4-11c-1 is the first PR of the Slice-4 graduation closer (#237). Before
it, ``Orchestrator(`` was constructed NOWHERE in ``src/`` — only in tests.
This test is the load-bearing e2e proof that ``build_orchestrator`` produces a
fully-wired orchestrator from ``Settings`` alone: it constructs the full
dependency graph against a real Postgres testcontainer + real migrations, then
drives one turn through the exact shape the TUI adapter uses (acquire pool →
tag T2 → ``handle_user_message`` → release) and asserts a non-empty assistant
reply.

The provider router is the ONLY mocked dependency (no real LLM call, per
CLAUDE.md test rules): we monkeypatch ``_bootstrap.build_router`` so the
internally-assembled router is a recorded ``AsyncMock``. Everything else —
resolver, session scope, budget guard, working-memory pool, audit writer — is
the real production object the builder wires.

Postgres setup mirrors ``tests/integration/test_audit_persistence.py``:
``Base.metadata.create_all`` + a manual operator/TUI-binding seed (the
audit-persistence path, isolated from migration-shape drift). The smoke test
covers the alembic-upgrade path separately.

``build_orchestrator`` reads its DB URL + API key from ``Settings``; we point
those at the testcontainer via ``monkeypatch.setenv`` for the test's duration.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.orm import sessionmaker
from testcontainers.postgres import PostgresContainer

from alfred.cli import _bootstrap
from alfred.config.settings import Settings
from alfred.identity import Authorization, Platform
from alfred.identity.models import PlatformIdentity, User
from alfred.memory.models import AuditEntry, Base, Episode
from alfred.orchestrator.core import Orchestrator
from alfred.providers.base import CompletionResponse
from alfred.security.tiers import T2, tag

_OPERATOR_SLUG = "operator"
_OPERATOR_LANGUAGE = "en-US"


def _seed_operator(sync_url: str) -> None:
    """Insert the canonical operator + TUI binding into a fresh container.

    Mirrors what migration 0004 backfills so ``resolver.get_operator()`` (the
    builder wires the real resolver) resolves on a freshly-created schema.
    """
    sync_engine = create_engine(sync_url, future=True)
    try:
        sync_factory = sessionmaker(sync_engine, expire_on_commit=False, future=True)
        with sync_factory.begin() as session:
            user = User(
                slug=_OPERATOR_SLUG,
                display_name=_OPERATOR_SLUG,
                authorization=Authorization.OPERATOR.value,
                daily_budget_usd=5.0,
                language=_OPERATOR_LANGUAGE,
            )
            session.add(user)
            session.flush()
            session.add(
                PlatformIdentity(
                    user_id=user.id,
                    platform=Platform.TUI.value,
                    platform_id=_OPERATOR_SLUG,
                )
            )
    finally:
        sync_engine.dispose()


@pytest.fixture
def recorded_router() -> MagicMock:
    """A provider router whose ``complete`` returns a fixed recorded response.

    No real LLM call — the recorded reply stands in for the routed provider.
    """
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
    return router


@pytest.mark.integration
async def test_build_orchestrator_drives_one_turn(
    monkeypatch: pytest.MonkeyPatch, recorded_router: MagicMock
) -> None:
    """``build_orchestrator`` → full graph → one real turn → non-empty reply."""
    with PostgresContainer("postgres:18") as pg:
        async_url = pg.get_connection_url().replace("psycopg2", "asyncpg")
        sync_url = async_url.replace("+asyncpg", "+psycopg")

        # The builder reads the DB URL + a (placeholder) API key from Settings.
        # ``environment`` is a required Settings field with no default; pin it
        # to ``test`` the way the other integration/smoke tests do.
        monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
        monkeypatch.setenv("ALFRED_DATABASE_URL", async_url)
        monkeypatch.setenv(
            "ALFRED_DEEPSEEK_API_KEY",
            "not-a-real-secret-bootstrap-test-placeholder",
        )

        # Create the schema (audit-persistence path; alembic is the smoke
        # test's job) and seed the operator the resolver will cache.
        engine = create_async_engine(async_url, future=True)
        try:
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
        finally:
            await engine.dispose()
        _seed_operator(sync_url)

        # The ONLY mocked seam: the internally-assembled provider router.
        # Patch at the point ``build_orchestrator`` calls it so the real
        # broker/router plumbing is bypassed without a live API key.
        monkeypatch.setattr(_bootstrap, "build_router", lambda _broker, _settings: recorded_router)

        settings = Settings()  # type: ignore[call-arg]  # reason: Settings.__init__ is untyped pending task-17
        orch = _bootstrap.build_orchestrator(settings, quarantined_extractor=None)
        assert isinstance(orch, Orchestrator)

        # Seam guard — PR-S4-11c-2 wires a REAL quarantined extractor THROUGH
        # this exact parameter, so a silent param-drop in build_orchestrator
        # would be an uncaught trust-boundary hole no other test sees. Pin both
        # the None default and verbatim forwarding of an injected value.
        assert orch._quarantined_extractor is None
        _extractor_sentinel = object()
        orch_with_extractor = _bootstrap.build_orchestrator(
            settings,
            quarantined_extractor=_extractor_sentinel,  # type: ignore[arg-type]  # reason: sentinel — __init__ stores it verbatim with no construction-time validation
        )
        assert orch_with_extractor._quarantined_extractor is _extractor_sentinel

        # Build the pool the same way the adapter does — the builder owns its
        # wiring; the adapter brackets acquire/release around the turn.
        pool = _bootstrap.build_working_memory_pool(
            settings,
            episodic_factory=_bootstrap._episodic_factory,
            session_scope=_bootstrap.build_session_scope(settings),
        )

        # The builder resolved + cached the operator from the seeded DB. We
        # read the private ``_operator`` deliberately: it is the construction-
        # time cache, so asserting it proves the builder wired a resolver that
        # resolved the seeded operator AT __init__ — a re-resolving public
        # ``get_operator()`` would not distinguish that from a broken cache.
        operator = orch._operator
        assert operator.slug == _OPERATOR_SLUG

        content = tag(T2, "hi alfred", source="bootstrap.integration")
        key = ("alfred", _OPERATOR_SLUG)
        wm = await pool.acquire(key)
        try:
            response = await orch.handle_user_message(
                user=operator,
                content=content,
                working_memory=wm,
            )
        finally:
            await pool.release(key, wm)

        assert isinstance(response, str)
        assert response == "Good evening, operator."

        # Persistence proof: the real session_scope the builder wired
        # committed the turn's episodes + audit row.
        verify_engine = create_async_engine(async_url, future=True)
        try:
            verify_sm = async_sessionmaker(bind=verify_engine, expire_on_commit=False)
            async with verify_sm() as session:
                ep_rows = (await session.execute(select(Episode))).scalars().all()
                assert {r.role for r in ep_rows} == {"user", "assistant"}
                audit_rows = (await session.execute(select(AuditEntry))).scalars().all()
                assert len(audit_rows) == 1
                assert audit_rows[0].result == "success"
        finally:
            await verify_engine.dispose()
