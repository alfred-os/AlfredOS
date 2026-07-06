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

PR-B Phase 6 update — the orchestrator now takes an
:class:`IdentityResolver` (cached operator at construction) rather than
literal ``operator_name`` / ``operator_language`` strings, and persists a
per-row ``language`` + ``actor_persona`` derived from the resolved user.
The setup inserts an operator + TUI binding into the per-test container so
``resolver.get_operator()`` returns a real ORM ``User``; the tests then
drive ``handle_user_message`` via the new ``user / content / working_memory``
keyword signature and assert the new attribution columns landed on the
audit row.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock

import pytest
from sqlalchemy import Engine, create_engine, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import sessionmaker
from testcontainers.postgres import PostgresContainer

from alfred.audit.log import AuditWriter
from alfred.budget.guard import BudgetGuard
from alfred.identity import (
    Authorization,
    IdentityResolver,
    IdentityVersionCounter,
    NullRateLimiter,
    Platform,
)
from alfred.identity.models import PlatformIdentity, User
from alfred.memory.models import AuditEntry, Base
from alfred.memory.working import WorkingMemory
from alfred.orchestrator.core import Orchestrator
from alfred.security.tiers import T2, tag

# Slice-2 single-operator: the smoke + integration setup mirrors what
# migration 0004 backfills (``operator`` slug, ``en-US`` language, ``tui``
# binding). Centralised here so a future change to the seed user is a
# one-line edit.
_OPERATOR_SLUG = "operator"
_OPERATOR_LANGUAGE = "en-US"
_OPERATOR_PLATFORM_ID = "operator"


def _seed_operator(sync_url: str) -> None:
    """Insert the canonical operator + TUI binding into a fresh container.

    The audit-persistence integration tests deliberately use
    ``Base.metadata.create_all`` (not ``alembic upgrade head``) to isolate
    the rollback regression from migration-shape drift. That means the
    0004 backfill that the smoke test relies on does NOT run here, so we
    insert the canonical operator row + ``(tui, operator)`` binding
    manually before constructing the resolver. Mirrors the seed shape
    migration 0004 uses so ``resolver.get_operator()`` returns the same
    structure both paths produce.
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
                    platform_id=_OPERATOR_PLATFORM_ID,
                )
            )
    finally:
        sync_engine.dispose()


def _build_resolver(sync_url: str) -> tuple[IdentityResolver, Engine]:
    """Construct an :class:`IdentityResolver` bound to the sync URL.

    Returns the resolver alongside the sync engine so the caller can
    ``dispose()`` it deterministically (CR review: avoid leaked
    connections across testcontainer lifecycles).

    The resolver uses sync sessions (docs/python-conventions.md §async); we
    build a sync engine against the same testcontainer URL the async
    orchestrator writes through. ``resolver.version_counter`` is the
    promoted-attribute contract the CLI relies on, mirrored here so the
    same lambda shape the production wiring uses works in test."""
    sync_engine = create_engine(sync_url, future=True)
    sync_factory = sessionmaker(sync_engine, expire_on_commit=False, future=True)
    version_counter = IdentityVersionCounter()
    resolver = IdentityResolver(
        session_factory=sync_factory,
        version_counter=version_counter,
        rate_limiter=NullRateLimiter(),
    )
    # Phase 1 contract: the orchestrator's resolver shares a version
    # counter with the BudgetGuard. The CLI promotes ``version_counter``
    # onto the resolver instance (typed property lands in Phase 5); we
    # mirror that here so the test wiring matches production.
    resolver.version_counter = version_counter  # type: ignore[attr-defined]
    return resolver, sync_engine


@pytest.mark.integration
async def test_provider_failure_audit_row_survives_rollback() -> None:
    """A provider exception triggers the orchestrator's outer rollback. The
    audit row must still be present because the writer uses its own session.

    PR-B Phase 6 additions: the row carries the resolved operator's
    ``language`` and ``actor_persona='alfred'``, and ``subject["phase"]``
    is the canonical English key ``"provider_call:0"`` (#339 PR3 suffixes
    the per-completion index; operator-readable even under a non-English
    operator language).
    """
    with PostgresContainer("postgres:18") as pg:
        url = pg.get_connection_url().replace("psycopg2", "asyncpg")
        engine = create_async_engine(url, future=True)
        try:
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)

            # Seed the operator + TUI binding against a sync URL so the
            # resolver can ``get_operator()``. Same physical DB; we just
            # need a sync handle to insert through the ORM.
            sync_url = url.replace("+asyncpg", "+psycopg")
            _seed_operator(sync_url)

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

            resolver, sync_engine = _build_resolver(sync_url)
            operator = resolver.get_operator()

            # PR-B BudgetGuard: per-user loader keyed on the canonical slug.
            # Headroom comfortably exceeds the would-be cost so the pre-check
            # passes and the failure lands on the provider arm.
            budget = BudgetGuard(
                user_loader=lambda user_id: resolver.show(slug=user_id),
                per_call_max_usd=0.10,
                version_counter=resolver.version_counter,  # type: ignore[attr-defined]
            )
            working = WorkingMemory()

            orch = Orchestrator(
                identity_resolver=resolver,
                session_scope=session_scope,
                router=router,
                budget=budget,
                audit_factory=lambda _f: audit,
            )

            content = tag(T2, "hi", source="test.audit_persistence")
            with pytest.raises(RuntimeError, match="upstream 503"):
                await orch.handle_user_message(
                    user=operator,
                    content=content,
                    working_memory=working,
                )

            # Open a separate session to read what survived.
            async with sm() as session:
                rows = (await session.execute(select(AuditEntry))).scalars().all()
                assert len(rows) == 1, (
                    "audit row was rolled back with the caller's txn — "
                    "AuditWriter is sharing the session, violating hard rule #7"
                )
                row = rows[0]
                assert row.result == "provider_failed"
                assert row.event == "orchestrator.turn"
                assert row.trust_tier_of_trigger == "T2"
                assert row.subject["error_type"] == "RuntimeError"
                # Subject JSONB stays operator-readable English — the
                # ``phase`` key is canonical, never translated. #339 PR3's
                # act-phase loop suffixes the per-completion index, so the
                # first (and here only) provider call is ``provider_call:0``.
                assert row.subject["phase"] == "provider_call:0"
                # PR-B per-row attribution — language matches the resolved
                # operator; actor_persona is pinned to ``alfred`` in
                # Slice 1+2 (the persona registry replaces this in Slice 5).
                assert row.language == operator.language
                assert row.actor_persona == "alfred"
        finally:
            await engine.dispose()
            sync_engine.dispose()


@pytest.mark.integration
async def test_budget_block_audit_row_survives_rollback() -> None:
    """Budget pre-check refusal also raises BudgetError, also triggers the
    outer rollback. Same invariant: the audit row must survive.

    PR-B Phase 6 additions: the row carries the resolved operator's
    ``language`` and ``actor_persona='alfred'``; ``subject["phase"]``
    stays ``"budget_pre_check"`` (canonical English key).
    """
    with PostgresContainer("postgres:18") as pg:
        url = pg.get_connection_url().replace("psycopg2", "asyncpg")
        engine = create_async_engine(url, future=True)
        try:
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)

            sync_url = url.replace("+asyncpg", "+psycopg")
            _seed_operator(sync_url)

            sm = async_sessionmaker(bind=engine, expire_on_commit=False)

            @asynccontextmanager
            async def session_scope() -> AsyncIterator[AsyncSession]:
                async with sm() as session, session.begin():
                    yield session

            audit = AuditWriter(session_factory=session_scope)

            # Budget guard with a cap so low that any pre-check estimate trips.
            # ``would_exceed`` is mocked to short-circuit to True regardless of
            # what the real guard would compute — we're testing audit-row
            # survival, not the per-user math (that's covered by the unit +
            # property suites). A MagicMock satisfies the duck-typed surface
            # the orchestrator reads.
            budget = MagicMock()
            budget.estimate_for = MagicMock(return_value=99.0)
            budget.would_exceed = MagicMock(return_value=True)

            router = MagicMock()
            router.complete = AsyncMock()

            resolver, sync_engine = _build_resolver(sync_url)
            operator = resolver.get_operator()
            working = WorkingMemory()

            orch = Orchestrator(
                identity_resolver=resolver,
                session_scope=session_scope,
                router=router,
                budget=budget,
                audit_factory=lambda _f: audit,
            )

            # BudgetError subclasses RuntimeError; match its message instead.
            from alfred.budget.guard import BudgetError

            content = tag(T2, "this would be expensive", source="test.audit_persistence")
            with pytest.raises(BudgetError, match="pre-check refused"):
                await orch.handle_user_message(
                    user=operator,
                    content=content,
                    working_memory=working,
                )

            async with sm() as session:
                rows = (await session.execute(select(AuditEntry))).scalars().all()
                assert len(rows) == 1
                row = rows[0]
                assert row.result == "budget_blocked"
                assert row.cost_actual_usd == 0.0
                # Subject JSONB phase is the canonical English key — operator
                # readable across non-English operator languages.
                assert row.subject["phase"] == "budget_pre_check"
                assert row.language == operator.language
                assert row.actor_persona == "alfred"

            # Provider was never called.
            router.complete.assert_not_awaited()
        finally:
            await engine.dispose()
            sync_engine.dispose()
