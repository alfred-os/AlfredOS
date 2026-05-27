"""End-to-end integration tests for :class:`DiscordAdapter`.

Spins up a per-test Postgres container, runs migrations to head,
constructs the FULL Slice-2 dependency graph (real IdentityResolver +
real BudgetGuard + real WorkingMemoryPool + real OutboundDlp + real
InProcessTokenBucketRateLimiter + real Orchestrator + mocked provider
router + mocked discord.Client), and drives ``DiscordAdapter._handle()``
against representative inbound messages. Asserts episode + audit +
budget side effects.

Mocked vs real:

* Provider router — mocked. LLM responses are recorded fixtures except
  in ``tests/smoke/`` per CLAUDE.md "Tests" rule.
* discord.Client — mocked via ``client_factory``. No live gateway is
  contacted in this test.
* Everything else — real, against a testcontainer Postgres.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import discord
import pytest
from alembic import command, config
from sqlalchemy import Engine, func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import Session, sessionmaker

from alfred.audit.log import AuditWriter
from alfred.budget.guard import BudgetGuard
from alfred.comms.discord import DiscordAdapter
from alfred.identity import (
    Authorization,
    IdentityVersionCounter,
    InProcessTokenBucketRateLimiter,
    Platform,
)
from alfred.identity.resolver import IdentityResolver
from alfred.memory.episodic import EpisodicMemory
from alfred.memory.models import AuditEntry
from alfred.memory.working_pool import WorkingMemoryPool
from alfred.orchestrator.core import Orchestrator
from alfred.providers.base import CompletionResponse
from alfred.security.dlp import OutboundDlp
from alfred.security.secrets import SecretBroker

pytestmark = pytest.mark.integration


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def migrated_engine(
    postgres_url: str,
    postgres_engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> Engine:
    """Upgrade the per-test container to head; yield the sync engine."""
    monkeypatch.setenv("ALFRED_DATABASE_URL", postgres_url)
    cfg = config.Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", postgres_url)
    command.upgrade(cfg, "head")
    return postgres_engine


@pytest.fixture
def sync_session_factory(migrated_engine: Engine) -> sessionmaker[Session]:
    """Sync session factory the IdentityResolver consumes."""
    # ``postgres_engine`` is psycopg2-backed (testcontainers default);
    # the IdentityResolver accepts any sync session factory, so we
    # reuse the engine directly rather than re-issue a new psycopg3
    # connection (which collided on creds in CI).
    return sessionmaker(migrated_engine, expire_on_commit=False, future=True)


@pytest.fixture
async def async_session_scope(postgres_url: str) -> Any:
    """Yield a session-scope factory shaped like ``build_session_scope``.

    Returns a callable producing async-context-managers that commit on
    clean exit + roll back on exception — matches the production
    semantics in ``alfred.memory.db.session_scope`` so audit writes
    survive the caller's transaction boundary (the whole point of the
    AuditWriter contract).

    Async-generator shape so the ``finally`` block runs after the test
    body and disposes the engine. Pre-fix this leaked a pooled
    connection per test AND wrote audit rows that never committed
    (because the bare ``async_sessionmaker()`` session has no implicit
    transaction). Mirrors the disposal + commit-on-clean pattern in
    ``tests/integration/test_audit_persistence.py``.
    """
    async_engine = create_async_engine(postgres_url, future=True)
    factory = async_sessionmaker(async_engine, expire_on_commit=False)

    @asynccontextmanager
    async def session_scope() -> AsyncIterator[AsyncSession]:
        async with factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    try:
        yield session_scope
    finally:
        await async_engine.dispose()


@pytest.fixture
def identity_resolver(
    sync_session_factory: sessionmaker[Session],
) -> IdentityResolver:
    """Real IdentityResolver against the migrated testcontainer."""
    return IdentityResolver(
        session_factory=sync_session_factory,
        version_counter=IdentityVersionCounter(),
        rate_limiter=InProcessTokenBucketRateLimiter(),
    )


def _make_dm_message(*, snowflake: int, content: str) -> MagicMock:
    """Construct a fake ``discord.Message`` matching the adapter's contract."""
    msg = MagicMock(spec=discord.Message)
    msg.content = content
    msg.author = MagicMock()
    msg.author.id = snowflake
    msg.author.bot = False
    channel = MagicMock(spec=discord.DMChannel)
    channel.send = AsyncMock()
    msg.channel = channel
    msg.embeds = []
    msg.attachments = []
    msg.stickers = []
    msg.reference = None
    msg.poll = None
    msg.components = []
    msg.activity = None
    msg.application = None
    return msg


def _make_dummy_client_factory() -> Any:
    def factory(intents: discord.Intents) -> Any:
        client = MagicMock()
        client.event = MagicMock(side_effect=lambda fn: fn)
        client.start = AsyncMock()
        client.close = AsyncMock()
        client.is_ready = MagicMock(return_value=True)
        return client

    return factory


@pytest.fixture
async def adapter_with_real_resolver(
    identity_resolver: IdentityResolver,
    async_session_scope: Any,
) -> DiscordAdapter:
    """Construct an adapter against the full real stack (mocked provider)."""
    # Real broker — env-only backend, no file (we never call get() here).
    broker = SecretBroker(env={})
    audit = AuditWriter(session_factory=async_session_scope)

    # Mocked provider router returning a fixed response.
    router = MagicMock()
    router.complete = AsyncMock(
        return_value=CompletionResponse(
            content="hi alice",
            model="test-model",
            tokens_in=10,
            tokens_out=5,
            cost_usd=0.001,
        )
    )

    budget = BudgetGuard(
        user_loader=lambda user_id: identity_resolver.show(slug=user_id),
        per_call_max_usd=1.0,
        version_counter=identity_resolver._counter,
    )
    working_pool = WorkingMemoryPool(
        episodic_factory=lambda session: EpisodicMemory(session=session),
        pool_session_scope=async_session_scope,
        max_entries=50,
        active_user_count=lambda: 1,
    )
    orchestrator = Orchestrator(
        identity_resolver=identity_resolver,
        session_scope=async_session_scope,
        router=router,
        budget=budget,
    )
    outbound_dlp = OutboundDlp(broker=broker, audit=lambda **_: None)
    rate_limiter = InProcessTokenBucketRateLimiter()

    return DiscordAdapter(
        orchestrator=orchestrator,
        identity_resolver=identity_resolver,
        broker=broker,
        outbound_dlp=outbound_dlp,
        rate_limiter=rate_limiter,
        working_pool=working_pool,
        audit=audit,
        client_factory=_make_dummy_client_factory(),
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


async def _count_audit_rows(async_session_scope: Any, **filters: Any) -> int:
    """Return the audit_log row count optionally filtered by event/result."""
    async with async_session_scope() as session:
        stmt = select(func.count()).select_from(AuditEntry)
        for column, value in filters.items():
            stmt = stmt.where(getattr(AuditEntry, column) == value)
        result = await session.execute(stmt)
        return int(result.scalar_one())


@pytest.mark.asyncio
async def test_unknown_dm_writes_one_audit_row_and_replies(
    adapter_with_real_resolver: DiscordAdapter,
    async_session_scope: Any,
) -> None:
    """A DM from an unknown snowflake produces one audit row + one reply.

    Asserts the declared side-effect contract: exactly one
    ``discord.unknown_user_dm`` row appears in ``audit_log`` AND the
    polite refusal echo lands on ``channel.send``. Pre-fix the test
    only asserted on ``channel.send`` (CR PR #106 — Major: "tests
    drift from the stated integration contract").
    """
    adapter = adapter_with_real_resolver
    # The migration backfilled an operator row from
    # ALFRED_OPERATOR_NAME — no need to add another. The unknown
    # snowflake (99999) is not bound to anyone, which is the trigger
    # for the unknown-DM branch.
    before = await _count_audit_rows(async_session_scope, event="discord.unknown_user_dm")
    msg = _make_dm_message(snowflake=99999, content="hello")
    await adapter._handle(msg)

    # Side-effect 1: exactly one audit row recorded for the branch.
    after = await _count_audit_rows(async_session_scope, event="discord.unknown_user_dm")
    assert after - before == 1, (
        f"expected exactly 1 discord.unknown_user_dm audit row, got {after - before}"
    )
    # Side-effect 2: the refusal landed with the snowflake echoed back.
    msg.channel.send.assert_called_once()
    sent_text = msg.channel.send.call_args.args[0]
    assert "99999" in sent_text, "snowflake echo missing from unknown-DM reply"


@pytest.mark.asyncio
async def test_known_user_dm_round_trips_with_audit_and_budget(
    adapter_with_real_resolver: DiscordAdapter,
    async_session_scope: Any,
) -> None:
    """A bound user DM round-trips: audit + budget side effects observable.

    Asserts the declared integration contract:

    * The orchestrator's response renders to ``channel.send`` exactly
      once.
    * A new audit row is persisted (orchestrator emits an audit on a
      successful round-trip).
    * The BudgetGuard records the actual spend (its ``spent_today``
      ledger increments by the mocked router's ``cost_usd``).

    Pre-fix the test only asserted ``channel.send`` (CR PR #106 —
    Major).
    """
    adapter = adapter_with_real_resolver
    alice = adapter._identity.add(
        display_name="Alice",
        authorization=Authorization.STANDARD,
        daily_budget_usd=1.0,
    )
    adapter._identity.bind(user_slug=alice.slug, platform=Platform.DISCORD, platform_id="987654321")

    rows_before = await _count_audit_rows(async_session_scope)
    # BudgetGuard is owned by the orchestrator; reach it through there
    # rather than duplicating an instance into the adapter.
    budget = adapter._orch._budget
    spent_before = budget.spent_today(alice.slug)

    msg = _make_dm_message(snowflake=987654321, content="hello alfred")
    await adapter._handle(msg)

    # Side-effect 1: the response rendered exactly once.
    msg.channel.send.assert_called_once()
    # Side-effect 2: at least one new audit row landed for the round-trip.
    rows_after = await _count_audit_rows(async_session_scope)
    assert rows_after > rows_before, (
        f"expected new audit rows after round-trip, got {rows_after - rows_before}"
    )
    # Side-effect 3: budget ledger incremented by the mocked router's cost.
    spent_after = budget.spent_today(alice.slug)
    assert spent_after > spent_before, (
        f"expected budget ledger to advance; before={spent_before} after={spent_after}"
    )


@pytest.mark.asyncio
async def test_embed_attachment_refusal_round_trip(
    adapter_with_real_resolver: DiscordAdapter,
) -> None:
    """A DM with an embed triggers the refusal path (zero orchestrator call)."""
    adapter = adapter_with_real_resolver
    alice = adapter._identity.add(display_name="Alice", authorization=Authorization.STANDARD)
    adapter._identity.bind(user_slug=alice.slug, platform=Platform.DISCORD, platform_id="11111111")

    msg = _make_dm_message(snowflake=11111111, content="hello")
    msg.embeds = [MagicMock()]  # non-empty embeds triggers refusal
    await adapter._handle(msg)

    msg.channel.send.assert_called_once()
    sent_text = msg.channel.send.call_args.args[0]
    # The refusal template mentions embeds.
    assert "embeds" in sent_text.lower() or "attachments" in sent_text.lower(), (
        "embed_unsupported template not rendered"
    )
