"""#410 PR1 headline proof: NO Postgres connection is held during the provider call.

Deterministic, not timing-based: a gate router parks ALL four concurrent
turns inside complete(); once every turn has arrived (arrival counter + one
release Event — nothing is mid-Phase-A/C at the measurement point), the test
reads the TURN pool's checked-out count while all four are parked and
asserts ZERO. Under the pre-#410 single-turn-transaction design this test
cannot even reach the measurement point: four turns each holding one of two
pooled connections across complete() is hold-and-wait — the last two turns
starve at Phase-A checkout until the 3s pool_timeout raises, failing the
TaskGroup loudly. The companion test proves the pool really is that small
(oracle independence: the detector is demonstrated to bite, not assumed to).

``migrated_url`` is the directory-scoped fixture from
``tests/integration/orchestrator/conftest.py`` (autodiscovered, no import
needed) — reused rather than re-declared here so the alembic-upgrade-to-head
mechanics stay defined in exactly one place.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
import sqlalchemy as sa
from pydantic import PostgresDsn

from alfred.memory.db import (
    ConnectionRole,
    build_session_scope,
    dispose_all_engines,
    make_engine,
    make_session_factory,
)
from alfred.memory.episodic import EpisodicMemory
from alfred.memory.turn_side_effects import PostgresTurnSideEffectLedger
from alfred.memory.working import WorkingMemory
from alfred.orchestrator.core import Orchestrator
from alfred.providers.base import CompletionResponse
from alfred.security.tiers import T2, tag

pytestmark = pytest.mark.integration

_PARTIES = 4


@dataclass(frozen=True)
class _StubUser:
    slug: str
    display_name: str
    language: str


class _SmallTurnPoolCfg:
    """TURN pool of 2 — SMALLER than the concurrency (4) — so any design that
    holds a connection across complete() starves instead of passing."""

    def __init__(self, url: str) -> None:
        self.database_url = PostgresDsn(url)

    db_turn_pool_max_connections = 2
    db_side_pool_max_connections = 4
    db_pool_checkout_timeout_seconds = 3.0
    db_idle_in_transaction_timeout_seconds = 5.0


class _GateRouter:
    """complete() parks every caller until the test releases them together."""

    def __init__(self, parties: int) -> None:
        self._parties = parties
        self._arrivals = 0
        self.all_arrived = asyncio.Event()
        self.release = asyncio.Event()

    async def complete(self, _request: Any) -> CompletionResponse:
        self._arrivals += 1
        if self._arrivals == self._parties:
            self.all_arrived.set()
        await self.release.wait()
        return CompletionResponse(
            content="Very good, Sir.",
            tokens_in=3,
            tokens_out=2,
            cost_usd=0.0001,
            model="gate-router",
        )


def _make_budget() -> MagicMock:
    budget = MagicMock()
    budget.estimate_for = MagicMock(return_value=0.001)
    budget.would_exceed = MagicMock(return_value=False)
    budget.check_and_charge = MagicMock(return_value=None)
    return budget


async def test_no_connection_is_held_while_all_turns_sit_in_the_provider_call(
    migrated_url: str,
) -> None:
    cfg = _SmallTurnPoolCfg(migrated_url)
    engine = make_engine(cfg, role=ConnectionRole.TURN)
    turn_scope = build_session_scope(cfg, role=ConnectionRole.TURN)
    router = _GateRouter(_PARTIES)
    audit = MagicMock()
    audit.append = AsyncMock()
    audit.append_schema = AsyncMock()
    resolver = MagicMock()
    resolver.get_operator = MagicMock(
        return_value=_StubUser(slug="bruce", display_name="Bruce", language="en-US")
    )
    orch = Orchestrator(
        identity_resolver=resolver,
        session_scope=turn_scope,
        router=router,  # type: ignore[arg-type]  # reason: duck-typed gate router; only .complete is consumed
        budget=_make_budget(),
        episodic_factory=lambda s: EpisodicMemory(session=s),
        audit_factory=lambda _f: audit,
        autocommit_audit_factory=lambda _f: audit,
        side_effect_ledger=PostgresTurnSideEffectLedger(),
    )
    user = _StubUser(slug="bruce", display_name="Bruce", language="en-US")

    async def one_turn(i: int) -> str:
        # Fresh WorkingMemory per turn: the pool/adapter owns per-user buffers
        # in production; here each turn is an independent conversation.
        return await orch.handle_user_message(
            user=user,
            content=tag(T2, f"barrier turn {i}", source="test.adapter"),
            working_memory=WorkingMemory(),
        )

    try:
        async with asyncio.timeout(60):
            async with asyncio.TaskGroup() as tg:
                tasks = [tg.create_task(one_turn(i)) for i in range(_PARTIES)]
                await router.all_arrived.wait()
                # All four turns are parked inside complete(); none is in
                # Phase A or C. THE deterministic invariant of ADR-0062:
                assert engine.pool.checkedout() == 0
                router.release.set()
        assert [task.result() for task in tasks] == ["Very good, Sir."] * _PARTIES
    finally:
        await dispose_all_engines()


async def test_hold_and_wait_on_this_pool_really_starves(migrated_url: str) -> None:
    """Oracle-independence companion: the barrier test's pass is only meaningful
    if this pool genuinely cannot serve held-across-the-park connections. Two
    held TURN sessions + a third checkout = SQLAlchemy TimeoutError within the
    3s checkout timeout — the failure the barrier test would produce under the
    pre-#410 design."""
    from sqlalchemy.exc import TimeoutError as SaTimeoutError

    cfg = _SmallTurnPoolCfg(migrated_url)
    factory = make_session_factory(cfg, role=ConnectionRole.TURN)
    try:
        async with factory() as held_a, factory() as held_b:
            await held_a.execute(sa.text("SELECT 1"))  # checkout + hold (in txn)
            await held_b.execute(sa.text("SELECT 1"))
            with pytest.raises(SaTimeoutError):
                async with asyncio.timeout(30):
                    async with factory() as starved:
                        await starved.execute(sa.text("SELECT 1"))
    finally:
        await dispose_all_engines()
