"""``Supervisor.request_plugin_restart`` lands a real Postgres audit row (#152).

C1 closure. The Wave-4 dispatch test (``test_comms_mcp_session_dispatch_real``)
asserts the supervisor hand-off against a *recording stand-in*, so the
``result="restart_requested"`` discriminator never reaches a real Postgres
``audit_log`` INSERT — the migration-0016 / ORM ``ck_audit_log_result`` CHECK
domain was never exercised end-to-end for that value.

This test closes the gap the plan named: it drives the **real**
:meth:`alfred.supervisor.core.Supervisor.request_plugin_restart` (no stub) through
a real :class:`AuditWriter` backed by a Postgres testcontainer. The INSERT only
succeeds if ``"restart_requested"`` is inside the CHECK domain — so the test
fails loudly (an ``IntegrityError`` on the constraint) if the migration / ORM
addition regresses.

The supervisor's ``request_plugin_restart`` is the only production emitter of the
row, and its only production caller is the comms-wired session
(``AlfredPluginSession`` unknown-notification arm) — so this PR (#152) owns the
end-to-end coverage of the value.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any
from unittest.mock import MagicMock

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from alfred.audit.log import AuditWriter
from alfred.memory.models import AuditEntry, Base
from alfred.supervisor.breaker import BreakerState
from alfred.supervisor.core import Supervisor
from tests.helpers.policies import _StubPoliciesSnapshotRef

pytestmark = pytest.mark.integration

_ADAPTER_ID = "alfred_comms_test"


@asynccontextmanager
async def _real_supervisor(postgres_url: str) -> AsyncIterator[tuple[Supervisor, Any]]:
    """Assemble a Supervisor whose audit writes hit a real Postgres container."""
    engine = create_async_engine(postgres_url, future=True)
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        sm = async_sessionmaker(bind=engine, expire_on_commit=False)

        @asynccontextmanager
        async def session_scope() -> AsyncIterator[AsyncSession]:
            async with sm() as session, session.begin():
                yield session

        # The supervisor never calls a gate method on the restart path, but the
        # constructor requires the dependency — a MagicMock is the narrow
        # fixture here (NOT an always-allow shim on any security boundary).
        supervisor = Supervisor(
            session_scope=session_scope,
            gate=MagicMock(),
            audit=AuditWriter(session_factory=session_scope),
            policies_ref=_StubPoliciesSnapshotRef(),
        )
        yield supervisor, sm
    finally:
        await engine.dispose()


async def _restart_rows(sm: Any) -> list[AuditEntry]:
    async with sm() as session:
        result = await session.execute(
            select(AuditEntry).where(
                AuditEntry.event == "supervisor.plugin.restart_requested"
            )
        )
        return list(result.scalars().all())


async def test_request_plugin_restart_persists_restart_requested_row(postgres_url: str) -> None:
    """The real INSERT succeeds — ``restart_requested`` is in the CHECK domain."""
    async with _real_supervisor(postgres_url) as (supervisor, sm):
        await supervisor.request_plugin_restart(
            adapter_id=_ADAPTER_ID,
            reason="unknown_notification",
        )

        rows = await _restart_rows(sm)
        assert len(rows) == 1
        row = rows[0]
        # The discriminator the migration-0016 CHECK must admit.
        assert row.result == "restart_requested"
        assert row.subject["plugin_id"] == _ADAPTER_ID
        assert row.subject["reason"] == "unknown_notification"
        assert row.trust_tier_of_trigger == "T0"

        # The adapter's breaker tripped OPEN as part of the same call (the
        # restart scheduler reads the breaker as its unhealthy signal).
        assert supervisor._breakers[_ADAPTER_ID].state == BreakerState.OPEN


async def test_recurring_restart_request_re_emits_not_silently_suppressed(
    postgres_url: str,
) -> None:
    """A recurring crash->restart re-audits every time (H2 — no silent gap).

    Two identical restart requests for the same ``(adapter_id, reason)`` emit
    two real audit rows. Before the H2 fix the second was silently swallowed by
    a per-tick dedup set that no production tick ever cleared — a recurring
    crash would go dark after the first row.
    """
    async with _real_supervisor(postgres_url) as (supervisor, sm):
        await supervisor.request_plugin_restart(
            adapter_id=_ADAPTER_ID, reason="unknown_notification"
        )
        await supervisor.request_plugin_restart(
            adapter_id=_ADAPTER_ID, reason="unknown_notification"
        )

        rows = await _restart_rows(sm)
        assert len(rows) == 2
        assert all(r.result == "restart_requested" for r in rows)
