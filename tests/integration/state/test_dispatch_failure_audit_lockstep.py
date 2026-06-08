"""err-002 transactional lockstep: ledger row + redacted audit twin commit atomically.

The #173 ``PROPOSAL_DISPATCH_FAILURE_REDACTED`` audit row is written into the
SAME SQLAlchemy session as the ``ProcessedProposal`` ledger insert — so the
two commit together. If the session commit fails, BOTH roll back and the
dispatch loop retries on the next tick (the sentinel stays unbumped). A
ledger row landing without its redaction-accounting twin would be silent
divergence (CLAUDE.md hard rule #7).

This test plants a session whose commit raises and asserts neither row
persisted — the atomic-rollback contract.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

import pytest
import structlog
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from alfred.audit.log import AuditWriter
from alfred.memory.models import AuditEntry, Base, ProcessedProposal
from alfred.state.dispatch_loop import _ProposalBlobRef, _record_failure
from tests.helpers.dlp import identity_outbound_dlp as _identity_dlp

pytestmark = [pytest.mark.asyncio, pytest.mark.integration]


def _ref() -> _ProposalBlobRef:
    return _ProposalBlobRef(
        proposal_type="breaker-reset",
        proposal_id="abc123def4567890",
        blob_sha="0" * 40,
        commit_sha="1" * 40,
        repo_path=Path("state.git"),
        content_path="policies/breaker-resets/abc123def4567890.json",
    )


async def test_redacted_row_and_ledger_row_roll_back_together(postgres_url: str) -> None:
    """A commit failure on the ledger+audit session rolls BOTH rows back."""
    engine = create_async_engine(postgres_url)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    sm = async_sessionmaker(bind=engine, expire_on_commit=False)

    fail_next = {"on": True}

    @asynccontextmanager
    async def _flaky_scope() -> AsyncIterator[AsyncSession]:
        async with sm() as session:
            try:
                yield session
                if fail_next["on"]:
                    # The lockstep session (ledger + redacted twin) is the
                    # first to commit — simulate a Postgres-side commit fault.
                    raise SQLAlchemyError("simulated commit failure")
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    @asynccontextmanager
    async def _clean_scope() -> AsyncIterator[AsyncSession]:
        async with sm() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    class _NoEffects:
        async def reset_breaker(self, component_id: str, *, operator_user_id: str) -> None: ...

    from alfred.state.dispatch_registry import ProposalContext

    ctx = ProposalContext(
        audit_writer=AuditWriter(session_factory=_clean_scope),
        effects=_NoEffects(),  # type: ignore[arg-type]
        logger=structlog.get_logger("test"),
        outbound_dlp=_identity_dlp(),
    )

    try:
        # The lockstep block raises on commit → propagates out of _record_failure.
        with pytest.raises(SQLAlchemyError):
            await _record_failure(
                ctx,  # type: ignore[arg-type]
                _ref(),
                _flaky_scope,
                result="failed_handler",
                failure_kind="handler_returned_failed",
                failure_detail="component_id_not_registered",
                operator_user_id=None,
                correlation_id="corr-lockstep",
                framework_error_kind=None,
            )

        fail_next["on"] = False
        # Neither the ledger row nor the redacted audit twin persisted.
        async with _clean_scope() as s:
            ledger = (await s.execute(select(ProcessedProposal))).scalars().all()
            audit = (await s.execute(select(AuditEntry))).scalars().all()
        assert list(ledger) == []
        assert list(audit) == []
    finally:
        await engine.dispose()
