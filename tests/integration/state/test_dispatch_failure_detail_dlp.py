"""End-to-end DLP scan of ``failure_detail`` before the ledger write (#173).

Real Postgres testcontainer so the ledger insert + the in-session
``PROPOSAL_DISPATCH_FAILURE_REDACTED`` audit twin (err-002 lockstep) and the
``AuditWriter``-path refusal / scan-failed rows are exercised against the
production engine (CHECK constraints, JSONB, timestamptz).

Covered branches (test-003 + sec-002 + sec-003 + err-002 + err-003):
* planted secret in ``failure_detail`` → redacted before the ledger row,
  ``dispatched_with_redactions`` row with ``dlp_redactions_count >= 1``;
* clean scan → ``dispatched_clean`` row with ``dlp_redactions_count == 0``;
* scan happens BEFORE truncation (512-char cap on the redacted text);
* ``failure_detail is None`` → no scan, ledger NULL, count 0 clean row;
* canary-trip ``HookRefusal`` → no ledger row, ``security.dlp_outbound_refused``;
* non-refusal scan exception → no ledger row, ``state.proposal.dispatch_dlp_scan_failed``;
* audit-emit failure after ledger insert (lockstep) → rollback, no rows.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable, Mapping
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from alfred.audit.log import AuditWriter
from alfred.hooks.errors import HookRefusal
from alfred.memory.models import AuditEntry, Base, ProcessedProposal
from alfred.security.dlp import OutboundDlp, OutboundDlpProtocol
from alfred.state.dispatch_loop import _ProposalBlobRef, _record_failure

pytestmark = [pytest.mark.asyncio, pytest.mark.integration]

_PLANTED_KEY = "sk-" + "DEADBEEF" * 5  # > 20 alnum after sk- → api-key-shape match


@pytest.fixture
async def session_scope_factory(
    postgres_url: str,
) -> AsyncIterator[Callable[[], AbstractAsyncContextManager[AsyncSession]]]:
    """A session_scope factory backed by a fresh schema on the test container."""
    engine = create_async_engine(postgres_url)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    sm = async_sessionmaker(bind=engine, expire_on_commit=False)

    @asynccontextmanager
    async def _scope() -> AsyncIterator[AsyncSession]:
        async with sm() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    try:
        yield _scope
    finally:
        await engine.dispose()


def _identity_dlp() -> OutboundDlp:
    """Clean scan — returns text unchanged (count stays 0)."""

    class _IdentityBroker:
        def redact(self, text: str) -> str:
            return text

    def _sink(*, event: str, subject: Mapping[str, object]) -> None:
        return None

    return OutboundDlp(broker=_IdentityBroker(), audit=_sink)


class _RefusingDlp:
    """A scanner whose scan() raises HookRefusal (canary-trip simulation)."""

    def scan(self, text: str) -> str:
        raise HookRefusal(
            hook_id="dlp.outbound",
            action_id="state.proposal.failure_detail",
            reason="canary_or_secret_in_failure_detail",
            correlation_id="t-1",
        )


class _BrokenDlp:
    """A scanner whose scan() raises a non-HookRefusal fault (regex engine error)."""

    def scan(self, text: str) -> str:
        raise RuntimeError("regex catastrophic backtrack")


def _ctx(
    scanner: OutboundDlpProtocol,
    session_scope: Callable[[], AbstractAsyncContextManager[AsyncSession]],
) -> object:
    from alfred.state.dispatch_registry import ProposalContext

    class _NoEffects:
        async def reset_breaker(self, component_id: str, *, operator_user_id: str) -> None: ...

    return ProposalContext(
        audit_writer=AuditWriter(session_factory=session_scope),
        effects=_NoEffects(),  # type: ignore[arg-type]
        logger=__import__("structlog").get_logger("test"),
        outbound_dlp=scanner,
    )


def _ref() -> _ProposalBlobRef:
    return _ProposalBlobRef(
        proposal_type="breaker-reset",
        proposal_id="abc123def4567890",
        blob_sha="0" * 40,
        commit_sha="1" * 40,
        repo_path=Path("state.git"),
        content_path="policies/breaker-resets/abc123def4567890.json",
    )


async def _all_audit(
    session_scope: Callable[[], AbstractAsyncContextManager[AsyncSession]],
) -> list[AuditEntry]:
    async with session_scope() as s:
        return list((await s.execute(select(AuditEntry))).scalars().all())


async def test_planted_secret_is_redacted_and_count_emitted(
    session_scope_factory: Callable[[], AbstractAsyncContextManager[AsyncSession]],
) -> None:
    """A planted API-key in failure_detail is redacted before the ledger write."""
    ctx = _ctx(_identity_dlp(), session_scope_factory)
    await _record_failure(
        ctx,  # type: ignore[arg-type]
        _ref(),
        session_scope_factory,
        result="failed_handler",
        failure_kind="handler_returned_failed",
        failure_detail=f"boom {_PLANTED_KEY} tail",
        operator_user_id=None,
        correlation_id="corr-1",
        framework_error_kind=None,
    )

    async with session_scope_factory() as s:
        row = (await s.execute(select(ProcessedProposal))).scalar_one()
    redacted = row.failure_detail
    assert redacted is not None
    # sec-003: assert the defense fired without coupling to the token shape.
    assert "sk-" not in redacted
    assert _PLANTED_KEY not in redacted

    audit = await _all_audit(session_scope_factory)
    redacted_rows = [a for a in audit if a.event == "state.proposal.failure_detail_redacted"]
    assert len(redacted_rows) == 1
    assert redacted_rows[0].subject["dlp_redactions_count"] >= 1
    assert redacted_rows[0].result == "dispatched_with_redactions"
    assert [a for a in audit if a.event == "security.dlp_outbound_refused"] == []


async def test_clean_scan_emits_zero_count(
    session_scope_factory: Callable[[], AbstractAsyncContextManager[AsyncSession]],
) -> None:
    """A clean scan still emits the redacted row with count == 0 / dispatched_clean."""
    ctx = _ctx(_identity_dlp(), session_scope_factory)
    await _record_failure(
        ctx,  # type: ignore[arg-type]
        _ref(),
        session_scope_factory,
        result="failed_handler",
        failure_kind="handler_returned_failed",
        failure_detail="component_id_not_registered",
        operator_user_id=None,
        correlation_id="corr-2",
        framework_error_kind=None,
    )
    audit = await _all_audit(session_scope_factory)
    redacted_rows = [a for a in audit if a.event == "state.proposal.failure_detail_redacted"]
    assert len(redacted_rows) == 1
    assert redacted_rows[0].subject["dlp_redactions_count"] == 0
    assert redacted_rows[0].result == "dispatched_clean"
    async with session_scope_factory() as s:
        row = (await s.execute(select(ProcessedProposal))).scalar_one()
    assert row.failure_detail == "component_id_not_registered"


async def test_scan_happens_before_truncation(
    session_scope_factory: Callable[[], AbstractAsyncContextManager[AsyncSession]],
) -> None:
    """The 512-char cap is applied to the redacted text (scan first, then truncate)."""
    ctx = _ctx(_identity_dlp(), session_scope_factory)
    planted = f"{_PLANTED_KEY} " + "X" * 600
    await _record_failure(
        ctx,  # type: ignore[arg-type]
        _ref(),
        session_scope_factory,
        result="failed_handler",
        failure_kind="handler_returned_failed",
        failure_detail=planted,
        operator_user_id=None,
        correlation_id="corr-3",
        framework_error_kind=None,
    )
    async with session_scope_factory() as s:
        row = (await s.execute(select(ProcessedProposal))).scalar_one()
    assert row.failure_detail is not None
    assert len(row.failure_detail) == 512
    assert "sk-" not in row.failure_detail


async def test_none_failure_detail_no_scan_null_ledger(
    session_scope_factory: Callable[[], AbstractAsyncContextManager[AsyncSession]],
) -> None:
    """failure_detail is None → no scan, ledger NULL, clean redacted row (count 0)."""
    ctx = _ctx(_identity_dlp(), session_scope_factory)
    await _record_failure(
        ctx,  # type: ignore[arg-type]
        _ref(),
        session_scope_factory,
        result="failed_unknown_type",
        failure_kind="unknown_proposal_type",
        failure_detail=None,
        operator_user_id=None,
        correlation_id="corr-4",
        framework_error_kind="unknown_proposal_type",
    )
    async with session_scope_factory() as s:
        row = (await s.execute(select(ProcessedProposal))).scalar_one()
    assert row.failure_detail is None
    audit = await _all_audit(session_scope_factory)
    redacted_rows = [a for a in audit if a.event == "state.proposal.failure_detail_redacted"]
    assert len(redacted_rows) == 1
    assert redacted_rows[0].subject["dlp_redactions_count"] == 0


async def test_canary_refusal_aborts_write(
    session_scope_factory: Callable[[], AbstractAsyncContextManager[AsyncSession]],
) -> None:
    """A HookRefusal aborts the write; the refusal row emits; no ledger row lands."""
    ctx = _ctx(_RefusingDlp(), session_scope_factory)
    await _record_failure(
        ctx,  # type: ignore[arg-type]
        _ref(),
        session_scope_factory,
        result="failed_handler",
        failure_kind="handler_returned_failed",
        failure_detail="detail-with-canary-XYZ",
        operator_user_id=None,
        correlation_id="corr-5",
        framework_error_kind=None,
    )
    async with session_scope_factory() as s:
        rows = (await s.execute(select(ProcessedProposal))).scalars().all()
    assert list(rows) == []
    audit = await _all_audit(session_scope_factory)
    refusal_rows = [a for a in audit if a.event == "security.dlp_outbound_refused"]
    assert len(refusal_rows) == 1
    assert refusal_rows[0].subject["scan_rule_matched"] == "canary_or_secret_in_failure_detail"
    assert [a for a in audit if a.event == "state.proposal.failure_detail_redacted"] == []


async def test_non_refusal_scan_exception_aborts_write(
    session_scope_factory: Callable[[], AbstractAsyncContextManager[AsyncSession]],
) -> None:
    """A non-HookRefusal scan fault emits the scan-failed row + aborts the insert."""
    ctx = _ctx(_BrokenDlp(), session_scope_factory)
    await _record_failure(
        ctx,  # type: ignore[arg-type]
        _ref(),
        session_scope_factory,
        result="failed_handler",
        failure_kind="handler_returned_failed",
        failure_detail="anything",
        operator_user_id=None,
        correlation_id="corr-6",
        framework_error_kind=None,
    )
    async with session_scope_factory() as s:
        rows = (await s.execute(select(ProcessedProposal))).scalars().all()
    assert list(rows) == []
    audit = await _all_audit(session_scope_factory)
    scan_failed = [a for a in audit if a.event == "state.proposal.dispatch_dlp_scan_failed"]
    assert len(scan_failed) == 1
    assert scan_failed[0].subject["scan_error_type"] == "RuntimeError"
    assert [a for a in audit if a.event == "state.proposal.failure_detail_redacted"] == []
