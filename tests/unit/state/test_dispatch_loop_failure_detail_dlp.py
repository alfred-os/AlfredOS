"""Unit-tier guards for the #173 DLP-into-failure_detail rename + helper.

The end-to-end scan-then-truncate behaviour (planted secret redacted,
canary refusal aborts, scan-error aborts) is exercised against a real
Postgres session in
``tests/integration/state/test_dispatch_failure_detail_dlp.py`` — those
paths need the real ledger insert + ``append_schema`` round-trip. This
module pins the pure, session-free surface: the rename is truthful and the
truncate helper's body is unchanged.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import pytest
import structlog
from sqlalchemy.exc import SQLAlchemyError

from alfred.audit.log import AuditWriter
from alfred.hooks.errors import HookRefusal
from alfred.memory.models import AuditEntry, ProcessedProposal
from alfred.state.dispatch_loop import (
    _PostHandlerAuditFailure,
    _ProposalBlobRef,
    _record_failure,
)
from alfred.state.dispatch_registry import ProposalContext
from tests.helpers.dlp import identity_outbound_dlp as _identity_dlp


def test_truncated_detail_was_renamed_to_redacted_detail() -> None:
    """The dishonest name is gone; the truthful name lives."""
    import alfred.state.dispatch_loop as dl

    assert not hasattr(dl, "_truncated_detail")
    assert hasattr(dl, "_redacted_detail")
    assert callable(dl._redacted_detail)


def test_redacted_detail_truncates_to_512() -> None:
    """The helper body is unchanged: text[:512]. (Scan happens at the call site.)"""
    from alfred.state.dispatch_loop import _redacted_detail

    assert _redacted_detail("x" * 513) == "x" * 512
    assert _redacted_detail("hello") == "hello"
    assert _redacted_detail("") == ""


# ---------------------------------------------------------------------------
# _record_failure DLP branches — unit tier (fake session, mocked audit writer)
# ---------------------------------------------------------------------------

_PLANTED_KEY = "sk-" + "DEADBEEF" * 5  # > 20 alnum after sk- → api-key-shape match


class _RefusingDlp:
    def scan(self, text: str) -> str:
        raise HookRefusal(
            hook_id="dlp.outbound",
            action_id="state.proposal.failure_detail",
            reason="canary_or_secret_in_failure_detail",
            correlation_id="t-1",
        )


class _BrokenDlp:
    def scan(self, text: str) -> str:
        raise RuntimeError("regex catastrophic backtrack")


class _CapturingSession:
    """Minimal async session double — records ``add`` calls, no real DB."""

    def __init__(self, added: list[Any], *, commit_raises: bool = False) -> None:
        self._added = added
        self._commit_raises = commit_raises

    def add(self, obj: Any) -> None:
        self._added.append(obj)

    async def commit(self) -> None:
        if self._commit_raises:
            raise SQLAlchemyError("simulated commit failure")


def _scope_factory(added: list[Any], *, commit_raises: bool = False) -> Any:
    @asynccontextmanager
    async def _scope() -> AsyncIterator[_CapturingSession]:
        session = _CapturingSession(added, commit_raises=commit_raises)
        try:
            yield session
            await session.commit()
        except Exception:
            raise

    return _scope


def _ctx(scanner: Any, audit_writer: Any) -> ProposalContext:
    class _NoEffects:
        async def reset_breaker(self, component_id: str, *, operator_user_id: str) -> None: ...

    return ProposalContext(
        audit_writer=audit_writer,
        effects=_NoEffects(),  # type: ignore[arg-type]
        logger=structlog.get_logger("test"),
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


@pytest.mark.asyncio
async def test_record_failure_redacts_planted_secret_unit() -> None:
    """Planted secret is scanned out of the ledger row; redacted twin emitted in-session."""
    added: list[Any] = []
    audit = AsyncMock(spec=AuditWriter)
    await _record_failure(
        _ctx(_identity_dlp(), audit),
        _ref(),
        _scope_factory(added),
        result="failed_handler",
        failure_kind="handler_returned_failed",
        failure_detail=f"boom {_PLANTED_KEY} tail",
        operator_user_id=None,
        correlation_id="corr-1",
        framework_error_kind=None,
    )
    ledger = next(o for o in added if isinstance(o, ProcessedProposal))
    assert "sk-" not in (ledger.failure_detail or "")
    redacted_row = next(o for o in added if isinstance(o, AuditEntry))
    assert redacted_row.event == "state.proposal.failure_detail_redacted"
    assert redacted_row.result == "dispatched_with_redactions"
    assert redacted_row.subject["dlp_redactions_count"] >= 1


@pytest.mark.asyncio
async def test_record_failure_clean_scan_count_zero_unit() -> None:
    """A clean scan emits dispatched_clean with count 0."""
    added: list[Any] = []
    await _record_failure(
        _ctx(_identity_dlp(), AsyncMock(spec=AuditWriter)),
        _ref(),
        _scope_factory(added),
        result="failed_handler",
        failure_kind="handler_returned_failed",
        failure_detail="component_id_not_registered",
        operator_user_id="op-1",
        correlation_id="corr-2",
        framework_error_kind=None,
    )
    redacted_row = next(o for o in added if isinstance(o, AuditEntry))
    assert redacted_row.result == "dispatched_clean"
    assert redacted_row.subject["dlp_redactions_count"] == 0


@pytest.mark.asyncio
async def test_record_failure_none_detail_no_scan_unit() -> None:
    """failure_detail None → ledger NULL, clean redacted row, framework_error path."""
    added: list[Any] = []
    audit = AsyncMock(spec=AuditWriter)
    await _record_failure(
        _ctx(_identity_dlp(), audit),
        _ref(),
        _scope_factory(added),
        result="failed_unknown_type",
        failure_kind="unknown_proposal_type",
        failure_detail=None,
        operator_user_id=None,
        correlation_id="corr-3",
        framework_error_kind="unknown_proposal_type",
    )
    ledger = next(o for o in added if isinstance(o, ProcessedProposal))
    assert ledger.failure_detail is None
    redacted_row = next(o for o in added if isinstance(o, AuditEntry))
    assert redacted_row.subject["dlp_redactions_count"] == 0
    # framework_error_kind set → DISPATCH_FAILED audit emit on the writer path.
    events = [c.kwargs.get("event") for c in audit.append_schema.await_args_list]
    assert "state.proposal.dispatch_failed" in events


@pytest.mark.asyncio
async def test_record_failure_refusal_aborts_unit() -> None:
    """HookRefusal → no ledger row, refusal audit row, early return."""
    added: list[Any] = []
    audit = AsyncMock(spec=AuditWriter)
    await _record_failure(
        _ctx(_RefusingDlp(), audit),
        _ref(),
        _scope_factory(added),
        result="failed_handler",
        failure_kind="handler_returned_failed",
        failure_detail="detail-XYZ",
        operator_user_id=None,
        correlation_id="corr-4",
        framework_error_kind=None,
    )
    assert added == []  # no ledger insert
    events = [c.kwargs.get("event") for c in audit.append_schema.await_args_list]
    assert events == ["security.dlp_outbound_refused"]


@pytest.mark.asyncio
async def test_record_failure_scan_error_aborts_unit() -> None:
    """Non-HookRefusal scan fault → no ledger row, scan-failed audit row."""
    added: list[Any] = []
    audit = AsyncMock(spec=AuditWriter)
    await _record_failure(
        _ctx(_BrokenDlp(), audit),
        _ref(),
        _scope_factory(added),
        result="failed_handler",
        failure_kind="handler_returned_failed",
        failure_detail="anything",
        operator_user_id=None,
        correlation_id="corr-5",
        framework_error_kind=None,
    )
    assert added == []
    call = audit.append_schema.await_args_list[0]
    assert call.kwargs["event"] == "state.proposal.dispatch_dlp_scan_failed"
    assert call.kwargs["subject"]["scan_error_type"] == "RuntimeError"
    # A scan crash is an infra fault, not a deliberate refusal.
    assert call.kwargs["result"] == "dlp_failed"


@pytest.mark.asyncio
async def test_record_failure_lockstep_commit_failure_propagates_unit() -> None:
    """A commit failure on the ledger+redacted session propagates (rollback → retry)."""
    added: list[Any] = []
    with pytest.raises(SQLAlchemyError):
        await _record_failure(
            _ctx(_identity_dlp(), AsyncMock(spec=AuditWriter)),
            _ref(),
            _scope_factory(added, commit_raises=True),
            result="failed_handler",
            failure_kind="handler_returned_failed",
            failure_detail="component_id_not_registered",
            operator_user_id=None,
            correlation_id="corr-6",
            framework_error_kind=None,
        )


@pytest.mark.asyncio
async def test_record_failure_refusal_audit_db_failure_trips_breaker_unit() -> None:
    """An audit DB-write failure on the refusal path raises _PostHandlerAuditFailure."""
    audit = AsyncMock(spec=AuditWriter)
    audit.append_schema = AsyncMock(side_effect=SQLAlchemyError("audit writer down"))
    with pytest.raises(_PostHandlerAuditFailure):
        await _record_failure(
            _ctx(_RefusingDlp(), audit),
            _ref(),
            _scope_factory([]),
            result="failed_handler",
            failure_kind="handler_returned_failed",
            failure_detail="detail-XYZ",
            operator_user_id=None,
            correlation_id="corr-7",
            framework_error_kind=None,
        )


@pytest.mark.asyncio
async def test_record_failure_scan_failed_audit_db_failure_trips_breaker_unit() -> None:
    """An audit DB-write failure on the scan-failed path raises _PostHandlerAuditFailure."""
    audit = AsyncMock(spec=AuditWriter)
    audit.append_schema = AsyncMock(side_effect=SQLAlchemyError("audit writer down"))
    with pytest.raises(_PostHandlerAuditFailure):
        await _record_failure(
            _ctx(_BrokenDlp(), audit),
            _ref(),
            _scope_factory([]),
            result="failed_handler",
            failure_kind="handler_returned_failed",
            failure_detail="anything",
            operator_user_id=None,
            correlation_id="corr-8",
            framework_error_kind=None,
        )


@pytest.mark.asyncio
async def test_record_failure_processed_audit_db_failure_trips_breaker_unit() -> None:
    """err-001: a DB-write failure on the trailing PROCESSED emit → _PostHandlerAuditFailure."""
    audit = AsyncMock(spec=AuditWriter)
    audit.append_schema = AsyncMock(side_effect=SQLAlchemyError("audit writer down"))
    with pytest.raises(_PostHandlerAuditFailure):
        await _record_failure(
            _ctx(_identity_dlp(), audit),
            _ref(),
            _scope_factory([]),
            result="failed_handler",
            failure_kind="handler_returned_failed",
            failure_detail="component_id_not_registered",
            operator_user_id=None,
            correlation_id="corr-9",
            framework_error_kind=None,
        )


@pytest.mark.asyncio
async def test_record_failure_processed_audit_programmer_error_propagates_unit() -> None:
    """err-001: a ValueError (programmer error) from the audit emit propagates raw."""
    audit = AsyncMock(spec=AuditWriter)
    audit.append_schema = AsyncMock(side_effect=ValueError("wrong-shape subject"))
    with pytest.raises(ValueError, match="wrong-shape"):
        await _record_failure(
            _ctx(_identity_dlp(), audit),
            _ref(),
            _scope_factory([]),
            result="failed_handler",
            failure_kind="handler_returned_failed",
            failure_detail="component_id_not_registered",
            operator_user_id=None,
            correlation_id="corr-10",
            framework_error_kind=None,
        )


def test_validate_subject_keys_raises_on_mismatch() -> None:
    """The in-session redacted-row key guard rejects missing/extra keys (sec guard)."""
    from alfred.audit.audit_row_schemas import PROPOSAL_DISPATCH_FAILURE_REDACTED_FIELDS
    from alfred.state.dispatch_loop import _validate_subject_keys

    # Missing every declared key + an extra one → raises naming the mismatch.
    with pytest.raises(ValueError, match="redacted audit subject mismatch"):
        _validate_subject_keys({"unexpected": 1}, PROPOSAL_DISPATCH_FAILURE_REDACTED_FIELDS)

    # An exactly-correct subject does NOT raise.
    correct = {k: "x" for k in PROPOSAL_DISPATCH_FAILURE_REDACTED_FIELDS}
    _validate_subject_keys(correct, PROPOSAL_DISPATCH_FAILURE_REDACTED_FIELDS)
