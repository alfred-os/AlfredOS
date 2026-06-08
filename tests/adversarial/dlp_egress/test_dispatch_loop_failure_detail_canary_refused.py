"""Executable counterpart to ``dispatch_loop_failure_detail_canary_refused.yaml``.

de-2026-006. Pins the #173 refusal arm: a DLP canary-trip ``HookRefusal``
from ``OutboundDlp.scan`` aborts the ``ProcessedProposal`` insert entirely
and emits ``security.dlp_outbound_refused`` — the deliberate no-write
signal, disjoint from the redacted-success path (spec §2.1).

TODO: Slice-5 — re-validate against the real canary mechanism once
Slice-3's ``OutboundDlp.scan()`` actually raises ``HookRefusal`` on a canary
trip. The canary stage is a no-op stub today, so the refusal arm is
exercised here via an injected refusing-DLP stub (sec-004).
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from pathlib import Path

import pytest
import structlog
import yaml
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from alfred.audit.log import AuditWriter
from alfred.hooks.errors import HookRefusal
from alfred.memory.models import AuditEntry, Base, ProcessedProposal
from alfred.state.dispatch_loop import _ProposalBlobRef, _record_failure
from tests.adversarial.payload_schema import AdversarialPayload

_PAYLOAD_PATH = Path(__file__).parent / "dispatch_loop_failure_detail_canary_refused.yaml"


def _load_payload() -> AdversarialPayload:
    return AdversarialPayload.model_validate(yaml.safe_load(_PAYLOAD_PATH.read_text()))


def test_payload_schema_valid() -> None:
    """The corpus YAML validates and declares the boundary_refused shape."""
    payload = _load_payload()
    assert payload.id == "de-2026-006"
    assert payload.category == "dlp_egress"
    assert payload.expected_outcome == "boundary_refused"
    assert payload.ingestion_path == "proposal_dispatch_failure"


def test_payload_carries_slice5_todo() -> None:
    """sec-004: the canary-fidelity Slice-5 TODO is documented in the corpus file."""
    text = _PAYLOAD_PATH.read_text()
    assert "TODO: Slice-5" in text


@pytest.fixture
async def session_scope_factory(
    postgres_url: str,
) -> AsyncIterator[Callable[[], AbstractAsyncContextManager[AsyncSession]]]:
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


class _RefusingDlp:
    """Simulates the Slice-5 canary stage raising HookRefusal on a canary trip."""

    def scan(self, text: str) -> str:
        raise HookRefusal(
            hook_id="dlp.outbound",
            action_id="state.proposal.failure_detail",
            reason="canary_or_secret_in_failure_detail",
            correlation_id="de-2026-006",
        )


@pytest.mark.integration
@pytest.mark.asyncio
async def test_canary_trip_aborts_write_and_emits_refusal(
    session_scope_factory: Callable[[], AbstractAsyncContextManager[AsyncSession]],
) -> None:
    """HookRefusal aborts the insert; refusal row emits; no ProcessedProposal lands."""
    payload = _load_payload()
    assert isinstance(payload.payload, dict)
    detail = str(payload.payload["failure_detail"])

    from alfred.state.dispatch_registry import ProposalContext

    class _NoEffects:
        async def reset_breaker(self, component_id: str, *, operator_user_id: str) -> None: ...

    ctx = ProposalContext(
        audit_writer=AuditWriter(session_factory=session_scope_factory),
        effects=_NoEffects(),  # type: ignore[arg-type]
        logger=structlog.get_logger("test"),
        outbound_dlp=_RefusingDlp(),
    )
    ref = _ProposalBlobRef(
        proposal_type="breaker-reset",
        proposal_id="abc123def4567890",
        blob_sha="0" * 40,
        commit_sha="1" * 40,
        repo_path=Path("state.git"),
        content_path="policies/breaker-resets/abc123def4567890.json",
    )
    await _record_failure(
        ctx,  # type: ignore[arg-type]
        ref,
        session_scope_factory,
        result="failed_handler",
        failure_kind="handler_returned_failed",
        failure_detail=detail,
        operator_user_id=None,
        correlation_id="de-2026-006",
        framework_error_kind=None,
    )

    async with session_scope_factory() as s:
        ledger = list((await s.execute(select(ProcessedProposal))).scalars().all())
        audit = list((await s.execute(select(AuditEntry))).scalars().all())

    assert ledger == []  # write aborted
    refusal = [a for a in audit if a.event == "security.dlp_outbound_refused"]
    assert len(refusal) == 1
    assert refusal[0].subject["scan_rule_matched"] == "canary_or_secret_in_failure_detail"
    assert [a for a in audit if a.event == "state.proposal.failure_detail_redacted"] == []
