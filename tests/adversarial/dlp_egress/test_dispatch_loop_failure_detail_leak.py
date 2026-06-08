"""Executable counterpart to ``dispatch_loop_failure_detail_leak.yaml`` (de-2026-005).

The YAML is corpus-density-validated by ``test_corpus_density.py`` but that
alone does not exercise the runtime contract. This module loads the payload,
drives the real :func:`alfred.state.dispatch_loop._record_failure` against a
real Postgres testcontainer with an identity ``OutboundDlp`` (so the stage-2
api-key-shape regex does the redaction), and pins the #173 defense:

* the planted ``sk-…`` key is NOT present in the ledger's ``failure_detail``;
* a ``state.proposal.failure_detail_redacted`` audit row is emitted with
  ``dlp_redactions_count >= 1`` and ``result='dispatched_with_redactions'``;
* NO ``security.dlp_outbound_refused`` row (this is the redaction path, not
  the refusal path — the two-disjoint-constants invariant, spec §2.1).

If this test fails after a code change you have either dropped the scan at
the dispatch boundary (the #173 leak shape returns) or broken the disjoint
audit-row contract — both merge-blocking.
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
from alfred.memory.models import AuditEntry, Base, ProcessedProposal
from alfred.state.dispatch_loop import _ProposalBlobRef, _record_failure
from tests.adversarial.payload_schema import AdversarialPayload
from tests.helpers.dlp import identity_outbound_dlp as _identity_dlp

_PAYLOAD_PATH = Path(__file__).parent / "dispatch_loop_failure_detail_leak.yaml"


def _load_payload() -> AdversarialPayload:
    return AdversarialPayload.model_validate(yaml.safe_load(_PAYLOAD_PATH.read_text()))


def test_payload_schema_valid() -> None:
    """The corpus YAML validates and declares the dlp_egress / caught_by_dlp shape."""
    payload = _load_payload()
    assert payload.id == "de-2026-005"
    assert payload.category == "dlp_egress"
    assert payload.expected_outcome == "caught_by_dlp"
    assert payload.ingestion_path == "proposal_dispatch_failure"


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


@pytest.mark.integration
@pytest.mark.asyncio
async def test_planted_key_redacted_before_ledger(
    session_scope_factory: Callable[[], AbstractAsyncContextManager[AsyncSession]],
) -> None:
    """The defense fires: planted key redacted, redaction audited, no refusal row."""
    payload = _load_payload()
    assert isinstance(payload.payload, dict)
    planted_detail = str(payload.payload["failure_detail"])
    planted_prefix = str(payload.payload["planted_secret_prefix"])

    from alfred.state.dispatch_registry import ProposalContext

    class _NoEffects:
        async def reset_breaker(self, component_id: str, *, operator_user_id: str) -> None: ...

    ctx = ProposalContext(
        audit_writer=AuditWriter(session_factory=session_scope_factory),
        effects=_NoEffects(),  # type: ignore[arg-type]
        logger=structlog.get_logger("test"),
        outbound_dlp=_identity_dlp(),
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
        failure_detail=planted_detail,
        operator_user_id=None,
        correlation_id="de-2026-005",
        framework_error_kind=None,
    )

    async with session_scope_factory() as s:
        row = (await s.execute(select(ProcessedProposal))).scalar_one()
        audit = list((await s.execute(select(AuditEntry))).scalars().all())

    assert row.failure_detail is not None
    assert planted_prefix not in row.failure_detail
    assert planted_detail not in row.failure_detail

    redacted = [a for a in audit if a.event == "state.proposal.failure_detail_redacted"]
    assert len(redacted) == 1
    assert redacted[0].subject["dlp_redactions_count"] >= 1
    assert redacted[0].result == "dispatched_with_redactions"
    assert [a for a in audit if a.event == "security.dlp_outbound_refused"] == []
