"""``ProposalContext.outbound_dlp`` is a required, protocol-typed field (#173).

PR-S4-2 threads the outbound DLP scanner through the dispatch context so
``_record_failure`` can scan ``failure_detail`` before it lands in the
ledger. The field is REQUIRED (no default) so a future construction site
that forgets to wire the scanner fails loudly at construction rather than
silently disarming the boundary.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Mapping
from unittest.mock import AsyncMock

import pytest
import structlog

from alfred.audit.log import AuditWriter
from alfred.security.dlp import OutboundDlp, OutboundDlpProtocol
from alfred.state.dispatch_registry import ProposalContext, ProposalEffectsProtocol


def _outbound_dlp_stub() -> OutboundDlp:
    class _IdentityBroker:
        def redact(self, text: str) -> str:
            return text

    def _sink(*, event: str, subject: Mapping[str, object]) -> None:
        return None

    return OutboundDlp(broker=_IdentityBroker(), audit=_sink)


def test_proposal_context_has_outbound_dlp_field() -> None:
    """ProposalContext declares an outbound_dlp field."""
    fields = {f.name for f in dataclasses.fields(ProposalContext)}
    assert "outbound_dlp" in fields


def test_proposal_context_outbound_dlp_required_no_default() -> None:
    """Instantiation without outbound_dlp raises TypeError (required field)."""
    with pytest.raises(TypeError, match="outbound_dlp"):
        ProposalContext(  # type: ignore[call-arg]
            audit_writer=AsyncMock(spec=AuditWriter),
            effects=AsyncMock(spec=ProposalEffectsProtocol),
            logger=structlog.get_logger("test"),
        )


def test_proposal_context_outbound_dlp_satisfies_protocol() -> None:
    """A constructed instance round-trips the OutboundDlpProtocol assertion."""
    ctx = ProposalContext(
        audit_writer=AsyncMock(spec=AuditWriter),
        effects=AsyncMock(spec=ProposalEffectsProtocol),
        logger=structlog.get_logger("test"),
        outbound_dlp=_outbound_dlp_stub(),
    )
    assert isinstance(ctx.outbound_dlp, OutboundDlpProtocol)
