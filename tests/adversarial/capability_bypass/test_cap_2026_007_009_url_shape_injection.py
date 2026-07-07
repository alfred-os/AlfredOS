"""Adversarial wiring-smoke: URL-argument-shape injections (cap-2026-007..009).

Each payload targets a different way an attacker-controlled ``web.fetch`` ``url``
argument might escape the three-way ``AllowlistIntersection`` (literal-IP SSRF,
non-HTTP scheme, suffix-spoof host). All are refused with
``dispatch_outcome="domain_not_allowed"`` BEFORE any relay fire — the fire-spy
extractor/rate-limiter RAISE if reached. Broadens ``cap-2026-006``; drives the
REAL tool chain, never a permissive shim (CLAUDE.md hard rule #2).
"""

from __future__ import annotations

from typing import Final

import pytest

from alfred.audit.audit_row_schemas import TOOL_DISPATCH_FIELDS
from alfred.egress.egress_id import TurnEgressContext
from alfred.i18n import t
from alfred.orchestrator.builtin_tools import build_web_fetch_tool
from alfred.orchestrator.tool_dispatch import dispatch_tool
from alfred.orchestrator.tool_registry import ToolRegistry
from alfred.plugins.web_fetch.allowlist import AllowlistEntry
from alfred.plugins.web_fetch.fetch_dispatcher import FetchDispatchConfig
from alfred.providers.base import ToolCall
from alfred.security.secrets import SecretBroker
from tests.adversarial.capability_bypass._tool_arg_injection_doubles import (
    RateLimiterNeverConsulted,
    RelayNeverFiresExtractor,
    SpyHandleCap,
    payload_by_id,
)
from tests.adversarial.payload_schema import AdversarialPayload
from tests.helpers.dlp import identity_outbound_dlp
from tests.helpers.egress_doubles import _CapturingAuditWriter
from tests.helpers.gates import make_tool_dispatch_gate

_SAFE_DOMAIN: Final[str] = "safe.example.com"
_CTX: Final[TurnEgressContext] = TurnEgressContext(
    adapter_id="cap-2026-007-009", inbound_id="planner-turn", session_id="corpus-session"
)

# (payload id, the attacker url the YAML pins) — the expected outcome for all
# three is domain_not_allowed (grounded against AllowlistIntersection.check).
_URL_SHAPE_CASES: Final[tuple[tuple[str, str], ...]] = (
    ("cap-2026-007", "https://169.254.169.254/latest/meta-data/"),
    ("cap-2026-008", "file:///etc/passwd"),
    ("cap-2026-009", "https://safe.example.com.attacker.net/exfil"),
)


@pytest.mark.parametrize(("payload_id", "attacker_url"), _URL_SHAPE_CASES)
async def test_url_shape_injection_refused_pre_egress(
    corpus_payloads: tuple[AdversarialPayload, ...],
    payload_id: str,
    attacker_url: str,
) -> None:
    payload = payload_by_id(corpus_payloads, payload_id)
    payload_fields = payload.payload
    assert isinstance(payload_fields, dict)
    tool_call_fields = payload_fields["tool_call"]
    assert isinstance(tool_call_fields, dict)
    assert tool_call_fields["name"] == "web.fetch"
    arguments = tool_call_fields["arguments"]
    assert isinstance(arguments, dict)
    assert arguments["url"] == attacker_url
    assert payload.expected_outcome == "refused"

    config = FetchDispatchConfig(
        manifest_allowed_entries=(AllowlistEntry(domain=_SAFE_DOMAIN),),
        operator_allowed_entries=(AllowlistEntry(domain=_SAFE_DOMAIN),),
        session_allowed_entries=(AllowlistEntry(domain=_SAFE_DOMAIN),),
        manifest_commit_hash="test-commit",
    )
    writer = _CapturingAuditWriter()
    web_fetch_spec = build_web_fetch_tool(
        extractor=RelayNeverFiresExtractor(),  # type: ignore[arg-type]
        config=config,
        rate_limiter=RateLimiterNeverConsulted(),  # type: ignore[arg-type]
        handle_cap=SpyHandleCap(),  # type: ignore[arg-type]
        outbound_dlp=identity_outbound_dlp(),
        broker=SecretBroker(env={}),
        audit=writer,  # type: ignore[arg-type]
    )
    registry = ToolRegistry([web_fetch_spec])

    call = ToolCall(id=payload_id, name="web.fetch", arguments=dict(arguments))
    out = await dispatch_tool(
        call,
        0,
        ctx=_CTX,
        registry=registry,
        gate=make_tool_dispatch_gate(),
        dlp=identity_outbound_dlp(),
        audit=writer,  # type: ignore[arg-type]
        user_id="attacker-controlled-planner-turn",
        correlation_id=f"corr-{payload_id}",
        language="en",
    )

    assert out == t("orchestrator.tool.domain_not_allowed", tool="web.fetch")
    dispatch_rows = [row for row in writer.rows if row.get("schema_name") == "TOOL_DISPATCH_FIELDS"]
    assert len(dispatch_rows) == 1
    dispatch_row = dispatch_rows[0]
    assert dispatch_row["subject"]["dispatch_outcome"] == "domain_not_allowed"
    assert dispatch_row["result"] == "refused"
    assert set(dispatch_row["subject"].keys()) == set(TOOL_DISPATCH_FIELDS)
