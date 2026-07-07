"""Adversarial wiring-smoke: dispatch-perimeter injections (cap-2026-010..011).

An unknown tool name and a web.fetch call missing its required url are both
refused by dispatch_tool at the registry-resolution / argument-validation
perimeter, BEFORE dispatch_web_fetch runs. Broadens cap-2026-006; drives the
REAL dispatch_tool chokepoint, never a permissive shim (CLAUDE.md hard rule #2).
"""

from __future__ import annotations

from typing import Final

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
    adapter_id="cap-2026-010-011", inbound_id="planner-turn", session_id="corpus-session"
)


def _registry_with_real_web_fetch(writer: _CapturingAuditWriter) -> ToolRegistry:
    config = FetchDispatchConfig(
        manifest_allowed_entries=(AllowlistEntry(domain=_SAFE_DOMAIN),),
        operator_allowed_entries=(AllowlistEntry(domain=_SAFE_DOMAIN),),
        session_allowed_entries=(AllowlistEntry(domain=_SAFE_DOMAIN),),
        manifest_commit_hash="test-commit",
    )
    web_fetch_spec = build_web_fetch_tool(
        extractor=RelayNeverFiresExtractor(),  # type: ignore[arg-type]
        config=config,
        rate_limiter=RateLimiterNeverConsulted(),  # type: ignore[arg-type]
        handle_cap=SpyHandleCap(),  # type: ignore[arg-type]
        outbound_dlp=identity_outbound_dlp(),
        broker=SecretBroker(env={}),
        audit=writer,  # type: ignore[arg-type]
    )
    return ToolRegistry([web_fetch_spec])


async def _dispatch(writer: _CapturingAuditWriter, call: ToolCall) -> str:
    return await dispatch_tool(
        call,
        0,
        ctx=_CTX,
        registry=_registry_with_real_web_fetch(writer),
        gate=make_tool_dispatch_gate(),
        dlp=identity_outbound_dlp(),
        audit=writer,  # type: ignore[arg-type]
        user_id="attacker-controlled-planner-turn",
        correlation_id="corr-perimeter",
        language="en",
    )


async def test_unknown_tool_refused(
    corpus_payloads: tuple[AdversarialPayload, ...],
) -> None:
    payload = payload_by_id(corpus_payloads, "cap-2026-010")
    assert payload.expected_outcome == "refused"
    tool_call = payload.payload["tool_call"]  # type: ignore[index]
    assert isinstance(tool_call, dict)
    arguments = tool_call["arguments"]
    assert isinstance(arguments, dict)
    writer = _CapturingAuditWriter()
    # Dispatch the payload's REAL attacker arguments (YAML↔test fidelity) — the
    # registry-resolution refusal fires before any arg parsing, so they are
    # never acted on, but the test drives what the YAML actually pins.
    out = await _dispatch(
        writer,
        ToolCall(id="cap-2026-010", name=str(tool_call["name"]), arguments=dict(arguments)),
    )
    assert out == t("orchestrator.tool.unknown_tool", tool=str(tool_call["name"]))
    rows = [r for r in writer.rows if r.get("schema_name") == "TOOL_DISPATCH_FIELDS"]
    assert len(rows) == 1
    assert rows[0]["subject"]["dispatch_outcome"] == "unknown_tool"
    assert rows[0]["result"] == "refused"
    assert set(rows[0]["subject"].keys()) == set(TOOL_DISPATCH_FIELDS)


async def test_missing_required_arg_refused(
    corpus_payloads: tuple[AdversarialPayload, ...],
) -> None:
    payload = payload_by_id(corpus_payloads, "cap-2026-011")
    assert payload.expected_outcome == "refused"
    tool_call = payload.payload["tool_call"]  # type: ignore[index]
    assert isinstance(tool_call, dict)
    arguments = tool_call["arguments"]
    assert isinstance(arguments, dict)
    assert "url" not in arguments  # the injection: required arg omitted
    writer = _CapturingAuditWriter()
    out = await _dispatch(
        writer, ToolCall(id="cap-2026-011", name="web.fetch", arguments=dict(arguments))
    )
    assert out == t("orchestrator.tool.invalid_arguments", tool="web.fetch")
    rows = [r for r in writer.rows if r.get("schema_name") == "TOOL_DISPATCH_FIELDS"]
    assert len(rows) == 1
    assert rows[0]["subject"]["dispatch_outcome"] == "invalid_arguments"
    assert rows[0]["result"] == "refused"
    assert set(rows[0]["subject"].keys()) == set(TOOL_DISPATCH_FIELDS)
