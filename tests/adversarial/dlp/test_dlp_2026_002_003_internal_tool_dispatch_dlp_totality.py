"""Adversarial corpus: `InternalToolSpec` DLP-scan surface (#410 PR3 Task 2a).

`dlp-2026-002` (canary trip) and `dlp-2026-003` (non-canary DLP fault) drive
the REAL `dispatch_tool` chokepoint against a REAL `InternalToolSpec` — the
trust-boundary gap this task closed. Before Task 2a, `dispatch_tool`'s
`InternalToolSpec` branch never called `dlp.scan()` at all (the `dlp`
parameter it received was simply unused on that leg). The corrected fix's
totality wrapper (finding sec-001, triple-confirmed) is itself untestable by
line/branch coverage alone — coverage tooling reports on lines/branches
PRESENT in the file, not an ABSENT `except` clause — so these two payloads
close the gap by asserting the observable behaviour end-to-end: a future
regression on either arm (the canary escalation, or the non-canary-fault
audit) fails the corpus, not just the unit suite.

`dlp-2026-002` wires a REAL `OutboundDlp` to a REAL `CanaryMatcher` holding
the payload's registered token — never a permissive DLP shim.
`dlp-2026-003` mirrors the unit-test double
(`tests/unit/orchestrator/test_tool_dispatch.py::test_internal_tool_dlp_non_canary_fault_is_audited`)
— the exact non-canary-fault shape `OutboundDlp.scan()` is deliberately
designed to let propagate rather than swallow (CLAUDE.md hard rule #7).
"""

from __future__ import annotations

from collections.abc import Mapping

import pytest

from alfred.egress.egress_id import TurnEgressContext
from alfred.orchestrator.tool_dispatch import dispatch_tool
from alfred.orchestrator.tool_registry import InternalToolSpec, ToolInvocation, ToolRegistry
from alfred.providers.base import ToolCall, ToolDefinition
from alfred.security.canary_matcher import CanaryMatcher, CanaryToken
from alfred.security.dlp import OutboundCanaryTripped, OutboundDlp
from tests.adversarial.payload_schema import AdversarialPayload
from tests.helpers.egress_doubles import _CapturingAuditWriter
from tests.helpers.gates import make_tool_dispatch_gate

_CTX = TurnEgressContext(
    adapter_id="dlp-2026-002-003", inbound_id="planner-turn", session_id="corpus-session"
)


def _payload_by_id(
    corpus_payloads: tuple[AdversarialPayload, ...], payload_id: str
) -> AdversarialPayload:
    """Filter the session-scoped corpus to one payload, failing loudly on a
    missing/duplicate id (mirrors `capability_bypass/_tool_arg_injection_doubles.payload_by_id`)."""
    matches = [p for p in corpus_payloads if p.id == payload_id]
    if len(matches) != 1:
        raise pytest.UsageError(
            f"adversarial corpus must have exactly one payload id={payload_id!r}; "
            f"found {len(matches)} under tests/adversarial/dlp/"
        )
    return matches[0]


def _int_spec(*, result_text: str) -> InternalToolSpec:
    """A `clock.now`-shaped `InternalToolSpec` whose dispatch returns a fixed
    T2 string — the surface `dispatch_tool`'s `InternalToolSpec` leg now
    DLP-scans before returning to the planner (#410 PR3 Task 2a)."""

    async def _d(_inv: ToolInvocation) -> str:
        return result_text

    return InternalToolSpec(
        name="clock.now",
        definition=ToolDefinition(
            name="clock.now",
            description="d",
            input_schema={"type": "object", "properties": {}},
        ),
        dispatch=_d,
    )


async def _dispatch(spec: InternalToolSpec, *, dlp: object, writer: _CapturingAuditWriter) -> str:
    registry = ToolRegistry([spec])
    return await dispatch_tool(
        ToolCall(id="1", name="clock.now", arguments={}),
        0,
        ctx=_CTX,
        registry=registry,
        gate=make_tool_dispatch_gate(),
        dlp=dlp,  # type: ignore[arg-type]
        audit=writer,  # type: ignore[arg-type]
        user_id="attacker-controlled-planner-turn",
        correlation_id="corr-internal-dlp",
        language="en",
    )


async def test_internal_tool_dlp_canary_escalates(
    corpus_payloads: tuple[AdversarialPayload, ...],
) -> None:
    """dlp-2026-002: a canary-bearing InternalToolSpec result ESCALATES
    (dlp_canary/quarantined audit row, OutboundCanaryTripped propagates) —
    driven through a REAL OutboundDlp + CanaryMatcher, not a stub."""
    payload = _payload_by_id(corpus_payloads, "dlp-2026-002")
    assert payload.expected_outcome == "quarantined"
    assert isinstance(payload.payload, dict)
    result_text = str(payload.payload["result"])
    canary_token = str(payload.payload["canary_token"])
    # YAML<->test fidelity: the token the test registers with CanaryMatcher
    # must actually be the one embedded in the tool's own result text.
    assert canary_token in result_text

    def _audit_sink(*, event: str, subject: Mapping[str, object]) -> None:
        return None

    dlp = OutboundDlp(
        broker=None,
        audit=_audit_sink,
        canary=CanaryMatcher(tokens=[CanaryToken(value=canary_token)]),
    )
    writer = _CapturingAuditWriter()
    with pytest.raises(OutboundCanaryTripped):
        await _dispatch(_int_spec(result_text=result_text), dlp=dlp, writer=writer)

    rows = [r for r in writer.rows if r.get("schema_name") == "TOOL_DISPATCH_FIELDS"]
    assert len(rows) == 1
    assert rows[0]["subject"]["dispatch_outcome"] == "dlp_canary"
    assert rows[0]["subject"]["result_tier"] == "T2"
    assert rows[0]["result"] == "quarantined"


class _RaisingDlp:
    """A non-canary `dlp.scan()` fault (broker.redact bug, DLP-internal
    audit-sink failure, canary-matcher bug) — the exact shape
    `OutboundDlp.scan()` is deliberately designed to propagate rather than
    swallow (CLAUDE.md hard rule #7; see `src/alfred/security/dlp.py`)."""

    def scan(self, text: str) -> str:
        raise ValueError("simulated broker.redact bug")


async def test_internal_tool_dlp_non_canary_fault_is_audited(
    corpus_payloads: tuple[AdversarialPayload, ...],
) -> None:
    """dlp-2026-003 (sec-001 correction): a non-canary DLP fault on the
    InternalToolSpec leg must still leave a loud terminal audit row
    (unexpected_error/fault) before propagating — it must NOT escape the
    tool-dispatch chokepoint unaudited."""
    payload = _payload_by_id(corpus_payloads, "dlp-2026-003")
    assert payload.expected_outcome == "audit_row_emitted"

    writer = _CapturingAuditWriter()
    with pytest.raises(ValueError):
        await _dispatch(_int_spec(result_text="13:00Z"), dlp=_RaisingDlp(), writer=writer)

    rows = [r for r in writer.rows if r.get("schema_name") == "TOOL_DISPATCH_FIELDS"]
    assert len(rows) == 1
    assert rows[0]["subject"]["dispatch_outcome"] == "unexpected_error"
    assert rows[0]["subject"]["result_tier"] == "T2"
    assert rows[0]["result"] == "fault"
