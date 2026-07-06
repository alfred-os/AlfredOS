"""Branch matrix for ``dispatch_tool`` — the #339 PR2 trust-boundary chokepoint.

Every branch asserts BOTH the observable outcome (the returned ``tool_result``
string on the recoverable paths, or the propagated exception on the escalation
paths) AND the loud audit row (``dispatch_outcome`` + ``result``) — the exact
HARD-#7 property that no dispatch leaves the chokepoint unaudited.

The gate is a real :class:`RealGate` fixture (:func:`make_tool_dispatch_gate` /
:func:`make_deny_all_gate`), never a permissive shim (CLAUDE.md HARD rule #2):
the T3 leg crosses two gate surfaces and a shim would hide a grant-policy
regression at either.
"""

from __future__ import annotations

import json
from typing import ClassVar, Literal

import pytest

from alfred.egress.egress_id import TurnEgressContext
from alfred.egress.egress_response_extract import EgressExtractOutcome
from alfred.egress.response_inspection import InboundCanaryTripped
from alfred.errors import AlfredError
from alfred.hooks.capability import CapabilityGate
from alfred.orchestrator.tool_dispatch import dispatch_tool
from alfred.orchestrator.tool_registry import (
    ExternalToolSpec,
    InternalToolSpec,
    ToolInvocation,
    ToolRegistry,
    ToolSpec,
)
from alfred.plugins.web_fetch.errors import (
    WebFetchDomainNotAllowed,
    WebFetchError,
    WebFetchRateLimited,
)
from alfred.providers.base import ToolCall, ToolDefinition
from alfred.security.dlp import OutboundCanaryTripped
from alfred.security.quarantine import (
    Extracted,
    ExtractionSchema,
    T3DerivedData,
    TypedRefusal,
)
from tests.helpers.egress_doubles import _CapturingAuditWriter
from tests.helpers.gates import make_deny_all_gate, make_tool_dispatch_gate

_CTX = TurnEgressContext(adapter_id="a", inbound_id="i", session_id="s")


class _Schema(ExtractionSchema):
    schema_version: ClassVar[Literal[1]] = 1
    text: str
    intent: str


def _extracted_outcome() -> EgressExtractOutcome:
    """A T2 ``Extracted`` outcome — the fused fetch+extract has already crossed
    the T3→T2 boundary; ``dispatch_tool`` then downgrades + DLP-scans it."""
    return EgressExtractOutcome(
        result=Extracted(
            data=T3DerivedData({"text": "hi", "intent": "greet"}),
            extraction_mode="native_constrained",
        ),
        deduplicated=False,
        language="en",
        status=200,
    )


def _ext_spec(
    *,
    returns: EgressExtractOutcome | None = None,
    raises: BaseException | None = None,
) -> ExternalToolSpec:
    async def _d(_inv: ToolInvocation) -> EgressExtractOutcome:
        if raises is not None:
            raise raises
        if returns is None:
            raise AssertionError("dispatch should not have run")
        return returns

    return ExternalToolSpec(
        name="web.fetch",
        definition=ToolDefinition(
            name="web.fetch",
            description="d",
            input_schema={"type": "object", "required": ["url"]},
        ),
        extraction_schema=_Schema,
        dispatch=_d,
    )


def _int_spec() -> InternalToolSpec:
    async def _d(_inv: ToolInvocation) -> str:
        return "13:00Z"

    return InternalToolSpec(
        name="clock.now",
        definition=ToolDefinition(
            name="clock.now",
            description="d",
            input_schema={"type": "object", "properties": {}},
        ),
        dispatch=_d,
    )


class _NoopDlp:
    """Pass-through DLP scanner — the extracted T2 carries no canary."""

    def scan(self, text: str) -> str:
        return text


class _CanaryDlp:
    """A DLP scanner that trips on the extracted T2 — the serious-leak path."""

    def scan(self, text: str) -> str:
        raise OutboundCanaryTripped(token="tok")  # noqa: S106


async def _dispatch(
    call: ToolCall,
    spec: ToolSpec | None,
    *,
    gate: CapabilityGate,
    dlp: object,
    writer: _CapturingAuditWriter,
) -> str:
    registry = ToolRegistry([spec] if spec is not None else [])
    return await dispatch_tool(
        call,
        0,
        ctx=_CTX,
        registry=registry,
        gate=gate,
        dlp=dlp,  # type: ignore[arg-type]
        audit=writer,  # type: ignore[arg-type]
        user_id="u",
        correlation_id="c",
        language="en",
    )


def _url_call() -> ToolCall:
    return ToolCall(id="1", name="web.fetch", arguments={"url": "https://x"})


# --------------------------------------------------------------------------- #
# Recoverable branches — return a t() error tool_result + a loud audit row.
# --------------------------------------------------------------------------- #


async def test_unknown_tool_recoverable_and_audited() -> None:
    writer = _CapturingAuditWriter()
    out = await _dispatch(
        ToolCall(id="1", name="nope", arguments={}),
        None,
        gate=make_tool_dispatch_gate(),
        dlp=_NoopDlp(),
        writer=writer,
    )
    assert "nope" in out
    assert writer.rows[-1]["subject"]["dispatch_outcome"] == "unknown_tool"
    assert writer.rows[-1]["result"] == "refused"


async def test_invalid_arguments_recoverable_and_audited() -> None:
    writer = _CapturingAuditWriter()
    await _dispatch(
        ToolCall(id="1", name="web.fetch", arguments={}),
        _ext_spec(),
        gate=make_tool_dispatch_gate(),
        dlp=_NoopDlp(),
        writer=writer,
    )
    assert writer.rows[-1]["subject"]["dispatch_outcome"] == "invalid_arguments"
    assert writer.rows[-1]["result"] == "refused"


async def test_gate_denied_recoverable_and_audited() -> None:
    writer = _CapturingAuditWriter()
    await _dispatch(
        _url_call(),
        _ext_spec(),
        gate=make_deny_all_gate(),
        dlp=_NoopDlp(),
        writer=writer,
    )
    assert writer.rows[-1]["subject"]["dispatch_outcome"] == "gate_denied"
    assert writer.rows[-1]["result"] == "refused"


async def test_internal_tool_dispatches_directly() -> None:
    writer = _CapturingAuditWriter()
    out = await _dispatch(
        ToolCall(id="1", name="clock.now", arguments={}),
        _int_spec(),
        gate=make_tool_dispatch_gate(),
        dlp=_NoopDlp(),
        writer=writer,
    )
    assert out == "13:00Z"
    assert writer.rows[-1]["subject"]["dispatch_outcome"] == "dispatched"
    assert writer.rows[-1]["subject"]["result_tier"] == "T2"
    assert writer.rows[-1]["result"] == "success"


async def test_t3_extracted_downgrades_and_dlp_scans() -> None:
    writer = _CapturingAuditWriter()
    out = await _dispatch(
        _url_call(),
        _ext_spec(returns=_extracted_outcome()),
        gate=make_tool_dispatch_gate(),
        dlp=_NoopDlp(),
        writer=writer,
    )
    assert json.loads(out) == {"text": "hi", "intent": "greet"}
    assert writer.rows[-1]["subject"]["dispatch_outcome"] == "dispatched"
    assert writer.rows[-1]["subject"]["result_tier"] == "T3"
    assert writer.rows[-1]["subject"]["phase"] == "tool_dispatch:web.fetch:0"
    assert writer.rows[-1]["result"] == "success"


async def test_t3_typed_refusal_returns_benign_string() -> None:
    writer = _CapturingAuditWriter()
    outcome = EgressExtractOutcome(
        result=TypedRefusal(reason="cannot_extract"),
        deduplicated=False,
        language="en",
        status=200,
    )
    out = await _dispatch(
        _url_call(),
        _ext_spec(returns=outcome),
        gate=make_tool_dispatch_gate(),
        dlp=_NoopDlp(),
        writer=writer,
    )
    assert "cannot_extract" in out
    assert writer.rows[-1]["subject"]["dispatch_outcome"] == "tool_refused"
    assert writer.rows[-1]["result"] == "refused"


@pytest.mark.parametrize(
    ("exc", "outcome_token", "result_token"),
    [
        (WebFetchDomainNotAllowed(domain="attacker.example.net"), "domain_not_allowed", "refused"),
        (WebFetchRateLimited(bucket="per_domain"), "rate_limited", "rate_limited"),
        (WebFetchError("boom"), "tool_error", "refused"),
        (TimeoutError(), "timeout", "refused"),
    ],
)
async def test_t3_recoverable_exceptions(
    exc: BaseException, outcome_token: str, result_token: str
) -> None:
    writer = _CapturingAuditWriter()
    await _dispatch(
        _url_call(),
        _ext_spec(raises=exc),
        gate=make_tool_dispatch_gate(),
        dlp=_NoopDlp(),
        writer=writer,
    )
    assert writer.rows[-1]["subject"]["dispatch_outcome"] == outcome_token
    assert writer.rows[-1]["result"] == result_token


# --------------------------------------------------------------------------- #
# Escalation branches — re-raise (halt the turn) AFTER a loud pre-raise audit.
# --------------------------------------------------------------------------- #


async def test_inbound_canary_escalates() -> None:
    writer = _CapturingAuditWriter()
    with pytest.raises(InboundCanaryTripped):
        await _dispatch(
            _url_call(),
            _ext_spec(raises=InboundCanaryTripped(destination="x", egress_id="e")),
            gate=make_tool_dispatch_gate(),
            dlp=_NoopDlp(),
            writer=writer,
        )
    assert writer.rows[-1]["subject"]["dispatch_outcome"] == "canary_tripped"
    assert writer.rows[-1]["result"] == "quarantined"


async def test_dlp_canary_on_extracted_t2_escalates() -> None:
    writer = _CapturingAuditWriter()
    with pytest.raises(OutboundCanaryTripped):
        await _dispatch(
            _url_call(),
            _ext_spec(returns=_extracted_outcome()),
            gate=make_tool_dispatch_gate(),
            dlp=_CanaryDlp(),
            writer=writer,
        )
    assert writer.rows[-1]["subject"]["dispatch_outcome"] == "dlp_canary"
    assert writer.rows[-1]["result"] == "quarantined"


async def test_downgrade_denied_escalates() -> None:
    writer = _CapturingAuditWriter()
    with pytest.raises(AlfredError):
        await _dispatch(
            _url_call(),
            _ext_spec(returns=_extracted_outcome()),
            # Grants tool.dispatch but DENIES the t3.downgrade_to_orchestrator
            # content-clearance → the second boundary refuses.
            gate=make_tool_dispatch_gate(grant_downgrade=False),
            dlp=_NoopDlp(),
            writer=writer,
        )
    assert writer.rows[-1]["subject"]["dispatch_outcome"] == "downgrade_denied"
    assert writer.rows[-1]["result"] == "refused"


class _UnexpectedBoomError(RuntimeError):
    """A novel exception none of the enumerated dispatch arms recognises."""


async def test_unexpected_error_escalates_and_is_audited() -> None:
    writer = _CapturingAuditWriter()
    with pytest.raises(_UnexpectedBoomError):
        await _dispatch(
            _url_call(),
            _ext_spec(raises=_UnexpectedBoomError()),
            gate=make_tool_dispatch_gate(),
            dlp=_NoopDlp(),
            writer=writer,
        )
    assert writer.rows[-1]["subject"]["dispatch_outcome"] == "unexpected_error"
    assert writer.rows[-1]["result"] == "fault"
