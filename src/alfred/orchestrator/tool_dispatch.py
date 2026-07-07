"""The single tool-dispatch trust-boundary chokepoint (#339 PR2, spec §3/§6).

Resolve → validate args → capability-gate (named ``tool.dispatch`` hookpoint) →
dispatch → classify. The planner receives ONLY a schema-extracted,
``downgrade_to_orchestrator``-cleared, DLP-scanned T2 string — never raw T3
(HARD rule #5). Every branch audits (HARD rule #7). Canary + DLP-canary +
downgrade-clearance failures ESCALATE (loud audit + re-raise, halt the turn);
all other tool failures are recoverable error ``tool_result`` strings the
planner can adapt to.

Layering note (arch-003 follow-up): importing the ``web_fetch``-plugin-specific
error taxonomy here is a deliberate one-tool inversion. A common tool-error
taxonomy is tracked as a follow-up once a second T3 tool lands.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import structlog

from alfred.audit.audit_row_schemas import TOOL_DISPATCH_FIELDS, TOOL_DISPATCH_TIMEOUT_FIELDS
from alfred.egress.response_inspection import InboundCanaryTripped
from alfred.errors import AlfredError
from alfred.i18n import t
from alfred.orchestrator.tool_hookpoints import TOOL_DISPATCH_HOOKPOINT, TOOL_DISPATCH_PLUGIN_ID
from alfred.orchestrator.tool_registry import (
    ExternalToolSpec,
    InternalToolSpec,
    ToolInvocation,
    arguments_conform,
)
from alfred.plugins.web_fetch.errors import (
    WebFetchActionTimeout,
    WebFetchDomainNotAllowed,
    WebFetchError,
    WebFetchRateLimited,
)
from alfred.security.dlp import OutboundCanaryTripped
from alfred.security.quarantine import TypedRefusal, downgrade_to_orchestrator

if TYPE_CHECKING:
    from alfred.audit.log import AuditWriter
    from alfred.egress.egress_id import TurnEgressContext
    from alfred.hooks.capability import CapabilityGate
    from alfred.orchestrator.tool_registry import ToolRegistry
    from alfred.providers.base import ToolCall
    from alfred.security.dlp import OutboundDlpProtocol

_log = structlog.get_logger(__name__)


async def dispatch_tool(
    call: ToolCall,
    call_index: int,
    *,
    ctx: TurnEgressContext,
    registry: ToolRegistry,
    gate: CapabilityGate,
    dlp: OutboundDlpProtocol,
    audit: AuditWriter,
    user_id: str,
    correlation_id: str,
    language: str | None,
) -> str:
    """Dispatch one tool call through the trust boundary; return a T2 string.

    Args:
        call: The provider-parsed tool-use request.
        call_index: The per-turn monotonic dispatch index (threaded to the
            egress path unchanged; the increment is PR3's loop).
        ctx: The committed per-turn egress anchor.
        registry: The tool registry to resolve ``call.name`` against.
        gate: The capability gate (real ``RealGate`` — never a permissive shim).
        dlp: The outbound DLP scanner applied to the extracted T2.
        audit: The audit writer — every branch writes exactly one dispatch row.
        user_id: The canonical triggering user id (forensic attribution).
        correlation_id: The turn correlation id (also the audit ``trace_id``).
        language: The active user's BCP-47 language, threaded to the tool
            invocation (the SOURCE — real ``User.language`` — is wired in PR3).

    Returns:
        The T2 ``tool_result`` string handed to the planner: the extracted +
        downgrade-cleared + DLP-scanned content on success, or a ``t()`` error
        message on a recoverable failure.

    Raises:
        Re-raises the original security event on the ESCALATION paths
        (``InboundCanaryTripped``, ``OutboundCanaryTripped``, the downgrade
        clearance ``AlfredError``, or any unexpected exception) — a canary trip
        or a clearance denial is a turn halt, never a recoverable tool result.
    """

    async def _audit(
        *,
        dispatch_outcome: str,
        result: str,
        tool_name: str,
        result_tier: str | None,
    ) -> None:
        await audit.append_schema(
            fields=TOOL_DISPATCH_FIELDS,
            schema_name="TOOL_DISPATCH_FIELDS",
            event="tool.dispatch",
            actor_user_id=user_id,
            subject={
                "tool_name": tool_name,
                "call_id": call.id,
                "call_index": call_index,
                "result_tier": result_tier,
                "dispatch_outcome": dispatch_outcome,
                "triggering_user_id": user_id,
                "correlation_id": correlation_id,
                # §10 audit-graph disambiguator (arch-002).
                "phase": f"tool_dispatch:{tool_name}:{call_index}",
            },
            trust_tier_of_trigger="T2",
            result=result,
            cost_estimate_usd=0.0,
            trace_id=correlation_id,
        )

    spec = registry.get(call.name)
    if spec is None:
        await _audit(
            dispatch_outcome="unknown_tool", result="refused", tool_name=call.name, result_tier=None
        )
        return t("orchestrator.tool.unknown_tool", tool=call.name)

    if not arguments_conform(call.arguments, spec.definition.input_schema):
        await _audit(
            dispatch_outcome="invalid_arguments",
            result="refused",
            tool_name=spec.name,
            result_tier=spec.result_tier,
        )
        return t("orchestrator.tool.invalid_arguments", tool=spec.name)

    if not gate.check(
        plugin_id=TOOL_DISPATCH_PLUGIN_ID,
        hookpoint=TOOL_DISPATCH_HOOKPOINT,
        requested_tier="system",
    ):
        await _audit(
            dispatch_outcome="gate_denied",
            result="refused",
            tool_name=spec.name,
            result_tier=spec.result_tier,
        )
        return t("orchestrator.tool.not_permitted", tool=spec.name)

    invocation = ToolInvocation(
        arguments=call.arguments,
        ctx=ctx,
        call_index=call_index,
        user_id=user_id,
        correlation_id=correlation_id,
        language=language,
    )

    if isinstance(spec, InternalToolSpec):
        try:
            content = await spec.dispatch(invocation)
        except Exception:
            # sec-003 totality (mirrors the external T3 arm): an internal tool
            # raising must NOT escape the chokepoint unaudited (HARD #7).
            await _audit(
                dispatch_outcome="unexpected_error",
                result="fault",
                tool_name=spec.name,
                result_tier="T2",
            )
            raise
        await _audit(
            dispatch_outcome="dispatched", result="success", tool_name=spec.name, result_tier="T2"
        )
        return content

    # ExternalToolSpec — the T3 leg. ``dispatch_web_fetch`` already fused
    # fetch+extract and returns a T2 EgressExtractOutcome (spec §6.2).
    external: ExternalToolSpec = spec
    try:
        outcome = await external.dispatch(invocation)
    except InboundCanaryTripped:
        # The response-inspection seam already recorded its terminal
        # TypedRefusal to the ledger; ESCALATE (halt the turn).
        await _audit(
            dispatch_outcome="canary_tripped",
            result="quarantined",
            tool_name=external.name,
            result_tier="T3",
        )
        raise
    except WebFetchRateLimited:
        await _audit(
            dispatch_outcome="rate_limited",
            result="rate_limited",
            tool_name=external.name,
            result_tier="T3",
        )
        return t("orchestrator.tool.rate_limited", tool=external.name)
    except WebFetchDomainNotAllowed:
        await _audit(
            dispatch_outcome="domain_not_allowed",
            result="refused",
            tool_name=external.name,
            result_tier="T3",
        )
        return t("orchestrator.tool.domain_not_allowed", tool=external.name)
    except WebFetchActionTimeout as exc:
        # #347 blocker 2: enrich the timeout row with the forensic fields the
        # dispatcher packaged (egress_id / destination host / in_doubt / ledger
        # state). Non-skippable (symmetric-key append_schema); HARD rule #7. The
        # forensic fields ride the exception — this chokepoint holds no ledger.
        # MUST precede `except WebFetchError` (subclass-before-base): otherwise
        # the generic arm below swallows it and the forensic fields are lost.
        await audit.append_schema(
            fields=TOOL_DISPATCH_TIMEOUT_FIELDS,
            schema_name="TOOL_DISPATCH_TIMEOUT_FIELDS",
            event="tool.dispatch",
            actor_user_id=user_id,
            subject={
                "tool_name": external.name,
                "call_id": call.id,
                "call_index": call_index,
                "result_tier": "T3",
                "dispatch_outcome": "timeout",
                "triggering_user_id": user_id,
                "correlation_id": correlation_id,
                "phase": f"tool_dispatch:{external.name}:{call_index}",
                "egress_id": exc.egress_id,
                "destination_host": exc.destination_host,
                "in_doubt": exc.in_doubt,
                "ledger_state": exc.ledger_state,
            },
            trust_tier_of_trigger="T2",
            result="refused",
            cost_estimate_usd=0.0,
            trace_id=correlation_id,
        )
        return t("orchestrator.tool.timeout", tool=external.name)
    except WebFetchError:
        await _audit(
            dispatch_outcome="tool_error",
            result="refused",
            tool_name=external.name,
            result_tier="T3",
        )
        return t("orchestrator.tool.error", tool=external.name)
    except TimeoutError:
        # Defensive fallback ONLY: a bare TimeoutError from an unexpected source
        # (NOT the web.fetch action-deadline path, which is now typed
        # WebFetchActionTimeout and handled above with the enriched forensic
        # row). Still audited + recoverable (HARD #7 totality) but tagged
        # "unexpected_timeout" (distinct from the enriched "timeout" token) and
        # logged loudly so a stray bare TimeoutError stays greppable.
        _log.warning(
            "orchestrator.tool_dispatch.unexpected_timeout",
            tool_name=external.name,
            call_index=call_index,
            correlation_id=correlation_id,
        )
        await _audit(
            dispatch_outcome="unexpected_timeout",
            result="refused",
            tool_name=external.name,
            result_tier="T3",
        )
        return t("orchestrator.tool.timeout", tool=external.name)
    except Exception:
        # sec-003 defensive arm (placed LAST): a bug, a new error type, or an
        # un-enumerated canary must never escape unaudited (HARD rule #7).
        await _audit(
            dispatch_outcome="unexpected_error",
            result="fault",
            tool_name=external.name,
            result_tier="T3",
        )
        raise

    result = outcome.result
    if isinstance(result, TypedRefusal):
        await _audit(
            dispatch_outcome="tool_refused",
            result="refused",
            tool_name=external.name,
            result_tier="T3",
        )
        return t("orchestrator.tool.refused", tool=external.name, reason=result.reason)

    # ``result`` is Extracted — cross the SECOND boundary into the planner.
    #
    # The WHOLE post-dispatch region (downgrade → json.dumps → dlp.scan →
    # terminal audit) is guarded so NO path escapes unaudited (HARD #7): the two
    # security refusals get their specific terminal rows, and ANY other
    # unexpected exception — a downgrade-side bug, a non-serialisable downgraded
    # value (``json.dumps`` TypeError), or a non-canary DLP fault — gets the
    # defensive ``unexpected_error``/``fault`` row before re-raising (sec-003,
    # mirroring the dispatch arm above). ``audited`` records whether an inner arm
    # already wrote the terminal row, so the broad arm never double-audits nor
    # mislabels an already-classified refusal.
    audited = False
    try:
        try:
            # Tightly scoped to the downgrade call ONLY: downgrade_to_orchestrator
            # raises a bare AlfredError SOLELY on clearance-deny (quarantine.py:1498),
            # so this arm cannot mask any other AlfredError (sec-004 / FIX-8d).
            data = await downgrade_to_orchestrator(result.data, gate=gate, audit_writer=audit)
        except AlfredError:
            await _audit(
                dispatch_outcome="downgrade_denied",
                result="refused",
                tool_name=external.name,
                result_tier="T3",
            )
            audited = True
            raise  # ESCALATE — a clearance denial is a security refusal, not a result.

        try:
            clean = dlp.scan(json.dumps(data))
        except OutboundCanaryTripped:
            await _audit(
                dispatch_outcome="dlp_canary",
                result="quarantined",
                tool_name=external.name,
                result_tier="T3",
            )
            audited = True
            raise  # ESCALATE — a canary in the EXTRACTED T2 is a serious leak.

        await _audit(
            dispatch_outcome="dispatched",
            result="success",
            tool_name=external.name,
            result_tier="T3",
        )
        return clean
    except Exception:
        # sec-003 totality: an exception the specific arms did NOT already audit
        # (e.g. json.dumps on a non-serialisable value) must still leave a loud
        # terminal row before propagating. Already-audited refusals fall through
        # untouched (``audited`` guard) so their classification is preserved.
        if not audited:
            await _audit(
                dispatch_outcome="unexpected_error",
                result="fault",
                tool_name=external.name,
                result_tier="T3",
            )
        raise
