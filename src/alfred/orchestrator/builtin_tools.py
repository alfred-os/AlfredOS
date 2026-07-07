"""The two tools #339 PR2 wires: the internal ≤T2 ``clock.now`` demo tool and the
T3 ``web.fetch`` tool (Task 5). Kept together as the registry's builtin surface."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from typing import TYPE_CHECKING, ClassVar, Final, Literal

from alfred.orchestrator.tool_registry import ExternalToolSpec, InternalToolSpec, ToolInvocation
from alfred.plugins.web_fetch.auth_allowlist import WEB_FETCH_AUTH_SECRET_ALLOWLIST
from alfred.plugins.web_fetch.constants import _DEFAULT_ACTION_DEADLINE_SECONDS
from alfred.plugins.web_fetch.fetch_dispatcher import dispatch_web_fetch
from alfred.providers.base import ToolDefinition
from alfred.security.quarantine import ExtractionSchema

if TYPE_CHECKING:
    from alfred.audit.log import AuditWriter
    from alfred.egress.egress_response_extract import EgressExtractOutcome, EgressResponseExtractor
    from alfred.plugins.web_fetch.auth_allowlist import _SecretSubstituter
    from alfred.plugins.web_fetch.fetch_dispatcher import FetchDispatchConfig
    from alfred.plugins.web_fetch.handle_cap import HandleCap
    from alfred.plugins.web_fetch.rate_limit import RateLimiter
    from alfred.security.dlp import OutboundDlp

_CLOCK_DEFINITION: Final[ToolDefinition] = ToolDefinition(
    name="clock.now",
    description="Return the current server time as an ISO-8601 UTC timestamp.",
    input_schema={"type": "object", "properties": {}, "additionalProperties": False},
)


def build_clock_tool(*, now: Callable[[], datetime]) -> InternalToolSpec:
    """First-party ≤T2 demo tool. Output is a server-generated timestamp — no
    external content — so its ≤T2 claim is true by construction (test-verified)."""

    async def _dispatch(_inv: ToolInvocation) -> str:
        return now().isoformat()

    return InternalToolSpec(name="clock.now", definition=_CLOCK_DEFINITION, dispatch=_dispatch)


class WebFetchExtraction(ExtractionSchema):
    """Default extraction schema for ``web.fetch`` (spec §8).

    TODO(#340): fields mirror the deterministic-echo child's ``{text, intent}``
    output so the fused fetch+extract validates against today's placeholder
    child. Refine to real web-content fields (e.g. ``title``, ``summary``) when
    the real quarantine child (#340) lands.
    """

    schema_version: ClassVar[Literal[1]] = 1
    text: str
    intent: str


_WEB_FETCH_DEFINITION: Final[ToolDefinition] = ToolDefinition(
    name="web.fetch",
    description="Fetch a URL and return its extracted, safety-checked text content.",
    input_schema={
        "type": "object",
        "required": ["url"],
        "properties": {
            "url": {"type": "string", "description": "The absolute https URL to fetch."},
            "headers": {"type": "object", "description": "Optional request headers."},
        },
    },
)


def build_web_fetch_tool(
    *,
    extractor: EgressResponseExtractor,
    config: FetchDispatchConfig,
    rate_limiter: RateLimiter,
    handle_cap: HandleCap,
    outbound_dlp: OutboundDlp,
    broker: _SecretSubstituter,
    auth_secret_allowlist: frozenset[str] = WEB_FETCH_AUTH_SECRET_ALLOWLIST,
    audit: AuditWriter,
    action_deadline_seconds: float = _DEFAULT_ACTION_DEADLINE_SECONDS,
) -> ExternalToolSpec:
    """The first real T3 tool. Its dispatch calls the fused ``dispatch_web_fetch``
    (which already runs URL-DLP + allowlist + rate-limit + T3→T2 extract) and
    returns the T2 ``EgressExtractOutcome``. ``dispatch_tool`` (Task 6) performs
    the downgrade + final DLP scan before the planner sees anything."""

    async def _dispatch(inv: ToolInvocation) -> EgressExtractOutcome:
        headers_arg = inv.arguments.get("headers", {})
        # A non-dict ``headers`` arg from the planner is silently dropped to
        # ``{}`` (no custom headers sent) rather than refused — benign, since
        # ``dispatch_web_fetch`` DLP-scans every header value downstream.
        # TODO(#339 follow-up): consider refuse-loud vs silent-drop for a
        # malformed headers arg (full JSON-Schema arg type-checking is deferred).
        headers = (
            {str(k): str(v) for k, v in headers_arg.items()}
            if isinstance(headers_arg, dict)
            else {}
        )
        return await dispatch_web_fetch(
            url=str(inv.arguments["url"]),
            headers=headers,
            user_id=inv.user_id,
            correlation_id=inv.correlation_id,
            egress_ctx=inv.ctx,
            call_index=inv.call_index,
            schema=WebFetchExtraction,
            config=config,
            rate_limiter=rate_limiter,
            handle_cap=handle_cap,
            outbound_dlp=outbound_dlp,
            broker=broker,
            auth_secret_allowlist=auth_secret_allowlist,
            audit=audit,
            extractor=extractor,
            action_deadline_seconds=action_deadline_seconds,
        )

    return ExternalToolSpec(
        name="web.fetch",
        definition=_WEB_FETCH_DEFINITION,
        extraction_schema=WebFetchExtraction,
        dispatch=_dispatch,
    )
