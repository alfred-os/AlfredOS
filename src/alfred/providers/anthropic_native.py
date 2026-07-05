"""Anthropic provider adapter using the native SDK. Fallback in Slice 1.

Pricing (as of 2026-05; check https://www.anthropic.com/pricing before updating):
  claude-sonnet-4-6:  $3 / 1M input tokens,  $15 / 1M output tokens
  claude-haiku-4-5:   $1 / 1M input tokens,   $5 / 1M output tokens
  claude-opus-4-7:   $15 / 1M input tokens,  $75 / 1M output tokens
"""

from __future__ import annotations

from typing import Any, cast

import httpx
import structlog
from anthropic import AsyncAnthropic
from anthropic.types import (
    ContentBlock,
    MessageParam,
    TextBlockParam,
    ToolChoiceAnyParam,
    ToolChoiceAutoParam,
    ToolChoiceParam,
    ToolChoiceToolParam,
    ToolParam,
    ToolResultBlockParam,
    ToolUseBlockParam,
)
from anthropic.types.tool_param import InputSchema

from alfred.i18n import t
from alfred.providers.base import (
    CompletionRequest,
    CompletionResponse,
    ForcedTool,
    Message,
    ProviderCapability,
    ProviderToolUnsupportedError,
    StopReason,
    ToolCall,
    ToolChoice,
    ToolDefinition,
    register_provider,
)

_log = structlog.get_logger()

# Explicit per-phase timeouts so a hung provider can't stall the orchestrator
# loop. The Anthropic SDK default is ~10 minutes for the full request, which is
# unacceptable for an interactive TUI. Read=60s is enough headroom for slow
# completions; connect/write/pool are tighter because they should be near-instant
# on a healthy network.
_HTTP_TIMEOUT = httpx.Timeout(connect=10.0, read=60.0, write=10.0, pool=5.0)

# Per-million-token prices in USD. Used to estimate cost_usd locally so the
# orchestrator can enforce per-user/per-task budgets without an extra round
# trip. Source of truth is Anthropic's public price sheet — bump on release.
_ANTHROPIC_PRICING: dict[str, tuple[float, float]] = {
    "claude-sonnet-4-6": (3.0, 15.0),
    "claude-haiku-4-5": (1.0, 5.0),
    "claude-opus-4-7": (15.0, 75.0),
}


def _estimate_cost(model: str, tokens_in: int, tokens_out: int) -> float:
    # Unknown models fail CLOSED: charge at the most expensive known tariff
    # (claude-opus-4-7 today) rather than the cheap sonnet default. CR (#89)
    # flagged the prior cheap-fallback as a budget-bypass — a new Anthropic
    # model name not yet in our table would silently undercount ``cost_usd``
    # and let the per-call / per-day guards approve spend they should block.
    # Logging the fallback makes price-sheet drift observable in real time.
    if model in _ANTHROPIC_PRICING:
        in_per_m, out_per_m = _ANTHROPIC_PRICING[model]
    else:
        in_per_m, out_per_m = max(_ANTHROPIC_PRICING.values(), key=lambda p: p[0] + p[1])
        _log.warning(
            "anthropic.unknown_model_pricing_fallback",
            model=model,
            in_per_m=in_per_m,
            out_per_m=out_per_m,
        )
    return (tokens_in / 1_000_000) * in_per_m + (tokens_out / 1_000_000) * out_per_m


# stop_reason -> normalized StopReason. Unknown/None falls to "other" at the
# call site (dict.get default).
_ANTHROPIC_STOP_REASON: dict[str, StopReason] = {
    "end_turn": "end_turn",
    "tool_use": "tool_use",
    "max_tokens": "max_tokens",
    "stop_sequence": "stop_sequence",
}


def _anthropic_tools(tools: tuple[ToolDefinition, ...]) -> list[ToolParam]:
    return [
        ToolParam(
            name=tool.name,
            description=tool.description,
            # input_schema is a JSON Schema by ToolDefinition's contract; cast to
            # the SDK's InputSchema union at the boundary.
            input_schema=cast("InputSchema", dict(tool.input_schema)),
        )
        for tool in tools
    ]


def _anthropic_tool_choice(choice: ToolChoice) -> ToolChoiceParam:
    if isinstance(choice, ForcedTool):
        return ToolChoiceToolParam(type="tool", name=choice.name)
    if choice == "required":
        return ToolChoiceAnyParam(type="any")
    # "auto"/"none" -> auto; "none" additionally omits tools upstream (see complete()).
    return ToolChoiceAutoParam(type="auto")


def _anthropic_assistant_content(m: Message) -> str | list[TextBlockParam | ToolUseBlockParam]:
    if not m.tool_calls:
        return m.content
    blocks: list[TextBlockParam | ToolUseBlockParam] = []
    if m.content:
        blocks.append(TextBlockParam(type="text", text=m.content))
    blocks.extend(
        ToolUseBlockParam(type="tool_use", id=c.id, name=c.name, input=dict(c.arguments))
        for c in m.tool_calls
    )
    return blocks


def _anthropic_messages(messages: list[Message]) -> list[MessageParam]:
    # Consecutive tool-result messages collapse into ONE user turn carrying
    # tool_result blocks (Anthropic requires tool_result blocks in a user
    # message immediately following the tool_use assistant turn).
    out: list[MessageParam] = []
    pending: list[ToolResultBlockParam] = []

    def flush() -> None:
        if pending:
            out.append(MessageParam(role="user", content=list(pending)))
            pending.clear()

    for m in messages:
        if m.role == "tool":
            pending.append(
                ToolResultBlockParam(
                    type="tool_result", tool_use_id=m.tool_call_id or "", content=m.content
                )
            )
            continue
        flush()
        if m.role == "assistant":
            out.append(MessageParam(role="assistant", content=_anthropic_assistant_content(m)))
        else:  # user
            out.append(MessageParam(role="user", content=m.content))
    flush()
    return out


def _parse_anthropic_content(blocks: list[ContentBlock]) -> tuple[str, tuple[ToolCall, ...]]:
    text_parts: list[str] = []
    calls: list[ToolCall] = []
    for block in blocks:
        if block.type == "tool_use":
            calls.append(ToolCall(id=block.id, name=block.name, arguments=block.input))
        elif block.type == "text":
            text_parts.append(block.text)
    return "".join(text_parts), tuple(calls)


@register_provider
class AnthropicProvider:
    """Native Anthropic client wrapper. Slice 1 fallback provider.

    Declares NATIVE_CONSTRAINED_GENERATION (spec §6.2): the tool-use shape
    with ``input_schema`` under ``tools[]`` provides schema-constrained
    generation at the provider level. This is the dispatch key the
    quarantined-LLM router uses to pick the native path over JSON-mode
    or prompt-embedded fallback (PR-S3-4).
    """

    name = "anthropic"

    # Class-level constant — no constructor required to read it (prov-007).
    # frozenset so a caller cannot mutate the declared set.
    CAPABILITIES: frozenset[ProviderCapability] = frozenset(
        {ProviderCapability.NATIVE_CONSTRAINED_GENERATION, ProviderCapability.TOOL_USE}
    )

    # `client` is typed Any because tests inject a MagicMock and the real
    # `AsyncAnthropic` doesn't expose a Protocol we can pin to. The from_settings
    # classmethod is the typed construction path for production use.
    def __init__(self, *, client: Any, model: str) -> None:
        self._client = client
        self._model = model

    def capabilities(self) -> frozenset[ProviderCapability]:
        # AnthropicProvider's capabilities are model-invariant in Slice 3 —
        # every Anthropic model we ship pricing for supports tool-use.
        # A future model that drops tool-use would need a model-aware
        # variant (see DeepSeekProvider for the pattern).
        return self.CAPABILITIES

    @classmethod
    def from_settings(
        cls, api_key: str, model: str, *, http_client: httpx.AsyncClient | None = None
    ) -> AnthropicProvider:
        # http_client is the G7-1 egress seam (Spec C, #333): a proxied client when
        # the gateway proxy is configured. The SDK builds its own (un-proxied) client
        # on None — kept as a general provider contract (tests inject None/mocks), but
        # post-G7-3 (ADR-0042) build_router ALWAYS injects the proxied client, and that
        # un-proxied path is dead-by-kernel on the connectivity-free core.
        #
        # timeout + max_retries STAY on the SDK ctor (rider 4): the SDK applies
        # timeout per-request and never inherits max_retries from the http_client,
        # so anthropic's explicit max_retries=2 survives. max_retries=2 matches the
        # SDK default but is stated explicitly: a transient failure on the fallback
        # should retry once with backoff before surfacing to the orchestrator.
        return cls(
            client=AsyncAnthropic(
                api_key=api_key, timeout=_HTTP_TIMEOUT, max_retries=2, http_client=http_client
            ),
            model=model,
        )

    async def complete(self, request: CompletionRequest) -> CompletionResponse:
        if request.tools and ProviderCapability.TOOL_USE not in self.capabilities():
            raise ProviderToolUnsupportedError(
                t("providers.tool_use_unsupported", provider=self.name, model=self._model)
            )
        # Anthropic separates the system prompt from the conversation: it goes
        # on the top-level `system` kwarg, not in `messages`. Strip any system
        # message out of the chat list and pass the first one's content
        # through. None is a valid value when there is no system prompt.
        system = next((m.content for m in request.messages if m.role == "system"), None)
        chat = _anthropic_messages([m for m in request.messages if m.role != "system"])
        kwargs: dict[str, Any] = {
            "model": self._model,
            "system": system,
            "messages": chat,
            "max_tokens": request.max_tokens,
            "temperature": request.temperature,
        }
        # tool_choice="none" omits tools entirely (Anthropic has no first-class
        # "none"; not advertising the tools is the equivalent).
        if request.tools and request.tool_choice != "none":
            kwargs["tools"] = _anthropic_tools(request.tools)
            kwargs["tool_choice"] = _anthropic_tool_choice(request.tool_choice)
        response = await self._client.messages.create(**kwargs)
        # Parse text + tool_use blocks (no longer discards non-text blocks).
        text, tool_calls = _parse_anthropic_content(response.content)
        usage = response.usage
        return CompletionResponse(
            content=text,
            tokens_in=usage.input_tokens,
            tokens_out=usage.output_tokens,
            cost_usd=_estimate_cost(self._model, usage.input_tokens, usage.output_tokens),
            model=self._model,
            stop_reason=_ANTHROPIC_STOP_REASON.get(response.stop_reason, "other"),
            tool_calls=tool_calls,
        )
