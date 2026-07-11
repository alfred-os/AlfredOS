"""DeepSeek provider adapter. Uses the OpenAI SDK with a custom base_url.

Pricing (as of 2026-05; check https://api.deepseek.com/pricing before updating):
  deepseek-chat:     $0.07 / 1M input tokens, $0.27 / 1M output tokens
  deepseek-reasoner: $0.14 / 1M input tokens, $2.19 / 1M output tokens
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

import httpx
import structlog
from openai import (
    APIConnectionError,
    APIStatusError,
    APITimeoutError,
    AsyncOpenAI,
    RateLimitError,
)
from openai.types.chat import (
    ChatCompletionAssistantMessageParam,
    ChatCompletionFunctionToolParam,
    ChatCompletionMessageFunctionToolCallParam,
    ChatCompletionMessageParam,
    ChatCompletionMessageToolCallUnion,
    ChatCompletionNamedToolChoiceParam,
    ChatCompletionSystemMessageParam,
    ChatCompletionToolChoiceOptionParam,
    ChatCompletionToolMessageParam,
    ChatCompletionUserMessageParam,
)
from openai.types.shared_params import FunctionDefinition

from alfred.i18n import t
from alfred.providers._tool_names import build_tool_name_map, sanitize_tool_name
from alfred.providers.base import (
    CompletionRequest,
    CompletionResponse,
    ForcedTool,
    Message,
    ProviderCapability,
    ProviderMalformedToolArgumentsError,
    ProviderUnavailableError,
    StopReason,
    ToolCall,
    ToolChoice,
    ToolDefinition,
    ensure_tool_capability,
    register_provider,
)

_log = structlog.get_logger()

# Explicit per-phase timeouts so a hung provider can't stall the orchestrator
# loop. The OpenAI SDK default is ~10 minutes for the full request, which is
# unacceptable for an interactive TUI. Read=60s is enough headroom for slow
# completions; connect/write/pool are tighter because they should be near-instant
# on a healthy network.
_HTTP_TIMEOUT = httpx.Timeout(connect=10.0, read=60.0, write=10.0, pool=5.0)

# Per-million-token prices in USD. Used to estimate cost_usd locally so the
# orchestrator can enforce per-user/per-task budgets without an extra round
# trip. Source of truth is DeepSeek's public price sheet — bump on release.
_DEEPSEEK_PRICING: dict[str, tuple[float, float]] = {
    "deepseek-chat": (0.07, 0.27),
    "deepseek-reasoner": (0.14, 2.19),
}


def _estimate_cost(model: str, tokens_in: int, tokens_out: int) -> float:
    # Unknown models fail CLOSED: charge at the most expensive known tariff
    # rather than the deepseek-chat default. CR (#89) flagged the prior
    # cheap-fallback as a budget-bypass — a model added by DeepSeek but not
    # yet in our pricing table would silently undercount ``cost_usd`` and
    # let the per-call / per-day guards approve spend they should block.
    # Logging the fallback makes price-sheet drift observable in real time.
    if model in _DEEPSEEK_PRICING:
        in_per_m, out_per_m = _DEEPSEEK_PRICING[model]
    else:
        in_per_m, out_per_m = max(_DEEPSEEK_PRICING.values(), key=lambda p: p[0] + p[1])
        _log.warning(
            "deepseek.unknown_model_pricing_fallback",
            model=model,
            in_per_m=in_per_m,
            out_per_m=out_per_m,
        )
    return (tokens_in / 1_000_000) * in_per_m + (tokens_out / 1_000_000) * out_per_m


# Per-model capability table (prov-009). DeepSeek's feature set varies by
# model: ``deepseek-chat`` supports JSON-object mode (``response_format=
# {"type": "json_object"}``); ``deepseek-reasoner`` does NOT. A single
# per-class constant would mis-classify reasoner and route to the wrong
# dispatch branch in the quarantined-LLM router (spec §6.2).
#
# Unknown models fall through to the empty default, which routes to
# ``prompt_embedded_fallback`` — the most-defensive branch and the same
# fail-closed pattern the cost-pricing fallback above already uses.
_DEEPSEEK_MODEL_CAPABILITIES: dict[str, frozenset[ProviderCapability]] = {
    "deepseek-chat": frozenset({ProviderCapability.JSON_OBJECT_MODE, ProviderCapability.TOOL_USE}),
    "deepseek-reasoner": frozenset(),
}
_DEEPSEEK_DEFAULT_CAPABILITIES: frozenset[ProviderCapability] = frozenset()

# finish_reason -> normalized StopReason. Unknown values fall to "other" at the
# call site (dict.get default).
_OPENAI_STOP_REASON: dict[str, StopReason] = {
    "stop": "end_turn",
    "tool_calls": "tool_use",
    "length": "max_tokens",
}


def _openai_tools(tools: tuple[ToolDefinition, ...]) -> list[ChatCompletionFunctionToolParam]:
    return [
        ChatCompletionFunctionToolParam(
            type="function",
            function=FunctionDefinition(
                # AlfredOS tool names are dotted (web.fetch); OpenAI/DeepSeek
                # 400 on '^[a-zA-Z0-9_-]+$' violations. Sanitize for the wire —
                # complete() reverse-maps the response via build_tool_name_map.
                name=sanitize_tool_name(tool.name),
                description=tool.description,
                parameters=dict(tool.input_schema),
            ),
        )
        for tool in tools
    ]


def _openai_tool_choice(choice: ToolChoice) -> ChatCompletionToolChoiceOptionParam:
    if isinstance(choice, ForcedTool):
        return ChatCompletionNamedToolChoiceParam(
            type="function", function={"name": sanitize_tool_name(choice.name)}
        )
    # "auto" | "none" | "required" are native OpenAI string values.
    return choice


def _openai_tool_call_param(call: ToolCall) -> ChatCompletionMessageFunctionToolCallParam:
    # Sanitize here too: this serializes a PRIOR assistant tool_call being
    # re-sent as message history. Without this, iteration >= 1 of the
    # act-phase loop re-sends the dotted canonical name and 400s exactly
    # like the initial tools[] declaration would.
    return ChatCompletionMessageFunctionToolCallParam(
        id=call.id,
        type="function",
        function={
            "name": sanitize_tool_name(call.name),
            "arguments": json.dumps(dict(call.arguments)),
        },
    )


def _openai_message(m: Message) -> ChatCompletionMessageParam:
    # Per-role serialization: emit tool fields ONLY on the roles that carry them,
    # so a plain user/system/assistant message never sends tool_calls=[] /
    # tool_call_id=null (which DeepSeek 400s on) — the arch-005/prov-002 fix.
    if m.role == "system":
        return ChatCompletionSystemMessageParam(role="system", content=m.content)
    if m.role == "user":
        return ChatCompletionUserMessageParam(role="user", content=m.content)
    if m.role == "tool":
        # The Message validator guarantees tool_call_id is set for role="tool";
        # assert narrows the type and fails loud if that invariant is ever broken.
        assert m.tool_call_id is not None
        return ChatCompletionToolMessageParam(
            role="tool", content=m.content, tool_call_id=m.tool_call_id
        )
    if m.tool_calls:
        return ChatCompletionAssistantMessageParam(
            role="assistant",
            content=m.content,
            tool_calls=[_openai_tool_call_param(c) for c in m.tool_calls],
        )
    return ChatCompletionAssistantMessageParam(role="assistant", content=m.content)


def _parse_tool_arguments(raw: str, *, model: str, tool: str) -> Mapping[str, object]:
    # DeepSeek returns tool-call arguments as a JSON *string*. An empty string
    # (some OpenAI-compatible backends) means "no arguments" -> {}. A value that
    # parses but is not a JSON object (e.g. "[]") is still malformed for our
    # tool schema, so both the parse failure AND the non-object case fail loud
    # via the SAME typed error the act-phase loop (#339 PR3) keys on.
    if raw == "":
        return {}
    try:
        args = json.loads(raw)
    except (ValueError, TypeError) as exc:
        raise ProviderMalformedToolArgumentsError(
            t("providers.malformed_tool_arguments", provider="deepseek", model=model, tool=tool)
        ) from exc
    if not isinstance(args, dict):
        raise ProviderMalformedToolArgumentsError(
            t("providers.malformed_tool_arguments", provider="deepseek", model=model, tool=tool)
        )
    return args


def _parse_openai_tool_calls(
    raw: list[ChatCompletionMessageToolCallUnion] | None,
    model: str,
    name_map: Mapping[str, str],
) -> tuple[ToolCall, ...]:
    if not raw:
        return ()
    parsed: list[ToolCall] = []
    for tc in raw:
        if tc.type != "function":
            # Custom tools are out of scope for #339; log (no payload) so
            # provider drift is observable rather than a silent drop.
            _log.debug("deepseek.tool_call_dropped_non_function", model=model, tool_type=tc.type)
            continue
        # Reverse the send-side sanitization: the provider echoes back the
        # WIRE name (e.g. "web_fetch"); name_map recovers the canonical
        # dotted name ("web.fetch") the tool registry/audit rows expect. An
        # unmapped name (not in this request's tools) falls back unchanged —
        # it then fails registry resolution loudly as unknown_tool, which is
        # the safe outcome for a name we cannot account for.
        canonical_name = name_map.get(tc.function.name, tc.function.name)
        args = _parse_tool_arguments(tc.function.arguments, model=model, tool=canonical_name)
        parsed.append(ToolCall(id=tc.id, name=canonical_name, arguments=args))
    return tuple(parsed)


@register_provider
class DeepSeekProvider:
    """OpenAI-compatible DeepSeek client wrapper.

    Capability declaration is model-aware (prov-009) — ``deepseek-chat``
    supports JSON-object mode; ``deepseek-reasoner`` does not. Use
    :meth:`_capabilities_for_model` to query capabilities by model name
    without constructing an instance (tests rely on this — prov-007).
    """

    name = "deepseek"

    # `client` is typed Any because tests inject a MagicMock and the real
    # `AsyncOpenAI` doesn't expose a Protocol we can pin to. The from_settings
    # classmethod is the typed construction path for production use.
    def __init__(self, *, client: Any, model: str) -> None:
        self._client = client
        self._model = model

    @classmethod
    def _capabilities_for_model(cls, model: str) -> frozenset[ProviderCapability]:
        """Return the capability set for a given DeepSeek model name.

        Class-level so capability-routing decisions can be made before
        a provider instance exists (tests + the router both use this).
        Unknown model → empty set → prompt_embedded_fallback dispatch.
        """
        return _DEEPSEEK_MODEL_CAPABILITIES.get(model, _DEEPSEEK_DEFAULT_CAPABILITIES)

    def capabilities(self) -> frozenset[ProviderCapability]:
        # Instance-side: dispatch on the bound model.
        return self._capabilities_for_model(self._model)

    @classmethod
    def from_settings(
        cls,
        api_key: str,
        base_url: str,
        model: str,
        *,
        http_client: httpx.AsyncClient | None = None,
        max_retries: int = 2,
        timeout: httpx.Timeout | None = None,
    ) -> DeepSeekProvider:
        # http_client is the G7-1 egress seam (Spec C, #333); see
        # AnthropicProvider.from_settings. None => the SDK builds its own (un-proxied)
        # client — a general provider contract, but post-G7-3 (ADR-0042) build_router
        # ALWAYS injects the proxied client and that path is dead-by-kernel on the
        # connectivity-free core. timeout + max_retries STAY on the SDK ctor (rider 4).
        # They are PARAMS (PR2b-prep, #340) whose DEFAULTS preserve today's posture
        # (max_retries=2 — previously the un-passed SDK default — + _HTTP_TIMEOUT); the
        # quarantine child (PR2b-golive) passes max_retries=0 + a short read timeout.
        return cls(
            client=AsyncOpenAI(
                api_key=api_key,
                base_url=base_url,
                timeout=timeout if timeout is not None else _HTTP_TIMEOUT,
                max_retries=max_retries,
                http_client=http_client,
            ),
            model=model,
        )

    async def complete(self, request: CompletionRequest) -> CompletionResponse:
        ensure_tool_capability(
            has_tools=bool(request.tools),
            capabilities=self.capabilities(),
            provider_name=self.name,
            model=self._model,
        )
        # Built once, before the request is sent, so a collision (two
        # canonical names sanitizing to the same wire name) fails loud
        # before any network call — and threaded into the response parser
        # below to reverse-map the wire name back to canonical.
        name_map = build_tool_name_map(request.tools)
        # kwargs is dict[str, Any] (not a typed CompletionCreateParams) because
        # tools/tool_choice are added conditionally; each value is an official
        # SDK param type built by a typed helper, so the wire shape stays checked.
        kwargs: dict[str, Any] = {
            "model": self._model,
            "messages": [_openai_message(m) for m in request.messages],
            "max_tokens": request.max_tokens,
            "temperature": request.temperature,
        }
        if request.tools:
            kwargs["tools"] = _openai_tools(request.tools)
            kwargs["tool_choice"] = _openai_tool_choice(request.tool_choice)
        try:
            response = await self._client.chat.completions.create(**kwargs)
        except (APIConnectionError, APITimeoutError, RateLimitError, httpx.HTTPError) as exc:
            # Transient/retryable transport failure. Map to the neutral seam error
            # at the adapter boundary (the only place the SDK types are in scope).
            # Never surface the raw exc text — it can carry provider-supplied strings.
            raise ProviderUnavailableError(
                t("providers.provider_unavailable", provider=self.name, model=self._model)
            ) from exc
        except APIStatusError as exc:
            # 5xx = a transient upstream outage -> provider-unavailable; deterministic
            # 4xx (auth/bad-request/permission/not-found/etc.) propagates loud as the
            # raw SDK error — a config/host-side bug must not be masked as a
            # retryable outage the router would silently fall back past.
            if exc.status_code >= 500:
                raise ProviderUnavailableError(
                    t("providers.provider_unavailable", provider=self.name, model=self._model)
                ) from exc
            raise
        msg = response.choices[0].message
        usage = response.usage
        tool_calls = _parse_openai_tool_calls(msg.tool_calls, self._model, name_map)
        stop_reason: StopReason = _OPENAI_STOP_REASON.get(
            response.choices[0].finish_reason, "other"
        )
        if stop_reason == "tool_use" and not tool_calls:
            # Every returned tool call was non-function (dropped) — keep the
            # response consistent for the CompletionResponse tool-use invariant.
            stop_reason = "other"
        return CompletionResponse(
            content=msg.content or "",
            tokens_in=usage.prompt_tokens,
            tokens_out=usage.completion_tokens,
            cost_usd=_estimate_cost(self._model, usage.prompt_tokens, usage.completion_tokens),
            model=self._model,
            stop_reason=stop_reason,
            tool_calls=tool_calls,
        )
