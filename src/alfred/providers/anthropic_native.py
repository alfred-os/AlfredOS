"""Anthropic provider adapter using the native SDK. Fallback in Slice 1.

Pricing (as of 2026-05; check https://www.anthropic.com/pricing before updating):
  claude-sonnet-4-6:  $3 / 1M input tokens,  $15 / 1M output tokens
  claude-haiku-4-5:   $1 / 1M input tokens,   $5 / 1M output tokens
  claude-opus-4-7:   $15 / 1M input tokens,  $75 / 1M output tokens
"""

from __future__ import annotations

from typing import Any

from anthropic import AsyncAnthropic

from alfred.providers.base import CompletionRequest, CompletionResponse

# Per-million-token prices in USD. Used to estimate cost_usd locally so the
# orchestrator can enforce per-user/per-task budgets without an extra round
# trip. Source of truth is Anthropic's public price sheet — bump on release.
_ANTHROPIC_PRICING: dict[str, tuple[float, float]] = {
    "claude-sonnet-4-6": (3.0, 15.0),
    "claude-haiku-4-5": (1.0, 5.0),
    "claude-opus-4-7": (15.0, 75.0),
}


def _estimate_cost(model: str, tokens_in: int, tokens_out: int) -> float:
    # Unknown models fall back to claude-sonnet-4-6 pricing rather than raising:
    # cost is an estimate used for budget enforcement, and a missing entry
    # should not break completion. Router/audit records the real model name
    # so price-sheet drift is observable downstream.
    in_per_m, out_per_m = _ANTHROPIC_PRICING.get(model, (3.0, 15.0))
    return (tokens_in / 1_000_000) * in_per_m + (tokens_out / 1_000_000) * out_per_m


class AnthropicProvider:
    """Native Anthropic client wrapper. Slice 1 fallback provider."""

    name = "anthropic"

    # `client` is typed Any because tests inject a MagicMock and the real
    # `AsyncAnthropic` doesn't expose a Protocol we can pin to. The from_settings
    # classmethod is the typed construction path for production use.
    def __init__(self, *, client: Any, model: str) -> None:
        self._client = client
        self._model = model

    @classmethod
    def from_settings(cls, api_key: str, model: str) -> AnthropicProvider:
        return cls(client=AsyncAnthropic(api_key=api_key), model=model)

    async def complete(self, request: CompletionRequest) -> CompletionResponse:
        # Anthropic separates the system prompt from the conversation: it goes
        # on the top-level `system` kwarg, not in `messages`. Strip any system
        # message out of the chat list and pass the first one's content
        # through. None is a valid value when there is no system prompt.
        system = next((m.content for m in request.messages if m.role == "system"), None)
        chat = [m.model_dump() for m in request.messages if m.role != "system"]
        response = await self._client.messages.create(
            model=self._model,
            system=system,
            messages=chat,
            max_tokens=request.max_tokens,
            temperature=request.temperature,
        )
        # Anthropic returns content as a list of blocks (text, tool_use, etc.).
        # Slice 1 only expects text; concatenate the text from every block and
        # ignore non-text blocks via the getattr default.
        text = "".join(getattr(block, "text", "") for block in response.content)
        usage = response.usage
        return CompletionResponse(
            content=text,
            tokens_in=usage.input_tokens,
            tokens_out=usage.output_tokens,
            cost_usd=_estimate_cost(self._model, usage.input_tokens, usage.output_tokens),
            model=self._model,
        )
