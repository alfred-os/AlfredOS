"""DeepSeek provider adapter. Uses the OpenAI SDK with a custom base_url.

Pricing (as of 2026-05; check https://api.deepseek.com/pricing before updating):
  deepseek-chat:     $0.07 / 1M input tokens, $0.27 / 1M output tokens
  deepseek-reasoner: $0.14 / 1M input tokens, $2.19 / 1M output tokens
"""

from __future__ import annotations

from typing import Any

import httpx
import structlog
from openai import AsyncOpenAI

from alfred.providers.base import CompletionRequest, CompletionResponse

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


class DeepSeekProvider:
    """OpenAI-compatible DeepSeek client wrapper."""

    name = "deepseek"

    # `client` is typed Any because tests inject a MagicMock and the real
    # `AsyncOpenAI` doesn't expose a Protocol we can pin to. The from_settings
    # classmethod is the typed construction path for production use.
    def __init__(self, *, client: Any, model: str) -> None:
        self._client = client
        self._model = model

    @classmethod
    def from_settings(cls, api_key: str, base_url: str, model: str) -> DeepSeekProvider:
        return cls(
            client=AsyncOpenAI(api_key=api_key, base_url=base_url, timeout=_HTTP_TIMEOUT),
            model=model,
        )

    async def complete(self, request: CompletionRequest) -> CompletionResponse:
        response = await self._client.chat.completions.create(
            model=self._model,
            messages=[m.model_dump() for m in request.messages],
            max_tokens=request.max_tokens,
            temperature=request.temperature,
        )
        msg = response.choices[0].message
        usage = response.usage
        return CompletionResponse(
            content=msg.content or "",
            tokens_in=usage.prompt_tokens,
            tokens_out=usage.completion_tokens,
            cost_usd=_estimate_cost(self._model, usage.prompt_tokens, usage.completion_tokens),
            model=self._model,
        )
