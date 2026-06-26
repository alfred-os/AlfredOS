"""Tests for the Anthropic provider adapter (fallback)."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from alfred.providers.anthropic_native import AnthropicProvider
from alfred.providers.base import CompletionRequest, Message


@pytest.mark.asyncio
async def test_complete_returns_assistant_text_and_usage() -> None:
    fake_client = MagicMock()
    fake_response = MagicMock()
    fake_response.content = [MagicMock(text="Hi, this is Alfred.")]
    fake_response.usage = MagicMock(input_tokens=12, output_tokens=6)
    fake_client.messages.create = AsyncMock(return_value=fake_response)

    provider = AnthropicProvider(client=fake_client, model="claude-sonnet-4-6")
    req = CompletionRequest(
        messages=[
            Message(role="system", content="You are Alfred."),
            Message(role="user", content="hi"),
        ],
        max_tokens=256,
    )
    res = await provider.complete(req)

    assert res.content == "Hi, this is Alfred."
    assert res.tokens_in == 12
    assert res.tokens_out == 6
    assert res.cost_usd > 0


def test_from_settings_passes_http_client_and_preserves_retries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import alfred.providers.anthropic_native as mod

    captured: dict[str, object] = {}
    monkeypatch.setattr(mod, "AsyncAnthropic", lambda **kw: captured.update(kw) or object())
    sentinel = object()
    mod.AnthropicProvider.from_settings(
        api_key="k", model="claude-sonnet-4-6", http_client=sentinel
    )
    assert captured["http_client"] is sentinel
    assert captured["max_retries"] == 2  # rider 4: SDK-level retry preserved


def test_from_settings_default_passes_none_http_client(monkeypatch: pytest.MonkeyPatch) -> None:
    """Behaviour-neutral default: http_client=None => SDK builds its own (today's path)."""
    import alfred.providers.anthropic_native as mod

    captured: dict[str, object] = {}
    monkeypatch.setattr(mod, "AsyncAnthropic", lambda **kw: captured.update(kw) or object())
    mod.AnthropicProvider.from_settings(api_key="k", model="claude-sonnet-4-6")
    assert captured["http_client"] is None
