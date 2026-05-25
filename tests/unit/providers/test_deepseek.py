"""Tests for the DeepSeek provider adapter (uses OpenAI SDK + custom base_url)."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from alfred.providers.base import CompletionRequest, Message
from alfred.providers.deepseek import DeepSeekProvider


@pytest.mark.asyncio
async def test_complete_returns_assistant_text_and_token_usage() -> None:
    fake_client = MagicMock()
    fake_response = MagicMock()
    fake_response.choices = [MagicMock(message=MagicMock(content="Hello, operator."))]
    fake_response.usage = MagicMock(prompt_tokens=10, completion_tokens=4)
    fake_client.chat.completions.create = AsyncMock(return_value=fake_response)

    provider = DeepSeekProvider(client=fake_client, model="deepseek-chat")
    req = CompletionRequest(
        messages=[
            Message(role="system", content="You are Alfred."),
            Message(role="user", content="hi"),
        ],
        max_tokens=512,
    )
    res = await provider.complete(req)

    assert res.content == "Hello, operator."
    assert res.tokens_in == 10
    assert res.tokens_out == 4
    assert res.cost_usd > 0
    fake_client.chat.completions.create.assert_awaited_once()


@pytest.mark.asyncio
async def test_complete_propagates_client_errors() -> None:
    fake_client = MagicMock()
    fake_client.chat.completions.create = AsyncMock(side_effect=RuntimeError("rate limited"))
    provider = DeepSeekProvider(client=fake_client, model="deepseek-chat")
    req = CompletionRequest(messages=[Message(role="user", content="hi")], max_tokens=10)
    with pytest.raises(RuntimeError, match="rate limited"):
        await provider.complete(req)
