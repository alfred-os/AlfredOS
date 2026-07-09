"""Tests for the Anthropic provider adapter (fallback)."""

from __future__ import annotations

import re
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from anthropic import APIConnectionError

from alfred.providers.anthropic_native import AnthropicProvider
from alfred.providers.base import (
    CompletionRequest,
    ForcedTool,
    Message,
    ProviderCapability,
    ProviderToolNameCollisionError,
    ProviderToolUnsupportedError,
    ProviderUnavailableError,
    ToolCall,
    ToolDefinition,
)


@pytest.fixture
def anthropic_provider() -> AnthropicProvider:
    """Reusable provider over a mocked ``_client`` — AsyncMock's child-attribute
    chaining (``client.messages.create`` stays an AsyncMock without explicit
    wiring) lets the SDK/transport-error-mapping tests set ``.side_effect``
    directly without needing a canned success response."""
    return AnthropicProvider(client=AsyncMock(), model="claude-haiku-4-5")


@pytest.mark.asyncio
async def test_complete_returns_assistant_text_and_usage() -> None:
    fake_client = MagicMock()
    fake_response = MagicMock()
    fake_response.content = [MagicMock(type="text", text="Hi, this is Alfred.")]
    fake_response.usage = MagicMock(input_tokens=12, output_tokens=6)
    fake_response.stop_reason = "end_turn"
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


def _anthropic_text_response(text: str = "ok") -> MagicMock:
    r = MagicMock()
    r.content = [MagicMock(type="text", text=text)]
    r.usage = MagicMock(input_tokens=1, output_tokens=1)
    r.stop_reason = "end_turn"
    return r


@pytest.mark.asyncio
async def test_multi_tool_turn_maps_to_anthropic_blocks() -> None:
    fake_client = MagicMock()
    fake_client.messages.create = AsyncMock(return_value=_anthropic_text_response())
    provider = AnthropicProvider(client=fake_client, model="claude-sonnet-4-6")
    c1 = ToolCall(id="c1", name="web.fetch", arguments={"url": "https://a.test"})
    c2 = ToolCall(id="c2", name="calc", arguments={"x": 1})
    td = ToolDefinition(name="web.fetch", description="fetch", input_schema={"type": "object"})
    req = CompletionRequest(
        messages=[
            Message(role="user", content="do it"),
            Message(role="assistant", content="working", tool_calls=(c1, c2)),
            Message(role="tool", content='{"ok": true}', tool_call_id="c1"),
            Message(role="tool", content="2", tool_call_id="c2"),
        ],
        tools=(td,),
        tool_choice=ForcedTool(name="web.fetch"),
    )
    await provider.complete(req)
    kw = fake_client.messages.create.await_args.kwargs
    # Canonical dotted names are sanitized to underscores on the WIRE —
    # Anthropic 400s on '^[a-zA-Z0-9_-]{1,64}$' violations (dots forbidden).
    # This applies to the tool definition, the forced tool_choice, AND the
    # prior assistant tool_use block being re-sent as history (load-bearing
    # at iteration >= 1 of the act-phase loop). "calc" has no unsafe
    # characters so it is unchanged — proving sanitization is a targeted
    # substitution, not a blanket rename.
    assert kw["tools"] == [
        {"name": "web_fetch", "description": "fetch", "input_schema": {"type": "object"}}
    ]
    assert kw["tool_choice"] == {"type": "tool", "name": "web_fetch"}
    msgs = kw["messages"]
    assert msgs[1]["role"] == "assistant"
    assert msgs[1]["content"] == [
        {"type": "text", "text": "working"},
        {"type": "tool_use", "id": "c1", "name": "web_fetch", "input": {"url": "https://a.test"}},
        {"type": "tool_use", "id": "c2", "name": "calc", "input": {"x": 1}},
    ]
    # consecutive tool results collapse into ONE user turn of tool_result blocks
    assert msgs[2]["role"] == "user"
    assert msgs[2]["content"] == [
        {"type": "tool_result", "tool_use_id": "c1", "content": '{"ok": true}'},
        {"type": "tool_result", "tool_use_id": "c2", "content": "2"},
    ]


@pytest.mark.asyncio
async def test_anthropic_tool_only_assistant_omits_empty_text_block() -> None:
    fake_client = MagicMock()
    fake_client.messages.create = AsyncMock(return_value=_anthropic_text_response())
    provider = AnthropicProvider(client=fake_client, model="claude-sonnet-4-6")
    call = ToolCall(id="c1", name="web.fetch", arguments={"url": "https://a.test"})
    td = ToolDefinition(name="web.fetch", description="f", input_schema={})
    await provider.complete(
        CompletionRequest(
            messages=[Message(role="assistant", content="", tool_calls=(call,))], tools=(td,)
        )
    )
    asst = fake_client.messages.create.await_args.kwargs["messages"][0]
    assert asst["content"] == [
        {"type": "tool_use", "id": "c1", "name": "web_fetch", "input": {"url": "https://a.test"}}
    ]  # NO empty text block; name sanitized for the wire


@pytest.mark.asyncio
async def test_anthropic_tool_choice_none_omits_tools_and_auto_required_map() -> None:
    fake_client = MagicMock()
    fake_client.messages.create = AsyncMock(return_value=_anthropic_text_response())
    provider = AnthropicProvider(client=fake_client, model="claude-sonnet-4-6")
    td = ToolDefinition(name="t", description="d", input_schema={})
    base = [Message(role="user", content="x")]
    await provider.complete(CompletionRequest(messages=base, tools=(td,), tool_choice="none"))
    assert "tools" not in fake_client.messages.create.await_args.kwargs
    await provider.complete(CompletionRequest(messages=base, tools=(td,), tool_choice="auto"))
    assert fake_client.messages.create.await_args.kwargs["tool_choice"] == {"type": "auto"}
    await provider.complete(CompletionRequest(messages=base, tools=(td,), tool_choice="required"))
    assert fake_client.messages.create.await_args.kwargs["tool_choice"] == {"type": "any"}


@pytest.mark.asyncio
async def test_sent_tool_name_matches_anthropic_function_name_grammar() -> None:
    """Anthropic 400s on any tools[].name not matching ^[a-zA-Z0-9_-]{1,64}$
    — dots (AlfredOS's canonical tool-name separator) are forbidden. Assert
    the actual grammar, not just the literal 'web_fetch' value, so a future
    sanitization-algorithm change can't silently drift away from provider
    compliance while keeping only the exact-value test green.
    """
    fake_client = MagicMock()
    fake_client.messages.create = AsyncMock(return_value=_anthropic_text_response())
    provider = AnthropicProvider(client=fake_client, model="claude-sonnet-4-6")
    td = ToolDefinition(name="web.fetch", description="fetch", input_schema={"type": "object"})
    await provider.complete(
        CompletionRequest(messages=[Message(role="user", content="x")], tools=(td,))
    )
    sent_name = fake_client.messages.create.await_args.kwargs["tools"][0]["name"]
    # Full Anthropic grammar incl. the 1..64-char length bound sanitize enforces.
    assert re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", sent_name) is not None


@pytest.mark.asyncio
async def test_complete_refuses_loud_on_tool_name_collision() -> None:
    fake_client = MagicMock()
    fake_client.messages.create = AsyncMock()
    provider = AnthropicProvider(client=fake_client, model="claude-sonnet-4-6")
    tools = (
        ToolDefinition(name="web.fetch", description="d", input_schema={}),
        ToolDefinition(name="web_fetch", description="d2", input_schema={}),
    )
    with pytest.raises(ProviderToolNameCollisionError):
        await provider.complete(
            CompletionRequest(messages=[Message(role="user", content="x")], tools=tools)
        )
    fake_client.messages.create.assert_not_awaited()  # refuse BEFORE the network call


@pytest.mark.asyncio
async def test_response_tool_use_blocks_parsed() -> None:
    # Round trip: the provider echoes back the SANITIZED wire name
    # ("web_fetch") — a real Anthropic response never sees the canonical
    # dot. The parser must reverse-map it via the request's tools back to
    # the canonical "web.fetch" so tool-registry dispatch / audit rows
    # never see the sanitized form.
    fake_client = MagicMock()
    resp = MagicMock()
    text_block = MagicMock(type="text", text="let me fetch")
    tool_block = MagicMock(type="tool_use", id="c1", input={"url": "https://a.test"})
    tool_block.name = "web_fetch"  # name= is a reserved MagicMock ctor kwarg; set post-ctor
    resp.content = [text_block, tool_block]
    resp.usage = MagicMock(input_tokens=5, output_tokens=3)
    resp.stop_reason = "tool_use"
    fake_client.messages.create = AsyncMock(return_value=resp)
    provider = AnthropicProvider(client=fake_client, model="claude-sonnet-4-6")
    td = ToolDefinition(name="web.fetch", description="fetch", input_schema={"type": "object"})
    res = await provider.complete(
        CompletionRequest(messages=[Message(role="user", content="x")], tools=(td,))
    )
    assert res.stop_reason == "tool_use"
    assert res.content == "let me fetch"
    assert res.tool_calls == (
        ToolCall(id="c1", name="web.fetch", arguments={"url": "https://a.test"}),
    )


@pytest.mark.asyncio
async def test_response_tool_use_unmapped_name_passes_through_unchanged() -> None:
    # Anti-spoofing guarantee: name_map.get(returned, returned) must fall
    # through unchanged when the provider echoes a name that is NOT in this
    # request's tools (a genuinely empty map trivially exercises the same
    # code path but proves nothing about a REAL, non-empty map). Declare a
    # real tool (web.fetch) so the map is non-trivial, then have the mocked
    # response echo a DIFFERENT, unmapped wire name — proving it is NOT
    # silently remapped onto the real tool. It flows to dispatch_tool's
    # unknown_tool refusal downstream (tool_dispatch.py), never resolving to
    # web.fetch.
    fake_client = MagicMock()
    resp = MagicMock()
    tool_block = MagicMock(type="tool_use", id="c1", input={})
    tool_block.name = "some_other_tool"  # name= is a reserved MagicMock ctor kwarg
    resp.content = [tool_block]
    resp.usage = MagicMock(input_tokens=5, output_tokens=3)
    resp.stop_reason = "tool_use"
    fake_client.messages.create = AsyncMock(return_value=resp)
    provider = AnthropicProvider(client=fake_client, model="claude-sonnet-4-6")
    td = ToolDefinition(name="web.fetch", description="fetch", input_schema={"type": "object"})
    res = await provider.complete(
        CompletionRequest(messages=[Message(role="user", content="x")], tools=(td,))
    )
    assert res.tool_calls == (ToolCall(id="c1", name="some_other_tool", arguments={}),)


@pytest.mark.asyncio
async def test_plain_text_response_still_end_turn() -> None:
    fake_client = MagicMock()
    fake_client.messages.create = AsyncMock(return_value=_anthropic_text_response("hi"))
    provider = AnthropicProvider(client=fake_client, model="claude-sonnet-4-6")
    res = await provider.complete(CompletionRequest(messages=[Message(role="user", content="x")]))
    assert res.content == "hi"
    assert res.stop_reason == "end_turn"  # back-compat lock
    assert res.tool_calls == ()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "stop,expected",
    [("max_tokens", "max_tokens"), ("stop_sequence", "stop_sequence"), ("weird", "other")],
)
async def test_anthropic_stop_reason_map(stop: str, expected: str) -> None:
    r = _anthropic_text_response("hi")
    r.stop_reason = stop
    fake_client = MagicMock()
    fake_client.messages.create = AsyncMock(return_value=r)
    res = await AnthropicProvider(client=fake_client, model="claude-sonnet-4-6").complete(
        CompletionRequest(messages=[Message(role="user", content="x")])
    )
    assert res.stop_reason == expected


def test_anthropic_declares_tool_use() -> None:
    provider = AnthropicProvider(client=MagicMock(), model="claude-sonnet-4-6")
    assert ProviderCapability.TOOL_USE in provider.capabilities()


@pytest.mark.asyncio
async def test_plain_assistant_history_stays_a_string() -> None:
    fake_client = MagicMock()
    fake_client.messages.create = AsyncMock(return_value=_anthropic_text_response())
    provider = AnthropicProvider(client=fake_client, model="claude-sonnet-4-6")
    await provider.complete(
        CompletionRequest(
            messages=[
                Message(role="user", content="hi"),
                Message(role="assistant", content="hello"),
                Message(role="user", content="again"),
            ]
        )
    )
    msgs = fake_client.messages.create.await_args.kwargs["messages"]
    assert msgs[1] == {"role": "assistant", "content": "hello"}  # plain string, not a block list


@pytest.mark.asyncio
async def test_no_system_message_omits_system_kwarg() -> None:
    fake_client = MagicMock()
    fake_client.messages.create = AsyncMock(return_value=_anthropic_text_response())
    provider = AnthropicProvider(client=fake_client, model="claude-sonnet-4-6")
    await provider.complete(CompletionRequest(messages=[Message(role="user", content="x")]))
    assert "system" not in fake_client.messages.create.await_args.kwargs  # not system=null


@pytest.mark.asyncio
async def test_anthropic_refuses_loud_when_model_lacks_tool_use() -> None:
    # The guard is structurally unreachable today (Anthropic always declares
    # TOOL_USE); patch capabilities() to pin the refuse-loud branch anyway.
    fake_client = MagicMock()
    fake_client.messages.create = AsyncMock()
    provider = AnthropicProvider(client=fake_client, model="claude-sonnet-4-6")
    td = ToolDefinition(name="t", description="d", input_schema={})
    with (
        patch.object(provider, "capabilities", return_value=frozenset()),
        pytest.raises(ProviderToolUnsupportedError),
    ):
        await provider.complete(
            CompletionRequest(messages=[Message(role="user", content="x")], tools=(td,))
        )
    fake_client.messages.create.assert_not_awaited()  # refuse BEFORE building the request


@pytest.mark.asyncio
async def test_complete_maps_sdk_error_to_provider_unavailable(
    anthropic_provider: AnthropicProvider,
) -> None:
    # anthropic_provider is the fixture whose _client is a mock; make the
    # network call raise the SDK's connection error.
    anthropic_provider._client.messages.create.side_effect = APIConnectionError(
        request=httpx.Request("POST", "https://api.anthropic.com/v1/messages")
    )
    req = CompletionRequest(messages=[Message(role="user", content="hi")])
    with pytest.raises(ProviderUnavailableError):
        await anthropic_provider.complete(req)


@pytest.mark.asyncio
async def test_complete_maps_httpx_error_to_provider_unavailable(
    anthropic_provider: AnthropicProvider,
) -> None:
    anthropic_provider._client.messages.create.side_effect = httpx.ConnectError("boom")
    req = CompletionRequest(messages=[Message(role="user", content="hi")])
    with pytest.raises(ProviderUnavailableError):
        await anthropic_provider.complete(req)


@pytest.mark.asyncio
async def test_provider_unavailable_message_omits_raw_sdk_exc_text(
    anthropic_provider: AnthropicProvider,
) -> None:
    # FIX-5: the mapped error's message must identify the provider/model but
    # must NOT render the raw SDK exception text — that text can carry
    # provider-supplied strings the operator-facing t() catalog should not
    # blindly interpolate.
    anthropic_provider._client.messages.create.side_effect = httpx.ConnectError(
        "leaked-upstream-detail-9f3c"
    )
    req = CompletionRequest(messages=[Message(role="user", content="hi")])
    with pytest.raises(ProviderUnavailableError) as exc_info:
        await anthropic_provider.complete(req)
    message = str(exc_info.value)
    assert "anthropic" in message
    assert "claude-haiku-4-5" in message
    assert "leaked-upstream-detail-9f3c" not in message
