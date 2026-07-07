"""Tests for the DeepSeek provider adapter (uses OpenAI SDK + custom base_url)."""

from __future__ import annotations

import re
from unittest.mock import AsyncMock, MagicMock

import pytest

from alfred.providers.base import (
    CompletionRequest,
    ForcedTool,
    Message,
    ProviderCapability,
    ProviderMalformedToolArgumentsError,
    ProviderToolNameCollisionError,
    ProviderToolUnsupportedError,
    ToolCall,
    ToolDefinition,
)
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


def test_from_settings_passes_http_client_and_base_url(monkeypatch: pytest.MonkeyPatch) -> None:
    import alfred.providers.deepseek as mod

    captured: dict[str, object] = {}
    monkeypatch.setattr(mod, "AsyncOpenAI", lambda **kw: captured.update(kw) or object())
    sentinel = object()
    mod.DeepSeekProvider.from_settings(
        api_key="k",
        base_url="https://api.deepseek.com/v1",
        model="deepseek-chat",
        http_client=sentinel,
    )
    assert captured["http_client"] is sentinel
    assert captured["base_url"] == "https://api.deepseek.com/v1"


def test_from_settings_default_passes_none_http_client(monkeypatch: pytest.MonkeyPatch) -> None:
    """Behaviour-neutral default: http_client=None => SDK builds its own (today's path)."""
    import alfred.providers.deepseek as mod

    captured: dict[str, object] = {}
    monkeypatch.setattr(mod, "AsyncOpenAI", lambda **kw: captured.update(kw) or object())
    mod.DeepSeekProvider.from_settings(
        api_key="k", base_url="https://api.deepseek.com/v1", model="deepseek-chat"
    )
    assert captured["http_client"] is None


def _openai_ok_response(content: str = "ok") -> MagicMock:
    r = MagicMock()
    r.choices = [
        MagicMock(message=MagicMock(content=content, tool_calls=None), finish_reason="stop")
    ]
    r.usage = MagicMock(prompt_tokens=1, completion_tokens=1)
    return r


def _openai_toolcall_response(args_json: str, *, name: str = "web.fetch") -> MagicMock:
    tc = MagicMock(id="c1", type="function")
    tc.function = MagicMock(arguments=args_json)
    tc.function.name = name  # name= is a reserved MagicMock ctor kwarg; set post-ctor
    r = MagicMock()
    r.choices = [
        MagicMock(message=MagicMock(content=None, tool_calls=[tc]), finish_reason="tool_calls")
    ]
    r.usage = MagicMock(prompt_tokens=3, completion_tokens=2)
    return r


@pytest.mark.asyncio
async def test_plain_messages_serialize_without_tool_keys() -> None:
    fake_client = MagicMock()
    fake_client.chat.completions.create = AsyncMock(return_value=_openai_ok_response())
    provider = DeepSeekProvider(client=fake_client, model="deepseek-chat")
    await provider.complete(
        CompletionRequest(
            messages=[Message(role="system", content="s"), Message(role="user", content="u")]
        )
    )
    kw = fake_client.chat.completions.create.await_args.kwargs
    # Plain messages MUST NOT carry tool_calls / tool_call_id (would 400 DeepSeek).
    assert kw["messages"] == [
        {"role": "system", "content": "s"},
        {"role": "user", "content": "u"},
    ]
    assert "tools" not in kw


@pytest.mark.asyncio
async def test_tools_and_tool_role_serialize_to_openai_shape() -> None:
    fake_client = MagicMock()
    fake_client.chat.completions.create = AsyncMock(return_value=_openai_ok_response())
    provider = DeepSeekProvider(client=fake_client, model="deepseek-chat")
    td = ToolDefinition(name="web.fetch", description="fetch", input_schema={"type": "object"})
    call = ToolCall(id="c1", name="web.fetch", arguments={"url": "https://a.test"})
    req = CompletionRequest(
        messages=[
            Message(role="assistant", content="", tool_calls=(call,)),
            Message(role="tool", content='{"ok": true}', tool_call_id="c1"),
        ],
        tools=(td,),
        tool_choice=ForcedTool(name="web.fetch"),
    )
    await provider.complete(req)
    kw = fake_client.chat.completions.create.await_args.kwargs
    # Canonical dotted names are sanitized to underscores on the WIRE — OpenAI/
    # DeepSeek 400 on '^[a-zA-Z0-9_-]+$' violations (dots forbidden). This
    # applies to the tool definition, the forced tool_choice, AND the prior
    # assistant tool_call being re-sent as history (load-bearing at iteration
    # >= 1 of the act-phase loop).
    assert kw["tools"] == [
        {
            "type": "function",
            "function": {
                "name": "web_fetch",
                "description": "fetch",
                "parameters": {"type": "object"},
            },
        }
    ]
    assert kw["tool_choice"] == {"type": "function", "function": {"name": "web_fetch"}}
    assert kw["messages"][0] == {
        "role": "assistant",
        "content": "",
        "tool_calls": [
            {
                "id": "c1",
                "type": "function",
                "function": {"name": "web_fetch", "arguments": '{"url": "https://a.test"}'},
            }
        ],
    }
    assert kw["messages"][1] == {"role": "tool", "content": '{"ok": true}', "tool_call_id": "c1"}


@pytest.mark.asyncio
async def test_sent_tool_name_matches_openai_function_name_grammar() -> None:
    """OpenAI/DeepSeek 400 on any tools[].function.name not matching
    ^[a-zA-Z0-9_-]+$ — dots (AlfredOS's canonical tool-name separator) are
    forbidden. Assert the actual grammar, not just the literal 'web_fetch'
    value, so a future sanitization-algorithm change can't silently drift
    away from provider compliance while keeping only the exact-value test
    green.
    """
    fake_client = MagicMock()
    fake_client.chat.completions.create = AsyncMock(return_value=_openai_ok_response())
    provider = DeepSeekProvider(client=fake_client, model="deepseek-chat")
    td = ToolDefinition(name="web.fetch", description="fetch", input_schema={"type": "object"})
    await provider.complete(
        CompletionRequest(messages=[Message(role="user", content="x")], tools=(td,))
    )
    kw = fake_client.chat.completions.create.await_args.kwargs
    sent_name = kw["tools"][0]["function"]["name"]
    assert re.fullmatch(r"[a-zA-Z0-9_-]+", sent_name) is not None


@pytest.mark.asyncio
async def test_complete_refuses_loud_on_tool_name_collision() -> None:
    fake_client = MagicMock()
    fake_client.chat.completions.create = AsyncMock()
    provider = DeepSeekProvider(client=fake_client, model="deepseek-chat")
    tools = (
        ToolDefinition(name="web.fetch", description="d", input_schema={}),
        ToolDefinition(name="web_fetch", description="d2", input_schema={}),
    )
    with pytest.raises(ProviderToolNameCollisionError):
        await provider.complete(
            CompletionRequest(messages=[Message(role="user", content="x")], tools=tools)
        )
    fake_client.chat.completions.create.assert_not_awaited()  # refuse BEFORE the network call


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "choice,expected", [("auto", "auto"), ("required", "required"), ("none", "none")]
)
async def test_deepseek_tool_choice_string_variants(choice: str, expected: str) -> None:
    fake_client = MagicMock()
    fake_client.chat.completions.create = AsyncMock(return_value=_openai_ok_response())
    provider = DeepSeekProvider(client=fake_client, model="deepseek-chat")
    td = ToolDefinition(name="t", description="d", input_schema={})
    await provider.complete(
        CompletionRequest(
            messages=[Message(role="user", content="x")],
            tools=(td,),
            tool_choice=choice,  # type: ignore[arg-type]
        )
    )
    assert fake_client.chat.completions.create.await_args.kwargs["tool_choice"] == expected


@pytest.mark.asyncio
async def test_response_tool_calls_parsed_and_stop_reason_mapped() -> None:
    # Round trip: the provider echoes back the SANITIZED wire name
    # ("web_fetch") — a real DeepSeek response never sees the canonical dot.
    # The parser must reverse-map it via the request's tools back to the
    # canonical "web.fetch" so tool-registry dispatch / audit rows never see
    # the sanitized form.
    fake_client = MagicMock()
    fake_client.chat.completions.create = AsyncMock(
        return_value=_openai_toolcall_response('{"url": "https://a.test"}', name="web_fetch")
    )
    provider = DeepSeekProvider(client=fake_client, model="deepseek-chat")
    td = ToolDefinition(name="web.fetch", description="fetch", input_schema={"type": "object"})
    res = await provider.complete(
        CompletionRequest(messages=[Message(role="user", content="x")], tools=(td,))
    )
    assert res.stop_reason == "tool_use"
    assert res.tool_calls == (
        ToolCall(id="c1", name="web.fetch", arguments={"url": "https://a.test"}),
    )
    assert res.content == ""  # content None -> ""


@pytest.mark.asyncio
async def test_response_tool_call_unmapped_name_passes_through_unchanged() -> None:
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
    fake_client.chat.completions.create = AsyncMock(
        return_value=_openai_toolcall_response("{}", name="some_other_tool")
    )
    provider = DeepSeekProvider(client=fake_client, model="deepseek-chat")
    td = ToolDefinition(name="web.fetch", description="fetch", input_schema={"type": "object"})
    res = await provider.complete(
        CompletionRequest(messages=[Message(role="user", content="x")], tools=(td,))
    )
    assert res.tool_calls == (ToolCall(id="c1", name="some_other_tool", arguments={}),)


@pytest.mark.asyncio
async def test_plain_text_response_maps_end_turn() -> None:
    fake_client = MagicMock()
    fake_client.chat.completions.create = AsyncMock(return_value=_openai_ok_response("hello"))
    provider = DeepSeekProvider(client=fake_client, model="deepseek-chat")
    res = await provider.complete(CompletionRequest(messages=[Message(role="user", content="x")]))
    assert res.stop_reason == "end_turn"  # back-compat lock
    assert res.tool_calls == ()
    assert res.content == "hello"


@pytest.mark.asyncio
async def test_malformed_tool_arguments_fail_loud() -> None:
    fake_client = MagicMock()
    fake_client.chat.completions.create = AsyncMock(
        return_value=_openai_toolcall_response("{not json")
    )
    provider = DeepSeekProvider(client=fake_client, model="deepseek-chat")
    with pytest.raises(ProviderMalformedToolArgumentsError):
        await provider.complete(CompletionRequest(messages=[Message(role="user", content="x")]))


@pytest.mark.asyncio
@pytest.mark.parametrize("finish,expected", [("length", "max_tokens"), ("weird", "other")])
async def test_deepseek_finish_reason_map(finish: str, expected: str) -> None:
    r = _openai_ok_response("hi")
    r.choices[0].finish_reason = finish
    fake_client = MagicMock()
    fake_client.chat.completions.create = AsyncMock(return_value=r)
    res = await DeepSeekProvider(client=fake_client, model="deepseek-chat").complete(
        CompletionRequest(messages=[Message(role="user", content="x")])
    )
    assert res.stop_reason == expected


def test_deepseek_chat_declares_tool_use() -> None:
    assert ProviderCapability.TOOL_USE in DeepSeekProvider._capabilities_for_model("deepseek-chat")


def test_deepseek_reasoner_lacks_tool_use() -> None:
    assert ProviderCapability.TOOL_USE not in DeepSeekProvider._capabilities_for_model(
        "deepseek-reasoner"
    )


@pytest.mark.asyncio
async def test_reasoner_refuses_loud_when_tools_requested() -> None:
    fake_client = MagicMock()
    fake_client.chat.completions.create = AsyncMock()
    provider = DeepSeekProvider(client=fake_client, model="deepseek-reasoner")
    td = ToolDefinition(name="web.fetch", description="f", input_schema={})
    with pytest.raises(ProviderToolUnsupportedError):
        await provider.complete(
            CompletionRequest(messages=[Message(role="user", content="x")], tools=(td,))
        )
    fake_client.chat.completions.create.assert_not_awaited()  # refuse BEFORE building the request


@pytest.mark.asyncio
async def test_non_object_json_args_fail_loud() -> None:
    fake_client = MagicMock()
    fake_client.chat.completions.create = AsyncMock(return_value=_openai_toolcall_response("[]"))
    provider = DeepSeekProvider(client=fake_client, model="deepseek-chat")
    with pytest.raises(ProviderMalformedToolArgumentsError):
        await provider.complete(CompletionRequest(messages=[Message(role="user", content="x")]))


@pytest.mark.asyncio
async def test_empty_string_args_become_empty_dict() -> None:
    fake_client = MagicMock()
    fake_client.chat.completions.create = AsyncMock(return_value=_openai_toolcall_response(""))
    provider = DeepSeekProvider(client=fake_client, model="deepseek-chat")
    res = await provider.complete(CompletionRequest(messages=[Message(role="user", content="x")]))
    assert res.tool_calls == (ToolCall(id="c1", name="web.fetch", arguments={}),)


@pytest.mark.asyncio
async def test_non_function_tool_calls_dropped_and_stop_reason_downgraded() -> None:
    tc = MagicMock(id="c1", type="custom")  # a non-function (custom) tool call
    r = MagicMock()
    r.choices = [
        MagicMock(message=MagicMock(content=None, tool_calls=[tc]), finish_reason="tool_calls")
    ]
    r.usage = MagicMock(prompt_tokens=1, completion_tokens=1)
    fake_client = MagicMock()
    fake_client.chat.completions.create = AsyncMock(return_value=r)
    res = await DeepSeekProvider(client=fake_client, model="deepseek-chat").complete(
        CompletionRequest(messages=[Message(role="user", content="x")])
    )
    assert res.tool_calls == ()
    assert res.stop_reason == "other"  # downgraded — no callable tool remained


@pytest.mark.asyncio
async def test_plain_assistant_history_serializes_without_tool_calls() -> None:
    fake_client = MagicMock()
    fake_client.chat.completions.create = AsyncMock(return_value=_openai_ok_response())
    provider = DeepSeekProvider(client=fake_client, model="deepseek-chat")
    await provider.complete(
        CompletionRequest(
            messages=[
                Message(role="user", content="hi"),
                Message(role="assistant", content="hello"),
                Message(role="user", content="again"),
            ]
        )
    )
    msgs = fake_client.chat.completions.create.await_args.kwargs["messages"]
    assert msgs[1] == {"role": "assistant", "content": "hello"}  # no stray tool_calls key
