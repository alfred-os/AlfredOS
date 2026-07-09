"""Tests for the provider router."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from alfred.providers.base import (
    CompletionRequest,
    CompletionResponse,
    Message,
    ProviderToolNameCollisionError,
    ProviderToolUnsupportedError,
    ProviderUnavailableError,
    ToolDefinition,
)
from alfred.providers.router import ProviderRouter


@pytest.mark.asyncio
async def test_uses_primary_when_it_succeeds() -> None:
    primary = MagicMock(name="primary")
    primary.name = "deepseek"
    primary.complete = AsyncMock(
        return_value=CompletionResponse(
            content="primary said hi",
            tokens_in=5,
            tokens_out=3,
            cost_usd=0.00001,
            model="deepseek-chat",
        )
    )
    fallback = MagicMock(name="fallback")
    fallback.complete = AsyncMock(return_value=None)

    router = ProviderRouter(primary=primary, fallback=fallback)
    res = await router.complete(CompletionRequest(messages=[Message(role="user", content="hi")]))

    assert res.content == "primary said hi"
    primary.complete.assert_awaited_once()
    fallback.complete.assert_not_awaited()


@pytest.mark.asyncio
async def test_falls_back_when_primary_raises() -> None:
    primary = MagicMock(name="primary")
    primary.name = "deepseek"
    primary.complete = AsyncMock(side_effect=RuntimeError("upstream 503"))
    fallback = MagicMock(name="fallback")
    fallback.name = "anthropic"
    fallback.complete = AsyncMock(
        return_value=CompletionResponse(
            content="fallback responded",
            tokens_in=4,
            tokens_out=3,
            cost_usd=0.001,
            model="claude-sonnet-4-6",
        )
    )

    router = ProviderRouter(primary=primary, fallback=fallback)
    res = await router.complete(CompletionRequest(messages=[Message(role="user", content="hi")]))

    assert res.content == "fallback responded"
    primary.complete.assert_awaited_once()
    fallback.complete.assert_awaited_once()


@pytest.mark.asyncio
async def test_no_fallback_means_primary_errors_propagate() -> None:
    primary = MagicMock(name="primary")
    primary.complete = AsyncMock(side_effect=RuntimeError("upstream"))
    router = ProviderRouter(primary=primary, fallback=None)
    with pytest.raises(RuntimeError, match="upstream"):
        await router.complete(CompletionRequest(messages=[Message(role="user", content="hi")]))


@pytest.mark.asyncio
async def test_router_does_not_fall_back_on_tool_unsupported() -> None:
    # A capability refusal is a loud operator-misconfiguration signal, NOT a
    # transient failure — the router must re-raise it, not silently use the
    # fallback for every tool turn (spec §4.1; "no capability routing").
    primary = MagicMock(name="primary")
    primary.complete = AsyncMock(side_effect=ProviderToolUnsupportedError("no tools"))
    fallback = MagicMock(name="fallback")
    fallback.complete = AsyncMock()
    router = ProviderRouter(primary=primary, fallback=fallback)
    with pytest.raises(ProviderToolUnsupportedError):
        await router.complete(
            CompletionRequest(
                messages=[Message(role="user", content="x")],
                tools=(ToolDefinition(name="t", description="d", input_schema={}),),
            )
        )
    fallback.complete.assert_not_awaited()


@pytest.mark.asyncio
async def test_router_does_not_fall_back_on_tool_name_collision() -> None:
    # A tool-name collision is a deterministic config error: the fallback would
    # build the same name-map from the same tools and raise identically, so the
    # router must re-raise it, not try (and mislabel) the fallback.
    primary = MagicMock(name="primary")
    primary.complete = AsyncMock(
        side_effect=ProviderToolNameCollisionError("web.fetch and web_fetch collide")
    )
    fallback = MagicMock(name="fallback")
    fallback.complete = AsyncMock()
    router = ProviderRouter(primary=primary, fallback=fallback)
    with pytest.raises(ProviderToolNameCollisionError):
        await router.complete(
            CompletionRequest(
                messages=[Message(role="user", content="x")],
                tools=(ToolDefinition(name="web.fetch", description="d", input_schema={}),),
            )
        )
    fallback.complete.assert_not_awaited()


@pytest.mark.asyncio
async def test_router_does_not_fall_back_on_malformed_tool_args() -> None:
    from alfred.providers.base import ProviderMalformedToolArgumentsError

    primary = MagicMock(name="primary")
    primary.complete = AsyncMock(side_effect=ProviderMalformedToolArgumentsError("bad json"))
    fallback = MagicMock(name="fallback")
    fallback.complete = AsyncMock()
    router = ProviderRouter(primary=primary, fallback=fallback)
    with pytest.raises(ProviderMalformedToolArgumentsError):
        await router.complete(CompletionRequest(messages=[Message(role="user", content="x")]))
    fallback.complete.assert_not_awaited()


@pytest.mark.asyncio
async def test_router_falls_back_on_provider_unavailable() -> None:
    # ProviderUnavailableError is deliberately NOT in _TOOL_PROTOCOL_ERRORS — a
    # transient transport failure SHOULD fall back to the secondary provider,
    # unlike the deterministic tool-protocol errors above. This is a regression
    # test proving the router's broad `except Exception` fallback still catches
    # it (i.e. no future edit accidentally adds it to _TOOL_PROTOCOL_ERRORS).
    primary = AsyncMock()
    primary.name = "primary"
    primary.complete = AsyncMock(side_effect=ProviderUnavailableError("down"))
    fallback = AsyncMock()
    fallback.name = "fallback"
    ok = CompletionResponse(
        content="ok", tokens_in=1, tokens_out=1, cost_usd=0.0, model="fallback-model"
    )
    fallback.complete = AsyncMock(return_value=ok)
    router = ProviderRouter(primary=primary, fallback=fallback)

    result = await router.complete(CompletionRequest(messages=[Message(role="user", content="hi")]))

    assert result is ok
    fallback.complete.assert_awaited_once()
