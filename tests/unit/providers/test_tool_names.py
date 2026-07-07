"""Tests for the provider tool-name sanitization / reverse-mapping helpers
(the OpenAI/DeepSeek + Anthropic function-name grammar boundary — #339).

AlfredOS tool names use dots (``web.fetch``, ``clock.now``) but OpenAI/
DeepSeek require ``^[a-zA-Z0-9_-]+$`` and Anthropic requires
``^[a-zA-Z0-9_-]{1,64}$`` — both forbid dots. These helpers sanitize on send
and reverse-map on receive so the rest of AlfredOS never sees the wire form.
"""

from __future__ import annotations

import re

import pytest

from alfred.providers._tool_names import build_tool_name_map, sanitize_tool_name
from alfred.providers.base import ProviderToolNameCollisionError, ToolDefinition

_PROVIDER_SAFE_NAME = re.compile(r"^[a-zA-Z0-9_-]+$")


class TestSanitizeToolName:
    def test_dots_replaced_with_underscore(self) -> None:
        assert sanitize_tool_name("web.fetch") == "web_fetch"

    def test_clock_now_sanitized(self) -> None:
        assert sanitize_tool_name("clock.now") == "clock_now"

    def test_already_safe_name_is_unchanged(self) -> None:
        assert sanitize_tool_name("already_safe-name123") == "already_safe-name123"

    def test_idempotent_on_sanitized_output(self) -> None:
        once = sanitize_tool_name("web.fetch")
        assert sanitize_tool_name(once) == once

    def test_multiple_unsafe_characters_all_replaced(self) -> None:
        assert sanitize_tool_name("a.b:c d") == "a_b_c_d"

    @pytest.mark.parametrize("name", ["web.fetch", "clock.now", "a:b/c d", "already-safe_123"])
    def test_output_always_matches_provider_grammar(self, name: str) -> None:
        assert _PROVIDER_SAFE_NAME.fullmatch(sanitize_tool_name(name)) is not None


class TestBuildToolNameMap:
    def test_maps_safe_name_to_canonical(self) -> None:
        tools = (
            ToolDefinition(name="web.fetch", description="d", input_schema={}),
            ToolDefinition(name="clock.now", description="d", input_schema={}),
        )
        name_map = build_tool_name_map(tools)
        assert name_map == {"web_fetch": "web.fetch", "clock_now": "clock.now"}

    def test_empty_tools_yields_empty_map(self) -> None:
        assert build_tool_name_map(()) == {}

    def test_collision_between_distinct_names_raises_loud(self) -> None:
        # Two distinct canonical names that sanitize to the same safe name —
        # HARD rule #7: no silent clobber. With today's shipped tool names
        # (web.fetch, clock.now) this can't happen; construct a synthetic
        # pair to prove the guard fires when it eventually could.
        tools = (
            ToolDefinition(name="web.fetch", description="d", input_schema={}),
            ToolDefinition(name="web_fetch", description="d2", input_schema={}),
        )
        with pytest.raises(ProviderToolNameCollisionError):
            build_tool_name_map(tools)

    def test_repeated_identical_canonical_name_is_not_a_collision(self) -> None:
        # The SAME canonical name appearing twice sanitizes to the same safe
        # name by construction — that's a repeat, not an ambiguity.
        tools = (
            ToolDefinition(name="web.fetch", description="d", input_schema={}),
            ToolDefinition(name="web.fetch", description="d2", input_schema={}),
        )
        name_map = build_tool_name_map(tools)
        assert name_map == {"web_fetch": "web.fetch"}
