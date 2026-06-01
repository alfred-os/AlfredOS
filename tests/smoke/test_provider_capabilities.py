"""Provider capabilities smoke tests — recorded fixtures, no live API calls (spec §6.1).

Uses class-level CAPABILITIES constants rather than constructing provider instances
(prov-007: constructors require SDK client instances, not api_key strings).

The wire-shape assertions read the recorded request bodies under
``tests/fixtures/providers/`` so a Slice-4 SDK upgrade re-records the
JSON without re-touching test code.
"""

from __future__ import annotations

from typing import Any

from alfred.providers.anthropic_native import AnthropicProvider
from alfred.providers.base import ProviderCapability
from alfred.providers.deepseek import DeepSeekProvider


def test_anthropic_native_constrained_capability_declared() -> None:
    """AnthropicProvider declares NATIVE_CONSTRAINED_GENERATION (prov-007: no constructor)."""
    assert ProviderCapability.NATIVE_CONSTRAINED_GENERATION in AnthropicProvider.CAPABILITIES


def test_deepseek_chat_json_object_mode_declared() -> None:
    """DeepSeekProvider chat model declares JSON_OBJECT_MODE (prov-007: class method)."""
    caps = DeepSeekProvider._capabilities_for_model("deepseek-chat")
    assert ProviderCapability.JSON_OBJECT_MODE in caps
    assert ProviderCapability.NATIVE_CONSTRAINED_GENERATION not in caps


def test_deepseek_reasoner_lacks_json_object_mode() -> None:
    """DeepSeek reasoner model does NOT declare JSON_OBJECT_MODE (prov-009)."""
    caps = DeepSeekProvider._capabilities_for_model("deepseek-reasoner")
    assert ProviderCapability.JSON_OBJECT_MODE not in caps


def test_anthropic_response_format_uses_tool_shape(
    recorded_anthropic_extraction_fixture: dict[str, Any],
) -> None:
    """Anthropic native constrained generation uses tool-use shape (spec §6.2).

    The schema lives at ``request_body["tools"][0]["input_schema"]`` — Anthropic's
    tool-use API nests the JSON schema inside the tool definition (see fixture
    ``tests/fixtures/providers/anthropic_native_constrained.json``).
    """
    request_body = recorded_anthropic_extraction_fixture["request_body"]
    tools = request_body.get("tools", [])
    assert tools, "Anthropic request must declare at least one tool"
    assert "input_schema" in tools[0], (
        "Anthropic tool-use shape requires input_schema nested under tools[0]"
    )


def test_openai_strict_true_in_response_format(
    recorded_openai_extraction_fixture: dict[str, Any],
) -> None:
    """OpenAI structured outputs must include strict: true (spec §6.2)."""
    req = recorded_openai_extraction_fixture["request_body"]
    rf = req.get("response_format", {})
    assert rf.get("type") == "json_schema"
    json_schema = rf.get("json_schema", {})
    assert json_schema.get("strict") is True, "OpenAI response_format must have strict: true"
