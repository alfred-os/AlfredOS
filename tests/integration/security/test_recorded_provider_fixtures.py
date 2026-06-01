"""Per-provider recorded extraction fixtures — shape pins (prov-006).

The fixture files under :mod:`tests.fixtures.providers` are the recorded
provider responses Tasks 9, 10, 11, 14 consume. This module pins the
shape contract so the fixture conftest (``tests/integration/security/
conftest.py``) and the JSON files in :mod:`tests.fixtures.providers`
cannot drift from the spec §6.2 wire shapes.

Pinning the fixture shapes at the integration-tests layer (rather than
inside the fixture conftest itself) keeps the conftest a thin loader —
shape regressions land in this file as failing assertions, not as
silent fixture-key changes.
"""

from __future__ import annotations

from typing import Any


def test_recorded_extraction_fixture_returns_dict_shape(
    recorded_extraction_fixture: dict[str, Any],
) -> None:
    """Default fixture carries request_body / response_body / extraction_mode keys."""
    assert isinstance(recorded_extraction_fixture, dict)
    assert "request_body" in recorded_extraction_fixture
    assert "response_body" in recorded_extraction_fixture
    assert "extraction_mode" in recorded_extraction_fixture


def test_anthropic_fixture_tool_use_shape(
    recorded_anthropic_extraction_fixture: dict[str, Any],
) -> None:
    """Anthropic native constrained extraction: tool-use wire shape (spec §6.2).

    The schema lives at ``request_body["tools"][0]["input_schema"]``.
    """
    req = recorded_anthropic_extraction_fixture["request_body"]
    tools = req.get("tools", [])
    assert tools, "Anthropic fixture must declare at least one tool"
    assert "input_schema" in tools[0]
    assert recorded_anthropic_extraction_fixture["extraction_mode"] == "native_constrained"


def test_deepseek_fixture_json_object_shape(
    recorded_deepseek_extraction_fixture: dict[str, Any],
) -> None:
    """DeepSeek JSON mode: ``response_format={"type": "json_object"}`` (spec §6.2)."""
    req = recorded_deepseek_extraction_fixture["request_body"]
    rf = req.get("response_format", {})
    assert rf.get("type") == "json_object"
    assert recorded_deepseek_extraction_fixture["extraction_mode"] == "json_object_unconstrained"


def test_recorded_injection_fixture_carries_extracted_and_instruction(
    recorded_injection_fixture: dict[str, Any],
) -> None:
    """Injection fixture: ``injected_instruction`` string + an :class:`Extracted` result.

    The structural invariant tested in Task 9 is that the
    ``injected_instruction`` string MUST NOT appear verbatim in any of
    the ``Extracted.data`` values. This fixture provides both halves.
    """
    from alfred.security.quarantine import Extracted

    assert "injected_instruction" in recorded_injection_fixture
    assert isinstance(recorded_injection_fixture["injected_instruction"], str)
    assert isinstance(recorded_injection_fixture["extracted_result"], Extracted)


def test_recorded_canary_fixture_reports_pre_extract_trip(
    recorded_canary_fixture: dict[str, Any],
) -> None:
    """Canary fixture: canary trip MUST be observable BEFORE quarantine.extract ran (spec §12.4)."""
    assert recorded_canary_fixture["canary_tripped"] is True
    assert recorded_canary_fixture["extract_was_called"] is False
