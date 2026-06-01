"""Pytest fixtures for the smoke suite (Task 14 — provider capabilities).

Mirrors the per-provider recorded-fixture loaders in
``tests/integration/security/conftest.py`` so the smoke layer can pin the
on-the-wire shape contract (Anthropic tool-use, OpenAI strict:true,
DeepSeek json_object) without depending on the integration conftest's
import side effects (e.g. ``alfred.security.quarantine``) — smoke tests
exercise the public Provider surface only.

The fixtures load the same JSON files under ``tests/fixtures/providers/``
that the integration suite consumes, so a Slice-4 provider upgrade
re-records both layers from one source of truth.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

_FIXTURE_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "providers"


def _load(name: str) -> dict[str, Any]:
    """Read and decode one recorded-provider JSON fixture by file name."""
    path = _FIXTURE_DIR / name
    return json.loads(path.read_text())


@pytest.fixture
def recorded_anthropic_extraction_fixture() -> dict[str, Any]:
    """Anthropic tool-use (native_constrained) recorded fixture."""
    return _load("anthropic_native_constrained.json")


@pytest.fixture
def recorded_openai_extraction_fixture() -> dict[str, Any]:
    """OpenAI structured-outputs (strict:true) recorded fixture."""
    return _load("openai_structured_outputs.json")


@pytest.fixture
def recorded_deepseek_extraction_fixture() -> dict[str, Any]:
    """DeepSeek json_object_mode recorded fixture."""
    return _load("deepseek_json_mode.json")
