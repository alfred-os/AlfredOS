"""Shared fixtures for the gate-integrity meta suite (#543 review, rev-002).

``_load_runner()`` — the importlib dance that loads ``scripts/run_coverage_gates.py``
as a module rather than a package — was byte-identical in
``test_coverage_gate_runner.py`` and ``test_gate_surfaces_are_pinned.py``, and the
``yaml.safe_load(ci.yml)`` fixture body was duplicated alongside it under two
different names. CLAUDE.md: refactor on the SECOND duplication, not the first;
this was the second.

Session scope on ``runner`` is deliberate. Every test that mutates the loaded
module does so through ``monkeypatch.setattr``, which reverts at test teardown,
so one instance is safe — and it removes 12 re-executions of the script per run.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
import yaml

REPO_ROOT: Path = Path(__file__).resolve().parents[3]
CI_WORKFLOW: Path = REPO_ROOT / ".github" / "workflows" / "ci.yml"
RUNNER_SCRIPT: Path = REPO_ROOT / "scripts" / "run_coverage_gates.py"


@pytest.fixture(scope="session")
def runner() -> ModuleType:
    """Import ``scripts/run_coverage_gates.py`` — a script, not a package."""
    spec = importlib.util.spec_from_file_location("run_coverage_gates", RUNNER_SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="session")
def ci_workflow() -> dict[str, Any]:
    """``.github/workflows/ci.yml``, parsed."""
    return yaml.safe_load(CI_WORKFLOW.read_text(encoding="utf-8"))


@pytest.fixture(scope="session")
def ci_workflow_raw() -> str:
    """``.github/workflows/ci.yml``, raw text — the second, independent oracle."""
    return CI_WORKFLOW.read_text(encoding="utf-8")
