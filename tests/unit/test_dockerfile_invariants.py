"""Static pins on docker/alfred-core.Dockerfile (#500)."""

from __future__ import annotations

from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]
_DOCKERFILE = _ROOT / "docker" / "alfred-core.Dockerfile"


def _runtime_stage(text: str) -> str:
    # Everything from the LAST `FROM ... AS runtime` to EOF — so a builder-stage COPY
    # can't satisfy a runtime-stage pin (test-007).
    marker = "AS runtime"
    idx = text.rfind(marker)
    assert idx != -1, "no `AS runtime` stage found in the Dockerfile."
    return text[idx:]


@pytest.fixture
def runtime_stage() -> str:
    return _runtime_stage(_DOCKERFILE.read_text())


def test_runtime_stage_copies_plugins(runtime_stage: str) -> None:
    assert "COPY plugins ./plugins" in runtime_stage


def test_runtime_stage_sets_repo_root_env(runtime_stage: str) -> None:
    assert "ALFRED_REPO_ROOT=/app" in runtime_stage


def test_dockerignore_excludes_venv_and_pycache() -> None:
    di = (_ROOT / ".dockerignore").read_text()
    for pat in ("**/.venv", "**/__pycache__"):
        assert pat in di, f".dockerignore must exclude {pat} (reproducible-image hygiene)."
