"""Static pins on docker/alfred-core.Dockerfile (#500)."""

from __future__ import annotations

from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]
_DOCKERFILE = _ROOT / "docker" / "alfred-core.Dockerfile"


def _runtime_stage_instructions(text: str) -> str:
    """Runtime-stage INSTRUCTION lines only (last real ``FROM … AS runtime`` → EOF, with
    comment lines stripped).

    Anchoring matters (CodeRabbit): matching raw text would let a removed ``COPY plugins`` /
    ``ALFRED_REPO_ROOT`` instruction still pass if the string survives in a comment, and an
    unanchored ``rfind("AS runtime")`` could latch onto a comment mentioning "AS runtime". So
    the boundary is the last line that is genuinely a ``FROM … AS runtime`` instruction (not a
    ``#`` comment), and comment lines within the stage are dropped before the substring pins.
    """
    lines = text.splitlines()
    start: int | None = None
    for i, ln in enumerate(lines):
        stripped = ln.strip()
        if (
            not stripped.startswith("#")
            and stripped.startswith("FROM ")
            and stripped.endswith("AS runtime")
        ):
            start = i
    assert start is not None, "no `FROM … AS runtime` instruction found in the Dockerfile."
    return "\n".join(ln for ln in lines[start:] if not ln.lstrip().startswith("#"))


@pytest.fixture
def runtime_instructions() -> str:
    return _runtime_stage_instructions(_DOCKERFILE.read_text())


def test_runtime_stage_copies_plugins(runtime_instructions: str) -> None:
    # plugins/ is a RUNTIME artifact (the daemon reads plugins/<id>/manifest.toml by path);
    # without this COPY the comms-adapter validator refuses every Settings() in the image.
    assert "COPY plugins ./plugins" in runtime_instructions


def test_runtime_stage_sets_repo_root_env(runtime_instructions: str) -> None:
    # The deploy seam so the installed image never depends on parents[N] arithmetic.
    assert "ALFRED_REPO_ROOT=/app" in runtime_instructions


def test_dockerignore_excludes_venv_and_pycache() -> None:
    di = (_ROOT / ".dockerignore").read_text()
    for pat in ("**/.venv", "**/__pycache__"):
        assert pat in di, f".dockerignore must exclude {pat} (reproducible-image hygiene)."
