"""Verify Settings.state_git_path defaults + override behaviour (#174 PR-S4-1)."""

from __future__ import annotations

from pathlib import Path

import pytest

from alfred.config.settings import Settings


def test_state_git_path_default(monkeypatch: pytest.MonkeyPatch) -> None:
    """Default is /var/lib/alfred/state.git per spec §3.1 reference shape."""
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-test")
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "development")
    monkeypatch.delenv("ALFRED_STATE_GIT_PATH", raising=False)
    settings = Settings()
    assert settings.state_git_path == Path("/var/lib/alfred/state.git")


def test_state_git_path_override(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """ALFRED_STATE_GIT_PATH env var overrides the default."""
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-test")
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "development")
    monkeypatch.setenv("ALFRED_STATE_GIT_PATH", str(tmp_path / "alt-state.git"))
    settings = Settings()
    assert settings.state_git_path == tmp_path / "alt-state.git"
