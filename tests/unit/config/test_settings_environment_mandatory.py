"""Verify Settings.environment is mandatory per spec §7.3 (#174 PR-S4-1)."""

from __future__ import annotations

from pathlib import Path

import pytest

from alfred.config.settings import Settings, SettingsError


def test_environment_required(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Settings() with no environment source raises SettingsError per sec-003."""
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-test")
    monkeypatch.delenv("ALFRED_ENVIRONMENT", raising=False)
    # Override etc path so the test never touches /etc.
    monkeypatch.setattr(
        "alfred.config._environment_loader._DEFAULT_ETC_PATH",
        tmp_path / "no-such-file",
    )
    with pytest.raises(SettingsError):
        Settings()


def test_environment_production_loads(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Settings(environment='production') constructs cleanly."""
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-test")
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "production")
    monkeypatch.setattr(
        "alfred.config._environment_loader._DEFAULT_ETC_PATH",
        tmp_path / "no-such-file",
    )
    settings = Settings()
    assert settings.environment == "production"


@pytest.mark.parametrize("value", ["development", "production", "test"])
def test_environment_literal_values(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, value: str
) -> None:
    """All three Literal values load."""
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-test")
    monkeypatch.setenv("ALFRED_ENVIRONMENT", value)
    monkeypatch.setattr(
        "alfred.config._environment_loader._DEFAULT_ETC_PATH",
        tmp_path / "no-such-file",
    )
    assert Settings().environment == value


def test_environment_unrecognised_value_refuses(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A value outside the Literal triple raises SettingsError."""
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-test")
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "staging")
    monkeypatch.setattr(
        "alfred.config._environment_loader._DEFAULT_ETC_PATH",
        tmp_path / "no-such-file",
    )
    with pytest.raises(SettingsError):
        Settings()


def test_environment_explicit_kwarg_bypasses_loader(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """An explicit environment= kwarg short-circuits the dual-source loader."""
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-test")
    monkeypatch.delenv("ALFRED_ENVIRONMENT", raising=False)
    monkeypatch.setattr(
        "alfred.config._environment_loader._DEFAULT_ETC_PATH",
        tmp_path / "no-such-file",
    )
    settings = Settings(environment="test")
    assert settings.environment == "test"
    assert settings.environment_load_result is None
