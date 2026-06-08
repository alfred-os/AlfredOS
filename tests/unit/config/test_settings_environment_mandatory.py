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


def test_environment_injected_from_etc_file_source(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """No env var but /etc file set → loader injects the value into the field.

    Covers the before-validator inject branch (``environment`` absent from
    data AND the loader resolves a value) and the after-validator capture of
    the single load result (source=etc_file). The ContextVar threads the one
    load result through so ``environment_load_result`` reflects the file
    source without a second disk read (#174 TOCTOU fix).
    """
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-test")
    monkeypatch.delenv("ALFRED_ENVIRONMENT", raising=False)
    etc = tmp_path / "environment"
    etc.write_text("development\n", encoding="utf-8")
    monkeypatch.setattr("alfred.config._environment_loader._DEFAULT_ETC_PATH", etc)

    settings = Settings()
    assert settings.environment == "development"
    result = settings.environment_load_result
    assert result is not None
    assert result.value == "development"
    assert result.source.value == "etc_file"


def test_resolve_environment_passthrough_on_non_dict() -> None:
    """The before-validator returns non-dict input untouched (defensive arm).

    Pydantic normally hands the validator a dict, but the ``not
    isinstance(data, dict)`` guard must pass anything else through unchanged
    rather than crash. Calling the validator directly exercises that arm.
    """
    sentinel = object()
    assert Settings._resolve_environment(sentinel) is sentinel
