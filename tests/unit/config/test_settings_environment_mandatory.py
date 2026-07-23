"""Verify Settings.environment is mandatory per spec §7.3 (#174 PR-S4-1)."""

from __future__ import annotations

from pathlib import Path

import pytest

from alfred.config.settings import Settings, SettingsError


def test_environment_required(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Settings() with no environment source raises SettingsError per sec-003."""
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-test")
    monkeypatch.delenv("ALFRED_ENVIRONMENT", raising=False)
    # I-1 (final-review): hermetic against a real repo-root .env — see the
    # matching comment in test_probe_environment_not_set.py for why chdir is
    # required, not just the etc-path override.
    monkeypatch.chdir(tmp_path)
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

    Covers the ``mode="wrap"`` ``_resolve_environment`` validator's inject
    branch (``environment`` absent from ``data`` AND the loader resolves a
    value) and its capture of the load result onto the private attribute
    afterwards. ``resolve_environment()`` runs exactly once — inside the
    single wrap validator, before ``handler(data)`` — so
    ``environment_load_result`` reflects the file source from that one read,
    with no ContextVar hand-off needed (#469 Blocker 1 retired the ContextVar
    that the old before/after validator pair used for this).
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


def test_environment_env_var_whitespace_is_normalized(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """CR #7: ``ALFRED_ENVIRONMENT`` with surrounding whitespace still loads.

    pydantic-settings populates the field from the RAW env value; the
    before-validator must strip it so ``"  production  "`` validates as
    ``"production"`` — parity with the file source the loader already
    strips.
    """
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-test")
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "  production  ")
    monkeypatch.setattr(
        "alfred.config._environment_loader._DEFAULT_ETC_PATH",
        tmp_path / "no-such-file",
    )
    settings = Settings()
    assert settings.environment == "production"


def test_explicit_non_str_environment_kwarg_rejected(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A non-str explicit ``environment=`` kwarg is rejected, not silently coerced.

    #469 Blocker 1 migration note: the old ``mode="before"`` validator was
    directly callable, so a prior version of this test invoked
    ``Settings._resolve_environment({"environment": 123})`` in isolation and
    asserted the dict came back untouched (Literal validation would reject it
    later). The ``mode="wrap"`` validator that replaced it has no
    standalone-callable form — ``handler`` only exists mid-construction — so
    this now goes through a real ``Settings()`` construction. Because
    ``settings_customise_sources`` strips ``environment`` out of every
    env/dotenv/secrets source, an explicit non-str kwarg is the ONLY way a
    non-str value can reach the field at all; asserting it fails cleanly
    (rather than being coerced to a string) is the externally-observable
    behavior the old test protected.
    """
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-test")
    monkeypatch.delenv("ALFRED_ENVIRONMENT", raising=False)
    monkeypatch.setattr(
        "alfred.config._environment_loader._DEFAULT_ETC_PATH",
        tmp_path / "no-such-file",
    )
    with pytest.raises(SettingsError):
        Settings(environment=123)  # type: ignore[arg-type]
