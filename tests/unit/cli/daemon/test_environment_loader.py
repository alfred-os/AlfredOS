"""Verify dual-source loader for Settings.environment per spec §7.3 (#174)."""

from __future__ import annotations

from pathlib import Path

import pytest

from alfred.config._environment_loader import (
    EnvironmentLoadResult,
    EnvironmentSource,
    load_environment,
)


def test_env_var_wins(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """ALFRED_ENVIRONMENT env var takes precedence over /etc/alfred/environment."""
    etc_file = tmp_path / "environment"
    etc_file.write_text("development\n", encoding="utf-8")
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "production")
    result = load_environment(etc_path=etc_file)
    assert result == EnvironmentLoadResult(
        value="production",
        source=EnvironmentSource.ENV_VAR,
        conflict=True,
        conflicting_file_value="development",
    )


def test_file_fallback(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """When env var unset, /etc/alfred/environment is the fallback."""
    etc_file = tmp_path / "environment"
    etc_file.write_text("production\n", encoding="utf-8")
    monkeypatch.delenv("ALFRED_ENVIRONMENT", raising=False)
    result = load_environment(etc_path=etc_file)
    assert result == EnvironmentLoadResult(
        value="production",
        source=EnvironmentSource.ETC_FILE,
        conflict=False,
        conflicting_file_value=None,
    )


def test_neither_set(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Neither source set → returns None value (probe converts this to refusal)."""
    monkeypatch.delenv("ALFRED_ENVIRONMENT", raising=False)
    missing = tmp_path / "does-not-exist"
    result = load_environment(etc_path=missing)
    assert result.value is None
    assert result.source is EnvironmentSource.NONE


def test_unrecognised_value(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """A value outside the Literal triple is treated as unset (probe refuses)."""
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "staging")  # not in {dev,prod,test}
    result = load_environment(etc_path=tmp_path / "absent")
    assert result.value is None
    assert result.source is EnvironmentSource.UNRECOGNISED
    assert result.unrecognised_value == "staging"


def test_unrecognised_file_value(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """An unrecognised value in the file (env unset) is echoed as UNRECOGNISED."""
    etc_file = tmp_path / "environment"
    etc_file.write_text("staging\n", encoding="utf-8")
    monkeypatch.delenv("ALFRED_ENVIRONMENT", raising=False)
    result = load_environment(etc_path=etc_file)
    assert result.value is None
    assert result.source is EnvironmentSource.UNRECOGNISED
    assert result.unrecognised_value == "staging"


def test_file_unreadable_is_treated_as_absent(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A directory at the etc path (IsADirectoryError) is treated as no file."""
    etc_dir = tmp_path / "environment"
    etc_dir.mkdir()
    monkeypatch.delenv("ALFRED_ENVIRONMENT", raising=False)
    result = load_environment(etc_path=etc_dir)
    assert result.value is None
    assert result.source is EnvironmentSource.NONE


def test_file_os_error_is_treated_as_absent(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A generic OSError on read is swallowed and treated as no file."""
    boom = tmp_path / "environment"

    def _raise_os_error(*_args: object, **_kwargs: object) -> str:
        raise OSError("disk gone")

    monkeypatch.delenv("ALFRED_ENVIRONMENT", raising=False)
    monkeypatch.setattr(Path, "read_text", _raise_os_error)
    result = load_environment(etc_path=boom)
    assert result.value is None
    assert result.source is EnvironmentSource.NONE


def test_file_trim_whitespace(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Trailing newlines + surrounding whitespace are stripped per spec §7.3."""
    etc_file = tmp_path / "environment"
    etc_file.write_text("  test  \n", encoding="utf-8")
    monkeypatch.delenv("ALFRED_ENVIRONMENT", raising=False)
    result = load_environment(etc_path=etc_file)
    assert result.value == "test"


def test_env_var_trim_whitespace(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """CR #7: the env-var source is stripped the SAME way as the file source.

    Both sources must normalize whitespace identically, so a value like
    ``" production"`` from the env var validates exactly as the bare
    ``"production"`` from the file — otherwise a stray space would
    spuriously fail validation or trigger a phantom source conflict.
    """
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "  production  ")
    result = load_environment(etc_path=tmp_path / "absent")
    assert result.value == "production"
    assert result.source is EnvironmentSource.ENV_VAR


def test_whitespace_parity_no_phantom_conflict(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """CR #7: whitespace differences alone must not register as a conflict.

    Env var ``"  production  "`` and file ``"production\\n"`` are the SAME
    value once normalized — no ``daemon.boot.environment_source_conflict``
    may be reported for a whitespace-only difference.
    """
    etc_file = tmp_path / "environment"
    etc_file.write_text("production\n", encoding="utf-8")
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "  production  ")
    result = load_environment(etc_path=etc_file)
    assert result.value == "production"
    assert result.source is EnvironmentSource.ENV_VAR
    assert result.conflict is False
