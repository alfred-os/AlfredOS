"""Verify the 3-layer `resolve_environment()` resolver per #469 Blocker 1 design.

Precedence: ``ALFRED_ENVIRONMENT`` env var > ``/etc/alfred/environment`` > ``.env``
(ADR-0053). Every test pins an explicit ``dotenv_path`` (usually an unwritten path
under ``tmp_path``) so a developer's real repo-root ``.env`` can never leak a value
into an assertion that isn't specifically exercising the ``.env`` layer.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from alfred.config._environment_loader import (
    EnvironmentLoadResult,
    EnvironmentSource,
    resolve_environment,
)


def _r(tmp_path: Path, **kwargs: object) -> EnvironmentLoadResult:
    """Resolve with both file sources pinned to not-yet-written paths under tmp_path.

    Callers that want a source to actually be SET write to `tmp_path / "etc"` and/or
    `tmp_path / ".env"` before calling; an un-written path reads as absent
    (`FileNotFoundError` -> skip), never a stray value from the real filesystem.
    """
    return resolve_environment(etc_path=tmp_path / "etc", dotenv_path=tmp_path / ".env", **kwargs)  # type: ignore[arg-type]


# --- env var (highest) ---


def test_env_var_wins(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """ALFRED_ENVIRONMENT env var takes precedence over /etc/alfred/environment."""
    etc_file = tmp_path / "environment"
    etc_file.write_text("development\n", encoding="utf-8")
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "production")
    result = resolve_environment(etc_path=etc_file, dotenv_path=tmp_path / ".env")
    assert result == EnvironmentLoadResult(
        value="production",
        source=EnvironmentSource.ENV_VAR,
        conflict=True,
        conflicting_file_value="development",
    )


def test_env_var_trim_whitespace(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """CR #7: the env-var source is stripped the SAME way as the file source.

    Both sources must normalize whitespace identically, so a value like
    ``" production"`` from the env var validates exactly as the bare
    ``"production"`` from the file — otherwise a stray space would
    spuriously fail validation or trigger a phantom source conflict.
    """
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "  production  ")
    result = _r(tmp_path)
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
    result = resolve_environment(etc_path=etc_file, dotenv_path=tmp_path / ".env")
    assert result.value == "production"
    assert result.source is EnvironmentSource.ENV_VAR
    assert result.conflict is False


def test_unrecognised_value(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """A value outside the Literal triple is treated as unset (probe refuses)."""
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "staging")  # not in {dev,prod,test}
    result = _r(tmp_path)
    assert result.value is None
    assert result.source is EnvironmentSource.UNRECOGNISED
    assert result.unrecognised_value == "staging"


def test_blank_env_is_skipped_not_unrecognised(  # core-plan-01
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A blank/whitespace-only env var normalizes to absent, not UNRECOGNISED("")."""
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "")
    (tmp_path / "etc").write_text("production\n", encoding="utf-8")
    result = resolve_environment(etc_path=tmp_path / "etc", dotenv_path=tmp_path / ".env")
    assert (result.value, result.source) == ("production", EnvironmentSource.ETC_FILE)


# --- /etc file (middle) ---


def test_file_fallback(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """When env var unset, /etc/alfred/environment is the fallback."""
    etc_file = tmp_path / "environment"
    etc_file.write_text("production\n", encoding="utf-8")
    monkeypatch.delenv("ALFRED_ENVIRONMENT", raising=False)
    result = resolve_environment(etc_path=etc_file, dotenv_path=tmp_path / ".env")
    assert result == EnvironmentLoadResult(
        value="production",
        source=EnvironmentSource.ETC_FILE,
        conflict=False,
        conflicting_file_value=None,
    )


def test_unrecognised_file_value(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """An unrecognised value in the file (env unset) is echoed as UNRECOGNISED."""
    etc_file = tmp_path / "environment"
    etc_file.write_text("staging\n", encoding="utf-8")
    monkeypatch.delenv("ALFRED_ENVIRONMENT", raising=False)
    result = resolve_environment(etc_path=etc_file, dotenv_path=tmp_path / ".env")
    assert result.value is None
    assert result.source is EnvironmentSource.UNRECOGNISED
    assert result.unrecognised_value == "staging"


def test_file_trim_whitespace(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Trailing newlines + surrounding whitespace are stripped per spec §7.3."""
    etc_file = tmp_path / "environment"
    etc_file.write_text("  test  \n", encoding="utf-8")
    monkeypatch.delenv("ALFRED_ENVIRONMENT", raising=False)
    result = resolve_environment(etc_path=etc_file, dotenv_path=tmp_path / ".env")
    assert result.value == "test"


def test_directory_at_etc_path_is_fail_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A directory at the etc path (IsADirectoryError) is now FAIL-CLOSED (D3/err-01).

    This is a deliberate behavior change from the old dual-source loader (which
    treated an unreadable /etc as merely absent): a present-but-unreadable /etc must
    never silently fall through to a lower source.
    """
    etc_dir = tmp_path / "environment"
    etc_dir.mkdir()
    monkeypatch.delenv("ALFRED_ENVIRONMENT", raising=False)
    result = resolve_environment(etc_path=etc_dir, dotenv_path=tmp_path / ".env")
    assert result.value is None
    assert result.source is EnvironmentSource.UNREADABLE


def test_generic_os_error_at_etc_path_is_fail_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A generic OSError on the /etc read is fail-closed (D3/err-01), not swallowed."""
    boom = tmp_path / "environment"

    def _raise_os_error(*_args: object, **_kwargs: object) -> str:
        raise OSError("disk gone")

    monkeypatch.delenv("ALFRED_ENVIRONMENT", raising=False)
    monkeypatch.setattr(Path, "read_text", _raise_os_error)
    result = resolve_environment(etc_path=boom, dotenv_path=tmp_path / ".env")
    assert result.value is None
    assert result.source is EnvironmentSource.UNREADABLE


def test_unreadable_etc_is_fail_closed(  # err-01
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """PermissionError on a present /etc file is fail-closed, NOT a fall-through to .env."""
    monkeypatch.delenv("ALFRED_ENVIRONMENT", raising=False)

    def _boom(*_a: object, **_k: object) -> str:
        raise PermissionError("perm")

    monkeypatch.setattr("alfred.config._environment_loader.Path.read_text", _boom)
    (tmp_path / ".env").write_text("ALFRED_ENVIRONMENT=development\n", encoding="utf-8")
    result = resolve_environment(etc_path=tmp_path / "etc", dotenv_path=tmp_path / ".env")
    assert result.value is None
    assert result.source is EnvironmentSource.UNREADABLE  # NOT development


def test_etc_typo_short_circuits_over_valid_dotenv(  # [D3]
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A typo'd /etc value short-circuits UNRECOGNISED — a valid .env never wins instead."""
    monkeypatch.delenv("ALFRED_ENVIRONMENT", raising=False)
    (tmp_path / "etc").write_text("staging\n", encoding="utf-8")
    (tmp_path / ".env").write_text("ALFRED_ENVIRONMENT=production\n", encoding="utf-8")
    result = resolve_environment(etc_path=tmp_path / "etc", dotenv_path=tmp_path / ".env")
    assert result.source is EnvironmentSource.UNRECOGNISED
    assert result.unrecognised_value == "staging"


# --- .env (lowest) ---


def test_dotenv_lowest(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """With neither env var nor /etc set, .env is the last-resort gap-fill source."""
    monkeypatch.delenv("ALFRED_ENVIRONMENT", raising=False)
    (tmp_path / ".env").write_text("ALFRED_ENVIRONMENT=production\n", encoding="utf-8")
    result = _r(tmp_path)
    assert result.source is EnvironmentSource.DOTENV
    assert result.value == "production"
    assert result.conflict is False  # .env can never participate in a conflict


def test_consult_dotenv_false_ignores_dotenv(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """consult_dotenv=False (the launcher path) ignores .env entirely — fail-closed."""
    monkeypatch.delenv("ALFRED_ENVIRONMENT", raising=False)
    (tmp_path / ".env").write_text("ALFRED_ENVIRONMENT=development\n", encoding="utf-8")
    result = _r(tmp_path, consult_dotenv=False)
    assert result.value is None
    assert result.source is EnvironmentSource.NONE  # fail-closed, never "development"


def test_non_utf8_dotenv_is_absent_not_crash(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:  # err-02
    """A non-UTF-8 / malformed .env is treated as absent, never a raw crash."""
    monkeypatch.delenv("ALFRED_ENVIRONMENT", raising=False)

    def _boom(*_a: object, **_k: object) -> None:
        raise UnicodeDecodeError("utf-8", b"", 0, 1, "bad")

    monkeypatch.setattr("alfred.config._environment_loader.dotenv_values", _boom, raising=False)
    result = _r(tmp_path)
    assert result.value is None
    assert result.source is EnvironmentSource.NONE


# --- neither set ---


def test_neither_set(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Neither source set → returns None value (probe converts this to refusal)."""
    monkeypatch.delenv("ALFRED_ENVIRONMENT", raising=False)
    result = _r(tmp_path)
    assert result.value is None
    assert result.source is EnvironmentSource.NONE
