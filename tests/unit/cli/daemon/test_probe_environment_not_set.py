"""Settings.environment missing → DAEMON_BOOT_FAILED + audit-before-exit (#174).

sec-001 closure: the AuditWriter is constructed BEFORE the environment
check, so the most common misconfig emits a DAEMON_BOOT_FAILED_FIELDS row
then exits 2 — never a silent failure.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from sqlalchemy.exc import OperationalError
from typer.testing import CliRunner

from alfred.cli.daemon import daemon_app
from alfred.i18n import t


def test_environment_not_set_refuses_and_audits(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.delenv("ALFRED_ENVIRONMENT", raising=False)
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-test")
    monkeypatch.setattr(
        "alfred.config._environment_loader._DEFAULT_ETC_PATH",
        tmp_path / "absent",
    )

    appended: list[dict[str, object]] = []

    class _FakeWriter:
        async def append_schema(self, **kw: object) -> None:
            appended.append(kw)

    monkeypatch.setattr(
        "alfred.cli.daemon._commands.build_boot_audit_writer",
        lambda **_kw: _FakeWriter(),
    )

    runner = CliRunner()
    result = runner.invoke(daemon_app, ["start"])
    assert result.exit_code == 2
    # A DAEMON_BOOT_FAILED row was emitted with environment_not_set.
    assert appended, "no audit row emitted before exit (sec-001 violated)"
    subject = appended[0]["subject"]
    assert isinstance(subject, dict)
    assert subject["failure_reason"] == "environment_not_set"


def test_post_env_settings_error_audits_settings_invalid(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A ``SettingsError`` from ``Settings()`` — env value present, so past the
    unset guard — is a DISTINCT failure from an unresolved environment (#469
    Blocker 1 Task 3): some OTHER required field (a secret, a DSN, a numeric
    bound) failed validation, not the environment. Audits ``settings_invalid``
    (exit 2), never a raw traceback and never the environment's own reason.

    Retires the former ``test_settings_error_after_valid_env_refuses`` (#256
    PR-4), which asserted the pre-Task-3 behavior of collapsing this case into
    ``environment_not_set`` — a right-failure/wrong-reason bug this task fixes.
    """
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.chdir(tmp_path)
    # Hermetic: never let a real host /etc/alfred/environment participate —
    # matches every sibling test in this file (resolve_environment reads /etc
    # unconditionally, ahead of the precedence loop, per err-01 fail-closed).
    monkeypatch.setattr(
        "alfred.config._environment_loader._DEFAULT_ETC_PATH",
        tmp_path / "absent",
    )

    appended: list[dict[str, object]] = []

    class _FakeWriter:
        async def append_schema(self, **kw: object) -> None:
            appended.append(kw)

    monkeypatch.setattr(
        "alfred.cli.daemon._commands.build_boot_audit_writer",
        lambda **_kw: _FakeWriter(),
    )

    from alfred.config.settings import SettingsError

    def _raise_settings_error(**_kw: object) -> object:
        raise SettingsError("settings blew up after the env was already validated")

    monkeypatch.setattr("alfred.config.settings.Settings", _raise_settings_error)

    result = CliRunner().invoke(daemon_app, ["start"])
    assert result.exit_code == 2
    assert appended, "no audit row emitted before exit (sec-001 violated)"
    subject = appended[0]["subject"]
    assert isinstance(subject, dict)
    assert subject["failure_reason"] == "settings_invalid"
    assert subject["environment_source"] == "env_var"


def test_environment_source_unreadable_refuses_and_audits(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A present-but-unreadable ``/etc/alfred/environment`` fails CLOSED (err-01).

    Distinct from ``environment_not_set``: the middle-precedence source EXISTED
    but the daemon process could not read it (here: it's a directory, so the
    read raises ``IsADirectoryError``) — never silently falls through to
    ``.env``/unset handling.
    """
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-test")
    monkeypatch.delenv("ALFRED_ENVIRONMENT", raising=False)
    etc_dir = tmp_path / "environment"
    etc_dir.mkdir()
    monkeypatch.setattr(
        "alfred.config._environment_loader._DEFAULT_ETC_PATH",
        etc_dir,
    )

    appended: list[dict[str, object]] = []

    class _FakeWriter:
        async def append_schema(self, **kw: object) -> None:
            appended.append(kw)

    monkeypatch.setattr(
        "alfred.cli.daemon._commands.build_boot_audit_writer",
        lambda **_kw: _FakeWriter(),
    )

    result = CliRunner().invoke(daemon_app, ["start"])
    assert result.exit_code == 2
    assert appended, "no audit row emitted before exit (sec-001 violated)"
    subject = appended[0]["subject"]
    assert isinstance(subject, dict)
    assert subject["failure_reason"] == "environment_source_unreadable"
    assert subject["environment_source"] == "unreadable"


def test_environment_not_set_exits_3_when_audit_unwritable(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """sec-003: an audit-write failure during refusal quarantines with exit 3."""
    monkeypatch.delenv("ALFRED_ENVIRONMENT", raising=False)
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-test")
    monkeypatch.setattr(
        "alfred.config._environment_loader._DEFAULT_ETC_PATH",
        tmp_path / "absent",
    )

    class _BrokenWriter:
        append_schema = AsyncMock(
            side_effect=OperationalError("pg down", None, Exception("refused"))
        )

    monkeypatch.setattr(
        "alfred.cli.daemon._commands.build_boot_audit_writer",
        lambda **_kw: _BrokenWriter(),
    )

    runner = CliRunner()
    result = runner.invoke(daemon_app, ["start"])
    assert result.exit_code == 3


def test_environment_unrecognised_echoes_typo_and_refuses(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """devex-222-01: a typo'd value echoes the typo + the accepted list.

    The operator set ALFRED_ENVIRONMENT to a value that is NOT one of
    development/production/test. The refusal must distinguish this from
    "unset" by echoing what they typed via the
    ``daemon.boot.environment_unrecognised`` message.
    """
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "staging")  # not a valid value
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-test")
    monkeypatch.setattr(
        "alfred.config._environment_loader._DEFAULT_ETC_PATH",
        tmp_path / "absent",
    )

    appended: list[dict[str, object]] = []

    class _FakeWriter:
        async def append_schema(self, **kw: object) -> None:
            appended.append(kw)

    monkeypatch.setattr(
        "alfred.cli.daemon._commands.build_boot_audit_writer",
        lambda **_kw: _FakeWriter(),
    )

    result = CliRunner().invoke(daemon_app, ["start"])
    assert result.exit_code == 2
    # The unrecognised message (with the echoed typo) was printed.
    assert t("daemon.boot.environment_unrecognised", value="staging") in result.output
    assert "staging" in result.output
    # The failed audit row still records the canonical failure_reason.
    subject = appended[0]["subject"]
    assert isinstance(subject, dict)
    assert subject["failure_reason"] == "environment_not_set"
    assert subject["environment_source"] == "unrecognised"
