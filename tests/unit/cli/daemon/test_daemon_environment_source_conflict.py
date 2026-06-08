"""env-var + file disagree → source-conflict audit row; env-var wins (#174)."""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from alfred.cli.daemon import daemon_app

from .conftest import FakeAuditWriter


def test_conflict_emits_audit_and_boots(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    boot_success_env: FakeAuditWriter,
) -> None:
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "production")
    etc = tmp_path / "environment"
    etc.write_text("development\n", encoding="utf-8")
    monkeypatch.setattr("alfred.config._environment_loader._DEFAULT_ETC_PATH", etc)

    runner = CliRunner()
    result = runner.invoke(daemon_app, ["start"])
    assert result.exit_code == 0

    conflict_rows = boot_success_env.rows_for("DAEMON_BOOT_ENVIRONMENT_SOURCE_CONFLICT_FIELDS")
    assert len(conflict_rows) == 1
    subject = conflict_rows[0]["subject"]
    assert subject["env_var_value"] == "production"
    assert subject["etc_file_value"] == "development"
    assert subject["resolved_value"] == "production"

    # The daemon still boots with the env-var value winning.
    boot_rows = boot_success_env.rows_for("DAEMON_BOOT_FIELDS")
    assert len(boot_rows) == 1
    assert boot_rows[0]["subject"]["environment"] == "production"


def test_no_conflict_emits_no_conflict_row(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    boot_success_env: FakeAuditWriter,
) -> None:
    """No file present → env var is the sole source → no conflict row."""
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    runner = CliRunner()
    result = runner.invoke(daemon_app, ["start"])
    assert result.exit_code == 0
    assert not boot_success_env.rows_for("DAEMON_BOOT_ENVIRONMENT_SOURCE_CONFLICT_FIELDS")
