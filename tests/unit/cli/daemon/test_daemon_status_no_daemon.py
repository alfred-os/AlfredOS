"""alfred daemon status with no PID file prints not-running, exits 0 (#174)."""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from alfred.cli.daemon import daemon_app


def test_status_no_pidfile(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "alfred.cli.daemon._commands.default_pidfile_path",
        lambda: tmp_path / "no-pid",
    )
    result = CliRunner().invoke(daemon_app, ["status"])
    # Status is read-only — no daemon is not an error.
    assert result.exit_code == 0
    assert "not running" in result.stdout.lower() or "daemon.status.not_running" in result.stdout
