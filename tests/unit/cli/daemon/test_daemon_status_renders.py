"""alfred daemon status renders PID + boot info for a live daemon (#174)."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from typer.testing import CliRunner

from alfred.cli.daemon import daemon_app
from alfred.cli.daemon._daemon_pidfile import write_pidfile


def test_status_renders_running_daemon(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pidfile = tmp_path / "daemon.pid"
    write_pidfile(
        pidfile, pid=os.getpid(), boot_id="boot-123", started_at="2026-06-07T00:00:00+00:00"
    )
    monkeypatch.setattr("alfred.cli.daemon._commands.default_pidfile_path", lambda: pidfile)
    result = CliRunner().invoke(daemon_app, ["status"])
    assert result.exit_code == 0
    assert str(os.getpid()) in result.stdout
    assert "boot-123" in result.stdout


def test_status_stale_pidfile(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pidfile = tmp_path / "daemon.pid"
    write_pidfile(pidfile, pid=999_999, boot_id="boot-x", started_at="now")
    monkeypatch.setattr("alfred.cli.daemon._commands.default_pidfile_path", lambda: pidfile)
    result = CliRunner().invoke(daemon_app, ["status"])
    # Status is read-only — a stale pidfile is not an error.
    assert result.exit_code == 0
