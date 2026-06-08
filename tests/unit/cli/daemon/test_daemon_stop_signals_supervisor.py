"""alfred daemon stop reads PID file, sends SIGTERM (#174)."""

from __future__ import annotations

import os
import signal
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from alfred.cli.daemon import daemon_app
from alfred.cli.daemon._daemon_pidfile import write_pidfile


def test_stop_sends_sigterm_to_pid(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pidfile = tmp_path / "daemon.pid"
    write_pidfile(pidfile, pid=os.getpid(), boot_id="b", started_at="now")
    monkeypatch.setattr("alfred.cli.daemon._commands.default_pidfile_path", lambda: pidfile)
    with patch("os.kill") as mock_kill:
        result = CliRunner().invoke(daemon_app, ["stop"])
        assert result.exit_code == 0
        # is_pid_alive uses kill(pid, 0); the SIGTERM is the final call.
        mock_kill.assert_any_call(os.getpid(), signal.SIGTERM)


def test_stop_no_pidfile_exits_zero(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "alfred.cli.daemon._commands.default_pidfile_path",
        lambda: tmp_path / "no-pid",
    )
    result = CliRunner().invoke(daemon_app, ["stop"])
    # Operator-safe: no daemon to stop is success, not error.
    assert result.exit_code == 0


def test_stop_stale_pidfile_is_noop_exit_zero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pidfile = tmp_path / "daemon.pid"
    write_pidfile(pidfile, pid=999_999, boot_id="b", started_at="now")
    monkeypatch.setattr("alfred.cli.daemon._commands.default_pidfile_path", lambda: pidfile)
    result = CliRunner().invoke(daemon_app, ["stop"])
    assert result.exit_code == 0


def test_stop_handles_process_vanishing_between_check_and_kill(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A race where the process dies after is_pid_alive but before SIGTERM."""
    pidfile = tmp_path / "daemon.pid"
    write_pidfile(pidfile, pid=os.getpid(), boot_id="b", started_at="now")
    monkeypatch.setattr("alfred.cli.daemon._commands.default_pidfile_path", lambda: pidfile)

    real_kill = os.kill

    def _kill(pid: int, sig: int) -> None:
        if sig == signal.SIGTERM:
            raise ProcessLookupError
        return real_kill(pid, sig)  # liveness probe kill(pid, 0) succeeds

    monkeypatch.setattr(os, "kill", _kill)
    result = CliRunner().invoke(daemon_app, ["stop"])
    assert result.exit_code == 0
