"""Stale + liveness behaviour for the daemon PID file (#174)."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from alfred.cli.daemon._daemon_pidfile import (
    default_pidfile_path,
    delete_pidfile,
    is_pid_alive,
    load_pidfile,
    write_pidfile,
)


@pytest.mark.skipif(
    sys.platform == "win32", reason="POSIX-only: os.O_NOFOLLOW (symlink-safe pidfile open)"
)
def test_stale_pid_detected(tmp_path: Path) -> None:
    pf = tmp_path / "daemon.pid"
    dead_pid = 999_999
    write_pidfile(path=pf, pid=dead_pid, boot_id="x", started_at="now")
    info = load_pidfile(pf)
    assert info.pid == dead_pid
    assert is_pid_alive(dead_pid) is False


def test_live_pid_detected() -> None:
    """Our own PID is alive."""
    assert is_pid_alive(os.getpid()) is True


def test_is_pid_alive_permission_error_counts_as_alive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A PermissionError from kill(pid, 0) means the process exists (alive)."""

    def _raise_permission(_pid: int, _sig: int) -> None:
        raise PermissionError

    monkeypatch.setattr(os, "kill", _raise_permission)
    assert is_pid_alive(4242) is True


def test_delete_pidfile_missing_is_noop(tmp_path: Path) -> None:
    delete_pidfile(tmp_path / "absent.pid")  # no raise


@pytest.mark.skipif(
    sys.platform == "win32", reason="POSIX-only: os.O_NOFOLLOW (symlink-safe pidfile open)"
)
def test_delete_pidfile_removes(tmp_path: Path) -> None:
    pf = tmp_path / "daemon.pid"
    write_pidfile(path=pf, pid=1, boot_id="x", started_at="now")
    assert pf.exists()
    delete_pidfile(pf)
    assert not pf.exists()


def test_default_pidfile_path_under_home() -> None:
    p = default_pidfile_path()
    assert p.name == "daemon.pid"
    assert "alfred" in str(p)
