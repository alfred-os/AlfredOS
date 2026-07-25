"""Unit tests for the shared compose lifecycle helper (tests/_compose.py)."""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest import mock

from tests import _compose


def test_compose_invokes_docker_compose_from_repo_root_with_project() -> None:
    with mock.patch.object(_compose.subprocess, "run") as run:
        run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        _compose.compose("proj-x", "up", "-d", "--no-deps", "alfred-redis")
    args, kwargs = run.call_args
    cmd = args[0]
    assert cmd[:6] == ["docker", "compose", "-f", str(_compose.COMPOSE_FILE), "-p", "proj-x"]
    assert cmd[-4:] == ["up", "-d", "--no-deps", "alfred-redis"]
    assert kwargs["cwd"] == _compose.REPO_ROOT
    assert kwargs["capture_output"] is True and kwargs["text"] is True


def test_compose_threads_env_file_before_the_subcommand(tmp_path: Path) -> None:
    # Use a real tmp Path + compare against ITS own str() so the assertion is platform-correct:
    # `_compose` stringifies the Path, and str(WindowsPath) renders with `\`, not `/` (a hardcoded
    # POSIX literal here false-failed the Windows cross-OS gate).
    env_file = tmp_path / "e2e.env"
    with mock.patch.object(_compose.subprocess, "run") as run:
        run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        _compose.compose("proj-y", "config", env_file=env_file)
    cmd = run.call_args[0][0]
    assert "--env-file" in cmd and cmd[cmd.index("--env-file") + 1] == str(env_file)
    assert cmd.index("--env-file") < cmd.index("config")


def test_down_project_issues_down_v() -> None:
    with mock.patch.object(_compose.subprocess, "run") as run:
        run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        _compose.down_project("proj-w")
    cmd = run.call_args[0][0]
    assert "proj-w" in cmd and cmd[-2:] == ["down", "-v"]


def test_down_project_never_raises_on_subprocess_or_os_error() -> None:
    # Documented never-raises contract, relied on by three teardown paths: a missing docker
    # (FileNotFoundError = OSError) or a hung `down` (TimeoutExpired = SubprocessError) must not
    # escape and mask a test result (CR + test-engineer review).
    for exc in (subprocess.TimeoutExpired(cmd=["docker"], timeout=1), FileNotFoundError("docker")):
        with mock.patch.object(_compose.subprocess, "run", side_effect=exc):
            _compose.down_project("proj-z")  # must not raise
