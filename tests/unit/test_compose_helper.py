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


def test_compose_threads_env_file_before_the_subcommand() -> None:
    with mock.patch.object(_compose.subprocess, "run") as run:
        run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        _compose.compose("proj-y", "config", env_file=Path("/tmp/e2e.env"))  # noqa: S108 — fixture path, never opened
    cmd = run.call_args[0][0]
    assert "--env-file" in cmd and cmd[cmd.index("--env-file") + 1] == "/tmp/e2e.env"  # noqa: S108 — fixture path, never opened
    assert cmd.index("--env-file") < cmd.index("config")
