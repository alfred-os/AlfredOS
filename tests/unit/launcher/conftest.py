"""Shared harness for the bash-launcher unit tests (PR-S4-6 Component G).

The launcher (``bin/alfred-plugin-launcher.sh``) runs as a subprocess. These
fixtures build the env it needs (PYTHONPATH so the embedded
``manifest_reader`` resolves; a fake ``bwrap`` that echoes its args so the
``kind: full`` branch can be observed without a real sandbox) and a callable
that invokes the launcher with controlled inputs.
"""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
LAUNCHER = REPO_ROOT / "bin" / "alfred-plugin-launcher.sh"


@dataclass(frozen=True)
class LauncherResult:
    """The outcome of one launcher invocation."""

    returncode: int
    stdout: str
    stderr: str


def _base_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "PYTHONPATH": str(REPO_ROOT / "src"),
    }
    if extra:
        env.update(extra)
    return env


@pytest.fixture
def echo_bwrap(tmp_path: Path) -> Path:
    """A fake ``bwrap`` on PATH that prints its args (prefixed) and exits 0."""
    fake = tmp_path / "echo-bwrap.sh"
    fake.write_text('#!/bin/sh\nprintf "BWRAP_ARGS: %s\\n" "$*"\nexit 0\n')
    fake.chmod(0o755)
    return fake


@pytest.fixture
def run_launcher(tmp_path: Path):
    """Return a callable that invokes the launcher with controlled env/args."""

    def _run(
        *args: str,
        env: dict[str, str] | None = None,
    ) -> LauncherResult:
        proc = subprocess.run(  # noqa: S603 — repo-owned launcher script path
            [str(LAUNCHER), *args],
            capture_output=True,
            text=True,
            env=_base_env(env),
            check=False,
        )
        return LauncherResult(proc.returncode, proc.stdout, proc.stderr)

    return _run
