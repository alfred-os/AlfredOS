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

# CR #229 R2 finding-6 (must-fix): bound every launcher spawn so a hung
# launcher (e.g. a wedged bwrap or a stuck fd-3 read) fails THIS test fast
# instead of stalling the whole unit job. ``subprocess.run`` kills the child
# on timeout and re-raises ``TimeoutExpired``, which surfaces as a test error.
_LAUNCHER_TIMEOUT_S = 30.0


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
        cwd: Path | None = None,
    ) -> LauncherResult:
        """Invoke the launcher. Pass ``cwd`` to control `.env` resolution.

        #486: the launcher resolves `.env` CWD-relative. Tests asserting an UNRESOLVED
        environment must pass an empty ``cwd`` (typically ``tmp_path``), or a repo-root
        `.env` — which the README instructs operators to create (`cp .env.example .env`,
        shipping `production`) — silently resolves it and the test fails for anyone who
        followed the setup docs. CI never sees it: runners have no `.env`. Default stays
        ``None`` (inherit) because other tests resolve manifests relative to the repo root.
        """
        proc = subprocess.run(  # noqa: S603 — repo-owned launcher script path
            [str(LAUNCHER), *args],
            capture_output=True,
            text=True,
            env=_base_env(env),
            cwd=cwd,
            check=False,
            timeout=_LAUNCHER_TIMEOUT_S,
        )
        return LauncherResult(proc.returncode, proc.stdout, proc.stderr)

    return _run
