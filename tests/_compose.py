"""Shared, isolated ``docker compose`` lifecycle helper for the test suite.

Extracted from the module-private copy in
``tests/smoke/test_gateway_core_link_smoke.py`` so the e2e harness (#494) and
the smoke tests share one seam (review rev-002/003). The seccomp ``security_opt``
path in docker-compose.yaml is resolved RELATIVE TO THE INVOCATION CWD, so every
call runs from ``REPO_ROOT``.
"""

from __future__ import annotations

import contextlib

# Self-aliased so ``mypy --strict`` (which implies --no-implicit-reexport) treats
# ``subprocess`` as an intentionally exported attribute of this module — tests patch
# ``_compose.subprocess.run`` directly rather than importing the stdlib module themselves.
import subprocess as subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
COMPOSE_FILE = REPO_ROOT / "docker-compose.yaml"


def compose(
    project: str,
    *args: str,
    env_file: Path | None = None,
    check: bool = True,
    timeout_s: float = 180.0,
) -> subprocess.CompletedProcess[str]:
    """Run ``docker compose -f <file> -p <project> [--env-file <f>] <args>`` from the repo root."""
    cmd = ["docker", "compose", "-f", str(COMPOSE_FILE), "-p", project]
    if env_file is not None:
        cmd += ["--env-file", str(env_file)]
    cmd += list(args)
    return subprocess.run(
        cmd,
        cwd=REPO_ROOT,
        check=check,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="surrogateescape",
        timeout=timeout_s,
    )


def down_project(project: str, *, timeout_s: float = 90.0) -> None:
    """Tear down a throwaway project + its named volumes (idempotent; never raises).

    Best-effort: a hung/failed ``down`` (e.g. a wedged daemon → ``TimeoutExpired``) must not
    mask a test result, so its own ``SubprocessError`` is swallowed.
    """
    # OSError too: a missing/uncallable `docker` raises FileNotFoundError (an OSError, NOT a
    # SubprocessError), and teardown must honour its documented never-raises guarantee.
    with contextlib.suppress(OSError, subprocess.SubprocessError):
        compose(project, "down", "-v", check=False, timeout_s=timeout_s)
