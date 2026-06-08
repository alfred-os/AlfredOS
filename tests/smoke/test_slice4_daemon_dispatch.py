"""Slice-4 smoke: daemon boot + state.git dispatch loop (#174 PR-S4-1).

Closes the #174 acceptance criterion: in deployed AlfredOS, the
merged-proposal dispatch loop must actually run in production. This test
boots the docker compose Postgres + state.git, runs ``alfred daemon
start`` as a subprocess, queues a breaker-reset proposal into state.git via
the operator CLI, and polls the ``audit_log`` for the
``state.proposal.processed`` row the Slice-3 dispatch loop emits when it
picks the proposal up — proving the loop fired (NOT a fixed ``sleep``;
core-eng-003). Teardown uses ``alfred daemon stop`` (the new SIGTERM-via-
PID-file path), NOT ``docker compose down`` of the daemon (core-eng-003).

Marked ``@pytest.mark.smoke`` so it only runs when an operator opts in via
``uv run pytest tests/smoke -m smoke``. It is NOT run locally during this
PR's development (no docker); it runs in CI's docker-in-docker runner.
"""

from __future__ import annotations

import os
import subprocess
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

_POSTGRES_READY_TIMEOUT_S = 30.0
_BOOT_COMPLETED_TIMEOUT_S = 20.0
_DISPATCH_TIMEOUT_S = 20.0
_PROPOSAL_DISPATCH_INTERVAL_S = "2"
_COMPONENT = "smoke-noop-component"


@pytest.fixture
def _compose_postgres() -> Iterator[None]:
    """Bring up the alfred-pg compose service and tear it down after."""
    subprocess.run(["docker", "compose", "up", "-d", "alfred-pg"], check=True)
    try:
        _wait_for_postgres_ready(_POSTGRES_READY_TIMEOUT_S)
        yield
    finally:
        subprocess.run(["docker", "compose", "down"], check=False)


@pytest.mark.smoke
@pytest.mark.skipif(
    not Path("docker-compose.yaml").exists(),
    reason="smoke requires docker-compose.yaml present",
)
def test_daemon_boots_and_dispatches(_compose_postgres: None, tmp_path: Path) -> None:
    """End-to-end: alfred daemon start → mutate state.git → dispatch fires."""
    state_git = tmp_path / "state.git"
    subprocess.run(["git", "init", "--bare", str(state_git)], check=True)

    env = os.environ.copy()
    env["ALFRED_ENVIRONMENT"] = "test"
    env["ALFRED_STATE_GIT_PATH"] = str(state_git)
    env["ALFRED_PROPOSAL_DISPATCH_INTERVAL_S"] = _PROPOSAL_DISPATCH_INTERVAL_S

    # Migrate the audit + dispatch schema into the compose Postgres.
    subprocess.run(["uv", "run", "alfred", "migrate"], env=env, check=True)

    daemon = subprocess.Popen(["uv", "run", "alfred", "daemon", "start"], env=env)
    try:
        _wait_for_boot_completed(env, _BOOT_COMPLETED_TIMEOUT_S)

        # Queue a breaker-reset proposal into state.git via the operator CLI.
        subprocess.run(
            ["uv", "run", "alfred", "supervisor", "reset", _COMPONENT, "--confirm"],
            env=env,
            check=True,
        )

        # Poll the audit_log for the dispatch-loop's processed row rather
        # than sleeping (core-eng-003). The loop interval is 2s.
        _wait_for_proposal_processed(env, _DISPATCH_TIMEOUT_S)
    finally:
        subprocess.run(["uv", "run", "alfred", "daemon", "stop"], env=env, check=False)
        daemon.wait(timeout=10.0)


def _wait_for_postgres_ready(timeout_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        result = subprocess.run(
            ["docker", "compose", "exec", "-T", "alfred-pg", "pg_isready", "-U", "alfred"],
            capture_output=True,
            check=False,
        )
        if result.returncode == 0:
            return
        time.sleep(1.0)
    raise TimeoutError("alfred-pg never became ready")


def _count_audit_rows(env: dict[str, str], event: str) -> int:
    """Return the audit_log row count for ``event`` via a SQL probe."""
    sql = f"SELECT count(*) FROM audit_log WHERE event = '{event}';"
    result = subprocess.run(
        ["docker", "compose", "exec", "-T", "alfred-pg", "psql", "-U", "alfred", "-tAc", sql],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    if result.returncode != 0:
        return 0
    try:
        return int(result.stdout.strip() or "0")
    except ValueError:
        return 0


def _wait_for_boot_completed(env: dict[str, str], timeout_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if _count_audit_rows(env, "daemon.boot.completed") >= 1:
            return
        time.sleep(0.5)
    raise TimeoutError("daemon.boot.completed audit row never landed")


def _wait_for_proposal_processed(env: dict[str, str], timeout_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if _count_audit_rows(env, "state.proposal.processed") >= 1:
            return
        time.sleep(0.5)
    raise TimeoutError(
        "state.proposal.processed audit row never landed — the dispatch loop "
        "did not fire in production (issue #174 not closed)"
    )
