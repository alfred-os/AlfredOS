"""Slice-4 smoke: daemon boot + state.git dispatch loop (#174 PR-S4-1).

Closes the #174 acceptance criterion: in deployed AlfredOS, the
merged-proposal dispatch loop must actually run in production. This test
boots the docker compose Postgres + state.git, runs ``alfred daemon
start`` as a subprocess, then commits a dispatchable breaker-reset blob to
``origin/main`` (simulating the reviewer-gate APPROVAL + merge), and polls
the ``audit_log`` for the ``state.proposal.processed`` row the Slice-3
dispatch loop emits when it picks the proposal up — proving the loop fired
(NOT a fixed ``sleep``; core-eng-003). Teardown uses ``alfred daemon stop``
(the new SIGTERM-via-PID-file path), NOT ``docker compose down`` of the
daemon (core-eng-003).

Why a direct commit to ``origin/main`` rather than ``alfred supervisor
reset`` (test-engineer HIGH, PR #222 review): ``supervisor reset`` pushes
an UNMERGED ``proposal/*`` branch, but the dispatch loop scans
``origin/main`` only (``dispatch_loop.py`` ``_resolve_origin_main``) and
nothing auto-merges it — so the observe step could never fire. The dispatch
loop's contract is "process blobs that landed on ``origin/main``", i.e.
proposals the reviewer gate already approved and merged. We simulate that
merged state directly: commit ``policies/breaker-resets/<id>.json`` and
point ``origin/main`` at it, mirroring the Slice-3 integration fixture
(``tests/integration/state/test_dispatch_loop.py``). The blob is committed
AFTER boot so it is NOT swallowed by the bootstrap cycle's baseline (the
first cycle seeds the sentinel to the then-current ``origin/main`` and
processes nothing).

Marked ``@pytest.mark.smoke`` so it only runs when an operator opts in via
``uv run pytest tests/smoke -m smoke``. It is NOT run locally during this
PR's development (no docker); it runs in CI's docker-in-docker runner.
"""

from __future__ import annotations

import json
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
# A 16-lowercase-hex proposal id matching the dispatch loop's
# ``_PROPOSAL_ID_RE`` (``policies/<type>/<id>.json``).
_PROPOSAL_ID = "a1b2c3d4e5f60718"
_PROPOSAL_PATH = f"policies/breaker-resets/{_PROPOSAL_ID}.json"


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
    """End-to-end: alfred daemon start → merge proposal to main → dispatch fires."""
    state_git = tmp_path / "state.git"
    _init_state_git_repo(state_git)

    env = os.environ.copy()
    env["ALFRED_ENVIRONMENT"] = "test"
    env["ALFRED_STATE_GIT_PATH"] = str(state_git)
    env["ALFRED_PROPOSAL_DISPATCH_INTERVAL_S"] = _PROPOSAL_DISPATCH_INTERVAL_S

    # Migrate the audit + dispatch schema into the compose Postgres.
    subprocess.run(["uv", "run", "alfred", "migrate"], env=env, check=True)

    daemon = subprocess.Popen(["uv", "run", "alfred", "daemon", "start"], env=env)
    try:
        _wait_for_boot_completed(env, _BOOT_COMPLETED_TIMEOUT_S)

        # Simulate the reviewer-gate APPROVAL + merge: land a dispatchable
        # breaker-reset blob on origin/main. Committed AFTER boot so the
        # bootstrap cycle's baseline does not already include it.
        _merge_dispatchable_proposal(state_git)

        # Poll the audit_log for the dispatch-loop's processed row rather
        # than sleeping (core-eng-003). The loop interval is 2s.
        _wait_for_proposal_processed(env, _DISPATCH_TIMEOUT_S)
    finally:
        subprocess.run(["uv", "run", "alfred", "daemon", "stop"], env=env, check=False)
        daemon.wait(timeout=10.0)


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True)


def _init_state_git_repo(repo: Path) -> None:
    """Create a state.git repo with a seeded ``origin/main`` ref.

    Mirrors ``tests/integration/state/test_dispatch_loop.py``: a real repo
    with an initial empty commit, and ``refs/remotes/origin/main`` pointed
    at HEAD so the dispatcher's ``git rev-parse origin/main`` resolves on
    the bootstrap cycle.
    """
    subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True)
    _git(repo, "config", "user.email", "smoke@alfred.test")
    _git(repo, "config", "user.name", "alfred-smoke")
    _git(repo, "commit", "--allow-empty", "-m", "init", "-q")
    _git(repo, "update-ref", "refs/remotes/origin/main", "HEAD")


def _merge_dispatchable_proposal(repo: Path) -> None:
    """Commit a breaker-reset blob and advance ``origin/main`` to it.

    The canonical ``BreakerResetProposal`` JSON shape the dispatch loop
    parses (``component_id`` + ``operator_user_id`` + ``reason``). Updating
    ``refs/remotes/origin/main`` is the in-test stand-in for the reviewer
    gate merging the approved proposal to ``main``.
    """
    target = repo / _PROPOSAL_PATH
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(
            {
                "component_id": _COMPONENT,
                "operator_user_id": "smoke-operator",
                "reason": "operator_initiated",
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    _git(repo, "add", _PROPOSAL_PATH)
    _git(repo, "commit", "-m", "merge: approved breaker-reset proposal", "-q")
    _git(repo, "update-ref", "refs/remotes/origin/main", "HEAD")


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
