"""Slice-4 smoke: daemon boot + state.git dispatch loop (#174 PR-S4-1).

Closes the #174 acceptance criterion: in deployed AlfredOS, the
merged-proposal dispatch loop must actually run in production. This test
boots a Postgres testcontainer + a seeded state.git, runs ``alfred daemon
start`` as a subprocess, then commits a dispatchable breaker-reset blob to
``origin/main`` (simulating the reviewer-gate APPROVAL + merge), and polls
the ``audit_log`` for the ``state.proposal.processed`` row the Slice-3
dispatch loop emits when it picks the proposal up — proving the loop fired
(NOT a fixed ``sleep``; core-eng-003). Teardown uses ``alfred daemon stop``
(the SIGTERM-via-PID-file path), NOT a container ``down`` (core-eng-003).

Why a Postgres testcontainer (NOT ``docker compose``)
-----------------------------------------------------
The CI Smoke job has no compose stack — it boots its own Postgres
testcontainer (``.github/workflows/ci.yml``). The earlier compose approach
was wrong on two counts: the service is named ``alfred-postgres`` (not
``alfred-pg``), and there is no stack to ``up`` in CI at all. We mirror the
proven pattern in ``tests/smoke/test_hello_alfred.py``: a
``PostgresContainer("postgres:16")`` context that testcontainers maps to a
random ``localhost`` port. The daemon subprocess runs on the SAME host, so
it reaches the container at that mapped port.

URL scheme
----------
``ALFRED_DATABASE_URL`` must be the **asyncpg** URL. The daemon's boot path
builds its async session scope via ``create_async_engine(database_url)``
(``alfred.memory.db``) for probe (c)'s ``SELECT 1`` handshake, and the
capability-gate ``PostgresBackend`` likewise does ``create_async_engine(dsn)``
— both require an async driver. ``alfred migrate`` runs alembic, whose
``env.py`` uses ``async_engine_from_config`` and reads the same
``Settings().database_url``, so asyncpg is correct there too. The test's own
direct audit-count probe is a short-lived **psycopg2** sync connection
against the default ``pg.get_connection_url()`` (no async driver needed for a
single ``SELECT count(*)``).

Why a direct commit to ``origin/main`` rather than ``alfred supervisor
reset``: ``supervisor reset`` pushes an UNMERGED ``proposal/*`` branch, but
the dispatch loop scans ``origin/main`` only (``dispatch_loop.py``
``_resolve_origin_main``) and nothing auto-merges it — so the observe step
could never fire. The dispatch loop's contract is "process blobs that landed
on ``origin/main``", i.e. proposals the reviewer gate already approved and
merged. We simulate that merged state directly: commit
``policies/breaker-resets/<id>.json`` and point ``origin/main`` at it,
mirroring the Slice-3 integration fixture
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
from pathlib import Path

# psycopg2 + testcontainers ship no type stubs / py.typed marker; the
# import-untyped ignore keeps `mypy --strict` green on this smoke file
# without a global override (they are dev/test-only deps).
import psycopg2  # type: ignore[import-untyped]
import pytest
from testcontainers.postgres import PostgresContainer  # type: ignore[import-untyped]

_BOOT_COMPLETED_TIMEOUT_S = 20.0
_DISPATCH_TIMEOUT_S = 20.0
_PROPOSAL_DISPATCH_INTERVAL_S = "2"
_COMPONENT = "smoke-noop-component"
# A 16-lowercase-hex proposal id matching the dispatch loop's
# ``_PROPOSAL_ID_RE`` (``policies/<type>/<id>.json``).
_PROPOSAL_ID = "a1b2c3d4e5f60718"
_PROPOSAL_PATH = f"policies/breaker-resets/{_PROPOSAL_ID}.json"


@pytest.mark.smoke
def test_daemon_boots_and_dispatches(tmp_path: Path) -> None:
    """End-to-end: alfred daemon start → merge proposal to main → dispatch fires."""
    with PostgresContainer("postgres:16") as pg:
        # testcontainers returns a psycopg2 URL by default; the daemon +
        # alfred migrate need the asyncpg async-driver URL (see module
        # docstring). The direct audit-count probe keeps the psycopg2 URL.
        sync_url = pg.get_connection_url()
        async_url = sync_url.replace("psycopg2", "asyncpg")

        state_git = tmp_path / "state.git"
        _init_state_git_repo(state_git)

        env = os.environ.copy()
        env["ALFRED_ENVIRONMENT"] = "test"
        env["ALFRED_STATE_GIT_PATH"] = str(state_git)
        env["ALFRED_DATABASE_URL"] = async_url
        env["ALFRED_PROPOSAL_DISPATCH_INTERVAL_S"] = _PROPOSAL_DISPATCH_INTERVAL_S

        # Migrate the audit + dispatch schema into the testcontainer Postgres.
        # alembic/env.py reads Settings().database_url (the asyncpg URL above).
        subprocess.run(["uv", "run", "alfred", "migrate"], env=env, check=True)

        daemon = subprocess.Popen(["uv", "run", "alfred", "daemon", "start"], env=env)
        try:
            _wait_for_boot_completed(sync_url, _BOOT_COMPLETED_TIMEOUT_S)

            # Simulate the reviewer-gate APPROVAL + merge: land a dispatchable
            # breaker-reset blob on origin/main. Committed AFTER boot so the
            # bootstrap cycle's baseline does not already include it.
            _merge_dispatchable_proposal(state_git)

            # Poll the audit_log for the dispatch-loop's processed row rather
            # than sleeping (core-eng-003). The loop interval is 2s.
            _wait_for_proposal_processed(sync_url, _DISPATCH_TIMEOUT_S)
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


def _count_audit_rows(sync_url: str, event: str) -> int:
    """Return the audit_log row count for ``event`` via a direct SQL probe.

    A short-lived psycopg2 connection straight at the testcontainer Postgres
    (no docker exec, no async engine). The query is parametrised, so ``event``
    is never string-interpolated into SQL. Any connection error (e.g. before
    the schema exists) is treated as zero rows so the caller keeps polling.
    """
    try:
        conn = psycopg2.connect(sync_url)
    except psycopg2.Error:
        return 0
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT count(*) FROM audit_log WHERE event = %s;", (event,))
            row = cur.fetchone()
            return int(row[0]) if row is not None else 0
    except psycopg2.Error:
        return 0
    finally:
        conn.close()


def _wait_for_boot_completed(sync_url: str, timeout_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if _count_audit_rows(sync_url, "daemon.boot.completed") >= 1:
            return
        time.sleep(0.5)
    raise TimeoutError("daemon.boot.completed audit row never landed")


def _wait_for_proposal_processed(sync_url: str, timeout_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if _count_audit_rows(sync_url, "state.proposal.processed") >= 1:
            return
        time.sleep(0.5)
    raise TimeoutError(
        "state.proposal.processed audit row never landed — the dispatch loop "
        "did not fire in production (issue #174 not closed)"
    )
