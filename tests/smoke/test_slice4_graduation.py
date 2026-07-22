"""Slice-4 graduation smoke — compose-up + login + round-trip (#206).

This is the slice-graduation smoke PR-S4-11 references (ops-006). It runs against
a clean ``docker compose`` deployment — Postgres + Redis + the ``alfred-core``
daemon — and proves the *deployed* shape an operator gets after running the
setup script, not just an in-process or testcontainer fixture:

  1. ``docker compose up -d --wait`` brings the stack healthy (or the test
     skips cleanly when docker / the daemon image is unavailable).
  2. ``alfred login`` against the seeded operator inside the ``alfred-core``
     container creates the operator session (#153 — the session file at
     ``~/.config/alfred/session``).
  3. A deterministic dispatch round-trip fires through the deployed daemon: a
     merged-proposal blob lands on ``state.git`` ``origin/main`` and the daemon's
     dispatch loop processes it (the ``state.proposal.processed`` audit row),
     proving the end-to-end ``compose -> daemon -> dispatch`` path is live in the
     real deployment.

Why the dispatch round-trip rather than ``alfred chat``: ``alfred chat`` launches
the Textual TUI and requires a PTY, so it cannot be driven non-interactively in a
headless CI runner. The operator chat round-trip against the launcher-spawned TUI
plugin is proven deterministically by ``tests/integration/test_tui_round_trip.py``
+ ``tests/smoke/test_tui_e2e.py``; this graduation smoke proves the *deployment*
(compose-up + login + a live daemon dispatch) that those plugin-level gates
assume. Together they close the full Slice-4 surface.

Runtime budget: 120s soft (warns) / 240s hard (fails) — perf-007. Building the
``alfred-core`` image + booting the stack dominates, so this test is **opt-in**:
it skips unless ``ALFRED_RUN_GRADUATION_SMOKE=1`` is set (CI's graduation job
sets it; a bare ``uv run pytest tests/smoke`` skips it cleanly). It also skips
when docker is absent, so it never *errors* on an unconfigured box.
"""

from __future__ import annotations

import json
import os
import secrets
import subprocess
import time
import uuid
import warnings
from collections.abc import Iterator

import pytest

from tests._docker_probe import docker_available

pytestmark = pytest.mark.smoke

# Soft budget — a UserWarning is emitted if the round-trip exceeds it.
# Hard budget — the test fails if the round-trip exceeds it.
SOFT_BUDGET_SECONDS = 120.0
HARD_BUDGET_SECONDS = 240.0

_OPT_IN_ENV = "ALFRED_RUN_GRADUATION_SMOKE"
_CORE_SERVICE = "alfred-core"
_DISPATCH_TIMEOUT_S = 40.0
_POLL_INTERVAL_S = 1.0

# A 16-lowercase-hex proposal id matching the dispatch loop's id regex
# (``policies/<type>/<id>.json``), mirroring test_slice4_daemon_dispatch.
_PROPOSAL_ID = "a1b2c3d4e5f60718"
_PROPOSAL_PATH = f"policies/breaker-resets/{_PROPOSAL_ID}.json"
_STATE_GIT_IN_CONTAINER = "/var/lib/alfred/state.git"


@pytest.fixture(scope="module")
def compose_stack() -> Iterator[None]:
    """Bring up docker compose for the module; tear it down (volumes) after."""
    if os.environ.get(_OPT_IN_ENV) != "1":
        pytest.skip(f"{_OPT_IN_ENV} != 1 — graduation smoke is opt-in (builds images)")
    if not docker_available():
        pytest.skip("docker unavailable — graduation smoke skipped cleanly")

    # #470: alfred-grafana's compose entrypoint fail-closes (exit 78) on an unset/
    # guessable GF_SECURITY_ADMIN_PASSWORD (docker-compose.yaml). Seed a non-guessable
    # value for this subprocess's `docker compose up` so Grafana boots — mirrors what
    # bin/alfred-setup.sh does for an operator.
    env = {**os.environ, "GF_SECURITY_ADMIN_PASSWORD": secrets.token_hex(24)}

    # The `up` call is INSIDE the try so `finally: down -v` still tears down even when
    # `up --wait` raises TimeoutExpired (a crash-looping service that hangs to the budget)
    # after partially creating containers/networks — a leak must not persist across smoke runs.
    try:
        up = subprocess.run(
            ["docker", "compose", "up", "-d", "--wait"],
            capture_output=True,
            text=True,
            check=False,
            timeout=HARD_BUDGET_SECONDS,
            env=env,
        )
        if up.returncode != 0:
            # docker-unavailable and opt-in-off were already ruled out above, and the
            # Grafana password is now seeded — a non-zero return here is a REAL stack-boot
            # failure, not an environment-unavailability skip. Fail loud (the #245
            # assert-RAN discipline): skipping would false-green the graduation smoke.
            pytest.fail(
                f"docker compose up --wait failed with docker available, "
                f"{_OPT_IN_ENV}=1, and GF_SECURITY_ADMIN_PASSWORD seeded: {up.stderr[-800:]}"
            )
        yield
    finally:
        subprocess.run(
            ["docker", "compose", "down", "-v"],
            capture_output=True,
            check=False,
            timeout=HARD_BUDGET_SECONDS,
        )


def test_compose_up_login_and_daemon_dispatch_round_trip(compose_stack: None) -> None:
    """End-to-end: deployed stack healthy -> alfred login -> daemon dispatch fires."""
    start = time.monotonic()

    # (2) alfred login against the seeded operator inside the deployed core.
    login = _core_exec(
        ["alfred", "login", "--as", os.environ.get("ALFRED_OPERATOR_NAME", "operator")],
        timeout=30,
    )
    assert login.returncode == 0, f"alfred login failed: {login.stderr[-400:]}"

    # (3) deterministic dispatch round-trip through the deployed daemon.
    _merge_dispatchable_proposal_in_container()
    _wait_for_proposal_processed()

    elapsed = time.monotonic() - start
    if elapsed > HARD_BUDGET_SECONDS:  # pragma: no cover - budget breach is a failure
        pytest.fail(f"graduation round-trip exceeded {HARD_BUDGET_SECONDS}s hard budget")
    if elapsed > SOFT_BUDGET_SECONDS:  # pragma: no cover - soft budget is host-dependent
        warnings.warn(
            f"graduation round-trip {elapsed:.0f}s exceeded {SOFT_BUDGET_SECONDS}s soft budget",
            UserWarning,
            stacklevel=2,
        )


# ---------------------------------------------------------------------------
# deployed-stack helpers (exec into the alfred-core container)
# ---------------------------------------------------------------------------


def _core_exec(argv: list[str], *, timeout: float) -> subprocess.CompletedProcess[str]:
    """Run a command inside the deployed ``alfred-core`` container."""
    return subprocess.run(
        ["docker", "compose", "exec", "-T", _CORE_SERVICE, *argv],
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout,
    )


def _merge_dispatchable_proposal_in_container() -> None:
    """Land a dispatchable breaker-reset blob on ``origin/main`` in state.git.

    Mirrors ``test_slice4_daemon_dispatch._merge_dispatchable_proposal`` but runs
    the git plumbing inside the deployed container so the blob lands on the same
    ``state.git`` the daemon's dispatch loop scans. Updating
    ``refs/remotes/origin/main`` is the in-test stand-in for the reviewer gate
    merging the approved proposal.
    """
    blob = json.dumps(
        {
            "component_id": f"graduation-smoke-{uuid.uuid4().hex[:8]}",
            "operator_user_id": "graduation-operator",
            "reason": "operator_initiated",
        },
        indent=2,
        sort_keys=True,
    )
    # A single shell pipeline inside the container: write the blob, commit it,
    # and advance origin/main. The state.git repo + identity were seeded at
    # daemon boot (alfred-setup / state-git-init).
    script = (
        f"set -e; cd {_STATE_GIT_IN_CONTAINER}; "
        f"mkdir -p $(dirname {_PROPOSAL_PATH}); "
        f"cat > {_PROPOSAL_PATH} <<'JSON'\n{blob}\nJSON\n"
        f"git add {_PROPOSAL_PATH}; "
        "git -c user.email=smoke@alfred.test -c user.name=alfred-smoke "
        'commit -q -m "merge: approved breaker-reset proposal"; '
        "git update-ref refs/remotes/origin/main HEAD"
    )
    result = _core_exec(["sh", "-c", script], timeout=30)
    assert result.returncode == 0, f"state.git merge failed: {result.stderr[-400:]}"


_PROCESSED_EVENT = "state.proposal.processed"


def _wait_for_proposal_processed() -> None:
    """Poll the deployed daemon's audit log for the dispatch-loop processed row.

    ``alfred audit log --event <e> --since <w>`` lists the matching rows (the
    real CLI surface — there is no ``--format count`` flag). The event name on a
    non-error, non-empty listing is the signal the loop fired; we look for the
    event token in the rendered output rather than counting lines, so a header or
    trailing blank line does not produce a false positive.
    """
    deadline = time.monotonic() + _DISPATCH_TIMEOUT_S
    while time.monotonic() < deadline:
        listing = _core_exec(
            ["alfred", "audit", "log", "--event", _PROCESSED_EVENT, "--since", "10m"],
            timeout=15,
        )
        if listing.returncode == 0 and _PROCESSED_EVENT in listing.stdout:
            return
        time.sleep(_POLL_INTERVAL_S)
    pytest.fail(
        f"{_PROCESSED_EVENT} never landed — the deployed daemon's dispatch loop "
        "did not fire (Slice-4 graduation not closed)"
    )
