"""Slice-4 smoke: a real ``alfred daemon start`` actually spawns a comms adapter.

PR-S4-11b end-to-end proof, production-process tier. Test 1
(``tests/integration/cli/daemon/test_daemon_comms_inbound_turn.py``) proves the
in-process turn (inbound -> full trust-boundary path -> T3-promotion row + ack)
against a launcher-spawned plugin. THIS test proves the remaining production link:
that a genuine ``alfred daemon start`` SUBPROCESS — booted exactly as an operator
would boot it, with ``ALFRED_COMMS_ENABLED_ADAPTERS`` set — actually walks its
boot path into ``_spawn_comms_adapter`` and handshakes the ``alfred_comms_test``
plugin through the real launcher. The signal is the ``plugin.lifecycle.loaded``
audit row for the adapter's manifest plugin id, which the session emits ONLY after
the gate check passes post-handshake.

No injection here (the in-process Test 1 owns the inbound-turn proof) — this leg's
job is purely "the daemon process spawns + handshakes the enabled adapter in
production", the link a fakes-patched unit test can never exercise.

The boot path now seeds the adapter's plugin-LOAD grant (ADR-0027: config-is-
authorization for enabled first-party adapters — see
``alfred.security.capability_gate._comms_adapter_grants.comms_adapter_load_grants``)
ALONGSIDE the static ADR-0026 first-party grants, so the post-handshake
``check_plugin_load`` clears and the ``plugin.lifecycle.loaded`` row lands. Before
ADR-0027 this test ``xfail``-ed on the missing load grant; the seed now makes it a
real assertion.

Why a Postgres testcontainer (NOT ``docker compose``)
-----------------------------------------------------
Mirrors ``tests/smoke/test_slice4_daemon_dispatch.py``: the CI Smoke job has no
compose stack, so a ``PostgresContainer("postgres:16")`` is mapped to a random
``localhost`` port the same-host daemon subprocess reaches. The daemon + ``alfred
migrate`` consume the asyncpg URL; the test's direct audit probe is a short-lived
psycopg2 connection.

Launcher-spawn CI posture (honest skip)
---------------------------------------
The reference manifest declares ``sandbox.kind = "none"``. Under
``ALFRED_ENVIRONMENT=test`` the daemon's launcher execs the plugin unsandboxed on
non-Linux dev hosts; a Linux runner UID-drops via ``runuser`` (root-only). Like
the TUI launcher-spawn leg + ``test_comms_runner_substrate.py``, this test
skips on non-root Linux and runs on macOS + the root CI integration runner. It is
``@pytest.mark.smoke`` so it only runs when an operator opts in via
``uv run pytest tests/smoke -m smoke``.
"""

from __future__ import annotations

import getpass
import os
import subprocess
import time
from pathlib import Path

# psycopg2 + testcontainers ship no type stubs / py.typed marker; the
# import-untyped ignore keeps `mypy --strict` green without a global override
# (they are dev/test-only deps).
import psycopg2  # type: ignore[import-untyped]
import pytest
from testcontainers.postgres import PostgresContainer  # type: ignore[import-untyped]

_BOOT_COMPLETED_TIMEOUT_S = 20.0
_ADAPTER_SPAWN_TIMEOUT_S = 30.0

# Teardown wait ceiling for the daemon SUBPROCESS after ``alfred daemon stop``
# (PR-S4-11b O3). Kept STRICTLY ABOVE the supervisor's graceful-drain budget
# (``_STOP_DRAIN_TIMEOUT_SECONDS`` = 10.0s) so this assert fails on a wedged
# shutdown (the DEFECT-1 force-cancel bug, which paid the full 10s) rather than
# on a timing TIE with the budget. With DEFECT 1 fixed the stop is sub-second;
# this ceiling only ever trips if the comms pump regresses and stops observing
# the shutdown signal.
_DAEMON_TEARDOWN_TIMEOUT_S = 15.0

# The adapter the operator enables + the manifest plugin id the
# ``plugin.lifecycle.loaded`` row carries (``[plugin] id`` in
# plugins/alfred_comms_test/manifest.toml — NOT the [comms_mcp] adapter_kind).
_ENABLED_ADAPTER = "alfred_comms_test"
_PLUGIN_ID = "alfred.comms-test"

# The reference plugin's kind="none" launcher UID-drops via ``runuser`` on Linux
# (root-only). Point ``ALFRED_PLUGIN_UID`` at the current user so a root Linux
# runner can UID-drop; the skipif covers the non-root Linux runner.
_LAUNCHER_TEST_UID = getpass.getuser()
_LAUNCHER_REQUIRES_ROOT = os.uname().sysname == "Linux" and os.geteuid() != 0


@pytest.mark.smoke
@pytest.mark.skipif(
    _LAUNCHER_REQUIRES_ROOT,
    reason="kind=none launcher UID-drops via runuser (root-only on Linux); "
    "runs locally + on the root CI integration runner",
)
def test_daemon_start_spawns_enabled_comms_adapter(tmp_path: Path) -> None:
    """End-to-end: alfred daemon start with comms enabled -> adapter loaded row."""
    with PostgresContainer("postgres:16") as pg:
        sa_url = pg.get_connection_url()
        async_url = sa_url.replace("postgresql+psycopg2://", "postgresql+asyncpg://")
        psycopg2_url = sa_url.replace("postgresql+psycopg2://", "postgresql://")

        state_git = tmp_path / "state.git"
        _init_state_git_repo(state_git)

        env = os.environ.copy()
        env["ALFRED_ENVIRONMENT"] = "test"
        # The reference plugin gates inject_inbound on ALFRED_ENV (no injection
        # here, but the launcher child-env allowlist carries it through); set it
        # for parity with the in-process proof's environment.
        env["ALFRED_ENV"] = "test"
        # ALFRED_DEEPSEEK_API_KEY is a REQUIRED Settings field; mirror the dispatch
        # smoke's placeholder so the daemon boots.
        env["ALFRED_DEEPSEEK_API_KEY"] = "not-a-real-secret-smoke-test-placeholder"
        env["ALFRED_STATE_GIT_PATH"] = str(state_git)
        env["ALFRED_DATABASE_URL"] = async_url
        # Opt the comms adapter in — this is the lever that drives the daemon boot
        # path into _build_comms_boot_graph + _spawn_comms_adapter.
        env["ALFRED_COMMS_ENABLED_ADAPTERS"] = f'["{_ENABLED_ADAPTER}"]'
        # The runuser UID-drop target on a root Linux runner.
        env["ALFRED_PLUGIN_UID"] = _LAUNCHER_TEST_UID

        subprocess.run(["uv", "run", "alfred", "migrate"], env=env, check=True)

        daemon = subprocess.Popen(["uv", "run", "alfred", "daemon", "start"], env=env)
        try:
            _wait_for_event(psycopg2_url, "daemon.boot.completed", _BOOT_COMPLETED_TIMEOUT_S)
            # The adapter's plugin.lifecycle.loaded row proves the daemon spawned
            # AND handshook the plugin through the real launcher in production —
            # the row is emitted only after the post-handshake gate check passes.
            _wait_for_adapter_loaded(psycopg2_url, _ADAPTER_SPAWN_TIMEOUT_S)
        finally:
            subprocess.run(["uv", "run", "alfred", "daemon", "stop"], env=env, check=False)
            # DEFECT-1 proof through teardown: the supervised comms pump observes
            # the shutdown signal, so the daemon process exits well under the drain
            # budget. The ceiling is ABOVE the budget so a regression (pump no
            # longer observing shutdown -> full-budget force-cancel) fails the
            # test on behaviour, not a timing tie.
            #
            # FIX 6 (PR-S4-11b review): a wedged daemon makes ``wait`` raise
            # ``TimeoutExpired`` — which, unhandled in a ``finally``, would skip
            # the rest of teardown and LEAK the subprocess, flaking every
            # follow-on smoke run on the same host. Hard-kill + a final ``wait``
            # so the child is always reaped; the ``TimeoutExpired`` then
            # re-raises to fail the test loudly on the regression it signals.
            try:
                daemon.wait(timeout=_DAEMON_TEARDOWN_TIMEOUT_S)
            except subprocess.TimeoutExpired:
                daemon.kill()
                daemon.wait()
                raise


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True)


def _init_state_git_repo(repo: Path) -> None:
    """Create a state.git repo with a seeded ``origin/main`` ref.

    Mirrors ``tests/smoke/test_slice4_daemon_dispatch.py``: a real repo with an
    initial empty commit and ``refs/remotes/origin/main`` at HEAD so the daemon's
    dispatch loop resolves ``origin/main`` on the bootstrap cycle.
    """
    subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True)
    _git(repo, "config", "user.email", "smoke@alfred.test")
    _git(repo, "config", "user.name", "alfred-smoke")
    _git(repo, "commit", "--allow-empty", "-m", "init", "-q")
    _git(repo, "update-ref", "refs/remotes/origin/main", "HEAD")


def _count_event_rows(sync_url: str, event: str) -> int:
    """Return the audit_log row count for ``event`` via a direct SQL probe.

    A short-lived psycopg2 connection straight at the testcontainer Postgres. The
    query is parametrised, so ``event`` is never string-interpolated into SQL. Any
    connection error (e.g. before the schema exists) is treated as zero rows so the
    caller keeps polling.
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


def _count_adapter_loaded_rows(sync_url: str) -> int:
    """Count ``plugin.lifecycle.loaded`` rows for the reference adapter's plugin id.

    Scopes to ``subject->>'plugin_id' = _PLUGIN_ID`` so an unrelated plugin load
    (none expected in this minimal boot, but the scope is the load-bearing signal)
    can never satisfy the poll. Parametrised query — no string interpolation.
    """
    try:
        conn = psycopg2.connect(sync_url)
    except psycopg2.Error:
        return 0
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT count(*) FROM audit_log "
                "WHERE event = 'plugin.lifecycle.loaded' "
                "AND subject->>'plugin_id' = %s;",
                (_PLUGIN_ID,),
            )
            row = cur.fetchone()
            return int(row[0]) if row is not None else 0
    except psycopg2.Error:
        return 0
    finally:
        conn.close()


def _wait_for_event(sync_url: str, event: str, timeout_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if _count_event_rows(sync_url, event) >= 1:
            return
        time.sleep(0.5)
    raise TimeoutError(f"{event} audit row never landed")


def _wait_for_adapter_loaded(sync_url: str, timeout_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if _count_adapter_loaded_rows(sync_url) >= 1:
            return
        time.sleep(0.5)
    raise TimeoutError(
        "plugin.lifecycle.loaded row for the comms adapter never landed — the "
        "daemon did not spawn + handshake the enabled comms plugin in production "
        "(PR-S4-11b daemon comms-spawn unproven end to end)"
    )
