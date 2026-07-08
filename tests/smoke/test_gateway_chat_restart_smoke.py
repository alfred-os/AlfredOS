"""LIVE-STACK smoke: ``alfred chat`` -> ``alfred gateway`` -> ``alfred daemon`` survives a
daemon restart and paints the reconnecting banner (Spec A G5 / #237).

This is the live-CLI COMPLEMENT to the release-blocking deterministic proof in
``tests/integration/test_gateway_restart_survival.py``. That integration test holds the
core as a controllable fake and asserts the EXACT ``[link.reconnecting, link.restored]``
sequence + the un-acked-input resume — it is the actual G5 gate and it blocks merge.

THIS smoke is a coarse end-to-end sanity check over the REAL three-process stack an
operator runs:

  1. ``alfred daemon start``   — the real core (socket-carrier ``comms-tui.sock``);
  2. ``alfred gateway start``  — dials the daemon core, binds ``comms-gateway.sock``,
                                 HOLDS the one client connection across core restarts;
  3. ``alfred chat`` over a PTY — dials the gateway socket, co-hosts the Textual TUI.

It then RESTARTS the daemon (``alfred daemon stop`` + ``start``, OR a kill+respawn) and
asserts the ``alfred chat`` PTY process SURVIVES (does not exit) and the reconnecting
banner string (``tui.banner.reconnecting`` -> "Reconnecting to Alfred...") appears in the
PTY's screen scrape.

Why this smoke is SKIPPED-pending (nightly stabilization, #237 PR-4)
--------------------------------------------------------------------
A reliable pass needs three things that do not co-exist on a dev mac or the ordinary CI
runner, and which together push a stable green well past a reasonable smoke budget:

* **The daemon refuses to boot without the ADR-0030 provisioning.** Booting with a comms
  adapter / socket-carrier enabled (the leg the gateway dials) drives the PR-S4-11c-2b
  go-live flip, which fail-closed spawns the bwrap-sandboxed quarantined-LLM child at
  boot — requiring ``bwrap`` + Linux + root + ``ALFRED_QUARANTINE_CHILD_PYTHON`` (the
  same gate ``tests/smoke/test_slice4_daemon_comms_spawn.py`` carries). On an
  unprovisioned host the daemon never reaches the steady state the gateway can dial.
* **``alfred chat`` is a full-screen Textual app over a PTY.** Asserting a localized
  banner RENDER (not just a control frame) means scraping the Textual screen buffer out
  of the PTY across an ANSI/redraw stream — timing-sensitive and terminal-dependent. The
  deterministic test pins the banner render against a REAL ``AlfredTuiApp`` under the
  Textual ``run_test`` pilot precisely because that scrape is the flaky part.
* **The daemon restart introduces a real timing gap.** The reconnect backoff, the
  gateway's accept-vs-shutdown race, and the PTY redraw cadence all have to line up
  inside a bounded wait without a deterministic observable to settle on.

Rather than sink unbounded effort or ship a flaky gate, the smoke SHELL (harness + the
asserts) is written and committed, but left ``@pytest.mark.skip`` so it is COLLECTED-BUT-
SKIPPED. The required PR Smoke job (``uv run pytest tests/smoke -v`` in
``.github/workflows/ci.yml``) runs this file but the unconditional ``skip`` marker means
it can NEVER gate merge. The skip names the #237 PR-4 follow-up that owns the nightly
stabilization (provision the ADR-0030 host in the nightly leg + a robust PTY scrape) and
flips the marker on.

To run the shell locally once a provisioned host exists, set
``ALFRED_RUN_NIGHTLY_SMOKE=1`` AND remove the ``skip`` marker — the body then gates
itself on the live-provisioning probes (``_LIVE_STACK_UNAVAILABLE``) and the env flag.
"""

from __future__ import annotations

import getpass
import os
import pty
import select
import shutil
import signal
import subprocess
import time
from collections.abc import Callable
from contextlib import suppress
from pathlib import Path

import pytest

pytestmark = pytest.mark.smoke

# --------------------------------------------------------------------------------------
# Live-provisioning gate (the body's OWN guard once the skip marker is removed).
# --------------------------------------------------------------------------------------
# Mirrors test_slice4_daemon_comms_spawn: the daemon's go-live flip spawns the bwrap
# quarantined child at boot, so the live stack needs bwrap + Linux + root + the ADR-0030
# bound interpreter. os.uname / os.geteuid are absent on Windows; probe behind hasattr so
# COLLECTION stays import-safe on non-Unix.
_HAS_BWRAP = shutil.which("bwrap") is not None
_CHILD_PYTHON = os.environ.get("ALFRED_QUARANTINE_CHILD_PYTHON")
_IS_LINUX_ROOT = (
    hasattr(os, "uname")
    and os.uname().sysname == "Linux"
    and hasattr(os, "geteuid")
    and os.geteuid() == 0
)
# The opt-in flag for the nightly leg. Defaults to OFF so even with the skip marker
# removed, a developer who has not opted in does not pay the live stack.
_NIGHTLY_OPT_IN = os.environ.get("ALFRED_RUN_NIGHTLY_SMOKE") == "1"
_LIVE_STACK_UNAVAILABLE = not (_HAS_BWRAP and _IS_LINUX_ROOT and _CHILD_PYTHON)

# The launcher UID-drop target on a root Linux runner (mirrors the comms-spawn smoke).
_LAUNCHER_TEST_UID = getpass.getuser()

# The localized banner string the reconnecting state paints. Sourced from the gettext
# catalog (locale/en/LC_MESSAGES/alfred.po :: ``tui.banner.reconnecting``). The
# deterministic test asserts the RENDER against AlfredTuiApp; here we scrape the rendered
# text out of the PTY screen buffer.
_RECONNECTING_BANNER = "Reconnecting to Alfred..."

# Timeouts (generous — this is a coarse live smoke, not a tight perf gate).
_BOOT_TIMEOUT_S = 30.0
_GATEWAY_READY_TIMEOUT_S = 20.0
_CHAT_INTERACTIVE_TIMEOUT_S = 20.0
_BANNER_TIMEOUT_S = 30.0
_TEARDOWN_TIMEOUT_S = 15.0


@pytest.mark.skip(
    reason="live restart smoke — tracked for nightly stabilization, #237 PR-4. The "
    "deterministic gate is tests/integration/test_gateway_restart_survival.py. This shell "
    "needs the ADR-0030 provisioned host (bwrap+Linux+root+bound interpreter) AND a robust "
    "Textual-over-PTY banner scrape before it can run green reliably."
)
@pytest.mark.skipif(
    _LIVE_STACK_UNAVAILABLE or not _NIGHTLY_OPT_IN,
    reason="live stack needs ADR-0030 provisioning (bwrap+Linux+root+"
    "ALFRED_QUARANTINE_CHILD_PYTHON) AND ALFRED_RUN_NIGHTLY_SMOKE=1 opt-in.",
)
def test_chat_survives_daemon_restart_and_paints_reconnecting_banner(tmp_path: Path) -> None:
    """chat -> gateway -> daemon: a daemon restart leaves chat alive + paints the banner.

    The coarse live complement to the deterministic G5 proof. Drives the three real
    processes, restarts the daemon, and asserts (a) the ``alfred chat`` PTY process is
    still alive after the restart, and (b) the reconnecting banner string rendered into
    the PTY screen.
    """
    env = _live_stack_env(tmp_path)
    subprocess.run(["uv", "run", "alfred", "migrate"], env=env, check=True)
    # #338 PR2: the daemon's comms boot graph now constructs a REAL Orchestrator,
    # whose constructor synchronously calls identity_resolver.get_operator() at
    # BOOT time — the daemon refuses to come up with zero operator users.
    subprocess.run(
        [
            "uv",
            "run",
            "alfred",
            "user",
            "add",
            "--name",
            "smoke-operator",
            "--authorization",
            "operator",
        ],
        env=env,
        check=True,
    )

    daemon = _spawn(["uv", "run", "alfred", "daemon", "start"], env=env)
    gateway: subprocess.Popen[bytes] | None = None
    chat_pid = -1
    chat_master_fd = -1
    try:
        _wait_for_daemon_socket(env, _BOOT_TIMEOUT_S)

        gateway = _spawn(["uv", "run", "alfred", "gateway", "start"], env=env)
        _wait_for_gateway_socket(env, _GATEWAY_READY_TIMEOUT_S)

        # ``alfred chat`` is a full-screen Textual app — it needs a real TTY, so spawn it
        # under a PTY and scrape its screen buffer (modelled on the PTY harness this file
        # introduces; tests/smoke/test_tui_e2e.py is the placeholder it supersedes).
        chat_pid, chat_master_fd = _spawn_chat_under_pty(env)

        # (1) chat reaches an interactive state: the gateway accepted the dial and the TUI
        # painted SOME chrome (a non-empty screen). A bare prompt/frame is enough — this
        # smoke does not type a turn (the deterministic test owns the turn proof).
        interactive = _scrape_until(
            chat_master_fd, lambda buf: len(buf.strip()) > 0, _CHAT_INTERACTIVE_TIMEOUT_S
        )
        assert interactive, "alfred chat never reached an interactive state through the gateway"
        assert _process_alive(chat_pid), "alfred chat exited before the restart"

        # (2) Restart the daemon. The gateway HOLDS the chat connection across the gap; the
        # core leg drops + re-dials. Stop, wait for the socket to vanish, then start again.
        subprocess.run(["uv", "run", "alfred", "daemon", "stop"], env=env, check=False)
        _wait_for_daemon_process_exit(daemon, _TEARDOWN_TIMEOUT_S)
        # Wait for the OLD socket inode to be unlinked before probing for the new one —
        # otherwise a stale inode makes the post-restart readiness probe vacuous (it would
        # pass on the dead daemon's socket before the new daemon ever binds).
        _wait_for_daemon_socket_gone(env, _TEARDOWN_TIMEOUT_S)
        daemon = _spawn(["uv", "run", "alfred", "daemon", "start"], env=env)
        _wait_for_daemon_socket(env, _BOOT_TIMEOUT_S)

        # (3) chat SURVIVED the restart (the gateway-held connection was not torn) AND the
        # reconnecting banner rendered into the PTY screen during the gap.
        banner_seen = _scrape_until(
            chat_master_fd,
            lambda buf: _RECONNECTING_BANNER in buf,
            _BANNER_TIMEOUT_S,
        )
        assert _process_alive(chat_pid), (
            "alfred chat exited during the daemon restart — the gateway did not hold the "
            "client connection across the core gap (Spec A G5 survival regression)"
        )
        assert banner_seen, (
            f"the reconnecting banner ({_RECONNECTING_BANNER!r}) never rendered in the chat "
            "PTY across the daemon restart"
        )
    finally:
        if chat_pid > 0:
            _reap_pty_child(chat_pid, chat_master_fd)
        if gateway is not None:
            _reap(gateway)
        # Best-effort daemon stop, then reap the process whatever state it is in.
        subprocess.run(["uv", "run", "alfred", "daemon", "stop"], env=env, check=False)
        _reap(daemon)


# --------------------------------------------------------------------------------------
# Live-stack env + state.git seeding (mirrors the comms-spawn smoke).
# --------------------------------------------------------------------------------------


def _live_stack_env(tmp_path: Path) -> dict[str, str]:
    """The operator-shaped environment the three processes share.

    Mirrors ``test_slice4_daemon_comms_spawn``: a seeded ``state.git``, the placeholder
    DeepSeek key, the enabled comms adapter (the socket-carrier leg the gateway dials),
    the launcher UID-drop target, and the ADR-0030 bound interpreter. NOTE: a real live
    run also needs ``ALFRED_DATABASE_URL`` pointed at a Postgres the daemon reaches — the
    nightly leg (#237 PR-4) provisions that (a testcontainer or compose Postgres); this
    shell leaves it to the caller's environment so the harness stays storage-agnostic.
    """
    state_git = tmp_path / "state.git"
    _init_state_git_repo(state_git)

    env = os.environ.copy()
    env["ALFRED_ENVIRONMENT"] = "test"
    env["ALFRED_ENV"] = "test"
    env["ALFRED_DEEPSEEK_API_KEY"] = "not-a-real-key-smoke-placeholder"
    # #338 PR2: the daemon now builds a REAL ProviderRouter inside
    # _build_comms_boot_graph; build_router's EgressClient.from_settings raises
    # IOPlaneUnavailableError fail-closed when this is unset. A dummy value is
    # enough — no live turn is driven by this smoke's restart-survival assertions.
    env["ALFRED_EGRESS_PROXY_URL"] = "http://proxy.invalid:3128"
    env["ALFRED_STATE_GIT_PATH"] = str(state_git)
    # The socket-carrier leg the gateway dials — enabling it drives the daemon's
    # _build_comms_boot_graph (and, post go-live flip, the bwrap quarantine-child spawn).
    env["ALFRED_COMMS_ENABLED_ADAPTERS"] = '["alfred_comms_test"]'
    env["ALFRED_PLUGIN_UID"] = _LAUNCHER_TEST_UID
    if _CHILD_PYTHON:
        env["ALFRED_QUARANTINE_CHILD_PYTHON"] = _CHILD_PYTHON
    return env


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True)


def _init_state_git_repo(repo: Path) -> None:
    """Seed a ``state.git`` with an ``origin/main`` ref (mirrors the comms-spawn smoke)."""
    subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True)
    _git(repo, "config", "user.email", "smoke@alfred.test")
    _git(repo, "config", "user.name", "alfred-smoke")
    _git(repo, "commit", "--allow-empty", "-m", "init", "-q")
    _git(repo, "update-ref", "refs/remotes/origin/main", "HEAD")


# --------------------------------------------------------------------------------------
# Process spawn / reap helpers.
# --------------------------------------------------------------------------------------


def _spawn(argv: list[str], env: dict[str, str]) -> subprocess.Popen[bytes]:
    """Spawn a long-running CLI process (daemon / gateway) detached from this test's TTY."""
    return subprocess.Popen(argv, env=env)


def _reap(proc: subprocess.Popen[bytes]) -> None:
    """SIGTERM then hard-kill a child, always waiting so it is never left a zombie."""
    if proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=_TEARDOWN_TIMEOUT_S)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


def _wait_for_daemon_process_exit(proc: subprocess.Popen[bytes], timeout_s: float) -> None:
    """Wait for the daemon subprocess to exit after ``alfred daemon stop``; hard-kill on wedge."""
    try:
        proc.wait(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


# --------------------------------------------------------------------------------------
# Socket-readiness probes (resolve the daemon / gateway socket paths the live processes
# bind, and poll for presence — never DIAL them, mirroring the non-dialing status probe).
# --------------------------------------------------------------------------------------


def _daemon_socket_path() -> Path:
    """The daemon socket-carrier path (``comms-tui.sock``) the gateway dials."""
    from alfred.plugins.comms_socket_transport import default_comms_socket_path

    return default_comms_socket_path("tui")


def _gateway_socket_path() -> Path:
    """The gateway's client-facing socket path (``comms-gateway.sock``) chat dials."""
    from alfred.gateway.client_listener import _GATEWAY_ADAPTER_ID
    from alfred.plugins.comms_socket_transport import default_comms_socket_path

    return default_comms_socket_path(_GATEWAY_ADAPTER_ID)


def _wait_for_path(path: Path, timeout_s: float, *, what: str) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if path.exists():
            return
        time.sleep(0.25)
    raise TimeoutError(f"{what} socket never appeared at {path} within {timeout_s}s")


def _wait_for_path_gone(path: Path, timeout_s: float, *, what: str) -> None:
    """Poll until ``path`` no longer exists (the old inode is unlinked)."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if not path.exists():
            return
        time.sleep(0.25)
    raise TimeoutError(f"{what} socket still present at {path} after {timeout_s}s")


def _wait_for_daemon_socket(env: dict[str, str], timeout_s: float) -> None:
    _wait_for_path(_daemon_socket_path(), timeout_s, what="daemon socket-carrier")


def _wait_for_daemon_socket_gone(env: dict[str, str], timeout_s: float) -> None:
    _wait_for_path_gone(_daemon_socket_path(), timeout_s, what="daemon socket-carrier")


def _wait_for_gateway_socket(env: dict[str, str], timeout_s: float) -> None:
    _wait_for_path(_gateway_socket_path(), timeout_s, what="gateway client")


# --------------------------------------------------------------------------------------
# PTY harness for the full-screen ``alfred chat`` Textual app.
# --------------------------------------------------------------------------------------


def _spawn_chat_under_pty(env: dict[str, str]) -> tuple[int, int]:
    """Fork ``alfred chat`` under a PTY; return ``(child_pid, master_fd)``.

    ``alfred chat`` is a full-screen Textual app that needs a real controlling TTY (it
    drives the alternate-screen + raw-mode terminal). ``pty.fork`` gives the child its own
    slave PTY as stdin/stdout/stderr; the parent reads the rendered ANSI stream off the
    master fd. ``TERM`` is forced to a known value so Textual's screen output is stable.
    """
    child_env = dict(env)
    child_env["TERM"] = "xterm-256color"
    pid, master_fd = pty.fork()
    if pid == 0:  # child — exec the real CLI; never returns on success
        try:
            os.execvpe("uv", ["uv", "run", "alfred", "chat"], child_env)
        except Exception:
            os._exit(127)
    return pid, master_fd


def _scrape_until(master_fd: int, predicate: Callable[[str], bool], timeout_s: float) -> bool:
    """Read the PTY master until ``predicate(accumulated_text)`` holds or the deadline passes.

    Accumulates the decoded PTY output (best-effort UTF-8, errors replaced — the ANSI/
    redraw stream is noisy) and evaluates ``predicate`` after each readable chunk. Returns
    ``True`` on a match, ``False`` on timeout. The predicate sees the FULL accumulated
    buffer, so a banner string split across read chunks still matches once both arrive.
    """
    buf = ""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        remaining = deadline - time.monotonic()
        readable, _, _ = select.select([master_fd], [], [], min(0.5, max(0.0, remaining)))
        if not readable:
            if predicate(buf):
                return True
            continue
        try:
            chunk = os.read(master_fd, 65536)
        except OSError:
            # The slave side closed (the child exited) — no more output will arrive.
            break
        if not chunk:
            break
        buf += chunk.decode("utf-8", errors="replace")
        if predicate(buf):
            return True
    return predicate(buf)


def _process_alive(pid: int) -> bool:
    """True if ``pid`` is still a live (non-reaped) process — signal 0 probes without killing."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # exists but not ours to signal — still alive
    # Reap any already-exited child so a zombie does not read as alive.
    try:
        waited_pid, _status = os.waitpid(pid, os.WNOHANG)
    except ChildProcessError:
        return True
    return waited_pid == 0


def _reap_pty_child(pid: int, master_fd: int) -> None:
    """Terminate the PTY-forked chat child and close the master fd; always wait for exit."""
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    else:
        deadline = time.monotonic() + _TEARDOWN_TIMEOUT_S
        while time.monotonic() < deadline:
            try:
                waited_pid, _status = os.waitpid(pid, os.WNOHANG)
            except ChildProcessError:
                break
            if waited_pid != 0:
                break
            time.sleep(0.1)
        else:
            try:
                os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)
            except (ProcessLookupError, ChildProcessError):
                pass
    if master_fd >= 0:
        with suppress(OSError):
            os.close(master_fd)
