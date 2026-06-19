"""LIVE COMPOSE smoke: the DEPLOYED daemon-core + gateway establish the comms-tui.sock link.

Spec B G6-0b (#288). G6-0b daemon-ifies ``alfred-core`` (``command: ["daemon","start"]`` +
``restart: unless-stopped``) and enables the socket-backed ``alfred_tui`` adapter, so the
always-up ``alfred-gateway`` (G6-0) — previously HEALTHY-but-buffering with no core to dial
— now LINKS to the core over the shared ``alfred_run`` socket volume.

The IN-PROCESS real-link proof already exists and gates merge: the integration test
``tests/integration/cli/daemon/test_chat_gateway_socket_turn.py`` boots the REAL daemon
comms graph + socket carrier and a REAL gateway core-link + relay + cohost, asserting the
gateway core leg reaches and HOLDS ``GatewayLinkState.UP``. THIS smoke proves the *next*
layer — that the **compose deployment** (the daemon-ified core image under the #290 bwrap
profiles + the gateway service, both mounting ``alfred_run``) actually composes the link in
a container, not just in-process. It scrapes the gateway's ``gateway_core_link_up`` gauge
and asserts it reads ``1`` (the link is ESTABLISHED, not merely buffering).

Why this smoke is SKIPPED-pending (nightly stabilization)
---------------------------------------------------------
Same posture as ``tests/smoke/test_gateway_chat_restart_smoke.py``: a reliable green pass
needs an ADR-0030 / #290 provisioned host that does not exist on a dev mac or the ordinary
PR CI runner:

* **The deployed core boots the bwrap quarantine child.** Enabling ``alfred_tui`` drives the
  PR-S4-11c-2b go-live flip — the daemon fail-closed spawns the bwrap-sandboxed quarantined
  child at boot. In the container this needs the #290 AppArmor (``alfred-bwrap``) + seccomp
  profiles LOADED on the host kernel first (``sudo apparmor_parser -r docker/apparmor/
  alfred-bwrap`` — what ``bin/alfred-setup.sh`` and ``.github/workflows/nightly.yml`` do). On
  an unprovisioned host Docker refuses to create the container and the core never binds.
* **The core refuse-boots without a seeded ``audit.hash_pepper``.** A fresh ``compose up``
  without ``bin/alfred-setup.sh`` refuse-boots and (under ``restart: unless-stopped``)
  crash-loops — so the harness seeds it.
* **Compose boot + link establishment + a metrics scrape inside a bounded wait** pushes a
  stable green well past a PR-smoke budget.

So the smoke SHELL (harness + the load-bearing ``gateway_core_link_up == 1`` assert) is
written and committed, but left ``@pytest.mark.skip`` so it is COLLECTED-BUT-SKIPPED on the
required PR Smoke job and can NEVER gate merge. The nightly leg (which already loads the
AppArmor profile + ``docker compose up -d --wait``) is where the marker flips on once the
provisioning + a deterministic link-up observable are wired. To run locally once a
provisioned host exists: load the AppArmor profile, set ``ALFRED_RUN_NIGHTLY_SMOKE=1``, and
remove the ``skip`` marker — the body then self-gates on ``_LIVE_STACK_UNAVAILABLE``.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest

pytestmark = pytest.mark.smoke

_REPO_ROOT = Path(__file__).resolve().parents[2]
_COMPOSE_FILE = _REPO_ROOT / "docker-compose.yaml"
_APPARMOR_PROFILE = _REPO_ROOT / "docker" / "apparmor" / "alfred-bwrap"

# --------------------------------------------------------------------------------------
# Live-provisioning gate. Mirrors test_gateway_chat_restart_smoke: the deployed core boots
# the bwrap quarantine child, so the live stack needs Docker + a Linux host with the #290
# AppArmor/seccomp profiles loadable. os.uname is absent on Windows; probe behind hasattr so
# COLLECTION stays import-safe on non-Unix.
# --------------------------------------------------------------------------------------
_HAS_DOCKER = shutil.which("docker") is not None
_IS_LINUX = hasattr(os, "uname") and os.uname().sysname == "Linux"
# Opt-in flag for the nightly leg. Defaults OFF so even with the skip marker removed a
# developer who has not opted in does not pay the live compose stack.
_NIGHTLY_OPT_IN = os.environ.get("ALFRED_RUN_NIGHTLY_SMOKE") == "1"
_LIVE_STACK_UNAVAILABLE = not (_HAS_DOCKER and _IS_LINUX)

# Generous bounds — this is a coarse live smoke, not a tight perf gate.
_BOOT_TIMEOUT_S = 120.0
_LINK_TIMEOUT_S = 60.0
_TEARDOWN_TIMEOUT_S = 60.0

# The gauge that reads 1 once the gateway's core leg is UP (src/alfred/gateway/metrics.py).
_CORE_LINK_UP_METRIC = "gateway_core_link_up"


def _compose(project: str, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    """Run ``docker compose -f <file> -p <project> <args>`` from the repo root.

    The seccomp ``security_opt`` path is resolved RELATIVE TO THE COMPOSE-INVOCATION CWD
    (docker-compose.yaml header documents this), so always invoke from ``_REPO_ROOT``.
    A throwaway ``-p`` project keeps this smoke's containers/volumes isolated from any
    operator stack on the same host.
    """
    return subprocess.run(
        ["docker", "compose", "-f", str(_COMPOSE_FILE), "-p", project, *args],
        cwd=_REPO_ROOT,
        check=check,
        capture_output=True,
        text=True,
        timeout=_BOOT_TIMEOUT_S,
    )


@pytest.fixture
def compose_project() -> Iterator[str]:
    """Yield an isolated compose project name; tear the whole stack + volumes down after."""
    project = f"alfred-g6-0b-smoke-{uuid.uuid4().hex[:8]}"
    try:
        yield project
    finally:
        # ``down -v`` removes the throwaway project's containers AND its named volumes
        # (alfred_run / state.git / pg / redis) so a re-run starts clean.
        subprocess.run(
            ["docker", "compose", "-f", str(_COMPOSE_FILE), "-p", project, "down", "-v"],
            cwd=_REPO_ROOT,
            check=False,
            capture_output=True,
            text=True,
            timeout=_TEARDOWN_TIMEOUT_S,
        )


def _load_apparmor_profile() -> None:
    """Load the #290 bwrap userns AppArmor profile (mirrors nightly.yml + alfred-setup.sh).

    docker-compose.yaml pins alfred-core at ``security_opt: apparmor=alfred-bwrap``; Docker
    REFUSES to create the container if that named profile is not loaded into the host
    kernel. Guarded on ``command -v apparmor_parser`` so a non-AppArmor Linux host (SELinux)
    skips gracefully (the security_opt line is a no-op there).
    """
    if shutil.which("apparmor_parser") is None:
        return
    subprocess.run(
        ["sudo", "apparmor_parser", "-r", "-W", str(_APPARMOR_PROFILE)],
        check=True,
        timeout=_TEARDOWN_TIMEOUT_S,
    )


def _scrape_core_link_up(project: str) -> bool:
    """True iff the gateway's ``gateway_core_link_up`` gauge reads >= 1.

    Scrapes /metrics from WITHIN the compose network (``docker compose exec alfred-gateway``)
    so no host port need be published — the gateway's /metrics is compose-internal by design
    (test_alfred_gateway_publishes_no_host_port). Uses the in-image Python so the smoke does
    not depend on curl/wget being present in the slim core image.
    """
    port = os.environ.get("ALFRED_GATEWAY_METRICS_PORT", "9464")
    probe = (
        "import urllib.request,sys;"
        f"body=urllib.request.urlopen('http://127.0.0.1:{port}/metrics',timeout=2)"
        ".read().decode('utf-8','replace');"
        f"print(body)"
    )
    result = _compose(project, "exec", "-T", "alfred-gateway", "python3", "-c", probe, check=False)
    if result.returncode != 0:
        return False
    sample_prefix = f"{_CORE_LINK_UP_METRIC} "
    for line in result.stdout.splitlines():
        if line.startswith("#") or not line.startswith(sample_prefix):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        try:
            return float(parts[1]) >= 1.0
        except ValueError:
            continue
    return False


@pytest.mark.skip(
    reason="live compose smoke — tracked for nightly stabilization. The in-process "
    "real-link gate is tests/integration/cli/daemon/test_chat_gateway_socket_turn.py. This "
    "shell needs the #290/ADR-0030 provisioned host (Docker + Linux + the loaded "
    "alfred-bwrap AppArmor/seccomp profiles + a seeded audit.hash_pepper) before it can run "
    "green reliably; the nightly leg owns flipping this marker on."
)
@pytest.mark.skipif(
    _LIVE_STACK_UNAVAILABLE or not _NIGHTLY_OPT_IN,
    reason="live compose stack needs Docker + Linux + the #290 bwrap profiles loaded AND "
    "ALFRED_RUN_NIGHTLY_SMOKE=1 opt-in.",
)
def test_deployed_daemon_core_and_gateway_link_up(compose_project: str) -> None:
    """The deployed daemon-core + gateway compose the comms-tui.sock link (G6-0b).

    Loads the #290 AppArmor profile, seeds the audit pepper, boots ``alfred-core`` (now a
    long-running daemon with ``alfred_tui`` enabled) + ``alfred-gateway`` (both mounting the
    shared ``alfred_run``), then asserts the gateway's ``gateway_core_link_up`` gauge reaches
    ``1`` — proving the deployed gateway LINKED to the deployed core (not just buffering).
    """
    _load_apparmor_profile()

    # Bring up the datastores first, then seed the audit.hash_pepper the daemon needs to
    # boot (a fresh stack without it refuse-boots + crash-loops under restart:unless-stopped).
    _compose(compose_project, "up", "-d", "--wait", "alfred-postgres", "alfred-redis")
    subprocess.run(
        ["bash", str(_REPO_ROOT / "bin" / "alfred-state-git-seed.sh")],
        cwd=_REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=_TEARDOWN_TIMEOUT_S,
    )

    # Boot the daemon-core + gateway. ``--wait`` blocks until alfred-core is up and the
    # gateway healthcheck goes healthy (the buffering state is HEALTHY by design).
    _compose(compose_project, "up", "-d", "--wait", "alfred-core", "alfred-gateway")

    # The load-bearing assertion: the gateway's core leg reached UP — the deployed link is
    # ESTABLISHED, not merely buffering core-down.
    deadline = time.monotonic() + _LINK_TIMEOUT_S
    linked = False
    while time.monotonic() < deadline:
        if _scrape_core_link_up(compose_project):
            linked = True
            break
        time.sleep(1.0)
    assert linked, (
        "the deployed gateway never reported gateway_core_link_up == 1 — the daemon-ified "
        "alfred-core did not bind comms-tui.sock on the shared alfred_run volume, or the "
        "gateway could not dial it (G6-0b deployment regression)."
    )
