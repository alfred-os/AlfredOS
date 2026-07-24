"""Session lifecycle for the e2e first-run boot lane (#494).

Owns an ISOLATED docker compose project (fixed name + temp --env-file) so a local run
never touches an operator's stack. Fails LOUD (raises) if Docker is absent — never skips.
"""

from __future__ import annotations

import json
import subprocess
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest

from tests import _compose
from tests._docker_probe import docker_available, docker_unavailable_reason
from tests.e2e import _env
from tests.e2e._assert_ran import write_tally
from tests.e2e._health import ServiceHealth, classify_health

pytestmark = pytest.mark.e2e

_HEALTH_TIMEOUT_S = (
    180.0  # per-service budget: generous so a slow-but-healthy baseline never false-reds.
)
_POLL_INTERVAL_S = 3.0
_BUILD_TIMEOUT_S = (
    1800.0  # a cold multi-stage py3.14 build must ERROR on failure, not silently time out.
)
_BASELINE = ("alfred-postgres", "alfred-redis", "alfred-prometheus", "alfred-grafana")
_TALLY_PATH = Path("e2e-tally.json")


@dataclass(frozen=True)
class BootStack:
    project: str
    env_file: Path

    def health(self, service: str, *, timeout_s: float = _HEALTH_TIMEOUT_S) -> ServiceHealth:
        """Poll Docker health for a service until HEALTHY or the budget expires."""
        deadline = time.monotonic() + timeout_s
        last = ServiceHealth.NOT_CREATED
        while time.monotonic() < deadline:
            cid = _compose.compose(
                self.project, "ps", "-q", service, env_file=self.env_file, check=False
            ).stdout.strip()
            if cid:
                cmd = ["docker", "inspect", cid]
                proc = subprocess.run(
                    cmd,
                    cwd=_compose.REPO_ROOT,
                    capture_output=True,
                    text=True,
                    timeout=30.0,
                    check=False,
                )
                payload = json.loads(proc.stdout) if proc.returncode == 0 and proc.stdout else []
                last = classify_health(payload)
                if last is ServiceHealth.HEALTHY:
                    return last
            time.sleep(_POLL_INTERVAL_S)
        return last


@pytest.fixture(scope="session")
def boot_stack(tmp_path_factory: pytest.TempPathFactory) -> Iterator[BootStack]:
    if not docker_available():
        raise RuntimeError(  # FAIL LOUD — never skip (rev-001).
            f"e2e boot lane requires a Docker daemon: {docker_unavailable_reason()}"
        )
    env_file = _env.write_e2e_env_file(tmp_path_factory.mktemp("e2e-env"))
    project = _env.E2E_PROJECT_NAME
    try:
        # Build the app images ONCE with a long timeout so a cold build fails LOUD (fixture
        # error -> tally error>0 -> RED) rather than tripping the per-`up` 180s timeout and
        # being swallowed by the gateway/core xfail (ops-001).
        _compose.compose(
            project,
            "build",
            "alfred-core",
            "alfred-gateway",
            env_file=env_file,
            timeout_s=_BUILD_TIMEOUT_S,
        )
        # Baseline: bring the infra tier up bypassing deps (a broken gateway/core must not
        # block or hang the baseline). --no-deps + explicit service list = start-then-poll.
        _compose.compose(project, "up", "-d", "--no-deps", *_BASELINE, env_file=env_file)
        yield BootStack(project=project, env_file=env_file)
    finally:
        # Capture logs BEFORE teardown (ops-104) so a failure's diagnosis survives — but a
        # hung/failed `logs` (TimeoutExpired isn't suppressed by check=False) must NEVER skip
        # teardown of the fixed-name project (final-review Important).
        try:
            logs = _compose.compose(project, "logs", "--no-color", env_file=env_file, check=False)
            Path("e2e-stack.log").write_text(logs.stdout + logs.stderr)
        except (OSError, subprocess.SubprocessError):
            pass
        _compose.down_project(project)


def pytest_terminal_summary(
    terminalreporter: pytest.TerminalReporter, exitstatus: int, config: pytest.Config
) -> None:
    """Write the outcome tally from pytest's OWN stats for the Task 6 non-vacuity guard.

    pytest's ``stats`` dict already separates xfailed/skipped/xpassed authoritatively, so the
    guard needs no junit XML (no XXE surface) and re-derives nothing.
    """
    stats = terminalreporter.stats
    outcomes = ("passed", "failed", "error", "skipped", "xfailed", "xpassed")
    counts = {k: len(stats.get(k, [])) for k in outcomes}
    counts["collected"] = sum(counts.values())
    write_tally(counts, _TALLY_PATH)
