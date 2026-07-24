"""The e2e first-run boot assertions (#494): green infra baseline + xfail'd blockers.

Baseline services are asserted healthy (regression net). The gateway/core/setup.sh
assertions are strict-xfail on their roadmap blockers — each reds via XPASS the instant
its blocker lands, forcing the assertion to tighten (Steps 2/3/5).
"""

from __future__ import annotations

import os
import shutil
import subprocess
from collections.abc import Iterator

import pytest

from tests import _compose
from tests.e2e import _services
from tests.e2e._env import E2E_PROJECT_NAME
from tests.e2e._health import ServiceHealth
from tests.e2e.conftest import BootStack

pytestmark = pytest.mark.e2e

# Cold image builds happen in the boot_stack fixture; per-service `up` here is fast, but keep a
# comfortable margin for local runs where the fixture just built.
_UP_TIMEOUT_S = 300.0
_SETUP_SH_TIMEOUT_S = 900.0


@pytest.mark.parametrize(
    "service",
    ["alfred-postgres", "alfred-redis", "alfred-prometheus", "alfred-grafana"],
)
def test_baseline_service_is_healthy(boot_stack: BootStack, service: str) -> None:
    assert boot_stack.health(service) is ServiceHealth.HEALTHY, (
        f"{service} did not reach healthy — a NEW infra regression (this is the green baseline)."
    )


def test_every_compose_service_is_classified(boot_stack: BootStack) -> None:
    # Derived-set guard (arch-001): a NEW compose service must not boot unobserved. Reds if
    # `docker compose config --services` returns anything not in BASELINE or XFAIL.
    out = _compose.compose(
        boot_stack.project, "config", "--services", env_file=boot_stack.env_file
    ).stdout
    discovered = _services.parse_services(out)
    _services.assert_service_floor(discovered)
    known = _services.BASELINE_SERVICES | set(_services.XFAIL_SERVICES)
    assert set(discovered) == known, (
        f"compose services {sorted(discovered)} != classified {sorted(known)} — add a new/removed "
        f"service to BASELINE_SERVICES or XFAIL_SERVICES in tests/e2e/_services.py."
    )


@pytest.mark.xfail(
    strict=True,
    reason="blocker #499: gateway _resolve_hosted_adapter_ids builds a "
    "full Settings() needing a provider key it is denied (ADR-0036). Roadmap Step 2.",
)
def test_gateway_is_healthy(boot_stack: BootStack) -> None:
    _compose.compose(
        boot_stack.project,
        "up",
        "-d",
        "--no-deps",
        "alfred-gateway",
        env_file=boot_stack.env_file,
        timeout_s=_UP_TIMEOUT_S,
    )
    assert boot_stack.health("alfred-gateway") is ServiceHealth.HEALTHY


@pytest.mark.xfail(
    strict=True,
    reason="blocker #500: alfred-core.Dockerfile omits plugins/ and "
    "_REPO_ROOT resolves to the install prefix. Ratchets green only when core is "
    "FULLY bootable (image + provisioning) at Roadmap Step 3, whose un-xfail must "
    "add posture assertions (sandbox/gate/egress), not a bare assert-healthy.",
)
def test_core_is_healthy(boot_stack: BootStack) -> None:
    _compose.compose(
        boot_stack.project,
        "up",
        "-d",
        "--no-deps",
        "alfred-core",
        env_file=boot_stack.env_file,
        timeout_s=_UP_TIMEOUT_S,
    )
    assert boot_stack.health("alfred-core") is ServiceHealth.HEALTHY


@pytest.fixture
def _stock_dotenv() -> Iterator[None]:
    """Deterministic, host-independent, operator-safe setup.sh precondition (sec-001).

    setup.sh reads repo-root ``.env``. If a dev box has a real .env with real keys, setup.sh
    would clear its credential gate and run the INVASIVE path (sudo apparmor / build / migrate)
    and hang. So we WRITE the stock ``.env.example`` (placeholder keys) to ``.env`` before the
    run — guaranteeing the fast credential-gate exit everywhere — and restore the original after.
    """
    dotenv = _compose.REPO_ROOT / ".env"
    example = _compose.REPO_ROOT / ".env.example"
    backup = dotenv.read_bytes() if dotenv.exists() else None
    try:
        shutil.copyfile(example, dotenv)
        yield
    finally:
        if backup is None:
            dotenv.unlink(missing_ok=True)
        else:
            dotenv.write_bytes(backup)


@pytest.mark.xfail(
    strict=True,
    reason="blocker #501: bin/alfred-setup.sh does not complete under the "
    "stock documented flow — it exits at the credential gate on the .env.example "
    "placeholder DeepSeek key (README:33 omits ALFRED_DEEPSEEK_API_KEY). Roadmap "
    "Step 4 (README/setup.sh reconciliation); after that, blocker #499's migrate hang.",
)
def test_setup_sh_completes(_stock_dotenv: None) -> None:
    setup_project = f"{E2E_PROJECT_NAME}-setup"
    try:
        cmd = ["bash", str(_compose.REPO_ROOT / "bin" / "alfred-setup.sh")]
        proc = subprocess.run(
            cmd,
            cwd=_compose.REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=_SETUP_SH_TIMEOUT_S,
            check=False,
            env={**os.environ, "COMPOSE_PROJECT_NAME": setup_project},
        )
        assert proc.returncode == 0, f"setup.sh exit {proc.returncode}: {proc.stderr[-800:]}"
    finally:
        # Belt-and-braces: on the stock fast-exit path setup.sh creates no containers, but tear
        # down the -setup project anyway in case a future change lets it reach `up`.
        _compose.down_project(setup_project)
