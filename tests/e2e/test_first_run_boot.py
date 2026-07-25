"""The e2e first-run boot assertions (#494): green infra baseline + xfail'd blockers.

Baseline services are asserted healthy (regression net). The gateway/core/setup.sh
assertions are strict-xfail on their roadmap blockers — each reds via XPASS the instant
its blocker lands, forcing the assertion to tighten (Steps 2/3/5).
"""

from __future__ import annotations

import contextlib
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from tests import _compose
from tests.e2e import _env, _services
from tests.e2e._health import ServiceHealth
from tests.e2e.conftest import BootStack

pytestmark = pytest.mark.e2e

# Cold image builds happen in the boot_stack fixture; per-service `up` here is fast, but keep a
# comfortable margin for local runs where the fixture just built.
_UP_TIMEOUT_S = 300.0
_SETUP_SH_TIMEOUT_S = 900.0
# The gateway/core xfail tests poll a SHORTER health budget: their blockers (#499/#500) crash-loop
# as perpetual `starting` and can never resolve early, so the full 180s baseline budget would just
# burn ~6 min/nightly (review: performance). Restore the full budget when Step 2/3 un-xfails them.
_XFAIL_HEALTH_TIMEOUT_S = 60.0


@pytest.mark.parametrize("service", sorted(_services.BASELINE_SERVICES))
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
    assert (
        boot_stack.health("alfred-gateway", timeout_s=_XFAIL_HEALTH_TIMEOUT_S)
        is ServiceHealth.HEALTHY
    )


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
    assert (
        boot_stack.health("alfred-core", timeout_s=_XFAIL_HEALTH_TIMEOUT_S) is ServiceHealth.HEALTHY
    )


@pytest.mark.xfail(
    strict=True,
    reason="blocker #501: bin/alfred-setup.sh does not complete under the "
    "stock documented flow — it exits at the credential gate on the .env.example "
    "placeholder DeepSeek key (README:33 omits ALFRED_DEEPSEEK_API_KEY). Roadmap "
    "Step 4 (README/setup.sh reconciliation); after that, blocker #499's migrate hang.",
)
def test_setup_sh_completes() -> None:
    # Run setup.sh in an ISOLATED detached git worktree so the operator's repo-root .env is
    # NEVER touched (CR: no backup/restore window, no SIGKILL residual, no concurrent-reader
    # placeholder exposure). On the stock flow setup.sh writes a placeholder .env INSIDE the
    # worktree then exits at the credential gate — before any docker build/up — so this is fast
    # and creates no containers. COMPOSE_PROJECT_NAME is per-run-unique for the same isolation.
    setup_project = _env.new_project_name()
    with tempfile.TemporaryDirectory(prefix="alfred-e2e-setup-") as tmp:
        worktree = Path(tmp) / "repo"
        add = ["git", "worktree", "add", "--detach", "--force", str(worktree), "HEAD"]
        subprocess.run(
            add, cwd=_compose.REPO_ROOT, capture_output=True, text=True, timeout=120.0, check=True
        )
        try:
            shutil.copyfile(worktree / ".env.example", worktree / ".env")
            run_setup = ["bash", str(worktree / "bin" / "alfred-setup.sh")]
            proc = subprocess.run(
                run_setup,
                cwd=worktree,
                capture_output=True,
                text=True,
                timeout=_SETUP_SH_TIMEOUT_S,
                check=False,
                env={**os.environ, "COMPOSE_PROJECT_NAME": setup_project},
            )
            assert proc.returncode == 0, f"setup.sh exit {proc.returncode}: {proc.stderr[-800:]}"
        finally:
            # Belt-and-braces teardown (stock flow creates no containers), then drop the worktree.
            _compose.down_project(setup_project)
            remove = ["git", "worktree", "remove", "--force", str(worktree)]
            # suppress: a hung `worktree remove` (TimeoutExpired isn't caught by check=False) must
            # not shadow the test result; a stale worktree is pruned by git's next op (err-review).
            with contextlib.suppress(subprocess.SubprocessError):
                subprocess.run(
                    remove,
                    cwd=_compose.REPO_ROOT,
                    capture_output=True,
                    text=True,
                    timeout=60.0,
                    check=False,
                )
