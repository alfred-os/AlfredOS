"""The e2e first-run boot assertions (#494): green infra baseline + xfail'd blockers.

Baseline services are asserted healthy (regression net). The gateway graduated to a plain
asserted-healthy test at #499; core graduated (provisioned + posture-asserted) at #500. Only
the setup.sh assertion remains strict-xfail on its roadmap blocker — it reds via XPASS the
instant that blocker lands, forcing the assertion to tighten (Roadmap Step 4).
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
# Named separately from _UP_TIMEOUT_S because it bounds `run --rm ... migrate` / `user add`
# provisioning, not an `up`; same budget today, but a future divergence won't need a rename.
_PROVISION_TIMEOUT_S = _UP_TIMEOUT_S
_SETUP_SH_TIMEOUT_S = 900.0


@pytest.mark.parametrize("service", sorted(_services.BASELINE_SERVICES))
def test_baseline_service_is_healthy(boot_stack: BootStack, service: str) -> None:
    assert boot_stack.health(service) is ServiceHealth.HEALTHY, (
        f"{service} did not reach healthy — a NEW infra regression (this is the green baseline)."
    )


def test_every_compose_service_is_classified(boot_stack: BootStack) -> None:
    # Derived-set guard (arch-001): a NEW compose service must not boot unobserved. Reds if
    # `docker compose config --services` returns anything not in BASELINE, HEALTHY_APP, or XFAIL.
    out = _compose.compose(
        boot_stack.project, "config", "--services", env_file=boot_stack.env_file
    ).stdout
    discovered = _services.parse_services(out)
    _services.assert_service_floor(discovered)
    known = (
        _services.BASELINE_SERVICES | _services.HEALTHY_APP_SERVICES | set(_services.XFAIL_SERVICES)
    )
    assert set(discovered) == known, (
        f"compose services {sorted(discovered)} != classified {sorted(known)} — add a new/removed "
        f"service to BASELINE_SERVICES, HEALTHY_APP_SERVICES, or XFAIL_SERVICES in "
        f"tests/e2e/_services.py."
    )


def test_gateway_is_healthy(boot_stack: BootStack) -> None:
    # #499 landed: the gateway resolves its hosted-adapter allowlist without a provider key
    # (ADR-0036), so it boots healthy standalone (core absent -> healthy-while-buffering).
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


def test_core_is_healthy(boot_stack: BootStack) -> None:
    # #500: core boots in the shipped image (plugins/ COPYed hermetically, repo_root()
    # unified, policies.yaml pointed at /app/config). Provision a migrated DB before boot:
    # `alfred migrate` runs migration 0004_users_and_identities, which SEEDS the bootstrap
    # operator (display name from ALFRED_OPERATOR_NAME — compose default "operator" — with
    # `ON CONFLICT (slug) DO NOTHING`). So the tui-default comms graph's real Orchestrator
    # finds its operator and does NOT refuse boot with `operator_not_seeded`. --no-deps:
    # baseline postgres/redis are already up; core reaches healthy without the gateway.
    #
    # NB: an earlier revision added a separate `user add --authorization operator` step per
    # review finding core-001 ("migrate seeds no operator"). The nightly Linux lane proved
    # that empirically wrong — migrate DOES seed the operator, so a second operator fails
    # with OperatorAlreadyExists (exit 2). The redundant step is removed; migrate suffices.
    from tests.e2e import _posture

    # check=False + assert-with-stderr: a provisioning failure (or the NEXT masked boot
    # blocker) must surface its cause in the CI log directly — a bare CalledProcessError
    # omits stderr (the same diagnostics gap that hid this very failure once).
    migrate = _compose.compose(
        boot_stack.project,
        "run",
        "--rm",
        "--no-deps",
        "alfred-core",
        "migrate",
        env_file=boot_stack.env_file,
        timeout_s=_PROVISION_TIMEOUT_S,
        check=False,
    )
    # Combine stdout+stderr before scrubbing/truncating: `alfred migrate` may write its
    # failure explanation to EITHER stream (CodeRabbit), and losing stdout would drop the
    # root cause on a CI red. Scrub the env-file's injected values (matches conftest's
    # e2e-stack.log handling; commit-security-review hardening) — the error text stays.
    migrate_out = _env.scrub_env_secrets(
        (migrate.stdout or "") + (migrate.stderr or ""), boot_stack.env_file
    )[-1000:]
    assert migrate.returncode == 0, (
        f"alfred migrate (provisioning) failed: rc={migrate.returncode} output={migrate_out!r}"
    )
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
    _posture.assert_core_boot_posture(boot_stack)  # sec-002: posture oracles, not bare-healthy.


@pytest.mark.xfail(
    strict=True,
    reason="blocker #501: bin/alfred-setup.sh does not complete under the "
    "stock documented flow — it exits at the credential gate on the .env.example "
    "placeholder DeepSeek key (README:33 omits ALFRED_DEEPSEEK_API_KEY). Roadmap "
    "Step 4 (README/setup.sh reconciliation) is the sole remaining blocker — "
    "#499 un-hung migrate (gateway healthy) and #500 landed core provisioning + posture.",
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
