"""The e2e first-run boot assertions (#494): green infra baseline.

Baseline services are asserted healthy (regression net). The gateway graduated to a plain
asserted-healthy test at #499; core graduated (provisioned + posture-asserted) at #500; the
setup.sh assertion graduated to a full-run provisioning test at #501, run in its OWN nightly
step (marker `e2e_full_setup`) so it does not collide with the session-scoped boot_stack. No
strict-xfail remains — the lane is fully green and ready for Step 5 (promote release-blocking;
close #494/#469).
"""

from __future__ import annotations

import contextlib
import os
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


@pytest.mark.e2e_full_setup
def test_setup_sh_completes(tmp_path: Path) -> None:
    # #501: the documented quickstart IS bin/alfred-setup.sh. Run the FULL script with
    # non-placeholder dummy keys (as test_core_is_healthy uses) in an ISOLATED detached worktree.
    # It runs in its OWN nightly pytest session (marker e2e_full_setup, deselected from the main
    # e2e step): setup.sh's `run --rm alfred-core ...` calls do NOT pass --no-deps, so they pull
    # up redis AND a (keyless-healthy, #499) gateway, and `up -d alfred-postgres` publishes host
    # 5432 — which would collide with the session-scoped boot_stack postgres if co-run. Asserts
    # (1) exit 0 (setup.sh `fail`s loudly on any step, so exit 0 gates migrate->seed->prime->
    # hash_pepper->operator), (2) a seeded operator (DB query, not the script's stdout), and
    # (3) a redirected hash_pepper artifact (a LATE step ran). user add is has_operator-guarded
    # and migration 0004 seeds the operator, so setup.sh skips create (no OperatorAlreadyExists,
    # the #500 trap). ALFRED_SECRETS_FILE redirects the real pepper secret into tmp_path (M1:
    # hermeticity — the pepper does not land in the runner $HOME) and gives us the artifact.
    from tests.e2e import _posture

    setup_project = _env.new_project_name()
    secrets_file = tmp_path / "secrets.toml"
    with tempfile.TemporaryDirectory(prefix="alfred-e2e-setup-") as tmp:
        worktree = Path(tmp) / "repo"
        add = ["git", "worktree", "add", "--detach", "--force", str(worktree), "HEAD"]
        subprocess.run(
            add,
            cwd=_compose.REPO_ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="surrogateescape",
            timeout=120.0,
            check=True,
        )
        env_file = _env.write_e2e_env_file(worktree, filename=".env")
        try:
            run_setup = ["bash", str(worktree / "bin" / "alfred-setup.sh")]
            proc = subprocess.run(
                run_setup,
                cwd=worktree,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="surrogateescape",
                timeout=_SETUP_SH_TIMEOUT_S,
                check=False,
                env={
                    **os.environ,
                    "COMPOSE_PROJECT_NAME": setup_project,
                    "ALFRED_SECRETS_FILE": str(secrets_file),
                },
            )
            setup_out = _env.scrub_env_secrets((proc.stdout or "") + (proc.stderr or ""), env_file)[
                -2000:
            ]
            assert proc.returncode == 0, f"setup.sh exit {proc.returncode}: {setup_out!r}"

            # (2) Outcome, not self-report: setup.sh's own postgres holds a seeded operator row.
            # `authorization` is a Postgres reserved keyword -> double-quote it.
            op = _compose.compose(
                setup_project,
                "exec",
                "-T",
                "alfred-postgres",
                "psql",
                "-U",
                "alfred",
                "-d",
                "alfred",
                "-tAc",
                "select count(*) from users where \"authorization\"='operator'",
                env_file=env_file,
                check=False,
            )
            op_out = _env.scrub_env_secrets(op.stdout, env_file)
            op_stderr = _env.scrub_env_secrets(op.stderr, env_file)[-400:]
            assert _posture.positive_count(op.stdout), (
                f"setup.sh did not seed an operator: psql count={op_out.strip()!r} "
                f"rc={op.returncode} stderr={op_stderr!r}"
            )

            # (3) A late step ran: the hash_pepper bootstrap wrote the redirected secrets file.
            assert secrets_file.is_file() and "audit.hash_pepper" in secrets_file.read_text(), (
                "setup.sh did not bootstrap audit.hash_pepper into ALFRED_SECRETS_FILE — the "
                "provisioning did not reach the late secret-seed step."
            )
        finally:
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
                    encoding="utf-8",
                    errors="surrogateescape",
                    timeout=60.0,
                    check=False,
                )
