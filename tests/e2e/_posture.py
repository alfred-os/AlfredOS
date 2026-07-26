"""Runtime boot-posture oracles for the un-xfail'd alfred-core (#500 sec-002).

Each property has its OWN concrete runtime observable on the BOOTED container — NOT
inferred from `healthy`. Distinct from tests/unit/test_compose_invariants.py, which pins
the static compose CONFIG (apparmor/seccomp present, internal network, SETUID).

NB (sec-001/test-002): the `bin/alfred-plugin-launcher.sh --self-test` answer is an
UNCONDITIONAL `printf 'policy-resolving'; exit 0` — it proves only the script was COPYed
in and would pass on a broken sandbox, so it is NOT used as the sandbox oracle. Instead we
functionally exercise the bwrap userns machinery the quarantine child actually depends on
(core-002: the daemon spawns that child under bwrap to reach healthy).
"""

from __future__ import annotations

import json
import subprocess
from collections.abc import Iterable

from tests import _compose
from tests.e2e import _env
from tests.e2e.conftest import BootStack


def _core_container_id(boot_stack: BootStack) -> str:
    cid = _compose.compose(
        boot_stack.project, "ps", "-q", "alfred-core", env_file=boot_stack.env_file
    ).stdout.strip()
    assert cid, "alfred-core container not found — cannot assert boot posture."
    return cid


def _is_egress_chokepoint_ok(networks: Iterable[tuple[str, bool]]) -> bool:
    """Pure decision: the container is attached to EXACTLY the kernel-internal network.

    The connectivity-free-core invariant (ADR-0040/0042) is that alfred-core joins ONLY the
    internal (``internal: true``) network. Two ways it can be violated: (1) a SECOND
    attachment (a bridge, the external plane, a stray default network — a routable egress
    path); (2) the sole attachment merely NAMING itself ``…alfred_internal`` while carrying
    ``Internal: false`` (routable — CodeRabbit: the name suffix alone is not the kernel
    primitive ADR-0040/0042 require). So require EXACTLY one attachment whose name ends with
    ``alfred_internal`` AND whose Docker ``Internal`` flag is ``True``. Each element is a
    ``(network_name, is_internal)`` pair. No I/O — unit-tested without a running container
    (tests/unit/e2e/test_posture.py).
    """
    nets = list(networks)
    return len(nets) == 1 and nets[0][0].endswith("alfred_internal") and nets[0][1] is True


def _is_gate_seeded(psql_stdout: str) -> bool:
    """Pure decision: the psql ``count(*)`` reply parses as a positive integer.

    No I/O — takes the already-captured stdout so it can be unit-tested without a running
    container (tests/unit/e2e/test_posture.py). A non-digit reply (e.g. a psql error message)
    or a zero count both mean "not seeded".
    """
    stripped = psql_stdout.strip()
    return stripped.isdigit() and int(stripped) > 0


def _docker(*args: str) -> str:
    """Run a read-only ``docker`` query and return stripped stdout (S607: trusted CLI)."""
    cmd = ["docker", *args]  # argv-as-local keeps ruff S607 out of scope; S603 is per-file-ignored.
    return subprocess.run(
        cmd, cwd=_compose.REPO_ROOT, capture_output=True, text=True, timeout=30.0, check=True
    ).stdout.strip()


def assert_egress_chokepoint(boot_stack: BootStack) -> None:
    """Core joins EXACTLY the kernel-internal (internal:true) network — no external route."""
    cid = _core_container_id(boot_stack)
    names = list(json.loads(_docker("inspect", cid))[0]["NetworkSettings"]["Networks"])
    # `docker inspect <container>` reports the ATTACHMENT, not the network's Internal
    # property, so resolve the ADR-0040/0042 kernel-isolation flag per network with a
    # `docker network inspect` — a name ending in `alfred_internal` on a routable
    # (Internal:false) network must NOT satisfy the chokepoint (CodeRabbit).
    nets = [
        (name, _docker("network", "inspect", name, "--format", "{{.Internal}}") == "true")
        for name in names
    ]
    assert _is_egress_chokepoint_ok(nets), (
        f"alfred-core must join EXACTLY the kernel-internal (internal:true) network "
        f"(connectivity-free core, ADR-0040/0042); got {nets}."
    )


def assert_capability_gate_seeded(boot_stack: BootStack) -> None:
    """The daemon boot seeded the first-party RealGate grants into Postgres (>0 rows)."""
    proc = _compose.compose(
        boot_stack.project,
        "exec",
        "-T",
        "alfred-postgres",
        "psql",
        "-U",
        "alfred",
        "-d",
        "alfred",
        "-tAc",
        "select count(*) from plugin_grants",
        env_file=boot_stack.env_file,
        check=False,
    )
    # Scrub the env-file's injected values from the surfaced stderr before it lands in the
    # CI log (matches conftest's e2e-stack.log handling; commit-security-review hardening).
    stderr_tail = _env.scrub_env_secrets(proc.stderr, boot_stack.env_file)[-400:]
    assert _is_gate_seeded(proc.stdout), (
        f"plugin_grants must be seeded by daemon boot; psql count={proc.stdout.strip()!r} "
        f"rc={proc.returncode} stderr={stderr_tail!r}."
    )


def assert_sandbox_machinery_live(boot_stack: BootStack) -> None:
    """bwrap can build an unprivileged userns INSIDE the running production container.

    Non-tautological with `healthy`: this exercises the SAME userns machinery the
    apparmor/seccomp profiles must permit and the quarantine child requires (core-002),
    independently of the daemon. A broken sandbox host fails HERE with a userns denial.
    """
    proc = _compose.compose(
        boot_stack.project,
        "exec",
        "-T",
        "alfred-core",
        "bwrap",
        "--ro-bind",
        "/",
        "/",
        "--unshare-user",
        "--uid",
        "0",
        "true",
        env_file=boot_stack.env_file,
        check=False,
    )
    stderr_tail = _env.scrub_env_secrets(proc.stderr, boot_stack.env_file)[-400:]
    assert proc.returncode == 0, (
        f"bwrap userns build failed inside alfred-core (sandbox machinery not live): "
        f"rc={proc.returncode} {stderr_tail!r}"
    )


def assert_core_boot_posture(boot_stack: BootStack) -> None:
    assert_egress_chokepoint(boot_stack)
    assert_capability_gate_seeded(boot_stack)
    assert_sandbox_machinery_live(boot_stack)


# SECURITY-ENGINEER SIGN-OFF (PR-time, owns the oracle — sec-001): confirm this set
# satisfies sec-002. In particular decide whether to ADD a negative production-refusal probe
# (assert an unsandboxed / policy-less launcher spawn is DENIED in the running production
# container — which makes sec-003's `ALFRED_ENVIRONMENT=production` load-bearing for the
# sandbox axis) and/or a boot-audit assertion that the quarantine child spawned sandboxed.
# The hard constraint the design commits to: NO property asserted by `healthy` alone, and
# the `--self-test` tautology is NOT used.
