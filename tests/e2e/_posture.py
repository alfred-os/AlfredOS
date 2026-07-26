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
from tests.e2e.conftest import BootStack


def _core_container_id(boot_stack: BootStack) -> str:
    cid = _compose.compose(
        boot_stack.project, "ps", "-q", "alfred-core", env_file=boot_stack.env_file
    ).stdout.strip()
    assert cid, "alfred-core container not found — cannot assert boot posture."
    return cid


def _is_egress_chokepoint_ok(network_names: Iterable[str]) -> bool:
    """Pure decision: joins the internal network AND does not join the external one.

    No I/O — takes already-parsed network names so it can be unit-tested without a running
    container (tests/unit/e2e/test_posture.py).
    """
    names = list(network_names)
    return any(n.endswith("alfred_internal") for n in names) and not any(
        n.endswith("alfred_external") for n in names
    )


def _is_gate_seeded(psql_stdout: str) -> bool:
    """Pure decision: the psql ``count(*)`` reply parses as a positive integer.

    No I/O — takes the already-captured stdout so it can be unit-tested without a running
    container (tests/unit/e2e/test_posture.py). A non-digit reply (e.g. a psql error message)
    or a zero count both mean "not seeded".
    """
    stripped = psql_stdout.strip()
    return stripped.isdigit() and int(stripped) > 0


def assert_egress_chokepoint(boot_stack: BootStack) -> None:
    """Core is attached ONLY to the internal (internal:true) network — no external route."""
    cid = _core_container_id(boot_stack)
    # Assigning the argv to a local before the call (matching tests/e2e/conftest.py) keeps
    # ruff's S607 (partial-executable-path) out of scope; only S603 remains (per-file ignore).
    cmd = ["docker", "inspect", cid]
    inspect = subprocess.run(
        cmd,
        cwd=_compose.REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=30.0,
        check=True,
    )
    names = set(json.loads(inspect.stdout)[0]["NetworkSettings"]["Networks"])
    assert _is_egress_chokepoint_ok(names), (
        f"alfred-core must join the internal network and must NOT join alfred_external "
        f"(connectivity-free core); got {sorted(names)}."
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
    assert _is_gate_seeded(proc.stdout), (
        f"plugin_grants must be seeded by daemon boot; psql count={proc.stdout.strip()!r} "
        f"rc={proc.returncode} stderr={proc.stderr[-400:]!r}."
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
    assert proc.returncode == 0, (
        f"bwrap userns build failed inside alfred-core (sandbox machinery not live): "
        f"rc={proc.returncode} {proc.stderr[-400:]!r}"
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
