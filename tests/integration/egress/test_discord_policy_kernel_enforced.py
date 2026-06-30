"""Discord adapter bwrap policy kernel-enforcement proof (G7-4, ADR-0043).

Asserts that the REAL shipped
``config/sandbox/discord-adapter.linux.bwrap.policy`` enforces network
containment at the kernel level:

* **(a)** A direct outbound ``connect(2)`` to an arbitrary external IP is
  refused with the empty network namespace the policy creates — no route, no
  loopback, no raw-socket access.
* **(b)** ``getaddrinfo`` for an external name fails — there is no resolver in
  the empty netns (no loopback, no ``/etc/resolv.conf`` visible even if bound,
  because the network namespace itself has no interfaces to serve DNS traffic).
* **(c)** Gateway-proxy allowlist enforcement (allowlisted Discord host succeeds,
  non-allowlisted host denied at the proxy) is *deferred*: exercising it in this
  harness would require a live gateway socket + the proxy shim wired up, which is
  impractical in a kernel-proof bwrap-direct test. That dimension is covered by
  the synthetic in-process AF_UNIX unit tests in the G7-4 Task 3 suite.

This is the partner of
``tests/integration/test_quarantined_llm_policy_kernel_enforced.py`` (quarantined-LLM
containment) and
``tests/integration/egress/test_core_network_isolation_kernel.py`` (docker
``internal:true`` isolation). Together they form the G7-3 / G7-4
kernel-observable containment chain for Spec C.

``bwrap`` is Linux-only; the whole module is skipped where it is absent (macOS
dev). CI's ``integration-privileged`` job (euid-0, AppArmor relaxed) ensures
bwrap can configure the empty network namespace — see the RTM_NEWADDR
skip-guard below.

**FIX-7**: a not-skipped CI guard in ``.github/workflows/ci.yml`` asserts this
test RUNS (not silently skips) on the privileged lane — the ``#245`` paper-gate
discipline applied to the privileged job.

The non-root structural assertion (corpus ``"net" in policy.unshare``) lives in
``tests/adversarial/sandbox_escape/test_sbx_corpus_executable.py`` (sbx-2026-014)
and runs on every branch in the plain adversarial workflow — so the gate is not
paper-only.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

from tests._sandbox_interp import interpreter_sandbox_roots

_REPO_ROOT = Path(__file__).resolve().parents[3]
_DISCORD_LINUX_POLICY = _REPO_ROOT / "config" / "sandbox" / "discord-adapter.linux.bwrap.policy"

pytestmark = pytest.mark.skipif(
    shutil.which("bwrap") is None,
    reason="bwrap required for the Discord adapter kernel-enforcement proof (Linux + CI only)",
)


def _discord_policy_flags_with_test_binds(plugin_dir: Path) -> list[str]:
    """bwrap flags from the REAL Discord Linux policy + test-interpreter binds.

    Mirrors the quarantine-test helper but for the Discord policy:

    * ``ro_binds`` whose SOURCE does not exist on this host are dropped — the
      production policy targets x86-64 Debian Bookworm; on aarch64 ``/lib64`` is
      absent and ``/etc/ssl/certs`` may live elsewhere. The /usr + /lib binds
      carry the loader via the usrmerge symlink on every arch, so the
      containment assertions stay meaningful.
    * ``rw_binds`` (the gateway egress socket dir
      ``/home/alfred/.egress/discord``) are dropped when the SOURCE does not
      exist — no live gateway socket is present in the integration runner; the
      network-containment probes do not route through the proxy and do not need
      the socket mount.
    * ``tmpfs`` (``/run/alfred/discord``) is dropped — irrelevant to the
      network-containment assertions.
    * Venv-interpreter + ``plugin_dir`` binds are APPENDED so ``sys.executable``
      (the pytest venv python) is exec'able inside the sandbox. This uses the
      same ``interpreter_sandbox_roots`` walk the quarantine tests use (follows
      the full symlink chain incl. uv minor-version alias hops).
    * The ``unshare``, ``die_with_parent``, and ``dev`` settings come from the
      SHIPPED policy bytes unchanged.
    """
    shipped = tomllib.loads(_DISCORD_LINUX_POLICY.read_text())

    # ro_binds: filter to paths that exist on this host.
    ro_binds: list[tuple[str, str]] = [
        (src, dst) for src, dst in shipped.get("ro_binds", []) if Path(src).exists()
    ]

    # Append venv interpreter + plugin_dir roots — NOT under /etc or /bin.
    interp_roots = interpreter_sandbox_roots() | {str(plugin_dir)}
    appended_roots = [
        root
        for root in sorted(interp_roots)
        if Path(root).exists() and not root.startswith(("/usr", "/lib", "/bin"))
    ]
    assert not any(
        os.path.realpath(root).startswith(("/etc", "/bin")) for root in appended_roots
    ), f"test bind resolves under /etc or /bin — would widen the sandbox: {appended_roots}"
    for root in appended_roots:
        ro_binds.append((root, root))

    # Build the flag list from policy primitives (drop tmpfs + absent rw_binds).
    flags: list[str] = []
    for src, dst in ro_binds:
        flags += ["--ro-bind", src, dst]
    # rw_binds: include only if the source path exists — the egress socket dir
    # is absent in the test runner (no live gateway), so this list is normally
    # empty during kernel-proof runs.
    for src, dst in shipped.get("rw_binds", []):
        if Path(src).exists():
            flags += ["--bind", src, dst]
    # Drop tmpfs — not needed for network-containment probes.
    if shipped.get("dev", True):
        flags += ["--dev", "/dev"]
    for kind in shipped.get("unshare", []):
        flags += [f"--unshare-{kind}"]
    if shipped.get("die_with_parent", True):
        flags += ["--die-with-parent"]
    return flags


def _bwrap_child_env() -> dict[str, str]:
    """Env for the sandboxed interpreter (bwrap inherits it; no --clearenv).

    ``LD_LIBRARY_PATH`` points the loader at the interpreter's lib dirs so a
    dynamically-linked Debian *venv* python (``RUNPATH $ORIGIN/../lib``, no
    ``/etc/ld.so.cache`` since /etc is unbound) can find ``libpython`` inside
    the sandbox — making the green gate depend on a test guarantee rather than
    the runner's interpreter layout. The uv-managed standalone CPython on the
    current runner doesn't need it; this keeps the test robust against the
    ``alfred-core`` Bookworm image the policy targets.
    """
    return {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "LD_LIBRARY_PATH": f"{sys.base_prefix}/lib:{sys.prefix}/lib:/usr/lib",
    }


def _skip_if_netns_unconfigurable(result: subprocess.CompletedProcess[str]) -> None:
    """Skip LOUDLY if bwrap could not configure the unshared net namespace.

    Spec C G7-4 adds ``--unshare-net`` to the Discord policy. bwrap brings up
    loopback in the new net namespace via netlink (RTM_NEWADDR); some
    unprivileged userns (e.g. GitHub-Actions runners without CAP_NET_ADMIN)
    forbid that, so bwrap exits BEFORE the plugin runs — the kernel-enforcement
    assertions below are then not exercisable. Skip loudly rather than fail or
    silent-pass, mirroring the quarantined-LLM policy test's guard.

    The signature (rc != 0 AND ``RTM_NEWADDR`` in stderr) is specific to netns
    SETUP failing before the child runs; a real containment regression runs the
    child and surfaces its own sentinel (``CONNECT_OK`` / ``DNS_OK``) with no
    RTM_NEWADDR, so this guard cannot mask one.
    """
    if result.returncode != 0 and "RTM_NEWADDR" in result.stderr:
        pytest.skip(
            "runner userns cannot configure the unshared net namespace's loopback "
            f"(bwrap: {result.stderr.strip()}); kernel-enforcement assertions not "
            "exercisable here (Spec C G7-4 --unshare-net)"
        )


def _run_probe(stub: Path, plugin_dir: Path) -> subprocess.CompletedProcess[str]:
    """Exec ``sys.executable stub`` under the REAL Discord Linux policy.

    Runs bwrap directly with the shipped policy's flags (no launcher / fd-3
    dance — the network-containment probes do not need the broker channel).
    Returns the CompletedProcess so the caller asserts on stdout.
    """
    flags = _discord_policy_flags_with_test_binds(plugin_dir)
    bwrap = shutil.which("bwrap")
    assert bwrap is not None  # gated by pytestmark on every caller
    result = subprocess.run(  # noqa: S603 — resolved bwrap path, repo-owned probe
        [bwrap, *flags, "--", sys.executable, str(stub)],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
        env=_bwrap_child_env(),
    )
    _skip_if_netns_unconfigurable(result)
    return result


def test_discord_policy_unshare_set_matches_shipped() -> None:
    """Guard: the shipped Discord policy unshares ``net`` (and the expected set).

    A future edit that drops ``net`` from the policy would silently re-open the
    adapter's outbound network surface without triggering a containment failure
    here unless this structural pin catches it first. This is the non-root
    counterpart of the kernel-observable probes below. NOTE: this test lives in
    ``tests/integration`` and is guarded by ``skipif(bwrap is None)`` — it
    requires bwrap and runs only on the privileged CI lane. The bwrap-free,
    runs-everywhere backstop is
    ``tests/adversarial/sandbox_escape/test_sbx_corpus_executable.py``
    (``test_sbx_2026_014_discord_outbound_contained``), which reads policy bytes
    only and runs on every branch in the plain adversarial workflow.

    Mirror of ``test_real_policy_unshare_set_matches_shipped`` in the quarantined-LLM
    kernel test (``tests/integration/test_quarantined_llm_policy_kernel_enforced.py``).
    """
    shipped = tomllib.loads(_DISCORD_LINUX_POLICY.read_text())
    unshare = set(shipped.get("unshare", []))
    assert {"pid", "uts", "cgroup", "ipc", "net"} <= unshare, (
        f"Discord policy missing expected unshare namespaces; got: {unshare}"
    )
    assert "net" in unshare, (
        "net dropped from Discord policy — adapter egress re-opened (Spec C G7-4 / ADR-0043)"
    )
    assert 3 in shipped.get("keep_fds", []), (
        "keep_fds must include fd 3 (broker channel) — arch-2 invariant"
    )


def test_discord_direct_connect_blocked_in_empty_netns(tmp_path: Path) -> None:
    """(a) A direct outbound ``connect(2)`` is refused in the empty netns.

    The empty network namespace created by ``--unshare-net`` has NO interfaces
    (not even loopback until bwrap brings it up, and external routes never
    exist), so any attempt to connect to an external IP fails with
    ``ENETUNREACH`` or ``ECONNREFUSED`` — an ``OSError``. A compromised Discord
    adapter CANNOT exfiltrate data or reach an attacker host by opening a raw
    socket to an arbitrary IP.

    The affirmative ``BLOCKED`` sentinel proves the probe RAN and the connect was
    refused — not a vacuous empty-stdout pass from a sandbox that never started.
    """
    stub = tmp_path / "probe_connect.py"
    stub.write_text(
        "import socket, sys\n"
        "try:\n"
        "    socket.create_connection(('1.1.1.1', 443), timeout=3)\n"
        "    print('CONNECT_OK', flush=True)\n"
        "    sys.exit(1)\n"
        "except OSError:\n"
        "    print('BLOCKED', flush=True)\n"
        "    sys.exit(0)\n"
    )
    result = _run_probe(stub, tmp_path)
    assert result.returncode == 0, result.stderr
    assert "CONNECT_OK" not in result.stdout, (
        "real Discord policy did NOT contain direct outbound connect — "
        "--unshare-net may be missing (Spec C G7-4 / ADR-0043)"
    )
    assert "BLOCKED" in result.stdout, (
        "probe stub did not run / connect was not refused — "
        "confirm bwrap started and the sandbox is alive"
    )


def test_discord_getaddrinfo_fails_in_empty_netns(tmp_path: Path) -> None:
    """(b) ``getaddrinfo`` for an external name fails in the empty netns.

    In the empty network namespace there is no interface connected to a DNS
    resolver; name resolution for external hosts fails with ``socket.gaierror``
    (EAI_AGAIN / EAI_NONAME). A compromised adapter CANNOT resolve an attacker's
    hostname to open a back-channel — even if it somehow bypassed the connect
    containment, DNS would fail first.

    Note: (c) gateway-proxy allowlist enforcement (allowlisted Discord host
    succeeds; non-allowlisted denied at the proxy layer) is deferred — exercising
    it requires a live gateway socket + proxy shim that is impractical in a
    bwrap-direct kernel-proof harness. That dimension is covered by the synthetic
    in-process AF_UNIX unit tests in the G7-4 Task 3 suite.
    """
    stub = tmp_path / "probe_dns.py"
    stub.write_text(
        "import socket, sys\n"
        "try:\n"
        "    socket.getaddrinfo('google.com', 443)\n"
        "    print('DNS_OK', flush=True)\n"
        "    sys.exit(1)\n"
        "except socket.gaierror:\n"
        "    print('DNS_BLOCKED', flush=True)\n"
        "    sys.exit(0)\n"
    )
    result = _run_probe(stub, tmp_path)
    assert result.returncode == 0, result.stderr
    assert "DNS_OK" not in result.stdout, (
        "real Discord policy did NOT block external DNS — "
        "--unshare-net may be missing (Spec C G7-4 / ADR-0043)"
    )
    assert "DNS_BLOCKED" in result.stdout, (
        "probe stub did not run / getaddrinfo was not refused — "
        "confirm bwrap started and the sandbox is alive"
    )
