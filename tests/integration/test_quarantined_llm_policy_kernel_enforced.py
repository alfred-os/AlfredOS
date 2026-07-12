"""Merge-blocking integration test: the REAL quarantined-LLM Linux policy is
kernel-enforced (PR-S4-7 Component H).

End-to-end with REAL subprocesses (no mocks): the real bash launcher, the real
``manifest_reader`` subprocess, the REAL shipped
``config/sandbox/quarantined-llm.linux.bwrap.policy`` bytes, and a real
``bwrap`` sandbox. This is the partner of PR-S4-6's
``test_launcher_policy_resolver.py`` (which exercised a *fixture* policy); this
module proves the bytes AlfredOS actually ships for the quarantined LLM contain
a compromised process. Asserts:

* the fd-3 provider key reaches the sandboxed plugin (bwrap inherits fd 3 by
  default — the test places the pipe read end on fd 3 in the parent +
  ``pass_fds=(3,)``);
* host ``/etc/passwd`` is unreadable (the real policy binds neither /etc);
* ``/bin/sh`` exec is contained (the real policy binds no /bin + unshares pid).

The real policy binds only the SYSTEM interpreter (/usr, /lib, /lib64); the
test runs under the pytest venv interpreter, so we template the real policy with
the minimal extra interpreter/plugin binds the test needs — NEVER removing any
of the policy's own confinement (no /etc, no /bin, unshare pid/uts/cgroup/ipc,
die_with_parent). This mirrors the S4-6 resolver fixture's bind logic against
the shipped bytes.

``bwrap`` is Linux-only; the whole module is skipped where it is absent (macOS
dev). CI's alfred-core image (PR-S4-0b) ships bubblewrap 0.8.0 so this runs in
docker-in-docker. Promoted to a required status check under PR-S4-7.

NB: Spec C G7-1 (#333) made the real policy ``--unshare-net`` — the shipped
deterministic-echo child needs no egress, so it runs in an empty network
namespace (egress kernel-closed). The 2c real-LLM child (still #230) reaches its
provider PROVIDER-ONLY through the gateway L7 CONNECT proxy, never by re-opening
this namespace. This test asserts the shipped policy unshares ``net`` (the
kernel-observable egress containment is enforced live in the
``integration-privileged`` job) — see
``tests/adversarial/sandbox_escape/sbx_2026_005_outbound_network_unrestricted.yaml``
(now an enforced-containment payload).
"""

from __future__ import annotations

import os
import re
import shutil
import struct
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

from tests._sandbox_interp import interpreter_sandbox_roots

_REPO_ROOT = Path(__file__).resolve().parents[2]
_LAUNCHER = _REPO_ROOT / "bin" / "alfred-plugin-launcher.sh"
_REAL_POLICY = _REPO_ROOT / "config" / "sandbox" / "quarantined-llm.linux.bwrap.policy"

pytestmark = pytest.mark.skipif(
    shutil.which("bwrap") is None,
    reason="bwrap required for the quarantined-LLM kernel-enforcement test (Linux + CI only)",
)


def _real_policy_body_with_test_binds(plugin_dir: Path) -> str:
    """The REAL quarantined-LLM Linux policy body + the test-interpreter binds.

    We parse the shipped policy's ``ro_binds`` AND ``ro_binds_try`` (so the
    /usr, /lib, /lib64 confinement is the production set verbatim), APPEND the
    venv-interpreter + plugin_dir binds the pytest interpreter needs, and re-emit
    a TOML policy body. We KEEP the policy's ``unshare`` / ``die_with_parent`` /
    ``keep_fds`` untouched and DROP only the production tmpfs scratch
    (``/run/alfred/...``) — irrelevant to the containment assertions and avoids a
    mountpoint-exists dependency in the test root. We deliberately do NOT add
    /etc or /bin, so the escape assertions stay meaningful.
    """
    shipped = tomllib.loads(_REAL_POLICY.read_text())
    # HARD binds pass through VERBATIM — no existence filter. /usr and /lib always
    # exist, and a missing one must fail loud here exactly as it would in
    # production rather than be quietly dropped into a weaker test sandbox.
    ro_binds: list[tuple[str, str]] = [(src, dst) for src, dst in shipped.get("ro_binds", [])]

    # SOFT binds (#269) pass through as SOFT binds, so this reconstruction mirrors
    # production on EVERY arch: bwrap binds `/lib64` where it exists (x86-64, where
    # it holds ld-linux-x86-64.so.2 — the ELF interpreter of every dynamically
    # linked binary, so it is LOAD-BEARING for exec) and skips it where it does not
    # (arm64, where the loader arrives via the already-bound /lib).
    #
    # Rebuilding from `ro_binds` ALONE — as this helper used to, back when /lib64
    # was a hard bind the test had to existence-filter itself — would now DROP
    # /lib64 entirely once it moved to `ro_binds_try`. On x86-64 the sandboxed
    # interpreter would then fail to exec, and every "the plugin cannot read
    # /etc/passwd" assertion below would hold VACUOUSLY (a child that never runs
    # reads nothing). That is the #245 paper-gate shape — a containment proof that
    # proves containment of nothing — so the soft binds are carried explicitly.
    ro_binds_try: list[tuple[str, str]] = [
        (src, dst) for src, dst in shipped.get("ro_binds_try", [])
    ]

    # The pytest interpreter is ``sys.executable`` (venv python); its script
    # lives under ``plugin_dir`` (pytest tmp_path). Neither is under the shipped
    # /usr,/lib,/lib64 binds, so bind the venv (sys.prefix), the base
    # interpreter install (sys.base_prefix — where the venv's bin/python symlink
    # resolves), the realpath'd interpreter root, and plugin_dir.
    # ``interpreter_sandbox_roots`` walks ``sys.executable``'s full symlink chain
    # (incl. any uv minor-version alias hop, e.g. ``cpython-3.14-`` ->
    # ``cpython-3.14.6-``) so the venv interpreter is exec'able in bwrap regardless
    # of the uv-managed interpreter location; ``plugin_dir`` carries the stub.
    interp_roots = interpreter_sandbox_roots() | {str(plugin_dir)}
    appended_roots = [
        root
        for root in sorted(interp_roots)
        if Path(root).exists() and not root.startswith(("/usr", "/lib", "/bin"))
    ]
    # finding-3 (PR #231): a venv-layout shift must NEVER let an appended test
    # bind resolve under /etc or /bin and silently widen the sandbox's read
    # surface. Fail loud here rather than quietly binding host secrets.
    assert not any(
        os.path.realpath(root).startswith(("/etc", "/bin")) for root in appended_roots
    ), f"test bind resolves under /etc or /bin — would widen the sandbox: {appended_roots}"
    for root in appended_roots:
        ro_binds.append((root, root))

    binds_toml = ",\n  ".join(f'["{src}", "{dst}"]' for src, dst in ro_binds)
    soft_binds_toml = ",\n  ".join(f'["{src}", "{dst}"]' for src, dst in ro_binds_try)
    unshare_toml = ", ".join(f'"{ns}"' for ns in shipped.get("unshare", []))
    lines = [
        "ro_binds = [\n  " + binds_toml + "\n]",
        "ro_binds_try = [\n  " + soft_binds_toml + "\n]",
        f"unshare = [{unshare_toml}]",
        f"dev = {str(shipped.get('dev', True)).lower()}",
        f"die_with_parent = {str(shipped.get('die_with_parent', True)).lower()}",
        f"keep_fds = {shipped.get('keep_fds', [3])}",
    ]
    return "\n".join(lines) + "\n"


def _fixture_manifest(tmp_path: Path) -> tuple[Path, Path]:
    """Write the manifest + the real-policy-derived policy under a tmp root.

    Returns ``(manifest_path, policy_dir)``. The policy_dir is passed to the
    launcher via ``ALFRED_SANDBOX_POLICY_DIR`` so the policy_ref resolves
    relative to it.
    """
    policy_dir = tmp_path / "policies"
    policy_dir.mkdir()
    (policy_dir / "quarantined-llm.linux.bwrap.policy").write_text(
        _real_policy_body_with_test_binds(tmp_path)
    )

    manifest = tmp_path / "plugins" / "alfred.quarantined-llm" / "manifest.toml"
    manifest.parent.mkdir(parents=True)
    manifest.write_text(
        """[alfred]
manifest_version = 1
[plugin]
id = "alfred.quarantined-llm"
subscriber_tier = "system"
sandbox_profile = "user-plugin"
[sandbox]
kind = "full"
[sandbox.policy_refs]
linux = "quarantined-llm.linux.bwrap.policy"
macos = "config/sandbox/quarantined-llm.macos.sb"
windows = "config/sandbox/quarantined-llm.windows.stub.policy"
"""
    )
    return manifest, policy_dir


def _launcher_env(manifest: Path, policy_dir: Path) -> dict[str, str]:
    # LD_LIBRARY_PATH makes the green gate depend on a test guarantee rather
    # than the runner's interpreter layout (test-reviewer MEDIUM). A
    # dynamically-linked Debian *venv* python (RUNPATH ``$ORIGIN/../lib``) can't
    # find ``libpython3.x.so`` inside the sandbox — /etc (hence ld.so.cache) is
    # unbound and ``sys.base_prefix`` is skipped when it lives under /usr. Point
    # the loader explicitly at the interpreter's lib dirs (both are bound: via
    # the /usr ro-bind and the appended sys.prefix/base_prefix binds). bwrap
    # inherits this env by default (no --clearenv). The uv-managed standalone
    # CPython on the current runner doesn't need it; this keeps the test robust
    # against the alfred-core Bookworm image the policy targets.
    return {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "PYTHONPATH": str(_REPO_ROOT / "src"),
        "LD_LIBRARY_PATH": f"{sys.base_prefix}/lib:{sys.prefix}/lib:/usr/lib",
        "ALFRED_ENVIRONMENT": "test",
        "ALFRED_PLUGIN_MANIFEST_PATH": str(manifest),
        "ALFRED_SANDBOX_POLICY_DIR": str(policy_dir),
    }


def _skip_if_netns_unconfigurable(result: subprocess.CompletedProcess[str]) -> None:
    """Skip LOUDLY if bwrap could not configure the unshared net namespace.

    Spec C G7-1 (#333) added ``--unshare-net`` to the real policy. bwrap brings up
    loopback in the new net namespace via netlink (RTM_NEWADDR); some unprivileged
    userns (e.g. GitHub-Actions runners without CAP_NET_ADMIN) forbid that, so
    bwrap exits BEFORE the plugin runs — the kernel-enforcement assertions below
    are then not exercisable. Skip loudly rather than fail or silent-pass, mirroring
    ``test_launcher_policy_resolver.py::test_plugin_cannot_open_outbound_network``.

    The signature (rc != 0 AND ``RTM_NEWADDR`` in stderr) is specific to netns
    SETUP failing before the child runs; a real containment regression runs the
    child and surfaces its own sentinel (``READ_OK`` / ``EXEC_OK``) with no
    RTM_NEWADDR, so this guard cannot mask one.
    """
    if result.returncode != 0 and "RTM_NEWADDR" in result.stderr:
        pytest.skip(
            "runner userns cannot configure the unshared net namespace's loopback "
            f"(bwrap: {result.stderr.strip()}); kernel-enforcement assertions not "
            "exercisable here (Spec C G7-1 --unshare-net)"
        )


def _spawn_with_fd3(
    stub: Path, manifest: Path, policy_dir: Path, key: bytes
) -> subprocess.CompletedProcess[str]:
    """Spawn the launcher with the framed provider key delivered over fd 3.

    Mirrors ``test_launcher_policy_resolver.py::_spawn_with_fd3`` exactly: the
    pipe read end is placed on fd 3 IN THE PARENT (saving/restoring the parent's
    own fd 3) + ``pass_fds=(3,)`` so ``close_fds`` keeps it and the child — and
    bwrap's default fd inheritance — carry it through to the plugin. A
    ``preexec_fn`` dup2 does NOT work (subprocess runs ``close_fds`` after
    preexec). See the S4-6 test's docstring for the full rationale.
    """
    read_fd, write_fd = os.pipe()
    try:
        os.fstat(3)
        saved_fd3: int | None = os.dup(3)
    except OSError:
        saved_fd3 = None
    os.dup2(read_fd, 3)
    os.set_inheritable(3, True)  # noqa: FBT003 -- stdlib API: bool is positional
    if read_fd != 3:
        os.close(read_fd)
    try:
        proc = subprocess.Popen(  # noqa: S603 — repo-owned launcher script path
            [str(_LAUNCHER), "alfred.quarantined-llm", sys.executable, str(stub)],
            env=_launcher_env(manifest, policy_dir),
            pass_fds=(3,),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=str(_REPO_ROOT),
        )
    finally:
        if saved_fd3 is not None:
            os.dup2(saved_fd3, 3)
            os.close(saved_fd3)
        else:
            os.close(3)
    try:
        os.write(write_fd, struct.pack(">I", len(key)))
        os.write(write_fd, key)
    except BrokenPipeError:
        pass
    finally:
        os.close(write_fd)
    stdout, stderr = proc.communicate(timeout=30)
    result = subprocess.CompletedProcess(proc.args, proc.returncode, stdout, stderr)
    _skip_if_netns_unconfigurable(result)
    return result


def test_real_policy_unshare_set_matches_shipped() -> None:
    """Guard: the test templates the SHIPPED unshare set, never a weaker one.

    If a future edit drops ``pid`` from the real policy the containment
    assertions below would silently weaken; this pins the production posture so
    the kernel-enforcement claims stay anchored to what AlfredOS actually ships.
    Also pins the Spec C G7-1 (#333) egress closure: the real policy MUST unshare
    ``net`` so the echo child runs in an empty network namespace; dropping it
    silently re-opens the child's egress.
    """
    shipped = tomllib.loads(_REAL_POLICY.read_text())
    unshare = set(shipped.get("unshare", []))
    assert {"pid", "uts", "cgroup", "ipc", "net"} <= unshare
    assert "net" in unshare, "net dropped — echo-child egress re-opened (Spec C G7-1)"
    assert 3 in shipped.get("keep_fds", [])


def test_quarantined_llm_fd3_key_delivered(tmp_path: Path) -> None:
    stub = tmp_path / "stub.py"
    stub.write_text(
        "import os, struct, sys\n"
        "prefix = os.read(3, 4)\n"
        "length, = struct.unpack('>I', prefix)\n"
        "key = os.read(3, length).decode()\n"
        "print(f'GOT key=len{len(key)}', flush=True)\n"
        "sys.exit(0)\n"
    )
    manifest, policy_dir = _fixture_manifest(tmp_path)
    result = _spawn_with_fd3(stub, manifest, policy_dir, key=b"sk-quarantined-123")
    assert result.returncode == 0, result.stderr
    assert "GOT key=len18" in result.stdout
    assert '"event":"supervisor.plugin.sandbox_refused"' not in result.stderr


def test_quarantined_llm_cannot_read_host_etc_passwd(tmp_path: Path) -> None:
    stub = tmp_path / "escape.py"
    stub.write_text(
        "import sys\n"
        "try:\n"
        "    open('/etc/passwd').read()\n"
        "    print('READ_OK', flush=True)\n"
        "    sys.exit(1)\n"
        "except OSError as e:\n"
        "    print(f'BLOCKED {e.errno}', flush=True)\n"
        "    sys.exit(0)\n"
    )
    manifest, policy_dir = _fixture_manifest(tmp_path)
    result = _spawn_with_fd3(stub, manifest, policy_dir, key=b"sk-x")
    # finding-1: rc==0 proves the sandbox started; the affirmative BLOCKED
    # sentinel proves the probe ran and the read was refused — not a vacuous
    # empty-stdout pass from a sandbox that never started.
    assert result.returncode == 0, result.stderr
    assert "READ_OK" not in result.stdout, "real policy leaked host /etc/passwd"
    assert "BLOCKED" in result.stdout, "stub did not run / read was not refused"


def test_quarantined_llm_cannot_exec_host_bin_sh(tmp_path: Path) -> None:
    stub = tmp_path / "exec_escape.py"
    stub.write_text(
        "import subprocess, sys\n"
        "try:\n"
        "    subprocess.run(['/bin/sh', '-c', 'echo escape'], check=True)\n"
        "    print('EXEC_OK', flush=True)\n"
        "    sys.exit(1)\n"
        "except (FileNotFoundError, OSError):\n"
        "    print('BLOCKED', flush=True)\n"
        "    sys.exit(0)\n"
    )
    manifest, policy_dir = _fixture_manifest(tmp_path)
    result = _spawn_with_fd3(stub, manifest, policy_dir, key=b"sk-x")
    # finding-1: a negative-only assertion passes VACUOUSLY if the sandbox never
    # starts (empty stdout). rc==0 proves it started; BLOCKED proves the probe
    # ran and the exec was refused — so a real exec-containment regression is
    # visible, not silently green.
    assert result.returncode == 0, result.stderr
    assert "EXEC_OK" not in result.stdout, "real policy did NOT contain /bin/sh exec"
    assert "BLOCKED" in result.stdout, "stub did not run / exec was not refused"


def test_launcher_invokes_bwrap_with_unshared_net(tmp_path: Path) -> None:
    """Spec C G7-1 (#333): the real policy passes --unshare-net.

    The echo child needs no egress, so the launcher's emitted flag set isolates
    the network namespace. Pinned here so a future edit that drops net isolation
    (silently re-opening the child's egress) is forced through review.
    """
    stub = tmp_path / "stub.py"
    stub.write_text(
        "import os, struct, sys\n"
        "os.read(3, 4)\n"  # drain the fd-3 frame so the parent write doesn't EPIPE
        "print('RAN', flush=True)\n"
        "sys.exit(0)\n"
    )
    manifest, policy_dir = _fixture_manifest(tmp_path)
    # Translate the policy directly (the launcher's exact path) and assert the
    # flag set, rather than scraping bwrap's argv. This reads the SAME bytes the
    # launcher resolves.
    from alfred.plugins.sandbox_policy import policy_to_bwrap_flags, read_policy_toml

    body = (policy_dir / "quarantined-llm.linux.bwrap.policy").read_text()
    flags = policy_to_bwrap_flags(read_policy_toml(body))
    assert "--unshare-net" in flags, "net isolation dropped — echo-child egress re-opened (G7-1)"
    assert "--unshare-pid" in flags
    # And the chain actually runs end-to-end.
    result = _spawn_with_fd3(stub, manifest, policy_dir, key=b"sk-x")
    assert "RAN" in result.stdout, result.stderr
    assert re.search(r"sandbox_refused", result.stderr) is None
