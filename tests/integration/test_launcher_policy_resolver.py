"""Merge-blocking integration test for the launcher policy resolver (PR-S4-6 J).

End-to-end with REAL subprocesses (no mocks): the real bash launcher, the
real ``manifest_reader`` subprocess, the real fixture policy file, and a real
``bwrap`` sandbox. Asserts:

* ``bwrap`` is invoked with ``--sync-fd 3`` and the fixture's policy flags,
  and the fd-3 provider key reaches the sandboxed plugin (Component J.1).
* The active escape attempts are contained by bwrap (Component test-1):
  the sandboxed plugin cannot read host ``/etc/passwd`` (``/etc`` not bound)
  and cannot exec ``/bin/sh`` outside the bound read-only tree.
* The refusal path (manifest without ``[sandbox]``) emits the audit JSON row.

``bwrap`` is Linux-only; the whole module is skipped where it is absent (macOS
dev). CI's alfred-core image (PR-S4-0b) ships bubblewrap 0.8.0 so this runs in
docker-in-docker. This test is promoted to a required status check under
PR-S4-6 (ops-007).
"""

from __future__ import annotations

import functools
import os
import shutil
import struct
import subprocess
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
_LAUNCHER = _REPO_ROOT / "bin" / "alfred-plugin-launcher.sh"

pytestmark = pytest.mark.skipif(
    shutil.which("bwrap") is None,
    reason="bwrap required for the policy-resolver integration test (Linux + CI only)",
)


# A bwrap policy adequate to RUN the Python plugin (read-only /usr, /lib*,
# tmpfs /tmp, plus PYTHONPATH for the alfred src tree) while STILL refusing
# the escape attempts: /etc is NOT bound (so /etc/passwd reads fail), /bin/sh
# is not separately bound, and ``net`` is unshared (so the plugin has no
# outbound network — only a loopback-only empty net namespace). keep_fds=[3]
# carries the provider key. The real quarantined-LLM policy bytes ship in
# PR-S4-7; this fixture is the resolver-integration analogue.
def _adequate_policy_body(plugin_dir: Path, *, unshare_net: bool = False) -> str:
    # /lib64 carries the ELF dynamic loader the interpreter needs. /bin is
    # DELIBERATELY NOT bound: on usrmerged Linux it's a symlink to /usr/bin, so
    # binding it would make ``/bin/sh`` available inside the sandbox and break
    # test_plugin_cannot_exec_host_bin_sh's containment assertion. The venv
    # interpreter is bound by absolute path below, so it needs no /bin.
    binds = ['["/usr", "/usr"]', '["/lib", "/lib"]']
    if Path("/lib64").exists():
        binds.append('["/lib64", "/lib64"]')
    binds.append(f'["{_REPO_ROOT / "src"}", "{_REPO_ROOT / "src"}"]')
    # The plugin entrypoint passed by the test is ``sys.executable`` (the venv
    # python), and its script lives under ``plugin_dir`` (pytest's tmp_path).
    # Neither is under the system binds above, so BOTH must be bound or bwrap
    # fails with ``execvp .../python: No such file or directory`` (interpreter)
    # or the interpreter can't open the script (plugin_dir). Bind the venv
    # (``sys.prefix``), the base interpreter install (``sys.base_prefix`` —
    # where the venv's ``bin/python`` symlink resolves, e.g. the uv-managed
    # CPython on CI) + the realpath'd interpreter root, and ``plugin_dir``.
    interp_roots = {
        sys.prefix,
        sys.base_prefix,
        str(Path(os.path.realpath(sys.executable)).parents[1]),
        str(plugin_dir),
    }
    for root in sorted(interp_roots):
        if Path(root).exists() and not root.startswith(("/usr", "/lib", "/bin")):
            binds.append(f'["{root}", "{root}"]')
    # NOTE: deliberately NO ``tmpfs = ["/tmp"]`` — pytest's tmp_path (where the
    # stub lives) is typically UNDER /tmp, so a fresh tmpfs there would shadow
    # the just-bound plugin_dir. The stubs need no writable /tmp; the escape
    # assertions (no /etc, no /bin/sh egress) hold without it.
    #
    # ``net`` is OPT-IN (network-containment test only). bwrap ``--unshare-net``
    # tries to bring up loopback via netlink (RTM_NEWADDR), which the
    # GitHub-Actions unprivileged userns FORBIDS — so unsharing net in the
    # shared fixture would break every filesystem/exec/fd-3 test too. Only the
    # dedicated network test requests it (and skips loudly when the runner can't
    # configure the netns — see test_plugin_cannot_open_outbound_network).
    unshare = ["pid", "uts", "cgroup", "ipc"]
    if unshare_net:
        unshare.append("net")
    unshare_toml = ", ".join(f'"{ns}"' for ns in unshare)
    return (
        "ro_binds = [\n  " + ",\n  ".join(binds) + "\n]\n"
        f"unshare = [{unshare_toml}]\n"
        "die_with_parent = true\n"
        "keep_fds = [3]\n"
    )


def _fixture_manifest(tmp_path: Path, *, unshare_net: bool = False) -> tuple[Path, Path]:
    """Write the manifest + an adequate policy under a tmp policy root.

    Returns ``(manifest_path, policy_dir)``. The policy_dir is passed to the
    launcher via ``ALFRED_SANDBOX_POLICY_DIR`` so confinement resolves the
    policy_ref relative to it. ``unshare_net`` opts into the network-namespace
    isolation (only the network-containment test; see _adequate_policy_body).
    """
    policy_dir = tmp_path / "policies"
    policy_dir.mkdir()
    # The stub is written directly under tmp_path by each test, so bind tmp_path
    # so the sandboxed interpreter can open it.
    (policy_dir / "fixture.linux.bwrap.policy").write_text(
        _adequate_policy_body(tmp_path, unshare_net=unshare_net)
    )

    manifest = tmp_path / "plugins" / "alfred.fixture" / "manifest.toml"
    manifest.parent.mkdir(parents=True)
    manifest.write_text(
        """[alfred]
manifest_version = 1
[plugin]
id = "alfred.fixture"
subscriber_tier = "user-plugin"
sandbox_profile = "user-plugin"
[sandbox]
kind = "full"
[sandbox.policy_refs]
linux = "fixture.linux.bwrap.policy"
macos = "config/sandbox/foo.macos.sb"
windows = "config/sandbox/foo.windows.stub.policy"
"""
    )
    return manifest, policy_dir


def _launcher_env(manifest: Path, policy_dir: Path) -> dict[str, str]:
    return {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "PYTHONPATH": str(_REPO_ROOT / "src"),
        "ALFRED_ENVIRONMENT": "test",
        "ALFRED_PLUGIN_MANIFEST_PATH": str(manifest),
        "ALFRED_SANDBOX_POLICY_DIR": str(policy_dir),
    }


def _remap_read_end_to_fd3(read_fd: int) -> None:
    """preexec_fn: place the pipe read end on fd 3 in the launcher child.

    Runs post-fork / pre-exec in the child. ``bwrap --sync-fd 3`` and the
    sandboxed plugin's ``os.read(3, ...)`` operate on fd **3** specifically,
    but ``os.pipe()`` hands us an arbitrary descriptor (under pytest it is NOT
    3). ``pass_fds`` keeps ``read_fd`` open + inheritable at its ORIGINAL
    number; this remap moves it onto 3 so the framing the parent writes reaches
    the plugin. Mirrors how the production Supervisor spawns the launcher with
    the pipe read end as fd 3 (see ``alfred.supervisor.fd3_key_delivery``).

    ``os.dup2`` always clears close-on-exec on its TARGET, so fd 3 survives the
    bwrap exec without an explicit ``set_inheritable``. The original ``read_fd``
    is closed when it isn't already 3 so the only surviving copy is fd 3.
    """
    os.dup2(read_fd, 3)
    if read_fd != 3:
        os.close(read_fd)


def _spawn_with_fd3(
    stub: Path, manifest: Path, policy_dir: Path, key: bytes
) -> subprocess.CompletedProcess[str]:
    """Spawn the launcher with the framed provider key delivered over fd 3."""
    read_fd, write_fd = os.pipe()
    proc = subprocess.Popen(  # noqa: S603 — repo-owned launcher script path
        [str(_LAUNCHER), "alfred.fixture", sys.executable, str(stub)],
        env=_launcher_env(manifest, policy_dir),
        # pass_fds keeps read_fd open + inheritable in the child; the
        # preexec_fn then dup2's it onto fd 3 (the channel bwrap --sync-fd 3
        # and the plugin's os.read(3) use). Without the remap the read end
        # lands at an arbitrary number and fd 3 is closed → the plugin's
        # os.read(3, 4) raises OSError(EBADF).
        pass_fds=(read_fd,),
        preexec_fn=functools.partial(_remap_read_end_to_fd3, read_fd),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=str(_REPO_ROOT),
    )
    os.close(read_fd)
    # CR #229 R2 finding-7: if os.write raises (e.g. EPIPE when the launcher
    # dies early), write_fd would leak. try/finally guarantees the close.
    #
    # On BrokenPipeError the launcher closed fd 3 (the read end) before we
    # delivered the key — i.e. it exited early. Swallow EPIPE here so we DON'T
    # mask the launcher's real failure: fall through to communicate() below and
    # surface its stderr in the assertion (the CompletedProcess carries the
    # launcher's nonzero rc + stderr).
    try:
        os.write(write_fd, struct.pack(">I", len(key)))
        os.write(write_fd, key)
    except BrokenPipeError:
        pass
    finally:
        os.close(write_fd)
    stdout, stderr = proc.communicate(timeout=30)
    return subprocess.CompletedProcess(proc.args, proc.returncode, stdout, stderr)


def test_resolver_invokes_bwrap_and_delivers_fd3_key(tmp_path: Path) -> None:
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
    result = _spawn_with_fd3(stub, manifest, policy_dir, key=b"sk-fixture-12345")
    assert result.returncode == 0, result.stderr
    assert "GOT key=len16" in result.stdout
    # The refusal row must NOT have fired on the success path.
    assert '"event":"supervisor.plugin.sandbox_refused"' not in result.stderr


def test_plugin_cannot_read_host_etc_passwd(tmp_path: Path) -> None:
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
    # The fixture policy does NOT bind /etc — the open must fail.
    assert "READ_OK" not in result.stdout
    assert result.returncode == 0, result.stderr


def test_plugin_cannot_exec_host_bin_sh(tmp_path: Path) -> None:
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
    assert "EXEC_OK" not in result.stdout


def test_plugin_cannot_open_outbound_network(tmp_path: Path) -> None:
    """test-1 vector 3 (CR PR #229 finding-3): a sandboxed plugin's outbound
    network attempt is contained by ``--unshare-net``.

    The fixture policy unshares the network namespace, so the plugin lives in an
    empty net namespace with no route off-box. A TCP connect to a routable host
    (1.1.1.1:443) must fail inside the sandbox — proving the network escape is
    kernel-enforced, not merely policy-advised. We bind a short connect timeout
    so the test never hangs if (regression) the namespace ISN'T unshared and the
    connect actually tries to traverse the network.
    """
    stub = tmp_path / "net_escape.py"
    stub.write_text(
        "import socket, sys\n"
        "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
        "s.settimeout(3)\n"
        "try:\n"
        "    s.connect(('1.1.1.1', 443))\n"
        "    print('NET_OK', flush=True)\n"
        "    sys.exit(1)\n"
        "except OSError as e:\n"
        # An empty net namespace yields ENETUNREACH/EHOSTUNREACH immediately.
        "    print(f'BLOCKED {e.errno}', flush=True)\n"
        "    sys.exit(0)\n"
        "finally:\n"
        "    s.close()\n"
    )
    manifest, policy_dir = _fixture_manifest(tmp_path, unshare_net=True)
    result = _spawn_with_fd3(stub, manifest, policy_dir, key=b"sk-x")
    # bwrap brings up loopback in the new net namespace via netlink
    # (RTM_NEWADDR); some unprivileged userns (e.g. GitHub-Actions runners
    # without CAP_NET_ADMIN) forbid that, so bwrap exits before the plugin
    # runs. SKIP LOUDLY rather than silent-pass — the containment assertion
    # below is only meaningful when the netns actually came up.
    if result.returncode != 0 and "RTM_NEWADDR" in result.stderr:
        pytest.skip(
            "runner userns cannot configure the unshared net namespace's "
            f"loopback (bwrap: {result.stderr.strip()}); network-containment "
            "assertion not exercisable here"
        )
    assert "NET_OK" not in result.stdout, "outbound network was NOT contained by --unshare-net"
    assert result.returncode == 0, result.stderr
    assert "BLOCKED" in result.stdout


def test_missing_sandbox_block_emits_refusal_row(tmp_path: Path) -> None:
    stub = tmp_path / "stub.py"
    stub.write_text("import sys; sys.exit(0)\n")
    policy_dir = tmp_path / "policies"
    policy_dir.mkdir()
    manifest = tmp_path / "plugins" / "alfred.fixture" / "manifest.toml"
    manifest.parent.mkdir(parents=True)
    manifest.write_text(
        """[alfred]
manifest_version = 1
[plugin]
id = "alfred.fixture"
subscriber_tier = "user-plugin"
sandbox_profile = "user-plugin"
"""
    )
    result = _spawn_with_fd3(stub, manifest, policy_dir, key=b"sk-x")
    assert result.returncode != 0
    assert '"event":"supervisor.plugin.sandbox_refused"' in result.stderr
    assert "sandbox_block_missing" in result.stderr
