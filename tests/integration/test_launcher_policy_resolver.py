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
def _adequate_policy_body() -> str:
    binds = ['["/usr", "/usr"]', '["/lib", "/lib"]']
    for extra in ("/lib64", "/bin"):
        if Path(extra).exists():
            binds.append(f'["{extra}", "{extra}"]')
    binds.append(f'["{_REPO_ROOT / "src"}", "{_REPO_ROOT / "src"}"]')
    return (
        "ro_binds = [\n  " + ",\n  ".join(binds) + "\n]\n"
        'tmpfs = ["/tmp"]\n'
        # test-1 vector 3 (CR PR #229 finding-3): ``net`` is unshared so the
        # sandboxed plugin runs in an empty network namespace — no host route,
        # so an outbound connect is kernel-contained, not policy-checked.
        'unshare = ["pid", "uts", "cgroup", "ipc", "net"]\n'
        "die_with_parent = true\n"
        "keep_fds = [3]\n"
    )


def _fixture_manifest(tmp_path: Path) -> tuple[Path, Path]:
    """Write the manifest + an adequate policy under a tmp policy root.

    Returns ``(manifest_path, policy_dir)``. The policy_dir is passed to the
    launcher via ``ALFRED_SANDBOX_POLICY_DIR`` so confinement resolves the
    policy_ref relative to it.
    """
    policy_dir = tmp_path / "policies"
    policy_dir.mkdir()
    (policy_dir / "fixture.linux.bwrap.policy").write_text(_adequate_policy_body())

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


def _spawn_with_fd3(
    stub: Path, manifest: Path, policy_dir: Path, key: bytes
) -> subprocess.CompletedProcess[str]:
    """Spawn the launcher with the framed provider key delivered over fd 3."""
    read_fd, write_fd = os.pipe()
    proc = subprocess.Popen(  # noqa: S603 — repo-owned launcher script path
        [str(_LAUNCHER), "alfred.fixture", sys.executable, str(stub)],
        env=_launcher_env(manifest, policy_dir),
        pass_fds=(read_fd,),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=str(_REPO_ROOT),
    )
    os.close(read_fd)
    # CR #229 R2 finding-7: if os.write raises (e.g. EPIPE when the launcher
    # dies early), write_fd would leak. try/finally guarantees the close.
    try:
        os.write(write_fd, struct.pack(">I", len(key)))
        os.write(write_fd, key)
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
    manifest, policy_dir = _fixture_manifest(tmp_path)
    result = _spawn_with_fd3(stub, manifest, policy_dir, key=b"sk-x")
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
