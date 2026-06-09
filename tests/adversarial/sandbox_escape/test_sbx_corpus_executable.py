"""Executable counterparts to the sbx-2026-* sandbox-escape payloads (PR-S4-6).

The YAML payloads are density- + schema-validated elsewhere, but neither
EXERCISES the runtime defence. This module loads each PR-S4-6 payload and
drives the REAL launcher / manifest parser / fd-3 delivery / session
handshake, asserting the declared ``expected_outcome`` actually fires at the
trust boundary — not just a Pydantic refusal at parse time.

PR-S4-7 ships the kernel-observable bwrap-escape payloads (filesystem,
network, process-fork); those need the real policy bytes to be meaningful.
"""

from __future__ import annotations

import os
import shutil
import struct
import subprocess
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
import yaml

from alfred.plugins.errors import (
    ManifestSandboxMissingError,
    SandboxInfoHandshakeMismatch,
)
from alfred.plugins.manifest import parse_manifest
from alfred.plugins.manifest_reader import PolicyRefEscapesRoot, resolve_policy_ref
from alfred.plugins.sandbox_policy import policy_to_bwrap_flags, read_policy_toml
from alfred.plugins.session import AlfredPluginSession
from alfred.supervisor.fd3_key_delivery import (
    ProviderKeyDeliveryError,
    deliver_provider_key_via_fd3,
)
from tests.adversarial.payload_schema import AdversarialPayload

_DIR = Path(__file__).parent
_REPO_ROOT = Path(__file__).resolve().parents[3]
_LAUNCHER = _REPO_ROOT / "bin" / "alfred-plugin-launcher.sh"
_HAS_JQ = shutil.which("jq") is not None
_HAS_BWRAP = shutil.which("bwrap") is not None
_QUARANTINED_LINUX_POLICY = _REPO_ROOT / "config" / "sandbox" / "quarantined-llm.linux.bwrap.policy"


def _load(payload_id: str) -> AdversarialPayload:
    path = next(_DIR.glob(f"{payload_id.replace('-', '_')}*.yaml"))
    return AdversarialPayload.model_validate(yaml.safe_load(path.read_text()))


def _real_policy_flags_with_test_binds(plugin_dir: Path) -> list[str]:
    """bwrap flags from the REAL quarantined-LLM Linux policy + test binds.

    The shipped policy binds /usr, /lib, /lib64 (the system interpreter), but
    the corpus runs under the pytest venv interpreter (``sys.executable``) whose
    prefix + the stub's ``plugin_dir`` (pytest tmp_path) are NOT under those
    system binds. We therefore translate the REAL policy and APPEND the minimal
    extra ro_binds the test interpreter needs — never removing any of the
    policy's own confinement (no /etc, no /bin, unshare-pid/uts/cgroup/ipc,
    die_with_parent). This is the same templating the PR-S4-6 resolver fixture
    does; it keeps the escape assertions meaningful against the shipped bytes.

    We also DROP the policy's tmpfs (``/run/alfred/quarantined``) from the test
    flag set: creating it needs the path to exist as a mountpoint inside the
    fresh root, which is fine, but it is irrelevant to the filesystem/exec
    containment assertions and keeps the bwrap invocation minimal.
    """
    policy = read_policy_toml(_QUARANTINED_LINUX_POLICY.read_text())
    flags = policy_to_bwrap_flags(policy)
    # Prune (a) the --tmpfs <scratch> pair — irrelevant to containment, avoids a
    # mountpoint dependency in the test root — and (b) any --ro-bind whose SOURCE
    # does not exist on this host. The production policy targets x86-64 Debian
    # Bookworm where /lib64 is a real dir; on aarch64 /lib64 is absent and
    # --ro-bind /lib64 would fail "Can't find source path". The /usr + /lib binds
    # carry the loader on every arch via the usrmerge symlink, so the escape
    # assertions stay meaningful. (bwrap --ro-bind-try is a #230 schema item.)
    pruned: list[str] = []
    i = 0
    while i < len(flags):
        flag = flags[i]
        if flag == "--tmpfs":
            i += 2
            continue
        if flag == "--ro-bind" and not Path(flags[i + 1]).exists():
            i += 3
            continue
        if flag == "--ro-bind":
            pruned += flags[i : i + 3]
            i += 3
            continue
        pruned.append(flag)
        i += 1
    # Append the test-interpreter + plugin_dir binds. sys.prefix (venv),
    # sys.base_prefix (base interpreter the venv symlinks to), the realpath'd
    # interpreter root, and plugin_dir. Skip anything already under a system
    # bind so we never double-bind /usr.
    interp_roots = {
        sys.prefix,
        sys.base_prefix,
        str(Path(os.path.realpath(sys.executable)).parents[1]),
        str(plugin_dir),
    }
    appended_roots = [
        root
        for root in sorted(interp_roots)
        if Path(root).exists() and not root.startswith(("/usr", "/lib", "/bin"))
    ]
    # finding-3 (PR #231): the test broadens the read surface with interpreter +
    # plugin_dir binds. A venv-layout shift must NEVER let one of those resolve
    # under /etc or /bin and silently widen the sandbox's read surface — fail
    # loud here instead.
    assert not any(
        os.path.realpath(root).startswith(("/etc", "/bin")) for root in appended_roots
    ), f"test bind resolves under /etc or /bin — would widen the sandbox: {appended_roots}"
    extra: list[str] = []
    for root in appended_roots:
        extra += ["--ro-bind", root, root]
    return pruned + extra


def _run_under_real_policy(stub: Path, plugin_dir: Path) -> subprocess.CompletedProcess[str]:
    """Exec ``sys.executable stub`` under the REAL quarantined-LLM Linux policy.

    Runs bwrap directly with the shipped policy's flags (no launcher / fd-3
    dance needed — these probes assert filesystem/process containment, not key
    delivery). Returns the CompletedProcess so the caller asserts on stdout.
    """
    flags = _real_policy_flags_with_test_binds(plugin_dir)
    bwrap = shutil.which("bwrap")
    assert bwrap is not None  # gated by _HAS_BWRAP on every caller
    return subprocess.run(  # noqa: S603 — resolved bwrap path, repo-owned probe
        [bwrap, *flags, "--", sys.executable, str(stub)],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


def _run_launcher(manifest_body: str, *, environment: str, tmp_path: Path) -> tuple[int, str]:
    manifest = tmp_path / "manifest.toml"
    manifest.write_text(manifest_body)
    stub = tmp_path / "stub.sh"
    stub.write_text("#!/bin/sh\nexit 0\n")
    stub.chmod(0o755)
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "PYTHONPATH": str(_REPO_ROOT / "src"),
        "ALFRED_ENVIRONMENT": environment,
        "ALFRED_PLUGIN_MANIFEST_PATH": str(manifest),
    }
    # sec-keystone (CR PR #229 finding-1): FAKE_UNAME is a test-only shim that
    # the launcher REFUSES in production. Only set it outside production; in
    # production the launcher uses the real host OS (Linux on CI).
    if environment != "production":
        env["FAKE_UNAME"] = "Linux"
    proc = subprocess.run(  # noqa: S603 — repo-owned launcher script path
        [str(_LAUNCHER), "attacker.example", str(stub)],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    return proc.returncode, proc.stderr


def test_sbx_2026_001_sandbox_block_missing(tmp_path: Path) -> None:
    payload = _load("sbx-2026-001")
    assert payload.expected_outcome == "refused"
    # Parser-level: the missing block raises the dedicated error.
    with pytest.raises(ManifestSandboxMissingError):
        parse_manifest(payload.payload["manifest_toml"])
    # Launcher-level (the real subprocess): refuses with the audit reason.
    # CR #229 R2 finding-5: an explicit skip when jq is absent — degrading to
    # parser-only while still reporting green would silently weaken the
    # executable-corpus guarantee (the launcher defence would go unexercised).
    if not _HAS_JQ:
        pytest.skip("jq required for sbx-2026-001 launcher refusal assertion")
    rc, stderr = _run_launcher(
        payload.payload["manifest_toml"], environment="production", tmp_path=tmp_path
    )
    assert rc != 0
    assert "sandbox_block_missing" in stderr


@pytest.mark.skipif(not _HAS_JQ, reason="jq required for the launcher branch")
def test_sbx_2026_002_kind_stub_in_production(tmp_path: Path) -> None:
    payload = _load("sbx-2026-002")
    assert payload.expected_outcome == "refused"
    rc, stderr = _run_launcher(
        payload.payload["manifest_toml"], environment="production", tmp_path=tmp_path
    )
    assert rc != 0
    # low-1: a kind:stub production refusal uses the host-accurate reason
    # (``stub_kind_in_production``) — it must never reuse the windows-specific
    # key on a non-windows host.
    assert "stub_kind_in_production" in stderr
    assert "windows_stub_in_production" not in stderr


@pytest.mark.skipif(not _HAS_JQ, reason="jq required for the launcher branch")
def test_sbx_2026_010_fake_uname_production_bypass_refused(tmp_path: Path) -> None:
    """sec-keystone: ALFRED_ENVIRONMENT=production + FAKE_UNAME=Darwin must NOT
    force the non-Linux unsandboxed exec. The launcher refuses at the FAKE_UNAME
    gate before any host-OS branch.
    """
    payload = _load("sbx-2026-010")
    assert payload.expected_outcome == "refused"
    manifest = tmp_path / "manifest.toml"
    manifest.write_text(payload.payload["manifest_toml"])
    stub = tmp_path / "stub.sh"
    sentinel = tmp_path / "executed.marker"
    stub.write_text(f"#!/bin/sh\ntouch {sentinel}\nexit 0\n")
    stub.chmod(0o755)
    proc = subprocess.run(  # noqa: S603 — repo-owned launcher script path
        [str(_LAUNCHER), "attacker.example", str(stub)],
        capture_output=True,
        text=True,
        env={
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "PYTHONPATH": str(_REPO_ROOT / "src"),
            "ALFRED_ENVIRONMENT": "production",
            "ALFRED_PLUGIN_MANIFEST_PATH": str(manifest),
            "FAKE_UNAME": payload.payload["fake_uname"],
        },
        check=False,
    )
    assert proc.returncode != 0
    assert not sentinel.exists(), "plugin executed unsandboxed — bypass NOT closed"
    assert "fake_uname_in_production" in proc.stderr
    assert "PLUGIN_EXECUTED_UNSANDBOXED" not in proc.stdout
    assert "config_insecure" not in proc.stderr


def test_sbx_2026_007_policy_ref_traversal_refused(tmp_path: Path) -> None:
    payload = _load("sbx-2026-007")
    assert payload.expected_outcome == "refused"
    (tmp_path / "config" / "sandbox").mkdir(parents=True)
    with pytest.raises(PolicyRefEscapesRoot) as exc_info:
        resolve_policy_ref(payload.payload["policy_ref"], install_root=tmp_path)
    assert exc_info.value.reason == "policy_ref_escapes_root"


def test_sbx_2026_008_fd3_partial_write_refused() -> None:
    payload = _load("sbx-2026-008")
    assert payload.expected_outcome == "refused"
    from unittest.mock import patch

    read_fd, write_fd = os.pipe()
    try:
        # Simulate a short write: writev returns fewer bytes than the frame.
        with patch(
            "alfred.supervisor.fd3_key_delivery.os.writev",
            return_value=struct.calcsize(">I"),  # only the prefix made it
        ):
            with pytest.raises(ProviderKeyDeliveryError) as exc_info:
                deliver_provider_key_via_fd3(write_fd=write_fd, key="sk-truncated")
            assert exc_info.value.reason == "provider_key_delivery_failed"
    finally:
        os.close(read_fd)
        with pytest.raises(OSError):
            os.close(write_fd)  # already closed by the refusal path


@pytest.mark.asyncio
async def test_sbx_2026_009_sandbox_info_lie_quarantined() -> None:
    payload = _load("sbx-2026-009")
    assert payload.expected_outcome == "quarantined"
    audit = MagicMock()
    audit.calls = []

    async def _append(**kwargs):
        audit.calls.append(kwargs)

    audit.append_schema = AsyncMock(side_effect=_append)
    gate = MagicMock()
    gate.check_plugin_load = MagicMock(return_value=True)
    transport = MagicMock()
    transport.kill = AsyncMock(return_value=True)

    manifest = """
[alfred]
manifest_version = 1
[plugin]
id = "attacker.example"
subscriber_tier = "user-plugin"
sandbox_profile = "user-plugin"
[sandbox]
kind = "none"
"""
    session = await AlfredPluginSession.create(
        manifest_raw=manifest, audit_writer=audit, gate=gate, transport=transport
    )
    await session._on_handshake_complete()
    with pytest.raises(SandboxInfoHandshakeMismatch):
        await session._on_post_handshake_method(
            "sandbox_info",
            {"effective_sandbox_kind": payload.payload["reported_effective_sandbox_kind"]},
        )
    transport.kill.assert_awaited_once()
    assert audit.calls[-1]["event"] == "plugin.lifecycle.quarantined"


def test_all_pr_s4_6_payloads_load() -> None:
    # Every PR-S4-6 sbx payload schema-validates + carries the sbx prefix.
    ids = [
        "sbx-2026-001",
        "sbx-2026-002",
        "sbx-2026-007",
        "sbx-2026-008",
        "sbx-2026-009",
        "sbx-2026-010",
    ]
    for pid in ids:
        payload = _load(pid)
        assert payload.id == pid
        assert payload.category == "sandbox_escape"


# ---------------------------------------------------------------------------
# PR-S4-7 kernel-observable payloads — driven against the REAL shipped
# quarantined-LLM Linux policy bytes via bwrap. Skipped where bwrap is absent
# (macOS dev); run in CI (alfred-core image ships bubblewrap 0.8.0).
# ---------------------------------------------------------------------------

_bwrap_required = pytest.mark.skipif(
    not _HAS_BWRAP,
    reason="bwrap required for the kernel-observable PR-S4-7 sandbox-escape payloads",
)


@_bwrap_required
def test_sbx_2026_003_host_etc_passwd_read_contained(tmp_path: Path) -> None:
    payload = _load("sbx-2026-003")
    assert payload.expected_outcome == "refused"
    stub = tmp_path / "probe.py"
    stub.write_text(
        "import sys\n"
        "try:\n"
        "    open('/etc/passwd').read()\n"
        "    print('READ_OK', flush=True)\n"
        "    sys.exit(1)\n"
        "except OSError:\n"
        "    print('BLOCKED', flush=True)\n"
        "    sys.exit(0)\n"
    )
    result = _run_under_real_policy(stub, tmp_path)
    # finding-1: rc==0 proves the sandbox started; BLOCKED proves the probe ran
    # and the read was refused — neither a vacuous empty-stdout pass nor a crash.
    assert result.returncode == 0, result.stderr
    assert "READ_OK" not in result.stdout, "host /etc/passwd was readable — containment failed"
    assert "BLOCKED" in result.stdout, "stub did not run / read was not refused"


@_bwrap_required
def test_sbx_2026_004_host_bin_sh_exec_contained(tmp_path: Path) -> None:
    payload = _load("sbx-2026-004")
    assert payload.expected_outcome == "refused"
    stub = tmp_path / "probe.py"
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
    result = _run_under_real_policy(stub, tmp_path)
    # MEDIUM (PR #231 finding-1): a negative-only assertion (`EXEC_OK not in`)
    # passes VACUOUSLY if the bwrap sandbox never STARTS (empty stdout). Assert
    # the probe actually ran (rc==0, surfacing stderr on failure) AND the
    # affirmative containment sentinel so the test PROVES the exec was refused,
    # not merely that nothing happened.
    assert result.returncode == 0, result.stderr
    assert "EXEC_OK" not in result.stdout, "/bin/sh exec was NOT contained"
    assert "BLOCKED" in result.stdout, "stub did not run / exec was not refused"


@_bwrap_required
def test_usr_bin_exec_reachable_known_permissive_pending_230(tmp_path: Path) -> None:
    """finding-4 (PR #231): document the KNOWN-PERMISSIVE /usr/bin exec surface.

    The /bin/sh containment passes only because /bin is not bound. The broad
    ``/usr`` ro_bind, however, leaves ``/usr/bin/*`` exec-reachable inside the
    sandbox. We assert that reachability as a TRACKED FACT (not a surprise): a
    compromised quarantined process CAN exec ``/usr/bin/true`` today. The
    load-bearing exec containment is --unshare-pid + --die-with-parent, NOT the
    absence of exec targets. #230 tightens the interpreter bind to the exact
    CPython prefix; when it lands this test flips (the exec should then fail) —
    forcing the corpus to track the posture change rather than silently widen.
    """
    stub = tmp_path / "probe.py"
    stub.write_text(
        "import subprocess, sys\n"
        "r = subprocess.run(['/usr/bin/true'])\n"
        "print('USRBIN_EXEC_RC', r.returncode, flush=True)\n"
        "sys.exit(0)\n"
    )
    result = _run_under_real_policy(stub, tmp_path)
    assert result.returncode == 0, result.stderr
    # Known-permissive: /usr/bin/true is exec-reachable (rc 0) under the broad
    # /usr bind. If this stops being true, #230 likely landed — update the doc.
    assert "USRBIN_EXEC_RC 0" in result.stdout, (
        "/usr/bin/* is no longer exec-reachable — #230 may have tightened the "
        "/usr bind; update config/sandbox/README.md + this tracked-fact test"
    )


@_bwrap_required
def test_sbx_2026_006_host_proc_environ_read_contained(tmp_path: Path) -> None:
    # finding-2 (PR #231): the prior assertion (rc==0 + BLOCKED||READ_LEN) was
    # self-fulfilling — under --unshare-pid the probe can ONLY ever see its own
    # pid namespace, so it could never construct a host-env leak and "passed"
    # regardless of containment. We make it HONEST with the option-(a) marker
    # probe: seed a recognizable host-env secret in the PARENT env, then assert
    # that whatever /proc/1/environ the sandboxed process can read NEVER contains
    # that marker.
    #
    # The containment that makes this true under the SHIPPED policy is the MOUNT
    # namespace: the policy binds no /proc, so /proc/1/environ does not even
    # exist inside the sandbox and the read raises (verified in Debian Bookworm +
    # bwrap 0.8.0 — the probe gets ENOENT, MARKER_PRESENT False). The host init's
    # secret env is therefore unreachable. A regression that exposed host /proc
    # (or a host-side pid-1 read) would surface the marker and fail this test.
    payload = _load("sbx-2026-006")
    assert payload.expected_outcome == "refused"
    marker = "ALFRED_HOST_SECRET_MARKER=sbx2026006_leak_canary"
    stub = tmp_path / "probe.py"
    # Always print PROBE_RAN (proves the stub executed, not a vacuous empty pass)
    # and a MARKER_PRESENT verdict. The marker is seeded into the host-side
    # parent env; the assertion is that it never appears in the /proc/1/environ
    # the sandboxed process can read.
    stub.write_text(
        "import sys\n"
        "marker = b'sbx2026006_leak_canary'\n"
        "print('PROBE_RAN', flush=True)\n"
        "try:\n"
        "    data = open('/proc/1/environ', 'rb').read()\n"
        "    print('MARKER_PRESENT', marker in data, flush=True)\n"
        "except OSError:\n"
        "    print('MARKER_PRESENT', False, flush=True)\n"
        "sys.exit(0)\n"
    )
    env = {**os.environ, "ALFRED_HOST_SECRET_MARKER": "sbx2026006_leak_canary"}
    flags = _real_policy_flags_with_test_binds(tmp_path)
    bwrap = shutil.which("bwrap")
    assert bwrap is not None  # gated by _bwrap_required
    result = subprocess.run(  # noqa: S603 — resolved bwrap path, repo-owned probe
        [bwrap, *flags, "--", sys.executable, str(stub)],
        capture_output=True,
        text=True,
        timeout=30,
        env=env,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "PROBE_RAN" in result.stdout, "stub did not run — sandbox never started"
    assert "MARKER_PRESENT True" not in result.stdout, (
        f"host pid-1 env marker {marker!r} leaked into the sandbox — pid-namespace isolation failed"
    )
    assert "MARKER_PRESENT False" in result.stdout


def test_sbx_2026_011_policy_ref_symlink_follow_contained(tmp_path: Path) -> None:
    """A symlink whose realpath escapes the policy root is refused (no bwrap)."""
    payload = _load("sbx-2026-011")
    assert payload.expected_outcome == "refused"
    policy_root = tmp_path / "config" / "sandbox"
    policy_root.mkdir(parents=True)
    # Plant a symlink under the policy root pointing OUTSIDE it (the payload's
    # symlink_target). Use a real outside file so resolve(strict=True) succeeds
    # and the confinement check — not a broken-link OSError — is what refuses.
    outside = tmp_path / "outside_secret"
    outside.write_text("SHADOW\n")
    link = policy_root / "quarantined-llm.linux.bwrap.policy"
    link.symlink_to(outside)
    with pytest.raises(PolicyRefEscapesRoot) as exc_info:
        resolve_policy_ref(payload.payload["policy_ref"], install_root=tmp_path)
    assert exc_info.value.reason == "policy_ref_escapes_root"


def test_sbx_2026_005_outbound_network_documented_unrestricted() -> None:
    """sbx-2026-005 is the HONEST egress gap, not a defended vector (#230).

    The payload is ``out_of_scope=True`` with a #230 rationale: the real Linux
    policy does NOT --unshare-net (the quarantined LLM needs its own provider
    HTTPS egress). We assert the corpus records that limitation rather than a
    containment that does not exist — and that the SHIPPED policy genuinely
    omits ``net`` from its unshare set, so the out_of_scope claim stays honest.
    """
    payload = _load("sbx-2026-005")
    assert payload.out_of_scope is True
    assert payload.out_of_scope_rationale is not None
    assert "#230" in payload.out_of_scope_rationale
    policy = read_policy_toml(_QUARANTINED_LINUX_POLICY.read_text())
    assert "net" not in policy.unshare, (
        "policy now unshares net — sbx-2026-005 must flip from out_of_scope to a "
        "defended containment payload (#230 landed)"
    )


def test_all_pr_s4_7_payloads_load() -> None:
    # Every PR-S4-7 sbx payload schema-validates + carries the sbx prefix.
    ids = ["sbx-2026-003", "sbx-2026-004", "sbx-2026-005", "sbx-2026-006", "sbx-2026-011"]
    for pid in ids:
        payload = _load(pid)
        assert payload.id == pid
        assert payload.category == "sandbox_escape"
