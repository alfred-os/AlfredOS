"""Behavioural tests for the PR-S4-6 launcher sandbox flow (Component G).

Exercises the bash launcher end-to-end against fixture manifests + a fake
bwrap, covering: --self-test, environment read, dev-escape-hatch production
refusal (sec-1 truthy parity), and the kind:full/none/stub branches including
the --sync-fd 3 bwrap invocation and the cross-OS matrix (devops-2 _uname
shim).
"""

from __future__ import annotations

import shutil

import pytest

_FULL_MANIFEST = """[alfred]
manifest_version = 1
[plugin]
id = "alfred.example"
subscriber_tier = "user-plugin"
sandbox_profile = "user-plugin"
[sandbox]
kind = "full"
[sandbox.policy_refs]
linux = "config/sandbox/_fixtures/policy_resolver_test.linux.bwrap.policy"
macos = "config/sandbox/foo.macos.sb"
windows = "config/sandbox/foo.windows.stub.policy"
"""

_FULL_MANIFEST_LINUX_ONLY = """[alfred]
manifest_version = 1
[plugin]
id = "alfred.example"
subscriber_tier = "user-plugin"
sandbox_profile = "user-plugin"
[sandbox]
kind = "full"
[sandbox.policy_refs]
macos = "config/sandbox/foo.macos.sb"
"""

_NONE_MANIFEST = """[alfred]
manifest_version = 1
[plugin]
id = "alfred.example"
subscriber_tier = "user-plugin"
sandbox_profile = "user-plugin"
[sandbox]
kind = "none"
"""

_STUB_MANIFEST = """[alfred]
manifest_version = 1
[plugin]
id = "alfred.example"
subscriber_tier = "user-plugin"
sandbox_profile = "user-plugin"
[sandbox]
kind = "stub"
"""

_NO_SANDBOX_MANIFEST = """[alfred]
manifest_version = 1
[plugin]
id = "alfred.example"
subscriber_tier = "user-plugin"
sandbox_profile = "user-plugin"
"""


_HAS_JQ = shutil.which("jq") is not None
_requires_jq = pytest.mark.skipif(not _HAS_JQ, reason="jq required for sandbox-kind branching")


def _write_manifest(tmp_path, body: str):
    manifest = tmp_path / "manifest.toml"
    manifest.write_text(body)
    return manifest


def _stub_binary(tmp_path, exit_code: int = 0):
    stub = tmp_path / "stub.sh"
    stub.write_text(f"#!/bin/sh\nexit {exit_code}\n")
    stub.chmod(0o755)
    return stub


# --------------------------------------------------------------------------
# --self-test (flips the daemon boot probe)
# --------------------------------------------------------------------------


def test_self_test_returns_policy_resolving(run_launcher) -> None:
    result = run_launcher("--self-test")
    assert result.returncode == 0
    assert result.stdout.strip() == "policy-resolving"


# --------------------------------------------------------------------------
# environment read
# --------------------------------------------------------------------------


def test_refuses_when_environment_unset(run_launcher, tmp_path) -> None:
    stub = _stub_binary(tmp_path)
    result = run_launcher(
        "alfred.example",
        str(stub),
        env={"ALFRED_ETC_ENV_FILE": str(tmp_path / "absent")},
    )
    assert result.returncode != 0
    assert "daemon.boot.environment_not_set" in result.stderr


# --------------------------------------------------------------------------
# dev escape hatch — production refusal (sec-1 truthy parity)
# --------------------------------------------------------------------------


@pytest.mark.parametrize("truthy", ["1", "true", "TRUE", "yes", "on", " on "])
def test_unsandboxed_refused_in_production(run_launcher, tmp_path, truthy: str) -> None:
    stub = _stub_binary(tmp_path)
    result = run_launcher(
        "alfred.example",
        str(stub),
        env={
            "ALFRED_ENVIRONMENT": "production",
            "ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED": truthy,
        },
    )
    assert result.returncode != 0
    assert "supervisor.sandbox.unsandboxed_refused_in_production" in result.stderr
    assert "unsandboxed_env_set_in_production" in result.stderr


@pytest.mark.parametrize("falsy", ["0", "false", "no", "off", "", "garbage"])
@_requires_jq
def test_unsandboxed_falsy_not_treated_as_set(run_launcher, tmp_path, falsy: str) -> None:
    # A falsy UNSANDBOXED value must NOT trip the production refusal; the flow
    # proceeds to the manifest read (which here is kind:none → runs the stub).
    manifest = _write_manifest(tmp_path, _NONE_MANIFEST)
    stub = _stub_binary(tmp_path, exit_code=0)
    result = run_launcher(
        "alfred.example",
        str(stub),
        env={
            "ALFRED_ENVIRONMENT": "production",
            "ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED": falsy,
            "ALFRED_PLUGIN_MANIFEST_PATH": str(manifest),
        },
    )
    assert "unsandboxed_refused_in_production" not in result.stderr


# --------------------------------------------------------------------------
# kind:full → bwrap (fd 3 inherited by default, NO --sync-fd flag; issue #218)
# --------------------------------------------------------------------------


@_requires_jq
def test_kind_full_invokes_bwrap_without_fd_flag(run_launcher, tmp_path, echo_bwrap) -> None:
    # FAKE_UNAME=Linux so the Linux bwrap branch runs on any host (the real
    # bwrap binary is Linux-only; the fake echo-bwrap is portable).
    manifest = _write_manifest(tmp_path, _FULL_MANIFEST)
    stub = _stub_binary(tmp_path)
    result = run_launcher(
        "alfred.example",
        str(stub),
        env={
            "ALFRED_ENVIRONMENT": "test",
            "ALFRED_PLUGIN_MANIFEST_PATH": str(manifest),
            "BWRAP": str(echo_bwrap),
            "FAKE_UNAME": "Linux",
        },
    )
    assert result.returncode == 0, result.stderr
    assert "BWRAP_ARGS:" in result.stdout
    # The launcher's bwrap line carries the policy's isolation flags (binds,
    # unshare, die-with-parent) but NO fd flag: fd 3 is inherited by bwrap's
    # default fd inheritance. --sync-fd 3 would CONSUME fd 3 (issue #218).
    assert "--ro-bind" in result.stdout
    assert "--unshare-pid" in result.stdout
    assert "--die-with-parent" in result.stdout
    assert "--sync-fd" not in result.stdout
    assert "--keep-fd" not in result.stdout
    # WITHOUT opt-in (ALFRED_SANDBOX_BIND_INTERP_PREFIX unset), a generic kind:full
    # plugin gets NO extra interpreter-prefix bind: the sandbox namespace stays the
    # policy's static binds only, never widened to the executable's host subtree
    # (CR #250). Only the quarantine-child spawn opts in (see the opt-in test below).
    interp_prefix = stub.resolve().parent.parent
    assert f"--ro-bind {interp_prefix} {interp_prefix}" not in result.stdout
    # The exec target is the executable arg verbatim (no realpath rewrite either).
    assert str(stub) in result.stdout


@_requires_jq
def test_kind_full_binds_interpreter_prefix_when_opted_in(
    run_launcher, tmp_path, echo_bwrap
) -> None:
    """With ALFRED_SANDBOX_BIND_INTERP_PREFIX=1 the launcher ro-binds the resolved
    interpreter's install prefix and execs the realpath.

    This is the quarantine-child path (#248/ADR-0030): it execs a bound interpreter
    that may live OUTSIDE the policy's static /usr,/lib,/lib64 binds (a proto/uv
    python under ~/.proto), so its install prefix must be bound. Only the
    quarantine-child spawn (`_child_env`) sets the flag; generic kind:full plugins
    do not (asserted by `test_kind_full_invokes_bwrap_without_fd_flag`).
    """
    manifest = _write_manifest(tmp_path, _FULL_MANIFEST)
    stub = _stub_binary(tmp_path)
    result = run_launcher(
        "alfred.example",
        str(stub),
        env={
            "ALFRED_ENVIRONMENT": "test",
            "ALFRED_PLUGIN_MANIFEST_PATH": str(manifest),
            "BWRAP": str(echo_bwrap),
            "FAKE_UNAME": "Linux",
            "ALFRED_SANDBOX_BIND_INTERP_PREFIX": "1",
        },
    )
    assert result.returncode == 0, result.stderr
    interp_real = stub.resolve()
    interp_prefix = interp_real.parent.parent
    assert f"--ro-bind {interp_prefix} {interp_prefix}" in result.stdout
    # Exec target is the realpath (resolves a venv symlink to a bound target).
    assert str(interp_real) in result.stdout


@_requires_jq
def test_kind_full_opt_in_execs_realpath_of_symlinked_interpreter(
    run_launcher, tmp_path, echo_bwrap
) -> None:
    """Opt-in + a SYMLINKED interpreter → bind the REAL prefix + exec the realpath.

    The load-bearing reason the bind exists (ADR-0030): a uv-venv ``python3`` is a
    symlink whose target lives OUTSIDE the bound prefix and fails ``execvp`` under
    bwrap. The launcher must ro-bind ``dirname(dirname(realpath))`` — the REAL
    interpreter tree, not the symlink's venv dir — and exec the realpath, not the
    link. The plain-file opt-in test above can't prove this (arg == realpath).
    """
    real = tmp_path / "realprefix" / "bin" / "python3"
    real.parent.mkdir(parents=True)
    real.write_text("#!/bin/sh\nexit 0\n")
    real.chmod(0o755)
    link = tmp_path / "venv" / "bin" / "python3"
    link.parent.mkdir(parents=True)
    link.symlink_to(real)

    manifest = _write_manifest(tmp_path, _FULL_MANIFEST)
    result = run_launcher(
        "alfred.example",
        str(link),
        env={
            "ALFRED_ENVIRONMENT": "test",
            "ALFRED_PLUGIN_MANIFEST_PATH": str(manifest),
            "BWRAP": str(echo_bwrap),
            "FAKE_UNAME": "Linux",
            "ALFRED_SANDBOX_BIND_INTERP_PREFIX": "1",
        },
    )
    assert result.returncode == 0, result.stderr
    real_resolved = real.resolve()
    real_prefix = real_resolved.parent.parent
    # The bound prefix is the REAL interpreter tree, NOT the symlink's venv dir.
    assert f"--ro-bind {real_prefix} {real_prefix}" in result.stdout
    assert f"--ro-bind {link.parent.parent} " not in result.stdout
    # The exec target is the realpath, NOT the symlink arg.
    assert str(real_resolved) in result.stdout
    assert str(link) not in result.stdout


@_requires_jq
def test_kind_full_refuses_root_level_interpreter_prefix(
    run_launcher, tmp_path, echo_bwrap
) -> None:
    """Opt-in + an interpreter whose prefix resolves to ``/`` → fail-closed refusal.

    A root-level interpreter (realpath one dir below ``/``) yields a ``/`` install
    prefix that would ro-bind the ENTIRE host root into the sandbox (re-exposing
    ``/etc``, ``/proc`` mounts the policy omits). The launcher must refuse LOUDLY
    (hard rule #7) and NEVER reach the bwrap exec. ``/`` is the portable depth-1
    realpath: ``readlink -f /`` == ``/`` and ``dirname(dirname(/))`` == ``/``.
    """
    manifest = _write_manifest(tmp_path, _FULL_MANIFEST)
    result = run_launcher(
        "alfred.example",
        "/",
        env={
            "ALFRED_ENVIRONMENT": "test",
            "ALFRED_PLUGIN_MANIFEST_PATH": str(manifest),
            "BWRAP": str(echo_bwrap),
            "FAKE_UNAME": "Linux",
            "ALFRED_SANDBOX_BIND_INTERP_PREFIX": "1",
        },
    )
    assert result.returncode != 0
    assert "supervisor.sandbox.refused.interpreter_prefix_too_broad" in result.stderr
    assert '"reason":"interpreter_prefix_too_broad"' in result.stderr
    # Refused BEFORE the bwrap exec: the fake bwrap never ran, so no host-root bind.
    assert "BWRAP_ARGS:" not in result.stdout
    assert "--ro-bind / /" not in result.stdout


@_requires_jq
def test_kind_full_policy_ref_missing_for_host_os(run_launcher, tmp_path) -> None:
    # Manifest declares only macos; on a Linux runner the linux key is absent.
    manifest = _write_manifest(tmp_path, _FULL_MANIFEST_LINUX_ONLY)
    stub = _stub_binary(tmp_path)
    result = run_launcher(
        "alfred.example",
        str(stub),
        env={
            "ALFRED_ENVIRONMENT": "test",
            "ALFRED_PLUGIN_MANIFEST_PATH": str(manifest),
            "FAKE_UNAME": "Linux",
        },
    )
    assert result.returncode != 0
    assert "policy_ref_missing" in result.stderr


@_requires_jq
def test_policy_schema_refusal_audit_row_carries_the_real_reason(run_launcher, tmp_path) -> None:
    """#428: a policy-translate failure is audited under the schema's OWN reason,
    not the hardcoded policy_ref_unreadable, which mislabels all five PRE-EXISTING
    schema refusals (this PR adds a sixth, bind_source_too_broad).
    """
    (tmp_path / "bad.linux.bwrap.policy").write_text(
        'ro_binds_try = [["/etc/ssl/certs", "/etc/ssl/certs"]]\nkeep_fds = [3]\n'
    )
    manifest_body = _FULL_MANIFEST.replace(
        'linux = "config/sandbox/_fixtures/policy_resolver_test.linux.bwrap.policy"',
        'linux = "bad.linux.bwrap.policy"',
    )
    manifest = _write_manifest(tmp_path, manifest_body)
    result = run_launcher(
        "alfred.example",
        "/usr/bin/python3",
        env={
            "ALFRED_ENVIRONMENT": "test",
            "ALFRED_PLUGIN_MANIFEST_PATH": str(manifest),
            "ALFRED_SANDBOX_POLICY_DIR": str(tmp_path),
            "FAKE_UNAME": "Linux",
        },
    )
    assert result.returncode != 0
    assert '"reason":"soft_bind_forbidden_path"' in result.stderr
    assert '"reason":"policy_ref_unreadable"' not in result.stderr


# --------------------------------------------------------------------------
# kind:stub
# --------------------------------------------------------------------------


@_requires_jq
def test_kind_stub_refused_in_production(run_launcher, tmp_path) -> None:
    manifest = _write_manifest(tmp_path, _STUB_MANIFEST)
    stub = _stub_binary(tmp_path)
    result = run_launcher(
        "alfred.example",
        str(stub),
        env={
            "ALFRED_ENVIRONMENT": "production",
            "ALFRED_PLUGIN_MANIFEST_PATH": str(manifest),
        },
    )
    assert result.returncode != 0
    # low-1: host-accurate reason on a non-windows host (this runs on the real
    # host OS; the kind:stub branch is host-agnostic).
    assert "stub_kind_in_production" in result.stderr


@_requires_jq
def test_kind_stub_emits_stub_used_in_development(run_launcher, tmp_path) -> None:
    manifest = _write_manifest(tmp_path, _STUB_MANIFEST)
    stub = _stub_binary(tmp_path, exit_code=7)
    result = run_launcher(
        "alfred.example",
        str(stub),
        env={
            "ALFRED_ENVIRONMENT": "development",
            "ALFRED_PLUGIN_MANIFEST_PATH": str(manifest),
        },
    )
    assert result.returncode == 7  # the stub exec'd
    assert "supervisor.plugin.sandbox_stub_used" in result.stderr


# --------------------------------------------------------------------------
# missing [sandbox] block
# --------------------------------------------------------------------------


@_requires_jq
def test_missing_sandbox_block_refused(run_launcher, tmp_path) -> None:
    manifest = _write_manifest(tmp_path, _NO_SANDBOX_MANIFEST)
    stub = _stub_binary(tmp_path)
    result = run_launcher(
        "alfred.example",
        str(stub),
        env={
            "ALFRED_ENVIRONMENT": "test",
            "ALFRED_PLUGIN_MANIFEST_PATH": str(manifest),
        },
    )
    assert result.returncode != 0
    assert "sandbox_block_missing" in result.stderr


# --------------------------------------------------------------------------
# cross-OS matrix (devops-2) — FAKE_UNAME shim
# --------------------------------------------------------------------------


@_requires_jq
def test_macos_full_refuses_not_yet_shipped(run_launcher, tmp_path) -> None:
    manifest = _write_manifest(tmp_path, _FULL_MANIFEST)
    stub = _stub_binary(tmp_path)
    result = run_launcher(
        "alfred.example",
        str(stub),
        env={
            "ALFRED_ENVIRONMENT": "test",
            "ALFRED_PLUGIN_MANIFEST_PATH": str(manifest),
            "FAKE_UNAME": "Darwin",
        },
    )
    assert result.returncode != 0
    assert "macos_full_not_yet_shipped" in result.stderr


@_requires_jq
def test_windows_full_dev_stub_used(run_launcher, tmp_path) -> None:
    manifest = _write_manifest(tmp_path, _FULL_MANIFEST)
    stub = _stub_binary(tmp_path, exit_code=5)
    result = run_launcher(
        "alfred.example",
        str(stub),
        env={
            "ALFRED_ENVIRONMENT": "development",
            "ALFRED_PLUGIN_MANIFEST_PATH": str(manifest),
            "FAKE_UNAME": "Windows_NT",
        },
    )
    assert result.returncode == 5
    assert "sandbox_stub_used" in result.stderr


@_requires_jq
def test_windows_full_production_refused_via_fake_uname_gate(run_launcher, tmp_path) -> None:
    """sec-keystone: FAKE_UNAME in production is now refused at the gate, BEFORE
    the windows kind:full branch. The Windows-production refusal is no longer
    reachable via FAKE_UNAME — that was precisely the bypass vector. A genuine
    Windows production host (no FAKE_UNAME) still hits ``windows_stub_in_-
    production`` in the kind:full branch; that path is exercised in CI on the
    real OS matrix, not via the shim.
    """
    manifest = _write_manifest(tmp_path, _FULL_MANIFEST)
    stub = _stub_binary(tmp_path)
    result = run_launcher(
        "alfred.example",
        str(stub),
        env={
            "ALFRED_ENVIRONMENT": "production",
            "ALFRED_PLUGIN_MANIFEST_PATH": str(manifest),
            "FAKE_UNAME": "Windows_NT",
        },
    )
    assert result.returncode != 0
    assert "fake_uname_in_production" in result.stderr


# --------------------------------------------------------------------------
# sec-keystone (CR PR #229 finding-1) — FAKE_UNAME production-bypass refusals
# --------------------------------------------------------------------------


@_requires_jq
def test_fake_uname_in_production_refuses_kind_none_bypass(run_launcher, tmp_path) -> None:
    """The keystone: ALFRED_ENVIRONMENT=production FAKE_UNAME=Darwin + kind:none
    must REFUSE rather than force the non-Linux unsandboxed exec.

    Before the fix this combination dropped into the non-Linux ``_do_exec``
    branch and exec'd the plugin WITHOUT the runuser UID-drop, emitting only an
    advisory ``config_insecure`` row (PLUGIN_EXECUTED_UNSANDBOXED, exit 0). The
    fix gates FAKE_UNAME to non-production and refuses loudly.
    """
    manifest = _write_manifest(tmp_path, _NONE_MANIFEST)
    stub = _stub_binary(tmp_path)
    sentinel = tmp_path / "executed.marker"
    # If the plugin ever runs, it touches the sentinel — proving the bypass.
    stub.write_text(f"#!/bin/sh\ntouch {sentinel}\nexit 0\n")
    stub.chmod(0o755)
    result = run_launcher(
        "alfred.example",
        str(stub),
        env={
            "ALFRED_ENVIRONMENT": "production",
            "FAKE_UNAME": "Darwin",
            "ALFRED_PLUGIN_MANIFEST_PATH": str(manifest),
        },
    )
    assert result.returncode != 0
    assert not sentinel.exists(), "plugin executed unsandboxed — the bypass is NOT closed"
    assert "fake_uname_in_production" in result.stderr
    # The advisory config_insecure row must NOT be the audit reason here.
    assert "config_insecure" not in result.stderr
    assert "PLUGIN_EXECUTED_UNSANDBOXED" not in result.stdout
    assert '"event":"supervisor.plugin.sandbox_refused"' in result.stderr


@_requires_jq
def test_fake_uname_in_production_refused_before_manifest_branch(run_launcher, tmp_path) -> None:
    """FAKE_UNAME in production is refused even with no manifest path — the gate
    fires before any host-OS or kind branch."""
    stub = _stub_binary(tmp_path)
    result = run_launcher(
        "alfred.example",
        str(stub),
        env={
            "ALFRED_ENVIRONMENT": "production",
            "FAKE_UNAME": "Linux",
        },
    )
    assert result.returncode != 0
    assert "fake_uname_in_production" in result.stderr


@_requires_jq
def test_fake_uname_ignored_in_production_real_uname_wins(run_launcher, tmp_path) -> None:
    """Even if the gate were bypassed, the _uname shim ignores FAKE_UNAME in
    production. This asserts the refusal reason is the FAKE_UNAME gate (not a
    downstream host-OS branch), proving the shim never honoured ``Darwin``."""
    manifest = _write_manifest(tmp_path, _FULL_MANIFEST)
    stub = _stub_binary(tmp_path)
    result = run_launcher(
        "alfred.example",
        str(stub),
        env={
            "ALFRED_ENVIRONMENT": "production",
            "FAKE_UNAME": "Darwin",
            "ALFRED_PLUGIN_MANIFEST_PATH": str(manifest),
        },
    )
    assert result.returncode != 0
    # macos_full_not_yet_shipped would prove the shim honoured Darwin — it MUST NOT.
    assert "macos_full_not_yet_shipped" not in result.stderr
    assert "fake_uname_in_production" in result.stderr


@_requires_jq
def test_kind_none_dev_non_linux_emits_stub_used_not_config_insecure(
    run_launcher, tmp_path
) -> None:
    """Dev/test on a non-Linux host may exec kind:none unsandboxed, but with an
    honest ``sandbox_stub_used`` row (low-1) — NOT the old advisory
    ``config_insecure`` row."""
    manifest = _write_manifest(tmp_path, _NONE_MANIFEST)
    stub = _stub_binary(tmp_path, exit_code=4)
    result = run_launcher(
        "alfred.example",
        str(stub),
        env={
            "ALFRED_ENVIRONMENT": "development",
            "FAKE_UNAME": "Darwin",
            "ALFRED_PLUGIN_MANIFEST_PATH": str(manifest),
        },
    )
    assert result.returncode == 4  # the stub exec'd (dev path)
    assert "supervisor.plugin.sandbox_stub_used" in result.stderr
    assert "uid_separation_unavailable" in result.stderr
    assert "config_insecure" not in result.stderr


@_requires_jq
def test_kind_none_production_non_linux_refuses(run_launcher, tmp_path) -> None:
    """A genuine non-Linux production host (no FAKE_UNAME) refuses kind:none —
    the second defense layer: _do_exec's non-Linux branch refuses in production
    with the host-accurate ``uid_separation_unavailable`` reason.

    Simulated here by forcing the non-Linux branch in DEVELOPMENT is impossible
    (dev execs), so this test relies on the host: it is meaningful only on a
    genuine non-Linux host. On Linux it is skipped.
    """
    import platform

    if platform.system() == "Linux":
        pytest.skip("non-Linux _do_exec production refusal only observable off-Linux")
    manifest = _write_manifest(tmp_path, _NONE_MANIFEST)
    stub = _stub_binary(tmp_path)
    sentinel = tmp_path / "executed.marker"
    stub.write_text(f"#!/bin/sh\ntouch {sentinel}\nexit 0\n")
    stub.chmod(0o755)
    result = run_launcher(
        "alfred.example",
        str(stub),
        env={
            "ALFRED_ENVIRONMENT": "production",
            "ALFRED_PLUGIN_MANIFEST_PATH": str(manifest),
        },
    )
    assert result.returncode != 0
    assert not sentinel.exists()
    assert "uid_separation_unavailable" in result.stderr
    assert "windows_stub_in_production" not in result.stderr  # low-1: host-accurate


@_requires_jq
def test_stub_kind_production_uses_host_accurate_reason(run_launcher, tmp_path) -> None:
    """low-1: the generic kind:stub production refusal uses a host-accurate
    reason (``stub_kind_in_production``), not the windows-specific key, on a
    non-windows host."""
    manifest = _write_manifest(tmp_path, _STUB_MANIFEST)
    stub = _stub_binary(tmp_path)
    # FAKE_UNAME in production is refused BEFORE the kind branch — assert that
    # gate fires (CR nitpick: don't leave this first call as dead code).
    gated = run_launcher(
        "alfred.example",
        str(stub),
        env={
            "ALFRED_ENVIRONMENT": "production",
            "FAKE_UNAME": "Linux",
            "ALFRED_PLUGIN_MANIFEST_PATH": str(manifest),
        },
    )
    assert gated.returncode != 0
    assert "fake_uname_in_production" in gated.stderr

    # Without FAKE_UNAME the stub branch is reached on the real host, and the
    # generic refusal uses the host-accurate ``stub_kind_in_production`` key
    # (NOT the windows-specific one) on a non-windows host.
    result = run_launcher(
        "alfred.example",
        str(stub),
        env={
            "ALFRED_ENVIRONMENT": "production",
            "ALFRED_PLUGIN_MANIFEST_PATH": str(manifest),
        },
    )
    assert result.returncode != 0
    assert "stub_kind_in_production" in result.stderr
    assert "windows_stub_in_production" not in result.stderr


def test_unknown_host_os_refused(run_launcher, tmp_path) -> None:
    stub = _stub_binary(tmp_path)
    result = run_launcher(
        "alfred.example",
        str(stub),
        env={
            "ALFRED_ENVIRONMENT": "test",
            "FAKE_UNAME": "Plan9",
        },
    )
    assert result.returncode != 0
    assert "unknown_host_os" in result.stderr
    # CR #229 R2 finding-10: the unknown-host-OS refusal also emits a
    # structured audit JSON row matching the other refusal rows' shape.
    assert '"event":"supervisor.plugin.sandbox_refused"' in result.stderr
    assert '"reason":"unknown_host_os"' in result.stderr
    assert '"host_os":"unknown"' in result.stderr
    assert '"environment":"test"' in result.stderr


# --------------------------------------------------------------------------
# preserved Slice-3 invariants
# --------------------------------------------------------------------------


def test_invalid_plugin_id_refused(run_launcher, tmp_path) -> None:
    stub = _stub_binary(tmp_path)
    result = run_launcher(
        'bad"id',
        str(stub),
        env={"ALFRED_ENVIRONMENT": "test"},
    )
    assert result.returncode != 0
    assert "plugin.launcher_plugin_id_invalid" in result.stderr


@pytest.mark.parametrize("flag", ["-h", "--help"])
def test_help_flag(run_launcher, flag: str) -> None:
    result = run_launcher(flag)
    assert result.returncode == 0
    assert "alfred-plugin-launcher.sh" in result.stdout
