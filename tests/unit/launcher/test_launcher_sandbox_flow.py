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
# kind:full → bwrap --sync-fd 3
# --------------------------------------------------------------------------


@_requires_jq
def test_kind_full_invokes_bwrap_with_sync_fd_3(run_launcher, tmp_path, echo_bwrap) -> None:
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
    assert "--sync-fd 3" in result.stdout


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
    assert "windows_stub_in_production" in result.stderr


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
def test_windows_full_production_refused(run_launcher, tmp_path) -> None:
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
    assert "windows_stub_in_production" in result.stderr


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
