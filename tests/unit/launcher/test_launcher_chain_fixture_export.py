"""Prove the arch-1 cross-PR contract: launcher_chain_fixture is importable.

PR-S4-7's policy-translation tests import ``launcher_chain_fixture`` from the
root conftest. Without it they don't compile. This test exercises the fixture
the same way PR-S4-7 will, so a regression that drops or renames it fails
here in PR-S4-6 rather than silently breaking PR-S4-7.
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

_NONE_MANIFEST = """[alfred]
manifest_version = 1
[plugin]
id = "alfred.example"
subscriber_tier = "user-plugin"
sandbox_profile = "user-plugin"
[sandbox]
kind = "none"
"""

_requires_jq = pytest.mark.skipif(
    shutil.which("jq") is None, reason="jq required for the launcher chain"
)


@_requires_jq
def test_fixture_runs_full_kind_through_bwrap(launcher_chain_fixture) -> None:
    result = launcher_chain_fixture(_FULL_MANIFEST)
    assert result.returncode == 0, result.stderr
    assert "--sync-fd 3" in result.stdout


@_requires_jq
def test_fixture_reports_refusal_on_missing_block(launcher_chain_fixture) -> None:
    no_sandbox = """[alfred]
manifest_version = 1
[plugin]
id = "alfred.example"
subscriber_tier = "user-plugin"
sandbox_profile = "user-plugin"
"""
    result = launcher_chain_fixture(no_sandbox)
    assert result.returncode != 0
    assert "sandbox_block_missing" in result.stderr


@_requires_jq
def test_fixture_env_extra_override(launcher_chain_fixture) -> None:
    # kind:none in production still execs (the stub exits 0). Proves env_extra
    # threads through.
    result = launcher_chain_fixture(_NONE_MANIFEST, env_extra={"ALFRED_ENVIRONMENT": "production"})
    # On macOS the _do_exec path runs the stub directly (exit 0); on Linux
    # with runuser absent it refuses. Either way the env_extra was honoured —
    # assert no production-unsandboxed refusal fired.
    assert "unsandboxed_refused_in_production" not in result.stderr
