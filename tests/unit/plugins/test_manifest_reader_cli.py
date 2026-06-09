"""Pre-launcher ``manifest_reader`` CLI helper (PR-S4-6 Component C, spec §7.2).

``bin/alfred-plugin-launcher.sh`` shells out to
``python3 -m alfred.plugins.manifest_reader <subcommand>`` to read the
manifest's ``[sandbox]`` block, resolve ``Settings.environment``, and
translate a policy file into bwrap flags — keeping the trust-tier-tagging
surface in Python (testable) rather than in bash.

Every refusal emits a bare i18n key on stderr + a non-zero exit so the bash
launcher can capture stderr and the supervisor can render the localised
message.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]

_FULL_MANIFEST = """[alfred]
manifest_version = 1
[plugin]
id = "alfred.example"
subscriber_tier = "user-plugin"
sandbox_profile = "user-plugin"
[sandbox]
kind = "full"
[sandbox.policy_refs]
linux = "config/sandbox/foo.linux.bwrap.policy"
macos = "config/sandbox/foo.macos.sb"
windows = "config/sandbox/foo.windows.stub.policy"
"""

_NO_SANDBOX_MANIFEST = """[alfred]
manifest_version = 1
[plugin]
id = "alfred.example"
subscriber_tier = "user-plugin"
sandbox_profile = "user-plugin"
"""


def _run(*args: str, env: dict[str, str] | None = None, stdin: str | None = None):
    base_env = {"PYTHONPATH": str(REPO_ROOT / "src"), "PATH": "/usr/bin:/bin"}
    if env:
        base_env.update(env)
    return subprocess.run(  # noqa: S603 — sys.executable + repo-owned module path
        [sys.executable, "-m", "alfred.plugins.manifest_reader", *args],
        capture_output=True,
        text=True,
        env=base_env,
        input=stdin,
        check=False,
    )


# --------------------------------------------------------------------------
# --read-sandbox
# --------------------------------------------------------------------------


def test_read_sandbox_emits_json(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest.toml"
    manifest.write_text(_FULL_MANIFEST)
    result = _run("--read-sandbox", "--manifest-path", str(manifest))
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["kind"] == "full"
    assert payload["policy_refs"]["linux"].endswith(".bwrap.policy")


def test_read_sandbox_missing_block_refuses(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest.toml"
    manifest.write_text(_NO_SANDBOX_MANIFEST)
    result = _run("--read-sandbox", "--manifest-path", str(manifest))
    assert result.returncode != 0
    assert "plugin.manifest_sandbox_block_missing" in result.stderr


def test_read_sandbox_malformed_toml_refuses(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest.toml"
    manifest.write_text("this is = = not toml [[[")
    result = _run("--read-sandbox", "--manifest-path", str(manifest))
    assert result.returncode != 0
    assert "plugin.manifest_invalid" in result.stderr


def test_read_sandbox_nonexistent_path_refuses(tmp_path: Path) -> None:
    result = _run("--read-sandbox", "--manifest-path", str(tmp_path / "nope.toml"))
    assert result.returncode != 0
    # Exact bare key (CR #229 R2 finding-8): a closed-vocab key regression must
    # fail here rather than slip past a generic substring check.
    assert "plugin.manifest_unreadable" in result.stderr


def test_read_sandbox_by_plugin_id_resolves_dir(tmp_path: Path) -> None:
    # plugin-id maps to plugins/<id_with_dots_and_hyphens_as_underscores>/.
    plugin_dir = tmp_path / "alfred_example"
    plugin_dir.mkdir()
    (plugin_dir / "manifest.toml").write_text(_FULL_MANIFEST)
    result = _run(
        "--read-sandbox",
        "--plugin-id",
        "alfred.example",
        env={"ALFRED_PLUGINS_DIR": str(tmp_path)},
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["kind"] == "full"


def test_read_sandbox_unsafe_plugin_id_refused() -> None:
    # Charset gate: a plugin-id with path-traversal characters is refused
    # before any filesystem lookup, with the exact bare key (CR #229 R2 f-8).
    result = _run("--read-sandbox", "--plugin-id", "../../etc/passwd")
    assert result.returncode != 0
    assert "plugin.launcher_plugin_id_invalid" in result.stderr


# --------------------------------------------------------------------------
# --read-environment
# --------------------------------------------------------------------------


def test_read_environment_emits_value() -> None:
    result = _run("--read-environment", env={"ALFRED_ENVIRONMENT": "development"})
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "development"


def test_read_environment_file_source(tmp_path: Path) -> None:
    env_file = tmp_path / "environment"
    env_file.write_text("production\n")
    result = _run(
        "--read-environment",
        env={"ALFRED_ETC_ENV_FILE": str(env_file)},
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "production"


def test_read_environment_unset_refuses(tmp_path: Path) -> None:
    result = _run(
        "--read-environment",
        env={"ALFRED_ETC_ENV_FILE": str(tmp_path / "no-file")},
    )
    assert result.returncode != 0
    assert "daemon.boot.environment_not_set" in result.stderr


def test_read_environment_unrecognised_refuses(tmp_path: Path) -> None:
    result = _run(
        "--read-environment",
        env={
            "ALFRED_ENVIRONMENT": "staging",
            "ALFRED_ETC_ENV_FILE": str(tmp_path / "no-file"),
        },
    )
    assert result.returncode != 0
    assert "environment" in result.stderr


# --------------------------------------------------------------------------
# --policy-to-bwrap-flags
# --------------------------------------------------------------------------


def test_policy_to_bwrap_flags_one_per_line() -> None:
    policy = 'keep_fds = [3]\ntmpfs = ["/tmp"]\n'
    result = _run("--policy-to-bwrap-flags", stdin=policy)
    assert result.returncode == 0, result.stderr
    lines = result.stdout.splitlines()
    assert "--keep-fd" in lines
    assert "3" in lines
    assert "--tmpfs" in lines


def test_policy_to_bwrap_flags_malformed_refuses() -> None:
    result = _run("--policy-to-bwrap-flags", stdin="keep_fds = []\n")
    assert result.returncode != 0
    assert "kind_full_requires_keep_fd_3" in result.stderr


def test_policy_to_bwrap_flags_bad_toml_refuses() -> None:
    result = _run("--policy-to-bwrap-flags", stdin="not = = toml [[[")
    assert result.returncode != 0


def test_policy_ref_escapes_root_refuses_with_exact_key(tmp_path: Path) -> None:
    # A confined --policy-ref pointing outside the root is refused with the
    # stable bare key (closed-vocab; not a rendered sentence).
    (tmp_path / "config" / "sandbox").mkdir(parents=True)
    result = _run(
        "--policy-to-bwrap-flags",
        "--policy-ref",
        "../../../etc/passwd",
        "--install-root",
        str(tmp_path),
    )
    assert result.returncode != 0
    assert "supervisor.sandbox.refused.policy_ref_escapes_root" in result.stderr


def test_policy_ref_unreadable_after_resolution_refuses(tmp_path: Path) -> None:
    # CR #229 R2 finding-1: resolve_policy_ref succeeds (the file is a real
    # regular file under the root) but read_text() then raises (here: the file
    # is chmod 0o000). The CLI must emit the stable ``policy_ref_unreadable``
    # bare key + nonzero exit, NOT leak an OSError traceback into the launcher's
    # stderr detail (which would break the bare-key contract).
    policy_dir = tmp_path / "config" / "sandbox"
    policy_dir.mkdir(parents=True)
    policy_file = policy_dir / "locked.linux.bwrap.policy"
    policy_file.write_text("keep_fds = [3]\n")
    policy_file.chmod(0o000)
    try:
        if os.access(policy_file, os.R_OK):  # pragma: no cover - root/unusual fs
            pytest.skip("cannot make file unreadable (running as root?)")
        result = _run(
            "--policy-to-bwrap-flags",
            "--policy-ref",
            "config/sandbox/locked.linux.bwrap.policy",
            "--install-root",
            str(tmp_path),
        )
    finally:
        policy_file.chmod(0o644)
    assert result.returncode != 0
    assert "supervisor.sandbox.refused.policy_ref_unreadable" in result.stderr
    # No raw traceback leaked into stderr.
    assert "Traceback" not in result.stderr


# --------------------------------------------------------------------------
# argument handling
# --------------------------------------------------------------------------


def test_no_subcommand_refuses() -> None:
    result = _run()
    assert result.returncode != 0


def test_read_sandbox_requires_a_source() -> None:
    # Neither --manifest-path nor --plugin-id → refuse with the exact bare key.
    result = _run("--read-sandbox")
    assert result.returncode != 0
    assert "plugin.manifest_reader_no_source" in result.stderr
