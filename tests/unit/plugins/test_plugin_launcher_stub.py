"""``bin/alfred-plugin-launcher.sh`` — fail-closed plugin launcher (spec §4.8, §5.2).

The launcher is the only path the supervisor uses to spawn a plugin
subprocess. It is a tiny shell script with three load-bearing
invariants:

* **Fail-closed.** Without a sandbox policy file, the launcher refuses
  to exec the plugin unless ``ALFRED_ENV=development`` AND
  ``ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED=1`` — and even then only after
  emitting a ``supervisor.config_insecure`` audit JSON line on stderr.
  Production never accepts the unsandboxed flag (sec-003).
* **UID-drop.** On Linux, ``runuser -u "${TARGET_UID}" -- ...`` runs
  the plugin under a different uid so a compromised plugin cannot read
  the parent process's secrets at the OS level. macOS dev does not
  have ``runuser``; the launcher emits a
  ``launcher_uid_separation_unavailable_macos`` audit JSON and execs
  without UID-drop.
* **Bare i18n keys on stderr.** No hardcoded English sentences — the
  supervisor renders localised text from the audit row. i18n-005
  option (b).

These tests cover the contract at the shell-script level: ``bash -n``
syntax check, the fail-closed exit code + stderr key, the
development-mode pass-through, and (on macOS dev where ``runuser`` is
absent) the ``supervisor.config_insecure`` JSON shape.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[3]
_LAUNCHER = _REPO_ROOT / "bin" / "alfred-plugin-launcher.sh"


def test_launcher_exists_and_is_executable() -> None:
    """``bin/alfred-plugin-launcher.sh`` exists and is marked executable."""
    assert _LAUNCHER.exists(), "launcher must live at bin/alfred-plugin-launcher.sh"
    assert os.access(_LAUNCHER, os.X_OK), "launcher must be chmod +x"


def test_launcher_passes_bash_syntax_check() -> None:
    """``bash -n`` rejects nothing — the script is syntactically valid.

    A typo'd ``fi`` or missing ``then`` would let ``set -eu`` deliver a
    cryptic error at exec time; ``bash -n`` catches the class at the
    static level so the failure surfaces at CI rather than at the
    first plugin spawn.
    """
    result = subprocess.run(
        ["bash", "-n", str(_LAUNCHER)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, f"bash -n failed: {result.stderr}"


def test_launcher_invokes_runuser_for_uid_drop() -> None:
    """The script contains a ``runuser`` invocation (sec-003 UID-drop).

    Grep-level static check: the production-Linux branch must call
    ``runuser`` for OS-level UID separation. A future refactor that
    drops the call breaks the sandbox contract at the language level
    and must be caught here.
    """
    source = _LAUNCHER.read_text()
    assert "runuser" in source, "launcher must call runuser for UID-drop (sec-003)"


def test_launcher_uses_seed_script_set_eu_convention() -> None:
    """The launcher uses ``set -eu`` per the seed-script convention.

    ``pipefail`` is intentionally omitted: the launcher has no pipes,
    so ``-o pipefail`` would be cargo-culted. Matches the style of
    ``bin/alfred-state-git-seed.sh`` so future shell-script readers
    have one convention to learn.
    """
    source = _LAUNCHER.read_text()
    assert "set -eu" in source


def test_launcher_defines_do_exec_before_calling_it() -> None:
    """``_do_exec`` is defined BEFORE the policy-file check that calls it.

    CR R2 on PR-S3-0a: a prior draft invoked ``_do_exec`` on the dev
    branch before its function definition; bash reports "command not
    found" silently on that branch and exits 127, which would let a
    dev-mode plugin spawn fail with no readable signal. Static
    inspection here catches a regression of the same shape.
    """
    source = _LAUNCHER.read_text()
    define_idx = source.find("_do_exec()")
    first_call_idx = source.find('_do_exec "$@"')
    assert define_idx != -1, "_do_exec function must be defined"
    assert first_call_idx != -1, "_do_exec must be invoked with explicit $@"
    assert define_idx < first_call_idx, (
        "_do_exec definition must precede the first invocation (CR R2 fix)"
    )


def test_launcher_exits_1_without_sandbox_policy_in_production() -> None:
    """Production + no policy file → exit 1 + bare i18n key on stderr.

    The launcher is fail-closed: without a sandbox policy file in
    ``${ALFRED_SANDBOX_POLICY_DIR}/<plugin_id>.policy``, the spawn
    refuses. The error is emitted as a bare i18n key, never a
    hardcoded English sentence (i18n-005 option b).
    """
    env = {
        **os.environ,
        "ALFRED_ENV": "production",
        "ALFRED_SANDBOX_POLICY_DIR": "/nonexistent/sandbox/dir",
    }
    env.pop("ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED", None)
    result = subprocess.run(
        [str(_LAUNCHER), "alfred.test-plugin", "/bin/echo", "hello"],
        capture_output=True,
        env=env,
    )
    assert result.returncode == 1
    assert b"plugin.launcher_no_sandbox_policy" in result.stderr


def test_launcher_refuses_unsandboxed_flag_in_production() -> None:
    """Even with the unsandboxed flag, production refuses to launch.

    The flag is a development-only escape hatch. Production must reject
    it loudly so an operator who accidentally sets it in their docker-
    compose env cannot bypass the sandbox.
    """
    env = {
        **os.environ,
        "ALFRED_ENV": "production",
        "ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED": "1",
        "ALFRED_SANDBOX_POLICY_DIR": "/nonexistent/sandbox/dir",
    }
    result = subprocess.run(
        [str(_LAUNCHER), "alfred.test-plugin", "/bin/echo", "hello"],
        capture_output=True,
        env=env,
    )
    assert result.returncode == 1
    assert b"plugin.launcher_no_sandbox_policy" in result.stderr


def test_launcher_accepts_unsandboxed_in_development() -> None:
    """Development + unsandboxed=1 → exec the plugin (the only escape hatch).

    The plugin is execed via ``/bin/echo`` so a successful exec
    produces a recognisable marker on stdout. Returncode 0 + marker
    present confirms the unsandboxed branch reached the exec.
    """
    env = {
        **os.environ,
        "ALFRED_ENV": "development",
        "ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED": "1",
        "ALFRED_SANDBOX_POLICY_DIR": "/nonexistent/sandbox/dir",
    }
    result = subprocess.run(
        [
            str(_LAUNCHER),
            "alfred.test-plugin",
            "/bin/echo",
            "alfred-launcher-test-marker",
        ],
        capture_output=True,
        env=env,
    )
    assert result.returncode == 0
    assert b"alfred-launcher-test-marker" in result.stdout


def test_launcher_emits_config_insecure_audit_row_in_development() -> None:
    """The unsandboxed dev branch writes a ``supervisor.config_insecure`` JSON line.

    Structured audit row on stderr — the supervisor parses and
    persists it. Asserts the JSON parses and carries the
    ``insecure_config_key`` + ``plugin_id`` fields.
    """
    env = {
        **os.environ,
        "ALFRED_ENV": "development",
        "ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED": "1",
        "ALFRED_SANDBOX_POLICY_DIR": "/nonexistent/sandbox/dir",
    }
    result = subprocess.run(
        [str(_LAUNCHER), "alfred.test-plugin", "/bin/echo", "ok"],
        capture_output=True,
        env=env,
    )
    assert b"supervisor.config_insecure" in result.stderr
    # The audit row is one JSON object per stderr line. Find the line
    # that contains the event marker and parse it.
    json_line = next(
        line
        for line in result.stderr.splitlines()
        if b"supervisor.config_insecure" in line
    )
    parsed = json.loads(json_line)
    assert parsed["event"] == "supervisor.config_insecure"
    assert parsed["plugin_id"] == "alfred.test-plugin"
    assert "insecure_config_key" in parsed


@pytest.mark.skipif(
    shutil.which("runuser") is not None,
    reason="macOS-dev branch only: runuser is unavailable",
)
def test_launcher_macos_dev_emits_uid_separation_unavailable_row() -> None:
    """On macOS dev (no ``runuser``), the script logs a config_insecure JSON.

    The launcher cannot UID-drop on macOS because ``runuser`` is a
    Linux util. The supervisor needs an audit trail of this
    deviation; the JSON-on-stderr pattern gives it that without
    pulling structlog into a shell script.

    Requires a sandbox policy file so the unsandboxed-dev escape hatch
    isn't what's writing the JSON — this test specifically targets the
    ``_do_exec`` macOS branch.
    """
    sandbox_dir = Path(__file__).parent / "_tmp_macos_uid_drop"
    sandbox_dir.mkdir(exist_ok=True)
    policy = sandbox_dir / "alfred.test-plugin.policy"
    policy.write_text("# placeholder sandbox policy for unit test")
    try:
        env = {
            **os.environ,
            "ALFRED_ENV": "production",
            "ALFRED_SANDBOX_POLICY_DIR": str(sandbox_dir),
        }
        env.pop("ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED", None)
        result = subprocess.run(
            [
                str(_LAUNCHER),
                "alfred.test-plugin",
                "/bin/echo",
                "macos-uid-drop-marker",
            ],
            capture_output=True,
            env=env,
        )
        # Successful exec via /bin/echo (no UID-drop) → 0 + marker present.
        assert result.returncode == 0
        assert b"macos-uid-drop-marker" in result.stdout
        # Audit row records the deviation.
        assert b"launcher_uid_separation_unavailable_macos" in result.stderr
        json_line = next(
            line
            for line in result.stderr.splitlines()
            if b"launcher_uid_separation_unavailable_macos" in line
        )
        parsed = json.loads(json_line)
        assert parsed["event"] == "supervisor.config_insecure"
        assert parsed["plugin_id"] == "alfred.test-plugin"
        assert (
            parsed["insecure_config_key"]
            == "launcher_uid_separation_unavailable_macos"
        )
    finally:
        policy.unlink(missing_ok=True)
        sandbox_dir.rmdir()
