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

import getpass
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[3]
_LAUNCHER = _REPO_ROOT / "bin" / "alfred-plugin-launcher.sh"

# The launcher's Linux UID-drop branch invokes ``runuser -u <user> -- ...``.
# The production default ``alfred-quarantine`` is provisioned out-of-band
# (see launcher --help) and does not exist on a vanilla GitHub Actions
# runner — runuser exits 1 ("user does not exist"), failing the dev /
# unsandboxed exec-reachability tests below. Pointing ``ALFRED_PLUGIN_UID``
# at the current process's user lets runuser succeed on CI without
# provisioning a system account; the assertion is still about reaching
# the exec branch, not about UID isolation (that's spec'd elsewhere).
_LAUNCHER_TEST_UID = getpass.getuser()


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
    result = subprocess.run(  # noqa: S603 — bash on PATH + repo-owned script path
        ["bash", "-n", str(_LAUNCHER)],  # noqa: S607 — bash is on PATH by convention
        capture_output=True,
        text=True,
        check=False,
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
    result = subprocess.run(  # noqa: S603 — literal repo-owned script path
        [str(_LAUNCHER), "alfred.test-plugin", "/bin/echo", "hello"],
        capture_output=True,
        env=env,
        check=False,
    )
    assert result.returncode == 1
    assert b"plugin.launcher_no_sandbox_policy" in result.stderr


def test_launcher_refuses_unsandboxed_flag_in_production() -> None:
    """Even with the unsandboxed flag, production refuses to launch.

    The flag is a development-only escape hatch. Production must reject
    it loudly so an operator who accidentally sets it in their docker-
    compose env cannot bypass the sandbox.

    Distinct i18n key (``plugin.launcher_unsandboxed_rejected``) — CR
    on PR #140 caught the previous reuse of the no-policy key as a real
    audit/render ambiguity. Operators must be able to distinguish
    "unsandboxed flag refused in production" from "sandbox policy file
    missing".
    """
    env = {
        **os.environ,
        "ALFRED_ENV": "production",
        "ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED": "1",
        "ALFRED_SANDBOX_POLICY_DIR": "/nonexistent/sandbox/dir",
    }
    result = subprocess.run(  # noqa: S603 — literal repo-owned script path
        [str(_LAUNCHER), "alfred.test-plugin", "/bin/echo", "hello"],
        capture_output=True,
        env=env,
        check=False,
    )
    assert result.returncode == 1
    assert b"plugin.launcher_unsandboxed_rejected" in result.stderr
    # Negative assertion: the no-policy key must NOT be emitted here —
    # it would collapse the two refusal cases back into one.
    assert b"plugin.launcher_no_sandbox_policy" not in result.stderr


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
        "ALFRED_PLUGIN_UID": _LAUNCHER_TEST_UID,
    }
    result = subprocess.run(  # noqa: S603 — literal repo-owned script path
        [
            str(_LAUNCHER),
            "alfred.test-plugin",
            "/bin/echo",
            "alfred-launcher-test-marker",
        ],
        capture_output=True,
        env=env,
        check=False,
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
    result = subprocess.run(  # noqa: S603 — literal repo-owned script path
        [str(_LAUNCHER), "alfred.test-plugin", "/bin/echo", "ok"],
        capture_output=True,
        env=env,
        check=False,
    )
    assert b"supervisor.config_insecure" in result.stderr
    # The audit row is one JSON object per stderr line. Find the line
    # that contains the event marker and parse it.
    json_line = next(
        line for line in result.stderr.splitlines() if b"supervisor.config_insecure" in line
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
        result = subprocess.run(  # noqa: S603 — literal repo-owned script path
            [
                str(_LAUNCHER),
                "alfred.test-plugin",
                "/bin/echo",
                "macos-uid-drop-marker",
            ],
            capture_output=True,
            env=env,
            check=False,
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
        assert parsed["insecure_config_key"] == "launcher_uid_separation_unavailable_macos"
    finally:
        policy.unlink(missing_ok=True)
        sandbox_dir.rmdir()


# ---------------------------------------------------------------------------
# CR-PR-140 fixes — charset validation + Linux-fail-closed-without-runuser.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad_id",
    [
        'alfred."evil-id',
        "alfred.evil\\id",
        "alfred.evil id",  # whitespace
        "alfred.evil$id",
        "alfred.evil`id",
        "",  # empty handled by ${1:?...} but the explicit charset case
        # is checked too so the launcher remains the last-line gate
        # if the upstream caller ever loosens the manifest contract.
    ],
)
def test_launcher_refuses_plugin_id_outside_safe_charset(bad_id: str) -> None:
    """A plugin_id with unsafe characters is refused at script entry.

    CR on PR #140: unescaped ``printf`` interpolation of PLUGIN_ID into
    the ``supervisor.config_insecure`` JSON row would produce malformed
    or forgeable audit lines if the id contained ``"`` / ``\\`` / newlines.
    The launcher charset-validates PLUGIN_ID at the entry point so every
    downstream JSON-emitting branch can safely interpolate without a
    shell-escape step. The bare i18n key
    ``plugin.launcher_plugin_id_invalid`` flags the refusal; the
    plugin_id itself is NOT echoed (a malformed id is exactly the thing
    we refuse to round-trip into the audit stream).
    """
    env = {
        **os.environ,
        "ALFRED_ENV": "production",
        "ALFRED_SANDBOX_POLICY_DIR": "/nonexistent/sandbox/dir",
    }
    env.pop("ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED", None)
    if not bad_id:
        # Empty positional triggers the ${1:?...} guard with exit 1 +
        # the standard bash error message — distinct from the explicit
        # charset case but still fail-closed.
        result = subprocess.run(  # noqa: S603 — literal repo-owned script path
            [str(_LAUNCHER)],
            capture_output=True,
            env=env,
            check=False,
        )
        assert result.returncode != 0
        return
    result = subprocess.run(  # noqa: S603 — literal repo-owned script path
        [str(_LAUNCHER), bad_id, "/bin/echo", "hello"],
        capture_output=True,
        env=env,
        check=False,
    )
    assert result.returncode == 1
    assert b"plugin.launcher_plugin_id_invalid" in result.stderr
    # The malformed id MUST NOT echo into stderr — otherwise the refusal
    # itself becomes a JSON-injection vector for log consumers.
    assert bad_id.encode() not in result.stderr


def test_launcher_accepts_well_formed_plugin_id() -> None:
    """The safe charset ``[A-Za-z0-9._-]+`` is accepted as before.

    Pinning the positive case so a future tightening of the charset
    (which would be a backward-incompatible break) shows up here.
    """
    env = {
        **os.environ,
        "ALFRED_ENV": "development",
        "ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED": "1",
        "ALFRED_SANDBOX_POLICY_DIR": "/nonexistent/sandbox/dir",
        "ALFRED_PLUGIN_UID": _LAUNCHER_TEST_UID,
    }
    result = subprocess.run(  # noqa: S603 — literal repo-owned script path
        [str(_LAUNCHER), "alfred.well-formed_id.v1", "/bin/echo", "marker"],
        capture_output=True,
        env=env,
        check=False,
    )
    assert result.returncode == 0
    assert b"marker" in result.stdout


@pytest.mark.skipif(
    shutil.which("runuser") is not None or os.uname().sysname != "Linux",
    reason="Linux-without-runuser branch — skip on Linux+runuser and on non-Linux",
)
def test_launcher_fails_closed_on_linux_without_runuser() -> None:
    """On Linux without ``runuser``, the launcher refuses to exec.

    CR on PR #140 MUST-FIX: the previous launcher gated the UID-drop
    branch on ``command -v runuser`` rather than the OS. A Linux box
    without ``runuser`` on PATH would silently fall through to the
    macOS-deviation branch and exec the plugin WITHOUT UID separation,
    silently dropping the security control this launcher exists to
    enforce. The fix gates on ``uname -s`` and fails closed on Linux
    when ``runuser`` is absent, with the distinct bare i18n key
    ``plugin.launcher_uid_drop_unavailable``.

    The test is hard to exercise on a real Linux+runuser host (runuser
    is almost always present in the util-linux package). The skipif
    above keeps the test honest on CI; the matching adversarial /
    coverage test below pins the script-level branch via grep.
    """
    sandbox_dir = Path(__file__).parent / "_tmp_linux_no_runuser"
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
        result = subprocess.run(  # noqa: S603 — literal repo-owned script path
            [str(_LAUNCHER), "alfred.test-plugin", "/bin/echo", "should-not-reach"],
            capture_output=True,
            env=env,
            check=False,
        )
        assert result.returncode == 1
        assert b"plugin.launcher_uid_drop_unavailable" in result.stderr
        # The exec never happened — the marker must not appear.
        assert b"should-not-reach" not in result.stdout
    finally:
        policy.unlink(missing_ok=True)
        sandbox_dir.rmdir()


def test_launcher_uid_drop_branch_uses_os_check_not_runuser_presence() -> None:
    """The script branches on ``uname -s = Linux``, not ``command -v runuser``.

    Static grep-level check that survives across CI hosts (Linux with
    runuser, macOS without). Documents the spec §4.8 + §5.2 invariant:
    Linux is the production target, so the UID-drop branch must be
    OS-gated. A future refactor that re-introduces the
    ``command -v runuser``-only gate would silently re-open the
    fail-OPEN regression CR caught on PR #140.
    """
    source = _LAUNCHER.read_text()
    assert "uname -s" in source, "_do_exec must gate on uname -s = Linux (CR PR #140 MUST-FIX)"
    assert "launcher_uid_drop_unavailable" in source, (
        "Linux-without-runuser branch must emit the dedicated bare i18n key"
    )


def test_launcher_json_emission_only_after_charset_validation() -> None:
    """JSON-emitting ``printf`` lines run only after the charset check.

    The charset validation must come BEFORE any branch that interpolates
    PLUGIN_ID into a JSON template — otherwise the unescaped
    interpolation CR flagged remains a live audit-stream integrity
    risk. Static check on script ordering.
    """
    source = _LAUNCHER.read_text()
    charset_idx = source.find("plugin.launcher_plugin_id_invalid")
    first_json_idx = source.find('{"event":"supervisor.config_insecure"')
    assert charset_idx != -1, "charset-invalid bare key must be present"
    assert first_json_idx != -1, "supervisor.config_insecure JSON template must be present"
    assert charset_idx < first_json_idx, (
        "charset validation must precede the first JSON-emitting branch "
        "(CR PR #140 audit-stream integrity)"
    )


# ---------------------------------------------------------------------------
# DEVEX-005 — --help discoverability. A first-time operator running
# `bin/alfred-plugin-launcher.sh --help` previously hit the unsafe-charset
# refusal because `--` is not in [A-Za-z0-9._-]. The fix runs the help
# branch BEFORE the charset gate; `--help` returns 0 + usage on stdout.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("flag", ["--help", "-h"])
def test_launcher_help_flag_prints_usage_and_exits_zero(flag: str) -> None:
    """``--help`` / ``-h`` short-circuits to a usage dump on stdout, exit 0.

    The help branch MUST run before the charset validation — otherwise
    `--help` (with its `--` prefix) trips the safe-charset refusal and
    the operator sees `plugin.launcher_plugin_id_invalid` instead of
    documentation. DEVEX-005 fix.
    """
    result = subprocess.run(  # noqa: S603 — literal repo-owned script path
        [str(_LAUNCHER), flag],
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, f"--help must exit 0, got {result.returncode}"
    # The help text documents the env-var surface so an operator can find
    # ALFRED_SANDBOX_POLICY_DIR / ALFRED_PLUGIN_UID etc. without grepping.
    assert b"USAGE" in result.stdout
    assert b"ALFRED_ENV" in result.stdout
    assert b"ALFRED_SANDBOX_POLICY_DIR" in result.stdout
    assert b"EXIT CODES" in result.stdout
    # The bare i18n key catalogue lives in the help text so operators can
    # decode an audit row without round-tripping through the supervisor's
    # renderer.
    assert b"plugin.launcher_no_sandbox_policy" in result.stdout
    # Negative: the charset refusal key must NOT appear on stderr —
    # otherwise the help branch is downstream of the charset check.
    assert b"plugin.launcher_plugin_id_invalid" not in result.stderr
