"""``bin/alfred-plugin-launcher.sh`` — fail-closed plugin launcher (spec §4.8, §5.2).

The launcher is the only path the supervisor uses to spawn a plugin
subprocess. It is a tiny shell script with three load-bearing
invariants:

* **Fail-closed.** Without a sandbox policy file, the launcher refuses
  to exec the plugin unless ``ALFRED_ENV=development`` AND
  ``ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED=1``. Production never accepts the
  unsandboxed flag (sec-003).
* **UID-drop.** On Linux, ``runuser -u "${TARGET_UID}" -- ...`` runs
  the plugin under a different uid so a compromised plugin cannot read
  the parent process's secrets at the OS level. A non-Linux host has no
  ``runuser``; in PRODUCTION the launcher REFUSES (sec-keystone, CR PR
  #229: no UID-drop containment → ``uid_separation_unavailable``), and
  only dev/test exec without UID-drop, emitting an honest
  ``supervisor.plugin.sandbox_stub_used`` audit JSON row (low-1: the prior
  advisory ``config_insecure`` row is gone).
* **Bare i18n keys on stderr.** No hardcoded English sentences — the
  supervisor renders localised text from the audit row. i18n-005
  option (b).

These tests cover the contract at the shell-script level: ``bash -n``
syntax check, the fail-closed exit code + stderr key, the
development-mode pass-through, and (on a non-Linux host where ``runuser``
is absent) the production-refusal / dev-stub_used JSON shapes.
"""

from __future__ import annotations

import getpass
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from alfred.plugins.manifest import _POLICY_REF_BAD_CHAR

_REPO_ROOT = Path(__file__).resolve().parents[3]
_LAUNCHER = _REPO_ROOT / "bin" / "alfred-plugin-launcher.sh"

# The launcher's Linux UID-drop branch invokes ``runuser -u <user> -- ...``.
# The production default ``alfred-quarantine`` is provisioned out-of-band
# (see launcher --help) and does not exist on a vanilla GitHub Actions
# runner. Pointing ``ALFRED_PLUGIN_UID`` at the current process's user lets
# runuser succeed when the test runs as root (production deployments invoke
# the launcher as root). The skipif on ``_LAUNCHER_REQUIRES_ROOT`` covers
# the second blocker: ``runuser -u`` requires root regardless of the target
# user. GitHub Actions Linux runners run as the unprivileged ``runner``
# account, so the two dev / unsandboxed exec-reachability tests below
# skip there; the launcher's Linux UID-drop is exercised on local + root
# CI, the macOS fallback is exercised on the macos matrix legs, and the
# grep-level static check at ``test_launcher_invokes_runuser_for_uid_drop``
# locks the contract on every leg.
_LAUNCHER_TEST_UID = getpass.getuser()
_LAUNCHER_REQUIRES_ROOT = os.uname().sysname == "Linux" and os.geteuid() != 0


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


def test_launcher_exits_1_without_sandbox_block_in_production() -> None:
    """Production + manifest lacking [sandbox] → exit 1 + bare key on stderr.

    PR-S4-6 contract: the launcher reads the manifest's [sandbox] block. A
    manifest without one refuses (sandbox_block_missing) — the fail-closed
    successor to the Slice-3 "no .policy file" refusal. The error is a bare
    i18n key, never a hardcoded English sentence (i18n-005 option b).
    """
    import tempfile

    with tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False) as f:
        f.write(
            "[alfred]\nmanifest_version = 1\n[plugin]\n"
            'id = "alfred.test-plugin"\nsubscriber_tier = "user-plugin"\n'
            'sandbox_profile = "user-plugin"\n'
        )
        manifest_path = f.name
    env = {
        **os.environ,
        "PYTHONPATH": str(_REPO_ROOT / "src"),
        "ALFRED_ENVIRONMENT": "production",
        "ALFRED_PLUGIN_MANIFEST_PATH": manifest_path,
    }
    env.pop("ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED", None)
    result = subprocess.run(  # noqa: S603 — literal repo-owned script path
        [str(_LAUNCHER), "alfred.test-plugin", "/bin/echo", "hello"],
        capture_output=True,
        env=env,
        check=False,
    )
    assert result.returncode == 1
    assert b"sandbox_block_missing" in result.stderr


def test_launcher_refuses_unsandboxed_flag_in_production() -> None:
    """Even with the unsandboxed flag, production refuses to launch.

    PR-S4-6 (devex-001): the dev escape hatch is refused in production with an
    operator-visible stderr key + a SANDBOX_REFUSED audit row. The env var is
    ALFRED_ENVIRONMENT (not the Slice-3 ALFRED_ENV).
    """
    env = {
        **os.environ,
        "PYTHONPATH": str(_REPO_ROOT / "src"),
        "ALFRED_ENVIRONMENT": "production",
        "ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED": "1",
    }
    result = subprocess.run(  # noqa: S603 — literal repo-owned script path
        [str(_LAUNCHER), "alfred.test-plugin", "/bin/echo", "hello"],
        capture_output=True,
        env=env,
        check=False,
    )
    assert result.returncode == 1
    assert b"supervisor.sandbox.unsandboxed_refused_in_production" in result.stderr
    assert b"unsandboxed_env_set_in_production" in result.stderr


@pytest.mark.skipif(
    _LAUNCHER_REQUIRES_ROOT,
    reason="Linux runuser branch requires root; this runner is non-root",
)
def _write_none_manifest() -> str:
    import tempfile

    with tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False) as f:
        f.write(
            "[alfred]\nmanifest_version = 1\n[plugin]\n"
            'id = "alfred.test-plugin"\nsubscriber_tier = "user-plugin"\n'
            'sandbox_profile = "user-plugin"\n[sandbox]\nkind = "none"\n'
        )
        return f.name


def _write_stub_manifest() -> str:
    import tempfile

    with tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False) as f:
        f.write(
            "[alfred]\nmanifest_version = 1\n[plugin]\n"
            'id = "alfred.test-plugin"\nsubscriber_tier = "user-plugin"\n'
            'sandbox_profile = "user-plugin"\n[sandbox]\nkind = "stub"\n'
        )
        return f.name


@pytest.mark.skipif(
    _LAUNCHER_REQUIRES_ROOT,
    reason="kind:none runuser branch requires root; this runner is non-root",
)
def test_launcher_kind_none_execs_plugin_in_development() -> None:
    """Development + kind:none manifest → exec the plugin (UID-separated path).

    The plugin is execed via ``/bin/echo`` so a successful exec produces a
    recognisable marker on stdout. Returncode 0 + marker confirms the
    kind:none branch reached _do_exec.
    """
    env = {
        **os.environ,
        "PYTHONPATH": str(_REPO_ROOT / "src"),
        "ALFRED_ENVIRONMENT": "development",
        "ALFRED_PLUGIN_MANIFEST_PATH": _write_none_manifest(),
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


@pytest.mark.skipif(
    shutil.which("runuser") is not None,
    reason="macOS-dev branch only: runuser is unavailable",
)
@pytest.mark.skipif(
    shutil.which("jq") is None, reason="jq required for the kind:none sandbox branch"
)
def test_launcher_non_linux_production_refuses_uid_separation_unavailable() -> None:
    """sec-keystone (CR PR #229 finding-1): on a non-Linux PRODUCTION host the
    kind:none path has no UID-drop containment, so the launcher REFUSES rather
    than exec'ing unsandboxed.

    This previously exec'd the plugin and emitted only an advisory
    ``config_insecure`` row — the second half of the FAKE_UNAME bypass (a
    genuine non-Linux production host also fell through to the unsandboxed
    exec). The fix refuses loudly with a host-accurate
    ``uid_separation_unavailable`` ``sandbox_refused`` row.

    Only observable on a genuine non-Linux host (FAKE_UNAME is refused in
    production, so it cannot fake the branch); skipped on Linux.
    """
    if platform.system() == "Linux":
        pytest.skip("non-Linux _do_exec production refusal only observable off-Linux")
    env = {
        **os.environ,
        "PYTHONPATH": str(_REPO_ROOT / "src"),
        "ALFRED_ENVIRONMENT": "production",
        "ALFRED_PLUGIN_MANIFEST_PATH": _write_none_manifest(),
    }
    env.pop("ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED", None)
    env.pop("FAKE_UNAME", None)
    result = subprocess.run(  # noqa: S603 — literal repo-owned script path
        [str(_LAUNCHER), "alfred.test-plugin", "/bin/echo", "macos-uid-drop-marker"],
        capture_output=True,
        env=env,
        check=False,
    )
    # Refused — the plugin was NOT exec'd.
    assert result.returncode != 0
    assert b"macos-uid-drop-marker" not in result.stdout
    # Host-accurate refusal reason (low-1) — NOT the advisory config_insecure row.
    assert b"config_insecure" not in result.stderr
    assert b"uid_separation_unavailable" in result.stderr
    json_line = next(
        line
        for line in result.stderr.splitlines()
        if b'"event":"supervisor.plugin.sandbox_refused"' in line
    )
    parsed = json.loads(json_line)
    assert parsed["event"] == "supervisor.plugin.sandbox_refused"
    assert parsed["plugin_id"] == "alfred.test-plugin"
    assert parsed["reason"] == "uid_separation_unavailable"
    assert parsed["environment"] == "production"


@pytest.mark.skipif(
    shutil.which("jq") is None, reason="jq required for the kind:none sandbox branch"
)
def test_launcher_non_linux_dev_execs_with_stub_used_row() -> None:
    """On a non-Linux DEV host the kind:none path may exec unsandboxed, but with
    an honest ``sandbox_stub_used`` row (low-1) — NOT the old advisory
    ``config_insecure`` row.

    Forced via FAKE_UNAME=Darwin (honoured in dev) so it runs on Linux CI too.
    """
    env = {
        **os.environ,
        "PYTHONPATH": str(_REPO_ROOT / "src"),
        "ALFRED_ENVIRONMENT": "development",
        "ALFRED_PLUGIN_MANIFEST_PATH": _write_none_manifest(),
        "FAKE_UNAME": "Darwin",
    }
    env.pop("ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED", None)
    result = subprocess.run(  # noqa: S603 — literal repo-owned script path
        [str(_LAUNCHER), "alfred.test-plugin", "/bin/echo", "macos-uid-drop-marker"],
        capture_output=True,
        env=env,
        check=False,
    )
    assert result.returncode == 0
    assert b"macos-uid-drop-marker" in result.stdout
    assert b"config_insecure" not in result.stderr
    json_line = next(
        line
        for line in result.stderr.splitlines()
        if b'"event":"supervisor.plugin.sandbox_stub_used"' in line
    )
    parsed = json.loads(json_line)
    assert parsed["event"] == "supervisor.plugin.sandbox_stub_used"
    assert parsed["plugin_id"] == "alfred.test-plugin"
    assert parsed["reason"] == "uid_separation_unavailable"
    assert parsed["host_os"] == "macos"


@pytest.mark.skipif(
    shutil.which("jq") is None, reason="jq required for the kind:stub sandbox branch"
)
def test_kind_stub_dev_row_carries_the_stub_kind_reason() -> None:
    """#436: at base this row carried NO `reason` key at all — a strict SUBSET of the
    kind:none non-Linux row (which already emitted `reason:uid_separation_unavailable`),
    not a byte-identical twin of it. An operator reading the kind:stub row had no way to
    tell why the plugin ran unsandboxed at all, and the `reason` the kind:none row DID
    emit was bound to no schema field (`SANDBOX_STUB_USED_FIELDS` declared none) — nothing
    pinned it to exist, let alone to differ between the two producers.
    """
    env = {
        **os.environ,
        "PYTHONPATH": str(_REPO_ROOT / "src"),
        "ALFRED_ENVIRONMENT": "development",
        "ALFRED_PLUGIN_MANIFEST_PATH": _write_stub_manifest(),
        "FAKE_UNAME": "Darwin",
    }
    env.pop("ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED", None)
    result = subprocess.run(  # noqa: S603 — literal repo-owned script path
        [str(_LAUNCHER), "alfred.test-plugin", "/bin/echo", "stub-kind-marker"],
        capture_output=True,
        env=env,
        check=False,
    )
    assert result.returncode == 0
    json_line = next(
        line
        for line in result.stderr.splitlines()
        if b'"event":"supervisor.plugin.sandbox_stub_used"' in line
    )
    parsed = json.loads(json_line)
    assert parsed["reason"] == "stub_kind"
    assert parsed["host_os"] == "macos"


@pytest.mark.skipif(
    shutil.which("jq") is None, reason="jq required for the kind:none/kind:stub sandbox branches"
)
def test_kind_none_and_kind_stub_rows_are_distinguishable_on_macos() -> None:
    """The crux of #436, asserted end-to-end: the two macOS-reachable stub_used producers must
    each name their cause in a POSITIVE field value, rather than leaving it to be inferred from
    which fields happen to be present. No parser exists for this row today (see the NOT PERSISTED
    note on SANDBOX_STUB_USED_FIELDS), but field-presence would be the wrong discriminator to rely
    on regardless: the sibling sandbox_refused parser canonicalizes an absent optional field to "",
    so presence is exactly what a parse boundary erases first. Drive BOTH real launcher paths on
    one host and prove each row names its own cause.
    """
    rows = {}
    for label, manifest_writer in (
        ("kind_none", _write_none_manifest),
        ("kind_stub", _write_stub_manifest),
    ):
        env = {
            **os.environ,
            "PYTHONPATH": str(_REPO_ROOT / "src"),
            "ALFRED_ENVIRONMENT": "development",
            "ALFRED_PLUGIN_MANIFEST_PATH": manifest_writer(),
            "FAKE_UNAME": "Darwin",
        }
        env.pop("ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED", None)
        result = subprocess.run(  # noqa: S603 — literal repo-owned script path
            [str(_LAUNCHER), "alfred.test-plugin", "/bin/echo", label],
            capture_output=True,
            env=env,
            check=False,
        )
        assert result.returncode == 0, f"{label} did not exec: {result.stderr!r}"
        json_line = next(
            line
            for line in result.stderr.splitlines()
            if b'"event":"supervisor.plugin.sandbox_stub_used"' in line
        )
        rows[label] = json.loads(json_line)

    # Both are macOS dev rows. Before #436 the kind:stub row carried no `reason`
    # key at all — a strict SUBSET of the kind:none row (which already emitted
    # `reason:uid_separation_unavailable`), not a byte-identical twin of it. An
    # operator reading the kind:stub row had no way to tell why the plugin ran
    # unsandboxed.
    assert rows["kind_none"]["host_os"] == rows["kind_stub"]["host_os"] == "macos"
    assert rows["kind_none"]["reason"] == "uid_separation_unavailable"
    # Red at base: `rows["kind_stub"]` had no "reason" key before #436, so this
    # line raised KeyError — the load-bearing oracle for this test. The two
    # asserts above already pin the positive values that distinguish the two
    # rows, so a further dict-level `!=` would be tautological given them.
    assert rows["kind_stub"]["reason"] == "stub_kind"


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


@pytest.mark.skipif(
    _LAUNCHER_REQUIRES_ROOT,
    reason="Linux runuser branch requires root; this runner is non-root",
)
def test_launcher_accepts_well_formed_plugin_id() -> None:
    """The safe charset ``[A-Za-z0-9._-]+`` is accepted as before.

    Pinning the positive case so a future tightening of the charset
    (which would be a backward-incompatible break) shows up here.
    """
    env = {
        **os.environ,
        "PYTHONPATH": str(_REPO_ROOT / "src"),
        "ALFRED_ENVIRONMENT": "development",
        "ALFRED_PLUGIN_MANIFEST_PATH": _write_none_manifest(),
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
    # The first JSON-emitting printf interpolates PLUGIN_ID into an
    # ``{"event":"supervisor...`` template. CR PR #229 low-1 removed the advisory
    # ``config_insecure`` row, so this asserts against the first remaining
    # JSON-emitting event template instead.
    first_json_idx = source.find('{"event":"supervisor.')
    assert charset_idx != -1, "charset-invalid bare key must be present"
    assert first_json_idx != -1, "a supervisor.* JSON template must be present"
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
    # ALFRED_ENVIRONMENT / ALFRED_SANDBOX_POLICY_DIR / ALFRED_PLUGIN_UID etc.
    # without grepping.
    assert b"USAGE" in result.stdout
    assert b"ALFRED_ENVIRONMENT" in result.stdout
    assert b"ALFRED_SANDBOX_POLICY_DIR" in result.stdout
    assert b"EXIT CODES" in result.stdout
    # Negative: the charset refusal key must NOT appear on stderr —
    # otherwise the help branch is downstream of the charset check.
    assert b"plugin.launcher_plugin_id_invalid" not in result.stderr


# ---------------------------------------------------------------------------
# #437 — launcher POLICY_REF charset guard (defense-in-depth).
#
# manifest.py's own producer-side validator (`_POLICY_REF_BAD_CHAR`, Task 1
# of #437) already refuses a charset-invalid `[sandbox.policy_refs]` entry at
# manifest-PARSE time — it walks every declared OS key, not just the current
# host's, so there is no legitimate manifest that lets a tainted value reach
# this launcher branch (verified: driving the launcher through a real
# ALFRED_PLUGIN_MANIFEST_PATH with a charset-invalid policy_ref refuses
# upstream with `sandbox_block_missing`, via `_read_sandbox`, before
# POLICY_REF is ever assigned).
#
# That is the point of a defense-in-depth guard: it must hold even if the
# upstream Python check regresses, is bypassed, or a future manifest_reader
# change loosens it. To exercise the launcher's OWN guard in isolation, these
# tests shadow `python3` on PATH with a stub that hands back a raw,
# unvalidated sandbox JSON — simulating exactly the "upstream check absent"
# scenario the guard exists to defend against.
# ---------------------------------------------------------------------------


def _run_launcher_with_policy_ref(policy_ref: str) -> subprocess.CompletedProcess[bytes]:
    """Drive the launcher's ``kind:full`` branch with an attacker-controlled
    ``POLICY_REF``, bypassing manifest.py's own charset validation via a
    PATH-shadowing ``python3`` stub (see module note above).

    The stub answers ``--read-environment`` with a fixed ``development`` and
    ``--read-sandbox`` with ``{"kind": "full", "policy_refs": {"linux":
    <policy_ref>}}`` — anything else is an unexpected invocation and fails
    loudly rather than silently returning nothing (so a future 3rd/4th
    ``python3`` call this stub does not understand cannot pass silently).
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        fake_bin = Path(tmpdir) / "fake_bin"
        fake_bin.mkdir()
        # Build the sandbox JSON via json.dumps (correct escaping for ANY payload,
        # including one containing a literal `"` or `\`) rather than hand-rolled
        # string interpolation, then shell-single-quote the result (POSIX
        # escaping: close, insert an escaped literal quote, reopen) so the
        # generated stub script is well-formed regardless of the payload's
        # content.
        sandbox_json = json.dumps({"kind": "full", "policy_refs": {"linux": policy_ref}})
        quoted_json = "'" + sandbox_json.replace("'", "'\\''") + "'"
        fake_python3 = fake_bin / "python3"
        fake_python3.write_text(
            "#!/bin/sh\n"
            'case "$*" in\n'
            "    *--read-environment*)\n"
            "        printf 'development\\n'\n"
            "        exit 0\n"
            "        ;;\n"
            "    *--read-sandbox*)\n"
            f"        printf '%s\\n' {quoted_json}\n"
            "        exit 0\n"
            "        ;;\n"
            "    *)\n"
            "        printf 'unexpected fake-python3 invocation: %s\\n' \"$*\" >&2\n"
            "        exit 1\n"
            "        ;;\n"
            "esac\n"
        )
        fake_python3.chmod(0o755)
        env = {
            **os.environ,
            # FAKE_UNAME forces HOST_OS=linux (honoured only outside production —
            # our stub's --read-environment always answers "development") so the
            # stub's "linux" policy_refs key is the one the launcher resolves.
            "FAKE_UNAME": "Linux",
            "PATH": f"{fake_bin}:{os.environ.get('PATH', '')}",
        }
        env.pop("ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED", None)
        env.pop("ALFRED_PLUGIN_MANIFEST_PATH", None)
        return subprocess.run(  # noqa: S603 — literal repo-owned script path
            [str(_LAUNCHER), "alfred.test-plugin", "/bin/echo", "should-not-run"],
            capture_output=True,
            env=env,
            check=False,
        )


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX launcher subprocess; winsock hermetic-PATH breaks the child (see #428)",
)
@pytest.mark.skipif(
    shutil.which("jq") is None,
    reason="jq required: the launcher refuses jq_unavailable before the kind:full charset guard",
)
def test_launcher_refuses_policy_ref_with_injection_charset() -> None:
    """A policy_ref carrying a JSON-injection payload is refused at the
    launcher's own chokepoint with ``policy_ref_charset_invalid``, exit 1,
    and — the security crux — the tainted value is NOT echoed anywhere in
    the launcher's output.

    See the module-level note above for why this drives the guard via a
    PATH-shadowed ``python3`` stub rather than a real manifest file.
    """
    tainted = 'config/x","event":"forged'
    result = _run_launcher_with_policy_ref(tainted)
    assert result.returncode == 1
    assert b"policy_ref_charset_invalid" in result.stderr
    # ANTI-ECHO: neither the forged substring nor a bare quote-sequence from
    # the payload appears anywhere in the launcher's output — the refusal
    # row omits the policy_ref field entirely rather than interpolating the
    # tainted value. Echoing it would BE the injection.
    assert b"forged" not in result.stderr
    assert b'","event":"' not in result.stderr
    assert b"forged" not in result.stdout
    # The plugin was never exec'd.
    assert b"should-not-run" not in result.stdout


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX launcher subprocess; winsock hermetic-PATH breaks the child (see #428)",
)
@pytest.mark.skipif(
    shutil.which("jq") is None,
    reason="jq required: the launcher refuses jq_unavailable before the kind:full charset guard",
)
def test_launcher_accepts_well_formed_policy_ref() -> None:
    """A charset-safe policy_ref (including its required ``/`` path
    separators) is NOT refused by the new guard.

    Pins the positive branch so a future tightening of the charset (which
    would be backward-incompatible) shows up here. The launcher proceeds
    past this guard to the next branch — the stub's fallback case for the
    ``--policy-to-bwrap-flags`` call it does not understand — and refuses
    downstream with the unrelated ``reason_unclassified`` reason (#434B: the
    stub's own "unexpected invocation" message is unclassifiable by the
    schema `case`, so it hits the `*)` alarm arm, not a real schema reason),
    proving THIS guard specifically let the value through.
    """
    result = _run_launcher_with_policy_ref("config/sandbox/x.linux.bwrap.policy")
    assert b"policy_ref_charset_invalid" not in result.stderr
    assert b"reason_unclassified" in result.stderr


def test_launcher_charset_class_matches_the_python_producer() -> None:
    """The launcher's negated POLICY_REF class is byte-identical to
    manifest.py's ``_POLICY_REF_BAD_CHAR`` producer-side validator (Task 1 of
    #437), so both layers refuse exactly the same values (the #432
    cross-reference pattern — a sync assertion, not a hand-kept copy).

    This in-process twin is also what actually exercises the SHARED
    predicate's accept/reject branches for coverage: a subprocess launcher
    run can never reach the reject branch for this exact payload (manifest.py
    refuses it first — see the module note above), so the subprocess test
    alone would leave the guard's own logic branch uncovered. Running here
    covers it on every platform, including win32 where the subprocess test
    is skipped.
    """
    launcher_source = _LAUNCHER.read_text()
    assert "*[!A-Za-z0-9._/-]*" in launcher_source, (
        "launcher POLICY_REF guard class drifted from manifest.py's _POLICY_REF_BAD_CHAR"
    )
    # Reject branch: the Python producer rejects the same injection payload
    # the launcher guard defends against.
    assert _POLICY_REF_BAD_CHAR.search('config/x","event":"forged')
    # Accept branch: a legitimate path-safe policy_ref (including its
    # required `/` path separators) is NOT rejected.
    assert _POLICY_REF_BAD_CHAR.search("config/sandbox/x.linux.bwrap.policy") is None
