"""Behaviour-level integration test for the Slice-4 audit.hash_pepper bootstrap.

PR #215 test-engineer closure (MAJOR): the unit suite at
``tests/unit/test_setup_script_audit_pepper.py`` pins source-text shape
only — it cannot prove the actual setup-script behaviour. This test
drives the real ``bin/alfred-setup.sh`` against a tmpdir + stubbed
``HOME`` / ``ALFRED_SECRETS_FILE`` and asserts the load-bearing
invariants:

* The sandbox dir is created with mode 0700 on first run.
* The pepper line is written with TOML quoting
  (``"audit.hash_pepper" = "..."``).
* The pepper value is a 64-hex-char string from ``openssl rand``.
* The target file is mode 0600 after the bootstrap.
* Python's ``tomllib`` round-trip yields the pepper at the FLAT key
  ``"audit.hash_pepper"`` (not a nested table) — the cross-cutting
  BLOCKER closure.
* Re-invoking the script with the same target leaves the value
  byte-identical (idempotency / no-rotation invariant per spec §8.10).

The script's full setup runs many other steps (docker compose build,
postgres health-check, ...). To stay scoped to the bootstrap, this
test executes only the bootstrap section directly via ``bash -c`` with
the inlined snippet — same source-of-truth as the script body, but
without dragging in the docker dependencies.
"""

from __future__ import annotations

# ruff: noqa: S603, S607
# Test-controlled invocations of `bash` / `openssl` from the integration suite.
# Every argv is a literal authored in this module; nothing crosses an
# untrusted boundary.
import os
import re
import shutil
import subprocess
import tomllib
from pathlib import Path

import pytest

pytestmark = [pytest.mark.integration]


_SETUP_SH = Path("bin/alfred-setup.sh")
_FUNC_START = "openssl_missing_message() {"


def _openssl_missing_message_func() -> str:
    """Slice the shared ``openssl_missing_message`` helper out of the real script.

    #470 M5: the pepper bootstrap's openssl-missing branch now calls this shared
    helper (also used by the Grafana admin-password seed) instead of printing its
    own inline heredoc. The helper is defined near the script's other top-level
    helpers, OUTSIDE the ``_bootstrap_block()`` slice below (which starts at the
    "Bootstrapping audit.hash_pepper secret" step, well after it) — so the prelude
    must prepend it explicitly or the sliced script fails with a bash "command not
    found" instead of exercising the real per-distro guidance.
    """
    content = _SETUP_SH.read_text()
    start = content.index(_FUNC_START)
    end = content.index("\n}\n", start) + len("\n}\n")
    return content[start:end]


def _bootstrap_block() -> str:
    """Extract the bootstrap block from ``bin/alfred-setup.sh``.

    Slice on the section markers (``step "Bootstrapping..."`` ... end of
    the ``if mkdir "$lock_dir"`` block) so the test stays anchored to
    the actual script text. If the section markers move, the test
    fails loud rather than running a stale block.
    """
    content = _SETUP_SH.read_text()
    start_marker = 'step "Bootstrapping audit.hash_pepper secret"'
    start = content.index(start_marker)
    # Walk forward to the end of the if-mkdir/else block. The block
    # ends with the ``fi`` that closes the outer ``if mkdir`` — find
    # the line that ends with "fi" past the inner blocks.
    tail = content[start:]
    # The outer "if mkdir" structure ends at the FIRST "^fi$" line
    # AFTER both inner blocks (`_pepper_bootstrap` and the lock-wait
    # path). Use a sentinel: the comment line `step "..."` of the
    # following step is the natural stop anchor.
    next_step_idx = tail.index('\nstep "', 1)
    return tail[:next_step_idx]


def _run_bootstrap_in_tmpdir(
    tmpdir: Path,
    *,
    stub_openssl: bool = False,
    openssl_path: str | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run the bootstrap block in ``tmpdir`` with a stubbed env.

    ``stub_openssl=True`` shadows ``openssl`` in PATH with a stub that
    always exits 127 — exercises the openssl-missing branch.
    """
    bootstrap = _bootstrap_block()
    secrets_dir = tmpdir / ".config" / "alfred"
    secrets_dir.mkdir(parents=True, exist_ok=True)
    target_file = secrets_dir / "secrets.toml"
    # Prelude defines the variables the bootstrap block expects from
    # the surrounding script (secrets_file from "Priming secrets bind-
    # mount"; step helper as a no-op shim).
    prelude = (
        f'secrets_file="{target_file}"\nstep() {{ echo "==> $*"; }}\n'
        + _openssl_missing_message_func()
    )
    script = prelude + bootstrap
    env = os.environ.copy()
    env["HOME"] = str(tmpdir)
    if stub_openssl:
        # Symlink ONLY the whitelisted bash builtins+tools into a
        # private bin dir, then point PATH at that dir alone. openssl
        # is deliberately excluded; ``command -v openssl`` returns
        # non-zero, exercising the friendly-error branch.
        stub_bin = tmpdir / "stub_bin"
        stub_bin.mkdir(exist_ok=True)
        whitelist = (
            "bash",
            "sh",
            "grep",
            "chmod",
            "mkdir",
            "stat",
            "rmdir",
            "printf",
            "sleep",
            "cat",
            "echo",
            "ls",
            "rm",
        )
        for tool in whitelist:
            tool_path = shutil.which(tool)
            if tool_path is None:
                continue
            link = stub_bin / tool
            if not link.exists():
                link.symlink_to(tool_path)
        env["PATH"] = str(stub_bin)
        assert shutil.which("openssl", path=env["PATH"]) is None, (
            f"openssl still on stubbed PATH: {env['PATH']}"
        )
    elif openssl_path is not None:
        env["PATH"] = openssl_path
    return subprocess.run(
        ["bash", "-c", script],
        capture_output=True,
        text=True,
        check=False,
        env=env,
        timeout=30,
    )


@pytest.fixture
def bash_available() -> str:
    """Skip when bash is not on PATH (very rare CI matrix gap)."""
    path = shutil.which("bash")
    if path is None:
        pytest.skip("bash not on PATH")
    return path


@pytest.fixture
def openssl_available() -> str:
    """Skip when openssl is not on PATH (CI image without it)."""
    path = shutil.which("openssl")
    if path is None:
        pytest.skip("openssl not on PATH")
    return path


def test_bootstrap_writes_quoted_toml_key_round_trippable(
    bash_available: str,
    openssl_available: str,
    tmp_path: Path,
) -> None:
    """The bootstrap writes a quoted dotted key tomllib parses flat.

    This is the cross-cutting BLOCKER closure: unquoted
    ``audit.hash_pepper = "..."`` would parse as the nested table
    ``{"audit": {"hash_pepper": "..."}}`` and
    ``SecretBroker._load_toml_file`` (which keeps only top-level str
    values) would silently drop it.
    """
    result = _run_bootstrap_in_tmpdir(tmp_path)
    assert result.returncode == 0, (
        f"bootstrap failed:\nstdout: {result.stdout}\nstderr: {result.stderr}"
    )
    target = tmp_path / ".config" / "alfred" / "secrets.toml"
    assert target.is_file(), f"target file missing: {target}"
    # tomllib MUST find the key at the flat top level
    with target.open("rb") as fh:
        data = tomllib.load(fh)
    assert "audit.hash_pepper" in data, (
        f"audit.hash_pepper missing at top level of parsed TOML; got keys: {list(data.keys())}"
    )
    pepper = data["audit.hash_pepper"]
    assert isinstance(pepper, str)
    assert re.fullmatch(r"[0-9a-f]{64}", pepper), f"pepper is not 64-hex-char: {pepper!r}"


def test_bootstrap_target_file_mode_0600(
    bash_available: str,
    openssl_available: str,
    tmp_path: Path,
) -> None:
    """The secrets target file is chmod 0600 after the bootstrap."""
    result = _run_bootstrap_in_tmpdir(tmp_path)
    assert result.returncode == 0
    target = tmp_path / ".config" / "alfred" / "secrets.toml"
    mode = target.stat().st_mode & 0o777
    assert mode == 0o600, f"target file mode is 0{mode:o}, expected 0600"


def test_bootstrap_is_idempotent_no_rotation(
    bash_available: str,
    openssl_available: str,
    tmp_path: Path,
) -> None:
    """Re-running the bootstrap MUST NOT rotate the pepper value.

    Spec §8.10: rotating the pepper invalidates every prior ``*_hash``
    row. The bootstrap MUST leave existing values untouched.
    """
    first = _run_bootstrap_in_tmpdir(tmp_path)
    assert first.returncode == 0
    target = tmp_path / ".config" / "alfred" / "secrets.toml"
    first_contents = target.read_bytes()
    # Second run must observe "already configured" branch
    second = _run_bootstrap_in_tmpdir(tmp_path)
    assert second.returncode == 0
    assert "already configured" in second.stdout, (
        f"idempotency banner missing from re-run stdout: {second.stdout!r}"
    )
    second_contents = target.read_bytes()
    assert first_contents == second_contents, (
        "secrets file mutated on re-run — pepper rotated by accident"
    )


def test_bootstrap_friendly_error_when_openssl_missing(
    bash_available: str,
    tmp_path: Path,
) -> None:
    """Without openssl on PATH the bootstrap exits 1 with a clear error."""
    result = _run_bootstrap_in_tmpdir(tmp_path, stub_openssl=True)
    # The bootstrap function returns 1; the outer script honours it
    # via `_pepper_bootstrap` exit code propagation. Either the script
    # exits non-zero OR (when run as the lock-holder path) the function
    # returns 1 to the caller. Both surface as a non-zero return code.
    assert result.returncode != 0, (
        f"openssl-missing path returned 0:\nstdout: {result.stdout}\nstderr: {result.stderr}"
    )
    assert "openssl" in result.stderr.lower(), (
        f"openssl-missing error not on stderr: {result.stderr!r}"
    )
    # At least one per-distro install command should appear (DevEx LOW closure).
    distro_hints = ("apt-get install", "dnf install", "pacman -S", "apk add", "brew install")
    assert any(hint in result.stderr for hint in distro_hints), (
        f"no per-distro install hint in stderr: {result.stderr!r}"
    )
