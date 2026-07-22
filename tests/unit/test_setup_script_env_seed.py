"""Real-execution regression test for the GF_SECURITY_ADMIN_PASSWORD seed step.

#470 PR2 Task 3 (rev.4 test-003): the seed guard's failure mode is a *silent weak
credential* — a bug here means an operator who ran ``bin/alfred-setup.sh`` still ends
up with an empty (or duplicated, last-wins-is-shell-dependent) admin password on a
normal first run. That is a RUNTIME fact about what the script does to a file — a
static-text/grep assertion cannot decide it (contrast the deliberately grep-only
``test_setup_script_audit_pepper.py`` in this directory, which pins only that certain
substrings exist in the source). So this test drives the REAL seed block under
``bash`` against a temp ``.env`` and asserts on the post-run file bytes.

Extraction seam: the seed step is sliced straight out of ``bin/alfred-setup.sh`` by
its ``step "..."`` markers — the same technique
``tests/integration/test_setup_script_credential_gate.py`` and
``tests/unit/test_setup_script_audit_pepper.py`` already use for their own blocks —
so the test can never silently drift onto stale source (the marker-presence
assertion below fails loud if the step is ever renamed or moved). Slicing the block
this way ALSO bypasses the credential-validation gate that immediately follows it
(``bin/alfred-setup.sh``'s "Validating .env credentials" step, which ``exit 1``s on a
placeholder ``.env``): the sliced block simply never reaches that gate, which is
exactly why block-extraction is required here rather than shelling the whole script.

No Docker, no testcontainers — just ``bash`` + ``openssl``, both already hard
prerequisites of this repo's dev/CI environment (the setup script itself requires
them). Stays in ``tests/unit`` alongside its grep-only sibling.
"""

from __future__ import annotations

# ruff: noqa: S603, S607
# Test-controlled invocations of `bash` from the unit suite. Every argv is a literal
# authored in this module; nothing crosses an untrusted boundary.
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from tests._setup_script_helpers import slice_shell_function

_SETUP_SH = Path("bin/alfred-setup.sh")
_BLOCK_START = 'step "Seeding Grafana admin password"'
_BLOCK_END = 'step "Validating .env credentials"'
_FUNC_START = "openssl_missing_message() {"


def _seed_block() -> str:
    """Slice the Grafana password seed step out of the real script.

    Anchored on the ``step`` markers so a moved/renamed block fails loud here
    rather than silently running a stale copy (mirrors
    ``test_setup_script_credential_gate.py::_credential_gate_block``).
    """
    content = _SETUP_SH.read_text()
    start = content.index(_BLOCK_START)
    end = content.index(_BLOCK_END)
    assert start < end, f"{_BLOCK_START!r} must precede {_BLOCK_END!r} in bin/alfred-setup.sh"
    return content[start:end]


def _openssl_missing_message_func() -> str:
    """Slice the shared ``openssl_missing_message`` helper out of the real script.

    #470 M5: the seed block's openssl-missing branch now calls this shared helper
    (also used by the audit.hash_pepper bootstrap further down) instead of printing
    its own inline message. The helper is defined OUTSIDE the ``_seed_block()``
    slice (it lives near the script's other top-level helpers, before "Checking
    prerequisites"), so ``_run_seed`` must prepend it explicitly or the sliced
    script would fail with a bash "command not found" instead of exercising the
    real per-distro guidance. Anchored on the function's opening line so a
    moved/renamed helper fails loud here rather than silently running a stale copy.
    """
    return slice_shell_function(_SETUP_SH, _FUNC_START)


def _run_seed(
    tmp_path: Path,
    env_text: str,
    *,
    stub_openssl: bool = False,
) -> subprocess.CompletedProcess[str]:
    """Run the real seed block in ``tmp_path`` against ``env_text`` as ``.env``.

    ``step()`` is stubbed to a no-op — the real definition (used only for a
    console banner) lives earlier in the script and pulls in nothing the seed
    block needs.
    """
    (tmp_path / ".env").write_text(env_text)
    script = (
        "set -euo pipefail\nstep() { :; }\n"
        + _openssl_missing_message_func()
        + "\n"
        + _seed_block()
    )
    path = "/usr/bin:/bin:/usr/sbin:/sbin"
    if stub_openssl:
        # Symlink only a safe whitelist into a private bin dir and point PATH at it
        # alone — openssl deliberately excluded, so `command -v openssl` fails and
        # the friendly-error branch runs. Mirrors
        # test_setup_script_audit_pepper.py's stub_openssl fixture.
        stub_bin = tmp_path / "stub_bin"
        stub_bin.mkdir(exist_ok=True)
        for tool in ("bash", "sh", "grep", "sed", "printf", "rm", "cat"):
            tool_path = shutil.which(tool)
            if tool_path is None:
                continue
            link = stub_bin / tool
            if not link.exists():
                link.symlink_to(tool_path)
        path = str(stub_bin)
        assert shutil.which("openssl", path=path) is None, f"openssl still on stubbed PATH: {path}"
    return subprocess.run(
        ["bash", "-c", script],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        env={"PATH": path},
        check=False,
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


def test_the_seed_markers_still_match_the_script() -> None:
    """Guard the guard — a silently-empty slice would make every test below vacuous."""
    block = _seed_block()
    assert "GF_SECURITY_ADMIN_PASSWORD" in block
    assert "openssl rand -hex 24" in block
    func = _openssl_missing_message_func()
    assert "openssl_missing_message() {" in func
    assert func.rstrip().endswith("}")


def test_existing_empty_line_is_replaced_with_a_generated_value(
    bash_available: str,
    openssl_available: str,
    tmp_path: Path,
) -> None:
    """The `cp .env.example .env` first-run shape: an existing EMPTY line is REPLACED.

    This is the exact case an "append if absent" guard misses (sec-004) —
    `.env.example` ships the key present-but-empty, so a script that only checks
    "is the key present at all" would silently skip seeding and Grafana would boot
    on an empty admin password.
    """
    result = _run_seed(tmp_path, "ALFRED_DEEPSEEK_API_KEY=sk-real\nGF_SECURITY_ADMIN_PASSWORD=\n")
    assert result.returncode == 0, f"seed failed:\nstdout: {result.stdout}\nstderr: {result.stderr}"
    content = (tmp_path / ".env").read_text()
    lines = [ln for ln in content.splitlines() if ln.startswith("GF_SECURITY_ADMIN_PASSWORD=")]
    assert len(lines) == 1, f"expected exactly one GF_SECURITY_ADMIN_PASSWORD= line, got: {lines!r}"
    value = lines[0].removeprefix("GF_SECURITY_ADMIN_PASSWORD=")
    assert value, "the empty line must be replaced with a generated (non-empty) value"
    assert re.fullmatch(r"[0-9a-f]{48}", value), (
        f"value is not a 48-hex-char string (openssl rand -hex 24): {value!r}"
    )
    # The rest of the file must be untouched (no reordering, no dropped lines).
    assert "ALFRED_DEEPSEEK_API_KEY=sk-real" in content


def test_existing_non_empty_value_is_preserved_byte_for_byte(
    bash_available: str,
    openssl_available: str,
    tmp_path: Path,
) -> None:
    """Re-running setup must NEVER rotate an operator's password from under a running Grafana."""
    original = "GF_SECURITY_ADMIN_PASSWORD=my-operator-chosen-value\n"
    result = _run_seed(tmp_path, original)
    assert result.returncode == 0, f"seed failed:\nstdout: {result.stdout}\nstderr: {result.stderr}"
    assert (tmp_path / ".env").read_text() == original, (
        "re-running the seed must leave an existing non-empty value byte-for-byte unchanged"
    )


def test_result_always_has_exactly_one_key_no_duplicate_append(
    bash_available: str,
    openssl_available: str,
    tmp_path: Path,
) -> None:
    """No duplicate-key append — last-wins semantics on a duplicate key are shell-dependent.

    Exercises the third required case: the key ABSENT entirely (an operator-authored
    `.env` written from scratch, never copied from `.env.example`).
    """
    result = _run_seed(tmp_path, "ALFRED_DEEPSEEK_API_KEY=sk-real\n")
    assert result.returncode == 0, f"seed failed:\nstdout: {result.stdout}\nstderr: {result.stderr}"
    content = (tmp_path / ".env").read_text()
    assert content.count("GF_SECURITY_ADMIN_PASSWORD=") == 1, (
        f"expected exactly one GF_SECURITY_ADMIN_PASSWORD= key, got:\n{content}"
    )


def test_openssl_missing_fails_loud_with_an_actionable_error(
    bash_available: str,
    tmp_path: Path,
) -> None:
    """Without openssl on PATH the seed exits non-zero with a clear, actionable error.

    Exercises the graceful `command -v openssl` preflight (rev.4 devops-003/sec-005)
    added alongside the seed itself — a bare `openssl rand` under `set -euo
    pipefail` would otherwise abort opaquely.

    #470 M5: a bare "openssl" substring passed even against a "command not found"
    shell error (which itself contains the word "openssl" in the failing command's
    NAME) — that would not have caught a regression back to an unhelpful one-liner.
    Assert the ACTIONABLE per-distro content the shared ``openssl_missing_message``
    helper prints (mirrors the audit.hash_pepper bootstrap's message): an install
    verb plus at least one concrete package manager, so the error tells an operator
    what to actually run rather than just naming the missing tool.
    """
    result = _run_seed(tmp_path, "GF_SECURITY_ADMIN_PASSWORD=\n", stub_openssl=True)
    assert result.returncode != 0, (
        f"openssl-missing path returned 0:\nstdout: {result.stdout}\nstderr: {result.stderr}"
    )
    stderr_lower = result.stderr.lower()
    assert "openssl" in stderr_lower, f"openssl-missing error not on stderr: {result.stderr!r}"
    assert "install" in stderr_lower, (
        f"openssl-missing error is not actionable (no install verb): {result.stderr!r}"
    )
    assert any(mgr in stderr_lower for mgr in ("apt", "dnf", "pacman", "apk", "brew")), (
        f"openssl-missing error names no concrete package manager: {result.stderr!r}"
    )
