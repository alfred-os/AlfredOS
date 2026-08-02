"""#496: every tracked shell script is LF-only.

A CRLF `.sh` breaks `bash` under WSL (over `/mnt/c` on a Windows checkout)
with a `\r`/bad-interpreter error. `.gitattributes` `eol=lf` enforces this on
checkout; this test guards the invariant directly, on every OS CI leg.

`test_all_shell_scripts_are_lf` alone is VACUOUS on a unix checkout — the
repo's `.sh` content is already LF there, so it can only ever pass locally
and can never demonstrate it would catch a real regression. The
`test_find_crlf_shell_scripts_*` / `test_has_crlf_*` / `test_is_shell_script_*`
cases below exercise the same detection logic
(`tests._shell_lf_guard`) against scratch fixtures, so the invariant has
tests that can actually go RED.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from tests._shell_lf_guard import find_crlf_shell_scripts, has_crlf, is_shell_script

_REPO_ROOT = Path(__file__).resolve().parents[3]


def test_all_shell_scripts_are_lf() -> None:
    """End-to-end: no tracked shell script in the real repo has CRLF."""
    tracked = subprocess.run(
        ["git", "ls-files", "*.sh", "bin/*"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="surrogateescape",
        check=True,
        cwd=_REPO_ROOT,
    ).stdout.split()
    assert tracked, "expected at least one tracked shell script under git ls-files"
    offenders = find_crlf_shell_scripts(tracked, _REPO_ROOT)
    assert not offenders, f"CRLF found in shell scripts (must be LF): {offenders}"


def test_is_shell_script_matches_dot_sh_extension() -> None:
    assert is_shell_script("bin/alfred-setup.sh", b"") is True


def test_is_shell_script_matches_bash_shebang_without_dot_sh_suffix() -> None:
    # Covers a hypothetical future bin/ launcher that wraps bash but doesn't
    # carry the .sh suffix (mirrors the brief's explicit shebang-sweep step).
    assert is_shell_script("bin/launcher", b"#!/usr/bin/env bash\necho hi\n") is True


def test_is_shell_script_rejects_non_shell_file() -> None:
    assert is_shell_script("bin/alfred-setup.ps1", b"# PowerShell comment\n") is False


def test_has_crlf_detects_crlf_bytes() -> None:
    assert has_crlf(b"echo hi\r\necho bye\n") is True


def test_has_crlf_false_on_lf_only_content() -> None:
    assert has_crlf(b"echo hi\necho bye\n") is False


def test_find_crlf_shell_scripts_flags_a_crlf_scratch_fixture(tmp_path: Path) -> None:
    """Non-vacuity proof: a real CRLF fixture makes the detector fail. This is
    the RED evidence the end-to-end guard test above cannot produce locally on
    a unix checkout (see module docstring)."""
    (tmp_path / "offender.sh").write_bytes(b"#!/bin/sh\r\necho hi\r\n")
    (tmp_path / "clean.sh").write_bytes(b"#!/bin/sh\necho hi\n")

    offenders = find_crlf_shell_scripts(["offender.sh", "clean.sh"], tmp_path)

    assert offenders == ["offender.sh"]


def test_find_crlf_shell_scripts_ignores_a_path_missing_on_disk(tmp_path: Path) -> None:
    """A path git reports that isn't a regular file on disk (e.g. a submodule
    gitlink) is skipped rather than raising."""
    assert find_crlf_shell_scripts(["does-not-exist.sh"], tmp_path) == []
