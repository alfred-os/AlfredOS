"""#496: pure CRLF-detection helpers for the shell-script LF-only invariant.

Factored out of `tests/unit/meta/test_shell_scripts_lf.py` so the detection
logic itself carries a unit test against a real CRLF fixture. The end-to-end
guard test alone can only prove a POSITIVE on a unix checkout — every tracked
`.sh` there is already LF, so it can never turn RED locally on its own; this
module gives the underlying detection logic something a test can actually
fail against (see `test_find_crlf_shell_scripts_flags_a_crlf_scratch_fixture`).
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path


def is_shell_script(rel_path: str, head: bytes) -> bool:
    """True if `rel_path` names a `.sh` file, or `head`'s first line is a
    POSIX-shell shebang (covers a hypothetical `bin/` launcher that wraps
    bash/sh without carrying the `.sh` suffix)."""
    if rel_path.endswith(".sh"):
        return True
    first_line = head.split(b"\n", 1)[0]
    return first_line.startswith(b"#!") and b"sh" in first_line


def has_crlf(content: bytes) -> bool:
    """True if `content` contains at least one CRLF (`\\r\\n`) byte pair."""
    return b"\r\n" in content


def find_crlf_shell_scripts(tracked_paths: Iterable[str], root: Path) -> list[str]:
    """Return the entries of `tracked_paths` (resolved under `root`) that are
    shell scripts (per `is_shell_script`) containing CRLF line endings.

    `tracked_paths` are repo-relative, as reported by `git ls-files`. A path
    git reports that isn't a regular file on disk (e.g. a submodule gitlink)
    is skipped rather than raising.
    """
    offenders = []
    for rel in tracked_paths:
        candidate = root / rel
        if not candidate.is_file():
            continue
        content = candidate.read_bytes()
        if is_shell_script(rel, content[:4096]) and has_crlf(content):
            offenders.append(rel)
    return offenders
