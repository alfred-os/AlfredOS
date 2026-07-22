"""Shared helpers for tests that slice functions out of ``bin/alfred-setup.sh``.

Several setup-script tests exercise a single shell function in isolation by
slicing it out of the real script and prepending it to a sliced call-site block.
Keeping the slice logic here (rather than duplicated per test file) means the
anchor/closing-brace heuristic lives in one place — see #470 M5 (CodeRabbit /
test-engineer flagged the duplication across
``tests/unit/test_setup_script_env_seed.py`` and
``tests/integration/test_setup_script_pepper_behavior.py``).
"""

from __future__ import annotations

from pathlib import Path


def slice_shell_function(setup_sh: Path, func_start: str) -> str:
    """Return a top-level shell function's source (from its ``name() {`` opening
    line through the matching ``\\n}\\n``) sliced out of ``setup_sh``.

    Anchored on the opening line so a moved/renamed function raises ``ValueError``
    here rather than silently returning a stale copy — the caller must prepend the
    result to a sliced block that calls the function, or the reconstructed script
    would fail with a bash "command not found" instead of exercising the real code.
    """
    content = setup_sh.read_text()
    start = content.index(func_start)
    end = content.index("\n}\n", start) + len("\n}\n")
    return content[start:end]
