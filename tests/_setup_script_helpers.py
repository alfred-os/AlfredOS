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

import re
from pathlib import Path


def slice_shell_function(setup_sh: Path, func_start: str) -> str:
    """Return a top-level shell function's source, sliced out of ``setup_sh``.

    ``func_start`` is the function's declaration line (``name() {``); it must appear at
    column 0. The closing ``}`` is located by a **heredoc-aware brace-depth scan** — not the
    first ``\\n}\\n`` — so a ``}`` line inside a heredoc, or a nested ``{ … }`` group, cannot
    truncate the slice (#470 CR: structurally safe). Anchoring on the declaration line means a
    moved/renamed function raises ``ValueError`` here rather than silently returning a stale
    copy; the caller prepends the result to a sliced call-site block.
    """
    lines = setup_sh.read_text().splitlines(keepends=True)
    anchor = func_start.rstrip("\n")
    start = next((i for i, ln in enumerate(lines) if ln.rstrip("\n") == anchor), None)
    if start is None:
        raise ValueError(f"{func_start!r} not found as a top-level declaration line")

    heredoc_delim: str | None = None
    depth = 0
    for i in range(start, len(lines)):
        line = lines[i]
        if heredoc_delim is not None:
            # Inside a heredoc everything is literal, including ``}`` lines; only the
            # delimiter (optionally indented, for ``<<-``) ends it.
            if line.strip() == heredoc_delim:
                heredoc_delim = None
            continue
        opened = re.search(r"<<-?\s*[\"']?([A-Za-z_][A-Za-z0-9_]*)[\"']?", line)
        if opened:
            heredoc_delim = opened.group(1)
        depth += line.count("{") - line.count("}")
        if depth == 0:
            return "".join(lines[start : i + 1])
    raise ValueError(f"{func_start!r} never closes (unbalanced braces)")


def slice_shell_step(setup_sh: Path, step_title: str) -> str:
    """Return one ``step "<step_title>"`` block, sliced out of ``setup_sh``.

    Runs from the ``step "<step_title>"`` marker line to (but not including) the next top-level
    ``step "`` marker, or EOF. Anchoring on the exact title raises ``ValueError`` on a
    renamed/removed step rather than returning a stale/empty block — same fail-loud contract as
    :func:`slice_shell_function`. Both the anchor and the boundary match at **column 0** (setup.sh
    calls ``step`` only at top level), so an *indented* ``step "..."`` (a nested call inside an
    ``if``/loop, or a heredoc line) can neither anchor nor prematurely truncate the slice, and the
    ``step()`` function *definition* (no quote) is skipped. For cross-document consistency tests
    that need a step's content.
    """
    lines = setup_sh.read_text().splitlines(keepends=True)
    anchor = f'step "{step_title}"'
    start = next((i for i, ln in enumerate(lines) if ln.rstrip() == anchor), None)
    if start is None:
        raise ValueError(f"{anchor!r} not found in {setup_sh}")
    end = next(
        (j for j in range(start + 1, len(lines)) if lines[j].startswith('step "')),
        len(lines),
    )
    return "".join(lines[start:end])
