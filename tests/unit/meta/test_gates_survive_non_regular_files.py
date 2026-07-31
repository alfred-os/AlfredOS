"""Every tree-reading gate script survives a non-regular file (#546).

Three scripts walk a directory tree and read what they find, and all three
had the same defect: `read_text`/`grep -r` on a FIFO named like a source file
BLOCKS FOREVER, so the gate never returns a verdict and CI burns its whole job
timeout with nothing reported.

They were fixed with THREE separate mechanisms, in three files, none of which
references the others:

* `check_tag_t3.py`          — `stat.S_ISREG` guard, REPORTS the path.
* `check_strict_declarations.py` — `rglob` pre-scan, REFUSES the run.
* `docs_check.py`            — `is_file()` filter, SKIPS the path.

That is exactly the shape #422 warns about: N copies of a property drift
SILENTLY, because nothing fails when one of them regresses. A shared helper
was considered and rejected for now — these are stdlib-only scripts invoked
as `python3 scripts/<name>.py`, and a sibling import resolves differently
under `spec_from_file_location` (how the suites load them) than under direct
execution, which is its own design pass.

So the drift-catcher is a DERIVED INVARIANT instead: one property, asserted
against every script, stated once. The scripts may disagree about WHAT to do
with a non-regular file — reporting, refusing and skipping are all defensible,
and the divergence is deliberate (see each site) — but none of them may HANG,
and that is what this file pins.

The census below is the anti-rot half: a NEW gate script that walks a tree
lands here as a failure on the day it is added, rather than joining the class
unguarded. It is default-deny — it derives the script list from the tree and
requires each one to be classified, rather than checking a list of the ones
somebody remembered.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

_REPO_ROOT: Path = Path(__file__).resolve().parents[3]
_SCRIPTS_DIR: Path = _REPO_ROOT / "scripts"

_NEEDS_FIFO = pytest.mark.skipif(sys.platform == "win32", reason="POSIX-only: os.mkfifo")

# How long a gate may take on a planted tree before we call it hung. Generous
# against the real work (these trees hold two files) so a loaded runner cannot
# flake it, and far below any CI job timeout so the failure is THIS assertion
# rather than a killed job with no diagnosis.
_DEADLINE_SECONDS: float = 30.0

# Scripts that walk a tree and read what they find. Each entry is
# (script name, argv builder given a planted tree root). Every one of these
# hung before #546 / the PR-#549 review.
_TREE_READING_GATES: tuple[tuple[str, str], ...] = (
    ("check_tag_t3.py", "scan_root"),
    ("check_strict_declarations.py", "repo_root_with_src"),
    ("docs_check.py", "docs_root"),
)


def _plant(tmp_path: Path, shape: str) -> tuple[Path, list[str]]:
    """Build the tree a given gate expects, with a FIFO hidden inside it.

    Returns the cwd to run from and the argv to pass. The FIFO is always named
    so that the gate's own glob picks it up — a `*.py` for the Python gates, a
    `*.md` for the docs gate. Planting one the glob ignores would make every
    assertion here vacuous.
    """
    if shape == "scan_root":
        root = tmp_path / "tree"
        root.mkdir()
        (root / "ok.py").write_text("x = 1\n", encoding="utf-8")
        fifo = root / "hang.py"
        os.mkfifo(fifo)
        # The FIFO is passed EXPLICITLY rather than by scanning `root`, and
        # that is load-bearing. `check_tag_t3.py` refuses a directory scan
        # holding fewer than `_MIN_SCANNED_FILES` (250) files with exit 2 —
        # BEFORE it reads anything. A two-file planted tree therefore returns a
        # verdict whether or not the guard exists, and the first version of
        # this case was measured VACUOUS for exactly that reason: deleting the
        # `S_ISREG` guard left it green. An explicit file argument is exempt
        # from the census and reaches the reader directly.
        return tmp_path, [str(fifo)]
    if shape == "repo_root_with_src":
        src = tmp_path / "src"
        src.mkdir()
        (src / "ok.py").write_text("x = 1\n", encoding="utf-8")
        os.mkfifo(src / "hang.py")
        return tmp_path, []
    root = tmp_path / "docs"
    root.mkdir()
    (root / "ok.md").write_text("# Title\n", encoding="utf-8")
    os.mkfifo(root / "hang.md")
    return tmp_path, [str(root)]


@_NEEDS_FIFO
@pytest.mark.parametrize(
    ("script_name", "shape"), _TREE_READING_GATES, ids=[s for s, _ in _TREE_READING_GATES]
)
def test_a_gate_script_returns_a_verdict_despite_a_fifo(
    tmp_path: Path, script_name: str, shape: str
) -> None:
    """No tree-reading gate may HANG on a non-regular file.

    Driven as a real SUBPROCESS, not in-process, for two reasons. It is how CI
    actually invokes these, so it exercises the same `__main__` path; and a
    blocked subprocess can be KILLED, whereas the in-process daemon-thread
    pattern used elsewhere leaks a thread stuck in `open()` for the life of the
    session (PR-#549 review, test-002 — measured as leaked `grep` children).

    Asserts only that a VERDICT arrives. Which verdict is each gate's own
    business and is pinned by that gate's own suite; unifying it here would
    force three scripts with three different jobs into one policy.

    `check_strict_declarations.py` resolves its scan root from `__file__`, so
    the planted tree is reached by copying the script into it rather than by
    an argument — the same trick its own suite uses.
    """
    cwd, argv = _plant(tmp_path, shape)
    script = _SCRIPTS_DIR / script_name

    if shape == "repo_root_with_src":
        (tmp_path / "scripts").mkdir()
        target = tmp_path / "scripts" / script_name
        target.write_bytes(script.read_bytes())
        script = target

    try:
        completed = subprocess.run(  # noqa: S603
            [sys.executable, str(script), *argv],
            capture_output=True,
            text=True,
            cwd=cwd,
            timeout=_DEADLINE_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired:  # pragma: no cover - the regression itself
        pytest.fail(
            f"{script_name} HUNG on a non-regular file in its scan tree: no verdict "
            f"within {_DEADLINE_SECONDS}s. In CI this burns the whole job timeout "
            f"and reports no diagnosis (#546)."
        )
    else:
        # In an `else`, not after the block: `pytest.fail` raises, so trailing
        # code is unreachable — but only if the reader (and the analyser) knows
        # that. CodeQL does not model it as NoReturn and flagged `completed` as
        # possibly-unbound (py/uninitialized-local-variable, error). Structuring
        # it so the binding cannot be missed is truer than suppressing the alert.
        assert completed.returncode in {0, 1, 2}, (
            f"{script_name} exited {completed.returncode}, which is outside its "
            f"documented exit contract\nstderr:\n{completed.stderr}"
        )


def test_the_tree_reading_gate_census_is_complete() -> None:
    """DEFAULT-DENY: a NEW tree-reading gate script must be classified here.

    Anti-rot for the parametrisation above. Without this, a fourth script that
    walks a tree and reads what it finds joins the class silently and inherits
    the hang — which is precisely how this defect came to exist in three places
    at once. Derived from the tree, not from a list somebody maintained.

    A script counts as tree-reading if its source contains a recursive glob.
    That is a LEXICAL test and cannot decide a runtime fact, so it catches a
    new script that is written like the existing ones and would miss one that
    walks a tree by some other means (`os.walk`, `iterdir` recursion). It is a
    floor, not a proof — the subprocess cases above are what actually measure
    the property.
    """
    walkers = {
        path.name
        for path in _SCRIPTS_DIR.glob("*.py")
        if "rglob(" in path.read_text(encoding="utf-8")
    }
    classified = {name for name, _ in _TREE_READING_GATES}

    assert walkers <= classified, (
        f"scripts/{sorted(walkers - classified)} walk a tree recursively but are "
        f"not covered by test_a_gate_script_returns_a_verdict_despite_a_fifo. A "
        f"gate that walks a tree can be hung by a FIFO in it (#546) — add it to "
        f"_TREE_READING_GATES with a planted-tree shape, deliberately."
    )
    assert classified <= walkers | {"check_strict_declarations.py"}, (
        f"_TREE_READING_GATES names {sorted(classified - walkers)}, which no longer "
        f"walks a tree. Stale entries make this census look broader than it is."
    )
