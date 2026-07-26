"""Structural invariants for the GitHub Actions workflows (#514).

Sibling of ``test_compose_invariants.py`` / ``test_dockerfile_invariants.py``: the
workflows are load-bearing infrastructure that no Python test would otherwise read, so
the invariants that keep the *gates* honest are pinned here.

The motivating defect (#514): every source-probe guard used

    find <dir> -name '*.py' | grep -q .

``grep -q`` exits on its FIRST match, ``find`` then takes ``SIGPIPE`` and dies with status
141, and ``set -o pipefail`` propagates that as the pipeline status — so the probe reports
"no source" for a tree that is full of source. It is a race that depends on how many paths
``find`` emits: on ``ubuntu-latest`` a 73-entry directory survived while a 292-entry one did
not, which is why it went unnoticed for a month and why "it passes today" is not a defence.

Six jobs in ``pr-validate-python.yml`` (including the REQUIRED ``tag(T3)`` security gate and
``i18n catalog drift``) plus CodeQL skipped every real step and reported success.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

_WORKFLOW_DIR = Path(__file__).resolve().parents[2] / ".github" / "workflows"

# `find ... | grep -q` — the pipe is the defect: `grep -q`'s early exit is what SIGPIPEs `find`.
# Applied to LOGICAL lines (shell continuations already joined), because the real CodeQL
# offender spells its `find` across five backslash-continued lines and a naive per-physical-line
# scan silently misses it — a drift guard that under-counts is worse than none.
_FIND_PIPED_TO_GREP_Q = re.compile(r"\bfind\b.*\|\s*grep\s+-q")


def _logical_lines(text: str) -> list[tuple[int, str]]:
    """Join backslash-continued shell lines, keeping each fragment's FIRST physical line no."""
    joined: list[tuple[int, str]] = []
    buffer = ""
    start = 0
    for lineno, physical in enumerate(text.splitlines(), start=1):
        if not buffer:
            start = lineno
        stripped = physical.rstrip()
        if stripped.endswith("\\"):
            buffer += stripped[:-1] + " "
            continue
        joined.append((start, buffer + physical))
        buffer = ""
    if buffer:
        joined.append((start, buffer))
    return joined


def _workflow_files() -> list[Path]:
    files = sorted(_WORKFLOW_DIR.glob("*.yml")) + sorted(_WORKFLOW_DIR.glob("*.yaml"))
    # Anti-vacuity: this suite is worthless if the glob silently matches nothing.
    assert files, f"no workflow files found under {_WORKFLOW_DIR} — the invariant is vacuous"
    return files


def test_detector_catches_a_multi_line_find() -> None:
    """Non-vacuity control: the detector must see a backslash-continued `find` (the CodeQL shape).

    Pinned because the first version of this guard scanned physical lines and therefore missed
    `codeql.yml` — the single most consequential offender (CodeQL security analysis had been
    silently skipping). A detector that cannot see the real bug is a paper gate.
    """
    multi_line = "if find . -name '*.py' \\\n     -not -path './x/*' 2>/dev/null | grep -q .; then"
    assert any(_FIND_PIPED_TO_GREP_Q.search(text) for _, text in _logical_lines(multi_line)), (
        "detector failed to join shell continuations — it would under-count real offenders"
    )

    single_line = "if [ -d src ] && find src -name '*.py' | grep -q .; then"
    assert any(_FIND_PIPED_TO_GREP_Q.search(text) for _, text in _logical_lines(single_line))

    # And it must NOT fire on a legitimate `grep -q` that reads a FILE, not a `find` pipe.
    benign = "if grep -q '^PROBE_RESULT=OK$' control.log; then"
    assert not any(_FIND_PIPED_TO_GREP_Q.search(text) for _, text in _logical_lines(benign))


def test_source_probes_are_fail_closed() -> None:
    """A source probe must never report success while gating nothing (#514).

    The original guards' else-branch wrote ``has_source=false`` + a ``::notice::`` and let the
    job PASS, so six jobs (including the required ``tag(T3)`` and ``i18n catalog drift`` gates)
    plus CodeQL reported success without executing a single real step. ``adversarial.yml``
    already had the right posture — fail loud — and this pins every probe to it.

    These directories are permanent; "nothing found" means the probe broke.
    """
    stale_skips = []
    for workflow in _workflow_files():
        for lineno, text in _logical_lines(workflow.read_text(encoding="utf-8")):
            stripped = text.strip()
            if stripped.startswith("#"):
                continue
            # The obsolete rationale that made a green skip look intentional.
            if "expected pre-Slice-1" in stripped:
                stale_skips.append(f"{workflow.name}:{lineno}: {stripped[:110]}")
    assert not stale_skips, (
        "a source probe still skips-and-passes on the obsolete 'pre-Slice-1' rationale; "
        "src/ and tests/ are permanent, so the probe finding nothing means it BROKE (#514):\n  "
        + "\n  ".join(stale_skips)
    )


@pytest.mark.parametrize("workflow", _workflow_files(), ids=lambda p: p.name)
def test_no_find_piped_into_grep_q(workflow: Path) -> None:
    """No workflow may probe for files with ``find ... | grep -q`` (#514).

    Use a form that cannot SIGPIPE because nothing reads the pipe early::

        if [ -n "$(find src -name '*.py' -print -quit)" ]; then

    ``-print -quit`` makes ``find`` stop after the first hit itself — one process, no pipe.
    """
    offenders = [
        f"{workflow.name}:{lineno}: {text.strip()[:120]}"
        for lineno, text in _logical_lines(workflow.read_text(encoding="utf-8"))
        # Skip comments: a `#`-prefixed line is not executable shell, and the fix's own
        # in-workflow note necessarily NAMES the banned idiom to warn against it.
        if not text.lstrip().startswith("#") and _FIND_PIPED_TO_GREP_Q.search(text)
    ]
    assert not offenders, (
        "`find … | grep -q` SIGPIPEs `find` under `set -o pipefail` once the file list is "
        "large enough, so the probe reports 'no source' and the gate silently skips while "
        'reporting success (#514). Use `[ -n "$(find … -print -quit)" ]`.\n  '
        + "\n  ".join(offenders)
    )
