"""Structural invariants for the CI gating surfaces (#514).

Sibling of ``test_compose_invariants.py`` / ``test_dockerfile_invariants.py``: workflows and
the ``Makefile`` are load-bearing infrastructure no other Python test reads, so the invariants
that keep the *gates honest* are pinned here.

The motivating defect (#514): source probes were written as::

    find <dir> -name '*.py' | grep -q .

``grep -q`` exits on its FIRST match, ``find`` then takes SIGPIPE and dies with status 141, and
``set -o pipefail`` propagates that — so the probe reports "no source" for a tree full of source.

It is a size/speed race, not a clean platform split: on ``ubuntu-latest`` a 73-entry directory
survived while a 292-entry one did not. "It passes today" is therefore never a defence — every
surviving instance is one directory-growth away from flipping. Six ``pr-validate-python`` jobs
(including the REQUIRED ``tag(T3)`` gate and ``i18n catalog drift``) plus CodeQL skipped every
real step and reported success for about a month.

The general hazard is **an early-exiting reader on the right-hand side of a pipe under
``pipefail``** — not specifically ``find`` and not specifically ``grep -q``. Both sides are
therefore matched as sets, because the first draft of this guard matched only ``find … |
grep -q`` and would have missed the ``grep -Eq`` spelling already live in two workflows.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
_WORKFLOW_DIR = _REPO_ROOT / ".github" / "workflows"

# Producers that stream (so a reader closing early can SIGPIPE/EPIPE them).
# Any command that STREAMS its output can be SIGPIPEd by a reader that closes early.
# `grep`/`awk`/`sed`/`jq`/`rg` reading a FILE are producers too — verified in ubuntu:24.04,
# `grep pat big.txt | head -1` and `awk … big.txt | head -1` both give pipeline status 141
# and an `if` around that shape evaluates FALSE (CodeRabbit, PR #516).
_PRODUCER = r"(?:find|git\s+ls-files|printf|echo|cat|ls|docker\s+compose\s+ps|grep|rg|awk|jq|sed)\b"
# Readers that exit before draining stdin. `grep -q`/`-Eq`/`-qE`/`-m1`, `head -1`, `sed q`, `read`.
_EARLY_EXIT_READER = (
    r"(?:grep\s+(?:-[A-Za-z]*q[A-Za-z]*|-m\s*1|--max-count[= ]1)"
    r"|head\s+(?:-n\s*)?-?1\b"
    r"|sed\s+(?:-n\s*)?['\"]?q"
    r"|read\b)"
)
_PIPE_INTO_EARLY_EXIT = re.compile(rf"{_PRODUCER}.*\|\s*{_EARLY_EXIT_READER}")

# `|| true` (or an explicit `|| :`) neutralises pipefail, so the pipeline cannot poison the
# exit status. ci.yml uses this deliberately for value extraction — not a defect.
_PIPEFAIL_NEUTRALISED = re.compile(r"\|\|\s*(?:true|:)\b")

# A probe that writes `has_*=false` and lets the job PASS. The quote after `false` is
# load-bearing: the real line is `echo "has_source=false" >> "$GITHUB_OUTPUT"`, and a
# pattern without `"?` silently matches nothing — verified by mutation, since the first
# attempt at this guard passed while the tag(T3) branch was reverted to skip-and-pass.
_SKIP_AND_PASS_WRITE = re.compile(r'has_[a-z_]*=false"?\s*>>\s*"?\$GITHUB_OUTPUT')

# Every CI gating surface whose source probes MUST fail closed. pr-validate-python/codeql/perf
# were the actively-broken ones (#514); ci.yml's probes were already SIGPIPE-safe but still
# skip-and-passed, converted in #517. A probe finding nothing means the PROBE broke.
_FAIL_CLOSED_FILES = ("pr-validate-python.yml", "codeql.yml", "perf.yml", "ci.yml")


def _scanned_files() -> list[Path]:
    """Every CI gating surface — workflows plus the Makefile perf.yml delegates to."""
    files = sorted(_WORKFLOW_DIR.glob("*.yml")) + sorted(_WORKFLOW_DIR.glob("*.yaml"))
    makefile = _REPO_ROOT / "Makefile"
    if makefile.exists():
        files.append(makefile)
    # Anti-vacuity: this suite is worthless if the glob silently matches nothing.
    assert len(files) > 5, f"expected the CI surface under {_REPO_ROOT}; found {files}"
    return files


def _logical_lines(text: str) -> list[tuple[int, str]]:
    """Join backslash-continued shell lines, keeping each fragment's FIRST physical line no.

    A COMMENT line is never treated as a continuation: a trailing ``\\`` inside a comment would
    otherwise swallow the following real line into a ``#``-prefixed logical line, and the
    comment-skipping in the checks below would then hide a genuine offender.
    """
    joined: list[tuple[int, str]] = []
    buffer = ""
    start = 0
    for lineno, physical in enumerate(text.splitlines(), start=1):
        if not buffer:
            start = lineno
        stripped = physical.rstrip()
        is_comment = stripped.lstrip().startswith("#")
        # A trailing `\\` is an escaped literal backslash, not a continuation.
        continues = stripped.endswith("\\") and not stripped.endswith("\\\\")
        if continues and not is_comment:
            buffer += stripped[:-1] + " "
            continue
        joined.append((start, buffer + physical))
        buffer = ""
    if buffer:
        joined.append((start, buffer))
    return joined


def _executable_lines(path: Path) -> list[tuple[int, str]]:
    """Logical lines with comments dropped — comments are not executable shell."""
    return [
        (lineno, text)
        for lineno, text in _logical_lines(path.read_text(encoding="utf-8"))
        if not text.lstrip().startswith("#")
    ]


def test_detector_sees_the_shapes_it_must_see() -> None:
    """Non-vacuity control for the detector itself.

    Every entry here is a shape that a PREVIOUS draft of this guard missed, or that exists in
    the tree today. A detector that cannot see the real bug is itself a paper gate — which is
    the whole subject of #514.
    """
    must_catch = {
        # The CodeQL shape: `find` spelled across backslash-continued lines.
        "multi-line find": (
            "if find . -name '*.py' \\\n  -not -path './x/*' 2>/dev/null | grep -q .; then"
        ),
        "single-line find": "if [ -d src ] && find src -name '*.py' | grep -q .; then",
        # `grep -Eq` — the spelling live in perf.yml / pr-validate-commits.yml that the
        # first draft's `grep -q`-only regex silently missed.
        "grep -Eq": "if printf '%s\\n' \"$changed\" | grep -Eq '^src/'; then",
        "grep -qE": "if printf '%s\\n' \"$s\" | grep -qE '^fix'; then",
        "head -1": "first=$(find src -name '*.py' | head -1)",
        "git ls-files": "if git ls-files '*.py' | grep -q .; then",
        # File-reading filters stream too — the shapes CodeRabbit flagged as a bypass route.
        "grep producer": "first=$(grep '^x' large.log | head -1)",
        "awk producer": "first=$(awk '{print $1}' large.log | head -1)",
    }
    for label, snippet in must_catch.items():
        assert any(_PIPE_INTO_EARLY_EXIT.search(text) for _, text in _logical_lines(snippet)), (
            f"detector missed the {label!r} shape — it would under-count real offenders"
        )

    must_ignore = {
        # Reads a FILE, no pipe from a streaming producer.
        "grep on a file": "if grep -q '^PROBE=OK$' control.log; then",
        # Reader drains to EOF — no early exit, so nothing to SIGPIPE.
        "sort | tail": "latest=$(printf '%s\\n' \"$v\" | sort -V | tail -1)",
    }
    for label, snippet in must_ignore.items():
        assert not any(_PIPE_INTO_EARLY_EXIT.search(text) for _, text in _logical_lines(snippet)), (
            f"detector false-positived on {label!r}"
        )


def test_logical_lines_does_not_let_a_comment_swallow_code() -> None:
    """A trailing ``\\`` in a COMMENT must not absorb the next line (L2).

    Otherwise a real offender becomes part of a ``#``-prefixed logical line and is skipped.
    """
    text = "# a trailing backslash in prose \\\nfind src -name '*.py' | grep -q .\n"
    executable = [t for _, t in _logical_lines(text) if not t.lstrip().startswith("#")]
    assert any(_PIPE_INTO_EARLY_EXIT.search(t) for t in executable), (
        "a comment ending in `\\` swallowed the following line — offenders could hide behind it"
    )


@pytest.mark.parametrize("path", _scanned_files(), ids=lambda p: p.name)
def test_no_streaming_producer_piped_into_an_early_exit_reader(path: Path) -> None:
    """No CI gating surface may pipe a streaming producer into an early-exiting reader (#514).

    Use a form with no pipe to break::

        if [ -n "$(find src -name '*.py' -print -quit)" ]; then   # find stops itself
        if grep -Eq 'pat' <<<"$var"; then                          # here-string, no producer

    A pipeline explicitly neutralised with ``|| true`` is exempt: ``pipefail`` cannot then
    poison the exit status, which is how ci.yml safely extracts values with ``head -1``.
    """
    offenders = [
        f"{path.name}:{lineno}: {text.strip()[:110]}"
        for lineno, text in _executable_lines(path)
        if _PIPE_INTO_EARLY_EXIT.search(text) and not _PIPEFAIL_NEUTRALISED.search(text)
    ]
    assert not offenders, (
        "a streaming producer piped into an early-exiting reader SIGPIPEs under `pipefail` "
        "once the output outgrows the pipe buffer, so the gate silently reports the wrong "
        "answer (#514):\n  " + "\n  ".join(offenders)
    )


@pytest.mark.parametrize(
    "workflow", [f for f in _scanned_files() if f.name in _FAIL_CLOSED_FILES], ids=lambda p: p.name
)
def test_source_probes_are_fail_closed(workflow: Path) -> None:
    """Every CI source probe must FAIL, never skip-and-pass (#514, #517).

    Asserted STRUCTURALLY — on the absence of a ``has_*=false`` output write — not on the
    presence of some notice string. The first draft of this test keyed on the literal
    ``"expected pre-Slice-1"``, which two of the eight replaced branches never contained,
    including ``tag(T3)`` — the headline gate this PR is named for. Keying a guard on
    incidental prose is how it becomes a paper gate.
    """
    skip_and_pass = [
        f"{workflow.name}:{lineno}: {text.strip()[:110]}"
        for lineno, text in _executable_lines(workflow)
        if _SKIP_AND_PASS_WRITE.search(text)
    ]
    assert not skip_and_pass, (
        f"{workflow.name} still has a probe that reports success while gating nothing; these "
        "paths are permanent, so finding nothing means the PROBE broke (#514):\n  "
        + "\n  ".join(skip_and_pass)
    )
