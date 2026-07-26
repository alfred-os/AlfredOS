"""Structural invariants for the CI gating surfaces (#514, #517).

Sibling of ``test_compose_invariants.py`` / ``test_dockerfile_invariants.py``: workflows, the
``Makefile`` and the CI-executed shell in ``bin/``/``scripts/`` are load-bearing infrastructure
no other Python test reads, so the invariants that keep the *gates honest* are pinned here.

The motivating defect (#514): source probes were written as::

    find <dir> -name '*.py' | grep -q .

``grep -q`` exits on its FIRST match, ``find`` then takes SIGPIPE and dies with status 141, and
``set -o pipefail`` propagates that — so the probe reports "no source" for a tree full of source.
It is a size/speed race: on ``ubuntu-latest`` a 73-entry directory survived while a 292-entry one
did not, so "it passes today" is never a defence. Six ``pr-validate-python`` jobs (including the
REQUIRED ``tag(T3)`` gate and ``i18n catalog drift``) plus CodeQL skipped every real step and
reported success for about a month.

BOTH invariants below are deliberately **derived and fail-closed**, because every hand-curated
version of this file has been wrong:

* v1 scanned physical lines and missed ``codeql.yml`` (its ``find`` spans continued lines).
* v2 keyed the fail-closed check on the prose ``"expected pre-Slice-1"``; two replaced branches
  never contained it — including ``tag(T3)``, the gate #514 is named for.
* v3 keyed on ``has_*=false`` but omitted the ``"?`` before ``>>``, so it matched nothing.
* v4's producer allow-list omitted ``grep``/``awk`` reading a file (CodeRabbit).
* v5's ``_FAIL_CLOSED_FILES`` was a hand-written tuple that omitted ``nightly.yml`` — whose
  ``has_adversarial`` probe gates the RELEASE-BLOCKING adversarial suite — and its
  ``has_[a-z_]*`` character class could not see ``has_e2e``.

So: the hazard test allow-lists the *safe* left-hand sides and flags everything else, and the
fail-closed test is derived from the workflow YAML rather than a file list.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

_REPO_ROOT = Path(__file__).resolve().parents[2]
_WORKFLOW_DIR = _REPO_ROOT / ".github" / "workflows"

# Readers that exit before draining stdin: `grep -q`/`-Eq`/`-qE`/`-m1`, `head -1`, `sed q`, `read`.
_EARLY_EXIT_READER = (
    r"(?:grep\s+(?:-[A-Za-z]*q[A-Za-z]*|-m\s*1|--max-count[= ]1)"
    r"|head\s+(?:-n\s*)?-?1\b"
    r"|sed\s+(?:-n\s*)?['\"]?q"
    r"|read\b)"
)
# A single `|` that is NOT part of `||`. `||` is a control operator, not a pipe.
_SINGLE_PIPE = r"(?<!\|)\|(?!\|)"
_PIPE_INTO_EARLY_EXIT = re.compile(rf"{_SINGLE_PIPE}\s*{_EARLY_EXIT_READER}")

# INVERTED POLARITY (fail-closed): anything piped into an early-exiting reader is a hazard unless
# its producer is known NOT to stream. A producer allow-list under-covers by construction — v4
# proved that — so the burden is on the safe case to be named.
_SAFE_PRODUCER_TAIL = re.compile(
    r"(?:"
    r"sort(?:\s+-\S+)*"  # sort must consume all input before emitting
    r"|wc(?:\s+-\S+)*"  # wc likewise
    r"|tail(?:\s+-\S+)*"  # tail must reach EOF
    r")\s*$"
)

# `|| true` / `|| :` neutralises pipefail so the pipeline cannot poison the exit status.
_PIPEFAIL_NEUTRALISED = re.compile(r"\|\|\s*(?:true|:)(?![\w-])")

# Steps whose `has_*` output is a PRESENCE probe must fail closed. `run_bench`-style relevance
# gates legitimately evaluate false and are excluded by the `has_` naming convention the repo uses.
_PRESENCE_OUTPUT = re.compile(r"\bhas_[a-z0-9_]*\s*=\s*true")


def _strip_quoted(text: str) -> str:
    """Blank out single/double-quoted spans so a `|` inside a regex or message is not a pipe.

    Without this, ``grep -Eq '^(src/|head -1/)'`` self-reports as a SIGPIPE hazard — a real
    false positive against perf.yml's changed-files gate.
    """
    out: list[str] = []
    quote = ""
    for ch in text:
        if quote:
            out.append(ch if ch == quote else " ")
            if ch == quote:
                quote = ""
        elif ch in "'\"":
            quote = ch
            out.append(ch)
        else:
            out.append(ch)
    return "".join(out)


def _logical_lines(text: str) -> list[tuple[int, str]]:
    """Join backslash-continued shell lines, keeping each fragment's FIRST physical line no.

    Splits on ``\\n`` only. ``str.splitlines()`` also breaks on ``\\v``/``\\f``/``\\x85``/
    ``\\u2028``, which the shell does not, so a stray form-feed would silently hide an offender.

    A COMMENT line is never a continuation: a trailing ``\\`` in prose would otherwise swallow the
    next real line into a ``#``-prefixed logical line that the checks below skip.
    """
    joined: list[tuple[int, str]] = []
    buffer = ""
    start = 0
    for lineno, physical in enumerate(text.split("\n"), start=1):
        if not buffer:
            start = lineno
        stripped = physical.rstrip("\r").rstrip()
        is_comment = stripped.lstrip().startswith("#")
        # An ODD number of trailing backslashes continues the line; an even count is
        # escaped literals.
        trailing = len(stripped) - len(stripped.rstrip("\\"))
        if trailing % 2 == 1 and not is_comment:
            # Drop the continuation backslash and collapse to exactly one separating space, so
            # the joined text is byte-comparable rather than accumulating indentation runs.
            buffer += stripped[:-1].rstrip() + " "
            continue
        joined.append((start, buffer + physical))
        buffer = ""
    if buffer:
        joined.append((start, buffer))
    return joined


def _shell_files() -> list[Path]:
    """Every CI-executed shell surface: workflows, the Makefile, and bin//scripts/ shell."""
    files = sorted(_WORKFLOW_DIR.glob("*.yml")) + sorted(_WORKFLOW_DIR.glob("*.yaml"))
    makefile = _REPO_ROOT / "Makefile"
    if makefile.exists():
        files.append(makefile)
    files += sorted((_REPO_ROOT / "bin").glob("*.sh"))
    files += sorted((_REPO_ROOT / "scripts").glob("*.sh"))
    assert len(files) > 10, f"CI shell surface not found under {_REPO_ROOT}; got {files}"
    return files


def _workflow_files() -> list[Path]:
    files = sorted(_WORKFLOW_DIR.glob("*.yml")) + sorted(_WORKFLOW_DIR.glob("*.yaml"))
    assert len(files) > 5, f"no workflows found under {_WORKFLOW_DIR} — the invariant is vacuous"
    return files


def _executable_lines(path: Path) -> list[tuple[int, str]]:
    return [
        (lineno, text)
        for lineno, text in _logical_lines(path.read_text(encoding="utf-8"))
        if not text.lstrip().startswith("#")
    ]


def _hazard_matches(raw: str) -> list[re.Match[str]]:
    """Un-neutralised, un-allow-listed pipelines feeding an early-exiting reader."""
    text = _strip_quoted(raw)
    out = []
    for match in _PIPE_INTO_EARLY_EXIT.finditer(text):
        # `|| true` AFTER the pipeline neutralises pipefail for it (scoped, not line-wide).
        if _PIPEFAIL_NEUTRALISED.search(text[match.end() :]):
            continue
        if _SAFE_PRODUCER_TAIL.search(text[: match.start()].strip()):
            continue
        out.append(match)
    return out


def _probe_steps(path: Path) -> list[tuple[str, str]]:
    """(job/step label, run-body) for every step writing a `has_*` presence output."""
    try:
        doc: Any = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:  # pragma: no cover - a malformed workflow is its own failure
        # `raise`, not `pytest.fail`: both abort, but only an explicit raise makes the
        # exception path obvious to a reader AND to static analysis. CodeQL flagged the
        # pytest.fail form as "doc may be used before initialization" because it does not
        # model NoReturn (alert 62) — technically a false positive, but the restructure is
        # strictly clearer than dismissing it, and a helper raising beats a helper calling
        # into pytest's outcome machinery.
        raise AssertionError(f"{path.name} is not valid YAML: {exc}") from exc
    found: list[tuple[str, str]] = []
    for job_name, job in ((doc or {}).get("jobs") or {}).items():
        for idx, step in enumerate((job or {}).get("steps") or []):
            body = (step or {}).get("run") or ""
            if _PRESENCE_OUTPUT.search(body):
                label = step.get("name") or step.get("id") or f"step {idx}"
                found.append((f"{job_name} :: {label}", body))
    return found


# ---------------------------------------------------------------------------
# Detector self-tests (non-vacuity + false-positive controls)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("label", "snippet"),
    [
        ("multi-line find", "if find . -name x \\\n  -not -path ./y 2>/dev/null | grep -q .; then"),
        ("single-line find", "if [ -d src ] && find src -name x | grep -q .; then"),
        ("grep -Eq", "if printf %s $changed | grep -Eq ^src/; then"),
        ("grep producer", "first=$(grep ^x large.log | head -1)"),
        ("awk producer", "first=$(awk {print} large.log | head -1)"),
        ("git ls-files", "if git ls-files *.py | grep -q .; then"),
        # v6: producers nobody would think to allow-list — why the polarity is inverted.
        ("gh api", "id=$(gh api repos/x/y/pulls --paginate | head -1)"),
        ("git diff", "if git diff --name-only | grep -q src/; then"),
        ("curl", "v=$(curl -s https://example.invalid/list | head -1)"),
        ("docker logs", "if docker compose logs | grep -q ERROR; then"),
        ("python -c", "n=$(python -c print | head -1)"),
        ("form feed is not a line break", "find src -name x \x0c| grep -q ."),
    ],
)
def test_detector_catches_hazard_shapes(label: str, snippet: str) -> None:
    """Non-vacuity: every shape a previous draft missed, or that exists in the tree."""
    assert any(_hazard_matches(t) for _, t in _logical_lines(snippet)), (
        f"detector missed the {label!r} shape — it would under-count real offenders"
    )


@pytest.mark.parametrize(
    ("label", "snippet"),
    [
        ("grep reads a file", "if grep -q ^PROBE=OK control.log; then"),
        ("sort drains its input", "latest=$(cat v.txt | sort -V | tail -1)"),
        ("neutralised by || true", "n=$(cat big.txt | head -1 || true)"),
        # False positives a greedy/unquoted matcher produced (v5).
        ("pipe inside a regex", "if grep -Eq '^(src/|head -1/)' <<<\"$c\"; then"),
        ("|| is not a pipe", 'echo "confirm" || read -r ans'),
        ("pipe inside a message", "echo 'see the README | read it'"),
    ],
)
def test_detector_ignores_safe_shapes(label: str, snippet: str) -> None:
    """False-positive control: a self-inflicted red is as bad as a miss."""
    assert not any(_hazard_matches(t) for _, t in _logical_lines(snippet)), (
        f"detector false-positived on {label!r}: {snippet!r}"
    )


def test_logical_lines_does_not_let_a_comment_swallow_code() -> None:
    """A trailing ``\\`` in a COMMENT must not absorb the next line."""
    text = "# a trailing backslash in prose \\\nfind src -name x | grep -q .\n"
    executable = [t for _, t in _logical_lines(text) if not t.lstrip().startswith("#")]
    assert any(_hazard_matches(t) for t in executable)


def test_logical_lines_preserves_content_and_line_numbers() -> None:
    """Joining must not lose text, and every reported line number must be real."""
    joined = _logical_lines("a\nb \\\nc\nd\n")
    assert [n for n, _ in joined] == [1, 2, 4, 5]
    assert [t for _, t in joined][:3] == ["a", "b c", "d"]


# ---------------------------------------------------------------------------
# The invariants
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("path", _shell_files(), ids=lambda p: p.name)
def test_no_pipe_into_an_early_exit_reader(path: Path) -> None:
    """Nothing CI executes may pipe into an early-exiting reader (#514).

    Use a form with no pipe to break::

        if [ -n "$(find src -name '*.py' -print -quit)" ]; then   # find stops itself
        if grep -Eq 'pat' <<<"$var"; then                          # here-string
    """
    offenders = [
        f"{path.name}:{lineno}: {raw.strip()[:110]}"
        for lineno, raw in _executable_lines(path)
        if _hazard_matches(raw)
    ]
    assert not offenders, (
        "a pipeline feeding an early-exiting reader SIGPIPEs its producer under `pipefail` once "
        "the output outgrows the pipe buffer, so the gate silently reports the wrong answer "
        "(#514):\n  " + "\n  ".join(offenders)
    )


@pytest.mark.parametrize("workflow", _workflow_files(), ids=lambda p: p.name)
def test_presence_probes_fail_closed(workflow: Path) -> None:
    """Every `has_*` presence probe must FAIL, never skip-and-pass (#514, #517).

    Asserted POSITIVELY — the step body must contain ``exit 1`` — and DERIVED from the workflow
    YAML, not a curated file list. A negative assertion on ``has_*=false`` was survivable by
    deleting the else-branch outright (the output then defaults to ``''``, every gated step
    skips, and the required job reports success), and a curated file list omitted ``nightly.yml``
    whose probe gates the release-blocking adversarial suite.
    """
    offenders = [
        f"{workflow.name} :: {where}"
        for where, body in _probe_steps(workflow)
        if "exit 1" not in body
    ]
    assert not offenders, (
        "a presence probe can report success while gating nothing; these paths are permanent, so "
        "finding nothing means the PROBE broke and the step must `exit 1` (#514, #517):\n  "
        + "\n  ".join(offenders)
    )
