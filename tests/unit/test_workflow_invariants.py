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

* v6 allow-listed `sort`/`wc`/`tail` as "safe producers"; measured, `sort big | head -1` is
  141 — they still EMIT a stream and the early-exiting reader SIGPIPEs them mid-emission.
  Safety belongs to the READER draining, not the producer (CodeRabbit).

So: the hazard test flags EVERY pipe into an early-exiting reader with no producer exceptions,
and the fail-closed test is derived from the workflow YAML rather than a file list.
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

# `|| true` / `|| :` neutralises pipefail ONLY when it binds to the offending pipeline itself.
# A trailing `|| true` on an enclosing compound does NOT rescue the guard: verified in
# ubuntu:24.04 that `if find … | grep -q .; then … fi || true` still evaluates the `if` as
# FALSE, because the SIGPIPE poisons the inner pipeline before `|| true` ever applies.
_PIPEFAIL_NEUTRALISED = re.compile(r"\|\|\s*(?:true|:)(?![\w-])")
# Anything that ends the current pipeline, so the `|| true` search cannot run past it.
_PIPELINE_END = re.compile(r"[;\n]|&&|\bthen\b|\bfi\b|\bdone\b")

# Steps whose `has_*` output is a PRESENCE probe must fail closed. `run_bench`-style relevance
# gates legitimately evaluate false and are excluded by the `has_` naming convention the repo uses.
_PRESENCE_OUTPUT = re.compile(r"\bhas_[a-z0-9_]*\s*=\s*true")


def _strip_quoted(text: str) -> str:
    """Reduce a shell line to its executable text: blank quoted literals, drop comments.

    Three things this must get right, each learned the hard way:

    * **Command substitution is code, not a literal.** The body of ``$( … )`` is shell even when
      the substitution sits inside double quotes, so ``$(`` pushes a fresh context. A naive
      scanner blanks ``passed="$(printf … | head -1 || true)"`` wholesale and goes blind.
    * **Grouping parens nest inside it.** In ``"$( ( : ); find … | grep -q . )"`` the FIRST ``)``
      closes the inner subshell, not the substitution — popping there blanks the pipeline that
      follows. Depth is tracked per context.
    * **An unquoted ``#`` at a word start begins a comment.** Otherwise
      ``… | grep -q . # || true`` reads as neutralised when bash actually returns 141.
    """
    out: list[str] = []
    stack: list[list[object]] = []  # [saved_quote, grouping-paren depth] per $( ) context
    quote = ""
    prev = ""
    i = 0
    while i < len(text):
        ch = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""
        # `$(` opens shell code (single quotes are literal, so no substitution happens there).
        if quote != "'" and ch == "$" and nxt == "(":
            stack.append([quote, 0])
            quote = ""
            out.append("$(")
            prev, i = "(", i + 2
            continue
        if not quote and stack:
            if ch == "(":
                stack[-1][1] = int(stack[-1][1]) + 1  # type: ignore[arg-type]
                out.append(ch)
                prev, i = ch, i + 1
                continue
            if ch == ")":
                if int(stack[-1][1]) > 0:  # type: ignore[arg-type]
                    stack[-1][1] = int(stack[-1][1]) - 1  # type: ignore[arg-type]
                else:
                    quote = str(stack.pop()[0])
                out.append(ch)
                prev, i = ch, i + 1
                continue
        # Unquoted `#` at a word start comments out the remainder.
        if not quote and ch == "#" and (prev == "" or prev.isspace()):
            break
        if quote:
            out.append(ch if ch == quote else " ")
            if ch == quote:
                quote = ""
        elif ch in "'\"":
            quote = ch
            out.append(ch)
        else:
            out.append(ch)
        prev, i = ch, i + 1
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
    """Pipelines feeding an early-exiting reader, minus those neutralised on the SAME pipeline.

    There is deliberately NO producer allow-list. v6 exempted `sort`/`wc`/`tail` on the reasoning
    that they consume all input before emitting — which is true and irrelevant: they still EMIT a
    stream, and the early-exiting reader SIGPIPEs them mid-emission. Measured in ubuntu:24.04 on a
    500k-line input: `sort big | head -1` => 141 and `tail -n +1 big | head -1` => 141. Safety
    comes from the READER draining, and readers that drain are already absent from
    ``_EARLY_EXIT_READER`` — so the producer side needs no exceptions at all.
    """
    text = _strip_quoted(raw)
    out = []
    for match in _PIPE_INTO_EARLY_EXIT.finditer(text):
        rest = text[match.end() :]
        end = _PIPELINE_END.search(rest)
        same_pipeline = rest[: end.start()] if end else rest
        if _PIPEFAIL_NEUTRALISED.search(same_pipeline):
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
        # v6 regressions (CodeRabbit): both were WRONGLY exempted. Measured in ubuntu:24.04.
        ("sort into head -1", "first=$(sort big.txt | head -1)"),  # => 141
        ("tail into head -1", "first=$(tail -n +1 big.txt | head -1)"),  # => 141
        # v7: `"$( … )"` is shell CODE, not a quoted literal. An earlier _strip_quoted blanked
        # the whole substitution and went blind to ci.yml's extractors — a false NEGATIVE
        # introduced while fixing a false positive.
        ("pipeline inside a quoted command substitution", 'n="$(cat big.txt | head -1)"'),
        ("nested command substitution", 'n="$(a | $(b) | head -1)"'),
        # v8 (CodeRabbit): the FIRST `)` closes the grouping subshell, not the substitution.
        ("grouping parens inside $( )", 'n="$( ( : ); find src -name x | grep -q . )"'),
        # An unquoted `#` starts a comment, so this `|| true` neutralises NOTHING — measured:
        # `cat big | head -1 # || true` still exits 141.
        ("|| true inside a trailing comment", "find src -name x | grep -q . # || true"),
        # `${#arr}` is a length expansion, not a comment introducer.
        ("hash inside a parameter expansion", "n=${#arr}; find s -name x | grep -q ."),
        # A trailing `|| true` on the ENCLOSING compound does not rescue the inner pipeline:
        # the `if` still evaluates FALSE because SIGPIPE poisons it before `|| true` applies.
        (
            "|| true on the compound, not the pipe",
            "if find src -name x | grep -q .; then echo ok; fi || true",
        ),
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
        # Safe because `tail -1` DRAINS (it must reach EOF), not because `sort` is a safe
        # producer — that inversion is exactly what v6 got wrong.
        ("reader drains to EOF", "latest=$(cat v.txt | sort -V | tail -1)"),
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


# ---------------------------------------------------------------------------
# Toolchain: `.prototools` is the single declared uv version (#525, PR #526)
# ---------------------------------------------------------------------------

# Both spellings CI uses: the workflow-level `env:` key and the shell assignment in
# ci.yml's WSL leg. A guard matching only the first would have missed the very
# inconsistency that motivated this — ci.yml was on 0.11.32 while three workflows sat on
# 0.5.14, roughly a year behind, in the tool that resolves the lockfile.
_UV_VERSION_DECL = re.compile(r"""UV_VERSION\s*[:=]\s*["']?(?P<version>\d+\.\d+\.\d+)["']?""")
_PROTOTOOLS_UV = re.compile(r"""^\s*uv\s*=\s*["'](?P<version>[^"']+)["']""", re.MULTILINE)


def _prototools_uv_version() -> str:
    proto = _REPO_ROOT / ".prototools"
    assert proto.exists(), (
        ".prototools is missing — it is the declared source of truth for the uv version "
        "that local and CI must share (#525)"
    )
    match = _PROTOTOOLS_UV.search(proto.read_text(encoding="utf-8"))
    assert match, f'no `uv = "..."` pin found in .prototools:\n{proto.read_text()}'
    version = match.group("version")
    assert re.fullmatch(r"\d+\.\d+\.\d+", version), (
        f"the .prototools uv pin must be EXACT, got {version!r}. A range (e.g. '~0.11') would "
        "let CI float across patch releases, which this repo does not do anywhere else — "
        "actions are SHA-pinned and dependencies are capped deliberately (ADR-0044)."
    )
    return version


def test_prototools_declares_an_exact_uv_version() -> None:
    """The toolchain pin exists and is exact — the anchor every workflow is checked against."""
    assert _prototools_uv_version()


def test_every_workflow_uv_version_matches_prototools() -> None:
    """No workflow may pin a uv version other than `.prototools`' (#525).

    Local (proto) and CI must resolve dependencies with the SAME uv. They silently diverged
    by a major version — `ci.yml`'s WSL leg on 0.11.32 while `adversarial`, `perf` and
    `pr-validate-python` sat on 0.5.14 — so five of six legs resolved the lockfile with a
    different tool than the sixth, and than every developer's machine.

    This is the repo's usual answer to "two copies must agree": pin one as the source and
    make drift loud, rather than deleting the copy (see `test_compose_invariants.py`,
    `test_setup_script_readme_consistency.py`). Installing uv FROM `.prototools` in CI was
    considered and rejected — it would add a third-party action to the SHA-pinned supply
    chain and, with a range pin, let CI float.
    """
    expected = _prototools_uv_version()
    mismatched = []
    found = 0
    for workflow in _workflow_files():
        for lineno, text in _executable_lines(workflow):
            for match in _UV_VERSION_DECL.finditer(text):
                found += 1
                if match.group("version") != expected:
                    mismatched.append(
                        f"{workflow.name}:{lineno}: pins {match.group('version')} "
                        f"(.prototools says {expected})"
                    )
    assert found >= 4, (
        f"vacuity floor: found only {found} UV_VERSION declarations across the workflows. "
        "Both spellings must be detected — the `env:` key AND ci.yml's shell assignment."
    )
    assert not mismatched, (
        "workflow uv pins have drifted from .prototools, so CI and local resolve the "
        "lockfile with different tools:\n  " + "\n  ".join(mismatched)
    )


def test_every_setup_uv_use_pins_its_version() -> None:
    """`astral-sh/setup-uv` must never be used without an explicit version (#525).

    An unpinned `uses: astral-sh/setup-uv@<sha>` silently installs whatever the ACTION
    defaults to — a floating uv that no file in this repo declares. It is invisible to the
    `.prototools`-vs-workflow guard above, because that only compares DECLARED versions: a
    job with no declaration has nothing to disagree with.

    That is exactly how it drifted. When this guard was written, 12 of 19 uses were
    unpinned — every `ci.yml` job (lint/types/unit, integration, coverage) and all of
    `nightly.yml`, which declared no `UV_VERSION` at all. Only the WSL leg's manual tarball
    install used the pinned version, which is why CI looked aligned while most of it was not.
    """
    unpinned = []
    total = 0
    for workflow in _workflow_files():
        lines = workflow.read_text(encoding="utf-8").split("\n")
        for i, line in enumerate(lines):
            if "astral-sh/setup-uv@" not in line or line.lstrip().startswith("#"):
                continue
            total += 1
            # The version must be supplied by the `with:` block attached to THIS step —
            # i.e. within the few lines before the next step begins.
            window = "\n".join(lines[i + 1 : i + 5])
            if "env.UV_VERSION" not in window:
                unpinned.append(f"{workflow.name}:{i + 1}")
    assert total >= 15, (
        f"vacuity floor: found only {total} setup-uv uses; the sweep is not seeing the "
        "workflows it is supposed to check"
    )
    assert not unpinned, (
        "these `astral-sh/setup-uv` steps take the ACTION'S DEFAULT uv, not the pinned one, "
        "so they resolve the lockfile with an undeclared floating version and the "
        ".prototools guard cannot see them (#525):\n  " + "\n  ".join(unpinned)
    )
