"""The gate surfaces #537 landed must not be silently removable (#541).

#537 added a `check_tag_t3` 100%-coverage step to ci.yml that a future edit
can delete, swap, or disarm with nothing saying a word:

* DELETE it -> 25 gates against a `--min-gates 20` floor: silent. Closed by
  raising the floor to the real count (test_coverage_gate_runner.py).
* SWAP it for an unrelated gate -> count still 26: silent. Closed here by
  pinning the include spec and threshold BY NAME.
* DISARM it -> the step (or the job, or the run: block, or the shell it
  executes under) is altered so the step never gates while every count and
  name pin stays green. `if: false` is the #514 shape review found first,
  but it is one shape among many. A first pass at this file closed `if:
  false` plus a *blocklist* of bad `run:` fragments (`|| true`, `; exit 0`,
  ...) — security review measured that a blocklist described as an
  allow-list, and proved five more shapes surviving it under real bash:
  `|| exit 0`, a leading `!`, a trailing `&`, `|| echo`, and a job- or
  workflow-level `defaults.run.shell` that drops the implicit `-e`. That is
  the #518 mistake replayed one level down: enumerating disarm shapes closes
  only the ones enumerated. So this file default-denies on TWO axes instead:
  the step's KEY SET (an allow-list already existed for this) and the step's
  RUN CONTENT (new here) — every non-blank, non-comment `run:` line must
  match one of the three fixed shapes this gate's invocation is allowed to
  take, or it is refused, whatever the fragment is called. A separate check
  refuses any `defaults.run.shell` override at workflow or job level, since
  that changes the failure semantics of every step underneath it (including
  this one). Review raised it against a planned two-`coverage report`-
  invocations-in-one-step design that would have DEPENDED on `-e` to stop at
  the first failure; #543 shipped one gate per step instead, so no gate step
  depends on `-e` today. The refusal stays — a defence that is currently
  belt-and-braces is the cheap half of not having to re-derive this when the
  next multi-command step lands.

**Two oracles per assertion.** Each surface is checked once against the
parsed/derived view and once against the raw file text. A pin reusing only
the implementation's own predicate would pass through the drift it exists
to catch — this repo has shipped a tautological oracle twice. The raw-text
oracle is scoped to the `python` job's own text (a second #541 correction):
searching the whole file would let a same-named, same-shaped gate living in
a DIFFERENT job satisfy a pin meant for `python`.

**The JOB axis (#543 review, sec-001/test-001).** The first version of this
file default-denied the STEP's key set and left the JOB's enumerated: it read
`jobs.python.continue-on-error` and `jobs.python.defaults.run.shell` and
nothing else. A measured mutation put `jobs.python.if: false` in ci.yml and
SURVIVED every assertion here — GitHub scores a skipped job as a PASSING
required check, so `Python (lint, types, unit)` stayed green with all 28
gates, `--include='src/alfred/security/*' --fail-under=100` among them, never
executed. That is the #514 paper-gate shape one level above the step the pin
defended. The scope half was the same mistake: the check ran against ci.yml's
`python` job only, so `tag-t3-grep` (the required check enforcing CLAUDE.md
hard rule #3) and this PR's own new `strict-declarations-lint` job had NO
disarm guard of any kind — deleting, `if: false`-ing or `|| true`-ing the
latter each left all 174 tests green.

Both halves are closed the same way the step axis was, one level up:
DEFAULT-DENY the job's KEY SET, and DERIVE the job list rather than
enumerating it. `_gate_bearing_jobs()` walks every workflow and picks out the
jobs that actually run a gate — a `scripts/check_*.py` invocation or a
`coverage report --fail-under=100` — so a NEW gate job is pinned the day it
lands, without an edit here. `test_the_gate_bearing_job_derivation_is_not_vacuous`
is the anti-vacuity floor: the derivation may widen, never silently narrow.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
import yaml

from tests.unit.meta.conftest import GATE_ENFORCING_SCRIPT_NAMES

_REPO_ROOT: Path = Path(__file__).resolve().parents[3]
_WORKFLOWS_DIR: Path = _REPO_ROOT / ".github" / "workflows"
_CI_WORKFLOW: Path = _WORKFLOWS_DIR / "ci.yml"
_REQUIRED_CHECKS_DOC: Path = _REPO_ROOT / "docs" / "ci" / "required-checks.md"

# `runner`, `ci_workflow` and `ci_workflow_raw` come from
# `tests/unit/meta/conftest.py` (#543 review, rev-002) — the loader and the
# yaml fixture were byte-identical here and in `test_coverage_gate_runner.py`.

# Coverage gates that must exist in ci.yml's `python` job BY NAME, as
# (include-spec, threshold). The count floor catches a net loss; this catches
# a swap, which keeps the count intact.
_REQUIRED_COVERAGE_GATES: tuple[tuple[str, int], ...] = (
    ("scripts/check_tag_t3.py", 100),
    # #543: the other two gate-enforcing scripts. `run_coverage_gates.py` runs
    # all 50 per-module gates — 28 in ci.yml's `python` job plus 22 in
    # `coverage-gates`, re-measured from `_iter_gates` against the ci.yml this
    # PR ships (the count moved 48 -> 50 when #543 added its own two gate
    # steps, so this comment is self-referential and must be re-measured, not
    # copied). #474 is the incident: the runner was skipping 3 of the 48 that
    # existed then, including the trust boundary. `check_strict_declarations.py`
    # enforces #119 SEC-Med-1. Both were measured-but-ungated after #537's
    # `--cov=scripts` widened the dataset without widening the gates.
    ("scripts/run_coverage_gates.py", 100),
    ("scripts/check_strict_declarations.py", 100),
    # #568: the CLI shell of the Dependabot Python-graph freshness monitor.
    # Task 5 left it omitted in pyproject.toml pending a caller; the
    # `.github/workflows/dependency-graph-freshness.yml` step this pin
    # anchors is that caller, so it is gated at 100% rather than omitted.
    ("scripts/check_dependency_graph_freshness.py", 100),
)

# `if:` conditions a gate step may carry, NORMALISED. `steps.check.outputs.has_py`
# is the `python` job's fail-closed source probe (id `check`, hardened in #517).
#
# Normalisation matters: `if: ${{ steps.check.outputs.has_py == 'true' }}` is the
# SAME condition and GitHub accepts both spellings, but raw string equality reds
# on it. Strip a surrounding `${{ … }}` and collapse whitespace before comparing —
# normalise, do not widen the set, or a genuinely different guard slips in.
_APPROVED_GATE_CONDITIONS: frozenset[str] = frozenset({"steps.check.outputs.has_py == 'true'"})

# Keys a pinned gate step may carry — DEFAULT-DENY, not an enumerated blocklist.
#
# `if: false` is only one way to disarm the step; `continue-on-error: true` (step
# OR job level) is another, and neither changes the step's key set into something
# the OLD (pre-#541) test would have accepted. Enumerating disarm shapes closes the
# ones we thought of — the #518 mistake. So: allow a known-good key set and refuse
# anything else, whatever it is called.
_ALLOWED_GATE_STEP_KEYS: frozenset[str] = frozenset({"name", "if", "run"})

# ONE STEP PER GATE, and the order must match `_REQUIRED_COVERAGE_GATES` above.
#
# #543's brief proposed a single step holding BOTH new `coverage report`
# invocations. That shape cannot be pinned by this file without widening
# `_approved_run_line_patterns` from "the three lines this gate is allowed to be"
# to a union over several gates — an allow-list that no longer constrains WHICH
# include pairs with WHICH threshold on a per-line basis. It would also make the
# step depend on bash's implicit `-e` to stop at the first failing invocation,
# which is precisely the dependency
# `test_the_python_job_defaults_do_not_relax_error_handling` below exists to
# defend. Splitting into one gate per step removes the dependency instead of
# guarding it, keeps this mapping 1:1, and names the regressing script in the
# step title. The pin was not weakened to fit the step; the step was shaped to
# fit the pin.
_GATE_STEP_NAMES: tuple[str, ...] = (
    "check_tag_t3 detector 100% line+branch coverage",
    "run_coverage_gates runner 100% line+branch coverage",
    "check_strict_declarations guard 100% line+branch coverage",
    "check_dependency_graph_freshness 100% line+branch coverage",
)

# Per-step (include, threshold), keyed by the SAME name pinned in _GATE_STEP_NAMES.
# `zip(..., strict=True)` is deliberate: if a future task extends one tuple without
# the other, this raises at collection time instead of silently pairing the wrong
# gate with the wrong name.
_APPROVED_RUN_SHAPES: dict[str, tuple[str, int]] = dict(
    zip(_GATE_STEP_NAMES, _REQUIRED_COVERAGE_GATES, strict=True)
)

_JOB_HEADER_RE: re.Pattern[str] = re.compile(r"^  ([A-Za-z0-9_-]+):[ \t]*$", re.MULTILINE)


def _python_job_steps(workflow: dict[str, Any]) -> list[dict[str, Any]]:
    return [s for s in workflow["jobs"]["python"]["steps"] if isinstance(s, dict)]


def _job_raw_text(full_text: str, job_id: str) -> str:
    """Slice ``full_text`` down to just ``job_id``'s block: header to next header.

    ``jobs:`` is ci.yml's LAST top-level key — ``on:``/``env:``/``permissions:``
    all sit above it — so every 2-space-indented header found from ``jobs:``
    onward is unambiguously a job name; there is no risk of matching something
    like ``on.pull_request`` (also 2-space indented, but above the marker).
    """
    jobs_marker = re.search(r"^jobs:[ \t]*$", full_text, re.MULTILINE)
    assert jobs_marker, f"{_CI_WORKFLOW} has no top-level `jobs:` key"
    headers = {m.group(1): m.start() for m in _JOB_HEADER_RE.finditer(full_text, jobs_marker.end())}
    assert job_id in headers, f"{_CI_WORKFLOW} has no job named {job_id!r}"
    start = headers[job_id]
    later = sorted(pos for pos in headers.values() if pos > start)
    end = later[0] if later else len(full_text)
    return full_text[start:end]


@pytest.mark.parametrize(("include", "threshold"), _REQUIRED_COVERAGE_GATES)
def test_the_gate_is_visible_to_the_runner(
    runner: ModuleType, ci_workflow: dict[str, Any], include: str, threshold: int
) -> None:
    """Oracle 1 — the DERIVED view: `run_coverage_gates.py` extracts it."""
    gates = runner._iter_gates(ci_workflow, "python")
    matching = [g for g in gates if g.include == include]
    assert matching, (
        f"no coverage gate with --include='{include}' in ci.yml's `python` job. "
        f"#537 added it and #541 exists because deleting it was silent. "
        f"Found: {sorted(g.include for g in gates)}"
    )
    assert [g.threshold for g in matching] == [threshold], (
        f"--include='{include}' must stay at --fail-under={threshold}; "
        f"got {[g.threshold for g in matching]}"
    )


@pytest.mark.parametrize(("include", "threshold"), _REQUIRED_COVERAGE_GATES)
def test_the_gate_is_present_in_the_raw_workflow_text(
    ci_workflow_raw: str, include: str, threshold: int
) -> None:
    """Oracle 2 — the RAW view, independent of the runner's regex.

    Scoped to the `python` job's own text (#541 correction): searching the
    WHOLE file, as an earlier draft did, would let a gate of this name and
    threshold living in some OTHER job satisfy the pin while `python`'s own
    copy was gone.
    """
    text = _job_raw_text(ci_workflow_raw, "python")
    pattern = re.compile(
        rf"--include='{re.escape(include)}'\s*\\?\s*\n?\s*--fail-under={threshold}\b"
    )
    assert pattern.search(text), (
        f"ci.yml's `python` job has no `coverage report --include='{include}' "
        f"--fail-under={threshold}` invocation (raw-text view, scoped to `python`)"
    )


def _normalise_condition(raw: object) -> str:
    """Strip a surrounding ``${{ … }}`` and collapse whitespace.

    GitHub accepts ``if: X`` and ``if: ${{ X }}`` as the same condition. Raw
    equality reds on the second, so normalise rather than widening the approved
    set — widening would admit conditions that are genuinely different.
    """
    text = " ".join(str(raw).split())
    if text.startswith("${{") and text.endswith("}}"):
        text = " ".join(text[3:-2].split())
    return text


def _approved_run_line_patterns(include: str, threshold: int) -> tuple[re.Pattern[str], ...]:
    """The exact line shapes this gate's `run:` block may contain, no more.

    DEFAULT-DENY on shell content, not a blocklist of bad fragments. An earlier
    draft's ``_EXIT_NEUTRALISERS = ("|| true", "; exit 0", ...)`` only caught the
    shapes it enumerated; security review measured five more surviving it —
    ``|| exit 0``, a leading ``!``, a trailing ``&``, ``|| echo``, each proven
    under real bash to exit 0 on a breached gate. Enumerating exit-neutralisers
    is the same mistake as enumerating disarm-shapes on the step's keys (#518)
    — so instead: this command is exactly three lines, pin what they ARE, and
    refuse any line that is not one of them, whatever it says.
    """
    return (
        re.compile(r"^uv run coverage report( \\)?$"),
        re.compile(rf"^--include='{re.escape(include)}'( \\)?$"),
        re.compile(rf"^--fail-under={threshold}$"),
    )


@pytest.mark.parametrize("step_name", _GATE_STEP_NAMES)
def test_a_gate_step_cannot_be_disarmed(ci_workflow: dict[str, Any], step_name: str) -> None:
    """DEFAULT-DENY the ways a gate step can be made not to gate.

    `_iter_gates` is a static parse: it counts a step whose `if:` is literally
    `false`, so the count floor and the name pins are both blind to disarming.
    Two independent allow-lists close this, on two different axes:

      1. the step's KEY SET — `continue-on-error`, `timeout-minutes`, `env`, or
         anything else beyond `name`/`if`/`run` is refused outright, and the
         `if:` value present must be the one approved condition;
      2. the step's `run:` CONTENT — every non-blank, non-comment line must be
         one of the three lines this invocation is allowed to be
         (`_approved_run_line_patterns`), so `|| true`, `; exit 0`, `|| exit 0`,
         a leading `!`, a trailing `&`, `|| echo`, or any other fragment nobody
         has thought of yet is refused by shape, not by name.

    A new disarm mechanism has to get past an allow-list on both axes, not past
    a blocklist on one of them (#518's lesson, #514's shape).
    """
    steps = [s for s in _python_job_steps(ci_workflow) if s.get("name") == step_name]
    assert steps, f"ci.yml's `python` job has no step named {step_name!r}"

    job = ci_workflow["jobs"]["python"]
    assert not job.get("continue-on-error"), (
        "the `python` job carries continue-on-error, which makes EVERY coverage "
        "gate in it advisory while every pin here stays green"
    )

    include, threshold = _APPROVED_RUN_SHAPES[step_name]
    approved_run_lines = _approved_run_line_patterns(include, threshold)

    for step in steps:
        unexpected = set(step) - _ALLOWED_GATE_STEP_KEYS
        assert not unexpected, (
            f"step {step_name!r} carries unexpected key(s) {sorted(unexpected)}. "
            f"Only {sorted(_ALLOWED_GATE_STEP_KEYS)} are allowed on a gate step: "
            f"anything else (continue-on-error, timeout-minutes, env, …) may "
            f"change whether a failure blocks the merge. If the new key is "
            f"legitimate, add it here deliberately (#541)."
        )
        condition = _normalise_condition(step.get("if", ""))
        assert condition in _APPROVED_GATE_CONDITIONS, (
            f"step {step_name!r} has if: {condition!r} (normalised), not in the "
            f"approved set {sorted(_APPROVED_GATE_CONDITIONS)}."
        )

        run_lines = [line.strip() for line in str(step.get("run", "")).splitlines()]
        for line in run_lines:
            if not line or line.startswith("#"):
                continue
            assert any(pattern.match(line) for pattern in approved_run_lines), (
                f"step {step_name!r} run: has a line {line!r} matching NONE of the "
                f"approved shapes for this gate. The block must be exactly "
                f"`uv run coverage report`, `--include='{include}'`, "
                f"`--fail-under={threshold}` (each optionally continuation-"
                f"backslashed) and NOTHING else — appending `|| exit 0`, a "
                f"trailing `&`, a leading `!`, `|| echo`, or any other fragment "
                f"is refused by default, not pattern-matched away (#541)."
            )


def test_the_python_job_defaults_do_not_relax_error_handling(ci_workflow: dict[str, Any]) -> None:
    """DEFAULT-DENY: no `defaults.run.shell` may replace bash's implicit `-e`.

    A `run:` step with no `shell:` key gets GitHub's implicit
    ``bash --noprofile --norc -eo pipefail {0}`` on ``ubuntu-latest`` — a
    non-zero exit anywhere in the block is fatal. `defaults.run.shell` at
    WORKFLOW or JOB level silently swaps that default for every step
    underneath it, including these gates.

    It defeats no gate step as they stand: every one is a single
    `coverage report` invocation whose `--fail-under=N` line is last, so the
    gate's own exit code IS the step's exit code whatever shell runs it.
    Security review raised it against #543's originally-planned design of
    chaining two `coverage report` invocations into one `run:` block, where a
    failing FIRST invocation would be masked by a passing second one with no
    `-e` to stop execution. #543 shipped one gate per step, which removes that
    dependency rather than guarding it — but the refusal stays, because the
    next multi-command step to land would otherwise reintroduce the hole
    silently. Refuse ANY override rather than trying to classify which
    replacement shells still fail loud.
    """
    workflow_shell = (ci_workflow.get("defaults") or {}).get("run", {}).get("shell")
    assert workflow_shell is None, (
        f"ci.yml sets a workflow-level defaults.run.shell ({workflow_shell!r}), "
        "which overrides bash's implicit -e for every step, including the "
        "coverage gates. Remove it, or — if a shell override is genuinely "
        "needed — update this pin deliberately (#541)."
    )
    job_shell = (ci_workflow["jobs"]["python"].get("defaults") or {}).get("run", {}).get("shell")
    assert job_shell is None, (
        f"the `python` job sets defaults.run.shell ({job_shell!r}), which "
        "overrides bash's implicit -e for every step in the job, including the "
        "coverage gates. Remove it, or update this pin deliberately (#541)."
    )


def test_the_approved_condition_is_a_real_probe(ci_workflow: dict[str, Any]) -> None:
    """Anti-vacuity: the approved `if:` must reference a step that EXISTS.

    Pinning a condition that names a nonexistent step id would pin a guard
    that is always false — the failure the pin exists to prevent, reproduced
    inside the pin.
    """
    ids = {s.get("id") for s in _python_job_steps(ci_workflow) if s.get("id")}
    assert "check" in ids, (
        "ci.yml's `python` job has no step with id `check`; the approved gate "
        f"condition references it. Step ids present: {sorted(i for i in ids if i)}"
    )


def test_the_two_gate_oracles_agree(
    runner: ModuleType, ci_workflow: dict[str, Any], ci_workflow_raw: str
) -> None:
    """Anti-vacuity floor: both views must SEE something, in the SAME job, and agree."""
    derived = {g.include for g in runner._iter_gates(ci_workflow, "python")}
    raw = set(re.findall(r"--include='([^']+)'", _job_raw_text(ci_workflow_raw, "python")))
    assert derived, "the runner extracted NO gates — this pin is gating nothing"
    assert raw, (
        "the raw view found NO --include= specs in the `python` job — this pin is gating nothing"
    )
    assert derived <= raw, f"runner saw gates absent from the raw text: {derived - raw}"


# ---------------------------------------------------------------------------
# THE JOB AXIS (#543 review — sec-001 High, test-001 High).
#
# The step-key allow-list above stops at the step. `jobs.<job>.if: false`
# skips the whole JOB, GitHub scores a skipped job as a PASSING required
# check, and every assertion in this file stays green — measured, on the
# shipped ci.yml, against these very assertion functions. Same gap on the
# scope axis: nothing here read `pr-validate-python.yml` at all, so the
# `tag-t3-grep` job (CLAUDE.md hard rule #3) and `strict-declarations-lint`
# (#119 SEC-Med-1, added by this PR to fix its own discovery that the guard
# ran in no workflow) could be deleted, `if: false`-d or `|| true`-d with all
# 174 tests green.
#
# Adding `if` to a refusal list would repeat #518's mistake one level up, so
# the job's KEY SET is default-denied exactly as the step's is, and the job
# LIST is DERIVED — every workflow, every job, keep the ones that actually run
# a gate. A new gate job is pinned the day it lands.
# ---------------------------------------------------------------------------

# A job bears a gate if one of its steps RUNS one. Matched against the step's
# own `run:` text with whitespace collapsed, in two shapes:
#
#   * a gate SCRIPT executed. Command position is load-bearing: `uv run mypy
#     --strict src scripts/check_tag_t3.py` names the same file as a
#     TYPE-CHECK TARGET, in four other jobs, and is not a gate invocation.
#     `test_the_derivation_distinguishes_running_a_gate_from_naming_one`
#     mutation-tests exactly that distinction.
#   * a 100% coverage gate. `--cov-fail-under=` (pytest's whole-tree floor)
#     cannot match: it carries a single dash before `fail-under`.
_GATE_SCRIPT_ALTERNATION: str = "|".join(
    re.escape(name) for name in sorted(GATE_ENFORCING_SCRIPT_NAMES)
)
_GATE_SCRIPT_RUN_RE: re.Pattern[str] = re.compile(
    r"(?:^|[\s;&|])python3?\s+scripts/" rf"(?:{_GATE_SCRIPT_ALTERNATION})\.py"
)
_COVERAGE_GATE_RUN_RE: re.Pattern[str] = re.compile(r"coverage\s+report\b[^\n]*?--fail-under=100\b")

# Keys a gate-bearing JOB may carry — DEFAULT-DENY, the step allow-list's twin.
#
# `if` and `continue-on-error` are the two known disarms and both fall out of
# this without being named; so do `defaults` (a `run.shell` override drops
# bash's implicit `-e`), `env`, `container`, `services`, `strategy` (a matrix
# that expands to nothing runs no job) and whatever the next one turns out to
# be. Measured against the four derived jobs: this is exactly the union of the
# keys they carry today, so the list constrains rather than describes.
_ALLOWED_GATE_JOB_KEYS: frozenset[str] = frozenset(
    {"name", "runs-on", "timeout-minutes", "permissions", "steps", "needs"}
)

# `needs` IS a disarm vector — a dependency that never succeeds skips the
# dependent job, which reports as a pass. It cannot be refused outright
# (`coverage-gates` legitimately needs the job that builds its coverage
# corpus), so it is bounded instead: every dependency must itself be a
# CURRENTLY REQUIRED check. A dependency that fails then reds its own required
# check, so the skip can never be silent. Derived from the tracked manifest,
# not restated here.
_REQUIRED_CHECKS_SECTION: str = "## Currently required"

# Job-key cell of a row that lives in the PENDING table and must therefore
# never appear in the Currently-required derivation. It is a tombstone row, so
# it is stable in a way a live pending row is not — the previous sentinel was a
# live row and #544 promoted it out from under this test.
_PENDING_SECTION_SENTINEL: str = "_(superseded)_"

# The anti-vacuity floor for the derivation. It may WIDEN silently (that is the
# point); it may not NARROW. Named as a floor, not as the search set — a
# derivation that collapsed to these four would still be wrong, which is what
# `test_the_derivation_distinguishes_running_a_gate_from_naming_one` covers.
_GATE_BEARING_JOB_FLOOR: frozenset[tuple[str, str]] = frozenset(
    {
        ("ci.yml", "python"),
        ("ci.yml", "coverage-gates"),
        ("pr-validate-python.yml", "tag-t3-grep"),
        ("pr-validate-python.yml", "strict-declarations-lint"),
    }
)

# For a job whose gate is a SCRIPT: the exact `run:` line and the exact `if:`
# it is allowed to carry. The same DEFAULT-DENY the coverage-gate steps get
# from `_approved_run_line_patterns` — `|| true`, `|| exit 0`, a leading `!`,
# a trailing `&` and every fragment nobody has thought of are refused by shape.
# A gate-script job MISSING from this mapping fails too: adding one is a
# deliberate edit here, not an omission that passes.
_APPROVED_GATE_SCRIPT_STEPS: dict[tuple[str, str], tuple[str, str]] = {
    ("pr-validate-python.yml", "tag-t3-grep"): (
        "python3 scripts/check_tag_t3.py",
        "steps.srccheck.outputs.has_source == 'true'",
    ),
    ("pr-validate-python.yml", "strict-declarations-lint"): (
        "python3 scripts/check_strict_declarations.py",
        "steps.srccheck.outputs.has_source == 'true'",
    ),
}

_STEP_ID_IN_CONDITION_RE: re.Pattern[str] = re.compile(r"steps\.([A-Za-z0-9_-]+)\.outputs\.")


def _workflow_files() -> list[Path]:
    """Every workflow file, derived — not a list of the ones we remembered."""
    return sorted(p for p in _WORKFLOWS_DIR.iterdir() if p.suffix in {".yml", ".yaml"})


def _job_steps(job: dict[str, Any]) -> list[tuple[dict[str, Any], str]]:
    """``(step, whitespace-collapsed run text)`` for each mapping step."""
    steps = job.get("steps") or []
    return [
        (step, " ".join(str(step.get("run", "")).split()))
        for step in steps
        if isinstance(step, dict)
    ]


def _gate_bearing_jobs() -> dict[tuple[str, str], dict[str, Any]]:
    """``(workflow filename, job id) -> job`` for every job that RUNS a gate."""
    found: dict[tuple[str, str], dict[str, Any]] = {}
    for path in _workflow_files():
        document = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for job_id, job in (document.get("jobs") or {}).items():
            if not isinstance(job, dict):
                continue
            if any(
                _GATE_SCRIPT_RUN_RE.search(run) or _COVERAGE_GATE_RUN_RE.search(run)
                for _step, run in _job_steps(job)
            ):
                found[(path.name, str(job_id))] = job
    return found


_GATE_BEARING_JOBS: dict[tuple[str, str], dict[str, Any]] = _gate_bearing_jobs()
_GATE_SCRIPT_JOBS: dict[tuple[str, str], dict[str, Any]] = {
    ref: job
    for ref, job in _GATE_BEARING_JOBS.items()
    if any(_GATE_SCRIPT_RUN_RE.search(run) for _step, run in _job_steps(job))
}


def _job_params(refs: dict[tuple[str, str], dict[str, Any]]) -> list[Any]:
    return [pytest.param(ref, id=f"{ref[0]}::{ref[1]}") for ref in sorted(refs)]


def _parse_job_keys(section: str) -> frozenset[str]:
    """Job keys from one markdown section's five-column table.

    Column 3 of a five-column table. Rationale cells contain escaped pipes
    (``\\|``), which only ever SPLIT INTO MORE cells, never fewer — so a
    minimum cell count is a safe row filter and column 3 stays column 3.

    Factored out of :func:`_currently_required_job_keys` so the Pending table
    can be parsed by the SAME code (#549 review, ops-003). The section-split
    sentinel used to be located with a raw substring search while the
    assertion it guards depends on the row PARSING — so reformatting the row
    would keep the presence check green while quietly making the real
    assertion vacuous. One parser, two callers, no such gap.
    """
    keys: set[str] = set()
    for line in section.splitlines():
        cells = [cell.strip() for cell in line.split("|")]
        if len(cells) < 7:  # leading empty + 5 columns + trailing empty
            continue
        job_key = cells[3].strip("`")
        if job_key and job_key != "Job key" and set(job_key) != {"-"}:
            keys.add(job_key)
    return frozenset(keys)


def _section_after(heading: str) -> str:
    """The text of ``docs/ci/required-checks.md`` under ``heading``."""
    _, _, after = _REQUIRED_CHECKS_DOC.read_text(encoding="utf-8").partition(heading)
    assert after, f"{_REQUIRED_CHECKS_DOC} has no {heading!r} section"
    return after.split("\n## ", 1)[0]


def _currently_required_job_keys() -> frozenset[str]:
    """Job keys from ``docs/ci/required-checks.md``'s Currently-required table."""
    return _parse_job_keys(_section_after(_REQUIRED_CHECKS_SECTION))


@pytest.mark.parametrize("job_ref", _job_params(_GATE_BEARING_JOBS))
def test_a_gate_bearing_job_cannot_be_disarmed(job_ref: tuple[str, str]) -> None:
    """DEFAULT-DENY the job's KEY SET — the step allow-list, one level up.

    `jobs.<job>.if: false` (or any never-true expression) skips the job, and a
    skipped job is a PASSING required status check, so every gate inside it
    goes unrun while this file stays green. Measured on ci.yml's `python`:
    that mutation SURVIVED all four assertion functions here before this test
    existed. `continue-on-error: true` at job level is the same shape.

    Neither is named. The job may carry the keys a gate job legitimately needs
    and nothing else — so the NEXT disarm mechanism has to get past an
    allow-list too, rather than past a list of the ones already known (#518).
    """
    job = _GATE_BEARING_JOBS[job_ref]

    unexpected = sorted(set(job) - _ALLOWED_GATE_JOB_KEYS)
    assert not unexpected, (
        f"{job_ref[0]} job {job_ref[1]!r} carries unexpected key(s) {unexpected}. "
        f"Only {sorted(_ALLOWED_GATE_JOB_KEYS)} are allowed on a job that runs a "
        f"gate: `if` and `continue-on-error` make the whole job advisory (a "
        f"SKIPPED job is a PASSING required check), and `defaults`/`env`/"
        f"`strategy`/`container` can each change whether its steps gate. If the "
        f"new key is legitimate, add it here deliberately (#543 sec-001)."
    )

    dependencies = job.get("needs") or []
    if isinstance(dependencies, str):
        dependencies = [dependencies]
    required = _currently_required_job_keys()
    for dependency in dependencies:
        assert dependency in required, (
            f"{job_ref[0]} job {job_ref[1]!r} needs {dependency!r}, which is not a "
            f"currently-required check in {_REQUIRED_CHECKS_DOC.name}. A dependency "
            f"that fails SKIPS this job, and a skipped job passes — so a `needs` "
            f"edge is only safe while the dependency's own failure blocks the "
            f"merge on its own account."
        )


@pytest.mark.parametrize("job_ref", _job_params(_GATE_SCRIPT_JOBS))
def test_a_gate_script_step_cannot_be_disarmed(job_ref: tuple[str, str]) -> None:
    """DEFAULT-DENY the `run:` content of a gate-SCRIPT step.

    `test_a_gate_step_cannot_be_disarmed` gives ci.yml's coverage-gate steps
    this treatment; the two `pr-validate-python.yml` jobs that invoke a gate
    script had nothing. Appending `|| true` to `strict-declarations-lint`'s
    `run:` block was measured green across all 174 tests.

    A gate-script job absent from `_APPROVED_GATE_SCRIPT_STEPS` fails here
    rather than passing unpinned — the mapping is an allow-list, so a new
    gate-script job is a deliberate entry, not a silent omission.
    """
    job = _GATE_SCRIPT_JOBS[job_ref]
    assert job_ref in _APPROVED_GATE_SCRIPT_STEPS, (
        f"{job_ref[0]} job {job_ref[1]!r} runs a gate script but has no approved "
        f"shape in _APPROVED_GATE_SCRIPT_STEPS. Add one deliberately — an "
        f"unpinned gate job can be disarmed with `|| true` and nothing says a "
        f"word (#543 test-001)."
    )
    approved_run, approved_condition = _APPROVED_GATE_SCRIPT_STEPS[job_ref]

    invocations = [step for step, run in _job_steps(job) if _GATE_SCRIPT_RUN_RE.search(run)]
    assert len(invocations) == 1, (
        f"{job_ref[0]} job {job_ref[1]!r} has {len(invocations)} gate-script steps; "
        f"the pin maps exactly one shape per job"
    )
    step = invocations[0]

    unexpected = sorted(set(step) - _ALLOWED_GATE_STEP_KEYS)
    assert not unexpected, (
        f"{job_ref[0]} job {job_ref[1]!r}'s gate step carries unexpected key(s) "
        f"{unexpected}; only {sorted(_ALLOWED_GATE_STEP_KEYS)} are allowed"
    )

    condition = _normalise_condition(step.get("if", ""))
    assert condition == approved_condition, (
        f"{job_ref[0]} job {job_ref[1]!r}'s gate step has if: {condition!r} "
        f"(normalised), not the approved {approved_condition!r}"
    )

    run_lines = [line.strip() for line in str(step.get("run", "")).splitlines()]
    body = [line for line in run_lines if line and not line.startswith("#")]
    assert body == [approved_run], (
        f"{job_ref[0]} job {job_ref[1]!r}'s gate step run: is {body!r}, not exactly "
        f"[{approved_run!r}]. Appending `|| true`, `|| exit 0`, a trailing `&`, a "
        f"leading `!` or any other fragment is refused by default, not pattern-"
        f"matched away (#543 test-001)."
    )


@pytest.mark.parametrize("job_ref", _job_params(_APPROVED_GATE_SCRIPT_STEPS))
def test_the_approved_gate_script_condition_is_a_real_probe(job_ref: tuple[str, str]) -> None:
    """Anti-vacuity: the approved `if:` must name a step that EXISTS.

    The twin of `test_the_approved_condition_is_a_real_probe` for the
    pr-validate jobs. Approving a condition that references a nonexistent step
    id pins a guard that is always false — the failure the pin exists to
    prevent, reproduced inside the pin.

    The probe's own fail-closed body (`exit 1` when it finds nothing) is
    pinned separately by `tests/unit/test_workflow_invariants.py`.
    """
    _, approved_condition = _APPROVED_GATE_SCRIPT_STEPS[job_ref]
    referenced = _STEP_ID_IN_CONDITION_RE.findall(approved_condition)
    assert referenced, f"the approved condition {approved_condition!r} names no step output"

    job = _GATE_SCRIPT_JOBS[job_ref]
    ids = {str(step.get("id")) for step, _run in _job_steps(job) if step.get("id")}
    for step_id in referenced:
        assert step_id in ids, (
            f"{job_ref[0]} job {job_ref[1]!r} has no step with id {step_id!r}, which "
            f"the approved gate condition references. Step ids present: {sorted(ids)}"
        )


@pytest.mark.parametrize(
    "workflow_name", sorted({ref[0] for ref in _GATE_BEARING_JOB_FLOOR | set(_GATE_BEARING_JOBS)})
)
def test_no_gate_bearing_workflow_relaxes_the_default_shell(workflow_name: str) -> None:
    """DEFAULT-DENY at WORKFLOW level, for every file that hosts a gate.

    `test_the_python_job_defaults_do_not_relax_error_handling` covers ci.yml
    only. `defaults.run.shell` at the top of `pr-validate-python.yml` would
    replace bash's implicit `-e` for `tag-t3-grep` and
    `strict-declarations-lint` alike, with nothing reading it.
    """
    path = _WORKFLOWS_DIR / workflow_name
    document = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    shell = (document.get("defaults") or {}).get("run", {}).get("shell")
    assert shell is None, (
        f"{workflow_name} sets a workflow-level defaults.run.shell ({shell!r}), "
        f"which overrides bash's implicit -e for every step in every job, "
        f"including the gates. Remove it, or update this pin deliberately (#543)."
    )


def test_the_gate_bearing_job_derivation_is_not_vacuous() -> None:
    """The derivation may widen silently; it may NOT narrow.

    Without this, renaming a job, restructuring a `run:` block or breaking the
    regex leaves `_GATE_BEARING_JOBS` empty and every parametrised case above
    collects ZERO tests — a pin that gates nothing and reports green, which is
    the #245 shape inside the guard meant to close it.

    The floor names the jobs carrying CLAUDE.md hard rule #3 (`tag-t3-grep`),
    #119 SEC-Med-1 (`strict-declarations-lint`) and the two coverage-gate
    hosts, so losing any ONE of them reds — a bare count would not.
    """
    derived = set(_GATE_BEARING_JOBS)
    assert derived >= _GATE_BEARING_JOB_FLOOR, (
        f"gate-bearing jobs the derivation no longer sees: "
        f"{sorted(_GATE_BEARING_JOB_FLOOR - derived)}. Found: {sorted(derived)}"
    )
    stale = sorted(set(_APPROVED_GATE_SCRIPT_STEPS) - set(_GATE_SCRIPT_JOBS))
    assert not stale, (
        f"_APPROVED_GATE_SCRIPT_STEPS pins {stale}, which the derivation no longer "
        f"finds — the allow-list is describing jobs that have moved or gone"
    )


def test_the_derivation_distinguishes_running_a_gate_from_naming_one() -> None:
    """Mutation-test the derivation regexes on synthetic text.

    A detector that cannot see the real shape is a paper gate, and the two
    near-misses here are both REAL lines in these workflows: `mypy --strict src
    scripts/check_tag_t3.py` type-checks the gate script in four other jobs,
    and `pytest --cov-fail-under=75` is the whole-tree floor that is
    deliberately not a per-module gate. Widening either regex to match them
    would pull unrelated jobs under a job-key allow-list they do not fit, and
    the fix would look like relaxing the allow-list.
    """
    assert _GATE_SCRIPT_RUN_RE.search("python3 scripts/check_tag_t3.py")
    assert _GATE_SCRIPT_RUN_RE.search("python3 scripts/check_strict_declarations.py")
    assert _GATE_SCRIPT_RUN_RE.search("uv run python3 scripts/run_coverage_gates.py --job python")
    assert not _GATE_SCRIPT_RUN_RE.search("uv run mypy --strict src scripts/check_tag_t3.py")
    assert not _GATE_SCRIPT_RUN_RE.search("uv run pyright src scripts/check_tag_t3.py")

    assert _COVERAGE_GATE_RUN_RE.search(
        "uv run coverage report --include='src/alfred/security/*' --fail-under=100"
    )
    assert not _COVERAGE_GATE_RUN_RE.search(
        "uv run pytest tests/unit -q --cov=src/alfred --cov-fail-under=100"
    )
    assert not _COVERAGE_GATE_RUN_RE.search("uv run coverage report --fail-under=75")


def test_the_required_check_manifest_parses_to_real_job_keys() -> None:
    """Anti-vacuity for the `needs` closure above.

    An empty or mis-parsed manifest makes `dependency in required` fail rather
    than pass, so this cannot go silently green — but a manifest that parsed to
    a huge set of junk WOULD, so pin the shape: the derived keys must include
    the jobs the floor names and must not include the table header.

    The section-split sentinel was `strict-declarations-lint` until #544
    promoted it to Currently-required, at which point the assertion it anchored
    would have been asserting the opposite of the truth. Its replacement is the
    tombstone row that still sits in the Pending table — and it is checked for
    PRESENCE first, because a sentinel that quietly stops existing turns the
    assertion below into one that cannot tell a working split from a broken one.
    """
    keys = _currently_required_job_keys()

    assert {"python", "integration", "tag-t3-grep"} <= keys, (
        f"{_REQUIRED_CHECKS_DOC.name}'s Currently-required table no longer yields "
        f"the job keys this pin reads; got {sorted(keys)}"
    )
    assert "Job key" not in keys, "the table header leaked into the parsed key set"

    # Located with the SAME parser the assertion below depends on, not a raw
    # substring search (#549 review, ops-003). A substring hit proves only that
    # the text exists somewhere; it does not prove the row still PARSES as a
    # job-key cell — so reformatting the row would leave this green while
    # `not in keys` became vacuously true.
    pending_keys = _parse_job_keys(_section_after("## Pending required"))
    assert _PENDING_SECTION_SENTINEL in pending_keys, (
        f"the section-split sentinel {_PENDING_SECTION_SENTINEL!r} no longer parses "
        f"out of {_REQUIRED_CHECKS_DOC.name}'s Pending table (got {sorted(pending_keys)}), "
        f"so the assertion below can no longer distinguish a working section split "
        f"from a broken one. Point it at a row that is still there."
    )
    assert _PENDING_SECTION_SENTINEL not in keys, (
        f"{_PENDING_SECTION_SENTINEL!r} comes from the PENDING table, so the "
        f"section split is not working and `needs` edges would be validated "
        f"against the wrong table"
    )


# ---------------------------------------------------------------------------
# #541: the gate's scan roots belong to the SCRIPT, not to its call sites.
# #537 widened the gate to `src/alfred plugins` by editing two invocation
# strings; dropping `plugins` from either was a one-word edit that stopped
# gating 39 first-party plugin files and no gate could see it.
# ---------------------------------------------------------------------------

# DEFAULT-DENY on location: search the WHOLE repo and subtract a short, pinned
# list of categories — do not enumerate the places a call site is allowed to
# live. An earlier revision of this file enumerated five roots
# (`Makefile`, `lefthook.yml`, `.github/workflows`, `bin`, `scripts`), which
# left `.pre-commit-config.yaml`, `ops/`, `docker/` and a `justfile` unsearched:
# an invocation planted in any of them was gated by neither this pin nor the
# script's runtime invariant. That is the enumerate-vs-default-deny trap this
# whole branch exists to close, reproduced inside the guard (#518's lesson).
#
# The file set comes from `git ls-files --cached --others --exclude-standard`,
# the same derivation the gate itself uses: it is default-deny (a file git
# ignores cannot land in a PR), it includes untracked-but-not-ignored NEW files
# (`--others`; without it a brand-new call site is invisible until `git add` —
# #540 err-001), and it never walks `.venv`/`node_modules`. Measured: 1763
# files in 0.39s.
_EXCLUDED_PREFIXES: tuple[str, ...] = (
    # Prose that quotes historical invocations. `docs/superpowers/plans/*` carry
    # `check_tag_t3.py src/alfred plugins` as a record of what #537 did; the pin
    # must not red a document for describing history. Measured: 15 matches here.
    "docs/",
    # Plan/brief working material — same reason. Gitignored in this checkout, so
    # excluded explicitly rather than by accident of another repo's .gitignore.
    ".superpowers/",
    # The suite drives the gate with fixture ARGUMENTS by design — that is the
    # single-file path this pin's sibling layer deliberately exempts — so test
    # files are not "call sites" in the sense meant here. This file in
    # particular must contain the pattern in order to test its own regex.
    "tests/",
)

# The gate script itself is searched-but-excluded, deliberately (#541). Its
# module docstring carries a `Usage: python scripts/check_tag_t3.py
# [file_or_dir ...]` line, which the regex below matches with a non-empty
# argv — so without this the pin could never pass, and worse, an edit to the
# script's own documentation could break or satisfy a pin about its CALLERS.
_GATE_SCRIPT: Path = (_REPO_ROOT / "scripts" / "check_tag_t3.py").resolve()

# The argv capture must consume BACKSLASH CONTINUATIONS. A class of
# `[^\n;&|]` looks like it does and does NOT: it is tried before the
# alternation, matches the backslash itself, and the match ends at the newline
# having never seen the wrapped line — so splitting the invocation across lines
# slipped a scan root past the pin entirely (measured against real `make`, with
# `plugins/` ungated and rc=0). Excluding `\` from the class is what lets the
# `\\\n` alternative fire and keep reading.
_INVOCATION_RE = re.compile(r"python3?\s+scripts/check_tag_t3\.py((?:[^\n;&|\\]|\\\n)*)")


def _searched_files() -> list[Path]:
    """Every repo file this pin reads, default-deny minus ``_EXCLUDED_PREFIXES``.

    ``check=True``: if git cannot answer, this raises rather than returning an
    empty list. A silent empty answer here would make every assertion below
    vacuously true — the paper-gate shape, inside the pin meant to prevent it.
    """
    listed = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],  # noqa: S607
        capture_output=True,
        check=True,
        cwd=_REPO_ROOT,
    ).stdout.decode("utf-8", errors="surrogateescape")
    return [
        path
        for name in listed.split("\0")
        if name and not name.startswith(_EXCLUDED_PREFIXES)
        if (path := _REPO_ROOT / name).is_file() and path.resolve() != _GATE_SCRIPT
    ]


def _invocation_sites() -> list[tuple[Path, str]]:
    """Every (file, argv) pair invoking the gate anywhere in the repo."""
    found: list[tuple[Path, str]] = []
    for path in _searched_files():
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        found.extend((path, argv) for argv in _INVOCATION_RE.findall(text))
    return found


def test_no_invocation_overrides_the_scripts_own_scan_roots() -> None:
    """Call sites must pass NO roots, so the script's tuple is authoritative.

    A call site that names roots re-opens #541: dropping one becomes a one-word
    edit again and the script's constant becomes decorative. Derived rather
    than enumerated so a NEW call site is covered the day it is added.

    This is the LEXICAL layer. It is the only one that can see an invocation
    enumerating explicit FILE paths (which the script's runtime invariant
    cannot refuse without breaking the single-file developer invocation) — and
    it is also the layer a shell can be written around, which is why the
    script carries a runtime invariant as well.
    """
    for path, argv in _invocation_sites():
        assert not argv.strip().rstrip("\\").strip(), (
            f"{path.relative_to(_REPO_ROOT)}: `check_tag_t3.py{argv}` passes "
            f"explicit scan roots. The roots belong in _DEFAULT_SCAN_ROOTS so "
            f"they cannot be dropped at a call site (#541)."
        )


def test_the_invocation_pin_is_not_vacuous() -> None:
    """Anti-vacuity floor: a rename must not make this pin gate nothing.

    Without it, renaming the script or restructuring the Makefile leaves
    `_invocation_sites()` empty and the assertion above passes over an empty
    list — the paper-gate shape, inside the pin meant to prevent it.

    Names the two call sites that must exist as a FLOOR (not as the search
    set): the excluding of the gate script's own text is a deliberate blind
    spot, and a floor of `>= 2` alone would be satisfied if that exclusion
    ever grew to swallow a real caller.
    """
    # Measured: 465 files survive _EXCLUDED_PREFIXES today (296 src/, 45
    # plugins/, 38 .rulesync/, 26 top-level, 19 .github/, 11 config/, 11 ops/,
    # 9 scripts/, 4 bin/, 3 docker/, …). The floor is the count that would
    # notice a whole category disappearing, not a number pulled from the air —
    # the exact exclusion tuple is pinned by
    # `test_the_invocation_search_is_default_deny_over_the_repo`, which is the
    # precise guard; this is the blunt one behind it.
    searched = len(_searched_files())
    assert searched > 300, (
        f"the default-deny file set collapsed to {searched} files — git "
        f"answered, but a category-sized chunk stopped surviving "
        f"_EXCLUDED_PREFIXES, so this pin is searching a fraction of the repo"
    )

    sites = _invocation_sites()
    seen = {p.relative_to(_REPO_ROOT).as_posix() for p, _ in sites}

    assert len(sites) >= 2, (
        f"expected at least the Makefile and workflow invocations, found "
        f"{[(str(p.relative_to(_REPO_ROOT)), a) for p, a in sites]}"
    )
    assert {"Makefile", ".github/workflows/pr-validate-python.yml"} <= seen, (
        f"a known call site is no longer visible to this pin; saw {sorted(seen)}"
    )


def test_the_invocation_regex_reads_through_a_backslash_continuation() -> None:
    """Mutation-test the guard itself: the regex must SEE a wrapped argv.

    A detector that cannot see the real bypass is a paper gate. `[^\\n;&|]`
    (no `\\` exclusion) matches the backslash, ends at the newline and reports
    an EMPTY argv for the line below — i.e. reports "clean" for the exact
    invocation the pin exists to refuse. Asserted on synthetic text so this
    holds whatever the Makefile currently says.
    """
    wrapped = "\t\tpython3 scripts/check_tag_t3.py \\\n\t\t\tsrc/alfred; \\\n"

    captured = _INVOCATION_RE.findall(wrapped)

    assert len(captured) == 1, f"the invocation was not matched at all: {captured}"
    assert "src/alfred" in captured[0], (
        f"the regex stopped at the continuation and captured {captured[0]!r} — a "
        f"wrapped invocation would slip a scan root past the pin (#541)"
    )
    # Negative twin: the shipped argument-less form must still read as empty.
    assert _INVOCATION_RE.findall("\t\tpython3 scripts/check_tag_t3.py; \\\n") == [""]


def test_the_invocation_search_is_default_deny_over_the_repo() -> None:
    """The exclusion list is SHORT, PINNED, and must not grow to hide a finding.

    The allow-list is "the whole repo"; these three prefixes are the only
    subtractions, and each is justified at its definition. Pinning them makes
    adding a fourth — say `ops/`, to silence a real invocation planted there —
    a visible, deliberate edit rather than a one-word fix to a red test. That
    one-word fix is exactly how the previous five-root enumeration came to leave
    `.pre-commit-config.yaml`, `ops/`, `docker/` and `justfile` unsearched.
    """
    assert _EXCLUDED_PREFIXES == ("docs/", ".superpowers/", "tests/")


def test_previously_unsearched_locations_are_now_searched() -> None:
    """Anti-vacuity for the widening itself: name places the old roots missed.

    A default-deny claim is worth nothing unless something that used to be
    invisible is now visible. These are real tracked files outside the five
    roots the earlier revision enumerated.
    """
    searched = {p.relative_to(_REPO_ROOT).as_posix() for p in _searched_files()}

    for previously_missed in ("docker-compose.yaml", "pyproject.toml", "lefthook.yml"):
        assert previously_missed in searched, (
            f"{previously_missed} is not in the searched set — an invocation "
            f"planted there would be gated by neither layer (#541)"
        )
    assert any(p.startswith("ops/") for p in searched), "ops/ is unsearched"
