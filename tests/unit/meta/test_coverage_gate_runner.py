"""``scripts/run_coverage_gates.py`` must keep finding CI's coverage gates (#474).

The runner is what makes ``make check``'s "same gates as CI" claim true, and it
earns that by DERIVING the gate list from ``.github/workflows/ci.yml`` rather than
restating it (a hand-copied list is a second source of truth that drifts silently —
#422). The derivation is a regex over the workflow's ``run:`` blocks, so a change
to how those steps are written could stop it matching. If that happened the runner
would report green having gated **nothing** — the exact paper-gate shape #245 exists
to prevent.

So these cases pin the runner's ability to SEE the gates, not the gates' contents.
They fail loudly if the workflow's shape drifts away from what the runner parses.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[3]
_RUNNER = _REPO_ROOT / "scripts" / "run_coverage_gates.py"
_CI_WORKFLOW = _REPO_ROOT / ".github" / "workflows" / "ci.yml"

# Pinned to the EXACT counts measured 2026-07-30 (26 unit / 22 combined). They
# were 20 / 18 — slack "so ordinary gate churn does not fail the build" — and
# #541 is the bill for that slack: deleting the `check_tag_t3` gate step from
# ci.yml left 25 gates, still clear of 20, so this suite stayed green while a
# 100%-coverage gate on a security detector silently stopped existing.
#
# A floor is the right shape, set in the wrong place. `_iter_gates` is asserted
# with `>=`, so ADDING a gate still passes and only REMOVING one fails. The cost
# is that a deliberate removal must edit these constants — which is exactly the
# reviewable signal that was missing.
#
# NOTE these floors are enforced in CI by THIS TEST, not by the Makefile:
# `scripts/run_coverage_gates.py` is invoked by no workflow (verified), so the
# `--min-gates` argument is a local-only signal. The CI teeth are here, inside
# the required `Python (lint, types, unit)` check.
# 2026-07-30, later in the same PR: #543 added two more unit-tier gates
# (scripts/run_coverage_gates.py, scripts/check_strict_declarations.py), so the
# `python` job's count moved 26 -> 28. Derived, not stated: `_iter_gates` over
# ci.yml reports 28 / 22. The combined job is untouched.
# 2026-08-05: #568 added a 29th unit-tier gate
# (scripts/check_dependency_graph_freshness.py) — the CLI shell Task 5 left
# omitted pending this task's caller.
_MIN_UNIT_GATES = 29
_MIN_COMBINED_GATES = 22

# `runner`, `ci_workflow` and `ci_workflow_raw` come from
# `tests/unit/meta/conftest.py` (#543 review, rev-002). The loader and the
# yaml fixture were byte-identical here and in
# `test_gate_surfaces_are_pinned.py`; CLAUDE.md says refactor on the second
# duplication, and this was the second.


def test_the_runner_script_exists() -> None:
    """`make check` depends on it; a rename must fail here, not silently skip gates."""
    assert _RUNNER.is_file(), f"{_RUNNER} is missing — `make coverage-gates` cannot work"


@pytest.mark.parametrize(
    ("job_id", "minimum"),
    [("python", _MIN_UNIT_GATES), ("coverage-gates", _MIN_COMBINED_GATES)],
)
def test_runner_still_finds_the_gates_in_each_ci_job(
    runner: ModuleType, ci_workflow: dict[str, Any], job_id: str, minimum: int
) -> None:
    """THE non-vacuity case: the parser must still see CI's gates.

    If the workflow starts writing its coverage steps differently, this fails here
    rather than letting `make check` pass while enforcing nothing.
    """
    gates = runner._iter_gates(ci_workflow, job_id)
    assert len(gates) >= minimum, (
        f"runner extracted only {len(gates)} gates from ci.yml job {job_id!r} "
        f"(floor {minimum}). The workflow's gate shape likely changed, so "
        "`make check` is now gating less than CI."
    )


def test_every_extracted_gate_has_a_threshold_and_real_paths(
    runner: ModuleType, ci_workflow: dict[str, Any]
) -> None:
    """A gate that parsed but points nowhere would run vacuously and pass."""
    gates = [
        *runner._iter_gates(ci_workflow, "python"),
        *runner._iter_gates(ci_workflow, "coverage-gates"),
    ]
    for gate in gates:
        assert gate.threshold > 0, f"{gate.name}: non-positive threshold"
        assert gate.paths, f"{gate.name}: parsed no --include paths"
        # Globs cannot be resolved with Path.exists, so only check literal paths.
        for raw in gate.paths:
            if "*" in raw:
                continue
            assert (_REPO_ROOT / raw).exists(), (
                f"{gate.name}: include path {raw!r} does not exist — the gate would "
                "report on nothing"
            )


def test_the_makefile_floors_match_the_ones_pinned_here() -> None:
    """The Makefile's --min-gates values are the runtime half of this guard.

    Pinning them in both places is deliberate: this test would still pass if
    someone dropped the floors to zero in the Makefile, so assert they agree.
    """
    makefile = (_REPO_ROOT / "Makefile").read_text(encoding="utf-8")
    assert f"--job python --min-gates {_MIN_UNIT_GATES}" in makefile
    assert f"--job coverage-gates --min-gates {_MIN_COMBINED_GATES}" in makefile


# ---------------------------------------------------------------------------
# A gate that SKIPS while reporting green is the paper-gate shape this whole PR
# exists to eliminate — so the runner's own skip logic needs pinning. Both cases
# below were live bugs found by CodeRabbit review of this PR.
# ---------------------------------------------------------------------------


def test_a_glob_bearing_gate_is_not_treated_as_absent(runner: ModuleType) -> None:
    """``--include='src/alfred/security/*'`` must RUN, not skip.

    ``Path("src/alfred/security/*").exists()`` is False — there is no file literally
    named ``*`` — so the original existence check reported every glob-bearing gate as
    "skipped, files absent", i.e. PASSED, without running it. Measured against CI: 3 of
    48 gates carry a glob, and one of them is ``src/alfred/security/*``, the 100%
    line-and-branch gate on the trust boundary.

    A silent skip inside the fix for silent skips. Pinned in both directions so neither
    the glob branch nor the literal branch can regress.
    """
    assert runner._gate_target_present("src/alfred/security/*"), (
        "a glob matching real files is being reported as absent — the gate would skip "
        "and report PASS without ever running"
    )
    assert runner._gate_target_present("src/alfred/security/tiers.py"), (
        "the literal-path branch regressed"
    )
    assert not runner._gate_target_present("src/alfred/definitely_not_a_module/*"), (
        "a glob matching nothing must still be absent, or every gate runs against an "
        "empty file set and trivially passes"
    )


def test_a_gate_without_its_own_include_does_not_inherit_the_previous_one(
    runner: ModuleType,
) -> None:
    """Each gate's ``--include`` must come from its OWN command, not an earlier one.

    The scan searched from the start of the ``run:`` block, so a second
    ``coverage report --fail-under=N`` with no ``--include`` of its own picked up the
    PREVIOUS gate's include and silently measured the wrong module — passing or failing
    on a file it was never meant to check.
    """
    block = (
        "uv run coverage report --include='src/alfred/a.py' --fail-under=100 "
        "&& uv run coverage report --fail-under=75"
    )
    workflow = {"jobs": {"j": {"steps": [{"name": "s", "run": block}]}}}

    gates = runner._iter_gates(workflow, "j")

    assert [(g.include, g.threshold) for g in gates] == [("src/alfred/a.py", 100)], (
        "the include-less gate was kept and inherited the previous gate's --include"
    )


def test_two_gates_in_one_block_are_both_found_when_each_has_an_include(
    runner: ModuleType,
) -> None:
    """The vacuity floor for the fix above: it must not drop legitimate gates.

    Narrowing the scan window could easily have made a multi-gate ``run:`` block yield
    only its first gate — which is how the runner ends up gating less than it claims.
    """
    block = (
        "uv run coverage report --include='src/alfred/a.py' --fail-under=100 "
        "&& uv run coverage report --include='src/alfred/b.py' --fail-under=90"
    )
    workflow = {"jobs": {"j": {"steps": [{"name": "s", "run": block}]}}}

    gates = runner._iter_gates(workflow, "j")

    assert [(g.include, g.threshold) for g in gates] == [
        ("src/alfred/a.py", 100),
        ("src/alfred/b.py", 90),
    ]


def test_every_real_ci_gate_target_is_present_in_this_tree(
    runner: ModuleType, ci_workflow: dict[str, Any]
) -> None:
    """No CI gate may silently skip when run locally against a full checkout.

    The end-to-end statement of the two bugs above: if any gate's targets read as
    absent here, ``make check`` reports it green having measured nothing.
    """
    gates = runner._iter_gates(ci_workflow, "python") + runner._iter_gates(
        ci_workflow, "coverage-gates"
    )
    assert gates, "no gates parsed — the assertion below would be vacuous"

    absent = [g.include for g in gates if not any(runner._gate_target_present(p) for p in g.paths)]

    assert not absent, f"these CI gates would skip while reporting PASS locally: {absent}"


# ---------------------------------------------------------------------------
# #543: the runner that runs every other gate was itself at 50%.
#
# `_run_gate` and `main` — the halves that decide whether a gate RUNS and
# whether the run FAILS — had no coverage at all. A bug in either silently
# un-enforces all 50 per-module gates (28 in ci.yml's `python` job + 22 in
# `coverage-gates`, re-measured from `_iter_gates` against the ci.yml THIS PR
# ships — the count moved 48 -> 50 when #543 added its own two gate steps).
# That is not hypothetical: #474 exists because this runner was skipping 3 of
# the 48 that existed then, including the trust-boundary
# `src/alfred/security/*` gate.
# ---------------------------------------------------------------------------


def test_a_non_dict_step_is_skipped_rather_than_crashing(runner: ModuleType) -> None:
    """A `steps:` entry that is not a mapping must not break extraction.

    YAML permits a bare string or null in a sequence, and `_iter_gates`
    guards with `if not isinstance(step, dict): continue`. Nothing exercised
    that line, leaving the file at 98% and the #543 gate red on its own PR.
    """
    workflow = {"jobs": {"python": {"steps": [None, "a bare string", {"run": "echo hi"}]}}}

    assert runner._iter_gates(workflow, "python") == []


def test_a_gate_whose_files_are_all_absent_is_skipped_without_running(
    runner: ModuleType,
) -> None:
    """`_run_gate` must not shell out for a gate with nothing to measure."""
    passed, output = runner._run_gate(
        runner.Gate(name="ghost", include="src/alfred/does_not_exist.py", threshold=100)
    )

    assert passed is True
    assert "skipped" in output


def test_a_glob_that_matches_nothing_is_treated_as_absent(runner: ModuleType) -> None:
    """The other arm of `_gate_target_present`: a glob with no matches."""
    assert runner._gate_target_present("src/alfred/no_such_dir_*/*.py") is False
    assert runner._gate_target_present("src/alfred/security/*") is True


@pytest.mark.parametrize(
    ("child_rc", "expect_pass"), [(0, 1), (1, 0)], ids=["child-ok", "child-fails"]
)
def test_a_gate_that_shells_out_reports_the_child_verdict(
    runner: ModuleType, monkeypatch: pytest.MonkeyPatch, child_rc: int, expect_pass: int
) -> None:
    """`_run_gate` passes/fails on the child's returncode and keeps its output.

    The subprocess is replaced with a REAL `subprocess.CompletedProcess`, not
    a Mock, so the arm reads the same attributes off the same type it reads in
    production. Shelling out for real would mean running `uv run coverage
    report` from inside a pytest-cov session against a half-written data file.

    Parametrised on ints, not bools — ruff FBT001 forbids boolean positional
    parameters and it applies to tests/.
    """
    gate = runner.Gate(name="real", include="scripts/run_coverage_gates.py", threshold=100)
    seen: list[list[str]] = []

    def _fake_run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        seen.append(argv)
        return subprocess.CompletedProcess(argv, child_rc, "TOTAL 42%\n", "boom\n")

    monkeypatch.setattr(runner.subprocess, "run", _fake_run)

    passed, output = runner._run_gate(gate)

    assert passed is bool(expect_pass)
    assert "TOTAL 42%" in output
    assert "boom" in output
    assert f"--include={gate.include}" in seen[0]
    assert f"--fail-under={gate.threshold}" in seen[0]


def test_main_refuses_when_the_workflow_is_missing(
    runner: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """No ci.yml — exit 2, not a green no-op."""
    monkeypatch.setattr(runner, "_CI_WORKFLOW", tmp_path / "absent.yml")
    monkeypatch.setattr(sys, "argv", ["run_coverage_gates.py", "--job", "python"])

    assert runner.main() == 2
    assert "not found" in capsys.readouterr().err


def test_main_refuses_when_too_few_gates_were_extracted(
    runner: ModuleType, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The #245 non-vacuity floor: gating nothing must exit 2, not 0.

    `_CI_WORKFLOW` is repointed at the ABSOLUTE workflow path. The script's own
    constant is `Path(".github/workflows/ci.yml")`, relative to the cwd — so run
    from anywhere but the repo root this would still return 2, but for the
    missing-file reason, i.e. pass while never reaching the floor at all. The
    stderr assertion distinguishes the two, and this pin removes the ambiguity.
    """
    monkeypatch.setattr(runner, "_CI_WORKFLOW", _CI_WORKFLOW)
    monkeypatch.setattr(
        sys, "argv", ["run_coverage_gates.py", "--job", "python", "--min-gates", "9999"]
    )

    assert runner.main() == 2
    assert "gating nothing" in capsys.readouterr().err


def test_main_refuses_an_unknown_job(runner: ModuleType, ci_workflow: dict[str, Any]) -> None:
    """A renamed CI job must fail loudly, not extract zero gates and pass."""
    with pytest.raises(SystemExit):
        runner._iter_gates(ci_workflow, "no-such-job")


@pytest.mark.parametrize(
    ("gate_verdict", "expected_rc"), [(1, 0), (0, 1)], ids=["all-pass", "one-fails"]
)
def test_main_returns_the_aggregate_verdict(
    runner: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    gate_verdict: int,
    expected_rc: int,
) -> None:
    """`main` reports 0 only when every gate passed, and prints the failures.

    `_run_gate` is substituted at the module seam so this drives `main`'s
    aggregation over the REAL gate list from ci.yml without spawning dozens of
    `uv run coverage report` children. Int parameters, not bools (FBT001).
    """
    passes = bool(gate_verdict)
    monkeypatch.setattr(runner, "_CI_WORKFLOW", _CI_WORKFLOW)
    monkeypatch.setattr(runner, "_run_gate", lambda gate: (passes, "" if passes else "TOTAL 1%"))
    monkeypatch.setattr(sys, "argv", ["run_coverage_gates.py", "--job", "python"])

    assert runner.main() == expected_rc

    captured = capsys.readouterr()
    if passes:
        assert "coverage gate(s) passed" in captured.out
    else:
        assert "coverage gate(s) FAILED" in captured.err


def test_a_segment_carrying_several_includes_uses_the_gates_own_last_one(
    runner: ModuleType,
) -> None:
    """`include=includes[-1]` — the LAST `--include` in the gate's own segment.

    Plan review measured this half of `_iter_gates` unpinned: mutating
    `includes[-1]` to `includes[0]` SURVIVED every other case in this file and
    in `tests/unit/meta` as a whole (77 passed, rc=0). The sibling half — the
    `prev_end` scan window — is killed by
    `test_a_gate_without_its_own_include_does_not_inherit_the_previous_one`,
    which is what made the whole guard read as covered while half of it was not.

    Two arrangements, both of which a real `run:` block can take:

    1. A NON-GATE command earlier in the segment carries its own `--include`.
       `_GATE_RE` requires `--fail-under=`, so `coverage html --include=…` is
       not a gate — but it IS inside the segment, and it is FIRST. Picking the
       first include would gate the wrong module while reporting the right
       step name: the #474 shape (a gate that runs, and measures something
       else) rather than the #245 shape (a gate that does not run).

    2. One invocation carrying `--include` TWICE. Verified against the
       installed coverage: `coverage.cmdline.Opts.include` is
       `action="store"`, so a repeated flag is LAST-WINS. The extractor must
       agree with the tool it is modelling, or the gate list says one module
       and the child measures another.
    """
    preceded = (
        "uv run coverage html --include='src/alfred/html_only/*' "
        "&& uv run coverage report --include='src/alfred/a.py' --fail-under=100"
    )
    gates = runner._iter_gates({"jobs": {"j": {"steps": [{"name": "s", "run": preceded}]}}}, "j")
    assert [(g.include, g.threshold) for g in gates] == [("src/alfred/a.py", 100)], (
        "the gate took an --include belonging to a NON-GATE command earlier in "
        "its segment — it would run against the wrong module under the right "
        "step name"
    )

    repeated = (
        "uv run coverage report --include='src/alfred/ignored.py' "
        "--include='src/alfred/wins.py' --fail-under=100"
    )
    gates = runner._iter_gates({"jobs": {"j": {"steps": [{"name": "s", "run": repeated}]}}}, "j")
    assert [(g.include, g.threshold) for g in gates] == [("src/alfred/wins.py", 100)], (
        "a repeated --include is last-wins in coverage (Opts.include is "
        "action='store'); the extractor must report the include the child will "
        "actually use"
    )
