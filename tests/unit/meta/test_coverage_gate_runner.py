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

import importlib.util
from pathlib import Path
from typing import Any

import pytest
import yaml

_REPO_ROOT = Path(__file__).resolve().parents[3]
_RUNNER = _REPO_ROOT / "scripts" / "run_coverage_gates.py"
_CI_WORKFLOW = _REPO_ROOT / ".github" / "workflows" / "ci.yml"

# The floors the Makefile targets pass. Deliberately a little below the counts at
# the time of writing (25 / 22) so ordinary gate churn does not fail the build,
# while a collapse to zero — the failure that matters — still does.
_MIN_UNIT_GATES = 20
_MIN_COMBINED_GATES = 18


def _load_runner() -> Any:
    spec = importlib.util.spec_from_file_location("run_coverage_gates", _RUNNER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def workflow() -> dict[str, Any]:
    return yaml.safe_load(_CI_WORKFLOW.read_text(encoding="utf-8"))


def test_the_runner_script_exists() -> None:
    """`make check` depends on it; a rename must fail here, not silently skip gates."""
    assert _RUNNER.is_file(), f"{_RUNNER} is missing — `make coverage-gates` cannot work"


@pytest.mark.parametrize(
    ("job_id", "minimum"),
    [("python", _MIN_UNIT_GATES), ("coverage-gates", _MIN_COMBINED_GATES)],
)
def test_runner_still_finds_the_gates_in_each_ci_job(
    workflow: dict[str, Any], job_id: str, minimum: int
) -> None:
    """THE non-vacuity case: the parser must still see CI's gates.

    If the workflow starts writing its coverage steps differently, this fails here
    rather than letting `make check` pass while enforcing nothing.
    """
    runner = _load_runner()
    gates = runner._iter_gates(workflow, job_id)
    assert len(gates) >= minimum, (
        f"runner extracted only {len(gates)} gates from ci.yml job {job_id!r} "
        f"(floor {minimum}). The workflow's gate shape likely changed, so "
        "`make check` is now gating less than CI."
    )


def test_every_extracted_gate_has_a_threshold_and_real_paths(
    workflow: dict[str, Any],
) -> None:
    """A gate that parsed but points nowhere would run vacuously and pass."""
    runner = _load_runner()
    gates = [
        *runner._iter_gates(workflow, "python"),
        *runner._iter_gates(workflow, "coverage-gates"),
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


def test_the_makefile_floors_match_the_ones_pinned_here(workflow: dict[str, Any]) -> None:
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


def test_a_glob_bearing_gate_is_not_treated_as_absent() -> None:
    """``--include='src/alfred/security/*'`` must RUN, not skip.

    ``Path("src/alfred/security/*").exists()`` is False — there is no file literally
    named ``*`` — so the original existence check reported every glob-bearing gate as
    "skipped, files absent", i.e. PASSED, without running it. Measured against CI: 3 of
    48 gates carry a glob, and one of them is ``src/alfred/security/*``, the 100%
    line-and-branch gate on the trust boundary.

    A silent skip inside the fix for silent skips. Pinned in both directions so neither
    the glob branch nor the literal branch can regress.
    """
    runner = _load_runner()

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


def test_a_gate_without_its_own_include_does_not_inherit_the_previous_one() -> None:
    """Each gate's ``--include`` must come from its OWN command, not an earlier one.

    The scan searched from the start of the ``run:`` block, so a second
    ``coverage report --fail-under=N`` with no ``--include`` of its own picked up the
    PREVIOUS gate's include and silently measured the wrong module — passing or failing
    on a file it was never meant to check.
    """
    runner = _load_runner()
    block = (
        "uv run coverage report --include='src/alfred/a.py' --fail-under=100 "
        "&& uv run coverage report --fail-under=75"
    )
    workflow = {"jobs": {"j": {"steps": [{"name": "s", "run": block}]}}}

    gates = runner._iter_gates(workflow, "j")

    assert [(g.include, g.threshold) for g in gates] == [("src/alfred/a.py", 100)], (
        "the include-less gate was kept and inherited the previous gate's --include"
    )


def test_two_gates_in_one_block_are_both_found_when_each_has_an_include() -> None:
    """The vacuity floor for the fix above: it must not drop legitimate gates.

    Narrowing the scan window could easily have made a multi-gate ``run:`` block yield
    only its first gate — which is how the runner ends up gating less than it claims.
    """
    runner = _load_runner()
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


def test_every_real_ci_gate_target_is_present_in_this_tree() -> None:
    """No CI gate may silently skip when run locally against a full checkout.

    The end-to-end statement of the two bugs above: if any gate's targets read as
    absent here, ``make check`` reports it green having measured nothing.
    """
    runner = _load_runner()
    workflow = yaml.safe_load(_CI_WORKFLOW.read_text(encoding="utf-8"))
    gates = runner._iter_gates(workflow, "python") + runner._iter_gates(workflow, "coverage-gates")
    assert gates, "no gates parsed — the assertion below would be vacuous"

    absent = [g.include for g in gates if not any(runner._gate_target_present(p) for p in g.paths)]

    assert not absent, f"these CI gates would skip while reporting PASS locally: {absent}"
