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
