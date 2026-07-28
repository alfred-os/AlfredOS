#!/usr/bin/env python3
"""Run CI's per-module 100% coverage gates locally (#474).

``make check`` advertised itself as "identical to CI" while running **none** of
the per-module ``--fail-under=100`` gates. The gap is not theoretical: PR #529
passed ``make check`` locally and then failed CI's "Gateway kernel trust-boundary
100%" gate on a single partial branch. Every one of those gates enforces
CLAUDE.md's hard rule that a security boundary is covered 100% line+branch, and
locally none of them ran.

**The gate list is DERIVED from ``.github/workflows/ci.yml``, never duplicated.**
A hand-maintained copy in the Makefile would be a second source of truth that
drifts silently — the #422 trap: a shared source fails LOUD, N copies drift
SILENTLY. Adding a gate to CI therefore adds it here automatically, and a gate
that exists in CI can never be missing locally.

Two datasets, mirroring the two CI jobs that hold gates:

* ``python`` — gates run against UNIT-ONLY coverage.
* ``coverage-gates`` — gates run against COMBINED unit + integration coverage.

Running a combined-job gate against unit-only data would report false failures,
so the caller names which job's gates to run and is responsible for having built
the matching ``.coverage`` first.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path
from typing import Final, NamedTuple

import yaml

_CI_WORKFLOW: Final = Path(".github/workflows/ci.yml")

# A gate step is a `coverage report` invocation carrying an explicit per-module
# include set and a threshold. The bare `--cov-fail-under=75` whole-tree floor in
# the pytest step is deliberately NOT one of these.
_GATE_RE: Final = re.compile(r"coverage\s+report\b[^\n]*?--fail-under=(\d+)", re.DOTALL)
_INCLUDE_RE: Final = re.compile(r"--include='([^']+)'")


class Gate(NamedTuple):
    name: str
    include: str
    threshold: int

    @property
    def paths(self) -> list[str]:
        return [p for p in self.include.split(",") if p]


def _iter_gates(workflow: dict[str, object], job_id: str) -> list[Gate]:
    jobs = workflow.get("jobs")
    if not isinstance(jobs, dict) or job_id not in jobs:
        raise SystemExit(f"{_CI_WORKFLOW}: no job {job_id!r} — did the workflow change?")
    job = jobs[job_id]
    steps = job.get("steps", []) if isinstance(job, dict) else []
    gates: list[Gate] = []
    for step in steps:
        if not isinstance(step, dict):
            continue
        # Each `run:` block may hold MORE THAN ONE gate (CI's "Unit tests +
        # coverage gates" step runs pytest and a gate in one block), so scan the
        # whole block rather than taking the first match.
        run = " ".join(str(step.get("run", "")).split())
        for match in _GATE_RE.finditer(run):
            segment = run[: match.end()]
            includes = _INCLUDE_RE.findall(segment)
            if not includes:
                continue
            gates.append(
                Gate(
                    name=str(step.get("name", "<unnamed step>")),
                    include=includes[-1],
                    threshold=int(match.group(1)),
                )
            )
    return gates


def _run_gate(gate: Gate) -> tuple[bool, str]:
    """Return ``(passed, output)``. A gate whose files are all absent is skipped."""
    if not any(Path(p).exists() for p in gate.paths):
        return True, "skipped — none of its files exist in this tree"
    argv = [
        "uv",
        "run",
        "coverage",
        "report",
        f"--include={gate.include}",
        f"--fail-under={gate.threshold}",
    ]
    proc = subprocess.run(argv, capture_output=True, text=True, check=False)  # noqa: S603
    return proc.returncode == 0, (proc.stdout + proc.stderr).strip()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--job",
        required=True,
        help="CI job id whose gates to run (e.g. 'python' or 'coverage-gates')",
    )
    parser.add_argument(
        "--min-gates",
        type=int,
        default=1,
        help=(
            "Fail if fewer than this many gates were extracted. A runner that "
            "silently matches nothing reports green while gating NOTHING (#245)."
        ),
    )
    args = parser.parse_args()

    if not _CI_WORKFLOW.exists():
        print(f"::error::{_CI_WORKFLOW} not found — run from the repo root", file=sys.stderr)
        return 2

    workflow = yaml.safe_load(_CI_WORKFLOW.read_text(encoding="utf-8"))
    gates = _iter_gates(workflow, args.job)

    # Non-vacuity floor: if the workflow's shape changes so the regex stops
    # matching, this must FAIL rather than pass having run nothing at all.
    if len(gates) < args.min_gates:
        print(
            f"::error::extracted only {len(gates)} coverage gate(s) from job "
            f"{args.job!r}, expected at least {args.min_gates}. The workflow's "
            "gate shape probably changed — this runner is now gating nothing.",
            file=sys.stderr,
        )
        return 2

    print(f"Running {len(gates)} coverage gate(s) from ci.yml job {args.job!r}\n")
    failures: list[tuple[Gate, str]] = []
    for gate in gates:
        passed, output = _run_gate(gate)
        marker = "ok  " if passed else "FAIL"
        print(f"  [{marker}] {gate.name}")
        if not passed:
            failures.append((gate, output))

    if failures:
        print(f"\n{len(failures)} coverage gate(s) FAILED:\n", file=sys.stderr)
        for gate, output in failures:
            print(f"--- {gate.name} (--fail-under={gate.threshold})", file=sys.stderr)
            print(output, file=sys.stderr)
            print(file=sys.stderr)
        return 1

    print(f"\nAll {len(gates)} coverage gate(s) passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
