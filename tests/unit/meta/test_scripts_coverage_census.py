"""Every `scripts/*.py` must be gated or explicitly omitted (#543).

#537 added `--cov=scripts` so `check_tag_t3.py` could carry a 100% gate. That
pulled all seven scripts into the dataset and gated exactly one —
`run_coverage_gates.py` at 50% and `check_strict_declarations.py` at 0%, both
gate-enforcing code. The whole-tree floor is 75% and scripts/ is a small enough
slice that a new file at 0% moves it by less than the floor's headroom, so
nothing would say a word.

This is the #423 mechanism: gate on the ALLOW-LIST, not the calendar. A new
`scripts/*.py` fails here until someone classifies it — a gate in ci.yml, or an
`omit` entry with a reason. There is no third state.
"""

from __future__ import annotations

import tomllib
from pathlib import Path
from types import ModuleType
from typing import Any

_REPO_ROOT: Path = Path(__file__).resolve().parents[3]
_PYPROJECT: Path = _REPO_ROOT / "pyproject.toml"
_SCRIPTS_DIR: Path = _REPO_ROOT / "scripts"

# The ONE directory exempt from the census, and it must name the SAME root as
# the `scripts/vendor/**` entry in pyproject.toml's `[tool.coverage.run] omit`.
# See `test_the_vendor_exemption_names_the_same_root_as_the_omit_entry`.
_VENDOR_DIR: Path = _SCRIPTS_DIR / "vendor"
_VENDOR_OMIT_ENTRY: str = "scripts/vendor/**"


def _gated_script_paths(runner: ModuleType, ci_workflow: dict[str, Any]) -> set[str]:
    """Scripts carrying a coverage gate of ANY threshold, derived from ci.yml.

    Deliberately not `threshold == 100`. The census exists to ensure every
    script is CLASSIFIED; a ratchet is a legitimate classification. Requiring
    100 would leave only "100% or invisible", pushing borderline scripts into
    `omit` — the opposite of what #543 wants.

    Only the `python` job is scanned: it is the job whose gates read the
    unit-only dataset that `--cov=scripts` populates. The `coverage-gates` job
    reads combined unit+integration data and holds no scripts/ gate.

    Takes the loaded runner and parsed workflow as ARGUMENTS (#548 review,
    rev-001). This was the third copy of the
    ``spec_from_file_location``/``module_from_spec``/``exec_module`` dance plus
    its own inline ``yaml.safe_load``; the shared session fixtures in
    ``conftest.py`` removed the other two, and leaving this one behind left the
    #543 rev-002 de-duplication incomplete.
    """
    return {
        path
        for gate in runner._iter_gates(ci_workflow, "python")
        for path in gate.paths
        if path.startswith("scripts/")
    }


def _omitted_script_paths() -> set[str]:
    config: dict[str, Any] = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))
    omit = config["tool"]["coverage"]["run"]["omit"]
    return {entry for entry in omit if entry.startswith("scripts/")}


def _is_censused(path: Path) -> bool:
    """Whether a `scripts/` file is subject to the census.

    Split out from `_measured_script_paths` so the exemption rule can be
    asserted against SYNTHETIC paths — a filter that is only ever run over the
    tree as it stands today is untestable in the direction that matters (does
    it exempt more than it should?).

    The vendor exemption is ANCHORED at `scripts/vendor/`, not "any path
    component named `vendor`". The looser rule would exempt, say,
    `scripts/tools/vendor/mod.py` from the census while pyproject.toml's
    `scripts/vendor/**` omit entry does NOT stop coverage measuring it — i.e. a
    file that is measured, unclassified, and invisible to the census. That is
    the exact hole this file exists to close, reproduced inside it (#543).
    """
    return "__pycache__" not in path.parts and not path.is_relative_to(_VENDOR_DIR)


def _measured_script_paths() -> set[str]:
    """Every `.py` under `scripts/` — what `--cov=scripts` measures.

    `as_posix()` is load-bearing: `str(PurePath)` renders with `os.sep`, so on
    the Windows unit leg every path would carry backslashes while the gated and
    omitted sets come from YAML/TOML with forward slashes. The mismatch would be
    total and the census would report every script unclassified.
    """
    return {
        p.relative_to(_REPO_ROOT).as_posix() for p in _SCRIPTS_DIR.rglob("*.py") if _is_censused(p)
    }


def test_every_script_is_either_gated_or_explicitly_omitted(
    runner: ModuleType, ci_workflow: dict[str, Any]
) -> None:
    """The #423 rule. A new script has no silent third state."""
    unclassified = (
        _measured_script_paths()
        - _gated_script_paths(runner, ci_workflow)
        - _omitted_script_paths()
    )

    assert not unclassified, (
        f"these scripts/ files are measured by `--cov=scripts` but are neither "
        f"gated in ci.yml nor omitted in pyproject.toml: {sorted(unclassified)}. "
        f"Give each one a coverage gate, or add it to [tool.coverage.run] omit "
        f"with a stated reason. Leaving it unclassified lets it join the 75% "
        f"whole-tree floor at 0% with nothing saying a word (#543, #423)."
    )


def test_the_two_classifications_do_not_overlap(
    runner: ModuleType, ci_workflow: dict[str, Any]
) -> None:
    """A file cannot be both gated and omitted — `omit` wins, so the gate would
    measure an empty set and pass vacuously. A paper gate with extra steps."""
    both = _gated_script_paths(runner, ci_workflow) & _omitted_script_paths()

    assert not both, (
        f"{sorted(both)} are both gated in ci.yml and omitted in pyproject.toml. "
        f"`omit` wins, so those gates measure nothing and pass vacuously."
    )


def test_the_census_is_not_vacuous(runner: ModuleType, ci_workflow: dict[str, Any]) -> None:
    """Anti-vacuity floor: an empty set on any side makes the two assertions
    above pass while checking nothing."""
    assert _measured_script_paths(), "no scripts/*.py found — the census is empty"
    assert _gated_script_paths(runner, ci_workflow), "no scripts/ coverage gates found in ci.yml"
    assert _omitted_script_paths(), "no scripts/ omit entries found in pyproject.toml"


def test_the_gate_enforcing_scripts_are_gated_not_omitted(
    runner: ModuleType, ci_workflow: dict[str, Any]
) -> None:
    """Naming these means moving either into `omit` is a failing edit."""
    gated = _gated_script_paths(runner, ci_workflow)

    for script in ("scripts/run_coverage_gates.py", "scripts/check_strict_declarations.py"):
        assert script in gated, (
            f"{script} is gate-enforcing code and must carry its own gate "
            f"(#543); found gated scripts: {sorted(gated)}"
        )


def test_the_vendor_exemption_names_the_same_root_as_the_omit_entry() -> None:
    """The census's one exemption and coverage's `omit` must describe ONE set.

    Two sides, two mechanisms: coverage stops MEASURING `scripts/vendor/**`,
    and `_is_censused` stops the census CLASSIFYING it. If they ever name
    different roots, the gap between them is measured-but-unclassified code —
    the state this whole file refuses. Pinned by root rather than by calling
    into `coverage.files`, whose matcher class was renamed within the versions
    this repo has installed (`FnmatchMatcher` -> `GlobMatcher`); a pin on a
    private API that breaks on upgrade teaches people to delete pins.
    """
    vendor_entries = {entry for entry in _omitted_script_paths() if "vendor" in entry}

    assert vendor_entries == {_VENDOR_OMIT_ENTRY}, (
        f"pyproject.toml's scripts/ omit entries mentioning `vendor` are "
        f"{sorted(vendor_entries)}, expected exactly {[_VENDOR_OMIT_ENTRY]!r}. "
        f"The census exempts {_VENDOR_DIR.relative_to(_REPO_ROOT).as_posix()!r}; "
        f"if coverage omits a different root the difference is measured but "
        f"unclassified (#543)."
    )
    assert _VENDOR_OMIT_ENTRY.removesuffix("/**") == _VENDOR_DIR.relative_to(_REPO_ROOT).as_posix()


def test_the_vendor_exemption_is_anchored_rather_than_name_based() -> None:
    """Exempt `scripts/vendor/` at ANY depth — and nothing else called `vendor`.

    The brief's filter was `"vendor" not in p.parts`, which exempts a `vendor`
    directory ANYWHERE under `scripts/`. Coverage's omit entry does not: it is
    rooted at `scripts/vendor/`. So `scripts/tools/vendor/mod.py` would be
    measured by `--cov=scripts`, unclassified by the census, and invisible.
    Asserted on synthetic paths so it holds regardless of what the tree
    contains today (`scripts/vendor/` currently holds one JSON file and no
    `.py`, which is what makes the looser rule DORMANT rather than benign).
    """
    assert not _is_censused(_VENDOR_DIR / "mod.py")
    assert not _is_censused(_VENDOR_DIR / "pkg" / "mod.py"), (
        "a vendored subpackage is exempt from coverage's `scripts/vendor/**` "
        "omit at any depth, so the census must exempt it at any depth too"
    )
    assert _is_censused(_SCRIPTS_DIR / "tools" / "vendor" / "mod.py"), (
        "a `vendor` directory NOT under scripts/vendor/ is still measured by "
        "`--cov=scripts`, so the census must still demand it be classified"
    )
    assert _is_censused(_SCRIPTS_DIR / "some_new_script.py"), (
        "the exemption swallowed an ordinary script — the census would pass "
        "over the very files it exists to count"
    )
