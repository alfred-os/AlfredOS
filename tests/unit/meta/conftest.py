"""Shared fixtures for the gate-integrity meta suite (#543 review, rev-002).

``_load_runner()`` — the importlib dance that loads ``scripts/run_coverage_gates.py``
as a module rather than a package — was byte-identical in
``test_coverage_gate_runner.py`` and ``test_gate_surfaces_are_pinned.py``, and the
``yaml.safe_load(ci.yml)`` fixture body was duplicated alongside it under two
different names. CLAUDE.md: refactor on the SECOND duplication, not the first;
this was the second.

Session scope on ``runner`` is deliberate. Every test that mutates the loaded
module does so through ``monkeypatch.setattr``, which reverts at test teardown,
so one instance is safe — and it removes 12 re-executions of the script per run.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
import yaml

REPO_ROOT: Path = Path(__file__).resolve().parents[3]
CI_WORKFLOW: Path = REPO_ROOT / ".github" / "workflows" / "ci.yml"
RUNNER_SCRIPT: Path = REPO_ROOT / "scripts" / "run_coverage_gates.py"

#: Canonical set of gate-enforcing script BASENAMES (no `.py`, no `scripts/`
#: prefix) — scripts whose OWN correctness underpins a merge-blocking CI gate,
#: so moving one to `[tool.coverage.run] omit` would silently drop the check
#: that check enforces. Single source of truth for two independent consumers
#: that must never drift apart (#568): `test_gate_surfaces_are_pinned.py`
#: builds `_GATE_SCRIPT_RUN_RE` from this to detect a REQUIRED-check
#: invocation in `ci.yml`; `test_scripts_coverage_census.py` uses it to assert
#: none of these may ever be reclassified to `omit`. Before #568 the census
#: side hand-copied a 2-item tuple that had already drifted from this set
#: (`check_tag_t3` was missing), so that regression guard silently protected
#: only 2 of the 3 real gate-enforcing scripts.
GATE_ENFORCING_SCRIPT_NAMES: frozenset[str] = frozenset(
    {"check_tag_t3", "check_strict_declarations", "run_coverage_gates"}
)


def _load_script(module_name: str, path: Path) -> ModuleType:
    """Load `path` as a standalone module (a script, not a package).

    Registers the module in `sys.modules` BEFORE `exec_module` runs. Without
    that registration, a script combining `from __future__ import annotations`
    with `@dataclass` raises a bare `AttributeError: 'NoneType' object has no
    attribute '__dict__'` — not on some later use, but DURING `exec_module`
    itself, while the `@dataclass` decorator is running as part of executing
    the class body. `@dataclass` resolves ClassVar/InitVar/KW_ONLY markers by
    string-evaluating the postponed annotations against
    `sys.modules.get(cls.__module__).__dict__`; that lookup is `None` for a
    module never registered under its own name. Reproduced directly: a
    synthetic module built with `spec_from_file_location` + `exec_module` and
    no registration fails inside `exec_module` on 3.14.6; the identical module
    with `sys.modules[name] = module` set first does not.

    Current `scripts/*.py` callers happen not to trip this (none currently
    combine both features while ALSO being loaded this way), which is exactly
    why it is a latent trap rather than a live failure — see
    `test_script_loader_handles_future_annotations_dataclasses.py`.
    """
    spec = importlib.util.spec_from_file_location(module_name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        # `.pop(name, None)`, not `del`: a script's OWN code can remove
        # itself from `sys.modules` before raising (e.g. some
        # self-unregistering pattern) — `del` on an absent key raises
        # `KeyError`, which REPLACES the script's real exception as what the
        # caller sees (it survives only as `__context__`, invisible to
        # `except OriginalType:` and to `pytest.raises(OriginalType, ...)`).
        # #574 review; reproduced: a script that does `del
        # sys.modules[__name__]` then `raise RuntimeError(...)` surfaced
        # `KeyError` to the caller under the old `del`.
        sys.modules.pop(module_name, None)
        raise
    return module


@pytest.fixture(scope="session")
def runner() -> ModuleType:
    """Import ``scripts/run_coverage_gates.py`` — a script, not a package."""
    return _load_script("run_coverage_gates", RUNNER_SCRIPT)


@pytest.fixture(scope="session")
def ci_workflow() -> dict[str, Any]:
    """``.github/workflows/ci.yml``, parsed."""
    return yaml.safe_load(CI_WORKFLOW.read_text(encoding="utf-8"))


@pytest.fixture(scope="session")
def ci_workflow_raw() -> str:
    """``.github/workflows/ci.yml``, raw text — the second, independent oracle."""
    return CI_WORKFLOW.read_text(encoding="utf-8")
