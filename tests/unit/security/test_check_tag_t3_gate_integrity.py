"""In-process gate-integrity suite for ``scripts/check_tag_t3.py`` (#537).

Imports the REAL script via ``spec_from_file_location``. A ``tmp_path`` copy
would recompute ``_REPO_ROOT`` from ``__file__`` and invert every exemption,
so the module identity assertion below is load-bearing, not decorative.

This suite is deliberately in-process rather than ``subprocess.run``. The
pre-existing suites (``test_tag_t3_capability_gate.py``,
``test_check_tag_t3_subscript.py``) shell out, which records **zero** coverage
without ``COVERAGE_PROCESS_START`` — measured: 0%, 120/120 statements missed.
The ``_scan_text`` seam plus in-process calls are what make the 100% gate in
#537 Task 7 achievable at all.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

_REPO_ROOT: Path = Path(__file__).resolve().parents[3]
_SCRIPT: Path = _REPO_ROOT / "scripts" / "check_tag_t3.py"


def _load_script() -> ModuleType:
    spec = importlib.util.spec_from_file_location("check_tag_t3_under_test", _SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


check_tag_t3: ModuleType = _load_script()

# If this fires, every exemption assertion in this file is measuring a
# different tree. ``_REPO_ROOT`` is derived from ``__file__``, so a copy of the
# script planted under ``tmp_path`` silently inverts ``_APPROVED_PATHS`` and
# the in-repo/out-of-repo split — a test suite built on such a copy would
# assert the opposite of the production behaviour and still pass.
assert check_tag_t3._REPO_ROOT == _REPO_ROOT, (
    f"loaded script computed _REPO_ROOT={check_tag_t3._REPO_ROOT!r}, "
    f"expected {_REPO_ROOT!r} — exemption tests would be inverted"
)


def test_scan_text_reports_a_violation_without_touching_the_filesystem() -> None:
    """``_scan_text`` is pure: it takes text + a path label, reads no file.

    The path deliberately does not exist. If the seam ever starts reading from
    disk this test fails rather than silently scanning an empty string.
    """
    text = "from alfred.security.tiers import tag, T3\nx = tag(T3, 'payload')\n"
    nonexistent = _REPO_ROOT / "src" / "alfred" / "does_not_exist_on_disk.py"

    violations = check_tag_t3._scan_text(text, nonexistent)

    assert len(violations) == 2, violations
    assert violations[0] == f"{nonexistent}:2: {check_tag_t3._TAG_T3_MESSAGE}"
    assert violations[1] == "  x = tag(T3, 'payload')"


def test_scan_text_returns_empty_for_clean_text() -> None:
    """Negative floor. Paired with the positive above, so neither is vacuous."""
    text = "from alfred.security.tiers import tag, T2\nx = tag(T2, 'fine')\n"
    label = _REPO_ROOT / "src" / "alfred" / "clean.py"

    assert check_tag_t3._scan_text(text, label) == []
