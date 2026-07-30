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


# ---------------------------------------------------------------------------
# Bypass 1 (#537): a file the gate cannot read is a file the gate is not
# gating. Python's import machinery is far more permissive than this reader.
# ---------------------------------------------------------------------------


def test_latin1_source_is_a_violation_not_a_silent_pass(tmp_path: Path) -> None:
    """Bypass 1: a PEP-263 non-UTF-8 file imports and runs, but read_text raises.

    Measured on the real script: rc=0 while ``python -c 'import ...'`` executed
    the module and constructed TaggedContent[T3]. Swallowing UnicodeDecodeError
    means one header line defeats every rule in the gate.
    """
    hidden = tmp_path / "launder.py"
    # 0xe9 is a valid latin-1 'e-acute' and an invalid UTF-8 start byte.
    hidden.write_bytes(
        b"# -*- coding: latin-1 -*-\n"
        b"# comment with a latin-1 byte: \xe9\n"
        b"from alfred.security.tiers import tag, T3\n"
        b"x = tag(T3, 'laundered')\n"
    )

    violations = check_tag_t3._scan_file(hidden)

    assert violations, "a file the gate cannot decode must not scan clean"
    assert check_tag_t3._UNDECODABLE_MESSAGE in violations[0]


def test_unparseable_source_is_a_violation(tmp_path: Path) -> None:
    """A file carrying a real violation AND a SyntaxError must not scan clean."""
    broken = tmp_path / "broken.py"
    broken.write_text(
        "from alfred.security.tiers import tag, T3\nx = tag(T3, 'payload')\ndef (\n",
        encoding="utf-8",
    )

    violations = check_tag_t3._scan_file(broken)

    assert violations, "an unparseable file must not scan clean"
    assert check_tag_t3._UNPARSEABLE_MESSAGE in violations[0]


def test_a_real_utf8_file_still_scans_normally(tmp_path: Path) -> None:
    """Positive twin: the same text as valid UTF-8 trips the ORDINARY rule.

    Without this, the two tests above would pass on a detector that flagged
    every file for every reason.
    """
    ok = tmp_path / "ordinary.py"
    # encoding="utf-8" is REQUIRED. Path.write_text defaults to the locale
    # encoding, which on the blocking windows-latest unit leg is cp1252 — the
    # file would be written as non-UTF-8 and this positive twin would assert
    # the exact opposite of what it means to.
    ok.write_text(
        "# comment with a real unicode char: é\n"
        "from alfred.security.tiers import tag, T3\n"
        "x = tag(T3, 'payload')\n",
        encoding="utf-8",
    )

    violations = check_tag_t3._scan_file(ok)

    assert any(check_tag_t3._TAG_T3_MESSAGE in v for v in violations)
    assert not any(check_tag_t3._UNDECODABLE_MESSAGE in v for v in violations)
    assert not any(check_tag_t3._UNPARSEABLE_MESSAGE in v for v in violations)


def test_the_real_scan_root_has_no_unreadable_or_unparseable_files(tmp_path: Path) -> None:
    """Non-vacuity floor: this change must cost zero false positives.

    Measured at plan time: 0 unparseable, 0 unreadable across 293 files.

    THREE separate anti-vacuity devices, because the obvious form of this test
    is green on a detector that does nothing:

    1. The message constants are read EAGERLY into ``collection_failures``.
       Referenced only inside the comprehension's ``if`` clause they are never
       evaluated on a clean tree — measured: this floor passed while the
       constants did not exist at all.
    2. A census assertion, so a floor that scanned nothing cannot pass.
    3. A positive control planted in ``tmp_path`` and scanned by the SAME
       predicate, proving the filter can actually distinguish.
    """
    # Device 1 — eager read. An AttributeError here is the point.
    collection_failures = (
        check_tag_t3._UNPARSEABLE_MESSAGE,
        check_tag_t3._UNREADABLE_MESSAGE,
        check_tag_t3._UNDECODABLE_MESSAGE,
    )

    def _collection_failures_in(path: Path) -> list[str]:
        return [
            v for v in check_tag_t3._scan_file(path) if any(msg in v for msg in collection_failures)
        ]

    # Device 3 — positive control FIRST, so a clean result below cannot come
    # from the predicate being unable to match anything.
    control = tmp_path / "control.py"
    control.write_bytes(b"# -*- coding: latin-1 -*-\n# \xe9\nx = 1\n")
    assert _collection_failures_in(control), (
        "the predicate did not flag a known-undecodable file — the clean "
        "result below would be meaningless"
    )

    # Device 2 — census.
    paths = check_tag_t3._collect_paths(["src/alfred"])
    assert len(paths) >= 250, f"scanned implausibly few files: {len(paths)}"

    noisy = [v for p in paths for v in _collection_failures_in(p)]
    assert noisy == [], noisy
