"""#246 Phase B — the win32 collection-ignore list is correct and non-rotting.

The win32 branch of ``collect_ignore_for`` never runs on the macOS/Linux dev box
or the Linux CI legs, so these tests pin it directly: the platform gating (win32
→ the listed modules, else empty), structural invariants on the list, that the
produced paths resolve to existing files (anti-orphan), and — via ``pytester`` —
that pytest actually honours a ``collect_ignore_glob`` built from the helper.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from tests import conftest as root_conftest
from tests._posix_only_tests import POSIX_ONLY_TEST_FILES, collect_ignore_for

_TESTS_ROOT = Path(__file__).resolve().parents[2]  # tests/


def test_non_win32_ignores_nothing() -> None:
    assert collect_ignore_for("linux", _TESTS_ROOT) == []
    assert collect_ignore_for("darwin", _TESTS_ROOT) == []


def test_win32_ignores_the_listed_posix_only_modules() -> None:
    ignored = collect_ignore_for("win32", _TESTS_ROOT)
    # Formula pin: absolute paths under tests_root for every listed module.
    assert ignored == [str(_TESTS_ROOT / rel) for rel in POSIX_ONLY_TEST_FILES]
    # Structural invariants. The list grew from 3 to ~20+ during the #246 Phase B
    # grind, so an exact-basename literal set is no longer maintainable; the
    # reviewed DIFF of POSIX_ONLY_TEST_FILES is what makes each entry a reviewed
    # decision. Enforce that every entry is a distinct, well-formed tests/unit
    # path so a typo/dup/absolute-path slip trips locally.
    assert len(set(POSIX_ONLY_TEST_FILES)) == len(POSIX_ONLY_TEST_FILES), "duplicate entry"
    for rel in POSIX_ONLY_TEST_FILES:
        assert rel.startswith("unit/") and rel.endswith(".py") and not rel.startswith("/"), rel


def test_every_listed_module_exists() -> None:
    """Anti-orphan: a rename/deletion that orphans an entry fails loudly here."""
    for rel in POSIX_ONLY_TEST_FILES:
        assert (_TESTS_ROOT / rel).is_file(), f"orphaned collect-ignore entry: {rel}"


def test_pytest_honours_collect_ignore_from_helper(pytester: pytest.Pytester) -> None:
    """End-to-end: a ``collect_ignore_glob`` built by the helper hides the file.

    Recreates one POSIX-only path under the pytester root plus a portable
    sibling, feeds ``collect_ignore_for("win32", ...)`` into a temp conftest, and
    asserts only the portable test is collected — proving the conftest wiring
    (Task 2) actually prevents collection, the link the pure-function tests above
    do not exercise.
    """
    target_rel = POSIX_ONLY_TEST_FILES[0]
    target = pytester.path / target_rel
    target.parent.mkdir(parents=True)
    target.write_text("def test_would_crash() -> None:\n    assert True\n")
    (pytester.path / "test_portable.py").write_text("def test_runs() -> None:\n    assert True\n")

    ignore = collect_ignore_for("win32", pytester.path)
    pytester.makeconftest(f"collect_ignore_glob = {ignore!r}\n")

    result = pytester.runpytest("-q")
    result.assert_outcomes(passed=1)  # POSIX-only file ignored; only portable ran


def test_no_intermediate_conftest_shadows_the_guard() -> None:
    """No conftest under tests/unit may define collect_ignore[_glob].

    pytest does NOT merge collect_ignore/collect_ignore_glob across the conftest
    chain — the DEEPEST definer wins. An intermediate conftest assigning either
    name would silently shadow the top-most win32 guard for its subtree and
    re-break Windows collection. This static guard forbids that (mirrors the
    docker-conftest anti-rot guard).
    """
    offenders = [
        cf
        for cf in (_TESTS_ROOT / "unit").rglob("conftest.py")
        if "collect_ignore" in cf.read_text(encoding="utf-8")
    ]
    assert offenders == [], (
        f"collect_ignore[_glob] is not merged across conftests; the win32 guard "
        f"lives only in the top-most tests/conftest.py. Offenders: {offenders}"
    )


def test_conftest_wiring_is_pinned() -> None:
    """The REAL conftest attribute is wired to the helper on every platform."""
    assert root_conftest.collect_ignore_glob == collect_ignore_for(
        sys.platform, Path(root_conftest.__file__).resolve().parent
    )
