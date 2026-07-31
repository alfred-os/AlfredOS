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

import ast
import contextlib
import importlib.util
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

_NEEDS_SYMLINKS = pytest.mark.skipif(
    sys.platform == "win32",
    reason="symlink creation needs elevation on the blocking windows-latest unit leg",
)

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
    # test-005, SECOND site. The plan named only the zero-false-positive floor
    # below; this enumeration is the other place a collection-failure message
    # can hide. A reviewer injected the fourth-message regression and this twin
    # SURVIVED — an ordinary file reported as unscannable would have gone
    # unnoticed here. Every enumeration of the collection-failure messages has
    # to move together or the set of them is only as complete as its shortest
    # copy.
    assert not any(check_tag_t3._UNSCANNABLE_MESSAGE in v for v in violations)


def test_the_real_scan_root_has_no_unreadable_or_unparseable_files(tmp_path: Path) -> None:
    """Non-vacuity floor: this change must cost zero false positives.

    Measured at plan time: 0 unparseable, 0 unreadable across 293 files;
    re-measured after #541 across the 332 files of BOTH declared roots, and
    again after #542 added the fourth message (0 unscannable).

    The tuple ENUMERATES the collection-failure messages, so a message missing
    from it is invisible to this floor (test-005): a real file that started
    failing that way would leave the floor green. The other enumeration lives
    in ``test_a_real_utf8_file_still_scans_normally``; both must list all four.

    #541: was ``_collect_paths(["src/alfred"])``. A partial in-repo directory
    scan is now refused at runtime, so this asserts over the production
    argument-less shape — which is also the wider tree, so the floor got
    stronger rather than weaker.

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
        check_tag_t3._UNSCANNABLE_MESSAGE,
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
    paths = check_tag_t3._collect_paths([])
    assert len(paths) >= 250, f"scanned implausibly few files: {len(paths)}"

    noisy = [v for p in paths for v in _collection_failures_in(p)]
    assert noisy == [], noisy


# ---------------------------------------------------------------------------
# Bypasses 2 and 4 (#537): the exemption matched the RAW path string before
# resolving, so `..` traversal and symlinks could present one identity to the
# matcher and another to the reader.
# ---------------------------------------------------------------------------


def test_dotdot_traversal_cannot_launder_a_src_file_into_exemption() -> None:
    """Bypass 2: the exemption regex ran on the RAW string, before resolve().

    ``tests/../src/alfred/...`` and ``src/alfred/...`` are the same file. One
    was exempt and one was not. Works with RELATIVE paths, so it is reachable
    from the production invocation (`Makefile` and CI both pass `src/alfred`).
    This is #428's `/lib64/../etc` traversal class on the exemption axis.

    The subject MUST be a non-exempt file. An equality assertion over
    ``tiers.py`` would be satisfied by 'both True' — it is exempt via
    _APPROVED_PATHS — and so passes against the UNFIXED script. Measured.
    """
    direct = Path("src/alfred/orchestrator/core.py")
    laundered = Path("tests/../src/alfred/orchestrator/core.py")

    assert direct.resolve() == laundered.resolve(), "precondition: same file"
    assert check_tag_t3._is_exempt(direct) is False, "precondition: not exempt"
    assert check_tag_t3._is_exempt(laundered) is False, (
        "a `..` hop through tests/ bought exemption for a src file"
    )


def test_dotdot_traversal_preserves_a_legitimate_exemption() -> None:
    """The negative twin: hardening must not break a real approved home."""
    direct = Path("src/alfred/security/tiers.py")
    laundered = Path("tests/../src/alfred/security/tiers.py")

    assert check_tag_t3._is_exempt(direct) is True
    assert check_tag_t3._is_exempt(laundered) is True


@_NEEDS_SYMLINKS
def test_an_in_repo_symlink_named_test_py_is_not_exempt(tmp_path: Path) -> None:
    """Bypass 4: ``path.name`` read the LINK, ``resolved`` read the TARGET.

    The live direction is an IN-repo link pointing OUT of the repo, because
    _is_exempt requires ``not resolved.is_relative_to(_REPO_ROOT)``. Round 1
    recorded this backwards; getting the direction wrong makes the regression
    test pass vacuously.
    """
    target = tmp_path / "payload.py"
    target.write_text(
        "from alfred.security.tiers import tag, T3\nx = tag(T3, 'p')\n", encoding="utf-8"
    )

    link_dir = _REPO_ROOT / "build" / "synthetic-537-symlink"
    link_dir.mkdir(parents=True, exist_ok=True)
    link = link_dir / "test_bypass.py"
    try:
        if link.exists() or link.is_symlink():
            link.unlink()
        link.symlink_to(target)

        assert check_tag_t3._is_exempt(link) is False, (
            "an in-repo file named test_*.py is exempt only under tests/; a "
            "symlink must not buy exemption by pointing out of the repo"
        )
        assert check_tag_t3._scan_file(link), "the link's content must be scanned"
    finally:
        if link.is_symlink() or link.exists():
            link.unlink()
        # Best-effort tidy-up: rmdir raises if another test's fixture is still
        # in the same directory, or if build/ is not empty. Leaving the empty
        # directory behind is harmless — the gate derives its scan set from git,
        # and build/ is gitignored — so a failure here must not mask the
        # assertion that ran above.
        with contextlib.suppress(OSError):
            link_dir.rmdir()
            link_dir.parent.rmdir()


def test_a_real_out_of_repo_tmp_path_fixture_is_still_exempt(tmp_path: Path) -> None:
    """Negative twin for the symlink hardening.

    The unit suite plants violating ``test_*.py`` fixtures under ``tmp_path``
    and relies on them being exempt. Keying the basename check on
    ``resolved.name`` must not break that.
    """
    fixture = tmp_path / "test_fixture_plant.py"
    fixture.write_text(
        "from alfred.security.tiers import tag, T3\nx = tag(T3, 'fixture')\n", encoding="utf-8"
    )

    assert check_tag_t3._is_exempt(fixture) is True
    assert check_tag_t3._scan_file(fixture) == []


def test_a_directory_literally_named_tests_is_still_exempt() -> None:
    """Negative floor: the legitimate exemption must survive the hardening."""
    assert check_tag_t3._is_exempt(Path("tests/unit/security/test_tag_t3_capability_gate.py"))


def test_a_path_segment_merely_containing_tests_is_not_exempt() -> None:
    """Component matching, not substring: 'contests/' must not be exempt.

    The old regex was ``(^|/)tests/`` which is already anchored, so this is a
    forward guard against a re-widening to a bare substring check.
    """
    assert check_tag_t3._is_exempt(Path("src/alfred/contests/foo.py")) is False
    assert check_tag_t3._is_exempt(Path("src/alfred/tests_helpers/foo.py")) is False


# ---------------------------------------------------------------------------
# Bypass 3 (#537): Path.rglob does not recurse a symlinked directory met
# mid-walk. Collection now derives from `git ls-files`, which removes the
# traversal entirely for in-repo directories.
# ---------------------------------------------------------------------------


@_NEEDS_SYMLINKS
def test_a_symlinked_package_directory_does_not_hide_its_subtree(tmp_path: Path) -> None:
    """Bypass 3: Path.rglob skips a symlinked directory met MID-WALK.

    The link must sit INSIDE the scanned root, not BE the scanned root.
    ``rglob`` DOES follow a symlink passed as the walk root, so a fixture that
    scans the link directly passes against the unfixed script — measured by the
    review fleet. The real bug is a link encountered during traversal.
    """
    root = tmp_path / "root"
    (root / "pkg").mkdir(parents=True)
    (root / "pkg" / "ordinary.py").write_text("x = 1\n", encoding="utf-8")

    hidden = tmp_path / "outside"
    hidden.mkdir()
    (hidden / "launder.py").write_text(
        "from alfred.security.tiers import tag, T3\nx = tag(T3, 'p')\n", encoding="utf-8"
    )

    (root / "pkg" / "linked").symlink_to(hidden, target_is_directory=True)

    collected = check_tag_t3._collect_paths([str(root)])

    assert any(p.name == "launder.py" for p in collected), (
        f"a symlinked directory met mid-walk hid its subtree: {collected}"
    )


def test_collect_paths_prefers_git_over_traversal_for_an_in_repo_directory() -> None:
    """The DIFFERENTIAL oracle: git's answer, not a hard-coded count.

    A live ``== 293`` assertion is vacuous on a clean CI checkout, because the
    856-file delta comes entirely from ``plugins/alfred_tui/.venv``, which is
    gitignored and created by no workflow — so there rglob and git agree and
    the test passes whichever implementation is in place. Asserting AGAINST git
    directly pins the behaviour on every runner.

    #541: the scanned side was ``["src/alfred"]``, now refused as a partial
    in-repo directory scan, so both sides move to the argument-less production
    shape.

    The git side names the roots LITERALLY and must stay that way. A first cut
    derived them from ``_DEFAULT_SCAN_ROOTS``, on the reasoning that a literal
    would drift — but that makes both sides of the oracle move together, which
    is this repo's tautological-oracle trap: **measured, that version SURVIVES
    the M5 mutation** (narrow the constant to ``("src/alfred",)`` and the test
    stays green, because the expectation narrows with it). A literal is an
    independent oracle, so M5 kills here as well as at the constant pin. If a
    third root is ever added, this list is a deliberate second edit — that is
    the cost of independence, and it is the right way round.
    """
    expected = {
        _REPO_ROOT / line
        for line in subprocess.run(
            ["git", "ls-files", "--", "src/alfred", "plugins"],  # noqa: S607
            capture_output=True,
            text=True,
            check=True,
            cwd=_REPO_ROOT,
        ).stdout.splitlines()
        if line.endswith(".py")
    }

    assert set(check_tag_t3._collect_paths([])) == expected
    assert len(expected) >= 250, "sanity: the census floor must be satisfiable"


def test_git_derivation_excludes_a_gitignored_file_a_traversal_would_find() -> None:
    """Pins the .venv exclusion WITHOUT depending on a .venv existing.

    ``plugins/alfred_tui/.venv`` is gitignored and no workflow creates it, so a
    CI runner sees 39 files either way and a count-based assertion proves
    nothing. This plants a gitignored file of its own, so the assertion means
    the same thing on every machine.
    """
    ignored_dir = _REPO_ROOT / "build" / "synthetic-537-ignored"
    ignored_dir.mkdir(parents=True, exist_ok=True)
    planted = ignored_dir / "vendored.py"
    try:
        planted.write_text(
            "from alfred.security.tiers import tag, T3\nx = tag(T3, 'p')\n", encoding="utf-8"
        )

        # Precondition: git really does ignore it, or the test proves nothing.
        assert (
            subprocess.run(  # noqa: S603
                ["git", "check-ignore", "-q", str(planted)],  # noqa: S607
                check=False,
                cwd=_REPO_ROOT,
            ).returncode
            == 0
        ), "fixture is not gitignored — the test would be vacuous"

        # Precondition: a traversal WOULD find it, or there is nothing to exclude.
        traversed = {p.resolve() for p in (_REPO_ROOT / "build").rglob("*.py")}
        assert planted.resolve() in traversed, (
            "rglob does not see the fixture — the test would be vacuous"
        )

        # git answers EMPTY (not "could not answer") for a fully-ignored tree.
        assert check_tag_t3._git_tracked_python_files(Path("build")) == []
    finally:
        planted.unlink(missing_ok=True)
        with contextlib.suppress(OSError):
            ignored_dir.rmdir()


def test_an_in_repo_directory_with_no_tracked_python_refuses_rather_than_traversing() -> None:
    """`git ls-files` exits 0 with EMPTY output for an ignored/absent path.

    Falling back to rglob there would re-scan exactly the gitignored trees the
    git derivation exists to exclude — so an in-repo root git reports empty
    must RAISE. Distinguishing 'git answered empty' ([]) from 'git could not
    answer' (None) is what makes that possible.

    The aggregate census cannot catch this: `src/alfred plugins` yielding
    293 + 0 still clears a 250-file floor while gating zero plugin files.

    #541 ORACLE INDEPENDENCE. ``build`` is also a partial in-repo directory
    scan, so the new root invariant raises here too — and if this test keyed
    only on the base exception type, deleting the per-directory floor it
    exists to guard would leave it GREEN (measured: it does). It therefore
    discriminates twice: on the message, and on the concrete subclass.
    """
    ignored_dir = _REPO_ROOT / "build" / "synthetic-537-empty"
    ignored_dir.mkdir(parents=True, exist_ok=True)
    try:
        with pytest.raises(
            check_tag_t3.EmptyScanRootError, match="no Python files found"
        ) as excinfo:
            check_tag_t3._collect_paths(["build"])
        assert not isinstance(excinfo.value, check_tag_t3.PartialScanRootError), (
            "the per-directory floor did not fire — the root-coverage invariant "
            "raised instead, and this guard would be passing on the wrong error"
        )
    finally:
        with contextlib.suppress(OSError):
            ignored_dir.rmdir()


def test_a_multi_root_scan_still_succeeds_when_every_root_is_populated() -> None:
    """Negative twin for the per-directory floor: the real invocation works."""
    collected = check_tag_t3._collect_paths(["src/alfred", "plugins"])

    assert collected
    assert not any(".venv" in p.parts for p in collected), (
        "the vendored plugins/alfred_tui/.venv reached the scan set"
    )


def test_an_explicit_file_argument_is_scanned_even_if_untracked(tmp_path: Path) -> None:
    """Positive control: file args bypass the git derivation entirely.

    The unit suite plants untracked fixtures and passes them by path; if the
    git derivation swallowed those, every subprocess test would go vacuous.
    """
    planted = tmp_path / "planted.py"
    planted.write_text(
        "from alfred.security.tiers import tag, T3\nx = tag(T3, 'p')\n", encoding="utf-8"
    )

    assert check_tag_t3._collect_paths([str(planted)]) == [planted]
    assert check_tag_t3._scan_file(planted)


# ---------------------------------------------------------------------------
# Bypass 5 (#537): `_collect_paths([])` resolves `src/alfred` relative to CWD,
# so an argument-less run from elsewhere scanned 0 files and exited 0.
# ---------------------------------------------------------------------------


def test_main_refuses_an_empty_scan_root_instead_of_reporting_success(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Exit 2 is distinct from 1 so a caller can tell 'the gate failed' from
    'the gate could not run'. Without the handler EmptyScanRootError escapes as
    an unhandled traceback, which is loud but is not a usable exit contract.
    """
    empty = tmp_path / "empty"
    empty.mkdir()

    rc = check_tag_t3.main([str(empty)])

    assert rc == 2, "scanning zero files must not report success"
    err = capsys.readouterr().err
    assert "no Python files found" in err
    assert "Traceback" not in err, "the error must be reported, not raised"


def test_main_refuses_when_the_default_scan_root_is_not_there(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The actual bypass: an argument-less run from the wrong directory.

    Before #537 this scanned 0 files and returned 0 with no diagnostic. Task 2
    already made it fail closed via the unreadable-file rule, but the message
    ('src/alfred:1: file could not be read') described a file, not the real
    fault. The census names the actual problem.
    """
    monkeypatch.chdir(tmp_path)

    rc = check_tag_t3.main([])

    assert rc == 2
    assert "no Python files found" in capsys.readouterr().err


def test_main_refuses_a_directory_scan_that_is_implausibly_small(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The aggregate census: a populated-but-tiny scan root is still suspect.

    The per-directory floor only catches ZERO files. A scan root that resolved
    somewhere unexpected but non-empty would clear it, so main keeps an
    aggregate floor as well.

    #541: was ``main(["src/alfred"])``, now refused as a partial in-repo
    directory scan before the census is ever reached. Driving the census from
    the production argument-less shape keeps this a test of the MECHANISM
    (the shipped value is pinned separately, below).
    """
    monkeypatch.setattr(check_tag_t3, "_MIN_SCANNED_FILES", 100_000)

    rc = check_tag_t3.main([])

    assert rc == 2
    err = capsys.readouterr().err
    assert "expected at least" in err


def test_the_configured_census_floor_actually_rejects_a_small_scan(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Pins the REAL ``_MIN_SCANNED_FILES`` value, not a monkeypatched one.

    ``test_main_refuses_a_directory_scan_that_is_implausibly_small`` patches the
    constant, so it proves the census MECHANISM works while saying nothing
    about the shipped value — measured: setting the real constant to 0 left
    that test green, which would disable the census in production silently.

    #541: was ``main(["scripts"])``, now refused as a partial in-repo directory
    scan before the census runs. The small root moves into
    ``_DEFAULT_SCAN_ROOTS`` instead, so the run is argument-less and LEGAL
    while still scanning far too few files. ``scripts/`` holds 7 tracked
    ``.py`` files against the shipped floor of 250, so this reds if the
    constant is ever lowered to nothing.

    Patching the ROOTS rather than the FLOOR is what keeps this a value pin:
    ``_MIN_SCANNED_FILES`` is read at its shipped value. It is also the only
    remaining route to the census branch at all — with the root invariant in
    place, every legal directory scan covers both roots and clears 250.
    """
    monkeypatch.setattr(check_tag_t3, "_DEFAULT_SCAN_ROOTS", ("scripts",))

    assert check_tag_t3.main([]) == 2
    assert "expected at least" in capsys.readouterr().err


def test_main_returns_zero_on_the_real_tree() -> None:
    """Positive twin: the census must not red the real invocation.

    #541: was ``main(["src/alfred"])``. That is now a refused partial scan, so
    this asserts the shape production actually uses — no arguments at all.
    """
    assert check_tag_t3.main([]) == 0


def test_main_still_returns_one_for_a_real_violation(tmp_path: Path) -> None:
    """A single planted file is below the census floor but must still red as 1.

    The census applies to DIRECTORY scans, not explicit file args — otherwise
    every fixture-based test in the suite would start returning 2.
    """
    bad = tmp_path / "bad.py"
    bad.write_text(
        "from alfred.security.tiers import tag, T3\nx = tag(T3, 'p')\n", encoding="utf-8"
    )

    assert check_tag_t3.main([str(bad)]) == 1


# ---------------------------------------------------------------------------
# Coverage completion (#537 Task 7). The rule branches below are exercised by
# the pre-existing subprocess suites, which record ZERO coverage. These call
# the same code in-process so the 100% gate is reachable without weakening it.
# ---------------------------------------------------------------------------


def test_is_exempt_returns_false_for_an_unresolvable_path() -> None:
    """The exception arm of _is_exempt's resolve().

    An embedded NUL raises ValueError — NOT OSError or RuntimeError. Catching
    only those two leaves this arm uncovered AND lets the exception escape, so
    the gate would crash on a malformed argument.
    """
    assert check_tag_t3._is_exempt(Path("bad\x00path.py")) is False


def test_unreadable_path_is_a_violation(tmp_path: Path) -> None:
    """The OSError arm of _scan_file — reading a directory as a file."""
    a_directory = tmp_path / "not_a_file.py"
    a_directory.mkdir()

    violations = check_tag_t3._scan_file(a_directory)

    assert violations
    assert check_tag_t3._UNREADABLE_MESSAGE in violations[0]


def test_qualified_and_unresolvable_call_shapes(tmp_path: Path) -> None:
    """_arg_name's Attribute and fall-through arms, and tag() with no args."""
    label = tmp_path / "shapes.py"

    qualified = check_tag_t3._scan_text("import tiers\nx = tiers.tag(tiers.T3, 'p')\n", label)
    assert any(check_tag_t3._TAG_T3_MESSAGE in v for v in qualified)

    # tag() with no positional args, and a non-Name/Attribute first arg.
    assert check_tag_t3._scan_text("tag()\n", label) == []
    assert check_tag_t3._scan_text("tag(1, 'p')\n", label) == []
    # A call whose func is neither Name nor Attribute (a lambda call).
    assert check_tag_t3._scan_text("(lambda: None)()\n", label) == []


def test_subscript_construction_slice_variants(tmp_path: Path) -> None:
    """The T3 / quoted-"T3" / benign / non-constant slice branches."""
    label = tmp_path / "slices.py"
    msg = check_tag_t3._TAGGED_CONTENT_T3_SUBSCRIPT_MESSAGE

    assert any(msg in v for v in check_tag_t3._scan_text("TaggedContent[T3](x)\n", label))
    assert any(msg in v for v in check_tag_t3._scan_text('TaggedContent["T3"](x)\n', label))
    # Benign tier and a non-T3 string must NOT trip.
    assert check_tag_t3._scan_text("TaggedContent[T2](x)\n", label) == []
    assert check_tag_t3._scan_text('TaggedContent["T2"](x)\n', label) == []
    # Non-Name, non-Constant slice, and a non-Subscript callee.
    assert check_tag_t3._scan_text("TaggedContent[1](x)\n", label) == []
    assert check_tag_t3._scan_text("Other[T3](x)\n", label) == []


def test_cast_bypass_and_type_ignore_suppression(tmp_path: Path) -> None:
    """The cast rule's arms and the line-based suppression rule."""
    label = tmp_path / "casts.py"

    cast_msg = check_tag_t3._CAST_TAGGED_CONTENT_MESSAGE
    assert any(
        cast_msg in v for v in check_tag_t3._scan_text("cast(TaggedContent[T2], x)\n", label)
    )
    assert any(
        cast_msg in v for v in check_tag_t3._scan_text('cast("TaggedContent[T2]", x)\n', label)
    )
    # cast() with no args, a non-subscript non-constant arg, and a plain string.
    assert check_tag_t3._scan_text("cast()\n", label) == []
    assert check_tag_t3._scan_text("cast(x, y)\n", label) == []
    assert check_tag_t3._scan_text('cast("int", y)\n', label) == []

    suppressed = check_tag_t3._scan_text(
        "x: TaggedContent = y  # type: ignore[assignment]\n", label
    )
    assert any(check_tag_t3._TYPE_IGNORE_MESSAGE in v for v in suppressed)


def test_git_derivation_returns_none_when_git_cannot_answer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Both 'git could not answer' arms: an exception, and a non-zero exit.

    None must mean 'could not answer' so the caller falls back, while [] means
    'answered: nothing tracked' so the caller refuses. Conflating them would
    let an empty in-repo root fall back to a traversal of gitignored trees.
    """

    def _raise(*args: object, **kwargs: object) -> None:
        raise OSError("git not found")

    monkeypatch.setattr(check_tag_t3.subprocess, "run", _raise)
    assert check_tag_t3._git_tracked_python_files(Path("src/alfred")) is None

    class _Failed:
        returncode = 128
        stdout = b""

    monkeypatch.setattr(check_tag_t3.subprocess, "run", lambda *a, **k: _Failed())
    assert check_tag_t3._git_tracked_python_files(Path("src/alfred")) is None


def test_git_unavailable_falls_back_to_traversal(monkeypatch: pytest.MonkeyPatch) -> None:
    """The fallback arm for an in-repo directory when git cannot answer.

    #541: ``scripts`` alone is now a partial in-repo directory scan. The arm
    under test needs an IN-repo directory (an out-of-repo one never consults
    git at all), so the root set is narrowed to match the argument rather than
    the argument widened away from the branch it exists to reach.
    """
    monkeypatch.setattr(check_tag_t3, "_DEFAULT_SCAN_ROOTS", ("scripts",))
    monkeypatch.setattr(check_tag_t3, "_git_tracked_python_files", lambda _d: None)

    collected = check_tag_t3._collect_paths(["scripts"])

    assert collected, "the rglob fallback found nothing"
    assert any(p.name == "check_tag_t3.py" for p in collected)


# ---------------------------------------------------------------------------
# PR #540 review findings. Each regression below was reproduced against the
# first revision of this branch before being fixed.
# ---------------------------------------------------------------------------


@_NEEDS_SYMLINKS
def test_a_symlink_from_src_into_tests_does_not_buy_exemption(tmp_path: Path) -> None:
    """sec-001: deciding exemption on the RESOLVED path alone was a regression.

    A tracked symlink at src/alfred/security/loader.py pointing into tests/
    resolved to a tests/ path and was exempt, so any production file could be
    laundered by pointing it at the test tree. Measured rc=0 where the previous
    gate reported rc=1. Both ends of a symlink are author-controlled, so the
    LEXICAL view must agree before anything is exempt.
    """
    link_dir = _REPO_ROOT / "build" / "synthetic-540-symlink-into-tests"
    link_dir.mkdir(parents=True, exist_ok=True)
    link = link_dir / "loader.py"
    target = _REPO_ROOT / "tests" / "unit" / "security" / "test_tag_t3_capability_gate.py"
    try:
        if link.is_symlink() or link.exists():
            link.unlink()
        link.symlink_to(target)

        assert check_tag_t3._is_exempt(link) is False, (
            "a symlink pointing into tests/ bought exemption for a non-test path"
        )
    finally:
        if link.is_symlink() or link.exists():
            link.unlink()
        with contextlib.suppress(OSError):
            link_dir.rmdir()


def test_a_nested_directory_named_tests_does_not_exempt_production_code() -> None:
    """sec-002: only the repo's TOP-LEVEL tests/ tree is exempt.

    ``src/alfred/security/tests/bypass.py`` is importable as
    ``alfred.security.tests.bypass`` and was exempt because ``tests`` appeared
    anywhere in the path components. The scan root now includes plugins/, so
    the same hole would have widened.
    """
    assert check_tag_t3._is_exempt(Path("src/alfred/security/tests/bypass.py")) is False
    assert check_tag_t3._is_exempt(Path("plugins/alfred_discord/tests/bypass.py")) is False
    # The real top-level tree stays exempt — the negative twin.
    assert (
        check_tag_t3._is_exempt(Path("tests/unit/security/test_check_tag_t3_subscript.py")) is True
    )


def test_an_untracked_new_file_is_still_scanned() -> None:
    """err-001: ``git ls-files`` without --others lists only the INDEX.

    A brand-new file was invisible to a directory scan until it was ``git
    add``ed — measured: an untracked src/alfred file containing
    TaggedContent[T3](...) scanned rc=0. CI was unaffected (it scans a committed
    merge ref), so the loss was entirely in the local ``make check`` loop, which
    is exactly where an author needs the gate to speak.
    """
    planted = _REPO_ROOT / "src" / "alfred" / "zz_540_untracked_probe.py"
    try:
        planted.write_text(
            "from alfred.security.tiers import tag, T3\nx = tag(T3, 'p')\n", encoding="utf-8"
        )
        # Precondition: genuinely untracked, or the test proves nothing.
        tracked = subprocess.run(  # noqa: S603
            ["git", "ls-files", "--error-unmatch", str(planted)],  # noqa: S607
            capture_output=True,
            check=False,
            cwd=_REPO_ROOT,
        )
        assert tracked.returncode != 0, "fixture is tracked — the test would be vacuous"

        # #541: was ``["src/alfred"]``, now a refused partial in-repo scan.
        collected = check_tag_t3._collect_paths([])
        assert planted in collected, "an untracked new file was not scanned"
    finally:
        planted.unlink(missing_ok=True)


def test_a_gitignored_file_is_still_excluded_despite_others() -> None:
    """The negative twin for --others: --exclude-standard must still apply.

    Adding --others without --exclude-standard would have scanned the vendored
    plugins/alfred_tui/.venv — 856 files — undoing the whole derivation.
    """
    ignored_dir = _REPO_ROOT / "build" / "synthetic-540-ignored"
    ignored_dir.mkdir(parents=True, exist_ok=True)
    planted = ignored_dir / "vendored.py"
    try:
        planted.write_text("x = 1\n", encoding="utf-8")
        assert (
            subprocess.run(  # noqa: S603
                ["git", "check-ignore", "-q", str(planted)],  # noqa: S607
                check=False,
                cwd=_REPO_ROOT,
            ).returncode
            == 0
        ), "fixture is not gitignored — the test would be vacuous"

        assert check_tag_t3._git_tracked_python_files(Path("build")) == []
    finally:
        planted.unlink(missing_ok=True)
        with contextlib.suppress(OSError):
            ignored_dir.rmdir()


def test_the_directory_scan_set_is_git_derived_not_a_traversal() -> None:
    """test-002: replaces an oracle that only pinned path FORM.

    The previous differential test compared against ``git ls-files`` output and
    so re-ran the implementation's own predicate; swapping the derivation for an
    absolute-path rglob left it green on any checkout without the vendored
    .venv — i.e. every CI runner. This pins the SET difference using a
    gitignored fixture, which exists on every machine.
    """
    ignored_dir = _REPO_ROOT / "build" / "synthetic-540-setdiff"
    ignored_dir.mkdir(parents=True, exist_ok=True)
    planted = ignored_dir / "traversal_only.py"
    try:
        planted.write_text("x = 1\n", encoding="utf-8")

        traversed = {p.resolve() for p in (_REPO_ROOT / "build").rglob("*.py")}
        assert planted.resolve() in traversed, "rglob cannot see the fixture — vacuous"

        # #541: was ``["src/alfred"]``, now a refused partial in-repo scan.
        collected = {p.resolve() for p in check_tag_t3._collect_paths([])}
        assert planted.resolve() not in collected
        # And the git-derived set for build/ is empty, where rglob finds one.
        assert check_tag_t3._git_tracked_python_files(Path("build")) == []
    finally:
        planted.unlink(missing_ok=True)
        with contextlib.suppress(OSError):
            ignored_dir.rmdir()


def test_a_directory_argument_with_dotdot_does_not_exempt_its_files() -> None:
    """test-001: the previous version of this test passed against unfixed code.

    `_collect_paths` normalises `tests/../src/alfred` via git before `_is_exempt`
    ever sees a path, so asserting over its output could not detect the bug.
    Call `_is_exempt` on the RAW traversal spelling directly instead.
    """
    raw = Path("tests/../src/alfred/orchestrator/core.py")

    assert raw.resolve().is_file(), "precondition: the traversal names a real file"
    assert check_tag_t3._is_exempt(raw) is False, "a `..` hop through tests/ exempted a src file"
    # Positive control: the same shape against a genuinely exempt file.
    assert (
        check_tag_t3._is_exempt(Path("tests/../tests/unit/security/test_t3_derived_data.py"))
        is True
    )


def test_a_relative_directory_argument_works_from_a_subdirectory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CodeRabbit: git runs with cwd=_REPO_ROOT, so the caller's spelling misresolves.

    From ``src/``, ``check_tag_t3.py alfred`` made ``git ls-files -- alfred``
    list 0 entries and the gate refused with "check whether it is gitignored"
    for a 293-file tree. Fails closed, but diagnoses the wrong fault.

    #541: ``["alfred"]`` alone is now a refused partial in-repo scan, so the
    second root is named the way a caller in ``src/`` would have to name it —
    ``../plugins``. That makes this a stronger test than it was: the root
    invariant compares RESOLVED paths, so it also proves a relative spelling
    from a subdirectory satisfies the coverage check rather than tripping it.
    """
    monkeypatch.chdir(_REPO_ROOT / "src")

    collected = check_tag_t3._collect_paths(["alfred", "../plugins"])

    assert len(collected) >= 250, f"a relative arg from a subdirectory collected {len(collected)}"
    assert all(p.is_absolute() for p in collected)


def test_a_nonexistent_scan_root_is_reported_as_such(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """ops-003: a missing directory fell through to the FILE branch.

    ``check_tag_t3.py src/alfred nosuchdir`` exited 1 with "file could not be
    read" — the code meaning "violations found", for a mistyped scan root.

    #541 ORACLE INDEPENDENCE: this argv is ALSO a partial in-repo directory
    scan, so an unqualified ``pytest.raises(EmptyScanRootError)`` would be
    satisfied by the root invariant firing after the missing-path branch was
    deleted. ``match=`` keeps it pinned to the branch it is about.
    """
    with pytest.raises(check_tag_t3.EmptyScanRootError, match="no such file or directory"):
        check_tag_t3._collect_paths(["src/alfred", "definitely-not-a-real-path"])

    assert check_tag_t3.main(["src/alfred", "definitely-not-a-real-path"]) == 2
    assert "no such file or directory" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# #541: the SCRIPT owns its scan roots. #537 widened the gate to
# `src/alfred plugins` by editing two invocation strings; dropping `plugins`
# from either was a one-word edit that stopped gating 39 first-party plugin
# files and the 250-file census could not see it (src/alfred alone is 293).
# ---------------------------------------------------------------------------


def test_the_default_scan_covers_every_required_root() -> None:
    """#541: the script — not the caller — decides what gets gated.

    Asserts the CONSTANT, without monkeypatching it — a monkeypatched constant
    is never a pin on that constant (#537). Several cases above DO monkeypatch
    ``_DEFAULT_SCAN_ROOTS`` to reach a branch; this is the one that does not,
    so narrowing the shipped tuple reds here whatever those do.
    """
    assert check_tag_t3._DEFAULT_SCAN_ROOTS == ("src/alfred", "plugins")


def test_the_default_scan_really_reaches_both_roots() -> None:
    """The constant is only worth pinning if it drives the real scan.

    Anti-vacuity companion to the case above: proves an argument-less run
    collects files from BOTH roots, rather than the constant being inert.
    """
    collected = check_tag_t3._collect_paths([])
    parts = {p.relative_to(check_tag_t3._REPO_ROOT).parts[0] for p in collected}

    assert {"src", "plugins"} <= parts, (
        f"an argument-less scan reached only {sorted(parts)} — the default "
        f"roots are not driving the scan"
    )
    assert len(collected) >= 300, f"expected the combined census, got {len(collected)}"


def test_a_partial_in_repo_directory_scan_is_refused_at_runtime() -> None:
    """The RUNTIME layer, independent of any call-site pin.

    The pin in ``tests/unit/meta/test_gate_surfaces_are_pinned.py`` is LEXICAL
    and review defeated it lexically: a backslash line-continuation split the
    argv across lines and slipped ``src/alfred`` through with ``plugins``
    dropped — measured against real ``make``, ``plugins/`` ungated, rc=0. This
    layer survives that, and survives every test in this repo being deleted.

    ``PartialScanRootError`` — not the base ``EmptyScanRootError``: "pointed at
    less than everything" is a different fault from "pointed at nothing", and
    sharing one type collapsed the base class's own regression oracle.
    """
    with pytest.raises(check_tag_t3.PartialScanRootError, match="does not cover every declared"):
        check_tag_t3._collect_paths(["src/alfred"])

    # The message must NAME the missing root; "a scan was refused" is not an
    # actionable diagnostic for a caller that thinks it passed everything.
    with pytest.raises(check_tag_t3.PartialScanRootError, match=r"missing \['src/alfred'\]"):
        check_tag_t3._collect_paths(["plugins"])

    # And through the exit contract: rc=2 ("the gate could not run"), not 1
    # ("violations found") and certainly not 0.
    assert check_tag_t3.main(["src/alfred"]) == 2


def test_an_out_of_repo_directory_fixture_is_exempt_from_the_root_invariant(
    tmp_path: Path,
) -> None:
    """Pins the NARROWING deliberately, so a future widening reds here.

    The invariant is scoped to IN-REPO directory arguments. Un-narrowing it to
    every directory argument was measured to red 11 pre-existing tests across
    two files — every ``tmp_path`` tree the suite plants and scans, none of
    which says anything about production, which only ever scans in-repo paths.
    """
    fixture = tmp_path / "tree"
    fixture.mkdir()
    (fixture / "ordinary.py").write_text("x = 1\n", encoding="utf-8")

    assert check_tag_t3._collect_paths([str(fixture)]) == [fixture / "ordinary.py"]


def test_the_file_argument_residual_is_not_closed_by_this_layer() -> None:
    """CHARACTERISATION of a MEASURED residual — read the docstring, not the name.

    The module docstring must not claim "no invocation can gate a subset",
    because an invocation that enumerates explicit FILE paths still can:
    passing the 293 tracked ``src/alfred/**.py`` files individually exits 0
    with ``plugins`` never scanned. Extending the invariant to cover it would
    have to refuse in-repo file arguments outright, which is the single-file
    developer invocation and the shape three pre-existing tests use.

    What closes it instead is the call-site pin in
    ``tests/unit/meta/test_gate_surfaces_are_pinned.py``, which requires every
    invocation site to pass NO arguments at all — so the enumeration cannot be
    written at a call site in the first place. This test exists so that the
    residual is a recorded fact rather than an assumption: if someone closes
    it at this layer, this reds and they delete it deliberately.
    """
    tracked = subprocess.run(
        ["git", "ls-files", "--", "src/alfred"],  # noqa: S607
        capture_output=True,
        text=True,
        check=True,
        cwd=_REPO_ROOT,
    ).stdout.splitlines()
    src_files = [line for line in tracked if line.endswith(".py")]
    assert len(src_files) >= 250, "precondition: the enumeration must be the real tree"

    collected = check_tag_t3._collect_paths(src_files)

    # Top-level component only: `src/alfred/plugins/` is a DIFFERENT tree from
    # the `plugins/` scan root, and a substring test would confuse the two.
    assert {p.parts[0] for p in collected} == {"src"}, (
        "a file enumeration reached the top-level plugins/ root — the residual "
        "this documents is closed, so delete this test and correct the docstring"
    )
    assert check_tag_t3.main(src_files) == 0, (
        "the enumeration no longer exits 0 — the residual is closed at this "
        "layer, so delete this test and correct the module docstring"
    )


# ---------------------------------------------------------------------------
# #542: `ast.parse` raises MORE than SyntaxError. Uncaught, the exception
# escaped `_scan_text`, escaped `main`, killed the process with a traceback
# (exit 1 — the code that means "violations found" — for a file that was never
# scanned) and ABORTED THE SCAN LOOP, so every later file went unscanned with
# nothing reported.
# ---------------------------------------------------------------------------

# REAL pathological input, never a mocked exception.
#
# WHICH exception `ast.parse` raises depends on the interpreter BUILD, not just
# the source. Measured on two CPython 3.14.6 builds:
#
#   * `"not " * 20000`  -> MemoryError("Parser stack overflowed") on BOTH.
#   * a 50 000-operand `+` chain -> RecursionError("Stack overflow (used
#     8144 kB) during compilation") on the uv/proto standalone build, and
#     PARSES CLEANLY on a Homebrew build of the identical version.
#
# CPython 3.14's stack guard trips on actual C-stack bytes consumed, not on
# sys.setrecursionlimit. CI provisions Python with `uv python install 3.14`
# (the standalone family), so RecursionError is live in CI even though a dev
# box may never see it.
#
# Hence: assert the PROPERTY (nothing escapes `_scan_text`) across several
# shapes rather than a specific exception type, which would make the suite
# pass or fail on which python built the venv.
_PATHOLOGICAL_SOURCES: tuple[tuple[str, str], ...] = (
    ("unary-not-chain", "not " * 20000 + "x\n"),
    ("unary-minus-chain", "-" * 20000 + "x\n"),
    ("binop-chain", "x = " + "+".join(["1"] * 50000) + "\n"),
    ("attribute-chain", "x = a" + ".b" * 50000 + "\n"),
)

# The one shape that behaved identically on every build measured, so it can
# carry the assertions that need a guaranteed trip.
_ALWAYS_UNSCANNABLE: str = "not " * 20000 + "x\n"


def test_the_portable_pathological_source_defeats_the_syntaxerror_arm() -> None:
    """Anti-vacuity premise for the cases below.

    If a future CPython turned this into a SyntaxError, the existing arm
    would handle it and the regressions below would pass for the wrong
    reason. Assert the premise directly.
    """
    with pytest.raises(MemoryError):
        ast.parse(_ALWAYS_UNSCANNABLE)


@pytest.mark.parametrize(
    "source",
    [pytest.param(source, id=label) for label, source in _PATHOLOGICAL_SOURCES],
)
def test_no_pathological_source_escapes_the_scanner(source: str) -> None:
    """`_scan_text` must never raise, whatever the parser does with the input.

    Build-agnostic by construction: a shape that parses cleanly on this
    interpreter returns [] and still satisfies "did not raise". The floor
    below guarantees the set is not ALL clean.
    """
    check_tag_t3._scan_text(source, Path("src/alfred/pathological.py"))


def test_at_least_one_pathological_source_actually_trips_the_arm() -> None:
    """Anti-vacuity floor for the parametrised case above.

    Without this, an interpreter that parsed every shape cleanly would make
    the whole set pass while exercising nothing — the paper-gate shape, in
    the tests that exist to close it.

    The message constant is read INSIDE the comprehension deliberately: the
    outer `_scan_text` call is evaluated first, so on the unfixed script this
    case reds with the real defect (the escaping parser exception) rather than
    with an AttributeError for a constant that does not exist yet. It cannot go
    vacuous either way — an absent constant raises as soon as any shape yields
    a violation, and a set of shapes that yields none reds on `assert tripped`.
    """
    tripped = [
        label
        for label, source in _PATHOLOGICAL_SOURCES
        if any(
            check_tag_t3._UNSCANNABLE_MESSAGE in line
            for line in check_tag_t3._scan_text(source, Path("src/alfred/p.py"))
        )
    ]
    assert tripped, (
        "no pathological shape reached the unscannable arm on this interpreter "
        "— the parametrised case above is vacuous here"
    )


def test_a_pathological_file_does_not_abort_the_scan_of_later_files(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The substantive #542 defect: later files go unscanned, silently.

    `main` sorts its paths, so `aaa_` is scanned first. Before the fix the
    MemoryError aborted the loop and the real violation in `zzz_` was never
    found — the gate would report a clean tree for a file that launders T3.

    Explicit FILE arguments: they are exempt from the `_MIN_SCANNED_FILES`
    census (directory scans only), and neither fixture may be named
    `test_*.py` or the out-of-repo exemption would make both vacuously clean.
    """
    bad = tmp_path / "aaa_pathological.py"
    bad.write_text(_ALWAYS_UNSCANNABLE, encoding="utf-8")
    later = tmp_path / "zzz_violation.py"
    later.write_text("tag(T3, payload)\n", encoding="utf-8")

    rc = check_tag_t3.main([str(bad), str(later)])

    err = capsys.readouterr().err
    assert rc == 1, "an unscannable file plus a real violation must fail the gate"
    assert check_tag_t3._UNSCANNABLE_MESSAGE in err, "the unscannable file was not reported"
    assert check_tag_t3._TAG_T3_MESSAGE in err, (
        "the violation in the LATER file was missed — the scan loop aborted, "
        "which is the paper-gate shape #542 exists to close"
    )


def test_a_violation_survives_a_scan_failure_in_the_same_file(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A collection failure must not DISCARD findings already collected.

    Widening the try-scope means an exception can fire AFTER the AST walk has
    found real violations. Replacing them with a bare "unscannable" message
    would downgrade a T3-laundering finding into a vague one — so the arm
    appends rather than replaces.

    **This pins an ORDERING property, and injects the fault at the seam.** A
    mock is the right instrument HERE SPECIFICALLY, and nowhere else in this
    section: the real-input cases above already prove the arm fires, so nothing
    is being stood in for. What no input can express is firing it *after* the
    walk has collected findings, because every reachable pathological shape
    fails inside `ast.parse` — before `ast.walk` has run and before a single
    violation exists to discard. A fixture-based version of this test could
    therefore only ever assert the property it cannot reach.

    An earlier draft did exactly that and **could never pass**:
    `_TYPE_IGNORE_PATTERN` requires a literal `TaggedContent` on the line and
    the fixture had none, so the test was red before its mutation as well as
    after, and the mutation meant to guard this property reported a kill while
    proving nothing.
    """

    class _Exploding:
        """Stands in for `_TYPE_IGNORE_PATTERN` — the LAST step of the scan."""

        def search(self, line: str) -> object:
            raise RecursionError(f"injected post-walk fault on {line!r}")

    monkeypatch.setattr(check_tag_t3, "_TYPE_IGNORE_PATTERN", _Exploding())
    violations = check_tag_t3._scan_text("tag(T3, payload)\n", Path("src/alfred/mixed.py"))

    assert any(check_tag_t3._TAG_T3_MESSAGE in line for line in violations), (
        "the tag(T3, ...) finding collected BEFORE the fault was discarded — "
        "the arm replaced rather than appended, downgrading a T3-laundering "
        "finding into a vague 'unscannable' one"
    )
    assert any(check_tag_t3._UNSCANNABLE_MESSAGE in line for line in violations), (
        "the scan failure itself was not reported"
    )


def test_a_nul_byte_path_is_reported_not_raised(tmp_path: Path) -> None:
    """Twin gap: `read_text` raises ValueError, not OSError, on an embedded NUL.

    `_is_exempt` already catches ValueError for exactly this cause and says
    so, but `_scan_file`'s read arm caught only UnicodeDecodeError and
    OSError — the same input handled by one function escaped the next.
    """
    violations = check_tag_t3._scan_file(tmp_path / "nul\x00name.py")
    assert violations, "an unreadable path must be reported, not silently clean"
    assert check_tag_t3._UNSCANNABLE_MESSAGE in violations[0]
