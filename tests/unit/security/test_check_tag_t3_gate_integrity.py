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


def test_a_directory_argument_cannot_poison_the_files_beneath_it() -> None:
    """The traversal's real blast radius: one arg exempts a whole subtree.

    `_is_exempt` was called per-file with the raw prefix still attached, so
    `check_tag_t3.py tests/../src/alfred` exempted all 293 files at once.
    """
    poisoned = check_tag_t3._collect_paths(["tests/../src/alfred"])

    assert poisoned, "precondition: the traversal path still collects files"
    assert not all(check_tag_t3._is_exempt(p) for p in poisoned), (
        "every file under the traversed directory was exempt"
    )


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
        try:
            link_dir.rmdir()
            link_dir.parent.rmdir()
        except OSError:
            pass


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
    """
    expected = {
        _REPO_ROOT / line
        for line in subprocess.run(
            ["git", "ls-files", "--", "src/alfred"],  # noqa: S607
            capture_output=True,
            text=True,
            check=True,
            cwd=_REPO_ROOT,
        ).stdout.splitlines()
        if line.endswith(".py")
    }

    assert set(check_tag_t3._collect_paths(["src/alfred"])) == expected
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
    """
    ignored_dir = _REPO_ROOT / "build" / "synthetic-537-empty"
    ignored_dir.mkdir(parents=True, exist_ok=True)
    try:
        with pytest.raises(check_tag_t3.EmptyScanRootError):
            check_tag_t3._collect_paths(["build"])
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
    """
    monkeypatch.setattr(check_tag_t3, "_MIN_SCANNED_FILES", 100_000)

    rc = check_tag_t3.main(["src/alfred"])

    assert rc == 2
    err = capsys.readouterr().err
    assert "expected at least" in err


def test_the_configured_census_floor_actually_rejects_a_small_scan(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Pins the REAL ``_MIN_SCANNED_FILES`` value, not a monkeypatched one.

    ``test_main_refuses_a_directory_scan_that_is_implausibly_small`` patches the
    constant, so it proves the census MECHANISM works while saying nothing
    about the shipped value — measured: setting the real constant to 0 left
    that test green, which would disable the census in production silently.

    ``scripts/`` holds a handful of tracked ``.py`` files, comfortably under any
    sane floor, so this reds if the constant is ever lowered to nothing.
    """
    assert check_tag_t3.main(["scripts"]) == 2
    assert "expected at least" in capsys.readouterr().err


def test_main_returns_zero_on_the_real_tree() -> None:
    """Positive twin: the census must not red the real invocation."""
    assert check_tag_t3.main(["src/alfred"]) == 0


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
    """The fallback arm for an in-repo directory when git cannot answer."""
    monkeypatch.setattr(check_tag_t3, "_git_tracked_python_files", lambda _d: None)

    collected = check_tag_t3._collect_paths(["scripts"])

    assert collected, "the rglob fallback found nothing"
    assert any(p.name == "check_tag_t3.py" for p in collected)
