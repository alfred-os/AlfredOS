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
import itertools
import os
import re
import subprocess
import sys
import threading
from collections.abc import Callable
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


@pytest.fixture(autouse=True)
def _pin_cwd_to_repo_root(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pin the CWD for EVERY test in this module (#548 review, test-001/test-003).

    ``_collect_paths`` resolves ``_DEFAULT_SCAN_ROOTS`` and every relative
    argument against the AMBIENT working directory, and this suite passes
    repo-relative paths throughout — ``_collect_paths([])``, ``_is_exempt(
    Path("src/alfred/..."))``, ``_collect_paths(["src/alfred"])``. Run pytest
    from anywhere but the repository root and those tests red for a reason
    unrelated to the property each one characterises: measured from ``src/``,
    **18 of 63 failed**, several on the wrong exception type
    (``EmptyScanRootError`` where the test pins ``PartialScanRootError``).

    AUTOUSE rather than a parameter on the three sites review named, because 18
    is not 3 and the next repo-relative test would join them silently. Tests
    that need a different directory still call ``monkeypatch.chdir`` in their
    own body — the fixture runs first, so their choice wins, and ``monkeypatch``
    restores in reverse order at teardown.
    """
    monkeypatch.chdir(_REPO_ROOT)


def test_the_cwd_pin_is_autouse() -> None:
    """Disarming the fixture must RED, not silently restore 18 fragile tests.

    Asserting ``Path.cwd() == _REPO_ROOT`` instead would be vacuous exactly
    where it matters: CI runs pytest from the repository root, so it passes
    whether or not the fixture exists. This asserts the MECHANISM — deleting
    the fixture is a NameError at collection, and dropping ``autouse=True``
    reds here.
    """
    marker = _pin_cwd_to_repo_root._fixture_function_marker
    assert marker.autouse is True, (
        "the CWD pin is no longer autouse — every repo-relative test in this "
        "module silently depends on pytest's working directory again"
    )


# THE collection-failure messages — the ones that mean "this file was not
# gated". Read EAGERLY, at import: an absent constant fails collection of the
# whole module, which is louder than the AttributeError the previous
# per-test tuple relied on.
#
# ONE tuple, two readers (#543 review, err-002). It used to be written out
# twice, the second copy listed three of four, and the comment above the first
# claimed both listed all four — so a regression that spuriously reported an
# ordinary file as `_UNREADABLE` passed the site named as its backstop.
# `test_every_collection_failure_message_is_enumerated` keeps the tuple honest
# against the module rather than against this comment.
_COLLECTION_FAILURE_MESSAGES: tuple[str, ...] = (
    check_tag_t3._UNPARSEABLE_MESSAGE,
    check_tag_t3._UNREADABLE_MESSAGE,
    check_tag_t3._UNDECODABLE_MESSAGE,
    check_tag_t3._UNSCANNABLE_MESSAGE,
    check_tag_t3._UNSCANNABLE_PATH_MESSAGE,
)


def test_every_collection_failure_message_is_enumerated() -> None:
    """DEFAULT-DENY the enumeration: derive the set, do not restate it.

    An enumeration only closes what it enumerates (#518). Both readers of
    `_COLLECTION_FAILURE_MESSAGES` are floors that assert a message is ABSENT,
    so a message missing from the tuple is invisible to both — the exact shape
    err-002 found live. Deriving the expected set from the module's own
    `_*_MESSAGE` constants means a SIXTH message reds here on the day it lands
    instead of quietly widening the blind spot.

    Scope, since #546 added a sibling naming class (#549 review, rev-002): the
    derivation keys on the `_MESSAGE` suffix, so `_NOT_A_REGULAR_FILE_REASON`
    is deliberately outside it — a REASON is the second line under a message,
    not a sixth message. Anything that is genuinely a new collection-failure
    MESSAGE must carry the `_MESSAGE` suffix to be seen here; naming one
    `_REASON` to dodge this test would defeat it silently.

    The two exclusions are named, not pattern-matched: `_TAG_T3_MESSAGE`,
    `_CAST_TAGGED_CONTENT_MESSAGE`, `_TAGGED_CONTENT_T3_SUBSCRIPT_MESSAGE` and
    `_TYPE_IGNORE_MESSAGE` are FINDINGS (the file was gated and failed), and
    `_GATE_INTERNAL_MESSAGE` says the GATE is broken — it never reaches a
    violation list at all, it travels on `GateInternalError` to exit 2.
    """
    findings = {
        check_tag_t3._TAG_T3_MESSAGE,
        check_tag_t3._CAST_TAGGED_CONTENT_MESSAGE,
        check_tag_t3._TAGGED_CONTENT_T3_SUBSCRIPT_MESSAGE,
        check_tag_t3._TYPE_IGNORE_MESSAGE,
        check_tag_t3._GATE_INTERNAL_MESSAGE,
        # #538 sole-layer rules. FINDINGS, not collection failures: each means the
        # file WAS gated and failed, so neither reader of
        # _COLLECTION_FAILURE_MESSAGES should see them.
        check_tag_t3._RAW_VEHICLE_ATTR_MESSAGE,
        check_tag_t3._RAW_VEHICLE_VARS_MESSAGE,
        check_tag_t3._RAW_VEHICLE_STR_MESSAGE,
        check_tag_t3._RAW_SETATTR_SHAPE_MESSAGE,
        check_tag_t3._RAW_SETATTR_ALIASED_MESSAGE,
        check_tag_t3._RAW_CLASS_SWAP_MESSAGE,
        check_tag_t3._RAW_CARRIER_MESSAGE,
        check_tag_t3._BASEMODEL_VALUE_MESSAGE,
        check_tag_t3._ALIAS_BUDGET_MESSAGE,
        check_tag_t3._PRIVATE_SURFACE_MESSAGE,
        # PR #553 security review. F1 added the bare-identifier carrier for the
        # vehicle-NAME set; F3 added the pair that closes `__init__` re-entry, shaped
        # like the `__setattr__` pair above (a call rule plus a one-position whitelist).
        check_tag_t3._RAW_VEHICLE_NAME_MESSAGE,
        check_tag_t3._RAW_INIT_SHAPE_MESSAGE,
        check_tag_t3._RAW_INIT_ALIASED_MESSAGE,
        # C1 completed the family: `__delattr__` had the folded-string treatment but
        # neither of the two rules its siblings got, so `object.__delattr__(low, "tier")`
        # and its aliased form both scanned clean.
        check_tag_t3._RAW_DELATTR_SHAPE_MESSAGE,
        check_tag_t3._RAW_DELATTR_ALIASED_MESSAGE,
        # #539's four construction rules. FINDINGS on the same terms as every entry
        # above: each means the file WAS gated and a T3-construction shape was written
        # in it. They arrive here automatically because the derivation below keys on the
        # `_MESSAGE` suffix — which is the property this test exists to have, and the
        # reason all four had to be classified rather than silently widening the two
        # message-is-ABSENT floors that read the complement.
        check_tag_t3._TAGGED_CONTENT_UNRESOLVED_SLICE_MESSAGE,
        check_tag_t3._UNPARAMETERISED_CONSTRUCTION_MESSAGE,
        check_tag_t3._TAGGED_SEAM_MESSAGE,
        check_tag_t3._TIER_MUTATING_COPY_MESSAGE,
    }
    declared = {
        value
        for name, value in vars(check_tag_t3).items()
        if name.endswith("_MESSAGE") and isinstance(value, str)
    }

    assert declared - findings == set(_COLLECTION_FAILURE_MESSAGES), (
        f"the module declares collection-failure messages this tuple does not "
        f"enumerate: {sorted(declared - findings - set(_COLLECTION_FAILURE_MESSAGES))}. "
        f"Every floor that asserts one is ABSENT is blind to it until it is added."
    )
    # CONTAINMENT, not equality (#548 review, test-002). Both readers match with
    # `message in violation`, so a message that is a strict SUBSTRING of a
    # sibling is satisfied by that sibling firing — two distinct strings, an
    # equality check still green, and the floors mutually satisfiable. The
    # near miss is live: `_UNSCANNABLE_MESSAGE` and `_UNSCANNABLE_PATH_MESSAGE`
    # share a prefix and neither contains the other. `permutations` subsumes
    # the equality case, because a duplicate is contained in its twin.
    overlapping = [
        (shorter, longer)
        for shorter, longer in itertools.permutations(_COLLECTION_FAILURE_MESSAGES, 2)
        if shorter in longer
    ]
    assert not overlapping, (
        f"a collection-failure message is contained in another: {overlapping} — "
        f"both readers match by substring, so a test for the shorter one would "
        f"be satisfied by the longer one firing"
    )
    # THE SAME PROPERTY OVER EVERY MESSAGE, not just the collection-failure five.
    # Most rule tests assert `MESSAGE in violation` too, so a finding message that is
    # a substring of a sibling makes those tests mutually satisfiable — a rule could
    # be deleted and its test would still pass on the longer sibling firing. Derived
    # from `declared` so it covers messages nobody thought to enumerate.
    shadowed = [
        (shorter, longer)
        for shorter, longer in itertools.permutations(sorted(declared), 2)
        if shorter in longer
    ]
    assert not shadowed, (
        f"a gate message is contained in another: {shadowed} — every test that "
        f"matches by substring is then satisfiable by the wrong rule firing"
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
    # test-005, SECOND site. The plan named only the zero-false-positive floor
    # below; this enumeration is the other place a collection-failure message
    # can hide. A reviewer injected the fourth-message regression and this twin
    # SURVIVED — an ordinary file reported as unscannable would have gone
    # unnoticed here. Every enumeration of the collection-failure messages has
    # to move together or the set of them is only as complete as its shortest
    # copy.
    #
    # #543 review (err-002): the floor below carried a comment claiming "both
    # must list all four" while THIS site listed three — `_UNREADABLE_MESSAGE`
    # was never checked here, before or after the PR that wrote the comment.
    # Measured: injecting a spurious `_UNREADABLE_MESSAGE` into `_scan_file`'s
    # output for an ordinary readable file left this test green. Derived from
    # the shared tuple now, so the two sites cannot drift again — and the
    # tuple's own completeness is what `test_every_collection_failure_message_
    # is_enumerated` asserts against the module.
    for message in _COLLECTION_FAILURE_MESSAGES:
        assert not any(message in v for v in violations), (
            f"an ordinary file was reported with {message!r}"
        )


def test_the_real_scan_root_has_no_unreadable_or_unparseable_files(tmp_path: Path) -> None:
    """Non-vacuity floor: this change must cost zero false positives.

    Measured at plan time: 0 unparseable, 0 unreadable across 293 files;
    re-measured after #541 across the 332 files of BOTH declared roots, and
    again after #542 added the fourth message (0 unscannable).

    The tuple ENUMERATES the collection-failure messages, so a message missing
    from it is invisible to this floor (test-005): a real file that started
    failing that way would leave the floor green. #543 review (err-002): the
    two enumeration sites are now ONE shared tuple
    (``_COLLECTION_FAILURE_MESSAGES``) read by both this floor and
    ``test_a_real_utf8_file_still_scans_normally``, because the previous
    comment here claimed both listed all four while the other listed three.
    ``test_every_collection_failure_message_is_enumerated`` derives the set
    from the module so the tuple cannot fall behind a new message either.

    #541: was ``_collect_paths(["src/alfred"])``. A partial in-repo directory
    scan is now refused at runtime, so this asserts over the production
    argument-less shape — which is also the wider tree, so the floor got
    stronger rather than weaker.

    THREE separate anti-vacuity devices, because the obvious form of this test
    is green on a detector that does nothing:

    1. The message constants are read EAGERLY — at MODULE IMPORT, into
       ``_COLLECTION_FAILURE_MESSAGES``. Referenced only inside the
       comprehension's ``if`` clause they are never evaluated on a clean tree —
       measured: this floor passed while the constants did not exist at all.
       Since #543 moved the tuple to module scope an absent constant fails
       COLLECTION of this whole module, which is louder than the
       ``AttributeError`` the previous per-test tuple raised (#548 review,
       doc-001: the prose here still described the per-test form).
    2. A census assertion, so a floor that scanned nothing cannot pass.
    3. A positive control planted in ``tmp_path`` and scanned by the SAME
       predicate, proving the filter can actually distinguish.
    """
    # Device 1 — the eager read lives at module scope now, so this is a plain
    # rebind and cannot itself raise. The device is STRONGER there: an absent
    # constant fails collection of the module rather than one test.
    collection_failures = _COLLECTION_FAILURE_MESSAGES

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


@_NEEDS_SYMLINKS
def test_a_symlink_to_a_regular_file_is_scanned_not_refused(tmp_path: Path) -> None:
    """The non-regular-file guard must FOLLOW symlinks (#549 review, sec-004).

    `stat()` follows; `lstat()` does not, and a symlink's own `st_mode` is
    `S_IFLNK`, never `S_IFREG`. So `path.lstat()` would refuse every symlinked
    source file as "not a regular file" — reporting it unreadable instead of
    reading its contents, and silently un-gating whatever it points at.

    That mutant SURVIVED all 68 tests in this file. The existing symlink cases
    assert only that `_scan_file(link)` returns SOMETHING truthy, which a
    refusal message satisfies just as well as a finding does — so nothing
    distinguished "scanned the target" from "declined to open the link". This
    repo has fought the symlink surface repeatedly (#537 bypass 3, #540), and
    under `lstat` the gate would exit 1 on a symlinked violation for the wrong
    reason, inviting a maintainer to "fix" it with an exemption.

    Asserts the T3 FINDING specifically, and asserts no collection-failure
    message is present — the two halves are what make it a scan rather than a
    refusal.
    """
    target = tmp_path / "real_source.py"
    target.write_text(
        "from alfred.security.tiers import tag, T3\nx = tag(T3, 'laundered')\n", encoding="utf-8"
    )
    link = tmp_path / "via_link.py"
    link.symlink_to(target)

    violations = check_tag_t3._scan_file(link)

    assert any(check_tag_t3._TAG_T3_MESSAGE in v for v in violations), (
        f"the symlink's TARGET was never scanned — the guard is not following "
        f"symlinks, so a symlinked source file is refused rather than gated; "
        f"got {violations}"
    )
    assert not any(msg in v for v in violations for msg in _COLLECTION_FAILURE_MESSAGES), (
        f"the link was reported as unreadable instead of scanned; got {violations}"
    )


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
            encoding="utf-8",
            errors="surrogateescape",
            check=True,
            cwd=_REPO_ROOT,
        ).stdout.splitlines()
        if line.endswith(".py")
    }

    # PRECONDITION, asserted rather than assumed (#548 review, test-004).
    # `_collect_paths` derives its set from `git ls-files --cached --others
    # --exclude-standard`, so it includes UNTRACKED files by design; this oracle
    # lists the INDEX only. The equality below is therefore a clean-tree
    # statement, and two ordinary situations break it without a defect: a
    # developer's scratch `.py` under either root, and
    # `test_an_untracked_new_file_is_still_scanned`, which plants
    # `src/alfred/zz_540_untracked_probe.py` and is visible here under parallel
    # execution. Adding `--others` to the oracle is the WRONG repair — it would
    # re-run the implementation's own predicate and collapse the independence
    # the docstring above exists to protect. State the precondition instead, so
    # the test diagnoses itself rather than reporting an opaque set difference.
    untracked_query = [
        "git",
        "ls-files",
        "--others",
        "--exclude-standard",
        "--",
        "src/alfred",
        "plugins",
    ]
    untracked = [
        line
        for line in subprocess.run(  # noqa: S603
            untracked_query,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="surrogateescape",
            check=True,
            cwd=_REPO_ROOT,
        ).stdout.splitlines()
        if line.endswith(".py")
    ]
    assert not untracked, (
        f"untracked .py files under the scan roots make this equality oracle "
        f"inapplicable — it lists the index, `_collect_paths` does not: {untracked}"
    )

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
    """The OSError arm of _scan_file, reached via a directory.

    It used to reach that arm by letting `read_text` raise `IsADirectoryError`.
    Since #546 the `S_ISREG` guard refuses the directory FIRST and raises into
    the same arm, so the arm and the message are unchanged but the route is
    not — keeping the old wording would describe a path the code no longer
    takes (#549 review, doc-002).
    """
    a_directory = tmp_path / "not_a_file.py"
    a_directory.mkdir()

    violations = check_tag_t3._scan_file(a_directory)

    assert violations
    assert check_tag_t3._UNREADABLE_MESSAGE in violations[0]


def _make_fifo(path: Path) -> None:
    """Create a FIFO at ``path`` — the shape that BLOCKS an unguarded reader."""
    os.mkfifo(path)


def _make_directory(path: Path) -> None:
    """Create a directory at ``path`` — non-regular, but it does not block.

    The second half of the class test. A FIFO alone cannot distinguish
    default-denying every non-regular file from closing the one shape #546
    named; a directory reaches the same guard by a different route.
    """
    path.mkdir()


def _scan_file_within_deadline(path: Path, timeout: float = 10.0) -> list[str]:
    """``_scan_file(path)``, but FAIL on a hang instead of reproducing it (#546).

    Every caller feeds this a path that blocks forever when the guard is
    absent, so a direct call does not fail the test — it hangs pytest. That is
    not hypothetical: mutation-testing the guard by DELETING it hung the suite
    until the harness killed it at five minutes, because one of these cases
    was still calling ``_scan_file`` directly. A test that converts a bug into
    a stalled CI job is worse than no test.

    The worker is ``daemon=True`` so a thread left blocked in ``open()`` never
    holds interpreter exit, and the deadline is generous relative to the work
    (a real scan of one file is sub-millisecond) so it cannot flake on a
    loaded runner.

    A worker that RAISES is reported WITH its exception (#549 review, test-003).
    The first version asserted only that ``result`` was non-empty, so a
    ``_scan_file`` that raised failed with a message naming nothing and the
    actual cause was lost — a diagnosis gap in the helper every other case here
    depends on.
    """
    result: list[list[str]] = []
    failure: list[BaseException] = []

    def _run() -> None:
        """Run the scan, capturing EITHER outcome for the main thread.

        Catches ``Exception``, not ``BaseException``. The point is to surface a
        BUG in ``_scan_file`` — which is an ``Exception`` — rather than let it
        vanish into ``threading.excepthook`` and fail with a message naming
        nothing. Widening to ``BaseException`` would additionally swallow
        ``KeyboardInterrupt`` and ``SystemExit`` in the worker, which is the
        exact behaviour ``_scan_file`` itself deliberately refuses (see its
        ``except Exception`` arm), and CodeQL flags it as py/catch-base-exception.
        """
        try:
            result.append(check_tag_t3._scan_file(path))
        except Exception as exc:  # surfaced on the main thread below
            failure.append(exc)

    worker = threading.Thread(target=_run, daemon=True)
    worker.start()
    worker.join(timeout)

    assert not worker.is_alive(), (
        f"_scan_file blocked on {path.name} — the gate hangs until its CI job "
        f"timeout and reports nothing"
    )
    if failure:
        raise AssertionError(f"_scan_file raised on {path.name}: {failure[0]!r}") from failure[0]
    assert result, "the worker neither returned nor raised"
    return result[0]


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX-only: os.mkfifo")
@pytest.mark.parametrize(
    ("make", "kind"),
    [(_make_fifo, "fifo"), (_make_directory, "directory")],
    ids=["fifo", "directory"],
)
def test_every_non_regular_file_is_refused_on_the_same_grounds(
    tmp_path: Path, make: Callable[[Path], None], kind: str
) -> None:
    """#546: the guard default-denies the CLASS, not the shape that was reported.

    This is the mutation the FIFO test alone cannot kill. Narrowing the guard
    to ``if stat.S_ISFIFO(...)`` — closing only the shape #546 named — leaves
    ``test_a_fifo_named_py_does_not_hang_the_gate`` green, because the FIFO is
    still refused. The directory then falls through to ``read_text`` and is
    reported by the OS as ``Is a directory``, so the REASON is what separates
    default-deny from enumerate-and-hope; the message alone does not (both
    arrive as ``_UNREADABLE_MESSAGE``). Measured: that mutation survives every
    other test in this file.

    Asserting the shared reason is not a tautological oracle — the test never
    re-states the ``S_ISREG`` predicate, it asserts that two unrelated
    non-regular types reach one verdict for one stated cause (#518).
    """
    target = tmp_path / f"{kind}.py"
    make(target)

    violations = _scan_file_within_deadline(target)

    assert violations, f"a {kind} named *.py must be reported, not silently clean"
    assert check_tag_t3._UNREADABLE_MESSAGE in violations[0]
    assert check_tag_t3._NOT_A_REGULAR_FILE_REASON in violations[1], (
        f"the {kind} was refused for some OTHER reason ({violations[1]!r}) — the "
        f"guard is enumerating shapes rather than requiring a regular file"
    )


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX-only: os.mkfifo")
def test_a_fifo_named_py_does_not_hang_the_gate(tmp_path: Path) -> None:
    """#546: `read_text` on a FIFO blocks FOREVER — the gate never returns.

    ``open()`` on a FIFO for reading blocks until a writer arrives, and nothing
    in the gate ever writes. Measured against the pre-fix script on both of the
    two ways a FIFO reaches ``_scan_file``: an explicit ``check_tag_t3.py
    hang.py`` argument, and the ``rglob`` traversal fallback (git unavailable /
    out-of-repo directory) sized past the 250-file census floor. Both timed out
    at exit 124 rather than reporting anything. CI would burn its whole job
    timeout and report no diagnosis at all.

    The assertion is bounded by ``_scan_file_within_deadline`` rather than a
    direct call — see that helper for why the un-bounded form is actively
    harmful.

    The git-derived collection path is unaffected (a FIFO is not a tracked
    file, and ``_git_tracked_python_files`` already filters on ``is_file()``) —
    the fix belongs in ``_scan_file`` because that is where BOTH remaining
    paths converge.
    """
    fifo = tmp_path / "hang.py"
    os.mkfifo(fifo)

    violations = _scan_file_within_deadline(fifo)

    assert violations, "a path the gate cannot read must be reported, not silently clean"
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
    """The T3 / quoted-"T3" / benign / unresolvable slice branches.

    THE NON-CONSTANT SLICE CHANGED SIDES IN #539, and that inversion is the point of the
    issue rather than a regression in this test. `TaggedContent[1](x)` used to be asserted
    CLEAN here, which recorded the rule's fail-OPEN posture: the old predicate asked "is
    this slice the name `T3`?" and answered "no" for every shape that was not a `Name` or a
    `"T3"` string — including `"T" + "3"`, `globals()["T3"]`, `TIERS["T3"]`,
    `T3 if x else T2` and `(T3,)`, each of which reaches a real T3 construction. A
    two-valued verdict cannot say "I could not read this", so the quiet answer and the safe
    answer were the same answer, and it was the quiet one.

    `_slice_verdict` is now total over `ast.expr` and default-denies on SHAPE, so an
    unreadable slice reports its own distinct message. `1` is not a tier this gate can
    resolve, so it reds — deliberately, and with the message that says why.
    """
    label = tmp_path / "slices.py"
    msg = check_tag_t3._TAGGED_CONTENT_T3_SUBSCRIPT_MESSAGE
    unresolved = check_tag_t3._TAGGED_CONTENT_UNRESOLVED_SLICE_MESSAGE

    assert any(msg in v for v in check_tag_t3._scan_text("TaggedContent[T3](x)\n", label))
    assert any(msg in v for v in check_tag_t3._scan_text('TaggedContent["T3"](x)\n', label))
    # Benign tier and a non-T3 string must NOT trip.
    assert check_tag_t3._scan_text("TaggedContent[T2](x)\n", label) == []
    assert check_tag_t3._scan_text('TaggedContent["T2"](x)\n', label) == []
    # An unreadable slice reds under the UNRESOLVED rule, never under the T3 one — the
    # messages are distinct so a shape test cannot be satisfied by the wrong rule firing.
    unreadable = check_tag_t3._scan_text("TaggedContent[1](x)\n", label)
    assert any(unresolved in v for v in unreadable)
    assert not any(msg in v for v in unreadable)
    # A foreign generic is not this gate's business at all.
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
    # #543 review (test-002): this was `>= 300` against a measured 332 — a
    # 7-file margin over `src/alfred` alone (293), i.e. the identical eroding
    # margin this PR WITHDREW the `_MIN_SCANNED_FILES` 250->300 raise for,
    # reproduced inside the test written to replace it. `src/alfred` grew +19
    # files in 23 days, so it would have stopped discriminating within weeks.
    #
    # Margin-free replacement: every declared root must contribute at least
    # one file. That is the property `>= 300` was proxying for, it cannot be
    # overtaken by growth in either root, and it is strictly stronger — a
    # `plugins`-shaped root that emptied would red here and would NOT have red
    # at 300 once `src/alfred` passed it on its own.
    for root in check_tag_t3._DEFAULT_SCAN_ROOTS:
        contributed = [p for p in collected if p.is_relative_to(check_tag_t3._REPO_ROOT / root)]
        assert contributed, (
            f"the argument-less scan collected {len(collected)} files and NONE "
            f"from {root!r} — that root is declared but contributes nothing"
        )


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
        encoding="utf-8",
        errors="surrogateescape",
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
#
# DERIVED from the tuple, not restated (#548 review, test-005). Three tests
# depend on the two staying identical — one asserts the PREMISE for this
# constant, one reads the tuple, one writes this constant to a fixture — so a
# repeat count tuned in a single copy would leave the premise test passing for
# one string while the parametrised set exercised another, and the anti-vacuity
# link between them would be gone. Lines 146-152 already state the rule: every
# enumeration moves together, or the set is only as complete as its shortest
# copy.
_ALWAYS_UNSCANNABLE: str = dict(_PATHOLOGICAL_SOURCES)["unary-not-chain"]


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

    def _exploding(text: str) -> list[tuple[int, tuple[int, int]]]:
        """Stands in for `_suppressed_spans` — the LAST step of the scan.

        #539 REPLACED THE SEAM THIS TEST INJECTS AT, and the replacement had to be made
        deliberately rather than by deletion. The stand-in used to be an object with a
        `.search()` method patched over `_TYPE_IGNORE_PATTERN`, because the last step was
        a per-line regex. It is now a `tokenize` pass over logical lines, so that constant
        no longer exists — and had the patch been left pointing at a name nothing calls,
        `monkeypatch.setattr` would still have succeeded and the injected fault would
        simply never have fired, leaving this test asserting a property it no longer
        reaches. Patching the function that IS the last step keeps the ordering property
        pinned.
        """
        raise RecursionError(f"injected post-walk fault on {text[:20]!r}")

    monkeypatch.setattr(check_tag_t3, "_suppressed_spans", _exploding)
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
    # #543 review (dx-003): the PATH arm has its own message now. Asserting the
    # CONTENT one here would pass on a regression that routed a path failure
    # through the parser arm, and vice versa.
    assert check_tag_t3._UNSCANNABLE_PATH_MESSAGE in violations[0]
    assert check_tag_t3._UNSCANNABLE_MESSAGE not in violations[0]


# ---------------------------------------------------------------------------
# #543 review, err-001: a fault in the GATE must not read as a finding in the
# FILE. `_scan_text`'s `except Exception` wrapped the detector predicates too,
# so an injected AttributeError in `_is_tag_t3_call` reported a completely
# clean file as an unscannable "violation" at rc=1 — the exit code that means
# "someone laundered T3", for a file containing no such thing.
# ---------------------------------------------------------------------------


def _clean_source() -> str:
    """Source with no tag / cast / subscript / type-ignore pattern in it."""
    return "def hello():\n    return foo(1, 2)\n"


def _predicates_detect_calls() -> frozenset[str]:
    """Every module-level predicate `_detect` invokes, derived from the gate's own AST.

    HAND-WRITTEN, this list went stale the moment #539 renamed one predicate and added two
    more — and a parametrisation that silently covers three of five leaves the fence
    unmeasured on the rest. It is the same enumerate-versus-derive lesson the identifier
    meta-guard in the sole-layer suite exists to teach, applied to the guard itself.
    """
    tree = ast.parse(_SCRIPT.read_text(encoding="utf-8"))
    module_functions = {
        node.name for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    detect = next(
        node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "_detect"
    )
    return frozenset(
        call.func.id
        for call in ast.walk(detect)
        if isinstance(call, ast.Call)
        and isinstance(call.func, ast.Name)
        and call.func.id in module_functions
        and call.func.id.startswith("_")
    )


# A SOURCE THAT REACHES EACH PREDICATE. Most are called on every `ast.Call`, so the clean
# fixture reaches them; three are guarded by a shape test and were NEVER fault-tested while
# this parametrisation was hand-written — which is exactly what deriving the set exposed.
_REACHING_SOURCE: dict[str, str] = {
    "_is_benign_state_mutation_target": 'obj.__setattr__(self, "x", 1)\n',
    "_is_self_init_re_entry": "obj.__init__(self)\n",
    "_private_surface_is_exempt": "_log_t3(x)\n",
}

_DETECT_PREDICATES = sorted(_predicates_detect_calls())


# The predicates the derivation MUST find. A floor, not a transcript: the derived set is
# allowed to grow past it, but never to shrink below it. Written out because a derivation
# compared only against ITSELF proves nothing — `_DETECT_PREDICATES` is literally
# `sorted(_predicates_detect_calls())`, so the equality that used to live here could not
# fail however broken the derivation became. Includes the three shape-guarded predicates
# whose absence from the hand-written list is what motivated deriving it at all.
_REQUIRED_DETECT_PREDICATES: frozenset[str] = frozenset(
    {
        "_is_tag_t3_call",
        "_is_cast_tagged_content_call",
        "_is_unbound_basemodel_seam_call",
        "_is_benign_state_mutation_target",
        "_is_self_init_re_entry",
        "_private_surface_hit",
        "_private_surface_is_exempt",
        "_tagged_subscript_verdict",
        "_is_tagged_seam_call",
        "_mutates_tier_in_a_copy",
    }
)


def test_the_faulting_predicate_parametrisation_is_derived_not_transcribed() -> None:
    """The derived set must cover a NAMED floor, not merely equal itself.

    An assertion that compares a derivation to its own output is vacuous — it holds if the
    derivation returns everything, nothing, or garbage. This is the shape this repo keeps
    finding in other people's tests and it went straight into one of mine.
    """
    assert _DETECT_PREDICATES, "no predicates derived — the derivation itself broke"
    missing = _REQUIRED_DETECT_PREDICATES - set(_DETECT_PREDICATES)
    assert not missing, (
        f"the derivation stopped finding {sorted(missing)}. Either `_detect` no longer "
        f"calls them — in which case the fence no longer covers them — or the derivation "
        f"is broken."
    )
    assert len(_DETECT_PREDICATES) >= len(_REQUIRED_DETECT_PREDICATES)


@pytest.mark.parametrize("predicate", _DETECT_PREDICATES)
def test_a_faulting_detector_predicate_raises_instead_of_reporting_a_violation(
    monkeypatch: pytest.MonkeyPatch, predicate: str
) -> None:
    """EVERY predicate, because the fence has to cover all of them.

    Parametrised rather than written once against `_is_tag_t3_call`: a fence around one
    predicate and not its siblings would pass a single-predicate test while leaving the
    rest of the detector misfiled.
    """

    def _buggy(*args: object, **kwargs: object) -> bool:
        """Signature-agnostic on purpose.

        The predicates do not share an arity — `_tagged_subscript_verdict` and
        `_is_tagged_seam_call` take the alias environment as a second argument. A stub
        fixed at one positional parameter would raise `TypeError` on those two instead of
        the `AttributeError` this test asserts travels as `__cause__`, so the fence would
        look covered while the assertion measured the stub's own arity bug.
        """
        raise AttributeError(f"simulated internal bug in {predicate}")

    monkeypatch.setattr(check_tag_t3, predicate, _buggy)
    source = _REACHING_SOURCE.get(predicate, _clean_source())

    with pytest.raises(
        check_tag_t3.GateInternalError, match=re.escape("BUG IN check_tag_t3.py")
    ) as caught:
        check_tag_t3._scan_text(source, Path("src/alfred/totally_clean_file.py"))

    # The ORIGINAL fault must survive, or a maintainer reads "the gate broke"
    # with no way to find out how.
    assert isinstance(caught.value.__cause__, AttributeError)
    assert predicate in str(caught.value.__cause__)


def test_a_faulting_detector_exits_two_not_one(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The end-to-end statement of err-001, at the exit-code contract.

    rc=1 means "violations found" and a caller is entitled to read every line
    it printed as a real finding. A faulting detector is the OTHER thing —
    "the gate could not run" — which `main` already spells rc=2 for an empty
    scan root, and now spells for this.

    Driven through `main` on a real file so the exit contract, not just the
    exception, is what is pinned.
    """
    clean = tmp_path / "ordinary.py"
    clean.write_text(_clean_source(), encoding="utf-8")

    def _buggy(node: ast.Call) -> bool:
        raise AttributeError("simulated internal bug")

    monkeypatch.setattr(check_tag_t3, "_is_tag_t3_call", _buggy)

    rc = check_tag_t3.main([str(clean)])

    err = capsys.readouterr().err
    assert rc == 2, "a gate-internal fault must not report as 'violations found'"
    assert check_tag_t3._GATE_INTERNAL_MESSAGE in err
    assert "AttributeError" in err
    assert check_tag_t3._UNSCANNABLE_MESSAGE not in err, (
        "the gate defect was still filed as an unscannable FILE — the broad "
        "arm swallowed GateInternalError, i.e. the handler order regressed"
    )


def test_an_input_fault_is_still_a_violation_and_still_exits_one(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The NEGATIVE twin. Narrowing must not turn #542 back on.

    #542's defect was an input-driven parser fault ABORTING the scan loop, so
    later files went unscanned while the gate exited 1 naming nothing. The
    err-001 fix deliberately introduces an abort — for gate faults only — and
    this is the case that proves it did not leak onto the input path: the
    pathological file is still reported, the LATER file is still scanned, and
    the exit code is still 1, not 2.
    """
    bad = tmp_path / "aaa_pathological.py"
    bad.write_text(_ALWAYS_UNSCANNABLE, encoding="utf-8")
    later = tmp_path / "zzz_violation.py"
    later.write_text("tag(T3, payload)\n", encoding="utf-8")

    rc = check_tag_t3.main([str(bad), str(later)])

    err = capsys.readouterr().err
    assert rc == 1, "an input fault must stay 'violations found', not become 'gate broken'"
    assert check_tag_t3._UNSCANNABLE_MESSAGE in err
    assert check_tag_t3._TAG_T3_MESSAGE in err, "the later file went unscanned — #542 is back"
    assert check_tag_t3._GATE_INTERNAL_MESSAGE not in err


class _AstWithExplodingWalk:
    """The real ``ast`` module in every respect EXCEPT ``walk``.

    Substituted for the SCRIPT's own module-global ``ast`` name, never for the
    stdlib module itself. Patching `check_tag_t3.ast.walk` — i.e. reaching
    through to the shared stdlib object — was measured to take pytest's own
    traceback machinery down with it (`_pytest._code.source` calls `ast.walk`
    while rendering a failure), turning any real failure in this file into an
    INTERNALERROR that reports nothing. A double must model the real object
    without becoming it.
    """

    def __getattr__(self, name: str) -> object:
        return getattr(ast, name)

    def walk(self, tree: ast.AST) -> object:
        raise RecursionError("simulated deep-nesting fault from the walker")


def test_the_detector_fence_does_not_swallow_a_walk_level_fault(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`ast.walk` stays OUTSIDE the fence: it is input-driven, not a predicate.

    Misfiling a walk-level fault as a gate defect is the same confusion in the
    other direction — a pathological FILE would report as "check_tag_t3.py is
    broken" and send the reader to the wrong repository entirely. Widening the
    fence to cover the walk is a one-line edit and this is what refuses it.
    """
    monkeypatch.setattr(check_tag_t3, "ast", _AstWithExplodingWalk())

    violations = check_tag_t3._scan_text(_clean_source(), Path("src/alfred/deep.py"))

    assert any(check_tag_t3._UNSCANNABLE_MESSAGE in v for v in violations), (
        "a walk-level fault stopped being reported as an unscannable FILE"
    )
    assert not any(check_tag_t3._GATE_INTERNAL_MESSAGE in v for v in violations)


# ---------------------------------------------------------------------------
# #543 review, sec-002: a REALISTIC decoy tree. The `_MIN_SCANNED_FILES`
# comment claimed a wrong checkout was "caught by this floor alone. Measured:
# 2 files scanned, rc=2" — true at 2 files, and measured FALSE at 260: the
# floor is 250, a real copy of this repo holds 332 under the two roots, and a
# decoy of realistic size exited 0 having scanned nothing.
# ---------------------------------------------------------------------------


_DECOY_REFUSAL: str = "do NOT resolve inside"


def _build_decoy_tree(root: Path, files_per_root: int) -> Path:
    """A tree that LOOKS like this repo: both declared roots, clean content."""
    for scan_root in check_tag_t3._DEFAULT_SCAN_ROOTS:
        directory = root / scan_root
        directory.mkdir(parents=True)
        for index in range(files_per_root):
            (directory / f"mod_{index:04d}.py").write_text("x = 1\n", encoding="utf-8")
    return root


def test_a_large_out_of_repo_decoy_tree_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The measured hole: 260 clean files cleared the 250-file census at rc=0.

    Both roots exist and are populated, so the per-directory floor passes;
    both resolve OUTSIDE this repo, so the root invariant exempts them by
    design; and the aggregate census only counts. The count was the wrong
    instrument. `_collect_paths` now asserts the PROPERTY — an argument-less
    run is gating THIS repo or it is gating nothing.

    Sized deliberately ABOVE `_MIN_SCANNED_FILES` so a regression that deletes
    the new check cannot be masked by the census firing instead.
    """
    decoy = _build_decoy_tree(tmp_path / "wrong-checkout", files_per_root=130)
    assert 130 * len(check_tag_t3._DEFAULT_SCAN_ROOTS) > check_tag_t3._MIN_SCANNED_FILES, (
        "the decoy is small enough for the census to catch — the test would "
        "pass without the check it exists for"
    )
    monkeypatch.chdir(decoy)

    with pytest.raises(check_tag_t3.EmptyScanRootError, match=_DECOY_REFUSAL):
        check_tag_t3._collect_paths([])

    assert check_tag_t3.main([]) == 2
    err = capsys.readouterr().err
    assert _DECOY_REFUSAL in err
    assert "expected at least" not in err, (
        "the CENSUS fired, not the repo-root check — this decoy is too small "
        "to prove anything about the hole sec-002 measured"
    )


@_NEEDS_SYMLINKS
def test_one_in_repo_symlink_does_not_buy_a_decoy_tree_a_pass(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """#548 review, sec-001: the decoy check sampled COLLECTED FILES, so one link passed it.

    The predicate was ``any(p.resolve().is_relative_to(_REPO_ROOT) for p in
    paths)`` — satisfied by a SINGLE collected file. ``_collect_paths`` reaches
    an out-of-repo directory through ``rglob(..., recurse_symlinks=True)``, so
    one link out of the decoy into any real repository ``.py`` file made the
    ``any(...)`` true while 260 decoy files supplied every verdict. Measured
    against the pre-fix script: ``rc=0``, 261 collected, 1 inside this repo.

    The census cannot catch it either — 261 clears the 250-file floor — which is
    why this asserts the ROOT refusal fired and not the count. Sized above
    ``_MIN_SCANNED_FILES`` for exactly that reason.
    """
    decoy = _build_decoy_tree(tmp_path / "wrong-checkout", files_per_root=130)
    link = decoy / check_tag_t3._DEFAULT_SCAN_ROOTS[0] / "zz_in_repo_link.py"
    link.symlink_to(_REPO_ROOT / "src" / "alfred" / "__init__.py")

    # Precondition: the link really does resolve into this repo, or the test
    # proves nothing about the bypass it characterises.
    assert link.resolve().is_relative_to(_REPO_ROOT), "the link does not reach this repo"
    monkeypatch.chdir(decoy)

    with pytest.raises(check_tag_t3.EmptyScanRootError, match=_DECOY_REFUSAL):
        check_tag_t3._collect_paths([])

    assert check_tag_t3.main([]) == 2
    err = capsys.readouterr().err
    assert _DECOY_REFUSAL in err
    assert "expected at least" not in err, (
        "the CENSUS fired, not the root check — 261 files clear the floor, so "
        "this decoy proves nothing unless the root refusal is what spoke"
    )


def test_the_decoy_check_does_not_red_an_out_of_repo_fixture_scan(tmp_path: Path) -> None:
    """The exemption the new check must NOT break: explicit arguments.

    The unit suite plants `tmp_path` trees and scans them by path — that is
    the single-file / fixture path, and holding it to "must be inside this
    repo" would red every one of those tests while saying nothing about
    production, which only ever runs argument-less.
    """
    fixture = tmp_path / "out_of_repo.py"
    fixture.write_text("x = 1\n", encoding="utf-8")

    assert check_tag_t3._collect_paths([str(fixture)]) == [fixture]
    assert check_tag_t3._collect_paths([str(tmp_path)]) == [fixture]


def test_a_partial_scan_refusal_names_the_remedy() -> None:
    """#543 review, dx-001: the message must say what to DO.

    `check_tag_t3.py src/alfred` is the documented pre-#541 usage and the most
    natural manual invocation; it now exits 2. The old message named what was
    missing and cited the internal `_DEFAULT_SCAN_ROOTS` symbol, leaving a
    first-time contributor to read the source to learn that the fix is to drop
    the argument.
    """
    with pytest.raises(check_tag_t3.PartialScanRootError) as caught:
        check_tag_t3._collect_paths(["src/alfred"])

    message = str(caught.value)
    assert "with NO arguments" in message, "the message does not state the remedy"
    for root in check_tag_t3._DEFAULT_SCAN_ROOTS:
        assert root in message, f"the message does not name the root {root!r} to pass instead"


# ---------------------------------------------------------------------------
# #547. The census must count files the gate READ AND PARSED, not files
# traversal collected. `_ScannedOk` marks the one path that means "this scan
# ran to completion"; every other return is a failure by construction.
# ---------------------------------------------------------------------------


def _trigger_unparseable(tmp: Path) -> Path:
    p = tmp / "unparseable.py"
    p.write_text("def (:\n", encoding="utf-8")
    return p


def _trigger_undecodable(tmp: Path) -> Path:
    p = tmp / "undecodable.py"
    p.write_bytes(b"# -*- coding: latin-1 -*-\nx = '\xff\xfe'\n")
    return p


def _trigger_unreadable(tmp: Path) -> Path:
    p = tmp / "a_directory.py"
    p.mkdir()
    return p


def _trigger_unscannable(tmp: Path) -> Path:
    # REUSE `_ALWAYS_UNSCANNABLE` — do NOT hand-roll a nesting depth. It is
    # derived from `_PATHOLOGICAL_SOURCES["unary-not-chain"]` and is pinned to
    # MemoryError by `test_the_always_unscannable_premise` above. The
    # RecursionError/Homebrew build divergence belongs to `binop-chain`, NOT to
    # this shape: name the fixture, not a remembered mechanism.
    p = tmp / "unscannable.py"
    p.write_text(_ALWAYS_UNSCANNABLE, encoding="utf-8")
    return p


def _trigger_unscannable_path(tmp: Path) -> Path:
    return tmp / "embedded\x00nul.py"


_FAILURE_TRIGGERS: dict[str, Callable[[Path], Path]] = {
    check_tag_t3._UNPARSEABLE_MESSAGE: _trigger_unparseable,
    check_tag_t3._UNDECODABLE_MESSAGE: _trigger_undecodable,
    check_tag_t3._UNREADABLE_MESSAGE: _trigger_unreadable,
    check_tag_t3._UNSCANNABLE_MESSAGE: _trigger_unscannable,
    check_tag_t3._UNSCANNABLE_PATH_MESSAGE: _trigger_unscannable_path,
}


def test_only_a_completed_scan_returns_the_scanned_ok_marker(tmp_path: Path) -> None:
    """DEFAULT-DENY the outcome axis.

    `main` counts a file toward the census only when `_scan_file` returns a
    `_ScannedOk`. Marking the FAILURES instead would enumerate them, and this
    file already carries two shapes enumeration misses: the `S_ISREG` refusal
    reuses `_UNREADABLE_MESSAGE`, and `_NOT_A_REGULAR_FILE_REASON` is a
    collection failure whose name carries no `_MESSAGE` suffix.

    Derived from the module's own constants, so a sixth message reds here.
    """
    assert set(_FAILURE_TRIGGERS) == set(_COLLECTION_FAILURE_MESSAGES), (
        "a collection-failure message has no trigger — add one, or the census "
        "can silently count its files as successfully scanned"
    )

    for index, (message, build) in enumerate(_FAILURE_TRIGGERS.items()):
        directory = tmp_path / f"case{index}"
        directory.mkdir()
        result = check_tag_t3._scan_file(build(directory))

        assert result, f"{message!r}: expected a collection failure, got a clean scan"
        assert any(message in line for line in result), f"expected {message!r} in {result!r}"
        assert not isinstance(result, check_tag_t3._ScannedOk), (
            f"{message!r}: marked as a completed scan, so `main` will count "
            f"this unreadable file toward the census — the fail-open direction"
        )


def test_a_clean_file_returns_the_scanned_ok_marker(tmp_path: Path) -> None:
    """The other side. Without this, the guard above passes on a build that
    never marks anything and the census would count zero files forever."""
    clean = tmp_path / "clean.py"
    clean.write_text("x = 1\n", encoding="utf-8")

    result = check_tag_t3._scan_file(clean)

    assert result == []
    assert isinstance(result, check_tag_t3._ScannedOk)


def test_a_file_with_a_real_finding_still_counts_as_scanned(tmp_path: Path) -> None:
    """A finding is not a collection failure. The gate READ this file fine."""
    bad = tmp_path / "bad.py"
    bad.write_text(
        "from alfred.security.tiers import tag, T3\nv = tag(T3, 'x')\n", encoding="utf-8"
    )

    result = check_tag_t3._scan_file(bad)

    assert result, "expected the tag(T3, ...) finding"
    assert isinstance(result, check_tag_t3._ScannedOk)


def test_the_scanned_ok_marker_is_constructed_in_exactly_one_place() -> None:
    """DEFAULT-DENY the construction site, by NAME CENSUS.

    The completion flag stops an `except` arm reaching the marked return by
    falling through. It does NOT stop anyone writing
    `_ScannedOk([... _UNREADABLE_MESSAGE ...])` directly, which fails open past
    every other guard here, and neither mypy nor pyright can see the invariant.

    NOT an `ast.Call`-whose-func-is-a-`Name` pin. That was proposed, executed
    and RETRACTED during review: it reports green against `_Alias = _ScannedOk`,
    a subclass, `functools.partial(_ScannedOk)` and `globals()["_ScannedOk"]`.
    Keying on the call shape is the alias-resolution mistake this repo keeps
    paying for. Every `ast.Name` reference is censused instead, whatever
    syntactic role it plays, and the allowed LOCATIONS are enumerated — so a
    reference from anywhere else reds regardless of how it is spelled.

    WHAT THIS CANNOT DO: `type(x)(...)` and `copy.copy(x)` reproduce the class
    without ever spelling the name, so no source-level instrument sees them.
    Named here and in ADR-0060 rather than claimed closed.
    """
    tree = ast.parse(_SCRIPT.read_text(encoding="utf-8"), filename=str(_SCRIPT))

    classes = [n for n in ast.walk(tree) if isinstance(n, ast.ClassDef) and n.name == "_ScannedOk"]
    assert len(classes) == 1, f"expected one _ScannedOk class, found {len(classes)}"

    enclosing: dict[int, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            end = node.end_lineno or node.lineno
            for line in range(node.lineno, end + 1):
                enclosing[line] = node.name

    references = [
        (enclosing.get(n.lineno, "<module>"), n.lineno)
        for n in ast.walk(tree)
        if isinstance(n, ast.Name) and n.id == "_ScannedOk"
    ]
    locations = {where for where, _ in references}
    assert locations <= {"_scan_text", "main"}, (
        f"_ScannedOk is referenced outside the two functions allowed to see it: "
        f"{sorted(locations - {'_scan_text', 'main'})} at {references!r}. A marker "
        f"minted anywhere else counts an ungated file as a completed scan."
    )

    built_in_scan_text = [where for where, _ in references if where == "_scan_text"]
    assert len(built_in_scan_text) == 1, (
        f"expected exactly one _ScannedOk reference in _scan_text (the single "
        f"construction site), found {len(built_in_scan_text)}: {references!r}"
    )


def _build_flat_tree(root: Path, count: int, body: str, prefix: str = "mod") -> Path:
    """`count` files of identical content in one out-of-repo directory."""
    root.mkdir(parents=True, exist_ok=True)
    for index in range(count):
        (root / f"{prefix}_{index:04d}.py").write_text(body, encoding="utf-8")
    return root


def test_a_tree_the_gate_cannot_read_exits_2_not_1(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Probe A. Measured on the pre-#547 gate as rc=1 with 521 stderr lines.

    Exit 1 is "violations found", and `main`'s docstring promises "every listed
    line is a finding in a file, not a fault in the gate". Files the gate could
    not parse are not findings in files.
    """
    monkeypatch.setattr(check_tag_t3, "_MIN_SCANNED_FILES", 4)
    tree = _build_flat_tree(tmp_path / "unreadable", 4, "def (:\n")

    assert check_tag_t3.main([str(tree)]) == 2
    err = capsys.readouterr().err
    # ALL THREE terms. Asserting only two let a mutant dropping `- exempt` from
    # the unreadable arithmetic survive every test in the suite.
    assert "0 exempt" in err and "0 scanned" in err and "4 unreadable" in err
    assert "not reaching the source tree" not in err, (
        "the PRE-SCAN floor fired, not the post-scan census — this tree does "
        "not clear the collection floor and the test proves nothing"
    )
    assert check_tag_t3._UNPARSEABLE_MESSAGE in err, (
        "the census refused without printing what it collected"
    )
    assert check_tag_t3._PARTIAL_HEADER in err, "wrong header on a refusal"
    assert check_tag_t3._FINDINGS_HEADER not in err, "read failures announced as 'violations found'"


def test_a_tree_of_only_exempt_files_exits_2_and_says_exempt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Probe C — the genuinely SILENT shape. Measured pre-#547 as rc=0, no output.

    The message must say EXEMPT, not "could not read it": every file here was
    read perfectly and simply was not gated.
    """
    monkeypatch.setattr(check_tag_t3, "_MIN_SCANNED_FILES", 4)
    tree = _build_flat_tree(tmp_path / "allexempt", 4, "x = 1\n", prefix="test_x")
    assert all(check_tag_t3._is_exempt(p) for p in tree.glob("*.py")), (
        "the fixture is not exempt — this test would pass for the wrong reason"
    )

    assert check_tag_t3.main([str(tree)]) == 2
    err = capsys.readouterr().err
    # THE THIRD TERM IS LOAD-BEARING. A mutant computing `unreadable` as
    # `len(distinct) - scanned_ok` reports "4 exempt, 0 scanned, 4 unreadable"
    # here and survives everything else, because this is the only test reaching
    # the census with exempt > 0.
    assert "4 exempt" in err and "0 scanned" in err and "0 unreadable" in err
    assert "not reaching the source tree" not in err


def test_the_census_passes_at_the_floor_and_fails_one_below(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Both sides of the new comparison.

    The failing half must be decided by the POST-SCAN census, not the pre-scan
    collection floor: an earlier draft planted 3 files with the floor at 4, so
    the pre-scan floor refused it and the test passed on unmodified code. Here
    the tree always CLEARS the collection floor and only the scanned tally
    varies.
    """
    monkeypatch.setattr(check_tag_t3, "_MIN_SCANNED_FILES", 4)

    at_floor = _build_flat_tree(tmp_path / "at", 4, "x = 1\n")
    assert check_tag_t3.main([str(at_floor)]) == 0

    one_below = _build_flat_tree(tmp_path / "below", 3, "x = 1\n")
    (one_below / "broken.py").write_text("def (:\n", encoding="utf-8")
    assert check_tag_t3.main([str(one_below)]) == 2
    err = capsys.readouterr().err
    assert "3 scanned" in err and "1 unreadable" in err
    assert "not reaching the source tree" not in err, (
        "the pre-scan floor decided this — 4 files were collected, so it must not"
    )


def test_one_unparseable_file_among_many_still_exits_1(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Proportionality: only a MASS read failure flips the exit code."""
    monkeypatch.setattr(check_tag_t3, "_MIN_SCANNED_FILES", 4)
    tree = _build_flat_tree(tmp_path / "mostly_fine", 5, "x = 1\n")
    (tree / "broken.py").write_text("def (:\n", encoding="utf-8")

    assert check_tag_t3.main([str(tree)]) == 1


def test_the_production_tree_is_gated_as_a_property() -> None:
    """DoD #4, as a PROPERTY over constants — never a count.

    An earlier draft bisected the floor around 331 and four reviewers rejected
    it: the production tree grows ~25 `.py` files per 30 days and `tests/unit`
    runs in four required checks, so the next unrelated merge would red it. An
    stderr-reading variant is no better — the post-scan census is reachable on
    the real tree at exactly ONE floor value, so any such test is structurally
    count-pinned.

    Every assertion here is against a CONSTANT or a relation. Oracle
    independence comes from pairing this with
    `test_only_a_completed_scan_returns_the_scanned_ok_marker`, which pins the
    marker itself without reference to any count.
    """
    paths = check_tag_t3._collect_paths([])
    distinct = {p.resolve(strict=False) for p in paths}
    exempt = {p for p in distinct if check_tag_t3._is_exempt(p)}
    unreadable = [
        p
        for p in sorted(distinct - exempt)
        if not isinstance(check_tag_t3._scan_file(p), check_tag_t3._ScannedOk)
    ]

    assert not unreadable, f"the gate cannot read its own tree: {unreadable}"
    assert len(distinct - exempt) >= check_tag_t3._MIN_SCANNED_FILES
    assert len(exempt) <= len(check_tag_t3._APPROVED_PATHS)
    assert check_tag_t3.main([]) != 2


def test_a_realistic_mass_failure_above_the_real_floor_exits_2(tmp_path: Path) -> None:
    """The one full-size case, at the SHIPPED floor with no monkeypatch."""
    tree = _build_flat_tree(tmp_path / "big", 260, "def (:\n")
    # `<` not `>`: ruff SIM300 reds a Yoda condition.
    assert check_tag_t3._MIN_SCANNED_FILES < 260

    assert check_tag_t3.main([str(tree)]) == 2


@_NEEDS_SYMLINKS
def test_symlink_copies_of_one_file_do_not_clear_the_census(tmp_path: Path) -> None:
    """NEW-1. `_collect_paths` never deduped, so the census counted scan EVENTS.

    MEASURED ON THE SHIPPED GATE, no monkeypatch: 260 symlinks to a single
    `x = 1` file exited 0 with empty stderr, having gated one distinct file.
    That falsifies the gate's own purpose, and a census over `scanned_ok` alone
    passes it too — all 260 scan perfectly.
    """
    tree = tmp_path / "links"
    tree.mkdir()
    (tree / "real.py").write_text("x = 1\n", encoding="utf-8")
    for index in range(260):
        (tree / f"link_{index:04d}.py").symlink_to(tree / "real.py")

    assert check_tag_t3.main([str(tree)]) == 2


def test_a_file_quoting_a_failure_message_still_counts_as_scanned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The NON-SUBSTRING requirement, stated as a test with NO SLACK.

    A substring implementation keys the census on file CONTENT, because
    `_record` appends a source snippet under every finding. This file is read
    and parsed perfectly and trips a REAL rule on a line quoting a
    collection-failure message, so its snippet carries that text.

    ZERO SLACK IS LOAD-BEARING. Plant exactly `_MIN_SCANNED_FILES` files of
    which ONE is the quoter. `==` is the unique solution: collected >= floor or
    the pre-scan floor decides the test instead, and collected <= floor or a
    misclassified quoter still clears the census and the substring mutant
    survives. An earlier draft planted floor-many files PLUS the quoter and
    returned rc=1 under BOTH implementations.
    """
    monkeypatch.setattr(check_tag_t3, "_MIN_SCANNED_FILES", 2)
    tree = _build_flat_tree(tmp_path / "quoter", 1, "x = 1\n")
    (tree / "quoter.py").write_text(
        "from alfred.security.tiers import tag, T3\n"
        f'v = tag(T3, "{check_tag_t3._UNPARSEABLE_MESSAGE}")\n',
        encoding="utf-8",
    )

    planted = sorted(tree.glob("*.py"))
    assert len(planted) == check_tag_t3._MIN_SCANNED_FILES, (
        "zero slack is the point: one more file and the substring mutant "
        "survives; one fewer and the pre-scan floor decides the test"
    )
    assert not any(check_tag_t3._is_exempt(p) for p in planted)

    assert check_tag_t3.main([str(tree)]) == 1, (
        "expected the real tag(T3, ...) finding under exit 1; exit 2 means the "
        "census classified a perfectly-scannable file as a read failure "
        "because its SOURCE quoted a message constant"
    )


_NAIVE_ARM = """    except MemoryError as exc:
        violations.append(f"{path}:1: {_UNSCANNABLE_MESSAGE}")
        violations.append(f"  {type(exc).__name__}: {exc}")
"""


def test_a_naive_new_except_arm_fails_closed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """DoD #7, against a REAL new arm in REAL source.

    The shape that broke two earlier designs: an `except` arm written the
    ordinary way — append messages, no `return` — reusing an EXISTING message
    so no `_*_MESSAGE`-derived guard can see it. Marking the failure sites
    scored these files as clean scans; so did marking the try statement's
    FALL-THROUGH, because a naive arm simply falls into it.

    A SOURCE-MUTATION HARNESS, not a monkeypatch. The property under test IS
    `_scan_text`'s control flow, so replacing the function cannot exercise it —
    an earlier draft stubbed `_scan_text` wholesale and passed against a
    fail-open build, which is how it reached review as a "proof".
    """
    source = _SCRIPT.read_text(encoding="utf-8")
    # Anchored on the GateInternalError re-raise: a bare `except Exception as
    # exc:` appears three times in this file, so it is not a unique anchor.
    anchor = "        raise\n    except Exception as exc:\n"
    assert source.count(anchor) == 1, "anchor drifted — the mutation would not apply"
    mutated = source.replace(
        anchor, "        raise\n" + _NAIVE_ARM + "    except Exception as exc:\n", 1
    )
    assert mutated != source, "MUTANT NEVER APPLIED — a green result would be meaningless"

    # `_REPO_ROOT` is derived from `__file__`, so WHERE the mutated script
    # lives decides which trees look in-repo to it. Put it under a fake repo
    # root and the scan tree OUTSIDE that root: otherwise the scan tree is
    # in-repo for the mutant, the `_DEFAULT_SCAN_ROOTS` runtime invariant fires
    # first, and rc=2 arrives from `PartialScanRootError` with the census never
    # consulted. Measured: that made this test pass identically against the
    # fail-open build, which is exactly the vacuity it exists to avoid.
    fake_repo = tmp_path / "fake_repo"
    scripts_dir = fake_repo / "scripts"
    scripts_dir.mkdir(parents=True)
    script = scripts_dir / "mutated_gate.py"
    script.write_text(mutated, encoding="utf-8")
    spec = importlib.util.spec_from_file_location("mutated_gate", script)
    assert spec is not None and spec.loader is not None
    gate = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gate)
    harness_root = gate._REPO_ROOT
    assert harness_root == fake_repo, "harness misplaced the mutant"

    gate._MIN_SCANNED_FILES = 4
    tree = _build_flat_tree(tmp_path / "trees" / "newarm", 4, _ALWAYS_UNSCANNABLE)
    assert not tree.resolve().is_relative_to(gate._REPO_ROOT), (
        "the scan tree is in-repo for the mutant — the root invariant will "
        "decide this test instead of the census"
    )

    rc = gate.main([str(tree)])
    err = capsys.readouterr().err

    assert rc == 2, (
        "a naive new except arm was counted as a clean scan — the marker is "
        "reachable by falling through instead of by a completion event"
    )
    # POSITIVE proof that the CENSUS refused, not another guard.
    assert "0 scanned" in err and "4 unreadable" in err, (
        f"rc=2 did not come from the census — stderr was {err!r}"
    )
