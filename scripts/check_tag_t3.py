#!/usr/bin/env python3
"""CI grep gate: reject unauthorised ``tag(T3`` and ``cast(TaggedContent[`` uses.

Invoked by ``make check`` and CI. Exits 0 if clean; exits 1 with violation
messages if any non-approved file contains:

- ``tag(T3, ...)``           — direct calls to the capability-gated factory
                               from outside the two approved homes
                               (``security/tiers.py`` and
                               ``security/quarantine.py``).
- ``TaggedContent[T3](...)`` — direct subscript construction that bypasses
                               the ``tag_t3_with_nonce`` capability gate.
                               The Pydantic field validator on ``tier`` does
                               NOT check the nonce; only ``tag_t3_with_nonce``
                               does. Direct construction therefore admits
                               raw T3 content without the per-process nonce
                               check that closes the import-copy-and-call
                               attack (spec §3.2). sec-S3-002.
- ``cast(TaggedContent[...]``— type-erasure bypasses that discard provenance.
- ``# type: ignore`` on a line containing ``TaggedContent`` — suppressing the
                               type error that prevents cast-bypass detection.

Detection strategy (CR-138 finding #2):

The call-site patterns are detected via :mod:`ast` so a call split across
multiple physical lines is still caught — line-based regex would have been
trivially bypassed by inserting a newline between ``tag(`` and ``T3``.
The ``# type: ignore`` suppression sits in comment text that the parser
discards, so it stays on a line-based regex.

Spec §3.2, §3.3, §3.7-3.8.

Authorised callers (the EXACT list — keep in sync with the briefing):

- ``src/alfred/security/tiers.py``      — the ``tag`` overload bodies
                                          (the home of the factory itself).
- ``src/alfred/security/quarantine.py`` — the ``downgrade_to_orchestrator``
                                          boundary that bridges T3 ➜ T3DerivedData.
- ``tests/unit/security/**``            — tests assert the gate's behaviour
                                          using the same patterns.

Usage:

    python scripts/check_tag_t3.py [file_or_dir ...]

If no arguments are given, scans every root declared in
``_DEFAULT_SCAN_ROOTS`` (``src/alfred`` and ``plugins``). An in-repo
DIRECTORY scan that does not cover all of them is refused at runtime — the
roots live here, not at the call sites (#541).

That runtime refusal covers directory arguments only. An invocation that
enumerates explicit FILE paths can still gate a subset (measured: the 293
tracked ``src/alfred/**.py`` files passed individually exit 0 with
``plugins`` unscanned). What closes THAT is the call-site pin in
``tests/unit/meta/test_gate_surfaces_are_pinned.py``, which requires every
invocation site to pass no arguments at all. Neither layer is complete on
its own; see :func:`_collect_paths` for the split.
"""

from __future__ import annotations

import ast
import os
import re
import subprocess
import sys
from pathlib import Path

# Line-based pattern. ``# type: ignore`` on a line containing
# ``TaggedContent`` is fundamentally a comment-and-line construct: the
# parser discards comments so AST detection cannot see them. Multiline
# bypass via newline-in-call is not relevant here either (the suppression
# applies to a specific physical line).
_TYPE_IGNORE_PATTERN: re.Pattern[str] = re.compile(r"TaggedContent.*#\s*type:\s*ignore")
_TYPE_IGNORE_MESSAGE: str = "# type: ignore on TaggedContent line — fix the type, don't suppress"

# AST-detected call-site violations. Each entry describes the call name
# and the shape of its first positional argument; ``_node_matches`` decides
# whether a given ``ast.Call`` node trips the rule.
_TAG_T3_MESSAGE: str = "tag(T3, ...) direct call — use tag_t3_with_nonce() with injected nonce"
_CAST_TAGGED_CONTENT_MESSAGE: str = (
    "cast(TaggedContent[...]) — use AnyTaggedContent for observers (spec §3.3)"
)
_TAGGED_CONTENT_T3_SUBSCRIPT_MESSAGE: str = (
    "TaggedContent[T3](...) direct subscript construction — use "
    "tag_t3_with_nonce() with injected nonce (spec §3.2, sec-S3-002)"
)

# Read-surface failures. These are VIOLATIONS, not silent passes (#537):
# a file the gate cannot read is a file the gate is not gating, and Python's
# import machinery is far more permissive than this reader.
#
# A ``# -*- coding: latin-1 -*-`` header (PEP 263) makes
# ``read_text(encoding="utf-8")`` raise ``UnicodeDecodeError`` while the module
# imports and executes perfectly. Measured: the gate returned rc=0 for a file
# that constructed ``TaggedContent[T3]`` — one header line defeated every rule
# here, current and proposed. The same swallow hid a file carrying a real
# violation alongside a ``SyntaxError``, and made every "must PASS" floor in
# the suite vacuously green on text that was never parsed.
#
# Three DISTINCT strings so a test for one cannot be satisfied by another
# firing. Measured false-positive cost across the scan root: 0 unparseable,
# 0 unreadable.
_UNDECODABLE_MESSAGE: str = (
    "file is not valid UTF-8 — the gate cannot read it but Python can execute "
    "it (PEP 263 coding declaration). Re-encode as UTF-8."
)
_UNPARSEABLE_MESSAGE: str = "file does not parse — the gate cannot scan it. Fix the syntax error."
_UNREADABLE_MESSAGE: str = "file could not be read — the gate cannot scan it."

# THE GATE OWNS ITS SCAN ROOTS (#541). They used to live in the two
# invocation strings (``Makefile`` and ``pr-validate-python.yml``), so
# dropping ``plugins`` from either one was a one-word edit that stopped
# gating 39 first-party plugin files — including
# ``plugins/alfred_discord/inbound_emitter.py``, a real ingestion boundary —
# while the census (293 for ``src/alfred`` alone, floor 250) still passed.
#
# Raising the census was considered and rejected: at 300 it sits 7 files
# above the ``src/alfred`` count, and that tree grew +19 files in 23 days, so
# the guard would have stopped working within about a week. A count is a
# proxy for "both roots were gated"; the runtime invariant in
# :func:`_collect_paths` is the property itself.
#
# Callers now pass NO arguments, so there is no root to drop. Changing what
# is gated means editing this tuple — in a file under a 100% coverage gate,
# mypy --strict and pyright, pinned by a test that does not monkeypatch it.
_DEFAULT_SCAN_ROOTS: tuple[str, ...] = ("src/alfred", "plugins")

# Assert-RAN floor (#245, #514). ``_collect_paths([])`` resolves the default
# roots relative to CWD, so an argument-less run from the wrong directory
# scanned 0 files, exited 0 and printed nothing — a required check reporting
# green while gating nothing. A test-side census cannot catch that, because
# the failure mode IS the caller.
#
# WHAT IT STILL GUARDS, corrected after #541 (the earlier text here claimed
# "the WRONG-DIRECTORY case only", which measurement contradicts):
#
#   * The PLAIN wrong-directory run no longer reaches this floor. From
#     ``/tmp``, ``src/alfred`` is not a directory, so the missing-default-root
#     branch in ``_collect_paths`` raises first — measured rc=2 with the
#     specific "the default scan root does not exist relative to the current
#     directory" message, which is a better diagnosis than a count ever was.
#   * A DECOY TREE still lands here, and only here. Run from a directory that
#     happens to contain ``src/alfred`` and ``plugins`` of its own — a wrong
#     checkout, a scratch copy — and both roots resolve OUTSIDE this repo, so
#     the root invariant exempts them by design (it is scoped to in-repo
#     directories). Measured: 2 files scanned, rc=2, caught by this floor
#     alone. The narrowing that makes the invariant tractable is precisely
#     what keeps this constant load-bearing.
#   * A GUTTED in-repo tree: both roots present and covered, but mass-deleted
#     below the floor.
#
# 332 tracked ``.py`` files live under the two roots today (293 + 39); 250
# leaves headroom for deletions without leaving room for the gate to go
# vacuous. Unchanged at 250 by #541 — it is not, and never was, a check that
# every root was supplied; that is what ``_DEFAULT_SCAN_ROOTS`` plus the
# runtime invariant are for.
_MIN_SCANNED_FILES: int = 250

# Authorised non-test homes — resolved to absolute paths inside THIS repo
# at import time. CR-138 finding #11: suffix matching (``endswith``) was
# bypassable by any file whose path happened to end with the same
# segment (``/tmp/attacker/src/alfred/security/tiers.py`` would have
# been exempt). Exact absolute-path equality against the real files in
# this checkout closes that path.
#
# ``__file__`` resolves to ``<repo>/scripts/check_tag_t3.py``; the repo
# root is two parents up. The script always runs against files in this
# same checkout (CI invokes it with paths under the workspace), so any
# path that does NOT resolve to one of these exact files is not the
# real authorised home — even if it ends with the same segment.
_REPO_ROOT: Path = Path(__file__).resolve().parent.parent
_APPROVED_PATHS: frozenset[Path] = frozenset(
    {
        _REPO_ROOT / "src" / "alfred" / "security" / "tiers.py",
        _REPO_ROOT / "src" / "alfred" / "security" / "quarantine.py",
    }
)

# Test trees are exempt: tests assert the patterns the gate forbids.
# Matched as a resolved PATH COMPONENT, never as a substring of the raw
# string. Two bugs lived in the old substring-on-raw-string form (#537):
#
#   * ``tests/../src/alfred/foo.py`` was exempt while ``src/alfred/foo.py``
#     was not — the same file. A DIRECTORY argument poisoned everything
#     beneath it, and it needed no absolute path, so it was reachable from
#     the production invocation (``Makefile`` and CI both pass relative
#     paths). This is #428's ``/lib64/../etc`` class on the exemption axis.
#   * a checkout under any ancestor directory named ``tests`` made the whole
#     gate vacuous for absolute-path invocations.
#
# Resolving first fixes both: the component check runs on the real location.
_TEST_DIR_NAME: str = "tests"


def _is_exempt(path: Path) -> bool:
    """Return True if ``path`` is allowed to contain the disallowed patterns.

    **Resolve first, then match.** Every exemption decision is made against
    the resolved absolute path, so ``..`` traversal and symlinks cannot
    present one identity to the matcher and another to the reader.

    Exempt set:
      * the explicit authorised homes in ``_APPROVED_PATHS``, by resolved
        absolute-path equality — a file outside this repo that merely ends
        with ``src/alfred/security/tiers.py`` is NOT exempt;
      * any path under this repo's own ``tests/`` tree, matched by resolved
        path COMPONENTS relative to the repo root. CR-138 round-2 finding #1
        still holds: an in-repo ``test_*.py`` outside ``tests/`` is not
        exempt, so an attacker cannot ship ``src/alfred/foo/test_bypass.py``;
      * any ``test_*.py`` whose **resolved** path is outside this repo — the
        ``tmp_path`` fixtures the unit suite plants. Keyed on
        ``resolved.name``, NOT ``path.name``: an in-repo symlink named
        ``test_bypass.py`` pointing at an out-of-repo file previously
        satisfied the basename check with the LINK and the location check
        with the TARGET.
    """
    try:
        resolved = path.resolve(strict=False)
        # ``absolute()`` + ``normpath`` are pure-lexical and consult the same cwd
        # ``resolve()`` does, so they cannot fail once it has succeeded. They
        # share this guard rather than carrying an unreachable one of their own.
        lexical = Path(os.path.normpath(path.absolute()))
    except (OSError, RuntimeError, ValueError):
        # A path we cannot resolve is not one of the known-good homes.
        # ValueError is NOT redundant: an embedded NUL raises ValueError,
        # not OSError, on every supported platform.
        return False

    # Lexical normalisation collapses ``..`` WITHOUT following symlinks. Both
    # views are needed because they answer different questions:
    #
    #   * ``..`` traversal is a pure string problem  -> normalise lexically.
    #   * a symlink is a filesystem fact             -> resolve().
    #
    # Deciding on the RESOLVED path alone was a regression: a tracked symlink at
    # ``src/alfred/security/loader.py`` pointing into ``tests/`` bought exemption
    # for production code (measured rc=0 where the previous gate reported rc=1).
    # Deciding on the LEXICAL path alone reopens the ``..`` traversal. Both ends
    # of a symlink are author-controlled, so a path is exempt only when BOTH
    # views agree that it is — the stricter of the two always wins.
    return _view_is_exempt(lexical) and _view_is_exempt(resolved)


def _view_is_exempt(candidate: Path) -> bool:
    """Exemption verdict for ONE absolute view of a path. See :func:`_is_exempt`.

    ``candidate`` must already be absolute and free of ``..`` segments.
    """
    if candidate in _APPROVED_PATHS:
        return True

    if candidate.is_relative_to(_REPO_ROOT):
        # In-repo: exempt only by living under the repo's own TOP-LEVEL tests/
        # tree. Matching ``tests`` at any depth exempted production code —
        # ``src/alfred/security/tests/bypass.py`` is importable as
        # ``alfred.security.tests.bypass`` and was exempt. That hole predates
        # this gate's rewrite but the scan root now includes ``plugins/`` too,
        # so it is closed here rather than carried forward.
        parts = candidate.relative_to(_REPO_ROOT).parts
        return bool(parts) and parts[0] == _TEST_DIR_NAME

    # Out-of-repo: the tmp_path fixture exemption. Keyed on this view's own
    # basename so a symlink cannot borrow a ``test_*`` name it does not own.
    return candidate.name.startswith("test_") and candidate.suffix == ".py"


def _call_name(node: ast.Call) -> str | None:
    """Return the bare callable name for ``node`` (e.g. ``tag``, ``cast``).

    Both shapes resolve to the same callable name from the gate's POV:

    - ``tag(T3, ...)``        → ``ast.Name(id="tag")``      → ``"tag"``
    - ``module.tag(T3, ...)`` → ``ast.Attribute(attr="tag")`` → ``"tag"``
    - ``typing.cast(...)``    → ``ast.Attribute(attr="cast")`` → ``"cast"``

    Returns ``None`` for any other shape (subscript, lambda call, etc.) —
    those are not the patterns the gate is looking for.

    CR-138 round-2 finding #2: prior versions returned ``None`` for any
    ``ast.Attribute`` target, so qualified calls like ``module.tag(T3,
    ...)`` or ``typing.cast(TaggedContent[T2], x)`` silently bypassed
    both ``_is_tag_t3_call`` and ``_is_cast_tagged_content_call``. The
    import-rename attack (``from … import tag as t; t(T3, x)``) remains
    out of scope — the renamed binding still trips the suppression-
    comment rule whenever a cast-style suppressor is added.
    """
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return None


def _arg_name(node: ast.expr) -> str | None:
    """Return the bare identifier for ``node`` (e.g. ``T3``, ``TaggedContent``).

    Mirrors :func:`_call_name` on the argument side: both ``T3`` and
    ``tiers.T3`` resolve to the identifier ``"T3"``. Without this, the
    qualified-call widening from CR-138 round-2 finding #2 would only
    cover the call target — the first positional arg pattern
    ``module.T3`` would still slip past.
    """
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _is_tag_t3_call(node: ast.Call) -> bool:
    """``tag(T3, ...)`` — first positional arg is the identifier ``T3``.

    Accepts both the bare ``T3`` (``ast.Name``) and the qualified
    ``module.T3`` (``ast.Attribute``) form via :func:`_arg_name`. The
    qualified-call widening for CR-138 round-2 finding #2 covers the
    callable target; this helper covers the matching arg shape so the
    pair stays consistent (``tiers.tag(tiers.T3, ...)`` is the most
    natural qualified form an author would write).
    """
    if _call_name(node) != "tag":
        return False
    if not node.args:
        return False
    return _arg_name(node.args[0]) == "T3"


def _is_tagged_content_t3_subscript_call(node: ast.Call) -> bool:
    """``TaggedContent[T3](...)`` — direct subscript construction.

    Matches:

    - ``TaggedContent[T3](...)``           — bare name + bare T3
    - ``tiers.TaggedContent[T3](...)``     — qualified Attribute target
    - ``TaggedContent[tiers.T3](...)``     — qualified Attribute slice
    - ``tiers.TaggedContent[tiers.T3](...)`` — both qualified
    - ``TaggedContent["T3"](...)``         — quoted string-form generic
    - ``tiers.TaggedContent["T3"](...)``   — qualified target + quoted slice

    sec-S3-002: ``tag_t3_with_nonce`` checks the per-process nonce; the
    ``TaggedContent`` Pydantic field validator does NOT. A direct
    subscript-construction call therefore admits raw T3 content without
    the gate. The two authorised homes (``security/tiers.py`` for the
    ``tag_t3_with_nonce`` body, ``security/quarantine.py`` for the
    boundary that bridges T3 → T3DerivedData) are exempted via
    ``_APPROVED_PATHS``; everywhere else this pattern trips the gate.

    The call target ``func`` is an ``ast.Subscript`` whose ``value`` is
    the identifier ``TaggedContent`` (covering bare + qualified forms
    via :func:`_arg_name`) and whose ``slice`` is the identifier ``T3``
    (covering bare + qualified forms the same way). CR-142 round-3
    extension: the quoted ``"T3"`` form parses as an ``ast.Constant``
    rather than an ``ast.Name``, so :func:`_arg_name` returns ``None``
    for it. Detect the quoted form explicitly so authors cannot bypass
    the gate by string-quoting the generic argument.
    """
    func = node.func
    if not isinstance(func, ast.Subscript):
        return False
    if _arg_name(func.value) != "TaggedContent":
        return False
    if _arg_name(func.slice) == "T3":
        return True
    # Quoted string-form generic: ``TaggedContent["T3"](...)`` parses
    # the slice as ``ast.Constant("T3")``. Without this branch the gate
    # admits the string-quoted bypass that mirrors the
    # ``cast("TaggedContent[T2]", x)`` shape already covered in
    # :func:`_is_cast_tagged_content_call`.
    if isinstance(func.slice, ast.Constant) and isinstance(func.slice.value, str):
        return func.slice.value == "T3"
    return False


def _is_cast_tagged_content_call(node: ast.Call) -> bool:
    """``cast(TaggedContent[...], ...)`` — first arg subscripts ``TaggedContent``.

    Accepts:

    - ``cast(TaggedContent[T2], x)``           — bare name
    - ``cast(tiers.TaggedContent[T2], x)``     — qualified Attribute
    - ``typing.cast(TaggedContent[T2], x)``    — qualified call target (covered by ``_call_name``)
    - ``cast("TaggedContent[T2]", x)``         — string-form generic

    The qualified subscript form (``tiers.TaggedContent[T2]``) is the
    matching round-2 finding #2 widening on the argument side: without
    it, an author who imports the security module and casts via
    ``tiers.TaggedContent[T2]`` would skip the gate.
    """
    if _call_name(node) != "cast":
        return False
    if not node.args:
        return False
    first = node.args[0]
    if isinstance(first, ast.Subscript):
        # ``_arg_name`` collapses ``ast.Name`` and ``ast.Attribute`` to the
        # same identifier so qualified subscripts also match.
        return _arg_name(first.value) == "TaggedContent"
    if isinstance(first, ast.Constant) and isinstance(first.value, str):
        # String-form generic: the parser keeps it as a literal, so look
        # for the same syntactic shape inside the constant.
        return "TaggedContent[" in first.value
    return False


def _scan_text(text: str, path: Path) -> list[str]:
    """Return violation messages for ``text``, attributed to ``path``.

    Pure: performs no filesystem access and applies no exemption — ``path`` is
    a label for the messages, not something this function reads.

    Split out of :func:`_scan_file` (#537) for two reasons:

    1. Tests can feed *mutated real source* under its REAL path. A ``tmp_path``
       copy of this script would recompute ``_REPO_ROOT`` from ``__file__`` and
       silently invert every exemption, so a copy-based test measures the
       wrong tree while still passing.
    2. It lets the suite run the scanner in-process, which is what makes a
       100%-coverage gate on this file achievable at all: a ``subprocess`` run
       records nothing without ``COVERAGE_PROCESS_START``, and the pre-existing
       suites are entirely subprocess-based (measured: 0% coverage).

    Two-pass scan:

    1. AST walk for ``tag(T3, ...)`` and ``cast(TaggedContent[...], ...)``
       calls — multiline-safe by construction (the parser doesn't care
       about line breaks inside a call).
    2. Per-line regex for ``# type: ignore`` on a ``TaggedContent`` line —
       comments are discarded by the parser, so they need the line-based
       scan.
    """
    violations: list[str] = []
    lines = text.splitlines()

    try:
        tree = ast.parse(text, filename=str(path))
    except SyntaxError as exc:
        # A file the parser cannot read is a file this gate is not gating.
        # Returning early skips the line-based suppression pass, which is
        # correct: a half-parsed view of a broken file is exactly what the
        # previous comment here warned against — the difference is that we now
        # REPORT it instead of passing it.
        return [f"{path}:{exc.lineno or 1}: {_UNPARSEABLE_MESSAGE}", f"  {exc.msg}"]

    # No ``if tree is not None`` guard: the SyntaxError arm above RETURNS, so
    # ``tree`` is always a parsed module here. The guard was a leftover from the
    # shape where an unparseable file set ``tree = None`` and fell through — it
    # became unreachable when that became a violation, and an unreachable branch
    # is a coverage hole that a pragma would hide rather than fix.
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        lineno = node.lineno
        snippet = lines[lineno - 1].rstrip() if 0 <= lineno - 1 < len(lines) else ""
        if _is_tag_t3_call(node):
            violations.append(f"{path}:{lineno}: {_TAG_T3_MESSAGE}")
            violations.append(f"  {snippet}")
        if _is_cast_tagged_content_call(node):
            violations.append(f"{path}:{lineno}: {_CAST_TAGGED_CONTENT_MESSAGE}")
            violations.append(f"  {snippet}")
        if _is_tagged_content_t3_subscript_call(node):
            violations.append(f"{path}:{lineno}: {_TAGGED_CONTENT_T3_SUBSCRIPT_MESSAGE}")
            violations.append(f"  {snippet}")

    for lineno, line in enumerate(lines, 1):
        if _TYPE_IGNORE_PATTERN.search(line):
            violations.append(f"{path}:{lineno}: {_TYPE_IGNORE_MESSAGE}")
            violations.append(f"  {line.rstrip()}")

    return violations


def _scan_file(path: Path) -> list[str]:
    """Return a list of violation messages for ``path``. Empty list = clean.

    Applies the exemption, reads the source, and delegates the scanning to
    :func:`_scan_text`.
    """
    if _is_exempt(path):
        return []
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return [f"{path}:1: {_UNDECODABLE_MESSAGE}", "  <undecodable>"]
    except OSError as exc:
        return [f"{path}:1: {_UNREADABLE_MESSAGE}", f"  {exc.strerror or exc}"]
    return _scan_text(text, path)


def _warn_git_unavailable(directory: Path, why: str) -> None:
    """Announce a degradation to filesystem traversal on stderr.

    Every other "the gate could not do the thing it claims" condition here is
    loud; this one was mute. Falling back to ``rglob`` restores the traversal
    this gate exists to remove — it scans a superset so it cannot hide a
    violation, but the operator should know the default-deny derivation is not
    the one that ran.
    """
    print(
        f"check_tag_t3: {directory}: {why} — falling back to filesystem "
        f"traversal. The git-derived scan set (which honours .gitignore) is NOT "
        f"in effect for this path.",
        file=sys.stderr,
    )


class EmptyScanRootError(RuntimeError):
    """A directory argument yielded no Python files.

    Not an ordinary violation: it means the gate was pointed somewhere it
    cannot gate. Raised rather than returned so no caller can mistake it for
    a clean result.
    """


class PartialScanRootError(EmptyScanRootError):
    """An in-repo directory scan covered only SOME of ``_DEFAULT_SCAN_ROOTS``.

    A DISTINCT type, not a reuse of the parent (#541). The parent means "the
    gate was pointed at nothing"; this means "the gate was pointed at less
    than everything" — a different fault with a different remedy.

    Sharing one type collapsed a real oracle: with the per-directory floor in
    :func:`_collect_paths` deleted, ``_collect_paths(["build"])`` raised the
    partial-coverage error instead and the guard's dedicated regression test
    still passed. Tests must therefore discriminate with ``match=`` (and, for
    the parent, an ``isinstance`` exclusion) rather than on the base type.

    Subclasses ``EmptyScanRootError`` on purpose: :func:`main` already turns
    that into exit 2 ("the gate could not run"), which is the correct exit
    contract here too.
    """


def _git_tracked_python_files(directory: Path) -> list[Path] | None:
    """Return the tracked ``.py`` files under ``directory``.

    ``None`` means **git could not answer** (not a checkout, git absent, or a
    non-zero exit). An empty list means **git answered: nothing tracked here** —
    the distinction is load-bearing, see :func:`_collect_paths`.

    ``git ls-files`` is DEFAULT-DENY where an exclusion list is
    enumerate-and-hope: a file that is not tracked cannot land in a PR, and
    gitignored trees (the vendored ``plugins/alfred_tui/.venv`` — 856 of that
    tree's 895 ``.py`` files) disappear without anyone maintaining a list of
    directory names to skip.

    It also removes the filesystem traversal that let a symlinked package
    directory hide its whole subtree: ``Path.rglob`` does not recurse a
    symlinked directory met mid-walk. Tracked files are listed under their own
    real paths regardless of what links point at them.
    """
    try:
        # S603/S607: literal argv, no shell, no user-controlled executable. The
        # two codes are reported on DIFFERENT lines — S603 on the call, S607 on
        # the argv list — so a single combined noqa suppresses neither.
        proc = subprocess.run(  # noqa: S603
            # --cached lists the index; --others adds files that are NOT yet
            # tracked; --exclude-standard keeps .gitignore honoured so the
            # default-deny property survives. Without --others a brand-new file
            # was invisible to a directory scan until it was `git add`ed —
            # measured: an untracked src/alfred file containing
            # TaggedContent[T3](...) scanned rc=0, while the previous rglob gate
            # reported rc=1. CI is unaffected (it scans a committed merge ref),
            # so the loss was entirely in the local `make check` loop, which is
            # exactly where an author needs the gate to speak.
            [  # noqa: S607 — git is resolved from PATH by design; no user input
                "git",
                "ls-files",
                "--cached",
                "--others",
                "--exclude-standard",
                "-z",
                "--",
                str(directory),
            ],
            capture_output=True,
            check=False,
            cwd=_REPO_ROOT,
        )
    except (OSError, ValueError):
        _warn_git_unavailable(directory, "git could not be executed")
        return None
    if proc.returncode != 0:
        _warn_git_unavailable(directory, f"git exited {proc.returncode}")
        return None
    names = proc.stdout.decode("utf-8", errors="surrogateescape").split("\0")
    # --cached also lists index entries whose working-tree file is gone (a
    # deletion that has not been staged). Those cannot contain a violation, and
    # reporting them as unreadable would be noise rather than a finding.
    return [p for n in names if n.endswith(".py") if (p := _REPO_ROOT / n).is_file()]


def _collect_paths(argv: list[str]) -> list[Path]:
    """Expand the CLI arg list into a flat list of ``.py`` paths to scan.

    Explicit FILE arguments are returned unconditionally — the unit suite
    plants untracked fixtures in ``tmp_path`` and passes them by path, and
    swallowing those would make every one of those tests vacuous.

    Directory arguments inside the repo are derived from ``git ls-files``.
    **An in-repo directory git reports as empty RAISES rather than falling
    back to traversal**: falling back there would re-scan exactly the
    gitignored trees the derivation exists to exclude.

    Finally, an in-repo DIRECTORY scan must cover every root in
    ``_DEFAULT_SCAN_ROOTS`` or it raises :class:`PartialScanRootError`.
    """
    default_root = not argv
    if default_root:
        argv = list(_DEFAULT_SCAN_ROOTS)
    paths: list[Path] = []
    in_repo_directory_args: set[Path] = set()
    for arg in argv:
        candidate = Path(arg)
        if not candidate.is_dir():
            # Order matters: the default-root case gets the more specific,
            # more actionable message, so it is tested first.
            if default_root:
                # The DEFAULT root is resolved relative to CWD, so an
                # argument-less run from the wrong directory used to scan 0
                # files and exit 0. Treating a missing default root as an
                # ordinary file argument would report it as an unreadable
                # FILE, which describes the symptom rather than the fault.
                raise EmptyScanRootError(
                    f"{arg}: no Python files found — the default scan root does "
                    f"not exist relative to the current directory. Run the gate "
                    f"from the repository root, or pass an explicit path."
                )
            if not candidate.exists():
                # Neither a directory nor a file. Falling through to the file
                # branch reported it as an unreadable FILE (rc=1, the code that
                # means "violations found") — the wrong exit code and the wrong
                # diagnosis for a mistyped scan root.
                raise EmptyScanRootError(
                    f"{arg}: no such file or directory — the gate cannot scan it."
                )
            paths.append(candidate)
            continue

        found: list[Path] | None = None
        resolved = candidate.resolve(strict=False)
        if resolved.is_relative_to(_REPO_ROOT):
            # Recorded here rather than in a second pass so the runtime
            # invariant below reuses this exact in-repo verdict — a separate
            # walk would be a second predicate that could drift from this one.
            in_repo_directory_args.add(resolved)
            # Pass the REPO-RELATIVE path, not the caller's spelling.
            # ``_git_tracked_python_files`` runs git with ``cwd=_REPO_ROOT``, so a
            # relative argument that is valid in the caller's directory resolves
            # against the wrong base: from ``src/``, ``check_tag_t3.py alfred``
            # made git list 0 entries and the gate refused with "check whether it
            # is gitignored" for a 293-file tree. Fails closed, but diagnoses the
            # wrong fault.
            found = _git_tracked_python_files(resolved.relative_to(_REPO_ROOT))

        if found is None:
            # Out-of-repo directory (test fixtures), or git could not answer.
            # recurse_symlinks=True is required: without it a symlinked package
            # met MID-WALK is skipped silently, which is the bypass this change
            # exists to close.
            found = list(candidate.rglob("*.py", recurse_symlinks=True))

        # PER-DIRECTORY floor. The aggregate census in main() cannot catch an
        # empty scan root: ``src/alfred plugins`` yielding 293 + 0 still clears
        # a 250-file floor while gating zero plugin files. ``git ls-files``
        # exits 0 with empty output for an ignored, absent or submodule path,
        # so this is the only place that failure becomes visible.
        if not found:
            raise EmptyScanRootError(
                f"{arg}: no Python files found. The gate refuses to treat an "
                f"empty scan root as clean — check the path, and check whether "
                f"it is gitignored."
            )
        paths.extend(found)

    # RUNTIME INVARIANT (#541). The call-site pin is a LEXICAL layer, and
    # review defeated it lexically: a backslash line-continuation split the
    # argv across lines and slipped `src/alfred` through with `plugins`
    # dropped — proved against real `make`, `plugins/` ungated, rc=0. So the
    # property holds at RUNTIME too, where no amount of shell quoting reaches
    # it: an in-repo DIRECTORY scan must cover every declared root.
    #
    # TWO exemptions, both deliberate:
    #
    #   * OUT-OF-REPO directories. The unit suite plants `tmp_path` trees and
    #     scans them by path. Holding a fixture directory to THIS repo's root
    #     set would red every one of those tests while saying nothing about
    #     production, which only ever scans in-repo paths.
    #   * Explicit FILE arguments. `check_tag_t3.py path/to/one.py` is the
    #     single-file developer invocation and the shape every fixture-based
    #     test uses.
    #
    # The second exemption is a MEASURED RESIDUAL, not a closed hole: passing
    # the 293 tracked `src/alfred/**.py` files individually exits 0 with
    # `plugins` never scanned. This layer cannot see that. What closes it is
    # the call-site pin in `tests/unit/meta/test_gate_surfaces_are_pinned.py`,
    # which requires every invocation site to pass NO arguments at all — so
    # the enumeration cannot be written at a call site in the first place.
    # Neither layer is complete alone: the pin covers arguments of ANY shape
    # but only at the call sites it searches; the invariant covers directory
    # subsetting from ANYWHERE, including a call site nobody has pinned yet.
    if in_repo_directory_args:
        missing = [
            root
            for root in _DEFAULT_SCAN_ROOTS
            if (_REPO_ROOT / root).resolve(strict=False) not in in_repo_directory_args
        ]
        if missing:
            raise PartialScanRootError(
                f"directory scan does not cover every declared root: missing "
                f"{missing}. The roots are declared in _DEFAULT_SCAN_ROOTS; a "
                f"caller may not gate a subset of them."
            )
    return paths


def main(argv: list[str]) -> int:
    """Return 0 clean, 1 violations found, 2 the gate could not run.

    Exit 2 is deliberately distinct from 1: a caller must be able to tell
    "the gate failed" from "the gate never gated anything".
    """
    try:
        paths = sorted(_collect_paths(argv))
    except EmptyScanRootError as exc:
        print(f"check_tag_t3: {exc}", file=sys.stderr)
        return 2

    # The AGGREGATE census. The per-directory floor in `_collect_paths` catches
    # a root that yields zero files; this catches a directory scan that
    # resolved somewhere unexpected but non-empty. Explicit file arguments are
    # how the unit suite plants fixtures, so they are exempt — holding those to
    # a 250-file floor would red every one of them.
    scanned_a_directory = not argv or any(Path(a).is_dir() for a in argv)
    if scanned_a_directory and len(paths) < _MIN_SCANNED_FILES:
        print(
            f"check_tag_t3: scanned {len(paths)} files, expected at least "
            f"{_MIN_SCANNED_FILES}. The gate is not reaching the source tree "
            f"(wrong working directory, or the scan root moved) — refusing to "
            f"report success while gating nothing.",
            file=sys.stderr,
        )
        return 2

    all_violations: list[str] = []
    for path in paths:
        all_violations.extend(_scan_file(path))

    if all_violations:
        print("check_tag_t3: violations found:", file=sys.stderr)
        for line in all_violations:
            print(line, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
