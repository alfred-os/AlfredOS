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

If no arguments are given, scans ``src/alfred/`` recursively.
"""

from __future__ import annotations

import ast
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
    except (OSError, RuntimeError, ValueError):
        # A path we cannot resolve is not one of the known-good homes.
        # ValueError is NOT redundant: an embedded NUL raises ValueError,
        # not OSError, on every supported platform.
        return False

    if resolved in _APPROVED_PATHS:
        return True

    if resolved.is_relative_to(_REPO_ROOT):
        # In-repo: exempt only by living under the repo's own tests/ tree.
        return _TEST_DIR_NAME in resolved.relative_to(_REPO_ROOT).parts

    # Out-of-repo: the tmp_path fixture exemption. Keyed on the RESOLVED name
    # so a symlink cannot borrow a test_* basename it does not own.
    return resolved.name.startswith("test_") and resolved.suffix == ".py"


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

    if tree is not None:
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


class EmptyScanRootError(RuntimeError):
    """A directory argument yielded no Python files.

    Not an ordinary violation: it means the gate was pointed somewhere it
    cannot gate. Raised rather than returned so no caller can mistake it for
    a clean result.
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
            ["git", "ls-files", "-z", "--", str(directory)],  # noqa: S607
            capture_output=True,
            check=False,
            cwd=_REPO_ROOT,
        )
    except (OSError, ValueError):
        return None
    if proc.returncode != 0:
        return None
    names = proc.stdout.decode("utf-8", errors="surrogateescape").split("\0")
    return [_REPO_ROOT / n for n in names if n.endswith(".py")]


def _collect_paths(argv: list[str]) -> list[Path]:
    """Expand the CLI arg list into a flat list of ``.py`` paths to scan.

    Explicit FILE arguments are returned unconditionally — the unit suite
    plants untracked fixtures in ``tmp_path`` and passes them by path, and
    swallowing those would make every one of those tests vacuous.

    Directory arguments inside the repo are derived from ``git ls-files``.
    **An in-repo directory git reports as empty RAISES rather than falling
    back to traversal**: falling back there would re-scan exactly the
    gitignored trees the derivation exists to exclude.
    """
    if not argv:
        argv = ["src/alfred"]
    paths: list[Path] = []
    for arg in argv:
        candidate = Path(arg)
        if not candidate.is_dir():
            paths.append(candidate)
            continue

        found: list[Path] | None = None
        resolved = candidate.resolve(strict=False)
        if resolved.is_relative_to(_REPO_ROOT):
            found = _git_tracked_python_files(candidate)

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
    return paths


def main(argv: list[str]) -> int:
    all_violations: list[str] = []
    for path in sorted(_collect_paths(argv)):
        all_violations.extend(_scan_file(path))

    if all_violations:
        print("check_tag_t3: violations found:", file=sys.stderr)
        for line in all_violations:
            print(line, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
