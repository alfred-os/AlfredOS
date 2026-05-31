#!/usr/bin/env python3
"""CI grep gate: reject unauthorised ``tag(T3`` and ``cast(TaggedContent[`` uses.

Invoked by ``make check`` and CI. Exits 0 if clean; exits 1 with violation
messages if any non-approved file contains:

- ``tag(T3, ...)``           — direct calls to the capability-gated factory
                               from outside the two approved homes
                               (``security/tiers.py`` and
                               ``security/quarantine.py``).
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
import sys
from pathlib import Path

# Line-based pattern. ``# type: ignore`` on a line containing
# ``TaggedContent`` is fundamentally a comment-and-line construct: the
# parser discards comments so AST detection cannot see them. Multiline
# bypass via newline-in-call is not relevant here either (the suppression
# applies to a specific physical line).
_TYPE_IGNORE_PATTERN: re.Pattern[str] = re.compile(r"TaggedContent.*#\s*type:\s*ignore")
_TYPE_IGNORE_MESSAGE: str = (
    "# type: ignore on TaggedContent line — fix the type, don't suppress"
)

# AST-detected call-site violations. Each entry describes the call name
# and the shape of its first positional argument; ``_node_matches`` decides
# whether a given ``ast.Call`` node trips the rule.
_TAG_T3_MESSAGE: str = (
    "tag(T3, ...) direct call — use tag_t3_with_nonce() with injected nonce"
)
_CAST_TAGGED_CONTENT_MESSAGE: str = (
    "cast(TaggedContent[...]) — use AnyTaggedContent for observers (spec §3.3)"
)

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

# Test paths are always exempt. Tests assert the patterns the gate forbids.
_TEST_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(^|/)tests/"),
    re.compile(r"(^|/)test_[^/]+\.py$"),
)


def _is_exempt(path: Path) -> bool:
    """Return True if ``path`` is allowed to contain the disallowed patterns.

    Exempt set:
      * any path under a ``tests/`` directory (regex on string form,
        because test files can live in ``tmp_path`` for fixtures),
      * any ``test_*.py`` filename (catches tmp-path test fixtures),
      * the explicit authorised homes in ``_APPROVED_PATHS`` — matched
        by resolved absolute-path equality, not suffix. A file outside
        this repo that happens to end with ``src/alfred/security/tiers.py``
        is NOT exempt.
    """
    # Normalise to forward slashes so the regex checks work the same on
    # POSIX and (theoretically) Windows checkouts.
    path_str = str(path).replace("\\", "/")
    for pat in _TEST_PATTERNS:
        if pat.search(path_str):
            return True

    # Resolve the path to an absolute realpath (follows symlinks,
    # collapses ``..``). Compare against the pre-resolved approved set.
    # Resolution may fail for paths that do not exist on disk (the
    # script can be passed a deleted file from a stale arg list); in
    # that case the file cannot be the real authorised home, so fall
    # through to "not exempt".
    try:
        resolved = path.resolve(strict=False)
    except (OSError, RuntimeError):
        return False
    return resolved in _APPROVED_PATHS


def _call_name(node: ast.Call) -> str | None:
    """Return the bare callable name for ``node`` (e.g. ``tag``, ``cast``).

    Returns ``None`` if the call's target is not a simple ``Name`` node —
    e.g. ``module.tag(T3, ...)`` deliberately falls through because the
    convention in this codebase is that the two forbidden patterns are
    invoked by their bare names and the import-rename attack
    (``from … import tag as t; t(T3, x)``) is out of scope (the renamed
    binding still trips the suppression-comment rule whenever a
    cast-style suppressor is added).
    """
    if isinstance(node.func, ast.Name):
        return node.func.id
    return None


def _is_tag_t3_call(node: ast.Call) -> bool:
    """``tag(T3, ...)`` — first positional arg is the bare name ``T3``."""
    if _call_name(node) != "tag":
        return False
    if not node.args:
        return False
    first = node.args[0]
    return isinstance(first, ast.Name) and first.id == "T3"


def _is_cast_tagged_content_call(node: ast.Call) -> bool:
    """``cast(TaggedContent[...], ...)`` — first arg is a Subscript of ``TaggedContent``.

    Also matches ``cast("TaggedContent[T2]", x)`` (the string-form generic
    used to suppress mypy's TypeVar complaint) — the literal substring
    ``TaggedContent[`` inside the constant string is the same provenance
    erasure as the live form.
    """
    if _call_name(node) != "cast":
        return False
    if not node.args:
        return False
    first = node.args[0]
    if isinstance(first, ast.Subscript):
        value = first.value
        return isinstance(value, ast.Name) and value.id == "TaggedContent"
    if isinstance(first, ast.Constant) and isinstance(first.value, str):
        # String-form generic: the parser keeps it as a literal, so look
        # for the same syntactic shape inside the constant.
        return "TaggedContent[" in first.value
    return False


def _scan_file(path: Path) -> list[str]:
    """Return a list of violation messages for ``path``. Empty list = clean.

    Two-pass scan:

    1. AST walk for ``tag(T3, ...)`` and ``cast(TaggedContent[...], ...)``
       calls — multiline-safe by construction (the parser doesn't care
       about line breaks inside a call).
    2. Per-line regex for ``# type: ignore`` on a ``TaggedContent`` line —
       comments are discarded by the parser, so they need the line-based
       scan.
    """
    violations: list[str] = []
    if _is_exempt(path):
        return violations
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        # Unreadable files are not violations — the type-checker / linter
        # will catch them elsewhere. This script is for grep-level patterns
        # only.
        return violations

    lines = text.splitlines()

    try:
        tree = ast.parse(text, filename=str(path))
    except SyntaxError:
        # A file the parser cannot read is not a violation: ruff / mypy /
        # the test suite will catch it. We do NOT fall back to the legacy
        # per-line regex here — silently accepting a syntactically broken
        # file is safer than scanning a half-parsed view of it.
        tree = None

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

    for lineno, line in enumerate(lines, 1):
        if _TYPE_IGNORE_PATTERN.search(line):
            violations.append(f"{path}:{lineno}: {_TYPE_IGNORE_MESSAGE}")
            violations.append(f"  {line.rstrip()}")

    return violations


def _collect_paths(argv: list[str]) -> list[Path]:
    """Expand the CLI arg list into a flat list of ``.py`` paths to scan."""
    if not argv:
        return list(Path("src/alfred").rglob("*.py"))
    paths: list[Path] = []
    for arg in argv:
        candidate = Path(arg)
        if candidate.is_dir():
            paths.extend(candidate.rglob("*.py"))
        else:
            paths.append(candidate)
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
