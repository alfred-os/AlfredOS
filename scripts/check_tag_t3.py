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
#
# CR-138 round-2 finding #1: the previous ``test_[^/]+\.py$`` pattern
# exempted ANY file whose basename started with ``test_`` regardless of
# location. A non-test file at ``src/alfred/foo/test_bypass.py`` would
# have slipped through the gate. The fix narrows the basename
# exemption to paths OUTSIDE the repo root (``tmp_path`` fixtures and
# similar) — in-repo ``test_*.py`` files must live under ``tests/`` to
# be exempt by directory, not by name alone.
_TEST_PATTERNS: tuple[re.Pattern[str], ...] = (re.compile(r"(^|/)tests/"),)


def _is_exempt(path: Path) -> bool:
    """Return True if ``path`` is allowed to contain the disallowed patterns.

    Exempt set:
      * any path under a ``tests/`` directory (regex on string form,
        because test files can live in ``tmp_path`` for fixtures
        whose path includes a ``/tests/`` segment),
      * any ``test_*.py`` file whose **resolved absolute path is OUTSIDE
        this repo** — this covers ``tmp_path`` test fixtures the unit
        suite plants under e.g. ``/private/var/folders/.../test_foo.py``.
        In-repo ``test_*.py`` files (basename-only match) are NOT exempt;
        they must live under ``tests/`` to qualify.
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

    # Out-of-repo ``test_*.py`` fixtures (tmp_path planted files etc.)
    # are exempt — they are genuine test artefacts the suite creates to
    # exercise the gate. In-repo ``test_*.py`` files outside ``tests/``
    # are NOT exempt: this would be an attacker shipping a file named
    # ``test_bypass.py`` under ``src/`` to dodge the grep gate.
    if (
        path.name.startswith("test_")
        and path.suffix == ".py"
        and not resolved.is_relative_to(_REPO_ROOT)
    ):
        return True

    return resolved in _APPROVED_PATHS


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
            if _is_tagged_content_t3_subscript_call(node):
                violations.append(f"{path}:{lineno}: {_TAGGED_CONTENT_T3_SUBSCRIPT_MESSAGE}")
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
