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
import errno
import os
import re
import stat
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

# ---------------------------------------------------------------------------
# #538 — THE SOLE-LAYER RULES.
#
# The runtime CANNOT refuse these. Raw state writes never traverse any method the
# model can override (`frozen=True` observes `__setattr__`, and none of these reach
# it), so no seam is left to guard. The authoring layer is the ONLY enforcement layer
# that can exist for them.
#
# DEFAULT-DENY THE VEHICLE OR THE SHAPE, NEVER ENUMERATE THE SPELLING. Round-2 probes
# minted two genuine `TaggedContent[T3]` objects with attacker-controlled content from
# a file that scanned clean under BOTH the merged detector AND a fully enumerated rule
# set. The decisive spelling:
#
#     object.__setattr__(obj, "__dict__", {..., "tier": T3})
#
# An earlier constraints doc mandated "key on the written `tier` attribute, not on the
# call". That rule cannot see this line BY CONSTRUCTION — the attribute written is
# `__dict__`.
#
# AND THE SAME MISTAKE RECURRED INSIDE THE FIX: the first revision of these rules
# matched the receiver as the bare identifier `object`, so `builtins.object.__setattr__`,
# `_o = object` and `from builtins import object as _o` all scanned clean. The review
# fleet executed all three and minted T3. Hence receiver-BLIND matching on
# `__setattr__`, and hence `_alias_names` on every other identifier a rule keys on.
_RAW_STATE_VEHICLE_ATTRS: frozenset[str] = frozenset(
    {
        "__dict__",
        "__setstate__",
        "__getstate__",
        "__reduce__",
        "__reduce_ex__",
        "__new__",
        "__mro__",
        "__bases__",
    }
)

# Vehicles when NAMED AS A STRING. DELIBERATELY WIDER than the attribute set above.
# `getattr(object, "__setattr__")(low, "tier", T3)` produces NO `ast.Attribute` node at
# all, so every attribute-keyed rule is blind to it — executed, it turned a
# TaggedContent[T2] into T3. `__setattr__` must NOT join the attribute set: the three
# live benign `object.__setattr__(...)` sites all carry that attribute node, and the
# receiver-blind rules below already cover the attribute form.
_RAW_STATE_VEHICLE_NAMES: frozenset[str] = _RAW_STATE_VEHICLE_ATTRS | frozenset(
    {"__setattr__", "__delattr__", "__class__"}
)

# The `TaggedContent` state fields no `__setattr__` call may write, whatever its target.
# `metadata` is deliberately ABSENT — `hooks/context.py:106` writes it on a `HookContext`,
# an unrelated frozen dataclass sharing the field name. Banning it would red a legitimate
# site for a name collision, and the residual cannot change `tier`, `content` or
# `source`, so it can neither mint nor relabel T3.
_TAGGED_STATE_FIELDS: frozenset[str] = frozenset({"tier", "content", "source"})

# Reaching PRIMITIVES that hand back an object's raw state. Scoped to the primitive,
# not the module: banning `gc` and `ctypes` outright costs two legitimate sites
# (`ctypes.CDLL` for libc in `supervisor/process_posture.py`, `gc.collect()` in
# `fd3_key_delivery.py`) while this form costs ZERO. The class is "primitives that
# hand back raw state", not "modules that happen to contain one".
_RAW_STATE_CARRIERS: frozenset[tuple[str, str]] = frozenset(
    {
        ("gc", "get_referents"),
        ("gc", "get_objects"),
        ("ctypes", "py_object"),
        ("ctypes", "cast"),
        ("copyreg", "_reconstructor"),
        ("copyreg", "__newobj__"),
    }
)

# Seam methods that write field state when dispatched with the CLASS as receiver.
# `copy` is pydantic v1's spelling and does NOT route through `model_copy` (it merges
# `update` inside `copy_internals`); the `model_validate*` pair is included because a
# wire round-trip is a construction path.
_BASEMODEL_SEAM_ATTRS: frozenset[str] = frozenset(
    {"copy", "model_copy", "model_construct", "model_validate", "model_validate_json"}
)

_RAW_VEHICLE_ATTR_MESSAGE: str = (
    "raw-state vehicle attribute — reaches instance state without traversing any "
    "method the model can guard. Use tag_t3_with_nonce()."
)
_RAW_VEHICLE_VARS_MESSAGE: str = (
    "vars() exposes the instance mapping directly — the same unguarded reach as "
    "__dict__. Use tag_t3_with_nonce()."
)
_RAW_VEHICLE_STR_MESSAGE: str = (
    "a raw-state vehicle named as a string in code position — getattr() and friends "
    "reach it without an attribute node. Use tag_t3_with_nonce()."
)
_RAW_SETATTR_SHAPE_MESSAGE: str = (
    "__setattr__ call whose target is not `self` or whose field name is computed, "
    "dunder or a TaggedContent state field — bypasses frozen=True and every tier guard."
)
_RAW_SETATTR_ALIASED_MESSAGE: str = (
    "__setattr__ referenced outside direct-call position — an alias defeats any rule "
    "keyed on the call. Call it inline on `self` with a literal field name."
)
_RAW_CLASS_SWAP_MESSAGE: str = (
    "assignment to __class__ — retypes a live object past every constructor guard. "
    "Build the right type instead."
)
_RAW_CARRIER_MESSAGE: str = (
    "a carrier primitive that hands back an object's raw state mapping — reaches "
    "instance state while naming no attribute. Use tag_t3_with_nonce()."
)
_BASEMODEL_VALUE_MESSAGE: str = (
    "unbound BaseModel seam dispatch — builds field state through "
    "_copy_and_set_values, reaching neither the class overrides nor model_post_init. "
    "Call the seam on the INSTANCE, or use tag_t3_with_nonce()."
)
_ALIAS_BUDGET_MESSAGE: str = (
    "alias chain deeper than the resolver's budget — the gate cannot decide what "
    "these names are bound to. Simplify the aliasing."
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
# FIVE DISTINCT strings so a test for one cannot be satisfied by another
# firing. Measured false-positive cost across the scan root: 0 unparseable,
# 0 unreadable, 0 unscannable.
#
# The fifth exists because ONE string used to cover both the parser arm in
# :func:`_scan_text` and the path arm in :func:`_scan_file`, so it had to
# suggest two remedies ("Simplify the file, or fix the path") of which the
# wrong one was always half the advice (#543 review, dx-003). Splitting them
# matches the ``_UNPARSEABLE``/``_UNREADABLE`` pair already here.
_UNDECODABLE_MESSAGE: str = (
    "file is not valid UTF-8 — the gate cannot read it but Python can execute "
    "it (PEP 263 coding declaration). Re-encode as UTF-8."
)
_UNPARSEABLE_MESSAGE: str = "file does not parse — the gate cannot scan it. Fix the syntax error."
_UNREADABLE_MESSAGE: str = "file could not be read — the gate cannot scan it."
_UNSCANNABLE_MESSAGE: str = (
    "file could not be scanned — the parser failed on its CONTENT. Simplify the file."
)
_UNSCANNABLE_PATH_MESSAGE: str = (
    "file could not be scanned — the reader failed on its PATH, before any "
    "content was read. Fix the path."
)

# The REASON line under `_UNREADABLE_MESSAGE` for a non-regular file (#546),
# where every other cause supplies the OS's own `strerror`. Deliberately NOT
# named `*_MESSAGE`: `test_every_collection_failure_message_is_enumerated`
# derives the collection-failure set from names with that suffix, and this is
# a reason under an existing message, not a sixth message.
_NOT_A_REGULAR_FILE_REASON: str = "not a regular file"

# NOT a collection-failure message: this one says the GATE is broken, not the
# file (#543 review, err-001). It travels on :class:`GateInternalError`, which
# `main` turns into exit 2 ("the gate could not run") rather than exit 1
# ("violations found") — the distinction the exit contract exists for.
_GATE_INTERNAL_MESSAGE: str = (
    "the gate's own detector raised while scanning this file. This is a BUG IN "
    "check_tag_t3.py, not a finding in the file. The scan is abandoned: no "
    "file's verdict is trustworthy while a detector predicate is faulting."
)

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
#   * A DECOY TREE **no longer lands here at all** (#543 review, sec-002).
#     The text this replaces claimed a decoy was "caught by this floor alone.
#     Measured: 2 files scanned, rc=2" — true of a 2-file decoy and FALSE of a
#     realistic one. Security review built a 260-file clean decoy, reached
#     through an in-repo symlink so both roots resolved OUTSIDE the repo and
#     the runtime invariant exempted them by design, and measured **rc=0 with
#     zero bytes of src/alfred or plugins scanned**: the floor is 250 and a
#     real copy of this repo holds 332 files under the two roots, so any decoy
#     of realistic size cleared it. A count was the wrong instrument — it has a
#     margin, and the margin was widening. The property itself now lives in
#     :func:`_collect_paths`: on the argument-less path, EVERY declared root
#     must resolve INSIDE this repo.
#
#     Stated over a SAMPLE of the collected files instead — "at least one
#     collected file resolves inside" — it had a margin after all, and #548
#     review found it: ``rglob`` runs with ``recurse_symlinks=True``, so a
#     decoy holding ONE link to any real repo ``.py`` file satisfied the
#     ``any(...)``. Measured rc=0, 261 files collected, 1 inside this repo and
#     260 decoy files carrying every verdict. The root form is what the
#     paragraph above always claimed; only the code was weaker.
#   * A GUTTED in-repo tree: both roots present and covered, but mass-deleted
#     below the floor. This is what the floor still catches, and all it
#     catches.
#
# 332 tracked ``.py`` files live under the two roots today (293 + 39); 250
# leaves headroom for deletions without leaving room for the gate to go
# vacuous. Unchanged at 250 by #541 and #543 — it is not, and never was, a
# check that every root was supplied, nor (as of #543) the decoy defence; that
# is what ``_DEFAULT_SCAN_ROOTS`` plus the two runtime invariants are for.
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


# Bounded, and deliberately INPUT-INDEPENDENT. A bound of `len(assignments) + 1`
# makes the loop-exhaustion arc unreachable BY CONSTRUCTION — the fixed point always
# converges first — and this file is under a REQUIRED 100% branch gate with no
# pragmas allowed, so an unreachable arc is an unsatisfiable gate, not a safe
# default. A fixed budget makes exhaustion a real outcome a test can reach, and the
# honest disposition for it is a reported violation: the input is pathological, not
# the gate (contrast `GateInternalError`, which means the gate itself is broken).
_ALIAS_RESOLUTION_BUDGET: int = 32

# `_fold_str` recurses once per nested operand, and it is called from inside
# `_scan_text`'s `GateInternalError` fence, where an exception means "the GATE is
# broken": `main` prints it, DISCARDS every violation collected so far and exits 2.
# So an unbounded fold turns one pathological `+` chain (~2000 operands raises
# RecursionError under the default limit) into the suppression of a real laundering
# finding in an EARLIER file. Bounding here keeps the fence meaning what it says.
#
# Past the bound `_fold_str` returns None, which every caller reads as "not a string
# literal". The cost is therefore local and one-directional: a name assembled by a
# chain that deep is not matched, exactly as a name assembled by `%`, `.format()` or
# `"".join()` is not matched — an already-stated residual, not a new class.
#
# Its OWN constant rather than a reuse of `_ALIAS_RESOLUTION_BUDGET`: one bounds a
# fixed-point iteration over a file's assignments, the other bounds expression
# nesting. Sharing a name would let a future retune of either silently move the other.
_FOLD_MAX_DEPTH: int = 32


def _prose_string_ids(tree: ast.AST) -> frozenset[int]:
    """``id()`` of every string constant that is PROSE rather than code.

    Prose is a **bare string expression statement**: a module, class or function
    docstring, or a PEP-258 attribute docstring (a bare string after an assignment).
    ``ast.get_docstring`` covers only the first three; ``src/alfred/hooks/invoke.py:466``
    is the fourth shape and is a MEASURED false positive without it.

    WHY NOT exclude every string constant: ``getattr(_t, "_set_authorized_t3_nonce")``
    hides the name in a string ARGUMENT. Excluding all strings would admit it. The
    discriminator is POSITION — a string that is a whole statement documents; a string
    anywhere else is data the program uses.

    WHAT THIS CANNOT DO: a ``#`` comment is invisible to the parser, so a private name
    there is neither prose-excluded nor flagged. Correct (a comment cannot launder) but
    a different mechanism from this one.
    """
    return frozenset(
        id(node.value)
        for node in ast.walk(tree)
        if isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Constant)
        and isinstance(node.value.value, str)
    )


def _enclosing_functions(tree: ast.AST) -> dict[int, str]:
    """Map every line to its INNERMOST enclosing function name.

    Module-scope lines are ABSENT from the map, which is load-bearing: the
    module-level import exemption keys on ``.get(lineno) is None``.

    **Both ``def`` and ``async def``**, in ONE ``isinstance`` over the tuple. A walk
    matching only ``ast.FunctionDef`` silently maps nothing for ``async def`` and no
    test in this repo fails — the sole real (path, function) exemption is a plain
    ``def``. One tuple check also means the 332-file real-tree scan exercises both
    node types, so the branch cannot rot behind a fixture.

    ``ast.walk`` is breadth-first, so a nested function is visited AFTER the function
    containing it and correctly overwrites its parent's lines.
    """
    mapping: dict[int, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            # MEASURED, not assumed: the parser sets `end_lineno` on every function it
            # produces — 13 381 function defs across the 1 211 tracked `.py` files in
            # this repo, zero of them None. typeshed types it `int | None` because a
            # HAND-BUILT node (constructed, never parsed) leaves it None, and this gate
            # only ever sees `ast.parse` output.
            #
            # ASSERTED, not defaulted. An `x if x is not None else node.lineno` fallback
            # would silently truncate the map on the one input that could reach it, and
            # `coverage.py` does not branch on a conditional expression — so that dead
            # arm would be invisible to this file's REQUIRED 100% branch gate, exempting
            # by construction precisely what the no-pragma rule forbids exempting.
            assert node.end_lineno is not None
            for line in range(node.lineno, node.end_lineno + 1):
                mapping[line] = node.name
    return mapping


def _fold_str(node: ast.expr, depth: int = 0) -> str | None:
    """Constant-fold a string expression, or ``None`` if it is not a literal.

    ``ast.parse`` folds IMPLICIT concatenation (``"a" "b"``) into one ``Constant`` but
    leaves ``"a" + "b"`` as a ``BinOp``. Matching raw ``Constant`` nodes therefore
    missed ``"_set_authorized" + "_t3_nonce"``, which the review fleet executed
    end-to-end: it registered an attacker nonce and minted a fully legitimate
    ``TaggedContent[T3]`` for attacker content through ``tag_t3_with_nonce``.

    Recursion is bounded by ``_FOLD_MAX_DEPTH`` rather than by the input's own depth,
    because this runs inside ``_scan_text``'s ``GateInternalError`` fence — see that
    constant for why an unbounded fold suppresses findings in OTHER files.

    RESIDUAL, stated rather than implied: this folds ``+`` and implicit concatenation
    and nothing else. ``"_set_authorized%s" % "_t3_nonce"``,
    ``"_set_authorized{}".format("_t3_nonce")`` and ``"".join([...])`` are assembled
    entirely from literals and all fold to ``None`` here.

    Deliberately NOT ``ast.literal_eval``: that evaluates tuples, dicts and numbers
    too, so it would answer a different question and raise on the common case.
    """
    if depth > _FOLD_MAX_DEPTH:
        return None
    if isinstance(node, ast.Constant):
        return node.value if isinstance(node.value, str) else None
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _fold_str(node.left, depth + 1)
        right = _fold_str(node.right, depth + 1)
        return None if left is None or right is None else left + right
    if isinstance(node, ast.JoinedStr):
        parts: list[str] = []
        for value in node.values:
            folded = _fold_str(value, depth + 1)
            if folded is None:
                return None
            parts.append(folded)
        return "".join(parts)
    return None


def _alias_names(tree: ast.AST, seed: str) -> tuple[frozenset[str], bool]:
    """Local names bound to ``seed``, to a fixed point. Returns (names, overflowed).

    Two binding forms: ``from m import X as Y`` and a plain ``B = X`` rebind, including
    chains. THE FIXED POINT IS PROVEN REQUIRED: with ``C = B`` written BEFORE
    ``B = BaseModel``, a single pass yields ``{BaseModel, B}`` and misses ``C``. Source
    order is the author's to choose, so a resolver that depends on it is one an attacker
    controls.

    Parameterised by ``seed`` because more than one rule needs it. v1 built this for
    ``BaseModel`` only and matched every other identifier bare, so ``_g = gc``,
    ``from gc import get_referents`` and ``_v = vars`` all scanned clean — and on the
    ``object`` receiver, executed, they minted genuine T3 objects with attacker content.

    RESIDUAL: the alias set is PER-FILE. A name re-exported through another module and
    imported under its new spelling is not resolved here.
    """
    names = {seed}
    assignments: list[tuple[str, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.alias) and node.name == seed and node.asname is not None:
            names.add(node.asname)
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Name):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    assignments.append((target.id, node.value.id))
    for _ in range(_ALIAS_RESOLUTION_BUDGET):
        grown = {t for t, source in assignments if source in names} - names
        if not grown:
            return frozenset(names), False
        names |= grown
    return frozenset(names), True


def _record(violations: list[str], lines: list[str], path: Path, lineno: int, message: str) -> None:
    """Append a violation MESSAGE line plus its source SNIPPET line.

    Every rule reports the same two-line shape, so tests assert the returned list by
    equality rather than by substring search. Factored out because every rule repeating
    the pair would be one more place for the shape to drift (#422: a shared helper fails
    LOUD, N copies drift SILENTLY). NO COUNT IS NAMED HERE, for the reason
    :class:`GateInternalError` gives: this text said "nine rules" and Task 3 made it ten
    on the first edit after it was written.

    ``path`` travels as an argument because this repo forbids global state.

    THE BOUNDS GUARD, and why it is an ``if``/``else`` rather than a conditional
    expression: ``coverage.py`` does not branch on a ternary, so writing it that way
    would hide the arm from this file's REQUIRED 100% branch gate — exempting by
    construction exactly what the no-pragma rule forbids exempting. No ``_scan_text``
    INPUT is known to reach the else arm (``str.splitlines`` splits on strictly more
    separators than the tokenizer does, so the line list is never SHORTER than the
    parser's line numbering). It stays anyway because every rule shares this helper, and
    a finding must never become an ``IndexError`` that the broad ``except`` re-files as
    an unscannable file — a real laundering finding downgraded to a vague one. It is
    covered by a direct unit test rather than by a pragma.
    """
    # The SIM108 suppression below is DELIBERATE and load-bearing, not a style
    # concession. `coverage.py` does not branch on a conditional expression, so ruff's
    # suggested ternary would make the else arm invisible to this file's REQUIRED 100%
    # branch gate — the no-pragma rule forbids exempting a branch, and a ternary
    # exempts it silently.
    if 0 <= lineno - 1 < len(lines):  # noqa: SIM108
        snippet = lines[lineno - 1].rstrip()
    else:
        snippet = ""
    violations.append(f"{path}:{lineno}: {message}")
    violations.append(f"  {snippet}")


def _is_benign_setattr_target(node: ast.Call) -> bool:
    """True for the established frozen-dataclass idiom, false for every vehicle.

    DEFAULT-DENY ON SHAPE. Admissible only when ALL of:

    * ``args[1]`` folds to a plain string literal — a computed name cannot be read by
      any lexical rule;
    * that literal is not a dunder — those reach interpreter state, not a field;
    * that literal is not in :data:`_TAGGED_STATE_FIELDS`. THIS IS THE CONDITION THAT
      HOLDS. v1 denied only ``"tier"``, so ``object.__setattr__(low, "content",
      ATTACKER)`` was admitted and EXECUTED to place raw attacker text inside a
      T2-tagged object the privileged orchestrator is entitled to read, and
      ``"source"`` forged audit provenance;
    * ``args[0]`` is the bare name ``self``. This NARROWS the surface but proves
      nothing on its own, and the comment here must not claim otherwise: an earlier
      revision justified it with "reaching a TaggedContent as ``self`` requires
      subclassing it, which ``__init_subclass__`` refuses at runtime". That is FALSE,
      and was disproved by execution — ``def _apply(self, v): object.__setattr__(self,
      "content", v)`` is a plain function whose first parameter merely happens to be
      called ``self``. ``self`` is a naming convention, not a type.

    A call with fewer than two arguments (``object.__setattr__(*parts)``) is refused
    rather than admitted: a call this rule cannot read is a call it must not admit.

    Three live sites depend on the admissible case and none may red:
    ``hooks/context.py:106``, ``plugins/web_fetch/allowlist.py:139``,
    ``plugins/web_fetch/fetch_dispatcher.py:219``. All three write ``self``. Measured
    false-positive cost of this shape across both scan roots: ZERO.

    ESCAPE HATCH, named so nobody invents one: a frozen dataclass that genuinely needs
    a ``tier`` field and is NOT a ``TaggedContent`` should set it through its own
    constructor, or the write belongs behind a named helper inside the already-exempt
    ``security/tiers.py`` — not behind a loosened rule.
    """
    if len(node.args) < 2:
        return False
    target = node.args[0]
    if not (isinstance(target, ast.Name) and target.id == "self"):
        return False
    name = _fold_str(node.args[1])
    if name is None:
        return False
    if name.startswith("__") and name.endswith("__"):
        return False
    return name not in _TAGGED_STATE_FIELDS


def _carrier_bindings(tree: ast.AST) -> tuple[frozenset[tuple[str, str]], frozenset[str], bool]:
    """Resolve :data:`_RAW_STATE_CARRIERS` against ONE file's bindings.

    Returns ``(qualified_pairs, direct_names, overflowed)``:

    * ``qualified_pairs`` — every ``(module_alias, primitive)`` the file could spell as
      an attribute call. The MODULE half is alias-resolved because keying on the literal
      ``gc`` left ``import gc as _g`` and ``_g = gc`` scanning clean (fleet sec2-003).
    * ``direct_names`` — primitives bound as bare ``Name``s by
      ``from gc import get_referents``. No module identifier appears at that call site
      at all, so no amount of receiver resolution can see it; it needs its own pass.
      That pass runs ONCE over ``ast.ImportFrom`` rather than inside a per-carrier loop:
      a ``break`` in the per-carrier form attributes the finding to whichever carrier
      the loop happened to be on.
    * ``overflowed`` — any module's alias chain exceeded
      :data:`_ALIAS_RESOLUTION_BUDGET`, which the caller reports as a violation.

    The ``from`` module is matched literally on purpose: Python has no syntax that
    aliases the module name in ``from <module> import <name>``, so there is no
    identifier to resolve on that side.
    """
    resolved: dict[str, frozenset[str]] = {}
    overflowed = False
    for module in sorted({module for module, _ in _RAW_STATE_CARRIERS}):
        aliases, module_overflowed = _alias_names(tree, module)
        resolved[module] = aliases
        overflowed = overflowed or module_overflowed
    pairs = frozenset(
        (alias, primitive)
        for module, primitive in _RAW_STATE_CARRIERS
        for alias in resolved[module]
    )
    direct: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            for imported in node.names:
                if (node.module, imported.name) in _RAW_STATE_CARRIERS:
                    direct.add(imported.asname or imported.name)
    return pairs, frozenset(direct), overflowed


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


def _is_unbound_basemodel_seam_call(node: ast.Call, basemodel_names: frozenset[str]) -> bool:
    """``BaseModel.<seam>(obj, ...)`` — dispatch with the CLASS as receiver.

    This is the original tl-2026-013 shape. Called on the class, the seam builds field
    state through ``_copy_and_set_values`` and reaches neither the subclass overrides
    nor ``model_post_init``, so a ``TaggedContent`` can be produced without the tier
    ever passing a guard the runtime owns.

    The receiver is collapsed with :func:`_arg_name`, which maps ``ast.Name`` and
    ``ast.Attribute`` to the same identifier. A hand-rolled
    ``isinstance(func.value, ast.Name)`` check saw only the bare spelling and missed
    ``pydantic.BaseModel.model_copy(...)`` — the CR-138 round-2 finding #2 class this
    very helper exists to close. Reusing ``_arg_name`` also means the two widenings
    cannot drift apart.

    RECEIVER-SCOPED on purpose: a receiver-blind rule flagging every ``model_copy``
    reds ordinary pydantic instance use across the tree. Measured cost of this form:
    ZERO sites in the 332 files under both scan roots.

    Two shapes: ``BM.model_copy(obj, …)`` and ``BM.model_construct.__func__(cls, …)``,
    the latter one hop further through the unbound function object — which skips every
    override on the way in exactly as the first does.

    WHAT THIS CANNOT DO: a cross-module re-export (``from x import BaseModel as Y`` in
    module A, imported from A by module B) is invisible — the alias set is per-file.
    ``TaggedContent.model_construct(...)`` is likewise not flagged here; it is refused
    at RUNTIME. Both are recorded residuals, not oversights.
    """
    func = node.func
    if not isinstance(func, ast.Attribute):
        return False
    if _arg_name(func.value) in basemodel_names and func.attr in _BASEMODEL_SEAM_ATTRS:
        return True
    receiver = func.value
    return (
        isinstance(receiver, ast.Attribute)
        and _arg_name(receiver.value) in basemodel_names
        and receiver.attr in _BASEMODEL_SEAM_ATTRS
    )


def _detect(
    node: ast.AST,
    prose: frozenset[int],
    call_func_ids: frozenset[int],
    vars_names: frozenset[str],
    carrier_pairs: frozenset[tuple[str, str]],
    carrier_names: frozenset[str],
    basemodel_names: frozenset[str],
) -> list[str]:
    """Every rule's verdict on ONE already-parsed node, as a list of messages.

    PURE and CONSTANT-WORK over its arguments, which is what lets ``_scan_text`` fence
    the whole detector behind a single :class:`GateInternalError` rather than fencing
    each rule separately. The per-file maps are built by the CALLER, outside that
    fence: a defect in one of them is a defect in the maps, not in the file, and
    reporting it as an unscannable FILE at exit 1 is the #543 err-001 failure the fence
    exists to prevent.

    ``ast.AST`` rather than a narrower type: the caller walks every node, because three
    of these rules key on ``ast.Attribute`` / ``ast.Constant`` rather than ``ast.Call``.
    """
    messages: list[str] = []
    if isinstance(node, ast.Call):
        if _is_tag_t3_call(node):
            messages.append(_TAG_T3_MESSAGE)
        if _is_cast_tagged_content_call(node):
            messages.append(_CAST_TAGGED_CONTENT_MESSAGE)
        if _is_tagged_content_t3_subscript_call(node):
            messages.append(_TAGGED_CONTENT_T3_SUBSCRIPT_MESSAGE)
        if _is_unbound_basemodel_seam_call(node, basemodel_names):
            messages.append(_BASEMODEL_VALUE_MESSAGE)
        func = node.func
        if isinstance(func, ast.Name):
            # `vars` and the directly-bound carrier primitives are BARE IDENTIFIERS, so
            # both name sets arrive alias-resolved. `_v = vars` was the last identifier
            # in this gate still matched as a literal, found by self-audit.
            if func.id in vars_names:
                messages.append(_RAW_VEHICLE_VARS_MESSAGE)
            if func.id in carrier_names:
                messages.append(_RAW_CARRIER_MESSAGE)
        elif isinstance(func, ast.Attribute):
            # RECEIVER-BLIND. The rule never asks who the receiver is, so there is no
            # identifier left to rebind — that, not a wider alias set, is what closed
            # the four executed sec-001 spellings.
            if func.attr == "__setattr__" and not _is_benign_setattr_target(node):
                messages.append(_RAW_SETATTR_SHAPE_MESSAGE)
            if (_arg_name(func.value), func.attr) in carrier_pairs:
                messages.append(_RAW_CARRIER_MESSAGE)
    if isinstance(node, ast.Attribute):
        if node.attr in _RAW_STATE_VEHICLE_ATTRS:
            messages.append(_RAW_VEHICLE_ATTR_MESSAGE)
        # `__class__` by CONTEXT, not by name: a class swap is a laundering vehicle and
        # `exc.__class__.__name__` (live at hooks/invoke.py:1265) is an ordinary read.
        # Banning the name costs a false positive; banning the store context costs zero.
        if node.attr == "__class__" and isinstance(node.ctx, (ast.Store, ast.Del)):
            messages.append(_RAW_CLASS_SWAP_MESSAGE)
        # ONE-POSITION WHITELIST. `Call.func` is the ONLY admissible position for a
        # `__setattr__` reference; every other position is the A05 alias vehicle. Never
        # an ancestor blacklist — that must ENUMERATE the bad positions and silently
        # widens the day a new one appears.
        if node.attr == "__setattr__" and id(node) not in call_func_ids:
            messages.append(_RAW_SETATTR_ALIASED_MESSAGE)
    if isinstance(node, (ast.Constant, ast.BinOp, ast.JoinedStr)) and id(node) not in prose:
        # EQUALITY, not containment: a docstring or message that merely mentions a
        # vehicle name is prose about the rule, and widening this to containment reds
        # nothing in the tree today while admitting no new attack.
        folded = _fold_str(node)
        if folded is not None and folded in _RAW_STATE_VEHICLE_NAMES:
            messages.append(_RAW_VEHICLE_STR_MESSAGE)
    return messages


class GateInternalError(RuntimeError):
    """A DETECTOR PREDICATE raised. The gate is broken, not the file.

    #543 review (err-001). ``_scan_text``'s ``except Exception`` wrapped the
    whole scan body, every ``_is_*`` predicate included, so an
    ``AttributeError`` in the gate's own logic reported as an unscannable
    FILE at exit 1 ("violations found") on a completely clean file —
    indistinguishable from a real T3-laundering finding. Measured, on a file
    with no ``tag``/``cast``/subscript pattern in it at all.

    NO COUNT IS NAMED HERE ON PURPOSE. This docstring said "the three
    predicates" while :func:`_detect` already dispatched more than three, and
    a number in prose rots silently the next time a rule is added. The
    property is about the KIND of work, not how many rules do it.

    Every detector predicate does BOUNDED work on one already-parsed node —
    ``isinstance`` checks, attribute reads, and ``_fold_str``'s recursion,
    which is capped at :data:`_FOLD_MAX_DEPTH` precisely so that this claim
    stays true (an unbounded fold would let a long ``+`` chain raise from
    INSIDE the fence, and ``main`` would then discard every violation
    collected so far — hiding a real laundering finding in an earlier file
    behind a "the gate is broken" exit). No I/O, no unbounded recursion, so
    no INPUT can make them raise. Anything they raise is a defect, and
    `main` reports it as exit 2, "the gate could not run".

    ``ast.parse`` and ``ast.walk`` stay OUTSIDE this fence deliberately: both
    are genuinely input-driven (a 20 000-deep ``not`` chain raises
    ``MemoryError`` from the parser), and misfiling those as gate defects
    would be the same confusion in the other direction.
    """


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

    1. AST walk over EVERY node, delegating to :func:`_detect` — the
       ``tag(T3, ...)`` / ``cast(TaggedContent[...], ...)`` call patterns plus
       the #538 raw-state-write vehicle rules, which key on ``ast.Attribute``
       and ``ast.Constant`` rather than on ``ast.Call``. Multiline-safe by
       construction (the parser doesn't care about line breaks inside a call).
    2. Per-line regex for ``# type: ignore`` on a ``TaggedContent`` line —
       comments are discarded by the parser, so they need the line-based
       scan.

    **Never raises for an INPUT fault** (short of ``BaseException``): a scan
    failure becomes a reported violation rather than an exception that aborts
    ``main``'s loop and leaves every later file unscanned (#542). See the
    ``except Exception`` arm.

    The one exception is :class:`GateInternalError`, raised when a DETECTOR
    PREDICATE faults. That is not an input fault and aborting is correct for
    it: the gate is broken, so no later file's verdict would mean anything.
    ``main`` reports it as exit 2, never as exit 1 — which is precisely the
    difference #542 was about (it exited 1, "violations found", naming none).
    """
    violations: list[str] = []
    try:
        lines = text.splitlines()

        try:
            tree = ast.parse(text, filename=str(path))
        except SyntaxError as exc:
            # A file the parser cannot read is a file this gate is not gating.
            # Returning early skips the line-based suppression pass, which is
            # correct: a half-parsed view of a broken file is exactly what the
            # previous comment here warned against — the difference is that we
            # now REPORT it instead of passing it.
            return [f"{path}:{exc.lineno or 1}: {_UNPARSEABLE_MESSAGE}", f"  {exc.msg}"]

        # No ``if tree is not None`` guard: the SyntaxError arm above RETURNS, so
        # ``tree`` is always a parsed module here. The guard was a leftover from the
        # shape where an unparseable file set ``tree = None`` and fell through — it
        # became unreachable when that became a violation, and an unreachable branch
        # is a coverage hole that a pragma would hide rather than fix.
        #
        # THE PER-FILE MAPS, built OUTSIDE the detector fence alongside `ast.parse`.
        # They walk the tree, so they are input-driven in exactly the way `ast.parse`
        # and `ast.walk` are; a fault in one is not a faulting PREDICATE, and reporting
        # it as exit 2 "the gate is broken" would be the #543 err-001 confusion in the
        # other direction.
        prose = _prose_string_ids(tree)
        # ONE-POSITION WHITELIST for `__setattr__`: `Call.func` is the only admissible
        # position, and this is the set of node identities occupying it.
        call_func_ids = frozenset(id(n.func) for n in ast.walk(tree) if isinstance(n, ast.Call))
        vars_names, vars_overflow = _alias_names(tree, "vars")
        carrier_pairs, carrier_names, carrier_overflow = _carrier_bindings(tree)
        basemodel_names, basemodel_overflow = _alias_names(tree, "BaseModel")

        # FAIL CLOSED, and LOUDLY. A chain past the budget means the resolver cannot say
        # what these names are bound to, so every alias-resolved rule below is deciding
        # on an incomplete set. Attributed to line 1 because the overflow is a property
        # of the FILE's alias graph, not of any single line.
        #
        # ONE condition over EVERY resolved seed, not one report per seed: an overflow
        # means the FILE's alias graph is past the budget, and three copies of the same
        # message on the same line would say the same thing three times.
        if vars_overflow or carrier_overflow or basemodel_overflow:
            _record(violations, lines, path, 1, _ALIAS_BUDGET_MESSAGE)

        for node in ast.walk(tree):
            # `getattr`, never `node.lineno`. `ast.walk` yields `ast.AST`, which carries
            # no `lineno`; the previous code type-checked only because the
            # `isinstance(node, ast.Call)` guard narrowed it, and that guard is gone —
            # three of these rules key on `ast.Attribute` / `ast.Constant`. Measured:
            # `mypy --strict` and `pyright` BOTH error on the attribute form, at 12
            # required sites including the pre-push lefthook.
            lineno = getattr(node, "lineno", 1)
            # THE DETECTOR, fenced off from the input-driven arms around it.
            # It does constant work on an already-parsed node, so an exception
            # here is a bug in this file — not a property of the scanned
            # source. Without the fence it reported as an unscannable FILE at
            # exit 1, i.e. as a T3-laundering finding in a clean file (#543
            # review, err-001). The `for` statement stays outside: it is
            # `ast.walk` advancing, which IS input-driven.
            try:
                findings = _detect(
                    node,
                    prose,
                    call_func_ids,
                    vars_names,
                    carrier_pairs,
                    carrier_names,
                    basemodel_names,
                )
            except Exception as exc:
                raise GateInternalError(
                    f"{path}:{lineno}: {_GATE_INTERNAL_MESSAGE} {type(exc).__name__}: {exc}"
                ) from exc
            for message in findings:
                _record(violations, lines, path, lineno, message)

        for lineno, line in enumerate(lines, 1):
            if _TYPE_IGNORE_PATTERN.search(line):
                _record(violations, lines, path, lineno, _TYPE_IGNORE_MESSAGE)
    except GateInternalError:
        # ORDER IS LOAD-BEARING. `GateInternalError` is an `Exception`, so the
        # broad arm below would swallow it and re-file the gate's own defect as
        # an unscannable input file at exit 1 — the exact confusion the fence
        # above exists to remove (#543 review, err-001). Re-raise so `main`
        # reports exit 2, "the gate could not run".
        raise
    except Exception as exc:
        # ``ast.parse`` raises more than ``SyntaxError``, and WHICH exception
        # depends on the interpreter BUILD. Measured on two CPython 3.14.6
        # builds: ``"not " * 20000`` raises MemoryError("Parser stack
        # overflowed") on both, while a 50 000-operand ``+`` chain raises
        # RecursionError("Stack overflow (used 8144 kB) during compilation")
        # on the uv/proto standalone build and parses CLEANLY on Homebrew.
        # 3.14's stack guard trips on real C-stack bytes, not on
        # sys.setrecursionlimit. CI uses ``uv python install 3.14``, so
        # RecursionError is live there even when a dev box never sees it.
        #
        # CONSEQUENCE FOR FUTURE TESTS (#545): "CPython 3.14.6" does not name
        # an environment. A test that asserts a SPECIFIC exception type out of
        # ``ast.parse`` is asserting a property of the BUILD, so it passes on
        # one runner and fails on another for reasons no version pin explains.
        # Assert the reported OUTCOME (a violation, this arm's message) rather
        # than the exception class, or skip on the builds where the input does
        # not trip the guard.
        #
        # Uncaught, these escaped ``_scan_text``, escaped ``main``, and killed
        # the process with a traceback — exit 1, the code that means
        # "violations found", for a file that was never scanned. Worse, they
        # ABORTED THE SCAN LOOP, so every later file went unscanned with
        # nothing reported (#542).
        #
        # Deliberately the CLASS, not a name list. Enumerating MemoryError and
        # RecursionError closes the two shapes we happened to think of and
        # leaves the next build-specific one open — the #518 guard-name-list
        # mistake. The scope covers the whole scan, not just ``ast.parse``:
        # ``splitlines``, ``ast.walk`` and the line pass can raise too, and an
        # exception in any of them aborted the loop just as effectively.
        #
        # APPEND, never replace: by the time this fires the walk may already
        # have found a real ``tag(T3, ...)``. Returning only the unscannable
        # message would downgrade a T3-laundering finding into a vague one.
        #
        # ``KeyboardInterrupt`` and ``SystemExit`` derive from
        # ``BaseException``, so they are NOT caught here and still interrupt
        # the run.
        #
        # Not a silent-failure concession: the result is a reported violation,
        # printed to stderr by ``main``, and the gate exits non-zero.
        violations.append(f"{path}:1: {_UNSCANNABLE_MESSAGE}")
        violations.append(f"  {type(exc).__name__}: {exc}")

    return violations


def _scan_file(path: Path) -> list[str]:
    """Return a list of violation messages for ``path``. Empty list = clean.

    Applies the exemption, reads the source, and delegates the scanning to
    :func:`_scan_text`.

    **Never raises for an INPUT fault** (short of ``BaseException``), for the
    same reason :func:`_scan_text` does not: a read failure this function lets
    escape aborts ``main``'s loop and silently un-gates every later file
    (#542). :class:`GateInternalError` from the delegate propagates by design —
    see :func:`_scan_text`.
    """
    if _is_exempt(path):
        return []
    try:
        # #546. `open()` on a FIFO for reading BLOCKS until a writer arrives,
        # and nothing here ever writes — so `read_text` on a FIFO named `*.py`
        # never returns and the gate hangs until CI kills the job, reporting
        # no diagnosis at all. Measured at exit 124 on both paths that reach
        # here: an explicit file argument, and the `rglob` traversal fallback
        # past the census floor. A character device (`/dev/zero`) is the same
        # shape with a different ending — an unbounded read instead of a
        # blocked one.
        #
        # DEFAULT-DENY the class, not the two shapes we thought of (#518): a
        # regular file is the only thing this gate can scan, so everything
        # else is refused by construction. `stat()` does not open the path, so
        # it cannot block on the very FIFO it is classifying — probed, not
        # assumed.
        #
        # WHAT THIS GUARD CANNOT DO: `stat` and `open` are two syscalls, so a
        # path swapped between them is still read as whatever it became. That
        # residual is accepted rather than closed. It needs write access to
        # the tree mid-scan (which already defeats a gate that reads the tree
        # it is gating), and its worst outcome is the ORIGINAL hang, not a
        # missed T3 violation — the security property this file exists for is
        # unaffected either way. Closing it would mean opening with
        # `O_NONBLOCK` and re-checking the fd, which is POSIX-only and would
        # red the Windows unit leg for no gain in the property that matters.
        #
        # Raised into the arm below rather than returned separately, and that
        # is deliberate on TWO counts. It is genuinely the same fault the arm
        # already reports — a path the reader cannot open — so it must give
        # the operator the same message. And a separate `return` would strand
        # `read_text`'s own OSError arm: a directory (its only portable
        # trigger, and what `test_unreadable_path_is_a_violation` uses) would
        # stop reaching it, leaving EACCES as the sole cover — untriggerable
        # on the root runners, which reds the required 100% branch gate on
        # this file. One funnel keeps both sides of the new branch covered.
        if not stat.S_ISREG(path.stat().st_mode):
            raise OSError(errno.EINVAL, _NOT_A_REGULAR_FILE_REASON)
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return [f"{path}:1: {_UNDECODABLE_MESSAGE}", "  <undecodable>"]
    except OSError as exc:
        return [f"{path}:1: {_UNREADABLE_MESSAGE}", f"  {exc.strerror or exc}"]
    except Exception as exc:
        # A path with an embedded NUL raises ``ValueError``, not ``OSError`` —
        # measured, and the exact cause ``_is_exempt`` already catches
        # ValueError for. The same input was handled by one function and
        # escaped the next. Same class-not-names reasoning as ``_scan_text``.
        #
        # No third catch-all in ``main``'s loop: with this arm and
        # ``_scan_text``'s, a per-file failure cannot reach it, so a backstop
        # there would be unreachable — a coverage hole on a file that must
        # stay at 100%.
        #
        # Its own message (#543 review, dx-003): this arm only ever fires on a
        # PATH the reader could not open, never on content, so it must not
        # suggest simplifying the file.
        return [f"{path}:1: {_UNSCANNABLE_PATH_MESSAGE}", f"  {type(exc).__name__}: {exc}"]
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
    #
    # `is_file()` is S_ISREG-following-symlinks, so this ALSO drops a tracked
    # path whose working-tree entry has become non-regular — the shape
    # `_scan_file` now refuses LOUDLY (#546). The asymmetry is deliberate and
    # narrow (#549 review, sec-001): git cannot store a FIFO, so the only way
    # to reach it is a local working tree where someone replaced a tracked file
    # with one, and this arm cannot tell that apart from the staged-deletion
    # case it exists for — both present as "in the index, not a regular file
    # on disk". Refusing here would fail the gate on an ordinary unstaged
    # deletion, which is a far more common state than a hand-planted FIFO.
    # A file swapped for a FIFO is therefore silently unscanned on this path
    # and reported on the other two; the census in `main` is what notices if
    # enough of them disappear.
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
            # The remedy, not just the diagnosis (#543 review, dx-001).
            # ``check_tag_t3.py src/alfred`` — the documented pre-#541 usage,
            # and the most natural manual invocation — now exits 2 here, and
            # the old message named an internal constant a first-time
            # contributor would have to read the source to act on.
            raise PartialScanRootError(
                f"directory scan does not cover every declared root: missing "
                f"{missing}. A caller may not gate a subset of them. Fix: run "
                f"`python3 scripts/check_tag_t3.py` with NO arguments to scan "
                f"every declared root ({', '.join(_DEFAULT_SCAN_ROOTS)}), or "
                f"pass all of them explicitly. To change WHAT is gated, edit "
                f"_DEFAULT_SCAN_ROOTS in this script (#541)."
            )

    # THE DECOY DEFENCE (#543 review, sec-002). An argument-less run whose
    # roots all resolve OUTSIDE this repo is a wrong checkout or a scratch copy
    # — and it is exempt from the invariant above by design, because that one
    # is scoped to in-repo directories. The aggregate census in `main` was
    # documented as covering this and does not: a 260-file decoy clears a
    # 250-file floor and exits 0 having gated nothing (measured).
    #
    # A property, not a count: the run is argument-less, so it is gating THIS
    # repo or it is gating nothing. Explicit arguments are untouched — the unit
    # suite plants `tmp_path` trees and scans them by path, and out-of-repo
    # fixtures are the whole point of that path.
    #
    # Asserted on the ROOTS, not on a sample of the COLLECTED FILES (#548
    # review, sec-001). The predicate here was
    # `any(p.resolve().is_relative_to(_REPO_ROOT) for p in paths)`, satisfied by
    # ONE collected file — and `rglob` above runs with `recurse_symlinks=True`,
    # so a decoy carrying a single link into this repo measured rc=0 with 260
    # decoy files supplying every verdict. EVERY root or none of them: that form
    # cannot be bought with one link, and it does not depend on what the walk
    # happened to reach.
    #
    # `argv` IS `_DEFAULT_SCAN_ROOTS` on this path (rebound above), so this
    # names the roots that were actually scanned rather than re-reading the
    # constant — a monkeypatched tuple reaches this check like any other.
    #
    # What it does NOT cover, stated so the next reader does not have to
    # measure it: an in-repo root whose every tracked file is a symlink out of
    # the repo. Reaching that needs TRACKED symlinks, and in-repo directory sets
    # are derived from `git ls-files` under `_REPO_ROOT`; it is not the wrong-
    # checkout shape this guard exists for.
    if default_root:
        outside = [
            root for root in argv if not Path(root).resolve(strict=False).is_relative_to(_REPO_ROOT)
        ]
        if outside:
            raise EmptyScanRootError(
                f"an argument-less scan collected {len(paths)} files and its "
                f"declared roots {outside} do NOT resolve inside {_REPO_ROOT} "
                f"— they resolved to a different tree (a wrong checkout, or a "
                f"scratch copy). Refusing to report success while gating "
                f"nothing. Run the gate from the repository root."
            )
    return paths


def main(argv: list[str]) -> int:
    """Return 0 clean, 1 violations found, 2 the gate could not run.

    Exit 2 is deliberately distinct from 1: a caller must be able to tell
    "the gate failed" from "the gate never gated anything".

    THREE routes to exit 2, all of them "the gate could not run":

    * :class:`EmptyScanRootError` (and its :class:`PartialScanRootError`
      subclass) — the gate was pointed at nothing, at less than everything,
      or at a tree that is not this repo;
    * the aggregate census below;
    * :class:`GateInternalError` — a detector predicate faulted. #543 review
      (err-001) found that arriving here as exit 1, so a broken predicate
      read as "violations found" on files that were clean.

    Exit 1 therefore means what it says: every listed line is a finding in a
    file, not a fault in the gate.
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
    try:
        for path in paths:
            all_violations.extend(_scan_file(path))
    except GateInternalError as exc:
        # NOT exit 1. Whatever was collected before the fault is discarded on
        # purpose: a faulting detector means no file's verdict is trustworthy,
        # including the ones that came back clean. Exit 2 says exactly that.
        print(f"check_tag_t3: {exc}", file=sys.stderr)
        return 2

    if all_violations:
        print("check_tag_t3: violations found:", file=sys.stderr)
        for line in all_violations:
            print(line, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
