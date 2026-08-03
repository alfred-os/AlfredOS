"""Unit tests for the #538 sole-layer rules in ``scripts/check_tag_t3.py``.

Loaded via ``spec_from_file_location`` against the REAL script path: a ``tmp_path``
copy would recompute ``_REPO_ROOT`` from ``__file__`` and silently invert every
exemption, so a copy-based test measures the wrong tree while still passing.
"""

from __future__ import annotations

import ast
import importlib.util
import re
import subprocess
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[3]
_SCRIPT = _REPO_ROOT / "scripts" / "check_tag_t3.py"

_spec = importlib.util.spec_from_file_location("check_tag_t3_sole_layer", _SCRIPT)
assert _spec is not None and _spec.loader is not None
check_tag_t3 = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = check_tag_t3
_spec.loader.exec_module(check_tag_t3)

assert check_tag_t3._REPO_ROOT == _REPO_ROOT, (
    f"loaded the wrong script: {check_tag_t3._REPO_ROOT} != {_REPO_ROOT}"
)

_PROBE = Path("/nonexistent/probe.py")
_NONCE_FACTORY = _REPO_ROOT / "src" / "alfred" / "bootstrap" / "nonce_factory.py"
_QUARANTINE = _REPO_ROOT / "src" / "alfred" / "security" / "quarantine.py"
_TIERS = _REPO_ROOT / "src" / "alfred" / "security" / "tiers.py"


def _messages(source: str, path: Path = _PROBE) -> list[str]:
    """Violation MESSAGE lines only — odd-indexed entries are code snippets."""
    return [v for v in check_tag_t3._scan_text(source, path) if not v.startswith("  ")]


def test_prose_string_ids_covers_all_four_docstring_shapes() -> None:
    """Module, class, function AND PEP-258 attribute docstrings are prose.

    ``ast.get_docstring`` sees only the first three. ``src/alfred/hooks/invoke.py:466``
    is the fourth shape and is a MEASURED false positive without it.
    """
    source = '''\
"""module docstring"""
X = 1
"""attribute docstring — PEP 258, NOT an ast docstring"""


class C:
    """class docstring"""


async def f() -> None:
    """async function docstring"""
'''
    tree = ast.parse(source)
    prose = check_tag_t3._prose_string_ids(tree)
    found = {
        n.value.value
        for n in ast.walk(tree)
        if isinstance(n, ast.Expr)
        and isinstance(n.value, ast.Constant)
        and isinstance(n.value.value, str)
        and id(n.value) in prose
    }
    assert found == {
        "module docstring",
        "attribute docstring — PEP 258, NOT an ast docstring",
        "class docstring",
        "async function docstring",
    }


def test_prose_string_ids_excludes_strings_in_code_position() -> None:
    """A string ARGUMENT is code, not prose — this is what catches A17.

    ``getattr(_t, "_set_authorized_t3_nonce")`` hides the name in a string. If the
    prose exclusion swallowed every string constant, A17 would walk straight through.
    POSITIVE TWIN included so this cannot pass on an empty prose set.
    """
    tree = ast.parse('getattr(_t, "_set_authorized_t3_nonce")\nx = "not prose"\n"""prose"""\n')
    prose = check_tag_t3._prose_string_ids(tree)
    strings = {
        n.value: id(n) in prose
        for n in ast.walk(tree)
        if isinstance(n, ast.Constant) and isinstance(n.value, str)
    }
    assert strings["_set_authorized_t3_nonce"] is False
    assert strings["not prose"] is False
    assert strings["prose"] is True, "positive twin: a bare string statement IS prose"


def test_prose_string_ids_ignores_a_bare_non_string_expression_statement() -> None:
    """COVERAGE + SHAPE: a bare ``...`` or ``42`` statement is an ``ast.Expr`` too.

    Not in the plan's suite, and required by this file's 100% BRANCH gate: without a
    bare non-string constant statement, the third arm of the prose predicate
    (``isinstance(node.value.value, str)``) is never evaluated False and its arc back
    to the loop is uncovered. The positive twin in the same source proves the walk
    reached both.
    """
    tree = ast.parse('...\n42\n"""prose"""\n')
    prose = check_tag_t3._prose_string_ids(tree)
    values = {
        n.value.value: id(n.value) in prose
        for n in ast.walk(tree)
        if isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant)
    }
    assert values[Ellipsis] is False
    assert values[42] is False
    assert values["prose"] is True, "positive twin: the string statement IS prose"


def test_enclosing_functions_matches_async_def_as_well_as_def() -> None:
    """THE SILENT TRAP: a ``FunctionDef``-only walk matches nothing for ``async def``.

    Nothing in the repo fails when that mutation is applied — the one real
    (path, function) exemption is a plain ``def``.
    """
    fmap = check_tag_t3._enclosing_functions(
        ast.parse("def sync_one():\n    a = 1\n\n\nasync def async_one():\n    b = 2\n")
    )
    assert fmap[2] == ("sync_one", 0)
    assert fmap[6] == ("async_one", 0), "async def unmapped — the walk matches ast.FunctionDef only"


def test_enclosing_functions_reports_the_innermost_function() -> None:
    """A nested def must shadow its parent, or an exemption leaks outward."""
    fmap = check_tag_t3._enclosing_functions(
        ast.parse("def outer():\n    def inner():\n        x = 1\n    y = 2\n")
    )
    assert fmap[3] == ("inner", 1)
    assert fmap[4] == ("outer", 0)


def test_enclosing_functions_reports_the_depth_of_every_enclosing_scope() -> None:
    """PR #553 SECURITY REVIEW, F4 — a CLASS body is a scope too.

    The depth the ``(path, function)`` exemption needs is "is this def at MODULE
    scope", not "how many ``def``s is it inside". A method of a module-level class is
    nested one scope deep even though no function encloses it, so counting only
    functions would hand a same-named METHOD the exemption a nested ``def`` is being
    denied.
    """
    fmap = check_tag_t3._enclosing_functions(
        ast.parse(
            "def top():\n"
            "    x = 1\n"
            "class C:\n"
            "    def method(self):\n"
            "        y = 2\n"
            "        def buried():\n"
            "            z = 3\n"
        )
    )
    assert fmap[2] == ("top", 0)
    assert fmap[5] == ("method", 1), "a method of a module-level class is one scope deep"
    assert fmap[7] == ("buried", 2)


def test_enclosing_functions_leaves_module_scope_unmapped() -> None:
    """Module-level lines have no enclosing function.

    Load-bearing: the module-level import exemption keys on this being ``None``.
    """
    fmap = check_tag_t3._enclosing_functions(ast.parse("import os\n\n\ndef f():\n    x = 1\n"))
    assert 1 not in fmap
    assert fmap[5] == ("f", 0)


def test_fold_str_folds_binop_and_fstring_but_not_computed_values() -> None:
    """``ast`` folds IMPLICIT concatenation but not ``+``.

    ``"_set_authorized" + "_t3_nonce"`` escaped the v1 rule and was executed to forge
    the nonce and mint a legitimate T3 for attacker content through the front door.
    """

    def fold(src: str) -> str | None:
        return check_tag_t3._fold_str(ast.parse(src, mode="eval").body)

    assert fold('"_set_authorized" + "_t3_nonce"') == "_set_authorized_t3_nonce"
    assert fold('"a" "b"') == "ab"
    assert fold('"__di" + "ct" + "__"') == "__dict__"
    # MEASURED outcome, not a disjunction that accepts either (R2-K). The source parses
    # to JoinedStr([Constant('__di'), FormattedValue(Constant('')), Constant('ct__')]);
    # `_fold_str` has no FormattedValue arm, so ONE replacement field — even one whose
    # own value is a literal — makes the whole f-string unfoldable. That is the
    # `"_set_authorized%s" % ...` / `.format(...)` residual in another spelling.
    assert fold('f"__di{""}ct__"') is None
    # The JoinedStr SUCCESS arm. Nothing else in this suite reaches it: CPython collapses
    # a replacement-field-free f-string to JoinedStr([Constant(...)]), NOT to a bare
    # Constant, so `f"__dict__"` is the only shape that folds through that arm.
    assert fold('f"__dict__"') == "__dict__"
    assert fold("name") is None, "a bare name is not a literal"
    assert fold('"".join(parts)') is None, "a computed value must not fold"
    assert fold("1 + 2") is None, "non-str BinOp must not fold"
    # THE `ast.Add` RESTRICTION, pinned (PR #553 review, T7). Dropping it — folding
    # every `ast.BinOp` — survived the whole suite: the `%` residual fixture below
    # uses `"__dict%s" % "__"`, which folds to `"__dict%s__"` and still equals no
    # member, so the widening was invisible. Two string operands under a NON-Add
    # operator is the shape that discriminates: it folds to a real member under the
    # mutant and to None here. The widening is false-positive-only, but a rule that
    # reds on `a % b` reds on prose nobody can predict.
    assert fold('"__dict" % "__"') is None, "only `+` folds — a non-Add BinOp must not"


def test_fold_str_gives_up_at_the_depth_bound_instead_of_recursing() -> None:
    """R2-L: ``_fold_str`` runs INSIDE ``_scan_text``'s ``GateInternalError`` fence.

    An exception raised there is reported as a GATE DEFECT: ``main`` exits 2 and
    DISCARDS every violation collected so far, so one pathological ``+`` chain would
    suppress a real laundering finding in an EARLIER file. The bound turns that into a
    local, silent non-match instead.

    The deep node is BUILT, not parsed, on purpose. A parsed chain long enough to blow
    the recursion limit is a property of the interpreter BUILD (this repo has already
    been bitten: a 50 000-operand chain raises RecursionError on the uv standalone
    build and parses cleanly on Homebrew), so a parse-based fixture would assert
    something no version pin explains.

    PR #553 REVIEW, T3 — THE BOUND ITSELF WAS PINNED BY A TAUTOLOGICAL ORACLE. Every
    assertion below used to open ``bound = _FOLD_MAX_DEPTH``, the constant under test,
    so a retune moved the oracle with it: ``_FOLD_MAX_DEPTH = 2`` survived the whole
    suite, and executed, a four-operand assembly of ``_set_authorized_t3_nonce`` then
    scanned CLEAN — the round-2 nonce forge reopened with the suite green. The FLOOR and
    the FIXED-SIZE fixtures below do not read the constant, so they cannot move with it.
    """
    bound = check_tag_t3._FOLD_MAX_DEPTH

    def chain(operands: int) -> str | None:
        source = " + ".join(f'"a{i}"' for i in range(operands))
        return check_tag_t3._fold_str(ast.parse(source, mode="eval").body)

    # THE FLOOR. Independent of the constant: a bound this low makes every string-keyed
    # rule blind to an ordinary hand-written `+` chain, which is the assembly the fold
    # exists to see. 8 is well under the shipped 32 and well over anything an author
    # would write, so it constrains a RETUNE without pinning the current value.
    assert bound >= 8, (
        f"_FOLD_MAX_DEPTH is {bound} — below ~8 a hand-written `+` chain folds to None "
        f"and every string-keyed rule goes blind to an assembled name"
    )
    # FIXED SIZE, so this assertion cannot move with the constant. Six operands nest
    # five BinOps; at the shipped bound they fold, at bound 2 they do not.
    assert chain(6) == "a0a1a2a3a4a5", "a six-operand chain must fold at any sane bound"
    # AND THE PROPERTY THE FLOOR IS FOR, end to end through the scanner: the executed
    # round-2 forge assembles the nonce setter from four literals. Fixed size, no
    # constant read.
    assert _messages('getattr(_t, "_set" + "_authorized" + "_t3" + "_nonce")(mine)\n') == [
        f"{_PROBE}:1: {check_tag_t3._PRIVATE_SURFACE_MESSAGE}"
    ], "a four-operand assembly of the nonce setter must still be seen"

    # A left-associative chain of N operands nests N-1 BinOps, so N == bound + 1
    # recurses to exactly `bound` and still folds. This is the positive twin: it proves
    # the bound is a CEILING and not a blanket refusal.
    assert chain(bound + 1) == "".join(f"a{i}" for i in range(bound + 1))
    assert chain(bound + 2) is None, "one operand past the bound must stop folding"

    # THE THREE RECURSION SITES, one hand-built spine each (PR #553 review, T5). The
    # LEFT spine was the only one measured, so a mutant that increments depth on the
    # left and not on the right or through `JoinedStr` survived every fixture in this
    # file — and executed, the unbounded spine raises RecursionError from INSIDE
    # `_scan_text`'s GateInternalError fence, which discards every violation collected
    # so far and exits 2. That is the R2-L failure this bound exists to prevent,
    # reachable through two spines nothing was watching.
    left: ast.expr = ast.Constant(value="a")
    right: ast.expr = ast.Constant(value="a")
    nested: ast.expr = ast.Constant(value="a")
    for _ in range(2000):
        left = ast.BinOp(left=left, op=ast.Add(), right=ast.Constant(value="b"))
        right = ast.BinOp(left=ast.Constant(value="b"), op=ast.Add(), right=right)
        nested = ast.JoinedStr(values=[nested])
    for spine, node in (("left", left), ("right", right), ("JoinedStr", nested)):
        assert check_tag_t3._fold_str(node) is None, (
            f"the {spine} recursion does not increment depth — an unbounded _fold_str "
            f"raises RecursionError here, which the fence re-files as a gate defect and "
            f"discards every violation found so far"
        )


def test_alias_names_reaches_a_fixed_point_in_reverse_order() -> None:
    """``C = B`` written BEFORE ``B = BaseModel``.

    PROVEN REQUIRED by mutation: a single pass yields ``{BaseModel, B}`` and MISSES
    ``C``. Asserted on membership, not on "trips", because the single-pass mutant
    still trips under a different rule.
    """
    names, overflow = check_tag_t3._alias_names(
        ast.parse("from pydantic import BaseModel\nC = B\nB = BaseModel\n"), "BaseModel"
    )
    assert names == frozenset({"BaseModel", "B", "C"})
    assert overflow is False


def test_alias_names_binds_an_import_asname_and_ignores_non_name_targets() -> None:
    """The ``from m import X as Y`` arm, and the non-``Name`` assignment target arm.

    Not in the plan's suite, and required by this file's 100% BRANCH gate: every
    fixture there imports ``BaseModel`` unaliased, so ``node.asname is not None`` is
    never True, and every assignment target is a bare ``Name``, so the target filter is
    never False. Both are live shapes — ``from builtins import object as _o`` is one of
    the four spellings the review fleet EXECUTED to mint a genuine ``TaggedContent[T3]``.

    ``obj.attr = B`` is the negative half: an attribute target rebinds nothing this
    per-file resolver can name, so it must not enter the alias set under any spelling.
    """
    names, overflow = check_tag_t3._alias_names(
        ast.parse(
            "from pydantic import BaseModel as _bm\n"
            "obj.attr = _bm\n"
            "first, second = _bm\n"
            "chained = _bm\n"
        ),
        "BaseModel",
    )
    assert names == frozenset({"BaseModel", "_bm", "chained"})
    assert overflow is False


def test_alias_names_reports_budget_exhaustion_instead_of_looping() -> None:
    """The budget is a NAMED CONSTANT, so exhaustion is REACHABLE — and testable.

    v1 bounded the loop by ``len(assignments) + 1``, which makes the loop-exhaustion
    arc unreachable BY CONSTRUCTION: two reviewers proved it independently (0 of
    406,901 and 0 of 16,276 exhaustive inputs reach it). Under the repo's no-pragma
    rule that made the required 100% branch gate unsatisfiable. An input-INDEPENDENT
    budget makes the arc a real, reachable, fail-closed outcome.
    """
    depth = check_tag_t3._ALIAS_RESOLUTION_BUDGET + 5
    chain = "from pydantic import BaseModel\n"
    chain += "".join(f"a{i} = a{i - 1}\n" for i in range(depth, 0, -1))
    chain += "a0 = BaseModel\n"
    _, overflow = check_tag_t3._alias_names(ast.parse(chain), "BaseModel")
    assert overflow is True

    _, shallow = check_tag_t3._alias_names(
        ast.parse("from pydantic import BaseModel\nB = BaseModel\n"), "BaseModel"
    )
    assert shallow is False, "positive twin: an ordinary file must NOT report overflow"


# ---------------------------------------------------------------------------
# Task 2 — the raw-state-write vehicle ban.
#
# The runtime CANNOT refuse these spellings: a raw state write traverses no
# method the model can override, so `frozen=True` never observes it. This gate
# is the ONLY enforcement layer that exists for them, which is why every rule
# below denies the VEHICLE or the SHAPE rather than an enumeration of spellings.
# ---------------------------------------------------------------------------


def test_a01_object_setattr_writing_dunder_dict_is_refused() -> None:
    """A01 — the decisive spelling; round-2 minted a real TaggedContent[T3] with it.

    A01 defeats the "key on the written ``tier`` attribute" rule BY CONSTRUCTION: the
    attribute written is ``__dict__``. That is why the VEHICLE is banned, not the spelling.
    """
    source = 'object.__setattr__(obj, "__dict__", {"tier": T3})\n'
    assert check_tag_t3._scan_text(source, _PROBE) == [
        f"{_PROBE}:1: {check_tag_t3._RAW_SETATTR_SHAPE_MESSAGE}",
        '  object.__setattr__(obj, "__dict__", {"tier": T3})',
        f"{_PROBE}:1: {check_tag_t3._RAW_VEHICLE_STR_MESSAGE}",
        '  object.__setattr__(obj, "__dict__", {"tier": T3})',
    ]


def test_setattr_receiver_is_matched_by_alias_not_by_the_bare_name_object() -> None:
    """FLEET FINDING sec-001 — v1 matched only the identifier ``object``.

    All four spellings below scanned CLEAN under v1 and were EXECUTED to mint genuine
    TaggedContent[T3] objects with attacker-controlled content; one downgraded a real
    tag_t3_with_nonce T3 to T2, putting raw untrusted text on the privileged plane.

    What closes the class is RECEIVER-BLINDNESS, not a wider alias set: the rule never
    asks who the receiver is, so there is no identifier left to rebind.
    """
    for label, source in {
        "builtins": 'import builtins\nbuiltins.object.__setattr__(low, "tier", T3)\n',
        "rebind": '_o = object\n_o.__setattr__(low, "tier", T3)\n',
        "import-alias": 'from builtins import object as _o\n_o.__setattr__(low, "tier", T3)\n',
        "mro": 'type(low).__mro__[-1].__setattr__(low, "tier", T3)\n',
    }.items():
        assert any(check_tag_t3._RAW_SETATTR_SHAPE_MESSAGE in m for m in _messages(source)), (
            f"{label} spelling was admitted"
        )


def test_setattr_shape_denies_every_tagged_content_field_target() -> None:
    """FLEET FINDING sec-002 — v1 denied only ``"tier"``.

    ``object.__setattr__(low, "content", ATTACKER)`` was EXECUTED to place raw
    attacker-controlled text inside a T2-tagged object the privileged orchestrator is
    entitled to read — a hard-rule-#1 breach. ``"source"`` forged audit provenance.
    """
    assert _messages('object.__setattr__(low, "content", ATTACKER)\n') == [
        f"{_PROBE}:1: {check_tag_t3._RAW_SETATTR_SHAPE_MESSAGE}"
    ]
    assert _messages('object.__setattr__(low, "source", "forged")\n') == [
        f"{_PROBE}:1: {check_tag_t3._RAW_SETATTR_SHAPE_MESSAGE}"
    ]
    assert _messages('object.__setattr__(low, "tier", T3)\n') == [
        f"{_PROBE}:1: {check_tag_t3._RAW_SETATTR_SHAPE_MESSAGE}"
    ]


# R2-E — PINNED HERE, SEPARATELY FROM THE IMPLEMENTATION, and at module level so the
# residual declaration at the foot of this file can name the same literal rather than a
# second copy of it.
_EXPECTED_TAGGED_STATE_FIELDS = frozenset({"tier", "content", "source"})


def test_setattr_denies_every_tagged_state_field_regardless_of_target() -> None:
    """Every member of ``_TAGGED_STATE_FIELDS``, with ``self`` AND a foreign target.

    R2-E: the expected set is pinned as a SEPARATE LITERAL here and asserted equal to
    the module constant FIRST. Looping over the constant under test is a tautological
    oracle — removing ``"source"`` would remove it from the oracle too.

    R2-G: the ``self`` cases are load-bearing. Every foreign-target fixture
    short-circuits on the ``self`` check, so the FIELD arm is never reached by one and
    the mutation row that names it would be attributed to a test that cannot
    discriminate. With ``self`` as the target, the field ban is the only thing left
    standing — and it is the condition that actually holds (``self`` is a naming
    convention, not a type).
    """
    expected = _EXPECTED_TAGGED_STATE_FIELDS
    assert expected == check_tag_t3._TAGGED_STATE_FIELDS, (
        "the declared TaggedContent state fields moved; this oracle pins them"
    )
    for field in sorted(expected):
        assert _messages(f'object.__setattr__(self, "{field}", v)\n') == [
            f"{_PROBE}:1: {check_tag_t3._RAW_SETATTR_SHAPE_MESSAGE}"
        ], f"self-targeted write to {field!r} was admitted"
        assert _messages(f'object.__setattr__(low, "{field}", v)\n') == [
            f"{_PROBE}:1: {check_tag_t3._RAW_SETATTR_SHAPE_MESSAGE}"
        ], f"foreign-targeted write to {field!r} was admitted"


def test_setattr_on_self_is_refused_for_a_dunder_or_a_computed_field_name() -> None:
    """R2-G — the DUNDER arm and the UNFOLDABLE arm, both reached through ``self``.

    Without a self-target fixture the ``self`` check short-circuits first and neither
    arm is ever evaluated, so the mutation rows that name them are scored by a test
    that cannot see them. The positive twin is the benign idiom in the same shape.
    """
    assert _messages('object.__setattr__(self, "__dict__", v)\n') == [
        f"{_PROBE}:1: {check_tag_t3._RAW_SETATTR_SHAPE_MESSAGE}",
        f"{_PROBE}:1: {check_tag_t3._RAW_VEHICLE_STR_MESSAGE}",
    ]
    assert _messages("object.__setattr__(self, computed, v)\n") == [
        f"{_PROBE}:1: {check_tag_t3._RAW_SETATTR_SHAPE_MESSAGE}"
    ]
    assert check_tag_t3._scan_text('object.__setattr__(self, "path_prefix", v)\n', _PROBE) == []


def test_frozen_dataclass_post_init_idiom_stays_clean_with_a_positive_twin() -> None:
    """NEGATIVE FLOOR + POSITIVE TWIN in one invocation.

    Three live sites depend on the clean half: ``src/alfred/hooks/context.py:106``,
    ``src/alfred/plugins/web_fetch/allowlist.py:139``,
    ``src/alfred/plugins/web_fetch/fetch_dispatcher.py:219``. Refusing ``object.__setattr__``
    outright reds all three.

    The twin swaps ONE token (``self`` -> ``low``) and must trip, which is what proves
    the clean text reached the rule at all rather than the rule being absent.
    """
    benign = 'object.__setattr__(self, "metadata", dict(self.metadata))\n'
    assert check_tag_t3._scan_text(benign, _PROBE) == []
    twin = 'object.__setattr__(low, "metadata", dict(self.metadata))\n'
    assert _messages(twin) == [f"{_PROBE}:1: {check_tag_t3._RAW_SETATTR_SHAPE_MESSAGE}"]


def test_setattr_outside_call_position_is_refused() -> None:
    """A05 — aliasing the callable defeats every rule keyed on the CALL.

    The one-position whitelist closes it: ``Call.func`` is the only admissible position.
    Never an ancestor blacklist — that must ENUMERATE the bad positions and silently
    widens the day a new one appears.
    """
    for source in (
        "_osa = object.__setattr__\n",
        "apply(object.__setattr__, obj, 'tier', T3)\n",
        "def get():\n    return object.__setattr__\n",
    ):
        assert any(check_tag_t3._RAW_SETATTR_ALIASED_MESSAGE in m for m in _messages(source)), (
            f"admitted: {source!r}"
        )


def test_setattr_with_fewer_than_two_arguments_is_refused() -> None:
    """COVERAGE + SHAPE. ``object.__setattr__(*parts)`` supplies no readable target.

    Default-deny: a call this rule cannot read is a call it must not admit.
    """
    assert _messages("object.__setattr__(*parts)\n") == [
        f"{_PROBE}:1: {check_tag_t3._RAW_SETATTR_SHAPE_MESSAGE}"
    ]


def test_delattr_on_a_foreign_object_is_refused() -> None:
    """PR #553 SECURITY REVIEW, C1 — the THIRD member of the family had no call rule.

    ``__delattr__`` sat in ``_RAW_STATE_VEHICLE_NAMES``, so the folded-string spelling
    red, but it had neither of the two rules ``__setattr__`` and ``__init__`` were both
    given. Both of these scanned CLEAN before this fix.

    WHAT IT DOES AT RUNTIME, executed against the real ``alfred.security.tiers`` rather
    than argued. The ordinary path is already refused — ``del low.tier`` and
    ``delattr(low, "tier")`` both raise pydantic's ``frozen_instance`` ValidationError —
    while ``object.__delattr__(low, "tier")`` SUCCEEDS, which is the sole-layer class
    exactly: the write traverses no method the model can override.

    And what it leaves is a LAUNDERING, not a crash. Measured on a genuine
    ``TaggedContent[T3]`` holding attacker content: the tag simply goes absent, so
    ``getattr(hot, "tier", None) is T3`` reads False, ``getattr(hot, "tier", T0)``
    reads T0, and ``repr()``, ``dict()`` and ``model_copy()`` all SUCCEED while silently
    omitting the field. Only a direct ``.tier`` read raises. That end state is one
    ``tiers.py`` already refuses wherever it can see it — ``_refuse_if_tier_is_narrowed_away``
    (``copy(exclude={"tier"})``) and the ``{"tier": None}`` erasure arm of
    ``_coerce_and_guard_update`` both cite the same ``getattr(obj, "tier", fallback)``
    mechanism in their own docstrings — so this rule is not a new judgement about what
    counts as laundering. It is the existing one, on the seam no runtime guard can reach.
    """
    for label, source in {
        "unbound-foreign-target": 'object.__delattr__(low, "tier")\n',
        "bound-instance-dispatch": 'low.__delattr__("tier")\n',
        "type-dispatch-on-content": 'type(low).__delattr__(low, "content")\n',
    }.items():
        assert any(check_tag_t3._RAW_DELATTR_SHAPE_MESSAGE in m for m in _messages(source)), (
            f"{label} was admitted"
        )

    # POSITIVE TWIN, one token from the first fixture: the frozen-dataclass idiom on a
    # non-state field must stay clean, or the rule is a blanket ban rather than a shape.
    assert check_tag_t3._scan_text('object.__delattr__(self, "metadata")\n', _PROBE) == []


def test_delattr_is_receiver_blind_like_its_two_siblings() -> None:
    """The receiver is the rebindable half, so the rule must never read it.

    ``object`` already carries a row in ``_KEYED_IDENTIFIER_SPELLINGS`` for the
    ``__setattr__`` rules; this asserts the SAME closure holds for ``__delattr__``
    rather than assuming the two rules share more than their shape. Every spelling names
    the same receiver differently and every one must red.
    """
    for label, source in {
        "DIRECT": 'object.__delattr__(low, "tier")\n',
        "REBOUND": '_o = object\n_o.__delattr__(low, "tier")\n',
        "IMPORT-ALIASED": 'from builtins import object as _o\n_o.__delattr__(low, "tier")\n',
        "QUALIFIED": 'import builtins\nbuiltins.object.__delattr__(low, "tier")\n',
    }.items():
        assert any(check_tag_t3._RAW_DELATTR_SHAPE_MESSAGE in m for m in _messages(source)), (
            f"the {label} receiver spelling was admitted — the rule is reading the receiver"
        )


def test_delattr_denies_every_tagged_state_field_regardless_of_target() -> None:
    """The FIELD arm, reached through ``__delattr__`` rather than through its sibling.

    R2-G's discipline applies unchanged: with a foreign target the ``self`` check
    short-circuits first, so the field ban is never evaluated and a mutation to it would
    be scored by a fixture that cannot see it. The ``self`` cases are what discriminate.

    Pinned against the same module-level literal the ``__setattr__`` test uses — the two
    rules share :func:`_is_benign_state_mutation_target`, so they must share the oracle
    for the set it reads, or the shared predicate can drift under one of them.
    """
    expected = _EXPECTED_TAGGED_STATE_FIELDS
    assert expected == check_tag_t3._TAGGED_STATE_FIELDS, (
        "the declared TaggedContent state fields moved; this oracle pins them"
    )
    for field in sorted(expected):
        assert _messages(f'object.__delattr__(self, "{field}")\n') == [
            f"{_PROBE}:1: {check_tag_t3._RAW_DELATTR_SHAPE_MESSAGE}"
        ], f"self-targeted DELETE of {field!r} was admitted"
        assert _messages(f'object.__delattr__(low, "{field}")\n') == [
            f"{_PROBE}:1: {check_tag_t3._RAW_DELATTR_SHAPE_MESSAGE}"
        ], f"foreign-targeted DELETE of {field!r} was admitted"


def test_delattr_on_self_is_refused_for_a_dunder_or_a_computed_field_name() -> None:
    """The DUNDER and UNFOLDABLE arms, both reached through ``self``.

    Same shape as the ``__setattr__`` twin, and it must be asserted separately: these
    two arms live in the shared predicate, but which RULE consults it is decided by the
    ``func.attr`` comparison, and that comparison is the thing a mutant deletes.
    """
    assert _messages('object.__delattr__(self, "__dict__")\n') == [
        f"{_PROBE}:1: {check_tag_t3._RAW_DELATTR_SHAPE_MESSAGE}",
        f"{_PROBE}:1: {check_tag_t3._RAW_VEHICLE_STR_MESSAGE}",
    ]
    assert _messages("object.__delattr__(self, computed)\n") == [
        f"{_PROBE}:1: {check_tag_t3._RAW_DELATTR_SHAPE_MESSAGE}"
    ]
    assert check_tag_t3._scan_text('object.__delattr__(self, "path_prefix")\n', _PROBE) == []


def test_delattr_with_fewer_than_two_arguments_is_refused() -> None:
    """``object.__delattr__(*parts)`` supplies no readable target — default-deny.

    The starred form matters more here than for ``__setattr__``: a two-argument
    ``__delattr__`` is the COMPLETE call, so ``*parts`` is the natural way to write one
    whose field name no lexical rule can read.
    """
    assert _messages("object.__delattr__(*parts)\n") == [
        f"{_PROBE}:1: {check_tag_t3._RAW_DELATTR_SHAPE_MESSAGE}"
    ]


def test_delattr_referenced_outside_call_position_is_refused() -> None:
    """PR #553 C1, the alias half — the ONE-POSITION WHITELIST its siblings both have.

    ``_d = object.__delattr__`` then ``_d(low, "tier")`` puts no ``__delattr__`` node in
    ``Call.func`` position, so the shape rule above is blind to it BY CONSTRUCTION. This
    is the second of the two spellings the review reproduced as a MISS.

    Measured across both scan roots: zero ``__delattr__`` attribute nodes exist in ANY
    position, so this costs nothing.
    """
    for source in (
        '_d = object.__delattr__\n_d(low, "tier")\n',
        "apply(object.__delattr__, obj, 'tier')\n",
        "def get():\n    return object.__delattr__\n",
    ):
        assert any(check_tag_t3._RAW_DELATTR_ALIASED_MESSAGE in m for m in _messages(source)), (
            f"admitted: {source!r}"
        )
    assert check_tag_t3._scan_text('object.__delattr__(self, "metadata")\n', _PROBE) == [], (
        "positive twin: a call-position __delattr__ on self must NOT trip the alias rule"
    )


def test_the_two_state_mutation_rules_share_one_admissibility_predicate() -> None:
    """DRY, asserted rather than assumed (#422: N copies drift SILENTLY).

    ``__setattr__`` and ``__delattr__`` put the TARGET at ``args[0]`` and the FIELD NAME
    at ``args[1]``, so the admissibility question is identical and
    :func:`_is_benign_state_mutation_target` answers it for both. If someone forks it,
    the two rules can diverge on the same input without any test noticing — one of them
    quietly admitting a shape the other refuses. This asserts the property directly: for
    every fixture, the two rules agree on admissibility.
    """
    assert check_tag_t3._is_benign_state_mutation_target.__doc__, "the shared predicate vanished"

    # EVERY ARM the predicate decides on, not just the field name (PR #553, CR).
    # Fixtures that vary only the FIELD exercise `_TAGGED_STATE_FIELDS` and the dunder
    # check; a fork that copies the field logic and relaxes the TARGET or the ARITY arm
    # agrees with its twin on all of them and survives. MEASURED: with the
    # `args[0] is the bare Name self` arm stubbed to always pass, the field-only
    # fixtures were still green.
    #
    # Each case is (setattr-argv, delattr-argv, admissible, arm) — the two argv strings
    # differ only in the value argument, which `__delattr__` does not take.
    cases = (
        # the FIELD arm
        ('self, "metadata", v', 'self, "metadata"', True, "benign field on self"),
        ('self, "tier", v', 'self, "tier"', False, "tier is state"),
        ('self, "content", v', 'self, "content"', False, "content is state"),
        ('self, "source", v', 'self, "source"', False, "source is state"),
        ('self, "__dict__", v', 'self, "__dict__"', False, "dunder reaches interpreter state"),
        # the TARGET arm — a benign FIELD on a foreign object is still a write to
        # someone else's state. `self` is a naming convention, not a type, so this arm
        # only narrows; it must nonetheless be exercised or a fork can drop it.
        ('low, "metadata", v', 'low, "metadata"', False, "foreign target"),
        ('obj.inner, "metadata", v', 'obj.inner, "metadata"', False, "attribute target"),
        ('"literal", "metadata", v', '"literal", "metadata"', False, "non-Name target"),
        # the ARITY arm — a call this rule cannot read is a call it must not admit.
        ("*parts", "*parts", False, "starred argv, unreadable"),
        ("", "", False, "no arguments at all"),
        ("self, name, v", "self, name", False, "computed field name"),
    )
    for set_argv, del_argv, admissible, arm in cases:
        set_clean = not any(
            check_tag_t3._RAW_SETATTR_SHAPE_MESSAGE in m
            for m in _messages(f"object.__setattr__({set_argv})\n")
        )
        del_clean = not any(
            check_tag_t3._RAW_DELATTR_SHAPE_MESSAGE in m
            for m in _messages(f"object.__delattr__({del_argv})\n")
        )
        assert set_clean is admissible and del_clean is admissible, (
            f"the two rules disagree on the {arm!r} arm ({set_argv!r}): "
            f"__setattr__ clean={set_clean}, __delattr__ clean={del_clean}, "
            f"expected {admissible} — the shared admissibility predicate has been forked"
        )
    assert any(a for *_, a, _ in cases), "anti-vacuity: no admissible fixture left"


def test_init_re_entry_on_a_foreign_object_is_refused() -> None:
    """PR #553 SECURITY REVIEW, F3 — pydantic's ``__init__`` IS a raw-state write.

    ``BaseModel.__init__`` calls ``validate_python(..., self_instance=self)``, which
    writes the instance ``__dict__`` directly — the "never traverses ``__setattr__``"
    class this whole rule set exists for. EXECUTED against a real
    ``TaggedContent[T2]``: ``content`` was replaced with attacker text and ``source``
    forged to ``operator.console``, and the gate returned rc=0.

    BOTH dispatch forms are covered, and the bound one was not in the review's report:
    ``low.__init__(content=…)`` re-enters the same initialiser with no positional
    argument at all, so a rule that only read ``args[0]`` would have missed it. The
    rule is receiver-BLIND for the same reason the ``__setattr__`` rules are.

    The TIER is safe by a different mechanism and the twin below records it: the
    cross-tier field validator refuses ``tier=T3`` on a ``TaggedContent[T2]`` with a
    ``security.t3_boundary.refused`` audit row. This rule closes ``content`` and
    ``source``, which nothing else did.
    """
    for label, source in {
        "unbound-class-dispatch": (
            'type(low).__init__(low, content=attacker, source="operator.console", tier=low.tier)\n'
        ),
        "bound-instance-dispatch": 'low.__init__(content=attacker, source="forged")\n',
        "basemodel-dispatch": "BaseModel.__init__(low, content=attacker)\n",
    }.items():
        assert any(check_tag_t3._RAW_INIT_SHAPE_MESSAGE in m for m in _messages(source)), (
            f"{label} was admitted"
        )

    # THE TWO LIVE SHAPES, both of which must stay clean. 62 `__init__` attribute nodes
    # exist across both scan roots: 59 zero-argument `super()` and 3
    # `AlfredError.__init__(self, …)` in `src/alfred/egress/errors.py`. Measured
    # false-positive cost of this rule: ZERO.
    assert (
        check_tag_t3._scan_text(
            "class C(B):\n    def __init__(self, **kw):\n        super().__init__(**kw)\n", _PROBE
        )
        == []
    ), "positive twin: zero-argument super().__init__() is the ordinary constructor chain"
    assert (
        check_tag_t3._scan_text(
            'class E(X):\n    def __init__(self, d):\n        AlfredError.__init__(self, t("k"))\n',
            _PROBE,
        )
        == []
    ), "positive twin: unbound dispatch onto `self` is the three live egress/errors.py sites"


def test_only_the_zero_argument_super_spelling_is_admissible() -> None:
    """The admissibility arm keys on ``super`` in the FAIL-CLOSED direction.

    ``super(TaggedContent, low)`` names a FOREIGN object explicitly, so it must red —
    the zero-argument form is the only one the compiler binds to the enclosing method's
    own first parameter.

    Rebinding the name makes the gate STRICTER, not weaker, which is why ``super`` needs
    no row in ``test_every_keyed_identifier_is_alias_resolved``. MEASURED, not assumed:
    ``_s = super`` followed by ``_s()`` raises ``RuntimeError: super(): __class__ cell
    not found``, because the compiler only creates the ``__class__`` cell when it sees
    the literal name ``super`` in the method body. The rebound spelling is dead at
    runtime AND refused here.
    """
    assert any(
        check_tag_t3._RAW_INIT_SHAPE_MESSAGE in m
        for m in _messages("super(TaggedContent, low).__init__(content=attacker)\n")
    ), "the two-argument super() form names a foreign object and was admitted"
    assert any(
        check_tag_t3._RAW_INIT_SHAPE_MESSAGE in m
        for m in _messages(
            "_s = super\nclass C(B):\n    def __init__(self):\n        _s().__init__()\n"
        )
    ), "a rebound super must fail CLOSED"
    assert (
        check_tag_t3._scan_text(
            "class C(B):\n    def __init__(self):\n        super().__init__()\n", _PROBE
        )
        == []
    ), "positive twin: the literal zero-argument spelling is the admissible one"


def test_init_referenced_outside_call_position_is_refused() -> None:
    """PR #553 F3, the alias half — the same ONE-POSITION WHITELIST ``__setattr__`` uses.

    ``_f = type(low).__init__`` then ``_f(low, content=attacker)`` reaches the identical
    write with no ``__init__`` node in ``Call.func`` position, so the shape rule above is
    blind to it by construction. ``Call.func`` is the only admissible position; every
    other one is the alias vehicle. Never an ancestor blacklist — that has to ENUMERATE
    the bad positions.

    Measured across both scan roots: all 62 ``__init__`` attribute nodes sit in
    ``Call.func``, so this costs ZERO false positives.
    """
    assert _messages("_f = type(low).__init__\n_f(low, content=attacker)\n") == [
        f"{_PROBE}:1: {check_tag_t3._RAW_INIT_ALIASED_MESSAGE}"
    ]
    assert (
        check_tag_t3._scan_text(
            "class C(B):\n    def __init__(self):\n        super().__init__()\n", _PROBE
        )
        == []
    ), "positive twin: a call-position __init__ must NOT trip the alias rule"


# R2-E — PINNED HERE, AS SEPARATE LITERALS, module-level so the three tests that
# need them share ONE copy (matching `_EXPECTED_SEAMS` / `_EXPECTED_PRIVATE_SURFACE`
# below). Each enforcement test asserts the literal EQUALS the constant under test
# first and then loops over the LITERAL — looping over the constant would remove the
# member from the oracle at the same moment a mutation removes it from the rule.
#
# Three carriers reach these names and each needs its own loop: an `ast.Attribute`
# node, a folded STRING, and a bare `ast.Name`.
_EXPECTED_VEHICLE_ATTRS = frozenset(
    {
        "__dict__",
        "__setstate__",
        "__getstate__",
        "__reduce__",
        "__reduce_ex__",
        "__new__",
        "__mro__",
        "__bases__",
        "__doc__",
    }
)
_EXPECTED_VEHICLE_NAMES = _EXPECTED_VEHICLE_ATTRS | frozenset(
    {"__setattr__", "__delattr__", "__class__", "__init__"}
)


def test_vehicle_attributes_are_refused() -> None:
    """A02, A07 and the rest of the raw-state class, banned as VEHICLES."""
    for source in (
        'obj.__dict__.update({"tier": T3})\n',
        'd = obj.__dict__\nd["tier"] = T3\n',
        'obj.__setstate__({"tier": T3})\n',
        "o = TaggedContent.__new__(TaggedContent[T3])\n",
        "f, args = obj.__reduce__()\n",
        "base = type(low).__mro__[-1]\n",
    ):
        assert any(check_tag_t3._RAW_VEHICLE_ATTR_MESSAGE in m for m in _messages(source)), (
            f"admitted: {source!r}"
        )


def test_every_declared_vehicle_attribute_is_enforced() -> None:
    """R2-E/R2-H — pin the set as a literal HERE, then loop over the PINNED copy.

    Three of the members were untested, so dropping them from the constant survived
    the whole suite AND the real-tree scan. Looping over the constant under test would
    not have caught it either: the mutation removes the member from the oracle at the
    same time.
    """
    expected = _EXPECTED_VEHICLE_ATTRS
    assert expected == check_tag_t3._RAW_STATE_VEHICLE_ATTRS, (
        "the declared vehicle-attribute set moved; this oracle pins it"
    )
    for attr in sorted(expected):
        assert _messages(f"x = obj.{attr}\n") == [
            f"{_PROBE}:1: {check_tag_t3._RAW_VEHICLE_ATTR_MESSAGE}"
        ], f"vehicle attribute {attr!r} is declared but not enforced"


def test_dunder_doc_hands_the_prose_exclusion_back_as_data() -> None:
    """PR #553 SECURITY REVIEW, F1 — the premise under the prose exclusion was FALSE.

    ``_prose_string_ids`` excludes a bare string statement from BOTH string-keyed rules
    on the grounds that "a string that is a whole statement documents; a string anywhere
    else is data". ``__doc__`` refutes that: it hands the very same string back in code
    position, and ``__doc__`` was in no vehicle set. Both spellings below were EXECUTED
    end to end — the first installed an attacker nonce and minted a genuine
    ``TaggedContent[T3]``, the second relabelled a live T2 object.

    The fix is not to stop excluding prose (that would readmit A17,
    ``getattr(_t, "_set_authorized_t3_nonce")``) but to make the RETRIEVAL a vehicle.
    Measured cost across both scan roots: ZERO ``__doc__`` nodes of any kind.
    """
    for label, source in {
        "class-docstring-as-nonce-name": (
            'class _Codec:\n    "_set_authorized_t3_nonce"\ngetattr(_t, _Codec.__doc__)(mine)\n'
        ),
        "function-docstring-as-vehicle-name": (
            'def _c(): "__dict__"\ngetattr(low, _c.__doc__)["tier"] = T3\n'
        ),
    }.items():
        assert any(check_tag_t3._RAW_VEHICLE_ATTR_MESSAGE in m for m in _messages(source)), (
            f"{label} was admitted — the prose exclusion is still a data channel"
        )
    assert check_tag_t3._scan_text('class _Codec:\n    "an ordinary docstring"\n', _PROBE) == [], (
        "positive twin: a docstring nobody reads back is still prose"
    )


def test_a_vehicle_name_reached_as_a_bare_identifier_is_refused() -> None:
    """PR #553 SECURITY REVIEW, F1 — the THIRD carrier for the same name set.

    A module's own docstring is bound to the bare identifier ``__doc__``, which is
    neither an ``ast.Attribute`` (so the attribute arm is blind) nor a string constant
    (so the folded-string arm is blind). A module docstring whose entire value is
    ``_set_authorized_t3_nonce``, followed by ``getattr(_t, __doc__)(mine)``, is the
    same F1 channel one level down — and the docstring is prose-excluded, so nothing
    else can see it either.

    Closed as a CARRIER rather than as the one name that has this spelling: every
    member of the name set is refused in bare-identifier position. Measured cost across
    both scan roots: ZERO bare ``ast.Name`` nodes carrying any of these ids.
    """
    assert _messages('"""_set_authorized_t3_nonce"""\ngetattr(_t, __doc__)(mine)\n') == [
        f"{_PROBE}:2: {check_tag_t3._RAW_VEHICLE_NAME_MESSAGE}"
    ]
    assert check_tag_t3._scan_text("x = ordinary_identifier\n", _PROBE) == [], (
        "positive twin: an ordinary bare name must NOT red"
    )


def test_every_declared_vehicle_name_is_enforced_as_a_bare_identifier() -> None:
    """The bare-``Name`` carrier's completeness loop, over the PINNED literal."""
    assert _EXPECTED_VEHICLE_NAMES == check_tag_t3._RAW_STATE_VEHICLE_NAMES, (
        "the declared vehicle-NAME set moved; this oracle pins it"
    )
    for name in sorted(_EXPECTED_VEHICLE_NAMES):
        assert _messages(f"x = {name}\n") == [
            f"{_PROBE}:1: {check_tag_t3._RAW_VEHICLE_NAME_MESSAGE}"
        ], f"vehicle name {name!r} is declared but not enforced as a bare identifier"


def test_class_swap_is_refused_but_a_class_read_is_not() -> None:
    """``__class__`` discriminated by CONTEXT, not by name.

    A class swap is a laundering vehicle; ``exc.__class__.__name__`` (live at
    ``hooks/invoke.py:1265``) is an ordinary read. Banning the name costs a false
    positive; banning the STORE/DEL context costs zero. ``del`` is included because
    ``ast.Del`` is a separate context and was untested (R2-H).
    """
    assert _messages("low.__class__ = Evil\n") == [
        f"{_PROBE}:1: {check_tag_t3._RAW_CLASS_SWAP_MESSAGE}"
    ]
    assert _messages("del obj.__class__\n") == [
        f"{_PROBE}:1: {check_tag_t3._RAW_CLASS_SWAP_MESSAGE}"
    ]
    assert check_tag_t3._scan_text('t = {"x": exc.__class__.__name__}\n', _PROBE) == []


def test_vars_is_refused_and_ordinary_getattr_is_not() -> None:
    """A03 — ``vars(obj)`` returns the mapping ``__dict__`` does.

    Twin floor: ``getattr(prev, field)`` is four live sites in
    ``policies/snapshot_ref.py``. Banning non-literal ``getattr`` outright costs 7
    false positives (measured); this rule does not do that.
    """
    assert _messages('vars(obj)["tier"] = T3\n') == [
        f"{_PROBE}:1: {check_tag_t3._RAW_VEHICLE_VARS_MESSAGE}"
    ]
    assert check_tag_t3._scan_text("prev_val = getattr(prev, field)\n", _PROBE) == []


def test_vars_is_matched_by_alias_not_by_the_bare_name() -> None:
    """SELF-AUDIT ROW — ``vars`` was the last identifier still matched as a literal.

    ``_v = vars; _v(obj)["tier"] = T3`` scanned clean until the receiver was resolved
    through ``_alias_names``. Every bare identifier a rule keys on is a NAME, and
    Python lets any name be rebound; matching one spelling closes one spelling.

    (The plan's mutation table attributes this row to Task 4's
    ``test_every_keyed_identifier_is_alias_resolved`` meta-test. That test does not
    exist yet, so the rule Task 2 ships carries its own behavioural oracle here.)
    """
    for label, source in {
        "rebind": '_v = vars\n_v(obj)["tier"] = T3\n',
        "import-alias": 'from builtins import vars as _v\n_v(obj)["tier"] = T3\n',
    }.items():
        assert any(check_tag_t3._RAW_VEHICLE_VARS_MESSAGE in m for m in _messages(source)), (
            f"{label} spelling was admitted"
        )


def test_vehicle_dunder_named_as_a_folded_string_is_refused() -> None:
    """A06 — ``getattr(obj, "__dict__")`` produces no ``ast.Attribute``.

    The folded form is the fleet's sec-004 shape: ``ast`` folds implicit concatenation
    but not ``+``.
    """
    for source in (
        'getattr(obj, "__dict__")["tier"] = T3\n',
        '_A = "__dict__"\n',
        'getattr(obj, "__di" + "ct__")["tier"] = T3\n',
    ):
        assert any(check_tag_t3._RAW_VEHICLE_STR_MESSAGE in m for m in _messages(source)), (
            f"admitted: {source!r}"
        )


def test_a_vehicle_named_only_as_a_string_is_refused() -> None:
    """FLEET FINDING sec2-001 — the STRING set is DELIBERATELY WIDER than the attribute set.

    ``getattr(object, "__setattr__")(low, "tier", T3)`` produces NO ``ast.Attribute``
    node at all, so every attribute-keyed rule is blind to it; executed, it turned a
    ``TaggedContent[T2]`` into T3.

    ``__setattr__`` must NOT join the ATTRIBUTE set: the three live benign
    ``object.__setattr__(self, ...)`` sites all carry that attribute node, and the
    receiver-blind rules already cover the attribute form. Both halves are asserted
    here — the widening and the thing that must not widen with it.
    """
    expected = _EXPECTED_VEHICLE_NAMES
    assert expected == check_tag_t3._RAW_STATE_VEHICLE_NAMES, (
        "the declared vehicle-NAME set moved; this oracle pins it"
    )
    assert expected > check_tag_t3._RAW_STATE_VEHICLE_ATTRS, (
        "the string set must be a STRICT superset of the attribute set — collapsing "
        "them reopens the getattr() spelling that carries no attribute node"
    )
    assert "__setattr__" not in check_tag_t3._RAW_STATE_VEHICLE_ATTRS, (
        "adding __setattr__ to the ATTRIBUTE set reds all three live benign sites"
    )
    # PR #553 F3 — `__init__` joins the NAME set on the same precedent, and must stay out
    # of the ATTRIBUTE set for the same reason: 62 live sites carry that attribute node.
    assert "__init__" not in check_tag_t3._RAW_STATE_VEHICLE_ATTRS, (
        "adding __init__ to the ATTRIBUTE set reds all 62 live super()/self sites"
    )
    assert any(
        check_tag_t3._RAW_VEHICLE_STR_MESSAGE in m
        for m in _messages('getattr(type(low), "__init__")(low, content=attacker)\n')
    ), "the string spelling carries no attribute node, so the call rule cannot see it"
    assert check_tag_t3._scan_text('object.__setattr__(self, "metadata", v)\n', _PROBE) == []
    for name in sorted(expected):
        assert _messages(f'_A = "{name}"\n') == [
            f"{_PROBE}:1: {check_tag_t3._RAW_VEHICLE_STR_MESSAGE}"
        ], f"vehicle name {name!r} is declared but not enforced as a string"


def test_a_raw_state_dunder_in_prose_stays_clean_with_a_positive_twin() -> None:
    """WIDENING GUARD for the string rule (fleet finding arch-004/test-003 M1).

    The real tree contains ZERO prose-position vehicle strings, so neither the
    real-tree scan nor any other floor can kill a mutant that drops the prose
    exclusion here. This test is the only thing that can.

    R2-F: the docstring's ENTIRE value must BE a set member. The plan's original
    fixture (``\"\"\"Explains ``obj.__dict__`` handling.\"\"\"``) folds to a whole
    sentence, which never equals a member, so the prose exclusion was never consulted
    and the mutant survived.
    """
    assert check_tag_t3._scan_text('"""__dict__"""\n', _PROBE) == []
    assert _messages('x = "__dict__"\n') == [f"{_PROBE}:1: {check_tag_t3._RAW_VEHICLE_STR_MESSAGE}"]


def test_the_string_rule_matches_the_whole_name_not_a_substring() -> None:
    """R2-H — the equality-to-containment WIDENING reds nothing in the tree today.

    PR #553 SECURITY REVIEW, F5 — the SECOND half of that claim was measurably wrong
    and is corrected here and at the rule. "Admitting no new attack" is false: an
    ``exec`` whose argument is a whole laundering statement scans clean under equality
    and would red under containment. The exposure is small because ``ruff`` refuses
    ``exec``/``eval`` independently (``S102``/``S307``, both verified by execution in
    BOTH scan roots — ``select`` carries ``"S"``, only ``S101`` is ignored,
    ``per-file-ignores`` covers ``tests/**`` only, and CI runs ``ruff check .``), but
    the CLAIM is what invites a future author to keep equality on bad reasoning.

    Equality STAYS: containment was measured as a widening with its own costs, and
    ``exec``/``eval`` are out of this rule's reach either way. The two floors below pin
    the residual so a switch to containment has to come and edit them.
    """
    assert check_tag_t3._scan_text('x = "reset the __dict__ mapping"\n', _PROBE) == []
    assert (
        check_tag_t3._scan_text(
            "exec(\"object.__setattr__(low, '__dict__', {'tier': T3})\")\n", _PROBE
        )
        == []
    ), "F5 residual moved: exec() is out of this rule's reach and ruff S102 is what refuses it"
    assert _messages('x = "__dict__"\n') == [f"{_PROBE}:1: {check_tag_t3._RAW_VEHICLE_STR_MESSAGE}"]


def test_the_fold_residual_covers_the_vehicle_names_not_only_private_ones() -> None:
    """PR #553 SECURITY REVIEW, F6 — the ``%``/``.format()``/``join()`` residual is GENERAL.

    It was documented only against ``_set_authorized_t3_nonce``. It applies to
    ``_RAW_STATE_VEHICLE_NAMES`` identically: ``"__dict%s" % "__"`` is assembled
    entirely from literals and folds to ``None``, so the string arm never sees it.
    The residual is the OPERATION, not the operands — pinned here so the documentation
    and the behaviour cannot drift apart.
    """
    assert check_tag_t3._scan_text('getattr(low, "__dict%s" % "__")["tier"] = T3\n', _PROBE) == []
    assert _messages('getattr(low, "__di" + "ct__")["tier"] = T3\n') == [
        f"{_PROBE}:1: {check_tag_t3._RAW_VEHICLE_STR_MESSAGE}"
    ], "positive twin: the `+` spelling IS folded, so this test is not vacuous"


def test_carrier_by_reference_primitives_are_refused() -> None:
    """FLEET FINDING sec-003 — ``gc.get_referents(obj)`` names no vehicle at all.

    Scoped to the reaching PRIMITIVES, not to the modules: a module-scoped ban costs
    two legitimate sites (``ctypes.CDLL`` for libc in ``supervisor/process_posture.py``,
    ``gc.collect()`` in ``fd3_key_delivery.py``); the primitive ban costs ZERO.
    Both live benign uses are the twin here.
    """
    for source in (
        'import gc\ngc.get_referents(low)[0]["tier"] = T3\n',
        # PR #553 F2: the unlisted sibling. `get_referrers` hands back an instance
        # `__dict__` exactly as `get_referents` and `get_objects` do, and executed it
        # relabelled a live object with the static type still reading T2.
        'import gc\ngc.get_referrers(low)[0]["tier"] = T3\n',
        "import ctypes\nctypes.cast(id(low), ctypes.py_object)\n",
    ):
        assert any(check_tag_t3._RAW_CARRIER_MESSAGE in m for m in _messages(source)), (
            f"admitted: {source!r}"
        )
    assert check_tag_t3._scan_text("import gc\ngc.collect()\n", _PROBE) == []
    assert (
        check_tag_t3._scan_text(
            'import ctypes\nlibc = ctypes.CDLL("libc.so.6", use_errno=True)\n', _PROBE
        )
        == []
    )


# R2-E — PINNED HERE, SEPARATELY FROM THE IMPLEMENTATION, and at module level for the
# same reason as `_EXPECTED_TAGGED_STATE_FIELDS`: the residual declaration at the foot of
# this file names this literal rather than restating its members a second time.
_EXPECTED_CARRIERS = frozenset(
    {
        ("gc", "get_referents"),
        ("gc", "get_objects"),
        ("gc", "get_referrers"),
        ("ctypes", "py_object"),
        ("ctypes", "cast"),
        ("copyreg", "_reconstructor"),
        ("copyreg", "__newobj__"),
    }
)


def test_every_declared_carrier_primitive_is_enforced() -> None:
    """R2-E/R2-H — four of the six were never exercised in ``Call.func`` position.

    ``ctypes.py_object`` appeared only as an ARGUMENT in its fixture, so dropping it
    from the constant survived the suite. Pin the set as a literal, then loop over the
    pinned copy with each primitive in the position the rule actually keys on.

    PR #553 SECURITY REVIEW, F2 — ``gc.get_referrers`` joined the set. It is the
    unlisted sibling of the two ``gc`` primitives that were already here and hands back
    an instance ``__dict__`` exactly as they do; executed, it relabelled a live object
    while its static type stayed ``TaggedContent[T2]``.
    """
    expected = _EXPECTED_CARRIERS
    assert expected == check_tag_t3._RAW_STATE_CARRIERS, (
        "the declared carrier-primitive set moved; this oracle pins it"
    )
    for module, primitive in sorted(expected):
        assert _messages(f"import {module}\n{module}.{primitive}(low)\n") == [
            f"{_PROBE}:2: {check_tag_t3._RAW_CARRIER_MESSAGE}"
        ], f"carrier {module}.{primitive} is declared but not enforced"


def test_carrier_module_is_matched_by_alias_not_by_the_bare_name() -> None:
    """FLEET FINDING sec2-003 — ``import gc as _g`` scanned clean.

    Four binding forms, three of which a rule keyed on the literal ``gc`` cannot see.
    The direct-binding forms need their own pass over ``ast.ImportFrom``: they bind the
    PRIMITIVE as a bare ``Name``, so no module identifier appears at the call site at all.

    PR #553 REVIEW, T4 — THE MULTI-NAME IMPORT. Every direct-binding fixture here used
    to import exactly ONE name, so a pass that stopped after the first ``node.names``
    entry survived the suite and the real-tree scan: ``from gc import collect,
    get_referents`` bound only the benign ``collect`` and the carrier walked through.
    Both direct rows below now import a benign name FIRST, so the loop has to reach past
    it.

    (As with ``vars`` above, the plan attributes this row to Task 4's
    ``test_every_keyed_identifier_is_alias_resolved``; Task 2's rule carries its own
    behavioural oracle until that meta-test lands.)
    """
    for label, source in {
        "module-rebind": "import gc\n_g = gc\n_g.get_referents(low)\n",
        "import-alias": "import gc as _g\n_g.get_referents(low)\n",
        "direct-binding": "from gc import collect, get_referents\nget_referents(low)\n",
        "direct-alias": "from gc import collect, get_referents as _gr\n_gr(low)\n",
    }.items():
        assert any(check_tag_t3._RAW_CARRIER_MESSAGE in m for m in _messages(source)), (
            f"{label} spelling was admitted"
        )
    assert check_tag_t3._scan_text("from gc import collect\ncollect()\n", _PROBE) == []


def test_a_deeper_than_budget_alias_chain_is_reported_by_the_scanner() -> None:
    """R2-J — nothing else drives ``_ALIAS_BUDGET_MESSAGE`` out of ``_scan_text``.

    ``_alias_names`` reports overflow, but until a chain deeper than the budget reaches
    the scanner the emitting arc is uncovered and the fail-closed disposition is
    untested end-to-end. Reported at line 1 because the overflow is a property of the
    FILE's alias graph, not of any single line.
    """
    depth = check_tag_t3._ALIAS_RESOLUTION_BUDGET + 5
    chain = "".join(f"a{i} = a{i - 1}\n" for i in range(depth, 0, -1)) + "a0 = vars\n"
    assert _messages(chain) == [f"{_PROBE}:1: {check_tag_t3._ALIAS_BUDGET_MESSAGE}"]
    assert check_tag_t3._scan_text("b = vars\n", _PROBE) == [], (
        "positive twin: an ordinary alias must NOT report overflow"
    )


def test_a_deeper_than_budget_carrier_chain_is_reported_by_the_scanner() -> None:
    """PR #553 REVIEW, T1 — the ``carrier_overflow`` half of the fan-in was UNTESTED.

    ``_scan_text`` reports the budget message when ANY of four flags is set, and only
    two of the four (``vars``, ``BaseModel``) had a behavioural test. Measured: dropping
    ``carrier_overflow`` from the fan-in, and separately breaking the accumulator in
    :func:`_carrier_bindings` so it can never become True, BOTH survived the whole suite
    AND the real-tree scan. Executed on the chain below, the shipped gate reports the
    budget message and each mutant reports NOTHING AT ALL — a total silent fail-open on
    the one input the budget exists to catch, in the layer that is the sole enforcement
    layer.

    Seeded on a CARRIER MODULE so this flag is the only one that can be set: no
    assignment in the fixture sources ``vars``, ``BaseModel`` or a private name, so
    ``_alias_names`` returns on its first iteration for all of those.
    """
    depth = check_tag_t3._ALIAS_RESOLUTION_BUDGET + 5
    chain = "import gc\n" + "".join(f"a{i} = a{i - 1}\n" for i in range(depth, 0, -1))
    chain += "a0 = gc\n"
    # Line 1 whatever the fixture looks like: the overflow is a property of the FILE's
    # alias graph, not of the line the deep chain happens to start on.
    assert _messages(chain) == [f"{_PROBE}:1: {check_tag_t3._ALIAS_BUDGET_MESSAGE}"]
    assert check_tag_t3._scan_text("import gc\nb = gc\n", _PROBE) == [], (
        "positive twin: an ordinary carrier alias must NOT report overflow"
    )


def test_a_deep_concatenation_chain_does_not_fault_the_detector_fence() -> None:
    """R2-L — ``_fold_str`` runs INSIDE the fence, so an unbounded fold suppresses findings.

    A ``GateInternalError`` here makes ``main`` exit 2 and DISCARD every violation
    collected so far, so one pathological ``+`` chain would hide a real laundering
    finding in an EARLIER file. The depth bound turns that into a local non-match.

    The chain is parsed rather than hand-built (Task 1 covers the hand-built case), so
    it is kept well inside the parser's own limits: a 50 000-operand chain raises
    ``RecursionError`` from ``ast.parse`` on the uv standalone build and parses cleanly
    on Homebrew, and asserting across that difference would pin the BUILD.

    R2-I — THE POSITIVE TWIN IS LOAD-BEARING. Measured: without it this was the single
    test in this file that PASSED against ``origin/main``, green for the OPPOSITE reason
    it exists. A gate with no fold rule at all also returns ``[]`` for the deep chain,
    so the floor alone cannot tell "the fold is bounded" from "there is no fold". The
    twin folds a chain INSIDE the bound to a vehicle name and requires it to TRIP, which
    is what proves the rule is present and reached before the floor is consulted.
    """
    assert _messages('x = "__di" + "ct" + "__"\n') == [
        f"{_PROBE}:1: {check_tag_t3._RAW_VEHICLE_STR_MESSAGE}"
    ], "positive twin: the BinOp fold must be live, or the deep-chain floor proves nothing"

    operands = 500
    source = "x = " + " + ".join(f'"a{i}"' for i in range(operands)) + "\n"
    assert check_tag_t3._scan_text(source, _PROBE) == []


# ---------------------------------------------------------------------------
# Task 3 — unbound `BaseModel` seam dispatch.
#
# `BaseModel.model_copy(low, update={"tier": T3})` builds field state through
# `_copy_and_set_values` with the CLASS as receiver, so it reaches neither the
# subclass overrides nor `model_post_init`. That is the original tl-2026-013
# shape, and no runtime guard sits on the path it takes.
# ---------------------------------------------------------------------------

# R2-E — PINNED HERE, SEPARATELY FROM THE IMPLEMENTATION. Looping over
# `check_tag_t3._BASEMODEL_SEAM_ATTRS` would be a TAUTOLOGICAL ORACLE: removing
# `model_validate` from the constant removes it from the oracle in the same edit, so
# the mutation cannot be observed. MEASURED — that exact mutation SURVIVED the
# loop-over-the-constant form. Assert equality against the module constant FIRST,
# then loop over this copy.
_EXPECTED_SEAMS = frozenset(
    {"copy", "model_copy", "model_construct", "model_validate", "model_validate_json"}
)


def test_unbound_basemodel_seam_dispatch_is_refused() -> None:
    """The original tl-2026-013 unbound-dispatch spellings, asserted by EQUALITY.

    ``copy`` is pydantic v1's spelling and does NOT route through ``model_copy`` — it
    merges ``update`` inside ``copy_internals`` — so both must be named.
    """
    # #539's tier-mutating-copy rule fires on the SAME lines, and both are correct:
    # `BaseModel.model_copy(low, update={"tier": T3})` is an unbound base dispatch AND an
    # update mapping that reaches a tier key. Asserting by EQUALITY is what surfaced that —
    # a containment assertion would have hidden the second rule's arrival entirely, which
    # is the property this file's equality style exists to have. The order is `_detect`'s
    # append order, not an alphabetisation.
    assert _messages('BaseModel.model_copy(low, update={"tier": T3})\n') == [
        f"{_PROBE}:1: {check_tag_t3._TIER_MUTATING_COPY_MESSAGE}",
        f"{_PROBE}:1: {check_tag_t3._BASEMODEL_VALUE_MESSAGE}",
    ]
    assert _messages('BaseModel.copy(low, update={"tier": T3})\n') == [
        f"{_PROBE}:1: {check_tag_t3._TIER_MUTATING_COPY_MESSAGE}",
        f"{_PROBE}:1: {check_tag_t3._BASEMODEL_VALUE_MESSAGE}",
    ]


def test_qualified_basemodel_receiver_is_refused() -> None:
    """FLEET FINDING test-005 — ``pydantic.BaseModel.model_copy(...)`` scanned CLEAN.

    The first revision hand-rolled ``isinstance(func.value, ast.Name)`` on the receiver
    and so saw only the bare spelling, reintroducing exactly the CR-138 round-2 finding
    #2 class that :func:`_arg_name` exists to close. Collapsing the receiver with
    ``_arg_name`` — the same helper the other widenings use — means the two cannot
    drift apart.
    """
    source = 'import pydantic\npydantic.BaseModel.model_copy(low, update={"tier": T3})\n'
    assert _messages(source) == [
        f"{_PROBE}:2: {check_tag_t3._TIER_MUTATING_COPY_MESSAGE}",
        f"{_PROBE}:2: {check_tag_t3._BASEMODEL_VALUE_MESSAGE}",
    ]


def test_qualified_receiver_does_not_widen_to_ordinary_modules() -> None:
    """NEGATIVE FLOOR + POSITIVE TWIN (R2-I).

    Collapsing the receiver must not make every two-deep attribute call a finding.
    The twin swaps ONE token in the second floor (``mod.helper`` -> ``pydantic.BaseModel``)
    and must TRIP — without it this is a bare floor that a gate with no rule at all
    satisfies, which is the shape R2-I counted four of.
    """
    assert check_tag_t3._scan_text("import os\np = os.path.join(a, b)\n", _PROBE) == []
    assert check_tag_t3._scan_text("x = mod.helper.copy()\n", _PROBE) == []
    assert _messages("import pydantic\nx = pydantic.BaseModel.copy(low)\n") == [
        f"{_PROBE}:2: {check_tag_t3._BASEMODEL_VALUE_MESSAGE}"
    ], "positive twin: the qualified receiver must still be collapsed and refused"


def test_basemodel_dunder_func_dispatch_is_refused() -> None:
    """``BaseModel.model_construct.__func__(cls, ...)`` — one hop further.

    Dispatch through the unbound function object skips every override on the way in,
    exactly as the two-level form does, and the receiver of the seam is one attribute
    deeper. Asserted by EQUALITY: containment on element 0 is the shape that let a
    mutant survive elsewhere in this suite.
    """
    source = "built = BaseModel.model_construct.__func__(TaggedContent[T3], tier=T3)\n"
    assert _messages(source) == [f"{_PROBE}:1: {check_tag_t3._BASEMODEL_VALUE_MESSAGE}"]


def test_a_non_seam_attribute_below_the_basemodel_receiver_stays_clean() -> None:
    """COVERAGE + SHAPE for the nested arm's OWN seam check.

    ``BaseModel.model_fields.get(x)`` reaches the nested arm with a BaseModel receiver
    and a non-seam middle attribute — the only shape that evaluates
    ``receiver.attr in _BASEMODEL_SEAM_ATTRS`` to False. Without it the nested arm is
    scored entirely by fixtures where the receiver check already decided the answer.
    """
    assert check_tag_t3._scan_text("v = BaseModel.model_fields.get(name)\n", _PROBE) == []
    assert _messages("v = BaseModel.model_copy.__func__(low)\n") == [
        f"{_PROBE}:1: {check_tag_t3._BASEMODEL_VALUE_MESSAGE}"
    ], "positive twin: the same two-deep shape with a SEAM in the middle must trip"


def test_import_aliased_basemodel_is_refused() -> None:
    """A09 — ``from pydantic import BaseModel as BM``."""
    source = "from pydantic import BaseModel as BM\nBM.model_copy(obj, update=u)\n"
    # ONE message, not two. #539's tier-mutating-copy rule does NOT fire here and must not:
    # `update=u` is a bare `ast.Name`, so the mapping is built somewhere this gate cannot
    # read. That is the rule's stated residual — refused at runtime by
    # `_coerce_and_guard_update`, not closable lexically without flagging every
    # `model_copy` in the tree. This assertion is where that residual is measured rather
    # than merely declared.
    assert _messages(source) == [f"{_PROBE}:2: {check_tag_t3._BASEMODEL_VALUE_MESSAGE}"]


def test_every_declared_seam_attribute_is_enforced() -> None:
    """R2-E — pin the set as a literal, then loop over the PINNED copy.

    FLEET FINDING test-003 M2/M4: v1 tested ``copy``/``model_copy`` only, so dropping
    ``model_validate`` / ``model_validate_json`` from the constant survived the suite.
    The plan's replacement looped over ``_BASEMODEL_SEAM_ATTRS`` itself, which is the
    project's own recorded "a test oracle must not reuse the implementation predicate"
    failure — MEASURED: that mutation survived the loop-over-the-constant form too.
    """
    assert check_tag_t3._BASEMODEL_SEAM_ATTRS == _EXPECTED_SEAMS, (
        "the declared BaseModel seam set moved; this oracle pins it independently"
    )
    for seam in sorted(_EXPECTED_SEAMS):
        assert _messages(f"BaseModel.{seam}(low, update=u)\n") == [
            f"{_PROBE}:1: {check_tag_t3._BASEMODEL_VALUE_MESSAGE}"
        ], f"seam {seam!r} is declared but not enforced"


def test_a_non_seam_attribute_on_the_basemodel_receiver_stays_clean() -> None:
    """NEGATIVE FLOOR + TWIN. The receiver alone must not be sufficient.

    FLEET FINDING test-003 M4: a mutant ignoring ``_BASEMODEL_SEAM_ATTRS`` entirely
    survived v1's suite, because every fixture named a seam.
    """
    assert check_tag_t3._scan_text("s = BaseModel.model_json_schema()\n", _PROBE) == []
    assert _messages("s = BaseModel.model_construct()\n") == [
        f"{_PROBE}:1: {check_tag_t3._BASEMODEL_VALUE_MESSAGE}"
    ]


def test_instance_model_copy_stays_clean_with_a_positive_twin() -> None:
    """NEGATIVE FLOOR + TWIN. ``obj.model_copy(...)`` is the supported API.

    THE RULE IS RECEIVER-SCOPED ON PURPOSE: a receiver-blind rule flagging every
    ``model_copy`` reds ordinary pydantic instance use across the tree. Measured cost
    of the receiver-scoped form: ZERO sites in 332 files.
    """
    assert check_tag_t3._scan_text('o = obj.model_copy(update={"a": 1})\n', _PROBE) == []
    assert _messages('o = BaseModel.model_copy(update={"a": 1})\n') == [
        f"{_PROBE}:1: {check_tag_t3._BASEMODEL_VALUE_MESSAGE}"
    ]


def test_basemodel_named_only_in_prose_stays_clean_with_a_positive_twin() -> None:
    """NEGATIVE FLOOR + TWIN. ``tiers.py`` and ``quarantine.py`` docstrings name these
    spellings repeatedly; measured, every textual ``BaseModel.<attr>`` hit under both
    scan roots is prose and there are ZERO real accesses."""
    assert (
        check_tag_t3._scan_text(
            '"""See ``BaseModel.model_copy(obj, update={"tier": T3})``."""\n', _PROBE
        )
        == []
    )
    assert _messages('BaseModel.model_copy(obj, update={"tier": T3})\n') == [
        f"{_PROBE}:1: {check_tag_t3._TIER_MUTATING_COPY_MESSAGE}",
        f"{_PROBE}:1: {check_tag_t3._BASEMODEL_VALUE_MESSAGE}",
    ]


def test_a_deeper_than_budget_basemodel_chain_is_reported_by_the_scanner() -> None:
    """The BaseModel overflow flag must be FOLDED into the scanner's budget report.

    Building the alias set and then dropping its ``overflowed`` half on the floor is a
    silent fail-OPEN: every seam decision in the file is then made on an alias set the
    resolver has already said is incomplete. Nothing else in the suite drives this arc —
    the ``vars`` chain test reports overflow through a different flag.
    """
    depth = check_tag_t3._ALIAS_RESOLUTION_BUDGET + 5
    chain = "".join(f"a{i} = a{i - 1}\n" for i in range(depth, 0, -1)) + "a0 = BaseModel\n"
    assert _messages(chain) == [f"{_PROBE}:1: {check_tag_t3._ALIAS_BUDGET_MESSAGE}"]
    assert check_tag_t3._scan_text("b = BaseModel\n", _PROBE) == [], (
        "positive twin: an ordinary alias must NOT report overflow"
    )


# THE META-GUARD'S BEHAVIOURAL TABLE. Identifier -> {label: source}, and every entry's
# LAST line is the USE the row is about.
#
# A DICT PER IDENTIFIER, not three fixed columns (PR #553 review, T11). The fixed shape
# forced one spelling per binding form and got two of them wrong: the `gc`/`ctypes`
# "import-aliased" column held a plain `from X import Y` — no alias at all — and neither
# had an assignment-rebind row, which is the spelling `_g = gc` that the fleet actually
# executed. A variable-length dict lets each identifier carry every binding form Python
# offers it, and `copyreg` carry the four its module and primitive halves need.
#
# `_DECLARED_ALIAS_RESIDUALS` at the foot of this file is the other half of the guard:
# every identifier the gate keys on must appear in ONE of the two.
_KEYED_IDENTIFIER_SPELLINGS: dict[str, dict[str, str]] = {
    "BaseModel": {
        "DIRECT": 'BaseModel.model_copy(low, update={"tier": T3})',
        "REBOUND": '_B = BaseModel\n_B.model_copy(low, update={"tier": T3})',
        "IMPORT-ALIASED": (
            'from pydantic import BaseModel as _B\n_B.model_copy(low, update={"tier": T3})'
        ),
    },
    "vars": {
        "DIRECT": 'vars(obj)["tier"] = T3',
        "REBOUND": '_v = vars\n_v(obj)["tier"] = T3',
        "IMPORT-ALIASED": 'from builtins import vars as _v\n_v(obj)["tier"] = T3',
    },
    # The three carrier modules take FOUR spellings each: the module identifier can be
    # rebound by assignment OR aliased at the import, and the PRIMITIVE can be bound
    # directly by a `from` import with or without an alias — a form in which no module
    # identifier appears at the call site at all.
    "gc": {
        "DIRECT": "import gc\ngc.get_referents(low)",
        "REBOUND": "import gc\n_g = gc\n_g.get_referents(low)",
        "MODULE-IMPORT-ALIASED": "import gc as _g\n_g.get_referents(low)",
        "PRIMITIVE-IMPORT-ALIASED": "from gc import get_referents as _gr\n_gr(low)",
    },
    "ctypes": {
        "DIRECT": "import ctypes\nctypes.cast(id(low), ctypes.py_object)",
        "REBOUND": "import ctypes\n_c = ctypes\n_c.cast(id(low), _c.py_object)",
        "MODULE-IMPORT-ALIASED": "import ctypes as _c\n_c.cast(id(low), _c.py_object)",
        "PRIMITIVE-IMPORT-ALIASED": "from ctypes import py_object as _po\n_po(id(low))",
    },
    # PR #553 REVIEW, T2 — `copyreg` was keyed on by the gate with NO row at all, and the
    # omission was a real gap rather than an oversight of form: with `gc` and `ctypes`
    # rowed and `copyreg` not, exempting `copyreg` alone from module-alias resolution AND
    # dropping its direct-import binding BOTH survived the whole suite, while the same
    # two mutations on either sibling died. That asymmetry is what a hand-written table
    # produces and what the derivation below now refuses.
    "copyreg": {
        "DIRECT": "import copyreg\ncopyreg._reconstructor(low, TaggedContent, None)",
        "REBOUND": "import copyreg\n_cr = copyreg\n_cr._reconstructor(low, TaggedContent, None)",
        "MODULE-IMPORT-ALIASED": (
            "import copyreg as _cr\n_cr._reconstructor(low, TaggedContent, None)"
        ),
        "PRIMITIVE-IMPORT-ALIASED": (
            "from copyreg import _reconstructor as _rc\n_rc(low, TaggedContent, None)"
        ),
    },
    "object": {
        "DIRECT": 'object.__setattr__(low, "tier", T3)',
        "REBOUND": '_o = object\n_o.__setattr__(low, "tier", T3)',
        "IMPORT-ALIASED": 'from builtins import object as _o\n_o.__setattr__(low, "tier", T3)',
    },
    # PR #553 F3. Like `object` above, closed by RECEIVER-BLINDNESS: the rule never asks
    # what the receiver is, so the spellings differ only in how they name it and all must
    # red. The ADMISSIBILITY arm keys on `self` and on zero-argument `super` — both in the
    # fail-CLOSED direction, where rebinding makes the gate stricter, so neither needs a
    # row (`test_only_the_zero_argument_super_spelling_is_admissible` proves it, and both
    # are declared residuals below).
    "__init__": {
        "DIRECT": "type(low).__init__(low, content=attacker)",
        "REBOUND": "_t = type(low)\n_t.__init__(low, content=attacker)",
        "IMPORT-ALIASED": (
            "from builtins import type as _ty\n_ty(low).__init__(low, content=attacker)"
        ),
    },
    # PR #553 C1. ROWED rather than left to `_VEHICLE_NAME_RESIDUAL`, on `__init__`'s
    # precedent and for `__init__`'s reason: once an identifier acquires a CALL-SHAPE
    # rule of its own, "matched as an attribute name, never as a binding" stops being
    # the whole story about it, and a residual is a promise where a row is a measurement.
    # The receiver is the rebindable half and all three spellings must red.
    "__delattr__": {
        "DIRECT": 'object.__delattr__(low, "tier")',
        "REBOUND": '_o = object\n_o.__delattr__(low, "tier")',
        "IMPORT-ALIASED": 'from builtins import object as _o\n_o.__delattr__(low, "tier")',
    },
    "_set_authorized_t3_nonce": {
        "DIRECT": "_set_authorized_t3_nonce(mine)",
        "REBOUND": "_reg = _set_authorized_t3_nonce\n_reg(mine)",
        "IMPORT-ALIASED": (
            "from alfred.security.tiers import _set_authorized_t3_nonce as _reg\n_reg(mine)"
        ),
    },
    # #539. `TaggedContent` and `T3` LEFT `_DECLARED_ALIAS_RESIDUALS` to sit here, which is
    # the stronger of the two dispositions: a row MEASURES the closure where a residual only
    # promises it. `test_the_pre_existing_call_rules_are_still_the_declared_residual` was
    # built to red on exactly this day, and its own failure message names this move as the
    # remedy.
    "TaggedContent": {
        "DIRECT": "TaggedContent[T3](content='x', tier=T3)",
        "REBOUND": "_TC = TaggedContent\n_TC[T3](content='x', tier=T3)",
        "IMPORT-ALIASED": (
            "from alfred.security.tiers import TaggedContent as _TC\n_TC[T3](content='x', tier=T3)"
        ),
    },
    "T3": {
        "DIRECT": "TaggedContent[T3](content='x', tier=T3)",
        "REBOUND": "_T = T3\nTaggedContent[_T](content='x', tier=_T)",
        "IMPORT-ALIASED": (
            "from alfred.security.tiers import T3 as _T\nTaggedContent[_T](content='x', tier=_T)"
        ),
    },
    # #539, and these three are rowed for a reason the entries above do not share: they are
    # keyed on the ADMITTING side. `T2` naming a benign tier is what makes a slice CLEAN, so
    # a rebind is not merely a bypass risk — it is the difference between a floor and a hole,
    # in both directions. The security review executed `T2 = T3` and measured
    # `TaggedContent["T2"](...)` scanning clean while `TaggedContent[T2](...)` red, because
    # one arm was alias-resolved and the other matched the raw seed tuple.
    #
    # The DIRECT spelling is therefore the benign floor (it must stay clean) and the two
    # rebinding spellings are the positive controls (they must red once the name points at
    # T3). The comprehension below builds all three for every seed, so the asymmetry cannot
    # creep back in one spelling at a time.
    **{
        tier: {
            "DIRECT": f"TaggedContent[{tier}](content='x')",
            "REBOUND": f"{tier} = T3\nTaggedContent[{tier}](content='x')",
            "IMPORT-ALIASED": (
                f"from alfred.security.tiers import T3 as {tier}\n"
                f"TaggedContent[{tier}](content='x')"
            ),
        }
        for tier in ("T0", "T1", "T2")
    },
    # PR REVIEW py-001. `dict` LEFT `_DECLARED_ALIAS_RESIDUALS`, whose entry claimed a
    # rebind "makes the gate stricter". Measured: true inside a `**` operand, FALSE at the
    # top level — `_d = dict; low.model_copy(update=_d(tier=T3))` scanned CLEAN. A promise
    # measurement refutes is exactly what a row exists to replace.
    "dict": {
        "DIRECT": "low.model_copy(update=dict(tier=T3))",
        "REBOUND": "_d = dict\nlow.model_copy(update=_d(tier=T3))",
        "IMPORT-ALIASED": "from builtins import dict as _d\nlow.model_copy(update=_d(tier=T3))",
    },
    "TrustTier": {
        "DIRECT": "type TierT = TrustTier\nTaggedContent[TierT](content='x')",
        "REBOUND": "TrustTier = T3\ntype TierT = TrustTier\nTaggedContent[TierT](content='x')",
        "IMPORT-ALIASED": (
            "from alfred.security.tiers import T3 as TrustTier\n"
            "type TierT = TrustTier\nTaggedContent[TierT](content='x')"
        ),
    },
}

# The three benign-tier seeds and `TrustTier` are keyed in the ADMITTING direction, so their
# rows invert the usual contract: DIRECT must stay CLEAN and the rebinding spellings must
# RED. `test_every_keyed_identifier_is_alias_resolved` reads this set to know which way round
# to score them, rather than inferring it from the identifier's name.
_ADMITTING_ROWS: frozenset[str] = frozenset({"T0", "T1", "T2", "TrustTier"})


def test_every_keyed_identifier_is_alias_resolved() -> None:
    """THE META-GUARD. Seven Criticals across two review rounds were ONE shape.

    Every one was a rule keyed on a bare identifier that Python lets you rebind:
    ``object``, ``gc``, ``ctypes``, ``BaseModel``, ``vars``. Each was fixed as a
    SPELLING and the next round found the next spelling. This test is the only thing
    in the suite that closes the CLASS rather than one member of it.

    An identifier is a NAME. Any name can be rebound by assignment or by an import
    alias. So for every identifier a rule keys on, all three spellings below must
    produce the SAME verdict — and the direct form is the positive control proving the
    probe reaches the rule at all. Without that control a row is vacuous: a typo'd
    fixture that matches nothing would "pass" all three assertions on an absent rule.

    Adding a rule that keys on a new identifier means adding a row HERE. If you cannot
    write the row, the rule is not alias-resolved and it is bypassable.

    Two identifiers are resolved by DIFFERENT mechanisms, and the row does not care
    which — it asserts the OUTCOME, so it stays honest if a rule changes technique:

    * ``vars``, ``gc``, ``ctypes``, ``BaseModel`` and the ``tiers`` private surface go
      through :func:`_alias_names`;
    * ``object`` is closed by RECEIVER-BLINDNESS instead. The ``__setattr__`` rules
      never ask who the receiver is, so no identifier is left to rebind. That is a
      STRONGER closure than resolution, not a missing one, and the row proves it
      behaviourally rather than trusting the claim.

    THE ASSERTION IS LINE-KEYED, and it must be. Every row's LAST line is the USE, and
    for the private-surface row the BINDING line reds on its own — so a bare "something
    was flagged" assertion would pass on the import alone and prove nothing about
    ``_reg(mine)``, which is the laundering. Keying on the use line makes every row
    discriminate on the property it claims.

    THE TABLE IS NO LONGER THE WHOLE GUARD (PR #553 review, T2). A hand-written table is
    an ENUMERATION, and this test — built to close the identifier-aliasing CLASS — had
    that exact disease: ``copyreg`` was keyed on by the gate with no row at all, and the
    mutations that would have caught it survived. What closes the class is
    ``test_every_identifier_the_gate_keys_on_is_rowed_or_declared_residual``, which
    DERIVES the identifier set from the gate's own source and requires each member to
    appear here or in ``_DECLARED_ALIAS_RESIDUALS``. This test is what proves a row is
    behaviourally true; that one is what proves no row is missing.
    """
    assert _KEYED_IDENTIFIER_SPELLINGS, "the behavioural table is empty — nothing is proven"
    assert set(_KEYED_IDENTIFIER_SPELLINGS) >= _ADMITTING_ROWS, (
        "_ADMITTING_ROWS names identifiers with no row — the inversion below would then "
        "silently score nothing"
    )
    for identifier, spellings in _KEYED_IDENTIFIER_SPELLINGS.items():
        assert "DIRECT" in spellings, (
            f"{identifier}: no DIRECT spelling. That row is the POSITIVE CONTROL — "
            f"without it a typo'd fixture matching nothing 'passes' on an absent rule"
        )
        # #539. An ADMITTING identifier is keyed the other way round: its DIRECT spelling is
        # the BENIGN FLOOR and must stay clean, while its rebinding spellings are the
        # positive controls. Scoring all rows the same way would have required the benign
        # floor to red, which is the opposite of the property `T0`/`T1`/`T2`/`TrustTier`
        # exist to have — and a table that cannot express the inversion would push those
        # four into `_DECLARED_ALIAS_RESIDUALS`, where nothing measures them at all.
        admitting = identifier in _ADMITTING_ROWS
        for label, source in spellings.items():
            use_line = source.count("\n") + 1
            flagged = _messages(source + "\n")
            used = [message for message in flagged if f":{use_line}: " in message]
            if admitting and label == "DIRECT":
                assert not used, (
                    f"{identifier}: the DIRECT spelling is the BENIGN FLOOR and it RED. "
                    f"A benign tier naming itself must not trip. Messages: {flagged}"
                )
                continue
            assert used, (
                f"{identifier}: the {label} spelling's USE (line {use_line}) was not "
                f"flagged. Messages: {flagged}"
            )


def test_record_appends_a_message_and_a_snippet_and_tolerates_a_missing_line() -> None:
    """``_record``'s bounds guard, exercised directly rather than through a ternary.

    R2-K: written as a ternary, ``coverage.py`` does not branch on it, so the guard
    would be invisible to this file's REQUIRED 100% branch gate — exempting by
    construction exactly what the no-pragma rule forbids exempting. Written as an
    ``if``/``else`` it is visible, and this is what covers the else arm.

    No ``_scan_text`` INPUT is known to reach it (``str.splitlines`` splits on strictly
    more separators than the tokenizer, so the line list is never shorter than the
    parser's line numbering). It stays because every rule shares this helper and a
    violation must never become an ``IndexError`` that re-files a real finding as an
    unscannable file.
    """
    violations: list[str] = []
    check_tag_t3._record(violations, ["first", "second  "], _PROBE, 2, "msg")
    assert violations == [f"{_PROBE}:2: msg", "  second"]
    check_tag_t3._record(violations, [], _PROBE, 1, "other")
    assert violations[2:] == [f"{_PROBE}:1: other", "  "]


# ---------------------------------------------------------------------------
# Task 4 — the `alfred.security.tiers` private-surface default-deny.
#
# These two bypasses (`_set_authorized_t3_nonce(mine)` and
# `_T3_CONSTRUCTION_AUTHORIZED.set(True)`) are the ONLY ones in the repo that no
# runtime guard catches — and cannot catch, because they ARE the authorisation
# mechanism. A guard that refused them would refuse the bootstrap that installs
# the real nonce. The authoring layer is therefore the sole enforcement layer.
# ---------------------------------------------------------------------------

# R2-E — PINNED HERE, AS A SEPARATE LITERAL. Two INDEPENDENT oracles cover this
# constant and they fail on different mutations:
#
#   * this literal catches an edit to `_TIERS_PRIVATE_SURFACE` alone;
#   * `_derive_tiers_private_surface` (below) reads the REAL `tiers.py`, so it
#     catches a name added to or removed from that module.
#
# Neither is tautological: the implementation is a HARD-CODED frozenset (the gate
# runs under bare `python3` with no venv and no `alfred` importable, so it cannot
# ask the module), and the derivation shares no predicate with it.
_EXPECTED_PRIVATE_SURFACE = frozenset(
    {
        "_APPROVED_TIERS",
        "_AUTHORIZED_T3_NONCE",
        "_FORENSICALLY_OPAQUE_PACKAGES",
        "_FORENSIC_FRAME_LIMIT",
        "_MAX_FORENSIC_REPR",
        "_PARAMETRISATION_ATTRS",
        "_T3_CONSTRUCTION_AUTHORIZED",
        "_TIER_GUARD_NAMES",
        "_bounded_repr",
        "_coerce_and_guard_update",
        "_enforce_tier_admissible",
        "_guard_tier_value",
        "_is_forensically_opaque",
        "_is_unauthorized_t3",
        "_log_t3",
        "_nearest_foreign_module",
        "_record_unauthorized_t3_attempt",
        "_refuse_if_tier_is_narrowed_away",
        "_refuse_unauthorized_t3",
        "_set_authorized_t3_nonce",
        "_tier_by_name",
    }
)


def test_a_deeper_than_budget_private_surface_chain_is_reported_by_the_scanner() -> None:
    """PR #553 REVIEW, T1 — the ``private_overflow`` half of the fan-in was UNTESTED.

    The twin of ``test_a_deeper_than_budget_carrier_chain_...`` on the rule that is the
    SOLE enforcement layer. Measured: dropping ``private_overflow`` from the fan-in, and
    separately breaking the accumulator in :func:`_private_surface_names` so it can never
    become True, both survived the whole suite AND the real-tree scan while leaving a
    >budget chain seeded on ``_set_authorized_t3_nonce`` completely unflagged.

    ASSERTED BY OCCURRENCE, not by list equality, and that is forced by the fixture: the
    chain is seeded on a private name, so every level the resolver DID reach is itself
    private and reds on its own line. The budget line is the property under test and it
    is the only one asserted; the twin is what proves it is not always emitted.
    """
    depth = check_tag_t3._ALIAS_RESOLUTION_BUDGET + 5
    chain = "".join(f"a{i} = a{i - 1}\n" for i in range(depth, 0, -1))
    chain += "a0 = _set_authorized_t3_nonce\n"
    budget = f"{_PROBE}:1: {check_tag_t3._ALIAS_BUDGET_MESSAGE}"
    assert _messages(chain).count(budget) == 1, (
        "a private-surface alias chain past the budget must fail CLOSED and say so"
    )
    assert budget not in _messages("a0 = _set_authorized_t3_nonce\n"), (
        "positive twin: an ordinary private-surface reference must NOT report overflow"
    )


def test_every_declared_private_name_is_enforced_on_every_carrier() -> None:
    """PR #553 REVIEW, T6 — the one pinned set with no loop-over-the-pinned-copy test.

    Five of the six pinned sets in this file are enforced by a loop that asserts each
    declared member actually reds. ``_TIERS_PRIVATE_SURFACE`` had only the two DRIFT
    guards (this file's literal, and the derivation against the real ``tiers.py``), which
    both compare SETS and neither of which asks whether a member is enforced. Measured:
    narrowing the ``ast.Attribute`` arm to ``_AUTHORIZED_T3_NONCE`` alone, and the folded
    -string arm to ``_set_authorized_t3_nonce`` alone, both survived the whole suite —
    twenty of the twenty-one names silently reachable through two of the four carriers.

    Looped over the PINNED literal, never over the constant under test (R2-E): a mutation
    that shrinks ``_TIERS_PRIVATE_SURFACE`` shrinks a loop over it in the same edit.

    Three carriers here; the fourth (``ast.alias``) is covered by
    ``test_an_import_asname_that_shadows_a_private_name_is_refused``, which is the only
    fixture that can reach the ``asname`` sub-arm.

    THE FIXTURE IS A CALL ARGUMENT, not an assignment, and that is forced rather than
    stylistic: ``x = _log_t3`` REBINDS, so ``x`` joins the alias set and the line reds
    TWICE. Correct behaviour (R2-A poisons the asname for exactly this reason), but it
    would make an equality assertion measure the aliasing rather than the carrier.
    """
    expected = _EXPECTED_PRIVATE_SURFACE
    assert expected == check_tag_t3._TIERS_PRIVATE_SURFACE, (
        "the declared private surface moved; this oracle pins it"
    )
    for name in sorted(expected):
        for carrier, source in (
            ("bare Name", f"use({name})\n"),
            ("Attribute", f"use(_t.{name})\n"),
            ("folded string", f'use("{name}")\n'),
        ):
            assert _messages(source) == [f"{_PROBE}:1: {check_tag_t3._PRIVATE_SURFACE_MESSAGE}"], (
                f"private name {name!r} is declared but not enforced as a {carrier}"
            )


def test_import_aliased_nonce_setter_is_refused() -> None:
    """A16 — the import alias hides the name from every rule keyed on the CALL.

    R2-A: the aliased import POISONS the asname. Both lines red, and they must:
    the import is the binding and ``_reg(mine)`` is the LAUNDERING CALL. A rule
    that flagged only the import would be closed by moving the import into a
    helper module, so the asname is resolved through the same per-file alias
    environment every other rule in this gate now uses.
    """
    source = "from alfred.security.tiers import _set_authorized_t3_nonce as _reg\n_reg(mine)\n"
    assert _messages(source) == [
        f"{_PROBE}:1: {check_tag_t3._PRIVATE_SURFACE_MESSAGE}",
        f"{_PROBE}:2: {check_tag_t3._PRIVATE_SURFACE_MESSAGE}",
    ]


def test_an_import_asname_that_shadows_a_private_name_is_refused() -> None:
    """R2-J — the ``asname`` SUB-ARM, which nothing else reaches.

    Every other alias fixture in this file binds a name that is ALREADY private, so
    the ``node.name`` check short-circuits and ``node.asname`` is never evaluated.
    Here the imported name is innocent and the LOCAL spelling is the private one, so
    only the asname arm can see it. Dropping that arm survives every other test.

    Denying it is the name-keyed-collision residual pointing the safe way: a file
    that binds ``_log_t3`` locally reads as tiers' ``_log_t3`` to every later reader.
    """
    assert _messages("from json import loads as _log_t3\n") == [
        f"{_PROBE}:1: {check_tag_t3._PRIVATE_SURFACE_MESSAGE}"
    ]
    assert check_tag_t3._scan_text("from json import loads as _parse\n", _PROBE) == [], (
        "positive twin: an ordinary asname must not red"
    )


def test_getattr_string_nonce_setter_is_refused() -> None:
    """A17 — the name lives in a STRING, so no Name/Attribute node carries it.

    This is why the prose exclusion must be position-based: excluding every string
    constant would admit this line.
    """
    source = 'import alfred.security.tiers as _t\ngetattr(_t, "_set_authorized_t3_nonce")(mine)\n'
    assert _messages(source) == [f"{_PROBE}:2: {check_tag_t3._PRIVATE_SURFACE_MESSAGE}"]


def test_a_private_name_assembled_by_binop_is_refused() -> None:
    """FLEET FINDING sec-004 — executed end-to-end, this forged the nonce and minted a
    fully legitimate TaggedContent[T3] for attacker content through the front door."""
    source = 'getattr(_t, "_set_authorized" + "_t3_nonce")(mine)\n'
    assert _messages(source) == [f"{_PROBE}:1: {check_tag_t3._PRIVATE_SURFACE_MESSAGE}"]


def test_private_surface_reached_through_an_attribute_is_refused() -> None:
    """FLEET FINDING test-003 M10 — deleting the ``ast.Attribute`` arm survived v1."""
    assert _messages("if _t._AUTHORIZED_T3_NONCE is not None:\n    pass\n") == [
        f"{_PROBE}:1: {check_tag_t3._PRIVATE_SURFACE_MESSAGE}"
    ]


def test_dotted_private_name_in_a_string_is_refused() -> None:
    """The string arm matches by CONTAINMENT so the dotted spelling is caught.

    Positive twin in the same test: a string that merely SHARES a prefix with a
    private name must not red, or containment would be a licence to flag anything.
    """
    assert _messages('n = "alfred.security.tiers._set_authorized_t3_nonce"\n') == [
        f"{_PROBE}:1: {check_tag_t3._PRIVATE_SURFACE_MESSAGE}"
    ]
    assert check_tag_t3._scan_text('n = "alfred.security.tiers.tag"\n', _PROBE) == []


def test_context_var_authorisation_flip_is_refused() -> None:
    """``_T3_CONSTRUCTION_AUTHORIZED.set(True)`` flips the guard off wholesale.

    THE SECOND BYPASS NOTHING ELSE CATCHES. The runtime cannot refuse it: the
    context var IS how an authorised mint says it is authorised, so a guard that
    denied the write would deny ``tag_t3_with_nonce`` itself.
    """
    assert _messages("_T3_CONSTRUCTION_AUTHORIZED.set(True)\n") == [
        f"{_PROBE}:1: {check_tag_t3._PRIVATE_SURFACE_MESSAGE}"
    ]


def test_private_surface_named_only_in_prose_stays_clean_with_a_positive_twin() -> None:
    """NEGATIVE FLOOR + TWIN. THREE live docstrings name these symbols:
    ``cli/daemon/_failures.py:150``, ``hooks/invoke.py:407`` and ``:469``. The last is a
    PEP-258 ATTRIBUTE docstring, which ``ast.get_docstring`` does not see."""
    assert (
        check_tag_t3._scan_text(
            '"""Sets ``alfred.security.tiers._AUTHORIZED_T3_NONCE`` once at start."""\n', _PROBE
        )
        == []
    )
    assert (
        check_tag_t3._scan_text(
            'X = 1\n"""See :func:`alfred.security.tiers._tier_by_name`."""\n', _PROBE
        )
        == []
    )
    assert _messages('X = _tier_by_name("T3")\n') == [
        f"{_PROBE}:1: {check_tag_t3._PRIVATE_SURFACE_MESSAGE}"
    ]


def test_nonce_factory_is_exempt_inside_its_registration_function_only() -> None:
    """(path, FUNCTION), never path-only, WITH the positive twin in the same test.

    ``_set_authorized_t3_nonce`` (``tiers.py``) is a bare ``global`` write with NO
    guard; the idempotency guard lives in the CALLER. A path-only exemption leaves the
    bypass open WITHIN the exempt file — which is the whole point of narrowing it.
    """
    inside = (
        "def create_and_register_t3_nonce():\n"
        "    nonce = CapabilityGateNonce()\n"
        "    _set_authorized_t3_nonce(nonce)\n"
        "    return nonce\n"
    )
    assert check_tag_t3._scan_text(inside, _NONCE_FACTORY) == []

    outside = "def some_other_helper():\n    _set_authorized_t3_nonce(attacker_nonce)\n"
    assert _messages(outside, _NONCE_FACTORY) == [
        f"{_NONCE_FACTORY}:2: {check_tag_t3._PRIVATE_SURFACE_MESSAGE}"
    ]


def test_nonce_factory_exemption_covers_async_def_too() -> None:
    """THE SILENT TRAP, WITH a twin so it cannot pass on a dead exemption.

    A ``FunctionDef``-only enclosing walk maps nothing for ``async def``, so the first
    body would red. Nothing else in the repo exercises the async half.
    """
    exempt = "async def create_and_register_t3_nonce():\n    _set_authorized_t3_nonce(nonce)\n"
    assert check_tag_t3._scan_text(exempt, _NONCE_FACTORY) == []

    not_exempt = "async def some_other_coro():\n    _set_authorized_t3_nonce(nonce)\n"
    assert _messages(not_exempt, _NONCE_FACTORY) == [
        f"{_NONCE_FACTORY}:2: {check_tag_t3._PRIVATE_SURFACE_MESSAGE}"
    ]


def test_a_same_named_def_below_module_scope_does_not_inherit_the_exemption() -> None:
    """PR #553 SECURITY REVIEW, F4 — the (path, function) key was defeatable by NESTING.

    ``_enclosing_functions`` maps each line to its INNERMOST function, so a nested
    ``def create_and_register_t3_nonce`` inside ``nonce_factory.py`` inherited the
    exemption — defeating the exact property the (path, function) key was chosen for:
    "a second function in this module could install any object it liked". The nested
    def IS that second function, wearing the first one's name.

    Closed with the discriminator ``_IMPORT_ONLY_EXEMPT_PATHS`` already uses: MODULE
    SCOPE. A class body counts as a scope, so the method spelling is denied too — a
    function-only depth count would have closed the ``def`` spelling and left that one.
    """
    nested = (
        "def outer():\n"
        "    def create_and_register_t3_nonce():\n"
        "        _set_authorized_t3_nonce(attacker)\n"
    )
    assert _messages(nested, _NONCE_FACTORY) == [
        f"{_NONCE_FACTORY}:3: {check_tag_t3._PRIVATE_SURFACE_MESSAGE}"
    ], "a nested def inherited the module-level function's exemption"

    method = (
        "class Sneak:\n"
        "    def create_and_register_t3_nonce(self):\n"
        "        _set_authorized_t3_nonce(attacker)\n"
    )
    assert _messages(method, _NONCE_FACTORY) == [
        f"{_NONCE_FACTORY}:3: {check_tag_t3._PRIVATE_SURFACE_MESSAGE}"
    ], "a method of a module-level class inherited the exemption"

    module_scope = (
        "def create_and_register_t3_nonce():\n"
        "    _set_authorized_t3_nonce(nonce)\n"
        "    return nonce\n"
    )
    assert check_tag_t3._scan_text(module_scope, _NONCE_FACTORY) == [], (
        "positive twin: the REAL module-scope function must stay exempt"
    )


def test_import_exemption_is_module_level_only() -> None:
    """FLEET FINDING sec-005 — an ``ast.alias``-only exemption is still path-only.

    A FUNCTION-LOCAL aliased import inside ``nonce_factory.py`` bought the exemption
    under the first revision, which made the whole narrowing cosmetic. Requiring
    module scope closes it for free.

    The function-local case reds TWICE (R2-A): the aliased import binds the name and
    ``_reg(attacker)`` uses it, and both are the laundering.
    """
    module_level = (
        "from alfred.security.tiers import CapabilityGateNonce, _set_authorized_t3_nonce\n"
    )
    assert check_tag_t3._scan_text(module_level, _NONCE_FACTORY) == []

    function_local = (
        "def sneak():\n"
        "    from alfred.security.tiers import _set_authorized_t3_nonce as _reg\n"
        "    _reg(attacker)\n"
    )
    assert _messages(function_local, _NONCE_FACTORY) == [
        f"{_NONCE_FACTORY}:2: {check_tag_t3._PRIVATE_SURFACE_MESSAGE}",
        f"{_NONCE_FACTORY}:3: {check_tag_t3._PRIVATE_SURFACE_MESSAGE}",
    ]


def test_module_level_calls_in_nonce_factory_still_red() -> None:
    """The import exemption is scoped to ``ast.alias``, so a module-level CALL reds."""
    assert _messages("_set_authorized_t3_nonce(attacker_nonce)\n", _NONCE_FACTORY) == [
        f"{_NONCE_FACTORY}:1: {check_tag_t3._PRIVATE_SURFACE_MESSAGE}"
    ]


def _exempt_function_private_reference_lines(source: str) -> list[int]:
    """Line numbers of the private-surface references inside the RENAMED exempt function.

    The oracle for ``test_the_real_nonce_factory_file_scans_clean``'s positive twin,
    and DELIBERATELY NOT the gate's own predicate (a tautological oracle passes through
    broken code). This matches the pinned private names against the raw TEXT of the
    function's body and excludes the function's own docstring, which names
    ``_AUTHORIZED_T3_NONCE`` in prose that the gate is right not to flag.
    """
    tree = ast.parse(source)
    exempt = [
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == "create_and_register_t3_nonce_renamed"
    ]
    assert len(exempt) == 1, f"expected one renamed exempt function, found {len(exempt)}"
    body = exempt[0]
    assert body.end_lineno is not None
    prose_lines: set[int] = set()
    first = body.body[0]
    if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant):
        assert first.end_lineno is not None
        prose_lines = set(range(first.lineno, first.end_lineno + 1))
    lines = source.splitlines()
    return [
        lineno
        for lineno in range(body.lineno, body.end_lineno + 1)
        if lineno not in prose_lines
        if any(private in lines[lineno - 1] for private in _EXPECTED_PRIVATE_SURFACE)
    ]


def test_the_real_nonce_factory_file_scans_clean() -> None:
    """THE REAL FILE under its REAL path — a fixture resembling it proves nothing.

    R2-I: WITH THE POSITIVE TWIN it was missing. The bare floor passed for two
    reasons it could not tell apart — the exemption working, and the rule being
    absent. The twin renames the exempt function in the REAL source and asserts the
    two in-function references then red, which proves the file is being scanned and
    that the (path, FUNCTION) key is what keeps it clean.

    ``_is_exempt`` is asserted False in the same test so this cannot pass because
    ``nonce_factory.py`` quietly joined ``_APPROVED_PATHS``.

    PR #553 REVIEW, T9 — THE EXPECTED LINES ARE DERIVED FROM CONTENT, not written down.
    They used to be the literals 100 and 108, so any edit ABOVE the exempt function —
    a docstring line, an import — red this test with a message about the private surface
    that had nothing to do with the change. Located instead by walking to the renamed
    function and matching the pinned private names against the text of its body, with
    its own docstring excluded (the docstring names ``_AUTHORIZED_T3_NONCE`` in prose,
    which the gate correctly does not flag). Independent of the gate: a substring match
    over ``_EXPECTED_PRIVATE_SURFACE`` shares no predicate with ``_private_surface_hit``.
    """
    assert not check_tag_t3._is_exempt(_NONCE_FACTORY), (
        "nonce_factory.py must NOT be blanket-exempt — this test would be vacuous"
    )
    assert check_tag_t3._scan_file(_NONCE_FACTORY) == []

    real = _NONCE_FACTORY.read_text(encoding="utf-8")
    renamed = real.replace(
        "def create_and_register_t3_nonce(", "def create_and_register_t3_nonce_renamed("
    )
    assert renamed != real, "the exempt function's def line moved; this twin measures nothing"

    exposed = _exempt_function_private_reference_lines(renamed)
    assert len(exposed) == 2, (
        f"expected exactly two in-function private-surface references in the renamed "
        f"nonce factory, located {exposed} — the twin measures whichever it finds, so a "
        f"change in that count is a change in what this test proves"
    )
    assert _messages(renamed, _NONCE_FACTORY) == [
        f"{_NONCE_FACTORY}:{lineno}: {check_tag_t3._PRIVATE_SURFACE_MESSAGE}" for lineno in exposed
    ], "renaming the exempt function must expose both in-function private references"


def test_nonce_factory_holds_exactly_one_private_reference_and_one_alias() -> None:
    """CARDINALITY PIN plus the ARGUMENT check the counts alone cannot make.

    The exemption is keyed on a function NAME, so a second function in this file
    renamed to ``create_and_register_t3_nonce`` would inherit it. Pinning the counts
    means any new private-surface reference in this file reds here.

    R2-M: the counts are defeated by swapping ONLY THE ARGUMENT of the exempt
    ``_set_authorized_t3_nonce`` call — ``(hits, aliases)`` stays ``(3, 1)`` while an
    attacker-held object becomes the authorised nonce (this was executed). So the pin
    also asserts the argument is a name bound exactly once, to a bare
    ``CapabilityGateNonce()`` construction.

    RESIDUAL, stated rather than implied: this reads the argument SYNTACTICALLY. A
    module-level rebind of the identifier ``CapabilityGateNonce`` in this file, or a
    mutation of the constructed object between the two statements, is not checked —
    the exemption still trusts ``nonce_factory.py``'s body to that degree.
    """
    tree = ast.parse(_NONCE_FACTORY.read_text(encoding="utf-8"))
    prose = check_tag_t3._prose_string_ids(tree)

    private_names, overflowed = check_tag_t3._private_surface_names(tree)
    assert not overflowed
    assert private_names == check_tag_t3._TIERS_PRIVATE_SURFACE, (
        "nonce_factory.py binds a local ALIAS to a tiers private name, so the "
        "two-argument _private_surface_hit calls below measure a narrower set than "
        "the scanner does — pass the resolved set explicitly if this ever holds"
    )

    hits = [n for n in ast.walk(tree) if check_tag_t3._private_surface_hit(n, prose)]
    aliases = [n for n in hits if isinstance(n, ast.alias)]
    assert len(aliases) == 1, f"expected exactly one exempt import alias, got {len(aliases)}"
    assert len(hits) == 3, (
        f"nonce_factory.py private-surface references changed ({len(hits)} != 3). "
        "Every one of them sits inside an exemption — justify the new reference or "
        "move it out."
    )

    calls = [
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.Call) and check_tag_t3._arg_name(n.func) == "_set_authorized_t3_nonce"
    ]
    assert len(calls) == 1
    call = calls[0]
    assert not call.keywords and len(call.args) == 1
    argument = call.args[0]
    assert isinstance(argument, ast.Name)

    bindings = [
        stmt.value
        for stmt in ast.walk(tree)
        if isinstance(stmt, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == argument.id for t in stmt.targets)
    ]
    assert len(bindings) == 1, f"{argument.id!r} is bound {len(bindings)} times, expected once"
    minted = bindings[0]
    assert isinstance(minted, ast.Call)
    assert check_tag_t3._arg_name(minted.func) == "CapabilityGateNonce"
    assert not minted.args and not minted.keywords


def test_scan_text_verdict_does_not_depend_on_the_working_directory() -> None:
    """PURITY, asserted as the PROPERTY (fleet finding test-004).

    An earlier revision resolved the path INSIDE ``_scan_text``; identical arguments
    then returned opposite verdicts depending on cwd, while the existing purity pin
    (``test_scan_text_reports_a_violation_without_touching_the_filesystem``) stayed
    green — a guard whose docstring had silently become false.

    THE FIXTURE IS AN EXEMPTION-SENSITIVE ONE, and it has to be. MEASURED: with a
    module-level reference the verdict is "red" under BOTH cwds even with the
    resolve put back inside ``_scan_text``, because a module-level line is outside
    the (path, function) exemption either way — so that fixture asserts equality
    between two verdicts the regression never disagreed about. The in-function form
    is the one the exemption can admit, so it is the one whose verdict moves: from
    the repo root it resolved to the real ``nonce_factory.py`` and returned CLEAN,
    from ``/`` it resolved elsewhere and returned a violation.

    Non-vacuous by construction: both verdicts are asserted NON-EMPTY, so the
    equality cannot be satisfied by two empty lists.
    """
    import os

    source = "def create_and_register_t3_nonce():\n    _set_authorized_t3_nonce(nonce)\n"
    relative = Path("src/alfred/bootstrap/nonce_factory.py")
    cwd = Path.cwd()
    try:
        os.chdir(_REPO_ROOT)
        here = check_tag_t3._scan_text(source, relative)
        os.chdir("/")
        elsewhere = check_tag_t3._scan_text(source, relative)
    finally:
        os.chdir(cwd)
    assert here == elsewhere
    assert here == [
        f"{relative}:2: {check_tag_t3._PRIVATE_SURFACE_MESSAGE}",
        "      _set_authorized_t3_nonce(nonce)",
    ]


def test_scan_text_keys_exemptions_on_the_resolved_path_it_is_given() -> None:
    """R2-D — the ``resolved is None`` DEFAULT ARM, which is a branch under the gate.

    ``_scan_file`` resolves once and passes the result down; every direct caller in
    this suite omits it and gets "use ``path`` as given". Both arms are exercised
    here, and the pair is what makes the default honest rather than incidental:
    the SAME source is clean under the resolved key and reds without it.
    """
    inside = "def create_and_register_t3_nonce():\n    _set_authorized_t3_nonce(nonce)\n"
    relative = Path("src/alfred/bootstrap/nonce_factory.py")

    assert check_tag_t3._scan_text(inside, relative, _NONCE_FACTORY) == []
    assert _messages(inside, relative) == [
        f"{relative}:2: {check_tag_t3._PRIVATE_SURFACE_MESSAGE}"
    ], "the default arm must key on `path` as given, NOT resolve it"


def test_private_surface_constant_matches_the_real_tiers_module() -> None:
    """DRIFT GUARD — derive the expected set, do not restate it.

    Hard-coding keeps the gate free of import-time I/O (it runs under bare ``python3``
    with no venv and no ``alfred`` importable); this test stops it drifting. A new
    private module-level name in ``tiers.py`` reds HERE on the day it lands.

    Two independent oracles, deliberately: ``_EXPECTED_PRIVATE_SURFACE`` is a literal
    in this file, and the derivation reads the real module. Editing the constant reds
    against the first; editing ``tiers.py`` reds against the second.
    """
    assert check_tag_t3._TIERS_PRIVATE_SURFACE == _EXPECTED_PRIVATE_SURFACE, (
        "the declared private surface moved; this literal pins it independently"
    )
    derived = check_tag_t3._derive_tiers_private_surface(_TIERS.read_text(encoding="utf-8"))
    assert derived == check_tag_t3._TIERS_PRIVATE_SURFACE, (
        f"tiers.py's private surface drifted. "
        f"Added: {sorted(derived - check_tag_t3._TIERS_PRIVATE_SURFACE)}. "
        f"Removed: {sorted(check_tag_t3._TIERS_PRIVATE_SURFACE - derived)}."
    )
    assert len(derived) == 21, f"expected 21 private names, derived {len(derived)}"


def test_the_private_surface_derivation_sees_every_binding_shape() -> None:
    """ORACLE SELF-TEST. A drift guard that cannot see a shape silently under-covers.

    R2-N: the earlier design enumerated SIX statement kinds and this fixture is built
    to DISCRIMINATE against it. Every shape below the ``_g`` line is one that a
    six-arm ``Assign``/``AnnAssign``/``TypeAlias``/``def``/``class``/recursion walk
    misses — ``import``, ``from ... import ... as``, ``for``, ``with ... as``,
    ``except ... as``, walrus, the three ``match`` capture kinds, and ``*_rest``.

    The four EXCLUSIONS are the other half of the oracle: names bound inside a nested
    ``def``, ``async def``, ``class`` or ``lambda`` belong to THAT scope, not to the
    module, so a walk that does not stop at a scope boundary over-collects.
    """
    source = (
        "import _mod\n"
        "from m import y as _z\n"
        "_a, _b = 1, 2\n"
        "_h, *_rest = seq\n"
        "_g: int = 1\n"
        "type _Alias = int\n"
        "if TYPE_CHECKING:\n"
        "    _c = 3\n"
        "if (_walrus := probe()):\n"
        "    pass\n"
        "try:\n"
        "    def _d() -> None:\n"
        "        _local_of_d = 1\n"
        "except ImportError as _err:\n"
        "    _e = None\n"
        "for _i in items:\n"
        "    pass\n"
        "with ctx() as _w:\n"
        "    pass\n"
        "class _F:\n"
        "    _class_attr = 1\n"
        "async def _afn() -> None:\n"
        "    _local_of_afn = 2\n"
        "_lam = lambda: (_inner := 1)\n"
        "match command:\n"
        '    case {"k": _mval, **_mrest}:\n'
        "        pass\n"
        "    case [*_mstar]:\n"
        "        pass\n"
        "    case _mcap:\n"
        "        pass\n"
    )
    derived = check_tag_t3._derive_tiers_private_surface(source)
    assert derived == {
        "_mod",
        "_z",
        "_a",
        "_b",
        "_h",
        "_rest",
        "_g",
        "_Alias",
        "_c",
        "_walrus",
        "_d",
        "_err",
        "_e",
        "_i",
        "_w",
        "_F",
        "_afn",
        "_lam",
        "_mval",
        "_mrest",
        "_mstar",
        "_mcap",
    }


def test_the_private_surface_derivation_ignores_dunder_and_public_names() -> None:
    """The filter, with both twins. ``from __future__ import annotations`` binds
    ``__future__`` at module level and is the live reason the dunder arm exists."""
    derived = check_tag_t3._derive_tiers_private_surface(
        "from __future__ import annotations\npublic = 1\n__all__ = []\n_private = 2\n"
    )
    assert derived == {"_private"}


# ---------------------------------------------------------------------------
# THE META-GUARD'S DEFAULT-DENY HALF (PR #553 review, T2).
#
# `test_every_keyed_identifier_is_alias_resolved` was built to close the
# identifier-aliasing CLASS and had that class's own disease: it hand-wrote its rows and
# derived nothing, so `copyreg` — an identifier three of the gate's rules key on — had no
# row at all, and the two mutations that would have exposed it survived the whole suite
# while the identical mutations on `gc` and `ctypes` died BECAUSE of that test.
#
# What follows derives the identifier set from the gate's OWN SOURCE. Every derived
# identifier must then appear either in `_KEYED_IDENTIFIER_SPELLINGS` (a behavioural row)
# or in `_DECLARED_ALIAS_RESIDUALS` (a stated reason). A rule that keys on a new
# identifier reds this test on the day it lands, which is the shape the guard was always
# supposed to have.
# ---------------------------------------------------------------------------

_GATE_SOURCE: str = _SCRIPT.read_text(encoding="utf-8")


def _module_level_string_constants(tree: ast.Module) -> dict[str, frozenset[str]]:
    """Module-level constant NAME -> every string literal anywhere inside its value.

    Deliberately shape-blind about the value: a frozenset of names, a frozenset of
    ``(module, primitive)`` tuples and a bare ``str`` all answer the same question here
    ("what strings does this constant put in front of a rule"), and enumerating the
    container shapes would be the mistake this whole file exists to stop repeating.
    """
    constants: dict[str, frozenset[str]] = {}
    for stmt in tree.body:
        if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
            name, value = stmt.target.id, stmt.value
        elif (
            isinstance(stmt, ast.Assign)
            and len(stmt.targets) == 1
            and isinstance(stmt.targets[0], ast.Name)
        ):
            name, value = stmt.targets[0].id, stmt.value
        else:
            continue
        if value is None:
            continue
        literals = frozenset(
            node.value
            for node in ast.walk(value)
            if isinstance(node, ast.Constant) and isinstance(node.value, str)
        )
        if literals:
            constants[name] = literals
    return constants


def _loop_target_iterables(tree: ast.Module) -> dict[str, frozenset[str]]:
    """Loop/comprehension target NAME -> the identifiers its iterable mentions.

    ``_alias_names`` is called with a literal seed twice and with a LOOP VARIABLE twice
    (``module`` over the carriers, ``seed`` over the private surface). Without this the
    derivation would see two of the four seed sources and silently under-collect — the
    failure direction that produces a missing row.
    """
    targets: dict[str, set[str]] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.For, ast.AsyncFor, ast.comprehension)):
            mentioned = {n.id for n in ast.walk(node.iter) if isinstance(n, ast.Name)}
            for bound in ast.walk(node.target):
                if isinstance(bound, ast.Name):
                    targets.setdefault(bound.id, set()).update(mentioned)
    return {name: frozenset(names) for name, names in targets.items()}


def _identifiers_the_gate_keys_on(source: str) -> dict[str, frozenset[str]]:
    """Every identifier literal the gate decides on, mapped to WHERE it came from.

    THREE collection channels, and each is a CLASS rather than a list of known sites:

    * every string literal on either side of an ``==``/``!=``/``in``/``not in``
      comparison — the shape ``_call_name(node) != "tag"`` and ``func.attr ==
      "__setattr__"`` share;
    * every string literal inside a module-level constant NAMED in such a comparison —
      the shape ``node.attr in _RAW_STATE_VEHICLE_ATTRS`` uses, which carries no literal
      of its own;
    * every seed reaching :func:`_alias_names`, whether written as a literal or fanned
      out of a constant through a loop variable.

    It OVER-collects: a file suffix, a path segment and the ``__main__`` guard all arrive
    here alongside real identifiers. That is the correct direction. An over-collected
    entry costs one declared-residual line; an under-collected one costs a silent bypass,
    which is what this guard exists to make impossible.

    Fails LOUDLY on a seed shape it cannot resolve rather than skipping it — a
    derivation that quietly returns a smaller set is a guard that quietly stops guarding.
    """
    tree = ast.parse(source)
    constants = _module_level_string_constants(tree)
    loops = _loop_target_iterables(tree)
    derived: dict[str, set[str]] = {}

    def record(identifier: str, provenance: str) -> None:
        derived.setdefault(identifier, set()).add(provenance)

    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "_alias_names"
        ):
            # ARITY AND KEYWORD GUARD (PR #553 review, C4). `node.args[1]` was indexed
            # blind, so `_alias_names(tree)` or `_alias_names(tree, seed=...)` raised
            # IndexError — and the docstring above claims this function "fails LOUDLY on
            # a seed shape it cannot resolve", which an IndexError is not. It names no
            # file, no line and no remedy, and it reads as a bug in the test rather than
            # as the gate having grown a shape the derivation cannot see. Same failure
            # direction as the `assert feeding` below, so it gets the same actionable
            # message.
            assert len(node.args) == 2 and not node.keywords, (
                f"scripts/check_tag_t3.py:{node.lineno}: _alias_names is CALLED in a "
                f"shape this derivation cannot read ({len(node.args)} positional "
                f"argument(s), keywords {sorted(kw.arg or '**' for kw in node.keywords)}). "
                f"Teach it that shape — a seed it cannot see is a rule this guard stops "
                f"covering."
            )
            seed = node.args[1]
            if isinstance(seed, ast.Constant) and isinstance(seed.value, str):
                record(seed.value, "alias-seed-literal")
                continue
            # A MODULE-LEVEL CONSTANT NAMED DIRECTLY — the third seed shape, taught here
            # rather than dodged (#539). `_trust_tier_type_aliases` calls
            # `_alias_names(tree, _TRUST_TIER_NAME)`, which is neither a literal nor a
            # loop variable, and this guard's own message says the remedy is to teach it.
            # Inlining the literal at the call site would have satisfied the guard while
            # making the gate less readable, and would have left the NEXT constant-seeded
            # call in the same hole.
            if isinstance(seed, ast.Name) and seed.id in constants:
                for literal in constants[seed.id]:
                    record(literal, f"alias-seed-constant:{seed.id}")
                continue
            feeding = [
                name
                for name in (loops.get(seed.id, frozenset()) if isinstance(seed, ast.Name) else ())
                if name in constants
            ]
            assert feeding, (
                f"scripts/check_tag_t3.py:{node.lineno}: _alias_names is seeded from a "
                f"shape this derivation cannot resolve ({ast.dump(seed)[:60]}). Teach it "
                f"that shape — a seed it cannot see is a rule this guard stops covering."
            )
            for constant in feeding:
                for literal in constants[constant]:
                    record(literal, f"alias-seed-via:{constant}")
        if isinstance(node, ast.Compare):
            if not all(isinstance(op, (ast.Eq, ast.NotEq, ast.In, ast.NotIn)) for op in node.ops):
                continue
            for side in (node.left, *node.comparators):
                if isinstance(side, ast.Constant) and isinstance(side.value, str):
                    record(side.value, "compare-literal")
                elif isinstance(side, ast.Name) and side.id in constants:
                    for literal in constants[side.id]:
                        record(literal, f"compare-set:{side.id}")
    return {identifier: frozenset(why) for identifier, why in derived.items()}


# THE RESIDUALS, each with a stated reason. An entry here is a claim that the identifier
# needs no alias-resolution row, and every claim names the mechanism that makes it true.
_PRE_EXISTING_RESIDUAL: str = (
    "PRE-EXISTING rule, NOT a #538 one, and #539's territory rather than this PR's. "
    "`_call_name`'s docstring already records it: 'The import-rename attack "
    "(`from … import tag as t; t(T3, x)`) remains out of scope.' Re-measured at PR #553 "
    "and still accurate — `tag`/`cast`/`TaggedContent`/`T3` are matched bare by "
    "`_call_name`/`_arg_name` with no alias environment, and "
    "`test_the_pre_existing_call_rules_are_still_the_declared_residual` pins that so the "
    "declaration cannot outlive the fact. Widening these rules here would be the "
    "'relax one rule to admit one caller' mistake the gate's module docstring names."
)
_VEHICLE_NAME_RESIDUAL: str = (
    "matched as an ATTRIBUTE name, a folded STRING or a bare `ast.Name` id — never as "
    "the local BINDING of an import or an assignment, so there is no name to rebind on "
    "the side the rule reads. The rules that read it are receiver-blind, and "
    "`_RAW_STATE_VEHICLE_NAMES` is deliberately wider than the attribute set so the "
    "getattr-string spelling (which carries no attribute node at all) is covered too. "
    "Enforced member by member by `test_every_declared_vehicle_attribute_is_enforced`, "
    "`test_every_declared_vehicle_name_is_enforced_as_a_bare_identifier` and "
    "`test_a_vehicle_named_only_as_a_string_is_refused`."
)
_SEAM_ATTR_RESIDUAL: str = (
    "the ATTRIBUTE half of `BaseModel.<seam>` — an attribute name, not a binding. The "
    "RECEIVER is the rebindable half and it carries the `BaseModel` row. Enforced member "
    "by member by `test_every_declared_seam_attribute_is_enforced`."
)
_TAGGED_FIELD_RESIDUAL: str = (
    "the folded STRING field-name argument of `__setattr__`, decided in the "
    "ADMISSIBILITY direction: a computed or unfoldable name is REFUSED, so no rebinding "
    "can make the gate weaker. Enforced by "
    "`test_setattr_denies_every_tagged_state_field_regardless_of_target`."
)
_CARRIER_PRIMITIVE_RESIDUAL: str = (
    "the PRIMITIVE half of a carrier, matched at the IMPORT site as `imported.name` — "
    "the one position Python offers no aliasing for (`from gc import X` has no syntax "
    "that renames X on the module's side). What the rule STORES is `imported.asname or "
    "imported.name`, so the rebindable half IS resolved, and the module half carries its "
    "own row. Enforced by `test_every_declared_carrier_primitive_is_enforced` and by the "
    "PRIMITIVE-IMPORT-ALIASED spelling in every carrier row."
)
_PRIVATE_SURFACE_RESIDUAL: str = (
    "resolved through the SAME `_alias_names` fan-out as `_set_authorized_t3_nonce`, "
    "which carries the row: `_private_surface_names` runs ONE resolver over the whole "
    "surface in a loop, so there is no per-name mechanism left to test. Enforced member "
    "by member on every carrier by "
    "`test_every_declared_private_name_is_enforced_on_every_carrier`."
)
_ADMISSIBILITY_RESIDUAL: str = (
    "keyed in the ADMISSIBILITY direction, so rebinding makes the gate STRICTER rather "
    "than weaker. `_is_self_init_re_entry` records the measurement: a rebound `super` is "
    "dead at runtime (`RuntimeError: super(): __class__ cell not found`) and refused here "
    "anyway. Pinned by `test_only_the_zero_argument_super_spelling_is_admissible`."
)
_PATH_SEGMENT_RESIDUAL: str = (
    "a PATH SEGMENT of `_APPROVED_PATHS`, compared as one resolved absolute `Path` "
    "against another — not an identifier, and nothing in a source file can rebind it."
)

_TYPEVAR_CALLEE_RESIDUAL: str = (
    "matched BY NAME as the callee of a `bound=TrustTier` binding, and NOT closable "
    "lexically. Requiring the callee at all is a NARROWING — without it, any call carrying "
    "`bound=TrustTier` seeded its target into the admitting set (`X = attacker(bound=TrustTier)` "
    "scanned clean, measured). What remains is that a `TypeVar` REBOUND to some other "
    "callable still matches by name, so the binding is still admitted. That is the same "
    "class as the benign-NAME residual in the module docstring — a name-keyed set cannot "
    "decide a runtime binding — and it is masked by the runtime guard. Aliases of the real "
    "`TypeVar` ARE resolved. Measured in both directions by "
    "`test_the_typevar_callee_residual_is_still_exactly_what_is_claimed`."
)
_KEYWORD_NAME_RESIDUAL: str = (
    "a KEYWORD ARGUMENT NAME read off `ast.keyword.arg`, not an identifier the scanned file "
    "binds. `bound=` in `TypeVar(..., bound=TrustTier)` and `tier=` in `dict(tier=...)` are "
    "fixed by the callee's signature, so nothing in a source file can rebind them — renaming "
    "either one changes which function is being called, not which rule applies. Pinned by "
    "`test_a_typevar_bound_to_trust_tier_is_a_benign_slice` and "
    "`test_a_tier_key_reaches_the_rule_through_every_mapping_shape`."
)
_DECLARED_ALIAS_RESIDUALS: dict[str, str] = {
    # #539 CLOSED `TaggedContent` and `T3`; both now carry behavioural rows in
    # `_KEYED_IDENTIFIER_SPELLINGS`, which is the stronger disposition — a row measures the
    # closure instead of asserting it. `tag` and `cast` stay: #539 widened the SUBSCRIPT and
    # CONSTRUCTION rules and left those two call rules exactly as they were.
    **dict.fromkeys(("tag",), _PRE_EXISTING_RESIDUAL),
    "bound": _KEYWORD_NAME_RESIDUAL,
    # `tier` reaches the derivation TWICE, and written as part of a `fromkeys` unpack the
    # keyword-argument reason silently displaced the state-field one. Spelled out for the
    # reason the `cast` entry below already is: which reason survives a dict merge is not
    # something a reader should have to work out.
    "tier": (
        "TWO ROLES. (1) a `TaggedContent` STATE FIELD in `_TAGGED_STATE_FIELDS`, compared "
        "against a folded string literal rather than an identifier — nothing in a source "
        "file can rebind the name of a field. Pinned by "
        "`test_every_tagged_state_field_is_refused_on_both_dunders`. (2) "
        f"{_KEYWORD_NAME_RESIDUAL}"
    ),
    "TypeVar": _TYPEVAR_CALLEE_RESIDUAL,
    # `__init__` and `__delattr__` are EXCLUDED because each has a behavioural row above.
    # The disjointness assertion in the meta-guard forbids being both, and a row is the
    # stronger of the two: it measures the closure instead of asserting it.
    **dict.fromkeys(
        sorted(_EXPECTED_VEHICLE_NAMES - {"__init__", "__delattr__"}), _VEHICLE_NAME_RESIDUAL
    ),
    **dict.fromkeys(sorted(_EXPECTED_SEAMS), _SEAM_ATTR_RESIDUAL),
    **dict.fromkeys(sorted(_EXPECTED_TAGGED_STATE_FIELDS), _TAGGED_FIELD_RESIDUAL),
    **dict.fromkeys(
        sorted({primitive for _, primitive in _EXPECTED_CARRIERS}), _CARRIER_PRIMITIVE_RESIDUAL
    ),
    **dict.fromkeys(
        sorted(_EXPECTED_PRIVATE_SURFACE - {"_set_authorized_t3_nonce"}),
        _PRIVATE_SURFACE_RESIDUAL,
    ),
    **dict.fromkeys(("self", "super"), _ADMISSIBILITY_RESIDUAL),
    **dict.fromkeys(("src", "alfred", "security", "tiers.py"), _PATH_SEGMENT_RESIDUAL),
    # `cast` reaches the derivation twice — as the pre-existing `cast(TaggedContent[…])`
    # rule's literal AND as `ctypes.cast`, a carrier primitive. Written out rather than
    # left to dict-merge order, because which reason survives that order is not a thing
    # a reader should have to work out.
    "cast": f"TWO ROLES. (1) {_PRE_EXISTING_RESIDUAL} (2) {_CARRIER_PRIMITIVE_RESIDUAL}",
    ".py": (
        "a FILE SUFFIX in `_view_is_exempt`'s out-of-repo `tmp_path` arm, not an "
        "identifier. Pinned by `test_a_real_out_of_repo_tmp_path_fixture_is_still_exempt`."
    ),
    "__main__": "the module-main guard at the foot of the script. Not a rule at all.",
    "TaggedContent[": (
        "a SUBSTRING of the string-form generic inside a `cast(...)` argument "
        '(`cast("TaggedContent[T2]", x)`), matched inside a string literal rather than '
        "against an identifier. Pinned by `test_cast_bypass_and_type_ignore_suppression`."
    ),
    "tests": (
        "a resolved path COMPONENT (`_TEST_DIR_NAME`), compared against "
        "`candidate.relative_to(_REPO_ROOT).parts[0]` — a directory name, not an "
        "identifier. Pinned by `test_a_path_segment_merely_containing_tests_is_not_exempt`."
    ),
    "create_and_register_t3_nonce": (
        "the exempt FUNCTION's name, keyed in the ADMISSIBILITY direction: renaming it "
        "makes the gate stricter, and `test_the_real_nonce_factory_file_scans_clean` does "
        "exactly that rename and requires both in-function references to red."
    ),
}


def test_the_pre_existing_call_rules_are_still_the_declared_residual() -> None:
    """PR #553 REVIEW, T2 — MEASURE the residual, do not merely declare it.

    ``tag``/``cast``/``TaggedContent``/``T3`` are declared in
    ``_DECLARED_ALIAS_RESIDUALS`` as PRE-EXISTING un-alias-resolved rules on the strength
    of ``_call_name``'s docstring. A declaration that nothing measures is a comment, and
    this repo has already shipped one that had silently become false. So the residual is
    asserted in BOTH directions: the direct spelling must red (the rules are live), and
    the rebound and import-aliased spellings must NOT (the residual is real).

    THIS TEST WAS MEANT TO RED WHEN #539 CLOSED THESE RULES, AND IT DID. `TaggedContent`
    and `T3` are gone from the residual set — both now carry behavioural rows in
    `_KEYED_IDENTIFIER_SPELLINGS`. What remains is `tag` and `cast`, whose CALL rules #539
    did not widen, and the contract is unchanged for them: it still reds the day a future PR
    closes either one, and the message still says so.
    """
    for label, source in {
        "tag": "tag(T3, payload)\n",
        "cast": "cast(TaggedContent[T2], x)\n",
    }.items():
        assert _messages(source), f"the pre-existing {label} rule is not live at all"

    for label, source in {
        "tag rebound": "_t = tag\n_t(T3, payload)\n",
        "tag import-aliased": ("from alfred.security.tiers import tag as _t\n_t(T3, payload)\n"),
        "cast rebound": "_c = cast\n_c(TaggedContent[T2], x)\n",
        "cast import-aliased": "from typing import cast as _c\n_c(TaggedContent[T2], x)\n",
    }.items():
        assert check_tag_t3._scan_text(source, _PROBE) == [], (
            f"the {label} spelling now REDS. That is a widening of a pre-existing rule "
            f"— good news, but _DECLARED_ALIAS_RESIDUALS still claims it is out of "
            f"scope. Give the identifier a row in _KEYED_IDENTIFIER_SPELLINGS and "
            f"delete the residual."
        )


# ---------------------------------------------------------------------------
# PR #553 REVIEW, C3 — THE CORPUS RECORD, DERIVED RATHER THAN TRANSCRIBED.
#
# `tl_base_dispatch_and_raw_state_write.yaml` and the `tl-2026-013` row of the corpus
# README both enumerate the shipped rules BY HAND, and both had stopped at the pre-fix
# set: `__doc__`, `gc.get_referrers` and three whole messages were missing, and a
# residual still named a count that had been wrong since the seventh carrier landed.
# That is the "comment outran the code" shape for the fourth time in this PR, so
# patching the numbers would have been the fourth patch of a recurring defect.
#
# A yaml file and a Markdown table cannot literally derive from a Python constant, so
# the DERIVATION lives here and the documents are checked against it. BOTH directions
# matter and the second is the one a hand-written test forgets: a rule that ships
# without landing in the record reds, AND a rule named in the record that no longer
# exists reds. Enumeration in the doc, default-deny in the oracle.
# ---------------------------------------------------------------------------

_CORPUS_DIR = _REPO_ROOT / "tests" / "adversarial" / "tier_laundering"
_CORPUS_YAML = _CORPUS_DIR / "tl_base_dispatch_and_raw_state_write.yaml"
_CORPUS_README = _CORPUS_DIR / "README.md"
_CORPUS_ROW_ID = "tl-2026-013"

# Messages that are NOT #538 authoring-layer rules, keyed BY NAME so the oracle is
# everything else. The direction is load-bearing: a NEW `_*_MESSAGE` constant falls into
# the expected set automatically and reds until the record names it, which is exactly the
# drift that happened three times. Each name is asserted to still EXIST, so a rename
# cannot silently widen the exclusion into a hole.
_NOT_AN_AUTHORING_LAYER_MESSAGE: frozenset[str] = frozenset(
    {
        # Pre-existing call rules — #539's territory, described elsewhere in the corpus.
        "_TAG_T3_MESSAGE",
        "_CAST_TAGGED_CONTENT_MESSAGE",
        "_TAGGED_CONTENT_T3_SUBSCRIPT_MESSAGE",
        "_TYPE_IGNORE_MESSAGE",
        # Collection failures — the file was not gated, so they are not findings.
        "_UNDECODABLE_MESSAGE",
        "_UNPARSEABLE_MESSAGE",
        "_UNREADABLE_MESSAGE",
        "_UNSCANNABLE_MESSAGE",
        "_UNSCANNABLE_PATH_MESSAGE",
        # The GATE is broken, not the file; travels on GateInternalError to exit 2.
        "_GATE_INTERNAL_MESSAGE",
    }
)

# Tokens the documents may name that are gate constants but not messages. Anything
# `_UPPER_CASE` outside this and the message set must resolve on the module, or the
# record is naming something that no longer exists.
_CORPUS_NON_MESSAGE_TOKENS: frozenset[str] = frozenset({"_TAGGED_STATE_FIELDS"})


def _authoring_layer_message_stems() -> frozenset[str]:
    """Every #538 rule's message constant, minus the ``_MESSAGE`` suffix.

    The STEM is what both documents can be checked against: the yaml writes the full
    constant name and the README row writes the stem, and a stem is a substring of its
    own full name, so one containment test reads both spellings.
    """
    return frozenset(
        name.removesuffix("_MESSAGE")
        for name, value in vars(check_tag_t3).items()
        if name.endswith("_MESSAGE")
        and isinstance(value, str)
        and name not in _NOT_AN_AUTHORING_LAYER_MESSAGE
    )


def test_the_corpus_record_matches_the_shipped_rule_set() -> None:
    """C3 — the record DERIVES from the gate and from the pinned literals.

    Four assertions, one per way the record has actually gone stale:

    * the EXCLUSION list still resolves — a renamed message must not fall out of the
      oracle by accident;
    * no stem is a substring of another, or a containment check for the shorter one is
      satisfied by the longer one appearing (the #548 test-002 shape, on this axis);
    * every shipped rule, vehicle attribute, vehicle name and carrier is NAMED in both
      documents — this is the direction that was broken;
    * every `_UPPER_CASE` token the documents name still EXISTS on the gate — the
      opposite direction, so a deleted or renamed rule cannot be left described.

    CONTAINMENT IS DOCUMENT-WIDE, and that is a deliberate looseness with a measured
    cost. Deleting ``__doc__`` from the yaml's slash-separated vehicle list SURVIVES this
    test, because a later sentence in the same rationale explains ``__doc__`` and the
    token is still present. Scoping the check to the list would key it on prose FORMAT,
    which rots faster than the list does and would red on any tidy-up. The direction that
    actually matters is proven instead: a vehicle attribute or carrier that ships WITHOUT
    appearing anywhere in the record reds here, verified by mutating the gate constant and
    its pinned literal together (so no neighbouring oracle fires first) and watching this
    test — and only this test — fail.
    """
    for excluded in sorted(_NOT_AN_AUTHORING_LAYER_MESSAGE):
        assert hasattr(check_tag_t3, excluded), (
            f"{excluded} is excluded from the corpus oracle but no longer exists on the "
            f"gate. A rename silently widens the exclusion into a hole — update this set."
        )

    stems = _authoring_layer_message_stems()
    assert stems, "the derivation found no authoring-layer rules — the oracle is vacuous"
    shadowed = sorted(
        (shorter, longer)
        for shorter in stems
        for longer in stems
        if shorter != longer and shorter in longer
    )
    assert not shadowed, (
        f"a rule stem is contained in another: {shadowed} — the containment checks below "
        f"would be satisfied for the shorter one by the longer one appearing"
    )

    # The pinned literals, asserted equal to the gate's own constants FIRST so this is
    # not a tautological oracle, then used as the expected vocabulary.
    assert _EXPECTED_VEHICLE_ATTRS == check_tag_t3._RAW_STATE_VEHICLE_ATTRS
    assert _EXPECTED_VEHICLE_NAMES == check_tag_t3._RAW_STATE_VEHICLE_NAMES
    assert _EXPECTED_CARRIERS == check_tag_t3._RAW_STATE_CARRIERS

    required = (
        {f"rule {stem}": stem for stem in stems}
        | {f"vehicle attribute {a}": a for a in _EXPECTED_VEHICLE_ATTRS}
        | {f"vehicle name {n}": n for n in _EXPECTED_VEHICLE_NAMES}
        | {f"carrier {m}.{p}": f"{m}.{p}" for m, p in _EXPECTED_CARRIERS}
    )

    readme_row = [
        line
        for line in _CORPUS_README.read_text(encoding="utf-8").splitlines()
        if _CORPUS_ROW_ID in line
    ]
    assert len(readme_row) == 1, (
        f"expected exactly one {_CORPUS_ROW_ID} row in the corpus README, found "
        f"{len(readme_row)} — the sweep below reads the wrong text otherwise"
    )
    documents = {
        _CORPUS_YAML.name: _CORPUS_YAML.read_text(encoding="utf-8"),
        # The README enumerates the RULES only; vehicle attributes, vehicle names and
        # carriers live in the payload's rationale, which is where a reader looks for
        # them. Scoped to the one row so an unrelated row cannot satisfy a check.
        f"README.md::{_CORPUS_ROW_ID}": readme_row[0],
    }
    scope = {
        _CORPUS_YAML.name: required,
        f"README.md::{_CORPUS_ROW_ID}": {f"rule {stem}": stem for stem in stems},
    }

    missing = [
        f"{document} does not name the {label}"
        for document, text in documents.items()
        for label, token in sorted(scope[document].items())
        if token not in text
    ]
    assert not missing, (
        "the adversarial corpus record has fallen behind the shipped rule set:\n  "
        + "\n  ".join(missing)
        + "\nThe record is the thing a reviewer reads to learn what the layer covers; a "
        "rule it omits is a rule nobody outside this file knows shipped."
    )

    live = {name for name in vars(check_tag_t3)} | {f"{stem}_MESSAGE" for stem in stems}
    stale = sorted(
        f"{document} names {token}, which no longer exists on the gate"
        for document, text in documents.items()
        for token in set(re.findall(r"_[A-Z][A-Z0-9_]{2,}", text))
        if token not in live
        and f"{token}_MESSAGE" not in live
        and token not in _CORPUS_NON_MESSAGE_TOKENS
    )
    assert not stale, (
        "the corpus record describes rules the gate no longer has:\n  "
        + "\n  ".join(stale)
        + "\nDelete them — a record that outlives the code is how a reviewer is told a "
        "boundary is covered when it is not."
    )


def test_the_alias_seed_derivation_fails_loudly_on_a_call_shape_it_cannot_read() -> None:
    """PR #553 REVIEW, C4 — an ``IndexError`` is not "failing LOUDLY".

    :func:`_identifiers_the_gate_keys_on` indexed ``node.args[1]`` blind while its own
    docstring promised it "fails LOUDLY on a seed shape it cannot resolve". The two
    shapes below are the ones Python allows and the derivation cannot read: a call with
    too few positional arguments, and the keyword spelling. Both used to raise
    ``IndexError`` (or silently read the wrong node), which names no file, no line and
    no remedy — it reads as a broken test rather than as the gate having grown a shape
    the guard stopped covering.

    POSITIVE TWIN FIRST, and it is the load-bearing half: a guard that refused
    EVERYTHING would satisfy both negative assertions while making the whole meta-guard
    unrunnable, and the real gate's four call sites are the only proof it does not.
    """
    good = 'x = _alias_names(tree, "BaseModel")\n'
    assert _identifiers_the_gate_keys_on(good) == {"BaseModel": frozenset({"alias-seed-literal"})}

    for label, source in {
        "too-few-positional": "x = _alias_names(tree)\n",
        "keyword-seed": 'x = _alias_names(tree, seed="BaseModel")\n',
        "starred-args": "x = _alias_names(*pair)\n",
    }.items():
        with pytest.raises(AssertionError, match="shape this derivation cannot read") as raised:
            _identifiers_the_gate_keys_on(source)
        # THE POINT OF THE GUARD, asserted rather than implied: the diagnosis names the
        # FILE and the LINE. An IndexError names neither, which is why it read as a bug
        # in the test rather than as the gate outgrowing the derivation.
        assert "scripts/check_tag_t3.py:1:" in str(raised.value), (
            f"the {label} shape failed without naming file:line — that IS the difference "
            f"between this guard and the IndexError it replaces: {raised.value}"
        )

    # AND THE REAL GATE STILL RESOLVES — the guard is a floor on shapes that do not
    # occur, not a wall in front of the ones that do.
    #
    # ASSERT THE GUARD WAS REACHED, not merely that the derivation returned something.
    # `_identifiers_the_gate_keys_on` collects from three channels and two of them do not
    # touch the guarded branch at all, so a non-empty result proves nothing about it.
    # MEASURED: transcribed onto `origin/main`, whose gate calls `_alias_names` ZERO
    # times, the bare truthiness assertion passed — this test was the second of two in
    # the file green against a gate with none of these rules in it. Requiring an
    # `alias-seed` provenance is what makes it discriminate: the branch's gate has four
    # such call sites, and every one of them goes through the arity guard above.
    derived = _identifiers_the_gate_keys_on(_GATE_SOURCE)
    seeded = sorted(
        identifier
        for identifier, why in derived.items()
        if any(provenance.startswith("alias-seed") for provenance in why)
    )
    assert seeded, (
        "the real gate's _alias_names call sites produced no alias-seed provenance, so "
        "the guard above was never exercised on real source and the assertion that it "
        "does not break the derivation is vacuous"
    )


def test_every_identifier_the_gate_keys_on_is_rowed_or_declared_residual() -> None:
    """THE DEFAULT-DENY HALF OF THE META-GUARD (PR #553 review, T2).

    Derives the identifier set from ``scripts/check_tag_t3.py`` itself and requires every
    member to be EITHER behaviourally rowed in ``_KEYED_IDENTIFIER_SPELLINGS`` OR
    declared in ``_DECLARED_ALIAS_RESIDUALS`` with a stated reason. An enumeration closes
    what it enumerates; this closes the class.

    FOUR assertions, and each catches a different way the guard could go quiet:

    * ANCHORS — the derivation returning an empty or truncated set would satisfy the
      coverage check vacuously, so known identifiers are required to be in it.
    * DISJOINT — an identifier must not be both rowed and excused; that would let a row
      rot behind its own residual.
    * COVERED — the property itself.
    * NO DEAD RESIDUALS — an excuse for an identifier no rule keys on any more is rot,
      and deleting it is how the reason stays true of the code.
    """
    derived = _identifiers_the_gate_keys_on(_GATE_SOURCE)

    for anchor in ("BaseModel", "vars", "gc", "ctypes", "copyreg", "_set_authorized_t3_nonce"):
        assert anchor in derived, (
            f"the derivation did not find {anchor!r}, which the gate demonstrably keys "
            f"on — it is under-collecting and the coverage check below is vacuous"
        )

    rowed = frozenset(_KEYED_IDENTIFIER_SPELLINGS)
    excused = frozenset(_DECLARED_ALIAS_RESIDUALS)
    assert not rowed & excused, (
        f"identifiers are both rowed and declared residual: {sorted(rowed & excused)}"
    )

    uncovered = {
        identifier: sorted(why)
        for identifier, why in sorted(derived.items())
        if identifier not in rowed and identifier not in excused
    }
    assert not uncovered, (
        f"the gate keys on identifiers the meta-guard neither rows nor excuses: "
        f"{uncovered}. Add a row to _KEYED_IDENTIFIER_SPELLINGS proving all its binding "
        f"spellings red, or an entry to _DECLARED_ALIAS_RESIDUALS stating why it needs "
        f"none. `copyreg` sat in this gap through two review rounds."
    )

    dead = sorted(excused - frozenset(derived))
    assert not dead, (
        f"_DECLARED_ALIAS_RESIDUALS excuses identifiers no rule keys on any more: "
        f"{dead}. Delete them — a reason nothing measures stops being true silently."
    )
    assert all(reason.strip() for reason in _DECLARED_ALIAS_RESIDUALS.values()), (
        "every residual must state a REASON; an empty one is an undeclared bypass"
    )


# ---------------------------------------------------------------------------
# #538 Task 5 — the ``security/quarantine`` module's exemption is DELETED, and
# every claim of it goes with it. Re-measured under the FULL rule set: 0
# violations across 1634 lines, 0 ``tag(`` calls, 0 ``TaggedContent`` builds.
#
# The prose here deliberately spells that module WITHOUT its ``.py`` suffix:
# ``test_no_stale_claim_...`` below sweeps every tracked file, this one
# included, and a comment is exactly the shape it is hunting.
# ---------------------------------------------------------------------------

# Pinned as a literal in the TEST file, per R2-E: an oracle built by reading the
# constant under test cannot tell a shrunk set from a grown one.
_EXPECTED_APPROVED_PATHS = frozenset({_TIERS})


def test_quarantine_is_no_longer_an_approved_path() -> None:
    """The exemption is DELETED, not narrowed.

    Narrowing keeps a live soft-landing zone inside the one module that provably does
    not need one. Deletion means the day a line there DOES need it back, the build
    fails loudly naming the decision.
    """
    assert _QUARANTINE not in check_tag_t3._APPROVED_PATHS
    assert check_tag_t3._APPROVED_PATHS == _EXPECTED_APPROVED_PATHS


def test_quarantine_scans_clean_without_its_exemption() -> None:
    """THE PIN. The REAL file, the REAL path, the FULL rule set — no fixture, no copy.

    ``assert not _is_exempt`` lives INSIDE this test on purpose (R2-I). Transcribed
    onto ``main``, where the file is still exempt, ``_scan_file`` returns ``[]`` from
    the exemption arm and the pin passes for the OPPOSITE reason it exists.

    PR #553 REVIEW, T8 — AND THE POSITIVE TWIN, which the plan's own Global Constraint
    requires of every negative floor and which this one was the last in the file to be
    missing. ``assert not _is_exempt`` rules out the exemption arm but not the OTHER way
    a bare ``== []`` goes green: the #538 rules being absent from this scan path
    altogether. Appending one vehicle line to the real source and requiring it to red is
    what tells those two apart.
    """
    assert not check_tag_t3._is_exempt(_QUARANTINE)
    assert check_tag_t3._scan_file(_QUARANTINE) == []

    seeded = _QUARANTINE.read_text(encoding="utf-8") + 'vars(_probe)["tier"] = T3\n'
    assert any(
        check_tag_t3._RAW_VEHICLE_VARS_MESSAGE in v
        for v in check_tag_t3._scan_text(seeded, _QUARANTINE)
    ), (
        "positive twin: quarantine.py yielded no #538 finding even with a vehicle line "
        "appended — the rules are not live on this scan path, so the floor above proves "
        "nothing"
    )


def test_tiers_still_needs_its_whole_file_exemption() -> None:
    """ANTI-VACUITY TWIN, discriminating on a #538 RULE.

    A bare ``assert violations`` is satisfied by the PRE-EXISTING ``tag(T3`` rule, so
    it passes with every #538 rule deleted and cannot tell a working detector from an
    empty diff. Requiring a #538 message is what makes this an oracle for the pin
    above: it proves the new rules are LIVE on this scan path.
    """
    assert _TIERS in check_tag_t3._APPROVED_PATHS
    violations = check_tag_t3._scan_text(
        _TIERS.read_text(encoding="utf-8"),
        _REPO_ROOT / "src" / "alfred" / "security" / "TIERS_NOT_EXEMPT.py",
    )
    assert any(check_tag_t3._RAW_VEHICLE_VARS_MESSAGE in v for v in violations), (
        "tiers.py yielded no #538 finding without its exemption — the new rules are "
        "not live on this scan path, so the pin above proves nothing"
    )


# The invariant sweep's vocabulary. Kept as module constants so the positive twin
# inside the test below runs the SAME predicate the repo-wide pass runs.
#
# PARAGRAPH-SCOPED, not line-scoped (R2-O). ``git grep`` decides one line at a time,
# and every one of the three claims inside ``check_tag_t3.py`` — the primary edit
# sites — wraps its qualifier onto a different line from its ``quarantine.py``
# mention. A line-scoped sweep reports those three as clean.
_SWEEP_QUALIFIERS: tuple[str, ...] = ("approv", "authoris", "authoriz", "may call")

# The CONJUNCTION is what removes the noise a bare qualifier match produces. Measured
# false positives from the qualifier alone: ``docs/subsystems/quarantine.md`` (a
# "refusal-authorisation contract" sentence four lines above a ``T3DerivedData``
# heading) and two ``authorized_t3_nonce`` FIXTURE PARAMETERS in
# ``tests/adversarial/tier_laundering/``. None of the three names an authoring
# surface; every real claim does.
_SWEEP_SURFACE_TERMS: tuple[str, ...] = (
    "_approved_paths",
    "home",
    "exempt",
    "tag(t3",
    "taggedcontent",
)

# Measured worst case in this repo is 4 (the gate module docstring's "Authorised
# callers" header at ``check_tag_t3.py:33`` against its bullet at ``:37``); 6 carries
# headroom without admitting any new match — 4, 6 and 8 all return the identical set.
_SWEEP_WINDOW: int = 6

# Dated design records, not live guidance. A plan or spec written before #538 is
# CORRECT about the world it was written in; rewriting it would falsify the record.
#
# THE FORWARD SLASHES ARE CORRECT ON WINDOWS and must not be "fixed" to `os.sep`: these
# match `git grep` OUTPUT, and git emits repo-relative paths with `/` on every platform.
# `_REPO_ROOT / rel` then accepts that string unchanged, because `WindowsPath` parses `/`
# as a separator. Recorded because the sibling defect in this same test WAS a real
# cross-OS failure (see the decode note in the sweep below) and the next reader will
# reasonably wonder about these too.
_SWEEP_EXCLUDED_PREFIXES: tuple[str, ...] = (
    "docs/superpowers/plans/",
    "docs/superpowers/specs/",
)

# R2-O's measured false positive, excluded BY PATH with its reason stated rather than
# by tuning the window until it disappears: ``docs/runbooks/slice-3-operator-migration.md``
# is a Markdown TABLE whose remediation column says "wait for reviewer approval" about
# an unrelated ``alfred plugin grant`` flow, on the same physical line as a source
# reference in another column. Nothing about that row concerns ``_APPROVED_PATHS``.
_SWEEP_EXCLUDED_FILES: tuple[str, ...] = ("docs/runbooks/slice-3-operator-migration.md",)

# Assembled at runtime so this file's own fixtures do not plant the literal the sweep
# hunts for — the sweep scans every tracked file, this one included.
_Q_PY: str = "quarantine" + ".py"


def _git_grep_bytes(pattern: str) -> bytes:
    """``git grep -n -E <pattern>`` over the whole repo, as RAW BYTES.

    BYTES, and never ``subprocess``'s text mode — that decodes with the PLATFORM LOCALE,
    which is ``cp1252`` on the windows-latest runner, and this repo's own docs are full
    of non-ASCII (the first offender is ``←`` U+2190, whose third UTF-8 byte 0x90 is an
    undefined slot in cp1252). It failed the cross-OS gate (#246) in a way worth writing
    down, because it did NOT surface as the decode error: Windows
    ``Popen._communicate`` reads each pipe on a ``_readerthread``, so the
    ``UnicodeDecodeError`` killed the THREAD, the buffer list stayed empty,
    ``stdout = stdout[0] if stdout else None`` handed back None, and the caller got
    ``AttributeError: 'NoneType' object has no attribute 'splitlines'`` with the real
    cause reduced to a stray traceback in the log. POSIX decodes on the main thread, so
    the same fault RAISES; reproduced locally by forcing ``encoding="cp1252"``, identical
    codec and identical byte. ``_git_tracked_python_files`` in the gate itself already had
    this right, and this is the same pattern for the same reason.

    (The offending keyword's literal spelling appears NOWHERE in this file:
    ``test_the_sweep_decodes_git_output_as_utf8_not_as_the_platform_locale`` sweeps this
    file for it, and planting what a sweep hunts for makes the sweep red on itself. Same
    problem ``_Q_PY`` has, same runtime-assembly solution.)

    A FUNCTION rather than an inline block so the empty-output guard below is REACHABLE
    from a test: inline, ``proc.stdout`` is never falsy on a host where the pattern
    matches, so removing the guard changed nothing any test could see — a floor no
    mutation could kill.
    """
    # S603/S607 are reported on DIFFERENT lines — S603 on the call, S607 on the argv
    # list — so a single combined noqa suppresses neither. `pattern` is supplied by this
    # module's own callers, never by input; argv is a literal list with no shell.
    proc = subprocess.run(  # noqa: S603
        ["git", "grep", "-n", "-E", pattern],  # noqa: S607
        cwd=_REPO_ROOT,
        capture_output=True,
        check=False,
    )
    assert proc.stdout, (
        f"git grep found nothing for {pattern!r} (returncode={proc.returncode}, "
        f"stderr={proc.stderr.decode('utf-8', errors='surrogateescape')[:300]!r}) — a "
        f"sweep with no input passes VACUOUSLY. Either the pattern stopped matching, or "
        f"git could not run here at all."
    )
    return proc.stdout


def _git_grep_lines(pattern: str) -> list[str]:
    """:func:`_git_grep_bytes`, decoded EXPLICITLY as UTF-8.

    ``surrogateescape`` so a path or a line this repo can hold but UTF-8 cannot
    round-trip degrades to a mangled string rather than to no sweep at all.
    """
    return _git_grep_bytes(pattern).decode("utf-8", errors="surrogateescape").splitlines()


def _stale_claim_lines(lines: list[str]) -> list[int]:
    """1-based line numbers whose paragraph claims ``quarantine.py`` may author T3.

    A "paragraph" is the mention line plus ``_SWEEP_WINDOW`` lines either side. A hit
    needs BOTH an approval qualifier and an authoring-surface term inside that window.
    """
    found: list[int] = []
    for index, line in enumerate(lines):
        if _Q_PY not in line:
            continue
        window = "\n".join(lines[max(0, index - _SWEEP_WINDOW) : index + _SWEEP_WINDOW + 1]).lower()
        if any(q in window for q in _SWEEP_QUALIFIERS) and any(
            s in window for s in _SWEEP_SURFACE_TERMS
        ):
            found.append(index + 1)
    return found


def test_no_stale_claim_that_quarantine_is_an_authorised_home_survives() -> None:
    """INVARIANT SWEEP. Deleting the exemption without deleting the claims leaves the
    repo asserting a security invariant that is no longer true — including inside the
    workflow that RUNS this gate, and inside a test that stays green while saying it.
    """
    # POSITIVE TWIN FIRST, on the same predicate: an emptied qualifier or surface list
    # would make the repo-wide floor below pass vacuously.
    same_line = [
        "  # gate is release-blocking — only `security/tiers.py` and",
        "  # `security/" + _Q_PY + "` may call `tag(T3, ...)`, and `cast(",
    ]
    assert _stale_claim_lines(same_line) == [2], "the sweep no longer recognises the claim"

    # SECOND POSITIVE TWIN, and it is the one that pins ``_SWEEP_WINDOW``. The
    # qualifier sits a full SIX lines above the mention — the repo's measured
    # line-wrap distance, transcribed from the module docstring this task edited.
    # Without it the window can be narrowed to 0 and every test here still passes
    # while the sweep goes blind to exactly the three claims R2-O names (measured:
    # the ``_SWEEP_WINDOW = 0`` mutant survived the first draft of this test).
    # A WIDER window still passes, which is intended — this is a floor, not a pin
    # on the exact value.
    wrapped = [
        "Authorised callers (the EXACT list — keep in sync with the briefing):",
        "",
        "- ``src/alfred/security/tiers.py``      — the ``tag`` overload bodies",
        "                                          (the home of the factory itself).",
        "- ``tests/unit/security/**``            — tests assert the gate's behaviour",
        "                                          using the same patterns.",
        "- ``src/alfred/security/" + _Q_PY + "`` — the downgrade boundary.",
    ]
    assert _stale_claim_lines(wrapped) == [7], (
        "the sweep no longer reaches a qualifier six lines from its mention — a "
        "line-scoped sweep is blind to every claim inside check_tag_t3.py (R2-O)"
    )

    # NEGATIVE TWINS: the two measured false-positive shapes the conjunction removes.
    assert (
        _stale_claim_lines(
            [
                "post-stage refusals — the refusal-authorisation contract is",
                "pre-stage-only by design.",
                "",
                "### `T3DerivedData` (`src/alfred/security/" + _Q_PY + "`)",
            ]
        )
        == []
    )
    assert (
        _stale_claim_lines(
            [
                "    authorized_t3_nonce: CapabilityGateNonce,",
                ") -> None:",
                '    """The orchestrator-side strict data-shape guard (' + _Q_PY + ":1075)",
                '    refuses a non-dict ``data`` rather than coercing it."""',
            ]
        )
        == []
    )

    mentions = _git_grep_lines(_Q_PY.replace(".", r"\."))

    candidates: dict[str, None] = {}
    for mention in mentions:
        rel = mention.split(":", 1)[0]
        if rel.startswith(_SWEEP_EXCLUDED_PREFIXES) or rel in _SWEEP_EXCLUDED_FILES:
            continue
        candidates[rel] = None

    live: list[str] = []
    for rel in candidates:
        text = (_REPO_ROOT / rel).read_text(encoding="utf-8", errors="replace")
        live.extend(f"{rel}:{n}" for n in _stale_claim_lines(text.splitlines()))

    assert live == [], (
        "stale claims that the security/quarantine module is an authorised T3 home:\n"
        + "\n".join(live)
    )


# The Windows locale codec, named once. `charmap` is what the error message calls it;
# `cp1252` is what `codecs` calls it, and they are the same decoder.
_WINDOWS_LOCALE_CODEC: str = "cp1252"


def test_the_sweep_decodes_git_output_as_utf8_not_as_the_platform_locale() -> None:
    """#246 CROSS-OS. The sweep above shipped in TEXT MODE and FAILED on Windows.

    Text mode — ``subprocess``'s ``text`` keyword set true, whose literal spelling is
    assembled at runtime below and never written out in this file — decodes with the
    LOCALE encoding, which is ``cp1252`` on the
    windows-latest runner. This repo's own documentation is full of non-ASCII, and the
    failure did not surface as a decode error: Windows ``Popen._communicate`` reads each
    pipe on a ``_readerthread``, so the ``UnicodeDecodeError`` killed the thread, the
    buffer list stayed empty, ``stdout = stdout[0] if stdout else None`` returned None,
    and the caller got ``AttributeError: 'NoneType' object has no attribute
    'splitlines'`` with the real cause reduced to a stray traceback in the log.

    THIS TEST RUNS THE PROPERTY, NOT THE PLATFORM. It cannot run Windows, so it asserts
    the two facts that together make the platform outcome inevitable:

    * the real command's output genuinely IS undecodable as ``cp1252`` — so the hazard
      is live rather than theoretical;
    * the shape the sweep now uses decodes it without raising, and yields the same lines.

    A mutant that reinstates text mode is not visible to this test on a UTF-8 host,
    which is why the second half is a LEXICAL floor over the two files this gate owns.
    That is the honest split: the byte-level half proves the fix, the lexical half is
    what a reverting edit trips.

    IF THIS TEST EVER REDS ON THE FIRST ASSERTION, the repo has become ASCII-only in
    everything ``git grep`` reaches. That is not a failure of the sweep — delete the
    first assertion and keep the rest.
    """
    raw = _git_grep_bytes(_Q_PY.replace(".", r"\."))

    with pytest.raises(UnicodeDecodeError) as raised:
        raw.decode(_WINDOWS_LOCALE_CODEC)
    assert raised.value.encoding in {_WINDOWS_LOCALE_CODEC, "charmap"}, (
        f"expected the Windows locale codec to be what fails, got "
        f"{raised.value.encoding!r} — the reproduction no longer models the runner"
    )
    assert _git_grep_lines(_Q_PY.replace(".", r"\.")), (
        "the utf-8 decode of the SAME bytes produced no lines"
    )

    # THE EMPTY-OUTPUT GUARD, which is why the helper exists at all. `git grep` exits 1
    # with empty stdout when nothing matches, and a sweep with no input passes
    # VACUOUSLY. Inline, this arm was unreachable from any test on a host where the real
    # pattern matches — measured: deleting the guard killed no test.
    with pytest.raises(AssertionError, match="passes VACUOUSLY"):
        _git_grep_lines("zzz" + "_no_such_pattern_in_this_repo_zzz")

    # THE LEXICAL FLOOR, scoped to the two files this task owns. Text-mode decoding of a
    # subprocess whose output can carry repo text is the CLASS, not this one call site.
    #
    # Both the pattern and its twin are ASSEMBLED so this file does not plant the
    # literal it sweeps for — the same runtime-assembly trick `_Q_PY` uses above, and
    # for the same reason: measured, spelling it out made this test fail on itself.
    #
    # POSITIVE TWIN: the pattern must match when the hazard IS present, or an emptied
    # regex makes the floor vacuous.
    keywords = ("text", "universal_newlines")
    hazard = re.compile("|".join(rf"\b{kw}\s*=\s*True\b" for kw in keywords))
    for kw in keywords:
        assert hazard.search(f"subprocess.run(argv, {kw}=True)"), (
            f"the hazard pattern no longer matches {kw} — the floor below is vacuous"
        )
    for owned in (_SCRIPT, Path(__file__).resolve()):
        assert not hazard.search(owned.read_text(encoding="utf-8")), (
            f"{owned.name} decodes subprocess output with the PLATFORM LOCALE. On the "
            f"windows-latest runner that is {_WINDOWS_LOCALE_CODEC}, and this repo's "
            f"text is not cp1252-decodable. Capture bytes and decode explicitly, as "
            f"_git_tracked_python_files does."
        )


def test_the_typevar_callee_residual_is_still_exactly_what_is_claimed() -> None:
    """PR REVIEW sec-003 — MEASURE the residual, never merely declare it.

    This repo has shipped a declared residual that had silently become false, and sec-003
    was another: `_trust_tier_type_aliases` did not check the callee at all, so ANY call
    carrying `bound=TrustTier` seeded its target into the ADMITTING set. Requiring the
    callee narrowed that, and the narrowing is asserted here in BOTH directions so the
    claim cannot rot:

    * an arbitrary callee must NOT admit (the narrowing is real);
    * an ALIAS of the real `TypeVar` must admit (aliases are resolved);
    * a REBOUND `TypeVar` still admits — the residual itself, stated rather than hidden.
    """
    assert _messages("X = attacker(bound=TrustTier)\nTaggedContent[X](c=1)\n"), (
        "the callee check is not live — any call with bound=TrustTier would admit"
    )

    assert (
        _messages('TierT = TypeVar("TierT", bound=TrustTier)\nTaggedContent[TierT](c=1)\n') == []
    ), "the benign floor red: a real TypeVar bound must still admit"
    assert (
        _messages(
            "from typing import TypeVar as _TV\n"
            'TierT = _TV("TierT", bound=TrustTier)\n'
            "TaggedContent[TierT](c=1)\n"
        )
        == []
    ), "an ALIAS of the real TypeVar must resolve"

    assert (
        _messages(
            "TypeVar = attacker\n"
            'TierT = TypeVar("TierT", bound=TrustTier)\n'
            "TaggedContent[TierT](c=1)\n"
        )
        == []
    ), (
        "a REBOUND TypeVar now REDS. That is a widening of the callee check — good news, "
        "but _DECLARED_ALIAS_RESIDUALS still claims it is open. Give TypeVar a row in "
        "_KEYED_IDENTIFIER_SPELLINGS and delete the residual."
    )
