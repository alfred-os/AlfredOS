"""Unit tests for the #538 sole-layer rules in ``scripts/check_tag_t3.py``.

Loaded via ``spec_from_file_location`` against the REAL script path: a ``tmp_path``
copy would recompute ``_REPO_ROOT`` from ``__file__`` and silently invert every
exemption, so a copy-based test measures the wrong tree while still passing.
"""

from __future__ import annotations

import ast
import importlib.util
import subprocess
import sys
from pathlib import Path

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
    assert fmap[2] == "sync_one"
    assert fmap[6] == "async_one", "async def unmapped — the walk matches ast.FunctionDef only"


def test_enclosing_functions_reports_the_innermost_function() -> None:
    """A nested def must shadow its parent, or an exemption leaks outward."""
    fmap = check_tag_t3._enclosing_functions(
        ast.parse("def outer():\n    def inner():\n        x = 1\n    y = 2\n")
    )
    assert fmap[3] == "inner"
    assert fmap[4] == "outer"


def test_enclosing_functions_leaves_module_scope_unmapped() -> None:
    """Module-level lines have no enclosing function.

    Load-bearing: the module-level import exemption keys on this being ``None``.
    """
    fmap = check_tag_t3._enclosing_functions(ast.parse("import os\n\n\ndef f():\n    x = 1\n"))
    assert 1 not in fmap
    assert fmap[5] == "f"


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
    """
    bound = check_tag_t3._FOLD_MAX_DEPTH

    def chain(operands: int) -> str | None:
        source = " + ".join(f'"a{i}"' for i in range(operands))
        return check_tag_t3._fold_str(ast.parse(source, mode="eval").body)

    # A left-associative chain of N operands nests N-1 BinOps, so N == bound + 1
    # recurses to exactly `bound` and still folds. This is the positive twin: it proves
    # the bound is a CEILING and not a blanket refusal.
    assert chain(bound + 1) == "".join(f"a{i}" for i in range(bound + 1))
    assert chain(bound + 2) is None, "one operand past the bound must stop folding"

    deep: ast.expr = ast.Constant(value="a")
    for _ in range(2000):
        deep = ast.BinOp(left=deep, op=ast.Add(), right=ast.Constant(value="b"))
    assert check_tag_t3._fold_str(deep) is None, (
        "an unbounded _fold_str raises RecursionError here, which the fence would "
        "re-file as a gate defect and discard every violation found so far"
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
    expected = frozenset({"tier", "content", "source"})
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

    Three live sites depend on the clean half: ``hooks/context.py:106``,
    ``plugins/web_fetch/allowlist.py:139``,
    ``plugins/web_fetch/fetch_dispatcher.py:219``. Refusing ``object.__setattr__``
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

    Three of the eight members were untested, so dropping them from the constant
    survived the whole suite AND the real-tree scan. Looping over the constant under
    test would not have caught it either: the mutation removes the member from the
    oracle at the same time.
    """
    expected = frozenset(
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
    assert expected == check_tag_t3._RAW_STATE_VEHICLE_ATTRS, (
        "the declared vehicle-attribute set moved; this oracle pins it"
    )
    for attr in sorted(expected):
        assert _messages(f"x = obj.{attr}\n") == [
            f"{_PROBE}:1: {check_tag_t3._RAW_VEHICLE_ATTR_MESSAGE}"
        ], f"vehicle attribute {attr!r} is declared but not enforced"


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
    expected = frozenset(
        {
            "__dict__",
            "__setstate__",
            "__getstate__",
            "__reduce__",
            "__reduce_ex__",
            "__new__",
            "__mro__",
            "__bases__",
            "__setattr__",
            "__delattr__",
            "__class__",
        }
    )
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
    """R2-H — the equality-to-containment WIDENING currently reds nothing.

    Relaxing ``folded in _RAW_STATE_VEHICLE_NAMES`` to "any member appears inside
    ``folded``" kept the real-tree scan at rc=0 and every other floor green, because
    no other fixture carries a vehicle name inside a longer string in CODE position.
    """
    assert check_tag_t3._scan_text('x = "reset the __dict__ mapping"\n', _PROBE) == []
    assert _messages('x = "__dict__"\n') == [f"{_PROBE}:1: {check_tag_t3._RAW_VEHICLE_STR_MESSAGE}"]


def test_carrier_by_reference_primitives_are_refused() -> None:
    """FLEET FINDING sec-003 — ``gc.get_referents(obj)`` names no vehicle at all.

    Scoped to the reaching PRIMITIVES, not to the modules: a module-scoped ban costs
    two legitimate sites (``ctypes.CDLL`` for libc in ``supervisor/process_posture.py``,
    ``gc.collect()`` in ``fd3_key_delivery.py``); the primitive ban costs ZERO.
    Both live benign uses are the twin here.
    """
    for source in (
        'import gc\ngc.get_referents(low)[0]["tier"] = T3\n',
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


def test_every_declared_carrier_primitive_is_enforced() -> None:
    """R2-E/R2-H — four of the six were never exercised in ``Call.func`` position.

    ``ctypes.py_object`` appeared only as an ARGUMENT in its fixture, so dropping it
    from the constant survived the suite. Pin the set as a literal, then loop over the
    pinned copy with each primitive in the position the rule actually keys on.
    """
    expected = frozenset(
        {
            ("gc", "get_referents"),
            ("gc", "get_objects"),
            ("ctypes", "py_object"),
            ("ctypes", "cast"),
            ("copyreg", "_reconstructor"),
            ("copyreg", "__newobj__"),
        }
    )
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

    (As with ``vars`` above, the plan attributes this row to Task 4's
    ``test_every_keyed_identifier_is_alias_resolved``; Task 2's rule carries its own
    behavioural oracle until that meta-test lands.)
    """
    for label, source in {
        "module-rebind": "import gc\n_g = gc\n_g.get_referents(low)\n",
        "import-alias": "import gc as _g\n_g.get_referents(low)\n",
        "direct-binding": "from gc import get_referents\nget_referents(low)\n",
        "direct-alias": "from gc import get_referents as _gr\n_gr(low)\n",
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
    assert _messages('BaseModel.model_copy(low, update={"tier": T3})\n') == [
        f"{_PROBE}:1: {check_tag_t3._BASEMODEL_VALUE_MESSAGE}"
    ]
    assert _messages('BaseModel.copy(low, update={"tier": T3})\n') == [
        f"{_PROBE}:1: {check_tag_t3._BASEMODEL_VALUE_MESSAGE}"
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
    assert _messages(source) == [f"{_PROBE}:2: {check_tag_t3._BASEMODEL_VALUE_MESSAGE}"]


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
        f"{_PROBE}:1: {check_tag_t3._BASEMODEL_VALUE_MESSAGE}"
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
    ``_reg(mine)``, which is the laundering. Keying on the use line makes all six rows
    discriminate on the property they claim.
    """
    # (identifier, direct spelling, rebound spelling, import-aliased spelling)
    cases = [
        (
            "BaseModel",
            'BaseModel.model_copy(low, update={"tier": T3})',
            '_B = BaseModel\n_B.model_copy(low, update={"tier": T3})',
            'from pydantic import BaseModel as _B\n_B.model_copy(low, update={"tier": T3})',
        ),
        (
            "vars",
            'vars(obj)["tier"] = T3',
            '_v = vars\n_v(obj)["tier"] = T3',
            'from builtins import vars as _v\n_v(obj)["tier"] = T3',
        ),
        (
            "gc",
            "import gc\ngc.get_referents(low)",
            "import gc as _g\n_g.get_referents(low)",
            "from gc import get_referents\nget_referents(low)",
        ),
        (
            "ctypes",
            "import ctypes\nctypes.cast(id(low), ctypes.py_object)",
            "import ctypes as _c\n_c.cast(id(low), _c.py_object)",
            "from ctypes import cast\ncast(id(low), py_object)",
        ),
        (
            "object",
            'object.__setattr__(low, "tier", T3)',
            '_o = object\n_o.__setattr__(low, "tier", T3)',
            'from builtins import object as _o\n_o.__setattr__(low, "tier", T3)',
        ),
        (
            "_set_authorized_t3_nonce",
            "_set_authorized_t3_nonce(mine)",
            "_reg = _set_authorized_t3_nonce\n_reg(mine)",
            "from alfred.security.tiers import _set_authorized_t3_nonce as _reg\n_reg(mine)",
        ),
    ]
    for identifier, direct, rebound, aliased in cases:
        for label, source in (
            ("DIRECT", direct),
            ("REBOUND", rebound),
            ("IMPORT-ALIASED", aliased),
        ):
            use_line = source.count("\n") + 1
            flagged = _messages(source + "\n")
            assert any(f":{use_line}: " in message for message in flagged), (
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


def test_the_real_nonce_factory_file_scans_clean() -> None:
    """THE REAL FILE under its REAL path — a fixture resembling it proves nothing.

    R2-I: WITH THE POSITIVE TWIN it was missing. The bare floor passed for two
    reasons it could not tell apart — the exemption working, and the rule being
    absent. The twin renames the exempt function in the REAL source and asserts the
    two in-function references then red, which proves the file is being scanned and
    that the (path, FUNCTION) key is what keeps it clean.

    ``_is_exempt`` is asserted False in the same test so this cannot pass because
    ``nonce_factory.py`` quietly joined ``_APPROVED_PATHS``.
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
    assert _messages(renamed, _NONCE_FACTORY) == [
        f"{_NONCE_FACTORY}:100: {check_tag_t3._PRIVATE_SURFACE_MESSAGE}",
        f"{_NONCE_FACTORY}:108: {check_tag_t3._PRIVATE_SURFACE_MESSAGE}",
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
    """
    assert not check_tag_t3._is_exempt(_QUARANTINE)
    assert check_tag_t3._scan_file(_QUARANTINE) == []


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
    claim = [
        "  # gate is release-blocking — only `security/tiers.py` and",
        "  # `security/" + _Q_PY + "` may call `tag(T3, ...)`, and `cast(",
    ]
    assert _stale_claim_lines(claim) == [2], "the sweep no longer recognises the claim"

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

    mentions = subprocess.run(
        ["git", "grep", "-n", "-E", r"quarantine\.py"],  # noqa: S607
        cwd=_REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    ).stdout.splitlines()
    assert mentions, "git grep returned nothing — the sweep would pass vacuously"

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
