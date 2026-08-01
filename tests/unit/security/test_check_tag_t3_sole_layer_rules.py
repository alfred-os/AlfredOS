"""Unit tests for the #538 sole-layer rules in ``scripts/check_tag_t3.py``.

Loaded via ``spec_from_file_location`` against the REAL script path: a ``tmp_path``
copy would recompute ``_REPO_ROOT`` from ``__file__`` and silently invert every
exemption, so a copy-based test measures the wrong tree while still passing.
"""

from __future__ import annotations

import ast
import importlib.util
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

    * ``vars``, ``gc`` and ``ctypes`` go through :func:`_alias_names`;
    * ``object`` is closed by RECEIVER-BLINDNESS instead. The ``__setattr__`` rules
      never ask who the receiver is, so no identifier is left to rebind. That is a
      STRONGER closure than resolution, not a missing one, and the row proves it
      behaviourally rather than trusting the claim.
    """
    # (identifier, direct spelling, rebound spelling, import-aliased spelling)
    # Task 3 adds the BaseModel row.
    cases = [
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
    ]
    for identifier, direct, rebound, aliased in cases:
        assert _messages(direct + "\n"), (
            f"{identifier}: the DIRECT spelling was not flagged — this probe never "
            f"reached the rule, so the two below prove nothing"
        )
        assert _messages(rebound + "\n"), f"{identifier}: REBOUND spelling admitted"
        assert _messages(aliased + "\n"), f"{identifier}: IMPORT-ALIASED spelling admitted"


def test_record_appends_a_message_and_a_snippet_and_tolerates_a_missing_line() -> None:
    """``_record``'s bounds guard, exercised directly rather than through a ternary.

    R2-K: written as a ternary, ``coverage.py`` does not branch on it, so the guard
    would be invisible to this file's REQUIRED 100% branch gate — exempting by
    construction exactly what the no-pragma rule forbids exempting. Written as an
    ``if``/``else`` it is visible, and this is what covers the else arm.

    No ``_scan_text`` INPUT is known to reach it (``str.splitlines`` splits on strictly
    more separators than the tokenizer, so the line list is never shorter than the
    parser's line numbering). It stays because nine rules share this helper and a
    violation must never become an ``IndexError`` that re-files a real finding as an
    unscannable file.
    """
    violations: list[str] = []
    check_tag_t3._record(violations, ["first", "second  "], _PROBE, 2, "msg")
    assert violations == [f"{_PROBE}:2: msg", "  second"]
    check_tag_t3._record(violations, [], _PROBE, 1, "other")
    assert violations[2:] == [f"{_PROBE}:1: other", "  "]
