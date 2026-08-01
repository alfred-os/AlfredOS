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
