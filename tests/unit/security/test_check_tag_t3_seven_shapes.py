"""#539 — the seven T3-construction shapes and the tier alias environment.

Loaded via ``spec_from_file_location`` against the REAL script path: a ``tmp_path`` copy
recomputes ``_REPO_ROOT`` from ``__file__`` and silently inverts every exemption, so a
copy-based suite measures the wrong tree while still passing.

IN-PROCESS ON PURPOSE. Its sibling ``test_check_tag_t3_subscript.py`` drives the gate
through ``subprocess``, which records NO coverage without ``COVERAGE_PROCESS_START`` and
binds neither the module nor a message helper — appending these cases there would have
produced ``NameError`` on every one of them and 0% coverage on the rules they test.

WHAT THIS FILE IS FOR, and what the split with the sole-layer suite is: #538's rules close
the classes the RUNTIME cannot refuse (raw state writes, the authorisation surface). These
close the classes the runtime ALREADY refuses — every one of the seven shapes raises today
— so they are defence-in-depth, and their whole justification is that the two layers fire
at different times: one when the line EXECUTES, one when it is WRITTEN. An unexercised
branch in ``src/`` ships unrefused until it runs.

Because the cost side of that trade is ergonomic rather than security, the false-positive
floors here are load-bearing in a way they are not in the sole-layer suite. Every one is
measured against the real 332-file tree, and the ergonomic cost of this whole file's rule
set is ZERO outside the single whole-file-exempt ``security/tiers.py``.
"""

from __future__ import annotations

import ast
import importlib.util
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[3]
_SCRIPT = _REPO_ROOT / "scripts" / "check_tag_t3.py"

_spec = importlib.util.spec_from_file_location("check_tag_t3_seven_shapes", _SCRIPT)
assert _spec is not None and _spec.loader is not None
check_tag_t3 = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = check_tag_t3
_spec.loader.exec_module(check_tag_t3)

assert check_tag_t3._REPO_ROOT == _REPO_ROOT, (
    f"loaded the wrong script: {check_tag_t3._REPO_ROOT} != {_REPO_ROOT}"
)

_PROBE = Path("/nonexistent/probe.py")
# Assembled rather than written out: ruff reads a directive inside a comment regardless of
# the surrounding prose. Same phenomenon the suppression suite tests, one layer up.
_HASH_ONLY = "#"
_ORACLE = (
    _REPO_ROOT / "tests" / "unit" / "security" / "test_t3_construction_requires_the_nonce_path.py"
)


def _messages(source: str, path: Path = _PROBE) -> list[str]:
    """Violation MESSAGE lines only — odd-indexed entries are code snippets.

    Returns the FULL ``"{path}:{lineno}: {message}"`` line, not the bare message. Assert
    with ``== [f"{_PROBE}:1: {MSG}"]`` or ``any(MSG in m for m in ...)``; a bare
    ``MSG in _messages(src)`` is always False, which makes the positive form fail and —
    far worse — makes every ``not in`` form vacuously true.
    """
    return [v for v in check_tag_t3._scan_text(source, path) if not v.startswith("  ")]


def _env(source: str) -> tuple[check_tag_t3.TierAliasEnv, bool]:
    return check_tag_t3._tier_alias_env(ast.parse(source))


# ---------------------------------------------------------------------------
# The alias environment.
# ---------------------------------------------------------------------------


def test_tc_bare_resolves_rebind_and_import_alias() -> None:
    env, overflowed = _env(
        "from alfred.security.tiers import TaggedContent as _Imported\n_Rebound = TaggedContent\n"
    )

    assert env.tc_bare == frozenset({"TaggedContent", "_Imported", "_Rebound"})
    assert not overflowed


def test_tc_bare_reaches_a_fixed_point_against_source_order() -> None:
    """``B = A`` written BEFORE ``A = TaggedContent``. A single pass misses ``B``.

    Source order is the author's to choose, so an order-dependent resolver is one an
    attacker controls.
    """
    env, _ = _env("B = A\nA = TaggedContent\n")

    assert env.tc_bare == frozenset({"TaggedContent", "A", "B"})


def test_the_reverse_order_alias_trips_under_the_t3_rule_not_the_unresolved_one() -> None:
    """THE FIXED-POINT MUTANT KILLER, and it must assert the EXACT rule.

    ``B = A`` before ``A = T3``. A single-pass resolver leaves ``B`` out of the T3 set, so
    the slice falls through to UNRESOLVED and the line STILL TRIPS — under the wrong rule.
    A "does it trip" assertion lets that mutant survive; this one does not.
    """
    messages = _messages("B = A\nA = T3\nTaggedContent[B](x)\n")

    assert any(check_tag_t3._TAGGED_CONTENT_T3_SUBSCRIPT_MESSAGE in m for m in messages)
    assert not any(check_tag_t3._TAGGED_CONTENT_UNRESOLVED_SLICE_MESSAGE in m for m in messages)


def test_a_parameterised_binding_carries_its_verdict_not_a_bucket() -> None:
    """``tc_param`` is a MAP. The two verdicts are opposite under the same binding form."""
    env, _ = _env("Hot = TaggedContent[T3]\nCool = TaggedContent[T2]\n")

    assert env.tc_param["Hot"] is check_tag_t3._SliceVerdict.T3
    assert env.tc_param["Cool"] is check_tag_t3._SliceVerdict.BENIGN


def test_an_unreadable_slice_binding_keeps_its_unresolved_verdict() -> None:
    """THE CRITICAL THE PLAN REVIEW FOUND, and the reason ``tc_param`` is not two sets.

    The first revision classified with ``t3_seeds if verdict is T3 else benign_seeds`` — a
    two-way ternary over a three-valued verdict — which routed every UNRESOLVED into the
    BENIGN bucket. Executed: ``X = TaggedContent["T" + "3"]`` then ``X(content=ATTACKER)``
    scanned CLEAN while the identical inline slice red.
    """
    env, _ = _env('X = TaggedContent["T" + "3"]\n')

    assert env.tc_param["X"] is check_tag_t3._SliceVerdict.UNRESOLVED


def test_a_parameterised_alias_chains_through_the_one_resolver() -> None:
    env, _ = _env("B = A\nA = TaggedContent[T3]\n")

    assert env.tc_param["A"] is check_tag_t3._SliceVerdict.T3
    assert env.tc_param["B"] is check_tag_t3._SliceVerdict.T3


def test_a_parameterised_binding_over_an_aliased_base_resolves() -> None:
    env, _ = _env("Y = TaggedContent\nHot = Y[T3]\n")

    assert env.tc_param["Hot"] is check_tag_t3._SliceVerdict.T3


def test_a_conflicting_rebind_takes_the_stricter_verdict() -> None:
    """A name cannot be walked back DOWN to benign by a second binding."""
    env, _ = _env("P = TaggedContent[T2]\nQ = TaggedContent[T3]\nX = P\nX = Q\n")

    assert env.tc_param["X"] is check_tag_t3._SliceVerdict.T3


def test_a_name_bound_both_bare_and_parameterised_is_ambiguous() -> None:
    """SECURITY REVIEW sec-002, executed: the intersection silenced the R1 rule.

    ``Cool = TaggedContent[T2]`` then ``Cool = TaggedContent`` returned BENIGN, so
    ``Cool(tier=T3)`` — an unparameterised construction — scanned clean.
    """
    source = "Cool = TaggedContent[T2]\nCool = TaggedContent\nCool(tier=T3)\n"
    env, _ = _env(source)

    assert env.tc_param["Cool"] is check_tag_t3._SliceVerdict.UNRESOLVED
    assert _messages(source)


def test_t3_and_benign_tier_are_distinct_sets() -> None:
    """``T3 as Wire`` must trip while ``T2 as Broadcast`` must pass."""
    env, _ = _env(
        "from alfred.security.tiers import T3 as Wire\n"
        "from alfred.security.tiers import T2 as Broadcast\n"
    )

    assert "Wire" in env.t3
    assert "Wire" not in env.benign_tier
    assert "Broadcast" in env.benign_tier
    assert "Broadcast" not in env.t3


@pytest.mark.parametrize(
    ("label", "source"),
    [
        ("pep695", "type TierT = TrustTier\n"),
        ("typevar", 'TierT = TypeVar("TierT", bound=TrustTier)\n'),
    ],
)
def test_a_typevar_bound_to_trust_tier_is_a_benign_slice(label: str, source: str) -> None:
    """BOTH spellings, each with its own fixture.

    The plan review found the first revision's test NAMED for the ``TypeVar(bound=...)``
    arm while its fixture exercised the PEP-695 one, leaving that arm's whole branch
    uncovered under a required 100% gate. Parametrising is what stops the pair drifting
    back into one.
    """
    env, _ = _env(source)

    assert "TierT" in env.benign_tier, label
    assert _messages(f"{source}TaggedContent[TierT](x)\n") == []


def test_a_rebound_trust_tier_cannot_admit_a_t3_slice() -> None:
    """SECURITY REVIEW sec-003. ``TrustTier`` sits on the ADMITTING side.

    A bare literal there is a bypass, not a residual: with ``TrustTier = T3`` in scope,
    ``type TierT = TrustTier`` made ``TaggedContent[TierT](...)`` scan clean. The first
    revision declared "rebinding makes the gate STRICTER", which is false in every
    direction for an admitting set.
    """
    source = "TrustTier = T3\ntype TierT = TrustTier\nTaggedContent[TierT](x)\n"
    env, _ = _env(source)

    assert "TierT" not in env.benign_tier
    assert _messages(source)


@pytest.mark.parametrize(
    ("label", "source"),
    [
        ("assign", "X = TaggedContent[T3]\nX(c=1)\n"),
        ("annassign", "X: TypeAlias = TaggedContent[T3]\nX(c=1)\n"),
        ("pep695", "type X = TaggedContent[T3]\nX(c=1)\n"),
        ("walrus", "(X := TaggedContent[T3])\nX(c=1)\n"),
        ("walrus-inline", "(X := TaggedContent[T3])(c=1)\n"),
        ("walrus-nested", "((X := (Y := TaggedContent[T3])))(c=1)\n"),
    ],
)
def test_every_binding_shape_is_read(label: str, source: str) -> None:
    """SECURITY REVIEW sec-005 — the scan read ``ast.Assign`` only.

    ``walrus-inline`` is the one the alias environment alone cannot answer: the call's
    ``func`` is an ``ast.NamedExpr``, so no identifier appears in callee position at all.
    It was found during acceptance, AFTER the environment was correct, because the earlier
    probe checked the MAP rather than the call site — a reminder that the map being right
    and the rule reading it being right are two different properties.
    """
    assert _messages(source), label


def test_a_benign_walrus_binding_stays_clean() -> None:
    """The twin for the shape above: unwrapping must not make every walrus a finding."""
    assert _messages("(X := TaggedContent[T2])(c=1)\n") == []


def test_an_alias_chain_past_the_budget_overflows_and_is_reported() -> None:
    """FAIL CLOSED AND LOUDLY, through the scanner rather than only in the return value.

    Building the environment and dropping its ``overflowed`` half on the floor is a silent
    fail-OPEN: every tier decision in the file is then made on a set the resolver has
    already said is incomplete.
    """
    depth = check_tag_t3._ALIAS_RESOLUTION_BUDGET + 5
    chain = "".join(f"a{i} = a{i - 1}\n" for i in range(depth, 0, -1)) + "a0 = TaggedContent\n"
    _, overflowed = _env(chain)

    assert overflowed
    assert any(check_tag_t3._ALIAS_BUDGET_MESSAGE in m for m in _messages(chain))


# ---------------------------------------------------------------------------
# `_slice_verdict` — total, default-deny on SHAPE.
# ---------------------------------------------------------------------------

_UNRESOLVED_SHAPES = {
    "binop": 'TaggedContent["T" + "3"](x)',
    "call": 'TaggedContent[globals()["T3"]](x)',
    "subscript": 'TaggedContent[TIERS["T3"]](x)',
    "ifexp": "TaggedContent[T3 if flag else T2](x)",
    "tuple": "TaggedContent[(T3,)](x)",
    "unknown_name": "TaggedContent[Mystery](x)",
    "integer": "TaggedContent[1](x)",
}


@pytest.mark.parametrize("label", sorted(_UNRESOLVED_SHAPES))
def test_every_non_name_slice_shape_is_default_denied(label: str) -> None:
    """The rule this replaces was fail-OPEN on every one of these."""
    messages = _messages(f"{_UNRESOLVED_SHAPES[label]}\n")

    assert any(check_tag_t3._TAGGED_CONTENT_UNRESOLVED_SLICE_MESSAGE in m for m in messages), label


def test_the_t3_slice_reports_the_t3_rule_not_the_unresolved_one() -> None:
    """DISTINCT messages, or a shape test is satisfied by the wrong rule firing."""
    messages = _messages("TaggedContent[T3](x)\n")

    assert any(check_tag_t3._TAGGED_CONTENT_T3_SUBSCRIPT_MESSAGE in m for m in messages)
    assert not any(check_tag_t3._TAGGED_CONTENT_UNRESOLVED_SLICE_MESSAGE in m for m in messages)


@pytest.mark.parametrize("tier", ["T0", "T1", "T2"])
def test_a_benign_tier_slice_is_clean_with_a_positive_twin(tier: str) -> None:
    assert _messages(f"TaggedContent[{tier}](x)\n") == []
    assert _messages("TaggedContent[T3](x)\n"), "positive twin: the T3 form must trip"


def test_a_benign_tier_alias_slice_is_clean_and_its_t3_twin_trips() -> None:
    benign = "from alfred.security.tiers import T2 as Broadcast\nTaggedContent[Broadcast](x)\n"
    hot = "from alfred.security.tiers import T3 as Wire\nTaggedContent[Wire](x)\n"

    assert _messages(benign) == []
    assert any(check_tag_t3._TAGGED_CONTENT_T3_SUBSCRIPT_MESSAGE in m for m in _messages(hot))


def test_a_quoted_generic_resolves_through_the_same_sets_as_the_bare_form() -> None:
    """SECURITY REVIEW sec-004 — the two arms were asymmetric.

    The string arm matched the RAW seed tuple while the name arm was alias-resolved, so
    with ``T2 = T3`` in scope ``TaggedContent[T2](...)`` red and ``TaggedContent["T2"](...)``
    scanned clean. A quoted generic is a forward-referenced NAME.
    """
    assert _messages('TaggedContent["T2"](x)\n') == []
    assert _messages('T2 = T3\nTaggedContent["T2"](x)\n')
    assert any(
        check_tag_t3._TAGGED_CONTENT_T3_SUBSCRIPT_MESSAGE in m
        for m in _messages('TaggedContent["T3"](x)\n')
    )


def test_slice_verdict_is_total_over_every_real_slice_shape() -> None:
    """TOTALITY over shapes the PARSER produces, not over hand-built nodes.

    A field-less ``expr_type()`` construction reads ``.value`` off an ``ast.Constant`` that
    has none and raises ``AttributeError`` on 3.14 — the plan's first totality test could
    not run at all, and it failed on exactly the three node types the function exists to
    read. Parsing real expressions asks the same question without inventing trees the
    parser never builds.

    Totality is load-bearing beyond correctness: this function is called from BOTH sides of
    ``_scan_text``'s ``GateInternalError`` fence, so a raise would surface as exit 2 down
    one path and exit 1 down the other for the same input.
    """
    expressions = [
        "T3",
        "T2",
        "tiers.T3",
        '"T3"',
        '"T2"',
        '"nonsense"',
        "1",
        "None",
        "...",
        '"T" + "3"',
        "globals()['T3']",
        "TIERS['T3']",
        "T3 if f else T2",
        "(T3,)",
        "[T3]",
        "{T3}",
        "{'a': T3}",
        "lambda: T3",
        "await x",
        "-T3",
        "not T3",
        "T3 and T2",
        "x.y.z",
        "f'{T3}'",
        "*T3,",
        "(i for i in x)",
        "[i for i in x]",
        "x[1:2]",
        "yield T3",
    ]
    verdicts = set(check_tag_t3._SliceVerdict)
    for text in expressions:
        node = ast.parse(f"async def _f():\n    _ = {text}\n").body[0].body[0].value
        assert isinstance(node, ast.expr)
        verdict = check_tag_t3._slice_verdict(node, frozenset({"T3"}), frozenset({"T2"}))
        assert verdict in verdicts, text


def test_slice_verdict_has_no_raise_path() -> None:
    """STRUCTURAL twin to the shape sweep above.

    A sweep over expressions can only ever cover the shapes someone thought to list. This
    asserts the property those shapes are evidence FOR: the function cannot raise, so it
    cannot mean two different exit codes depending on which side of the fence called it.
    """
    source = _SCRIPT.read_text(encoding="utf-8")
    function = next(
        node
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.FunctionDef) and node.name == "_slice_verdict"
    )

    assert not [n for n in ast.walk(function) if isinstance(n, ast.Raise)]
    assert isinstance(function.body[-1], ast.Return)


# ---------------------------------------------------------------------------
# R4 — the subscript rule, and annotation immunity.
# ---------------------------------------------------------------------------


def test_a_renamed_import_subscript_trips() -> None:
    source = (
        "from alfred.security.tiers import TaggedContent as _Renamed\n"
        "_Renamed[T3](content='x', source='s', tier=T3, metadata={})\n"
    )

    assert any(check_tag_t3._TAGGED_CONTENT_T3_SUBSCRIPT_MESSAGE in m for m in _messages(source))


def test_a_non_literal_generic_argument_trips() -> None:
    source = "_TIER = T3\nTaggedContent[_TIER](content='x', tier=_TIER)\n"

    assert any(check_tag_t3._TAGGED_CONTENT_T3_SUBSCRIPT_MESSAGE in m for m in _messages(source))


def test_a_parameterised_alias_call_trips_with_no_subscript_at_the_call_site() -> None:
    """``Hot = TaggedContent[T3]`` then ``Hot(...)`` — no ``ast.Subscript`` in ``Call.func``."""
    messages = _messages("Hot = TaggedContent[T3]\nHot(content='x', tier=T3)\n")

    assert any(check_tag_t3._TAGGED_CONTENT_T3_SUBSCRIPT_MESSAGE in m for m in messages)


def test_a_benign_parameterised_alias_call_is_clean() -> None:
    assert _messages("Cool = TaggedContent[T2]\nCool(content='x', tier=T2)\n") == []


def test_annotation_position_is_immune_and_the_call_twin_trips() -> None:
    """22 annotation sites across 5 files depend on this; 13 are outside any exempt file.

    ONE-POSITION WHITELIST — ``Call.func`` is the only position read. Never an ancestor
    blacklist: a blacklist must ENUMERATE annotation-bearing positions and silently widens
    the day the grammar grows one, which ``ast.TypeAlias`` already did.
    """
    annotations = (
        "def f(x: TaggedContent[T3]) -> TaggedContent[T3]: ...\n"
        "y: TaggedContent[T3]\n"
        "class C:\n    z: TaggedContent[T3]\n"
        "def g(a: int = 0, *, b: TaggedContent[T3] | None = None) -> None: ...\n"
    )

    assert _messages(annotations) == []
    assert _messages("y: TaggedContent[T3] = TaggedContent[T3](x)\n"), (
        "positive twin: the RHS is a real construction and must trip even though the "
        "annotation beside it does not"
    )


# ---------------------------------------------------------------------------
# R1 / R2 / R3.
# ---------------------------------------------------------------------------


def test_bare_keyword_construction_trips() -> None:
    source = "TaggedContent(content='untrusted', source='t', tier=T3, metadata={})\n"

    assert any(check_tag_t3._UNPARAMETERISED_CONSTRUCTION_MESSAGE in m for m in _messages(source))


@pytest.mark.parametrize(
    "source",
    ["TaggedContent(content='x', tier=_ALIAS)\n", "TaggedContent(**payload)\n"],
)
def test_unparameterised_construction_trips_regardless_of_the_tier_argument(source: str) -> None:
    """R1 reads NO tier: ``tier=_ALIAS`` and ``**payload`` reach the same write."""
    assert any(check_tag_t3._UNPARAMETERISED_CONSTRUCTION_MESSAGE in m for m in _messages(source))


def test_a_rebound_bare_construction_trips() -> None:
    messages = _messages("_TC = TaggedContent\n_TC(content='x', tier=T3)\n")

    assert any(check_tag_t3._UNPARAMETERISED_CONSTRUCTION_MESSAGE in m for m in messages)


def test_a_parameterised_construction_does_not_report_the_unparameterised_rule() -> None:
    messages = _messages("TaggedContent[T2](content='x', tier=T2)\n")

    assert messages == []


def test_an_annotation_naming_bare_taggedcontent_is_clean() -> None:
    assert _messages("def f(x: TaggedContent) -> TaggedContent: ...\n") == []


_SEAMS = ("model_construct", "model_validate", "model_validate_json")


@pytest.mark.parametrize("seam", _SEAMS)
def test_a_t3_receiver_seam_call_trips(seam: str) -> None:
    assert any(
        check_tag_t3._TAGGED_SEAM_MESSAGE in m
        for m in _messages(f"TaggedContent[T3].{seam}(payload)\n")
    )


@pytest.mark.parametrize("seam", _SEAMS)
def test_a_benign_receiver_seam_call_is_clean(seam: str) -> None:
    """THE NAMED FLOOR, and the entire argument for R2 being slice-discriminating.

    ``test_model_construct_still_works_for_a_lower_tier`` in the nonce-path suite is
    ``TaggedContent[T2].model_construct(...)``. A receiver-scoped but tier-AGNOSTIC rule
    fires on it, failing a floor this repo explicitly named "still works". Discrimination
    costs nothing and saves that floor.
    """
    assert _messages(f"TaggedContent[T2].{seam}(payload)\n") == []


@pytest.mark.parametrize("seam", _SEAMS)
def test_a_foreign_receiver_seam_call_is_clean(seam: str) -> None:
    """34 legitimate seam sites live outside ``tiers.py``; a naked rule reds every one."""
    assert _messages(f"Schema.{seam}(payload)\nnotification.{seam}(payload)\n") == []


def test_an_unparameterised_receiver_seam_call_trips() -> None:
    """Default-deny: a bare ``TaggedContent`` receiver names no tier the gate can read."""
    messages = _messages("TaggedContent.model_construct(p)\n")

    assert any(check_tag_t3._TAGGED_SEAM_MESSAGE in m for m in messages)


def test_an_unresolved_slice_receiver_seam_call_trips() -> None:
    messages = _messages('TaggedContent["T" + "3"].model_validate(p)\n')

    assert any(check_tag_t3._TAGGED_SEAM_MESSAGE in m for m in messages)


def test_an_aliased_t3_receiver_seam_call_trips() -> None:
    messages = _messages("Hot = TaggedContent[T3]\nHot.model_validate(p)\n")

    assert any(check_tag_t3._TAGGED_SEAM_MESSAGE in m for m in messages)


def test_the_seam_partition_covers_basemodel_seam_attrs() -> None:
    """DISJOINT AND EXHAUSTIVE, so a sixth seam cannot belong to neither half.

    Three overlapping vocabularies of the same five names is the #422 shape. Deriving the
    two halves from the parent means adding a seam forces a decision about which rule owns
    it, instead of it silently belonging to nothing.
    """
    assert check_tag_t3._TAGGED_SEAM_ATTRS.isdisjoint(check_tag_t3._COPY_SEAM_ATTRS)
    assert (
        check_tag_t3._TAGGED_SEAM_ATTRS | check_tag_t3._COPY_SEAM_ATTRS
    ) == check_tag_t3._BASEMODEL_SEAM_ATTRS


@pytest.mark.parametrize(
    ("label", "source"),
    [
        ("literal", 'lower.model_copy(update={"tier": T3})\n'),
        ("dict-call", "lower.model_copy(update=dict(tier=T3))\n"),
        ("unpack-literal", 'lower.model_copy(update={**{"tier": T3}})\n'),
        ("folded-key", 'lower.model_copy(update={"ti" + "er": T3})\n'),
        ("positional", 'BaseModel.copy(obj, None, None, {"tier": T3})\n'),
        ("v1-copy", 'lower.copy(update={"tier": T3})\n'),
    ],
)
def test_a_tier_key_reaches_the_rule_through_every_mapping_shape(label: str, source: str) -> None:
    """SECURITY REVIEW sec-006 — ``dict(tier=...)`` and ``**`` both scanned clean."""
    assert any(check_tag_t3._TIER_MUTATING_COPY_MESSAGE in m for m in _messages(source)), label


@pytest.mark.parametrize(
    ("label", "source"),
    [
        ("unpack-opaque", "lower.model_copy(update={**payload})\n"),
        ("dict-unpack-opaque", "lower.model_copy(update=dict(**payload))\n"),
    ],
)
def test_an_unreadable_update_mapping_is_refused(label: str, source: str) -> None:
    """A mapping the rule cannot read is one it must not admit.

    Measured cost of that strictness across both scan roots: ZERO — the two live
    ``model_copy(update=...)`` sites carry literal ``wire_seq`` keys.
    """
    assert any(check_tag_t3._TIER_MUTATING_COPY_MESSAGE in m for m in _messages(source)), label


def test_a_copy_not_touching_the_tier_is_clean_with_a_positive_twin() -> None:
    """The two live sites outside ``tiers.py``, and the one-token twin that must trip."""
    assert _messages("notification.model_copy(update={'wire_seq': wire_seq})\n") == []
    assert _messages("original.model_copy()\n") == []
    assert _messages("original.model_copy(update={'source': 'elsewhere'})\n") == []
    assert any(
        check_tag_t3._TIER_MUTATING_COPY_MESSAGE in m
        for m in _messages("notification.model_copy(update={'tier': wire_seq})\n")
    )


def test_a_tier_dict_not_passed_to_a_copy_seam_is_clean() -> None:
    """R3 is scoped to the copy seams — a bare dict with a tier key is ordinary data."""
    assert _messages("payload = {'tier': T3}\nlog.info('x', extra={'tier': T3})\n") == []


# ---------------------------------------------------------------------------
# The independent oracle, and the real-tree floor.
# ---------------------------------------------------------------------------

# LITERALS, not a glob. `test_model_construct_still_works_for_a_lower_tier` does NOT end
# with `_still_works`, so a suffix pattern silently drops the floor that matters most —
# the one that is the whole argument for R2 being slice-discriminating.
_MUST_TRIP = frozenset(
    {
        "test_bare_keyword_construction_is_refused",
        "test_model_construct_is_refused",
        "test_model_validate_is_refused",
        "test_model_validate_json_is_refused",
        "test_model_copy_update_to_t3_is_refused",
        "test_renamed_import_subscript_is_refused",
        "test_non_literal_generic_argument_is_refused",
    }
)
_MUST_BE_CLEAN = frozenset(
    {
        "test_the_authorised_path_still_works",
        "test_a_lower_tier_is_unaffected",
        "test_model_construct_still_works_for_a_lower_tier",
        "test_model_copy_still_works_when_not_touching_the_tier",
    }
)


def _violations_by_function(text: str, path: Path) -> dict[str, int]:
    """Violation count per enclosing test function in ``text``.

    Parses the location from the RIGHT. ``"{path}:{lineno}: {message}"`` split from the
    left breaks on the required ``windows-latest`` leg, where an absolute path carries a
    drive letter and its own colon.

    Raises on a message line it cannot parse rather than skipping it: a silent ``continue``
    would let a format change quietly zero every count and turn both oracle tests green on
    a gate that found nothing.
    """
    tree = ast.parse(text)
    spans = {
        node.name: range(node.lineno, (node.end_lineno or node.lineno) + 1)
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    counts = dict.fromkeys(spans, 0)
    for line in check_tag_t3._scan_text(text, path):
        if line.startswith("  "):
            continue
        location, _, _ = line.rpartition(": ")
        lineno = int(location.rsplit(":", 1)[1])
        for name, span in spans.items():
            if lineno in span:
                counts[name] += 1
    return counts


def test_the_independent_oracle_trips_on_every_refused_shape() -> None:
    """THE MANDATED INDEPENDENT ORACLE — real source the gate was not written against.

    That file states all seven shapes as executable Python and scored ZERO violations
    before this work. Feeding its own text back through the scanner under a synthetic
    non-exempt path is the strongest single measure that the rules reach real code rather
    than only the fixtures above.
    """
    text = _ORACLE.read_text(encoding="utf-8")
    counts = _violations_by_function(text, _REPO_ROOT / "src" / "alfred" / "_synthetic_probe.py")

    assert set(counts) >= _MUST_TRIP, "the oracle file's function set moved"
    assert {name for name in _MUST_TRIP if counts[name] == 0} == set()


def test_the_independent_oracle_leaves_every_named_floor_clean() -> None:
    """The other half. Refusing EVERYTHING would satisfy the test above."""
    text = _ORACLE.read_text(encoding="utf-8")
    counts = _violations_by_function(text, _REPO_ROOT / "src" / "alfred" / "_synthetic_probe.py")

    assert set(counts) >= _MUST_BE_CLEAN, "the oracle file's floor set moved"
    assert {name: counts[name] for name in _MUST_BE_CLEAN if counts[name]} == {}


def test_the_real_tree_scans_clean_with_an_assert_ran_census() -> None:
    """ASSERT-RAN in the SAME invocation. "The real tree is clean" is otherwise a tautology.

    Every rule in this file has ZERO live sites, so a no-op detector satisfies the clean
    half trivially. The census is what proves the scan reached the tree at all.
    """
    paths = check_tag_t3._collect_paths([])

    assert len(paths) >= check_tag_t3._MIN_SCANNED_FILES
    assert [v for p in paths for v in check_tag_t3._scan_file(p)] == []


def test_the_benign_tier_seeds_match_the_real_module() -> None:
    """DRIFT GUARD for the hard-coded seeds.

    The gate cannot import ``alfred.security.tiers`` — it runs under bare ``python3`` from
    the Makefile with no venv — so the tier names are hard-coded on
    ``_TIERS_PRIVATE_SURFACE``'s precedent. This is the guard that keeps the copy honest,
    and it reads the real module rather than restating the constant.
    """
    source = (_REPO_ROOT / "src" / "alfred" / "security" / "tiers.py").read_text(encoding="utf-8")
    module_level: set[str] = set()
    for node in ast.parse(source).body:
        # THE TIERS ARE CLASSES, not assignments — `class T0(TrustTier)`. A guard reading
        # only `Assign`/`AnnAssign` found none of them and failed while the constant it
        # guards was perfectly correct, which is the wrong failure direction for a drift
        # guard: it cries wolf about the gate when the fault is in the guard's own model
        # of the module.
        if isinstance(node, ast.ClassDef):
            module_level.add(node.name)
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            module_level.update(t.id for t in targets if isinstance(t, ast.Name))

    for seed in check_tag_t3._BENIGN_TIER_SEEDS:
        assert seed in module_level, f"{seed} is no longer a module-level name in tiers.py"
    assert "T3" not in check_tag_t3._BENIGN_TIER_SEEDS, "T3 must never be a benign seed"
    assert check_tag_t3._TRUST_TIER_NAME in source


def test_the_seed_loop_variable_is_named_seed() -> None:
    """A COUPLING MADE VISIBLE rather than left to be discovered.

    The meta-guard's identifier derivation recognises a runtime-seeded ``_alias_names``
    call by the loop variable's NAME. Renaming it in the gate hard-reds
    ``test_every_keyed_identifier_is_alias_resolved`` with a message about seed shapes,
    which reads as a gate bug rather than as a rename. Pinning it here means the rename is
    caught where the coupling actually is.
    """
    source = _SCRIPT.read_text(encoding="utf-8")
    function = next(
        node
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.FunctionDef) and node.name == "_tier_alias_env"
    )
    # Only the loops that actually SEED `_alias_names` with their own target are coupled to
    # the derivation. `_tier_alias_env` has others — a tuple-target walk over parameterised
    # bindings, and a `(seed, verdict)` unpack — and holding those to the same rule asserted
    # a property nothing depends on.
    seeding: list[ast.For] = []
    for loop in (n for n in ast.walk(function) if isinstance(n, ast.For)):
        bound = {t.id for t in ast.walk(loop.target) if isinstance(t, ast.Name)}
        for call in (n for n in ast.walk(loop) if isinstance(n, ast.Call)):
            if (
                isinstance(call.func, ast.Name)
                and call.func.id == "_alias_names"
                and len(call.args) == 2
                and isinstance(call.args[1], ast.Name)
                and call.args[1].id in bound
            ):
                seeding.append(loop)
                break

    assert seeding, "_tier_alias_env no longer fans _alias_names out over a loop variable"
    assert {
        call.args[1].id
        for loop in seeding
        for call in ast.walk(loop)
        if isinstance(call, ast.Call)
        and isinstance(call.func, ast.Name)
        and call.func.id == "_alias_names"
        and len(call.args) == 2
        and isinstance(call.args[1], ast.Name)
    } == {"seed"}


# ---------------------------------------------------------------------------
# Branch coverage. `scripts/check_tag_t3.py` is under a REQUIRED 100% line+branch gate
# with NO pragmas allowed, so every arm below is reached by a real input rather than
# excused. Each of these was an uncovered arc measured by the gate itself.
# ---------------------------------------------------------------------------


def test_stricter_keeps_the_incumbent_when_the_candidate_is_weaker() -> None:
    """The arm that stops a second binding walking a name back DOWN to benign.

    `_stricter` is the whole mechanism by which a conflicting rebind fails closed, so the
    "candidate loses" branch is the one that actually carries the property — the other two
    arms only handle the empty and the winning case.
    """
    verdict = check_tag_t3._SliceVerdict

    assert check_tag_t3._stricter(verdict.BENIGN, verdict.T3) is verdict.T3
    assert check_tag_t3._stricter(verdict.BENIGN, verdict.UNRESOLVED) is verdict.UNRESOLVED
    assert check_tag_t3._stricter(verdict.UNRESOLVED, verdict.T3) is verdict.T3
    assert check_tag_t3._stricter(verdict.T3, verdict.BENIGN) is verdict.T3
    assert check_tag_t3._stricter(verdict.T3, None) is verdict.T3


def test_a_chained_typevar_assignment_binds_every_target() -> None:
    """`A = B = TypeVar(..., bound=TrustTier)` — the multi-target loop arc.

    A single-target fixture never exercises the loop's second pass, so a rule that bound
    only `node.targets[0]` would pass every other test in this file while silently leaving
    the second name unresolved — and an unresolved name in the BENIGN set reds a legitimate
    generic helper rather than admitting a bypass, which is the quiet kind of wrong.
    """
    env, _ = _env('A = B = TypeVar("T", bound=TrustTier)\n')

    assert "A" in env.benign_tier
    assert "B" in env.benign_tier
    assert _messages('A = B = TypeVar("T", bound=TrustTier)\nTaggedContent[B](x)\n') == []


def test_a_readable_unpack_without_a_tier_key_continues_the_scan() -> None:
    """`{**{"a": 1}, "tier": T3}` — the `**` arm must not short-circuit the rest.

    The unpacked operand is readable and mentions no tier, so the scan has to carry on to
    the sibling keys. Returning early there would make the rule blind to every key written
    after any `**`.
    """
    assert not any(
        check_tag_t3._TIER_MUTATING_COPY_MESSAGE in m
        for m in _messages('low.model_copy(update={**{"a": 1}, "b": 2})\n')
    )
    assert any(
        check_tag_t3._TIER_MUTATING_COPY_MESSAGE in m
        for m in _messages('low.model_copy(update={**{"a": 1}, "tier": T3})\n')
    )


def test_a_positional_mapping_inside_a_dict_call_is_read() -> None:
    """`dict({"tier": T3})` — the constructor's POSITIONAL mapping argument."""
    assert any(
        check_tag_t3._TIER_MUTATING_COPY_MESSAGE in m
        for m in _messages('low.model_copy(update=dict({"tier": T3}))\n')
    )
    assert not any(
        check_tag_t3._TIER_MUTATING_COPY_MESSAGE in m
        for m in _messages('low.model_copy(update=dict({"wire_seq": w}))\n')
    )


def test_a_foreign_parameterised_receiver_seam_call_is_clean() -> None:
    """`Other[T3].model_validate(...)` — a subscripted receiver that is not TaggedContent.

    The seam rule is receiver-SCOPED, and this is the arm that scopes it. Without it every
    generic class in the tree with a `model_validate` would red.
    """
    assert _messages("Other[T3].model_validate(payload)\n") == []
    assert any(
        check_tag_t3._TAGGED_SEAM_MESSAGE in m
        for m in _messages("TaggedContent[T3].model_validate(payload)\n")
    ), "positive twin: the same shape with the real receiver must trip"


def test_a_non_name_typevar_target_is_skipped_without_stopping_the_scan() -> None:
    """`obj.attr = TypeVar(..., bound=TrustTier)` — a target that binds no local name.

    The loop must SKIP it and carry on rather than crash or stop: an attribute target binds
    nothing this gate can resolve, but a sibling target in the same statement still does.
    """
    env, _ = _env('obj.attr = Ok = TypeVar("T", bound=TrustTier)\n')

    assert "Ok" in env.benign_tier
    assert _messages('obj.attr = Ok = TypeVar("T", bound=TrustTier)\nTaggedContent[Ok](x)\n') == []


def test_a_blank_logical_line_opens_no_span() -> None:
    """A file whose only statement follows blank lines and comments.

    `NEWLINE` with no span open is reached by any module that emits a logical-line
    terminator before any code token has opened one — the shape a trailing blank line or a
    comment-only prologue produces. It must not append a span, or a suppressor would be
    attributed to a line range that contains no statement.
    """
    source = f"\n\n{_HASH_ONLY} a plain comment\n\n{_HASH_ONLY} another\nx = 1\n"

    assert check_tag_t3._suppressed_spans(source) == []
    assert _messages(source) == []


# ---------------------------------------------------------------------------
# PR REVIEW — the walrus wrapper, the unreadable base, and the opaque mapping.
# ---------------------------------------------------------------------------

_WALRUS_BLINDED = {
    "R1 bare construction": (
        "(X := TaggedContent)(content=A, tier=T3)\n",
        "TaggedContent(content=A, tier=T3)\n",
    ),
    "tag()": ("(f := tag)(T3, A)\n", "tag(T3, A)\n"),
    "cast()": ("(f := cast)(TaggedContent[T2], x)\n", "cast(TaggedContent[T2], x)\n"),
    "BaseModel seam": (
        "(f := BaseModel.model_copy)(low, update={'tier': T3})\n",
        "BaseModel.model_copy(low, update={'tier': T3})\n",
    ),
    "R3 copy seam": (
        "(f := low.model_copy)(update={'tier': T3})\n",
        "low.model_copy(update={'tier': T3})\n",
    ),
    "R2 tagged seam": (
        "(f := TaggedContent[T3].model_construct)(p)\n",
        "TaggedContent[T3].model_construct(p)\n",
    ),
    "#538 setattr": (
        '(f := object.__setattr__)(low, "tier", T3)\n',
        'object.__setattr__(low, "tier", T3)\n',
    ),
    "#538 vars": ('(f := vars)(obj)["tier"] = T3\n', 'vars(obj)["tier"] = T3\n'),
}


@pytest.mark.parametrize("label", sorted(_WALRUS_BLINDED))
def test_a_walrus_wrapper_does_not_blind_any_rule(label: str) -> None:
    """PR REVIEW, err-001 (Critical) — SEVEN of eight rules were blind to this.

    #539's first revision introduced `_unwrap_walrus` and applied it at TWO of the eight
    positions that read a callable, so the subscript rule saw through the wrapper and
    seven others did not — including two #538 SOLE-LAYER rules, whose docstrings state
    that no runtime guard for them can exist.

    Most spellings were already blind BEFORE #539 (`_call_name` has always returned None
    for a non-Name/Attribute callee), so this is a pre-existing hole rather than a
    regression. That is precisely why fixing two positions and leaving six was the wrong
    answer: it is the enumerate-the-spelling mistake this epic exists to stop.

    The TWIN is the positive control — it proves the rule is live at all, so a fixture
    that matched nothing could not pass this as "both clean".
    """
    walrus, twin = _WALRUS_BLINDED[label]

    assert _messages(twin), f"{label}: the rule is not live at all — the twin is vacuous"
    assert _messages(walrus), f"{label}: the walrus-wrapped spelling scanned CLEAN"


def test_no_rule_reads_call_func_directly() -> None:
    """THE META-GUARD that stops the walrus hole reopening one rule at a time.

    Derived from the gate's own AST rather than written as a list, for the reason the
    identifier meta-guard in the sole-layer suite gives: an enumeration closes what it
    enumerates. A future rule that writes the obvious `node.func` reds here on the day it
    lands instead of quietly reintroducing a bypass seven of eight rules already had.

    `_callee` is the one function allowed to touch it — that is what it is for. `_scan_text`
    is allowed because its `call_func_ids` set deliberately keys on the RAW node identity:
    a walrus-wrapped `__setattr__` carries no attribute node in `Call.func` position, so
    the one-position whitelist reports it under the ALIASED rule, which is correct for it.
    """
    source = _SCRIPT.read_text(encoding="utf-8")
    # `_is_self_init_re_entry` is allowed, and the reason is the direction it keys in.
    # It reads the RECEIVER call's callable to recognise a zero-argument `super()`, which
    # is an ADMISSIBILITY test — so `(s := super)()` failing to match makes the gate
    # STRICTER, not weaker. Unwrapping there would admit a shape that is currently
    # refused, and the existing comment records that a rebound `super` is dead at runtime
    # anyway (`RuntimeError: super(): __class__ cell not found`).
    allowed = {"_callee", "_scan_text", "_is_self_init_re_entry"}
    offenders: list[str] = []
    for function in ast.walk(ast.parse(source)):
        if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if function.name in allowed:
            continue
        for node in ast.walk(function):
            if isinstance(node, ast.Attribute) and node.attr == "func":
                offenders.append(f"{function.name}:{node.lineno}")

    assert not offenders, (
        f"these functions read `.func` directly instead of through `_callee`: "
        f"{offenders}. A walrus wrapper `(f := target)(...)` puts an ast.NamedExpr in "
        f"Call.func, so every such read scans CLEAN. Use _callee(node)."
    )


@pytest.mark.parametrize(
    ("label", "source"),
    [
        ("call base", "_get_tc()[T3](content=A)\n"),
        ("subscript base", "_TCS[0][T3](content=A)\n"),
    ],
)
def test_an_unreadable_subscript_base_with_a_t3_slice_is_refused(label: str, source: str) -> None:
    """PR REVIEW, err-002 — the two-valued guess, reintroduced on the BASE axis.

    Returning the not-a-construction sentinel for a base the gate cannot name is the same
    fail-open `_SliceVerdict` exists to remove from the slice axis.
    """
    assert _messages(source), label


def test_an_unreadable_base_with_a_benign_slice_stays_clean() -> None:
    """The twin that keeps the base rule from costing anything."""
    assert _messages("_get_tc()[T2](content=A)\n") == []
    assert _messages("whatever()[T1](x)\n") == []


def test_a_readable_but_unknown_base_stays_clean_and_is_a_stated_residual() -> None:
    """The BOUNDARY of the rule above, pinned so the next reader does not mistake it.

    `a.b().c[T3](...)` has a base `_arg_name` CAN read — it collapses the chain to the
    identifier `c` — which simply is not a `TaggedContent` alias. That is the same class
    as `Other[T3](...)` and stays clean by design: the unreadable-base rule closes bases
    that name NO identifier, not bases that name one this file never bound.

    Widening it to "any base not in `tc_bare`" would flag every generic construction in
    the tree. The residual it leaves is the per-file alias environment's, already stated
    in the module docstring: a `TaggedContent` re-exported through another module and
    reached as `mod.Alias[T3](...)` is not resolved.
    """
    assert _messages("a.b().c[T3](content=A)\n") == []
    assert _messages("Other[T3](content=A)\n") == []


@pytest.mark.parametrize(
    ("label", "source"),
    [
        ("opaque call", "low.model_copy(update={**build_update()})\n"),
        ("opaque method", "low.model_copy(update={**self.build()})\n"),
        ("opaque name", "low.model_copy(update={**payload})\n"),
    ],
)
def test_an_unreadable_unpack_operand_is_refused_whatever_its_shape(
    label: str, source: str
) -> None:
    """CODERABBIT (major) — an opaque CALL was admitted while an opaque NAME was refused.

    The `**` arm exempted every `ast.Call` rather than only a `dict(...)` one, so
    `{**build_update()}` scanned clean. An opaque call is exactly as unreadable as an
    opaque name; readability is now decided by `_is_readable_mapping`, not by node class.
    """
    assert any(check_tag_t3._TIER_MUTATING_COPY_MESSAGE in m for m in _messages(source)), label


def test_a_readable_unpack_operand_is_still_admitted() -> None:
    """The twin. Default-deny on unreadable must not become deny-everything."""
    assert _messages("low.model_copy(update={**dict(a=1)})\n") == []
    assert _messages("low.model_copy(update={**{'wire_seq': w}})\n") == []


def test_a_pathological_mapping_nest_is_bounded_not_a_gate_fault() -> None:
    """PR REVIEW, err-005 — the one uncapped recursive predicate inside the fence.

    An unbounded recursion here would let one pathological file raise from INSIDE the
    `GateInternalError` fence, and `main` then discards every violation collected so far
    and exits 2 — hiding a real laundering finding in an EARLIER file behind "the gate is
    broken". Bounded on `_fold_str`'s precedent, and past the bound the answer is REFUSE.
    """
    depth = check_tag_t3._FOLD_MAX_DEPTH + 5
    nested = "{**" * depth + "{'a': 1}" + "}" * depth

    assert check_tag_t3._mapping_mentions_tier(
        ast.parse(nested, mode="eval").body, frozenset({"dict"})
    )
    assert _messages(f"low.model_copy(update={nested})\n")


def test_the_strictness_map_covers_every_slice_verdict() -> None:
    """PR REVIEW py-002 — `_stricter` reads a dict keyed on enum members.

    A verdict added to `_SliceVerdict` without a strictness entry makes `_stricter` raise
    `KeyError` — from INSIDE `_scan_text`'s detector fence on the `_detect` path, which
    `main` reports as exit 2 with every violation collected so far discarded. Deriving the
    expectation from the enum means the map cannot go stale silently.
    """
    assert set(check_tag_t3._SLICE_VERDICT_STRICTNESS) == set(check_tag_t3._SliceVerdict)
    assert len(set(check_tag_t3._SLICE_VERDICT_STRICTNESS.values())) == len(
        check_tag_t3._SliceVerdict
    ), "two verdicts share a rank, so `_stricter` cannot order them"


def test_a_trust_tier_chain_past_the_budget_is_reported_by_the_scanner() -> None:
    """PR REVIEW err-003 — the ONE `_alias_names` call site of nine that swallowed its flag.

    A SURVIVING MUTANT is what put this test here: dropping the flag again passed the whole
    suite, because every other overflow test drives a different seed. The direction is
    fail-CLOSED (an unresolved `TrustTier` chain SHRINKS the admitting set, so the gate gets
    stricter) — which is precisely why nothing else noticed. But the gate's contract is to
    fail closed AND LOUDLY, and a swallowed flag means an overflowing file is decided on an
    admittedly incomplete set with no diagnosis at all.
    """
    depth = check_tag_t3._ALIAS_RESOLUTION_BUDGET + 5
    chain = "".join(f"_n{i} = _n{i - 1}\n" for i in range(depth, 0, -1)) + "_n0 = TrustTier\n"
    _, overflowed = _env(chain)

    assert overflowed, "the TrustTier chain's overflow flag was dropped"
    assert any(check_tag_t3._ALIAS_BUDGET_MESSAGE in m for m in _messages(chain)), (
        "the overflow was not reported by the scanner — fail-closed but silent"
    )


def test_a_dict_chain_past_the_budget_is_reported_by_the_scanner() -> None:
    """The same guard for the `dict` seed #539 added, so it cannot repeat err-003."""
    depth = check_tag_t3._ALIAS_RESOLUTION_BUDGET + 5
    chain = "".join(f"_d{i} = _d{i - 1}\n" for i in range(depth, 0, -1)) + "_d0 = dict\n"
    _, overflowed = _env(chain)

    assert overflowed
    assert any(check_tag_t3._ALIAS_BUDGET_MESSAGE in m for m in _messages(chain))


@pytest.mark.parametrize(
    ("label", "source"),
    [
        ("annassign", "X: TypeAlias = TaggedContent\nX(content=A, tier=T3)\n"),
        ("pep695", "type X = TaggedContent\nX(content=A, tier=T3)\n"),
        ("walrus", "(X := TaggedContent)\nX(content=A, tier=T3)\n"),
        ("assign", "X = TaggedContent\nX(content=A, tier=T3)\n"),
    ],
)
def test_the_shared_resolver_reads_every_binding_shape(label: str, source: str) -> None:
    """PR REVIEW sec-001 (Critical) — `_alias_names` read `ast.Assign` alone.

    A name outside `tc_bare` silences the unparameterised, seam AND subscript rules at
    once, so three of the four binding shapes above scanned CLEAN while the plain
    assignment red. It is the same enumeration `_parameterised_bindings` was written to
    avoid one layer up — fixed there and not here, which is what left the bare-class axis
    open. The fix is in the SHARED resolver, so #538's rules gain the closure too.
    """
    assert _messages(source), label


def test_a_seam_receiver_the_gate_cannot_resolve_is_refused() -> None:
    """PR REVIEW sec-005 — the seam rule ADMITTED an unreadable receiver.

    Its own docstring says "an unparameterised receiver is refused"; a receiver it could
    not name at all was admitted, which is the two-valued guess `_SliceVerdict` exists to
    remove, reintroduced on the receiver axis.
    """
    assert any(
        check_tag_t3._TAGGED_SEAM_MESSAGE in m for m in _messages("_get()[T3].model_validate(p)\n")
    )
    assert _messages("_get()[T2].model_validate(p)\n") == [], (
        "the benign twin red — the unreadable-receiver arm must be slice-scoped"
    )


def test_a_suppressor_on_an_aliased_construction_is_not_invisible() -> None:
    """PR REVIEW sec-004 — the suppression pass keyed on the raw substring.

    Every other rule resolves the name; this one is a text pass over comment spans, so it
    has to be HANDED the resolved set. Keying on the literal meant an alias walked past it.

    The other half of sec-004 — that ruff honours a `noqa` following prose, making the
    `re.match` anchor too narrow — was DECLINED on measurement: `x = undefined  # we do
    not noqa here` is still reported by `ruff check --select F821`, so the anchor matches
    ruff's real behaviour and the prose floor below is correct.
    """
    assert _messages("from a import TaggedContent as TC\nx = TC[T2](y)  # type: ig" + "nore\n")
    assert _messages("Cool = TaggedContent[T2]\nx = Cool(y)  # noq" + "a: E501\n")
    assert _messages("x = plain(y)  # type: ig" + "nore\n") == []
