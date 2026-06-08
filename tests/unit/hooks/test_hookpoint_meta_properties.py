"""Hypothesis property tests for :class:`HookpointMeta` value semantics.

The metadata record sits at the heart of the per-hookpoint contract: it
is the value the registry compares (``stored == new``) to decide
whether a re-declaration is an idempotent re-import or a genuine drift
that must raise :class:`HookError` (#119, CLAUDE.md hard rule #7). The
example-based tests in :mod:`tests.unit.hooks.test_registration_enforcement`
pin individual representative shapes; this module turns those handful
of examples into universal properties.

The five properties below match the five legs of the value-semantics
contract Issue #127 calls out:

1. **Equality reflexivity + symmetry** — ``a == a`` for every instance;
   ``(a == b) == (b == a)`` for every pair. The dataclass default
   ``__eq__`` gives this for free, but a future refactor that
   overrides ``__eq__`` (e.g. to special-case tier-set comparison) is
   exactly the kind of well-meaning change that can silently break it.
2. **Hash agrees with equality** — ``a == b`` implies
   ``hash(a) == hash(b)``. Frozen + slots gives this by default; the
   ``__hash__`` is content-derived because :class:`frozenset` hashes
   by content. A subclass that flips ``unsafe_hash=False`` (or that
   makes any field a mutable type by mistake) breaks this and the
   registry's idempotency check silently mis-matches.
3. **Field-wise equality** — ``a == b`` iff every field matches
   (``name``, ``subscribable_tiers``, ``refusable_tiers``,
   ``fail_closed``). The example tests pin individual drift axes; this
   property covers every cross-product of drifted vs equal field
   combinations.
4. **Registry idempotent-on-equal** — declaring the same
   :class:`HookpointMeta` twice is a no-op. This is the property that
   makes a re-import of a publisher module safe (pytest test isolation,
   Slice-3 reload-by-module). A drift in the equality semantics breaks
   the no-op-on-equal contract and re-imports start raising.
5. **Registry conflict-on-drift** — declaring twice with ANY single
   field drifted raises :class:`HookError`. This is the
   defense-in-depth pair to property 4 — the registry must refuse the
   second call iff the new metadata is not equal to the stored one.

Why hypothesis here and not more examples in
``test_registration_enforcement.py``:

* The equality + hash contracts are universal — they hold for every
  instance and every pair. An example test pins one shape; hypothesis
  pins the property across the space.
* The example tests already cover the load-bearing English-text
  representative cases. Adding more example cases would dilute that
  file's "this is the canonical example" intent without expanding
  coverage of the property.
* The dataclass-default ``__eq__`` / ``__hash__`` semantics are exactly
  the kind of "looks right at the example level, breaks at the corner"
  contract hypothesis is good at stress-testing.

The strategies build :class:`HookpointMeta` instances from the
known-tier vocabulary (``"system"`` / ``"operator"`` /
``"user-plugin"``) because the registry validates against
``_TIER_RANK`` at declaration time. Generating a string that is not in
``_TIER_RANK`` would surface
:class:`alfred.hooks.errors.HookError` at declaration — useful for the
example tests in ``test_registration_enforcement.py`` (which pin that
loud refusal), but not the property being tested here. The ``name``
field is generated as a non-empty printable string because the
registry treats it as an opaque identifier; the empty-string and
unicode-edge-cases live elsewhere.

``settings(max_examples=...)`` is tuned per-property: registry
round-trips boot a fresh :class:`HookRegistry` per example so the
hot-path budget caps at 50 examples each; pure-value-semantics
properties run 200 examples because they only construct dataclass
instances.
"""

from __future__ import annotations

from typing import Final

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from alfred.hooks.errors import HookError
from alfred.hooks.registry import HookpointMeta, HookRegistry
from alfred.security.tiers import T0, T1, T2, T3
from tests.helpers.gates import make_permissive_fixture_gate

# ──────────────────────────────────────────────────────────────────────
# Strategies
# ──────────────────────────────────────────────────────────────────────

# The known-tier vocabulary the registry validates against. Sourcing
# the strings explicitly (rather than importing ``_TIER_RANK`` and
# iterating) pins the test against the vocabulary at the time the
# property was written: a future addition to ``_TIER_RANK`` does NOT
# silently widen what this property covers. If a new tier lands, the
# property author should add it here deliberately.
_KNOWN_TIERS: Final[tuple[str, ...]] = ("system", "operator", "user-plugin")


# Hookpoint names: short, identifier-like strings. The registry treats
# the name as an opaque key — uniqueness within the strategy is not
# required (hypothesis will happily generate ``"x"`` twice across
# examples, which is exactly the registry-collision shape property 4
# and 5 exercise).
_name_strategy = st.text(
    alphabet=st.characters(
        min_codepoint=ord("a"),
        max_codepoint=ord("z"),
        # No category filter beyond the range — the alphabet is a
        # narrow ASCII slice so every generated name is a valid
        # identifier-ish string the registry stores without
        # normalisation.
    ),
    min_size=1,
    max_size=32,
)


# Tier sets: a frozenset over the known vocabulary. ``min_size=0``
# because the registry accepts an empty allow-list (it just means "no
# subscriber tier is permitted"); the test still needs to exercise
# that shape.
_tier_set_strategy = st.frozensets(
    st.sampled_from(_KNOWN_TIERS),
    min_size=0,
    max_size=len(_KNOWN_TIERS),
)


# Full :class:`HookpointMeta` factory. Builder closure keeps the
# strategy declaration site readable; the four argument strategies
# compose without any hypothesis-specific glue.
_meta_strategy = st.builds(
    HookpointMeta,
    name=_name_strategy,
    subscribable_tiers=_tier_set_strategy,
    refusable_tiers=_tier_set_strategy,
    fail_closed=st.booleans(),
    # PR-S4-3: carrier_tier is sampled across the full {T0, T1, T2, T3}
    # range so the equality / drift / idempotency properties actually
    # exercise the new field (CR closure — a fixed T3 left carrier_tier
    # drift untested).
    carrier_tier=st.sampled_from([T0, T1, T2, T3]),
)


# ──────────────────────────────────────────────────────────────────────
# 1. Equality is reflexive + symmetric
# ──────────────────────────────────────────────────────────────────────


@given(meta=_meta_strategy)
@settings(max_examples=200, deadline=None)
def test_hookpoint_meta_equality_is_reflexive(meta: HookpointMeta) -> None:
    """For every :class:`HookpointMeta` instance ``m``, ``m == m``.

    Reflexivity is the floor of equality — a value not equal to itself
    breaks dict-keys, set-membership, the registry's
    ``stored == new`` idempotency check, and basically every Python
    invariant that leans on ``__eq__``. The dataclass default gives
    this for free; the property is here to catch the refactor that
    breaks it.
    """
    assert meta == meta


@given(a=_meta_strategy, b=_meta_strategy)
@settings(max_examples=200, deadline=None)
def test_hookpoint_meta_equality_is_symmetric(a: HookpointMeta, b: HookpointMeta) -> None:
    """For every pair of :class:`HookpointMeta` instances ``a``, ``b``,
    ``(a == b) == (b == a)``.

    Symmetry is the property that makes the registry's collision check
    direction-agnostic — the second declaration compares ``new ==
    stored``, but a subscriber-side cache that compares ``stored ==
    new`` MUST get the same answer. A non-symmetric ``__eq__`` would
    make the two sites silently disagree on what "drift" means.
    """
    assert (a == b) == (b == a)


# ──────────────────────────────────────────────────────────────────────
# 2. Hash agrees with equality
# ──────────────────────────────────────────────────────────────────────


@given(a=_meta_strategy, b=_meta_strategy)
@settings(max_examples=200, deadline=None)
def test_hookpoint_meta_hash_agrees_with_equality(
    a: HookpointMeta,
    b: HookpointMeta,
) -> None:
    """``a == b`` implies ``hash(a) == hash(b)``.

    The Python data model requires this and dicts / sets silently
    misbehave when it is violated. Frozen + slots gives it for free
    today, but the property protects against a refactor that adds a
    mutable field (e.g. a plain ``set`` of tiers) or an
    ``__eq__`` override that ignores a field the default ``__hash__``
    still folds in.
    """
    if a == b:
        assert hash(a) == hash(b)


# ──────────────────────────────────────────────────────────────────────
# 3. Field-wise equality
# ──────────────────────────────────────────────────────────────────────


@given(a=_meta_strategy, b=_meta_strategy)
@settings(max_examples=200, deadline=None)
def test_hookpoint_meta_equality_is_field_wise(
    a: HookpointMeta,
    b: HookpointMeta,
) -> None:
    """``a == b`` iff every field matches.

    The six fields are :attr:`HookpointMeta.name`,
    :attr:`HookpointMeta.subscribable_tiers`,
    :attr:`HookpointMeta.refusable_tiers`,
    :attr:`HookpointMeta.fail_closed`, and the PR-S4-3 additions
    :attr:`HookpointMeta.carrier_tier` +
    :attr:`HookpointMeta.allow_error_substitution`. The example tests in
    ``test_registration_enforcement.py`` pin drift on each field
    individually; this property covers every cross-product (drift on
    multiple fields, equal on others) hypothesis generates.

    The forward implication catches an ``__eq__`` that misses a field
    (e.g. ignores ``fail_closed`` or the new ``carrier_tier``); the
    reverse catches an ``__eq__`` that adds a field the dataclass does
    not carry (e.g. object identity creeping in). The strategy varies
    ``carrier_tier`` across {T0, T1, T2, T3} so a regression that drops
    it from ``__eq__`` is caught here (CR closure).
    """
    fields_equal = (
        a.name == b.name
        and a.subscribable_tiers == b.subscribable_tiers
        and a.refusable_tiers == b.refusable_tiers
        and a.fail_closed == b.fail_closed
        and a.carrier_tier == b.carrier_tier
        and a.allow_error_substitution == b.allow_error_substitution
    )
    assert (a == b) == fields_equal


# ──────────────────────────────────────────────────────────────────────
# 4. Registry idempotent-on-equal
# ──────────────────────────────────────────────────────────────────────


@given(meta=_meta_strategy)
@settings(max_examples=50, deadline=None)
def test_register_hookpoint_is_idempotent_on_equal_meta(meta: HookpointMeta) -> None:
    """Two ``register_hookpoint`` calls with identical args succeed.

    The realistic shape is a publisher module re-imported under pytest
    test isolation or the Slice-3 reload-by-module flow. The re-import
    re-runs the module-init declaration; the registry MUST treat the
    second call as a no-op so publishers do not have to wrap each
    declaration in a "have I declared this yet?" check.

    The property feeds the same generated metadata into
    ``register_hookpoint`` twice and asserts both calls succeed AND
    the stored metadata still equals the input. A fresh registry per
    example so the test does not leak state across hypothesis cases.
    """
    registry = HookRegistry(
        gate=make_permissive_fixture_gate(allow_system=True),
        strict_declarations=True,
    )
    registry.register_hookpoint(
        name=meta.name,
        subscribable_tiers=meta.subscribable_tiers,
        refusable_tiers=meta.refusable_tiers,
        fail_closed=meta.fail_closed,
        carrier_tier=meta.carrier_tier,
    )
    # Second call with identical args — must not raise.
    registry.register_hookpoint(
        name=meta.name,
        subscribable_tiers=meta.subscribable_tiers,
        refusable_tiers=meta.refusable_tiers,
        fail_closed=meta.fail_closed,
        carrier_tier=meta.carrier_tier,
    )
    assert registry.hookpoint_meta(meta.name) == meta


# ──────────────────────────────────────────────────────────────────────
# 5. Registry conflict-on-drift
# ──────────────────────────────────────────────────────────────────────


@given(a=_meta_strategy, b=_meta_strategy)
@settings(max_examples=50, deadline=None)
def test_register_hookpoint_raises_on_drift(
    a: HookpointMeta,
    b: HookpointMeta,
) -> None:
    """If ``a != b`` (excluding the name — collision requires same
    name), a second ``register_hookpoint`` with ``b``'s fields after
    declaring ``a`` raises :class:`HookError`.

    The registry stores per-hookpoint metadata keyed on ``name``, so
    "drift" only triggers when both declarations target the same
    name. The strategy generates an independent ``b``; we force the
    name to match ``a`` and then check whether the *other* fields
    drift. When they do — and only then — the second call must raise
    with the "already declared with different metadata" attribution.

    This is the conflict-on-drift pair to property 4's
    idempotent-on-equal: together they pin the equality semantics the
    registry's idempotency check leans on (CLAUDE.md hard rule #7 —
    loud failure, no silent acceptance of "last import wins").
    """
    # The drift check is per-name. Force same name; the rest of ``b``
    # is hypothesis-generated and may or may not drift from ``a``.
    other = HookpointMeta(
        name=a.name,
        subscribable_tiers=b.subscribable_tiers,
        refusable_tiers=b.refusable_tiers,
        fail_closed=b.fail_closed,
        carrier_tier=b.carrier_tier,
    )
    registry = HookRegistry(
        gate=make_permissive_fixture_gate(allow_system=True),
        strict_declarations=True,
    )
    registry.register_hookpoint(
        name=a.name,
        subscribable_tiers=a.subscribable_tiers,
        refusable_tiers=a.refusable_tiers,
        fail_closed=a.fail_closed,
        carrier_tier=a.carrier_tier,
    )
    if a == other:
        # No drift: idempotent path. Already covered by property 4 —
        # this branch just keeps the property symmetric to the
        # drift-or-not case so hypothesis is not penalised for
        # generating an accidentally-equal pair.
        registry.register_hookpoint(
            name=other.name,
            subscribable_tiers=other.subscribable_tiers,
            refusable_tiers=other.refusable_tiers,
            fail_closed=other.fail_closed,
            carrier_tier=other.carrier_tier,
        )
        assert registry.hookpoint_meta(a.name) == a
        return

    # Drift: must raise with the operator-attribution message.
    with pytest.raises(HookError, match="already declared with different metadata"):
        registry.register_hookpoint(
            name=other.name,
            subscribable_tiers=other.subscribable_tiers,
            refusable_tiers=other.refusable_tiers,
            fail_closed=other.fail_closed,
            carrier_tier=other.carrier_tier,
        )
