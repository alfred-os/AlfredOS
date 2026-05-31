"""Tests for T1/T3 tier classes, nonce-gated tag(T3,...) factory,
and wire-format serializer/parser.

Depends on: PR-S3-0a audit_row_schemas.py (for T3_BOUNDARY_REFUSAL_FIELDS),
PR-S3-0b i18n catalog (security.tag_t3_unauthorized key).
"""

from __future__ import annotations

import typing

import pytest

from alfred.security.tiers import (
    T0,
    T1,
    T2,
    T3,
    AnyTaggedContent,
    CapabilityGateNonce,
    TaggedContent,
    TrustTier,
    _APPROVED_TIERS,
    tag,
    tag_t3_with_nonce,
)


def test_t1_class_name() -> None:
    assert T1.name == "T1"
    assert issubclass(T1, TrustTier)


def test_t3_class_name() -> None:
    assert T3.name == "T3"
    assert issubclass(T3, TrustTier)


def test_approved_tiers_contains_all_four() -> None:
    assert _APPROVED_TIERS == frozenset({T0, T1, T2, T3})


def test_any_tagged_content_protocol_accepts_t0() -> None:
    """TaggedContent[T0] satisfies AnyTaggedContent structurally."""

    def _observer(c: AnyTaggedContent) -> str:
        return c.tier.name

    tagged = TaggedContent[T0](content="sys", source="test", tier=T0)
    assert _observer(tagged) == "T0"


def test_any_tagged_content_protocol_accepts_t2() -> None:
    tagged = TaggedContent[T2](content="hello", source="test", tier=T2)
    # AnyTaggedContent is a Protocol — structural typing, no cast needed
    result: AnyTaggedContent = tagged
    assert result.tier.name == "T2"


def test_any_tagged_content_has_no_content_mutation() -> None:
    """AnyTaggedContent is read-only: no setattr."""
    tagged = TaggedContent[T2](content="hello", source="test", tier=T2)
    result: AnyTaggedContent = tagged
    with pytest.raises((AttributeError, TypeError, ValueError)):
        result.content = "mutated"  # type: ignore[misc]


def test_tag_t1_returns_tagged_content_t1() -> None:
    """tag(T1, ...) routes through the shared body and returns a T1 envelope."""
    tc = tag(T1, "operator input", source="tui")
    assert tc.tier is T1
    assert tc.content == "operator input"


def test_tag_t1_type_roundtrip() -> None:
    """Wire-format round trip via the T1 overload preserves the tier name."""
    tc = tag(T1, "x", source="tui")
    dumped = tc.model_dump()
    assert dumped["tier"] == "T1"


def test_tag_t1_overload_is_registered() -> None:
    """A static @overload signature for tag(type[T1], ...) is registered.

    ``typing.get_overloads`` returns every @overload-decorated stub for
    a function. Spec §3.1 pins the typed overload as part of the public
    surface — without it, callers of tag(T1, ...) lose the
    TaggedContent[T1] return type and observers downstream lose static
    provenance.
    """
    overloads = typing.get_overloads(tag)
    overload_tier_params: list[type[TrustTier]] = []
    for ovl in overloads:
        hints = typing.get_type_hints(ovl)
        tier_hint = hints.get("tier")
        # ``tier`` is annotated as ``type[T_X]`` — the inner arg is the tier.
        if tier_hint is None:
            continue
        args = typing.get_args(tier_hint)
        if args:
            overload_tier_params.append(args[0])
    assert T1 in overload_tier_params, (
        f"tag() overloads must include a type[T1] variant; saw {overload_tier_params}"
    )


# ---------------------------------------------------------------------------
# tag(T3, ...) capability-gated factory — spec §3.2
# ---------------------------------------------------------------------------


def test_tag_t3_without_nonce_raises() -> None:
    """tag_t3_with_nonce with caller_token=None refuses construction.

    The error message contains the i18n key ``security.tag_t3_unauthorized``
    (the t() helper returns the key itself when the catalog entry is the
    untranslated source — see locale/en/LC_MESSAGES/alfred.po). Spec §3.2.
    """
    with pytest.raises(ValueError, match="security.tag_t3_unauthorized"):
        tag_t3_with_nonce(
            "fetched html",
            source="web.fetch",
            caller_token=None,
        )


def test_tag_t3_with_wrong_nonce_raises() -> None:
    """A nonce that is a DIFFERENT OBJECT is rejected by the identity check.

    Two ``CapabilityGateNonce()`` instances pass an ``==`` test (they have
    no attributes) but fail the ``is`` check the gate uses. Spec §3.2.
    """
    nonce_a = CapabilityGateNonce()
    nonce_b = CapabilityGateNonce()  # different object
    with pytest.raises(ValueError, match="security.tag_t3_unauthorized"):
        tag_t3_with_nonce(
            "x",
            source="test",
            caller_token=nonce_b,
            _authorized_nonce=nonce_a,
        )


def test_tag_t3_with_correct_nonce_succeeds() -> None:
    """The holder of the live nonce reference can tag T3 content. Spec §3.2."""
    nonce = CapabilityGateNonce()
    tc = tag_t3_with_nonce(
        "fetched html",
        source="web.fetch",
        caller_token=nonce,
        _authorized_nonce=nonce,
    )
    assert tc.tier is T3
    assert tc.content == "fetched html"


def test_tag_t3_imported_nonce_is_same_object() -> None:
    """Importing a module-level nonce yields the SAME object (CPython
    reference semantics) — this is the expected DI pattern.

    This documents why import-based forgery fails: importing a module-level
    nonce gives you the live reference, so two authorised modules sharing
    the same nonce holder pass the ``is`` check. An *unauthorised* module
    that constructs its own ``CapabilityGateNonce`` gets a different object
    and fails. Spec §3.2 threat model.
    """
    nonce = CapabilityGateNonce()
    # Simulate an authorised module holding the same reference.
    authorized_module_ref = nonce  # same object in same process
    assert authorized_module_ref is nonce  # passes `is` check
    # Simulate an unauthorised module constructing its own nonce.
    attacker_nonce = CapabilityGateNonce()
    assert attacker_nonce is not nonce  # fails `is` check


def test_tag_via_overload_t3_is_always_refused() -> None:
    """Direct callers using ``tag(T3, ...)`` (without the nonce) are refused.

    The shared ``tag()`` body routes T3 through ``tag_t3_with_nonce`` with
    ``caller_token=None``, which always raises. Only authorised call sites
    that invoke ``tag_t3_with_nonce`` directly (with their injected nonce)
    can tag T3 content. Spec §3.2.
    """
    with pytest.raises(ValueError, match="security.tag_t3_unauthorized"):
        tag(T3, "fetched html", source="web.fetch")
