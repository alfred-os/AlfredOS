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
    TaggedContent,
    TrustTier,
    _APPROVED_TIERS,
    tag,
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
