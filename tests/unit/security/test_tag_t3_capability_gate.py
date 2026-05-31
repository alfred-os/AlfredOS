"""Tests for T1/T3 tier classes, nonce-gated tag(T3,...) factory,
and wire-format serializer/parser.

Depends on: PR-S3-0a audit_row_schemas.py (for T3_BOUNDARY_REFUSAL_FIELDS),
PR-S3-0b i18n catalog (security.tag_t3_unauthorized key).
"""

from __future__ import annotations

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
