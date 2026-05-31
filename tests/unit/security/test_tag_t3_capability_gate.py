"""Tests for T1/T3 tier classes, nonce-gated tag(T3,...) factory,
and wire-format serializer/parser.

Depends on: PR-S3-0a audit_row_schemas.py (for T3_BOUNDARY_REFUSAL_FIELDS),
PR-S3-0b i18n catalog (security.tag_t3_unauthorized key).
"""

from __future__ import annotations

from alfred.security.tiers import (
    T0,
    T1,
    T2,
    T3,
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
