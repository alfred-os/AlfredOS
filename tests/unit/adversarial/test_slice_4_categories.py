"""Tests for the Slice-4 adversarial-corpus schema extensions.

The 5 new prefixes (``sbx``, ``csb``, ``crf``, ``osf``, ``cib``) plus the
matching ``Category`` literals, ``IngestionPath`` literals, and
``ExpectedOutcome`` literals form a closed-contract surface that every
Slice-4 corpus YAML asserts against. Without these tests a typo, a
forgotten mapping entry, or a divergent ID-pattern silently broadens the
admit-set.
"""

from __future__ import annotations

import typing
from pathlib import Path

import pytest

from tests.adversarial.payload_schema import (
    _ID_PATTERN,
    _PREFIX_TO_CATEGORY,
    AdversarialPayload,
    Category,
    ExpectedOutcome,
    IngestionPath,
)

SLICE_4_PREFIXES: tuple[str, ...] = ("sbx", "csb", "crf", "osf", "cib")
SLICE_4_CATEGORIES: tuple[str, ...] = (
    "sandbox_escape",
    "config_reload_bypass",
    "carrier_substitution_tamper",
    "operator_session_forgery",
    "comms_identity_boundary",
)


# ---------------------------------------------------------------------------
# Prefix / category symmetry
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("prefix", SLICE_4_PREFIXES)
def test_slice_4_prefix_in_dispatch_table(prefix: str) -> None:
    """Every Slice-4 prefix is registered in ``_PREFIX_TO_CATEGORY``."""
    assert prefix in _PREFIX_TO_CATEGORY, (
        f"Slice-4 prefix {prefix!r} missing from _PREFIX_TO_CATEGORY"
    )


@pytest.mark.parametrize(
    ("prefix", "category"),
    list(zip(SLICE_4_PREFIXES, SLICE_4_CATEGORIES, strict=True)),
)
def test_slice_4_prefix_category_round_trip(prefix: str, category: str) -> None:
    """Each prefix resolves to its declared category."""
    assert _PREFIX_TO_CATEGORY[prefix] == category


@pytest.mark.parametrize("category", SLICE_4_CATEGORIES)
def test_slice_4_category_in_literal(category: str) -> None:
    """Every Slice-4 category appears in the ``Category`` Literal."""
    assert category in typing.get_args(Category)


@pytest.mark.parametrize("prefix", SLICE_4_PREFIXES)
def test_slice_4_prefix_in_id_pattern(prefix: str) -> None:
    """The compiled regex round-trips each Slice-4 prefix."""
    assert _ID_PATTERN.match(f"{prefix}-2026-001"), (
        f"_ID_PATTERN fails to match Slice-4 prefix {prefix!r}"
    )


def test_slice_4_categories_and_prefixes_same_count() -> None:
    """Exactly 5 new prefixes and 5 new categories — drift fails here."""
    s4_prefixes_in_table = [p for p in _PREFIX_TO_CATEGORY if p in SLICE_4_PREFIXES]
    assert len(s4_prefixes_in_table) == 5
    assert len([c for c in typing.get_args(Category) if c in SLICE_4_CATEGORIES]) == 5


# ---------------------------------------------------------------------------
# IngestionPath / ExpectedOutcome additions
# ---------------------------------------------------------------------------


SLICE_4_INGESTION_PATHS: tuple[str, ...] = (
    "sandbox_policy_load",
    "operator_session_file",
    "mtime_poll",
    "inbound_notification_handler",
    "proposal_dispatch_failure",
    "comms_inbound_message",
    "stdio_fd3_key_delivery",
)

SLICE_4_EXPECTED_OUTCOMES: tuple[str, ...] = (
    "policy_swap_aborted_on_audit_failure",
    "recursion_refused",
)


@pytest.mark.parametrize("path", SLICE_4_INGESTION_PATHS)
def test_slice_4_ingestion_path_in_literal(path: str) -> None:
    """Each new IngestionPath value is in the Literal."""
    assert path in typing.get_args(IngestionPath)


@pytest.mark.parametrize("outcome", SLICE_4_EXPECTED_OUTCOMES)
def test_slice_4_expected_outcome_in_literal(outcome: str) -> None:
    """Each new ExpectedOutcome value is in the Literal."""
    assert outcome in typing.get_args(ExpectedOutcome)


# ---------------------------------------------------------------------------
# Negative path — prefix/category mismatch refused
# ---------------------------------------------------------------------------


def test_prefix_category_mismatch_refused() -> None:
    """A payload that pairs a Slice-4 prefix with the WRONG category is
    refused by the cross-field validator (pre-existing schema invariant;
    this test pins it for the new prefixes)."""
    with pytest.raises(ValueError, match="prefix"):
        AdversarialPayload(
            id="sbx-2026-001",
            category="comms_identity_boundary",  # wrong — should be sandbox_escape
            threat="(test) prefix/category mismatch detection",
            ingestion_path="sandbox_policy_load",
            payload="<demo>",
            expected_outcome="audit_row_emitted",
            provenance="tests/unit/adversarial/test_slice_4_categories.py",
            references=("PR-S4-0a",),
        )


# ---------------------------------------------------------------------------
# README presence (the corpus-health test also covers this; pin it here too
# so a fresh implementer of e.g. PR-S4-7 doesn't accidentally delete a README)
# ---------------------------------------------------------------------------


CORPUS_ROOT = Path(__file__).parent.parent.parent / "adversarial"


@pytest.mark.parametrize("category", SLICE_4_CATEGORIES)
def test_slice_4_corpus_dir_has_readme(category: str) -> None:
    """Every Slice-4 category dir has a README.md placeholder."""
    readme = CORPUS_ROOT / category / "README.md"
    assert readme.is_file(), f"missing: {readme}"
    body = readme.read_text()
    # Cheap provenance — README must name the prefix.
    prefix = next(p for p, c in _PREFIX_TO_CATEGORY.items() if c == category)
    assert f"`{prefix}-`" in body, f"{readme} does not document its prefix {prefix!r}"
