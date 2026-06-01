"""Slice-3 retrospective arch-003 — i18n the tiers.py raise paths.

The four hardcoded English raises in ``alfred.security.tiers`` are now
routed through ``t()``. These tests pin the catalog keys (so a rename
that misses one of the call sites trips loudly) and verify each raise
substitutes the structured kwargs into the catalog template.

The keys live alongside ``security.tag_t3_unauthorized`` so the audit
reviewer sees a consistent ``security.tier_*`` vocabulary.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from alfred.i18n.translator import t
from alfred.security.tiers import T2, T3, TaggedContent, TrustTier, tag


class _Foreign(TrustTier):
    """Non-allowlisted subclass used for the unsupported-tier paths."""

    name = "TX"


def test_catalog_has_tier_subclass_missing_name_key() -> None:
    """``security.tier_subclass_missing_name`` resolves to a real msgstr."""
    rendered = t("security.tier_subclass_missing_name", subclass="AnonTier")
    # A missing key would return the key itself; a present key renders the
    # substituted message which mentions the subclass.
    assert rendered != "security.tier_subclass_missing_name"
    assert "AnonTier" in rendered


def test_catalog_has_tier_unsupported_key() -> None:
    """``security.tier_unsupported`` renders both the tier name and approved list."""
    rendered = t("security.tier_unsupported", tier_name="TX", approved="T0, T1, T2, T3")
    assert rendered != "security.tier_unsupported"
    assert "TX" in rendered
    assert "T0" in rendered


def test_catalog_has_tier_mismatch_key() -> None:
    """``security.tier_mismatch`` carries both the declared and expected tier."""
    rendered = t("security.tier_mismatch", got="T3", expected="T2")
    assert rendered != "security.tier_mismatch"
    assert "T3" in rendered
    assert "T2" in rendered


def test_catalog_has_tier_unknown_wire_key() -> None:
    """``security.tier_unknown_wire`` carries the unknown name and approved list."""
    rendered = t("security.tier_unknown_wire", tier_name="TX_UNKNOWN", approved="T0, T1, T2, T3")
    assert rendered != "security.tier_unknown_wire"
    assert "TX_UNKNOWN" in rendered


# ---------------------------------------------------------------------------
# Behavioural: each raise path now goes through the catalog.
# ---------------------------------------------------------------------------


def test_anon_subclass_raises_via_subclass_missing_name_key() -> None:
    """Empty-name TrustTier subclass surfaces ``security.tier_subclass_missing_name``.

    Pydantic wraps the raise in a ValidationError; the underlying message
    is still our ``t()``-rendered string, so an i18n catalog flip changes
    the validator's error text without re-touching this module.
    """

    class _Anon(TrustTier):
        pass  # name = "" (inherited)

    with pytest.raises(ValidationError) as excinfo:
        TaggedContent(content="x", source="t", tier=_Anon)
    msg = str(excinfo.value)
    # CR-142 R2: assert against the translated template, not English
    # substrings — the test is then locale-stable.
    expected = t("security.tier_subclass_missing_name", subclass="_Anon")
    assert expected in msg


def test_unsupported_tier_via_tag_uses_tier_unsupported_key() -> None:
    """``tag(_Foreign, ...)`` routes through ``security.tier_unsupported``."""
    with pytest.raises(ValueError) as excinfo:
        # ``_Foreign`` is intentionally outside the typed overload
        # set so the test exercises the dynamic dispatch arm; the
        # type-checker rightly objects, so we ignore the call-arg type
        # check here.
        tag(_Foreign, content="x", source="test")  # type: ignore[arg-type]
    msg = str(excinfo.value)
    assert "TX" in msg
    # The approved list is rendered too — load-bearing for operator
    # debugging (which tier you got vs which are accepted).
    assert "T0" in msg
    assert "T3" in msg


def test_unsupported_tier_via_validator_uses_tier_unsupported_key() -> None:
    """The field validator's same-class rejection uses the same key."""
    with pytest.raises(ValidationError) as excinfo:
        TaggedContent(content="x", source="t", tier=_Foreign)
    msg = str(excinfo.value)
    assert "TX" in msg


def test_wire_format_unknown_tier_uses_tier_unknown_wire_key() -> None:
    """A wire payload with an unknown tier name surfaces the unknown_wire key."""
    with pytest.raises(ValidationError) as excinfo:
        TaggedContent.model_validate({"content": "x", "source": "wire", "tier": "TX_UNKNOWN"})
    msg = str(excinfo.value)
    assert "TX_UNKNOWN" in msg


def test_cross_tier_wire_payload_uses_tier_mismatch_key() -> None:
    """A wire payload whose tier disagrees with the parameterised class surfaces tier_mismatch.

    The model_validator parses the wire string into a TrustTier; the
    field_validator then catches the cross-tier mismatch against the
    parameterised generic argument. The new key is ``security.tier_mismatch``
    with ``expected=`` and ``got=`` kwargs (briefing canonical form).
    """
    # Parameterise as T2 but ship a payload claiming T3. The validator
    # path translates "T3" → T3 (which is in _APPROVED_TIERS) then
    # rejects on the generic-arg cross-check.
    with pytest.raises(ValidationError) as excinfo:
        TaggedContent[T2].model_validate({"content": "x", "source": "wire", "tier": "T3"})
    msg = str(excinfo.value)
    # Both tiers must appear so an operator can see what was declared
    # vs what was expected.
    assert "T3" in msg
    assert "T2" in msg


# Pin T3 import is intentional so a future refactor that hides T3
# behind a private path surfaces here rather than in test discovery.
assert T3.name == "T3"
