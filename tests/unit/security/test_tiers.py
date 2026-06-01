"""Trust-tier tests for Slice 1: T0 and T2 only."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from alfred.security.tiers import T0, T2, TaggedContent, TrustTier, tag


class TestTierMarkers:
    def test_t0_and_t2_are_distinct_trust_tier_subclasses(self) -> None:
        assert issubclass(T0, TrustTier)
        assert issubclass(T2, TrustTier)
        assert not issubclass(T0, T2)
        assert not issubclass(T2, T0)


class TestTaggedContent:
    def test_holds_content_source_tier_metadata(self) -> None:
        c = TaggedContent[T2](content="hi", source="tui.input", tier=T2, metadata={"line": 1})
        assert c.content == "hi"
        assert c.source == "tui.input"
        assert c.tier is T2
        assert c.tier.name == "T2"
        assert c.metadata == {"line": 1}

    def test_is_frozen(self) -> None:
        c = TaggedContent[T2](content="hi", source="tui.input", tier=T2)
        with pytest.raises(ValidationError):
            c.content = "tampered"  # type: ignore[misc]

    def test_extra_fields_rejected(self) -> None:
        with pytest.raises(ValidationError):
            TaggedContent[T2](content="x", source="s", tier=T2, evil="leak")  # type: ignore[call-arg]


class TestTaggedContentTierValidator:
    """Pydantic + `arbitrary_types_allowed=True` accepts any class object for
    `tier` at runtime. The field_validator is the runtime gate that backs the
    static type parameter — without it, a caller bypassing mypy could smuggle
    in `tier=str` and short-circuit the trust-tier invariant the dual-LLM split
    relies on. These tests pin the gate."""

    def test_rejects_non_trust_tier_class(self) -> None:
        # The most important case: `str` is a class, but not a TrustTier
        # subclass. Without the validator, Pydantic would happily store it.
        with pytest.raises(ValidationError):
            TaggedContent(content="x", source="t", tier=str)  # type: ignore[type-var]

    def test_rejects_unrelated_class(self) -> None:
        class NotATier:
            name = "T0"  # spoofed name attribute is not enough

        with pytest.raises(ValidationError):
            TaggedContent(content="x", source="t", tier=NotATier)  # type: ignore[type-var]

    def test_rejects_non_class_value(self) -> None:
        # A bare instance, not a class — must fail before the issubclass check.
        with pytest.raises(ValidationError):
            TaggedContent(content="x", source="t", tier=T2())  # type: ignore[arg-type]

    def test_rejects_trust_tier_subclass_with_empty_name(self) -> None:
        # A subclass that forgets to set `name` would still type-check but
        # produces "" in the audit log — meaningless. Reject at construction.
        class AnonTier(TrustTier):
            pass  # inherits name = ""

        with pytest.raises(ValidationError):
            TaggedContent(content="x", source="t", tier=AnonTier)

    def test_accepts_approved_tier(self) -> None:
        # Sanity check the happy path: T2 (an approved tier in
        # ``_APPROVED_TIERS``) passes the validator.
        c = TaggedContent(content="x", source="t", tier=T2)
        assert c.tier is T2

    def test_rejects_named_subclass_outside_slice1_allowlist(self) -> None:
        """A TrustTier subclass with a non-empty name is no longer enough.

        CR (#89) tightened the validator to enforce ``_APPROVED_TIERS``
        (slice-1: only T0 and T2). The previous behaviour accepted any
        properly-named subclass — that drifted from PRD §7.1's closed
        T0..T3 tier model.
        """

        class ImpostorTier(TrustTier):
            name = "T9"

        with pytest.raises(ValidationError):
            TaggedContent(content="x", source="t", tier=ImpostorTier)


class TestTagHelper:
    def test_tags_t0_system_content(self) -> None:
        c = tag(T0, content="persona prompt", source="persona.alfred")
        assert isinstance(c, TaggedContent)
        assert c.content == "persona prompt"

    def test_tags_t2_user_content_with_metadata(self) -> None:
        c = tag(T2, content="hi alfred", source="tui.input", line=3)
        assert c.metadata["line"] == 3

    def test_rejects_trust_tier_outside_slice1_allowlist(self) -> None:
        """Runtime guard: `tag()` rejects any TrustTier subclass not in the
        slice-1 allowlist (`_APPROVED_TIERS = frozenset({T0, T2})`).

        The Pydantic `_validate_tier` already rejects empty-name and
        non-class values; this complementary guard at the `tag()` boundary
        closes the "named subclass that looks like a TrustTier but isn't on
        the active slice's list" hole — exactly the case PRD §7.1 expects
        the ingestion boundary to enforce.
        """

        class ImpostorTier(TrustTier):
            name = "T9"

        # CR-142 round-3 test-001: assert on locale-stable signal
        # (the offending tier token + the approved-tier names) rather
        # than English wording. The error is rendered via
        # t("security.tier_unsupported", tier_name=..., approved=...);
        # both substitutions land in the output regardless of locale,
        # which makes the assertion stable when a future i18n pass
        # ships a non-English msgstr.
        with pytest.raises(ValueError) as excinfo:
            tag(ImpostorTier, content="x", source="test")
        msg = str(excinfo.value)
        assert "T9" in msg, f"expected impostor tier token in {msg!r}"
        # The approved tiers list is sorted by name and inserted as a
        # comma-separated string; each canonical name must appear so
        # the operator can see WHICH tiers ARE accepted vs the rejected
        # impostor name.
        for approved_name in ("T0", "T1", "T2", "T3"):
            assert approved_name in msg, (
                f"expected approved tier {approved_name!r} in error message {msg!r}"
            )
