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


class TestTagHelper:
    def test_tags_t0_system_content(self) -> None:
        c = tag(T0, content="persona prompt", source="persona.alfred")
        assert isinstance(c, TaggedContent)
        assert c.content == "persona prompt"

    def test_tags_t2_user_content_with_metadata(self) -> None:
        c = tag(T2, content="hi alfred", source="tui.input", line=3)
        assert c.metadata["line"] == 3
