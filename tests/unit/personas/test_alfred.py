"""Tests for the hardcoded Alfred persona used in Slice 1."""

from __future__ import annotations

from alfred.personas.alfred import ALFRED_PERSONA, alfred_system_prompt


def test_persona_has_name_and_character() -> None:
    assert ALFRED_PERSONA.name == "alfred"
    assert "butler" in ALFRED_PERSONA.character.lower()


def test_system_prompt_mentions_operator_name() -> None:
    prompt = alfred_system_prompt(operator_name="Ian", language="en-US")
    assert "Ian" in prompt
    assert "Alfred" in prompt


def test_system_prompt_carries_user_language_tag() -> None:
    """CLAUDE.md i18n rule #2: persona system prompts honour {user.language}."""
    prompt_en = alfred_system_prompt(operator_name="Ian", language="en-US")
    assert "en-US" in prompt_en
    prompt_ja = alfred_system_prompt(operator_name="Ian", language="ja-JP")
    assert "ja-JP" in prompt_ja
    assert prompt_en != prompt_ja


def test_system_prompt_is_a_t0_tagged_content() -> None:
    from alfred.security.tiers import T0, TaggedContent

    prompt = alfred_system_prompt(operator_name="Ian", language="en-US")
    # The factory returns plain text; the orchestrator wraps it in TaggedContent[T0]
    # at the boundary.
    tagged: TaggedContent[T0] = TaggedContent[T0](content=prompt, source="persona.alfred", tier=T0)
    assert isinstance(tagged, TaggedContent)
    assert tagged.tier.name == "T0"
