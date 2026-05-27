"""Tests for the hardcoded Alfred persona used in Slice 1.

PR-B Phase 3 replaces the per-call interpolated ``alfred_system_prompt`` with
``render_persona_prompt`` — a cacheable-prefix + ``<user_context>`` XML tail
design. The cacheable prefix references element names (``<operator_name>``,
``<addressed_user_name>``, ``<addressed_user_language>``) rather than
interpolated values so the prefix is byte-identical across users and
languages → prompt-cache friendly.
"""

from __future__ import annotations

from alfred.personas.alfred import ALFRED_PERSONA, Persona, render_persona_prompt


def test_persona_has_name_and_character() -> None:
    assert ALFRED_PERSONA.name == "alfred"
    assert "butler" in ALFRED_PERSONA.character.lower()


def _split_at_user_context(prompt: str) -> tuple[str, str]:
    """Return (prefix, tail) split at the ``<user_context>`` opening tag."""
    idx = prompt.index("<user_context>")
    return prompt[:idx], prompt[idx:]


# ---------------------------------------------------------------------------
# Task 8 — failing tests for render_persona_prompt
# ---------------------------------------------------------------------------


def test_render_persona_prompt_contains_persona_name() -> None:
    prompt = render_persona_prompt(
        operator_name="Ian",
        requesting_user_name="Ian",
        language="en-US",
    )
    assert "Alfred" in prompt


def test_render_persona_prompt_contains_persona_character() -> None:
    prompt = render_persona_prompt(
        operator_name="Ian",
        requesting_user_name="Ian",
        language="en-US",
    )
    assert ALFRED_PERSONA.character in prompt


def test_cacheable_prefix_uses_element_name_references() -> None:
    """The cacheable prefix must reference element names, not interpolated values."""
    prompt = render_persona_prompt(
        operator_name="Ian",
        requesting_user_name="Alice",
        language="en-US",
    )
    prefix, _tail = _split_at_user_context(prompt)
    assert "<operator_name>" in prefix
    assert "<addressed_user_name>" in prefix
    assert "<addressed_user_language>" in prefix


def test_cacheable_prefix_carries_bcp47_imperative() -> None:
    """Spec i18n-002: BCP-47 imperative must appear in the cacheable prefix."""
    prompt = render_persona_prompt(
        operator_name="Ian",
        requesting_user_name="Ian",
        language="en-US",
    )
    prefix, _tail = _split_at_user_context(prompt)
    assert "BCP-47" in prefix
    assert "<addressed_user_language>" in prefix
    assert "Respond in the BCP-47 language tag identified by <addressed_user_language>" in prefix


def test_user_context_xml_tail_has_three_elements() -> None:
    """The <user_context> tail must contain exactly three elements."""
    prompt = render_persona_prompt(
        operator_name="Ian",
        requesting_user_name="Alice",
        language="ja-JP",
    )
    _prefix, tail = _split_at_user_context(prompt)
    assert tail.count("<operator_name>") == 1
    assert tail.count("</operator_name>") == 1
    assert tail.count("<addressed_user_name>") == 1
    assert tail.count("</addressed_user_name>") == 1
    assert tail.count("<addressed_user_language>") == 1
    assert tail.count("</addressed_user_language>") == 1
    assert "<operator_name>Ian</operator_name>" in tail
    assert "<addressed_user_name>Alice</addressed_user_name>" in tail
    assert "<addressed_user_language>ja-JP</addressed_user_language>" in tail
    assert tail.endswith("</user_context>")


def test_cacheable_prefix_is_byte_identical_across_languages() -> None:
    """Prefix MUST NOT depend on language — language goes in the XML tail."""
    prompt_en = render_persona_prompt(
        operator_name="Ian",
        requesting_user_name="Ian",
        language="en-US",
    )
    prompt_ja = render_persona_prompt(
        operator_name="Ian",
        requesting_user_name="Ian",
        language="ja-JP",
    )
    prefix_en, _ = _split_at_user_context(prompt_en)
    prefix_ja, _ = _split_at_user_context(prompt_ja)
    assert prefix_en == prefix_ja
    assert prefix_en.encode("utf-8") == prefix_ja.encode("utf-8")


def test_cacheable_prefix_is_byte_identical_across_users() -> None:
    """Prefix MUST NOT depend on user — addressee goes in the XML tail."""
    prompt_a = render_persona_prompt(
        operator_name="Ian",
        requesting_user_name="Alice",
        language="en-US",
    )
    prompt_b = render_persona_prompt(
        operator_name="Bruce",
        requesting_user_name="Diana",
        language="en-US",
    )
    prefix_a, _ = _split_at_user_context(prompt_a)
    prefix_b, _ = _split_at_user_context(prompt_b)
    assert prefix_a == prefix_b
    assert prefix_a.encode("utf-8") == prefix_b.encode("utf-8")


def test_household_owner_distinguished_from_addressee() -> None:
    """Persona must distinguish the household owner from the current addressee."""
    prompt = render_persona_prompt(
        operator_name="Ian",
        requesting_user_name="Alice",
        language="en-US",
    )
    prefix, _tail = _split_at_user_context(prompt)
    assert "head butler in <operator_name>'s household" in prefix
    assert "currently addressing <addressed_user_name>" in prefix


def test_render_with_lucius_persona() -> None:
    """``render_persona_prompt`` is persona-agnostic — non-Alfred personas work."""
    lucius = Persona(
        name="lucius",
        character=(
            "Lucius is the in-house financial strategist — analytical, quiet, "
            "and meticulously discreet about ledger details."
        ),
    )
    prompt = render_persona_prompt(
        persona=lucius,
        operator_name="Ian",
        requesting_user_name="Ian",
        language="en-US",
    )
    prefix, _tail = _split_at_user_context(prompt)
    assert "Lucius" in prefix
    assert lucius.character in prefix


def test_render_persona_prompt_is_a_t0_tagged_content() -> None:
    """The persona system prompt is T0 (canonical, trusted)."""
    from alfred.security.tiers import T0, TaggedContent

    prompt = render_persona_prompt(
        operator_name="Ian",
        requesting_user_name="Ian",
        language="en-US",
    )
    tagged: TaggedContent[T0] = TaggedContent[T0](content=prompt, source="persona.alfred", tier=T0)
    assert isinstance(tagged, TaggedContent)
    assert tagged.tier.name == "T0"
