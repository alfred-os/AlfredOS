"""The default Alfred persona, hardcoded for Slice 1/2.

Slice 5 replaces this with the persona registry (manifest in
/var/lib/alfred/state.git/personas/alfred/). For now, Alfred is a Python
constant + a system-prompt factory.

PR-B Phase 3 reshapes the system-prompt factory into ``render_persona_prompt``:
a **cacheable prefix** (byte-identical across users and languages because it
references element names rather than interpolated values) followed by a
``<user_context>`` XML tail that carries the per-call substitutions. The split
is load-bearing — it is what makes Anthropic-style prompt caching effective.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Persona:
    name: str
    character: str  # one-paragraph description for prompt assembly


ALFRED_PERSONA = Persona(
    name="alfred",
    character=(
        "Alfred is the head butler of the household — discreet, loyal, anticipatory, "
        "multi-skilled, and unfailingly polite. He keeps confidences, prefers brevity "
        "to flourish, and prefers a useful next step to a long explanation. He addresses "
        "the operator by name."
    ),
)


def render_persona_prompt(
    *,
    persona: Persona = ALFRED_PERSONA,
    operator_name: str,
    requesting_user_name: str,
    language: str,
) -> str:
    """Assemble a persona system prompt with a cacheable prefix + ``<user_context>`` tail.

    The cacheable prefix references element names (``<operator_name>``,
    ``<addressed_user_name>``, ``<addressed_user_language>``) rather than
    interpolated values; the substitutions live in the ``<user_context>`` XML
    tail. The prefix is therefore byte-identical across users and languages
    for a given persona — a prerequisite for Anthropic-style prompt caching.

    The BCP-47 imperative ("Respond in the BCP-47 language tag identified by
    ``<addressed_user_language>``") sits in the prefix. Losing it silently
    re-monolinguals the bot, so spec i18n-002 marks it load-bearing.

    The persona prompt is T0 system-prompt text and stays canonical English —
    it does NOT go through ``t()``.
    """
    prefix = (
        f"You are {persona.name.title()}, head butler in <operator_name>'s "
        f"household. {persona.character} "
        "You are currently addressing <addressed_user_name>. "
        "Respond in the BCP-47 language tag identified by <addressed_user_language>. "
        "Keep responses tight unless asked to elaborate. "
        "If you do not know something, say so plainly; do not invent."
    )
    tail = (
        "<user_context>\n"
        f"  <operator_name>{operator_name}</operator_name>\n"
        f"  <addressed_user_name>{requesting_user_name}</addressed_user_name>\n"
        f"  <addressed_user_language>{language}</addressed_user_language>\n"
        "</user_context>"
    )
    return f"{prefix}\n\n{tail}"
