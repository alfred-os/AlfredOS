"""A ``T3`` object must be unconstructable off the nonce path (#518).

CLAUDE.md hard rule #3 says every external-content boundary tags input ``T3`` at
ingestion, and spec §3.2 makes ``tag_t3_with_nonce`` the capability gate that
authorises it. The gate lives in that FUNCTION; the model itself never checked.
``TaggedContent``'s field validator verifies the tier is approved and matches the
generic argument — it does not ask whether the caller held the nonce.

So a ``T3``-tagged object could be built by seven constructions that never pass the
gate, and ``scripts/check_tag_t3.py`` (a static detector) modelled none of them.
None is present in ``src/`` today, so nothing has slipped through — but the gate
would not have caught them, and a static grep is the wrong layer for this: it can
only see the shapes it was taught, while a runtime invariant closes the whole class.

These cases pin that invariant. Each constructs ``T3`` by a distinct route that
bypasses ``tag_t3_with_nonce``, and each must be refused.

The authorised path is exercised too (see ``test_the_authorised_path_still_works``):
without it, refusing every construction would satisfy the file.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from alfred.security.tiers import T2, T3, TaggedContent, tag_t3_with_nonce

# The generic alias under a different local name — the "renamed import" shape. Binding
# it here is exactly what an author would write, and what a name-based static grep
# cannot follow.
_Renamed = TaggedContent

# A non-literal generic argument: the tier arrives through a variable, so the
# subscript's AST slice is not the identifier ``T3`` the detector looks for.
_TIER = T3

_PAYLOAD = {"content": "untrusted", "source": "test", "tier": T3, "metadata": {}}


def _expect_refusal() -> pytest.RaisesExc[Exception]:
    """T3 construction off the nonce path must raise, whatever the route."""
    return pytest.raises((ValidationError, ValueError))


def test_bare_keyword_construction_is_refused() -> None:
    """``TaggedContent(tier=T3, ...)`` — no subscript, so no generic to cross-check."""
    with _expect_refusal():
        TaggedContent(content="untrusted", source="test", tier=T3, metadata={})


def test_model_construct_is_refused() -> None:
    """``model_construct`` skips validation entirely — the sharpest bypass."""
    with _expect_refusal():
        TaggedContent[T3].model_construct(**_PAYLOAD)


def test_model_validate_is_refused() -> None:
    """Deserialisation must not mint a T3 object off the gate."""
    with _expect_refusal():
        TaggedContent[T3].model_validate(_PAYLOAD)


def test_model_validate_json_is_refused() -> None:
    """The JSON door is the same door."""
    with _expect_refusal():
        TaggedContent[T3].model_validate_json('{"content":"x","source":"s","tier":"T3"}')


def test_model_copy_update_to_t3_is_refused(authorized_t3_nonce: object) -> None:
    """Upgrading a lower tier to T3 via ``model_copy`` must not work.

    The most plausible accident of the seven: an author copies an existing object and
    edits the tier, never touching a function the gate protects.
    """
    lower = TaggedContent[T2](content="ok", source="test", tier=T2, metadata={})
    with _expect_refusal():
        lower.model_copy(update={"tier": T3})


def test_renamed_import_subscript_is_refused() -> None:
    """``_Renamed[T3](...)`` — the alias a name-based static grep cannot follow."""
    with _expect_refusal():
        _Renamed[T3](content="untrusted", source="test", tier=T3, metadata={})


def test_non_literal_generic_argument_is_refused() -> None:
    """``TaggedContent[_TIER](...)`` — the slice is a variable, not the literal ``T3``."""
    with _expect_refusal():
        TaggedContent[_TIER](content="untrusted", source="test", tier=_TIER, metadata={})


def test_the_authorised_path_still_works(authorized_t3_nonce: object) -> None:
    """The vacuity floor: refusing EVERYTHING would satisfy every case above.

    ``tag_t3_with_nonce`` with the real nonce is the one route that must succeed, and
    the object it returns must actually carry T3 — a guard that produced a T2 object
    would satisfy a bare "did not raise" assertion.
    """
    tagged = tag_t3_with_nonce("untrusted", "test", caller_token=authorized_t3_nonce)  # type: ignore[arg-type]

    assert tagged.tier is T3
    assert tagged.content == "untrusted"


def test_a_lower_tier_is_unaffected() -> None:
    """The invariant is about T3 only; ordinary tiers must construct freely."""
    ok = TaggedContent[T2](content="fine", source="test", tier=T2, metadata={})

    assert ok.tier is T2


def test_model_construct_still_works_for_a_lower_tier() -> None:
    """The override must not break legitimate use — it guards T3, nothing else.

    Also a vacuity floor for the override: refusing every ``model_construct`` would
    satisfy the T3 case above while breaking a documented pydantic API.
    """
    built = TaggedContent[T2].model_construct(content="fine", source="test", tier=T2, metadata={})

    assert built.tier is T2


def test_model_copy_still_works_when_not_touching_the_tier() -> None:
    """Copying without a tier change is ordinary use and must stay ordinary."""
    original = TaggedContent[T2](content="fine", source="test", tier=T2, metadata={})

    plain = original.model_copy()
    relabelled = original.model_copy(update={"source": "elsewhere"})

    assert plain.tier is T2
    assert plain.content == "fine"
    assert relabelled.source == "elsewhere"
    assert relabelled.tier is T2


def test_a_t3_object_can_still_be_copied_by_an_authorised_holder(
    authorized_t3_nonce: object,
) -> None:
    """Holding a legitimately-tagged T3 object must not make it unusable.

    The invariant is about MINTING T3, not about handling it. A copy that leaves the
    tier alone is not a new authorisation, and breaking it would push callers back
    towards the bypasses this closes.
    """
    tagged = tag_t3_with_nonce("untrusted", "test", caller_token=authorized_t3_nonce)  # type: ignore[arg-type]

    copied = tagged.model_copy(update={"source": "relabelled"})

    assert copied.tier is T3
    assert copied.source == "relabelled"
