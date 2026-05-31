"""Wire-format serializer + cross-tier rejection tests. Spec §3.5.

The TaggedContent wire format emits ``tier`` as a string name (``"T0"``,
``"T1"``, etc.) rather than the runtime class object so audit rows,
transport frames, and cross-process JSON survive a round trip.

The model_validator closes the deserialization hole: a payload claiming
``tier="T3"`` parsed as ``TaggedContent[T2]`` must fail — that is the
"cross-tier confusion" attack from the adversarial corpus.
"""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from alfred.security.tiers import T0, T1, T2, TaggedContent


def test_t2_round_trip_via_model_dump() -> None:
    tc = TaggedContent[T2](content="hello", source="tui", tier=T2)
    dumped = tc.model_dump()
    assert dumped["tier"] == "T2"
    restored = TaggedContent[T2].model_validate(dumped)
    assert restored.tier is T2
    assert restored.content == "hello"


def test_t1_round_trip_via_model_dump() -> None:
    tc = TaggedContent[T1](content="op msg", source="tui", tier=T1)
    dumped = tc.model_dump()
    assert dumped["tier"] == "T1"
    restored = TaggedContent[T1].model_validate(dumped)
    assert restored.tier is T1


def test_t0_round_trip_via_model_dump() -> None:
    tc = TaggedContent[T0](content="sys", source="internal", tier=T0)
    dumped = tc.model_dump()
    assert dumped["tier"] == "T0"
    restored = TaggedContent[T0].model_validate(dumped)
    assert restored.tier is T0


def test_cross_tier_confusion_rejected_on_parse() -> None:
    """A JSON payload claiming tier T3 while parsed as TaggedContent[T2] is rejected.

    Pydantic v2 preserves generic-parameter metadata on the parameterised
    class (``TaggedContent[T2].__pydantic_generic_metadata__["args"]``).
    The validator consults that metadata when present and rejects any
    resolved tier that doesn't match — closing the "tier-laundering"
    attack where an adversary crafts a wire payload whose ``tier`` field
    disagrees with the consumer's expected generic parameter.
    """
    wire = {"content": "injected", "source": "wire", "tier": "T3", "metadata": {}}
    with pytest.raises((ValidationError, ValueError)):
        TaggedContent[T2].model_validate(wire)


def test_unknown_tier_string_rejected_on_parse() -> None:
    """A tier string not in _APPROVED_TIERS is rejected at parse time."""
    wire = {"content": "x", "source": "wire", "tier": "TX_UNKNOWN", "metadata": {}}
    with pytest.raises((ValidationError, ValueError)):
        TaggedContent[T0].model_validate(wire)


def test_json_round_trip_preserves_tier() -> None:
    """Full JSON encode → decode cycle preserves tier identity."""
    tc = TaggedContent[T2](content="user text", source="discord", tier=T2)
    json_str = tc.model_dump_json()
    data = json.loads(json_str)
    assert data["tier"] == "T2"
    restored = TaggedContent[T2].model_validate_json(json_str)
    assert restored.tier is T2
    assert restored.content == "user text"
