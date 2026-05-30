"""Tests for :class:`alfred.memory.episodic.EpisodicRecordInput`.

Slice-2.5 PR-B Task 1. Pins the immutable carrier dataclass that PR-B
Task 2 will use to refactor :meth:`EpisodicMemory.record` through
:func:`alfred.hooks.invoking` (one frozen value carries the call shape
across five hookpoints — pre/post/error/observe — so subscribers and
the dispatcher both consume a single hashable snapshot).

Five invariants pinned:

* **Signature parity drift-guard** — the dataclass fields equal the
  parameters of ``EpisodicMemory.record`` minus ``self``, with the same
  names, types AND defaults, in the same order. The whole point of the
  carrier is that adding a kwarg to ``record`` without a matching
  dataclass field breaks the carrier contract; this test is the
  drift-guard for that.
* **Frozen** — assigning to a field after construction raises
  :class:`dataclasses.FrozenInstanceError`. PR-B Task 5 depends on this
  for the "no mutation across stages" invariant the dispatcher relies
  on.
* **Slots enforced** — assigning an arbitrary attribute raises
  :class:`AttributeError`. Slots is what makes the immutability claim
  airtight (otherwise ``__dict__`` could be patched around the frozen
  guard).
* **``replace()`` round-trip property** (hypothesis) — for any field
  values, ``dataclasses.replace(inp, content=x)`` mutates *only*
  ``content`` and preserves every other field. The PR-B Task 4 wrapper
  builds a new input per turn via ``replace`` rather than constructing
  from scratch; this property guarantees that pattern is sound.
* **Defaults match ``record``** — the six fields with defaults match
  the plan's locked-in values verbatim. The signature-parity test
  already covers this transitively, but a direct assertion catches the
  failure mode where someone "fixes" both sides in lockstep to the
  wrong value.
"""

from __future__ import annotations

import dataclasses
import inspect
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from alfred.memory.episodic import EpisodicMemory, EpisodicRecordInput
from alfred.providers.base import Role


def _record_params() -> list[inspect.Parameter]:
    """``record``'s parameters minus ``self``, in declaration order."""
    sig = inspect.signature(EpisodicMemory.record)
    return [p for p in sig.parameters.values() if p.name != "self"]


# Strategy for the ``role`` Literal — hand-rolled because
# ``builds(EpisodicRecordInput, ...)`` over a Literal needs an explicit
# sampled_from to avoid hypothesis falling back to ``Any``.
_role_strategy: st.SearchStrategy[Role] = st.sampled_from(["system", "user", "assistant"])


def _input_strategy() -> st.SearchStrategy[EpisodicRecordInput]:
    """All-fields strategy. Hand-rolled (not ``builds``) so the typed
    Literal for ``role`` and the floats-without-nan constraint for
    ``cost_usd`` are explicit."""
    return st.builds(
        EpisodicRecordInput,
        user_id=st.text(),
        role=_role_strategy,
        content=st.text(),
        trust_tier=st.sampled_from(["T0", "T1", "T2", "T3"]),
        tokens_in=st.integers(min_value=0, max_value=1_000_000),
        tokens_out=st.integers(min_value=0, max_value=1_000_000),
        cost_usd=st.floats(min_value=0.0, max_value=1_000.0, allow_nan=False, allow_infinity=False),
        persona=st.text(min_size=1, max_size=32),
        persona_id=st.one_of(st.none(), st.text(min_size=1, max_size=32)),
        language=st.sampled_from(["en-US", "en-GB", "fr-FR", "ja-JP", "de-DE"]),
    )


class TestSignatureParityDriftGuard:
    """The carrier must mirror ``record``'s signature 1:1. Adding a kwarg
    to ``record`` without a corresponding dataclass field — or shifting
    a default — fails this test in CI before it can ship."""

    def test_field_names_match_record_params_in_order(self) -> None:
        record_names = [p.name for p in _record_params()]
        field_names = [f.name for f in dataclasses.fields(EpisodicRecordInput)]
        assert field_names == record_names

    def test_field_types_match_record_annotations(self) -> None:
        record_types = {p.name: p.annotation for p in _record_params()}
        field_types = {f.name: f.type for f in dataclasses.fields(EpisodicRecordInput)}
        # Dataclass field types come back as strings under
        # ``from __future__ import annotations``; normalise both sides
        # through the source annotation strings on ``record`` for a
        # like-for-like compare.
        record_type_strs = {
            name: t if isinstance(t, str) else getattr(t, "__name__", repr(t))
            for name, t in record_types.items()
        }
        field_type_strs = {
            name: t if isinstance(t, str) else getattr(t, "__name__", repr(t))
            for name, t in field_types.items()
        }
        assert field_type_strs == record_type_strs

    def test_field_defaults_match_record_defaults(self) -> None:
        # ``inspect.Parameter.empty`` ↔ ``dataclasses.MISSING``: a param
        # with no default maps to a field with no default.
        record_defaults: dict[str, Any] = {}
        for p in _record_params():
            record_defaults[p.name] = (
                dataclasses.MISSING if p.default is inspect.Parameter.empty else p.default
            )
        field_defaults: dict[str, Any] = {
            f.name: f.default for f in dataclasses.fields(EpisodicRecordInput)
        }
        assert field_defaults == record_defaults


class TestImmutability:
    """Frozen + slots together are what make the carrier safe to pass
    across hookpoint boundaries — subscribers can't tamper with the
    snapshot the dispatcher hashed at the pre stage."""

    def test_frozen_blocks_field_reassignment(self) -> None:
        inp = EpisodicRecordInput(
            user_id="u",
            role="user",
            content="hi",
            trust_tier="T2",
        )
        with pytest.raises(dataclasses.FrozenInstanceError):
            inp.user_id = "other"  # type: ignore[misc]

    def test_slots_blocks_arbitrary_attribute_injection(self) -> None:
        inp = EpisodicRecordInput(
            user_id="u",
            role="user",
            content="hi",
            trust_tier="T2",
        )
        # Without ``slots=True`` a frozen dataclass still raises
        # FrozenInstanceError here, not AttributeError — the distinct
        # AttributeError is what proves slots is in effect.
        with pytest.raises((AttributeError, dataclasses.FrozenInstanceError)):
            inp.unknown_field = "x"  # type: ignore[attr-defined]
        # And the no-``__dict__`` property is the load-bearing slots
        # guarantee: it prevents attribute injection via
        # ``object.__setattr__`` workarounds.
        assert not hasattr(inp, "__dict__")


class TestDefaultsMatchPlan:
    """The plan locks specific defaults; a regression here means the
    carrier and ``record`` drifted to a *consistent-but-wrong* shape
    that the signature-parity test alone wouldn't catch."""

    def test_defaults_are_the_plan_values(self) -> None:
        inp = EpisodicRecordInput(
            user_id="u",
            role="user",
            content="hi",
            trust_tier="T2",
        )
        assert inp.tokens_in == 0
        assert inp.tokens_out == 0
        assert inp.cost_usd == 0.0
        assert inp.persona == "alfred"
        assert inp.persona_id is None
        assert inp.language == "en-US"


class TestReplaceRoundTrip:
    """PR-B Task 4 builds new inputs via ``dataclasses.replace`` rather
    than reconstructing from scratch. The property below proves that
    pattern doesn't silently corrupt other fields."""

    @given(_input_strategy(), st.text())
    def test_replace_content_preserves_every_other_field(
        self, inp: EpisodicRecordInput, new_content: str
    ) -> None:
        replaced = dataclasses.replace(inp, content=new_content)
        assert replaced.content == new_content
        # Every other field unchanged — iterate fields rather than name
        # them so the property tracks future field additions for free.
        for f in dataclasses.fields(EpisodicRecordInput):
            if f.name == "content":
                continue
            assert getattr(replaced, f.name) == getattr(inp, f.name)

    @given(_input_strategy())
    def test_replace_with_no_changes_is_value_equal(self, inp: EpisodicRecordInput) -> None:
        # Frozen dataclasses are value-equal by default (eq=True is the
        # default); the carrier must keep that — the dispatcher uses
        # equality to dedupe observed inputs across a chain.
        assert dataclasses.replace(inp) == inp
