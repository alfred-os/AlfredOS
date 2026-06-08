"""ErrorOutcome[T] discriminated union (PR-S4-3, ADR-0022).

Component C of PR-S4-3. Pins the shape of the recoverable-carrier
semantic's return type: ``_run_error`` returns
``ErrorOutcome[T] = ReRaise | SubstituteResult[T]`` instead of
``HookContext[T]``. The caller pattern-matches on the outcome.

Two Pydantic v2 frozen models + one PEP 695 type alias:
* ``ReRaise()`` — no payload; "propagate the original exception"
* ``SubstituteResult[T]`` — payload + source_tier + subscriber_id;
  "this error-stage subscriber's recovery payload replaces the exception"
* ``ErrorOutcome[T]`` — the union the caller pattern-matches over

mypy strict enforces exhaustive matches via the union shape.
"""

from __future__ import annotations

import pytest
from pydantic import BaseModel, ConfigDict, ValidationError

from alfred.hooks.invoke import ErrorOutcome, ReRaise, SubstituteResult


class _DemoPayload(BaseModel):
    """Test payload shape — frozen Pydantic so it's hashable + immutable."""

    model_config = ConfigDict(frozen=True)
    value: str


def test_reraise_is_frozen_pydantic_model_no_fields() -> None:
    """``ReRaise()`` is a frozen Pydantic v2 model with no payload.

    ``extra="forbid"`` so a future field-addition refactor surfaces
    at the call site rather than silently accepting unknown kwargs.
    ``frozen=True`` so a subscriber pattern-matching on
    ``case ReRaise():`` can rely on value semantics.
    """
    ReRaise()  # constructs cleanly
    with pytest.raises(ValidationError):
        ReRaise(extra="x")  # type: ignore[call-arg]


def test_substitute_result_typed_payload() -> None:
    """``SubstituteResult[T]`` carries a typed payload + tier + subscriber_id."""
    p = _DemoPayload(value="ok")
    s = SubstituteResult[_DemoPayload](
        payload=p,
        source_tier="T0",
        subscriber_id="m.func",
    )
    assert s.payload.value == "ok"
    assert s.source_tier == "T0"
    assert s.subscriber_id == "m.func"


def test_substitute_result_source_tier_literal_rejects_invalid() -> None:
    """``source_tier`` is closed-vocab Literal of {T0, T1, T2, T3}.

    A non-tier value (e.g. ``"T4"``) is refused at construction so a
    typo cannot mask a tier-upgrade attack: the tier-upgrade guard
    reads this field to decide if ``source_tier > carrier_tier``.
    """
    p = _DemoPayload(value="ok")
    with pytest.raises(ValidationError):
        SubstituteResult[_DemoPayload](
            payload=p,
            source_tier="T4",  # type: ignore[arg-type]
            subscriber_id="x",
        )


def test_error_outcome_alias_resolves_union() -> None:
    """``ErrorOutcome[T]`` is a PEP 695 type alias over the discriminated union.

    Runtime ``match``/``case`` reaches both arms; mypy strict pins
    exhaustiveness at type-check time.
    """
    reraise_outcome: ErrorOutcome[_DemoPayload] = ReRaise()
    substitute_outcome: ErrorOutcome[_DemoPayload] = SubstituteResult[_DemoPayload](
        payload=_DemoPayload(value="x"),
        source_tier="T0",
        subscriber_id="s",
    )
    match reraise_outcome:
        case ReRaise():
            ok_reraise = True
        case SubstituteResult():
            ok_reraise = False
    match substitute_outcome:
        case SubstituteResult(payload=p, source_tier=tt, subscriber_id=sid):
            ok_sub = p.value == "x" and tt == "T0" and sid == "s"
        case ReRaise():
            ok_sub = False
    assert ok_reraise and ok_sub


def test_reraise_equality_is_value_based() -> None:
    """All ``ReRaise()`` instances compare equal (value semantics)."""
    a = ReRaise()
    b = ReRaise()
    assert a == b
    assert hash(a) == hash(b)


def test_substitute_result_equality_is_field_wise() -> None:
    """Field-wise equality picks up payload / tier / subscriber_id differences."""
    a = SubstituteResult[_DemoPayload](
        payload=_DemoPayload(value="x"),
        source_tier="T0",
        subscriber_id="s",
    )
    b = SubstituteResult[_DemoPayload](
        payload=_DemoPayload(value="x"),
        source_tier="T0",
        subscriber_id="s",
    )
    c = SubstituteResult[_DemoPayload](
        payload=_DemoPayload(value="x"),
        source_tier="T1",
        subscriber_id="s",
    )
    assert a == b
    assert a != c
