"""Full ``ExtractionResult`` / ``Extracted`` / ``TypedRefusal`` types
(PR-S3-4 Task 3; spec §6.7).

The PR-S3-1 stubs (in ``src/alfred/security/quarantine.py``) carried only
``data``/``handle`` and ``reason``/``handle`` to satisfy the import chain
at PR-S3-3a's ``DispatchResult`` site. This task promotes them to the
full Pydantic shape:

* ``Extracted(kind="extracted", data: T3DerivedData, extraction_mode: Literal[...])``
* ``TypedRefusal(kind="typed_refusal", reason: Literal[<closed-set>])``
* ``ExtractionResult = Extracted | TypedRefusal``  (plain union per core-011 —
  the discriminator field is for Pydantic TypeAdapter callers, not the
  runtime union alias)

T3 provenance discipline (the load-bearing reason this PR exists):

* ``T3DerivedData`` remains a NewType so type-checkers refuse implicit
  ``dict`` substitution at trust-boundary call sites (scripts/check_tag_t3.py
  enforces). At runtime it is a plain dict.
* ``Extracted.data`` is annotated ``T3DerivedData``, not plain ``dict`` —
  the provenance metadata travels with the value through the orchestrator.
* The only T3 escape hatch is ``downgrade_to_orchestrator`` which writes
  ``downgrade_explicit=True`` to the audit row. ``Extracted`` cannot be
  silently treated as T2 just because it deserialises to a dict.

The closed reason vocabulary (scope-mandated):

* ``cannot_extract`` — exhausted retries (plan §6.3)
* ``refused_by_safety`` — provider safety filter (plan §6.7)
* ``ambiguous_input`` — schema-incompatible input (plan §6.7)
* ``provider_refused`` — provider sent a structured refusal
* ``provider_unavailable`` — circuit breaker / supervisor unreachable
* ``dlp_outbound_refused`` — DLP post-scan blocked the result
* ``nonce_check_failed`` — handle-id nonce mismatch (PR-S3-5 contract)

``kind="malformed_output"`` is deliberately NOT a valid ``Extracted`` kind
nor a valid ``TypedRefusal.reason`` — the host treats unexpected ``kind``
values as protocol violations (spec §6.7 / prov-011), not as legitimate
outcomes the orchestrator can branch on.
"""

from __future__ import annotations

import typing

import pytest
from pydantic import ValidationError

from alfred.security.quarantine import (
    Extracted,
    ExtractionResult,
    T3DerivedData,
    TypedRefusal,
)

# ---------------------------------------------------------------------------
# Extracted shape
# ---------------------------------------------------------------------------


def test_extracted_kind_is_literal_extracted() -> None:
    result = Extracted(
        data=T3DerivedData({"title": "hello"}),
        extraction_mode="native_constrained",
    )
    assert result.kind == "extracted"


def test_extracted_carries_data_t3_derived() -> None:
    """``.data`` round-trips a T3DerivedData payload unchanged."""
    payload = T3DerivedData({"title": "x", "url": "https://example.com"})
    result = Extracted(data=payload, extraction_mode="native_constrained")
    # At runtime T3DerivedData is a dict; equality is structural.
    assert result.data == {"title": "x", "url": "https://example.com"}


def test_extracted_accepts_native_constrained_mode() -> None:
    result = Extracted(data=T3DerivedData({}), extraction_mode="native_constrained")
    assert result.extraction_mode == "native_constrained"


def test_extracted_accepts_json_object_unconstrained_mode() -> None:
    result = Extracted(data=T3DerivedData({}), extraction_mode="json_object_unconstrained")
    assert result.extraction_mode == "json_object_unconstrained"


def test_extracted_accepts_prompt_embedded_fallback_mode() -> None:
    result = Extracted(data=T3DerivedData({}), extraction_mode="prompt_embedded_fallback")
    assert result.extraction_mode == "prompt_embedded_fallback"


def test_extracted_rejects_unknown_extraction_mode() -> None:
    """``extraction_mode`` is a closed Literal — unknown strings are refused."""
    with pytest.raises(ValidationError):
        Extracted(
            data=T3DerivedData({}),
            extraction_mode="creative_freestyle",  # type: ignore[arg-type]
        )


def test_extracted_rejects_malformed_output_kind_override() -> None:
    """``kind`` is a closed Literal["extracted"] — ``malformed_output`` is a
    protocol-violation marker handled at the transport boundary, never a
    legitimate Extracted variant (spec §6.7 / prov-011).
    """
    with pytest.raises(ValidationError):
        Extracted(
            data=T3DerivedData({}),
            extraction_mode="native_constrained",
            kind="malformed_output",  # type: ignore[arg-type]
        )


def test_extracted_is_frozen() -> None:
    """Frozen so the audit-emit path cannot mutate the result mid-flight."""
    result = Extracted(data=T3DerivedData({}), extraction_mode="native_constrained")
    with pytest.raises(ValidationError):
        result.extraction_mode = "json_object_unconstrained"  # type: ignore[misc]


def test_extracted_data_annotation_is_t3_derived_data() -> None:
    """The ``.data`` field annotation is ``T3DerivedData``, NOT plain dict.

    This is the load-bearing type-level provenance assertion. A reviewer
    or refactor that silently widens the annotation to ``dict[str, object]``
    would erase the T3 provenance tag — which is exactly the escape hatch
    this PR ships to gate.
    """
    hints = typing.get_type_hints(Extracted)
    assert hints["data"] is T3DerivedData


# ---------------------------------------------------------------------------
# TypedRefusal shape
# ---------------------------------------------------------------------------


def test_typed_refusal_kind_is_literal_typed_refusal() -> None:
    refusal = TypedRefusal(reason="cannot_extract")
    assert refusal.kind == "typed_refusal"


def test_typed_refusal_accepts_cannot_extract() -> None:
    assert TypedRefusal(reason="cannot_extract").reason == "cannot_extract"


def test_typed_refusal_accepts_refused_by_safety() -> None:
    assert TypedRefusal(reason="refused_by_safety").reason == "refused_by_safety"


def test_typed_refusal_accepts_ambiguous_input() -> None:
    assert TypedRefusal(reason="ambiguous_input").reason == "ambiguous_input"


def test_typed_refusal_accepts_provider_refused() -> None:
    assert TypedRefusal(reason="provider_refused").reason == "provider_refused"


def test_typed_refusal_accepts_provider_unavailable() -> None:
    assert TypedRefusal(reason="provider_unavailable").reason == "provider_unavailable"


def test_typed_refusal_accepts_dlp_outbound_refused() -> None:
    assert TypedRefusal(reason="dlp_outbound_refused").reason == "dlp_outbound_refused"


def test_typed_refusal_accepts_nonce_check_failed() -> None:
    assert TypedRefusal(reason="nonce_check_failed").reason == "nonce_check_failed"


def test_typed_refusal_rejects_open_string_reason() -> None:
    """``reason`` is a closed Literal — free-form strings are refused.

    A free-form reason would leak provider-supplied text (potentially
    T3-derived) into orchestrator-readable fields. The closed enum is
    the audit-row vocabulary boundary.
    """
    with pytest.raises(ValidationError):
        TypedRefusal(reason="something_arbitrary")  # type: ignore[arg-type]


def test_typed_refusal_rejects_malformed_output_as_reason() -> None:
    """``malformed_output`` is a protocol-violation marker, never a
    legitimate refusal reason (spec §6.7 / prov-011).
    """
    with pytest.raises(ValidationError):
        TypedRefusal(reason="malformed_output")  # type: ignore[arg-type]


def test_typed_refusal_is_frozen() -> None:
    refusal = TypedRefusal(reason="cannot_extract")
    with pytest.raises(ValidationError):
        refusal.reason = "refused_by_safety"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# T3DerivedData NewType semantics
# ---------------------------------------------------------------------------


def test_t3_derived_data_is_dict_at_runtime() -> None:
    """NewType is a no-op at runtime — isinstance(dict) holds."""
    data = T3DerivedData({"k": "v"})
    assert isinstance(data, dict)


def test_t3_derived_data_round_trips_through_extracted() -> None:
    """Constructing an Extracted with T3DerivedData does NOT widen the
    runtime type — the value is still a dict-equivalent payload."""
    payload = T3DerivedData({"title": "x"})
    result = Extracted(data=payload, extraction_mode="native_constrained")
    # The model_dump output is a dict the audit-row writer can serialise.
    dumped = result.model_dump()
    assert dumped["data"] == {"title": "x"}


# ---------------------------------------------------------------------------
# ExtractionResult union shape
# ---------------------------------------------------------------------------


def test_extraction_result_union_includes_extracted_and_typed_refusal() -> None:
    """ExtractionResult is the union the transport layer parses against.

    Plain ``Extracted | TypedRefusal`` per core-011 — no Annotated
    discriminator wrapper. Pydantic TypeAdapter callers add the
    discriminator at parse time when they need it.
    """
    args = typing.get_args(ExtractionResult)
    assert Extracted in args
    assert TypedRefusal in args


def test_extraction_result_isinstance_check_works_for_both_branches() -> None:
    """Dispatch sites branch by isinstance — Extracted and TypedRefusal are
    both concrete classes that respond to isinstance checks."""
    extracted = Extracted(data=T3DerivedData({}), extraction_mode="native_constrained")
    refusal = TypedRefusal(reason="cannot_extract")
    assert isinstance(extracted, Extracted)
    assert isinstance(refusal, TypedRefusal)
    # Cross-check: each is NOT an instance of the other.
    assert not isinstance(extracted, TypedRefusal)
    assert not isinstance(refusal, Extracted)


# ---------------------------------------------------------------------------
# Provenance discipline — Extracted is NOT a transparent T2 dict.
# ---------------------------------------------------------------------------


def test_extracted_is_not_a_plain_dict_subclass() -> None:
    """Critical: ``Extracted`` is a Pydantic model, NOT a dict subclass.

    A downstream consumer cannot mistakenly treat it as a T2 dict via
    duck-typing on ``__getitem__`` — they must explicitly read ``.data``
    (which is T3-tagged) and explicitly call ``downgrade_to_orchestrator``
    to escape the tier. Provenance-preservation invariant (PRD §7.1).
    """
    result = Extracted(data=T3DerivedData({"x": 1}), extraction_mode="native_constrained")
    assert not isinstance(result, dict)


def test_extracted_does_not_carry_handle_field() -> None:
    """The full shape drops ``handle`` — ContentHandle is the input to
    quarantine.extract, not part of the structured-extraction result.
    The audit row carries handle_id via correlation, not by embedding."""
    hints = typing.get_type_hints(Extracted)
    assert "handle" not in hints
