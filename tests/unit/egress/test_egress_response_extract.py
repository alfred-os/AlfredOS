"""Unit tests for §4.3 egress-response quarantine-extract (C2, G7-2c-1, #333).

Four required behaviours exercised against stubs (no Postgres, no real extractor):

1. Fresh — gate + extractor run exactly once; ledger records the post-extraction T2
   (not the raw T3 body); returned outcome is T2, deduplicated=False.
2. Gate-denial — AlfredError raised by quarantined_to_structured; extractor.extract
   never awaited; ledger.record_response never called.
3. Replay — fire() returns Deduplicated; extractor not called; outcome is
   deduplicated=True with the deserialized stored T2.
4. Tier-downgrade guard — the orchestrator-visible result is an
   Extracted | TypedRefusal instance (structural T2), never raw bytes.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any
from unittest.mock import AsyncMock

import pytest

from alfred.bootstrap.nonce_factory import _NONCE_LOCK
from alfred.egress.egress_id import TurnEgressContext
from alfred.egress.egress_response_extract import (
    EgressResponseExtractor,
)
from alfred.egress.relay_client import Deduplicated, Fired
from alfred.egress.relay_protocol import EgressResponse, _RawToolRequest
from alfred.errors import AlfredError
from alfred.memory.egress_idempotency import CommitIntentResult, IntentFresh
from alfred.security import tiers as _tiers
from alfred.security.quarantine import (
    Extracted,
    ExtractionResult,
    ExtractionSchema,
    T3DerivedData,
    TypedRefusal,
)
from alfred.security.quarantine_transport import QuarantineStagingMap, T3BodyRecorder
from alfred.security.tiers import CapabilityGateNonce
from tests.helpers.gates import make_deny_all_gate, make_quarantined_extract_chain_gate

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def authorized_t3_nonce() -> Iterator[CapabilityGateNonce]:
    """Install a fresh CapabilityGateNonce as the authorised slot for the test."""
    with _NONCE_LOCK:
        previous = _tiers._AUTHORIZED_T3_NONCE
        nonce = CapabilityGateNonce()
        _tiers._set_authorized_t3_nonce(nonce)
    try:
        yield nonce
    finally:
        with _NONCE_LOCK:
            _tiers._set_authorized_t3_nonce(previous)


# ---------------------------------------------------------------------------
# Test schema
# ---------------------------------------------------------------------------


class _TestSchema(ExtractionSchema):
    """Minimal extraction schema for tests."""

    payload: str


# ---------------------------------------------------------------------------
# Stubs
# ---------------------------------------------------------------------------


@dataclass
class _StubLedger:
    """Fake EgressIdempotencyStore that captures record_response calls."""

    commit_result: CommitIntentResult = field(default_factory=IntentFresh)
    record_calls: list[dict[str, Any]] = field(default_factory=list)

    async def commit_intent(self, **_kwargs: Any) -> CommitIntentResult:
        return self.commit_result

    async def record_response(self, *, egress_id: str, response: str, language: str | None) -> None:
        self.record_calls.append(
            {"egress_id": egress_id, "response": response, "language": language}
        )

    async def prune_expired(self, **_kwargs: Any) -> int:
        return 0


@dataclass
class _StubRelayClient:
    """Scripted relay client whose fire() returns a preset RelayOutcome.

    Exposes a ``ledger`` property so EgressResponseExtractor can access the
    same ledger instance via the single-ledger API (M8).
    """

    outcome: Fired | Deduplicated
    _ledger: _StubLedger = field(default_factory=_StubLedger)

    @property
    def ledger(self) -> _StubLedger:
        return self._ledger

    async def fire(self, **_kwargs: Any) -> Fired | Deduplicated:
        return self.outcome


@dataclass
class _SpyRelayClient:
    """Relay client that captures every fire() call's kwargs for assertion."""

    outcome: Fired | Deduplicated
    _ledger: _StubLedger = field(default_factory=_StubLedger)
    fire_calls: list[dict[str, Any]] = field(default_factory=list)

    @property
    def ledger(self) -> _StubLedger:
        return self._ledger

    async def fire(self, **kwargs: Any) -> Fired | Deduplicated:
        self.fire_calls.append(dict(kwargs))
        return self.outcome


def _make_extracted(payload: str = "structured-data") -> Extracted:
    return Extracted(data=T3DerivedData({"payload": payload}), extraction_mode="native_constrained")


def _make_raw_request(url: str = "https://api.example.com/data") -> _RawToolRequest:
    return _RawToolRequest(
        method="GET",
        url=url,
        headers={},
        body="",
        idempotent=True,
    )


def _make_fired_response(body: bytes = b"raw T3 bytes") -> Fired:
    return Fired(response=EgressResponse(status=200, headers={}, body=body))


_CTX = TurnEgressContext(adapter_id="ada-1", inbound_id="in-1", session_id="sess-1")
_CALL_INDEX = 0


# ---------------------------------------------------------------------------
# Helper: build the extractor under test
# ---------------------------------------------------------------------------


def _make_extractor(
    *,
    relay_outcome: Fired | Deduplicated,
    extracted: ExtractionResult | None = None,
    authorized_nonce: CapabilityGateNonce,
    grant_dereference: bool = True,
    deny_gate: bool = False,
) -> tuple[EgressResponseExtractor, _StubLedger, AsyncMock]:
    """Build an EgressResponseExtractor with injected stubs.

    Returns the extractor, the spy ledger, and the spy extractor mock.
    The spy extractor is an AsyncMock wrapping QuarantinedExtractor.extract.
    """
    # relay_client holds the spy ledger (single-ledger invariant, M8).
    relay_client = _StubRelayClient(outcome=relay_outcome)
    staging = QuarantineStagingMap()
    recorder = T3BodyRecorder(nonce=authorized_nonce, staging=staging)

    # Gate: allow dereference by default; use deny_all for gate-denial tests.
    if deny_gate:
        gate = make_deny_all_gate()
    else:
        gate = make_quarantined_extract_chain_gate(
            grant_dereference_t3=True,
            dereference_plugin_id="alfred.quarantined-llm",
        )

    # Stub QuarantinedExtractor: we do NOT construct a real one (it tries to
    # register a DLP subscriber). Use a plain AsyncMock with the extract method.
    mock_extractor = AsyncMock()
    mock_extractor.extract = AsyncMock(return_value=extracted or _make_extracted())

    extractor = EgressResponseExtractor(
        relay_client=relay_client,  # type: ignore[arg-type]
        gate=gate,
        extractor=mock_extractor,  # type: ignore[arg-type]
        recorder=recorder,
    )
    # Return relay_client._ledger as the spy ledger so callers can assert
    # `record_calls` — EgressResponseExtractor now fetches the ledger via
    # relay_client.ledger (single-ledger invariant, M8).
    # Return the child `.extract` AsyncMock as the spy so callers can assert
    # `spy.assert_awaited_once()` — the parent mock_extractor is what
    # quarantined_to_structured receives; it calls .extract on it.
    return extractor, relay_client._ledger, mock_extractor.extract


# ---------------------------------------------------------------------------
# Test 1 — Fresh fire: gate + extractor run once; ledger records T2 (not raw)
# ---------------------------------------------------------------------------


async def test_fresh_fire_runs_extractor_once_and_records_t2(
    authorized_t3_nonce: CapabilityGateNonce,
) -> None:
    """A Fired response runs gate + extractor exactly once; ledger gets post-extraction T2."""
    raw_body = b"raw T3 bytes from upstream"
    outcome_extracted = _make_extracted("fresh-payload")

    extractor_obj, ledger, spy_extract = _make_extractor(
        relay_outcome=_make_fired_response(body=raw_body),
        extracted=outcome_extracted,
        authorized_nonce=authorized_t3_nonce,
    )
    raw_req = _make_raw_request()

    result = await extractor_obj.handle(
        raw_request=raw_req,
        ctx=_CTX,
        call_index=_CALL_INDEX,
        schema=_TestSchema,
        language="en",
    )

    # Extractor called exactly once.
    spy_extract.assert_awaited_once()

    # deduplicated is False on a fresh fire.
    assert result.deduplicated is False
    assert result.language == "en"

    # The result is T2 (Extracted or TypedRefusal).
    assert isinstance(result.result, (Extracted, TypedRefusal))

    # ledger.record_response was called exactly once.
    assert len(ledger.record_calls) == 1
    rec = ledger.record_calls[0]

    # The stored value must be the post-extraction T2 JSON — NOT the raw T3 bytes.
    assert rec["response"] == outcome_extracted.model_dump_json()
    assert rec["response"] != raw_body.decode("utf-8", errors="replace")
    assert rec["language"] == "en"

    # Sanity: stored value round-trips cleanly via the module's TypeAdapter.
    from alfred.egress.egress_response_extract import _EXTRACTION_RESULT_ADAPTER

    replayed = _EXTRACTION_RESULT_ADAPTER.validate_json(rec["response"])
    assert isinstance(replayed, Extracted)
    assert replayed.data == outcome_extracted.data


# ---------------------------------------------------------------------------
# Test 2 — Gate-denial: AlfredError propagates; extractor + ledger not called
# ---------------------------------------------------------------------------


async def test_gate_denial_raises_and_does_not_reach_ledger(
    authorized_t3_nonce: CapabilityGateNonce,
) -> None:
    """A deny gate makes quarantined_to_structured raise AlfredError before the extractor runs."""
    extractor_obj, ledger, spy_extract = _make_extractor(
        relay_outcome=_make_fired_response(),
        authorized_nonce=authorized_t3_nonce,
        deny_gate=True,
    )

    with pytest.raises(AlfredError):
        await extractor_obj.handle(
            raw_request=_make_raw_request(),
            ctx=_CTX,
            call_index=_CALL_INDEX,
            schema=_TestSchema,
            language=None,
        )

    # Extractor never called (gate denied before extract).
    spy_extract.assert_not_called()

    # Ledger record_response never called (row stays committed_no_response).
    assert ledger.record_calls == []


# ---------------------------------------------------------------------------
# Test 3 — Replay: Deduplicated → stored T2 returned; extractor not called
# ---------------------------------------------------------------------------


async def test_replay_returns_stored_t2_without_calling_extractor(
    authorized_t3_nonce: CapabilityGateNonce,
) -> None:
    """A Deduplicated outcome returns the stored T2 directly, never calling the extractor."""
    stored_extracted = _make_extracted("stored-payload")
    stored_t2_json = stored_extracted.model_dump_json()
    stored_language = "fr"

    extractor_obj, ledger, spy_extract = _make_extractor(
        relay_outcome=Deduplicated(stored_t2=stored_t2_json, language=stored_language),
        authorized_nonce=authorized_t3_nonce,
    )

    result = await extractor_obj.handle(
        raw_request=_make_raw_request(),
        ctx=_CTX,
        call_index=_CALL_INDEX,
        schema=_TestSchema,
        language="en",  # language kwarg is ignored on replay — stored lang wins
    )

    # Extractor must NOT be called on replay (no re-tagging T3, HARD rule #5).
    spy_extract.assert_not_called()

    # Outcome is marked deduplicated.
    assert result.deduplicated is True

    # Stored language is returned (not the caller's "en").
    assert result.language == stored_language

    # The result is the deserialized stored T2.
    assert isinstance(result.result, Extracted)
    assert result.result.data == stored_extracted.data

    # Ledger record_response must NOT be called on replay.
    assert ledger.record_calls == []


# ---------------------------------------------------------------------------
# Test 4 — Tier-downgrade guard: orchestrator only sees T2 (Extracted | TypedRefusal)
# ---------------------------------------------------------------------------


async def test_result_is_always_structural_t2(
    authorized_t3_nonce: CapabilityGateNonce,
) -> None:
    """The returned result is always Extracted | TypedRefusal — never raw bytes or T3 content."""
    # Case A: fresh fire returning Extracted.
    extractor_obj_a, _, _ = _make_extractor(
        relay_outcome=_make_fired_response(),
        extracted=_make_extracted("t2-payload"),
        authorized_nonce=authorized_t3_nonce,
    )
    outcome_a = await extractor_obj_a.handle(
        raw_request=_make_raw_request(),
        ctx=_CTX,
        call_index=_CALL_INDEX,
        schema=_TestSchema,
    )
    assert isinstance(outcome_a.result, (Extracted, TypedRefusal)), (
        f"Expected T2 (Extracted|TypedRefusal), got {type(outcome_a.result)}"
    )

    # Case B: fresh fire returning TypedRefusal.
    refusal = TypedRefusal(reason="cannot_extract")

    # Each test gets a fresh nonce slot; but the fixture is already installed,
    # so reuse the same nonce — just build a new extractor with the refusal result.
    extractor_obj_b, _, _ = _make_extractor(
        relay_outcome=_make_fired_response(),
        extracted=refusal,
        authorized_nonce=authorized_t3_nonce,
    )
    outcome_b = await extractor_obj_b.handle(
        raw_request=_make_raw_request(),
        ctx=_CTX,
        call_index=_CALL_INDEX,
        schema=_TestSchema,
    )
    assert isinstance(outcome_b.result, (Extracted, TypedRefusal)), (
        f"Expected T2 (Extracted|TypedRefusal), got {type(outcome_b.result)}"
    )
    assert isinstance(outcome_b.result, TypedRefusal)
    assert outcome_b.result.reason == "cannot_extract"

    # Case C: replay — also T2.
    stored_extracted = _make_extracted("replay-t2")
    extractor_obj_c, _, _ = _make_extractor(
        relay_outcome=Deduplicated(stored_t2=stored_extracted.model_dump_json(), language=None),
        authorized_nonce=authorized_t3_nonce,
    )
    outcome_c = await extractor_obj_c.handle(
        raw_request=_make_raw_request(),
        ctx=_CTX,
        call_index=_CALL_INDEX,
        schema=_TestSchema,
    )
    assert isinstance(outcome_c.result, (Extracted, TypedRefusal))


# ---------------------------------------------------------------------------
# Test 5 — C6 request_descriptor: handle() passes a non-empty descriptor to fire()
# ---------------------------------------------------------------------------


async def test_handle_passes_non_empty_request_descriptor_to_fire(
    authorized_t3_nonce: CapabilityGateNonce,
) -> None:
    """C6: EgressResponseExtractor.handle() computes a request_descriptor from
    raw_request.method + url + schema identity and passes it to relay_client.fire()
    as a non-empty string.  A non-empty descriptor proves the method+url+schema
    fields are folded into the body_hash (Spec C §5 / G7-2.5 C6).
    """
    raw_req = _make_raw_request()
    fired_response = _make_fired_response()
    ledger = _StubLedger()

    spy_client = _SpyRelayClient(outcome=fired_response, _ledger=ledger)
    staging = QuarantineStagingMap()
    recorder = T3BodyRecorder(nonce=authorized_t3_nonce, staging=staging)
    gate = make_quarantined_extract_chain_gate(
        grant_dereference_t3=True,
        dereference_plugin_id="alfred.quarantined-llm",
    )
    mock_extractor = AsyncMock()
    mock_extractor.extract = AsyncMock(return_value=_make_extracted("desc-test"))

    extractor_obj = EgressResponseExtractor(
        relay_client=spy_client,  # type: ignore[arg-type]
        gate=gate,
        extractor=mock_extractor,  # type: ignore[arg-type]
        recorder=recorder,
    )

    await extractor_obj.handle(
        raw_request=raw_req,
        ctx=_CTX,
        call_index=_CALL_INDEX,
        schema=_TestSchema,
        language="en",
    )

    assert len(spy_client.fire_calls) == 1, "fire() must be called exactly once"
    descriptor = spy_client.fire_calls[0].get("request_descriptor")
    assert descriptor, "request_descriptor must be a non-empty string passed to fire()"
    # It must be a 64-char sha256 hex digest.
    assert len(descriptor) == 64, f"expected 64-char hex digest, got {len(descriptor)}"
    assert all(c in "0123456789abcdef" for c in descriptor), (
        "request_descriptor must be lowercase hex"
    )


# ---------------------------------------------------------------------------
# Test 6 — C7 status: Fired outcome carries the upstream HTTP status; Deduplicated is None
# ---------------------------------------------------------------------------


async def test_fired_outcome_carries_upstream_http_status(
    authorized_t3_nonce: CapabilityGateNonce,
) -> None:
    """C7: A fresh Fired extraction surfaces EgressResponse.status on the outcome."""
    fake_status = 201
    fired = Fired(response=EgressResponse(status=fake_status, headers={}, body=b"body"))

    extractor_obj, _, _ = _make_extractor(
        relay_outcome=fired,
        extracted=_make_extracted("status-test"),
        authorized_nonce=authorized_t3_nonce,
    )

    result = await extractor_obj.handle(
        raw_request=_make_raw_request(),
        ctx=_CTX,
        call_index=_CALL_INDEX,
        schema=_TestSchema,
        language="en",
    )

    assert result.status == fake_status, (
        f"Expected outcome.status == {fake_status}, got {result.status!r}"
    )


async def test_replay_outcome_status_is_none(
    authorized_t3_nonce: CapabilityGateNonce,
) -> None:
    """C7: A Deduplicated (replay) outcome has status=None — original status not stored in ledger.

    The ledger persists only the post-extraction T2; the HTTP status code is absent.
    """
    stored_extracted = _make_extracted("replay-status")

    extractor_obj, _, _ = _make_extractor(
        relay_outcome=Deduplicated(stored_t2=stored_extracted.model_dump_json(), language="de"),
        authorized_nonce=authorized_t3_nonce,
    )

    result = await extractor_obj.handle(
        raw_request=_make_raw_request(),
        ctx=_CTX,
        call_index=_CALL_INDEX,
        schema=_TestSchema,
        language="en",
    )

    assert result.status is None, (
        f"Expected outcome.status is None on replay, got {result.status!r}"
    )
