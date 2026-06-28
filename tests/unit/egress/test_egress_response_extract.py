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

import asyncio
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
from alfred.egress.response_inspection import (
    InboundCanaryTripped,
    ResponsePolicy,
)
from alfred.errors import AlfredError
from alfred.memory.egress_idempotency import CommitIntentResult, IntentFresh
from alfred.security import tiers as _tiers
from alfred.security.canary_matcher import CanaryMatcher, CanaryToken
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

    # Fix 1: policy_refusal_token is None on a successful extraction (no D1 refusal).
    assert result.policy_refusal_token is None


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

    # Fix 1: policy_refusal_token is None on a deduplicated replay (no D1 refusal).
    assert result.policy_refusal_token is None


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
    # CR-11 / CR-cloud-12: assert the EXACT descriptor handle() computes — folded
    # from method + url + schema identity — not merely the sha256 SHAPE. A
    # shape-only check would pass even if handle() folded the wrong fields.
    from alfred.egress.egress_id import compute_request_descriptor
    from alfred.egress.egress_response_extract import _schema_identity

    expected_descriptor = compute_request_descriptor(
        method=raw_req.method,
        url=raw_req.url,
        schema_id=_schema_identity(_TestSchema),
    )
    assert descriptor == expected_descriptor


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


# ---------------------------------------------------------------------------
# Test 8 — C9 gate-denial no-orphan: staging map is empty after AlfredError
# ---------------------------------------------------------------------------


async def test_gate_denial_leaves_no_orphaned_body(
    authorized_t3_nonce: CapabilityGateNonce,
) -> None:
    """C9: A gate denial raises AlfredError AND leaves no orphaned body in the staging map.

    Before the fix, ``self._recorder(handle=handle, body=...)`` staged the T3 body and
    then ``quarantined_to_structured`` raised ``AlfredError`` (gate-first deny) before
    the extractor's transport could drain it.  The staged ``TaggedContent[T3]`` would
    then orphan in the unbounded ``QuarantineStagingMap`` for process lifetime.

    After the fix, the ``except BaseException`` wrapper in ``handle()`` calls
    ``self._recorder.discard_staged(handle.id)`` so the map is empty on exit.
    """
    relay_client = _StubRelayClient(outcome=_make_fired_response())
    staging = QuarantineStagingMap()
    recorder = T3BodyRecorder(nonce=authorized_t3_nonce, staging=staging)
    gate = make_deny_all_gate()
    mock_extractor = AsyncMock()
    mock_extractor.extract = AsyncMock()

    extractor_obj = EgressResponseExtractor(
        relay_client=relay_client,  # type: ignore[arg-type]
        gate=gate,
        extractor=mock_extractor,  # type: ignore[arg-type]
        recorder=recorder,
    )

    with pytest.raises(AlfredError):
        await extractor_obj.handle(
            raw_request=_make_raw_request(),
            ctx=_CTX,
            call_index=_CALL_INDEX,
            schema=_TestSchema,
            language=None,
        )

    # No orphaned body — the staging map must be empty after the gate denial (C9).
    assert len(staging._staged) == 0, (
        f"Orphaned body detected: staging map is not empty after gate denial: {staging._staged!r}"
    )


# ---------------------------------------------------------------------------
# Test 9 — C9 cancellation no-orphan: staging map is empty after CancelledError
# ---------------------------------------------------------------------------


async def test_cancelled_error_leaves_no_orphaned_body(
    authorized_t3_nonce: CapabilityGateNonce,
) -> None:
    """C9: A CancelledError mid-quarantined_to_structured leaves no orphaned body.

    This covers the Task 6 action-deadline path: the deadline cancels the
    ``handle()`` coroutine AFTER ``self._recorder(...)`` has staged the T3 body but
    BEFORE the extractor's transport drains it.  A bare ``except Exception`` would
    NOT catch ``CancelledError`` (it is a ``BaseException`` subclass, not an
    ``Exception`` subclass), so the orphan would escape.  The fix uses
    ``except BaseException`` so the discard fires on cancellation too.
    """
    relay_client = _StubRelayClient(outcome=_make_fired_response())
    staging = QuarantineStagingMap()
    recorder = T3BodyRecorder(nonce=authorized_t3_nonce, staging=staging)
    gate = make_quarantined_extract_chain_gate(
        grant_dereference_t3=True,
        dereference_plugin_id="alfred.quarantined-llm",
    )
    mock_extractor = AsyncMock()
    # Simulate the action-deadline cancellation landing inside the extractor.
    mock_extractor.extract = AsyncMock(side_effect=asyncio.CancelledError())

    extractor_obj = EgressResponseExtractor(
        relay_client=relay_client,  # type: ignore[arg-type]
        gate=gate,
        extractor=mock_extractor,  # type: ignore[arg-type]
        recorder=recorder,
    )

    with pytest.raises(asyncio.CancelledError):
        await extractor_obj.handle(
            raw_request=_make_raw_request(),
            ctx=_CTX,
            call_index=_CALL_INDEX,
            schema=_TestSchema,
            language=None,
        )

    # No orphaned body — the staging map must be empty after the CancelledError (C9).
    assert len(staging._staged) == 0, (
        "Orphaned body detected: staging map is not empty after CancelledError:"
        f" {staging._staged!r}"
    )


# ---------------------------------------------------------------------------
# Test 10 — D1 soft refusal: disallowed MIME → TypedRefusal; extractor not called
# ---------------------------------------------------------------------------


def _make_response_policy(
    *,
    mime_allowlist: frozenset[str] | None = None,
    max_bytes: int = 10 * 1024 * 1024,
    canary: CanaryMatcher | None = None,
) -> ResponsePolicy:
    # CR-9: explicit ``is None`` rather than ``mime_allowlist or ...`` — an
    # intentionally-empty ``frozenset()`` (a valid "allow nothing" policy) is falsy
    # and the ``or`` form would silently swap in the default, masking the test.
    if mime_allowlist is None:
        mime_allowlist = frozenset({"text/html", "text/plain", "application/json"})
    return ResponsePolicy(
        mime_allowlist=mime_allowlist,
        max_bytes=max_bytes,
        canary=canary,
    )


async def test_d1_disallowed_mime_returns_soft_refusal_extractor_not_called(
    authorized_t3_nonce: CapabilityGateNonce,
) -> None:
    """D1: a Fired response with an disallowed MIME type returns TypedRefusal(cannot_extract).

    The extractor is NOT called and the ledger row is committed_with_response
    (replay returns Deduplicated, no re-fetch).
    """
    raw_body = b"binary content"
    fired = Fired(
        response=EgressResponse(
            status=200,
            headers={"Content-Type": "application/octet-stream"},
            body=raw_body,
        )
    )
    relay_client = _StubRelayClient(outcome=fired)
    staging = QuarantineStagingMap()
    recorder = T3BodyRecorder(nonce=authorized_t3_nonce, staging=staging)
    gate = make_quarantined_extract_chain_gate(
        grant_dereference_t3=True,
        dereference_plugin_id="alfred.quarantined-llm",
    )
    mock_extractor = AsyncMock()
    spy_extract = mock_extractor.extract = AsyncMock()

    extractor_obj = EgressResponseExtractor(
        relay_client=relay_client,  # type: ignore[arg-type]
        gate=gate,
        extractor=mock_extractor,  # type: ignore[arg-type]
        recorder=recorder,
        response_policy=_make_response_policy(),
    )

    outcome = await extractor_obj.handle(
        raw_request=_make_raw_request(),
        ctx=_CTX,
        call_index=_CALL_INDEX,
        schema=_TestSchema,
        language="en",
    )

    # Extractor must NOT be called (soft refusal before extraction).
    spy_extract.assert_not_called()

    # Result is TypedRefusal(reason="cannot_extract") — structural T2.
    assert isinstance(outcome.result, TypedRefusal)
    assert outcome.result.reason == "cannot_extract"
    assert outcome.deduplicated is False
    assert outcome.status == 200

    # Ledger received record_response (row is now committed_with_response).
    assert len(relay_client.ledger.record_calls) == 1
    rec = relay_client.ledger.record_calls[0]
    assert rec["language"] == "en"

    # Attacker-controlled Content-Type MUST NOT appear in the stored refusal value.
    assert "application/octet-stream" not in rec["response"]
    assert raw_body.decode("latin-1") not in rec["response"]

    # CR-cloud-13: a D1 soft refusal returns BEFORE minting a ContentHandle /
    # staging the T3 body, so NO raw T3 body is staged — nothing can orphan.
    assert len(staging._staged) == 0, (
        f"D1 refusal must stage no T3 body; staging map non-empty: {staging._staged!r}"
    )

    # Fix 1: policy_refusal_token surfaces the D1 subject token for Task 6 auditing.
    assert outcome.policy_refusal_token == "mime_type_not_allowed"  # noqa: S105 — audit token, not a credential


# ---------------------------------------------------------------------------
# Test 10b — D1 soft refusal: size limit exceeded → size_limit_exceeded token
# ---------------------------------------------------------------------------


async def test_d1_size_limit_exceeded_returns_size_token(
    authorized_t3_nonce: CapabilityGateNonce,
) -> None:
    """D1: a Fired response whose body exceeds max_bytes returns TypedRefusal(cannot_extract)
    with policy_refusal_token="size_limit_exceeded".
    """
    large_body = b"x" * 100
    fired = Fired(
        response=EgressResponse(
            status=200,
            headers={"Content-Type": "text/plain"},
            body=large_body,
        )
    )
    relay_client = _StubRelayClient(outcome=fired)
    staging = QuarantineStagingMap()
    recorder = T3BodyRecorder(nonce=authorized_t3_nonce, staging=staging)
    gate = make_quarantined_extract_chain_gate(
        grant_dereference_t3=True,
        dereference_plugin_id="alfred.quarantined-llm",
    )
    mock_extractor = AsyncMock()
    spy_extract = mock_extractor.extract = AsyncMock()

    # Set max_bytes to 50 — the 100-byte body exceeds it.
    policy = _make_response_policy(max_bytes=50)

    extractor_obj = EgressResponseExtractor(
        relay_client=relay_client,  # type: ignore[arg-type]
        gate=gate,
        extractor=mock_extractor,  # type: ignore[arg-type]
        recorder=recorder,
        response_policy=policy,
    )

    outcome = await extractor_obj.handle(
        raw_request=_make_raw_request(),
        ctx=_CTX,
        call_index=_CALL_INDEX,
        schema=_TestSchema,
        language="en",
    )

    spy_extract.assert_not_called()
    assert isinstance(outcome.result, TypedRefusal)
    assert outcome.result.reason == "cannot_extract"
    assert outcome.policy_refusal_token == "size_limit_exceeded"  # noqa: S105 — audit token, not a credential


# ---------------------------------------------------------------------------
# Test 11 — D1 canary hit: InboundCanaryTripped raised; ledger has refused_by_safety FIRST
# ---------------------------------------------------------------------------


async def test_d1_canary_hit_raises_inbound_canary_tripped_after_ledger_write(
    authorized_t3_nonce: CapabilityGateNonce,
) -> None:
    """D1: a canary token in the response body raises InboundCanaryTripped AFTER ledger write.

    C8 invariant: the ledger row must be committed_with_response(refused_by_safety)
    BEFORE the raise, so a §5 replay returns Deduplicated and never re-fires.
    """
    canary_token = "CANARY-UNIT-TEST-XYZ"  # noqa: S105
    canary_matcher = CanaryMatcher(tokens=[CanaryToken(value=canary_token)])
    policy = _make_response_policy(canary=canary_matcher)

    fired = Fired(
        response=EgressResponse(
            status=200,
            headers={"Content-Type": "text/html"},
            body=f"<html>contains {canary_token}</html>".encode(),
        )
    )
    relay_client = _StubRelayClient(outcome=fired)
    staging = QuarantineStagingMap()
    recorder = T3BodyRecorder(nonce=authorized_t3_nonce, staging=staging)
    gate = make_quarantined_extract_chain_gate(
        grant_dereference_t3=True,
        dereference_plugin_id="alfred.quarantined-llm",
    )
    mock_extractor = AsyncMock()
    spy_extract = mock_extractor.extract = AsyncMock()

    extractor_obj = EgressResponseExtractor(
        relay_client=relay_client,  # type: ignore[arg-type]
        gate=gate,
        extractor=mock_extractor,  # type: ignore[arg-type]
        recorder=recorder,
        response_policy=policy,
    )

    with pytest.raises(InboundCanaryTripped) as exc_info:
        await extractor_obj.handle(
            raw_request=_make_raw_request(url="https://hostile.example.com/data"),
            ctx=_CTX,
            call_index=_CALL_INDEX,
            schema=_TestSchema,
            language="en",
        )

    # Extractor MUST NOT be called.
    spy_extract.assert_not_called()

    # C8: ledger record_response was called BEFORE the raise.
    assert len(relay_client.ledger.record_calls) == 1
    rec = relay_client.ledger.record_calls[0]
    # The stored value is TypedRefusal(reason="refused_by_safety") — terminal.
    assert "refused_by_safety" in rec["response"]
    assert rec["language"] == "en"

    # Exception is payload-blind: carries destination + egress_id; no body content.
    exc = exc_info.value
    assert exc.destination == "hostile.example.com"
    assert exc.reason == "inbound_canary_tripped"
    assert canary_token not in str(exc)  # payload-blind: token not in message


# ---------------------------------------------------------------------------
# Test 12 — D1 no policy: response_policy=None → seam skipped entirely
# ---------------------------------------------------------------------------


async def test_d1_no_policy_seam_skipped(
    authorized_t3_nonce: CapabilityGateNonce,
) -> None:
    """With response_policy=None, the D1 seam is skipped and extraction proceeds normally."""
    extracted = _make_extracted("no-policy-payload")
    fired = Fired(
        response=EgressResponse(
            status=200,
            headers={"Content-Type": "application/octet-stream"},  # would be refused with a policy
            body=b"binary-body",
        )
    )
    extractor_obj, _ledger, spy_extract = _make_extractor(
        relay_outcome=fired,
        extracted=extracted,
        authorized_nonce=authorized_t3_nonce,
        # response_policy defaults to None → seam skipped
    )

    outcome = await extractor_obj.handle(
        raw_request=_make_raw_request(),
        ctx=_CTX,
        call_index=_CALL_INDEX,
        schema=_TestSchema,
        language="en",
    )

    # Extractor ran normally (seam was not invoked).
    spy_extract.assert_awaited_once()
    assert outcome.deduplicated is False
    assert isinstance(outcome.result, Extracted)


# ---------------------------------------------------------------------------
# Test 13 — D1 _Proceed: policy set but verdict passes → extraction runs
# ---------------------------------------------------------------------------


async def test_d1_proceed_verdict_falls_through_to_extraction(
    authorized_t3_nonce: CapabilityGateNonce,
) -> None:
    """D1: when response_policy is set and inspection returns _Proceed, extraction runs normally."""
    extracted = _make_extracted("d1-proceed-payload")
    fired = Fired(
        response=EgressResponse(
            status=200,
            headers={"Content-Type": "text/html"},  # allowed MIME
            body=b"hello world",  # under default max_bytes; no canary
        )
    )
    relay_client = _StubRelayClient(outcome=fired)
    staging = QuarantineStagingMap()
    recorder = T3BodyRecorder(nonce=authorized_t3_nonce, staging=staging)
    gate = make_quarantined_extract_chain_gate(
        grant_dereference_t3=True,
        dereference_plugin_id="alfred.quarantined-llm",
    )
    mock_extractor = AsyncMock()
    spy_extract = mock_extractor.extract = AsyncMock(return_value=extracted)

    extractor_obj = EgressResponseExtractor(
        relay_client=relay_client,  # type: ignore[arg-type]
        gate=gate,
        extractor=mock_extractor,  # type: ignore[arg-type]
        recorder=recorder,
        response_policy=_make_response_policy(),  # policy is set; verdict will be _Proceed
    )

    outcome = await extractor_obj.handle(
        raw_request=_make_raw_request(),
        ctx=_CTX,
        call_index=_CALL_INDEX,
        schema=_TestSchema,
        language="en",
    )

    # Extraction proceeded normally after the _Proceed verdict.
    spy_extract.assert_awaited_once()
    assert outcome.deduplicated is False
    assert isinstance(outcome.result, Extracted)
    assert outcome.result == extracted
