"""Adversarial tier_laundering — cross-mode tier-downgrade (tl-2026-010).

Pins the structural invariants that prevent a mode-(b) T3 egress response
from acquiring T2 provenance without going through the gate-checked
``quarantined_to_structured()`` extractor path.

Design of the defence (§4.3 boundary invariants):

1. ``EgressResponse.body`` is ``bytes`` — it has no ``model_dump_json()`` /
   ExtractionResult shape.  Any attempt to cast / treat it as T2 is a
   structural type error caught at import/construction time.
2. ``EgressResponseExtractor.handle()`` on a ``Fired`` outcome ALWAYS routes
   through ``T3BodyRecorder`` → ``quarantined_to_structured()`` → ledger
   before returning an ``EgressExtractOutcome``.  The orchestrator receives
   ``EgressExtractOutcome.result``, which is ``ExtractionResult`` (typed T2).
   It NEVER sees ``outcome.response.body``.
3. ``EgressResponseExtractor.handle()`` on a ``Deduplicated`` outcome returns
   the stored T2 (already-extracted, already-ledgered) — the extractor is NOT
   called again (HARD rule #5).
4. A direct call to ``quarantined_to_structured()`` without a gate-authorised
   T3 content-clearance grant raises ``AlfredError`` (boundary_refused), proving
   the gate is the only crossing point.

PRD §7.1, Spec C §4.3, CLAUDE.md hard rules #1/#5.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
import yaml

from alfred.egress.egress_id import TurnEgressContext
from alfred.egress.egress_response_extract import EgressResponseExtractor
from alfred.egress.relay_client import Deduplicated, Fired
from alfred.egress.relay_protocol import EgressResponse, _RawToolRequest
from alfred.errors import AlfredError
from alfred.memory.egress_idempotency import IntentFresh
from alfred.security.quarantine import (
    ContentHandle,
    Extracted,
    ExtractionSchema,
    T3DerivedData,
    quarantined_to_structured,
)
from alfred.security.quarantine_transport import QuarantineStagingMap, T3BodyRecorder
from tests.adversarial.payload_schema import AdversarialPayload
from tests.helpers.gates import make_deny_all_gate, make_quarantined_extract_chain_gate

_PAYLOAD_PATH = Path(__file__).parent / "tl_cross_mode_tier_downgrade.yaml"


def _load_payload() -> AdversarialPayload:
    return AdversarialPayload.model_validate(yaml.safe_load(_PAYLOAD_PATH.read_text()))


def test_payload_schema_valid() -> None:
    """The corpus YAML validates and declares the boundary_refused shape."""
    payload = _load_payload()
    assert payload.id == "tl-2026-010"
    assert payload.category == "tier_laundering"
    assert payload.expected_outcome == "boundary_refused"
    assert payload.ingestion_path == "mcp.tool.output"


# ---------------------------------------------------------------------------
# Invariant 1: EgressResponse.body is bytes — not an ExtractionResult shape
# ---------------------------------------------------------------------------


def test_egress_response_body_is_bytes_not_extraction_result() -> None:
    """EgressResponse.body is bytes — it has no T2 ExtractionResult API.

    tl-2026-010 structural pin: the raw egress body has NO ``.model_dump_json()``
    / ``.data`` / ``.kind`` attributes.  Any caller that tried to use it as an
    ExtractionResult would get an AttributeError at the call site — the type
    system makes the bypass visible, not silent.  PRD §7.1.
    """
    response = EgressResponse(
        status=200,
        headers={},
        body=b'{"kind":"extracted","data":{"payload":"secret"},"extraction_mode":"native_constrained"}',
    )
    # The body is raw bytes — NOT an ExtractionResult.
    assert isinstance(response.body, bytes)
    # It has no ExtractionResult-shaped attributes.
    assert not hasattr(response.body, "model_dump_json")
    assert not hasattr(response.body, "data")
    assert not hasattr(response.body, "kind")


# ---------------------------------------------------------------------------
# Invariant 2: quarantined_to_structured gate denies without a T3 grant
# ---------------------------------------------------------------------------


class _TestSchema(ExtractionSchema):
    payload: str


@pytest.mark.asyncio
async def test_quarantined_to_structured_gate_denies_without_t3_grant(
    authorized_t3_nonce: Any,
) -> None:
    """quarantined_to_structured raises AlfredError without a T3 content grant.

    tl-2026-010 gate-check pin: the content-clearance check in
    ``quarantined_to_structured()`` uses the supplied ``gate``. A ``make_deny_all_gate()``
    denies EVERY check — including the T3 content-clearance — so the call raises.
    This proves the gate IS the single crossing point: no T3 content can become
    T2 without an authorised gate grant.  Spec C §4.3, HARD rule #1.
    """
    handle = ContentHandle(
        id="tl-010-handle-1",
        source_url="https://example.com/tool",
        fetch_timestamp=datetime.now(UTC),
    )
    deny_gate = make_deny_all_gate()
    mock_extractor = AsyncMock()
    mock_extractor.extract = AsyncMock(
        return_value=Extracted(
            data=T3DerivedData({"payload": "raw-t3-value"}),
            extraction_mode="native_constrained",
        )
    )

    with pytest.raises(AlfredError, match=r"quarantine\.dereference"):
        await quarantined_to_structured(
            handle,
            _TestSchema,
            extractor=mock_extractor,
            gate=deny_gate,
        )

    # The extractor was NOT called — the gate denied BEFORE extraction.
    mock_extractor.extract.assert_not_called()


# ---------------------------------------------------------------------------
# Invariant 3: EgressResponseExtractor on Fired always routes through extractor
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_egress_response_extractor_fired_path_never_returns_raw_body(
    authorized_t3_nonce: Any,
) -> None:
    """EgressResponseExtractor.handle(Fired) never returns raw body as T2.

    tl-2026-010 structural pin: the Fired path routes through T3BodyRecorder
    → quarantined_to_structured → record_response.  The orchestrator receives
    EgressExtractOutcome.result (ExtractionResult = T2), never EgressResponse.body.

    We verify by asserting:
    (a) the extractor was called (T3 crossed via the gate-checked boundary);
    (b) the returned outcome.result is the Extracted value from the extractor,
        NOT the raw body bytes;
    (c) outcome.deduplicated is False (fresh extraction).
    """
    # Set up the authorized nonce in the staging map.
    staging = QuarantineStagingMap()
    recorder = T3BodyRecorder(nonce=authorized_t3_nonce, staging=staging)
    gate = make_quarantined_extract_chain_gate(
        grant_dereference_t3=True,
        dereference_plugin_id="alfred.quarantined-llm",
    )

    raw_body = b"<html>raw T3 content from external tool</html>"
    expected_extraction = Extracted(
        data=T3DerivedData({"payload": "structured-t2-result"}),
        extraction_mode="native_constrained",
    )

    mock_extractor = AsyncMock()
    mock_extractor.extract = AsyncMock(return_value=expected_extraction)

    class _StubLedger:
        async def commit_intent(self, **_kw: Any) -> Any:
            return IntentFresh()

        async def record_response(self, **_kw: Any) -> None:
            return None

        async def get_state(self, **_kw: Any) -> str | None:
            return None

        async def prune_expired(self, **_kw: Any) -> int:
            return 0

    stub_ledger = _StubLedger()

    # Stub relay_client.fire() to return a Fired with raw T3 bytes.
    mock_relay_client = MagicMock()
    mock_relay_client.ledger = stub_ledger
    mock_relay_client.fire = AsyncMock(
        return_value=Fired(
            response=EgressResponse(
                status=200,
                headers={"content-type": "text/html"},
                body=raw_body,
            )
        )
    )

    extractor_obj = EgressResponseExtractor(
        relay_client=mock_relay_client,  # type: ignore[arg-type]
        gate=gate,
        extractor=mock_extractor,
        recorder=recorder,
    )

    ctx = TurnEgressContext(adapter_id="ada-tl010", inbound_id="in-tl010", session_id="s-tl010")
    raw_request = _RawToolRequest(
        method="GET",
        url="https://example.com/tool",
        headers={},
        body="safe-body",
        idempotent=True,
    )

    outcome = await extractor_obj.handle(
        raw_request=raw_request,
        ctx=ctx,
        call_index=0,
        schema=_TestSchema,
        language="en",
    )

    # (a) The extractor was called — T3 crossed via gate-checked boundary.
    mock_extractor.extract.assert_called_once()

    # (b) The outcome carries the typed ExtractionResult, NOT the raw body.
    assert isinstance(outcome.result, Extracted), (
        "Outcome.result must be an Extracted instance from the extractor"
    )
    assert outcome.result.extraction_mode == "native_constrained"
    assert outcome.result.data["payload"] == "structured-t2-result"  # type: ignore[index]
    # The raw body bytes are NOT reachable from the outcome.
    assert not hasattr(outcome.result, "body")

    # (c) Fresh extraction, not deduplicated.
    assert outcome.deduplicated is False


# ---------------------------------------------------------------------------
# Invariant 4: Deduplicated path returns stored T2, never calls extractor
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_egress_response_extractor_deduplicated_path_skips_extractor(
    authorized_t3_nonce: Any,
) -> None:
    """EgressResponseExtractor.handle(Deduplicated) returns stored T2 without re-extraction.

    tl-2026-010 HARD rule #5 pin: a Deduplicated relay outcome carries the
    already-extracted T2 string (model_dump_json() of a prior ExtractionResult).
    The extractor is NOT called again — re-entering the raw-T3 ingestion path
    is forbidden.  The orchestrator receives the deserialised ExtractionResult,
    NOT the raw body from the prior call.
    """
    staging = QuarantineStagingMap()
    recorder = T3BodyRecorder(nonce=authorized_t3_nonce, staging=staging)
    gate = make_quarantined_extract_chain_gate(
        grant_dereference_t3=True,
        dereference_plugin_id="alfred.quarantined-llm",
    )

    stored_extraction = Extracted(
        data=T3DerivedData({"payload": "already-extracted-t2"}),
        extraction_mode="native_constrained",
    )
    stored_t2_json = stored_extraction.model_dump_json()

    mock_extractor = AsyncMock()
    mock_extractor.extract = AsyncMock(
        side_effect=AssertionError("extractor must NOT be called on Deduplicated path")
    )

    class _StubLedger:
        async def commit_intent(self, **_kw: Any) -> Any:
            return IntentFresh()

        async def record_response(self, **_kw: Any) -> None:
            return None

        async def get_state(self, **_kw: Any) -> str | None:
            return None

        async def prune_expired(self, **_kw: Any) -> int:
            return 0

    stub_ledger = _StubLedger()
    mock_relay_client = MagicMock()
    mock_relay_client.ledger = stub_ledger
    mock_relay_client.fire = AsyncMock(
        return_value=Deduplicated(stored_t2=stored_t2_json, language="en")
    )

    extractor_obj = EgressResponseExtractor(
        relay_client=mock_relay_client,  # type: ignore[arg-type]
        gate=gate,
        extractor=mock_extractor,
        recorder=recorder,
    )

    ctx = TurnEgressContext(
        adapter_id="ada-tl010-d", inbound_id="in-tl010-d", session_id="s-tl010-d"
    )
    raw_request = _RawToolRequest(
        method="GET",
        url="https://example.com/tool",
        headers={},
        body="safe-body",
        idempotent=True,
    )

    outcome = await extractor_obj.handle(
        raw_request=raw_request,
        ctx=ctx,
        call_index=0,
        schema=_TestSchema,
        language="en",
    )

    # The extractor was NOT called (the AssertionError side_effect would have fired).
    mock_extractor.extract.assert_not_called()

    # The outcome carries the stored T2 (deserialised ExtractionResult).
    assert outcome.deduplicated is True
    assert isinstance(outcome.result, Extracted)
    assert outcome.result.data["payload"] == "already-extracted-t2"  # type: ignore[index]
