"""Executable counterpart to ``de_egress_inbound_canary_unwired.yaml`` (de-2026-012).

The web.fetch INBOUND egress-response canary scan is BUILT
(``ResponsePolicy.canary`` → ``response_inspection.inspect_response`` →
``_CanaryHit`` → ``InboundCanaryTripped``) and, as of #339 PR4a, WIRED:
``build_web_fetch_egress_extractor`` derives a non-``None`` ``CanaryMatcher``
from ``settings.web_fetch_canary_tokens`` (``ALFRED_WEB_FETCH_CANARY_TOKENS``,
the core-side token source #339 PR4a introduced) unless an explicit ``canary``
is passed. A LIVE web.fetch caller now trips on a canary token reflected in the
upstream RESPONSE.

This file used to carry the alfred-security-engineer-signed-off tracked
residual for PR #339 (#347 obligation list) as a
``@pytest.mark.xfail(strict=True)`` stub — an explicit **merge-blocker on PR
#339**. #339 PR4a converts that stub into three real tests:

1. ``test_inbound_canary_reflected_response_trips`` — the core conversion: a
   seeded canary reflected in the response trips ``InboundCanaryTripped``
   before the quarantined extractor is ever awaited.
2. ``test_factory_wires_non_none_canary_from_settings`` — a wiring guard on
   the actual merge-blocker subject: the FACTORY (not just the seam) derives a
   non-``None`` canary from settings. A future regression back to
   ``canary=None`` fails here, not just in the seam-level test above.
3. ``test_armed_canary_benign_body_does_not_trip`` — false-positive guard: an
   armed matcher over a benign body (that carries the ``Content-Type`` header
   the MIME check requires) does NOT trip, and the quarantined extractor IS
   reached.

Distinct from de-2026-008 (the OUTBOUND canary on the gateway relay's stage-3
DLP scan of the REQUEST body — wired and tripping). This entry is the INBOUND
reflection seam on the RESPONSE side.

CLAUDE.md security rule #7: a canary trip is loud, never fail-open.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final
from unittest.mock import AsyncMock, Mock

import pytest
import yaml

from alfred.config.settings import Settings
from alfred.egress.egress_id import TurnEgressContext
from alfred.egress.egress_response_extract import EgressResponseExtractor
from alfred.egress.relay_client import Fired
from alfred.egress.relay_protocol import EgressResponse, _RawToolRequest
from alfred.egress.response_inspection import InboundCanaryTripped, ResponsePolicy
from alfred.memory.egress_idempotency import CommitIntentResult, IntentFresh
from alfred.plugins.web_fetch.assembly import build_web_fetch_egress_extractor
from alfred.security.canary_matcher import CanaryMatcher, CanaryToken
from alfred.security.quarantine import Extracted, ExtractionSchema, T3DerivedData
from alfred.security.quarantine_transport import QuarantineStagingMap, T3BodyRecorder
from alfred.security.tiers import CapabilityGateNonce
from tests.adversarial.payload_schema import AdversarialPayload
from tests.helpers.gates import make_quarantined_extract_chain_gate

_PAYLOAD_PATH: Final[Path] = Path(__file__).parent / "de_egress_inbound_canary_unwired.yaml"

# A relay URL the factory accepts so construction reaches the ResponsePolicy build
# (the fail-closed unset-URL branch refuses before the policy is assembled).
_RELAY_URL: Final[str] = "tcp://127.0.0.1:8890"

# Shared turn-egress context + call index for the seam-level tests (1 and 3).
_CTX: Final[TurnEgressContext] = TurnEgressContext(
    adapter_id="ada-cn", inbound_id="in-cn", session_id="sess-cn"
)
_CALL_INDEX: Final[int] = 0

# The seeded canary token every test in this file uses — reused (not
# per-test-random) so the wiring guard (test 2) and the seam tests (1, 3) can
# assert against the SAME literal value.
_CANARY_TOKEN: Final[str] = "ALFRED-CANARY-TEST-TOKEN-8675309"  # noqa: S105 -- canary sentinel, not a credential


def _load_payload() -> AdversarialPayload:
    return AdversarialPayload.model_validate(yaml.safe_load(_PAYLOAD_PATH.read_text()))


class _TestSchema(ExtractionSchema):
    """Minimal extraction schema for de-2026-012 adversarial corpus tests."""

    payload: str


@dataclass
class _StubLedger:
    """Fake EgressIdempotencyStore — captures record_response calls for assertions.

    Independent of the sibling ``test_egress_no_orphan_and_inflight.py`` copy
    (this file defines its own so the two adversarial entries never share
    mutable state), but structurally identical.
    """

    record_calls: list[dict[str, Any]] = field(default_factory=list)

    async def commit_intent(self, **_kwargs: Any) -> CommitIntentResult:
        return IntentFresh()

    async def record_response(self, *, egress_id: str, response: str, language: str | None) -> None:
        self.record_calls.append(
            {"egress_id": egress_id, "response": response, "language": language}
        )

    async def get_state(self, **_kwargs: Any) -> str | None:
        return None

    async def prune_expired(self, **_kwargs: Any) -> int:
        return 0


# ---------------------------------------------------------------------------
# Test 1 — corpus schema validation + the (now-satisfied) conversion record
# ---------------------------------------------------------------------------


def test_payload_schema_valid() -> None:
    """Corpus YAML is well-formed and records the de-2026-012 CONVERSION (not a pending obligation).

    #339 PR4a wired a non-None ``ResponsePolicy.canary`` and converted the
    strict-xfail stub into the three real tests below — ``merge_blocker`` is
    now ``False`` and ``converted_in`` machine-records which PR closed it.
    """
    payload = _load_payload()
    assert payload.id == "de-2026-012"
    assert payload.category == "dlp_egress"
    assert payload.ingestion_path == "web.fetch"
    assert payload.expected_outcome == "caught_by_dlp"
    assert isinstance(payload.payload, dict)
    deferred = payload.payload.get("deferred_property", {})
    assert isinstance(deferred, dict)
    assert deferred.get("id") == "inbound_response_canary_scan"
    assert deferred.get("merge_blocker") is False
    assert deferred.get("converted_in") == "PR #339 PR4a"


# ---------------------------------------------------------------------------
# Test 2 — reflected-canary trip (the core conversion)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_inbound_canary_reflected_response_trips(
    authorized_t3_nonce: CapabilityGateNonce,
) -> None:
    """A seeded canary token reflected in the fetched RESPONSE trips InboundCanaryTripped.

    Converts the de-2026-012 merge-blocker (#347 blocker 5): #339 PR4a wires a
    non-None ResponsePolicy.canary. Asserts handle() raises InboundCanaryTripped
    (loud, HARD #7), the quarantined extractor is NEVER awaited (canary is
    pre-extract, HARD #5), and a terminal refused_by_safety refusal was recorded.
    """

    class _ReflectingRelay:
        """Relay double whose upstream response reflects the seeded canary token."""

        def __init__(self, ledger: _StubLedger) -> None:
            self._ledger = ledger

        @property
        def ledger(self) -> _StubLedger:
            return self._ledger

        async def fire(self, **_kwargs: object) -> Fired:
            body = f"upstream page reflecting {_CANARY_TOKEN} back".encode()
            return Fired(response=EgressResponse(status=200, headers={}, body=body))

    ledger = _StubLedger()
    staging = QuarantineStagingMap()
    recorder = T3BodyRecorder(nonce=authorized_t3_nonce, staging=staging)
    gate = make_quarantined_extract_chain_gate(
        grant_dereference_t3=True, dereference_plugin_id="alfred.quarantined-llm"
    )
    mock_extractor = AsyncMock()
    mock_extractor.extract = AsyncMock()  # must NOT be reached (canary is pre-extract)

    policy = ResponsePolicy(
        mime_allowlist=frozenset({"text/html", "text/plain"}),
        max_bytes=5 * 1024 * 1024,
        canary=CanaryMatcher(tokens=[CanaryToken(_CANARY_TOKEN)]),
    )
    extractor_obj = EgressResponseExtractor(
        relay_client=_ReflectingRelay(ledger),  # type: ignore[arg-type]
        gate=gate,
        extractor=mock_extractor,
        recorder=recorder,
        response_policy=policy,
    )
    raw_req = _RawToolRequest(
        method="GET", url="https://example.com/", headers={}, body="", idempotent=True
    )
    with pytest.raises(InboundCanaryTripped):
        await extractor_obj.handle(
            raw_request=raw_req,
            ctx=_CTX,
            call_index=_CALL_INDEX,
            schema=_TestSchema,
            language="en",
        )
    mock_extractor.extract.assert_not_awaited()
    assert ledger.record_calls, "canary trip must record a terminal ledger refusal"
    assert "refused_by_safety" in ledger.record_calls[-1]["response"]
    assert len(staging._staged) == 0, (
        "No-orphan BREACH (canary trip): staging map non-empty — a T3 body "
        f"must never survive a canary-tripped handle(): {staging._staged!r}"
    )


# ---------------------------------------------------------------------------
# Test 3 — factory-wiring guard (guards the actual merge-blocker subject)
# ---------------------------------------------------------------------------


def test_factory_wires_non_none_canary_from_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    """de-2026-012 WIRING guard: the FACTORY derives a non-None canary from settings.

    ``build_web_fetch_egress_extractor`` MUST thread a real ``CanaryMatcher``
    (``canary != None``) before a live caller merges — a future regression
    back to ``canary=None`` fails HERE, not just in the seam-level test above
    (which constructs its own ``ResponsePolicy`` and would stay green even if
    the factory regressed).
    """
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-test")
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.delenv("ALFRED_EGRESS_RELAY_URL", raising=False)

    # Inert daemon-graph doubles — the factory only STORES these at construction;
    # none are invoked while assembling the ResponsePolicy. Erased to dict[str, Any]
    # (mirrors tests/unit/plugins/web_fetch/test_assembly.py::_collaborators and the
    # old xfail stub this test replaces) so mypy does not check the fake
    # ``session_scope=lambda: None`` against the real
    # ``Callable[[], AbstractAsyncContextManager[AsyncSession]]`` signature — it is
    # never invoked at construction time, only stored.
    collaborator: dict[str, Any] = {
        "gate": Mock(name="gate"),
        "extractor": Mock(name="extractor"),
        "recorder": Mock(name="recorder"),
        "outbound_dlp": Mock(name="outbound_dlp"),
        "audit_writer": Mock(name="audit_writer"),
        "session_scope": lambda: None,
    }
    assembled = build_web_fetch_egress_extractor(
        settings=Settings(egress_relay_url=_RELAY_URL, web_fetch_canary_tokens=(_CANARY_TOKEN,)),
        gate=collaborator["gate"],
        extractor=collaborator["extractor"],
        recorder=collaborator["recorder"],
        outbound_dlp=collaborator["outbound_dlp"],
        audit_writer=collaborator["audit_writer"],
        session_scope=collaborator["session_scope"],
    )
    policy = assembled._response_policy
    assert policy is not None
    assert policy.canary is not None
    assert policy.canary.first_match(_CANARY_TOKEN) == _CANARY_TOKEN


# ---------------------------------------------------------------------------
# Test 4 — armed canary + benign body → NO trip (false-positive guard)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_armed_canary_benign_body_does_not_trip(
    authorized_t3_nonce: CapabilityGateNonce,
) -> None:
    """Armed matcher + benign body → NO trip, extractor reached (false-positive guard).

    CRITICAL: inspect_response runs canary FIRST, MIME SECOND. The response MUST
    carry Content-Type: text/html, else the missing-MIME soft-refusal short-circuits
    before the extractor and 'extract awaited' would be vacuous.
    """

    class _BenignRelay:
        """Relay double whose upstream response never mentions the canary token."""

        def __init__(self, ledger: _StubLedger) -> None:
            self._ledger = ledger

        @property
        def ledger(self) -> _StubLedger:
            return self._ledger

        async def fire(self, **_kwargs: object) -> Fired:
            return Fired(
                response=EgressResponse(
                    status=200,
                    headers={"content-type": "text/html"},
                    body=b"benign page, no token here",
                )
            )

    ledger = _StubLedger()
    staging = QuarantineStagingMap()
    recorder = T3BodyRecorder(nonce=authorized_t3_nonce, staging=staging)
    gate = make_quarantined_extract_chain_gate(
        grant_dereference_t3=True, dereference_plugin_id="alfred.quarantined-llm"
    )
    mock_extractor = AsyncMock()
    mock_extractor.extract = AsyncMock(
        return_value=Extracted(
            data=T3DerivedData({"payload": "ok"}), extraction_mode="native_constrained"
        )
    )
    policy = ResponsePolicy(
        mime_allowlist=frozenset({"text/html", "text/plain"}),
        max_bytes=5 * 1024 * 1024,
        canary=CanaryMatcher(tokens=[CanaryToken(_CANARY_TOKEN)]),
    )
    extractor_obj = EgressResponseExtractor(
        relay_client=_BenignRelay(ledger),  # type: ignore[arg-type]
        gate=gate,
        extractor=mock_extractor,
        recorder=recorder,
        response_policy=policy,
    )
    raw_req = _RawToolRequest(
        method="GET", url="https://example.com/", headers={}, body="", idempotent=True
    )
    outcome = await extractor_obj.handle(
        raw_request=raw_req,
        ctx=_CTX,
        call_index=_CALL_INDEX,
        schema=_TestSchema,
        language="en",
    )
    mock_extractor.extract.assert_awaited_once()
    # No canary exception raised; the extracted T2 came back.
    assert isinstance(outcome.result, Extracted)
