"""Executable counterpart to ``egress_inflight_and_no_orphan.yaml`` (de-2026-004).

Re-targeted from ``test_handle_cap_exhaustion.py`` (de-2026-004, pre-G7-2.5) when
the per-user ContentHandle cap was removed from the fused fetch+extract path. The
original de-2026-004 proved an ACTIVE per-user resource-exhaustion REFUSAL bound
(handle_cap=5 → 6th concurrent call refused with
``WebFetchRateLimited(bucket='handle_cap')`` BEFORE the plugin call). That property
is DEFERRED to PR #339 (needs the real turn-user the C1 global semaphore lacks; no
production caller until after G7-3) and is machine-visible here as a
``@pytest.mark.xfail(strict=True)`` stub that is an explicit **merge-blocker on
PR #339**.

Two properties exercised here — both are release-blocking:

(a) **No-orphan (C9)** — a gate-denied or cancelled egress fetch must not leave a
    raw T3 body alive in the unbounded ``QuarantineStagingMap``:

    * Gate-deny path: ``make_deny_all_gate()`` causes
      ``quarantined_to_structured`` to raise ``AlfredError`` at the gate-first
      check, before the extractor runs.  The ``except BaseException:`` block in
      ``EgressResponseExtractor.handle()`` calls ``discard_staged(handle.id)``
      → the staging map is empty after the raise.
    * Cancellation path: ``CancelledError`` injected at ``extractor.extract()``
      (simulating Task 6's action-deadline) propagates through the same
      ``except BaseException:`` block → staging map empty after the raise.
      A bare ``except Exception:`` would NOT catch ``CancelledError`` (it is a
      ``BaseException`` subclass), so the orphan would escape without the fix.

(b) **In-flight liveness (C1)** — two concurrent ``handle()`` calls serialise
    through the shared single quarantine child without deadlock: both complete
    within ``_LIVENESS_DEADLINE_S``.  A ``TimeoutError`` from
    ``asyncio.wait_for`` is a FAIL, not a skip.  This test is entirely
    in-process (no Postgres, no Docker) so it completes in milliseconds.

The unit-level proofs of (a) live in
``tests/unit/egress/test_egress_response_extract.py`` tests 8 and 9.  The full-
stack integration proof of (b) lives in
``tests/integration/egress/test_quarantine_contention.py``.  This file is the
**adversarial corpus anchor** — CI MUST keep these green.

CLAUDE.md security rule #7: no silent failures in security paths.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

import pytest
import yaml

from alfred.egress.egress_id import TurnEgressContext
from alfred.egress.egress_response_extract import EgressResponseExtractor
from alfred.egress.relay_client import Fired
from alfred.egress.relay_protocol import EgressResponse, _RawToolRequest
from alfred.errors import AlfredError
from alfred.memory.egress_idempotency import CommitIntentResult, IntentFresh
from alfred.security.quarantine import (
    Extracted,
    ExtractionSchema,
    T3DerivedData,
)
from alfred.security.quarantine_transport import QuarantineStagingMap, T3BodyRecorder
from alfred.security.tiers import CapabilityGateNonce
from tests.adversarial.payload_schema import AdversarialPayload
from tests.helpers.gates import make_deny_all_gate, make_quarantined_extract_chain_gate

_PAYLOAD_PATH: Final[Path] = Path(__file__).parent / "egress_inflight_and_no_orphan.yaml"

# Two distinct turn contexts for concurrent in-flight liveness test.
_CTX_A: Final[TurnEgressContext] = TurnEgressContext(
    adapter_id="ada-no-orphan-a",
    inbound_id="in-no-orphan-a",
    session_id="sess-no-orphan",
)
_CTX_B: Final[TurnEgressContext] = TurnEgressContext(
    adapter_id="ada-no-orphan-b",
    inbound_id="in-no-orphan-b",
    session_id="sess-no-orphan",
)
_CALL_INDEX: Final[int] = 0

# Wall-clock deadline for the in-flight liveness test.  Generous but bounded:
# a HoL deadlock surfaces as a FAIL within this many seconds rather than timing
# out CI.  No subprocess, no Docker — the deadline covers asyncio scheduling only.
_LIVENESS_DEADLINE_S: Final[float] = 10.0


# ---------------------------------------------------------------------------
# Corpus loading
# ---------------------------------------------------------------------------


def _load_payload() -> AdversarialPayload:
    return AdversarialPayload.model_validate(yaml.safe_load(_PAYLOAD_PATH.read_text()))


# ---------------------------------------------------------------------------
# In-process stubs (no Postgres, no Docker required)
# ---------------------------------------------------------------------------


@dataclass
class _StubLedger:
    """Fake EgressIdempotencyStore — captures record_response calls for assertions."""

    record_calls: list[dict[str, Any]] = field(default_factory=list)

    async def commit_intent(self, **_kwargs: Any) -> CommitIntentResult:
        return IntentFresh()

    async def record_response(self, *, egress_id: str, response: str, language: str | None) -> None:
        self.record_calls.append(
            {"egress_id": egress_id, "response": response, "language": language}
        )

    async def prune_expired(self, **_kwargs: Any) -> int:
        return 0


@dataclass
class _StubRelayClient:
    """Scripted relay client — returns a canned Fired outcome on every fire() call.

    Holds a real ``_StubLedger`` so ``EgressResponseExtractor`` can reach
    ``record_response`` via ``relay_client.ledger`` (single-ledger invariant M8).
    The ``fire()`` implementation is fully stubbed: no network, no Postgres.
    """

    _ledger: _StubLedger = field(default_factory=_StubLedger)

    @property
    def ledger(self) -> _StubLedger:
        return self._ledger

    async def fire(self, **_kwargs: Any) -> Fired:
        return Fired(response=EgressResponse(status=200, headers={}, body=b"raw-t3-body"))


class _TestSchema(ExtractionSchema):
    """Minimal extraction schema for de-2026-004 adversarial corpus tests."""

    payload: str


# ---------------------------------------------------------------------------
# Gated extractor for in-flight liveness (C1)
#
# Mirrors _GatedExtractor in tests/integration/egress/test_quarantine_contention.py
# but without the completions list — the adversarial proof asserts LIVENESS only
# (both calls complete within the deadline), not strict A-before-B ordering.
# ---------------------------------------------------------------------------


class _GatedExtractor:
    """Fake QuarantinedExtractor whose first call blocks until an event is set.

    A single ``asyncio.Lock`` (``_slot``) serialises concurrent ``extract()``
    invocations, modelling the real quarantine child's single-instance contract.
    The FIRST call acquires the slot and blocks on ``_gate`` while HOLDING the
    slot — so the SECOND call cannot enter ``extract()`` until the gate fires
    and the first call returns.  This is the structural serialisation the
    liveness test asserts: B cannot bypass A on the shared extractor.
    """

    def __init__(self, *, gate: asyncio.Event) -> None:
        self._gate = gate
        self._call_count: int = 0
        self._slot = asyncio.Lock()

    @property
    def call_count(self) -> int:
        return self._call_count

    async def extract(self, handle: Any, schema: type[ExtractionSchema]) -> Extracted:
        async with self._slot:
            self._call_count += 1
            if self._call_count == 1:
                # Block while holding the slot: the second concurrent call
                # waits at the asyncio.Lock acquisition, not at this await.
                await self._gate.wait()
            return Extracted(
                data=T3DerivedData({"payload": f"ok-{self._call_count}"}),
                extraction_mode="native_constrained",
            )


# ---------------------------------------------------------------------------
# Test 1 — corpus schema validation
# ---------------------------------------------------------------------------


def test_payload_schema_valid() -> None:
    """Corpus YAML is well-formed and carries the re-targeted de-2026-004 identity."""
    payload = _load_payload()
    assert payload.id == "de-2026-004"
    assert payload.category == "dlp_egress"
    assert payload.expected_outcome == "refused"
    assert payload.ingestion_path == "web.fetch"
    # Confirm the sub-scenarios are declared in the payload dict.
    assert isinstance(payload.payload, dict)
    sub = payload.payload.get("sub_scenarios")
    assert isinstance(sub, list)
    assert "gate_deny_no_orphan" in sub
    assert "cancellation_no_orphan" in sub
    assert "inflight_liveness" in sub
    # Deferred-property obligation is machine-documented in the payload.
    deferred = payload.payload.get("deferred_property", {})
    assert isinstance(deferred, dict)
    assert deferred.get("merge_blocker") is True


# ---------------------------------------------------------------------------
# Test 2 — no-orphan: gate-deny path (C9)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_gate_deny_no_orphan(authorized_t3_nonce: CapabilityGateNonce) -> None:
    """C9: a gate-denial raises AlfredError AND leaves no T3 body in the staging map.

    ``make_deny_all_gate()`` causes ``quarantined_to_structured`` to raise
    ``AlfredError`` at the gate-first content-clearance check, before the extractor
    is ever called.  The ``except BaseException:`` wrapper in
    ``EgressResponseExtractor.handle()`` calls ``recorder.discard_staged(handle.id)``
    so the ``QuarantineStagingMap`` is empty on exit — the T3 body cannot orphan in
    host-process memory for process lifetime.

    The extractor mock's ``extract`` must NOT be awaited: the gate-first deny means
    the extractor is bypassed entirely (HARD rule #5, spec §4.3).

    CLAUDE.md security rule #7: no silent failures in security paths.
    """
    staging = QuarantineStagingMap()
    recorder = T3BodyRecorder(nonce=authorized_t3_nonce, staging=staging)
    gate = make_deny_all_gate()

    from unittest.mock import AsyncMock

    mock_extractor = AsyncMock()
    mock_extractor.extract = AsyncMock()  # must NOT be reached

    extractor_obj = EgressResponseExtractor(
        relay_client=_StubRelayClient(),  # type: ignore[arg-type]
        gate=gate,
        extractor=mock_extractor,
        recorder=recorder,
    )
    raw_req = _RawToolRequest(
        method="GET", url="https://example.com/", headers={}, body="", idempotent=True
    )

    with pytest.raises(AlfredError):
        await extractor_obj.handle(
            raw_request=raw_req,
            ctx=_CTX_A,
            call_index=_CALL_INDEX,
            schema=_TestSchema,
            language=None,
        )

    # C9 invariant: no orphaned T3 body in the staging map.
    assert len(staging._staged) == 0, (
        "No-orphan BREACH (gate-deny): staging map non-empty after AlfredError — "
        f"discard_staged was not called: {staging._staged!r}"
    )
    # Gate-first: extractor must NOT have been reached.
    mock_extractor.extract.assert_not_awaited()


# ---------------------------------------------------------------------------
# Test 3 — no-orphan: cancellation path (C9)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cancellation_no_orphan(authorized_t3_nonce: CapabilityGateNonce) -> None:
    """C9: a CancelledError mid-extract leaves no T3 body in the staging map.

    ``CancelledError`` is a ``BaseException`` subclass, NOT an ``Exception``.
    A bare ``except Exception:`` block would let it escape without discarding the
    staged body, leaking the ``TaggedContent[T3]`` into the unbounded staging map
    for process lifetime.  The ``except BaseException:`` wrapper catches it and
    calls ``discard_staged(handle.id)`` before re-raising.

    This adversarial corpus proof mirrors the unit-level proof in
    ``tests/unit/egress/test_egress_response_extract.py::test_cancelled_error_leaves_no_orphaned_body``
    but is the release-blocking anchor: CI MUST keep this green.

    CLAUDE.md security rule #7: no silent failures in security paths.
    """
    staging = QuarantineStagingMap()
    recorder = T3BodyRecorder(nonce=authorized_t3_nonce, staging=staging)
    gate = make_quarantined_extract_chain_gate(
        grant_dereference_t3=True,
        dereference_plugin_id="alfred.quarantined-llm",
    )

    from unittest.mock import AsyncMock

    mock_extractor = AsyncMock()
    # Simulate the action-deadline CancelledError landing inside the extractor.
    mock_extractor.extract = AsyncMock(side_effect=asyncio.CancelledError())

    extractor_obj = EgressResponseExtractor(
        relay_client=_StubRelayClient(),  # type: ignore[arg-type]
        gate=gate,
        extractor=mock_extractor,
        recorder=recorder,
    )
    raw_req = _RawToolRequest(
        method="GET", url="https://example.com/", headers={}, body="", idempotent=True
    )

    with pytest.raises(asyncio.CancelledError):
        await extractor_obj.handle(
            raw_request=raw_req,
            ctx=_CTX_A,
            call_index=_CALL_INDEX,
            schema=_TestSchema,
            language=None,
        )

    # CR-cloud-10: the CancelledError must actually REACH extract() (i.e. land
    # inside the ``try:`` at ``quarantined_to_structured``), not somewhere earlier —
    # otherwise the test would pass even if the cancellation never exercised the
    # except-BaseException discard path.
    mock_extractor.extract.assert_awaited_once()

    # C9 invariant: no orphaned T3 body in the staging map.
    assert len(staging._staged) == 0, (
        "No-orphan BREACH (cancellation): staging map non-empty after CancelledError — "
        f"except BaseException: discard_staged path was not taken: {staging._staged!r}"
    )


# ---------------------------------------------------------------------------
# Test 4 — in-flight liveness: concurrent fires serialise without deadlock (C1)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_inflight_liveness_concurrent_handles_no_deadlock(
    authorized_t3_nonce: CapabilityGateNonce,
) -> None:
    """C1: two concurrent handle() calls serialise through the shared extractor without hang.

    The shared single ``_GatedExtractor`` instance holds an ``asyncio.Lock``
    (modelling the one quarantine child's serialisation contract).  Call A acquires
    the slot and blocks on the gate event while HOLDING the slot; call B queues at
    the lock acquisition.  The test body releases the gate after confirming A is
    blocking — both calls then complete within ``_LIVENESS_DEADLINE_S``.

    A ``TimeoutError`` from ``asyncio.wait_for`` is a FAIL (HoL regression), NOT a
    skip.  The test is entirely in-process (no Postgres, no Docker) and completes in
    milliseconds on any host.

    Anchors alongside
    ``tests/integration/egress/test_quarantine_contention.py`` which proves the
    same liveness property against the real Postgres + real relay stack.

    CLAUDE.md security rule #7: no silent failures in security paths.
    """
    staging = QuarantineStagingMap()
    recorder = T3BodyRecorder(nonce=authorized_t3_nonce, staging=staging)
    gate = make_quarantined_extract_chain_gate(
        grant_dereference_t3=True,
        dereference_plugin_id="alfred.quarantined-llm",
    )

    extraction_gate = asyncio.Event()
    gated_extractor = _GatedExtractor(gate=extraction_gate)

    extractor_obj = EgressResponseExtractor(
        relay_client=_StubRelayClient(),  # type: ignore[arg-type]
        gate=gate,
        extractor=gated_extractor,  # type: ignore[arg-type]
        recorder=recorder,
    )

    raw_req_a = _RawToolRequest(
        method="GET", url="https://a.example.com/", headers={}, body="", idempotent=True
    )
    raw_req_b = _RawToolRequest(
        method="GET", url="https://b.example.com/", headers={}, body="", idempotent=True
    )

    # Signal when call A has entered the blocking gate-wait inside the extractor.
    a_blocked = asyncio.Event()
    outcomes: dict[str, Any] = {}

    async def _run_a() -> None:
        """Fire call A; instrument gate-wait to signal a_blocked."""
        original_wait = extraction_gate.wait

        async def _instrumented_wait() -> None:
            a_blocked.set()
            await original_wait()

        extraction_gate.wait = _instrumented_wait  # type: ignore[method-assign, assignment]
        try:
            outcomes["a"] = await extractor_obj.handle(
                raw_request=raw_req_a,
                ctx=_CTX_A,
                call_index=_CALL_INDEX,
                schema=_TestSchema,
                language="en",
            )
        finally:
            # Restore so call B is NOT gated on the instrumented wrapper.
            extraction_gate.wait = original_wait  # type: ignore[method-assign]

    async def _run_b() -> None:
        """Fire call B after A is confirmed blocking; B must complete without hang."""
        await asyncio.wait_for(a_blocked.wait(), timeout=_LIVENESS_DEADLINE_S)
        outcomes["b"] = await extractor_obj.handle(
            raw_request=raw_req_b,
            ctx=_CTX_B,
            call_index=_CALL_INDEX,
            schema=_TestSchema,
            language="en",
        )

    async def _release_gate_after_a_blocks() -> None:
        """Release the extraction gate once A is confirmed blocking."""
        await asyncio.wait_for(a_blocked.wait(), timeout=_LIVENESS_DEADLINE_S)
        extraction_gate.set()

    try:
        async with asyncio.timeout(_LIVENESS_DEADLINE_S):
            await asyncio.gather(_run_a(), _run_b(), _release_gate_after_a_blocks())
    except TimeoutError as exc:
        raise AssertionError(
            f"In-flight liveness BREACH: concurrent handle() calls did not complete "
            f"within {_LIVENESS_DEADLINE_S}s — HoL deadlock on the shared quarantine child."
        ) from exc

    assert "a" in outcomes, "Call A did not complete — HoL hang detected"
    assert "b" in outcomes, "Call B did not complete — HoL hang detected"
    assert gated_extractor.call_count == 2, (
        f"Expected 2 extractor calls (one per handle), got {gated_extractor.call_count} — "
        "concurrent calls may have been fused or dropped"
    )


# ---------------------------------------------------------------------------
# Test 5 — deferred property: per-user exhaustion REFUSAL (xfail, #339 merge-blocker)
# ---------------------------------------------------------------------------


@pytest.mark.xfail(
    reason=(
        "Per-user egress resource-exhaustion REFUSAL bound deferred to PR #339 "
        "(needs real turn-user; no production dispatch_web_fetch caller until after G7-3). "
        "This xfail is a MERGE-BLOCKER on PR #339: "
        "WebFetchRateLimited(bucket='handle_cap') refusal-before-network "
        "(Lua-atomic Redis ZADD, handle_cap=5 → 6th call refused, spec §7.10) "
        "MUST be reinstated before the first live caller merges on #339."
    ),
    # CR-16: strict=True — the body raises today (XFAIL). When #339 reinstates the
    # property the body will pass → XPASS → strict turns the XPASS into a FAILURE,
    # mechanically forcing this stub's removal rather than leaving a silent XPASS.
    strict=True,
)
def test_per_user_exhaustion_refusal_deferred_to_339() -> None:
    """Deferred: per-user WebFetchRateLimited(bucket='handle_cap') refusal before network.

    The original de-2026-004 proved that the 6th concurrent web.fetch call for a
    single user is refused with ``WebFetchRateLimited(bucket='handle_cap')`` BEFORE
    the plugin call (Lua-atomic Redis ZADD pre-gate, spec §7.10 HandleCap):

    * Five concurrent reserves succeed (ZSET ZCARD == 5).
    * The 6th is refused atomically before any network round-trip.
    * A ``tool.web.fetch`` audit row with ``rate_limit_bucket='handle_cap'``,
      ``dlp_scan_result='handle_cap_exceeded'``, ``result='rate_limited'`` fires.

    This property was REMOVED when the per-user ContentHandle cap was replaced by the
    C1 global semaphore in G7-2.5 (the fused fetch+extract stages T3 in-memory
    transiently; no Redis handle store).

    It is DEFERRED to PR #339 which:
      - Introduces the first live ``dispatch_web_fetch`` caller (after G7-3).
      - Has access to the real turn-user context the per-user cap requires.
      - MUST reinstate the per-user REFUSAL bound BEFORE merging.

    Until then this test is a ``@pytest.mark.xfail(strict=True)`` stub — CI
    surfaces it as a machine-visible known-gap (XFAIL), not prose a reviewer may
    miss.  When PR #339 reinstates the property:

    1. Replace this body with the real per-user REFUSAL test (drive
       ``dispatch_web_fetch`` against a real or fake Redis handle-cap with
       ``cap=5``; issue 6 concurrent calls; assert 5 succeed and the 6th raises
       ``WebFetchRateLimited(bucket='handle_cap')`` before the plugin call).
    2. Update ``expected_outcome`` in the YAML to ``audit_row_emitted`` (or
       add a sub-scenario) once the audit row is re-verified.
    3. The mark is already ``strict=True``: once the reinstated body passes, the
       XPASS becomes a strict FAILURE that forces this step.
    4. Remove the ``xfail`` mark entirely once stable.

    **PR #339 merge-blocker**: do NOT merge PR #339 until this xfail is converted
    to a passing test.  The obligation is recorded in the G7-2.5 Task-9 commit and
    in the de-2026-004 YAML ``payload.deferred_property.merge_blocker``.
    """
    # This body INTENTIONALLY FAILS: there is no per-user handle-cap wired into
    # dispatch_web_fetch in the current codebase (G7-2.5 removed it).  The xfail
    # mark ensures CI shows XFAIL rather than RED — a machine-visible gap, not a
    # passing false-green.
    raise AssertionError(
        "Per-user resource-exhaustion REFUSAL bound not yet reinstated — "
        "PR #339 merge-blocker. See docstring for reinstatement requirements."
    )
