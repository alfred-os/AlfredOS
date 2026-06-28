"""Integration test: §4.3 egress-response extract against real Postgres.

Proves the ``committed_no_response → committed_with_response`` ledger
transition stores the post-extraction T2 (not raw T3 bytes), and that a
second ``handle`` call with the same logical ``(ctx, call_index)`` returns
``Deduplicated`` without re-calling the extractor.

The test uses a real ``PostgresEgressIdempotencyStore`` (testcontainers) and
a stub relay client whose ``fire`` is scripted to return first a ``Fired``
(fresh path) and then a ``Deduplicated`` (replay path).  A real
``T3BodyRecorder`` and staging map prove the T3 staging seam.  The extractor
is a thin ``AsyncMock`` (no subprocess quarantined LLM required; the
production-call semantics and gate check are the load-bearing invariants).
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any
from unittest.mock import AsyncMock

import pytest
import sqlalchemy as sa
from alembic import command, config
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from alfred.bootstrap.nonce_factory import _NONCE_LOCK
from alfred.egress.egress_id import TurnEgressContext
from alfred.egress.egress_response_extract import (
    _EXTRACTION_RESULT_ADAPTER,
    EgressResponseExtractor,
)
from alfred.egress.relay_client import Deduplicated, Fired, RelayEgressClient
from alfred.egress.relay_protocol import EgressResponse, _RawToolRequest
from alfred.egress.response_inspection import (
    InboundCanaryTripped,
    ResponsePolicy,
)
from alfred.errors import AlfredError
from alfred.memory.db import session_scope
from alfred.memory.egress_idempotency import (
    PostgresEgressIdempotencyStore,
)
from alfred.security import tiers as _tiers
from alfred.security.canary_matcher import CanaryMatcher, CanaryToken
from alfred.security.quarantine import (
    Extracted,
    ExtractionSchema,
    T3DerivedData,
    TypedRefusal,
)
from alfred.security.quarantine_transport import QuarantineStagingMap, T3BodyRecorder
from alfred.security.tiers import CapabilityGateNonce
from tests.helpers.dlp import identity_outbound_dlp
from tests.helpers.egress_doubles import _NullAuditWriter
from tests.helpers.gates import make_deny_all_gate, make_quarantined_extract_chain_gate

pytestmark = pytest.mark.integration

# ---------------------------------------------------------------------------
# Test schema
# ---------------------------------------------------------------------------


class _TestSchema(ExtractionSchema):
    """Minimal extraction schema for integration tests."""

    payload: str


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def migrated_url(postgres_url: str, monkeypatch: pytest.MonkeyPatch) -> str:
    """Yield a migrated-to-head Postgres URL for this test function."""
    monkeypatch.setenv("ALFRED_DATABASE_URL", postgres_url)
    cfg = config.Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", postgres_url)
    command.upgrade(cfg, "head")
    return postgres_url


@pytest.fixture
async def store(migrated_url: str) -> AsyncIterator[PostgresEgressIdempotencyStore]:
    """Yield a live ``PostgresEgressIdempotencyStore`` for the migration."""
    engine = create_async_engine(migrated_url, future=True)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        yield PostgresEgressIdempotencyStore(session_scope=lambda: session_scope(factory))
    finally:
        await engine.dispose()


@pytest.fixture
def authorized_t3_nonce() -> Any:
    """Install a fresh CapabilityGateNonce as the authorised slot."""
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
# Helpers
# ---------------------------------------------------------------------------


def _make_extracted(payload: str = "integration-payload") -> Extracted:
    return Extracted(
        data=T3DerivedData({"payload": payload}),
        extraction_mode="native_constrained",
    )


def _make_raw_request(url: str = "https://api.example.com/fetch") -> _RawToolRequest:
    return _RawToolRequest(
        method="GET",
        url=url,
        headers={},
        body="",
        idempotent=True,
    )


async def _query_row(migrated_url: str, egress_id: str) -> dict[str, Any] | None:
    """Return the ledger row for ``egress_id`` as a plain dict, or ``None``."""
    engine = create_async_engine(migrated_url, future=True)
    try:
        async with engine.connect() as conn:
            row = await conn.execute(
                sa.text(
                    "SELECT state, response, language FROM egress_idempotency WHERE egress_id = :e"
                ),
                {"e": egress_id},
            )
            rec = row.fetchone()
            if rec is None:
                return None
            return {"state": rec[0], "response": rec[1], "language": rec[2]}
    finally:
        await engine.dispose()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


async def test_fresh_handle_stores_t2_in_ledger(
    store: PostgresEgressIdempotencyStore,
    migrated_url: str,
    authorized_t3_nonce: CapabilityGateNonce,
) -> None:
    """A fresh handle() transitions the row to committed_with_response storing the T2 JSON."""
    ctx = TurnEgressContext(adapter_id="ada-int", inbound_id="in-int", session_id="sess-int")
    call_index = 0
    extracted = _make_extracted("t2-stored")

    # Pre-commit the intent row so EgressResponseExtractor.handle() can recompute
    # egress_id and call record_response against it.
    from alfred.egress.egress_id import compute_body_hash, compute_egress_id

    egress_id = compute_egress_id(ctx, call_index=call_index)
    await store.commit_intent(
        egress_id=egress_id,
        adapter_id=ctx.adapter_id,
        inbound_id=ctx.inbound_id,
        session_id=ctx.session_id,
        call_index=call_index,
        body_hash=compute_body_hash(""),  # body_hash for empty body
    )

    # Build extractor with a relay that returns Fired (skips the C1 commit_intent
    # — that's already done above; the relay_client stub does NOT re-commit).
    # The stub exposes ``ledger`` so EgressResponseExtractor can call
    # record_response on the SAME real Postgres store (single-ledger, M8).
    class _DirectFiredRelay:
        def __init__(self, _store: Any) -> None:
            self._ledger = _store

        @property
        def ledger(self) -> Any:
            return self._ledger

        async def fire(self, **_kw: Any) -> Fired:
            return Fired(response=EgressResponse(status=200, headers={}, body=b"raw T3 body"))

    staging = QuarantineStagingMap()
    recorder = T3BodyRecorder(nonce=authorized_t3_nonce, staging=staging)
    gate = make_quarantined_extract_chain_gate(
        grant_dereference_t3=True,
        dereference_plugin_id="alfred.quarantined-llm",
    )
    mock_extractor = AsyncMock()
    mock_extractor.extract = AsyncMock(return_value=extracted)

    extractor_obj = EgressResponseExtractor(
        relay_client=_DirectFiredRelay(store),  # type: ignore[arg-type]
        gate=gate,
        extractor=mock_extractor,
        recorder=recorder,
    )

    outcome = await extractor_obj.handle(
        raw_request=_make_raw_request(),
        ctx=ctx,
        call_index=call_index,
        schema=_TestSchema,
        language="en",
    )

    # Outcome is T2, not deduplicated.
    assert outcome.deduplicated is False
    assert isinstance(outcome.result, (Extracted, TypedRefusal))

    # Ledger row must now be committed_with_response.
    row = await _query_row(migrated_url, egress_id)
    assert row is not None
    assert row["state"] == "committed_with_response"

    # Stored response must be the post-extraction T2 JSON — NOT the raw T3 bytes.
    assert row["response"] == extracted.model_dump_json()
    assert row["response"] != b"raw T3 body".decode()

    # Round-trip deserialization via the module-level TypeAdapter.
    replayed_result = _EXTRACTION_RESULT_ADAPTER.validate_json(row["response"])
    assert isinstance(replayed_result, Extracted)
    assert replayed_result.data == extracted.data

    assert row["language"] == "en"


async def test_replay_handle_returns_deduplicated_without_re_extracting(
    store: PostgresEgressIdempotencyStore,
    migrated_url: str,
    authorized_t3_nonce: CapabilityGateNonce,
) -> None:
    """A second handle() for the same (ctx, call_index) returns Deduplicated.

    The extractor must not be called on replay (HARD rule #5).
    """
    ctx = TurnEgressContext(adapter_id="ada-int-rep", inbound_id="in-rep", session_id="sess-rep")
    call_index = 0
    extracted = _make_extracted("replay-t2")
    stored_t2 = extracted.model_dump_json()

    from alfred.egress.egress_id import compute_body_hash, compute_egress_id

    egress_id = compute_egress_id(ctx, call_index=call_index)

    # Pre-populate a committed_with_response row (simulates a prior successful run).
    await store.commit_intent(
        egress_id=egress_id,
        adapter_id=ctx.adapter_id,
        inbound_id=ctx.inbound_id,
        session_id=ctx.session_id,
        call_index=call_index,
        body_hash=compute_body_hash(""),
    )
    await store.record_response(egress_id=egress_id, response=stored_t2, language="fr")

    # Second commit_intent returns IntentReplayComplete — the relay client would
    # return Deduplicated.  Simulate this by having the relay return Deduplicated
    # directly (the real C1 would do the same after seeing IntentReplayComplete).
    # The stub exposes ``ledger`` for API consistency (M8); record_response is not
    # called on a Deduplicated path so the ledger reference is unused here.
    class _DeduplicatedRelay:
        def __init__(self, _store: Any) -> None:
            self._ledger = _store

        @property
        def ledger(self) -> Any:
            return self._ledger

        async def fire(self, **_kw: Any) -> Deduplicated:
            return Deduplicated(stored_t2=stored_t2, language="fr")

    staging = QuarantineStagingMap()
    recorder = T3BodyRecorder(nonce=authorized_t3_nonce, staging=staging)
    gate = make_quarantined_extract_chain_gate(
        grant_dereference_t3=True,
        dereference_plugin_id="alfred.quarantined-llm",
    )
    mock_extractor = AsyncMock()
    spy_extract = mock_extractor.extract = AsyncMock(return_value=extracted)

    extractor_obj = EgressResponseExtractor(
        relay_client=_DeduplicatedRelay(store),  # type: ignore[arg-type]
        gate=gate,
        extractor=mock_extractor,
        recorder=recorder,
    )

    outcome = await extractor_obj.handle(
        raw_request=_make_raw_request(),
        ctx=ctx,
        call_index=call_index,
        schema=_TestSchema,
        language="en",  # caller's language ignored on replay — stored "fr" wins
    )

    # Outcome is deduplicated; extractor NOT called.
    assert outcome.deduplicated is True
    spy_extract.assert_not_called()

    # Language comes from the stored row, not the caller's "en".
    assert outcome.language == "fr"

    # The deserialized result matches the stored T2.
    assert isinstance(outcome.result, Extracted)
    assert outcome.result.data == extracted.data

    # The ledger row state must still be committed_with_response (not modified).
    row = await _query_row(migrated_url, egress_id)
    assert row is not None
    assert row["state"] == "committed_with_response"
    assert row["response"] == stored_t2


async def test_gate_denial_leaves_ledger_committed_no_response(
    store: PostgresEgressIdempotencyStore,
    migrated_url: str,
    authorized_t3_nonce: CapabilityGateNonce,
) -> None:
    """S12: a DENY gate raises before record_response → the real Postgres row STAYS
    ``committed_no_response``.

    The at-most-once firewall (HARD rules #5/#7) is proven against real Postgres, not
    just a unit stub: a denied T3 dereference must never store a T2, and the intent row
    must remain un-finalized so the egress is never recorded as completed.
    """
    ctx = TurnEgressContext(adapter_id="ada-deny", inbound_id="in-deny", session_id="sess-deny")
    call_index = 0

    from alfred.egress.egress_id import compute_body_hash, compute_egress_id

    egress_id = compute_egress_id(ctx, call_index=call_index)
    await store.commit_intent(
        egress_id=egress_id,
        adapter_id=ctx.adapter_id,
        inbound_id=ctx.inbound_id,
        session_id=ctx.session_id,
        call_index=call_index,
        body_hash=compute_body_hash(""),
    )

    class _DirectFiredRelay:
        def __init__(self, _store: Any) -> None:
            self._ledger = _store

        @property
        def ledger(self) -> Any:
            return self._ledger

        async def fire(self, **_kw: Any) -> Fired:
            return Fired(response=EgressResponse(status=200, headers={}, body=b"raw T3 body"))

    staging = QuarantineStagingMap()
    recorder = T3BodyRecorder(nonce=authorized_t3_nonce, staging=staging)
    gate = make_deny_all_gate()  # empty-grant RealGate → check_content_clearance is False
    mock_extractor = AsyncMock()
    mock_extractor.extract = AsyncMock()  # must NOT be awaited on a denied dereference

    extractor_obj = EgressResponseExtractor(
        relay_client=_DirectFiredRelay(store),  # type: ignore[arg-type]
        gate=gate,
        extractor=mock_extractor,
        recorder=recorder,
    )

    # Pin the raise to the gate-denial path specifically (the rendered
    # ``security.quarantine.dereference_denied`` message names the hookpoint) — a bare
    # ``pytest.raises(AlfredError)`` would also pass on an unrelated earlier failure
    # (staging, fire), masking a regression that skips the gate check.
    with pytest.raises(AlfredError, match=r"quarantine\.dereference"):
        await extractor_obj.handle(
            raw_request=_make_raw_request(),
            ctx=ctx,
            call_index=call_index,
            schema=_TestSchema,
            language="en",
        )

    # The gate denied BEFORE the extractor ran.
    mock_extractor.extract.assert_not_awaited()

    # The real ledger row stays committed_no_response — no T2 was stored.
    row = await _query_row(migrated_url, egress_id)
    assert row is not None
    assert row["state"] == "committed_no_response"
    assert row["response"] is None


# ---------------------------------------------------------------------------
# Test D1-C8: canary hit → ledger committed_with_response BEFORE raise;
#             replay returns Deduplicated → fire NOT re-called (no re-fetch).
# ---------------------------------------------------------------------------


async def test_canary_replay_no_refire(
    store: PostgresEgressIdempotencyStore,
    migrated_url: str,
    authorized_t3_nonce: CapabilityGateNonce,
) -> None:
    """D1 / C8 integration: inbound canary records a terminal row; replay short-circuits.

    Scenario:
    1. First handle() fires — response contains a canary token.
    2. D1 detects the canary; C2 records TypedRefusal(refused_by_safety) → row
       becomes committed_with_response BEFORE InboundCanaryTripped is raised.
    3. Second handle() of the same (ctx, call_index) → relay sees IntentReplayComplete
       → returns Deduplicated(stored_t2) — fire() NOT called again; no re-fetch.

    This proves the C8 invariant against a real Postgres store.
    """
    canary_token = "CANARY-INTEGRATION-C8-TEST"  # noqa: S105
    canary_matcher = CanaryMatcher(tokens=[CanaryToken(value=canary_token)])
    policy = ResponsePolicy(
        mime_allowlist=frozenset({"text/html"}),
        max_bytes=10 * 1024 * 1024,
        canary=canary_matcher,
    )

    ctx = TurnEgressContext(
        adapter_id="ada-canary", inbound_id="in-canary", session_id="sess-canary"
    )
    call_index = 0

    from alfred.egress.egress_id import (
        compute_egress_body_hash,
        compute_egress_id,
        compute_request_descriptor,
    )
    from alfred.egress.egress_response_extract import _schema_identity

    egress_id = compute_egress_id(ctx, call_index=call_index)
    raw_req = _make_raw_request(url="https://canary-target.example.com/fetch")

    # CR-6 / CR-cloud-11: seed Round-1 with the REAL request_descriptor handle()
    # computes (NOT request_descriptor="") so Round-2's real C1 exercises the
    # production C1/C2 idempotency contract — the stored body_hash MUST equal the
    # descriptor + headers + body folded hash compute_egress_body_hash produces,
    # else commit_intent would raise EgressIdIntegrityError instead of returning
    # IntentReplayComplete on the replay.
    real_descriptor = compute_request_descriptor(
        method=raw_req.method, url=raw_req.url, schema_id=_schema_identity(_TestSchema)
    )
    expected_body_hash = compute_egress_body_hash(
        request_descriptor=real_descriptor,
        headers=raw_req.headers,
        redacted_body="",  # identity DLP of the empty body
    )

    # Pre-commit the intent row (simulates C1's commit_intent before fire).
    await store.commit_intent(
        egress_id=egress_id,
        adapter_id=ctx.adapter_id,
        inbound_id=ctx.inbound_id,
        session_id=ctx.session_id,
        call_index=call_index,
        body_hash=expected_body_hash,
    )

    # Track how many times fire() is called across both handle() calls.
    fire_call_count = 0
    canary_body = f"<html>{canary_token}</html>".encode()

    class _CountingFiredRelay:
        """Relay that counts fire() calls and returns Fired on the first call,
        but the EgressResponseExtractor should never reach a second fire() after
        C2 records the committed_with_response row."""

        def __init__(self, _store: Any) -> None:
            self._ledger = _store

        @property
        def ledger(self) -> Any:
            return self._ledger

        async def fire(self, **_kw: Any) -> Any:
            nonlocal fire_call_count
            fire_call_count += 1
            return Fired(
                response=EgressResponse(
                    status=200,
                    headers={"Content-Type": "text/html"},
                    body=canary_body,
                )
            )

    staging = QuarantineStagingMap()
    recorder = T3BodyRecorder(nonce=authorized_t3_nonce, staging=staging)
    gate = make_quarantined_extract_chain_gate(
        grant_dereference_t3=True,
        dereference_plugin_id="alfred.quarantined-llm",
    )
    mock_extractor = AsyncMock()
    mock_extractor.extract = AsyncMock()  # must NOT be awaited

    relay = _CountingFiredRelay(store)
    extractor_obj = EgressResponseExtractor(
        relay_client=relay,  # type: ignore[arg-type]
        gate=gate,
        extractor=mock_extractor,
        recorder=recorder,
        response_policy=policy,
    )

    # --- Round 1: canary detected → InboundCanaryTripped ---
    with pytest.raises(InboundCanaryTripped) as exc_info:
        await extractor_obj.handle(
            raw_request=raw_req,
            ctx=ctx,
            call_index=call_index,
            schema=_TestSchema,
            language="en",
        )

    exc = exc_info.value
    assert exc.destination == "canary-target.example.com"

    # Verify fire() was called exactly once.
    assert fire_call_count == 1

    # C8: the ledger row must now be committed_with_response (terminal).
    row = await _query_row(migrated_url, egress_id)
    assert row is not None
    assert row["state"] == "committed_with_response", (
        f"Expected committed_with_response after canary hit, got {row['state']!r}"
    )
    # Stored value is the refused_by_safety TypedRefusal — payload-blind.
    assert row["response"] is not None
    assert "refused_by_safety" in row["response"]
    assert canary_token not in row["response"]  # no canary token in the stored refusal

    # Extractor was NOT called.
    mock_extractor.extract.assert_not_awaited()

    # --- Round 2: drive the REAL RelayEgressClient.fire() against the same Postgres store.
    #
    # The row is now committed_with_response (terminal).  When C1 calls commit_intent it
    # receives IntentReplayComplete and short-circuits with Deduplicated — WITHOUT opening
    # a new connection to the gateway relay.  We inject a spy open_connection that raises
    # if called, proving no re-dial occurs (C8 invariant proven end-to-end vs real Postgres).
    #
    # ``real_descriptor`` matches the body_hash stored in Round 1's pre-commit
    # (compute_egress_body_hash with the SAME descriptor + headers + empty body) —
    # the production C1/C2 idempotency contract, not a synthetic-stub shortcut.

    open_conn_called = False

    async def _never_dial(host: str, port: int) -> tuple[Any, Any]:
        nonlocal open_conn_called
        open_conn_called = True
        # Prove no re-dial occurred; message is test-only, never reaches production.
        raise AssertionError(f"C1 re-dialed on {host}:{port} — C8 regression")

    relay_c1 = RelayEgressClient(
        relay_url="tcp://127.0.0.1:1",  # unreachable; open_connection must NOT be called
        core_dlp=identity_outbound_dlp(),
        ledger=store,
        audit_writer=_NullAuditWriter(),  # type: ignore[arg-type]
        concurrency=1,
        open_connection=_never_dial,  # type: ignore[arg-type]
    )

    c1_outcome = await relay_c1.fire(
        raw_request=raw_req,
        ctx=ctx,
        call_index=call_index,
        request_descriptor=real_descriptor,  # the REAL descriptor handle() computes
    )

    # C1 must return Deduplicated (row is committed_with_response → IntentReplayComplete).
    assert isinstance(c1_outcome, Deduplicated), (
        f"Expected Deduplicated from real C1 on replay, got {type(c1_outcome)}"
    )
    assert "refused_by_safety" in c1_outcome.stored_t2

    # open_connection must NOT have been called — no re-dial on replay.
    assert not open_conn_called, (
        "open_connection was called — C1 re-dialed on canary replay (C8 regression)"
    )

    # fire_call_count must still be 1 — the real C1 never touched _CountingFiredRelay.
    assert fire_call_count == 1, f"fire_call_count={fire_call_count} — unexpected re-fire"
