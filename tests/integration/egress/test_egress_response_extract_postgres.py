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
from alfred.egress.relay_client import Deduplicated, Fired
from alfred.egress.relay_protocol import EgressResponse, _RawToolRequest
from alfred.memory.db import session_scope
from alfred.memory.egress_idempotency import (
    PostgresEgressIdempotencyStore,
)
from alfred.security import tiers as _tiers
from alfred.security.quarantine import (
    Extracted,
    ExtractionSchema,
    T3DerivedData,
    TypedRefusal,
)
from alfred.security.quarantine_transport import QuarantineStagingMap, T3BodyRecorder
from alfred.security.tiers import CapabilityGateNonce
from tests.helpers.gates import make_quarantined_extract_chain_gate

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
    yield nonce
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
    class _DirectFiredRelay:
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
        relay_client=_DirectFiredRelay(),  # type: ignore[arg-type]
        ledger=store,
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
    class _DeduplicatedRelay:
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
        relay_client=_DeduplicatedRelay(),  # type: ignore[arg-type]
        ledger=store,
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
