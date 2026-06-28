"""Executable counterpart to ``de_egress_id_replay_forgery.yaml``.

de-2026-009. Four sub-assertions against the real egress-id ledger (loopback
relay stack + real PostgresEgressIdempotencyStore):

(a) ``committed_with_response`` replay: a clean fire records T2, then a
    second call with the same (ctx, call_index) short-circuits with
    Deduplicated — fire_count stays 1 (memoize invariant, HARD rule #5).
(b) ``committed_no_response`` (in-doubt) + non-idempotent: after a barrier
    kill leaves the row in-doubt, a re-call raises EgressInDoubtError WITHOUT
    re-firing — fire_count stays 1 (at-most-once, Spec C §5 H3).
(c) Different-hash on the SAME egress-id slot: directly calling
    commit_intent with a different body_hash raises EgressIdIntegrityError
    (HARD rule #7 — non-deterministic re-run is loud, never silent).
(d) Forged / unknown egress-id: calling record_response with a syntactically-
    valid 64-char sha256-hex string that was NEVER committed via commit_intent
    raises EgressLedgerStateError (caller-contract violation — loud,
    HARD rule #7; a forged id can never inject a response into the ledger).
    Also proves that incrementing call_index produces a DIFFERENT egress-id
    (collision-resistance across logical call slots).

All four must refuse or deduplicate without an additional upstream fire.
The egress-id is a tamper-evident, collision-resistant gate (Spec C §5).
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import pytest
import yaml
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from alfred.egress.egress_id import (
    EgressIdIntegrityError,
    TurnEgressContext,
    compute_body_hash,
    compute_egress_id,
)
from alfred.egress.egress_response_extract import EgressResponseExtractor
from alfred.egress.errors import EgressInDoubtError
from alfred.egress.relay_client import RelayEgressClient
from alfred.egress.relay_protocol import _RawToolRequest
from alfred.gateway.egress_relay import EgressRelay
from alfred.gateway.egress_relay_audit import record_egress_relay
from alfred.memory.db import session_scope
from alfred.memory.egress_idempotency import EgressLedgerStateError, PostgresEgressIdempotencyStore
from alfred.security.canary_matcher import CanaryMatcher
from alfred.security.dlp import OutboundDlp
from alfred.security.quarantine import Extracted, ExtractionSchema, T3DerivedData
from alfred.security.quarantine_transport import QuarantineStagingMap, T3BodyRecorder
from alfred.security.tiers import CapabilityGateNonce
from tests.adversarial.payload_schema import AdversarialPayload
from tests.helpers.egress_doubles import _await_relay_ready, _CapturingAuditWriter
from tests.helpers.gates import make_quarantined_extract_chain_gate

_PAYLOAD_PATH = Path(__file__).parent / "de_egress_id_replay_forgery.yaml"

_FAKE_HOST = "safe-upstream.example"
_FAKE_PORT = 443
_FAKE_URL = f"https://{_FAKE_HOST}/api/tool"
_FAKE_ALLOWLIST: frozenset[tuple[str, int]] = frozenset({(_FAKE_HOST, _FAKE_PORT)})


def _load_payload() -> AdversarialPayload:
    return AdversarialPayload.model_validate(yaml.safe_load(_PAYLOAD_PATH.read_text()))


def test_payload_schema_valid() -> None:
    payload = _load_payload()
    assert payload.id == "de-2026-009"
    assert payload.category == "dlp_egress"
    assert payload.expected_outcome == "deduped_or_refused"
    assert payload.ingestion_path == "web.fetch"


class _BarrierKillError(Exception):
    """Sentinel: simulates a process kill after fire, before record_response."""


class _TestSchema(ExtractionSchema):
    payload: str


pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
async def _shutdown_default_executor() -> Any:
    yield
    await asyncio.get_running_loop().shutdown_default_executor()


@pytest.fixture
def migrated_url(postgres_url: str, monkeypatch: pytest.MonkeyPatch) -> str:
    from alembic import command, config

    monkeypatch.setenv("ALFRED_DATABASE_URL", postgres_url)
    cfg = config.Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", postgres_url)
    command.upgrade(cfg, "head")
    return postgres_url


@pytest.fixture
async def store(migrated_url: str) -> Any:
    engine = create_async_engine(migrated_url, future=True)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        yield PostgresEgressIdempotencyStore(session_scope=lambda: session_scope(factory))
    finally:
        await engine.dispose()


async def _build_loopback(
    *,
    store: PostgresEgressIdempotencyStore,
    authorized_t3_nonce: CapabilityGateNonce,
    open_client_factory: Any,
    post_fire_hook: Any = None,
) -> tuple[EgressResponseExtractor, asyncio.Task[Any], asyncio.Event, RelayEgressClient, AsyncMock]:
    """Build a loopback relay stack.

    Returns ``(extractor, serve_task, shutdown, relay_client, mock_extractor_spy)``.

    The ``mock_extractor_spy`` is the ``AsyncMock`` used as the extractor so callers can
    assert on ``mock_extractor_spy.extract.await_count`` — proving the extractor is NOT
    re-called on a dedup replay (HARD rule #5).
    """
    srv = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0)
    port: int = srv.sockets[0].getsockname()[1]
    srv.close()
    await srv.wait_closed()

    gateway_dlp = OutboundDlp(
        broker=None, audit=lambda **_kw: None, canary=CanaryMatcher(tokens=[])
    )
    relay = EgressRelay(
        tool_allowlist=_FAKE_ALLOWLIST,
        dlp=gateway_dlp,
        audit=record_egress_relay,
        bind_host="127.0.0.1",
        port=port,
        resolve=lambda _h: "1.1.1.1",
        open_client=open_client_factory,
        response_byte_cap=4096,
        upstream_deadline_s=10.0,
    )
    shutdown = asyncio.Event()
    serve_task: asyncio.Task[Any] = asyncio.ensure_future(relay.serve(shutdown))
    await _await_relay_ready(port, serve_task)

    audit_writer = _CapturingAuditWriter()
    core_dlp = OutboundDlp(broker=None, audit=lambda **_kw: None)
    relay_client = RelayEgressClient(
        relay_url=f"tcp://127.0.0.1:{port}",
        core_dlp=core_dlp,
        ledger=store,
        audit_writer=audit_writer,  # type: ignore[arg-type]
        concurrency=4,
    )

    staging = QuarantineStagingMap()
    recorder = T3BodyRecorder(nonce=authorized_t3_nonce, staging=staging)
    gate = make_quarantined_extract_chain_gate(
        grant_dereference_t3=True,
        dereference_plugin_id="alfred.quarantined-llm",
    )
    mock_extractor = AsyncMock()
    mock_extractor.extract = AsyncMock(
        return_value=Extracted(
            data=T3DerivedData({"payload": "de-2026-009-result"}),
            extraction_mode="native_constrained",
        )
    )

    kwargs: dict[str, Any] = dict(
        relay_client=relay_client,
        gate=gate,
        extractor=mock_extractor,
        recorder=recorder,
    )
    if post_fire_hook is not None:
        kwargs["post_fire_hook"] = post_fire_hook

    extractor = EgressResponseExtractor(**kwargs)
    return extractor, serve_task, shutdown, relay_client, mock_extractor


@pytest.mark.asyncio
async def test_replay_complete_deduplicates_without_refire(
    store: PostgresEgressIdempotencyStore,
    migrated_url: str,
    authorized_t3_nonce: CapabilityGateNonce,
    fake_external_world: tuple[Any, Any, Any],
) -> None:
    """(a) committed_with_response replay: deduplicates without re-firing.

    de-2026-009 sub-assertion (a): a clean fire stores T2 (committed_with_response).
    A subsequent identical call returns Deduplicated — the upstream is NOT re-fired
    and fire_count stays 1 (HARD rule #5 memoize invariant, Spec C §5).
    """
    open_client_factory, fire_counter, _canned = fake_external_world
    extractor, serve_task, shutdown, _rc, mock_extractor = await _build_loopback(
        store=store,
        authorized_t3_nonce=authorized_t3_nonce,
        open_client_factory=open_client_factory,
    )

    ctx = TurnEgressContext(adapter_id="ada-009a", inbound_id="in-009a", session_id="sess-009a")
    raw_request = _RawToolRequest(
        method="GET", url=_FAKE_URL, headers={}, body="safe-body-a", idempotent=True
    )

    try:
        # First call: clean fire (fire_count → 1).
        outcome_1 = await extractor.handle(
            raw_request=raw_request,
            ctx=ctx,
            call_index=0,
            schema=_TestSchema,
            language="en",
        )
        assert outcome_1.deduplicated is False, "first call must NOT be deduplicated"
        assert fire_counter.value == 1

        # Second call: same (ctx, call_index) → Deduplicated, fire_count stays 1.
        outcome_2 = await extractor.handle(
            raw_request=raw_request,
            ctx=ctx,
            call_index=0,
            schema=_TestSchema,
            language="en",
        )
        assert outcome_2.deduplicated is True, "second call MUST be deduplicated"
        assert fire_counter.value == 1, f"replay must not re-fire; fire_count={fire_counter.value}"

        # The extractor must have been called exactly ONCE — across BOTH the first
        # call and the replay.  On the dedup replay the ledger short-circuits before
        # the extractor (HARD rule #5 — no re-extraction of raw T3 on dedup).
        mock_extractor.extract.assert_called_once()
    finally:
        shutdown.set()
        await asyncio.wait_for(serve_task, timeout=5)


@pytest.mark.asyncio
async def test_in_doubt_non_idempotent_raises_without_refire(
    store: PostgresEgressIdempotencyStore,
    migrated_url: str,
    authorized_t3_nonce: CapabilityGateNonce,
    fake_external_world: tuple[Any, Any, Any],
) -> None:
    """(b) In-doubt + non-idempotent: EgressInDoubtError, no re-fire.

    de-2026-009 sub-assertion (b): a barrier kill after the first fire leaves
    the row committed_no_response (in-doubt).  A non-idempotent re-call raises
    EgressInDoubtError WITHOUT touching the upstream (fire_count stays 1,
    at-most-once firewall — Spec C §5 H3).
    """
    open_client_factory, fire_counter, _canned = fake_external_world

    async def _barrier_hook() -> None:
        raise _BarrierKillError("simulated kill after fire, before record_response")

    extractor, serve_task, shutdown, _rc, _mock_extractor = await _build_loopback(
        store=store,
        authorized_t3_nonce=authorized_t3_nonce,
        open_client_factory=open_client_factory,
        post_fire_hook=_barrier_hook,
    )

    ctx = TurnEgressContext(adapter_id="ada-009b", inbound_id="in-009b", session_id="sess-009b")
    raw_request = _RawToolRequest(
        method="GET", url=_FAKE_URL, headers={}, body="safe-body-b", idempotent=False
    )

    try:
        # First call: fires upstream (fire_count → 1), then barrier hook kills it.
        with pytest.raises(_BarrierKillError):
            await extractor.handle(
                raw_request=raw_request,
                ctx=ctx,
                call_index=0,
                schema=_TestSchema,
                language="en",
            )
        assert fire_counter.value == 1

        # Second call (non-idempotent): EgressInDoubtError, fire_count stays 1.
        with pytest.raises(EgressInDoubtError):
            await extractor.handle(
                raw_request=raw_request,
                ctx=ctx,
                call_index=0,
                schema=_TestSchema,
                language="en",
            )
        assert fire_counter.value == 1, (
            f"in-doubt must not re-fire; fire_count={fire_counter.value}"
        )
    finally:
        shutdown.set()
        await asyncio.wait_for(serve_task, timeout=5)


@pytest.mark.asyncio
async def test_different_hash_raises_integrity_error(
    store: PostgresEgressIdempotencyStore,
    migrated_url: str,
) -> None:
    """(c) Same egress-id, different body hash → EgressIdIntegrityError (HARD rule #7).

    de-2026-009 sub-assertion (c): directly drives commit_intent twice with the same
    egress_id but DIFFERENT body_hash values.  The second call must raise
    EgressIdIntegrityError — a non-deterministic re-run is loud, never silent.
    """
    ctx = TurnEgressContext(adapter_id="ada-009c", inbound_id="in-009c", session_id="sess-009c")
    egress_id = compute_egress_id(ctx, call_index=0)
    body_hash_1 = compute_body_hash("first-body")
    body_hash_2 = compute_body_hash("second-body-different")
    assert body_hash_1 != body_hash_2

    # First commit — fresh insert.
    result_1 = await store.commit_intent(
        egress_id=egress_id,
        adapter_id=ctx.adapter_id,
        inbound_id=ctx.inbound_id,
        session_id=ctx.session_id,
        call_index=0,
        body_hash=body_hash_1,
    )
    from alfred.memory.egress_idempotency import IntentFresh

    assert isinstance(result_1, IntentFresh)

    # Second commit — same egress_id, DIFFERENT hash → EgressIdIntegrityError.
    with pytest.raises(EgressIdIntegrityError) as exc_info:
        await store.commit_intent(
            egress_id=egress_id,
            adapter_id=ctx.adapter_id,
            inbound_id=ctx.inbound_id,
            session_id=ctx.session_id,
            call_index=0,
            body_hash=body_hash_2,
        )
    assert exc_info.value.egress_id == egress_id, (
        f"EgressIdIntegrityError must carry the egress_id; got {exc_info.value.egress_id!r}"
    )


@pytest.mark.asyncio
async def test_forged_unknown_id_raises_ledger_state_error(
    store: PostgresEgressIdempotencyStore,
    migrated_url: str,
) -> None:
    """(d) Forged / unknown egress-id → EgressLedgerStateError (HARD rule #7).

    de-2026-009 sub-assertion (d): a caller attempts to record a response for
    an egress-id that was NEVER committed via ``commit_intent``.  The ledger
    must raise ``EgressLedgerStateError`` rather than silently no-op'ing or
    accepting the injection — a forged id cannot plant a response into the
    ledger (Spec C §5, HARD rule #7).

    A syntactically-valid 64-char sha256-hex string is used (not a random
    string) to demonstrate the check is not merely a format guard: the ledger
    enforces the committed-intent-first contract at the DATA layer.

    Additionally proves that ``compute_egress_id`` is call_index-sensitive:
    incrementing the call_index produces a DIFFERENT egress-id, so a forger
    cannot collide another logical call's slot by guessing a neighbouring index.
    """
    ctx = TurnEgressContext(adapter_id="ada-009d", inbound_id="in-009d", session_id="sess-009d")

    # A syntactically-valid sha256 hex that was NEVER committed via commit_intent.
    # "a" * 64 is a valid 64-char hex string but corresponds to no DB row.
    forged_id = "a" * 64

    with pytest.raises(EgressLedgerStateError) as exc_info:
        await store.record_response(
            egress_id=forged_id,
            response="injected-payload",
            language="en",
        )
    assert exc_info.value.egress_id == forged_id, (
        f"EgressLedgerStateError must carry the forged egress_id; got {exc_info.value.egress_id!r}"
    )

    # Prove call_index-sensitivity: different call_index → different egress-id.
    # A forger cannot collide a neighbouring call's slot by incrementing the index.
    id_at_0 = compute_egress_id(ctx, call_index=0)
    id_at_1 = compute_egress_id(ctx, call_index=1)
    assert id_at_0 != id_at_1, (
        "compute_egress_id must produce a DIFFERENT id for each call_index "
        f"(call_index=0 → {id_at_0!r}, call_index=1 → {id_at_1!r})"
    )
