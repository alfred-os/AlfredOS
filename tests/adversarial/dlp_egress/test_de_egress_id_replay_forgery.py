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

All three must refuse or deduplicate without an additional upstream fire.
The egress-id is a tamper-evident, collision-resistant gate (Spec C §5).
"""

from __future__ import annotations

import asyncio
import contextlib
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import pytest
import yaml
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from alfred.bootstrap.nonce_factory import _NONCE_LOCK
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
from alfred.memory.egress_idempotency import PostgresEgressIdempotencyStore
from alfred.security import tiers as _tiers
from alfred.security.canary_matcher import CanaryMatcher
from alfred.security.dlp import OutboundDlp
from alfred.security.quarantine import Extracted, ExtractionSchema, T3DerivedData
from alfred.security.quarantine_transport import QuarantineStagingMap, T3BodyRecorder
from alfred.security.tiers import CapabilityGateNonce
from tests.adversarial.payload_schema import AdversarialPayload
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
    assert payload.expected_outcome == "refused"
    assert payload.ingestion_path == "web.fetch"


class _BarrierKillError(Exception):
    """Sentinel: simulates a process kill after fire, before record_response."""


class _CapturingAuditWriter:
    def __init__(self) -> None:
        self.rows: list[dict[str, Any]] = []

    async def append_schema(self, **kwargs: Any) -> None:
        self.rows.append(dict(kwargs))


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


@pytest.fixture
def authorized_t3_nonce() -> Any:
    with _NONCE_LOCK:
        previous = _tiers._AUTHORIZED_T3_NONCE
        nonce = CapabilityGateNonce()
        _tiers._set_authorized_t3_nonce(nonce)
    try:
        yield nonce
    finally:
        with _NONCE_LOCK:
            _tiers._set_authorized_t3_nonce(previous)


async def _await_relay_ready(port: int, serve_task: asyncio.Task[Any]) -> None:
    for _ in range(500):
        if serve_task.done():
            await serve_task
        try:
            _reader, writer = await asyncio.open_connection("127.0.0.1", port)
        except OSError:
            await asyncio.sleep(0.005)
            continue
        writer.close()
        with contextlib.suppress(Exception):
            await asyncio.wait_for(writer.wait_closed(), timeout=1)
        return
    raise AssertionError("EgressRelay did not become ready within 2.5 s")


async def _build_loopback(
    *,
    store: PostgresEgressIdempotencyStore,
    authorized_t3_nonce: CapabilityGateNonce,
    open_client_factory: Any,
    post_fire_hook: Any = None,
) -> tuple[EgressResponseExtractor, asyncio.Task[Any], asyncio.Event, RelayEgressClient]:
    """Build a loopback stack; return (extractor, serve_task, shutdown, relay_client)."""
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
    return extractor, serve_task, shutdown, relay_client


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
    extractor, serve_task, shutdown, _rc = await _build_loopback(
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

    extractor, serve_task, shutdown, _rc = await _build_loopback(
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
