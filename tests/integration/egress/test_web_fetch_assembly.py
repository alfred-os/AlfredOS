"""Integration: the production ``web.fetch`` assembly factory over a loopback relay.

Spec C G7-2.5 PR2 (#333) / §5.3 / ADR-0041. Proves the parked assembly
(:func:`alfred.plugins.web_fetch.assembly.build_web_fetch_egress_extractor`) is a
WORKING production path, not dangling construction:

* the factory-built :class:`EgressResponseExtractor`, driven over a REAL loopback
  :class:`~alfred.gateway.egress_relay.EgressRelay` (upstream faked by
  ``fake_external_world`` — NO live egress), completes a fetch+extract end to end
  through the sanctioned ``quarantined_to_structured`` seam against a REAL
  :class:`~alfred.memory.egress_idempotency.PostgresEgressIdempotencyStore`
  (testcontainers) and a REAL :class:`CapabilityGate`, returning a T2
  :class:`EgressExtractOutcome` whose ``result`` is :class:`Extracted`;
* the assembly REUSES the daemon's quarantine extractor — it spawns NO second
  quarantined child (§4.3 one production extractor; CORE-4 shared-child HoL): the
  extraction routes through the SAME extractor instance handed to the factory.

The extractor double is the recorded-LLM-response pattern the egress integration
suite sanctions (``test_egress_response_extract_postgres.py``); the load-bearing
invariants are the production wiring + the gate-first crossing, not the LLM call.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock

import pytest
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from alfred.config.settings import Settings
from alfred.egress.egress_id import TurnEgressContext
from alfred.egress.egress_response_extract import EgressExtractOutcome
from alfred.gateway.egress_relay import EgressRelay
from alfred.gateway.egress_relay_audit import record_egress_relay
from alfred.memory.db import session_scope
from alfred.memory.egress_idempotency import PostgresEgressIdempotencyStore
from alfred.plugins.web_fetch.assembly import build_web_fetch_egress_extractor
from alfred.security.canary_matcher import CanaryMatcher
from alfred.security.dlp import OutboundDlp
from alfred.security.quarantine import Extracted, ExtractionSchema, T3DerivedData
from alfred.security.quarantine_transport import QuarantineStagingMap, T3BodyRecorder
from alfred.security.tiers import CapabilityGateNonce
from tests.helpers.dlp import identity_outbound_dlp
from tests.helpers.egress_doubles import _await_relay_ready, _NullAuditWriter
from tests.helpers.gates import make_quarantined_extract_chain_gate

pytestmark = pytest.mark.integration

_FAKE_HOST = "safe-upstream.example"
_FAKE_PORT = 443
_FAKE_URL = f"https://{_FAKE_HOST}/api/tool"
_FAKE_ALLOWLIST: frozenset[tuple[str, int]] = frozenset({(_FAKE_HOST, _FAKE_PORT)})


class _TestSchema(ExtractionSchema):
    payload: str


@pytest.fixture(autouse=True)
async def _shutdown_default_executor() -> Any:
    # The C2 pre-extract seam runs ``inspect_response`` via ``asyncio.to_thread``;
    # reap the default executor so no worker thread outlives the test loop.
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
def authorized_t3_nonce() -> Any:
    """Install a fresh CapabilityGateNonce as the authorised slot."""
    from alfred.bootstrap.nonce_factory import _NONCE_LOCK
    from alfred.security import tiers as _tiers

    with _NONCE_LOCK:
        previous = _tiers._AUTHORIZED_T3_NONCE
        nonce = CapabilityGateNonce()
        _tiers._set_authorized_t3_nonce(nonce)
    try:
        yield nonce
    finally:
        with _NONCE_LOCK:
            _tiers._set_authorized_t3_nonce(previous)


def _settings(monkeypatch: pytest.MonkeyPatch, *, relay_url: str) -> Settings:
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-test")
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    return Settings(egress_relay_url=relay_url)


async def _query_row(migrated_url: str, egress_id: str) -> dict[str, Any] | None:
    engine = create_async_engine(migrated_url, future=True)
    try:
        async with engine.connect() as conn:
            row = await conn.execute(
                sa.text("SELECT state, response FROM egress_idempotency WHERE egress_id = :e"),
                {"e": egress_id},
            )
            rec = row.fetchone()
            return None if rec is None else {"state": rec[0], "response": rec[1]}
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_assembled_extractor_completes_fetch_extract_reusing_graph(
    migrated_url: str,
    authorized_t3_nonce: CapabilityGateNonce,
    monkeypatch: pytest.MonkeyPatch,
    fake_external_world: tuple[Any, Any, Any],
) -> None:
    """The factory-assembled extractor fetch+extracts → Extracted, reusing the graph."""
    open_client_factory, fire_counter, _canned = fake_external_world

    # --- Boot a real loopback gateway EgressRelay (upstream faked). -----------
    srv = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0)
    port: int = srv.sockets[0].getsockname()[1]
    srv.close()
    await srv.wait_closed()

    # No canary tokens on the gateway DLP — the benign body must forward cleanly.
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
    # Tear the serve task down if readiness times out / the relay fails at startup
    # — otherwise ``shutdown`` is never set below and ``serve_task`` leaks.
    try:
        await _await_relay_ready(port, serve_task)
    except BaseException:
        shutdown.set()
        await asyncio.wait_for(serve_task, timeout=5)
        raise

    # --- The daemon quarantine-graph components (reused, never re-spawned). ----
    staging = QuarantineStagingMap()
    recorder = T3BodyRecorder(nonce=authorized_t3_nonce, staging=staging)
    gate = make_quarantined_extract_chain_gate(
        grant_dereference_t3=True,
        dereference_plugin_id="alfred.quarantined-llm",
    )
    extracted = Extracted(
        data=T3DerivedData({"payload": "assembled-ok"}),
        extraction_mode="native_constrained",
    )
    mock_extractor = AsyncMock()
    mock_extractor.extract = AsyncMock(return_value=extracted)

    # --- The factory's own ledger rides this testcontainer-backed scope. -------
    engine = create_async_engine(migrated_url, future=True)
    factory = async_sessionmaker(engine, expire_on_commit=False)

    try:
        assembled = build_web_fetch_egress_extractor(
            settings=_settings(monkeypatch, relay_url=f"tcp://127.0.0.1:{port}"),
            gate=gate,
            extractor=mock_extractor,
            recorder=recorder,
            outbound_dlp=identity_outbound_dlp(),
            audit_writer=_NullAuditWriter(),  # type: ignore[arg-type]
            session_scope=lambda: session_scope(factory),
        )

        # The factory built a REAL relay client + ledger, REUSING the graph.
        assert assembled._extractor is mock_extractor
        assert assembled._gate is gate
        assert assembled._recorder is recorder
        assert isinstance(assembled._relay_client.ledger, PostgresEgressIdempotencyStore)

        ctx = TurnEgressContext(adapter_id="ada-asm", inbound_id="in-asm", session_id="sess-asm")
        from alfred.egress.relay_protocol import _RawToolRequest

        raw_request = _RawToolRequest(
            method="GET", url=_FAKE_URL, headers={}, body="", idempotent=True
        )

        outcome = await assembled.handle(
            raw_request=raw_request,
            ctx=ctx,
            call_index=0,
            schema=_TestSchema,
            language="en",
        )

        # The end-to-end outcome is a fresh T2 Extracted (production wiring works).
        assert isinstance(outcome, EgressExtractOutcome)
        assert outcome.deduplicated is False
        assert isinstance(outcome.result, Extracted)
        assert outcome.result.data == extracted.data
        assert outcome.status == 200

        # The upstream fired exactly once through the real relay (no live egress —
        # the fake world counts it).
        assert fire_counter.value == 1

        # No second quarantine child: the extraction routed through the SAME
        # extractor instance handed to the factory.
        mock_extractor.extract.assert_awaited_once()

        # The factory's ledger persisted the post-extraction T2 (terminal row).
        from alfred.egress.egress_id import compute_egress_id

        egress_id = compute_egress_id(ctx, call_index=0)
        row = await _query_row(migrated_url, egress_id)
        assert row is not None
        assert row["state"] == "committed_with_response"
        assert row["response"] == extracted.model_dump_json()
    finally:
        # Nest the relay teardown inside ``try`` so a re-raise from
        # ``wait_for(serve_task)`` cannot skip ``engine.dispose()`` (async-engine leak).
        try:
            shutdown.set()
            await asyncio.wait_for(serve_task, timeout=5)
        finally:
            await engine.dispose()
