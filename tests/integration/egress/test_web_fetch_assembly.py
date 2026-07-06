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
from alfred.egress.egress_id import TurnEgressContext, compute_egress_id
from alfred.egress.egress_response_extract import EgressExtractOutcome
from alfred.egress.response_inspection import InboundCanaryTripped
from alfred.errors import AlfredError
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
from tests.helpers.gates import make_deny_all_gate, make_quarantined_extract_chain_gate

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


@pytest.mark.asyncio
async def test_assembled_extractor_refuses_on_gate_deny(
    migrated_url: str,
    authorized_t3_nonce: CapabilityGateNonce,
    monkeypatch: pytest.MonkeyPatch,
    fake_external_world: tuple[Any, Any, Any],
) -> None:
    """The SAME factory-assembled extractor REFUSES when the gate denies clearance.

    Closes the trust-boundary proof at the composition root: the allow-arm test
    above proves the happy path; this proves the deny arm of the SAME
    ``build_web_fetch_egress_extractor`` output. With ``make_deny_all_gate()`` the
    gate-first content-clearance check inside ``quarantined_to_structured`` denies,
    so:

    * ``handle`` raises ``AlfredError`` (loud refusal — HARD rule #7), and
    * the quarantined extractor is NEVER awaited (gate-first short-circuit — the
      orchestrator/quarantine child never dereferences the T3 body, HARD rule #5),
      and
    * the staged T3 body is discarded — the ``QuarantineStagingMap`` is empty on
      exit (C9 no-orphan), proving the assembled extractor's drain-on-error path.

    Note on ordering: the content-clearance gate is consulted AFTER the relay
    fires (``EgressResponseExtractor.handle`` step 1 fires; step 3 gate-checks the
    T3→T2 dereference), so the upstream IS reached once (``fire_counter == 1``).
    The gate governs whether the RESPONSE body may cross into T2, not whether the
    allowlisted request may egress — the refusal is on the inbound boundary.
    """
    open_client_factory, fire_counter, _canned = fake_external_world

    # --- Boot the same loopback gateway EgressRelay (upstream faked). ---------
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
    try:
        await _await_relay_ready(port, serve_task)
    except BaseException:
        shutdown.set()
        await asyncio.wait_for(serve_task, timeout=5)
        raise

    # --- DENY gate: every content-clearance check returns False (RealGate, no
    #     grants) — never a permissive shim (CLAUDE.md hard rule #2). ----------
    staging = QuarantineStagingMap()
    recorder = T3BodyRecorder(nonce=authorized_t3_nonce, staging=staging)
    deny_gate = make_deny_all_gate()
    mock_extractor = AsyncMock()
    mock_extractor.extract = AsyncMock()  # must NOT be reached on a gate-deny

    engine = create_async_engine(migrated_url, future=True)
    factory = async_sessionmaker(engine, expire_on_commit=False)

    try:
        assembled = build_web_fetch_egress_extractor(
            settings=_settings(monkeypatch, relay_url=f"tcp://127.0.0.1:{port}"),
            gate=deny_gate,
            extractor=mock_extractor,
            recorder=recorder,
            outbound_dlp=identity_outbound_dlp(),
            audit_writer=_NullAuditWriter(),  # type: ignore[arg-type]
            session_scope=lambda: session_scope(factory),
        )

        ctx = TurnEgressContext(adapter_id="ada-deny", inbound_id="in-deny", session_id="sess-deny")
        from alfred.egress.relay_protocol import _RawToolRequest

        raw_request = _RawToolRequest(
            method="GET", url=_FAKE_URL, headers={}, body="", idempotent=True
        )

        # The deny propagates as a loud AlfredError — the orchestrator gets no T2.
        with pytest.raises(AlfredError):
            await assembled.handle(
                raw_request=raw_request,
                ctx=ctx,
                call_index=0,
                schema=_TestSchema,
                language="en",
            )

        # Gate-first: the quarantine child was bypassed — it never saw the T3 body.
        mock_extractor.extract.assert_not_awaited()
        # C9 no-orphan at the composition root: the staged T3 body was discarded.
        assert len(staging._staged) == 0, (
            "No-orphan BREACH: staging map non-empty after gate-deny AlfredError — "
            f"discard_staged was not called: {staging._staged!r}"
        )
        # The request did reach the (faked) upstream once — the deny is on the
        # inbound T3→T2 crossing, not on the outbound egress (see docstring).
        assert fire_counter.value == 1
    finally:
        try:
            shutdown.set()
            await asyncio.wait_for(serve_task, timeout=5)
        finally:
            await engine.dispose()


@pytest.mark.asyncio
async def test_factory_canary_from_settings_trips_over_real_relay(
    migrated_url: str,
    authorized_t3_nonce: CapabilityGateNonce,
    monkeypatch: pytest.MonkeyPatch,
    fake_external_world: tuple[Any, Any, Any],
) -> None:
    """A canary token in ``Settings.web_fetch_canary_tokens``, reflected by the
    upstream, trips ``InboundCanaryTripped`` end-to-end through the
    factory-built extractor + real loopback relay + real Postgres ledger
    (de-2026-012 wiring closure, #339 PR4a).

    Closes the "settings → factory → real relay → terminal ledger row" wiring
    loop: A3 proved the in-process trip + the factory-wiring guard (unit-level,
    no live relay); this proves the SAME canary-derivation path
    (``_resolve_web_fetch_canary``) fires over a REAL loopback ``EgressRelay``
    and REAL Postgres idempotency store, landing a terminal
    ``committed_with_response`` row BEFORE the loud raise (C8 invariant).
    """
    open_client_factory, fire_counter, canned = fake_external_world
    token = "ALFRED-CANARY-TEST-TOKEN-8675309"  # noqa: S105 -- canary sentinel, not a credential
    canned.body = f"upstream page reflecting {token}".encode()

    # --- Boot a real loopback gateway EgressRelay (upstream faked). -----------
    srv = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0)
    port: int = srv.sockets[0].getsockname()[1]
    srv.close()
    await srv.wait_closed()

    # No canary tokens on the gateway DLP — we are testing the CORE inbound
    # canary (web.fetch's own ResponsePolicy), not the gateway's outbound DLP.
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
    mock_extractor = AsyncMock()
    mock_extractor.extract = AsyncMock()  # canary is pre-extract → never reached

    engine = create_async_engine(migrated_url, future=True)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-test")
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    settings = Settings(
        egress_relay_url=f"tcp://127.0.0.1:{port}",
        web_fetch_canary_tokens=(token,),
    )
    try:
        assembled = build_web_fetch_egress_extractor(
            settings=settings,
            gate=gate,
            extractor=mock_extractor,
            recorder=recorder,
            outbound_dlp=identity_outbound_dlp(),
            audit_writer=_NullAuditWriter(),  # type: ignore[arg-type]
            session_scope=lambda: session_scope(factory),
        )

        # The factory derived a non-None canary matcher from Settings — this is
        # the de-2026-012 wiring closure under test, not a re-check of A3's
        # in-process assertion.
        assert assembled._response_policy is not None
        assert assembled._response_policy.canary is not None

        ctx = TurnEgressContext(adapter_id="ada-cn", inbound_id="in-cn", session_id="sess-cn")
        from alfred.egress.relay_protocol import _RawToolRequest

        raw_request = _RawToolRequest(
            method="GET", url=_FAKE_URL, headers={}, body="", idempotent=True
        )

        with pytest.raises(InboundCanaryTripped):
            await assembled.handle(
                raw_request=raw_request,
                ctx=ctx,
                call_index=0,
                schema=_TestSchema,
                language="en",
            )

        # Gate-first / pre-extract: the quarantine child never saw the T3 body.
        mock_extractor.extract.assert_not_awaited()
        # The request DID reach the (faked) upstream once through the real relay
        # — the canary lives in the REFLECTED response body, not the outbound
        # request.
        assert fire_counter.value == 1

        # C8 invariant: a terminal committed_with_response row lands BEFORE the
        # raise — a replay must never re-fire at the flagged-hostile destination.
        egress_id = compute_egress_id(ctx, call_index=0)
        row = await _query_row(migrated_url, egress_id)
        assert row is not None
        assert row["state"] == "committed_with_response"
        assert "refused_by_safety" in row["response"]
    finally:
        try:
            shutdown.set()
            await asyncio.wait_for(serve_task, timeout=5)
        finally:
            await engine.dispose()
