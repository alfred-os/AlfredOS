"""Release-blocking barrier / dedup / TTL proof — real Postgres, real loopback relay.

Spec C G7-2c-2, epic #333. Proves the egress relay path end-to-end:

    EgressResponseExtractor (C2)
      → RelayEgressClient (C1, real framed TCP loopback)
        → EgressRelay (gateway, fake_external_world upstream)
          → fake_external_world (_FakeClient, fire_count)

against a REAL PostgresEgressIdempotencyStore.  The only substitution is the
upstream (``fake_external_world`` replaces the live internet); the relay,
relay client, and extractor are all real production objects.

TE-1 / TE-3 scenarios
----------------------
A  barrier kill → in-doubt → EgressInDoubtError, fire_count == 1.
B  clean → replay → Deduplicated, fire_count == 1, extractor not re-called.
C  TTL prune → re-fire (expiry is NOT a silent drop), fire_count increments.

Plus 8-way concurrent commit_intent → exactly one winner (the Postgres
INSERT … ON CONFLICT DO NOTHING RETURNING race-free property).

No skip gate
------------
The loopback fixture removes every real-network / budget dependency, so
there is NO excuse for a pytest.mark.skip or xfail on this module.  The
test is in tests/integration/ (a required CI check) and must stay green on
every push.  A failing scenario blocks the release (the at-most-once and
dedup properties are HARD egress-trust-boundary invariants — CLAUDE.md
security rule #7).
"""

from __future__ import annotations

import asyncio
import contextlib
import datetime as dt
from collections.abc import AsyncIterator
from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock

import pytest
import sqlalchemy as sa
from alembic import command, config
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from alfred.bootstrap.nonce_factory import _NONCE_LOCK
from alfred.egress.egress_id import TurnEgressContext, compute_body_hash, compute_egress_id
from alfred.egress.egress_response_extract import EgressResponseExtractor
from alfred.egress.errors import EgressInDoubtError
from alfred.egress.relay_client import RelayEgressClient
from alfred.egress.relay_protocol import _RawToolRequest
from alfred.gateway.egress_relay import EgressRelay
from alfred.gateway.egress_relay_audit import record_egress_relay
from alfred.memory.db import session_scope
from alfred.memory.egress_idempotency import (
    IntentFresh,
    IntentInDoubt,
    PostgresEgressIdempotencyStore,
)
from alfred.security import tiers as _tiers
from alfred.security.dlp import OutboundDlp
from alfred.security.quarantine import (
    Extracted,
    ExtractionSchema,
    T3DerivedData,
)
from alfred.security.quarantine_transport import QuarantineStagingMap, T3BodyRecorder
from alfred.security.tiers import CapabilityGateNonce
from tests.helpers.egress_doubles import _await_relay_ready, _NullAuditWriter
from tests.helpers.gates import make_quarantined_extract_chain_gate

if TYPE_CHECKING:
    from tests.integration.egress.conftest import _CannedResponse, _FireCounter

pytestmark = pytest.mark.integration


# ---------------------------------------------------------------------------
# autouse executor drain (mirrors test_provider_forward_proxy_e2e.py)
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
async def _shutdown_default_executor() -> AsyncIterator[None]:
    """Join the per-test loop's default executor on teardown.

    The relay resolves DNS off-loop via ``run_in_executor(None, …)``; the
    workers otherwise leak into the next test and can trigger
    ``ResourceWarning: Task destroyed but it is pending!``.
    """
    yield
    await asyncio.get_running_loop().shutdown_default_executor()


# ---------------------------------------------------------------------------
# Test schema
# ---------------------------------------------------------------------------


class _TestSchema(ExtractionSchema):
    """Minimal extraction schema for the barrier/dedup tests."""

    payload: str


# ---------------------------------------------------------------------------
# Postgres fixtures (mirrors test_egress_response_extract_postgres.py)
# ---------------------------------------------------------------------------


@pytest.fixture
def migrated_url(postgres_url: str, monkeypatch: pytest.MonkeyPatch) -> str:
    """Yield a head-migrated Postgres URL for one test function."""
    monkeypatch.setenv("ALFRED_DATABASE_URL", postgres_url)
    cfg = config.Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", postgres_url)
    command.upgrade(cfg, "head")
    return postgres_url


@pytest.fixture
async def store(migrated_url: str) -> AsyncIterator[PostgresEgressIdempotencyStore]:
    """Yield a live ``PostgresEgressIdempotencyStore`` backed by testcontainers Postgres."""
    engine = create_async_engine(migrated_url, future=True)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        yield PostgresEgressIdempotencyStore(session_scope=lambda: session_scope(factory))
    finally:
        await engine.dispose()


@pytest.fixture
def authorized_t3_nonce() -> Any:
    """Install a fresh CapabilityGateNonce as the authorised T3 slot."""
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
# Loopback relay helpers — imported from tests.helpers.egress_doubles so
# the implementation is shared with the adversarial dlp_egress suite.
# _await_relay_ready: probes until the relay's listener accepts a TCP
#   connection; portable (no fixed sleep, narrows OSError/TimeoutError).
# _NullAuditWriter: discards every append_schema call; the egress_idempotency
#   ledger (not audit rows) is what the barrier/contention tests care about.
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Wiring helpers
# ---------------------------------------------------------------------------

_FAKE_HOST = "fake-upstream.internal"
_FAKE_PORT = 443
_FAKE_URL = f"https://{_FAKE_HOST}/tool"
# The relay allowlist must contain the fake upstream's (host, port) so the
# SSRF chain passes; resolve= returns a globally-routable IP so the
# resolved-IP guard passes; the open_client= seam is the fake_external_world.
_FAKE_ALLOWLIST: frozenset[tuple[str, int]] = frozenset({(_FAKE_HOST, _FAKE_PORT)})


def _make_raw_request(*, idempotent: bool = False) -> _RawToolRequest:
    """Build a _RawToolRequest pointing at the fake upstream."""
    return _RawToolRequest(
        method="GET",
        url=_FAKE_URL,
        headers={},
        body="",
        idempotent=idempotent,
    )


def _make_ctx(suffix: str = "a") -> TurnEgressContext:
    """Build a deterministic TurnEgressContext with a unique per-scenario suffix."""
    return TurnEgressContext(
        adapter_id=f"ada-{suffix}",
        inbound_id=f"in-{suffix}",
        session_id=f"sess-{suffix}",
    )


def _make_extracted(payload: str = "test-payload") -> Extracted:
    return Extracted(data=T3DerivedData({"payload": payload}), extraction_mode="native_constrained")


async def _build_loopback_stack(
    *,
    store: PostgresEgressIdempotencyStore,
    authorized_t3_nonce: CapabilityGateNonce,
    fake_external_world: tuple[Any, _FireCounter, _CannedResponse],
    migrated_url: str,
    mock_extractor: Any,
    post_fire_hook: Any = None,
) -> tuple[EgressResponseExtractor, asyncio.Task[Any], asyncio.Event, int]:
    """Construct the full loopback stack and return (extractor, serve_task, shutdown, port).

    Starts a real EgressRelay on loopback port 0, probes until ready, then
    builds a RelayEgressClient dialling it.  The caller is responsible for
    shutting down: set ``shutdown`` and await ``serve_task``.
    """
    open_client_factory, _fire_counter, _canned = fake_external_world

    # Reserve a free port (bind port=0 → OS assigns; read back from socket).
    srv = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0)
    port: int = srv.sockets[0].getsockname()[1]
    srv.close()
    await srv.wait_closed()

    relay = EgressRelay(
        tool_allowlist=_FAKE_ALLOWLIST,
        dlp=OutboundDlp(broker=None, audit=lambda **_kw: None),
        audit=record_egress_relay,
        bind_host="127.0.0.1",
        port=port,
        resolve=lambda _h: "1.1.1.1",  # globally-routable → SSRF guard passes
        open_client=open_client_factory,
        response_byte_cap=4096,
        upstream_deadline_s=10.0,
    )
    shutdown = asyncio.Event()
    serve_task: asyncio.Task[Any] = asyncio.ensure_future(relay.serve(shutdown))

    # Guard: if readiness-probing or any downstream construction raises after
    # ensure_future, cancel the relay task rather than leaking it.
    try:
        await _await_relay_ready(port, serve_task)

        # Build the relay client
        audit_writer = _NullAuditWriter()
        relay_client = RelayEgressClient(
            relay_url=f"tcp://127.0.0.1:{port}",
            core_dlp=OutboundDlp(broker=None, audit=lambda **_kw: None),
            ledger=store,
            audit_writer=audit_writer,  # type: ignore[arg-type]
            concurrency=8,
        )

        # Build the gate + recorder
        staging = QuarantineStagingMap()
        recorder = T3BodyRecorder(nonce=authorized_t3_nonce, staging=staging)
        gate = make_quarantined_extract_chain_gate(
            grant_dereference_t3=True,
            dereference_plugin_id="alfred.quarantined-llm",
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
    except BaseException:
        shutdown.set()
        with contextlib.suppress(Exception):
            await asyncio.wait_for(serve_task, timeout=2)
        raise

    return extractor, serve_task, shutdown, port


async def _teardown(serve_task: asyncio.Task[Any], shutdown: asyncio.Event) -> None:
    """Cleanly shut down the loopback relay."""
    shutdown.set()
    await asyncio.wait_for(serve_task, timeout=5)


# ---------------------------------------------------------------------------
# Helpers for DB state inspection
# ---------------------------------------------------------------------------


async def _query_state(migrated_url: str, egress_id: str) -> str | None:
    engine = create_async_engine(migrated_url, future=True)
    try:
        async with engine.connect() as conn:
            return await conn.scalar(
                sa.text("SELECT state FROM egress_idempotency WHERE egress_id = :e"),
                {"e": egress_id},
            )
    finally:
        await engine.dispose()


# ---------------------------------------------------------------------------
# Scenario A — barrier kill: in-doubt → EgressInDoubtError, fire_count == 1
# ---------------------------------------------------------------------------


class _EgressBarrierKillError(Exception):
    """Sentinel exception injected by the post_fire_hook in Scenario A."""


async def test_scenario_a_barrier_kill_yields_in_doubt_and_no_refire(
    store: PostgresEgressIdempotencyStore,
    migrated_url: str,
    authorized_t3_nonce: CapabilityGateNonce,
    fake_external_world: tuple[Any, _FireCounter, _CannedResponse],
) -> None:
    """Scenario A: the post_fire_hook kills the process after the upstream fires.

    The relay fires the external call (fire_count == 1), then the hook raises
    _EgressBarrierKillError before record_response runs.  The ledger row stays
    committed_no_response (in-doubt).  A subsequent identical call sees
    IntentInDoubt and the non-idempotent policy raises EgressInDoubtError
    WITHOUT re-firing (fire_count stays 1).

    This proves the at-most-once invariant (Spec C §5 H3): an in-doubt
    side-effect is NEVER blindly re-fired.
    """
    _, fire_counter, _ = fake_external_world
    extracted = _make_extracted("scenario-a")
    mock_extractor = AsyncMock()
    spy_extract = mock_extractor.extract = AsyncMock(return_value=extracted)

    ctx = _make_ctx("a")
    call_index = 0
    egress_id = compute_egress_id(ctx, call_index=call_index)

    async def _barrier_hook() -> None:
        raise _EgressBarrierKillError("simulated process kill after fire, before record")

    extractor, serve_task, shutdown, _port = await _build_loopback_stack(
        store=store,
        authorized_t3_nonce=authorized_t3_nonce,
        fake_external_world=fake_external_world,
        migrated_url=migrated_url,
        mock_extractor=mock_extractor,
        post_fire_hook=_barrier_hook,
    )

    try:
        # First call: the upstream fires (fire_count → 1), then the hook kills
        # the request before record_response.
        with pytest.raises(_EgressBarrierKillError):
            await extractor.handle(
                raw_request=_make_raw_request(idempotent=False),
                ctx=ctx,
                call_index=call_index,
                schema=_TestSchema,
                language="en",
            )

        # The hook kills BEFORE extraction runs — the extractor must NOT have
        # been called (a misplaced hook AFTER extraction would silently pass
        # the fire_count guard but violate this property).
        spy_extract.assert_not_called()

        assert fire_counter.value == 1, (
            f"expected exactly 1 upstream fire, got {fire_counter.value}"
        )

        # The ledger row must be committed_no_response (in-doubt) — the hook
        # fired BEFORE record_response, so the response was never stored.
        row_state = await _query_state(migrated_url, egress_id)
        assert row_state == "committed_no_response", (
            f"expected committed_no_response after barrier kill, got {row_state!r}"
        )

        # Second call with the SAME (ctx, call_index): commit_intent returns
        # IntentInDoubt → the non-idempotent policy raises EgressInDoubtError
        # WITHOUT dialling the relay again.
        with pytest.raises(EgressInDoubtError):
            await extractor.handle(
                raw_request=_make_raw_request(idempotent=False),
                ctx=ctx,
                call_index=call_index,
                schema=_TestSchema,
                language="en",
            )

        # fire_count must still be 1 — the in-doubt path short-circuits before
        # any network call.
        assert fire_counter.value == 1, (
            f"EgressInDoubtError must not re-fire; fire_count is {fire_counter.value}"
        )

        # The extractor must still not have been called — the in-doubt path
        # short-circuits at the ledger level, before the relay is dialled and
        # before extraction runs.
        spy_extract.assert_not_called()

    finally:
        await _teardown(serve_task, shutdown)


# ---------------------------------------------------------------------------
# Scenario B — clean fire then replay: Deduplicated, fire_count == 1
# ---------------------------------------------------------------------------


async def test_scenario_b_clean_fire_then_replay_deduplicates(
    store: PostgresEgressIdempotencyStore,
    migrated_url: str,
    authorized_t3_nonce: CapabilityGateNonce,
    fake_external_world: tuple[Any, _FireCounter, _CannedResponse],
) -> None:
    """Scenario B: a clean fire stores T2; a replay short-circuits without re-firing.

    Fire once (fire_count → 1, extractor called once, ledger reaches
    committed_with_response).  Then replay the SAME (ctx, call_index) call:
    ``fire()`` sees IntentReplayComplete and returns ``Deduplicated`` without
    dialling the relay; the extractor is NOT re-called; fire_count stays 1;
    the outcome is EgressExtractOutcome(deduplicated=True).

    This proves the dedup / memoize invariant (Spec C §5 + HARD rule #5).
    """
    _, fire_counter, _ = fake_external_world
    extracted = _make_extracted("scenario-b")
    mock_extractor = AsyncMock()
    spy_extract = mock_extractor.extract = AsyncMock(return_value=extracted)

    ctx = _make_ctx("b")
    call_index = 0
    egress_id = compute_egress_id(ctx, call_index=call_index)

    extractor, serve_task, shutdown, _port = await _build_loopback_stack(
        store=store,
        authorized_t3_nonce=authorized_t3_nonce,
        fake_external_world=fake_external_world,
        migrated_url=migrated_url,
        mock_extractor=mock_extractor,
    )

    try:
        # First call — clean fire.
        outcome_1 = await extractor.handle(
            raw_request=_make_raw_request(idempotent=True),
            ctx=ctx,
            call_index=call_index,
            schema=_TestSchema,
            language="en",
        )
        assert outcome_1.deduplicated is False, "first call must NOT be deduplicated"
        assert fire_counter.value == 1, (
            f"expected 1 fire after fresh call, got {fire_counter.value}"
        )
        spy_extract.assert_called_once()

        # Ledger must now be committed_with_response.
        row_state = await _query_state(migrated_url, egress_id)
        assert row_state == "committed_with_response", (
            f"expected committed_with_response after clean fire, got {row_state!r}"
        )

        # Second call — replay.
        outcome_2 = await extractor.handle(
            raw_request=_make_raw_request(idempotent=True),
            ctx=ctx,
            call_index=call_index,
            schema=_TestSchema,
            language="en",
        )
        assert outcome_2.deduplicated is True, "second call must be deduplicated"
        assert fire_counter.value == 1, (
            f"replay must not re-fire; fire_count is {fire_counter.value}"
        )
        # The extractor must NOT be called on a Deduplicated path (HARD rule #5).
        spy_extract.assert_called_once()  # still exactly once from the first call

    finally:
        await _teardown(serve_task, shutdown)


# ---------------------------------------------------------------------------
# Scenario C — TTL prune then re-fire
# ---------------------------------------------------------------------------


async def test_scenario_c_ttl_prune_triggers_refire(
    store: PostgresEgressIdempotencyStore,
    migrated_url: str,
    authorized_t3_nonce: CapabilityGateNonce,
    fake_external_world: tuple[Any, _FireCounter, _CannedResponse],
) -> None:
    """Scenario C: after TTL prune the same logical call re-fires.

    After a clean fire (Scenario B shape), ``prune_expired`` removes the row
    (backdated in Postgres).  A subsequent identical call finds no row →
    IntentFresh → fires the upstream again (fire_count increments).  Expiry is
    NOT a silent drop — the call can still succeed.
    """
    _, fire_counter, _ = fake_external_world
    extracted = _make_extracted("scenario-c")
    mock_extractor = AsyncMock()
    mock_extractor.extract = AsyncMock(return_value=extracted)

    ctx = _make_ctx("c")
    call_index = 0
    egress_id = compute_egress_id(ctx, call_index=call_index)

    extractor, serve_task, shutdown, _port = await _build_loopback_stack(
        store=store,
        authorized_t3_nonce=authorized_t3_nonce,
        fake_external_world=fake_external_world,
        migrated_url=migrated_url,
        mock_extractor=mock_extractor,
    )

    try:
        # Initial clean fire (fire_count → 1).
        outcome_1 = await extractor.handle(
            raw_request=_make_raw_request(idempotent=True),
            ctx=ctx,
            call_index=call_index,
            schema=_TestSchema,
            language="en",
        )
        assert outcome_1.deduplicated is False
        assert fire_counter.value == 1

        # Backdate the ledger row past the TTL window so prune_expired deletes it.
        engine = create_async_engine(migrated_url, future=True)
        try:
            async with engine.begin() as conn:
                await conn.execute(
                    sa.text(
                        "UPDATE egress_idempotency "
                        "SET committed_at = now() - interval '30 days' "
                        "WHERE egress_id = :e"
                    ),
                    {"e": egress_id},
                )
        finally:
            await engine.dispose()

        # Prune: the backdated row is swept.
        cutoff = dt.datetime.now(dt.UTC) - dt.timedelta(days=1)
        pruned = await store.prune_expired(older_than=cutoff)
        assert pruned == 1, f"expected 1 pruned row, got {pruned}"

        # Third call: no row → IntentFresh → re-fire.
        outcome_2 = await extractor.handle(
            raw_request=_make_raw_request(idempotent=True),
            ctx=ctx,
            call_index=call_index,
            schema=_TestSchema,
            language="en",
        )
        assert outcome_2.deduplicated is False, "post-prune call must NOT be deduplicated"
        assert fire_counter.value == 2, (
            f"post-prune call must re-fire; fire_count is {fire_counter.value}"
        )

    finally:
        await _teardown(serve_task, shutdown)


# ---------------------------------------------------------------------------
# 8-way concurrent commit_intent → exactly one winner
# (lifted from test_egress_idempotency_postgres.py; proves the real Postgres
# INSERT … ON CONFLICT DO NOTHING RETURNING is race-free in the full stack)
# ---------------------------------------------------------------------------


async def test_concurrent_commit_intent_exactly_one_winner(
    store: PostgresEgressIdempotencyStore,
) -> None:
    """8-way concurrent commit_intent → exactly one IntentFresh winner.

    The single-statement INSERT … ON CONFLICT (egress_id) DO NOTHING RETURNING
    is race-free: Postgres blocks the losers until the winner commits, so the
    loser's subsequent SELECT sees committed_no_response → IntentInDoubt.
    Proves the concurrency property that guards double-fire at the store level.
    """
    egress_id = "race-" + "x" * 59

    async def _commit() -> Any:
        return await store.commit_intent(
            egress_id=egress_id,
            adapter_id="ada-race",
            inbound_id="in-race",
            session_id="sess-race",
            call_index=0,
            body_hash=compute_body_hash(""),
        )

    # Wrap in a wall-clock timeout so a Postgres-pool hang surfaces as a clean
    # failure rather than a CI stall (perf-001).
    async with asyncio.timeout(30.0):
        results = await asyncio.gather(*(_commit() for _ in range(8)))
    fresh_count = sum(isinstance(r, IntentFresh) for r in results)
    in_doubt_count = sum(isinstance(r, IntentInDoubt) for r in results)

    assert fresh_count == 1, (
        f"expected exactly 1 IntentFresh winner, got {fresh_count}; "
        f"results={[type(r).__name__ for r in results]}"
    )
    assert in_doubt_count == 7, f"expected 7 IntentInDoubt losers, got {in_doubt_count}"
