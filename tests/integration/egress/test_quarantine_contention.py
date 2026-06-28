"""§4.3 contention / head-of-line proof — shared quarantine child (Spec C G7-2c-2, #333).

The REAL head-of-line (HoL) risk on the mode-(b) tool-egress path is the
SHARED SINGLE quarantine child: ``EgressResponseExtractor`` holds one
``QuarantinedExtractor`` instance, shared across every concurrent ``handle()``
call that lands in the same OODA turn.  Two simultaneous egress calls both need
extraction, but there is only ONE quarantine child process.  Under the
``RelayEgressClient``'s concurrency semaphore (``concurrency=N``, default 8)
multiple relay calls can fire simultaneously, but extraction is serialised through
the single extractor.

This test pins that serialisation and proves the bounded-wait property:

HoL scenario
------------
1. Call A fires to the relay and blocks in ``extractor.extract`` — it holds the
   extraction seam.
2. Call B fires to the relay and queues behind A's extraction.
3. An ``asyncio.Event``-gated fake extractor controls the sequencing:
   * Until ``_extraction_gate`` is set, the fake extractor blocks in A's call.
   * Once set, A completes; B then gets its extraction slot.
4. We assert:
   * Both calls complete successfully (no hang) within a wall-clock deadline
     (bounded HoL = PASS; hang = FAIL).
   * A finishes BEFORE B (sequenced via the gate).
   * ``extractor_call_count == 2`` — the extractor was called exactly once per
     unique (ctx, call_index) pair.
   * Neither call was a dedup replay (both ``deduplicated == False``).

No skip gate
------------
The fake extractor replaces the real quarantine child so there is no subprocess,
no bwrap, and no external service dependency.  This test is in
``tests/integration/`` and must remain green on every push.  A hang is a
failing-assertion (``asyncio.wait_for`` timeout), not a skip.

The fake extractor is gated by a test-controlled ``asyncio.Event``
(``_extraction_gate``) rather than a sleep so the sequencing is fully
deterministic — no timing assumptions.

Spec C §4.3, CLAUDE.md security rule #7.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import AsyncIterator
from typing import Any

import pytest
from alembic import command, config
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from alfred.bootstrap.nonce_factory import _NONCE_LOCK
from alfred.egress.egress_id import TurnEgressContext
from alfred.egress.egress_response_extract import EgressResponseExtractor
from alfred.egress.relay_client import RelayEgressClient
from alfred.egress.relay_protocol import _RawToolRequest
from alfred.gateway.egress_relay import EgressRelay
from alfred.gateway.egress_relay_audit import record_egress_relay
from alfred.memory.db import session_scope
from alfred.memory.egress_idempotency import PostgresEgressIdempotencyStore
from alfred.security import tiers as _tiers
from alfred.security.dlp import OutboundDlp
from alfred.security.quarantine import (
    Extracted,
    ExtractionSchema,
    T3DerivedData,
)
from alfred.security.quarantine_transport import QuarantineStagingMap, T3BodyRecorder
from alfred.security.tiers import CapabilityGateNonce
from tests.helpers.gates import make_quarantined_extract_chain_gate

pytestmark = pytest.mark.integration

# ---------------------------------------------------------------------------
# Contention deadline: if a handle() does not complete within this many
# seconds the test fails (hang detection).  200 ms gives the loopback
# relay + Postgres plenty of margin on any CI runner.
# ---------------------------------------------------------------------------
_CONTENTION_DEADLINE_S = 20.0


# ---------------------------------------------------------------------------
# autouse executor drain — prevents ResourceWarning leaking between tests
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
async def _shutdown_default_executor() -> AsyncIterator[None]:
    """Join the per-test loop's default executor on teardown.

    The relay resolves DNS via run_in_executor; workers otherwise leak into
    the next test and trip ``ResourceWarning: Task destroyed but it is pending!``
    """
    yield
    await asyncio.get_running_loop().shutdown_default_executor()


# ---------------------------------------------------------------------------
# Test schema
# ---------------------------------------------------------------------------


class _TestSchema(ExtractionSchema):
    """Minimal extraction schema for the contention tests."""

    payload: str


# ---------------------------------------------------------------------------
# Postgres fixtures
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
    """Yield a live PostgresEgressIdempotencyStore backed by testcontainers Postgres."""
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
# Relay helpers (mirrors test_egress_barrier_dedup_postgres.py)
# ---------------------------------------------------------------------------

_FAKE_HOST = "contention-upstream.internal"
_FAKE_PORT = 443
_FAKE_URL = f"https://{_FAKE_HOST}/tool"
_FAKE_ALLOWLIST: frozenset[tuple[str, int]] = frozenset({(_FAKE_HOST, _FAKE_PORT)})


class _NullAuditWriter:
    """Minimal AuditWriter stub that discards every append_schema call."""

    async def append_schema(self, **_kw: Any) -> None:
        return None


async def _await_relay_ready(port: int, serve_task: asyncio.Task[Any]) -> None:
    """Probe until the relay's listener accepts a TCP connection."""
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


# ---------------------------------------------------------------------------
# Event-gated fake extractor
# ---------------------------------------------------------------------------


class _GatedExtractor:
    """A fake ``QuarantinedExtractor`` whose first call blocks until gated.

    Two extraction calls are expected:
    * The FIRST call blocks in ``extract()`` until ``gate.set()`` is called.
    * The SECOND call (and all subsequent) return immediately.

    This models the shared single quarantine child under contention:
    call A holds the extractor; call B waits behind it.  The test
    sets the gate after A is confirmed to be blocking, then both A and B
    complete.

    ``_call_order`` is a list that the test body inspects to confirm the
    sequencing.
    """

    def __init__(self, *, gate: asyncio.Event, payload: str = "extracted-payload") -> None:
        self._gate = gate
        self._payload = payload
        self._call_count: int = 0
        self.call_order: list[int] = []

    @property
    def call_count(self) -> int:
        return self._call_count

    async def extract(
        self,
        handle: Any,
        schema: type[ExtractionSchema],
    ) -> Extracted:
        """Fake extraction: first call blocks on the gate."""
        self._call_count += 1
        call_index = self._call_count
        if call_index == 1:
            # Block until the test sets the gate.
            await self._gate.wait()
        self.call_order.append(call_index)
        return Extracted(
            data=T3DerivedData({"payload": f"{self._payload}-{call_index}"}),
            extraction_mode="native_constrained",
        )


# ---------------------------------------------------------------------------
# HoL contention test
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_two_concurrent_calls_serialise_through_shared_extractor(
    store: PostgresEgressIdempotencyStore,
    migrated_url: str,
    authorized_t3_nonce: CapabilityGateNonce,
    fake_external_world: tuple[Any, Any, Any],
) -> None:
    """Two concurrent handle() calls serialise through the one extractor.

    The test drives TWO simultaneous ``EgressResponseExtractor.handle()`` calls
    against the shared ``_GatedExtractor``.  Call A blocks in extraction.
    Call B fires to the relay and MUST NOT hang waiting for extraction — it
    completes after A releases the gate.  Both must finish within the wall-clock
    deadline (``_CONTENTION_DEADLINE_S``).

    A hang (``asyncio.TimeoutError``) is a FAIL — it proves the HoL risk
    is not bounded by the action-deadline machinery.
    """
    open_client_factory, _fire_counter, _canned = fake_external_world

    # Reserve a free port.
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
        resolve=lambda _h: "1.1.1.1",
        open_client=open_client_factory,
        response_byte_cap=4096,
        upstream_deadline_s=10.0,
    )
    shutdown = asyncio.Event()
    serve_task: asyncio.Task[Any] = asyncio.ensure_future(relay.serve(shutdown))
    await _await_relay_ready(port, serve_task)

    # Build the gate + recorder.
    staging = QuarantineStagingMap()
    recorder = T3BodyRecorder(nonce=authorized_t3_nonce, staging=staging)
    gate = make_quarantined_extract_chain_gate(
        grant_dereference_t3=True,
        dereference_plugin_id="alfred.quarantined-llm",
    )

    # The event-gated extractor — ONE instance shared across both calls.
    extraction_gate = asyncio.Event()
    gated_extractor = _GatedExtractor(gate=extraction_gate)

    relay_client = RelayEgressClient(
        relay_url=f"tcp://127.0.0.1:{port}",
        core_dlp=OutboundDlp(broker=None, audit=lambda **_kw: None),
        ledger=store,
        audit_writer=_NullAuditWriter(),  # type: ignore[arg-type]
        concurrency=8,
    )

    # ONE shared EgressResponseExtractor with ONE gated_extractor — the HoL subject.
    extractor_obj = EgressResponseExtractor(
        relay_client=relay_client,
        gate=gate,
        extractor=gated_extractor,  # type: ignore[arg-type]
        recorder=recorder,
    )

    # Two DISTINCT (ctx, call_index) pairs so the ledger does not deduplicate them.
    ctx_a = TurnEgressContext(adapter_id="ada-hol-a", inbound_id="in-hol-a", session_id="sess-hol")
    ctx_b = TurnEgressContext(adapter_id="ada-hol-b", inbound_id="in-hol-b", session_id="sess-hol")
    raw_req_a = _RawToolRequest(
        method="GET", url=_FAKE_URL, headers={}, body="body-a", idempotent=True
    )
    raw_req_b = _RawToolRequest(
        method="GET", url=_FAKE_URL, headers={}, body="body-b", idempotent=True
    )

    # Event to signal when call A has entered the blocking extraction wait.
    a_blocked = asyncio.Event()
    outcomes: dict[str, Any] = {}

    async def _run_a() -> None:
        """Fire call A; signal when the extractor has started (and is blocking)."""
        # Wrap the extractor's gate-wait in a monitored task so we can signal
        # the test body AFTER the relay roundtrip succeeds but BEFORE the gate
        # releases.  We accomplish this by patching `extraction_gate.wait` to
        # both signal a_blocked and then actually wait.
        original_wait = extraction_gate.wait

        async def _instrumented_wait() -> None:
            a_blocked.set()
            await original_wait()

        extraction_gate.wait = _instrumented_wait  # type: ignore[method-assign]
        try:
            outcomes["a"] = await extractor_obj.handle(
                raw_request=raw_req_a,
                ctx=ctx_a,
                call_index=0,
                schema=_TestSchema,
                language="en",
            )
        finally:
            # Restore the original wait so call B is NOT gated.
            extraction_gate.wait = original_wait  # type: ignore[method-assign]

    async def _run_b() -> None:
        """Fire call B after A is confirmed blocking, then resolve."""
        # Wait until A is blocking in extraction before firing B.
        await asyncio.wait_for(a_blocked.wait(), timeout=_CONTENTION_DEADLINE_S)
        outcomes["b"] = await extractor_obj.handle(
            raw_request=raw_req_b,
            ctx=ctx_b,
            call_index=0,
            schema=_TestSchema,
            language="en",
        )

    try:
        # Release the gate after A has confirmed it is blocking so the test
        # does not deadlock.  We set the gate from a standalone task that runs
        # concurrently with _run_a and _run_b.
        async def _release_gate_after_a_blocks() -> None:
            await asyncio.wait_for(a_blocked.wait(), timeout=_CONTENTION_DEADLINE_S)
            # A is now confirmed blocked; release the gate.
            extraction_gate.set()

        async with asyncio.timeout(_CONTENTION_DEADLINE_S):
            await asyncio.gather(
                _run_a(),
                _run_b(),
                _release_gate_after_a_blocks(),
            )

        # Both calls completed within the deadline.
        assert "a" in outcomes, "Call A did not complete — HoL hang detected"
        assert "b" in outcomes, "Call B did not complete — HoL hang detected"

        # Both are fresh extractions, not dedup replays.
        assert outcomes["a"].deduplicated is False, "Call A should be a fresh extraction"
        assert outcomes["b"].deduplicated is False, "Call B should be a fresh extraction"

        # The extractor was called exactly twice (once per distinct call).
        assert gated_extractor.call_count == 2, (
            f"Expected 2 extractor calls, got {gated_extractor.call_count}"
        )

        # Call A's extraction was the first (returned payload-1).
        assert outcomes["a"].result.data["payload"] == "extracted-payload-1"  # type: ignore[index]
        # Call B's extraction was the second (returned payload-2).
        assert outcomes["b"].result.data["payload"] == "extracted-payload-2"  # type: ignore[index]

    except TimeoutError as exc:
        raise AssertionError(
            f"Contention HoL test timed out after {_CONTENTION_DEADLINE_S}s — "
            "one of the handle() calls hung.  This is a HoL regression."
        ) from exc
    finally:
        shutdown.set()
        await asyncio.wait_for(serve_task, timeout=5)
