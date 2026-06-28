"""Executable counterpart to ``de_egress_io_plane_down_audit.yaml``.

de-2026-010. Pins the IO-plane-down audit completeness contract: every typed
refusal path in RelayEgressClient MUST write exactly one
``security.egress_relay_refused`` audit row BEFORE raising the error.

Three paths under test:

* RelayIOPlaneUnavailableError — relay unreachable (OSError on connect).
  Reason token: ``"io_plane_unavailable"``.
* EgressDeniedError — gateway deny frame (destination not allowlisted here).
  Reason token: ``EgressRelayDenyReason.DESTINATION_NOT_ALLOWLISTED.value``.
* EgressInDoubtError — in-doubt ledger state + non-idempotent call.
  Reason token: ``"egress_in_doubt"``.

Each path must produce EXACTLY ONE ``security.egress_relay_refused`` row
with the correct closed-vocab reason token.  Zero rows or a swallowed error
is a HARD rule #7 violation.

These tests do NOT need the full loopback relay stack for the
IOPlaneUnavailableError and EgressInDoubtError paths — a direct call to
RelayEgressClient.fire() with a mock ledger/non-existent relay is enough.
For EgressDeniedError we drive the deny frame via a real relay on loopback
(the gateway refuses the destination so the body never reaches the upstream).

CLAUDE.md hard rule #7, Spec C §6.
"""

from __future__ import annotations

import asyncio
import contextlib
from pathlib import Path
from typing import Any

import pytest
import yaml
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from alfred.bootstrap.nonce_factory import _NONCE_LOCK
from alfred.egress.egress_id import TurnEgressContext
from alfred.egress.errors import EgressDeniedError, EgressInDoubtError
from alfred.egress.relay_client import RelayEgressClient
from alfred.egress.relay_protocol import _RawToolRequest
from alfred.gateway.egress_relay import EgressRelay
from alfred.gateway.egress_relay_audit import record_egress_relay
from alfred.memory.db import session_scope
from alfred.memory.egress_idempotency import IntentInDoubt, PostgresEgressIdempotencyStore
from alfred.security import tiers as _tiers
from alfred.security.canary_matcher import CanaryMatcher
from alfred.security.dlp import OutboundDlp
from alfred.security.tiers import CapabilityGateNonce
from tests.adversarial.payload_schema import AdversarialPayload

_PAYLOAD_PATH = Path(__file__).parent / "de_egress_io_plane_down_audit.yaml"


def _load_payload() -> AdversarialPayload:
    return AdversarialPayload.model_validate(yaml.safe_load(_PAYLOAD_PATH.read_text()))


def test_payload_schema_valid() -> None:
    payload = _load_payload()
    assert payload.id == "de-2026-010"
    assert payload.category == "dlp_egress"
    assert payload.expected_outcome == "audit_row_emitted"
    assert payload.ingestion_path == "web.fetch"


class _CapturingAuditWriter:
    def __init__(self) -> None:
        self.rows: list[dict[str, Any]] = []

    async def append_schema(self, **kwargs: Any) -> None:
        self.rows.append(dict(kwargs))


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


@pytest.mark.asyncio
async def test_relay_unreachable_emits_audit_row_before_raise(
    store: PostgresEgressIdempotencyStore,
    migrated_url: str,
) -> None:
    """Path 1: relay unreachable → RelayIOPlaneUnavailableError + audit row.

    de-2026-010 path 1: the relay URL points to a port with no listener.
    RelayEgressClient.fire() catches the OSError, writes the
    security.egress_relay_refused audit row with reason=io_plane_unavailable,
    then raises RelayIOPlaneUnavailableError.  Exactly one row must land
    BEFORE the raise (HARD rule #7).
    """
    from alfred.egress.errors import RelayIOPlaneUnavailableError

    audit_writer = _CapturingAuditWriter()
    core_dlp = OutboundDlp(broker=None, audit=lambda **_kw: None)

    # Point the relay client at a port with no listener (connection refused).
    relay_client = RelayEgressClient(
        relay_url="tcp://127.0.0.1:1",  # port 1 — guaranteed no listener
        core_dlp=core_dlp,
        ledger=store,
        audit_writer=audit_writer,  # type: ignore[arg-type]
        concurrency=2,
        per_call_timeout=5.0,
    )

    ctx = TurnEgressContext(adapter_id="ada-010-1", inbound_id="in-010-1", session_id="s-010-1")
    raw_request = _RawToolRequest(
        method="GET",
        url="https://safe-upstream.example/tool",
        headers={},
        body="safe-body",
        idempotent=True,
    )

    with pytest.raises(RelayIOPlaneUnavailableError):
        await relay_client.fire(raw_request=raw_request, ctx=ctx, call_index=0)

    # Exactly one security.egress_relay_refused audit row with reason=io_plane_unavailable.
    refused = [r for r in audit_writer.rows if r.get("event") == "security.egress_relay_refused"]
    assert len(refused) == 1, f"Expected 1 audit row, got {len(refused)}: {refused}"
    assert refused[0]["subject"]["reason"] == "io_plane_unavailable"
    assert refused[0]["subject"]["destination"] == "safe-upstream.example"


@pytest.mark.asyncio
async def test_gateway_deny_emits_audit_row_before_raise(
    store: PostgresEgressIdempotencyStore,
    migrated_url: str,
    authorized_t3_nonce: CapabilityGateNonce,
    fake_external_world: tuple[Any, Any, Any],
) -> None:
    """Path 2: gateway deny frame → EgressDeniedError + audit row.

    de-2026-010 path 2: the request targets a destination NOT in the relay's
    allowlist.  The relay returns a deny frame (destination_not_allowlisted).
    RelayEgressClient.fire() writes the security.egress_relay_refused audit
    row with the deny_reason, then raises EgressDeniedError.  Exactly one
    row (HARD rule #7).
    """
    open_client_factory, fire_counter, _canned = fake_external_world

    # Reserve a free port.
    srv = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0)
    port: int = srv.sockets[0].getsockname()[1]
    srv.close()
    await srv.wait_closed()

    # Empty allowlist → every destination is denied.
    gateway_dlp = OutboundDlp(
        broker=None, audit=lambda **_kw: None, canary=CanaryMatcher(tokens=[])
    )
    relay = EgressRelay(
        tool_allowlist=frozenset(),  # empty — all destinations denied
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
        concurrency=2,
    )

    ctx = TurnEgressContext(adapter_id="ada-010-2", inbound_id="in-010-2", session_id="s-010-2")
    raw_request = _RawToolRequest(
        method="GET",
        url="https://blocked-destination.example/tool",
        headers={},
        body="safe-body",
        idempotent=True,
    )

    try:
        with pytest.raises(EgressDeniedError) as exc_info:
            await relay_client.fire(raw_request=raw_request, ctx=ctx, call_index=0)

        # The upstream must NOT have been reached.
        assert fire_counter.value == 0

        # Exactly one audit row with the deny reason.
        refused = [
            r for r in audit_writer.rows if r.get("event") == "security.egress_relay_refused"
        ]
        assert len(refused) == 1, f"Expected 1 audit row, got {len(refused)}"
        assert refused[0]["subject"]["reason"] == exc_info.value.deny_reason

    finally:
        shutdown.set()
        await asyncio.wait_for(serve_task, timeout=5)


@pytest.mark.asyncio
async def test_in_doubt_emits_audit_row_before_raise(
    store: PostgresEgressIdempotencyStore,
    migrated_url: str,
) -> None:
    """Path 3: in-doubt (committed_no_response) + non-idempotent → EgressInDoubtError + row.

    de-2026-010 path 3: a stub ledger returns IntentInDoubt for a non-idempotent
    call.  RelayEgressClient.fire() must write the security.egress_relay_refused
    audit row with reason=egress_in_doubt BEFORE raising EgressInDoubtError.
    Exactly one row (HARD rule #7).
    """

    # Stub ledger that always returns IntentInDoubt (simulates in-doubt state).
    class _AlwaysInDoubtLedger:
        async def commit_intent(self, **_kw: Any) -> Any:
            return IntentInDoubt()

        async def record_response(self, **_kw: Any) -> None:
            return None

        async def prune_expired(self, **_kw: Any) -> int:
            return 0

    audit_writer = _CapturingAuditWriter()
    core_dlp = OutboundDlp(broker=None, audit=lambda **_kw: None)

    relay_client = RelayEgressClient(
        relay_url="tcp://127.0.0.1:1",  # port doesn't matter — in-doubt short-circuits
        core_dlp=core_dlp,
        ledger=_AlwaysInDoubtLedger(),  # type: ignore[arg-type]
        audit_writer=audit_writer,  # type: ignore[arg-type]
        concurrency=2,
    )

    ctx = TurnEgressContext(adapter_id="ada-010-3", inbound_id="in-010-3", session_id="s-010-3")
    raw_request = _RawToolRequest(
        method="GET",
        url="https://safe-upstream.example/tool",
        headers={},
        body="safe-body",
        idempotent=False,  # non-idempotent → must refuse on in-doubt
    )

    with pytest.raises(EgressInDoubtError):
        await relay_client.fire(raw_request=raw_request, ctx=ctx, call_index=0)

    # Exactly one security.egress_relay_refused audit row with reason=egress_in_doubt.
    refused = [r for r in audit_writer.rows if r.get("event") == "security.egress_relay_refused"]
    assert len(refused) == 1, f"Expected 1 audit row, got {len(refused)}: {refused}"
    assert refused[0]["subject"]["reason"] == "egress_in_doubt"
    assert refused[0]["subject"]["destination"] == "safe-upstream.example"
