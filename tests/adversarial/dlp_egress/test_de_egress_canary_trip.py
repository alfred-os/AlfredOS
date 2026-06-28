"""Executable counterpart to ``de_egress_canary_trip.yaml``.

de-2026-008. Pins the canary-trip-on-egress threat: a canary token in the
egress request body trips the GATEWAY relay's DLP stage-3 canary scanner.
The relay denies with ``deny_reason=canary_tripped``; the in-core
RelayEgressClient translates to EgressDeniedError and writes the
``security.egress_relay_refused`` audit row before raising.

The canary scanner is fail-loud (HARD rule #7): a match NEVER produces a
forwarded response.  The upstream (_FakeClient) is never reached.

This test seeds a specific CanaryToken into the gateway relay's OutboundDlp
and drives the body carrying that token through the real loopback relay stack.

Spec C §4.2 (G7-2b), CLAUDE.md hard rule #7.
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
from alfred.egress.egress_id import TurnEgressContext
from alfred.egress.egress_response_extract import EgressResponseExtractor
from alfred.egress.errors import EgressDeniedError
from alfred.egress.relay_client import RelayEgressClient
from alfred.egress.relay_protocol import _RawToolRequest
from alfred.gateway.egress_relay import EgressRelay
from alfred.gateway.egress_relay_audit import record_egress_relay
from alfred.memory.db import session_scope
from alfred.memory.egress_idempotency import PostgresEgressIdempotencyStore
from alfred.security import tiers as _tiers
from alfred.security.canary_matcher import CanaryMatcher, CanaryToken
from alfred.security.dlp import OutboundDlp
from alfred.security.quarantine import Extracted, ExtractionSchema, T3DerivedData
from alfred.security.quarantine_transport import QuarantineStagingMap, T3BodyRecorder
from alfred.security.tiers import CapabilityGateNonce
from tests.adversarial.payload_schema import AdversarialPayload
from tests.helpers.gates import make_quarantined_extract_chain_gate

_PAYLOAD_PATH = Path(__file__).parent / "de_egress_canary_trip.yaml"

_FAKE_HOST = "safe-upstream.example"
_FAKE_PORT = 443
_FAKE_URL = f"https://{_FAKE_HOST}/api/tool"
_FAKE_ALLOWLIST: frozenset[tuple[str, int]] = frozenset({(_FAKE_HOST, _FAKE_PORT)})


def _load_payload() -> AdversarialPayload:
    return AdversarialPayload.model_validate(yaml.safe_load(_PAYLOAD_PATH.read_text()))


def test_payload_schema_valid() -> None:
    """The corpus YAML validates with the expected shape."""
    payload = _load_payload()
    assert payload.id == "de-2026-008"
    assert payload.category == "dlp_egress"
    assert payload.expected_outcome == "caught_by_dlp"
    assert payload.ingestion_path == "web.fetch"


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


@pytest.mark.asyncio
async def test_gateway_canary_trip_denies_before_upstream_fire(
    store: PostgresEgressIdempotencyStore,
    migrated_url: str,
    authorized_t3_nonce: CapabilityGateNonce,
    fake_external_world: tuple[Any, Any, Any],
) -> None:
    """Gateway relay trips a seeded canary token and denies before the upstream fires.

    de-2026-008: a canary token is seeded in the gateway relay's CanaryMatcher.
    The egress body carries the token verbatim.  The gateway's DLP stage-3
    scanner trips, raises OutboundCanaryTripped, and the relay denies with
    deny_reason=canary_tripped — the upstream is NEVER reached.  The in-core
    relay client translates to EgressDeniedError and writes the
    security.egress_relay_refused audit row before raising.
    """
    payload = _load_payload()
    assert isinstance(payload.payload, dict)
    canary_token: str = str(payload.payload["canary_token"])
    body_with_canary: str = str(payload.payload["body"])

    open_client_factory, fire_counter, _canned = fake_external_world

    # Reserve a free port.
    srv = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0)
    port: int = srv.sockets[0].getsockname()[1]
    srv.close()
    await srv.wait_closed()

    # Build the gateway relay with the seeded canary token in its DLP.
    gateway_dlp = OutboundDlp(
        broker=None,
        audit=lambda **_kw: None,
        canary=CanaryMatcher(tokens=[CanaryToken(value=canary_token)]),
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
    # Core-side DLP has NO canary tokens — the trip happens ONLY on the gateway.
    core_dlp = OutboundDlp(broker=None, audit=lambda **_kw: None, canary=CanaryMatcher(tokens=[]))

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
            data=T3DerivedData({"payload": "should-never-reach-here"}),
            extraction_mode="native_constrained",
        )
    )

    extractor_obj = EgressResponseExtractor(
        relay_client=relay_client,
        gate=gate,
        extractor=mock_extractor,
        recorder=recorder,
    )

    ctx = TurnEgressContext(adapter_id="ada-008", inbound_id="in-008", session_id="sess-008")
    raw_request = _RawToolRequest(
        method="GET",
        url=_FAKE_URL,
        headers={},
        body=body_with_canary,
        idempotent=True,
    )

    try:
        with pytest.raises(EgressDeniedError) as exc_info:
            await extractor_obj.handle(
                raw_request=raw_request,
                ctx=ctx,
                call_index=0,
                schema=_TestSchema,
                language="en",
            )

        # The deny reason must be canary_tripped (stage-3 caught it).
        assert exc_info.value.deny_reason == "canary_tripped", (
            f"Expected deny_reason='canary_tripped', got {exc_info.value.deny_reason!r}"
        )

        # The upstream must NOT have been reached (denied during DLP inspection).
        assert fire_counter.value == 0, (
            f"Expected fire_count=0 (canary trip before TLS origination), got {fire_counter.value}"
        )

        # Exactly one security.egress_relay_refused audit row (HARD rule #7).
        refused_rows = [
            r for r in audit_writer.rows if r.get("event") == "security.egress_relay_refused"
        ]
        assert len(refused_rows) == 1, (
            f"Expected exactly 1 refused audit row, got {len(refused_rows)}"
        )
        row = refused_rows[0]
        assert row["subject"]["reason"] == "canary_tripped"
        assert row["subject"]["destination"] == _FAKE_HOST

        # The extractor must NOT have been called.
        mock_extractor.extract.assert_not_called()

    finally:
        shutdown.set()
        await asyncio.wait_for(serve_task, timeout=5)
