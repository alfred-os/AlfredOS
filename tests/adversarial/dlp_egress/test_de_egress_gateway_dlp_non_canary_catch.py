"""Executable counterpart to ``de_egress_gateway_dlp_non_canary_catch.yaml``.

de-2026-007. Pins the compromised-core threat: when the in-core OutboundDlp
is replaced by a no-op, a secret-shaped body value escapes the core
unredacted.  The GATEWAY's DLP second pass (broker=None, stages 2+3, real
CanaryMatcher) MUST catch it and deny with ``deny_reason=dlp_redacted``.  The
in-core RelayEgressClient translates the deny frame to EgressDeniedError and
writes the ``security.egress_relay_refused`` audit row before raising.

This test runs the FULL loopback relay stack:

    EgressResponseExtractor (gate + extractor mock)
      → RelayEgressClient (real, no-op core DLP injected)
        → EgressRelay (real, REAL gateway DLP with stage-2 regex)
          → fake_external_world (never reached — denied before fire)

The no-op core DLP is the attestation instrument: it makes the gateway
PROVABLY the catcher (if the core DLP were real, the body would be redacted
BEFORE reaching the relay, and the gateway would see clean text).

Spec C §4.2 decision 12, CLAUDE.md hard rules #4/#7.
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
from alfred.security.canary_matcher import CanaryMatcher
from alfred.security.dlp import OutboundDlp
from alfred.security.quarantine import Extracted, ExtractionSchema, T3DerivedData
from alfred.security.quarantine_transport import QuarantineStagingMap, T3BodyRecorder
from alfred.security.tiers import CapabilityGateNonce
from tests.adversarial.payload_schema import AdversarialPayload
from tests.helpers.gates import make_quarantined_extract_chain_gate

_PAYLOAD_PATH = Path(__file__).parent / "de_egress_gateway_dlp_non_canary_catch.yaml"

_FAKE_HOST = "safe-upstream.example"
_FAKE_PORT = 443
_FAKE_URL = f"https://{_FAKE_HOST}/api/tool"
_FAKE_ALLOWLIST: frozenset[tuple[str, int]] = frozenset({(_FAKE_HOST, _FAKE_PORT)})


def _load_payload() -> AdversarialPayload:
    return AdversarialPayload.model_validate(yaml.safe_load(_PAYLOAD_PATH.read_text()))


def test_payload_schema_valid() -> None:
    """The corpus YAML validates with the expected shape."""
    payload = _load_payload()
    assert payload.id == "de-2026-007"
    assert payload.category == "dlp_egress"
    assert payload.expected_outcome == "caught_by_dlp"
    assert payload.ingestion_path == "web.fetch"


# ---------------------------------------------------------------------------
# No-op core DLP — the attestation instrument for de-2026-007.
# Returning the body unchanged means the secret-shaped value exits the core
# unredacted, proving the GATEWAY is the catcher.
# ---------------------------------------------------------------------------


class _NoOpDlp:
    """Core-side OutboundDlp replacement that performs NO redaction.

    This is the de-2026-007 attestation instrument: substituting this for the
    real OutboundDlp means stage-1+2 redaction does NOT fire on the core side,
    so the secret-shaped body value reaches the relay relay unredacted.  The
    gateway's second-pass DLP MUST catch it (Spec C §4.2 decision 12).
    """

    def scan_for_outbound(self, raw_body: str) -> Any:  # type: ignore[return]
        """Return the body unchanged as a ScannedOutboundBody-shaped tuple.

        We return a tuple (raw_body, fake_result) so RelayEgressClient's
        stage-1 DLP call (which unpacks the tuple at index [0]) gets the
        unredacted text verbatim.  The fake_result is not inspected.
        """
        from alfred.security.dlp import OutboundDlpScanResult, ScannedOutboundBody

        result = OutboundDlpScanResult(dlp_redactions_count=0, canary_tripped=False)
        return ScannedOutboundBody((raw_body, result))


# ---------------------------------------------------------------------------
# AuditWriter capture stub
# ---------------------------------------------------------------------------


class _CapturingAuditWriter:
    """Captures append_schema calls without touching Postgres."""

    def __init__(self) -> None:
        self.rows: list[dict[str, Any]] = []

    async def append_schema(self, **kwargs: Any) -> None:
        self.rows.append(dict(kwargs))


# ---------------------------------------------------------------------------
# Schema for extraction (the extractor should NOT be called in this test
# because the relay denies before the upstream fires)
# ---------------------------------------------------------------------------


class _TestSchema(ExtractionSchema):
    payload: str


# ---------------------------------------------------------------------------
# Loopback relay + integration fixtures (inline, mirrors barrier test)
# ---------------------------------------------------------------------------

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
async def test_gateway_dlp_catches_secret_when_core_dlp_is_noop(
    store: PostgresEgressIdempotencyStore,
    migrated_url: str,
    authorized_t3_nonce: CapabilityGateNonce,
    fake_external_world: tuple[Any, Any, Any],
) -> None:
    """Gateway DLP second pass catches a secret-shaped body when the core DLP is a no-op.

    de-2026-007: the core OutboundDlp is replaced with a no-op, so the
    api-key-shaped body token is NOT redacted at the core side.  The gateway
    relay's OutboundDlp (broker=None, stages 2+3) MUST catch it and deny with
    deny_reason=dlp_redacted.  The in-core relay client translates the deny
    to EgressDeniedError and writes the security.egress_relay_refused audit
    row before raising.  The upstream (_FakeClient) is NEVER reached because
    the gateway denies during inspection, before originating the real TLS.
    """
    payload = _load_payload()
    assert isinstance(payload.payload, dict)
    malicious_body: str = str(payload.payload["body"])

    open_client_factory, fire_counter, _canned = fake_external_world

    # Reserve a free port.
    srv = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0)
    port: int = srv.sockets[0].getsockname()[1]
    srv.close()
    await srv.wait_closed()

    # Build the gateway relay with REAL DLP (stage-2 regex will catch sk-…).
    # No canary tokens needed — the api-key-shape regex is stage 2.
    gateway_dlp = OutboundDlp(
        broker=None,
        audit=lambda **_kw: None,
        canary=CanaryMatcher(tokens=[]),  # no canary tokens; stage-2 catches it
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

    # Build the capturing audit writer and no-op core DLP.
    audit_writer = _CapturingAuditWriter()
    no_op_core_dlp = _NoOpDlp()

    relay_client = RelayEgressClient(
        relay_url=f"tcp://127.0.0.1:{port}",
        core_dlp=no_op_core_dlp,  # type: ignore[arg-type]  # test double
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

    # The extractor must NOT be called (the relay denies before the upstream fires).
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

    ctx = TurnEgressContext(adapter_id="ada-007", inbound_id="in-007", session_id="sess-007")
    raw_request = _RawToolRequest(
        method="GET",
        url=_FAKE_URL,
        headers={},
        body=malicious_body,
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

        # The deny reason must be dlp_redacted (gateway DLP caught it, not SSRF/canary).
        assert exc_info.value.deny_reason == "dlp_redacted", (
            f"Expected deny_reason='dlp_redacted', got {exc_info.value.deny_reason!r}"
        )

        # The upstream must NOT have been reached (denied during inspection).
        assert fire_counter.value == 0, (
            f"Expected fire_count=0 (relay denied before TLS origination), got {fire_counter.value}"
        )

        # Exactly one security.egress_relay_refused audit row must land (HARD rule #7).
        refused_rows = [
            r for r in audit_writer.rows if r.get("event") == "security.egress_relay_refused"
        ]
        assert len(refused_rows) == 1, (
            f"Expected exactly 1 security.egress_relay_refused row, "
            f"got {len(refused_rows)}: {refused_rows}"
        )
        row = refused_rows[0]
        assert row["subject"]["reason"] == "dlp_redacted"
        assert row["subject"]["destination"] == _FAKE_HOST

        # The extractor must NOT have been called (no T3 to extract).
        mock_extractor.extract.assert_not_called()

    finally:
        shutdown.set()
        await asyncio.wait_for(serve_task, timeout=5)
