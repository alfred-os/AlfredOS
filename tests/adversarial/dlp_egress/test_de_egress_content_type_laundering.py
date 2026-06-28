"""Executable counterpart to ``de_egress_content_type_laundering.yaml``.

de-2026-011. Pins the content-type-laundering threat: a malicious or compromised
upstream returns a response whose declared Content-Type is off the web.fetch MIME
allowlist (``application/octet-stream``), attempting to smuggle binary bytes into
the quarantined extractor.

The C2 D1 pre-extract seam (:func:`~alfred.egress.response_inspection.inspect_response`)
detects the disallowed MIME type and returns
:class:`~alfred.egress.response_inspection._SoftRefusal` with
``subject_token="mime_type_not_allowed"``.
:meth:`~alfred.egress.egress_response_extract.EgressResponseExtractor.handle`
maps this to ``TypedRefusal(reason="cannot_extract")``, records it to the ledger
(``committed_with_response``), and returns — the quarantined extractor is NEVER
called and the binary bytes NEVER reach the quarantined LLM (HARD rule #5).

This test drives the FULL loopback relay stack:

    EgressResponseExtractor (web.fetch ResponsePolicy; mock extractor as spy)
      → RelayEgressClient (real; real Postgres ledger)
        → EgressRelay (real; standard DLP — no canary tokens needed)
          → fake_external_world (REACHED: upstream returns application/octet-stream)

Unlike de-2026-007 / de-2026-008 (gateway outbound-DLP + canary catches):

* ``fire_counter.value == 1`` — the upstream IS reached.  The outbound request
  goes through the relay fine; the bad Content-Type is on the INBOUND response.
  The D1 refusal is on the response side, not the request side.
* No ``security.egress_relay_refused`` audit row is written.  That row is only
  written by :meth:`~alfred.egress.relay_client.RelayEgressClient._audit_refused`
  on relay-level error paths; the D1 soft refusal is a C2-level return, not a
  relay-level deny.

Spec C G7-2.5 Task 4, CLAUDE.md hard rule #5.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import pytest
import sqlalchemy as sa
import yaml
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from alfred.egress.egress_id import TurnEgressContext, compute_egress_id
from alfred.egress.egress_response_extract import (
    _EXTRACTION_RESULT_ADAPTER,
    EgressResponseExtractor,
)
from alfred.egress.relay_client import RelayEgressClient
from alfred.egress.relay_protocol import _RawToolRequest
from alfred.egress.response_inspection import ResponsePolicy
from alfred.gateway.egress_relay import EgressRelay
from alfred.gateway.egress_relay_audit import record_egress_relay
from alfred.memory.db import session_scope
from alfred.memory.egress_idempotency import PostgresEgressIdempotencyStore
from alfred.security.canary_matcher import CanaryMatcher
from alfred.security.dlp import OutboundDlp
from alfred.security.quarantine import Extracted, ExtractionSchema, T3DerivedData, TypedRefusal
from alfred.security.quarantine_transport import QuarantineStagingMap, T3BodyRecorder
from alfred.security.tiers import CapabilityGateNonce
from tests.adversarial.payload_schema import AdversarialPayload
from tests.helpers.egress_doubles import (
    _await_bound_port,
    _await_relay_ready,
    _CapturingAuditWriter,
)
from tests.helpers.gates import make_quarantined_extract_chain_gate

_PAYLOAD_PATH = Path(__file__).parent / "de_egress_content_type_laundering.yaml"

# Canonical web.fetch MIME allowlist (Spec C G7-2.5 Task 4).
_WEB_FETCH_MIME_ALLOWLIST: frozenset[str] = frozenset(
    {"text/html", "text/plain", "application/json", "application/xml", "text/markdown"}
)

_FAKE_HOST = "safe-upstream.example"
_FAKE_PORT = 443
_FAKE_URL = f"https://{_FAKE_HOST}/api/data"
_FAKE_ALLOWLIST: frozenset[tuple[str, int]] = frozenset({(_FAKE_HOST, _FAKE_PORT)})


def _load_payload() -> AdversarialPayload:
    return AdversarialPayload.model_validate(yaml.safe_load(_PAYLOAD_PATH.read_text()))


def test_payload_schema_valid() -> None:
    """The corpus YAML validates with the expected shape."""
    payload = _load_payload()
    assert payload.id == "de-2026-011"
    assert payload.category == "dlp_egress"
    assert payload.expected_outcome == "caught_by_dlp"
    assert payload.ingestion_path == "web.fetch"


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


async def _query_ledger_row(migrated_url: str, egress_id: str) -> dict[str, Any] | None:
    """Return the egress_idempotency ledger row for ``egress_id``, or ``None``."""
    engine = create_async_engine(migrated_url, future=True)
    try:
        async with engine.connect() as conn:
            result = await conn.execute(
                sa.text(
                    "SELECT state, response, language FROM egress_idempotency WHERE egress_id = :e"
                ),
                {"e": egress_id},
            )
            rec = result.fetchone()
            if rec is None:
                return None
            return {"state": rec[0], "response": rec[1], "language": rec[2]}
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_content_type_laundering_refused_pre_extract(
    store: PostgresEgressIdempotencyStore,
    migrated_url: str,
    authorized_t3_nonce: CapabilityGateNonce,
    fake_external_world: tuple[Any, Any, Any],
) -> None:
    """D1 pre-extract seam refuses application/octet-stream before calling the extractor.

    de-2026-011: the fake upstream returns Content-Type: application/octet-stream
    (off the web.fetch MIME allowlist).  The C2 D1 inspection seam
    (:func:`~alfred.egress.response_inspection.inspect_response`) returns
    ``_SoftRefusal(mime_type_not_allowed)``.
    :meth:`~alfred.egress.egress_response_extract.EgressResponseExtractor.handle`
    maps this to ``TypedRefusal(cannot_extract)``, records it to the ledger
    (``committed_with_response``), and returns WITHOUT calling the quarantined
    extractor.

    Key invariants under test
    -------------------------
    * ``outcome.result`` is ``TypedRefusal(reason="cannot_extract")`` — structural T2.
    * ``outcome.policy_refusal_token == "mime_type_not_allowed"`` — closed-vocab
      audit subject token; NEVER the attacker Content-Type value.
    * ``mock_extractor.extract.assert_not_called()`` — binary bytes never reach
      the quarantined LLM (HARD rule #5).
    * ``fire_counter.value == 1`` — the upstream IS reached; the D1 refusal is on
      the inbound RESPONSE, not the outbound request.
    * Ledger row transitions to ``committed_with_response`` storing
      ``TypedRefusal(cannot_extract).model_dump_json()`` — replay short-circuits
      (Spec C §5) without re-fetching.
    * Payload-blind: ``"application/octet-stream"`` MUST NOT appear in the stored
      ledger value or any T2 field (HARD rule #5).
    """
    payload = _load_payload()
    assert isinstance(payload.payload, dict)
    off_allowlist_content_type: str = str(payload.payload["content_type"])
    binary_body: bytes = bytes.fromhex(str(payload.payload["body_hex"]))

    open_client_factory, fire_counter, canned = fake_external_world

    # Configure the fake upstream to return the attacker's off-allowlist Content-Type
    # with a PNG magic-byte body (simulates binary smuggling attempt).
    canned.status_code = 200
    canned.headers = {"content-type": off_allowlist_content_type}
    canned.body = binary_body

    # Gateway relay with standard outbound DLP — no canary needed.  The outbound
    # request body is clean; the laundering is on the inbound content-type.
    gateway_dlp = OutboundDlp(
        broker=None,
        audit=lambda **_kw: None,
        canary=CanaryMatcher(tokens=[]),
    )
    # CR-14: bind directly to port 0 (NO close-then-rebind free-port reservation
    # TOCTOU) and read the OS-assigned port back off the relay once it binds.
    relay = EgressRelay(
        tool_allowlist=_FAKE_ALLOWLIST,
        dlp=gateway_dlp,
        audit=record_egress_relay,
        bind_host="127.0.0.1",
        port=0,
        resolve=lambda _h: "1.1.1.1",
        open_client=open_client_factory,
        response_byte_cap=4096,
        upstream_deadline_s=10.0,
    )
    shutdown = asyncio.Event()
    serve_task: asyncio.Task[Any] = asyncio.ensure_future(relay.serve(shutdown))
    port = await _await_bound_port(relay, serve_task)
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

    # The extractor MUST NOT be called (D1 refuses before minting a ContentHandle).
    mock_extractor = AsyncMock()
    mock_extractor.extract = AsyncMock(
        return_value=Extracted(
            data=T3DerivedData({"payload": "should-never-reach-here"}),
            extraction_mode="native_constrained",
        )
    )

    # web.fetch's ResponsePolicy: canonical MIME allowlist; 10 MiB cap; no canary.
    response_policy = ResponsePolicy(
        mime_allowlist=_WEB_FETCH_MIME_ALLOWLIST,
        max_bytes=10 * 1024 * 1024,
        canary=None,
    )

    extractor_obj = EgressResponseExtractor(
        relay_client=relay_client,
        gate=gate,
        extractor=mock_extractor,
        recorder=recorder,
        response_policy=response_policy,
    )

    ctx = TurnEgressContext(adapter_id="ada-011", inbound_id="in-011", session_id="sess-011")
    raw_request = _RawToolRequest(
        method="GET",
        url=_FAKE_URL,
        headers={},
        body="",
        idempotent=True,
    )

    try:
        outcome = await extractor_obj.handle(
            raw_request=raw_request,
            ctx=ctx,
            call_index=0,
            schema=_TestSchema,
            language="en",
        )

        # --- Core outcome assertions ---

        # D1 soft refusal returns TypedRefusal(cannot_extract) — structural T2.
        assert isinstance(outcome.result, TypedRefusal), (
            f"Expected TypedRefusal, got {type(outcome.result)}"
        )
        assert outcome.result.reason == "cannot_extract", (
            f"Expected reason='cannot_extract', got {outcome.result.reason!r}"
        )
        assert outcome.deduplicated is False
        # The closed-vocab audit token, NOT the attacker Content-Type string.
        assert outcome.policy_refusal_token == "mime_type_not_allowed", (  # noqa: S105
            f"Expected policy_refusal_token='mime_type_not_allowed', "
            f"got {outcome.policy_refusal_token!r}"
        )

        # --- Extractor-not-called assertion ---

        # quarantined_to_structured must NEVER be entered: binary bytes must not
        # reach the quarantined LLM (HARD rule #5).
        mock_extractor.extract.assert_not_called()

        # CR-15 / CR-cloud-13: the D1 MIME refusal returns BEFORE minting a
        # ContentHandle / staging the T3 body, so nothing can orphan — the staging
        # map is empty (no raw T3 body alive after the refusal).
        assert len(staging._staged) == 0, (
            f"No-orphan BREACH (MIME refusal): staging map non-empty: {staging._staged!r}"
        )

        # --- Upstream-reached assertion ---

        # The D1 seam inspects the INBOUND response: the relay fires the outbound
        # request to the upstream (fire_counter == 1), receives the response, and
        # returns it to C2 as Fired.  C2 then runs inspect_response and refuses.
        # Unlike de-2026-007 (gateway deny before fire), here the upstream IS reached.
        assert fire_counter.value == 1, (
            f"Expected fire_count=1 (upstream reached; D1 refuses on response), "
            f"got {fire_counter.value}"
        )

        # --- Ledger committed_with_response assertion ---

        # The D1 soft refusal path records TypedRefusal(cannot_extract) to the ledger
        # (committed_with_response) so a §5 replay returns Deduplicated without
        # re-fetching the hostile upstream.
        egress_id = compute_egress_id(ctx, call_index=0)
        ledger_row = await _query_ledger_row(migrated_url, egress_id)
        assert ledger_row is not None, (
            f"Expected a ledger row for egress_id={egress_id!r}; got None"
        )
        assert ledger_row["state"] == "committed_with_response", (
            f"Expected state='committed_with_response'; got {ledger_row['state']!r}"
        )
        assert ledger_row["language"] == "en"

        # Stored value round-trips as TypedRefusal(cannot_extract).
        stored_response: str = str(ledger_row["response"])
        replayed = _EXTRACTION_RESULT_ADAPTER.validate_json(stored_response)
        assert isinstance(replayed, TypedRefusal), (
            f"Expected stored value to deserialise as TypedRefusal; got {type(replayed)}"
        )
        assert replayed.reason == "cannot_extract"

        # --- Payload-blind assertions ---

        # The attacker Content-Type MUST NOT leak into any T2 output (HARD rule #5).
        assert off_allowlist_content_type not in stored_response, (
            f"PAYLOAD LEAK: attacker Content-Type {off_allowlist_content_type!r} "
            f"appeared in the stored ledger response"
        )
        assert off_allowlist_content_type not in outcome.result.model_dump_json(), (
            "PAYLOAD LEAK: attacker Content-Type appeared in outcome.result.model_dump_json()"
        )
        # policy_refusal_token is the closed-vocab token, NOT the attacker value.
        assert outcome.policy_refusal_token != off_allowlist_content_type
        # Binary body bytes must not appear in the stored refusal value.
        assert binary_body.decode("latin-1") not in stored_response, (
            "PAYLOAD LEAK: binary body bytes appeared in the stored ledger response"
        )

        # --- Audit row shape assertion ---

        # No security.egress_relay_refused row is written on the D1 soft-refusal
        # path — that row is only emitted by RelayEgressClient._audit_refused on
        # relay-level error paths (EgressDeniedError / RelayIOPlaneUnavailableError /
        # EgressInDoubtError), not on C2-level TypedRefusal returns.
        refused_rows = [
            r for r in audit_writer.rows if r.get("event") == "security.egress_relay_refused"
        ]
        assert len(refused_rows) == 0, (
            f"Unexpected security.egress_relay_refused rows on D1 path: {refused_rows}"
        )

    finally:
        shutdown.set()
        await asyncio.wait_for(serve_task, timeout=5)
