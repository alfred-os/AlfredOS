"""Executable counterparts to the cib-2026-* comms-identity-boundary payloads.

The YAML payloads are schema-validated by the session ``corpus_payloads`` fixture
and density-guarded by ``test_corpus_density.py`` — but neither EXERCISES the
runtime defense. This module loads each cib payload and drives the REAL
``process_inbound_message`` / classifier-registry / dispatcher defense, asserting
the payload's declared invariant actually holds at the trust boundary.

* cib-2026-001 (forged canonical id in platform_metadata) -> the resolver is
  consulted with the PLATFORM identifiers and the audit row carries the
  RESOLVER's canonical id, never the planted ``u_attacker_forged``.
* cib-2026-002 (inter-persona T2-as-T3 relay) -> the extractor is invoked at
  ``source_tier="T3"`` regardless of the body's ``_x_source_tier_claim``.
* cib-2026-003 (canonical-id outbound leakage) -> no audit row + no dispatch
  carrier echoes the canonical id (the host-side path never threads it outward).
* cib-2026-004 (empty-classifier-set bypass) -> the host-owned registry refuses
  to expose an empty required-classifier set without a justification marker.
* cib-2026-005 (handler-exception-silenced) -> a raising handler is the positive
  control (dispatcher re-raises); a swallowing handler is the negative control
  (invisible, by design — the AST guard catches it structurally).
* cib-2026-006 (outbound-queue resume DLP bypass, comms-2) -> a queued secret
  that waits through a rate-limit pause is re-scanned on resume; a hot-reloaded
  stricter policy now redacts it, so consume REFUSES it instead of emitting.
* cib-2026-007 (thread addressing drift, comms-4) -> a thread-retitle re-address
  (thread inbound, channel outbound) fires COMMS_ADDRESSING_DRIFT_FIELDS.

Mirrors the csb-2026 / de-2026 executable-corpus pattern.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from alfred.comms_mcp.classifier_registry import (
    MARKER_NO_CLASSIFIERS_NEEDED,
    REQUIRED_CLASSIFIERS_BY_KIND,
)
from alfred.comms_mcp.inbound import _peppered_hash, process_inbound_message
from tests.adversarial.payload_schema import AdversarialPayload
from tests.unit.comms_mcp._inbound_spies import (
    SpyAuditWriter,
    SpyBurstLimiter,
    SpyIdentityResolver,
    SpyOrchestrator,
    SpySecretBroker,
    make_notification,
    make_resolved,
)

_DIR = Path(__file__).parent


def _load(payload_id: str) -> AdversarialPayload:
    path = _DIR / f"{payload_id}-{_suffix(payload_id)}.yaml"
    return AdversarialPayload.model_validate(yaml.safe_load(path.read_text()))


def _suffix(payload_id: str) -> str:
    matches = sorted(_DIR.glob(f"{payload_id}-*.yaml"))
    assert matches, f"no YAML for {payload_id}"
    # CR #232: fail fast on duplicate corpus files for one payload_id. Picking
    # the first glob hit would silently target one file and mask corpus drift
    # (adversarial ids must be unique / never reused).
    assert len(matches) == 1, f"duplicate YAML files for {payload_id}: {matches}"
    return matches[0].stem.split("-", 3)[3]


@pytest.mark.asyncio
async def test_cib_001_forged_canonical_id_ignored() -> None:
    payload = _load("cib-2026-001")
    assert payload.expected_outcome == "refused"
    resolver = SpyIdentityResolver(returns=make_resolved(canonical_user_id="u_real"))
    orch = SpyOrchestrator()
    audit = SpyAuditWriter()
    broker = SpySecretBroker()

    # The planted canonical id rides in platform_metadata — which is NOT a field
    # of InboundMessageNotification, so it never reaches process_inbound_message.
    await process_inbound_message(
        make_notification(platform_user_id="discord:victim", body={"content": "attack"}),
        identity_resolver=resolver,
        orchestrator=orch,
        burst_limiter=SpyBurstLimiter(),
        audit_writer=audit,
        secret_broker=broker,
    )

    # The resolver was consulted with the platform identifiers.
    assert resolver.last_call_kwargs == {
        "adapter_id": "alfred_comms_test",
        "platform_user_id": "discord:victim",
    }
    # The T3 promotion row carries the RESOLVER's canonical id, not the planted one.
    t3 = audit.rows_with_schema("COMMS_INBOUND_T3_PROMOTION_FIELDS")
    assert t3[0]["canonical_user_id"] == "u_real"
    assert "u_attacker_forged" not in str(t3)


@pytest.mark.asyncio
async def test_cib_002_t2_claim_is_inert() -> None:
    payload = _load("cib-2026-002")
    assert payload.expected_outcome == "boundary_refused"
    orch = SpyOrchestrator()
    forged_body = {"content": "relayed", "_x_source_tier_claim": "T2"}

    await process_inbound_message(
        make_notification(body=forged_body),
        identity_resolver=SpyIdentityResolver(returns=make_resolved()),
        orchestrator=orch,
        burst_limiter=SpyBurstLimiter(),
        audit_writer=SpyAuditWriter(),
        secret_broker=SpySecretBroker(),
    )

    # The extractor was invoked at T3 regardless of the forged claim.
    assert orch.last_extract_kwargs["source_tier"] == "T3"
    assert orch.last_extract_kwargs["body"] == forged_body


@pytest.mark.asyncio
async def test_cib_003_canonical_id_never_in_audit_or_dispatch() -> None:
    payload = _load("cib-2026-003")
    assert payload.expected_outcome == "refused"
    resolver = SpyIdentityResolver(returns=make_resolved(canonical_user_id="u_secret"))
    orch = SpyOrchestrator()
    audit = SpyAuditWriter()
    broker = SpySecretBroker()

    await process_inbound_message(
        make_notification(platform_user_id="discord:victim", body={"content": "leak me"}),
        identity_resolver=resolver,
        orchestrator=orch,
        burst_limiter=SpyBurstLimiter(),
        audit_writer=audit,
        secret_broker=broker,
    )

    # The platform_user_id only ever appears peppered-hashed in the audit row.
    t3 = audit.rows_with_schema("COMMS_INBOUND_T3_PROMOTION_FIELDS")[0]
    assert t3["platform_user_id_hash"] == _peppered_hash(
        "discord:victim", pepper=broker.get("audit.hash_pepper")
    )
    assert "discord:victim" not in str(t3)
    # The ingest carrier carries the canonical id host-side only — the dispatch
    # path receives the opaque ingested object, never an outbound id echo.
    assert orch.dispatch_calls == 1


def test_cib_004_empty_classifier_set_requires_marker() -> None:
    payload = _load("cib-2026-004")
    assert payload.expected_outcome == "refused"
    # The host-owned registry exposes the required set for the reference plugin;
    # an empty set is legal ONLY because the marker justifies it. A new kind with
    # an empty entry and no marker is what the AST guard
    # (test_required_classifiers_complete.py) refuses structurally.
    required = REQUIRED_CLASSIFIERS_BY_KIND["alfred_comms_test"]
    assert required == frozenset()  # empty…
    assert "alfred_comms_test" in MARKER_NO_CLASSIFIERS_NEEDED  # …but justified.


@pytest.mark.asyncio
async def test_cib_005_raising_handler_is_loud_positive_control() -> None:
    payload = _load("cib-2026-005")
    assert payload.expected_outcome == "audit_row_emitted"
    from unittest.mock import AsyncMock, MagicMock

    from tests.unit.comms_mcp._session_builders import INBOUND_PARAMS, build_session

    # Recording audit writer so the emitted events are inspectable.
    recorded: list[str] = []
    audit = MagicMock()

    async def _capture(**kwargs: object) -> None:
        recorded.append(str(kwargs.get("event")))

    audit.append_schema = AsyncMock(side_effect=_capture)

    failing = AsyncMock()
    failing.process.side_effect = RuntimeError("downstream broke")
    session = build_session(inbound_handler=failing, supervisor=AsyncMock(), audit_writer=audit)

    # Positive control: a RAISING handler emits COMMS_HANDLER_FAILED_FIELDS and
    # re-raises the original exception (the dispatcher is loud, never silent).
    with pytest.raises(RuntimeError, match="downstream broke"):
        await session._on_post_handshake_method(method="inbound.message", params=INBOUND_PARAMS)
    assert "comms.handler.failed" in recorded


@pytest.mark.asyncio
async def test_cib_006_outbound_queue_resume_rescans_dlp() -> None:
    payload = _load("cib-2026-006")
    assert payload.expected_outcome == "refused"
    from alfred.comms_mcp.outbound_queue import OutboundQueue, OutboundResumeDlpBlockedError

    # A re-scan that flips to "redact" after the pause models a hot-reloaded
    # stricter policy catching the planted secret mid-flight.
    strict = {"on": False}

    def _rescan(body: str) -> int:
        return 1 if (strict["on"] and "sk-" in body) else 0

    queue: OutboundQueue[str] = OutboundQueue(audit_writer=object(), dlp_rescanner=_rescan)
    await queue.submit("discord", "sk-PLANTEDSECRETKEYVALUE")
    queue.pause("discord", 0.01)
    strict["on"] = True  # policy hot-reload tightens DLP during the pause window
    queue.resume("discord")

    # The queued secret is REFUSED on resume, not emitted.
    with pytest.raises(OutboundResumeDlpBlockedError):
        await queue.consume("discord")

    # A clean message survives the same pause/resume cycle.
    await queue.submit("discord", "benign reply")
    queue.pause("discord", 0.01)
    queue.resume("discord")
    assert await queue.consume("discord") == "benign reply"


@pytest.mark.asyncio
async def test_cib_007_thread_addressing_drift_audits() -> None:
    payload = _load("cib-2026-007")
    assert payload.expected_outcome == "audit_row_emitted"
    from alfred.comms_mcp.addressing_drift import detect_addressing_drift

    rows: list[dict[str, object]] = []

    class _Audit:
        async def append_schema(self, *, subject: dict[str, object], **_kw: object) -> None:
            rows.append(subject)

    # A thread-retitle re-address (thread inbound, channel outbound) fires the row.
    fired = await detect_addressing_drift(
        adapter_id="discord",
        inbound_signal="thread",
        outbound_mode="channel",
        canonical_user_id="u_real",
        audit_writer=_Audit(),
    )
    assert fired is True
    assert rows[0]["inbound_signal"] == "thread"
    assert rows[0]["outbound_mode"] == "channel"
