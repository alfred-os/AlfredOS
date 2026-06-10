"""``InboundMessageHandler`` threads the sub-payload promoter (P1, #206).

The handler is the long-lived production object that owns the per-adapter
dependencies. P1 adds an optional ``sub_payload_promoter`` it forwards on every
``process`` call so production inbound traffic goes through host-side promotion.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from alfred.comms_mcp.errors import PromoterRequiredError
from alfred.comms_mcp.handlers import InboundMessageHandler
from alfred.comms_mcp.inbound import process_inbound_message
from alfred.comms_mcp.inbound_scanner import InboundContentScanner
from alfred.comms_mcp.protocol import InboundMessageNotification
from alfred.comms_mcp.sub_payload_promotion import (
    CONTENT_HANDLE_REF_KEY,
    SubPayloadPromoter,
)
from alfred.security.quarantine import ContentHandle

from ._inbound_spies import (
    SpyAuditWriter,
    SpyBurstLimiter,
    SpyIdentityResolver,
    SpyOrchestrator,
    SpySecretBroker,
    make_resolved,
)


class _SpyContentStore:
    def __init__(self) -> None:
        self.writes: list[dict[str, Any]] = []

    async def write(self, *, handle_id: str, body: bytes, source_url: str) -> ContentHandle:
        self.writes.append({"handle_id": handle_id, "body": body, "source_url": source_url})
        return ContentHandle(
            id=handle_id, source_url=source_url, fetch_timestamp=datetime.now(tz=UTC)
        )


@pytest.mark.asyncio
async def test_handler_forwards_promoter_to_inbound() -> None:
    store = _SpyContentStore()
    promoter = SubPayloadPromoter(
        adapter_kind="discord", scanner=InboundContentScanner(), content_store=store
    )
    orchestrator = SpyOrchestrator()
    handler = InboundMessageHandler(
        identity_resolver=SpyIdentityResolver(returns=make_resolved()),
        orchestrator=orchestrator,
        burst_limiter=SpyBurstLimiter(),
        audit_writer=SpyAuditWriter(),
        secret_broker=SpySecretBroker(),
        sub_payload_promoter=promoter,
    )
    notification = InboundMessageNotification(
        adapter_id="discord",
        platform_user_id="discord:user",
        body={"content": "hi", "embeds": [{"title": "injection"}]},
        sub_payload_refs=(),
        received_at=datetime.now(UTC),
        addressing_signal="dm",
    )

    await handler.process(notification)

    # The promoter ran: the extract body carries a handle ref, not raw bytes.
    extracted_body = orchestrator.last_extract_kwargs["body"]
    assert extracted_body["embeds"][0].keys() == {CONTENT_HANDLE_REF_KEY}
    assert len(store.writes) == 1


@pytest.mark.asyncio
async def test_non_empty_classifier_kind_without_promoter_fails_closed() -> None:
    # M2: a "discord" inbound (non-empty REQUIRED_CLASSIFIERS_BY_KIND) processed
    # with a None promoter must NOT silently fall back to trusting the
    # wire-asserted sub_payload_refs. The host refuses loudly — audits a handler
    # failure and raises — so the misconfiguration fails closed rather than
    # opening a sub-payload-trust hole.
    audit = SpyAuditWriter()
    orchestrator = SpyOrchestrator()
    notification = InboundMessageNotification(
        adapter_id="discord",
        platform_user_id="discord:attacker",
        body={"content": "hi", "embeds": [{"title": "injection"}]},
        sub_payload_refs=("embed_card",),  # attacker-asserted off the untrusted wire
        received_at=datetime.now(UTC),
        addressing_signal="dm",
    )

    with pytest.raises(PromoterRequiredError):
        await process_inbound_message(
            notification,
            identity_resolver=SpyIdentityResolver(returns=make_resolved(adapter_id="discord")),
            orchestrator=orchestrator,
            burst_limiter=SpyBurstLimiter(),
            audit_writer=audit,
            secret_broker=SpySecretBroker(),
            sub_payload_promoter=None,
        )

    # No extract / ingest / dispatch happened — the guard fired before any
    # processing, so the untrusted body never reached the quarantined extractor.
    assert orchestrator.quarantined_extract_calls == 0
    assert orchestrator.ingest_calls == 0
    # A loud handler-failure audit row was written with the promoter_required reason.
    failed = audit.rows_with_schema("COMMS_HANDLER_FAILED_FIELDS")
    assert len(failed) == 1
    assert failed[0]["reason"] == "promoter_required"
    assert failed[0]["adapter_id"] == "discord"


@pytest.mark.asyncio
async def test_empty_classifier_kind_without_promoter_is_allowed() -> None:
    # The reference plugin (alfred_comms_test) has an EMPTY required-classifier
    # set, so a None promoter is legitimate (plain-text only, no sub-payloads).
    # The guard must NOT fire for it.
    orchestrator = SpyOrchestrator()
    notification = InboundMessageNotification(
        adapter_id="alfred_comms_test",
        platform_user_id="test:user",
        body={"content": "plain hello"},
        sub_payload_refs=(),
        received_at=datetime.now(UTC),
        addressing_signal="dm",
    )

    await process_inbound_message(
        notification,
        identity_resolver=SpyIdentityResolver(returns=make_resolved()),
        orchestrator=orchestrator,
        burst_limiter=SpyBurstLimiter(),
        audit_writer=SpyAuditWriter(),
        secret_broker=SpySecretBroker(),
        sub_payload_promoter=None,
    )

    assert orchestrator.dispatch_calls == 1
