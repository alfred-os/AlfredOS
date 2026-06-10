"""``InboundMessageHandler`` threads the sub-payload promoter (P1, #206).

The handler is the long-lived production object that owns the per-adapter
dependencies. P1 adds an optional ``sub_payload_promoter`` it forwards on every
``process`` call so production inbound traffic goes through host-side promotion.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from alfred.comms_mcp.handlers import InboundMessageHandler
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
