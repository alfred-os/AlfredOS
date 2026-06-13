"""InboundMessageHandler forwards its idempotency_store to process_inbound_message."""

from __future__ import annotations

import pytest

from alfred.comms_mcp.handlers import InboundMessageHandler
from tests.unit.comms_mcp._inbound_spies import (
    SpyAuditWriter,
    SpyBurstLimiter,
    SpyIdentityResolver,
    SpyOrchestrator,
    SpySecretBroker,
    make_notification,
    make_resolved,
)

pytestmark = pytest.mark.asyncio


class _FakeStore:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    async def commit_once(self, *, inbound_id: str, adapter_id: str) -> bool:
        self.calls.append((inbound_id, adapter_id))
        return True


async def test_handler_forwards_store_to_pipeline() -> None:
    store = _FakeStore()
    handler = InboundMessageHandler(
        identity_resolver=SpyIdentityResolver(returns=make_resolved()),
        orchestrator=SpyOrchestrator(),
        burst_limiter=SpyBurstLimiter(),
        audit_writer=SpyAuditWriter(),
        secret_broker=SpySecretBroker(),
        idempotency_store=store,
    )
    await handler.process(make_notification(inbound_id="frame-9", adapter_id="alfred_comms_test"))
    assert store.calls == [("frame-9", "alfred_comms_test")]
