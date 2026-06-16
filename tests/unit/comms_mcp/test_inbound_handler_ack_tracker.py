"""InboundMessageHandler binds + forwards the per-connection ack tracker (G4b-2a-pre).

The tracker is PER-CONNECTION (the socket carrier sets it via ``set_ack_tracker``
AFTER the handshake, not at construction). The handler forwards it on every
``process`` so the durable-intake ack advances on each G0 ``commit_once``.
"""

from __future__ import annotations

import pytest

from alfred.comms_mcp.handlers import InboundMessageHandler
from alfred.gateway._seq_tracker import BoundedSeqAckTracker
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
    async def commit_once(self, *, inbound_id: str, adapter_id: str) -> bool:
        return True


def _handler(*, ack_tracker: BoundedSeqAckTracker | None = None) -> InboundMessageHandler:
    return InboundMessageHandler(
        identity_resolver=SpyIdentityResolver(returns=make_resolved()),
        orchestrator=SpyOrchestrator(),
        burst_limiter=SpyBurstLimiter(),
        audit_writer=SpyAuditWriter(),
        secret_broker=SpySecretBroker(),
        idempotency_store=_FakeStore(),
        ack_tracker=ack_tracker,
    )


async def test_constructor_injected_tracker_advances_on_commit() -> None:
    tracker = BoundedSeqAckTracker()
    handler = _handler(ack_tracker=tracker)
    await handler.process(make_notification(inbound_id="frame-0", wire_seq=0))
    assert tracker.cumulative_ack() == 0


async def test_set_ack_tracker_binds_a_per_connection_tracker() -> None:
    # The production path: the handler is built with no tracker (per-boot), then the
    # socket carrier binds a fresh per-connection tracker after the handshake.
    handler = _handler()
    tracker = BoundedSeqAckTracker()
    handler.set_ack_tracker(tracker)
    await handler.process(make_notification(inbound_id="frame-0", wire_seq=0))
    await handler.process(make_notification(inbound_id="frame-1", wire_seq=1))
    assert tracker.cumulative_ack() == 1


async def test_no_tracker_is_a_safe_no_op() -> None:
    # No tracker set (the stdio path) — the inbound still processes, advances nothing.
    handler = _handler()
    await handler.process(make_notification(inbound_id="frame-0", wire_seq=0))
    # No assertion on a tracker; the point is no crash + the message processed.
