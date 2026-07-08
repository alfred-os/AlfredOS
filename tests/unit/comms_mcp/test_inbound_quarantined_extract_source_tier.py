"""Task 24 + 27 — extract called with source_tier="T3"; ingest->dispatch order.

The inbound entrypoint hard-codes ``source_tier="T3"`` at the call site (no
path promotes a comms inbound body to T2), and the post-extract order is
extract -> ingest -> dispatch.
"""

from __future__ import annotations

import pytest

from alfred.comms_mcp.inbound import process_inbound_message

from ._inbound_spies import (
    SpyAuditWriter,
    SpyBurstLimiter,
    SpyIdentityResolver,
    SpyOrchestrator,
    SpySecretBroker,
    make_notification,
    make_resolved,
)


@pytest.mark.asyncio
async def test_extract_called_with_t3() -> None:
    orch = SpyOrchestrator()
    await process_inbound_message(
        make_notification(),
        identity_resolver=SpyIdentityResolver(returns=make_resolved()),
        orchestrator=orch,
        burst_limiter=SpyBurstLimiter(),
        audit_writer=SpyAuditWriter(),
        secret_broker=SpySecretBroker(),
    )
    assert orch.quarantined_extract_calls == 1
    assert orch.last_extract_kwargs["source_tier"] == "T3"
    assert orch.last_extract_kwargs["canonical_user_id"] == "u_resolved"


@pytest.mark.asyncio
async def test_ingest_receives_display_name() -> None:
    """The resolved ``display_name`` is threaded into the ``ingest(...)`` call (#338 PR1).

    Guards the ``inbound.py`` seam (``display_name=resolved.display_name``) that the
    PR2 real-turn adapter consumes to build the turn's ``UserLike``. Without this
    assertion a dropped/renamed forwarding would be caught by nothing (the live echo
    adapter ignores the kwarg, so only this seam-level check protects it).
    """
    orch = SpyOrchestrator()
    await process_inbound_message(
        make_notification(),
        identity_resolver=SpyIdentityResolver(returns=make_resolved(display_name="Ada Lovelace")),
        orchestrator=orch,
        burst_limiter=SpyBurstLimiter(),
        audit_writer=SpyAuditWriter(),
        secret_broker=SpySecretBroker(),
    )
    assert orch.ingest_calls == 1
    assert orch.last_ingest_kwargs["display_name"] == "Ada Lovelace"


@pytest.mark.asyncio
async def test_ingest_then_dispatch_after_extract() -> None:
    call_order: list[str] = []
    orch = SpyOrchestrator(call_order=call_order)
    limiter = SpyBurstLimiter(call_order=call_order)
    await process_inbound_message(
        make_notification(),
        identity_resolver=SpyIdentityResolver(returns=make_resolved()),
        orchestrator=orch,
        burst_limiter=limiter,
        audit_writer=SpyAuditWriter(),
        secret_broker=SpySecretBroker(),
    )
    assert call_order == ["burst", "extract", "ingest", "dispatch"]
    assert orch.ingest_calls == 1
    assert orch.dispatch_calls == 1
