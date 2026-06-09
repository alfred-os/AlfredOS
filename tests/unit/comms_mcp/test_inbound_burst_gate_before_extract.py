"""Task 23 — burst-limiter acquire precedes quarantined_extract.

Spec §8.2: the bucket refuses to call ``quarantined_extract`` when empty. The
acquire MUST happen before the extract; a ``Dropped`` result returns early
without calling the extractor.
"""

from __future__ import annotations

import pytest

from alfred.comms_mcp.inbound import process_inbound_message
from alfred.orchestrator.burst_limiter import Dropped

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
async def test_burst_limiter_acquire_precedes_extract() -> None:
    call_order: list[str] = []
    resolver = SpyIdentityResolver(returns=make_resolved())
    limiter = SpyBurstLimiter(call_order=call_order)
    orch = SpyOrchestrator(call_order=call_order)

    await process_inbound_message(
        make_notification(),
        identity_resolver=resolver,
        orchestrator=orch,
        burst_limiter=limiter,
        audit_writer=SpyAuditWriter(),
        secret_broker=SpySecretBroker(),
    )

    assert call_order.index("burst") < call_order.index("extract")


@pytest.mark.asyncio
async def test_dropped_returns_early_without_extract() -> None:
    from datetime import UTC, datetime

    resolver = SpyIdentityResolver(returns=make_resolved())
    limiter = SpyBurstLimiter(
        result=Dropped(waited_seconds=30.0, bucket_empty_since=datetime.now(UTC))
    )
    orch = SpyOrchestrator()

    await process_inbound_message(
        make_notification(),
        identity_resolver=resolver,
        orchestrator=orch,
        burst_limiter=limiter,
        audit_writer=SpyAuditWriter(),
        secret_broker=SpySecretBroker(),
    )

    assert limiter.acquire_calls == 1
    assert orch.quarantined_extract_calls == 0
    assert orch.ingest_calls == 0
    assert orch.dispatch_calls == 0


@pytest.mark.asyncio
async def test_acquire_threaded_with_adapter_and_language() -> None:
    resolver = SpyIdentityResolver(returns=make_resolved(language="ja-JP"))
    limiter = SpyBurstLimiter()
    await process_inbound_message(
        make_notification(),
        identity_resolver=resolver,
        orchestrator=SpyOrchestrator(),
        burst_limiter=limiter,
        audit_writer=SpyAuditWriter(),
        secret_broker=SpySecretBroker(),
    )
    assert limiter.last_acquire_kwargs["adapter_id"] == "alfred_comms_test"
    assert limiter.last_acquire_kwargs["language"] == "ja-JP"
    assert limiter.last_acquire_kwargs["persona"] == "alfred"
