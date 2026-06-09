"""Task 22 — resolution-first ordering + binding-flow early return.

``process_inbound_message`` MUST consult the identity resolver BEFORE any
orchestrator call. A ``None`` resolution (first-contact) emits
``COMMS_BINDING_REQUESTED_FIELDS`` and returns early — no extract, no ingest,
no dispatch.
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
)


@pytest.mark.asyncio
async def test_resolution_consulted_before_orchestrator_on_first_contact() -> None:
    resolver = SpyIdentityResolver(returns=None)  # first-contact
    orch = SpyOrchestrator()
    limiter = SpyBurstLimiter()
    audit = SpyAuditWriter()

    await process_inbound_message(
        make_notification(),
        identity_resolver=resolver,
        orchestrator=orch,
        burst_limiter=limiter,
        audit_writer=audit,
        secret_broker=SpySecretBroker(),
    )

    assert resolver.resolve_calls == 1
    assert orch.quarantined_extract_calls == 0
    assert orch.ingest_calls == 0
    assert orch.dispatch_calls == 0
    assert limiter.acquire_calls == 0
    rows = audit.rows_with_schema("COMMS_BINDING_REQUESTED_FIELDS")
    assert len(rows) == 1


@pytest.mark.asyncio
async def test_resolver_called_with_platform_identifiers() -> None:
    resolver = SpyIdentityResolver(returns=None)
    await process_inbound_message(
        make_notification(platform_user_id="discord:victim"),
        identity_resolver=resolver,
        orchestrator=SpyOrchestrator(),
        burst_limiter=SpyBurstLimiter(),
        audit_writer=SpyAuditWriter(),
        secret_broker=SpySecretBroker(),
    )
    assert resolver.last_call_kwargs == {
        "adapter_id": "alfred_comms_test",
        "platform_user_id": "discord:victim",
    }


@pytest.mark.asyncio
async def test_binding_row_carries_hashed_platform_user_id_not_raw() -> None:
    audit = SpyAuditWriter()
    await process_inbound_message(
        make_notification(platform_user_id="discord:victim"),
        identity_resolver=SpyIdentityResolver(returns=None),
        orchestrator=SpyOrchestrator(),
        burst_limiter=SpyBurstLimiter(),
        audit_writer=audit,
        secret_broker=SpySecretBroker(),
    )
    row = audit.rows_with_schema("COMMS_BINDING_REQUESTED_FIELDS")[0]
    assert "platform_user_id_hash" in row
    assert "verification_phrase_hash" in row
    assert "discord:victim" not in str(row)
