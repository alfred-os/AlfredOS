"""Task 28 — canonical id stays host-side; resolver consulted exactly once.

The canonical ``user_id`` is resolved host-side and never crosses the stdio
boundary outward. At the Wave-2 (``process_inbound_message``) layer the
assertion is two-fold:

* the resolver is consulted exactly once per inbound (positive control), and
* the raw ``platform_user_id`` never leaks into any emitted audit row (it is
  always replaced by its peppered hash).

The full outbound-stdio-frame capture (host -> plugin direction) is exercised
by the merge-blocking integration test once the session dispatcher (Wave 3)
is wired; this unit test pins the host-side invariant the inbound entrypoint
owns.
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
async def test_resolver_consulted_exactly_once() -> None:
    resolver = SpyIdentityResolver(returns=make_resolved())
    await process_inbound_message(
        make_notification(),
        identity_resolver=resolver,
        orchestrator=SpyOrchestrator(),
        burst_limiter=SpyBurstLimiter(),
        audit_writer=SpyAuditWriter(),
        secret_broker=SpySecretBroker(),
    )
    assert resolver.resolve_calls == 1


@pytest.mark.asyncio
async def test_raw_platform_user_id_never_in_any_audit_row() -> None:
    audit = SpyAuditWriter()
    raw = "discord:super-secret-victim-id"
    await process_inbound_message(
        make_notification(platform_user_id=raw),
        identity_resolver=SpyIdentityResolver(returns=make_resolved()),
        orchestrator=SpyOrchestrator(),
        burst_limiter=SpyBurstLimiter(),
        audit_writer=audit,
        secret_broker=SpySecretBroker(),
    )
    for row in audit.schema_rows + audit.event_rows:
        assert raw not in str(row)
