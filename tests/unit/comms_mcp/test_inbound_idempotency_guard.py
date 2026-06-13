"""process_inbound_message commits accept-once before side effects; a replay short-circuits."""

from __future__ import annotations

import pytest

from alfred.comms_mcp import audit_hash
from alfred.comms_mcp.inbound import process_inbound_message
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
    def __init__(self, *, won: bool) -> None:
        self._won = won
        self.calls: list[tuple[str, str]] = []

    async def commit_once(self, *, inbound_id: str, adapter_id: str) -> bool:
        self.calls.append((inbound_id, adapter_id))
        return self._won


async def test_new_message_commits_then_proceeds_to_dispatch() -> None:
    store = _FakeStore(won=True)
    resolver = SpyIdentityResolver(returns=make_resolved())
    orch = SpyOrchestrator()
    await process_inbound_message(
        make_notification(inbound_id="frame-1", adapter_id="alfred_comms_test"),
        identity_resolver=resolver,
        orchestrator=orch,
        burst_limiter=SpyBurstLimiter(),
        audit_writer=SpyAuditWriter(),
        secret_broker=SpySecretBroker(),
        idempotency_store=store,
    )
    assert store.calls == [("frame-1", "alfred_comms_test")]
    # The pipeline ran end-to-end (integer counters, not booleans).
    assert resolver.resolve_calls == 1
    assert orch.quarantined_extract_calls == 1
    assert orch.dispatch_calls == 1


async def test_replay_short_circuits_before_any_side_effect() -> None:
    store = _FakeStore(won=False)
    resolver = SpyIdentityResolver(returns=make_resolved())
    orch = SpyOrchestrator()
    await process_inbound_message(
        make_notification(inbound_id="frame-1", adapter_id="alfred_comms_test"),
        identity_resolver=resolver,
        orchestrator=orch,
        burst_limiter=SpyBurstLimiter(),
        audit_writer=SpyAuditWriter(),
        secret_broker=SpySecretBroker(),
        idempotency_store=store,
    )
    assert store.calls == [("frame-1", "alfred_comms_test")]
    # NOTHING downstream ran — the replay was a clean DROP.
    assert resolver.resolve_calls == 0
    assert orch.quarantined_extract_calls == 0
    assert orch.dispatch_calls == 0


async def test_replay_writes_exactly_one_content_free_audit_row() -> None:
    # A replay DROP is a side effect, so it must be observable in the SIGNED
    # audit log — content-free, carrying a peppered hash of inbound_id (never
    # the raw string).
    store = _FakeStore(won=False)
    audit = SpyAuditWriter()
    broker = SpySecretBroker()
    await process_inbound_message(
        make_notification(inbound_id="frame-dup", adapter_id="alfred_comms_test"),
        identity_resolver=SpyIdentityResolver(returns=make_resolved()),
        orchestrator=SpyOrchestrator(),
        burst_limiter=SpyBurstLimiter(),
        audit_writer=audit,
        secret_broker=broker,
        idempotency_store=store,
    )
    rows = audit.rows_with_schema("COMMS_INBOUND_IDEMPOTENCY_REPLAY_FIELDS")
    assert len(rows) == 1
    row = rows[0]
    # The production guard wired audit_hash to broker; recompute the digest
    # through the same authoritative helper.
    assert row["inbound_id_hash"] == audit_hash.hash_inbound_id("frame-dup")
    assert "frame-dup" not in str(row)  # raw id never on the row
    # Pin the security-provenance fields: a replay is a T3-triggered DROP. A
    # regression flipping the disposition to ``"success"`` or downgrading the
    # trigger tier to T0 would otherwise pass green.
    assert row["trust_tier_of_trigger"] == "T3"
    assert row["result"] == "dropped"


async def test_none_store_preserves_legacy_behavior() -> None:
    orch = SpyOrchestrator()
    await process_inbound_message(
        make_notification(inbound_id="frame-1", adapter_id="alfred_comms_test"),
        identity_resolver=SpyIdentityResolver(returns=make_resolved()),
        orchestrator=orch,
        burst_limiter=SpyBurstLimiter(),
        audit_writer=SpyAuditWriter(),
        secret_broker=SpySecretBroker(),
        idempotency_store=None,
    )
    assert orch.dispatch_calls == 1  # no store => pipeline runs as before
