"""Task 25 — COMMS_INBOUND_T3_PROMOTION_FIELDS emit after a successful extract.

Exactly one promotion row per successful inbound. It carries the peppered
``platform_user_id_hash`` (never the raw id), the resolved ``canonical_user_id``,
``language``, ``addressing_signal``, a host-minted ``inbound_message_id``, and
``sub_payload_kinds``.
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
async def test_t3_promotion_audit_row_emitted_after_extract() -> None:
    audit = SpyAuditWriter()
    notification = make_notification(platform_user_id="discord:victim")
    await process_inbound_message(
        notification,
        identity_resolver=SpyIdentityResolver(returns=make_resolved(language="ja-JP")),
        orchestrator=SpyOrchestrator(),
        burst_limiter=SpyBurstLimiter(),
        audit_writer=audit,
        secret_broker=SpySecretBroker(),
    )

    rows = audit.rows_with_schema("COMMS_INBOUND_T3_PROMOTION_FIELDS")
    assert len(rows) == 1
    row = rows[0]
    assert row["adapter_id"] == "alfred_comms_test"
    assert "platform_user_id_hash" in row
    assert row["canonical_user_id"] == "u_resolved"
    assert row["addressing_signal"] == "dm"
    assert row["language"] == "ja-JP"
    assert "inbound_message_id" in row
    # Provenance: sub_payload_kinds is the sorted projection of the notification's
    # sub_payload_refs (empty here -> empty list). Pin its presence + shape so the
    # documented provenance field is never silently dropped from the row.
    assert row["sub_payload_kinds"] == []
    # The raw platform_user_id must NOT appear anywhere in the row.
    assert "discord:victim" not in str(row)


@pytest.mark.asyncio
async def test_t3_promotion_row_not_emitted_on_first_contact() -> None:
    audit = SpyAuditWriter()
    await process_inbound_message(
        make_notification(),
        identity_resolver=SpyIdentityResolver(returns=None),
        orchestrator=SpyOrchestrator(),
        burst_limiter=SpyBurstLimiter(),
        audit_writer=audit,
        secret_broker=SpySecretBroker(),
    )
    assert audit.rows_with_schema("COMMS_INBOUND_T3_PROMOTION_FIELDS") == []
