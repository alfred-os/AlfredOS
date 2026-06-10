"""Host-side addressing-drift detection (comms-4, #206).

When the outbound ``addressing_mode`` for a conversation diverges from the
inbound ``addressing_signal`` that opened it — e.g. a message arrives in a
``thread`` but the persona response is addressed to the parent ``channel``, or a
thread-retitle attempt re-addresses the binding — that is *addressing drift*. It
is a (benign-or-adversarial) signal worth a forensic row:
``COMMS_ADDRESSING_DRIFT_FIELDS``. ``detect_addressing_drift`` emits the row when,
and only when, the signal and mode differ.
"""

from __future__ import annotations

from typing import Any

import pytest

from alfred.comms_mcp.addressing_drift import detect_addressing_drift


class _SpyAudit:
    def __init__(self) -> None:
        self.rows: list[dict[str, Any]] = []

    async def append_schema(
        self, *, fields: frozenset[str], subject: dict[str, Any], **kw: Any
    ) -> None:
        missing = fields - subject.keys()
        extra = subject.keys() - fields
        assert not missing and not extra, f"missing={missing} extra={extra}"
        self.rows.append({**subject, **kw})


@pytest.mark.asyncio
async def test_drift_emits_row_when_signal_and_mode_differ() -> None:
    audit = _SpyAudit()
    fired = await detect_addressing_drift(
        adapter_id="discord",
        inbound_signal="thread",
        outbound_mode="channel",
        canonical_user_id="u_real",
        audit_writer=audit,
    )
    assert fired is True
    assert len(audit.rows) == 1
    assert audit.rows[0]["inbound_signal"] == "thread"
    assert audit.rows[0]["outbound_mode"] == "channel"


@pytest.mark.asyncio
async def test_no_drift_when_signal_matches_mode() -> None:
    audit = _SpyAudit()
    fired = await detect_addressing_drift(
        adapter_id="discord",
        inbound_signal="thread",
        outbound_mode="thread",
        canonical_user_id="u_real",
        audit_writer=audit,
    )
    assert fired is False
    assert audit.rows == []
