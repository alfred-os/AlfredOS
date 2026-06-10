"""Host-side addressing-drift detection (comms-4, #206).

A conversation is opened by an inbound message whose ``addressing_signal`` is one
of ``dm | mention | channel | thread`` (spec §8.6). When the persona's outbound
reply is addressed with a different ``addressing_mode`` than the signal that
opened the conversation — a thread message answered to the parent channel, or a
thread-retitle attempt re-addressing the binding — that is *addressing drift*. It
may be benign (an operator deliberately redirecting) or adversarial (an attacker
trying to steer a reply out of the thread that contains it), so it is always
worth a forensic ``COMMS_ADDRESSING_DRIFT_FIELDS`` audit row.

This is the host-side detector: a pure check plus an audit emission. It is loud
(it never swallows) and side-effect-free beyond the audit write.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Protocol, runtime_checkable

import structlog

from alfred.audit import audit_row_schemas

_log = structlog.get_logger(__name__)


@runtime_checkable
class _AuditWriterLike(Protocol):
    async def append_schema(self, **kwargs: Any) -> None: ...


async def detect_addressing_drift(
    *,
    adapter_id: str,
    inbound_signal: str,
    outbound_mode: str,
    canonical_user_id: str,
    audit_writer: _AuditWriterLike,
) -> bool:
    """Emit ``COMMS_ADDRESSING_DRIFT_FIELDS`` when signal and mode diverge.

    Returns ``True`` when drift was detected (and the row emitted), ``False`` when
    the outbound mode matches the inbound signal (no row). The audit row carries
    both the inbound signal and the outbound mode so an auditor can see the exact
    redirection an attacker (or operator) attempted.
    """
    if inbound_signal == outbound_mode:
        return False
    await audit_writer.append_schema(
        fields=audit_row_schemas.COMMS_ADDRESSING_DRIFT_FIELDS,
        schema_name="COMMS_ADDRESSING_DRIFT_FIELDS",
        event="comms.addressing.drift",
        actor_user_id=canonical_user_id,
        subject={
            "adapter_id": adapter_id,
            "inbound_signal": inbound_signal,
            "outbound_mode": outbound_mode,
            "canonical_user_id": canonical_user_id,
            "observed_at": datetime.now(UTC).isoformat(),
        },
        trust_tier_of_trigger="T3",
        result="drift_detected",
        cost_estimate_usd=0.0,
        trace_id=canonical_user_id,
    )
    _log.warning(
        "comms.addressing.drift",
        adapter_id=adapter_id,
        inbound_signal=inbound_signal,
        outbound_mode=outbound_mode,
    )
    return True


__all__ = ["detect_addressing_drift"]
