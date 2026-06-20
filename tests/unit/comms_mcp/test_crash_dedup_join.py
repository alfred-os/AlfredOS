"""One physical crash -> one correlated incident, two loud audit rows (G6-2b-2b / #288).

Proves the de-dup join where the two signals MEET: the in-child AdapterCrashHandler
and the gateway-fed AdapterStatusObserver share one CrashIncidentReconciler (as the
daemon wires them), so a single physical crash that emits BOTH signals is ONE
incident — without dropping either loud audit row (hard rule #7).

SEC-01 (the production path): these tests drive REAL ``up(seq=N)`` -> in-child
crash -> gateway ``crashed(seq=N)`` frames with NO manual ``note_incarnation`` —
the observer advances the incarnation on the up frame, so the COMMON
child-before-gateway order folds to one incident.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from alfred.comms_mcp.adapter_status_observer import AdapterStatusObserver
from alfred.comms_mcp.crash_incident_reconciler import CrashIncidentReconciler
from alfred.comms_mcp.handlers import AdapterCrashHandler
from alfred.comms_mcp.protocol import CrashedNotification

from ._inbound_spies import SpyAuditWriter

pytestmark = pytest.mark.asyncio

_EPOCH = "c" * 32
_FIXED_NOW = datetime(2026, 6, 20, 12, 0, 0, tzinfo=UTC)


class _NoopHookInvoker:
    async def fire_adapter_crashed(self, *, adapter_id: str, error_class: str) -> None:
        return None


def _wire(audit: SpyAuditWriter) -> tuple[AdapterStatusObserver, AdapterCrashHandler]:
    """Wire an observer + crash handler over ONE reconciler, as the daemon does."""
    reconciler = CrashIncidentReconciler()
    observer = AdapterStatusObserver(
        audit=audit,  # type: ignore[arg-type]
        expected_epoch=lambda: _EPOCH,
        now=lambda: _FIXED_NOW,
        reconciler=reconciler,
    )
    crash_handler = AdapterCrashHandler(
        audit_writer=audit,  # type: ignore[arg-type]
        hook_invoker=_NoopHookInvoker(),
        reconciler=reconciler,
    )
    return observer, crash_handler


def _crash_rows(audit: SpyAuditWriter) -> list[dict[str, object]]:
    return [
        r
        for r in audit.schema_rows
        if r["event"] in {"gateway.adapter.crashed", "comms.adapter.crashed"}
    ]


async def test_gateway_then_child_one_incident_two_rows() -> None:
    audit = SpyAuditWriter()
    observer, crash_handler = _wire(audit)

    # The adapter was serving incarnation 0; the gateway observed the process exit.
    await observer.observe(
        "gateway.adapter.crashed",
        {
            "adapter_id": "discord",
            "error_class": "BrokenPipeError",
            "detail": "",
            "host_restart_seq": 0,
        },
    )
    # The in-child diagnostic for the SAME physical crash arrives via the relay.
    await crash_handler.process(
        CrashedNotification(adapter_id="discord", error_class="ValueError", detail="")
    )

    crash_rows = _crash_rows(audit)
    # TWO audit rows (both loud, neither dropped) ...
    assert len(crash_rows) == 2
    # ... but ONE incident: both rows carry the SAME crash_incident_id.
    incident_ids = {r["crash_incident_id"] for r in crash_rows}
    assert len(incident_ids) == 1


async def test_common_child_before_gateway_order_is_one_incident() -> None:
    """SEC-01: the COMMON order (child crash fires as the child dies, BEFORE the
    gateway observes the exit). The observer advanced the incarnation on the up
    frame, so the child folds onto the SAME incarnation the gateway crash opens —
    NO manual note_incarnation, this is the production path.
    """
    audit = SpyAuditWriter()
    observer, crash_handler = _wire(audit)

    # The adapter reached its 2nd serving incarnation (after one restart): the
    # gateway up frame carries host_restart_seq=1, advancing the reconciler.
    await observer.observe(
        "gateway.adapter.up",
        {"adapter_id": "discord", "epoch": _EPOCH, "host_restart_seq": 1},
    )
    # The in-child diagnostic arrives FIRST (the child dies before the gateway sees it).
    await crash_handler.process(
        CrashedNotification(adapter_id="discord", error_class="ValueError", detail="")
    )
    # The gateway then observes the exit for incarnation 1.
    await observer.observe(
        "gateway.adapter.crashed",
        {
            "adapter_id": "discord",
            "error_class": "BrokenPipeError",
            "detail": "",
            "host_restart_seq": 1,
        },
    )

    crash_rows = _crash_rows(audit)
    assert len(crash_rows) == 2  # both loud
    incident_ids = {r["crash_incident_id"] for r in crash_rows}
    assert len(incident_ids) == 1  # ONE incident despite the child-first order
    # Both rows fold into incarnation 1's incident, corroborated by BOTH signals.
    incidents = observer._reconciler.incidents("discord")
    assert len(incidents) == 1
    assert incidents[0].host_restart_seq == 1
    assert incidents[0].crash_signal_source == "both"
