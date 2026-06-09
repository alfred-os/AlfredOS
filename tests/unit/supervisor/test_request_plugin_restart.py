"""``Supervisor.request_plugin_restart`` — restart request + unhealthy mark (Task 43, 45).

The comms dispatcher calls this when a plugin sends an unknown notification
method or repeatedly fails its handler. The method writes the
``SUPERVISOR_PLUGIN_RESTART_REQUESTED_FIELDS`` audit row, marks the adapter
unhealthy (trips its breaker OPEN), and is idempotent per supervisor tick so a
handler-failure storm cannot spam the audit graph.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from alfred.supervisor.breaker import BreakerState
from alfred.supervisor.core import Supervisor
from tests.helpers.policies import _StubPoliciesSnapshotRef


@asynccontextmanager
async def _fake_session_scope() -> AsyncIterator[Any]:
    session = AsyncMock()
    session.commit = AsyncMock()
    yield session


def _build_supervisor() -> tuple[Supervisor, AsyncMock]:
    gate = MagicMock()
    audit = AsyncMock()
    audit.append = AsyncMock()
    audit.append_schema = AsyncMock()
    sup = Supervisor(
        session_scope=_fake_session_scope,
        gate=gate,
        audit=audit,
        policies_ref=_StubPoliciesSnapshotRef(),
    )
    return sup, audit


def _restart_rows(audit: AsyncMock) -> list[dict[str, Any]]:
    return [
        call.kwargs
        for call in audit.append_schema.await_args_list
        if call.kwargs.get("schema_name") == "SUPERVISOR_PLUGIN_RESTART_REQUESTED_FIELDS"
    ]


@pytest.mark.asyncio
async def test_writes_restart_requested_audit_row() -> None:
    sup, audit = _build_supervisor()
    await sup.request_plugin_restart(
        adapter_id="alfred_comms_test",
        reason="unknown_notification",
    )
    rows = _restart_rows(audit)
    assert len(rows) == 1
    subject = rows[0]["subject"]
    assert subject["plugin_id"] == "alfred_comms_test"
    assert subject["reason"] == "unknown_notification"
    assert subject["requester"] == "AlfredPluginSession"
    assert "requested_at" in subject


@pytest.mark.asyncio
async def test_marks_adapter_unhealthy() -> None:
    sup, _audit = _build_supervisor()
    await sup.request_plugin_restart(
        adapter_id="alfred_comms_test",
        reason="unknown_notification",
    )
    # The adapter's breaker is now OPEN — the restart scheduler sees it as
    # unhealthy and spawns a fresh adapter on its next tick.
    assert sup._breakers["alfred_comms_test"].state == BreakerState.OPEN


@pytest.mark.asyncio
async def test_invalid_reason_rejected() -> None:
    sup, _audit = _build_supervisor()
    with pytest.raises(ValueError):
        await sup.request_plugin_restart(
            adapter_id="alfred_comms_test",
            reason="bogus",  # type: ignore[arg-type]
        )


@pytest.mark.asyncio
async def test_idempotent_within_tick() -> None:
    sup, audit = _build_supervisor()
    # Two identical requests within one tick → exactly one audit row.
    await sup.request_plugin_restart(adapter_id="alfred_comms_test", reason="unknown_notification")
    await sup.request_plugin_restart(adapter_id="alfred_comms_test", reason="unknown_notification")
    assert len(_restart_rows(audit)) == 1


@pytest.mark.asyncio
async def test_distinct_reason_not_deduplicated() -> None:
    sup, audit = _build_supervisor()
    await sup.request_plugin_restart(adapter_id="alfred_comms_test", reason="unknown_notification")
    await sup.request_plugin_restart(
        adapter_id="alfred_comms_test", reason="handler_repeated_failures"
    )
    # Different reasons are distinct dedup keys → two rows.
    assert len(_restart_rows(audit)) == 2


@pytest.mark.asyncio
async def test_dedup_cleared_at_tick_boundary() -> None:
    sup, audit = _build_supervisor()
    await sup.request_plugin_restart(adapter_id="alfred_comms_test", reason="unknown_notification")
    sup._reset_restart_dedup()
    # Next tick: the same request re-emits (the storm guard is within-tick
    # only, not a permanent suppression).
    await sup.request_plugin_restart(adapter_id="alfred_comms_test", reason="unknown_notification")
    assert len(_restart_rows(audit)) == 2
