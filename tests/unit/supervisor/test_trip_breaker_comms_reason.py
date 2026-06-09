"""``Supervisor.trip_breaker`` — reason-checked façade over the breaker (Task 44).

``trip_breaker`` is the public, reason-checked counterpart to ``reset_breaker``:
it drives the per-component :class:`CircuitBreaker` to ``OPEN`` through the
breaker's real ``record_failure`` API (there is no public ``trip(reason)`` —
arch-004), accepting the new comms Literal reason plus the Slice-3 reasons.

The dispatcher (``AlfredPluginSession._on_post_handshake_method`` extension)
calls this with ``reason="comms_handler_repeated_failures"`` on the third
handler failure inside a five-minute window.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from alfred.supervisor.breaker import BreakerState, CircuitBreaker
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


@pytest.mark.asyncio
async def test_trip_breaker_accepts_comms_reason() -> None:
    sup, _audit = _build_supervisor()
    breaker = sup.get_or_create_breaker("alfred_comms_test")
    assert breaker.state == BreakerState.CLOSED

    await sup.trip_breaker(
        component_id="alfred_comms_test",
        reason="comms_handler_repeated_failures",
    )

    assert breaker.state == BreakerState.OPEN


@pytest.mark.asyncio
async def test_trip_breaker_creates_breaker_if_absent() -> None:
    sup, _audit = _build_supervisor()
    assert "novel_component" not in sup._breakers

    await sup.trip_breaker(
        component_id="novel_component",
        reason="plugin_lifecycle_crash",
    )

    assert sup._breakers["novel_component"].state == BreakerState.OPEN


@pytest.mark.asyncio
async def test_trip_breaker_emits_tripped_audit_row() -> None:
    sup, audit = _build_supervisor()
    await sup.trip_breaker(
        component_id="alfred_comms_test",
        reason="comms_handler_repeated_failures",
    )
    schema_rows = [
        call.kwargs
        for call in audit.append_schema.await_args_list
        if call.kwargs.get("schema_name") == "SUPERVISOR_BREAKER_TRIPPED_FIELDS"
    ]
    assert len(schema_rows) == 1
    assert schema_rows[0]["subject"]["component_id"] == "alfred_comms_test"
    # The closed-vocab reason rides ``last_failure_type`` — the breaker's
    # T3-safe carrier for the trip cause (it is a closed-vocab Literal here,
    # not ``str(exc)``).
    assert schema_rows[0]["subject"]["last_failure_type"] == "comms_handler_repeated_failures"
    assert schema_rows[0]["subject"]["breaker_state"] == "OPEN"


@pytest.mark.asyncio
async def test_trip_breaker_unknown_reason_rejected() -> None:
    sup, _audit = _build_supervisor()
    with pytest.raises(ValueError):
        await sup.trip_breaker(
            component_id="alfred_comms_test",
            reason="bogus",  # type: ignore[arg-type]
        )


@pytest.mark.asyncio
async def test_trip_breaker_idempotent_when_already_open() -> None:
    sup, audit = _build_supervisor()
    await sup.trip_breaker(
        component_id="alfred_comms_test",
        reason="comms_handler_repeated_failures",
    )
    audit.append_schema.reset_mock()

    # Second trip against an already-OPEN breaker is a no-op transition: no
    # second tripped row (the state did not change).
    await sup.trip_breaker(
        component_id="alfred_comms_test",
        reason="comms_handler_repeated_failures",
    )
    tripped = [
        call.kwargs
        for call in audit.append_schema.await_args_list
        if call.kwargs.get("schema_name") == "SUPERVISOR_BREAKER_TRIPPED_FIELDS"
    ]
    assert tripped == []
    assert sup._breakers["alfred_comms_test"].state == BreakerState.OPEN
