"""Breaker trips on 3 handler failures inside a 5-minute window (Task 41).

The dispatcher counts handler failures in a sliding window; the third failure
inside 5 minutes trips the adapter's breaker via
``supervisor.trip_breaker(reason="comms_handler_repeated_failures")``. Two
failures do not trip; failures outside the window age out.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock

import pytest

from alfred.utils.sliding_window_counter import SlidingWindowCounter

from ._session_builders import INBOUND_PARAMS, build_session


def _failing_handler() -> AsyncMock:
    handler = AsyncMock()
    handler.process = AsyncMock(side_effect=RuntimeError("boom"))
    return handler


@pytest.mark.asyncio
async def test_two_failures_does_not_trip() -> None:
    supervisor = AsyncMock()
    session = build_session(supervisor=supervisor, inbound_handler=_failing_handler())
    for _ in range(2):
        with pytest.raises(RuntimeError):
            await session._on_post_handshake_method(method="inbound.message", params=INBOUND_PARAMS)
    supervisor.trip_breaker.assert_not_awaited()


@pytest.mark.asyncio
async def test_third_failure_trips_breaker() -> None:
    supervisor = AsyncMock()
    session = build_session(supervisor=supervisor, inbound_handler=_failing_handler())
    for _ in range(3):
        with pytest.raises(RuntimeError):
            await session._on_post_handshake_method(method="inbound.message", params=INBOUND_PARAMS)
    supervisor.trip_breaker.assert_awaited_once_with(
        component_id=session._effective_adapter_id,
        reason="comms_handler_repeated_failures",
    )


@pytest.mark.asyncio
async def test_failures_outside_5min_window_do_not_trip() -> None:
    clock = [datetime.now(UTC)]
    counter = SlidingWindowCounter(clock=lambda: clock[0])
    supervisor = AsyncMock()
    session = build_session(
        supervisor=supervisor,
        inbound_handler=_failing_handler(),
        error_counter=counter,
    )
    # Two failures, then jump 6 minutes, then one more: only 1 in the window.
    for _ in range(2):
        with pytest.raises(RuntimeError):
            await session._on_post_handshake_method(method="inbound.message", params=INBOUND_PARAMS)
    clock[0] += timedelta(minutes=6)
    with pytest.raises(RuntimeError):
        await session._on_post_handshake_method(method="inbound.message", params=INBOUND_PARAMS)
    supervisor.trip_breaker.assert_not_awaited()
