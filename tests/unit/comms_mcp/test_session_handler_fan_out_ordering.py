"""A single notification dispatches to exactly one handler (Task 42).

perf-003 clarification (spec §8.4 last paragraph): handler callbacks are
awaited sequentially per notification — a single message never fires two
handlers concurrently. Concurrency across notifications is bounded by the
dispatch semaphore.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock

import pytest

from ._session_builders import INBOUND_PARAMS, build_session


@pytest.mark.asyncio
async def test_single_notification_hits_exactly_one_handler() -> None:
    inbound = AsyncMock()
    binding = AsyncMock()
    rate_limit = AsyncMock()
    crash = AsyncMock()
    session = build_session(
        inbound_handler=inbound,
        binding_handler=binding,
        rate_limit_handler=rate_limit,
        crash_handler=crash,
    )

    await session._on_post_handshake_method(method="inbound.message", params=INBOUND_PARAMS)

    inbound.process.assert_awaited_once()
    binding.process.assert_not_awaited()
    rate_limit.process.assert_not_awaited()
    crash.process.assert_not_awaited()


@pytest.mark.asyncio
async def test_two_notifications_proceed_concurrently_up_to_cap() -> None:
    # With a cap of 2, two in-flight notifications run concurrently.
    order: list[str] = []

    async def _proc(_notification: object) -> None:
        order.append("start")
        await asyncio.sleep(0.05)
        order.append("end")

    handler = AsyncMock()
    handler.process = _proc
    sem = asyncio.BoundedSemaphore(value=2)
    session = build_session(inbound_handler=handler, dispatch_semaphore=sem)

    await asyncio.gather(
        session._on_post_handshake_method(method="inbound.message", params=INBOUND_PARAMS),
        session._on_post_handshake_method(method="inbound.message", params=INBOUND_PARAMS),
    )
    # Both started before either ended → concurrent (start, start, end, end).
    assert order[:2] == ["start", "start"]
