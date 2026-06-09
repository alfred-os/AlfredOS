"""Dispatch semaphore acquired/released + per-adapter isolation (Task 39).

``async with self._dispatch_semaphore`` guarantees release on both the success
and exception paths (core-008). The semaphore is per-adapter (perf-003): two
sessions hold distinct instances, so one adapter's slow handler cannot starve
another.
"""

from __future__ import annotations

import asyncio
import time
from unittest.mock import AsyncMock

import pytest

from ._session_builders import INBOUND_PARAMS, build_session


async def _acquire(sem: asyncio.BoundedSemaphore) -> bool:
    """Try to acquire ``sem`` immediately; True if a slot was free."""
    try:
        await asyncio.wait_for(sem.acquire(), timeout=0.1)
    except TimeoutError:
        return False
    return True


@pytest.mark.asyncio
async def test_semaphore_acquired_and_released_on_success() -> None:
    sem = asyncio.BoundedSemaphore(value=2)
    session = build_session(dispatch_semaphore=sem)
    await session._on_post_handshake_method(method="inbound.message", params=INBOUND_PARAMS)
    # Fully restored — both slots re-acquirable.
    assert await _acquire(sem)
    assert await _acquire(sem)
    assert sem.locked()  # both slots now held


@pytest.mark.asyncio
async def test_semaphore_released_on_exception() -> None:
    sem = asyncio.BoundedSemaphore(value=1)
    handler = AsyncMock()
    handler.process = AsyncMock(side_effect=RuntimeError("boom"))
    session = build_session(dispatch_semaphore=sem, inbound_handler=handler, supervisor=AsyncMock())
    with pytest.raises(RuntimeError):
        await session._on_post_handshake_method(method="inbound.message", params=INBOUND_PARAMS)
    assert await _acquire(sem)  # released despite the exception


@pytest.mark.asyncio
async def test_two_sessions_hold_independent_semaphores() -> None:
    sem_a = asyncio.BoundedSemaphore(value=1)
    sem_b = asyncio.BoundedSemaphore(value=1)

    slow = AsyncMock()

    async def _slow_process(_notification: object) -> None:
        await asyncio.sleep(0.5)

    slow.process = _slow_process
    session_a = build_session(dispatch_semaphore=sem_a, inbound_handler=slow)
    session_b = build_session(dispatch_semaphore=sem_b)

    # A's slow handler holds A's semaphore; B proceeds immediately on its own.
    task_a = asyncio.create_task(
        session_a._on_post_handshake_method(method="inbound.message", params=INBOUND_PARAMS)
    )
    await asyncio.sleep(0)  # let A start + acquire its semaphore
    start = time.monotonic()
    await session_b._on_post_handshake_method(method="inbound.message", params=INBOUND_PARAMS)
    assert time.monotonic() - start < 0.2
    await task_a
