"""``run()`` performs an immediate ``_tick`` before the first sleep (perf-003).

The first poll must not wait a full ``poll_interval`` second — a freshly
started daemon should observe an already-edited file within one tick, not one
poll-interval.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from ._watcher_harness import build_watcher

pytestmark = pytest.mark.asyncio


async def test_run_ticks_immediately_before_first_sleep(tmp_path: Path, monkeypatch) -> None:
    watcher, _ref, _audit, _invoker = build_watcher(tmp_path, poll_interval=1000.0)
    ticked = asyncio.Event()
    real_tick = watcher._tick

    async def _counting_tick() -> None:
        ticked.set()
        await real_tick()

    monkeypatch.setattr(watcher, "_tick", _counting_tick)
    task = asyncio.create_task(watcher.run())
    try:
        # With a 1000 s interval, only an immediate-first-tick design lets this
        # resolve quickly.
        await asyncio.wait_for(ticked.wait(), timeout=1.0)
    finally:
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
