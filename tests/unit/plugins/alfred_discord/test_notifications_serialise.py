"""M3: concurrent ``StdoutNotificationSink.emit`` frames must not interleave.

``emit`` runs ``write + flush`` on an ``asyncio.to_thread`` worker. Two
concurrent emits — e.g. a rate-limit signal racing an inbound frame — land on
DIFFERENT worker threads, so without a serialising lock their byte writes can
interleave on the shared ``sys.stdout``, corrupting the line-delimited JSON-RPC
stream the host parses. The sink must guarantee exactly one frame is written +
flushed at a time.

This test drives many concurrent emits through a recording stdout whose
``write`` sleeps mid-frame to widen the interleave window, then asserts every
emitted line round-trips as a single intact JSON object.
"""

from __future__ import annotations

import asyncio
import json
import time

import pytest

from plugins.alfred_discord.notifications import StdoutNotificationSink, notification_frame

_EMIT_COUNT = 20


class _SlowStdout:
    """A stdout double whose ``write`` sleeps so concurrent writers can interleave.

    Records every ``write`` chunk. A real ``threading``-level sleep inside the
    write (the sink runs ``_write`` on a ``to_thread`` worker) is what exposes a
    missing lock: two unserialised workers append their chunks out of order.
    """

    def __init__(self) -> None:
        self.chunks: list[str] = []

    def write(self, chunk: str) -> int:
        # Split the write so an unsynchronised second writer can wedge between
        # this frame's first and second halves.
        midpoint = len(chunk) // 2
        self.chunks.append(chunk[:midpoint])
        time.sleep(0.001)
        self.chunks.append(chunk[midpoint:])
        return len(chunk)

    def flush(self) -> None:
        return None


async def test_concurrent_emits_do_not_interleave(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _SlowStdout()
    monkeypatch.setattr("plugins.alfred_discord.notifications.sys.stdout", fake)
    sink = StdoutNotificationSink()

    frames = [
        notification_frame("inbound.message", {"seq": n, "body": "x" * 40})
        for n in range(_EMIT_COUNT)
    ]

    async with asyncio.TaskGroup() as tg:
        for frame in frames:
            tg.create_task(sink.emit(frame))

    # Reassemble the recorded chunks and split on the line delimiter. With a
    # serialising lock every line is one intact JSON object; without it the
    # chunks interleave and at least one line fails to parse.
    rendered = "".join(fake.chunks)
    lines = [line for line in rendered.split("\n") if line]
    assert len(lines) == _EMIT_COUNT
    seqs = sorted(json.loads(line)["params"]["seq"] for line in lines)
    assert seqs == list(range(_EMIT_COUNT))
