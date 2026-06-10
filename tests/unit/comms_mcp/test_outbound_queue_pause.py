"""``OutboundQueue`` per-adapter FIFO + pause/resume (PR-S4-9 Task A1, #206).

The queue is the host-side outbound dispatch backpressure primitive. It is a
trust-boundary surface: every outbound message a persona emits flows through it,
and a Discord ``adapter.rate_limit_signal`` calls :meth:`OutboundQueue.pause` to
suspend emission until the platform's retry-after window elapses.

These tests pin the seven behaviours the plan enumerates for Task A1. They use a
real (in-process) :class:`asyncio.Queue` and real ``loop.call_later`` timers —
no mocks of the queue itself — and a fixture audit writer (never a bypass).
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import pytest

from alfred.comms_mcp.outbound_queue import OutboundQueue

if TYPE_CHECKING:
    from collections.abc import Sequence


class _RecordingAuditWriter:
    """Minimal :class:`AuditWriterProtocol` stand-in for the cap-required dep.

    Records nothing of security consequence here — the queue's ``pause`` emits a
    structlog *observability* event, not an audit row (Task A1 note). The writer
    is required by ``__init__`` so a future emission path can be observed; this
    fixture proves the queue accepts and stores it.
    """

    def __init__(self) -> None:
        self.rows: list[object] = []


def _req(adapter_id: str, marker: str) -> dict[str, str]:
    """Build an opaque request payload.

    The queue is generic over the request type; the unit tests use a plain dict
    so they do not couple to ``OutboundMessageRequest``'s DLP-minted body.
    """
    return {"adapter_id": adapter_id, "marker": marker}


@pytest.mark.asyncio
async def test_submit_consume_round_trips_fifo() -> None:
    queue: OutboundQueue[dict[str, str]] = OutboundQueue(audit_writer=_RecordingAuditWriter())
    await queue.submit("discord", _req("discord", "a"))
    await queue.submit("discord", _req("discord", "b"))
    await queue.submit("discord", _req("discord", "c"))

    out = [
        (await queue.consume("discord"))["marker"],
        (await queue.consume("discord"))["marker"],
        (await queue.consume("discord"))["marker"],
    ]
    assert out == ["a", "b", "c"]


@pytest.mark.asyncio
async def test_pause_blocks_consume_until_retry_after_elapses() -> None:
    queue: OutboundQueue[dict[str, str]] = OutboundQueue(audit_writer=_RecordingAuditWriter())
    await queue.submit("discord", _req("discord", "a"))
    queue.pause("discord", retry_after_seconds=0.05)

    consume_task = asyncio.ensure_future(queue.consume("discord"))
    # Immediately after pause, consume must NOT have completed.
    await asyncio.sleep(0.01)
    assert not consume_task.done()

    # After the retry-after window the auto-resume timer fires and consume
    # completes with the queued request.
    result = await asyncio.wait_for(consume_task, timeout=1.0)
    assert result["marker"] == "a"


@pytest.mark.asyncio
async def test_manual_resume_overrides_the_timer() -> None:
    queue: OutboundQueue[dict[str, str]] = OutboundQueue(audit_writer=_RecordingAuditWriter())
    await queue.submit("discord", _req("discord", "a"))
    queue.pause("discord", retry_after_seconds=100.0)  # long timer
    queue.resume("discord")  # manual override returns control immediately

    result = await asyncio.wait_for(queue.consume("discord"), timeout=1.0)
    assert result["marker"] == "a"


@pytest.mark.asyncio
async def test_pause_is_per_adapter() -> None:
    queue: OutboundQueue[dict[str, str]] = OutboundQueue(audit_writer=_RecordingAuditWriter())
    await queue.submit("discord", _req("discord", "d"))
    await queue.submit("tui", _req("tui", "t"))
    queue.pause("discord", retry_after_seconds=100.0)

    # Adapter "tui" is unaffected and consumes immediately.
    result = await asyncio.wait_for(queue.consume("tui"), timeout=1.0)
    assert result["marker"] == "t"


@pytest.mark.asyncio
async def test_concurrent_submit_and_pause_delivers_each_once() -> None:
    queue: OutboundQueue[dict[str, str]] = OutboundQueue(audit_writer=_RecordingAuditWriter())
    markers: Sequence[str] = tuple(f"m{i}" for i in range(20))
    received: list[str] = []

    async def producer() -> None:
        for i, m in enumerate(markers):
            await queue.submit("discord", _req("discord", m))
            if i == 5:
                queue.pause("discord", retry_after_seconds=0.02)

    async def consumer() -> None:
        for _ in markers:
            req = await queue.consume("discord")
            received.append(req["marker"])

    async with asyncio.TaskGroup() as tg:
        tg.create_task(producer())
        tg.create_task(consumer())

    assert sorted(received) == sorted(markers)
    assert len(received) == len(markers)  # exactly once each


@pytest.mark.asyncio
async def test_pause_idempotent_extends_to_later_window() -> None:
    queue: OutboundQueue[dict[str, str]] = OutboundQueue(audit_writer=_RecordingAuditWriter())
    await queue.submit("discord", _req("discord", "a"))
    queue.pause("discord", retry_after_seconds=0.30)
    # A shorter follow-up window is a no-op: it must NOT shorten the resume.
    queue.pause("discord", retry_after_seconds=0.02)

    consume_task = asyncio.ensure_future(queue.consume("discord"))
    # At 0.08s the short window would already have resumed; the longer window
    # must still be holding consume blocked.
    await asyncio.sleep(0.08)
    assert not consume_task.done()

    result = await asyncio.wait_for(consume_task, timeout=1.0)
    assert result["marker"] == "a"


@pytest.mark.asyncio
async def test_pause_extends_to_a_later_window_reschedules_timer() -> None:
    queue: OutboundQueue[dict[str, str]] = OutboundQueue(audit_writer=_RecordingAuditWriter())
    await queue.submit("discord", _req("discord", "a"))
    queue.pause("discord", retry_after_seconds=0.03)
    # A LATER window extends the pause: it cancels the first timer and
    # reschedules. The original 0.03 window must NOT resume consume.
    queue.pause("discord", retry_after_seconds=0.30)

    consume_task = asyncio.ensure_future(queue.consume("discord"))
    await asyncio.sleep(0.08)  # past the original 0.03 window
    assert not consume_task.done()  # extended window still holds

    result = await asyncio.wait_for(consume_task, timeout=1.0)
    assert result["marker"] == "a"


@pytest.mark.asyncio
async def test_resume_on_running_adapter_is_a_noop() -> None:
    queue: OutboundQueue[dict[str, str]] = OutboundQueue(audit_writer=_RecordingAuditWriter())
    await queue.submit("discord", _req("discord", "a"))
    # Resume without a preceding pause: the adapter is already running, there is
    # no timer to cancel, and consume proceeds normally.
    queue.resume("discord")
    result = await asyncio.wait_for(queue.consume("discord"), timeout=1.0)
    assert result["marker"] == "a"


@pytest.mark.asyncio
async def test_init_requires_audit_writer_and_caps_per_adapter() -> None:
    writer = _RecordingAuditWriter()
    queue: OutboundQueue[dict[str, str]] = OutboundQueue(
        max_in_flight_per_adapter=2, audit_writer=writer
    )
    assert queue.max_in_flight_per_adapter == 2
    assert queue.audit_writer is writer

    # The cap is per-adapter, not process-wide: a third in-flight submit on the
    # SAME adapter blocks until a consume frees a slot, but a different adapter
    # is unaffected.
    await queue.submit("discord", _req("discord", "1"))
    await queue.submit("discord", _req("discord", "2"))
    third = asyncio.ensure_future(queue.submit("discord", _req("discord", "3")))
    await asyncio.sleep(0.01)
    assert not third.done()  # cap reached on "discord"

    # A different adapter has its own cap.
    await asyncio.wait_for(queue.submit("tui", _req("tui", "x")), timeout=1.0)

    # Draining one "discord" slot lets the third submit proceed.
    await queue.consume("discord")
    await asyncio.wait_for(third, timeout=1.0)
