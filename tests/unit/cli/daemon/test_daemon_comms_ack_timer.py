"""The daemon's per-connection durable-intake ack timer (Spec A G4b-2a-pre / ADR-0032).

``_emit_durable_intake_ack_loop`` reads the host tracker's ``cumulative_ack`` on a
bounded interval and emits ONE ``daemon.comms.ack{cumulative_ack}`` via the runner's
``send_notification`` ONLY when the high-water advanced since the last emit. Key
invariants (F5):

* the last-emitted sentinel inits to ``-1`` (NOT 0) so the first commit
  (``cumulative_ack -1 -> 0``) DOES emit;
* the emitted value floors to ``max(ack, 0)`` (the tracker returns ``-1`` before any
  commit);
* emit-only-on-advance (quiet-link suppression);
* a broken-pipe send is FAIL-LOUD (re-raises — the pump's crash arm handles the
  connection death; never swallowed into a quiet retry).

The timer is reaped per-connection by the ``_accept_and_pump`` ``finally`` (a
cancel -> await); these unit cases drive the loop body directly with a short
interval + a shutdown event so the cancellation path is deterministic.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Mapping

import pytest

from alfred.cli.daemon._commands import _emit_durable_intake_ack_loop
from alfred.comms_mcp.protocol import DAEMON_COMMS_ACK
from alfred.gateway._seq_tracker import BoundedSeqAckTracker

pytestmark = pytest.mark.asyncio

_FAST_INTERVAL = 0.01


class _RecordingSender:
    """Records every (method, params) the loop emits."""

    def __init__(self, *, broken: bool = False) -> None:
        self.sent: list[tuple[str, Mapping[str, object]]] = []
        self._broken = broken

    async def send_notification(self, method: str, params: Mapping[str, object]) -> None:
        if self._broken:
            raise BrokenPipeError("peer gone")
        self.sent.append((method, params))


async def _run_until(
    *,
    sender: _RecordingSender,
    tracker: BoundedSeqAckTracker,
    condition: Callable[[], bool],
    timeout: float = 2.0,
) -> None:
    """Start the loop, wait for ``condition()``, then cancel + reap it."""
    shutdown = asyncio.Event()
    task = asyncio.ensure_future(
        _emit_durable_intake_ack_loop(
            send_notification=sender.send_notification,
            cumulative_ack=tracker.cumulative_ack,
            shutdown_event=shutdown,
            interval_seconds=_FAST_INTERVAL,
        )
    )
    try:
        async with asyncio.timeout(timeout):
            while not condition():
                await asyncio.sleep(_FAST_INTERVAL)
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)


async def test_first_commit_emits_ack_zero() -> None:
    # cumulative_ack goes -1 -> 0; the sentinel is -1, so the first commit DOES emit.
    sender = _RecordingSender()
    tracker = BoundedSeqAckTracker()
    tracker.observe(0)
    await _run_until(sender=sender, tracker=tracker, condition=lambda: len(sender.sent) >= 1)
    method, params = sender.sent[0]
    assert method == DAEMON_COMMS_ACK
    assert params == {"cumulative_ack": 0}


async def test_quiet_link_emits_nothing() -> None:
    # No commit ever — cumulative_ack stays -1, which floors to 0 but never EXCEEDS
    # the -1 sentinel-advance gate (no advance => no frame).
    sender = _RecordingSender()
    tracker = BoundedSeqAckTracker()
    shutdown = asyncio.Event()
    task = asyncio.ensure_future(
        _emit_durable_intake_ack_loop(
            send_notification=sender.send_notification,
            cumulative_ack=tracker.cumulative_ack,
            shutdown_event=shutdown,
            interval_seconds=_FAST_INTERVAL,
        )
    )
    # Let several intervals elapse with no advance.
    await asyncio.sleep(_FAST_INTERVAL * 5)
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)
    assert sender.sent == []


async def test_emits_once_per_advance_not_per_tick() -> None:
    # Advance to 2, wait for the emit, then assert no further frame while quiet.
    sender = _RecordingSender()
    tracker = BoundedSeqAckTracker()
    for seq in (0, 1, 2):
        tracker.observe(seq)
    await _run_until(sender=sender, tracker=tracker, condition=lambda: len(sender.sent) >= 1)
    # A quiet window after the emit must NOT produce a second redundant frame.
    await asyncio.sleep(_FAST_INTERVAL * 4)
    assert [p["cumulative_ack"] for _m, p in sender.sent] == [2]


async def test_advance_after_emit_emits_again() -> None:
    sender = _RecordingSender()
    tracker = BoundedSeqAckTracker()
    tracker.observe(0)
    await _run_until(sender=sender, tracker=tracker, condition=lambda: len(sender.sent) >= 1)
    tracker.observe(1)
    await _run_until(sender=sender, tracker=tracker, condition=lambda: len(sender.sent) >= 2)
    assert [p["cumulative_ack"] for _m, p in sender.sent] == [0, 1]


async def test_broken_pipe_send_is_fail_loud() -> None:
    # A broken-pipe send must PROPAGATE (the pump's crash arm handles the death),
    # never be swallowed into a quiet retry (F5).
    sender = _RecordingSender(broken=True)
    tracker = BoundedSeqAckTracker()
    tracker.observe(0)
    shutdown = asyncio.Event()
    with pytest.raises(BrokenPipeError):
        async with asyncio.timeout(2.0):
            await _emit_durable_intake_ack_loop(
                send_notification=sender.send_notification,
                cumulative_ack=tracker.cumulative_ack,
                shutdown_event=shutdown,
                interval_seconds=_FAST_INTERVAL,
            )


async def test_shutdown_event_ends_the_loop() -> None:
    # Setting the shutdown event ends the loop promptly (no cancel needed).
    sender = _RecordingSender()
    tracker = BoundedSeqAckTracker()
    shutdown = asyncio.Event()
    task = asyncio.ensure_future(
        _emit_durable_intake_ack_loop(
            send_notification=sender.send_notification,
            cumulative_ack=tracker.cumulative_ack,
            shutdown_event=shutdown,
            interval_seconds=_FAST_INTERVAL,
        )
    )
    shutdown.set()
    async with asyncio.timeout(2.0):
        await task  # returns cleanly, no cancel
