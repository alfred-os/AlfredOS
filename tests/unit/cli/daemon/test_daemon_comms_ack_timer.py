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
from collections.abc import AsyncIterator, Callable, Mapping
from contextlib import asynccontextmanager

import pytest

from alfred.cli.daemon._comms_boot import _emit_durable_intake_ack_loop
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


@asynccontextmanager
async def _running_loop(
    *, sender: _RecordingSender, tracker: BoundedSeqAckTracker
) -> AsyncIterator[None]:
    """Run ONE ack loop for the whole block; cancel + reap on exit.

    Unlike :func:`_run_until` (which cancels as soon as its condition fires), the loop
    stays ALIVE for the entire ``async with`` body — so a test can drive the tracker,
    wait for an emit, AND then assert over a further quiet/advance window against the
    SAME loop instance. The loop's internal ``last_emitted`` state therefore persists
    across those steps, which is exactly what the F5 emit-on-advance invariant needs
    (a fresh loop per step would reset ``last_emitted`` to the ``-1`` sentinel and make
    the suppression / re-emit assertions vacuous — CodeRabbit, Spec A G4b-2a-pre).
    """
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
        yield
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)


async def _wait_until(condition: Callable[[], bool], *, timeout: float = 2.0) -> None:
    """Poll ``condition()`` on the fast interval until true (or the timeout fires)."""
    async with asyncio.timeout(timeout):
        while not condition():
            await asyncio.sleep(_FAST_INTERVAL)


async def _run_until(
    *,
    sender: _RecordingSender,
    tracker: BoundedSeqAckTracker,
    condition: Callable[[], bool],
    timeout: float = 2.0,
) -> None:
    """Start the loop, wait for ``condition()``, then cancel + reap it (one-shot)."""
    async with _running_loop(sender=sender, tracker=tracker):
        await _wait_until(condition, timeout=timeout)


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
    # Advance to 2, wait for the emit, then — with the SAME loop STILL RUNNING — assert
    # a quiet window produces no second frame. The loop must be alive during the quiet
    # window or the suppression check is vacuous (CodeRabbit).
    sender = _RecordingSender()
    tracker = BoundedSeqAckTracker()
    for seq in (0, 1, 2):
        tracker.observe(seq)
    async with _running_loop(sender=sender, tracker=tracker):
        await _wait_until(lambda: len(sender.sent) >= 1)
        # Many ticks elapse with no advance — the live loop must NOT re-emit.
        await asyncio.sleep(_FAST_INTERVAL * 5)
        assert [p["cumulative_ack"] for _m, p in sender.sent] == [2]


async def test_advance_after_emit_emits_again() -> None:
    # ONE loop instance: emit at 0, then a LATER advance to 1 must emit again — proving
    # the loop's internal last_emitted carries 0 across the advance (a fresh loop per
    # step would reset to the -1 sentinel and emit 1 regardless, hiding the bug).
    sender = _RecordingSender()
    tracker = BoundedSeqAckTracker()
    tracker.observe(0)
    async with _running_loop(sender=sender, tracker=tracker):
        await _wait_until(lambda: len(sender.sent) >= 1)
        tracker.observe(1)
        await _wait_until(lambda: len(sender.sent) >= 2)
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


async def test_shutdown_before_first_tick_ends_the_loop() -> None:
    # Shutdown already set before the first ``while`` check — exits at the top guard.
    sender = _RecordingSender()
    tracker = BoundedSeqAckTracker()
    shutdown = asyncio.Event()
    shutdown.set()
    async with asyncio.timeout(2.0):
        await _emit_durable_intake_ack_loop(
            send_notification=sender.send_notification,
            cumulative_ack=tracker.cumulative_ack,
            shutdown_event=shutdown,
            interval_seconds=_FAST_INTERVAL,
        )
    assert sender.sent == []


async def test_shutdown_during_a_parked_tick_ends_the_loop() -> None:
    # The loop is parked in the interval wait (long interval); setting the shutdown
    # mid-wait wins the race and the loop returns at the post-wait guard — NOT after a
    # full interval. Drives the mid-loop shutdown return (graceful-stop promptness).
    sender = _RecordingSender()
    tracker = BoundedSeqAckTracker()
    shutdown = asyncio.Event()
    task = asyncio.ensure_future(
        _emit_durable_intake_ack_loop(
            send_notification=sender.send_notification,
            cumulative_ack=tracker.cumulative_ack,
            shutdown_event=shutdown,
            interval_seconds=30.0,  # long — the loop is parked in the wait
        )
    )
    await asyncio.sleep(_FAST_INTERVAL)  # let the loop enter the parked wait
    shutdown.set()
    async with asyncio.timeout(2.0):
        await task  # returns promptly (does NOT wait out the 30s interval)
    assert sender.sent == []
