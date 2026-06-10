"""Host-side outbound dispatch queue (PR-S4-9 Task A1, #206).

:class:`OutboundQueue` is the **new Slice-4 host-side primitive** (verified
absent on ``main`` per the plan's verification gate) that every persona's
outbound message flows through before it reaches a comms-MCP adapter. It owns
two trust-boundary-adjacent responsibilities:

* **Per-adapter backpressure** — an ``asyncio.Semaphore(max_in_flight_per_adapter)``
  bounds how many messages can be in flight (submitted-but-not-consumed) for a
  single adapter, so a misbehaving or slow adapter cannot exhaust host memory
  with an unbounded outbound backlog. The cap is per-adapter, NOT process-wide:
  a stalled Discord adapter must not starve the TUI adapter.

* **Rate-limit pause/resume** — when a Discord ``adapter.rate_limit_signal``
  reports a 429, the host calls :meth:`pause` with the platform's
  ``retry_after_seconds``. ``pause`` clears the per-adapter resume gate (an
  ``asyncio.Event``) so :meth:`consume` blocks, and schedules a
  ``loop.call_later`` auto-resume after the window. :meth:`resume` is the manual
  override (operator action / explicit signal) that returns control immediately.

This module is observability-only at the queue layer: :meth:`pause` emits the
``comms.outbound_queue.paused`` structlog event. It does NOT write an audit row
— the authoritative audit row for a rate-limit signal is
``COMMS_RATE_LIMIT_SIGNAL_FIELDS``, emitted by the host's signal handler, not by
the queue. The ``audit_writer`` is a REQUIRED constructor dependency so the
emission surface is wired and observable from construction (no global state), but
the queue itself never bypasses it with a silent path.

Wiring status (#235). The queue is TESTED but NOT yet on the live persona-outbound
path — the daemon does not spawn the discord plugin until the PR-S4-10 flag-day,
which wires every persona's outbound message through this queue. Until then the
backpressure + rate-limit pause/resume + comms-2 resume re-scan are exercised only
by tests. See ``docs/subsystems/comms.md`` (Slice-4 wiring-status note) and #235.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import Protocol

import structlog

from alfred.comms_mcp.errors import CommsMcpError

_log = structlog.get_logger(__name__)

_DEFAULT_MAX_IN_FLIGHT_PER_ADAPTER = 32


class OutboundResumeDlpBlockedError(CommsMcpError):
    """A queued message was refused on resume because a re-scan now redacts it.

    comms-2: ``pause``/``resume`` re-runs the outbound DLP scan defensively so a
    policy hot-reload that tightened the rules during the pause window cannot let
    a now-prohibited secret slip out on resume. Raised by :meth:`OutboundQueue.consume`
    when the post-resume re-scan redacts content the original scan did not; the
    host emits ``DLP_OUTBOUND_REFUSED_FIELDS(reason="dlp_post_resume_block")`` and
    drops the message rather than emitting it.
    """


class AuditWriterProtocol(Protocol):
    """Structural contract for the audit writer the queue holds.

    Intentionally minimal: the queue never writes an audit row itself (its only
    signal is the ``comms.outbound_queue.paused`` structlog event). The writer is
    a required dependency so the emission surface is wired explicitly rather than
    reached through a module global — a future requeue path that needs an audit
    row has the handle without re-plumbing construction.
    """


class _AdapterState[RequestT]:
    """Per-adapter mutable state: the FIFO, the resume gate, the cap.

    Frozen-by-discipline rather than by type — the queue object owns exactly one
    of these per adapter and never shares them across event loops.
    """

    __slots__ = (
        "cap",
        "generation",
        "queue",
        "rescan_through_generation",
        "resume_deadline",
        "resume_event",
        "timer",
    )

    def __init__(self, *, max_in_flight: int) -> None:
        # comms-2 / H2: each item carries the resume-``generation`` it was
        # enqueued under so EVERY message held back across a pause is re-scanned
        # on resume — not just the first. The bare request is unwrapped at
        # ``consume``; callers never see the stamp.
        self.queue: asyncio.Queue[tuple[int, RequestT]] = asyncio.Queue()
        # The resume gate starts SET (running). ``pause`` clears it; ``resume``
        # (manual or timer-driven) sets it again.
        self.resume_event = asyncio.Event()
        self.resume_event.set()
        self.cap = asyncio.Semaphore(max_in_flight)
        # Loop-time deadline of the currently-scheduled auto-resume, or ``None``
        # when the adapter is running. Used to make ``pause`` extend-only.
        self.resume_deadline: float | None = None
        self.timer: asyncio.TimerHandle | None = None
        # comms-2 / H2: monotonically increasing generation, bumped on every
        # resume. ``submit`` stamps the CURRENT generation onto each item;
        # ``rescan_through_generation`` records the highest generation whose
        # messages must still be re-scanned (i.e. were enqueued before the most
        # recent resume). A message is re-scanned iff its stamped generation is
        # ``<=`` this watermark — so the WHOLE backlog held through one pause is
        # covered, while a message enqueued AFTER resume (a higher generation) is
        # not.
        self.generation = 0
        self.rescan_through_generation = -1


class OutboundQueue[RequestT]:
    """Per-adapter outbound FIFO with rate-limit pause/resume.

    Generic over the request type ``RequestT`` so the production wiring uses
    :class:`alfred.comms_mcp.protocol.OutboundMessageRequest` while unit tests can
    drive it with an opaque payload. The class holds no module-level state; every
    adapter's queue/gate/cap is lazily created on first reference.
    """

    def __init__(
        self,
        *,
        max_in_flight_per_adapter: int = _DEFAULT_MAX_IN_FLIGHT_PER_ADAPTER,
        audit_writer: AuditWriterProtocol,
        dlp_rescanner: Callable[[str], int] | None = None,
    ) -> None:
        """Construct an empty queue.

        Args:
            max_in_flight_per_adapter: Per-adapter in-flight cap. A submit blocks
                once this many messages are queued-but-not-consumed for that
                adapter. Per-adapter, not process-wide. Keyword-only.
            audit_writer: Required emission dependency (see module docstring).
                Keyword-only — passed explicitly, never reached via a global.
            dlp_rescanner: Optional ``body -> redaction_count`` callable (comms-2).
                When wired, :meth:`consume` re-runs it on a message that waited
                through a pause; a non-zero count means a hot-reloaded stricter
                policy now redacts the body, so the message is REFUSED
                (:class:`OutboundResumeDlpBlockedError`) rather than emitted. ``None``
                preserves the legacy consume path (PR-S4-10 TUI wiring).
        """
        self.max_in_flight_per_adapter = max_in_flight_per_adapter
        self.audit_writer = audit_writer
        self._dlp_rescanner = dlp_rescanner
        self._adapters: dict[str, _AdapterState[RequestT]] = {}

    def _state(self, adapter_id: str) -> _AdapterState[RequestT]:
        state = self._adapters.get(adapter_id)
        if state is None:
            state = _AdapterState(max_in_flight=self.max_in_flight_per_adapter)
            self._adapters[adapter_id] = state
        return state

    async def submit(self, adapter_id: str, request: RequestT) -> None:
        """Enqueue ``request`` for ``adapter_id``, honouring the in-flight cap.

        Acquires the per-adapter semaphore first so the call blocks (rather than
        growing the queue unbounded) once ``max_in_flight_per_adapter`` messages
        are queued-but-not-consumed. The slot is released in :meth:`consume`.
        """
        state = self._state(adapter_id)
        await state.cap.acquire()
        # Stamp the current resume-generation so ``consume`` knows whether this
        # item waited through a pause (H2).
        await state.queue.put((state.generation, request))

    async def consume(self, adapter_id: str) -> RequestT:
        """Return the next request for ``adapter_id`` in FIFO order.

        Blocks while the adapter is paused (the resume gate is cleared) and while
        the queue is empty. Releases one in-flight cap slot once a request is
        pulled, so a blocked :meth:`submit` can proceed.
        """
        state = self._state(adapter_id)
        await state.resume_event.wait()
        generation, request = await state.queue.get()
        state.cap.release()
        # comms-2 / H2: a message enqueued at or before the resume watermark
        # waited through a pause and is re-scanned before re-emission, so a
        # policy hot-reload during the pause window cannot leak a now-prohibited
        # secret. EVERY such message is covered (not just the first), while a
        # message enqueued after the resume (a higher generation) skips the scan.
        if generation <= state.rescan_through_generation:
            self._rescan_or_refuse(adapter_id, request)
        return request

    def _rescan_or_refuse(self, adapter_id: str, request: RequestT) -> None:
        if self._dlp_rescanner is None:
            return
        redactions = self._dlp_rescanner(str(request))
        if redactions > 0:
            _log.warning(
                "comms.outbound_queue.dlp_post_resume_block",
                adapter_id=adapter_id,
                redactions=redactions,
            )
            raise OutboundResumeDlpBlockedError(
                f"outbound message refused on resume for adapter {adapter_id!r}: "
                f"post-resume re-scan redacted {redactions} segment(s) "
                "(reason=dlp_post_resume_block)"
            )

    def pause(self, adapter_id: str, retry_after_seconds: float) -> None:
        """Suspend emission for ``adapter_id`` for ``retry_after_seconds``.

        Clears the resume gate (so :meth:`consume` blocks) and schedules a
        ``loop.call_later`` auto-resume. Idempotent and extend-only: a second
        ``pause`` whose window ends LATER reschedules the auto-resume to the
        later deadline; a shorter window is a no-op (it must never cut a pause
        short). Emits the ``comms.outbound_queue.paused`` observability event —
        NOT an audit row.
        """
        loop = asyncio.get_running_loop()
        state = self._state(adapter_id)
        new_deadline = loop.time() + retry_after_seconds

        if state.resume_deadline is not None and new_deadline <= state.resume_deadline:
            # Already paused until a later-or-equal deadline — shorter window is
            # a no-op (extend-only contract).
            return

        if state.timer is not None:
            state.timer.cancel()
        state.resume_event.clear()
        state.resume_deadline = new_deadline
        state.timer = loop.call_later(retry_after_seconds, self._auto_resume, adapter_id)
        _log.info(
            "comms.outbound_queue.paused",
            adapter_id=adapter_id,
            retry_after_seconds=retry_after_seconds,
        )

    def resume(self, adapter_id: str) -> None:
        """Resume emission for ``adapter_id`` immediately (manual override).

        Cancels any pending auto-resume timer and sets the resume gate so blocked
        :meth:`consume` calls proceed. A no-op when the adapter is already
        running.
        """
        state = self._state(adapter_id)
        self._clear_pause(state)

    def _auto_resume(self, adapter_id: str) -> None:
        """Timer callback: resume the adapter when its retry-after window ends."""
        state = self._adapters.get(adapter_id)
        if state is None:  # pragma: no cover - adapter cannot vanish mid-pause
            return
        self._clear_pause(state)

    @staticmethod
    def _clear_pause(state: _AdapterState[RequestT]) -> None:
        was_paused = not state.resume_event.is_set()
        if state.timer is not None:
            state.timer.cancel()
            state.timer = None
        state.resume_deadline = None
        state.resume_event.set()
        # comms-2 / H2: if this resume actually ended a pause, EVERY message
        # stamped with the generation that just ended (i.e. enqueued at or before
        # this point) must be re-scanned on consume. Record the watermark at the
        # current generation, then bump so messages submitted AFTER resume are a
        # fresh generation and skip the re-scan. Guarded on ``was_paused`` so a
        # redundant resume on a running adapter is a no-op (no spurious rescans).
        if was_paused:
            state.rescan_through_generation = state.generation
            state.generation += 1


__all__ = ["AuditWriterProtocol", "OutboundQueue", "OutboundResumeDlpBlockedError"]
