"""Top-level crash handler → ``adapter.crashed`` + ``SystemExit(1)`` (Task G3, #206).

When an uncaught exception escapes the adapter's main loop, :class:`CrashEmitter`:

1. ignores operator-initiated shutdowns (``KeyboardInterrupt`` / ``SystemExit``)
   — those are not crashes; it re-raises them unchanged;
2. scrubs ``str(exc)`` with the in-plugin DLP-lite (closure sec-2) so a leaked
   secret in the exception string never crosses stdio raw;
3. emits ONE ``adapter.crashed`` notification (re-entry guarded — a crash during
   crash handling does not double-emit), best-effort flushing it;
4. exits with ``SystemExit(1)`` so the host's supervisor sees the process die
   and trips its breaker (spec §8.4: 3-in-5min → ``trip_breaker``).

If the notification write itself fails (broken pipe — the host is already gone),
the secondary exception is swallowed (logged best-effort) and the emitter still
exits 1: a failed crash-notification must never prevent the process from dying.

The sink is SYNCHRONOUS (:class:`SyncNotificationSink`): this handler may run as
the event loop is torn down, so there is no loop to ``await``.
"""

from __future__ import annotations

import structlog

from alfred.comms_mcp.protocol import CrashedNotification
from plugins.alfred_discord.dlp_lite import scrub_in_plugin
from plugins.alfred_discord.notifications import (
    NOTIFY_CRASHED,
    SyncNotificationSink,
    notification_frame,
)

_log = structlog.get_logger(__name__)

# Bound for the crash detail before it crosses the wire. The plan floats 256/512;
# 256 matches the outbound terminal-detail bound and the spec's tightest cap.
_DETAIL_MAX_LEN = 256


class CrashEmitter:
    """Emits a single DLP-scrubbed ``adapter.crashed`` frame, then exits 1."""

    def __init__(self, *, adapter_id: str, sink: SyncNotificationSink) -> None:
        self._adapter_id = adapter_id
        self._sink = sink
        # Re-entry latch: a crash WHILE handling a crash must not double-emit.
        self._emitted = False

    def handle_crash(self, exc: BaseException) -> None:
        """Handle an uncaught ``exc``: emit (once), then ``SystemExit(1)``.

        Re-raises ``KeyboardInterrupt`` / ``SystemExit`` unchanged — those are
        operator shutdowns, not crashes.
        """
        if isinstance(exc, KeyboardInterrupt | SystemExit):
            raise exc

        if not self._emitted:
            self._emitted = True
            self._emit_crash(exc)

        raise SystemExit(1)

    def _emit_crash(self, exc: BaseException) -> None:
        """Build + write the crash frame, swallowing any write failure."""
        detail = scrub_in_plugin(str(exc))[:_DETAIL_MAX_LEN]
        notification = CrashedNotification(
            adapter_id=self._adapter_id,
            error_class=type(exc).__qualname__,
            detail=detail,
        )
        frame = notification_frame(NOTIFY_CRASHED, notification.model_dump(mode="json"))
        try:
            self._sink.emit_sync(frame)
        except Exception:
            # Host already gone (broken pipe) or stdout closed — a failed crash
            # notification must NOT block the exit. Best-effort log only.
            _log.warning("comms.crash.notify_failed", adapter=self._adapter_id)
        else:
            _log.error("comms.crash.notified", adapter=self._adapter_id)


__all__ = ["CrashEmitter"]
