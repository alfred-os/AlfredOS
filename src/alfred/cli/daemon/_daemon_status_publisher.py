"""Periodic daemon status-snapshot publisher (G6-2b-2c / #288).

A supervised async task that polls the in-process AdapterStatusObserver +
CrashIncidentReconciler, builds a DaemonStatusSnapshot, and writes it to the 0600
runtime-dir file IF the serialised content changed since the last write. The
observer/reconciler stay pure (their G6-2b constructor signatures are NOT
re-touched) — the publisher reads their additive enumeration surfaces.

Lifecycle MIRRORS the daemon's other supervised resources (socket listeners): the
boot loop calls ``start()`` after the comms graph is built and ``aclose()`` in the
drain ``finally`` on EVERY exit path (cancel + await + delete the file, so a dead
daemon leaves no stale snapshot — the boot_id cross-check is the belt; this reap is
the braces).

SELF-HEALING, fail-loud-but-non-fatal (sec-MEDIUM-4, correction #2): the snapshot
is daemon-internal observability, NOT a security boundary. A failure to BUILD or
WRITE one refresh is logged LOUD (a structured warning, NEVER silent) but is
NON-fatal — a status-display hiccup must not crash the daemon. ``refresh_once``
therefore catches ``Exception`` (build AND write inside the try), and ``_run``
wraps each iteration so one bad refresh logs and the supervised loop CONTINUES
(a silently-dead publisher would mislead an operator worse than a missing
snapshot). This is DISTINCT from the hard-rule-#7 security paths, which escalate
loudly + quarantine.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Final

import structlog

from alfred.cli.daemon._daemon_status_snapshot import (
    build_daemon_status_snapshot,
    delete_status_snapshot,
    write_status_snapshot,
)

if TYPE_CHECKING:
    from alfred.cli.daemon._daemon_status_snapshot import DaemonStatusSnapshot
    from alfred.comms_mcp.adapter_status_observer import AdapterStatusObserver
    from alfred.comms_mcp.crash_incident_reconciler import CrashIncidentReconciler

_log = structlog.get_logger(__name__)
_DEFAULT_INTERVAL_SECONDS: Final[float] = 2.0


class DaemonStatusSnapshotPublisher:
    """Periodically publish the per-adapter status snapshot to the runtime-dir file."""

    def __init__(
        self,
        *,
        path: Path,
        boot_id: str,
        observer: AdapterStatusObserver,
        reconciler: CrashIncidentReconciler,
        now: Callable[[], datetime],
        interval_seconds: float = _DEFAULT_INTERVAL_SECONDS,
    ) -> None:
        self._path = path
        self._boot_id = boot_id
        self._observer = observer
        self._reconciler = reconciler
        self._now = now
        self._interval = interval_seconds
        self._task: asyncio.Task[None] | None = None
        self._last_json: str | None = None

    def _build(self) -> DaemonStatusSnapshot:
        return build_daemon_status_snapshot(
            boot_id=self._boot_id,
            written_at=self._now(),
            observer=self._observer,
            reconciler=self._reconciler,
        )

    async def refresh_once(self) -> None:
        """Build + write the snapshot IF its content changed. Loud-but-non-fatal on error.

        The build, content-key computation, AND write all sit INSIDE the try
        (correction #2): an exception from ANY of them — a bad poll, a serialise
        fault, or a filesystem error — is caught, logged LOUD, and swallowed so the
        daemon never dies for a status-display hiccup. The catch is ``Exception``
        (not just ``OSError``) for the same reason. The ``error`` field is bounded
        to the exception TYPE name (correction #16d) so a wide catch never funnels
        attacker-influenced text into the log line.
        """
        try:
            snapshot = self._build()
            # Compare on content EXCLUDING written_at (the timestamp always advances;
            # we only rewrite on a real state change to avoid churn). The builder's
            # ``sorted(adapter_ids)`` order makes this key stable across refreshes.
            content_key = snapshot.model_copy(update={"written_at": ""}).model_dump_json()
            if content_key == self._last_json:
                return
            write_status_snapshot(self._path, snapshot)
            self._last_json = content_key
        except Exception as exc:
            _log.warning(
                "daemon_status_snapshot_write_failed",
                path=str(self._path),
                error=type(exc).__name__,
            )

    def start(self) -> None:
        """Start the periodic refresh task (idempotent)."""
        if self._task is None:
            self._task = asyncio.create_task(self._run(), name="daemon-status-publisher")

    async def _run(self) -> None:
        """The supervised refresh loop — resilient: one bad iteration never kills it.

        ``refresh_once`` already swallows its own faults, but the loop body is ALSO
        guarded (correction #2) so a fault outside ``refresh_once`` (e.g. a sleep
        cancellation that is NOT a real shutdown, or a future refactor) logs and the
        loop continues rather than silently dying. ``CancelledError`` is re-raised so
        ``aclose`` can cancel + await the task cleanly.
        """
        while True:
            try:
                await self.refresh_once()
                await asyncio.sleep(self._interval)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                _log.warning("daemon_status_snapshot_refresh_failed", error=type(exc).__name__)

    async def aclose(self) -> None:
        """Cancel + await the task and delete the snapshot file (reaped like the pidfile)."""
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None
        delete_status_snapshot(self._path)


__all__ = ["DaemonStatusSnapshotPublisher"]
