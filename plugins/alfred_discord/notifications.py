"""Plugin → host JSON-RPC notification sink + frame builders (PR-S4-9 #206).

The Discord adapter emits four plugin→host notifications over stdio
(``inbound.message``, ``adapter.binding_request``, ``adapter.rate_limit_signal``,
``adapter.crashed``). Each is a JSON-RPC *notification* — a ``{"jsonrpc": "2.0",
"method": <name>, "params": {...}}`` frame with NO ``id`` (the host does not
reply to a notification).

This module owns the single :class:`NotificationSink` contract every emitter
writes through, plus the frame builders that stamp the wire method names. The
production sink writes one line-delimited JSON frame to ``sys.stdout`` (matching
the host's line-delimited transport); the emitters are constructed with the sink
so they hold no I/O global and are unit-testable with a recording double.

The ``params`` payloads mirror the host-side ADR-0024 notification schemas in
``alfred.comms_mcp.protocol`` (``RateLimitSignal`` / ``BindingRequestNotification``
/ ``CrashedNotification`` / ``InboundMessageNotification``). The builders take an
already-validated source model and emit its ``model_dump`` so a typo'd field
surfaces host-side as a loud validation failure (the host re-parses the frame).
"""

from __future__ import annotations

import asyncio
import json
import sys
from collections.abc import Mapping
from typing import Final, Protocol

# Plugin -> host notification method names (ADR-0024 wire contract).
NOTIFY_INBOUND: Final[str] = "inbound.message"
NOTIFY_BINDING: Final[str] = "adapter.binding_request"
NOTIFY_RATE_LIMIT: Final[str] = "adapter.rate_limit_signal"
NOTIFY_CRASHED: Final[str] = "adapter.crashed"


class NotificationSink(Protocol):
    """An awaitable sink that writes one plugin→host notification frame.

    Awaitable by contract (closure comms-3): an emitter that must block its
    caller until the frame is fully accepted — e.g. the rate-limit signal that
    has to land host-ward BEFORE any further outbound emit — ``await``\\s this.
    """

    async def emit(self, frame: Mapping[str, object]) -> None: ...


class SyncNotificationSink(Protocol):
    """A SYNCHRONOUS sink for the crash path, where the event loop may be gone.

    The crash emitter runs from a top-level except handler that fires as the
    process tears down — there may be no running event loop to ``await`` an async
    sink. This sync sink writes + flushes a single frame inline so the crash
    notification lands before ``sys.exit``.
    """

    def emit_sync(self, frame: Mapping[str, object]) -> None: ...


def notification_frame(method: str, params: Mapping[str, object]) -> dict[str, object]:
    """Build a JSON-RPC notification frame (no ``id``) for ``method`` + ``params``."""
    return {"jsonrpc": "2.0", "method": method, "params": dict(params)}


class StdoutNotificationSink:
    """Production sink: write one line-delimited JSON frame to ``sys.stdout``.

    The write runs in a thread so a blocked stdout pipe does not stall the event
    loop; the flush is explicit so a frame is not buffered past a subsequent
    ``sys.exit`` (the crash emitter relies on this to land its frame before the
    process exits).

    M3: two concurrent :meth:`emit` calls — e.g. a rate-limit signal racing an
    inbound frame — would otherwise land on DIFFERENT ``to_thread`` workers and
    interleave their byte writes on the shared ``sys.stdout``, corrupting the
    line-delimited JSON-RPC stream. An ``asyncio.Lock`` serialises the
    write+flush so exactly one frame crosses the wire at a time. The lock is
    held across the ``to_thread`` await, so the second emitter waits for the
    first frame's flush before its own worker starts writing.
    """

    def __init__(self) -> None:
        self._emit_lock = asyncio.Lock()

    async def emit(self, frame: Mapping[str, object]) -> None:
        async with self._emit_lock:
            await asyncio.to_thread(self._write, frame)

    def emit_sync(self, frame: Mapping[str, object]) -> None:
        """Write + flush a frame inline (no event loop) — the crash-path sink."""
        self._write(frame)

    @staticmethod
    def _write(frame: Mapping[str, object]) -> None:
        sys.stdout.write(json.dumps(frame) + "\n")
        sys.stdout.flush()


__all__ = [
    "NOTIFY_BINDING",
    "NOTIFY_CRASHED",
    "NOTIFY_INBOUND",
    "NOTIFY_RATE_LIMIT",
    "NotificationSink",
    "StdoutNotificationSink",
    "SyncNotificationSink",
    "notification_frame",
]
