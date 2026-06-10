"""Emit ``adapter.rate_limit_signal`` on a Discord 429 (Task G1, PR-S4-9 #206).

When Discord answers an outbound send with HTTP 429, the adapter signals the
host so the host's ``OutboundQueue.pause(adapter_id, retry_after_seconds)``
suspends further emit for the platform's back-off window.

**Ordering (closure comms-3).** The signal is AWAITED, never fire-and-forget:
:meth:`RateLimitEmitter.emit_for_rate_limit` does not return until the sink has
fully accepted the frame. The outbound emit loop awaits this BEFORE any further
outbound send, so no message slips out between the 429 and the host-side pause.
(The plan's original Task-G1 text floated a fire-and-forget task for latency
decoupling; closure comms-3 overrides that — correctness over latency at the
rate-limit boundary.)

**Debounce.** A burst of 429s for the same ``platform_endpoint`` inside one
retry-after window would otherwise storm the host with redundant pause signals.
The emitter keeps a per-endpoint last-signalled deadline and suppresses a repeat
inside the window. A successful outbound calls :meth:`clear` to reset the state
so the next genuine 429 emits a fresh signal.
"""

from __future__ import annotations

import math
import time
from typing import Final

import discord
import structlog

from alfred.comms_mcp.protocol import RateLimitSignal
from plugins.alfred_discord.notifications import (
    NOTIFY_RATE_LIMIT,
    NotificationSink,
    notification_frame,
)

_log = structlog.get_logger(__name__)

_DEFAULT_RETRY_AFTER_SECONDS: Final[int] = 5
_UNKNOWN_ENDPOINT: Final[str] = "discord.com:unknown"


class RateLimitEmitter:
    """Emits a debounced ``adapter.rate_limit_signal`` for a Discord 429."""

    def __init__(self, *, adapter_id: str, sink: NotificationSink) -> None:
        self._adapter_id = adapter_id
        self._sink = sink
        # Per-endpoint loop-time deadline until which a repeat 429 is suppressed.
        self._debounce_until: dict[str, float] = {}

    async def emit_for_rate_limit(self, exc: discord.HTTPException) -> None:
        """Emit one rate-limit signal for ``exc`` unless debounced.

        AWAITED end-to-end (comms-3): on return, the host has the frame.
        """
        await self.emit_signal(
            retry_after_seconds=self._retry_after(exc),
            platform_endpoint=self._endpoint(exc),
        )

    async def emit_signal(self, *, retry_after_seconds: int, platform_endpoint: str) -> None:
        """Emit one debounced rate-limit signal for an explicit window + endpoint.

        The dispatcher path (closure comms-3) calls this with the fields it
        recovered from the ``_OutboundRetryable`` result — the raw exception is
        already consumed by the outbound handler by then. AWAITED end-to-end.
        """
        now = time.monotonic()
        deadline = self._debounce_until.get(platform_endpoint)
        if deadline is not None and now < deadline:
            # Within the prior window for this endpoint — one signal is enough.
            _log.debug(
                "comms.rate_limit.debounced", adapter=self._adapter_id, endpoint=platform_endpoint
            )
            return

        self._debounce_until[platform_endpoint] = now + retry_after_seconds
        signal = RateLimitSignal(
            adapter_id=self._adapter_id,
            retry_after_seconds=retry_after_seconds,
            platform_endpoint=platform_endpoint,
        )
        frame = notification_frame(NOTIFY_RATE_LIMIT, signal.model_dump(mode="json"))
        await self._sink.emit(frame)
        _log.info(
            "comms.rate_limit.signalled", adapter=self._adapter_id, endpoint=platform_endpoint
        )

    def clear(self) -> None:
        """Reset all debounce state (call after a successful outbound)."""
        self._debounce_until.clear()

    @staticmethod
    def _retry_after(exc: discord.HTTPException) -> int:
        """Read ``retry_after`` (seconds), rounded UP, with header + default fallback."""
        raw = getattr(exc, "retry_after", None)
        if raw is None:
            response = getattr(exc, "response", None)
            headers = getattr(response, "headers", None)
            if headers is not None:
                raw = headers.get("Retry-After")
        try:
            return math.ceil(float(raw)) if raw is not None else _DEFAULT_RETRY_AFTER_SECONDS
        except (TypeError, ValueError):
            return _DEFAULT_RETRY_AFTER_SECONDS

    @staticmethod
    def _endpoint(exc: discord.HTTPException) -> str:
        """Derive a coarse ``host:segment`` endpoint label from the 429 response URL.

        Audit-safety: the label must NEVER carry the full URL. A Discord API
        response always targets ``discord.com``; for that host we keep a coarse
        ``discord.com:<trailing-segment>`` shape. For ANY other host — only
        reachable via a malicious redirect, a MITM, or a library bug — the URL
        could carry an id/token in its path, so we collapse to the stable
        ``_UNKNOWN_ENDPOINT`` placeholder rather than echo any of it into the
        audit row.
        """
        response = getattr(exc, "response", None)
        url = getattr(response, "url", None)
        if url is None:
            return _UNKNOWN_ENDPOINT
        text = str(url)
        if "discord.com" not in text:
            # Non-Discord host: fail safe — never echo a foreign URL's id-bearing
            # path into the audit label.
            return _UNKNOWN_ENDPOINT
        # Coarse label: the known host + a single trailing path segment shape.
        return f"discord.com:{text.rsplit('/', 1)[-1]}" if "/" in text else "discord.com"


__all__ = ["RateLimitEmitter"]
