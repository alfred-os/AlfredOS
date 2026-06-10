"""Outbound dispatch loop with the comms-3 rate-limit ordering guarantee (#206).

:class:`OutboundDispatcher` is the thin coordinator that ties the
:class:`~plugins.alfred_discord.outbound_handler.OutboundHandler` send-path to
the :class:`~plugins.alfred_discord.rate_limit_emitter.RateLimitEmitter`. It
exists to enforce closure **comms-3**: when a send returns a rate-limited
``_OutboundRetryable``, the rate-limit signal is AWAITED before
:meth:`dispatch` returns — so the host's pause lands before the caller submits
the next outbound. No fire-and-forget; the ordering is a hard sequence:

    send → (on 429) await signal → return → next send

A clean delivery clears the emitter's debounce state so a later genuine 429
emits a fresh signal.
"""

from __future__ import annotations

from typing import Final

import structlog

from alfred.comms_mcp.protocol import (
    OutboundMessageRequest,
    OutboundMessageResult,
    _OutboundRetryable,
)
from plugins.alfred_discord.outbound_handler import OutboundHandler
from plugins.alfred_discord.rate_limit_emitter import RateLimitEmitter

_log = structlog.get_logger(__name__)

# The error_class the outbound handler stamps on a 429-derived retryable result.
_RATE_LIMITED_CLASS: Final[str] = "discord_rate_limited"
# Coarse endpoint label for the host pause keying. The raw 429 response URL is
# consumed inside the handler; the host only needs the send-shape, never an id.
_SEND_ENDPOINT: Final[str] = "discord.com:channel.send"


class OutboundDispatcher:
    """Coordinates a single outbound send with the comms-3 ordering guarantee."""

    def __init__(self, *, handler: OutboundHandler, rate_limit_emitter: RateLimitEmitter) -> None:
        self._handler = handler
        self._emitter = rate_limit_emitter

    async def dispatch(self, request: OutboundMessageRequest) -> OutboundMessageResult:
        """Send ``request``; on a 429, AWAIT the rate-limit signal before returning.

        Returns the same ``OutboundMessageResult`` the handler produced — the
        signal emission is a side effect sequenced strictly before the return so
        the host's pause is in place before the next dispatch.
        """
        result = await self._handler.handle_outbound(request)

        if isinstance(result, _OutboundRetryable) and result.error_class == _RATE_LIMITED_CLASS:
            # comms-3: block here until the host has the pause signal — no
            # further outbound can be dispatched until this await completes.
            await self._emitter.emit_signal(
                retry_after_seconds=result.retry_after_seconds,
                platform_endpoint=_SEND_ENDPOINT,
            )
            return result

        if result.outcome == "delivered":
            # A clean send means the rate-limit window (if any) has cleared;
            # reset debounce so a later genuine 429 is not suppressed.
            self._emitter.clear()
        return result


__all__ = ["OutboundDispatcher"]
