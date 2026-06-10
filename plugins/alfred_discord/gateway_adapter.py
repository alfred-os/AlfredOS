"""Bridge ``AlfredDiscordBot`` to the lifecycle's ``GatewayProtocol`` seam (#206).

``DiscordLifecycle`` drives the Discord connection through the ``GatewayProtocol``
contract (``connect(token)`` / ``close()`` / ``queue_depth``).
:class:`AlfredDiscordBot` exposes discord.py's ``start(token)`` — which BLOCKS
until the gateway disconnects — and ``close()``. This adapter runs ``start`` on a
background task so :meth:`connect` returns promptly: ``lifecycle.start`` must not
block on a never-returning gateway loop.

The adapter holds no global state; it owns the one background task for its bot's
lifetime and cancels nothing the bot does not already own.
"""

from __future__ import annotations

import asyncio
import contextlib
from typing import Protocol

import structlog

_log = structlog.get_logger(__name__)


class _BotLike(Protocol):
    """The subset of ``AlfredDiscordBot`` the adapter drives."""

    async def start(self, token: str, *, reconnect: bool = True) -> None: ...

    async def close(self) -> None: ...


class DiscordGatewayAdapter:
    """Adapts a discord.py bot's ``start``/``close`` to the ``GatewayProtocol``."""

    def __init__(self, *, bot: _BotLike) -> None:
        self._bot = bot
        self._task: asyncio.Task[None] | None = None

    async def connect(self, token: str) -> None:
        """Spawn the gateway loop on a background task and return promptly.

        ``bot.start(token)`` blocks until disconnect, so it runs detached; the
        lifecycle handler's ``start`` returns as soon as the task is scheduled.
        """
        self._task = asyncio.create_task(self._bot.start(token))
        # Yield once so the task begins logging in before ``start`` returns.
        await asyncio.sleep(0)
        _log.info("comms.gateway.connecting", adapter="discord")

    async def close(self) -> int:
        """Close the bot + await the background task; return the flushed count."""
        await self._bot.close()
        if self._task is not None:
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None
        return 0

    @property
    def queue_depth(self) -> int:
        """In-flight outbound depth — zero until a real outbound buffer is wired."""
        return 0


__all__ = ["DiscordGatewayAdapter"]
