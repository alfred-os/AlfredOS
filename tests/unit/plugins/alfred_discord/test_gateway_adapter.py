"""``DiscordGatewayAdapter`` bridges ``AlfredDiscordBot`` to ``GatewayProtocol`` (#206).

The lifecycle handler drives the gateway through the ``GatewayProtocol`` seam
(``connect(token)`` / ``close()`` / ``queue_depth``). ``AlfredDiscordBot`` exposes
``start(token)`` (which blocks until disconnect) and ``close()``, so the adapter
runs the connect on a background task and returns promptly — ``lifecycle.start``
must not block on a never-returning gateway loop.
"""

from __future__ import annotations

import asyncio

from plugins.alfred_discord.gateway_adapter import DiscordGatewayAdapter


class _FakeBot:
    def __init__(self) -> None:
        self.started_with: str | None = None
        self.closed = False
        self._started = asyncio.Event()

    async def start(self, token: str, *, reconnect: bool = True) -> None:
        self.started_with = token
        self._started.set()
        # Emulate the real bot: block until closed.
        while not self.closed:
            await asyncio.sleep(0.001)

    async def close(self) -> None:
        self.closed = True


async def test_connect_spawns_background_start_and_returns() -> None:
    bot = _FakeBot()
    adapter = DiscordGatewayAdapter(bot=bot)
    await adapter.connect("secret-token")
    # connect returned WITHOUT blocking on the never-ending start() loop.
    await asyncio.sleep(0.01)
    assert bot.started_with == "secret-token"
    flushed = await adapter.close()
    assert bot.closed is True
    assert flushed == 0


async def test_queue_depth_is_zero_before_inbound() -> None:
    bot = _FakeBot()
    adapter = DiscordGatewayAdapter(bot=bot)
    assert adapter.queue_depth == 0
