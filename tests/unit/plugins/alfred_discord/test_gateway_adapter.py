"""``DiscordGatewayAdapter`` bridges ``AlfredDiscordBot`` to ``GatewayProtocol`` (#206).

The lifecycle handler drives the gateway through the ``GatewayProtocol`` seam
(``connect(token)`` / ``close()`` / ``queue_depth``). ``AlfredDiscordBot`` exposes
``login(token)`` (raises early on bad credentials), ``connect(reconnect=...)``
(blocks until disconnect) and ``close()``.

C1: the adapter logs in SYNCHRONOUSLY so an early login failure surfaces to
``lifecycle.start`` (which returns ``ok=False``) instead of being swallowed in a
detached task; and it attaches a done-callback to the detached ``connect`` task
so a runtime gateway crash routes through the crash emitter (emitting
``adapter.crashed`` so the supervisor breaker can trip) rather than being
silently discarded.
"""

from __future__ import annotations

import asyncio

import discord
import pytest

from plugins.alfred_discord.gateway_adapter import DiscordGatewayAdapter
from plugins.alfred_discord.lifecycle import GatewayError


class _CrashSpy:
    def __init__(self) -> None:
        self.handled: list[BaseException] = []

    def handle_crash(self, exc: BaseException) -> None:
        self.handled.append(exc)


class _FakeBot:
    """A bot double exposing login/connect/close + the crash forwarder seam."""

    def __init__(
        self,
        *,
        login_error: Exception | None = None,
        connect_error: Exception | None = None,
    ) -> None:
        self.logged_in_with: str | None = None
        self.connected = False
        self.closed = False
        self._login_error = login_error
        self._connect_error = connect_error
        self.crash_forwarder = _CrashSpy()

    async def login(self, token: str) -> None:
        if self._login_error is not None:
            raise self._login_error
        self.logged_in_with = token

    async def connect(self, *, reconnect: bool = True) -> None:
        self.connected = True
        if self._connect_error is not None:
            raise self._connect_error
        # Emulate the real bot: block until closed.
        while not self.closed:
            await asyncio.sleep(0.001)

    async def close(self) -> None:
        self.closed = True


async def test_connect_logs_in_then_spawns_background_connect() -> None:
    bot = _FakeBot()
    adapter = DiscordGatewayAdapter(bot=bot)
    await adapter.connect("secret-token")
    await asyncio.sleep(0.01)
    assert bot.logged_in_with == "secret-token"
    assert bot.connected is True
    flushed = await adapter.close()
    assert bot.closed is True
    assert flushed == 0
    # A clean start emits NO crash.
    assert bot.crash_forwarder.handled == []


async def test_login_failure_raises_gateway_error() -> None:
    # C1: a LoginFailure must surface to the lifecycle as GatewayError (so
    # lifecycle.start returns ok=False) rather than dying in an orphan task.
    bot = _FakeBot(login_error=discord.LoginFailure("bad token"))
    adapter = DiscordGatewayAdapter(bot=bot)
    with pytest.raises(GatewayError):
        await adapter.connect("bad-token")
    assert bot.connected is False


async def test_runtime_connect_crash_routes_through_crash_emitter() -> None:
    # C1: a crash inside the detached connect task (post-login, e.g. a
    # ConnectionClosed/PrivilegedIntentsRequired) must reach the crash emitter
    # via the done-callback, not be silently discarded.
    boom = RuntimeError("gateway exploded mid-run")
    bot = _FakeBot(connect_error=boom)
    adapter = DiscordGatewayAdapter(bot=bot)
    await adapter.connect("secret-token")
    # Let the detached task run to completion + the done-callback fire.
    await asyncio.sleep(0.02)
    assert bot.crash_forwarder.handled == [boom]


async def test_cancelled_connect_task_is_not_a_crash() -> None:
    # A normal close cancels/awaits the connect task; a CancelledError on
    # teardown is NOT a crash and must not reach the emitter.
    bot = _FakeBot()
    adapter = DiscordGatewayAdapter(bot=bot)
    await adapter.connect("secret-token")
    await asyncio.sleep(0.01)
    await adapter.close()
    await asyncio.sleep(0.01)
    assert bot.crash_forwarder.handled == []


async def test_cancelled_connect_task_done_callback_is_not_a_crash() -> None:
    # C1: a directly-cancelled connect task (the ``task.cancelled()`` branch of
    # the done-callback) is normal teardown, not a crash — the emitter is untouched.
    bot = _FakeBot()
    adapter = DiscordGatewayAdapter(bot=bot)
    await adapter.connect("secret-token")
    assert adapter._task is not None
    adapter._task.cancel()
    await asyncio.sleep(0.01)
    assert bot.crash_forwarder.handled == []


async def test_close_without_an_open_task_is_a_noop() -> None:
    # The ``_task is None`` branch of close (close before connect / double close).
    bot = _FakeBot()
    adapter = DiscordGatewayAdapter(bot=bot)
    flushed = await adapter.close()
    assert flushed == 0
    assert bot.closed is True


async def test_queue_depth_is_zero_before_inbound() -> None:
    bot = _FakeBot()
    adapter = DiscordGatewayAdapter(bot=bot)
    assert adapter.queue_depth == 0
