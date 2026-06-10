"""``discord_gateway`` listeners + reconnect (Task H1, PR-S4-9 #206).

``AlfredDiscordBot`` is a ``commands.Bot`` subclass whose ``on_message`` /
``on_message_edit`` listeners normalise a Discord event onto an
``inbound.message`` notification and enqueue it for stdio emission, and whose
``on_disconnect`` / ``on_ready`` track a reconnect OBSERVABILITY counter (H3:
discord.py owns the reconnect loop + backoff; the bot does not sleep).
``on_error`` forwards an uncaught event-handler exception to the crash emitter.

All Discord inputs come from ``discord_mock_factory`` (closure test-1); the bot's
collaborators (sink, crash forwarder) are injected so the listeners are
exercised without a live gateway.
"""

from __future__ import annotations

from collections.abc import Mapping

from plugins.alfred_discord.discord_gateway import AlfredDiscordBot
from tests.support.discord_mocks import DiscordMockFactory

_ADAPTER = "discord"
_BOT_ID = 9999


class _RecordingSink:
    def __init__(self) -> None:
        self.frames: list[Mapping[str, object]] = []

    async def emit(self, frame: Mapping[str, object]) -> None:
        self.frames.append(frame)


class _CrashSpy:
    def __init__(self) -> None:
        self.handled: list[BaseException] = []

    def handle_crash(self, exc: BaseException) -> None:
        self.handled.append(exc)


def _bot(
    sink: _RecordingSink,
    *,
    crash: _CrashSpy | None = None,
) -> AlfredDiscordBot:
    return AlfredDiscordBot(
        adapter_id=_ADAPTER,
        bot_user_id=_BOT_ID,
        sink=sink,
        crash_emitter=crash or _CrashSpy(),
        channel_listen_set=frozenset({10}),
    )


async def test_on_message_enqueues_normalised_notification(
    discord_mock_factory: DiscordMockFactory,
) -> None:
    sink = _RecordingSink()
    bot = _bot(sink)
    msg = discord_mock_factory.message(
        content="hello",
        channel=discord_mock_factory.dm_channel(),
        author=discord_mock_factory.user(user_id=42),
    )
    await bot.on_message(msg)
    assert len(sink.frames) == 1
    assert sink.frames[0]["method"] == "inbound.message"


async def test_on_message_from_bot_itself_is_ignored(
    discord_mock_factory: DiscordMockFactory,
) -> None:
    sink = _RecordingSink()
    bot = _bot(sink)
    own = discord_mock_factory.message(
        content="echo",
        channel=discord_mock_factory.dm_channel(),
        author=discord_mock_factory.user(user_id=_BOT_ID),
    )
    await bot.on_message(own)
    assert sink.frames == []


async def test_on_message_edit_enqueues_after_content(
    discord_mock_factory: DiscordMockFactory,
) -> None:
    sink = _RecordingSink()
    bot = _bot(sink)
    before = discord_mock_factory.message(
        content="old", channel=discord_mock_factory.channel(channel_id=10)
    )
    after = discord_mock_factory.message(
        content="new", channel=discord_mock_factory.channel(channel_id=10)
    )
    await bot.on_message_edit(before, after)
    assert len(sink.frames) == 1
    params = sink.frames[0]["params"]
    assert isinstance(params, Mapping)
    body = params["body"]
    assert isinstance(body, Mapping)
    assert body["content"] == "new"


async def test_reconnect_counter_resets_after_inbound(
    discord_mock_factory: DiscordMockFactory,
) -> None:
    sink = _RecordingSink()
    bot = _bot(sink)
    await bot.on_disconnect()
    await bot.on_disconnect()
    assert bot.reconnect_attempts == 2
    await bot.on_ready()  # connection re-established
    msg = discord_mock_factory.message(content="back", channel=discord_mock_factory.dm_channel())
    await bot.on_message(msg)
    assert bot.reconnect_attempts == 0


async def test_crash_forwarder_property_exposes_the_injected_emitter() -> None:
    # C1: the gateway adapter reaches the bot's crash emitter via this property to
    # route a detached-task exception through the same crash path on_error uses.
    sink = _RecordingSink()
    crash = _CrashSpy()
    bot = _bot(sink, crash=crash)
    assert bot.crash_forwarder is crash


async def test_on_disconnect_does_not_sleep_or_schedule_retry() -> None:
    # H3: discord.py owns the reconnect loop + backoff; on_disconnect must only
    # bump the observability counter and return promptly — no sleep, no retry
    # scheduling. The bot no longer accepts a sleeper, so a dead custom backoff
    # cannot regress in.
    sink = _RecordingSink()
    bot = _bot(sink)
    assert not hasattr(bot, "backoff_seconds")
    await bot.on_disconnect()
    assert bot.reconnect_attempts == 1


async def test_on_error_forwards_to_crash_emitter() -> None:
    sink = _RecordingSink()
    crash = _CrashSpy()
    bot = _bot(sink, crash=crash)
    boom = RuntimeError("handler exploded")
    # discord.py calls on_error from inside an except block, so the live
    # exception is reachable via sys.exc_info(); simulate that.
    try:
        raise boom
    except RuntimeError:
        await bot.on_error("on_message")
    assert crash.handled == [boom]
