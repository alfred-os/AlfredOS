"""``infer_addressing_signal`` maps Discord events to the four wire Literals (Task D1).

The four-mode mapping (spec §8.6) with explicit precedence (high to low):

1. ``message.author`` is the bot itself -> ``None`` (no feedback loop).
2. channel is a thread -> ``"thread"`` (overrides DM and channel).
3. channel is a DM -> ``"dm"``.
4. the bot is directly user-mentioned -> ``"mention"`` (overrides channel-allowlist gating).
5. channel id in the listen-set -> ``"channel"``.
6. else -> ``None`` (bot ignores; no notification emitted).

All Discord inputs are built through the shared ``discord_mock_factory`` (closure
test-1) — no ad-hoc ``Mock(spec=discord.Message)``.
"""

from __future__ import annotations

import discord

from plugins.alfred_discord.addressing_inference import infer_addressing_signal
from tests.support.discord_mocks import DiscordMockFactory

_BOT_ID = 9999


def test_dm_channel_infers_dm(discord_mock_factory: DiscordMockFactory) -> None:
    msg = discord_mock_factory.message(channel=discord_mock_factory.dm_channel())
    assert infer_addressing_signal(msg, bot_user_id=_BOT_ID, channel_listen_set=frozenset()) == "dm"


def test_guild_channel_mentioning_bot_infers_mention(
    discord_mock_factory: DiscordMockFactory,
) -> None:
    bot = discord_mock_factory.user(user_id=_BOT_ID, bot=True)
    msg = discord_mock_factory.message(
        channel=discord_mock_factory.channel(channel_id=10),
        mentions=[bot],
    )
    assert (
        infer_addressing_signal(msg, bot_user_id=_BOT_ID, channel_listen_set=frozenset({10}))
        == "mention"
    )


def test_guild_channel_in_listen_set_no_mention_infers_channel(
    discord_mock_factory: DiscordMockFactory,
) -> None:
    msg = discord_mock_factory.message(channel=discord_mock_factory.channel(channel_id=10))
    assert (
        infer_addressing_signal(msg, bot_user_id=_BOT_ID, channel_listen_set=frozenset({10}))
        == "channel"
    )


def test_thread_channel_infers_thread(discord_mock_factory: DiscordMockFactory) -> None:
    msg = discord_mock_factory.message(channel=discord_mock_factory.thread_channel())
    assert (
        infer_addressing_signal(msg, bot_user_id=_BOT_ID, channel_listen_set=frozenset())
        == "thread"
    )


def test_unconfigured_channel_no_mention_returns_none(
    discord_mock_factory: DiscordMockFactory,
) -> None:
    msg = discord_mock_factory.message(channel=discord_mock_factory.channel(channel_id=10))
    assert infer_addressing_signal(msg, bot_user_id=_BOT_ID, channel_listen_set=frozenset()) is None


def test_bots_own_message_returns_none(discord_mock_factory: DiscordMockFactory) -> None:
    # Highest-precedence rung: prevent a feedback loop on the bot's own output.
    bot = discord_mock_factory.user(user_id=_BOT_ID, bot=True)
    msg = discord_mock_factory.message(
        author=bot,
        channel=discord_mock_factory.dm_channel(),
    )
    assert infer_addressing_signal(msg, bot_user_id=_BOT_ID, channel_listen_set=frozenset()) is None


def test_mention_wins_over_channel_allowlist(discord_mock_factory: DiscordMockFactory) -> None:
    # Rung 4 > rung 5: a direct @bot mention in a NON-listen-set channel still
    # infers "mention" (operator may want explicit callouts in unlistened channels).
    bot = discord_mock_factory.user(user_id=_BOT_ID, bot=True)
    msg = discord_mock_factory.message(
        channel=discord_mock_factory.channel(channel_id=10),
        mentions=[bot],
    )
    assert (
        infer_addressing_signal(msg, bot_user_id=_BOT_ID, channel_listen_set=frozenset())
        == "mention"
    )


def test_thread_overrides_channel_mode(discord_mock_factory: DiscordMockFactory) -> None:
    # Rung 2 > rung 5: a thread whose parent is in the listen-set still infers
    # "thread" (reply goes to the thread, not the parent channel).
    msg = discord_mock_factory.message(
        channel=discord_mock_factory.thread_channel(channel_id=10),
    )
    assert (
        infer_addressing_signal(msg, bot_user_id=_BOT_ID, channel_listen_set=frozenset({10}))
        == "thread"
    )


def test_private_thread_infers_thread(discord_mock_factory: DiscordMockFactory) -> None:
    # Rung 2: a private (DM-style) thread overrides DM precedence -> "thread".
    msg = discord_mock_factory.message(
        channel=discord_mock_factory.thread_channel(private=True),
    )
    assert (
        infer_addressing_signal(msg, bot_user_id=_BOT_ID, channel_listen_set=frozenset())
        == "thread"
    )


def test_role_mention_does_not_boost_to_mention(discord_mock_factory: DiscordMockFactory) -> None:
    # Only DIRECT user-mentions count. A role-mention (bot absent from
    # message.mentions) falls through to the underlying channel context. Here the
    # channel is unlistened -> None.
    other = discord_mock_factory.user(user_id=1234)
    msg = discord_mock_factory.message(
        channel=discord_mock_factory.channel(channel_id=10),
        mentions=[other],
    )
    assert infer_addressing_signal(msg, bot_user_id=_BOT_ID, channel_listen_set=frozenset()) is None


def test_returns_literal_in_known_set(discord_mock_factory: DiscordMockFactory) -> None:
    # Structural guard: every non-None result is one of the four wire Literals.
    msg = discord_mock_factory.message(channel=discord_mock_factory.dm_channel())
    result = infer_addressing_signal(msg, bot_user_id=_BOT_ID, channel_listen_set=frozenset())
    assert result in {"dm", "mention", "channel", "thread"}
    # discord import exercised so the module-level ChannelType reference is live.
    assert discord.ChannelType.private is not None
