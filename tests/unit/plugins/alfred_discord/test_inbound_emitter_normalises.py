"""``inbound_emitter.normalise`` builds an ``InboundMessageNotification`` (Task E1).

The adapter ships the nine Discord sub-payloads INLINE in the wire ``body``; the
host-side ``DiscordSubPayloadClassifier`` (not the adapter) promotes each to a
``ContentHandle``. So ``normalise`` only marshals the Discord event into the
ADR-0024 ``InboundMessageNotification`` shape and tags the BCP-47 ``language``
(closure i18n-1) + boolean ``forwarded`` / ``pinned`` disambiguation flags
(Wave-1 finding) onto the body.

All Discord inputs come from the shared ``discord_mock_factory`` (closure test-1).
"""

from __future__ import annotations

import discord

from alfred.comms_mcp.protocol import InboundMessageNotification
from plugins.alfred_discord.inbound_emitter import normalise
from tests.support.discord_mocks import DiscordMockFactory

_BOT_ID = 9999
_ADAPTER = "discord"


def _kwargs() -> dict[str, object]:
    return {"adapter_id": _ADAPTER, "bot_user_id": _BOT_ID, "channel_listen_set": frozenset()}


def test_plain_dm_text_body(discord_mock_factory: DiscordMockFactory) -> None:
    msg = discord_mock_factory.message(
        content="hello alfred",
        channel=discord_mock_factory.dm_channel(),
        author=discord_mock_factory.user(user_id=42),
    )
    note = normalise(msg, **_kwargs())
    assert isinstance(note, InboundMessageNotification)
    assert note.adapter_id == "discord"
    assert note.addressing_signal == "dm"
    assert note.platform_user_id == "42"
    assert note.body["content"] == "hello alfred"
    assert note.sub_payload_refs == ()


def test_channel_message_with_embed_inline(discord_mock_factory: DiscordMockFactory) -> None:
    embed = {"title": "t", "description": "d"}
    msg = discord_mock_factory.message(
        content="see embed",
        channel=discord_mock_factory.channel(channel_id=10),
        embeds=[embed],
    )
    note = normalise(
        msg, adapter_id=_ADAPTER, bot_user_id=_BOT_ID, channel_listen_set=frozenset({10})
    )
    assert note is not None
    # Embed ships verbatim inline; promotion is host-side.
    assert note.body["embeds"] == [embed]


def test_message_with_attachment_url_not_downloaded(
    discord_mock_factory: DiscordMockFactory,
) -> None:
    attachment = {"url": "https://cdn.discordapp.com/x.png", "content_type": "image/png"}
    msg = discord_mock_factory.message(
        channel=discord_mock_factory.dm_channel(),
        attachments=[attachment],
    )
    note = normalise(msg, **_kwargs())
    assert note is not None
    assert note.body["attachments"] == [attachment]


def test_message_with_poll(discord_mock_factory: DiscordMockFactory) -> None:
    poll = {"question": {"text": "?"}}
    msg = discord_mock_factory.message(channel=discord_mock_factory.dm_channel(), poll=poll)
    note = normalise(msg, **_kwargs())
    assert note is not None
    assert note.body["poll"] == poll


def test_message_with_sticker(discord_mock_factory: DiscordMockFactory) -> None:
    sticker = {"id": "1", "name": "wave"}
    msg = discord_mock_factory.message(
        channel=discord_mock_factory.dm_channel(), stickers=[sticker]
    )
    note = normalise(msg, **_kwargs())
    assert note is not None
    assert note.body["stickers"] == [sticker]


def test_voice_message_content_type_preserved(discord_mock_factory: DiscordMockFactory) -> None:
    voice = {"url": "https://cdn/v.ogg", "content_type": "audio/ogg"}
    msg = discord_mock_factory.message(
        channel=discord_mock_factory.dm_channel(), attachments=[voice]
    )
    note = normalise(msg, **_kwargs())
    assert note is not None
    # The content_type prefix is what the host classifier uses to pick voice_message.
    assert note.body["attachments"][0]["content_type"] == "audio/ogg"


def test_forwarded_reference_sets_forwarded_flag(discord_mock_factory: DiscordMockFactory) -> None:
    ref = discord_mock_factory.reference(message_id=7001, channel_id=10)
    msg = discord_mock_factory.message(channel=discord_mock_factory.dm_channel(), reference=ref)
    note = normalise(msg, **_kwargs())
    assert note is not None
    assert note.body["message_reference"]["message_id"] == 7001
    # Wave-1 finding: forwarded vs pinned disambiguation flags.
    assert note.body["forwarded"] is True
    assert note.body["pinned"] is False


def test_pinned_reference_sets_pinned_flag(discord_mock_factory: DiscordMockFactory) -> None:
    ref = discord_mock_factory.reference(message_id=7001)
    msg = discord_mock_factory.message(
        channel=discord_mock_factory.dm_channel(), reference=ref, pinned=True
    )
    note = normalise(msg, **_kwargs())
    assert note is not None
    assert note.body["pinned"] is True
    assert note.body["forwarded"] is False


def test_unconfigured_channel_returns_none(discord_mock_factory: DiscordMockFactory) -> None:
    msg = discord_mock_factory.message(channel=discord_mock_factory.channel(channel_id=10))
    note = normalise(msg, **_kwargs())
    assert note is None


def test_received_at_is_message_created_at(discord_mock_factory: DiscordMockFactory) -> None:
    from datetime import UTC, datetime

    created = datetime(2026, 6, 10, 12, 0, 0, tzinfo=UTC)
    msg = discord_mock_factory.message(
        channel=discord_mock_factory.dm_channel(), created_at=created
    )
    note = normalise(msg, **_kwargs())
    assert note is not None
    assert note.received_at == created


def test_language_from_guild_preferred_locale(discord_mock_factory: DiscordMockFactory) -> None:
    guild = discord_mock_factory.guild(preferred_locale="fr")
    msg = discord_mock_factory.message(
        channel=discord_mock_factory.channel(channel_id=10), guild=guild
    )
    note = normalise(
        msg, adapter_id=_ADAPTER, bot_user_id=_BOT_ID, channel_listen_set=frozenset({10})
    )
    assert note is not None
    assert note.body["language"] == "fr"


def test_language_falls_back_to_author_locale_for_dm(
    discord_mock_factory: DiscordMockFactory,
) -> None:
    author = discord_mock_factory.user(user_id=42, locale="ja")
    msg = discord_mock_factory.message(channel=discord_mock_factory.dm_channel(), author=author)
    note = normalise(msg, **_kwargs())
    assert note is not None
    assert note.body["language"] == "ja"


def test_language_fallback_en(discord_mock_factory: DiscordMockFactory) -> None:
    # No guild locale, DM author with no locale -> "en".
    msg = discord_mock_factory.message(
        channel=discord_mock_factory.dm_channel(),
        author=discord_mock_factory.user(user_id=42, locale=None),
    )
    note = normalise(msg, **_kwargs())
    assert note is not None
    assert note.body["language"] == "en"
    # discord import exercised.
    assert discord.ChannelType.private is not None
