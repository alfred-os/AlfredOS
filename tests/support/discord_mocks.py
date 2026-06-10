"""Typed Discord test doubles + the shared ``discord_mock_factory`` (closure test-1).

PR-S4-9 (#206) Wave 2 ships the host/plugin-side scaffolding for the Discord
comms-MCP adapter. The adapter normalises ``discord.Message`` events onto the
ADR-0024 wire schemas; its unit tests must construct Discord-shaped inputs
*without* a live gateway connection.

Rather than scatter ad-hoc ``Mock(spec=discord.Message)`` constructions across
the suite (each one re-deciding which attributes matter, drifting over time),
every Discord-shaped input is built through one typed factory. The factory
returns frozen dataclasses whose attribute names mirror the real ``discord.py``
2.x surface the adapter reads:

* ``DiscordMockUser.id`` / ``.bot`` / ``.locale`` (``locale`` is optional — only
  interaction payloads carry it on the real surface; ``None`` otherwise);
* ``DiscordMockGuild.preferred_locale`` (BCP-47 guild locale, i18n-1 precedence);
* ``DiscordMockChannel.id`` / ``.type`` (a real ``discord.ChannelType`` enum
  member — the idiomatic, ``isinstance``-free channel discriminator the adapter
  uses so the same code path serves real channels and these doubles);
* ``DiscordMockMessage.author`` / ``.mentions`` / ``.channel`` / ``.guild`` /
  ``.content`` / ``.created_at`` / ``.embeds`` / ``.attachments`` / ``.poll`` /
  ``.stickers`` / ``.components`` / ``.reference``.

An AST guard (``tests/unit/discord/test_no_ad_hoc_mocks.py``) forbids ad-hoc
Discord mocks elsewhere; this module is the single sanctioned construction site.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime

import discord


@dataclass(frozen=True, slots=True)
class DiscordMockUser:
    """A Discord user/member double (subset of ``discord.User`` / ``discord.Member``)."""

    id: int
    bot: bool = False
    # Optional BCP-47 locale; only interaction payloads carry it on the real
    # surface, so ``None`` is the common case (i18n-1 precedence rung b).
    locale: str | None = None


@dataclass(frozen=True, slots=True)
class DiscordMockGuild:
    """A Discord guild double (subset of ``discord.Guild``)."""

    id: int
    # BCP-47 guild locale; i18n-1 precedence rung a (highest).
    preferred_locale: str = "en-US"


@dataclass(frozen=True, slots=True)
class DiscordMockChannel:
    """A Discord channel double; ``type`` is a real ``discord.ChannelType`` member.

    The adapter discriminates DM / thread / guild-text by ``channel.type`` (the
    idiomatic ``isinstance``-free path), so a double need only carry a faithful
    ``ChannelType`` to exercise the real inference code.
    """

    id: int
    type: discord.ChannelType


@dataclass(frozen=True, slots=True)
class DiscordMockMessageReference:
    """A Discord message-reference double (subset of ``discord.MessageReference``)."""

    message_id: int | None = None
    channel_id: int | None = None
    guild_id: int | None = None


@dataclass(frozen=True, slots=True)
class DiscordMockMessage:
    """A Discord message double mirroring the ``discord.Message`` attributes read."""

    id: int
    author: DiscordMockUser
    channel: DiscordMockChannel
    content: str = ""
    guild: DiscordMockGuild | None = None
    mentions: Sequence[DiscordMockUser] = field(default_factory=tuple)
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    embeds: Sequence[object] = field(default_factory=tuple)
    attachments: Sequence[object] = field(default_factory=tuple)
    poll: object | None = None
    stickers: Sequence[object] = field(default_factory=tuple)
    components: Sequence[object] = field(default_factory=tuple)
    reference: DiscordMockMessageReference | None = None
    # Adapter-side hint: is this message in the channel's pinned set? discord.py
    # does not expose a per-message ``pinned`` boolean for arbitrary messages,
    # so the gateway layer computes it; the double carries it directly.
    pinned: bool = False


@dataclass(frozen=True, slots=True)
class DiscordMockFactory:
    """Typed constructors for Discord doubles — the sole sanctioned mock site."""

    def user(
        self, *, user_id: int = 1001, bot: bool = False, locale: str | None = None
    ) -> DiscordMockUser:
        return DiscordMockUser(id=user_id, bot=bot, locale=locale)

    def guild(self, *, guild_id: int = 5001, preferred_locale: str = "en-US") -> DiscordMockGuild:
        return DiscordMockGuild(id=guild_id, preferred_locale=preferred_locale)

    def channel(
        self,
        *,
        channel_id: int = 9001,
        channel_type: discord.ChannelType = discord.ChannelType.text,
    ) -> DiscordMockChannel:
        return DiscordMockChannel(id=channel_id, type=channel_type)

    def dm_channel(self, *, channel_id: int = 9001) -> DiscordMockChannel:
        return DiscordMockChannel(id=channel_id, type=discord.ChannelType.private)

    def thread_channel(
        self, *, channel_id: int = 9002, private: bool = False
    ) -> DiscordMockChannel:
        kind = discord.ChannelType.private_thread if private else discord.ChannelType.public_thread
        return DiscordMockChannel(id=channel_id, type=kind)

    def reference(
        self,
        *,
        message_id: int | None = 7001,
        channel_id: int | None = None,
        guild_id: int | None = None,
    ) -> DiscordMockMessageReference:
        return DiscordMockMessageReference(
            message_id=message_id, channel_id=channel_id, guild_id=guild_id
        )

    def message(
        self,
        *,
        message_id: int = 3001,
        author: DiscordMockUser | None = None,
        channel: DiscordMockChannel | None = None,
        content: str = "",
        guild: DiscordMockGuild | None = None,
        mentions: Sequence[DiscordMockUser] = (),
        created_at: datetime | None = None,
        embeds: Sequence[object] = (),
        attachments: Sequence[object] = (),
        poll: object | None = None,
        stickers: Sequence[object] = (),
        components: Sequence[object] = (),
        reference: DiscordMockMessageReference | None = None,
        pinned: bool = False,
    ) -> DiscordMockMessage:
        return DiscordMockMessage(
            id=message_id,
            author=author if author is not None else self.user(),
            channel=channel if channel is not None else self.channel(),
            content=content,
            guild=guild,
            mentions=tuple(mentions),
            created_at=created_at if created_at is not None else datetime.now(UTC),
            embeds=tuple(embeds),
            attachments=tuple(attachments),
            poll=poll,
            stickers=tuple(stickers),
            components=tuple(components),
            reference=reference,
            pinned=pinned,
        )


__all__ = [
    "DiscordMockChannel",
    "DiscordMockFactory",
    "DiscordMockGuild",
    "DiscordMockMessage",
    "DiscordMockMessageReference",
    "DiscordMockUser",
]
