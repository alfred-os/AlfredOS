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
from unittest.mock import Mock

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
    # ``None`` for a never-edited message; the edit timestamp once edited. Mirrors
    # ``discord.Message.edited_at`` so ``normalise`` can stamp ``received_at`` with
    # the edit instant on the edit path (M4).
    edited_at: datetime | None = None
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
class DiscordMockSentMessage:
    """A returned ``discord.Message`` double — only the ``id`` the handler reads."""

    id: int


class DiscordMockSendable:
    """A sendable Discord target double (``discord.User`` / ``TextChannel`` / ``Thread``).

    The outbound handler calls ``await target.send(content)`` and reads
    ``sent.id``. The double records every send and either returns a sent-message
    double or raises a pre-seeded exception, so a test can drive both the
    happy-path and every error mapping (429 / Forbidden / NotFound) without a
    live gateway. It is a plain class (not a ``DiscordMock*`` dataclass) because
    it is STATEFUL — it accumulates a call log — and the AST guard's
    ``DiscordMock*`` factory rule targets the frozen value doubles, not this
    behavioural double; it is still built here, the sole sanctioned mock site.
    """

    def __init__(self, *, sent_id: int = 42, raises: BaseException | None = None) -> None:
        self._sent_id = sent_id
        self._raises = raises
        self.sent: list[str] = []

    async def send(self, content: str) -> DiscordMockSentMessage:
        self.sent.append(content)
        if self._raises is not None:
            raise self._raises
        return DiscordMockSentMessage(id=self._sent_id)


@dataclass(frozen=True, slots=True)
class DiscordMockFactory:
    """Typed constructors for Discord doubles — the sole sanctioned mock site."""

    def sendable(
        self, *, sent_id: int = 42, raises: BaseException | None = None
    ) -> DiscordMockSendable:
        """A send target that returns a message double or raises ``raises``."""
        return DiscordMockSendable(sent_id=sent_id, raises=raises)

    def http_exception(
        self, *, status: int, retry_after: float | None = None
    ) -> discord.HTTPException:
        """A ``discord.HTTPException`` with a synthetic response carrying ``status``.

        ``discord.HTTPException`` reads ``status`` (and ``reason``) off its
        ``response``; ``retry_after`` is not a native attribute (discord.py reads
        it from headers on a 429), so the outbound handler reads it defensively —
        this double attaches it directly to mirror ``discord.RateLimited``\\'s
        ``.retry_after`` surface.
        """
        response = Mock()
        response.status = status
        response.reason = "synthetic"
        response.url = "https://discord.com/api/v10/channels/1/messages"
        exc = discord.HTTPException(response, f"synthetic {status}")
        if retry_after is not None:
            exc.retry_after = retry_after  # type: ignore[attr-defined]
        return exc

    def forbidden(self) -> discord.Forbidden:
        """A ``discord.Forbidden`` (HTTP 403) double."""
        response = Mock()
        response.status = 403
        response.reason = "Forbidden"
        response.url = "https://discord.com/api/v10/channels/1/messages"
        return discord.Forbidden(response, "missing permissions")

    def not_found(self) -> discord.NotFound:
        """A ``discord.NotFound`` (HTTP 404) double — e.g. a deleted channel."""
        response = Mock()
        response.status = 404
        response.reason = "Not Found"
        response.url = "https://discord.com/api/v10/channels/1/messages"
        return discord.NotFound(response, "unknown channel")

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
        edited_at: datetime | None = None,
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
            edited_at=edited_at,
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
    "DiscordMockSendable",
    "DiscordMockSentMessage",
    "DiscordMockUser",
]
