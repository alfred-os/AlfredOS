"""Infer the inbound ``addressing_signal`` from a Discord message (spec §8.6).

Maps a platform event onto one of the four ADR-0024 wire ``Literal`` values
(``dm`` / ``mention`` / ``channel`` / ``thread``) or ``None`` when the bot must
ignore the message (its own output, or an unaddressed message in a channel it
does not listen to).

Channel discrimination uses ``message.channel.type`` (a ``discord.ChannelType``
enum member) rather than ``isinstance(channel, discord.DMChannel)``: the enum
path is structural, so the same inference code serves a live ``discord.Message``
*and* the typed test doubles in ``tests/support/discord_mocks.py`` — no parallel
double-only branch that could drift from production behaviour.

The precedence list (high to low) is the load-bearing contract:

1. ``message.author.id == bot_user_id``      -> ``None``  (no feedback loop)
2. channel is a thread                       -> ``"thread"`` (overrides DM/channel)
3. channel is a DM                           -> ``"dm"``
4. the bot is directly user-mentioned        -> ``"mention"`` (overrides allowlist)
5. ``channel.id in channel_listen_set``      -> ``"channel"``
6. else                                       -> ``None``  (bot ignores)
"""

from __future__ import annotations

from collections.abc import Iterable, Set
from typing import Literal, Protocol, runtime_checkable

import discord

AddressingSignal = Literal["dm", "mention", "channel", "thread"]

# ``discord.ChannelType`` members that denote a thread (public or private,
# guild- or DM-parented). A thread always overrides DM/channel inference.
_THREAD_TYPES: frozenset[discord.ChannelType] = frozenset(
    {
        discord.ChannelType.public_thread,
        discord.ChannelType.private_thread,
        discord.ChannelType.news_thread,
    }
)


@runtime_checkable
class _HasId(Protocol):
    id: int


@runtime_checkable
class _ChannelLike(Protocol):
    id: int
    type: discord.ChannelType


@runtime_checkable
class _MessageLike(Protocol):
    """Structural view of the ``discord.Message`` attributes inference reads."""

    @property
    def author(self) -> _HasId: ...

    @property
    def channel(self) -> _ChannelLike: ...

    @property
    def mentions(self) -> Iterable[_HasId]: ...


def infer_addressing_signal(
    message: _MessageLike,
    *,
    bot_user_id: int,
    channel_listen_set: Set[int],
) -> AddressingSignal | None:
    """Return the inferred addressing signal, or ``None`` when the bot must ignore.

    See the module docstring for the load-bearing precedence contract.
    """
    # Rung 1: the bot's own message -> never re-ingest (feedback-loop guard).
    if message.author.id == bot_user_id:
        return None

    channel = message.channel

    # Rung 2: a thread overrides DM and channel inference.
    if channel.type in _THREAD_TYPES:
        return "thread"

    # Rung 3: a 1:1 DM.
    if channel.type is discord.ChannelType.private:
        return "dm"

    # Rung 4: a direct @bot user-mention wins over channel-allowlist gating.
    # Only DIRECT user-mentions count; role-mentions leave the bot absent from
    # ``message.mentions`` and fall through to channel context.
    if any(user.id == bot_user_id for user in message.mentions):
        return "mention"

    # Rung 5: a channel the adapter is configured to listen to.
    if channel.id in channel_listen_set:
        return "channel"

    # Rung 6: unaddressed message in an unlistened channel -> ignore.
    return None


__all__ = ["AddressingSignal", "infer_addressing_signal"]
