"""Discord gateway: ``commands.Bot`` subclass with reconnect (Task H1, #206).

:class:`AlfredDiscordBot` is the discord.py wrapper that turns live Discord
gateway events into ``inbound.message`` notifications and tracks an
exponential-backoff reconnect schedule. It declares a least-privilege intent set
(messages + content + DMs + guilds; presence/voice/integration intents OFF), and
forwards any uncaught event-handler exception to the crash emitter.

Trust boundary: an inbound Discord message is adversary-authorable platform
content. The bot does NOT promote it — :func:`inbound_emitter.normalise` marshals
it into the wire ``body`` and the HOST tags it T3 at ``process_inbound_message``.
The bot's listeners are thin: normalise → enqueue → done.

Collaborators (sink, crash emitter, sleeper) are injected so the listeners are
unit-testable without a live gateway connection.
"""

from __future__ import annotations

import random
import sys
from collections.abc import Awaitable, Callable, Set
from typing import Final, Protocol, cast

import discord
import structlog
from discord.ext import commands

from plugins.alfred_discord.inbound_emitter import _MessageLike, normalise
from plugins.alfred_discord.notifications import (
    NOTIFY_INBOUND,
    NotificationSink,
    notification_frame,
)

_log = structlog.get_logger(__name__)

# Exponential-backoff reconnect ceiling (seconds) and jitter fraction. The cap
# bounds the worst-case retry interval; the jitter avoids a thundering-herd of
# adapters reconnecting in lockstep after a shared Discord outage.
_BACKOFF_CAP_SECONDS: Final[float] = 60.0
_JITTER_FRACTION: Final[float] = 0.2

_Sleeper = Callable[[float], Awaitable[None]]


class _CrashForwarder(Protocol):
    """Structural view of the crash emitter the gateway forwards uncaught errors to."""

    def handle_crash(self, exc: BaseException) -> None: ...


def _least_privilege_intents() -> discord.Intents:
    """Build the minimal intent set the adapter needs (spec §8.6 / H1).

    messages + message_content (for ``on_message``), DMs, and guild messages +
    guild metadata (mention / channel / thread modes). Every other intent —
    presence, voice, integrations, typing — stays OFF (least privilege).
    """
    intents = discord.Intents.none()
    intents.guilds = True
    intents.messages = True
    intents.message_content = True
    intents.dm_messages = True
    intents.guild_messages = True
    return intents


class AlfredDiscordBot(commands.Bot):
    """discord.py ``commands.Bot`` that emits ``inbound.message`` + tracks reconnects."""

    def __init__(
        self,
        *,
        adapter_id: str,
        bot_user_id: int,
        sink: NotificationSink,
        crash_emitter: _CrashForwarder,
        channel_listen_set: Set[int],
        sleeper: _Sleeper,
    ) -> None:
        super().__init__(command_prefix="!", intents=_least_privilege_intents())
        self._adapter_id = adapter_id
        self._bot_user_id = bot_user_id
        self._sink = sink
        self._crash_emitter = crash_emitter
        self._channel_listen_set = channel_listen_set
        self._sleeper = sleeper
        self.reconnect_attempts = 0

    async def on_message(self, message: discord.Message) -> None:
        """Normalise + enqueue an inbound message; reset the reconnect counter."""
        self.reconnect_attempts = 0
        await self._emit_inbound(message)

    async def on_message_edit(self, _before: discord.Message, after: discord.Message) -> None:
        """A Discord edit becomes a fresh inbound notification (spec §8.6)."""
        await self._emit_inbound(after)

    async def on_disconnect(self) -> None:
        """Count a gateway disconnect; back off before discord.py reconnects."""
        self.reconnect_attempts += 1
        delay = self.backoff_seconds(self.reconnect_attempts)
        _log.warning(
            "comms.gateway.disconnected",
            adapter=self._adapter_id,
            attempt=self.reconnect_attempts,
            backoff_seconds=delay,
        )
        await self._sleeper(delay)

    async def on_ready(self) -> None:
        """Connection re-established — log; the counter zeroes on the next inbound."""
        _log.info("comms.gateway.ready", adapter=self._adapter_id)

    async def on_error(self, event_method: str, /, *_args: object, **_kwargs: object) -> None:
        """Forward an uncaught event-handler exception to the crash emitter.

        discord.py invokes this from inside an ``except`` block, so the live
        exception is reachable via ``sys.exc_info()``. A crash here is terminal:
        the forwarder emits ``adapter.crashed`` and exits so the supervisor trips.
        """
        exc = sys.exc_info()[1]
        if exc is not None:
            _log.error(
                "comms.gateway.event_error",
                adapter=self._adapter_id,
                event_method=event_method,
            )
            self._crash_emitter.handle_crash(exc)

    def backoff_seconds(self, attempt: int) -> float:
        """Return ``min(2 ** attempt, cap)`` with ±20% jitter (thundering-herd guard)."""
        base = min(2.0**attempt, _BACKOFF_CAP_SECONDS)
        jitter = base * _JITTER_FRACTION
        return base + random.uniform(-jitter, jitter)  # noqa: S311 - jitter, not crypto

    async def _emit_inbound(self, message: discord.Message) -> None:
        """Normalise ``message`` and enqueue the notification if not ignored.

        ``normalise`` consumes the structural ``_MessageLike`` view its tests pin;
        a live ``discord.Message`` satisfies it at runtime, but mypy treats the
        read-only properties (``created_at`` etc.) as incompatible with the
        protocol's plain-attribute declarations — a known property-vs-attribute
        strictness artifact. The ``cast`` asserts the runtime-true shape.
        """
        notification = normalise(
            cast(_MessageLike, message),
            adapter_id=self._adapter_id,
            bot_user_id=self._bot_user_id,
            channel_listen_set=self._channel_listen_set,
        )
        if notification is None:
            return  # bot's own message, or unaddressed in an unlistened channel
        frame = notification_frame(NOTIFY_INBOUND, notification.model_dump(mode="json"))
        await self._sink.emit(frame)


__all__ = ["AlfredDiscordBot"]
