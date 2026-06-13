"""Normalise a Discord message event onto an ``InboundMessageNotification``.

The adapter is a thin marshaller: it ships the user's typed text plus the nine
Discord sub-payload kinds INLINE in the wire ``body``. The host-side
``DiscordSubPayloadClassifier`` (NOT the adapter) promotes each sub-payload to a
``ContentHandle`` at the transport boundary — so the adapter never downloads
attachment bytes, never dereferences embeds, never sees a ``ContentHandle``.

Trust-boundary note: the marshalled ``body`` is adversary-authorable platform
content. It is tagged T3 host-side the instant it crosses
``process_inbound_message``; this adapter does no T3 promotion in-process. The
body therefore carries only raw, structurally-shaped data — no extraction.

Two adapter-side annotations the host classifier depends on:

* ``body["language"]`` — a BCP-47 tag (closure i18n-1) resolved by the
  precedence: guild ``preferred_locale`` -> DM ``author.locale`` -> ``"en"``.
  Stored on the host's inbound audit row at ingest time.
* ``body["forwarded"]`` / ``body["pinned"]`` — boolean disambiguation flags
  (Wave-1 finding). Both a forwarded message and a pinned message carry a
  ``message_reference``; only these flags let the host classifier choose
  ``forwarded_ref`` vs ``pinned_ref`` without guessing.
"""

from __future__ import annotations

from collections.abc import Iterable, Set
from typing import Any, Protocol, runtime_checkable

import discord

from alfred.comms_mcp.protocol import InboundMessageNotification
from plugins.alfred_discord.addressing_inference import infer_addressing_signal

_DEFAULT_LANGUAGE = "en"


@runtime_checkable
class _GuildLike(Protocol):
    preferred_locale: object


@runtime_checkable
class _HasId(Protocol):
    id: int


@runtime_checkable
class _AuthorLike(Protocol):
    id: int
    locale: str | None


@runtime_checkable
class _ReferenceLike(Protocol):
    message_id: int | None
    channel_id: int | None
    guild_id: int | None


@runtime_checkable
class _ChannelLike(Protocol):
    id: int
    type: discord.ChannelType


@runtime_checkable
class _MessageLike(Protocol):
    """Structural view of the ``discord.Message`` attributes the emitter reads."""

    id: int
    content: str
    created_at: Any
    # ``None`` for a never-edited message; the edit timestamp once edited (M4).
    edited_at: Any
    embeds: Iterable[object]
    attachments: Iterable[object]
    poll: object | None
    stickers: Iterable[object]
    components: Iterable[object]
    pinned: bool

    @property
    def author(self) -> _AuthorLike: ...

    @property
    def channel(self) -> _ChannelLike: ...

    @property
    def guild(self) -> _GuildLike | None: ...

    @property
    def mentions(self) -> Iterable[_HasId]: ...

    @property
    def reference(self) -> _ReferenceLike | None: ...


def _as_payload(value: object) -> object:
    """Coerce a sub-payload to a JSON-able structure.

    Real ``discord.py`` objects (``Embed``, ``Attachment``, ``Poll``, ...)
    expose ``.to_dict()``; plain dicts (the test-double shape and the wire
    shape) pass through untouched. No bytes are fetched — only the structural
    metadata Discord already delivered on the gateway event is marshalled.
    """
    to_dict = getattr(value, "to_dict", None)
    if callable(to_dict):
        result: object = to_dict()
        return result
    return value


def _serialise_each(values: Iterable[object]) -> list[object]:
    return [_as_payload(v) for v in values]


def _reference_payload(reference: _ReferenceLike) -> dict[str, object]:
    return {
        "message_id": reference.message_id,
        "channel_id": reference.channel_id,
        "guild_id": reference.guild_id,
    }


def _resolve_language(message: _MessageLike) -> str:
    """Resolve the BCP-47 language tag per closure i18n-1 precedence.

    (a) guild ``preferred_locale`` for guild messages; (b) ``author.locale`` for
    DMs (if available); (c) fallback ``"en"``. The host resolver's canonical
    ``User.language`` (precedence rung c in the closure) is applied host-side —
    the adapter cannot see the resolved identity, so it stops at rungs a/b/d.
    """
    guild = message.guild
    if guild is not None:
        locale = guild.preferred_locale
        if locale:
            return str(locale)
    author_locale = message.author.locale
    if author_locale:
        return author_locale
    return _DEFAULT_LANGUAGE


def normalise(
    message: _MessageLike,
    *,
    adapter_id: str,
    bot_user_id: int,
    channel_listen_set: Set[int],
) -> InboundMessageNotification | None:
    """Build an ``InboundMessageNotification``, or ``None`` if the bot must ignore.

    Returns ``None`` when ``infer_addressing_signal`` returns ``None`` (the bot's
    own message, or an unaddressed message in an unlistened channel) so the caller
    skips emission.
    """
    signal = infer_addressing_signal(
        message, bot_user_id=bot_user_id, channel_listen_set=channel_listen_set
    )
    if signal is None:
        return None

    reference = message.reference
    has_reference = reference is not None
    reference_payload = _reference_payload(reference) if reference is not None else None
    body: dict[str, object] = {
        # BODY_FIELD_BY_KIND["discord"] == "content": the host scanner reads the
        # user's typed text from here.
        "content": message.content,
        "embeds": _serialise_each(message.embeds),
        "attachments": _serialise_each(message.attachments),
        "poll": _as_payload(message.poll) if message.poll is not None else None,
        "stickers": _serialise_each(message.stickers),
        "components": _serialise_each(message.components),
        "message_reference": reference_payload,
        # Wave-1 finding: forwarded vs pinned disambiguation. A pinned reference
        # is flagged ``pinned``; any other reference is treated as a forward.
        "pinned": bool(message.pinned),
        "forwarded": has_reference and not bool(message.pinned),
        # closure i18n-1: BCP-47 language tag for the host inbound audit row.
        "language": _resolve_language(message),
    }

    return InboundMessageNotification(
        adapter_id=adapter_id,
        # Spec A decision 4 (G0): a STABLE per-frame dedup id. A Discord gateway
        # event can be redelivered (reconnect / resume), so the id is derived from
        # the platform ``message.id`` (a stable snowflake) rather than a fresh
        # uuid4 per emit — a redelivered event reproduces the SAME inbound_id, so
        # the host's accept-once commit dedups the replay. (M4: an edit is a new
        # event but keeps the same message id; the host commit-once treats the
        # edit as a duplicate of the original — acceptable for G0, since the body
        # extraction already happened on first contact.)
        inbound_id=str(message.id),
        platform_user_id=str(message.author.id),
        body=body,
        sub_payload_refs=(),
        # M4: an edited message is a fresh inbound event at the edit instant, so
        # stamp ``received_at`` with ``edited_at`` when present; a never-edited
        # message has ``edited_at is None`` and falls back to ``created_at``.
        received_at=message.edited_at or message.created_at,
        addressing_signal=signal,
    )


__all__ = ["normalise"]
