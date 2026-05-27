"""Pin the ``discord.py`` surface the DiscordAdapter relies on.

The adapter is mocked in every unit test via the ``client_factory`` seam
so a minor-version rename in ``discord.py`` would silently slip past
every other test layer. This module imports the real ``discord`` package
and asserts each attribute and signature the adapter touches via
``hasattr`` / ``inspect.signature``. A failure here means ``discord.py``
broke a contract we depend on — either roll back to the previous
2.x version or write an adapter migration alongside the version bump.

Why ``>=2.4,<3``: 2.4 is the first version with stable ``message.poll``
(introduced 2024); 3.x is the eventual rewrite that will need a
coordinated adapter sweep. Every failure message here cites that pin so
future contributors know the remediation surface.
"""

from __future__ import annotations

import inspect

import discord
import pytest

_PIN_HINT = "(discord.py pinned >=2.4,<3 — adapter assumes 2.x surface)"


@pytest.mark.parametrize(
    "attribute",
    [
        "content",
        "author",
        "channel",
        "embeds",
        "attachments",
        "stickers",
        "reference",
        "poll",
        "components",
        "activity",
        "application",
    ],
)
def test_discord_message_has_attribute(attribute: str) -> None:
    """Every allowlist field the adapter inspects must exist on ``Message``.

    ``Message`` is the inbound type from ``discord.Client.on_message``.
    The allowlist refusal path reads every one of these to decide whether
    to refuse + audit. A renamed attribute in discord.py would silently
    make the refusal a no-op (the missing attribute defaults to absent
    via ``getattr``-style checks, so the adapter would *admit* embeds /
    attachments / polls without refusing). Pin the names here.
    """
    assert hasattr(discord.Message, attribute), (
        f"discord.Message has no attribute {attribute!r}; the DiscordAdapter "
        f"allowlist refusal path depends on it. {_PIN_HINT}"
    )


def test_discord_message_author_has_required_fields() -> None:
    """``msg.author.id`` (snowflake) and ``msg.author.bot`` (flag) must exist.

    The adapter uses ``author.id`` as the per-DM dedup key (audit-DoS
    mitigation) and ``author.bot`` to short-circuit bot messages before
    any orchestrator call. Both are documented on
    ``discord.User``/``discord.Member`` and ``discord.Message.author``
    resolves to one of those.
    """
    # The discord.py 2.x type for ``Message.author`` is ``Union[User, Member]``.
    # Both expose ``id`` and ``bot``; checking on the concrete ``User`` type is
    # the strongest pin we can do without instantiating a Message.
    assert hasattr(discord.User, "id"), f"discord.User has no .id; {_PIN_HINT}"
    assert hasattr(discord.User, "bot"), f"discord.User has no .bot; {_PIN_HINT}"


def test_discord_dm_channel_exists_and_distinct_from_group() -> None:
    """``DMChannel`` and ``GroupChannel`` must be importable and distinct.

    The adapter accepts DM channels only; group channels are out-of-scope
    for Slice 2 (group persona sessions land in Slice 4 via threads). If
    discord.py merged the two classes, the adapter's ``isinstance(channel,
    discord.DMChannel)`` short-circuit would let group traffic through.
    """
    assert hasattr(discord, "DMChannel"), f"discord.DMChannel missing; {_PIN_HINT}"
    assert hasattr(discord, "GroupChannel"), f"discord.GroupChannel missing; {_PIN_HINT}"
    assert discord.DMChannel is not discord.GroupChannel, (
        f"discord.DMChannel and GroupChannel must remain distinct types; {_PIN_HINT}"
    )


def test_discord_client_start_signature_accepts_token_and_reconnect() -> None:
    """``Client.start(token, *, reconnect=True)`` must remain the canonical entry.

    The adapter calls ``await client.start(token, reconnect=True)``; a
    renamed parameter (e.g. ``reconnect`` → ``auto_reconnect``) would
    surface as a TypeError on first launch, but only at production-boot
    time. Catch the drift here.
    """
    sig = inspect.signature(discord.Client.start)
    params = sig.parameters
    assert "token" in params, f"Client.start lost the ``token`` parameter; {_PIN_HINT}"
    assert "reconnect" in params, f"Client.start lost the ``reconnect`` parameter; {_PIN_HINT}"


def test_discord_client_init_accepts_slim_cache_kwargs() -> None:
    """``Client.__init__`` must accept the slim-cache kwargs the compose service sets.

    Per spec §3 (perf-005), the adapter constructs a ``discord.Client``
    with ``max_messages=100``, ``chunk_guilds_at_startup=False``, and
    ``member_cache_flags=…`` to keep the 256M memory cap viable. A renamed
    kwarg would either OOM the container or fall back to discord.py's
    defaults silently. Pin the kwargs here so the surface test fails
    loudly before deploy.

    discord.py 2.7+ types ``__init__`` as ``**options: Unpack[_ClientOptions]``,
    so ``inspect.signature`` only sees ``**options`` (not the individual
    kwarg names). The robust check is to actually construct a ``Client``
    with the kwargs — discord.py only raises ``TypeError`` if an unknown
    kwarg lands in ``**options`` once it tries to resolve the TypedDict.
    Pinning via constructor invocation matches what the adapter does at
    runtime so any future kwarg removal trips here.
    """
    intents = discord.Intents.default()
    # Construct with the exact kwargs the adapter passes. If discord.py
    # ever removes one, the TypedDict would reject the unknown key and
    # raise ``TypeError`` (or a future ``DiscordException``). We don't
    # try to ``client.start()`` — instantiation alone is sufficient to
    # validate the kwarg surface.
    try:
        discord.Client(
            intents=intents,
            max_messages=100,
            chunk_guilds_at_startup=False,
            member_cache_flags=discord.MemberCacheFlags.none(),
        )
    except TypeError as exc:  # pragma: no cover - regression guard
        pytest.fail(f"discord.Client(...) rejected adapter kwargs: {exc!r}. {_PIN_HINT}")
    # Independent smoke: ``MemberCacheFlags.none()`` is the slim
    # construction the adapter relies on. If discord.py renamed it,
    # the constructor above would have raised first; the explicit
    # ``hasattr`` keeps the failure message specific.
    assert hasattr(discord.MemberCacheFlags, "none"), (
        f"discord.MemberCacheFlags.none() missing; the slim cache config depends on it. {_PIN_HINT}"
    )


def test_discord_intents_default_and_message_content_flags_exist() -> None:
    """``Intents.default()`` + ``message_content`` flag must remain available.

    The adapter computes its required intents via
    ``intents = discord.Intents.default()`` then opts in to
    ``intents.message_content = True``. The Message Content gateway intent
    is the one Discord requires the operator to enable in the developer
    portal; if discord.py renames the field, the adapter would silently
    fail to request it.
    """
    intents = discord.Intents.default()
    assert hasattr(intents, "message_content"), (
        f"discord.Intents.message_content missing; the adapter cannot read DM bodies "
        f"without it. {_PIN_HINT}"
    )
    assert hasattr(intents, "dm_messages"), (
        f"discord.Intents.dm_messages missing; the adapter relies on the DM intent. {_PIN_HINT}"
    )


def test_discord_login_failure_and_http_exception_types_exist() -> None:
    """Typed exception classes the reconnect-classification table maps must exist.

    The adapter's ``_classify_gateway_exception`` matches on
    ``discord.LoginFailure``, ``discord.ConnectionClosed``, and
    ``discord.HTTPException`` — all documented public types in 2.x. A
    rename would collapse the exit-code table.
    """
    assert hasattr(discord, "LoginFailure"), f"discord.LoginFailure missing; {_PIN_HINT}"
    assert hasattr(discord, "ConnectionClosed"), f"discord.ConnectionClosed missing; {_PIN_HINT}"
    assert hasattr(discord, "HTTPException"), f"discord.HTTPException missing; {_PIN_HINT}"
