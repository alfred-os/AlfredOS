"""closure i18n-1: the inbound emitter tags a BCP-47 ``language`` on the body.

Every Discord inbound carries a BCP-47 ``language`` tag resolved by the
adapter-visible precedence: (a) ``guild.preferred_locale`` for guild messages;
(b) ``author.locale`` for DMs (if available); (d) fallback ``"en"``. The
canonical ``User.language`` rung (c) is applied host-side from the resolved
identity — the adapter cannot see it, so it stops at rungs a/b/d.

The host's inbound handler lifts ``body["language"]`` onto the
``COMMS_INBOUND_*`` audit rows at ingest time (the audit-row constant extension
is the coordinated PR-S4-0a delta named in the closure).
"""

from __future__ import annotations

import pytest

from plugins.alfred_discord.inbound_emitter import normalise
from tests.support.discord_mocks import DiscordMockFactory


@pytest.mark.parametrize(
    ("case", "expected"),
    [
        ("guild_with_locale", "fr"),
        ("dm_with_locale", "ja"),
        ("dm_no_locale", "en"),
        ("guild_default_locale", "en-US"),
    ],
)
def test_language_field_precedence(
    discord_mock_factory: DiscordMockFactory, case: str, expected: str
) -> None:
    if case == "guild_with_locale":
        msg = discord_mock_factory.message(
            channel=discord_mock_factory.channel(channel_id=10),
            guild=discord_mock_factory.guild(preferred_locale="fr"),
        )
        listen = frozenset({10})
    elif case == "dm_with_locale":
        msg = discord_mock_factory.message(
            channel=discord_mock_factory.dm_channel(),
            author=discord_mock_factory.user(user_id=42, locale="ja"),
        )
        listen = frozenset()
    elif case == "dm_no_locale":
        msg = discord_mock_factory.message(
            channel=discord_mock_factory.dm_channel(),
            author=discord_mock_factory.user(user_id=42, locale=None),
        )
        listen = frozenset()
    else:  # guild_default_locale — guild present, no explicit locale override
        msg = discord_mock_factory.message(
            channel=discord_mock_factory.channel(channel_id=10),
            guild=discord_mock_factory.guild(),
        )
        listen = frozenset({10})

    note = normalise(msg, adapter_id="discord", bot_user_id=9999, channel_listen_set=listen)
    assert note is not None
    assert note.body["language"] == expected
