"""Thread continuity: two messages in one thread resume one session (comms-4, #206).

Drives two ``discord_mock_factory`` messages in the SAME Discord thread through
the real ``inbound_emitter.normalise`` and the real
``ThreadConversationLedger``. Asserts both messages bind to the same
``conversation_session_id`` and that the second message RESUMES the session
(``resumed=True``) rather than forking a fresh one. A message in a DIFFERENT
thread binds to a distinct session.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

import pytest

from alfred.comms_mcp.protocol import InboundMessageNotification
from alfred.comms_mcp.thread_conversation_ledger import ThreadConversationLedger
from plugins.alfred_discord.inbound_emitter import normalise
from tests.support.discord_mocks import DiscordMockFactory

if TYPE_CHECKING:
    from plugins.alfred_discord.inbound_emitter import _MessageLike

pytestmark = pytest.mark.integration

_ADAPTER_ID = "discord"
_BOT_USER_ID = 999
_THREAD_CHANNEL_ID = 4242
_OTHER_THREAD_CHANNEL_ID = 4343


def _thread_message(factory: DiscordMockFactory, *, channel_id: int, content: str) -> _MessageLike:
    message = factory.message(
        author=factory.user(user_id=1001),
        channel=factory.thread_channel(channel_id=channel_id),
        content=content,
    )
    return cast("_MessageLike", message)


def _normalise(message: _MessageLike) -> InboundMessageNotification | None:
    return normalise(
        message,
        adapter_id=_ADAPTER_ID,
        bot_user_id=_BOT_USER_ID,
        channel_listen_set=frozenset(),
    )


@pytest.mark.asyncio
async def test_two_thread_messages_resume_one_session(
    discord_mock_factory: DiscordMockFactory,
) -> None:
    ledger = ThreadConversationLedger()
    thread_id = str(_THREAD_CHANNEL_ID)

    first_msg = _thread_message(
        discord_mock_factory, channel_id=_THREAD_CHANNEL_ID, content="opening message"
    )
    first_note = _normalise(first_msg)
    assert first_note is not None and first_note.addressing_signal == "thread"
    first = ledger.bind(adapter_id=_ADAPTER_ID, thread_id=thread_id)
    assert first.resumed is False

    second_msg = _thread_message(
        discord_mock_factory, channel_id=_THREAD_CHANNEL_ID, content="follow-up message"
    )
    second_note = _normalise(second_msg)
    assert second_note is not None and second_note.addressing_signal == "thread"
    second = ledger.bind(adapter_id=_ADAPTER_ID, thread_id=thread_id)

    # comms-4: both messages bind to the SAME conversation session; the second
    # RESUMES it rather than forking a fresh session.
    assert second.conversation_session_id == first.conversation_session_id
    assert second.resumed is True


@pytest.mark.asyncio
async def test_different_thread_forks_a_new_session(
    discord_mock_factory: DiscordMockFactory,
) -> None:
    ledger = ThreadConversationLedger()
    in_thread = ledger.bind(adapter_id=_ADAPTER_ID, thread_id=str(_THREAD_CHANNEL_ID))
    other_thread = ledger.bind(adapter_id=_ADAPTER_ID, thread_id=str(_OTHER_THREAD_CHANNEL_ID))
    assert other_thread.conversation_session_id != in_thread.conversation_session_id
    assert other_thread.resumed is False
