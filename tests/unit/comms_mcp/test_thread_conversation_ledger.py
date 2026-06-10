"""Thread → conversation-session binding (comms-4, #206).

A Discord thread is a durable conversation: every message in the same thread must
bind to the same orchestrator ``conversation_session_id`` so the second (and
later) messages RESUME the session rather than fork a fresh one. The
:class:`ThreadConversationLedger` is the host-side binder: the first message in a
thread mints a session id (``resumed=False``); every later message in the same
thread returns the SAME id with ``resumed=True``.

Keyed on ``(adapter_id, thread_id)`` so two adapters' threads never collide and a
thread on one adapter cannot resume another adapter's session.
"""

from __future__ import annotations

from alfred.comms_mcp.thread_conversation_ledger import ThreadConversationLedger


def test_first_message_in_thread_creates_session() -> None:
    ledger = ThreadConversationLedger()
    binding = ledger.bind(adapter_id="discord", thread_id="t1")
    assert binding.resumed is False
    assert binding.conversation_session_id


def test_second_message_in_thread_resumes_same_session() -> None:
    ledger = ThreadConversationLedger()
    first = ledger.bind(adapter_id="discord", thread_id="t1")
    second = ledger.bind(adapter_id="discord", thread_id="t1")
    assert second.resumed is True
    assert second.conversation_session_id == first.conversation_session_id


def test_different_threads_get_distinct_sessions() -> None:
    ledger = ThreadConversationLedger()
    a = ledger.bind(adapter_id="discord", thread_id="t1")
    b = ledger.bind(adapter_id="discord", thread_id="t2")
    assert a.conversation_session_id != b.conversation_session_id


def test_same_thread_id_on_different_adapters_does_not_collide() -> None:
    ledger = ThreadConversationLedger()
    a = ledger.bind(adapter_id="discord", thread_id="t1")
    b = ledger.bind(adapter_id="telegram", thread_id="t1")
    assert a.conversation_session_id != b.conversation_session_id
    assert b.resumed is False
