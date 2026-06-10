"""Thread → conversation-session binding ledger (comms-4, #206).

A platform thread is a durable conversation. Every inbound message in the same
thread must bind to the SAME orchestrator ``conversation_session_id`` so the
second and later messages RESUME the session instead of forking a fresh one — a
re-create would lose the thread's accumulated context and let an attacker reset
the conversation state by re-posting.

:class:`ThreadConversationLedger` is the host-side binder. The first message in a
``(adapter_id, thread_id)`` thread mints a fresh ``conversation_session_id``
(``resumed=False``); every later message in the same thread returns the same id
with ``resumed=True``. The key includes ``adapter_id`` so two adapters' threads
never collide and a thread on one adapter cannot resume another adapter's session.

In-memory for this PR (a daemon restart loses the bindings — acceptable for the
mid-flight slice; durable persistence is a Slice-5 enhancement tracked alongside
``OutboundQueue`` persistence). The class holds no module-level state.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ConversationBinding:
    """The session a thread message binds to.

    ``conversation_session_id`` is stable for the life of the thread binding;
    ``resumed`` is ``False`` only for the first message in the thread and ``True``
    for every subsequent message (the orchestrator resumes rather than re-creates).
    """

    conversation_session_id: str
    resumed: bool


class ThreadConversationLedger:
    """Binds ``(adapter_id, thread_id)`` to a stable conversation session id."""

    def __init__(self) -> None:
        self._sessions: dict[tuple[str, str], str] = {}

    def bind(self, *, adapter_id: str, thread_id: str) -> ConversationBinding:
        """Return the conversation session for this thread, minting on first contact.

        First message in the thread mints a fresh session (``resumed=False``);
        every later message returns the same id (``resumed=True``).
        """
        key = (adapter_id, thread_id)
        existing = self._sessions.get(key)
        if existing is not None:
            return ConversationBinding(conversation_session_id=existing, resumed=True)
        session_id = str(uuid.uuid4())
        self._sessions[key] = session_id
        return ConversationBinding(conversation_session_id=session_id, resumed=False)


__all__ = ["ConversationBinding", "ThreadConversationLedger"]
