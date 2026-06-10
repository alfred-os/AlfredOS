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

Wiring status (#235). This comms-4 primitive is TESTED but NOT yet on the live
inbound path — the daemon does not spawn the discord plugin until the PR-S4-10
flag-day. Thread→session binding is wired into the live path in PR-S4-10; until
then it is not operationally enforced. See ``docs/subsystems/comms.md`` (Slice-4
wiring-status note) and issue #235.
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

        First-bind is ATOMIC-by-construction via ``dict.setdefault`` rather than a
        check-then-create (``get`` then ``[key] = mint``). The check-then-create
        shape leaves a window where two binds could each observe no session and
        each mint a distinct id, the second clobbering the first — splitting one
        thread across two sessions and letting an attacker reset accumulated
        context. ``setdefault`` commits the first writer's id and returns it for
        every later caller, so ``resumed`` is simply "an id already existed".
        """
        key = (adapter_id, thread_id)
        candidate = str(uuid.uuid4())
        # setdefault returns the EXISTING value if present, else stores+returns
        # the candidate. ``stored is candidate`` is True only for the writer that
        # actually created the binding — that is the single non-resumed bind.
        stored = self._sessions.setdefault(key, candidate)
        return ConversationBinding(conversation_session_id=stored, resumed=stored is not candidate)


__all__ = ["ConversationBinding", "ThreadConversationLedger"]
