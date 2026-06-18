"""MERGE-BLOCKING: chat -> gateway -> core survives a core restart (Spec A G5 / #237).

This is the G5 graduation proof — it closes #237 criterion #7 ("a real ``alfred chat``
turn survives a core restart"). It drives the REAL chat -> gateway -> core stack across
a controlled core restart, with everything real EXCEPT the core (a controllable fake):

* the **client leg is a REAL AF_UNIX socket** — :class:`GatewayProcess` binds the REAL
  :class:`GatewayClientListener` (``comms-gateway.sock``) and the chat side dials in over
  the REAL :class:`CommsSocketTransport`. NOT an in-memory pair: the held-across-restart
  single-accept-for-life wire is the property under test, so it must be a genuine socket.
* the **chat side runs the REAL cohost wire pump** — :func:`run_cohosted` answers the
  gateway's client-leg HOST handshake via the REAL :class:`TuiServer` and routes
  ``link.*`` control frames to a recording ``on_link_state``. (The terminal-bound Textual
  app half is a parking double; the banner render is asserted against a REAL
  :class:`AlfredTuiApp` in the R5b test.)
* the **core is a controllable fake** — :class:`_ScriptedCoreTransport` / :class:`_DialRecorder`
  REUSED from ``tests/unit/gateway/test_core_link.py``, scripting the handshake + the
  going_down / ack / EOF sequence that drives the restart.

DETERMINISM (flakiness is failure). The reconnect backoff is instant but the 30 s buffer-
evict sweep PARKS (an instant sleep there would busy-spin + starve the loop); ``jitter`` is
the identity; the fake-core EOF is a per-leg distinct blocking event; every wait is a
bounded ``settle`` on an observable, never a fixed timeout.
"""

from __future__ import annotations

import asyncio

import pytest

from tests.integration._gateway_restart_harness import (
    _ScriptedCoreTransport,
    fresh_epoch,
    gateway_stack,
    settle,
    start_frame,
)

pytestmark = pytest.mark.integration


# ---------------------------------------------------------------------------
# TASK 1 — the harness + steady-state smoke.
# ---------------------------------------------------------------------------


async def test_stack_handshakes_reaches_steady_state_and_tears_down_clean(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The full stack builds, handshakes the first epoch, idles (no banner), tears down.

    Steady-state smoke: a REAL chat dials the REAL gateway socket, the gateway dials the
    fake core (first epoch handshake), and the relay pumps with NO ``link.*`` banner yet
    (a healthy link is silent). On context exit the shutdown event fires and BOTH legs
    return cleanly — no leaked task, the fake-core transport closed, the gateway's socket
    reaped (the hard-rule-#7 symmetric teardown end-to-end).
    """
    epoch = fresh_epoch()
    blocked = asyncio.Event()
    # ONE core leg: handshake start, then a blocked read held for the life of the test
    # (the steady-state pump parks on it until shutdown). The block is a per-leg event,
    # never the gateway shutdown event.
    core = _ScriptedCoreTransport([start_frame(epoch), blocked])

    async with gateway_stack(monkeypatch=monkeypatch, core_outcomes=[lambda: core]) as stack:
        # Steady state: exactly one core dial, the handshake ack written back, NO banner.
        assert stack.dial.calls == 1
        assert await settle(lambda: bool(core.sent)), "core handshake ack never written"
        # A healthy link emits no link.* control frame — the banner stays silent.
        assert stack.link_states == []
        # Both legs are still live (neither task finished early on a crash).
        assert not stack.gateway_task.done()
        assert not stack.chat_task.done()

    # After teardown: both tasks done (no leak), the fake-core transport closed.
    assert stack.gateway_task.done()
    assert stack.chat_task.done()
    assert core.closed is True
    # The chat cohost returned its clean-exit code (0) — a graceful symmetric teardown.
    assert stack.chat_task.result() == 0
