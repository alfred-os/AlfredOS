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
import json

import pytest
from alfred_tui.session import TuiSession
from alfred_tui.textual.app import AlfredTuiApp
from textual.widgets import Static

from alfred.comms_mcp.protocol import LINK_RECONNECTING, LINK_RESTORED
from tests.integration._gateway_restart_harness import (
    _GoDownCoreTransport,
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


# ---------------------------------------------------------------------------
# TASK 2 — banner transition on restart (R5).
# ---------------------------------------------------------------------------


async def test_core_restart_paints_reconnecting_then_restored_and_chat_survives(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A core restart drives ``[link.reconnecting, link.restored]`` to chat; chat survives.

    Drive to steady state on epoch 1, then trigger ``go_down()`` on the live core: the
    gateway's core-link consumes the ``going_down`` (-> ``link.reconnecting`` pushed to
    chat), the EOF opens the gap, the ``_DialRecorder`` hands a FRESH-epoch core, the
    reconnect handshake closes the gap (-> ``link.restored``). Assert:

    (a) the recorded ``on_link_state`` sequence is EXACTLY ``[reconnecting, restored]`` —
        the control frames crossed the REAL socket from gateway to chat;
    (b) replaying those SAME methods through a REAL :class:`AlfredTuiApp.set_link_state`
        PAINTS the ``tui.banner.reconnecting`` reactive on ``reconnecting`` and CLEARS it
        (reactive -> ``None``) on ``restored`` (restore = hide; ``restored`` has no
        banner key by design);
    (c) the chat wire pump did NOT exit across the gap — it survived the restart.
    """
    epoch1 = fresh_epoch()
    epoch2 = fresh_epoch()
    first = _GoDownCoreTransport(epoch1)
    blocked = asyncio.Event()
    # The reconnect target: a fresh-epoch core that holds steady (blocked) post-handshake
    # so the restored state is observable before teardown. Distinct per-leg block event.
    second = _ScriptedCoreTransport([start_frame(epoch2), blocked])

    async with gateway_stack(
        monkeypatch=monkeypatch, core_outcomes=[lambda: first, lambda: second]
    ) as stack:
        # Steady state on epoch 1: handshake done, no banner yet.
        assert await settle(lambda: bool(first.sent))
        assert stack.link_states == []

        # Trigger the planned drain on the LIVE core -> reconnecting, then reconnect to
        # the fresh epoch -> restored.
        first.go_down()

        # Settle until the reconnect reached the second leg's handshake (restored emitted).
        assert await settle(lambda: bool(second.sent)), "reconnect never handshaked epoch 2"
        assert await settle(lambda: len(stack.link_states) >= 2), "restored never emitted"

        # (a) Exactly one gap: reconnecting (the drain) then restored (the reconnect).
        assert stack.link_states == [LINK_RECONNECTING, LINK_RESTORED]

        # (c) The chat wire pump SURVIVED the restart — neither leg's task finished.
        assert not stack.chat_task.done()
        assert not stack.gateway_task.done()
        # The dial recorder dialed exactly twice (initial + the one reconnect).
        assert stack.dial.calls == 2

    # (b) Replay the recorded methods through a REAL AlfredTuiApp: reconnecting PAINTS the
    # banner reactive, restored CLEARS it (-> None). Driven under Textual's run_test pilot,
    # the same seam the widget tests pin.
    await _assert_banner_paints_then_clears(stack.link_states)


async def _assert_banner_paints_then_clears(methods: list[str]) -> None:
    """Replay ``methods`` into a REAL AlfredTuiApp; assert the banner reactive paints/clears.

    The gateway sends only the STATE (the ``link.*`` method); the TUI paints its OWN
    localized banner via the ``_link_banner_key`` reactive. ``reconnecting`` sets the
    ``tui.banner.reconnecting`` key (banner shown); ``restored`` sets it to ``None``
    (banner hidden) — ``restored`` has no banner key by design, so we assert the CLEAR,
    not a ``tui.banner.restored`` render.
    """
    assert methods == [LINK_RECONNECTING, LINK_RESTORED]  # the recorded gap sequence
    app = AlfredTuiApp(session=TuiSession())
    async with app.run_test() as pilot:
        app.set_link_state(LINK_RECONNECTING)
        await pilot.pause()
        # reconnecting PAINTS the banner (the tui.banner.reconnecting render is shown).
        assert app.query_one("#link_banner", Static).display is True

        app.set_link_state(LINK_RESTORED)
        await pilot.pause()
        # restored CLEARS the banner (restore = hide; no tui.banner.restored render).
        assert app.query_one("#link_banner", Static).display is False


# ---------------------------------------------------------------------------
# TASK 3 — un-acked operator input REPLAYS across the restart (the crit-#7 proof, R4).
# ---------------------------------------------------------------------------


def _operator_text(payload: bytes) -> str:
    """The operator-typed text inside a relayed ``inbound.message`` payload.

    The opaque client->core payload is the inner ``inbound.message`` JSON-RPC frame; the
    TUI body is ``{"content": "<typed text>"}`` (``BODY_FIELD_BY_KIND["tui"] == "content"``).
    Extracting it lets the test identify WHICH operator turn a recorded/replayed unit is.
    """
    frame = json.loads(payload)
    body = frame["params"]["body"]
    content = body["content"]
    assert isinstance(content, str)
    return content


def _texts(units: list[tuple[bytes, int, int]]) -> list[str]:
    """The operator texts of a transport's recorded ``sent_units``, in order."""
    return [_operator_text(payload) for payload, _seq, _ack in units]


async def test_unacked_operator_input_replays_across_a_core_restart(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Un-acked operator input replays on the NEW core; already-acked input does NOT.

    THE crit-#7 proof (R4 / G4b-2b resume). Send operator turns chat -> gateway -> core
    over the REAL socket. The fake core WITHHOLDS ``daemon.comms.ack`` for the input that
    must replay (it stays genuinely UN-ACKED at restart), but DELIVERS an ack for a
    CONTROL turn first. Then ``go_down()`` opens the gap and the reconnect binds a fresh
    core. Assert:

    * the un-acked turns replay on the NEW core, in FIFO order, with FRESH per-connection
      seqs (0, 1, ...) — the resume re-sends the buffered remainder;
    * a post-restart fresh turn lands AFTER the replayed ones (fresh input never jumps the
      replay);
    * CONTROL (non-vacuity): the ALREADY-ACKED turn does NOT replay — else a blind re-send
      of the whole stream would pass trivially.

    Mutation note: with Task 0's buffer injection removed (``replay_buffer=None``) nothing
    is buffered, so nothing replays and this test FAILS — the buffer is load-bearing.
    """
    epoch1 = fresh_epoch()
    epoch2 = fresh_epoch()
    first = _GoDownCoreTransport(epoch1)
    blocked = asyncio.Event()
    second = _ScriptedCoreTransport([start_frame(epoch2), blocked])

    async with gateway_stack(
        monkeypatch=monkeypatch, core_outcomes=[lambda: first, lambda: second]
    ) as stack:
        assert await settle(lambda: bool(first.sent))  # epoch-1 handshake done

        # Three operator turns on the live leg, each a REAL inbound.message over the REAL
        # socket. The gateway mints client->core seqs 0,1,2 and buffers each (un-acked).
        await stack.send_operator_input("acked-turn")  # seq 0 — will be ACKED (control)
        await stack.send_operator_input("unacked-one")  # seq 1 — stays un-acked -> replays
        await stack.send_operator_input("unacked-two")  # seq 2 — stays un-acked -> replays
        # Settle until all three reached the live core (its sent_units recorded them).
        assert await settle(
            lambda: (
                _texts(first.sent_units)
                == [
                    "acked-turn",
                    "unacked-one",
                    "unacked-two",
                ]
            )
        ), f"live core never received all three turns: {_texts(first.sent_units)}"

        # The core ACKS ONLY the first turn (cumulative_ack=0 covers seq 0). That trims
        # "acked-turn" from the gateway's ReplayBuffer BEFORE the gap — so it is NOT
        # un-acked at restart and must NOT replay (the non-vacuity control).
        first.deliver_ack(0, seq=10)
        # The seqs 1,2 ("unacked-one"/"unacked-two") are NEVER acked: genuinely un-acked.

        # Trigger the restart: going_down -> reconnecting -> reconnect to epoch 2.
        first.go_down()
        assert await settle(lambda: bool(second.sent)), "reconnect never handshaked epoch 2"

        # The resume replays the un-acked remainder on the NEW core, FIFO, FRESH seqs 0,1.
        assert await settle(lambda: _texts(second.sent_units) == ["unacked-one", "unacked-two"]), (
            f"un-acked input did not replay on the new core: {_texts(second.sent_units)}"
        )
        replayed = list(second.sent_units)
        # FRESH per-connection seqs 0,1 (NOT the original 1,2) — the G4b-2b reseq.
        assert [seq for _p, seq, _a in replayed] == [0, 1]
        # CONTROL: the already-acked turn is ABSENT from the replay (no blind re-send).
        assert "acked-turn" not in _texts(replayed)

        # A post-restart fresh turn lands AFTER the replayed ones (fresh input never jumps
        # the replay): it takes the next fresh seq (2) and trails the two replayed frames.
        await stack.send_operator_input("post-restart")
        assert await settle(
            lambda: _texts(second.sent_units) == ["unacked-one", "unacked-two", "post-restart"]
        ), f"post-restart input did not land after the replay: {_texts(second.sent_units)}"
        assert second.sent_units[-1][1] == 2  # fresh seq 2, after the replayed 0,1

        assert not stack.chat_task.done()  # chat survived the whole restart
