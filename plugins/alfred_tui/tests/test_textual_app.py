"""The moved Textual app feeds input into the session and renders outbound.

Verbatim move from ``src/alfred/comms/tui.py`` (PR-S4-10): the widget tree
(input area + RichLog) is preserved; only the *bindings* to the surrounding
adapter change — the app now feeds a session's ``consume_user_input`` (which the
plugin's wire layer turns into an ``inbound.message`` notification) instead of
calling an in-process orchestrator.
"""

from __future__ import annotations

from typing import get_args

import pytest
from alfred_tui.textual.app import AlfredTuiApp, _turn_failure_message
from textual.widgets import Input, RichLog, Static

from alfred.comms_mcp.protocol import (
    LINK_RECONNECTING,
    LINK_RESTORED,
    LINK_UNAVAILABLE,
    TurnFailureStage,
)
from alfred.i18n import t

# A short watchdog for tests that need to observe a real expiry (or merely
# avoid leaving a live 90s `Timer` task running past `run_test()`'s teardown
# — see `test_enter_submits_input_to_session` below, which does not itself
# care about the watchdog but would otherwise leave one armed for the
# duration of the real 90s default).
_FAST_TIMEOUT_SECONDS = 0.05


def _plain_text(log: RichLog) -> str:
    """The visible plain text of a RichLog, stripped of style metadata.

    ``str(strip)`` renders the Strip *repr* (Segment + Style noise), which would
    let a markup assertion pass on style attributes rather than literal glyphs.
    Joining each strip's ``Segment.text`` gives exactly what the operator sees,
    so an assertion on literal ``[red]…[/red]`` glyphs is meaningful.
    """
    return "\n".join("".join(seg.text for seg in strip) for strip in log.lines)


class _RecordingSession:
    """Structural ``_SessionLike`` double recording consumed input."""

    def __init__(self) -> None:
        self.consumed: list[str] = []
        self.flushed: int = 0

    async def consume_user_input(self, chunk: str) -> None:
        self.consumed.append(chunk)

    async def flush_keystroke_batch(self) -> None:
        self.flushed += 1


class _FailingSession:
    """Structural ``_SessionLike`` double whose flush never reaches the wire.

    Simulates a dead local transport (``consume_user_input``/``flush_keystroke_batch``
    raising) so ``on_input_submitted``'s except-branch (#593) can be exercised: the
    inbound never reaches the wire, so no reply can ever come, and the turn must be
    ended immediately rather than left pending for the full watchdog window.
    """

    async def consume_user_input(self, _chunk: str) -> None:
        # The exact message is asserted to NOT appear in the rendered line —
        # only the exception CLASS NAME should reach the operator.
        raise RuntimeError("transport internals: fd 7 broken pipe detail")

    async def flush_keystroke_batch(self) -> None:  # pragma: no cover - unreachable
        raise AssertionError("consume_user_input should have raised first")


@pytest.mark.asyncio
async def test_enter_submits_input_to_session() -> None:
    session = _RecordingSession()
    # A short watchdog so this test does not leave a live 90s `Timer` task
    # running inside `run_test()`'s teardown (#593 watchdog — this test
    # predates it and does not itself exercise it).
    app = AlfredTuiApp(session=session, turn_timeout_seconds=_FAST_TIMEOUT_SECONDS)
    async with app.run_test() as pilot:
        app.query_one("#user_input", Input).value = "hello alfred"
        await pilot.press("enter")
        await pilot.pause()
    assert session.consumed == ["hello alfred"]
    assert session.flushed == 1


@pytest.mark.asyncio
async def test_outbound_render_writes_visible_richlog_line() -> None:
    session = _RecordingSession()
    app = AlfredTuiApp(session=session)
    async with app.run_test() as pilot:
        app.write_outbound("hello back from alfred")
        await pilot.pause()
        log = app.query_one("#conversation_log", RichLog)
        rendered = _plain_text(log)
    assert "hello back from alfred" in rendered


@pytest.mark.asyncio
async def test_outbound_markup_in_body_is_rendered_literally_not_interpreted() -> None:
    """Console markup in a host-delivered outbound body must NOT be interpreted.

    The outbound ``body`` is persona output that can carry T3-derived content;
    the RichLog runs ``markup=True``, so an attacker-influenced ``[red]…[/red]``
    (or ``[link=…]``) would otherwise be parsed as a Rich style tag (markup
    injection). The app escapes the untrusted body so the brackets show as
    literal text. The app-controlled label prefix keeps its legitimate markup.
    """
    session = _RecordingSession()
    app = AlfredTuiApp(session=session)
    async with app.run_test() as pilot:
        app.write_outbound("[red]evil[/red]")
        await pilot.pause()
        log = app.query_one("#conversation_log", RichLog)
        rendered = _plain_text(log)
    assert "[red]evil[/red]" in rendered, (
        "outbound markup was interpreted, not escaped — markup-injection vector"
    )


@pytest.mark.asyncio
async def test_echoed_user_input_markup_is_rendered_literally_not_interpreted() -> None:
    """Console markup typed by the operator is echoed literally, not interpreted.

    Symmetric to the outbound guard: the echoed user line is interpolated into
    the same ``markup=True`` RichLog, so it gets escaped too.
    """
    session = _RecordingSession()
    app = AlfredTuiApp(session=session)
    async with app.run_test() as pilot:
        app.query_one("#user_input", Input).value = "[blink]boom[/blink]"
        await pilot.press("enter")
        await pilot.pause()
        log = app.query_one("#conversation_log", RichLog)
        rendered = _plain_text(log)
    assert "[blink]boom[/blink]" in rendered, (
        "echoed user markup was interpreted, not escaped — markup-injection vector"
    )


# ---------------------------------------------------------------------------
# Reconnect banner — gateway link-state render (Spec A G5 / ADR-0031).
#
# The gateway sends only the STATE (the ``link.*`` method); the TUI paints its
# OWN localized banner text via ``t("tui.banner.*")`` (no operator text on the
# wire). ``set_link_state`` is invoked by the cohost pump on the SAME loop as the
# Textual app (M1) — a direct reactive set, never ``call_from_thread``.
# ---------------------------------------------------------------------------


def _banner(app: AlfredTuiApp) -> Static:
    return app.query_one("#link_banner", Static)


@pytest.mark.asyncio
async def test_banner_hidden_on_mount() -> None:
    """No link gap yet: the banner is not displayed when the app first mounts."""
    app = AlfredTuiApp(session=_RecordingSession())
    async with app.run_test() as pilot:
        await pilot.pause()
        banner = _banner(app)
        assert banner.display is False


@pytest.mark.asyncio
async def test_reconnecting_state_shows_localized_banner() -> None:
    """``link.reconnecting`` paints the localized reconnecting banner text."""
    app = AlfredTuiApp(session=_RecordingSession())
    async with app.run_test() as pilot:
        app.set_link_state(LINK_RECONNECTING)
        await pilot.pause()
        banner = _banner(app)
        assert banner.display is True
        assert _plain_text_static(banner) == t("tui.banner.reconnecting")


@pytest.mark.asyncio
async def test_restored_state_clears_the_banner() -> None:
    """``link.restored`` hides the banner after a prior gap."""
    app = AlfredTuiApp(session=_RecordingSession())
    async with app.run_test() as pilot:
        app.set_link_state(LINK_RECONNECTING)
        await pilot.pause()
        app.set_link_state(LINK_RESTORED)
        await pilot.pause()
        banner = _banner(app)
        assert banner.display is False


@pytest.mark.asyncio
async def test_unavailable_state_shows_localized_banner() -> None:
    """``link.unavailable`` (G4-latent) paints the localized unavailable text."""
    app = AlfredTuiApp(session=_RecordingSession())
    async with app.run_test() as pilot:
        app.set_link_state(LINK_UNAVAILABLE)
        await pilot.pause()
        banner = _banner(app)
        assert banner.display is True
        assert _plain_text_static(banner) == t("tui.banner.unavailable")


def _plain_text_static(banner: Static) -> str:
    """The visible plain text of the banner ``Static``, stripped of style noise."""
    from rich.console import Console
    from rich.text import Text

    renderable = banner.render()
    if isinstance(renderable, str):
        return renderable
    if isinstance(renderable, Text):
        return renderable.plain
    # Any other Rich renderable: render to a throwaway console and read the glyphs.
    return "".join(seg.text for seg in Console().render(renderable)).rstrip("\n")


# ---------------------------------------------------------------------------
# Turn-in-flight indicator + watchdog + turn-failure rendering (#593).
#
# Before this task, `alfred chat` echoed the operator's message and then went
# completely silent — no "thinking..." indicator, no error, no timeout, ever.
# These tests cover the client-side half: the `.busy` CSS class actually
# getting toggled, the watchdog actually firing when nothing answers, and a
# core-reported `turn.failed` actually reaching the transcript.
# ---------------------------------------------------------------------------


# A watchdog timeout comfortably longer than the real wall-clock overhead of
# a `pilot.press()` + `pilot.pause()` round trip (Textual's `pilot.pause()`
# idle-detection loop alone costs tens of milliseconds — see
# `textual._wait.wait_for_idle`), so tests that assert the turn is STILL
# pending after normal message-loop processing never race the watchdog
# itself. Only the dedicated watchdog tests below use `_FAST_TIMEOUT_SECONDS`.
_MODERATE_TIMEOUT_SECONDS = 5.0


def _user_input(app: AlfredTuiApp) -> Input:
    return app.query_one("#user_input", Input)


def _log(app: AlfredTuiApp) -> RichLog:
    return app.query_one("#conversation_log", RichLog)


async def _submit(app: AlfredTuiApp, text: str) -> None:
    """Drive ``on_input_submitted`` directly with a synthetic ``Input.Submitted``.

    Deterministic and free of ``pilot.press()``'s real-time key-dispatch +
    idle-wait overhead (`Pilot.pause()`'s no-delay form polls CPU idleness in
    real time — see `textual._wait.wait_for_idle`) — important for the
    watchdog tests below, where that overhead alone could rival a
    deliberately-short timeout. The real keyboard path (key press ->
    ``Input`` posts ``Submitted`` -> this handler) is already covered
    end-to-end by ``test_enter_submits_input_to_session`` above; these tests
    are about what happens once the handler runs, not the dispatch mechanism
    itself.
    """
    input_widget = _user_input(app)
    input_widget.value = text
    await app.on_input_submitted(Input.Submitted(input=input_widget, value=text))


@pytest.mark.asyncio
async def test_enter_marks_turn_pending_and_disables_input() -> None:
    """Pressing Enter marks the turn pending and disables + dims the input.

    `_RecordingSession` never produces a reply on its own, so after the
    handler returns the turn is still (correctly) pending — nothing has
    ended it yet.
    """
    session = _RecordingSession()
    app = AlfredTuiApp(session=session, turn_timeout_seconds=_MODERATE_TIMEOUT_SECONDS)
    async with app.run_test() as pilot:
        _user_input(app).value = "hello alfred"
        await pilot.press("enter")
        await pilot.pause()
        input_widget = _user_input(app)
        assert app._turn_pending is True
        assert input_widget.disabled is True
        assert input_widget.has_class("busy")


@pytest.mark.asyncio
async def test_enter_writes_the_thinking_line() -> None:
    """The "thinking..." line is written after the operator's own echoed line."""
    session = _RecordingSession()
    app = AlfredTuiApp(session=session, turn_timeout_seconds=_MODERATE_TIMEOUT_SECONDS)
    async with app.run_test() as pilot:
        _user_input(app).value = "hello alfred"
        await pilot.press("enter")
        await pilot.pause()
        rendered = _plain_text(_log(app))
    you_index = rendered.index(t("tui.label_you"))
    thinking_index = rendered.index(t("tui.thinking"))
    assert you_index < thinking_index, "the operator's echo must precede the thinking line"


@pytest.mark.asyncio
async def test_outbound_reply_clears_pending_and_refocuses_input() -> None:
    """A host-delivered reply ends the pending turn and restores focus + enabled state."""
    session = _RecordingSession()
    app = AlfredTuiApp(session=session, turn_timeout_seconds=_MODERATE_TIMEOUT_SECONDS)
    async with app.run_test() as pilot:
        await _submit(app, "hello alfred")
        await pilot.pause()
        assert app._turn_pending is True  # sanity: the turn really was pending

        app.write_outbound("hello back from alfred")
        await pilot.pause()

        input_widget = _user_input(app)
        assert app._turn_pending is False
        assert input_widget.disabled is False
        assert not input_widget.has_class("busy")
        assert app.focused is input_widget


@pytest.mark.asyncio
async def test_second_enter_while_pending_is_ignored_and_preserves_typed_text() -> None:
    """A second submission while a turn is pending is dropped, not echoed/cleared.

    The second ``_submit`` exercises the guard directly rather than relying on
    the disabled widget to block the keystroke — the guard inside the handler
    is BELT-AND-BRACES for a queued event landing after the disable takes
    effect, and this test exercises that guard path directly regardless of the
    widget's interactive-disabled state.

    Since #594 Fix-10 the FIRST such drop writes exactly one rate-limited
    ``tui.turn_still_pending`` ack line (see the dedicated Fix-10 test section
    below for the rate-limiting behaviour itself) — this test only asserts
    that the drop is otherwise a genuine no-op: no session traffic, no typed
    text loss, and no OTHER/additional transcript line.
    """
    session = _RecordingSession()
    app = AlfredTuiApp(session=session, turn_timeout_seconds=_MODERATE_TIMEOUT_SECONDS)
    async with app.run_test() as pilot:
        await _submit(app, "first message")
        await pilot.pause()
        assert app._turn_pending is True
        lines_before = _plain_text(_log(app))

        # A second submission arrives while the first turn is still pending —
        # exactly the "queued event after disable" shape the guard defends.
        await _submit(app, "second message, should be ignored")
        await pilot.pause()

        assert session.consumed == ["first message"], "second submission must not reach the session"
        assert session.flushed == 1
        lines_after = _plain_text(_log(app))
        assert lines_after == lines_before + "\n" + t("tui.turn_still_pending"), (
            "the only new content for the dropped submission must be the "
            "one-time rate-limited ack line"
        )
        assert _user_input(app).value == "second message, should be ignored", (
            "typed text must NOT be cleared for a dropped submission"
        )


@pytest.mark.asyncio
async def test_turn_watchdog_fires_and_writes_the_timeout_line() -> None:
    """No reply within the budget: the watchdog ends the turn and paints a timeout line."""
    session = _RecordingSession()
    app = AlfredTuiApp(session=session, turn_timeout_seconds=_FAST_TIMEOUT_SECONDS)
    async with app.run_test() as pilot:
        await _submit(app, "hello alfred")

        # Outlive the short watchdog window by a comfortable margin — a real
        # `asyncio.sleep`, during which the app's own message loop keeps
        # running and eventually processes the watchdog's queued callback.
        await pilot.pause(_FAST_TIMEOUT_SECONDS * 20)

        input_widget = _user_input(app)
        assert app._turn_pending is False
        assert input_widget.disabled is False
        rendered = _plain_text(_log(app))
    expected = t("tui.turn_timeout", seconds=int(_FAST_TIMEOUT_SECONDS))
    assert expected in rendered


@pytest.mark.asyncio
async def test_watchdog_does_not_fire_after_a_reply_arrives() -> None:
    """A reply that beats the watchdog prevents the timeout line from ever appearing."""
    session = _RecordingSession()
    app = AlfredTuiApp(session=session, turn_timeout_seconds=_FAST_TIMEOUT_SECONDS)
    async with app.run_test() as pilot:
        # `_submit` + `write_outbound` back-to-back, with no `pilot.pause()`
        # (real time) in between, so the reply reaches `_end_turn()` — and
        # stops the watchdog `Timer` — as close to instantly as possible
        # after arming, leaving the short window as little chance as
        # possible to have already fired.
        await _submit(app, "hello alfred")
        app.write_outbound("a reply that beats the clock")
        await pilot.pause()
        assert app._turn_pending is False
        assert app._turn_watchdog is None, "the watchdog Timer must be stopped, not merely ignored"

        # Outlive the watchdog window; if the timer were not truly stopped,
        # this is where a stray timeout line would appear.
        await pilot.pause(_FAST_TIMEOUT_SECONDS * 20)

        rendered = _plain_text(_log(app))
    expected = t("tui.turn_timeout", seconds=int(_FAST_TIMEOUT_SECONDS))
    assert expected not in rendered
    assert "a reply that beats the clock" in rendered


@pytest.mark.asyncio
async def test_watchdog_callback_after_turn_already_ended_is_a_safe_no_op() -> None:
    """The same-tick race ``_on_turn_timeout``'s idempotence guard exists for:
    ``Timer.stop()`` cannot un-queue a callback the message pump already
    scheduled onto the CURRENT tick, so a reply that lands in the same tick
    as the watchdog's expiry can still reach ``_on_turn_timeout`` AFTER
    ``_end_turn()`` already ran via the reply path (``write_outbound`` /
    ``set_turn_failed``). Simulated directly here — real same-tick Textual
    scheduling would be flaky to construct reliably: end the turn normally
    via ``write_outbound``, THEN call ``_on_turn_timeout()`` directly,
    standing in for the stale queued callback the real ``Timer.stop()``
    couldn't have prevented.

    Distinct from ``test_watchdog_does_not_fire_after_a_reply_arrives``
    above (which proves the watchdog ``Timer`` is genuinely STOPPED and so
    never fires at all) and from ``test_stale_outbound_reply_does_not_clobber_the_next_turn``
    below (which drives ``_on_turn_timeout`` to ABANDON a still-pending turn,
    the opposite direction of this race) — this is the callback firing
    AFTER the turn already ended through the normal path, which neither of
    those covers.
    """
    session = _RecordingSession()
    app = AlfredTuiApp(session=session, turn_timeout_seconds=_MODERATE_TIMEOUT_SECONDS)
    async with app.run_test() as pilot:
        await _submit(app, "hello alfred")
        await pilot.pause()
        assert app._turn_pending is True  # sanity: turn genuinely pending

        app.write_outbound("a normal reply that ends the turn")
        await pilot.pause()
        assert app._turn_pending is False  # sanity: the reply really did end it
        rendered_before = _plain_text(_log(app))

        # The stale queued callback: fires AFTER the turn already ended,
        # standing in for a callback the message pump had already scheduled
        # onto this tick before `Timer.stop()` could un-queue it.
        app._on_turn_timeout()
        await pilot.pause()

        assert app._turn_pending is False, "the guard must not toggle pending back on"
        assert app._stale_turns_awaiting_signal == 0, (
            "a stale call caught by the guard must never reach the debt-counter increment"
        )
        assert app._stale_debt_expiries == [], (
            "and must therefore arm no debt-expiry timer either (#594 R1) — the "
            "increment and its expiry timer are one indivisible step"
        )
        rendered_after = _plain_text(_log(app))
    assert rendered_after == rendered_before, (
        "a stale watchdog callback for an already-ended turn must add nothing to the transcript"
    )
    timeout_line = t("tui.turn_timeout", seconds=int(_MODERATE_TIMEOUT_SECONDS))
    assert timeout_line not in rendered_after


@pytest.mark.asyncio
@pytest.mark.parametrize("stage", get_args(TurnFailureStage))
async def test_set_turn_failed_renders_localized_copy_and_clears_pending(
    stage: TurnFailureStage,
) -> None:
    """A core ``turn.failed`` notification paints the matching copy and ends the turn."""
    session = _RecordingSession()
    app = AlfredTuiApp(session=session, turn_timeout_seconds=_MODERATE_TIMEOUT_SECONDS)
    async with app.run_test() as pilot:
        await _submit(app, "hello alfred")
        await pilot.pause()
        assert app._turn_pending is True

        app.set_turn_failed(stage)
        await pilot.pause()

        input_widget = _user_input(app)
        assert app._turn_pending is False
        assert input_widget.disabled is False
        rendered = _plain_text(_log(app))
    assert _turn_failure_message(stage) in rendered


def test_turn_failure_message_is_exhaustive_over_the_wire_literal() -> None:
    """``_turn_failure_message`` handles every stage the closed wire Literal allows.

    A future stage added to ``TurnFailureStage`` without a corresponding
    ``match`` arm here would hit the ``assert_never`` fallthrough, which
    raises at runtime — turning a silently-unrendered turn state into an
    immediate, loud test failure instead.
    """
    for stage in get_args(TurnFailureStage):
        message = _turn_failure_message(stage)
        assert isinstance(message, str)
        assert message  # never blank


@pytest.mark.asyncio
async def test_stale_outbound_reply_does_not_clobber_the_next_turn() -> None:
    """A late reply for an already-timed-out turn must not touch the NEW turn.

    Concrete race (comms-engineer finding on PR #594): turn 1 outruns the
    watchdog and is abandoned client-side (pending cleared, watchdog stopped);
    the operator resubmits as turn 2 (pending set again, a NEW watchdog
    armed); THEN turn 1's late reply finally arrives from the core (it kept
    running server-side even though the client gave up on it). Before this
    fix, ``write_outbound`` called ``_end_turn()`` unconditionally — stopping
    turn 2's watchdog and clearing ``_turn_pending`` even though turn 2 is
    genuinely still in flight, which is the exact "operator can't tell what
    state their turn is in" problem #593 exists to fix, recurring one layer
    up. Turn 1's late message must still render (informative), but must not
    end turn 2's turn.

    Uses ``_MODERATE_TIMEOUT_SECONDS`` for the app (not ``_FAST_TIMEOUT_SECONDS``)
    so turn 2's OWN watchdog cannot spuriously fire for real during this
    test's several ``pilot.pause()`` calls — each costs "tens of
    milliseconds" of real wall-clock idle-detection overhead (see the module
    comment above ``_MODERATE_TIMEOUT_SECONDS``), which would rival a 0.05s
    watchdog and make the test racy. Turn 1's abandonment is instead driven
    directly through ``_on_turn_timeout`` — the exact callback a real watchdog
    invokes on expiry, just invoked deterministically rather than by sleeping
    through the real timer (mirroring how ``_submit`` above drives
    ``on_input_submitted`` directly for the same determinism reason).
    """
    session = _RecordingSession()
    app = AlfredTuiApp(session=session, turn_timeout_seconds=_MODERATE_TIMEOUT_SECONDS)
    async with app.run_test() as pilot:
        await _submit(app, "first message")
        await pilot.pause()
        assert app._turn_pending is True  # sanity: turn 1 really is pending

        # Simulate turn 1's watchdog expiring (same code path a real firing
        # takes) without waiting out the real timeout window.
        app._on_turn_timeout()
        assert app._turn_pending is False  # sanity: turn 1 really was abandoned
        assert app._stale_turns_awaiting_signal == 1
        assert len(app._stale_debt_expiries) == 1  # ...with its expiry armed (#594 R1)

        await _submit(app, "second message")
        await pilot.pause()
        assert app._turn_pending is True  # sanity: turn 2 is genuinely pending
        turn_2_watchdog = app._turn_watchdog
        assert turn_2_watchdog is not None

        # Turn 1's late reply finally arrives.
        app.write_outbound("stale reply for the abandoned first turn")
        await pilot.pause()

        assert app._turn_pending is True, (
            "turn 2's pending indicator must survive turn 1's late reply"
        )
        assert app._turn_watchdog is turn_2_watchdog, (
            "turn 2's watchdog must not be stopped by turn 1's late reply"
        )
        assert app._stale_turns_awaiting_signal == 0
        assert app._stale_debt_expiries == [], (
            "the settled debt's expiry timer must be stopped and dropped, not "
            "left armed to write the SAME debt off a second time (#594 R1)"
        )
        input_widget = _user_input(app)
        assert input_widget.disabled is True, "input must stay disabled — turn 2 is still pending"

        # Turn 2's OWN reply then arrives normally — the debt is settled, so
        # this one DOES end the turn, exactly like the no-staleness case.
        app.write_outbound("real reply for the still-pending second turn")
        await pilot.pause()
        assert app._turn_pending is False
        assert input_widget.disabled is False

        rendered = _plain_text(_log(app))
    assert "stale reply for the abandoned first turn" in rendered, (
        "a late reply for an abandoned turn is still informative and must render"
    )
    assert "real reply for the still-pending second turn" in rendered


@pytest.mark.asyncio
async def test_stale_turn_failed_does_not_clobber_the_next_turn() -> None:
    """Same race as above, but the late signal is a ``turn.failed`` rather than a reply.

    See ``test_stale_outbound_reply_does_not_clobber_the_next_turn`` for why
    ``_MODERATE_TIMEOUT_SECONDS`` + a direct ``_on_turn_timeout()`` call (not
    a real sleep through ``_FAST_TIMEOUT_SECONDS``) is used to drive turn 1's
    abandonment deterministically.
    """
    session = _RecordingSession()
    app = AlfredTuiApp(session=session, turn_timeout_seconds=_MODERATE_TIMEOUT_SECONDS)
    async with app.run_test() as pilot:
        await _submit(app, "first message")
        await pilot.pause()
        assert app._turn_pending is True  # sanity: turn 1 really is pending

        app._on_turn_timeout()
        assert app._turn_pending is False  # sanity: turn 1 really was abandoned

        await _submit(app, "second message")
        await pilot.pause()
        assert app._turn_pending is True  # sanity: turn 2 is genuinely pending
        turn_2_watchdog = app._turn_watchdog
        assert turn_2_watchdog is not None

        # Turn 1's late `turn.failed` finally arrives.
        app.set_turn_failed("internal_error")
        await pilot.pause()

        assert app._turn_pending is True, (
            "turn 2's pending indicator must survive turn 1's late turn.failed"
        )
        assert app._turn_watchdog is turn_2_watchdog, (
            "turn 2's watchdog must not be stopped by turn 1's late turn.failed"
        )
        assert app._stale_turns_awaiting_signal == 0
        assert app._stale_debt_expiries == []  # settled debt -> expiry stopped (#594 R1)
        input_widget = _user_input(app)
        assert input_widget.disabled is True, "input must stay disabled — turn 2 is still pending"

        rendered = _plain_text(_log(app))
    assert _turn_failure_message("internal_error") in rendered, (
        "a late turn.failed for an abandoned turn is still informative and must render"
    )


# ---------------------------------------------------------------------------
# #594 R1: the stale-turn debt is BOUNDED IN TIME.
#
# The debt counter above encodes "the core still owes this client exactly one
# late completion signal for each watchdog-abandoned turn". The core only ever
# offered that as BEST EFFORT — the dominant real-world miss is the
# unbound-identity path (#592), which writes a binding-request audit row and
# puts NOTHING on the wire. With no expiry, ONE missed signal desynchronized
# the client permanently: the next turn's own correct reply got consumed as the
# missing late signal, so it rendered but never released the input, and that
# turn then timed out and printed a red timeout line UNDER an answer that had
# already succeeded — once per turn, forever, until a TUI restart.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_stale_turn_debt_expires_after_one_timeout_window() -> None:
    """A late signal that NEVER comes must not eat the next turn's own reply.

    The regression this whole section exists for. Turn 1 is abandoned by its
    watchdog and no signal for it is ever sent (the unbound-identity /
    burst-drop / transient-audit-fault class); one further watchdog window
    later the debt must have been written off, so turn 2's genuine reply ends
    turn 2 instead of being consumed as turn 1's missing signal.

    Deliberately driven by REAL timers end to end (``_FAST_TIMEOUT_SECONDS``
    plus the file's usual 20x pause margin) rather than by calling the
    callbacks directly: the whole point of the fix is that an expiry timer is
    genuinely ARMED, which a direct-call test could not distinguish from a
    no-op. The single pause deliberately spans BOTH windows (the watchdog at
    1x, then the debt's expiry at 2x) — the intermediate "debt is exactly 1"
    state lives in a 1x-to-2x gap far too narrow to sample reliably against
    ``pilot.pause``'s own tens-of-milliseconds idle-detection overhead, so
    the timeout line in the transcript stands in as proof that the watchdog
    genuinely fired. Fails on pre-#594-R1 code at the first assertion below
    (the debt would still be 1) and again at the last (turn 2 never ends).
    """
    session = _RecordingSession()
    app = AlfredTuiApp(session=session, turn_timeout_seconds=_FAST_TIMEOUT_SECONDS)
    async with app.run_test() as pilot:
        await _submit(app, "first message")

        # Turn 1's real watchdog expires (nothing is ever sent for it), then
        # its debt's own expiry window elapses too.
        await pilot.pause(_FAST_TIMEOUT_SECONDS * 20)
        assert app._turn_pending is False  # sanity: turn 1 really was abandoned
        assert t("tui.turn_timeout", seconds=int(_FAST_TIMEOUT_SECONDS)) in _plain_text(
            _log(app)
        ), "sanity: the real watchdog genuinely fired and incurred the debt"
        assert app._stale_turns_awaiting_signal == 0, (
            "a debt whose late signal never arrives must be written off after "
            "one watchdog window, not held forever"
        )
        assert app._stale_debt_expiries == []

        # Turn 2 now behaves like any first turn: its OWN reply ends it.
        # Submitted and answered back-to-back (no real-time pause in between)
        # so turn 2's own short watchdog cannot fire mid-test.
        await _submit(app, "second message")
        app.write_outbound("real reply for the second turn")
        await pilot.pause()

        assert app._turn_pending is False, (
            "turn 2's own reply must END turn 2 — before this fix it was "
            "swallowed as turn 1's never-arriving late signal, leaving the "
            "input dead until turn 2's watchdog painted a false timeout line"
        )
        assert _user_input(app).disabled is False
        rendered = _plain_text(_log(app))
    assert "real reply for the second turn" in rendered


@pytest.mark.asyncio
async def test_a_discharged_debt_cannot_decrement_twice() -> None:
    """A debt settled by a real late signal must not ALSO be written off.

    Two halves, because there are two ways the double-decrement could land:
    the expiry ``Timer`` firing later on its own (closed by ``.stop()`` in
    ``_discharge_stale_turn_debt``), and the un-un-queueable same-tick
    callback that ``Timer.stop()`` structurally cannot prevent (closed by
    ``_expire_stale_turn_debt``'s ``> 0`` guard — the same race
    ``test_watchdog_callback_after_turn_already_ended_is_a_safe_no_op``
    pins for the watchdog). A double decrement would drive the count negative
    and re-introduce the drift in the opposite direction.

    Turn 1's abandonment is driven directly through ``_on_turn_timeout`` (the
    exact callback a real watchdog invokes) so the late reply lands INSIDE
    the debt's window with no real-time race — with equal-length windows,
    sleeping to the watchdog but not past the expiry is a ~50ms target that
    ``pilot.pause``'s own overhead cannot hit reliably.
    """
    session = _RecordingSession()
    app = AlfredTuiApp(session=session, turn_timeout_seconds=_FAST_TIMEOUT_SECONDS)
    async with app.run_test() as pilot:
        await _submit(app, "first message")
        app._on_turn_timeout()  # turn 1 abandoned -> debt 1, expiry armed
        assert app._stale_turns_awaiting_signal == 1  # sanity
        assert len(app._stale_debt_expiries) == 1

        # Turn 1's late reply DOES arrive — the debt is genuinely settled.
        app.write_outbound("late reply for the abandoned first turn")
        assert app._stale_turns_awaiting_signal == 0
        assert app._stale_debt_expiries == []

        # Half 1: the stopped expiry must never fire at all.
        await pilot.pause(_FAST_TIMEOUT_SECONDS * 20)
        assert app._stale_turns_awaiting_signal == 0, (
            "a settled debt's expiry timer must have been stopped, not left "
            "armed to decrement the count a second time"
        )

        # Half 2: the same-tick callback the pump had already scheduled before
        # `.stop()` could un-queue it, invoked directly (the file's standard
        # deterministic stand-in for that race).
        app._expire_stale_turn_debt()
        assert app._stale_turns_awaiting_signal == 0, (
            "an expiry for an already-settled debt must be a no-op, never a decrement below zero"
        )

        # And the ledger being genuinely settled, turn 2's own reply ends it.
        await _submit(app, "second message")
        app.write_outbound("real reply for the second turn")
        await pilot.pause()
        assert app._turn_pending is False
        assert _user_input(app).disabled is False


@pytest.mark.asyncio
async def test_two_abandoned_turns_expire_independently() -> None:
    """Two outstanding debts settle one-for-one: one by signal, one by expiry.

    Driven through the callbacks directly (``_MODERATE_TIMEOUT_SECONDS``, the
    same idiom the stale-signal tests above use) rather than through real
    timers: two debts can only be outstanding SIMULTANEOUSLY if the second
    abandonment happens inside the first debt's window, which equal-length
    real windows cannot produce deterministically.
    """
    session = _RecordingSession()
    app = AlfredTuiApp(session=session, turn_timeout_seconds=_MODERATE_TIMEOUT_SECONDS)
    async with app.run_test() as pilot:
        await _submit(app, "first message")
        await pilot.pause()
        app._on_turn_timeout()  # turn 1 abandoned -> debt 1

        await _submit(app, "second message")
        await pilot.pause()
        app._on_turn_timeout()  # turn 2 abandoned -> debt 2

        assert app._stale_turns_awaiting_signal == 2
        assert len(app._stale_debt_expiries) == 2

        # One late signal arrives — it settles exactly ONE debt (they are
        # fungible; nothing correlates a signal with a particular turn).
        app.write_outbound("late reply for one of the abandoned turns")
        await pilot.pause()
        assert app._stale_turns_awaiting_signal == 1
        assert len(app._stale_debt_expiries) == 1

        # The OTHER debt's window then elapses with nothing ever arriving.
        # A real expiry's one-shot `Timer` has already fired by the time its
        # callback runs; this direct stand-in leaves the real handle armed, so
        # stop it here to keep teardown free of a dangling 5s timer.
        remaining_expiry = app._stale_debt_expiries[0]
        app._expire_stale_turn_debt()
        remaining_expiry.stop()

        assert app._stale_turns_awaiting_signal == 0
        assert app._stale_debt_expiries == [], "no orphan expiry handles may survive"


@pytest.mark.asyncio
async def test_unmount_stops_every_live_stale_debt_timer() -> None:
    """Teardown disarms outstanding debt timers rather than leaking them.

    A debt incurred shortly before the app closes owns a one-shot ``Timer``
    armed for a full ``_turn_timeout_seconds`` that nothing else would ever
    stop — the dangling-``Timer`` leak this repo has a documented history of,
    and which this file's ``-W error::ResourceWarning`` runs exist to catch.
    """
    session = _RecordingSession()
    app = AlfredTuiApp(session=session, turn_timeout_seconds=_MODERATE_TIMEOUT_SECONDS)
    async with app.run_test() as pilot:
        await _submit(app, "first message")
        await pilot.pause()
        app._on_turn_timeout()
        assert len(app._stale_debt_expiries) == 1  # sanity: genuinely armed at teardown

    assert app._stale_debt_expiries == [], (
        "on_unmount must stop and drop every still-armed debt-expiry timer"
    )


@pytest.mark.asyncio
async def test_flush_failure_paints_error_class_and_reraises() -> None:
    """A dead local wire ends the turn immediately, renders the exception CLASS
    NAME (never ``str(exc)``), and re-raises rather than swallowing the fault.

    ``_submit`` calls ``on_input_submitted`` directly (not via a simulated
    keypress dispatched through Textual's message pump), so the ``raise`` in
    its except-branch propagates straight out of this ``await`` — exactly
    where ``pytest.raises`` catches it — rather than being intercepted by
    Textual's own ``_handle_exception``/panic machinery, which would put the
    app into a teardown state this test has no need to reason about.
    """
    session = _FailingSession()
    app = AlfredTuiApp(session=session, turn_timeout_seconds=_MODERATE_TIMEOUT_SECONDS)
    async with app.run_test() as pilot:
        with pytest.raises(RuntimeError):
            await _submit(app, "hello alfred")
        await pilot.pause()
        input_widget = _user_input(app)
        rendered = _plain_text(_log(app))
        assert app._turn_pending is False, "a local send failure must end the turn immediately"
        assert input_widget.disabled is False
        # Computed via `t("tui.alfred_error", ...)` (same call the app makes),
        # not asserted as a hardcoded literal — the class name must reach the
        # transcript, never `str(exc)`.
        assert t("tui.alfred_error", error="RuntimeError") in rendered
        assert "transport internals" not in rendered, (
            "str(exc) must never reach the operator-facing transcript"
        )


# ---------------------------------------------------------------------------
# Live elapsed-time counter + rate-limited dropped-keystroke ack (#594 Fix-10).
#
# The operator's own calibration: the elapsed-time indicator must be a live
# widget SEPARATE from the transcript (never a new RichLog line), while a
# dropped second Enter DOES deserve exactly one RichLog line -- rate-limited
# so mashing Enter doesn't spam the transcript.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_elapsed_counter_hidden_before_any_turn_starts() -> None:
    """No turn yet: the live elapsed-time counter widget is not displayed."""
    app = AlfredTuiApp(session=_RecordingSession())
    async with app.run_test() as pilot:
        await pilot.pause()
        status = app.query_one("#turn_status", Static)
        assert status.display is False


@pytest.mark.asyncio
async def test_elapsed_counter_shows_after_a_tick_and_is_never_logged() -> None:
    """After >=1 real tick, the counter shows plausible elapsed text as a
    LIVE WIDGET -- and that exact text never reaches the RichLog transcript.

    This is the operator's explicit instruction ("shouldn't be logged, I
    want an elapsed time counter that isn't logged") locked into a test:
    the assertion on ``rendered_log`` below is what would fail if the
    counter were implemented as a new ``RichLog`` line instead of the
    separate ``#turn_status`` widget.
    """
    session = _RecordingSession()
    app = AlfredTuiApp(session=session, turn_timeout_seconds=_MODERATE_TIMEOUT_SECONDS)
    async with app.run_test() as pilot:
        await _submit(app, "hello alfred")
        await pilot.pause()
        assert app._turn_pending is True  # sanity: turn genuinely pending

        # Outlive at least one 1s tick of the elapsed-counter's repeating
        # timer by a comfortable real-time margin.
        await pilot.pause(1.1)

        status = app.query_one("#turn_status", Static)
        assert status.display is True
        assert app._turn_elapsed_seconds >= 1, "at least one tick must have landed"
        expected = t("tui.thinking_elapsed", seconds=app._turn_elapsed_seconds)
        assert _plain_text_static(status) == expected

        rendered_log = _plain_text(_log(app))
    assert expected not in rendered_log, (
        "the elapsed-time counter must never be written into the RichLog transcript"
    )


@pytest.mark.asyncio
async def test_elapsed_counter_hidden_again_after_turn_ends() -> None:
    """A normal reply ends the turn and re-hides the elapsed-time counter."""
    session = _RecordingSession()
    app = AlfredTuiApp(session=session, turn_timeout_seconds=_MODERATE_TIMEOUT_SECONDS)
    async with app.run_test() as pilot:
        await _submit(app, "hello alfred")
        await pilot.pause(1.1)
        status = app.query_one("#turn_status", Static)
        assert status.display is True  # sanity: it was showing while pending

        app.write_outbound("hello back from alfred")
        await pilot.pause()

        assert status.display is False


@pytest.mark.asyncio
async def test_second_drop_while_pending_writes_exactly_one_rate_limited_ack_line() -> None:
    """The FIRST dropped Enter while a turn is pending writes ONE dim ack
    line into the transcript; a SECOND dropped Enter during the SAME pending
    turn adds no further line (rate-limited, #594 Fix-10).
    """
    session = _RecordingSession()
    app = AlfredTuiApp(session=session, turn_timeout_seconds=_MODERATE_TIMEOUT_SECONDS)
    async with app.run_test() as pilot:
        await _submit(app, "first message")
        await pilot.pause()
        assert app._turn_pending is True

        # Second Enter while pending: the FIRST drop for this turn, earns
        # exactly one ack line.
        await _submit(app, "second message, dropped")
        await pilot.pause()
        rendered = _plain_text(_log(app))
        assert rendered.count(t("tui.turn_still_pending")) == 1

        # Third Enter while still pending: a SECOND drop for this same
        # turn, must add no further line.
        await _submit(app, "third message, dropped")
        await pilot.pause()
        rendered = _plain_text(_log(app))
    assert rendered.count(t("tui.turn_still_pending")) == 1, (
        "a second dropped keystroke in the same pending turn must not add another ack line"
    )


@pytest.mark.asyncio
async def test_new_turn_gets_its_own_fresh_dropped_keystroke_ack() -> None:
    """The one-time ack flag resets per-turn: a NEW pending turn earns its
    own fresh ack rather than staying permanently exhausted after the first
    ever drop (#594 Fix-10).
    """
    session = _RecordingSession()
    app = AlfredTuiApp(session=session, turn_timeout_seconds=_MODERATE_TIMEOUT_SECONDS)
    async with app.run_test() as pilot:
        await _submit(app, "first message")
        await pilot.pause()
        await _submit(app, "dropped during first turn")
        await pilot.pause()
        rendered = _plain_text(_log(app))
        assert rendered.count(t("tui.turn_still_pending")) == 1

        app.write_outbound("reply ending the first turn")
        await pilot.pause()
        assert app._turn_pending is False  # sanity: the first turn really ended

        await _submit(app, "second message")
        await pilot.pause()
        assert app._turn_pending is True  # sanity: a new turn is genuinely pending
        await _submit(app, "dropped during second turn")
        await pilot.pause()

        rendered = _plain_text(_log(app))
    assert rendered.count(t("tui.turn_still_pending")) == 2, (
        "a NEW pending turn must get its own fresh one-time ack, not stay "
        "permanently exhausted after the first ever drop"
    )
