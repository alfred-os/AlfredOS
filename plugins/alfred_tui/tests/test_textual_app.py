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
        assert lines_after == lines_before, (
            "no new line should be written for the ignored submission"
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
        input_widget = _user_input(app)
        assert input_widget.disabled is True, "input must stay disabled — turn 2 is still pending"

        rendered = _plain_text(_log(app))
    assert _turn_failure_message("internal_error") in rendered, (
        "a late turn.failed for an abandoned turn is still informative and must render"
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
