"""Textual app shell for the AlfredOS TUI MCP-plugin adapter.

Verbatim move from ``src/alfred/comms/tui.py`` (PR-S4-10). The widget tree
(scrolling RichLog conversation log + bottom Input box) is preserved one-for-one
from the Slice-1/2 in-process TUI; only the *bindings* between the widgets and
the surrounding adapter changed.

The Slice-1/2 app called an in-process orchestrator inside ``on_input_submitted``
and owned the trust-tier tagging + working-memory lifecycle itself. In the
comms-MCP rewrite those responsibilities move host-side: the app now feeds a
:class:`_SessionLike` collaborator's ``consume_user_input`` + ``flush_keystroke_batch``
on Enter (the session turns each batch into an ``inbound.message`` wire
notification), and renders host-delivered outbound via :meth:`write_outbound`
(the ``outbound.message`` wire handler calls into it). The app holds NO
orchestrator, identity resolver, working pool, or tier-tagging logic — that all
lives across the wire boundary now.

Operator-facing strings go through ``alfred.i18n.t`` using the EXISTING ``tui.*``
catalog keys (unchanged from the Slice-1 app); no new catalog entries are
introduced by the move.
"""

from __future__ import annotations

from typing import Final, Protocol, assert_never

from rich.markup import escape
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.reactive import reactive
from textual.timer import Timer
from textual.widgets import Input, RichLog, Static

from alfred.comms_mcp.protocol import LINK_RECONNECTING, LINK_UNAVAILABLE, TurnFailureStage
from alfred.i18n import t

# Map the gateway's id-less ``link.*`` STATE method (Spec A G5 / ADR-0031) to the
# LOCAL catalog key the TUI renders. The gateway carries NO operator text — only
# the state — so the banner copy is the TUI's own localized ``t()`` render. The
# ``link.restored`` state is absent: it CLEARS the banner (no text to show).
# ``link.unavailable`` is vocab-complete but latent until G4 wires its trigger.
_LINK_STATE_BANNER_KEY: dict[str, str] = {
    LINK_RECONNECTING: "tui.banner.reconnecting",
    LINK_UNAVAILABLE: "tui.banner.unavailable",
}


def _reserve_banner_catalog_keys() -> None:
    """Pybabel-extraction anchor for the reconnect-banner catalog keys.

    The banner copy is rendered via ``t(banner_key)`` where ``banner_key`` comes
    from :data:`_LINK_STATE_BANNER_KEY` — a VARIABLE, which ``pybabel extract``
    cannot follow. These literal ``t(...)`` calls give the extractor a static
    reference so ``tui.banner.*`` are active msgids (not marked obsolete on the
    next ``pybabel update``, which the i18n drift gate trips on). The
    ``tui.banner.restored`` key is reserved for symmetry/future use even though
    the restored STATE clears the banner rather than rendering text. Never called.
    """
    t("tui.banner.reconnecting")
    t("tui.banner.restored")
    t("tui.banner.unavailable")


# Historical value from the deleted in-process TUI (PR-S4-10 removed it along
# with the rest of the old turn lifecycle). Must comfortably exceed a
# multi-completion Act-loop turn (live since #410 PR3), not just one
# completion — a tight timeout would fire mid-turn on legitimate multi-step
# work and paint a false failure.
TURN_TIMEOUT_SECONDS: Final[float] = 90.0


def _turn_failure_message(stage: TurnFailureStage) -> str:
    """Localized operator copy for a core turn-failure stage (#593).

    Deliberately NOT the ``_LINK_STATE_BANNER_KEY`` dict + ``t(variable)`` +
    ``_reserve_banner_catalog_keys`` anchor shape used above for the banner:
    each arm here is a LITERAL ``t("...")`` call, so ``pybabel extract`` sees
    all three msgids statically without needing a separate reservation
    function.

    Exhaustive via ``assert_never`` over the CLOSED wire ``TurnFailureStage``
    Literal — a future stage added to the wire type without a decision here
    is a type-check failure, not a silent unrendered turn state.
    """
    match stage:
        case "refused":
            return t("tui.turn_failed.refused")
        case "budget_exhausted":
            return t("tui.turn_failed.budget_exhausted")
        case "internal_error":
            return t("tui.turn_failed.internal_error")
    assert_never(stage)  # pragma: no cover


class _SessionLike(Protocol):
    """The structural seam the app needs from its session.

    Keeping the app decoupled from the concrete :class:`alfred_tui.session.TuiSession`
    (via a Protocol, not a direct import) preserves the Slice-1 discipline of a
    widget tree that is testable without the surrounding adapter — a recording
    double satisfies this Protocol in the widget tests.
    """

    async def consume_user_input(self, chunk: str) -> None:
        raise NotImplementedError

    async def flush_keystroke_batch(self) -> None:
        raise NotImplementedError


class AlfredTuiApp(App[None]):
    """Textual app: scrolling conversation log + bottom input box.

    Enter feeds the typed line into the session as one keystroke-batch; the
    session emits the ``inbound.message`` notification. Host-delivered outbound
    is painted via :meth:`write_outbound`.
    """

    CSS = """
    Screen { layout: vertical; }
    #link_banner { dock: top; width: 100%; padding: 0 1; background: $warning; color: $text; }
    #turn_status { dock: top; width: 100%; padding: 0 1; color: $text-muted; }
    #conversation_log { height: 1fr; border: solid white; padding: 1; }
    #user_input { dock: bottom; }
    #user_input.busy { background: $boost; color: $text-muted; }
    """

    # The current gateway link-state banner key, or ``None`` when the link is
    # healthy (banner hidden). A Textual ``reactive`` so a ``set_link_state``
    # mutation drives the ``watch_*`` render on the app's own loop (M1) — no
    # off-loop ``call_from_thread`` (the cohost pump shares this loop).
    _link_banner_key: reactive[str | None] = reactive[str | None](None)

    # The turn-in-flight indicator. `True` between the operator pressing Enter
    # and whichever of {reply, turn.failed, watchdog} lands first. A Textual
    # `reactive` so every mutation drives `watch__turn_pending` on the app's
    # OWN loop — the wire pump shares that loop, so this is a DIRECT set,
    # never `call_from_thread` (same M1 discipline as `_link_banner_key`).
    _turn_pending: reactive[bool] = reactive[bool](default=False)

    # Seconds elapsed since the current turn began, ticked by a repeating
    # timer while `_turn_pending` is `True` (#594 Fix-10). `always_update`
    # is deliberate: the reset-to-0 at the START of a new turn (see
    # `on_input_submitted`) must repaint even when the PREVIOUS turn's own
    # elapsed count happened to already be 0 (the very first turn of the
    # app's lifetime) — without it, that one turn's counter would stay
    # hidden until the first tick a full second later instead of showing
    # "0s" immediately alongside the pending indicator. This drives a
    # SEPARATE, non-logged widget (`#turn_status`) — deliberately NOT new
    # `RichLog` lines; see `watch__turn_elapsed_seconds`.
    _turn_elapsed_seconds: reactive[int] = reactive[int](default=0, always_update=True)

    BINDINGS = [  # noqa: RUF012  # Textual reads BINDINGS off the class; mutable is the documented contract.
        # Footer descriptions are operator-facing and go through t() per
        # CLAUDE.md i18n hard rule #1. Existing tui.* catalog keys (unchanged
        # from the Slice-1 app) — the move introduces no new catalog entries.
        Binding("ctrl+c", "quit", t("tui.binding.quit"), show=True, priority=True),
        Binding("ctrl+q", "quit", t("tui.binding.quit"), show=True),
    ]

    def __init__(
        self, *, session: _SessionLike, turn_timeout_seconds: float = TURN_TIMEOUT_SECONDS
    ) -> None:
        super().__init__()
        self._session = session
        self._turn_timeout_seconds = turn_timeout_seconds
        # Plain instance state, not a reactive — a `Timer` handle is not a
        # render input, and tearing one down on every reactive-diff cycle
        # would be spurious churn.
        self._turn_watchdog: Timer | None = None
        # Same reasoning as `_turn_watchdog` above: the REPEATING timer handle
        # that drives the live elapsed-time counter (#594 Fix-10) is plain
        # instance state, not a reactive.
        self._turn_elapsed_timer: Timer | None = None
        # How many watchdog-abandoned turns the client still owes exactly one
        # late completion signal (a reply or a `turn.failed`) for. See
        # `_resolve_pending_turn`.
        self._stale_turns_awaiting_signal: int = 0
        # Whether the operator has already been told (via ONE dim log line)
        # that their last keystroke was dropped because a turn is still
        # pending. Reset to `False` at the start of each new turn (see
        # `on_input_submitted`) so a NEW pending turn gets its own fresh
        # one-time acknowledgement rather than being permanently exhausted
        # after the first ever drop (#594 Fix-10).
        self._drop_acked_for_current_turn: bool = False

    def compose(self) -> ComposeResult:
        # The reconnect banner is mounted hidden (``display=False``); it is shown
        # and its text set by ``watch__link_banner_key`` when the gateway signals a
        # core-link gap, and re-hidden on restore.
        banner = Static(id="link_banner")
        banner.display = False
        yield banner
        # The live elapsed-time counter (#594 Fix-10). Mounted hidden, same as
        # the banner above; shown by ``watch__turn_elapsed_seconds`` while a
        # turn is pending and re-hidden by ``_end_turn`` on completion. Docked
        # top like the banner, but mounted AFTER it so the two stack rather
        # than overlap (Textual docks in mount order along the same edge).
        turn_status = Static(id="turn_status")
        turn_status.display = False
        yield turn_status
        yield Vertical(
            RichLog(id="conversation_log", highlight=True, markup=True, wrap=True),
            Input(placeholder=t("tui.input_placeholder"), id="user_input"),
        )

    async def on_mount(self) -> None:
        """Place initial focus on the input box.

        Textual defaults focus to the first focusable widget in the compose
        tree — that's the RichLog, not the Input — so without this the first
        keystrokes silently scroll the log rather than typing into the input.
        """
        self.query_one("#user_input", Input).focus()

    def _arm_turn_watchdog(self) -> None:
        """One-shot watchdog for the in-flight turn. Replaces any prior timer.

        Uses Textual's ``self.set_timer`` — NOT ``asyncio.wait_for`` — because
        the turn is no longer locally awaitable: ``inbound.message`` is a
        fire-and-forget wire notification, so there is no local coroutine to
        wrap in a timeout. The watchdog is a separate, independently-scheduled
        callback racing the reply/failure paths, not a wrapper around them.
        """
        self._stop_turn_watchdog()
        self._turn_watchdog = self.set_timer(
            self._turn_timeout_seconds, self._on_turn_timeout, name="alfred-turn-watchdog"
        )

    def _stop_turn_watchdog(self) -> None:
        if self._turn_watchdog is not None:
            self._turn_watchdog.stop()
            self._turn_watchdog = None

    def _arm_turn_elapsed_timer(self) -> None:
        """Start the repeating 1s tick driving the live elapsed-time counter.

        Unlike ``_arm_turn_watchdog``'s one-shot ``set_timer`` (fires once,
        at the timeout budget), this needs to fire every second for as long
        as the turn is pending, so it uses ``set_interval`` instead. Any
        prior timer is stopped first so a resubmission never accumulates
        stray running timers.
        """
        self._stop_turn_elapsed_timer()
        self._turn_elapsed_timer = self.set_interval(
            1.0, self._tick_turn_elapsed, name="alfred-turn-elapsed-tick"
        )

    def _stop_turn_elapsed_timer(self) -> None:
        if self._turn_elapsed_timer is not None:
            self._turn_elapsed_timer.stop()
            self._turn_elapsed_timer = None

    def _tick_turn_elapsed(self) -> None:
        """One second has passed on the current turn: bump the live counter.

        The increment alone is enough to repaint: mutating a ``reactive``
        drives ``watch__turn_elapsed_seconds`` on this same tick.
        """
        self._turn_elapsed_seconds += 1

    def _end_turn(self) -> None:
        """Release the in-flight turn: stop the watchdog + elapsed timer, hide
        the elapsed-counter widget, re-enable + refocus input.

        Hooking the elapsed-counter hide here (rather than in
        ``watch__turn_pending``/``watch__turn_elapsed_seconds``) covers all
        three ways a turn can end — a normal reply, a core-reported
        ``turn.failed``, and a watchdog timeout — since all three already
        funnel through this one method.
        """
        self._stop_turn_watchdog()
        self._stop_turn_elapsed_timer()
        self._turn_pending = False
        self.query_one("#turn_status", Static).display = False

    def _on_turn_timeout(self) -> None:
        """No reply inside the budget: tell the operator and release the input.

        Idempotence guard: ``Timer.stop()`` cannot un-queue a callback the
        message pump has ALREADY scheduled onto this tick, so a reply that
        lands in the SAME tick as the expiry can still reach here after
        ``_end_turn()`` already ran (via ``write_outbound`` or
        ``set_turn_failed``). This guard is LOAD-BEARING, not defensive
        padding: without it, a same-tick reply-then-timeout ordering would
        re-paint a timeout line — and re-arm nothing, since
        ``self._turn_pending`` is already ``False`` — for a turn that in fact
        completed, which is a lie to the operator.
        """
        self._turn_watchdog = None
        if not self._turn_pending:
            return
        # This turn is being ABANDONED client-side, not resolved — the core
        # may still be processing it and can still send a reply or
        # `turn.failed` for it later. Record that one late completion signal
        # is now owed so `_resolve_pending_turn` recognizes it as stale
        # (rather than the CURRENT turn's own signal) whenever it arrives.
        self._stale_turns_awaiting_signal += 1
        self._end_turn()
        self.query_one("#conversation_log", RichLog).write(
            f"[bold red]{t('tui.turn_timeout', seconds=int(self._turn_timeout_seconds))}[/]"
        )

    async def on_input_submitted(self, event: Input.Submitted) -> None:
        """Enter: feed the typed line to the session as one keystroke-batch.

        Empty submissions are dropped (the session's flush is a no-op on an
        empty buffer too — belt and braces). One turn at a time: while a turn
        is already pending, a submission is dropped WITHOUT clearing/echoing
        the typed text — ``watch__turn_pending`` already disables the Input,
        but a queued event can still arrive after the disable takes effect, so
        this is belt-and-braces, not the primary guard. Nothing typed is lost.

        The FIRST drop while a turn is pending writes ONE dim reassurance
        line into the transcript (rate-limited, #594 Fix-10) — an operator
        mashing Enter while Alfred is still thinking gets told once, not
        spammed once per keystroke. ``_drop_acked_for_current_turn`` gates
        this and is reset per-turn below.

        The line is echoed into the log so the operator sees their own turn
        (mirroring the Slice-1 affordance), THEN the turn is marked pending
        and the "thinking..." line written — in that order, so the echo
        always precedes the pending indicator in the transcript.
        """
        text = event.value.strip()
        if not text:
            return
        if self._turn_pending:
            if not self._drop_acked_for_current_turn:
                self.query_one("#conversation_log", RichLog).write(
                    f"[dim]{t('tui.turn_still_pending')}[/]"
                )
                self._drop_acked_for_current_turn = True
            return
        log = self.query_one("#conversation_log", RichLog)
        # ``text`` is operator-typed and echoed into a ``markup=True`` RichLog;
        # escape it so any ``[red]``/``[link=…]`` is shown literally, not parsed
        # as Rich console markup. The app-controlled label prefix keeps its
        # legitimate markup. (PR-S4-10 review #1 — markup-injection guard.)
        log.write(f"[bold cyan]{t('tui.label_you')}[/]: {escape(text)}")
        event.input.value = ""
        self._turn_pending = True  # -> watcher: disable + .busy
        # Fresh per-turn state (#594 Fix-10): the elapsed counter must not
        # carry over the PREVIOUS turn's count, and a new turn earns its own
        # one-time dropped-keystroke acknowledgement.
        self._turn_elapsed_seconds = 0
        self._drop_acked_for_current_turn = False
        log.write(f"[dim]{t('tui.thinking')}[/]")
        self._arm_turn_watchdog()
        self._arm_turn_elapsed_timer()
        try:
            await self._session.consume_user_input(text)
            await self._session.flush_keystroke_batch()
        except Exception as exc:
            # The inbound never reached the wire. No reply can ever come, so
            # release the turn NOW rather than making the operator wait out
            # the full watchdog for a failure we already know about. The
            # rendered line carries the exception CLASS NAME only, never
            # `str(exc)` (which could leak transport internals into the
            # transcript). Re-raised: this is a dead local wire, and
            # swallowing it here would be the exact silent-failure shape
            # #593 is about.
            self._end_turn()
            log.write(f"[bold red]{t('tui.alfred_error', error=type(exc).__name__)}[/]")
            raise

    def _resolve_pending_turn(self) -> None:
        """Gate ``_end_turn()`` against a late signal for an ALREADY-abandoned turn.

        ``write_outbound``/``set_turn_failed`` are invoked from wire callbacks
        with no per-turn correlation available at all — ``TurnFailedNotification``
        deliberately carries no ``inbound_id`` (the TUI is structurally
        1:1/single-turn, ``protocol.py``), and a reply carries none either. So
        this cannot check "does this signal match generation N": a generation
        counter bumped on both submission and abandonment returns to the SAME
        value on resubmission that a same-tick "matches the current
        generation" comparison would accept, which makes "turn 2's own
        signal" and "turn 1's late signal arriving while turn 2 is pending"
        genuinely indistinguishable by that check alone.

        What IS available, with no wire tag at all, is a COUNT. The core
        serializes one session's turns behind a per-(persona, slug) mutex
        (``RealTurnOrchestratorAdapter.dispatch``, FOLD-R1) and only starts
        sending a turn's notify/reply AFTER releasing that mutex, with no
        ``await`` in between — so a later turn cannot even begin server-side
        processing, let alone have ITS OWN signal reach the wire, until every
        earlier turn's signal for that session has already been sent. That
        guarantees the ``_stale_turns_awaiting_signal`` late signals — one per
        watchdog-abandoned turn — arrive, in order, before the CURRENTLY
        pending turn's own signal. Consume that backlog first, without
        touching ``_turn_pending``/the watchdog; only once it is empty does a
        completion signal end the turn that is actually still pending.

        This is a CROSS-MODULE contract, not something enforceable from this
        file alone: see the ``DOWNSTREAM CONTRACT`` note on
        ``real_turn_adapter._TurnFailed`` and the matching note on
        ``RealTurnOrchestratorAdapter.dispatch``
        (``src/alfred/comms_mcp/real_turn_adapter.py``), and the regression
        test that would fail if that ordering ever regressed:
        ``test_dispatch_notifies_same_key_turns_in_submission_order_even_when_concurrent``
        in ``tests/unit/comms_mcp/test_real_turn_adapter_dispatch.py``.
        """
        if self._stale_turns_awaiting_signal > 0:
            self._stale_turns_awaiting_signal -= 1
            return
        self._end_turn()

    def write_outbound(self, body: str) -> None:
        """Paint a host-delivered outbound message into the conversation log.

        Called from the ``outbound.message`` wire handler (via the session's
        render hook). Synchronous: a RichLog write is non-blocking and the
        outbound handler awaits nothing on the render itself.

        Also ENDS the in-flight turn (#593), UNLESS this reply is a late
        arrival for a turn the watchdog already abandoned (#594 review
        finding) — see ``_resolve_pending_turn``. Either way the body still
        renders: a late reply is still informative to the operator, just not
        a signal that the CURRENT turn is done. A host-pushed outbound with no
        pending turn and no stale backlog is a harmless no-op (a reactive set
        to its current value does not fire the watcher).
        """
        self._resolve_pending_turn()
        log = self.query_one("#conversation_log", RichLog)
        # ``body`` is host-delivered persona output that can carry T3-derived
        # content; escape it so console markup in the body renders literally
        # rather than being interpreted by the ``markup=True`` RichLog. The
        # app-controlled label prefix keeps its legitimate markup.
        # (PR-S4-10 review #1 — markup-injection guard.)
        log.write(f"[bold green]{t('tui.label_alfred')}[/]: {escape(body)}")

    def set_turn_failed(self, stage: TurnFailureStage) -> None:
        """Render the core's turn-failure state and release the in-flight turn.

        Implements the ``_AppLike.set_turn_failed`` Protocol member declared
        in ``cohost.py`` (Task 13). Rendered into the CONVERSATION LOG, not
        the ``#link_banner``: a failed turn is a transcript event, not a
        connection state, and must remain visible above the next turn (a
        banner would be overwritten/cleared by the NEXT link-state change,
        silently erasing the record that this turn failed).

        Releases the in-flight turn UNLESS this failure is a late arrival for
        a turn the watchdog already abandoned (#594 review finding) — see
        ``_resolve_pending_turn``. The failure copy still renders either way;
        only whether it touches ``_turn_pending``/the watchdog is gated.
        """
        self._resolve_pending_turn()
        self.query_one("#conversation_log", RichLog).write(
            f"[bold red]{_turn_failure_message(stage)}[/]"
        )

    def set_link_state(self, method: str) -> None:
        """Update the reconnect banner from a gateway ``link.*`` state method.

        Invoked by the cohost wire pump (``run_cohosted``'s ``on_link_state``) on
        the SAME asyncio loop as this app (M1 — the pump and ``run_async()`` share
        one ``TaskGroup``/loop), so this is a DIRECT reactive set, NOT
        ``call_from_thread`` (which is for OFF-loop threads). Mutating the reactive
        drives ``watch__link_banner_key`` on the next render cycle.

        ``link.reconnecting`` / ``link.unavailable`` show the matching localized
        banner; ``link.restored`` clears it. ``link.unavailable`` is vocab-complete
        but latent until G4 wires its trigger (the gateway only emits
        ``reconnecting`` / ``restored`` today).
        """
        self._link_banner_key = _LINK_STATE_BANNER_KEY.get(method)

    def watch__link_banner_key(self, banner_key: str | None) -> None:
        """Paint or hide the reconnect banner when the link-state reactive changes.

        ``None`` (healthy / restored) hides the banner; a catalog key shows it with
        the TUI's OWN localized ``t()`` render — the gateway sends only state, never
        operator text (Spec A G5). The banner text is app-controlled (a fixed
        catalog string, no untrusted interpolation), so no markup-escape is needed.
        """
        banner = self.query_one("#link_banner", Static)
        if banner_key is None:
            banner.display = False
            return
        banner.update(t(banner_key))
        banner.display = True

    def watch__turn_elapsed_seconds(self, elapsed: int) -> None:
        """Paint the live elapsed-time counter while a turn is in flight.

        Deliberately a SEPARATE ``#turn_status`` ``Static`` widget, not a new
        ``RichLog`` line: the operator explicitly did not want this
        informational tick logged into the transcript (#594 Fix-10) — see
        ``test_elapsed_counter_shows_after_a_tick_and_is_never_logged``.

        Guarded on ``_turn_pending``: a reactive-diff firing outside a
        pending turn (e.g. Textual's own ``init=True`` watcher call at mount
        time, which fires once with the default value ``0`` while
        ``_turn_pending`` is still ``False``) must not paint or reveal the
        widget. Hiding it again on completion is ``_end_turn``'s job, not
        this watcher's — this method only ever shows/updates, never hides.
        """
        if not self._turn_pending:
            return
        status = self.query_one("#turn_status", Static)
        status.update(t("tui.thinking_elapsed", seconds=elapsed))
        status.display = True

    def watch__turn_pending(self, pending: bool) -> None:  # noqa: FBT001 - Textual's watch_<name>(value) calling convention is positional; not this app's API to redesign.
        """Disable + dim the input while a turn is in flight; restore on completion.

        ``#user_input.busy`` (the CSS rule declared above, orphaned since the
        in-process TUI was deleted) is what makes the disabled state VISIBLE.
        Textual blurs a widget when it is disabled, so the completion edge
        must re-``focus()`` or the operator's next keystrokes go nowhere.
        """
        user_input = self.query_one("#user_input", Input)
        user_input.set_class(pending, "busy")
        user_input.disabled = pending
        if not pending:
            user_input.focus()
