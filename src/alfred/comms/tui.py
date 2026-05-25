"""Slice-1 TUI built on Textual.

Scrolling conversation log + bottom input box. Enter submits through the
orchestrator; response renders in the log. Slice-1 affordances:
- Ctrl+C / Ctrl+Q exits cleanly.
- A pending submission disables the input + shows a "thinking" hint so a stalled
  provider doesn't look like a frozen UI. Esc cancels the in-flight turn.
- Errors render as a one-line message routed through t() — never a raw traceback.

Slice 2+ adds streaming UX.
"""

from __future__ import annotations

import asyncio
from typing import Protocol

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.widgets import Input, RichLog

from alfred.i18n import t

# Per-turn wall-clock cap. If the provider doesn't respond in this long, the TUI
# cancels the turn and renders a friendly timeout message. Slice 2+ may make this
# per-persona configurable.
TURN_TIMEOUT_SECONDS = 90


class _OrchestratorLike(Protocol):
    """Structural type the TUI needs from its orchestrator.

    Letting the TUI depend on a Protocol (not the concrete Orchestrator class)
    keeps the comms layer decoupled from the core wiring — exactly what slice 2's
    plugin-supervised comms adapter pattern needs. The test substitutes an
    AsyncMock that matches this shape.
    """

    async def handle_user_message(self, content: str, /) -> str: ...


class AlfredTuiApp(App[None]):
    CSS = """
    Screen { layout: vertical; }
    #conversation_log { height: 1fr; border: solid white; padding: 1; }
    #user_input { dock: bottom; }
    #user_input.busy { background: $boost; color: $text-muted; }
    """

    BINDINGS = [  # noqa: RUF012  # Textual reads BINDINGS off the class; mutable is the documented contract.
        Binding("ctrl+c", "quit", "Quit", show=True, priority=True),
        Binding("ctrl+q", "quit", "Quit", show=True),
        Binding("escape", "cancel_turn", "Cancel turn", show=True),
    ]

    def __init__(self, *, orchestrator: _OrchestratorLike) -> None:
        super().__init__()
        self._orchestrator = orchestrator
        self._in_flight: asyncio.Task[str] | None = None

    def compose(self) -> ComposeResult:
        yield Vertical(
            RichLog(id="conversation_log", highlight=True, markup=True),
            Input(placeholder=t("tui.input_placeholder"), id="user_input"),
        )

    async def on_mount(self) -> None:
        """Place initial focus on the input box.

        Textual 8.x defaults focus to the first focusable widget in the
        compose tree — that's the RichLog, not the Input — so without this
        the first ``alfred chat`` keystrokes silently scroll the log rather
        than typing into the input. Test pilots set focus explicitly so this
        is intentionally not covered by ``tests/unit/comms/test_tui.py``;
        the value is on real-terminal launch via the CLI.
        """
        self.query_one("#user_input", Input).focus()

    async def on_input_submitted(self, event: Input.Submitted) -> None:
        text = event.value.strip()
        if not text:
            return
        if self._in_flight is not None and not self._in_flight.done():
            # Slice-1 policy: one turn at a time. Slice 3+ revisits when persona
            # coordination needs concurrent inbound turns.
            return
        log = self.query_one("#conversation_log", RichLog)
        input_widget = self.query_one("#user_input", Input)
        log.write(f"[bold cyan]{t('tui.label_you')}[/]: {text}")
        event.input.value = ""

        input_widget.disabled = True
        input_widget.add_class("busy")
        log.write(f"[dim]{t('tui.thinking')}[/]")

        self._in_flight = asyncio.create_task(self._run_turn(text))
        try:
            response = await asyncio.wait_for(self._in_flight, timeout=TURN_TIMEOUT_SECONDS)
        except asyncio.CancelledError:
            log.write(f"[yellow]{t('tui.turn_cancelled')}[/]")
            return
        except TimeoutError:
            log.write(f"[bold red]{t('tui.turn_timeout', seconds=TURN_TIMEOUT_SECONDS)}[/]")
            return
        except Exception as exc:
            # Friendly render of every failure mode: BudgetError, provider crash,
            # audit-write failure. The orchestrator already audited; we just paint.
            log.write(f"[bold red]{t('tui.alfred_error', error=str(exc))}[/]")
            return
        finally:
            input_widget.remove_class("busy")
            input_widget.disabled = False
            input_widget.focus()
            self._in_flight = None

        log.write(f"[bold green]{t('tui.label_alfred')}[/]: {response}")

    async def _run_turn(self, text: str) -> str:
        return await self._orchestrator.handle_user_message(text)

    async def action_cancel_turn(self) -> None:
        """Esc: cancel the in-flight turn if any.

        The orchestrator audits the cancellation on its side; the TUI's
        ``on_input_submitted`` handler catches the resulting CancelledError
        and paints ``tui.turn_cancelled``.
        """
        if self._in_flight is not None and not self._in_flight.done():
            self._in_flight.cancel()
