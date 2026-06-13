"""TuiSession — connection state + keystroke-batch debouncer + render hook.

A "keystroke-batch" is the unit of inbound emission: the operator types into the
input widget; the app collects the line until Enter, then asks the session to
flush. The session emits exactly one :class:`InboundMessageNotification` per
non-empty batch with ``addressing_signal='dm'`` — the TUI is structurally a 1:1
channel (one operator, one persona); the orchestrator routes by canonical
``user_id`` host-side, never by addressing mode within the TUI.

Wire-shape invariants (verified against ``alfred.comms_mcp.protocol`` — the host
schema, not the spec pseudocode):

* ``adapter_id`` carries the EXACT ``adapter_kind`` member ``"tui"``. The host's
  ``AdapterId`` validator is exact-match, not a prefix match, so a per-instance
  launcher id like ``tui-<uuid>`` would fail validation; the wire field is the
  kind. The per-instance id (passed to :meth:`start`) is retained for health /
  structlog attribution only.
* ``body`` is a ``Mapping[str, object]`` keyed by
  ``BODY_FIELD_BY_KIND["tui"] == "content"`` — NOT a bare string — so the host
  inbound scanner can locate the operator's typed text. A BCP-47 ``language``
  tag rides alongside for the host inbound audit row (closure i18n-1, mirroring
  the Discord emitter).

This module does NOT own the Textual app — the app lives in
``alfred_tui.textual.app`` and feeds the session via ``consume_user_input`` /
``flush_keystroke_batch``. Keeping them separate means the session is testable
without an actual terminal, and the outbound render hook (``render_outbound``)
is injected by ``alfred_tui.render`` at runtime.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Final

import structlog

from alfred.comms_mcp.protocol import BODY_FIELD_BY_KIND, InboundMessageNotification
from alfred_tui._addressing import TUI_INBOUND_ADDRESSING_SIGNAL

_log = structlog.get_logger(__name__)

# The exact ``adapter_kind`` member emitted on the wire. The launcher hands the
# plugin a per-instance ``adapter_id`` (e.g. ``tui-9f3c...``) at handshake, but
# the wire ``InboundMessageNotification.adapter_id`` field is exact-match
# validated against ``adapter_kind`` host-side, so the kind is what crosses.
_ADAPTER_KIND: Final[str] = "tui"

# The body-text field path the host scanner reads for TUI inbound (== "content").
_BODY_FIELD: Final[str] = BODY_FIELD_BY_KIND[_ADAPTER_KIND]

# The TUI operator's default language (BCP-47). The Slice-1 in-process app
# resolved bindings against ``_active_lang = "en-US"``; the comms-MCP rewrite
# keeps that default. Per-session language switching is future work host-side.
_DEFAULT_LANGUAGE: Final[str] = "en-US"

# A non-empty fallback for ``platform_user_id`` (the host bounds it to
# ``1 <= len <= 512``); a shell with an empty ``$USER`` must not crash the emit.
_UNKNOWN_OPERATOR: Final[str] = "unknown-operator"

type InboundNotify = Callable[[InboundMessageNotification], Awaitable[None]]
type RenderOutbound = Callable[[str], None]


@dataclass(frozen=True)
class HealthSnapshot:
    """Immutable health view for the ``adapter.health`` wire method."""

    ok: bool
    last_inbound_at: datetime | None
    queue_depth: int
    error_count: int


async def _noop_notify(_note: InboundMessageNotification) -> None:
    """Default sink: drop the notification (the server wires the real sink)."""


def _noop_render(_body: str) -> None:
    """Default render: drop the body (render.py wires the real Textual hook)."""


class TuiSession:
    """Stateful session for one TUI plugin subprocess lifetime."""

    def __init__(
        self,
        *,
        notify: InboundNotify | None = None,
        render_outbound: RenderOutbound | None = None,
    ) -> None:
        self._adapter_id: str | None = None
        self._buffer: list[str] = []
        # The dedup id for the CURRENTLY-buffered batch. Minted on first flush of
        # a batch and held until a successful flush clears the buffer, so a
        # re-flush of the same retained buffer reproduces the SAME id (Spec A
        # dedup-id-stability invariant #1). ``None`` ⇒ no batch in flight.
        self._pending_inbound_id: str | None = None
        self._last_inbound_at: datetime | None = None
        self._error_count: int = 0
        self._notify: InboundNotify = notify or _noop_notify
        self._render: RenderOutbound = render_outbound or _noop_render

    async def start(self, *, adapter_id: str) -> None:
        """Record the per-instance adapter id (for health / log attribution)."""
        self._adapter_id = adapter_id
        _log.info("comms.tui.session_started", adapter_id=adapter_id)

    async def stop(self, *, reason: str) -> int:
        """Discard any un-flushed buffer; report the discarded keystroke count."""
        flushed = len(self._buffer)
        self._buffer.clear()
        _log.info("comms.tui.session_stopped", reason=reason, flushed=flushed)
        return flushed

    async def consume_user_input(self, chunk: str) -> None:
        """Append a keystroke chunk to the current batch."""
        self._buffer.append(chunk)

    async def flush_keystroke_batch(self) -> None:
        """Emit one ``inbound.message`` notification for the buffered batch.

        A no-op on an empty buffer (the operator pressed Enter on a blank line).
        The body is a ``Mapping`` keyed by the host's body-field path so the
        inbound scanner can read the typed text.
        """
        if not self._buffer:
            return
        body = "".join(self._buffer)
        # Spec A decision 4 (G0), dedup-id-stability invariant #1: a buffering
        # emitter MUST reproduce the SAME id when it re-flushes a retained batch.
        # ``TuiSession`` keeps its buffer on a failed notify and re-flushes the
        # SAME operator text on retry; a fresh uuid4 per emit would make the host
        # idempotency ledger see the retry as a NEW frame → double-dispatch. So we
        # mint the id once per batch and hold it (in ``_pending_inbound_id``) until
        # a SUCCESSFUL flush clears the buffer; a re-flush reuses it, and the next
        # fresh batch (after the buffer cleared) mints a new one.
        if self._pending_inbound_id is None:
            self._pending_inbound_id = uuid.uuid4().hex
        note = InboundMessageNotification(
            adapter_id=_ADAPTER_KIND,
            inbound_id=self._pending_inbound_id,
            platform_user_id=os.environ.get("USER") or _UNKNOWN_OPERATOR,
            body={_BODY_FIELD: body, "language": _DEFAULT_LANGUAGE},
            sub_payload_refs=(),
            received_at=datetime.now(UTC),
            addressing_signal=TUI_INBOUND_ADDRESSING_SIGNAL,
        )
        # Emit FIRST, then clear/stamp. If the sink raises, the operator's
        # buffered keystrokes must survive (a retry re-flushes the same text)
        # and health must NOT report a false-successful inbound. The failure is
        # loud (counted + logged + re-raised), never a silent drop.
        # (PR-S4-10 review #2 — buffered-input-loss guard.)
        try:
            await self._notify(note)
        except Exception:
            self._error_count += 1
            _log.exception("comms.tui.inbound_notify_failed")
            raise
        self._buffer.clear()
        # Batch committed: drop the held id so the NEXT batch mints a fresh one.
        self._pending_inbound_id = None
        self._last_inbound_at = note.received_at

    def set_render_hook(self, render_outbound: RenderOutbound) -> None:
        """Install the Textual render hook after the app is constructed.

        ``render.py`` builds the :class:`AlfredTuiApp` from the session, then
        wires the app's ``write_outbound`` back as the render hook — a
        construction-order cycle the session breaks by allowing the hook to be
        set post-init (it defaults to a no-op for the unit tests).
        """
        self._render = render_outbound

    async def render_outbound(self, body: str) -> None:
        """Paint a host-delivered outbound body into the Textual conversation log.

        Delegates to the injected render hook. A no-op when no app is wired (the
        unit tests for the outbound handler do not mount a terminal).
        """
        self._render(body)

    def health_snapshot(self) -> HealthSnapshot:
        """Snapshot for the ``adapter.health`` wire method."""
        return HealthSnapshot(
            ok=self._adapter_id is not None,
            last_inbound_at=self._last_inbound_at,
            queue_depth=len(self._buffer),
            error_count=self._error_count,
        )


__all__ = ["HealthSnapshot", "InboundNotify", "RenderOutbound", "TuiSession"]
