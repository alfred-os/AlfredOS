"""``outbound.message`` handler for the TUI plugin.

The host-side outbound queue refuses ``mention/channel/thread`` to TUI per spec
§8.1 (the TUI is 1:1 — there is no channel or thread to address). This handler
is the defensive SECOND layer: a non-``dm`` mode that escapes the host guard
returns a typed ``terminal_failure`` rather than silently rendering into the
operator's terminal. A ``dm`` message is painted into the Textual conversation
log via the session's render hook and acknowledged ``delivered``.
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, Final

from alfred.comms_mcp.protocol import (
    OutboundMessageRequest,
    OutboundMessageResult,
    _OutboundDelivered,
    _OutboundTerminal,
)

if TYPE_CHECKING:
    from alfred_tui.session import TuiSession

# The terminal error_class a non-dm outbound is refused with. Stable string the
# host audit row keys on; matched by the unit + (later) integration tests.
_ERR_ADDRESSING_UNSUPPORTED: Final[str] = "tui_addressing_mode_not_supported"


async def handle_outbound_message(
    req: OutboundMessageRequest,
    *,
    session: TuiSession,
) -> OutboundMessageResult:
    """Render a ``dm`` outbound into the TUI log; refuse any other mode.

    ``req.body`` is ``ScannedOutboundBody`` — a DLP-minted ``(redacted_text,
    scan_result)`` tuple — so the visible text is ``req.body[0]``. No outbound
    can reach this handler without having passed the DLP chokepoint host-side
    (the body type is unconstructable otherwise).
    """
    if req.addressing_mode != "dm":
        # detail_redacted is bounded (max_length=256) and carries no body bytes —
        # only the offending mode name, so a loud audit row stays redaction-safe.
        return _OutboundTerminal(
            outcome="terminal_failure",
            error_class=_ERR_ADDRESSING_UNSUPPORTED,
            detail_redacted=f"mode={req.addressing_mode} unsupported by TUI (1:1 only)",
        )
    redacted_text, _scan_result = req.body
    await session.render_outbound(redacted_text)
    return _OutboundDelivered(
        outcome="delivered",
        platform_message_id=str(uuid.uuid4()),
    )


__all__ = ["handle_outbound_message"]
