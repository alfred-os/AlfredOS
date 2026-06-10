"""Addressing-signal invariant for the TUI plugin.

The TUI is structurally a 1:1 channel — the operator is the only user and the
persona is the only addressee. Every inbound message therefore emits
``addressing_signal='dm'``.

The host refuses outbound ``mode=mention/channel/thread`` to TUI with a
``COMMS_ADDRESSING_DRIFT_FIELDS`` audit row + delivery refusal (spec §8.1
routing-rule table). This constant pins the invariant on the plugin side so the
wire-level guarantee has a single source of truth — ``session.py`` stamps every
``InboundMessageNotification`` with it rather than an inline literal.
"""

from __future__ import annotations

from typing import Final, Literal

# Narrowed to the literal ``"dm"`` (a member of the host's
# ``alfred.comms_mcp.protocol.InboundAddressingSignal`` Literal) so a typo here
# is a type error, not a silent wrong-mode emit.
TUI_INBOUND_ADDRESSING_SIGNAL: Final[Literal["dm"]] = "dm"
