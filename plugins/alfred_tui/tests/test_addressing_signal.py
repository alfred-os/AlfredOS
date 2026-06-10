"""Every inbound emits addressing_signal='dm'.

The TUI is structurally 1:1 — one operator, one persona. The plugin pins this
invariant in a single constant so the wire-level guarantee has one source of
truth (the host additionally refuses outbound mention/channel/thread to TUI per
spec §8.1).
"""

from __future__ import annotations

from alfred_tui._addressing import TUI_INBOUND_ADDRESSING_SIGNAL


def test_tui_inbound_addressing_signal_is_dm() -> None:
    assert TUI_INBOUND_ADDRESSING_SIGNAL == "dm"
