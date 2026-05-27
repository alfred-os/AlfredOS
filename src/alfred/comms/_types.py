"""Comms-adapter value types shared between the Protocol and concrete adapters.

Carved out of :mod:`alfred.comms.adapter` to break the static import
cycle CodeQL flagged on PR D1:

* ``adapter.py`` defines the ``CommsAdapter`` Protocol and the
  ``build_tui_adapter`` factory; the factory lazy-imports
  ``alfred.comms.tui_adapter`` inside its body so module-load order
  doesn't recurse.
* ``tui_adapter.py`` returned :class:`AdapterHealth` from its
  ``health()`` method, and so imported the dataclass from
  ``adapter.py`` at module load — which CodeQL's static
  ``py/cyclic-import`` analyser flagged because it could not see the
  laziness inside the factory.

Moving the dataclass here breaks the static cycle: both consumers
import from this leaf module, which imports nothing from the rest of
``alfred.comms``. The leading-underscore module name keeps it
private — outside callers continue to consume ``AdapterHealth`` via
``alfred.comms.adapter`` (which re-exports the symbol for backwards
compatibility).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class AdapterHealth:
    """Point-in-time adapter health snapshot.

    Three fields, shape-compatible with both the Textual TUI and the future
    Discord gateway:

    * ``gateway_connected`` — Discord-specific signal that the gateway
      websocket is currently alive. TUI returns ``True`` while the Textual
      loop is running (the in-process loop is the "gateway" for the TUI).
    * ``last_on_ready_at`` — Discord-specific timestamp of the most recent
      ``on_ready`` event. TUI returns its ``start()`` time.
    * ``recent_reconnect_count`` — Discord-specific recent-window counter.
      TUI returns ``0`` (no reconnect concept).

    Slice-3's MCP transport carries an analogous shape so the supervisor
    can compare adapter health across transports uniformly.
    """

    gateway_connected: bool
    last_on_ready_at: datetime | None
    recent_reconnect_count: int


__all__ = ["AdapterHealth"]
