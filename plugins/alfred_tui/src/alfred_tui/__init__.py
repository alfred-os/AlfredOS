"""alfred_tui — comms-MCP TUI adapter (Slice 4, PR-S4-10).

The operator-local terminal adapter, rewritten from the Slice-1 in-process
Textual app as an MCP-stdio plugin. Serves the four ADR-0024 host->plugin
wire methods and emits the ``inbound.message`` notification; the daemon spawns
it via ``bin/alfred-plugin-launcher.sh`` when an operator runs ``alfred chat``.
"""

__version__ = "0.1.0"
