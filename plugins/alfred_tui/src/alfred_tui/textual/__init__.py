"""Textual rendering layer for the AlfredOS TUI MCP-plugin adapter.

Verbatim move of the widget tree from ``src/alfred/comms/tui.py`` (PR-S4-10).
The widgets (input area + RichLog) are unchanged; only their bindings to the
surrounding adapter changed — the app now feeds a session rather than calling an
in-process orchestrator.
"""
