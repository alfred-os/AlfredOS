# alfred_tui — AlfredOS TUI comms-MCP adapter

This is the in-tree TUI adapter, rewritten from the Slice-1 in-process Textual
app as an MCP-stdio plugin. The daemon spawns it via
`bin/alfred-plugin-launcher.sh` when an operator runs `alfred chat`.

## Install

Bundled with AlfredOS — operators do not install this manually.

## Sandbox profile

`sandbox.kind = none`. Unlike the Discord adapter (`kind = full`, because it
ingests adversary-controlled bytes from arbitrary platform users), the TUI runs
in the operator's foreground PTY. No OS sandbox applies because:

- there is no adversary-controlled network ingress — the operator is the only,
  trusted, user; and
- the process must own the terminal's stdin/stdout to render the Textual app,
  which a bwrap (Linux) / sandbox-exec (macOS) mount-and-fd namespace would
  sever.

The operator's typed body is still tagged content trust tier **T3** host-side
the instant it crosses `process_inbound_message` — the host quarantines inbound
content regardless of the adapter's process trust. `sandbox.kind = none` is a
statement about the *process* isolation posture, not the *content* trust tier.

## Addressing

The TUI is structurally a 1:1 channel: one operator, one persona. Every inbound
message therefore carries `addressing_signal = "dm"` — see `_addressing.py`.

## Windows operators

On Windows, the launcher requires WSL2. Native Windows hosts do not satisfy the
PRD §6.7 quarantined-LLM containerisation invariant (ADR-0015); see
`bin/alfred-setup.ps1` for the WSL2 redirect.
