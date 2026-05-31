# 0009 — `CommsAdapter` is an in-process Python Protocol for Slice 2 only

- **Status**: Superseded by ADR-0016 for new adapters; in-process Discord + TUI adapters unchanged through Slice 3
- **Date**: 2026-05-27
- **Slice**: 2 — `docs/superpowers/plans/2026-05-26-slice-2-pr-A-identity.md`
- **Supersedes**: —
- **Superseded by**: ADR-0016 (2026-05-31, for new adapters only)

## Context

PRD §5 lists "Plugins are MCP servers (comms adapters, …)" as a non-negotiable
architectural invariant: every comms surface — TUI, Discord, future Slack, future
voice — eventually speaks to the orchestrator across the MCP transport, not
through a Python import.

Slice 2 ships two comms surfaces (TUI carried over from Slice 1, Discord newly
added) but the MCP plugin transport itself doesn't land until Slice 3 (PRD §6.1
sequencing — MCP plugin host is a Slice-3 deliverable). Shipping the Discord
adapter as an in-process Python module in Slice 2 is therefore a deliberate,
bounded deviation from PRD §5, taken to keep Slice 2's surface area finite. The
deviation needs an explicit record so future readers understand why
`src/alfred/comms/` ships Python classes today and an MCP RPC server tomorrow.

## Decision

Define `CommsAdapter` as an in-process Python `Protocol`:

- `name: str` — stable identifier (`"tui"`, `"discord"`).
- `async start(orchestrator) -> None` — bind to the orchestrator and any
  external transport (Discord gateway, terminal).
- `async run() -> None` — the adapter's long-running task; the orchestrator
  supervises it via `TaskGroup`.
- `async stop() -> None` — graceful shutdown.
- `health() -> AdapterHealth` — synchronous snapshot for `alfred status`.

Slice 2 ships two concrete implementations (`TuiAdapter`, `DiscordAdapter`)
behind that Protocol, both in `src/alfred/comms/`.

**No call site outside `src/alfred/comms/` may import the concrete adapter
classes directly.** Callers depend on the Protocol type and receive a concrete
adapter via the registry / startup wiring. The import-isolation test at
`tests/unit/comms/test_no_direct_adapter_imports.py` (lands in PR D1) enforces
this with an AST scan of the rest of the source tree. PR A does not need this
test (there is no Discord adapter yet to gate), but documenting the rule here
means PR D1's test lands against an already-accepted ADR rather than minting
the constraint retroactively.

## Consequences

- **Single-module rewrite at Slice 3.** The in-process Protocol becomes an MCP
  RPC client/server pair. Because no external call site imports the concrete
  classes, the rewrite is confined to `src/alfred/comms/` plus the plugin host
  in `src/alfred/core/`.
- **Polarity inversion is explicit.** The Slice-3 MCP shape inverts the
  in-process polarity — the adapter becomes the RPC server, the orchestrator
  becomes the client. This Slice-2 Protocol shape is therefore *not* preserved
  across slices; the rewrite is intentional. Code that needs to outlive the
  rewrite should depend on the orchestrator-facing message contract, not on
  the adapter Protocol shape.
- **Slice-3 reviewer gate re-checks PRD §5 compliance.** When the MCP transport
  lands, the reviewer agent must confirm `src/alfred/comms/` no longer
  contains in-process adapter classes and that this ADR transitions to
  "Superseded by 00NN".

Slice 3 ships a `CommsAdapterMCP` Protocol stub (`src/alfred/comms/mcp_protocol.py`)
and a reference test plugin (`plugins/alfred-comms-test/`) that validates the MCP
comms transport contract. The existing `DiscordAdapter` and `TuiAdapter` remain
in-process through Slice 3, untouched. ADR-0016 commits Slice 4 to the full rewrite.

## Alternatives considered

- **Ship the MCP plugin transport in Slice 2.** Rejected — the MCP host,
  capability gate plumbing, and per-plugin sandbox would roughly double
  Slice 2's surface area on top of the identity + Discord + file broker work
  already committed. Slice splits exist to keep individual slices reviewable.
- **Hardcode TUI + Discord with no Protocol.** Rejected — without a uniform
  Protocol, Slice 3's MCP rewrite becomes a multi-module sprawl (every adapter
  call site is a separate refactor). The Protocol pays for itself the moment
  Slice 3 starts.

## References

- PRD §5 — Plugin architecture invariant ("Plugins are MCP servers").
- PRD §6.1 — Slice sequencing (MCP plugin host lands Slice 3).
- ADR-0008 — Trust-tier handling for LLM output (sets the precedent for
  explicit Slice-N tier/surface deviations).
- `docs/superpowers/specs/2026-05-26-slice-2-discord-multiuser-design.md`
  §2 lines 99-122 — `CommsAdapter` Protocol shape.
- `docs/superpowers/specs/2026-05-26-slice-2-discord-multiuser-design.md`
  §3 lines 315-417 — Discord adapter design.
- `tests/unit/comms/test_no_direct_adapter_imports.py` — Import-isolation
  enforcement (lands in PR D1).
