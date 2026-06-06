# ADR-0016 — Slice 4: rewrite Discord and TUI adapters as MCP plugins

## Status

Proposed

**Date:** 2026-05-31

## Context

ADR-0009 shipped Discord and TUI adapters as in-process Python Protocols,
explicitly noting that "the rewrite is intentional" and that "the Slice-3
reviewer gate re-checks PRD §5 compliance." Slice 3 ships the `PluginTransport`
Protocol and `StdioTransport` implementation (ADR-0017 §4) plus a
`CommsAdapterMCP` Protocol stub and a reference test plugin
(`plugins/alfred_comms_test/`). The in-process adapters remain unchanged
through Slice 3.

PRD §5 requires all comms surfaces to speak MCP. The MCP transport is now
shipped. The remaining gap is the adapter implementations themselves.

## Decision

Slice 4 rewrites `DiscordAdapter` and `TuiAdapter` as MCP plugins under the
Slice-3 `StdioTransport`. The message-contract definition (full field schema,
error shapes, rate-limit signalling) is co-defined with this ADR at Slice-4
implementation time. The four wire methods contracted in the Slice-3
reference test plugin (`lifecycle.start`, `lifecycle.stop`,
`inbound.message`, `adapter.health`) are the seed; Slice 4 extends this
contract with Discord-specific fields (embeds T3-promotion, attachment
handling) and finalises the ADR-0009 polarity-inversion note.

## Consequences

### Positive

- PRD §5 "Plugins are MCP servers" invariant fully satisfied for comms adapters.
- T3-promotion for Discord embeds/attachments/polls lands naturally alongside
  the MCP rewrite — the DLP scan is at the transport boundary, not in-adapter.

### Negative

- The `CommsAdapter` in-process Protocol (`src/alfred/comms/`) is removed.
  Any external code (custom personas, third-party skills) that imported
  concrete adapter classes directly rather than using the Protocol type will
  break. The import-isolation AST test (`tests/unit/comms/test_no_direct_adapter_imports.py`)
  already enforces this invariant, so breakage is restricted to code that
  bypasses the test gate.

### Neutral

- The `IdentityResolver` placement (host-side in Slice 3, per §9.1) is
  revisited when the full host-side callback wire type is designed for Slice 4.

## References

- [PRD §5](../../PRD.md#5-architecture-overview) — "Plugins are MCP servers."
- [ADR-0009](0009-comms-adapter-protocol-slice2-only.md) — in-process Protocol; superseded by this ADR for new adapters.
- [ADR-0017](0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md) — Slice-3 transport decision.
- [Spec §9](../superpowers/specs/2026-05-30-slice-3-trust-tier-completion-design.md#9-adr-0009-comms-mcp-rewrite-fork-8) — ADR-0009 comms-MCP rewrite scope.
