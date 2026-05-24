# 0004 — Textual TUI for slice 1

- **Status**: Accepted
- **Date**: 2026-05-24
- **Slice**: 1 (`docs/superpowers/plans/2026-05-24-slice-1-hello-alfred.md`)
- **Supersedes**: —
- **Superseded by**: —

## Context

PRD §6.5 ("Comms") lists Discord, Telegram, and a local TUI as MVP adapters. The slice-1 plan keeps Discord and Telegram out of scope. We still need an interactive surface a contributor can use to talk to Alfred — both for the smoke test and for the "second-run remembers context" DoD criterion.

The choices for a local TUI are: (a) raw `prompt_toolkit`, (b) `textual` (modern, async-native, widget-based), (c) `rich`-only (no input handling), (d) a web UI shipped via FastAPI + a static page. Web UI was rejected at PRD time because it adds an HTTP server, a port to manage, and a browser dependency to the smoke test. `rich`-only was rejected because it has no input loop. `prompt_toolkit` is solid but the widget model is more code for the same outcome as `textual`.

## Decision

Slice 1 uses **`textual`** for the interactive TUI. The app shape is: one `RichLog` for conversation, one `Input` for the user, async handlers that call into the orchestrator.

## Consequences

**Positive**

- `textual` is async-native and integrates with the orchestrator's asyncio loop without a separate event-loop wrapper.
- The widget model means future affordances (cost-per-turn pill, persona pill once slice 5 lands, command palette) drop in without rewriting the loop.
- A contributor can run `alfred chat` over SSH; no display server needed.

**Negative**

- `textual` adds a dependency. ~6 MB installed. Acceptable.
- Some screen-reader compatibility is uneven in terminal UIs; we will need to ship a `--no-color` or `--plain` mode in a later slice for accessibility.
- Testing a `textual` app requires the `textual` test harness; we cannot just call functions. The slice-1 smoke test uses the `App.run_test()` pattern.

**Neutral**

- The TUI is one of several future comms adapters. Discord, Telegram, web, and possibly a Slack adapter follow the same `Adapter` interface defined in slice 2. The TUI is the reference implementation.

## Slice-2 implications

- When Discord/Telegram adapters land in slice 2, they implement the same `Adapter` interface. The TUI in slice 1 must shape that interface — single-user, single-channel, async, with explicit input-tag at the boundary (see ADR on trust tiers — to be written in slice 2 when T1/T3 land).
- Accessibility work (high-contrast, `--plain` mode, screen-reader hints) belongs in a later slice with its own ADR.
