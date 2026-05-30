# 0014 — Every action AlfredOS takes is hookable

- **Status**: Accepted
- **Date**: 2026-05-27
- **Slice**: 2.5 (target — final placement by `alfred-architect` at Slice-2-graduation
  planning; recommended between Slice 2's identity/Discord/secret-broker work and
  Slice 3's MCP plugin transport)
- **Supersedes**: —
- **Superseded by**: —

## Context

AlfredOS already ships several extension points:

- **MCP plugins** (PRD §5, §6.3) — skills, memory backends, integrations, the
  reviewer agent. Plugins add new *actions* AlfredOS can take.
- **Event bus** (PRD §5 Redis streams) — components publish typed events;
  other components subscribe. Strictly observe-only; subscribers cannot mutate
  the originating action or refuse it.
- **Capability gate** (PRD §5 architectural invariants, §7.1) — gates a
  plugin's permission to *invoke* a tool. Once permission is granted, the
  gate is out of the loop until the next call.
- **Audit log** (PRD §7.4) — after-the-fact record of every action.

None of these surfaces lets a plugin (or the core itself) **intercept** an
action mid-flight to mutate, refuse, replace, or react. Concrete cases the
household-OS vision requires that today have no clean implementation path:

- "Whenever any persona sends a Discord DM, run my custom filter first and
  refuse if it would expose `<topic>` outside the household." Today: requires
  modifying `DiscordAdapter` or pre-publishing every outbound message to a
  bespoke queue and racing the send. Neither is plugin-shaped.
- "Whenever any tool call returns a body containing a tracking pixel, strip
  it before the orchestrator consumes the result." Today: requires patching
  each tool individually.
- "Whenever a persona reaches into the secret broker, log to my external
  SIEM in real time." Today: only the post-hoc audit log; no synchronous
  hook for the SIEM to refuse.
- "Whenever a memory consolidation pass writes a fact, run my deduplication
  pass before commit." Today: requires forking `memory/consolidation.py`.

The pattern is the same in every case: **a third party (plugin, operator,
or system component) needs to observe or intercept actions taken by other
components, without those components knowing about the third party**. PRD §5
already commits to "plugins are MCP servers"; the missing piece is a uniform
seam *every action passes through* so plugins can register interest.

The event bus is the closest existing surface and it's load-bearing for
*observation*. What it cannot do (and was never designed to do) is mutate
the action's input, refuse the action, replace the result, or run reliably
synchronously in-band with the action.

## Decision

**Every action AlfredOS takes is registered with a hookable interface.** An
action is any unit of work the agentic core dispatches: a tool call, a
provider call, a memory write, a comms outbound, a consolidation pass, a
budget check, an audit write, a persona-to-persona message, a skill
invocation. The list is exhaustive: if it's a verb the core executes, it's
hookable.

Hook types (an action carries up to four):

- **Pre-action hook** — called with the action's input *before* the action
  runs. Can mutate the input, refuse the action (raising a typed `HookRefusal`),
  or pass through unchanged. Multiple pre-hooks chain in deterministic order.
- **Post-action hook** — called with the action's result *after* the action
  runs successfully. Can mutate or annotate the result, or pass through.
- **Error hook** — called with `(input, exception)` when the action raises.
  Can swallow the exception and synthesise a replacement result, or re-raise
  (default).
- **Cancel hook** — called on `asyncio.CancelledError` mid-action for cleanup.
  Cannot suppress the cancellation; cleanup-only.

Hook registration is **plugin-scoped and capability-gated**. A plugin
declares `hook.<action-name>` in its manifest capabilities; the operator
grants or refuses at install time per the existing capability-gate flow
(PRD §6.3, §7.1). Registration without the capability is refused at plugin
load time, audited, and surfaces in `alfred status`.

Hook ordering is deterministic by **capability tier** then **registration
order within tier**:

1. **System tier** — core AlfredOS hooks (audit writer, DLP scanner, capability
   gate enforcer). Always run first; cannot be re-ordered by plugins.
2. **Operator tier** — hooks the operator has explicitly trusted via the
   capability grant flow. Run after system, before user-plugin.
3. **User-plugin tier** — hooks third-party or agent-authored plugins
   register. Run last; refusals here are the most common surface.

Pre-action chain short-circuits on first refusal: the action does not run,
the post chain does not run, and the error chain receives the `HookRefusal`
exception (so audit + telemetry observe the refusal uniformly).

Plugin authors register hooks via **the same MCP protocol they use to
expose tools** — a `hooks` block in the plugin manifest declares the
`(action, kind)` tuples the plugin handles, and the MCP transport routes
calls. In-tree (in-process) plugins may also register via a Python
decorator at module-import time for ergonomics; the decorator routes
through the same capability-gated registry.

Hooks are **synchronous, in-band interception** — they run within the
action's call stack, not asynchronously or out-of-band. This contrasts
with the event bus (observe-only, fire-and-forget; PRD §5). Every hook
invocation is **auditable and correlation-tagged**: the audit log records
each pre-/post-/error-/cancel-hook call keyed to the originating action's
correlation ID, so the full hook chain for any action (including
refusals) is reproducible from the audit trail.

**This is NOT a Slice-2 deliverable.** Slice 2 ships as currently scoped
(identity + Discord + secret broker + per-user budget + memory + orchestrator
hardening). Hooks land in a dedicated slice — call it Slice 2.5 — between
Slice 2's graduation and Slice 3's MCP-transport rewrite. The architect
finalises slice placement at Slice-2-graduation planning; Slice 2.5 is the
recommendation because the hook-registry contract should be in place
*before* Slice 3 swaps the comms-adapter transport to MCP (so MCP plugins
register hooks via the same Python contract on the in-process side, the
transport on the remote side).

## Consequences

- Every action acquires a registration point. The PRD's "every action is
  audited" invariant (§7.4) gains a sibling: "every action is hookable."
- Retrofit is bounded by the slice that ships hooks (Slice 2.5). Slice-1
  and Slice-2 actions are wrapped in the registry in that slice's PRs;
  no earlier PR is reopened.
- Forward-compat with the Slice-3+ MCP plugin transport is clean: the
  hook contract is a Python protocol; MCP is one transport, in-process
  is another. Plugins port between transports without rewriting hooks.
- Performance budget is non-trivial. Every action pays the hook-dispatch
  cost (a registry lookup + per-tier ordered iteration) on the hot path.
  The default-empty case must be a single dict lookup ~O(1); the populated
  case is O(n) in registered hooks per action. Slice 2.5's plan must
  publish a latency budget (recommended: ≤10µs per action with no hooks,
  ≤100µs per action with 5 hooks, measured on the orchestrator hot path).
- Security surface grows. A malicious plugin with a hook capability can
  observe every input to that action across every persona. The capability-
  gate flow must reflect this in the install-time prompt ("this plugin
  will see all inputs to `comms.discord.send` across every persona").
- Audit log gains hook-trace events. Each pre-/post-/error-hook invocation
  emits an audit row keyed to the originating action's correlation ID,
  so a refused action's full hook chain is reproducible from the log.
- Testing convention extends. Every action acquires a contract test:
  "with no hooks registered, action behaves as before; with a refusing
  pre-hook, action does not run; with a mutating pre-hook, downstream
  sees mutated input; with an error-hook returning a replacement result,
  downstream sees the replacement." Slice 2.5's plan templates these.

## Alternatives considered

- **(a) Use the event bus (PRD §5 Redis streams) as the hook surface.**
  Rejected: events are observe-only by design. Bolting refusal/mutation
  onto Redis streams would require a request-reply layer on top of a
  fire-and-forget pub/sub, and synchronous in-band semantics on top of
  an out-of-band transport. The event bus stays the observation surface;
  hooks are the interception surface. They coexist.
- **(b) MCP-only — wrap every internal action as an MCP tool so existing
  plugin extension points cover it.** Rejected: forces every internal
  action through MCP serialisation cost; couples in-process action
  semantics to a network-shaped protocol; would slow hot paths (memory
  writes, audit writes) by orders of magnitude. MCP stays the *plugin*
  protocol; hooks are the *interception* protocol on the in-process side.
- **(c) Retrofit hooks into Slice-2 PRs.** Rejected: reopens every Slice-2
  PR (already merged or in flight at the time of writing) for a contract
  change that has no Slice-2 consumer. Disproportionate churn for zero
  Slice-2 user-visible benefit.
- **(d) Generic AOP-style decorator framework (Python decorators that
  intercept arbitrary calls).** Rejected: decorators don't carry plugin
  identity, so the capability-gate cannot enforce "hook.<action>" at
  registration time. Decorators also entangle hook registration with
  the decorated module's import time, which makes hot-reload semantics
  (Slice 3+) intractable.
- **(e) Defer until Slice 3 and bundle with MCP transport.** Rejected:
  Slice 3 is already a large slice (MCP transport rewrite + T1/T3 +
  dual-LLM split per ADR-0013). Adding the hooks contract on top would
  push Slice 3 past a sensible merge window. Slice 2.5 isolates the
  hooks contract as its own slice with its own acceptance gates.

## References

- PRD §5 (Architecture Overview — architectural invariants including
  "plugins are MCP servers" and the event bus).
- PRD §6.3 (Agentic Skills & MCP Integration).
- PRD §7.1 (Security & Prompt Injection Defense — capability gate, DLP).
- PRD §7.4 (Audit Trail & Rollback).
- ADR-0009 (CommsAdapter Protocol Slice-2-only — Slice 3 swaps to MCP).
- ADR-0013 (Defer T1/T3 + dual-LLM to Slice 3).
- CLAUDE.md hard rules (capability gate, audit, trust tiers).
- [Slice 2.5 hooks design spec](../superpowers/specs/2026-05-27-slice-2.5-hooks-design.md).

## Amendment (Slice 2.5)

Slice 2.5 shipping is the trigger to move this ADR from *Proposed* to
*Accepted* and append the following clarifying paragraph (spec §9.1):

> **Core lifecycle methods are themselves hookpoint producers.** They use the same `invoke()`/`invoking()` primitive that plugins use to declare extension points. There is no asymmetry between "core actions get hooks" and "plugins publish hooks" — a hookpoint is a named, string-keyed extension point, and any code (core or plugin) may both publish and subscribe. The four kinds (pre/post/error/cancel) are routing semantics on an invocation, not the structure-defining concept.

The matching PRD §5.1 refinement is proposed separately for human approval
per CLAUDE.md self-improvement rule #4; the proposed-diff artifact lands in
a follow-up commit in this same PR (Slice 2.5 PR-C, Task 5).
