# 0003 — Plain asyncio orchestrator for slice 1 (defer Redis-streams event bus)

- **Status**: Accepted
- **Date**: 2026-05-24
- **Slice**: 1 (`docs/superpowers/plans/2026-05-24-slice-1-hello-alfred.md`)
- **Supersedes**: —
- **Superseded by**: —

## Context

PRD §5 ("Architecture") and §6.7 ("Core runtime") describe the orchestrator as the consumer of an internal **event bus** built on Redis streams, with a plugin supervisor, hot-reload, and an MCP client all reading and writing events. The architectural diagram in PRD §5 explicitly shows the event bus as a first-class component.

Slice 1 has exactly one event source (the TUI), one event sink (the provider router), one writer of working memory (the orchestrator), and one writer of episodic memory (the orchestrator). There are no plugins, no hot-reload, no MCP servers, no inter-persona coordination. Introducing Redis-streams to mediate a single producer/consumer pair would buy us nothing in slice 1 and would inflate the smoke-test setup cost.

## Decision

Slice 1 uses **plain asyncio coroutines** for the orchestrator's OODA loop. No event bus, no Redis, no plugin supervisor, no hot-reload, no MCP client. The orchestrator is a `class Orchestrator` with `handle_user_message()` as the public entry point and Observe → Orient → Decide → Act phases distinguishable as method calls.

The orchestrator's structure leaves room to **slot in** the Redis-streams bus in slice 3 without rewriting the loop: every cross-phase boundary is an `await` on an injectable transport. Slice 3 swaps the in-process transport for a Redis-streams transport.

## Consequences

**Positive**

- Slice 1 ships with two containers (`alfred-core` + `alfred-postgres`). The Redis dependency stays in the PRD but is staged.
- The orchestrator's loop is debuggable with a plain Python debugger. No streams to inspect, no consumer groups to reason about.
- Plain asyncio matches the slice-1 invariant of "one process, one user, one persona" and makes the OODA phases auditable as a simple call graph.

**Negative**

- The PRD architecture diagram is technically wrong for slice 1. The README must say "slice 1 = single-process, see ADR-0003."
- A contributor reading the orchestrator code for the first time will not see the bus. They must read this ADR to understand that the bus is intentional future work, not an oversight.
- The orchestrator interface must be designed with the slice-3 swap in mind. If we get the boundaries wrong, slice 3 becomes a rewrite, not a swap. Mitigation (intent-level, not contract-level): each OODA phase exposes an awaitable boundary that takes/produces a structured value (typed `Message` / `CompletionRequest` / `CompletionResponse` today) so a future `Transport` can replace direct method calls with `redis-streams` enqueue/dequeue without changing the orchestrator's public shape. The slice-1 plan keeps phases as in-class methods on `Orchestrator` for now — see Task 13 — and the slice-3 plan owns the transport-injection refactor.

**Neutral**

- Plugin supervisor, hot-reload, MCP client, and persona registry all defer to later slices. Each gets its own ADR when it lands.

## Slice-3 implications

- Slice-3 plan owns the Redis-streams swap: replace the in-process transport with `redis.asyncio.Stream`. The orchestrator class should not change.
- Adversarial tests for the bus (replay safety, consumer-group correctness, dead-letter handling) belong in slice 3, not slice 1.
- Hot-reload of plugins is downstream of the bus existing.
