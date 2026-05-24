# 0002 — In-process working memory for slice 1

- **Status**: Accepted
- **Date**: 2026-05-24
- **Slice**: 1 (`docs/superpowers/plans/2026-05-24-slice-1-hello-alfred.md`)
- **Supersedes**: —
- **Superseded by**: —

## Context

PRD §6.2 ("Memory architecture") and §8 ("Memory subsystem") describe the working-memory layer as a Redis-backed buffer keyed by `(user_id, session_id)` so that multiple processes (orchestrator, comms adapters, plugin supervisors) can share live conversation state. PRD §11 ("Deployment") lists Redis 7 as a default-stack datastore.

Slice 1 ships a single-process `alfred-core` container that holds the TUI, the orchestrator, the provider router, and the audit writer in one Python event loop. Episodic memory (durable conversation log) lives in Postgres from day 1. The only consumer of working memory in slice 1 is the orchestrator, and there is exactly one orchestrator process.

## Decision

Slice 1's **working memory is an in-process Python buffer** (a bounded list owned by the orchestrator), not Redis. Redis is deferred until a second process needs to read working memory (slice 3, when the plugin supervisor / event bus lands).

## Consequences

**Positive**

- The slice-1 stack is `alfred-core` + `alfred-postgres`. Two containers, not three. A contributor can run the smoke test with ~600 MB of RAM committed to dependencies.
- The in-process buffer is trivial to test (just a Python list), trivial to reason about (no IPC, no eviction race), and zero-latency to read.
- The interface the orchestrator uses is identical to what a Redis-backed implementation will expose: `append(role, content)`, `turns()` (returns the bounded-history list), `clear()`. The slice-1 backing store is a `deque(maxlen=N)` so eviction is already happening — oldest turns drop when the buffer fills. The slice-3 Redis implementation preserves the external contract; its own eviction policy (LRU or capped stream) is decided at swap time.

**Negative**

- Working memory is lost on `alfred-core` restart. This is acceptable in slice 1 because episodic memory rehydrates the buffer on startup (last-N turns from Postgres). The slice-1 plan covers this in the orchestrator boot sequence.
- A reader of the PRD will expect Redis-backed working memory. This ADR is the answer.
- We risk shipping a working-memory interface that quietly assumes single-process semantics. Mitigation: the interface is async even when the body is sync, and the buffer is wrapped in an `asyncio.Lock` so the slice-3 swap is purely backend-internal.

**Neutral**

- The dependency on Redis remains in the PRD but is staged to slice 3.

## Slice-3 implications

- When the event bus lands (Redis-streams), working memory moves to Redis with the same interface. The orchestrator should not need to change.
- The eviction policy (slice-1: `deque(maxlen=N)` — oldest-turn FIFO eviction once N is hit) may need rework for the Redis-backed version. Slice-3 plan owns that decision; default carry-over is "Redis stream with MAXLEN trimming at the same N."
