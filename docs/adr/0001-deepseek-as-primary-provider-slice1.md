# 0001 — DeepSeek as primary provider for slice 1

- **Status**: Accepted
- **Date**: 2026-05-24
- **Slice**: 1 (`docs/superpowers/plans/2026-05-24-slice-1-hello-alfred.md`)
- **Supersedes**: —
- **Superseded by**: —

## Context

PRD §6.6 ("Providers") lists Anthropic, OpenAI, and DeepSeek as the MVP set, with tiered routing and capability fallback as deferred work. PRD §9 ("MVP scope") echoes this. The PRD does not name a primary; the choice was deferred to implementation.

For the first runnable slice we need exactly two providers exercised end-to-end so the multi-provider pattern lands from day 1 (a single-provider slice would force a structural change in slice 2). We also want a cost profile that lets a contributor run the smoke test repeatedly without budget anxiety.

## Decision

Slice 1 uses **DeepSeek as the primary provider** (via the OpenAI SDK with a custom `base_url`) and **Anthropic as the fallback** (via the native `anthropic` SDK).

OpenAI is deferred to slice 2+ when the router widens to tiered routing.

## Consequences

**Positive**

- DeepSeek is ~40× cheaper per token than Anthropic Sonnet, so contributors can run smoke tests freely.
- Two SDK shapes are exercised (OpenAI-compat and Anthropic-native), proving the `Provider` protocol's polymorphism from slice 1.
- The OpenAI-SDK+custom-base_url adapter generalises to any OpenAI-compatible provider added later (Together, Groq, Fireworks).
- The Anthropic-native adapter forces us to think about provider-specific features early (prompt caching, native tool-use shape).

**Negative**

- DeepSeek is an external dependency on a smaller provider with less SLA track record than the Big Three. If DeepSeek has an outage, slice-1 development is impacted. Mitigation: Anthropic fallback works for development; the smoke test can be configured to use Anthropic-only via env var.
- A reader of the PRD might expect Anthropic to be primary; this ADR is the canonical answer to "why DeepSeek?"
- Cost-per-call accounting must already understand DeepSeek's response shape in slice 1, locking us into one cost-extraction pattern early.

**Neutral**

- The `Provider` protocol must support both "OpenAI SDK + base_url" and "native SDK" callers; this surfaces the right abstraction sooner.

## Slice-2 implications

- When tiered routing lands (PRD §6.6), DeepSeek-primary becomes a *tier-default*, not a *router-default*. The router gains a tier parameter.
- The capability-fallback machinery added in slice 2 must continue to honour the cost ordering: try cheap first, fall back to expensive only when capability requires it (vision, long context, etc.).
