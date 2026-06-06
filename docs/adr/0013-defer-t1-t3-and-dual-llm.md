# 0013 — Defer T1 operator tier, T3 untrusted ingestion, and dual-LLM split to Slice 3

- **Status**: Superseded by [ADR-0017](0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md) — Slice 3 delivers the full stack this ADR committed to
- **Date**: 2026-05-27
- **Slice**: 2 — `docs/superpowers/plans/2026-05-26-slice-2-pr-A-identity.md`
- **Supersedes**: [ADR-0008](0008-llm-output-trust-tier.md) (in part)
- **Superseded by**: [ADR-0017](0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md) (2026-05-31)

## Context

[ADR-0008](0008-llm-output-trust-tier.md) introduced AlfredOS's trust-tier
discriminant for LLM output and committed three additional surfaces to land
in Slice 2:

- **T1** — operator-tier content marking on TUI ingress and outbound.
- **T3** — untrusted-content tagging at every external-ingestion boundary
  (web, email, file, MCP tool output, inter-persona relay).
- **Dual-LLM split** — the privileged orchestrator never sees raw T3; a
  quarantined LLM does, and only via structured-extraction handoff. PRD
  §7.1 names this as the load-bearing prompt-injection defence.

Revised Slice 2 scope (multi-user identity + Discord adapter + file-backed
secret broker + per-user budget guard + working memory pool + rate limiter,
outbound DLP scan) is already wide enough for one slice. Adding T1, T3,
and the dual-LLM split — three load-bearing security surfaces, each with
its own test corpus and review burden — would roughly double the
changeset and miss the merge window.

The contradiction with ADR-0008's original commitment needs to land on
`main` explicitly. Otherwise a future reader treats ADR-0008 as the
authoritative commitment for Slice 2 and writes downstream code against
trust tiers that do not yet exist.

## Decision

Slice 2 ships [trust tier](../glossary.md#trust-tier) **T2 only** (authenticated user).
Specifically:

- Discord DM bodies are tagged T2 at ingestion. Every other content-bearing
  Discord field (`embeds`, `attachments`, `stickers`, `reference`, `poll`,
  `components`, `activity`, `application`) is **refused at the boundary**,
  not silently inlined as T3. The orchestrator's contract accepts
  `TaggedContent[T2]` only.
- T1 (operator-tier marking on TUI ingress + outbound), T3 (untrusted
  tagging at every external boundary), and the privileged ↔ quarantined
  LLM split are **rescheduled to Slice 3**.

Slice 3 ships the full trust-tier stack alongside the MCP plugin transport
(the privileged ↔ quarantined LLM split runs as MCP plugins under that
transport). One coherent slice closes the trust-tier story; ADR-0008's
amendment record already names this ADR as the partial superseder.

## Alternatives considered

- **(a) Ship everything in Slice 2 as ADR-0008 originally committed.**
  Rejected. The Slice-2 surface area (Discord + identity + file broker +
  per-user budget + WMP + rate-limiter + DLP scan) is already large enough
  for one slice; adding T1+T3+dual-LLM would double the changeset and miss
  the merge window. Slice splits exist to keep individual slices
  reviewable.
- **(b) Ship T1 only (operator-tier marking) without T3 or dual-LLM.**
  Rejected. T1 alone is wasted scaffolding without T3 — the whole point
  of the operator tier is to distinguish operator-originated content from
  authenticated-user content from untrusted-ingestion content, and the
  discriminator only earns its keep when T3 is also present. The DB
  rows would mark every row T1 from one source and T2 from another with
  no third value present, which is no information.
- **(c) Ship T3-tagging at the comms boundary without the dual-LLM
  split.** Rejected. T3 content without the quarantined LLM is
  taint-tagging only, which provides no actual prompt-injection defence.
  The whole point of T3 is that the privileged orchestrator never sees
  it — that is the PRD §7.1 invariant. Slice 3 must commit the full
  stack to honour that invariant.
- **(d) Chosen — Defer all three to Slice 3 alongside the MCP plugin
  transport.** The quarantined LLM runs as a plugin under that
  transport, so the dependency edges align: MCP plugin host →
  quarantined LLM → T3 tagging on every plugin output. One coherent
  slice closes the trust-tier story.

## Consequences

**Slice 2 acquires no T3 exposure.** Every external-ingestion boundary
that would carry T3 content under ADR-0008's original commitment instead
refuses the content:

- **Discord embeds/attachments/stickers/poll/components/activity/
  application/reference** are refused at the boundary with an audit row
  and a polite `discord.embed_unsupported` reply. The orchestrator is
  never invoked.
- **`web.fetch`, `email.read`, and `mcp.tool.output`** do not yet exist
  as Slice-2 tools. They land in Slice 3 with T3 tagging from day one.

The discriminator `TaggedContent[T2]` is a type-level guarantee in the
orchestrator's input contract for Slice 2. Slice 3 introduces
`TaggedContent[T3]` as a new type-level discriminant, not a runtime flag —
the type system enforces that T3 cannot reach a T2-only path without an
explicit `quarantined_to_structured()` conversion.

**Slice 3 commits the full stack.** Slice 3 ships:

- T1 (operator-tier marking on TUI ingress + outbound).
- T3 (untrusted-content tagging at every external-ingestion boundary).
- The privileged ↔ quarantined LLM split via the MCP plugin transport.
- The first real T3-ingesting tool (`web.fetch`).

ADR-0008's amendment note already records `Superseded in part by
ADR-0013`. After Slice 3 lands, this ADR's Status flips to "Superseded
by ADR-NNNN" where NNNN is the Slice-3 ADR that commits the full stack.

**No `main`-resident drift.** ADR-0013 lands on `main` as a placeholder
body at PR-A merge; this PR (PR-E) supplies the full prose. Between
PR-A merge and PR-E merge, a reader of ADR-0008 sees the supersession
edge but no rationale — acceptable because the placeholder explicitly
says "full body in PR E."

ADR-0013 deferred T1+T3+dual-LLM to Slice 3. Slice 3 delivered all three per this commitment. ADR-0017 supersedes this ADR and records the five structural decisions that govern the implementation. The Slice-3 tracking issues for §6.10 deferred items are retired in PR-S3-7.

## References

- PRD §7.1 — security & prompt-injection defence; the dual-LLM split is
  the load-bearing invariant.
- PRD §7.2 — multi-user identity model that Slice 2 actually ships.
- [ADR-0008](0008-llm-output-trust-tier.md) — LLM output trust tier;
  superseded in part by this ADR for the Slice-2 commitment surfaces.
- [ADR-0009](0009-comms-adapter-protocol-slice2-only.md) — Slice-2-only
  in-process comms-adapter Protocol; Slice 3 rewrites this to the MCP
  transport under which the dual-LLM split runs.
- [ADR-0010](0010-canonical-user-id-and-listen-notify.md) — canonical
  user_id, the Slice-2 identity primitive that T2 keys on.
- [`docs/subsystems/comms.md`](../subsystems/comms.md) — Discord ingress
  allowlist that bounds Slice-2 trust-tier exposure to T2 only.
- [Glossary: trust tier](../glossary.md#trust-tier).
