# 0008 — LLM output is T2 in Slice 1 (not T0)

- **Status**: Superseded by [ADR-0017](0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md) — Slice 3 delivers the full trust-tier stack this ADR committed to in Slice 1/2
- **Date**: 2026-05-26
- **Slice**: 1 (`docs/superpowers/plans/2026-05-24-slice-1-hello-alfred.md`)
- **Supersedes**: —
- **Superseded by**: [ADR-0017](0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md) (2026-05-31)

## Context

PRD §7.1 defines the AlfredOS trust tiers:

- **T0 — System.** AlfredOS internals: source code, prompts, configs, system
  policies. Highest trust; runs with full capability.
- **T1 — Operator.** Direct, authenticated operator input — typing into the
  TUI, voice, signed messages from the operator's devices. Lands in Slice 2/3
  when AlfredOS first distinguishes operator-from-user input.
- **T2 — Authenticated user.** Known, identified users who are not the
  operator (family member, colleague, etc.).
- **T3 — Untrusted ingestion.** Web pages, email bodies, file contents, MCP
  tool outputs, anything the dual-LLM split holds at arm's length. Lands
  alongside the quarantined-LLM in Slice 2.

The initial Slice-1 orchestrator tagged provider responses as `T0`. That was
wrong on two counts:

1. **Definitionally wrong.** Provider output is LLM-generated text. The T0
   tier is reserved for AlfredOS-authored internals — source files, prompt
   templates, security policies, configs. An LLM completion is none of those
   things. Tagging it T0 inflates its trust above the operator input that
   triggered it, which is the opposite of the invariant the tier system is
   meant to enforce.
2. **Trust-bound violation.** A response is at-most-as-trusted-as the input
   that produced it. The user input is T2 (Slice 1 has no operator
   distinction yet), so the response cannot exceed T2.

Tagging assistant output T0 also broke the future invariant the audit log
will need: "the LLM never sees raw T3, and never produces output more trusted
than its input." Today there is no T3 ingestion, so the bug doesn't have an
exploit, but Slice 2 introduces T3 the moment a web-fetch or email-read tool
lands — at which point the bug becomes a sandbox-escape.

## Decision

In Slice 1, **assistant output is tagged T2** at the orchestrator boundary
(`src/alfred/orchestrator/core.py`).

Slice 1 ships only T0 and T2:

- **T0** — Alfred's own source, prompts, configs (untouched at runtime).
- **T2** — Both user input AND assistant output. Same tier because Slice 1
  has no operator/user distinction yet; the only "user" is the single
  operator, and the response is constrained to that operator's trust ceiling.

T1 and T3 are deliberately deferred to Slice 2 alongside the dual-LLM split.

Slice 2 will refine:

- **T1** — Operator input becomes its own tier, distinguishable from T2.
- **T1** — Provider output from the privileged orchestrator becomes T1
  (at-most-as-trusted as the T1 operator input that triggered it).
- **T3** — Untrusted ingestion (web/email/files/tool output) becomes its own
  tier. The quarantined LLM (PRD §7.2) is the only component that handles
  T3 directly; the privileged orchestrator only ever sees T3-via-structured-
  extraction.

## Alternatives considered

- **Keep T0 for assistant output and add T3 instead.** Rejected — even with
  T3 separated, T0 is still definitionally wrong for LLM output. Fixing the
  semantics now is cheaper than threading the bug through the rest of Slice 1
  and unwinding it in Slice 2.
- **Introduce T1 in Slice 1.** Rejected — the operator/user distinction has
  no consumer yet (Slice 1 is single-operator), and introducing T1 without
  the dual-LLM split obscures what T1 will actually mean. Keeping the tier
  alphabet minimal in Slice 1 (T0 + T2 only) keeps the slice's surface area
  small and the invariants enforceable.
- **Add a new T-tier specifically for LLM output.** Rejected — the tier
  hierarchy is about trust, not provenance. Provenance ("this string came
  from a provider") belongs in the `source` metadata field on
  `TaggedContent`, which we already populate (`source=f"provider.{model}"`).

## Consequences

- `tests/unit/orchestrator/test_core.py` asserts `trust_tier == "T2"` on
  the assistant episode (was `"T0"`).
- The audit log's `trust_tier_of_trigger` for `orchestrator.turn` events
  is `T2` for both directions of the turn (the trigger is the user input;
  the response inherits the trigger's tier in the audit row, not the
  response's own tier).
- The `T0` import is removed from `src/alfred/orchestrator/core.py`. T0
  remains exported from `src/alfred/security/tiers` for system-source
  callers (system-prompt assembly etc.) that legitimately handle AlfredOS
  internals.
- Slice 2's dual-LLM PR introduces T1 + T3 and updates this ADR's status
  to "Superseded by 00NN" referencing the new tier-refinement ADR.

## References

- PRD §7.1 — Trust tiers and the input-tagging invariant.
- PRD §7.2 — Dual-LLM split (Slice 2).
- `src/alfred/security/tiers.py` — Tier type definitions.
- `src/alfred/orchestrator/core.py` — `tag(T2, response.content, ...)`.
