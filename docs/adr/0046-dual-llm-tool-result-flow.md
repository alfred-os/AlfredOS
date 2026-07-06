# ADR-0046: Dual-LLM tool-result-flow trust boundary

- **Status:** Accepted
- **Date:** 2026-07-06
- **Deciders:** #339 (LLM tool-calling epic), PR2; 7-agent plan-review (design spec §13/§14)
- **Related:** [ADR-0041](0041-web-fetch-fused-fetch-extract-contract.md) (web.fetch fused
  fetch+extract contract), [ADR-0045](0045-provider-tool-protocol.md) (provider
  tool-protocol seam), the #339 design spec
  (`docs/superpowers/specs/2026-07-05-issue-339-llm-tool-calling-design.md` §3/§9/§13),
  PRD [§7.1](../../PRD.md#71-security--prompt-injection-defense)

## Context

The textbook agentic tool-calling loop feeds a raw tool result straight back to the
planner LLM's next completion request. HARD security rule #5 (CLAUDE.md; PRD §7.1)
forbids exactly this: the privileged orchestrator never sees raw T3 content — only the
quarantined LLM does, and only via structured extraction. A tool-calling loop is the
shape that rule was written to constrain, because a tool result *is* attacker-influenced
content the instant the tool is external (web fetch, MCP output, file read).

Issue #339 PR2 (`src/alfred/orchestrator/tool_dispatch.py`, `tool_registry.py`,
`tool_hookpoints.py`) builds the chokepoint every tool call crosses before its result
reaches the planner. The design question this ADR answers: how does a T3 tool result get
from "bytes an untrusted origin sent back" to "a string the privileged orchestrator can
safely inject into its next completion request" — and what stops a tool's own manifest
from lying about how trustworthy its output is.

## Decision

**1. The tool-result-flow invariant.** A T3-sourced tool result crosses two independent
gated boundaries, both mandatory and both audited, before it reaches the planner:

```
dispatch_web_fetch(...)                                    # fused fetch+extract, ADR-0041
  -> EgressExtractOutcome (T2: Extracted | TypedRefusal)
  -> downgrade_to_orchestrator(data, gate=gate, audit_writer=audit)   # 2nd clearance gate
  -> OutboundDlp.scan(json.dumps(cleared))                            # DLP over the T2
  -> tool_result string handed to the planner
```

`dispatch_web_fetch` already performs the T3->T2 quarantine-extract crossing
(ADR-0041). `dispatch_tool` (`tool_dispatch.py:49`) adds the second crossing —
`downgrade_to_orchestrator` gate-checks (`t3.downgrade_to_orchestrator`, content
tier T3) and audits the T3-derived->T2 transition — plus a third, independent pass, DLP,
over the downgraded JSON before it is ever handed to the planner. The planner sees only
schema-extracted, downgrade-cleared, DLP-scanned T2 — never raw T3, and never T2 that
skipped either gate.

**2. `result_tier` defaults to T3; only a hardcoded allowlist may claim less.**
`ToolSpec.result_tier` (`tool_registry.py`) defaults to `"T3"` for every
`ExternalToolSpec`. A tool may declare `result_tier="T2"` (the `InternalToolSpec`
direct-dispatch path — no quarantine-extract, no DLP) only if its name is in
`FIRST_PARTY_LE_T2_TOOL_ALLOWLIST` (`tool_registry.py:26`, currently `{"clock.now"}`) —
a frozen, hardcoded set a plugin manifest can never add to. `ToolRegistry.__init__`
enforces this at construction: a spec claiming <=T2 outside the allowlist raises
`ToolTierClaimError` before the registry is usable at all (sec-001/rev-002).

**3. Why the internal <=T2 tool skips DLP.** `clock.now`'s `InternalToolSpec` dispatch
(`dispatch_tool`, `tool_dispatch.py:157-162`) returns its content straight to the planner
with no `OutboundDlp.scan` call. This is not a gap in the T3 tool-result flow — it is a
distinct, narrower claim: the tool is first-party, server-generated, and never touches
external content, so there is no secret or canary risk a DLP pass would catch that the
allowlist gate did not already rule out at construction time. Framed against CLAUDE.md
hard rule #4 ("DLP is on by default and cannot be disabled per-call; pure-internal tools
can declare 'no DLP needed' once in their manifest and the test suite verifies the
claim"): the allowlist entry *is* that declaration, and
`test_internal_le_t2_tool_must_be_on_allowlist` (PR2) is the verification — the claim is
proven at construction time, not assumed at dispatch time. The allowlist is the surface a
future first-party tool must earn a place on before its output can skip the T3 leg.

**4. Escalation vs. recoverable failure classification.** Every `dispatch_tool` branch
writes exactly one `tool.dispatch` audit row (HARD rule #7) — audit subjects carry only
closed-vocabulary tokens (`tool_name`, `call_id`, `call_index`, `result_tier`,
`dispatch_outcome`, correlation id), never raw arguments, URLs, or `str(exc)`. Two
classes of outcome:

- **Escalate (halt the turn, re-raise):** `InboundCanaryTripped`, `OutboundCanaryTripped`
  (a canary surfacing in the *extracted* T2, audited as `dlp_canary`), and a downgrade-
  clearance denial (`downgrade_denied`) — a gate refusal at the T3-derived->T2 crossing
  is a security event, not a retryable tool failure. An unexpected or un-enumerated
  exception anywhere in the dispatch or post-dispatch (downgrade -> DLP) region also
  escalates (`unexpected_error` / `fault`) rather than silently degrading to a
  recoverable result — a bug or a new error type must never masquerade as ordinary tool
  failure.
- **Recoverable (T2 error `tool_result`, planner adapts):** unknown tool, invalid
  arguments, gate-denied, domain-not-allowed, rate-limited, tool-error, timeout.

**5. Intra-turn tool history is ephemeral (D3).** The in-turn tool-call transcript built
across a turn's iterations is not persisted to episodic memory in #339 — only the final
assistant answer is, as today. This keeps the `Episode.role` DB CHECK (`user` /
`assistant` only) fail-closed without a migration. Forensic reconstruction of a turn's
tool activity relies on the `tool.dispatch` audit rows (design spec §10), not on memory
rehydrate.

## Consequences

- **Production wiring needs three first-party grants PR2 did not seed.** The live path
  requires `tool.dispatch` (subscriber-tier, `TOOL_DISPATCH_PLUGIN_ID`),
  `quarantine.dereference` (content-tier T3), and `t3.downgrade_to_orchestrator`
  (content-tier T3) all approved. PR2 is fixture-tested only (`make_allow_system_gate`
  and similar test helpers) and is deliberately **not** the first live caller. PR3
  (#399) now seeds all three grants at boot in `FIRST_PARTY_SYSTEM_GRANTS`
  (`src/alfred/security/capability_gate/_bootstrap_grants.py`), and the daemon's
  post-install grant assertion checks the same constant with an axis-faithful
  liveness check (subscriber-tier `tool.dispatch` via `gate.check`; content-tier
  `quarantine.dereference` / `t3.downgrade_to_orchestrator` via
  `gate.check_content_clearance`) before accepting boot — the trust boundary is
  live, not pending. A missing grant still fails loud at the gate rather than
  silently succeeding with an unintended trust posture.
- **`dispatch_tool` imports `web_fetch`-plugin-specific exception types**
  (`WebFetchDomainNotAllowed`, `WebFetchError`, `WebFetchRateLimited`) directly. This is a
  deliberate one-tool layering inversion, acceptable while `web.fetch` is the only T3
  tool. A follow-up (arch-003) introduces a common tool-error taxonomy once a second T3
  tool lands, so `dispatch_tool` stops depending on any single plugin's error hierarchy.
- The `result_tier`-defaults-to-T3 rule and the allowlist gate are now the one place a
  future tool integrator reasons about trust: a new external tool inherits T3 for free; a
  new <=T2 tool costs a deliberate, test-verified allowlist entry.
- `downgrade_to_orchestrator`'s existing gate + audit contract (`quarantine.py:1444`,
  documented in [docs/subsystems/security.md](../subsystems/security.md)) is reused as-is
  for the tool-result leg — no new downgrade mechanism, only a new caller.

## Alternatives considered

### Trust the tool manifest's declared result tier

Let a plugin manifest declare its own `result_tier` and honor it directly. Rejected
(sec-001/rev-002): a plugin manifest is attacker-adjacent — a compromised or malicious
plugin would simply declare `T2` and skip quarantine entirely. PRD §7.1 already treats
MCP/plugin output as T3 by default; trusting a self-declared tier defeats that model. The
hardcoded allowlist keeps the "which tools skip quarantine" decision in host-controlled
code, verified by a construction-time test — never runtime-configurable by anything a
plugin ships.

### Blanket-catch all dispatch exceptions into a recoverable tool_result

Catch every exception from a T3 tool's dispatch and downgrade/DLP path uniformly,
returning an error string in all cases. Rejected: this would swallow
`InboundCanaryTripped` and a downgrade-clearance denial into an ordinary-looking tool
failure the planner could shrug off and retry — the silent-failure-in-a-security-path
CLAUDE.md hard rule #7 forbids exactly this. Classifying escalation vs. recoverable
explicitly (Decision 4) keeps a canary trip a turn-halting event, not noise the loop
paves over.

### Persist intra-turn tool messages to episodic memory now

Store the full tool-call transcript so a later turn can recall what a tool returned
mid-conversation. Rejected for #339: this requires an `Episode.role` CHECK migration
(`user`/`assistant` -> also `tool`/`system`) and a rehydrate-path change, both out of
scope for a PR whose job is the trust-boundary chokepoint, not memory schema evolution.
Audit rows already give a forensic trail; faithful tool-turn memory is a tracked
follow-up, not a regression introduced here.
