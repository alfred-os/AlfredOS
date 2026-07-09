# ADR-0049 — Real privileged turn on comms inbound: the conversational-first cutover

- **Status**: Accepted (on #338 PR2 merge)
- **Date**: 2026-07-09
- **Slice**: 4 — #338 PR2 (`docs/superpowers/plans/2026-07-08-issue-338-pr2-daemon-cutover.md`)
- **Relates to**: [ADR-0015](0015-slice4-containerised-quarantined-llm.md) (Slice-4
  containerised quarantined LLM — #340, the sibling half this ADR does not touch),
  [ADR-0017](0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md) (the
  dual-LLM split this ADR wires a live privileged consumer into), [ADR-0029](0029-inline-over-wire-quarantine-content-path.md)
  (the inline-over-wire quarantine content path this cutover reuses unchanged),
  [ADR-0036](0036-gateway-adapter-hosting-inversion.md) (the gateway-hosted comms
  adapters this turn now answers), [ADR-0039](0039-gateway-adapter-inbound-bridge.md)
  (the forwarded-dispatch poison ceiling this ADR's accepted residual is bounded
  by), [ADR-0040](0040-connectivity-free-core-mandatory-egress-chokepoint.md) /
  [ADR-0042](0042-connectivity-free-core-cutover.md) (the connectivity-free core the
  new `ProviderRouter` must egress through), [ADR-0045](0045-provider-tool-protocol.md)
  / [ADR-0046](0046-dual-llm-tool-result-flow.md) (#339's tool-calling mechanism,
  closed with zero production callers until this ADR), issue #338 (epic), issue
  #339 (closed prerequisite), issue #340 (the deferred quarantine half)
- **Supersedes**: [ADR-0027](0027-daemon-comms-runtime-fixture-extractor-first-cut.md)
  in part — see Context

> **Sign-off flag.** This ADR records the first production wiring of the
> **privileged** half of the [dual-LLM split](../glossary.md#dual-llm-split) — the
> orchestrator that was, until this cutover, absent from the comms-inbound path
> rather than fed anything. Per CLAUDE.md's dual-LLM-boundary rule, this ships with
> `alfred-security-engineer` sign-off + the adversarial suite + 100% line-and-branch
> coverage on the boundary translator as release-blocking gates, mirroring the
> [ADR-0048](0048-web-fetch-authenticated-fetch-secret-substitution.md) precedent
> for a new trust-boundary contract landing in the same PR as its ADR.

## Context

[ADR-0027](0027-daemon-comms-runtime-fixture-extractor-first-cut.md) made the daemon
a live comms runtime but deliberately deferred the privileged orchestrator: standing
up `WorkingMemory`/`BudgetGuard`/`EpisodicMemory` and the dual-LLM split alongside
"the daemon spawns comms plugins and runs the inbound boundary" was "two epics in
one PR, on the most security-sensitive path in the system" (ADR-0027 Context). Its
`CommsInboundOrchestratorAdapter` satisfied the inbound `_OrchestratorLike` Protocol
(`quarantined_extract` / `ingest` / `dispatch`) with a deterministic `"ack"` — it
discarded the extracted result and never touched `handle_user_message`. ADR-0027
Decision 3 explicitly recorded this as a throwaway bridge future PRs would *replace,
not extend*.

Issue #339 closed the tool-calling **mechanism**: the Act-phase loop, `ToolRegistry`,
and the capability-gate/DLP ctor seams on `Orchestrator` all landed and are fully
tested. But `build_orchestrator` (`src/alfred/cli/_bootstrap.py:459`) and
`build_tool_registry` (`src/alfred/orchestrator/tool_assembly.py:68`) stayed
test-only — zero production callers. The comms-inbound path still ran the fixed-ack
placeholder; real Discord/TUI users never got a real LLM answer.

Wiring the full agentic loop live — egress tools advertised, `build_tool_registry`
wired into `build_orchestrator`, the deterministic-replay journal, the
[ADR-0048](0048-web-fetch-authenticated-fetch-secret-substitution.md) forward gates
— in the same PR as the first-ever live privileged-orchestrator caller would repeat
exactly the risk ADR-0027 was written to avoid: two epics, one PR, the
security-sensitive path. #338's own issue text lists "the LLM tool-calling (agentic)
loop" as out of scope; #339 closed that mechanism separately for a reason.

## Decision

**Ship a real *conversational* privileged turn on comms inbound, egress tools
deferred.** `RealTurnOrchestratorAdapter` (`src/alfred/comms_mcp/real_turn_adapter.py`)
replaces `CommsInboundOrchestratorAdapter` in `_build_comms_boot_graph`
(`src/alfred/cli/daemon/_comms_boot.py:807`), satisfying the SAME
`_OrchestratorLike` Protocol so every Spec A/B idempotency/replay invariant in
`process_inbound_message` stays untouched.

- **Empty tool registry → exactly one completion.** No `build_tool_registry` call;
  the [OODA loop](../glossary.md#ooda-loop) reduces to the proven single-completion
  shape `alfred chat` already exercises. This is the boundary the launch prompt's
  "`build_tool_registry` → `build_orchestrator` → the Act phase" describes as an
  eventual end-state, not this cutover's scope.
- **DM/1:1 reply only** (`_ADDRESSING_MODE="dm"`). `InboundMessageNotification`
  carries no channel/thread target id, so a group reply cannot be targeted; group
  `addressing_mode` derivation is an explicit follow-up.
- **The adapter owns the gate-checked T3→T2 downgrade, not `handle_user_message`.**
  `ingest` *prepares only*: on an `Extracted` result it calls
  `downgrade_to_orchestrator(data, gate=<boot RealGate>, audit_writer=<boot
  AuditWriter>)` (`quarantine.py:1444`) before `tag(T2, ...)`. `handle_user_message`'s
  contract already assumes pre-cleared `TaggedContent[T1|T2]` — proven by the
  `alfred chat` smoke path — so keeping the downgrade in the adapter keeps that
  contract unchanged and the boundary auditable at one site.
- **The turn + outbound send run inside `dispatch`, not `ingest`.** `ingest`'s
  refusal legs never propagate uncaught: a `TypedRefusal` returns a benign
  `t()` reply rendered in the user's language, a gate-DENY halts with a loud
  audit row, and only a `_PreparedTurn` reaches `dispatch`. Placing the (paid) turn
  itself inside `dispatch` means a turn failure takes the forwarded path's audited
  `dispatch_failed` + bounded-replay handling (`inbound.py:884`), instead of an
  uncaught exception from `ingest` propagating straight to the poison ceiling.
- **Adapter-owned loud, content-free audit rows on every deny/error leg**
  (`COMMS_INBOUND_TURN_REFUSED_FIELDS`, `audit_row_schemas.py:1450`): downgrade-denied,
  downgrade-malformed (a distinct stage from a policy deny), budget-denied,
  turn-error, and send-failed. Each is keyed by the peppered `inbound_id_hash`
  (`audit_hash.hash_inbound_id`), never the raw id; `error_class` is the exception's
  class name, never `str(exc)` (which could embed T3-derived text).
- **A per-`(persona, canonical_user_id)` turn mutex serialises the whole
  acquire→turn→release span.** The comms pump dispatches notifications
  concurrently (32/adapter semaphore, `comms_runner.py:663`), and
  [`WorkingMemoryPool`](../glossary.md#workingmemorypool)'s own lock
  (`working_pool.py:135-146`) guards only rehydrate, not a turn — two concurrent
  same-user frames would otherwise race the one shared `deque`. The adapter holds
  its own `asyncio.Lock` per key across `pool.acquire → handle_user_message →
  pool.release` (`real_turn_adapter.py:382-409`).
- **The orchestrator assembly reuses the boot graph's already-built components.**
  `build_orchestrator` (DI-refactored, `_bootstrap.py:459`) takes the graph's
  already-built `broker`/`resolver` plus a freshly-built proxied `ProviderRouter`
  (`_comms_boot.py:785`) — never a bare `build_orchestrator(settings)`, which would
  double-build the broker and re-fire the process-global
  `install_identity_factories_for_settings` (desyncing the identity version
  counter). A `router_override` seam keeps boot-graph tests offline.
- **Three audited refuse-boot arms** guard the new construction-time dependencies
  (`_commands.py:715-767`, `_failures.py:269-330`), all fail-closed (exit 2,
  audited `daemon.boot.failed`) rather than an uncaught traceback (the #368
  anti-pattern): `EgressPlaneUnavailableFailure` (`IOPlaneUnavailableError` —
  reachable, `ALFRED_EGRESS_PROXY_URL` is optional), `RouterSecretMissingFailure`
  (`UnknownSecretError` — defense-in-depth; `deepseek_api_key` is a required
  `Settings` field, so an earlier guard catches this first today), and
  `OperatorNotSeededFailure` (`IdentityResolutionError` — reachable; the real
  `Orchestrator.__init__` now synchronously calls `identity_resolver.get_operator()`
  at boot, `core.py:308`).

## Consequences

### Positive

- Real users on the comms-inbound path get a real LLM answer for the first time —
  the MVP-critical graduation this epic exists for.
- The dual-LLM invariant (PRD §7.1 / DEC-007: the privileged orchestrator never
  sees raw T3) is upheld at one auditable site — the adapter, not
  `handle_user_message` — matching how ADR-0027 kept the invariant honest by
  keeping the privileged side *absent* rather than mis-fed.
- The cutover stays incremental and reviewable: the conversational wiring (#338)
  is separated from egress-tools-on, mirroring ADR-0027's own decision to separate
  the runtime substrate from the privileged orchestrator + dual-LLM split.

### Negative

- **Forwarded-path bounded double-apply residual (accepted).** The forwarded
  comms path commits *after* a successful dispatch
  (`commit_at_dispatch_edge=True`, `inbound.py:917-935`). `handle_user_message`
  commits episodic rows and charges the in-process budget guard *before* that
  commit point, so a crash between a successful turn and the commit replays the
  frame and re-runs the turn: the episodic transcript double-writes and the
  budget double-charges. This is bounded by the forwarded-dispatch poison ceiling
  (5, `inbound.py:201`, [ADR-0039](0039-gateway-adapter-inbound-bridge.md) item
  4b) and never crosses a user partition — tested (exactly-twice on one injected
  failure). The deterministic-replay **journal** (tools-on follow-up) is the
  durable fix; making the episodic write + budget charge `inbound_id`-idempotent
  is a ratifiable in-scope alternative, deliberately not implemented here.
- **New operational precondition.** A comms-enabled `alfred daemon start` now
  hard-requires exactly one pre-seeded `authorization=operator` user — previously
  the daemon never touched identity resolution before a live turn ran. An operator
  must run `alfred user add --name <name> --authorization operator` before first
  boot with comms enabled, or boot refuses (`OperatorNotSeededFailure`).
- `CommsInboundOrchestratorAdapter` (the echo adapter) is retained as the
  documented rollback fallback (per ADR-0027 Decision 3) but is now dead on the
  production path — a bit-rot risk if this cutover is never revisited.
- **New trust surface: `display_name` reaches the privileged prompt outside
  the downgrade seam (accepted, guarded).** Unlike the extracted T3 body —
  always gate-checked through `downgrade_to_orchestrator` before it reaches
  the orchestrator — the platform-supplied, adversary-influenced
  `display_name` metadata (`RealTurnOrchestratorAdapter`'s
  `_InboundUser.display_name`) flows straight into `render_persona_prompt`'s
  `requesting_user_name` substitution with NO T3→T2 downgrade step. This is
  correct-by-design (it is resolved identity metadata, not extracted T3 body
  content, so CLAUDE.md hard rule #5 does not apply), but it is a real,
  untrusted, platform-influenced input reaching the PRIVILEGED persona
  prompt. The only containment is `render_persona_prompt`'s `html.escape` of
  every `<user_context>` substitution, pinned by the `pi-2026-014`
  adversarial corpus entry
  (`tests/adversarial/prompt_injection/test_pi_2026_014_inbound_display_name_injection.py`).

### Neutral

- Egress tools, the deterministic-replay journal, and the
  [ADR-0048](0048-web-fetch-authenticated-fetch-secret-substitution.md) forward
  gates (per-secret↔destination binding, the one-broker-instance invariant, the
  gateway re-scan residual) are explicitly deferred to the tools-on follow-up
  (spec §9) — this ADR records the boundary the follow-up inherits, not the
  mechanism itself.
- Group / multi-persona addressing stays out of scope; `InboundMessageNotification`
  needs a wire-widening to carry a channel/thread target id before it is
  reachable.
- `handle_user_message` gains an optional `egress_context: TurnEgressContext |
  None` parameter with a synthesis fallback (`_synthesize_egress_context`,
  `core.py:1108`) — behaviour-neutral for every existing caller (`alfred chat`,
  fixtures, tests); the real identity now threads through for the comms caller,
  future-proofing the tools-on wire without activating it.
- **The HARD#5 provenance test uses a schema-extracting child double, not the
  production echo child.**
  `tests/integration/comms_mcp/test_real_turn_inbound_boundary.py`'s
  provenance proof substitutes `_ExtractionAwareChildDouble` (which performs
  the SAME `CommsBodyExtraction{text, intent}` schema-shaped extraction a
  real quarantined LLM would) rather than the `_EchoingChildDouble` every
  other integration test in this tree uses — the echo double's verbatim-echo
  behaviour would make the "the schema drops framing keys" property
  untestable. Production today runs the echo child (the real quarantine
  child is #340), so this provenance property MUST be RE-VALIDATED against
  the real extractor's actual schema once #340 lands — the double is a
  faithful stand-in for the CONTRACT, not proof the contract holds against
  the eventual real implementation.

## Alternatives considered

### Option A — Ship egress tools live in the same PR

The launch prompt's literal "`build_tool_registry` → `build_orchestrator` → the Act
phase" reads as one PR. Rejected: reachable egress tools before the
deterministic-replay journal and the ADR-0048 forward gates land would turn the
forwarded-path replay hazard from bounded episodic/budget bookkeeping into an
unbounded double-fire risk on live network side effects (the mem-001 hazard) — the
exact "two epics, one PR, the security-sensitive path" pattern ADR-0027 avoided.

### Option B — Route the T3→T2 downgrade inside `handle_user_message`

Rejected: `handle_user_message`'s contract already assumes pre-cleared
`TaggedContent[T1|T2]`, proven by the `alfred chat` smoke path. Moving the downgrade
inside would special-case the comms caller, duplicating boundary logic at a second
site instead of keeping the one auditable adapter-owned seam ADR-0027's Decision 2
already established as the pattern.

### Option C — Rely on `WorkingMemoryPool`'s own lock instead of an adapter-owned mutex

Rejected by inspection, not assumption: the pool's per-key lock
(`working_pool.py:135-146`) guards only rehydrate — `_in_use` is a set, not a
refcount, and nothing serialises the turn itself. Two concurrent same-user frames
(the comms pump's 32-wide semaphore, `comms_runner.py:663`) would race the one
shared `deque`. This was the plan-review's sole Critical finding (FOLD-R1); the
adapter's own `asyncio.Lock` per `(persona, slug)` closes it.

## References

- [PRD §5 Architecture Overview](../../PRD.md#5-architecture-overview) — the
  privileged-orchestrator / quarantined-LLM split diagram this ADR wires a live
  caller into.
- [PRD §7.1 Security & Prompt Injection Defense](../../PRD.md#71-security--prompt-injection-defense)
  — DEC-007, the non-negotiable dual-LLM invariant.
- [ADR-0027](0027-daemon-comms-runtime-fixture-extractor-first-cut.md) —
  superseded in part: its Decision 2/3 deferred bridge (`CommsInboundOrchestratorAdapter`)
  is now *replaced*, exactly as its own Decision 3 forecast, not extended.
- Spec: [2026-07-08-issue-338-real-llm-turn-graduation-design.md](../superpowers/specs/2026-07-08-issue-338-real-llm-turn-graduation-design.md)
- Plan: [2026-07-08-issue-338-pr2-daemon-cutover.md](../superpowers/plans/2026-07-08-issue-338-pr2-daemon-cutover.md)
- Glossary: [dual-LLM split](../glossary.md#dual-llm-split), [trust tier](../glossary.md#trust-tier),
  [T3 (untrusted-ingestion tier)](../glossary.md#t3-untrusted-ingestion-tier),
  [T3DerivedData](../glossary.md#t3deriveddata), [WorkingMemoryPool](../glossary.md#workingmemorypool),
  [BudgetGuard](../glossary.md#budgetguard), [OutboundDlp](../glossary.md#outbounddlp),
  [OODA loop](../glossary.md#ooda-loop), [in_doubt](../glossary.md#in_doubt),
  [committed_no_response](../glossary.md#committed_no_response),
  [committed_with_response](../glossary.md#committed_with_response).
