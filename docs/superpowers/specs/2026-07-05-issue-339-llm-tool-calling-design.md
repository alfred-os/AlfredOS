# Design: LLM tool-calling (agentic) subsystem — issue #339

**Status:** DRAFT (rev. 2, post plan-review) — awaiting design sign-off before writing-plans.
**Epic:** #339 (blocker on the MVP critical path #339 → #338 → #340).
**Date:** 2026-07-05.
**Author:** AI agent (brainstorming pass; revised after a 7-reviewer plan-review — see §15).

> This is the converged epic design. Like #351, it produces ONE design doc for
> the whole epic (the cross-cutting architecture + invariants + the PR
> decomposition); each PR then gets its own thinner plan as we reach it.

---

## 1. Problem

AlfredOS cannot let a model call a tool. Three verified gaps:

1. **The provider abstraction cannot represent a tool call.**
   `CompletionRequest` / `CompletionResponse` are `frozen, extra="forbid"` with
   no `tools` / `tool_choice` / `tool_use` / `tool_calls` / `stop_reason`
   fields (`src/alfred/providers/base.py:93,110`); `Message{role, content}` has
   roles `{system, user, assistant}` only — no `tool` role.
2. **Neither adapter carries tool data.** Anthropic discards non-text blocks
   (`anthropic_native.py:135`); DeepSeek never sends/reads `tool_calls`
   (`deepseek.py:132-147`). The `ProviderCapability.TOOL_USE` enum member is
   declared-but-dead, and the DeepSeek capability table (`deepseek.py:70-74`)
   lists deepseek-chat as `{JSON_OBJECT_MODE}` only.
3. **The Act phase is a single `router.complete(request)`**
   (`orchestrator/core.py:750`) — no loop, no dispatch. Consequently every tool
   is unreachable: `dispatch_web_fetch` has **zero production callers**
   (`plugins/web_fetch/fetch_dispatcher.py:182`).

This epic builds the tool-calling subsystem so a model can actually invoke
tools — under AlfredOS's hard trust-boundary, egress-idempotency, and
connectivity-free-core constraints.

## 2. Scope decision (adopted)

**#339 = mechanism + smoke.** It delivers the provider seam, the agentic
act-phase loop, and the trust-boundary integration, proven with **recorded
fixtures** (unit/integration) as the **release-gating** signal, **plus** a
real-LLM smoke test in `tests/smoke/`. It does NOT wire the live comms turn
(that is **#338**) and does NOT ship the real-LLM quarantine child (that is
**#340**).

Release-gate discipline (plan-review, test/security lens):

- The **deterministic fixture + adversarial suite is the merge gate**. The
  real-LLM smoke test is **nightly / retry-tolerant**, runs on a **cheap-tier
  model under the budget guard**, and is NOT a per-commit gate (a live model's
  behaviour is too flaky to block merges on).
- The loop runs against today's **deterministic-echo** extractor for fixtures.
  The echo child emits a fixed `{text, intent}` shape, so it validates only the
  **structural containment** of the T3 leg (that raw T3 never reaches the
  planner), NOT the quarantined LLM's injection robustness — that is **#340**.
- The echo extractor MUST be guarded out of the production assembly path, and
  **#338 must not go live before #340's real child + a full adversarial pass**.

Rationale: the issue and the MVP scorecard both treat #339/#338/#340 as
separate epics; the small-PR cadence forbids a mega-epic; and this mirrors how
G7-2 shipped the egress *spine* with a synthetic driver, then cut over live.
This resolves the issue's apparent circular dependency ("#339 blocked-by
real-turn-graduation" vs. "MVP: #338 depends on #339"): #339 builds the
mechanism proven by fixtures; #338 does the live cutover.

**Build order vs go-live order (these differ — do not conflate them).** The MVP
scorecard's "#339 → #338 → #340" is a *criteria-unlock* ordering (which epic
lights up which acceptance criterion), not a deploy sequence. The *go-live*
constraint is the binding one: #339 lands first (mechanism), and #340's real
quarantine child must be live **before** #338's live comms cutover, because a
live tool turn routes T3 results through the quarantined LLM (§3) — shipping #338
against the echo extractor would expose the very injection surface #340 closes. #338 and #340 may be *built* in either order after #339; only the
cutover is ordered (#340 before #338). §12 and §15 restate this constraint.

## 3. The crux: the dual-LLM tool-result flow

The textbook agentic loop feeds a raw tool result back to the planner. **We
cannot** — HARD security rule #5: the privileged orchestrator never sees raw T3.
So the loop is:

```
privileged (planner) LLM emits tool_use request(s)
  → orchestrator dispatches each tool in deterministic order
      → tool returns T3 (external tools) or ≤T2 (internal first-party tools)
      → T3 path ONLY: raw T3 body → quarantined LLM extracts to the tool's
        declared schema → structured T2 (Extracted | TypedRefusal)
        → downgrade_to_orchestrator(gate, audit) → plain dict
      → the T2 dict is DLP-scanned before it is fed back to the planner
  → the structured T2 is fed back as the tool_result
  → planner re-completes until stop_reason != tool_use
```

The planner sees **only** the schema-extracted, DLP-scanned T2 — never raw tool
output. The sole sanctioned T3→T2 path is `quarantined_to_structured(handle,
schema, *, extractor, gate)` (`quarantine.py:1385`); putting the result into a
privileged prompt goes through `downgrade_to_orchestrator(data, *, gate,
audit_writer)` (`quarantine.py:1444`). `web_fetch`'s
`EgressResponseExtractor.handle` + `dispatch_web_fetch` is a working template
for the whole T3 leg — and `dispatch_web_fetch` **already** accepts `egress_ctx:
TurnEgressContext` and `call_index: int` (`fetch_dispatcher.py:188-189`), so
wiring it is "supply real values," not "rebuild the plumbing."

**Result-tier routing (fail-closed — security finding sec-001/rev-002):** a
tool's result tier is NOT trusted from an arbitrary plugin manifest. The threat
model says MCP / plugin / file / web outputs are **T3**. Therefore:

- `result_tier` **defaults to T3** (quarantine-extract path) for every tool.
- Only a **hardcoded first-party allowlist** of tools may declare `result_tier
  ≤ T2` (direct path), and the test suite **verifies the ≤T2 claim** (mirrors
  the DLP-manifest "no DLP needed" verification rule, CLAUDE.md security rule #4).
- The `web.fetch` tool is T3 (external egress); the #339 internal demo tool is
  a first-party ≤T2 tool on the allowlist.

## 4. Provider tool-protocol seam (design the seam first)

### 4.1 Two wire shapes to bridge

| | Anthropic (fallback provider) | OpenAI/DeepSeek (**primary** provider) |
| --- | --- | --- |
| request tools | `tools=[{name, description, input_schema}]`, `tool_choice={type: auto\|any\|tool}` | `tools=[{type:function, function:{name, description, parameters}}]`, `tool_choice="auto"\|"none"\|"required"\|{type:function,function:{name}}` |
| model asks for a tool | `content` block `{type:tool_use, id, name, input}`; `stop_reason="tool_use"` | `message.tool_calls=[{id, type:function, function:{name, arguments:<JSON string>}}]`; `finish_reason="tool_calls"` |
| sending a result back | `user` message with `{type:tool_result, tool_use_id, content}` block | `role:"tool"` message `{tool_call_id, content}` |

**Provider capability reality (plan-review, provider lens):** deepseek-chat
(the default `settings.deepseek_model`, V3) **does support OpenAI-style
function-calling** — the primary path can tool-call, so the flat shape (§4.2) is
justified. But **deepseek-reasoner does NOT support function-calling**. Since #339
keeps the router as primary→fallback with no capability routing, a
reasoner-primary config would silently 400 every tool turn. Therefore:

- PR1 **wires `TOOL_USE`** into the capability tables: deepseek-chat gains
  `TOOL_USE`; Anthropic declares `TOOL_USE` (model-invariant today).
- The tool-advertising path **gates on `TOOL_USE`**: if the resolved primary
  provider lacks `TOOL_USE`, the orchestrator **refuses loudly** (typed refusal +
  audit) rather than emitting a request the provider will 400 on.

### 4.2 Neutral internal representation (flat tool-role shape)

Chosen over Anthropic content-blocks because DeepSeek (the *primary* provider)
is flat-shaped, the flat form maps cleanly onto the existing `(role, content)`
storage with additive fields, and the Anthropic content-block ↔ flat mapping is
mechanical and localized to that adapter.

Models (all `frozen, extra="forbid"`; tuples for immutability):

```python
Role = Literal["system", "user", "assistant", "tool"]

class ToolDefinition(BaseModel):        # provider-neutral tool advertisement
    name: str
    description: str
    input_schema: Mapping[str, JsonValue]   # JSON Schema

class ToolCall(BaseModel):              # a parsed tool-use request OR its echo in history
    id: str
    name: str
    arguments: Mapping[str, JsonValue]  # DeepSeek JSON-string args are parsed to dict at the adapter

class ForcedTool(BaseModel):           # tool_choice: force exactly this tool (used by #340 constrained-gen)
    name: str

ToolChoice = Literal["auto", "none", "required"] | ForcedTool
StopReason = Literal["end_turn", "tool_use", "max_tokens", "stop_sequence", "other"]

class Message(BaseModel):              # + new optional fields, default-empty
    role: Role
    content: str = ""                   # may be "" on a pure-tool_calls assistant turn
    tool_calls: tuple[ToolCall, ...] = ()   # assistant only
    tool_call_id: str | None = None         # tool-role only (links the result to its call)

class CompletionRequest(BaseModel):    # + tools/tool_choice
    messages: list[Message]
    max_tokens: int = 1024
    temperature: float = 0.7
    tools: tuple[ToolDefinition, ...] = ()
    tool_choice: ToolChoice = "auto"

class CompletionResponse(BaseModel):   # + stop_reason/tool_calls
    content: str
    tokens_in: int; tokens_out: int; cost_usd: float; model: str
    stop_reason: StopReason = "end_turn"
    tool_calls: tuple[ToolCall, ...] = ()
```

All additions carry defaults, so the current single-completion path constructs
these unchanged. **Correction (plan-review arch-005/prov-002):** default-empty
fields are safe for *Python construction* but NOT on the *wire* — both adapters
currently pass a bare `m.model_dump()` to their SDK, which would now serialise
`tool_calls=[]` / `tool_call_id=null` onto every plain user/system message and
**400 the provider**. PR1 MUST replace the blanket `model_dump()` with
**per-role serialisation** that emits tool fields only on the roles that carry
them. `extra="forbid"` is preserved.

### 4.3 Adapter mapping obligations

- **Anthropic** (`anthropic_native.py`): map `tools`/`tool_choice` to the SDK
  shape; STOP discarding non-text blocks — parse `tool_use` blocks into
  `CompletionResponse.tool_calls`; map `stop_reason`. When sending history back,
  pack `role="tool"` messages into a `user` message carrying `tool_result`
  blocks keyed by `tool_use_id`, and pack assistant `tool_calls` into
  `tool_use` content blocks. Fixtures MUST round-trip a **multi-tool assistant
  turn** (multiple `tool_use` blocks + their paired `tool_result`s) so #340's
  constrained-gen port onto this seam is not lossy.
- **DeepSeek** (`deepseek.py`): pass `tools`/`tool_choice`; read
  `message.tool_calls` + `finish_reason`; **parse the JSON-string `arguments`
  into a dict at the boundary** — malformed JSON **fails loud** as a normalized
  parse error the loop turns into an error tool_result; emit `role:"tool"`
  messages verbatim; a `tool_call_id` must link to a real emitted call.

### 4.4 Reconciling the pre-existing aspirational shape

`security/quarantine_child/provider_dispatch.py` already calls an aspirational
`provider.complete(messages=, tools=, tool_choice=, response_format=)` and reads
`response.tool_use_input` — a shape no shipped adapter implements. That code is
in the **quarantine child** (separate process, unwired, echo today; the real
child is **#340**). Under this seam, constrained generation becomes
`complete()` with `tools=(one ToolDefinition,)` + `tool_choice=ForcedTool(name)`,
reading `response.tool_calls[0].arguments`. **#339 defines the unified seam; #340
ports `provider_dispatch` onto it.** #339 does not touch the child.

`response_format` / DeepSeek JSON-object mode (structured output WITHOUT tools)
is **out of scope** for #339 — the agentic loop uses `tools`, and constrained
generation (which still needs JSON-object mode as a fallback for a non-tool
provider) is #340's concern.

## 5. Determinism & the egress-id contract (reframed — resolves the Critical)

The G7-2 ledger keys egress on `compute_egress_id(TurnEgressContext, *,
call_index)` where `TurnEgressContext = (adapter_id, inbound_id, session_id)`
and `call_index` is a per-turn ordinal (`egress_id.py:30,61`). The ledger is
tri-state in Postgres (`IntentFresh` / `IntentReplayComplete` / `IntentInDoubt`,
`memory/egress_idempotency.py:91-109`), and `commit_intent` is an `INSERT … ON
CONFLICT (egress_id) DO NOTHING`. Today `call_index` is a required int fixed at
`0` in tests; #339 supplies **real** ordinals.

**Contract for #339:** `call_index` is a per-turn monotonic counter,
incremented **once per tool dispatch in deterministic iteration order** (never
completion order), assigned *before* dispatch. The loop dispatches sequentially
— **never `asyncio.gather()`** — so ordering is a hard invariant.

**What the ledger does and does NOT guarantee (plan-review Critical mem-001,
confirmed against the ledger code — corroborated by arch-001/sec-003/prov-003/
core-001):**

- The body-hash integrity check fires **only on an `egress_id` conflict** (same
  `call_index`). It catches a *divergent* request replayed at the **same slot**
  — loudly, via `EgressIdIntegrityError`.
- It does **NOT** provide at-most-once under **re-planning**. `egress_id` is a
  positional hash of `call_index`, and internal (non-egress) dispatches consume
  ordinals without writing a ledger row. So a non-deterministic resume that
  changes the count of internal dispatches before an egress call **shifts that
  egress call to a fresh `call_index` → a fresh `egress_id` → no conflict →
  `IntentFresh` → the side-effect fires again, SILENTLY** (the body-hash never
  runs, because it's a different row). This is a real silent-double-fire path.

**Why #339 is safe, and the #338 prerequisite.** In #339 the extractor is echo
and there is no live comms resume, so this is not reachable. But the design must
not carry a false at-most-once claim into #338. **Deterministic replay is a
hard #338 prerequisite:**

1. **Journal the committed ordered dispatch sequence** for the turn (tool name +
   args + assigned `call_index`, per dispatch). Spec-A resume **replays the
   journal** — it does NOT re-ask a fresh (stochastic) planner — so every
   `call_index` (and thus every `egress_id`) is reproduced exactly and the
   ledger dedups correctly. This is the guarantee.
2. **`temperature=0` on tool-calling completions** as defense-in-depth (not all
   providers are bit-deterministic at temp=0, so this hardens but does not by
   itself guarantee replay).

This is captured as an **ADR to be written in #338** (§13). `TurnEgressContext`
is built from the turn's adapter/inbound/session identity; for the fixture /
`alfred chat` path it is synthesized deterministically (as G7-2's synthetic
driver did), now with a real incrementing `call_index`. Same-URL-twice in one
turn correctly mints **distinct** egress-ids (distinct `call_index`) — two
intended fires, not a dedup collision (confirmed, mem-006).

## 6. Orchestrator act-phase loop

Replace the single `router.complete` (`core.py:750`) with:

```
base_messages = system + history                     # as today
local: list[Message] = []                            # in-turn tool transcript (ephemeral)
call_index = 0
for iteration in range(max_iterations):
    request = CompletionRequest(messages=base_messages + local,
                                tools=registry.definitions(), tool_choice="auto")
    if budget.would_exceed(user, budget.estimate_for(user, request)):
        refuse + audit; break
    try:
        response = await router.complete(request)     # NEVER gather()
    except Exception as exc:
        audit(phase=f"provider_call:{iteration}", result="provider_failed")   # re-establish the 7th arm
        raise
    try:
        budget.check_and_charge(user, response.cost_usd)
    except BudgetError as exc:
        force-record budget_overrun + audit; break     # money already spent — record, do not lose it
    audit(phase=f"provider_call:{iteration}", result="ok")
    if response.stop_reason != "tool_use" or not response.tool_calls:
        final = response.content; break
    if len(response.tool_calls) > MAX_TOOL_CALLS_PER_ITERATION:
        refuse + audit; break                          # bound intra-iteration fan-out
    local.append(assistant Message with response.tool_calls)
    for call in response.tool_calls:                   # deterministic order
        result_t2 = await dispatch_tool(call, call_index); call_index += 1
        local.append(tool Message(tool_call_id=call.id, content=truncate(result_t2)))
else:
    final = "reached max tool iterations"; audit(max_iterations_reached)
persist final assistant answer (as today); return final
```

`dispatch_tool` — every branch emits an audit row (§10):

- Resolve `registry[call.name]`; **unknown name → error tool_result + audit**
  (recoverable).
- **Validate `call.arguments` against the tool's `input_schema`; invalid →
  error tool_result + audit** (recoverable).
- **Capability gate** the dispatch (never bypass) — the tool's grant, via a
  named hookpoint, fixture-grant only in tests.
- **T3 tool** → `dispatch_web_fetch(..., egress_ctx, call_index,
  schema=tool.schema)` → `EgressExtractOutcome`. `Extracted` →
  `downgrade_to_orchestrator(.data)` → DLP-scan → JSON string tool_result.
  `TypedRefusal` → a benign "tool refused: {reason}" T2 string.
- **Internal first-party tool** (allowlisted ≤T2) → dispatch directly.

**Failure classification (plan-review sec-002/core-002 — canary must NOT be
swallowed):** `dispatch_tool` classifies dispatch exceptions rather than
blanket-catching:

- **Escalation → propagate + quarantine + loud audit:** `InboundCanaryTripped`
  (HARD rule #7 — halt the turn, do NOT feed a tool_result and continue), DLP
  scan failures.
- **Recoverable → T2 error tool_result + audit:** domain-not-allowed,
  rate-limited, unknown tool, invalid args.

**Deadline reconciliation (core-004):** the outer `action_deadline` wraps the
whole turn; `max_iterations × per-completion latency` must be reconciled with it
(either the deadline is the real bound and `max_iterations` a backstop, or the
per-iteration budget check also considers remaining deadline). PR3 makes this
explicit; `asyncio.CancelledError` from the deadline propagates to the existing
top-level arm (never swallowed).

**In-turn tool messages are ephemeral** (built in `local`, discarded after the
turn). Only the final assistant answer is persisted to working/episodic memory,
exactly as today — which is also what keeps the `Episode.role` DB CHECK
(`IN ('user','assistant')`) fail-closed on tool/system rows without a migration.
Auditability is preserved via per-completion + per-dispatch audit rows (§10),
not via episodic memory. A negative-persistence test asserts tool_result content
never lands in episodic storage.

## 7. Budget across N completions

`check_and_charge` is additive and already correct across N calls. The gaps and
fixes (plan-review §7, mem-002/mem-003/core-004):

- **Per-iteration pre-check** inside the loop (`would_exceed` before each
  completion), replacing the single pre-flight check.
- **`max_iterations`** hard cap (config) bounds the number of completions;
  **`MAX_TOOL_CALLS_PER_ITERATION`** bounds intra-iteration egress fan-out
  (a single completion could otherwise request N tools that all fire before the
  next per-iteration check).
- **`check_and_charge` can RAISE** (`PerCallCapExceededError` when actual >
  per-call cap; `BudgetExceededError` over daily). The loop MUST NOT let the
  charge be lost: catch, **force-record** the `budget_overrun` result + audit,
  then break (mirrors the existing single-completion arm at `core.py:786-804`,
  which the loop must not drop).
- **Per-turn accounting** — the existing per-call cap does not bound
  `N × per_call_max`. Track per-turn spend; refuse the next iteration if it
  would breach a per-turn ceiling. (A dedicated `per_turn_max_usd` config key
  may be a small follow-up; the accumulator + `max_iterations` +
  `MAX_TOOL_CALLS_PER_ITERATION` is enough for the mechanism.)
- **Extraction-cost seam** — when #340's real quarantine child lands, the
  extraction completion also costs; the dispatch path must charge it. #339
  leaves the seam (echo extractor ≈ free today).

`estimate_for` stays flat-rate (fine as a per-iteration gate); token-aware
estimation remains a separate future PR.

## 8. Tool registry

A `ToolRegistry` maps `name → (ToolDefinition, dispatch, result_tier,
extraction_schema)`. It builds the `tools` list for each `CompletionRequest` and
routes dispatch. For #339 the registry ships **two** tools:

- **`web.fetch`** — the first real external (T3) tool, closing the zero-callers
  gap and exercising the full T3→quarantine→downgrade leg.
- **one internal first-party ≤T2 demo tool** — **mandatory, not optional**
  (plan-review D4, near-unanimous): it is required to give the internal-dispatch
  branch real coverage, to prove multi-tool ordered dispatch, and to prove
  `call_index` increments on a **non-egress** dispatch. It is on the §3
  first-party allowlist and its ≤T2 claim is test-verified.

Broad MCP-plugin tool discovery (deriving `ToolDefinition`s from plugin
manifests/capabilities across the fleet) is a follow-up; #339 wires the registry
seam + these two tools only. Tools declare a **default extraction schema**;
intent-driven dynamic schemas are a later enhancement.

## 9. Loop control & failure handling

- Stop: `stop_reason != "tool_use"` (final answer in `response.content`).
- `max_iterations` reached → bounded "reached max tool iterations" message +
  audit; `MAX_TOOL_CALLS_PER_ITERATION` exceeded → refuse + audit.
- Malformed/unknown tool, invalid args → recoverable error tool_result + audit.
- **Canary trip → HALT the turn + quarantine + loud audit** (never a recoverable
  tool_result); DLP-scan failure → loud audit + propagate.
- `stop_reason=="tool_use"` but empty `tool_calls` → treat as end_turn/error.

## 10. Audit & i18n

- **Every** completion AND **every** dispatch — including unknown-tool and
  invalid-args dispatches — emits an audit row sharing the turn `trace_id`,
  disambiguated by the existing `subject.phase` convention (e.g.
  `provider_call:2`, `tool_dispatch:web.fetch:3`). No new turn-seq column.
- The per-tool dispatch capability check uses a **named hookpoint** (audit-graph
  join key); tests use a fixture grant, never an always-allow stub.
- All operator/user-facing strings (`t()`), including new refusal/loop messages.
- The extracted T2 fed back to the planner is **DLP-scanned** (§3).
- Persisted rows keep per-row `trust_tier` + `language` (the final answer, as
  today).

## 11. PR decomposition

1. **PR1 — Provider tool-protocol seam.** §4: neutral models (incl.
   `ForcedTool`); extend `CompletionRequest`/`CompletionResponse`/`Message`;
   **per-role wire serialisation** (arch-005/prov-002); map both adapters
   (round-trip tool_use incl. Anthropic multi-tool); **wire `TOOL_USE`** into the
   capability tables + gate tool-advertisement / refuse-loud for a non-tool
   primary (prov-001); router passes `tools` through (no capability *routing* —
   still primary→fallback). Recorded-fixture unit tests per adapter incl. a
   malformed-args error path. **Lands the provider-schema ADR** (§13). No
   orchestrator/loop change.
2. **PR2 — Tool registry + dispatch abstraction + its boundary coverage.** §8,
   §3 T3 leg. `ToolRegistry`; wire `web.fetch` + the mandatory internal tool;
   `result_tier` **defaults to T3** with a first-party ≤T2 allowlist + a
   tier-claim-verification test (sec-001/rev-002); the
   T3→quarantine-extract→downgrade→DLP→T2 path + the internal direct path;
   named capability-gate hookpoint with a fixture-grant test; supply
   `TurnEgressContext` + real `call_index`. **This is the trust-boundary PR:**
   it carries **100% line+branch coverage** on `dispatch_tool` **and** the
   **tool-argument-injection adversarial corpus entry** (a recorded planner
   fixture emitting an attacker-chosen URL → assert allowlist/gate refuses) —
   NOT deferred to PR4 (arch-002/test-003/sec-006).
3. **PR3 — Agentic act-phase loop.** §6, §7, §9, §10. Replace the single
   `complete`; per-iteration budget + `max_iterations` +
   `MAX_TOOL_CALLS_PER_ITERATION` + per-turn accumulator + **charge-raise
   force-record** (mem-002); ordered dispatch with monotonic `call_index` (never
   `gather()`); **per-iteration `provider_failed` audit arm** (core-003);
   canary/DLP escalation-vs-recoverable classification (§9); deadline
   reconciliation (core-004). Integration tests (fixtures) proving a 2-tool turn
   (one egress + one internal) + a budget-refusal path + a negative-persistence
   test.

   **SHIPPED (2026-07-06).** The loop, the per-iteration budget/cap machinery,
   and the three production first-party grants (`tool.dispatch`,
   `quarantine.dereference`, `t3.downgrade_to_orchestrator`) plus the
   axis-faithful boot assertion all merged, proven by fixture-driven unit tests
   and a live real-chain integration test exercising a 2-tool turn (one egress
   leg and one internal leg). Per the Option-A scope reconciliation recorded in
   the "Scope reconciliation" section of
   [the PR3 plan](../plans/2026-07-06-issue-339-pr3-act-phase-loop.md),
   two items originally piled onto "PR3" by PR2's memory notes are explicitly
   **deferred to PR4**: converting the two `xfail(strict=True)` merge-blockers
   (`test_inbound_canary_unwired_deferred_to_339`,
   `test_per_user_exhaustion_refusal_deferred_to_339` — both stay green XFAIL
   until PR4's live caller lands) and three of the four #347 blockers (live-relay
   `TimeoutError`/`in_doubt` cross-layer audit test, per-user resource bound,
   broker auth — properties of the web.fetch egress *live* path, whose first
   live exercise is PR4). The fourth #347 item, `User.language` sourcing, is
   **NOT deferred** — PR3 threads the real `language=user.language` through
   `dispatch_tool`. No decision above is reversed by this note.
4. **PR4 — Corpus breadth + real-LLM smoke.** Broaden the `prompt_injection/`
   tool-argument-injection corpus beyond PR2's structural case, and add the
   `tests/smoke/` real-LLM turn driving the loop end-to-end (nightly /
   retry-tolerant, cheap-tier, budget-guarded). The **structural** injection
   defense is already proven deterministically in PR2; PR4 adds breadth + the
   live-model acceptance.

Each PR names its **happy / error / refusal** test trio explicitly. Each PR:
brainstorm-thin-plan → TDD → full `/review-pr` fleet (security always) +
CodeRabbit → resolve threads → non-admin `--rebase --auto`.

## 12. Explicitly out of scope for #339 (deferred)

- Live comms wiring / real privileged turn in the daemon inbound path — **#338**
  (which also owns the deterministic-replay journal + resume-safety ADR, §5).
- Real-LLM quarantine child (loop runs against the echo extractor;
  extraction-cost charging is a seam) — **#340**, which also ports
  `provider_dispatch` onto this seam and owns `response_format`/JSON-object
  constrained-generation.
- Faithful **episodic persistence** of tool turns (multi-turn tool memory,
  `Episode.role` CHECK migration, rehydrate) — a follow-up; #339 keeps in-turn
  tool messages ephemeral.
- Capability-aware / tiered **router routing** — router stays
  primary→fallback-on-exception (with the new `TOOL_USE` refuse-loud guard).
- Broad MCP-plugin **tool discovery** across the fleet — #339 wires web.fetch +
  the internal demo tool + the registry seam only.
- Token-aware budget estimation; dynamic intent-driven extraction schemas.

## 13. ADRs

- **PR1 — provider tool-protocol schema change** (breaking `CompletionRequest`/
  `CompletionResponse` extension): a structural invariant change; lands in PR1.
- **The dual-LLM tool-result flow** (T3 result → quarantine-extract → downgrade
  → DLP → planner) as a named trust-boundary invariant, incl. the
  `result_tier`-defaults-to-T3 rule.
- **The D3 ephemeral-tool-turn deferral** — record that intra-turn tool history
  is not persisted in #339 and why (avoids the `Episode.role` migration; audit
  rows carry forensics).
- **#338 — deterministic-replay resume-safety** (§5): the journal-the-dispatch-
  sequence guarantee + `temperature=0` hardening. Written when #338 wires live
  resume; #339 only removes the false at-most-once claim and states the
  prerequisite.

## 14. Decisions (reviewed by the 7-agent plan-review; all endorsed)

1. **Scope = mechanism + smoke** (§2) — ENDORSED 7/7; the smoke test is a
   nightly non-gate, the deterministic suite gates.
2. **Internal representation = flat tool-role** (§4.2) — ENDORSED 7/7;
   DeepSeek-chat confirmed to support function-calling.
3. **In-turn tool messages ephemeral** (§6) — ENDORSED; also required to avoid
   the `Episode.role` migration; recorded as an ADR (§13).
4. **`web.fetch` + a MANDATORY internal first-party tool** (§8) — the internal
   tool was upgraded from "optional" to mandatory per near-unanimous review.
5. **`call_index` = per-dispatch monotonic ordinal** (§5) — the mechanism is
   endorsed; the resume at-most-once *claim* was false and is reframed (§5), with
   deterministic replay a hard #338 prerequisite.
6. **PR count = 4, seam first** (§11) — ENDORSED; boundary coverage +
   adversarial corpus rebalanced into PR2.

## 15. Plan-review outcome (2026-07-05)

A 7-reviewer plan-review (architect, cross-cutting reviewer, security, test,
provider-, core-, memory-engineer) ran against rev. 1. All six §14 decisions
were endorsed; the direction was not challenged. Rev. 2 folds in:

- **1 Critical** — the §5 silent-double-fire on resume (mem-001, confirmed
  against the ledger code): §5 fully reframed; deterministic-replay journaling +
  temp=0 made an explicit #338 prerequisite + ADR.
- **High cluster** — canary must halt not recover (§6/§9); `result_tier`
  defaults to T3 + first-party allowlist (§3); internal tool mandatory (§8);
  adversarial corpus + 100% branch coverage moved into PR2 (§11); `TOOL_USE`
  wired + refuse-loud for a non-tool primary (§4.1); per-iteration
  `provider_failed` audit arm + budget charge-raise force-record + intra-iteration
  fan-out cap + deadline reconciliation (§6/§7); audit every dispatch (§10).
- **Medium/Low** — per-role wire serialisation (§4.2); `ForcedTool` defined
  (§4.2); DLP on the extracted-T2→planner path (§3/§10); named dispatch
  hookpoint (§10); never-`gather()` invariant + tool_result truncation (§6).

Verified strengths retained: all anchors match source; DeepSeek-primary supports
FC; `dispatch_web_fetch` already accepts `egress_ctx`/`call_index`/`schema`; the
web.fetch T3 leg hands the planner no raw T3.
