# Issue #338 — Real-LLM turn graduation (live comms cutover) — design

Status: **DRAFT, holding at the design-approval gate.** Written on best-judgment
while the requester was away (per the launch authorization: "best-judgment + let
plan-review vet if the requester is away"). Do NOT proceed to writing-plans /
implementation until the requester ratifies the scope decision in §3.

Date: 2026-07-08. Branch: `338-real-llm-turn-graduation` (off `main` @ `5c85af84`).
Related: epic #338; closed prerequisite #339 (LLM tool-calling mechanism); #340
(real quarantine child); #370 (daemon-side `build_orchestrator` refuse-boot guard);
ADR-0048 (broker authenticated-fetch forward gates).

---

## 1. Problem

The production comms/Discord inbound path does **not** run a real LLM turn. It
runs a deterministic-echo placeholder: `CommsInboundOrchestratorAdapter.dispatch`
emits a fixed `"ack"` and, per its own docstring, *"does NOT call any privileged
`handle_user_message`"* (`src/alfred/comms_mcp/daemon_runtime.py:15-16`, `:91`).
The real OODA orchestrator (`Orchestrator.handle_user_message`,
`src/alfred/orchestrator/core.py:379`) is fully built + tested but has **zero
production callers**. `build_orchestrator` (`src/alfred/cli/_bootstrap.py:459`) and
`build_tool_registry` (`src/alfred/orchestrator/tool_assembly.py:68`) are likewise
unwired (test-only callers).

This epic graduates the **privileged planner** to a real provider on the comms
inbound path.

## 2. Verified current-state anchors (confirmed against the tree, 2026-07-08)

- **The echo adapter.** `CommsInboundOrchestratorAdapter`
  (`daemon_runtime.py:125`) satisfies the inbound `_OrchestratorLike` Protocol via
  three methods — `quarantined_extract` / `ingest` / `dispatch`
  (`comms_mcp/inbound.py:111-125`). `ingest` builds an ack descriptor;
  `dispatch` scans a fixed `_ACK_CONTENT="ack"` through `OutboundDlp` and sends it.
  It never touches `handle_user_message`, `TurnEgressContext`, or a
  `WorkingMemory`. It **discards** the `extracted` result entirely.
- **The boot graph** lives in `src/alfred/cli/daemon/_comms_boot.py`
  (`_build_comms_boot_graph`, `:605`), driven by `_commands.py::_start_async`.
  Construction order: `build_broker` (`_comms_boot.py:656`) → resolver bridge
  (`:657-658`) → `ContentStore` (`:665`) → live quarantine child + extractor via
  `_build_comms_inbound_extractor` (`:684`) → `T3BodyRecorder` + `CommsExtractorBridge`
  (`:703-704`) → `BurstLimiter` (`:735`) → **`CommsInboundOrchestratorAdapter`**
  (`:736-742`). The runner + `bind_outbound_sender` are paired later in
  `_build_comms_runner` (`:1011`, bind at `:1074`), per-adapter. `outbound_dlp` +
  the boot `RealGate` already exist at boot (`_commands.py:571`, gate threaded at
  `:768,:781`) — today they flow into the echo adapter, not a real Orchestrator.
- **`build_orchestrator`** (`_bootstrap.py:459`) builds
  broker→router→resolver→session_scope→budget→`Orchestrator(...)`, passing
  `identity_resolver / session_scope / router / budget / episodic_factory /
  quarantined_extractor`. It does **NOT** build a `ToolRegistry`, does not build/pass
  a `gate`, and does not pass `tool_registry / gate / outbound_dlp` (the Act-phase
  ctor seams added in #339 PR3 — `core.py:298-300`). Self-documented as "unwired
  today (no live caller); #370 tracks adding the correct daemon-side guard"
  (`_bootstrap.py:489`).
- **`handle_user_message`** (`core.py:379`): `async def handle_user_message(self, *,
  user: UserLike, content: TaggedContent[T1] | TaggedContent[T2], working_memory:
  WorkingMemory) -> str`. `UserLike` (`core.py:158-187`) exposes only `slug /
  display_name / language`. **T3 never reaches this method** (`core.py:396-399`).
  The per-turn shape the TUI/tests use (documented at
  `tests/smoke/test_hello_alfred.py:184-200`): resolve user → `tag(T2, text)` →
  `pool.acquire(key)` → `handle_user_message(...)` → `pool.release` in `finally`.
- **`TurnEgressContext` synthesis** (`core.py:762`, `_synthesize_egress_context`
  `:1097`): today `TurnEgressContext(adapter_id="orchestrator.synthetic",
  inbound_id=trace_id, session_id=user.slug)`. The docstring states directly:
  "#338 REPLACES this synthesis with the real adapter/inbound/session identity"
  (`:1104-1105`).
- **The inbound trust boundary.** `quarantined_extract` (via
  `CommsExtractorBridge.extract`, `comms_mcp/bootstrap.py:138`) returns
  `ExtractionResult = Extracted | TypedRefusal` (`quarantine.py:335`). `Extracted.data`
  is `T3DerivedData` — the orchestrator **MUST** call `downgrade_to_orchestrator(data,
  *, gate, audit_writer)` (`quarantine.py:1444`, writes `downgrade_explicit=True` +
  runs the content-clearance gate) before injecting it into a privileged prompt
  (`quarantine.py:279-282`). The **echo adapter never did this** — #338 is the first
  inbound consumer of the T3→T2 downgrade.
- **The quarantine child is already the LIVE deterministic-echo bwrap child**
  (`_build_comms_inbound_extractor`, `daemon_runtime.py:301`; PR-S4-11c-2b). #338
  does not touch it; the **real** quarantine LLM is #340.
- **Audit cost model** (`core.py:1025-1048`): the `completed` `orchestrator.turn`
  row carries `cost_actual_usd=pending_completion_cost` (**terminal completion
  only**) AND `subject.turn_cost_usd=per_turn_spent_usd` (**turn total**). Turn total
  = `subject.turn_cost_usd`, OR Σ `cost_actual_usd` across the trace's rows — NEVER
  the `completed` row's `cost_actual_usd`.
- **G0 resume.** The **direct** daemon path commits-once at **receipt**, before any
  side effect (`inbound.py:671-697`, `commit_at_dispatch_edge=False`): a replay
  short-circuits and the turn never re-runs. The **forwarded** (gateway-hosted) path
  commits **after a successful dispatch** (`inbound.py:917-935`,
  `commit_at_dispatch_edge=True`): a crash before commit replays the frame and the
  turn re-runs — the bounded at-least-once envelope Spec B accepts (ADR-0039 item 4,
  poison-ceiling dead-letter G6-7-5).

## 3. Scope decision (RATIFY THIS FIRST)

**#338's first live cutover ships a real *conversational* privileged turn with
egress tools DEFERRED.** The Act loop advertises an **empty tool registry** →
exactly one completion → byte-for-byte the proven single-completion turn shape.

Rationale:

1. It is #338's own stated boundary — the issue lists "the LLM tool-calling
   (agentic) loop" as out of scope (that was #339's mechanism, now closed).
2. It delivers the MVP — a real LLM answering real users — at the lowest risk.
3. With no tool dispatch there are **no egress ledger writes**, so the mem-001
   double-fire hazard is not reachable and the turn is resume-safe under the
   **existing** Spec A commit-once oracle. The hard deterministic-replay journal
   subsystem + ADR-0048 forward gates get their own focused follow-up (§9) instead
   of bloating this epic.
4. It cleanly separates the two halves of the dual-LLM split: **#338 = real
   privileged planner; #340 = real quarantine child.**

The launch prompt's "`build_tool_registry` → `build_orchestrator` → the Act phase"
describes the eventual end-state; the journal + ADR-0048 gates it calls out are the
**prerequisites** for turning egress tools on, and belong to the follow-up.

## 4. Architecture

Replace the echo `CommsInboundOrchestratorAdapter` with a
**`RealTurnOrchestratorAdapter`** satisfying the same `_OrchestratorLike`
(`quarantined_extract` / `ingest` / `dispatch`), so the load-bearing inbound order
(`comms_mcp/inbound.py:555`) and all Spec A/B idempotency/replay logic are
untouched. The adapter maps the three-method surface onto the real turn:

```
quarantined_extract(body, canonical_user_id, source_tier="T3")
    → delegate to the SAME CommsExtractorBridge  (live echo child, unchanged)
    → Extracted | TypedRefusal

ingest(notification, extracted, canonical_user_id, addressing_signal, language):
    if TypedRefusal:
        → build a benign i18n reply envelope; the planner NEVER runs
    else (Extracted):
        → cleared = downgrade_to_orchestrator(extracted.data, gate=<boot gate>,
                                              audit_writer=<boot audit>)      # HARD #5
        → text    = cleared["text"]        # CommsBodyExtraction.text (T2 message body)
        → content = tag(T2, text, source="comms.inbound")                    # TaggedContent[T2]
        → user    = UserLike(slug=canonical_user_id, display_name=<resolved>,
                             language=language)
        → egress  = TurnEgressContext(adapter_id=notification.adapter_id,     # constraint 4
                                      inbound_id=notification.inbound_id,
                                      session_id=canonical_user_id)
        → wm = await pool.acquire(("alfred", canonical_user_id))
          try:
              answer = await orchestrator.handle_user_message(
                  user=user, content=content, working_memory=wm,
                  egress_context=egress)                                      # new optional param
          finally:
              await pool.release(("alfred", canonical_user_id), wm)
    → return {answer, adapter_id, target_platform_id, addressing_mode}

dispatch(ingested):
    → scanned = outbound_dlp.scan_for_outbound(answer)                       # HARD #4, mirrors echo
    → OutboundMessageRequest(..., body=scanned, addressing_mode=...)
    → await sender.send_outbound(request)                                    # late-bound seam, unchanged
```

**Why the downgrade lives in the adapter, not in `handle_user_message`:** the
orchestrator's contract already takes *already-cleared* `TaggedContent[T1|T2]` (the
smoke test proves it; T3 is refused at `core.py:396-399`). The adapter is the
inbound trust-boundary translator — it owns the gate-checked T3→T2 downgrade using
the boot `RealGate` + `AuditWriter`. This keeps `handle_user_message` unchanged and
the boundary auditable at one site.

**Components:**

- **`RealTurnOrchestratorAdapter`** (new; likely `comms_mcp/daemon_runtime.py`
  alongside the echo adapter, or a sibling module). Deps injected at construction:
  the real `Orchestrator`, the `WorkingMemoryPool`, the boot `RealGate`, the
  `AuditWriter`, the `OutboundDlp`, and the late-bound `OutboundSenderLike`. Holds
  the same `bind_outbound_sender` seam.
- **`build_orchestrator` call** wired into `_build_comms_boot_graph`, threading the
  already-built broker/router/resolver. For the conversational cutover the tool
  registry stays absent (empty); the orchestrator's tool-path `gate`/`outbound_dlp`
  ctor seams are for the tools-on follow-up. The daemon-side refuse-boot guard (#370)
  routes a `SecretBrokerConfigError` through the audited `_refuse_boot` path.
- **`WorkingMemoryPool`** built at boot (`build_working_memory_pool`,
  `_bootstrap.py`) and injected into the adapter; the adapter brackets
  acquire/release per turn.
- **Identity widening:** `ResolvedInbound` (`inbound.py:83-99`) gains a
  `display_name` (or the adapter does a resolver `show(slug=...)` lookup) so the
  adapter can build a full `UserLike`.

## 5. Resume-safety analysis

- **Direct path (TUI, `commit_at_dispatch_edge=False`):** commit-once at receipt →
  a mid-turn crash short-circuits on replay → the turn does **not** re-run
  (at-most-once; a lost turn is user-recoverable by resending). No egress ⇒ no
  ledger ⇒ mem-001 not reachable. **Fully safe under the existing oracle.**
- **Forwarded path (gateway-hosted, `commit_at_dispatch_edge=True`):** commit after
  successful dispatch. A crash in the narrow dispatch→commit window replays the
  frame → the turn re-runs → a duplicate LLM call + possible duplicate reply. This
  is within Spec B's **already-accepted, ceilinged at-least-once envelope** (ADR-0039
  item 4). For a conversational turn the only cost is a wasted completion + a rare
  double-reply — NOT a security double-fire (no external side-effect beyond the
  reply). Documented as an accepted residual; the deterministic-replay **journal**
  (tools-on follow-up, §9) is what tightens this when egress side-effects go live.

Because tools are deferred, **no journal ADR and no `temp=0` are required in #338**
(both are mem-001 defenses for the egress-tool path).

## 6. Audit cost model (constraint 1)

This epic introduces **no cost aggregator**. The existing loop writes the `completed`
row (`subject.turn_cost_usd` = turn total; `cost_actual_usd` = terminal only) and
any `provider_call:{iteration}` rows unchanged. The constraint is honoured by *not*
adding anything that reads the `completed` row's `cost_actual_usd` as the turn
total. A test asserts the real-turn path emits the expected `orchestrator.turn`
row shape (turn total on `subject.turn_cost_usd`).

## 7. Identity mapping (constraint 4)

| target | source |
| --- | --- |
| `TurnEgressContext.adapter_id` | `notification.adapter_id` |
| `TurnEgressContext.inbound_id` | `notification.inbound_id` (real committed G0 id, replacing `trace_id`) |
| `TurnEgressContext.session_id` | `resolved.canonical_user_id` |
| `UserLike.slug` | `resolved.canonical_user_id` |
| `UserLike.language` | `resolved.language` |
| `UserLike.display_name` | resolver widening / `show(slug=...)` (gap today) |

`handle_user_message` gains an optional `egress_context: TurnEgressContext | None =
None`, threaded to `_handle_turn` and consumed at `core.py:762` instead of the
synthesis when provided. When `None` (alfred chat, fixtures, tests) it falls back to
`_synthesize_egress_context` — behaviour-neutral for every existing caller. Though
the egress context is functionally dead without tools, threading the real identity
now satisfies constraint 4 and future-proofs the tools-on wire.

## 8. PR decomposition

- **PR1 — core seams (behaviour-neutral, no live caller).** (a) optional
  `egress_context` param on `handle_user_message`/`_handle_turn` with synthesis
  fallback; (b) `ResolvedInbound`/resolver `display_name` widening. Proven by
  contract/unit tests. Daemon still echoes → `main` stays coherent (seam-first
  precedent: #339 PR1, G7-2a). *Plan-review may fold PR1 into PR2 if it is too thin
  to stand alone.*
- **PR2 — the daemon cutover (behaviour change; security-reviewed; UAT).**
  `RealTurnOrchestratorAdapter` (extract → downgrade → tag T2 → pool-bracketed
  `handle_user_message(egress_context=real)` → answer envelope; `dispatch` sends via
  DLP), swap into `_build_comms_boot_graph`, `build_orchestrator` call + boot
  `WorkingMemoryPool`, daemon-side refuse-boot guard (#370), cost-model-shape test,
  resume-safety tests (direct at-most-once; forwarded at-least-once residual), and a
  real-message → real-answer UAT. Touches the dual-LLM boundary → security sign-off +
  adversarial suite are release-blocking.

## 9. Out of scope — the tools-on follow-up (new issue)

Deferred, with forward gates recorded here so the follow-up inherits them:

- Advertise `web.fetch` / wire `build_tool_registry` into `build_orchestrator` + the
  Act phase (the first live `build_tool_registry` caller).
- **Deterministic-replay journal ADR** — journal the committed ordered dispatch
  sequence so a forwarded-path resume replays the journal, not a fresh stochastic
  planner (the mem-001 CRITICAL); `temp=0` on tool turns as defense-in-depth.
- **ADR-0048 forward gates** before any live authenticated fetch: per-secret↔
  destination binding before populating `WEB_FETCH_AUTH_SECRET_ALLOWLIST` (empty
  today); the one-broker-instance invariant (`build_tool_registry`'s broker == the
  boot `SecretBroker` backing `outbound_dlp`); the gateway re-scan positive-path
  residual.
- **#340** (real quarantine child) is independent and not folded here.

## 10. Testing

- **PR1:** unit tests — `egress_context` override path vs synthesis fallback (both
  branches); resolved `display_name` presence.
- **PR2:** integration — real-chain turn on the direct path (live echo quarantine
  child → downgrade → real router completion → answer sent), asserting HARD#5 (the
  planner request never contains raw T3), the `orchestrator.turn` cost-row shape,
  and pool acquire/release symmetry; the `TypedRefusal` benign-reply branch;
  resume tests for both idempotency edges; refuse-boot guard (#370). Adversarial
  suite is release-blocking (dual-LLM boundary touched). Real-provider behaviour is
  covered by the existing nightly smoke; #338 adds no per-commit paid calls.

## 11. ADRs

- Amend the ADR that records the comms inbound path (ADR-0027 lineage / ADR-0041
  vicinity) to note the privileged-turn graduation and the echo→real adapter swap.
- The deterministic-replay journal ADR is authored in the **tools-on follow-up**,
  not here.
- CLAUDE.md / PRD edits remain human-gated.

## 12. Risks & residuals

- **Forwarded-path double-reply** under a dispatch→commit crash (§5) — accepted,
  ceilinged; tightened by the journal follow-up.
- **`display_name` widening** touches the identity resolver seam — keep it additive
  and covered by the identity tests.
- **Protocol-surface fit:** the adapter maps three methods onto one turn; ingest
  running the turn (and dispatch only sending) mirrors the echo adapter's
  ingest/dispatch split and keeps the observable send inside the forwarded-path
  commit-after-dispatch logic.
- **`build_orchestrator` sufficiency:** for the conversational turn it is nearly
  sufficient as-is; the tool-path ctor seams (`tool_registry`/`gate`/`outbound_dlp`)
  are threaded in the tools-on follow-up, not #338.
