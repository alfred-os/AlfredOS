# Issue #338 — Real-LLM turn graduation (live comms cutover) — design

Status: **DRAFT rev.2 — 8-lens `/review-plan` folded (§3a), holding at the
design-approval gate.** Written on best-judgment while the requester was away (per
the launch authorization: "best-judgment + let plan-review vet if the requester is
away"); the fleet then vetted it (0 runtime Criticals; shape endorsed; 6 Highs
folded). Do NOT proceed to writing-plans / implementation until the requester
ratifies the scope decision in §3 (+ §3a corrections).

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

**Reply addressing (FOLD-6):** #338 is scoped to **DM/1:1 replies** (the echo adapter
is already `dm`-only). `InboundMessageNotification` carries no channel/thread target
id, so a Discord *group* reply cannot be targeted; group `addressing_mode` derivation
(and the wire-widening it needs) is an explicit follow-up, not #338.

## 3a. Plan-review findings folded (rev.2 — 2026-07-08)

An 8-lens `/review-plan` fleet (architect, reviewer, test, security, comms, core,
provider, memory) reviewed rev.1. **0 Criticals in the runtime design; the shape
is endorsed** (dual-LLM invariant verified sound, the adapter seam is a genuine
adapter, the scope split is defensible + correctly gated). These corrections are
folded below and are AUTHORITATIVE where they touch a section — read them first.

- **FOLD-1 (High, core-001/comms — VERIFIED).** `build_orchestrator(settings)` builds
  its OWN broker/router/resolver/session_scope and re-fires the **process-global**
  `install_identity_factories_for_settings` (`_bootstrap.py:211` — "a single shared
  engine per process keeps the version counter coherent"). `_build_comms_boot_graph`
  already builds a broker (`:656`) + resolver (`:657`); calling `build_orchestrator`
  there double-builds them and diverges the version-counter contract the inbound
  resolver bridge relies on. **Fix:** DI-refactor `build_orchestrator` to accept the
  pre-built `broker`/`router`/`resolver`/`session_scope` (optional params, default to
  building — preserves existing test callers), OR add a daemon-side assembly that
  reuses the graph's components and constructs `Orchestrator(...)` directly. §4 is
  corrected accordingly.
- **FOLD-2 (High, prov-001/arch-002/core-002 — VERIFIED).** `build_router` calls
  `EgressClient.from_settings` first (`_bootstrap.py:165`), which raises
  `IOPlaneUnavailableError` when `ALFRED_EGRESS_PROXY_URL` is unset. The daemon
  comms-graph build (`_commands.py:631`) catches `SecretBrokerConfigError` /
  `QuarantineChildSpawnError` / `_ForwardedInboundRegistryMisconfiguredError` but NOT
  `IOPlaneUnavailableError` — so #338 (first boot caller of `build_router`) introduces
  an un-audited fail-closed boot path (the #368 anti-pattern). **Fix:** add an
  `IOPlaneUnavailableError` refuse-boot arm (and cover the router's
  `deepseek_api_key` `UnknownSecretError`, prov-002) → audited `daemon.boot.failed` +
  exit 2. NOTE (core-004): the `SecretBrokerConfigError` guard already exists at
  `_commands.py:638` — #338's work is getting `build_orchestrator` called *behind* it,
  not adding it.
- **FOLD-3 (High, core-003/comms/mem — turn placement + resume).** Run the turn inside
  the **dispatch-edge envelope**, not in `ingest`: an `ingest`-time turn exception
  (BudgetError / provider outage / deadline) is *outside* the forwarded-path `dispatch`
  try/except (`inbound.py:872` vs `:884`), so it bypasses the `dispatch_failed` audit
  and replays up to the poison ceiling (**up to 5 duplicate paid completions**). §4/§5
  corrected: `ingest` prepares inputs; the real turn + outbound send run in `dispatch`.
- **FOLD-4 (High, mem-001 — §5 was WRONG).** `handle_user_message` commits **episodic
  rows** (append-only, no `inbound_id` dedup) and charges the **in-process budget**
  (`core.py:852`) in its own `session_scope` (`core.py:423`) — durable side-effects a
  forwarded-path re-run double-applies (transcript pollution + double budget-charge),
  independent of egress tools. §5 is rewritten: EITHER document these as bounded
  residuals (≤twice, no-partition-crossing, tested) OR make the durable writes
  `inbound_id`-idempotent. Best-judgment: **document as bounded residual for #338**
  (the deferred replay-journal is the durable fix), with a bounded-to-twice test.
- **FOLD-5 (High, sec-001/test-002/comms/rev-003 — refusal/error leg).** The downgrade
  gate-DENY (`AlfredError`), BudgetError, and turn-error branches need a LOUD audit row
  owned by the adapter (HARD#7) — `check_content_clearance` writes NO audit on a policy
  deny (verified). Plus a specified benign i18n reply (FOLD-8) and tests. §4/§10 add
  the error-leg contract.
- **FOLD-6 (High → scope, comms-High-2).** `InboundMessageNotification` carries no
  channel/thread target id, so a Discord *group* reply can't be targeted. **#338 is
  scoped to DM/1:1 replies** (matches conversational-first + the echo adapter's
  `dm`-only reply); group addressing + the wire widening is an explicit follow-up. §3
  scope amended.
- **FOLD-7 (Critical test-design, test-001 — VERIFIED).** Because the quarantine child
  is the **echo** child, extracted T2 `text` == the raw T3 body byte-for-byte, so a
  body-scan HARD#5 test false-fails. The non-vacuous guard is **provenance-based**:
  assert the `downgrade_to_orchestrator` receipt (`downgrade_explicit=True`) fired
  before the planner request + a marker in a schema-dropped framing field. §10 corrected.
- **FOLD-8 (Medium punch list).** (a) benign refusal reply goes through a named `t()`
  key rendering in `{user.language}` (rev-001); (b) `display_name` must be threaded to
  the `ingest(...)` call, not just added to `ResolvedInbound` (PR1 widens
  `ResolvedInbound` + the bridge populates it, rev-002/comms); (c) add an inbound-injection adversarial
  corpus entry + canary — first live downgrade consumer (sec-002/test-006); (d) pin
  **ADR-0027** (the ADR that deferred this bridge), not "0041 vicinity"; decide
  new-ADR-vs-amendment (arch-003); (e) reconcile the stale `core.py:1104-1111` comments
  that still call the journal "a hard #338 prerequisite" (arch-004); (f) explicit 100%
  line+branch target on the boundary translator + the `cost_actual_usd`=terminal-only
  negative assertion + real-PG/Redis resume seam + TDD-first (test-003/004/005/007,
  sec-004); (g) state the seeded-grant reuse explicitly (sec-003); (h) `egress_context`
  is inert in #338 (no dispatch reads it) — thread it now as forward-prep but its PR1
  test can only assert branch selection (rev-004/core-006); (i) `UserLike` is a Protocol
  — build a concrete impl (rev-005); (j) make the "all-three-or-none" seam wiring
  explicit so PR2 never trips the `core.py:962` `dispatch_seams_unwired` guard (prov-004);
  (k) note the pool hands a shared buffer per `(persona, canonical_user_id)` — safe for
  the single-adapter cutover via leg serialization, revisit for multi-adapter (mem-002).

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
    # ingest ONLY PREPARES inputs — the turn does NOT run here (FOLD-3).
    if TypedRefusal:
        → return {refusal_reply: <benign i18n string>, adapter_id, target_platform_id,
                  addressing_mode}                                            # no turn will run
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
    → return {prepared: (content, user, egress), adapter_id, target_platform_id,
              addressing_mode}

dispatch(ingested):                                                          # FOLD-3: the turn runs HERE
    if ingested carries a refusal_reply:
        → answer = ingested.refusal_reply
    else:                                                                    # run the pool-bracketed turn
        → wm = await pool.acquire(("alfred", canonical_user_id))
          try:
              answer = await orchestrator.handle_user_message(
                  user=user, content=content, working_memory=wm,
                  egress_context=egress)                                      # new optional param
          finally:
              await pool.release(("alfred", canonical_user_id), wm)
    → scanned = outbound_dlp.scan_for_outbound(answer)                       # HARD #4, mirrors echo
    → OutboundMessageRequest(..., body=scanned, addressing_mode=...)
    → await sender.send_outbound(request)                                    # late-bound seam, unchanged
```

**Turn placement (FOLD-3):** as the sketch shows, `ingest` only prepares the turn
inputs (extract → downgrade → tag T2 → build `user`/`egress`) and the real turn +
outbound send run inside the **`dispatch`-edge envelope**. This is load-bearing: on
the forwarded path a turn failure then takes the audited `dispatch_failed` +
bounded-replay path (`inbound.py:884`) rather than propagating uncaught from `ingest`
(`:872`) up to the poison ceiling. `dispatch` acquires the pool buffer, runs
`handle_user_message`, and sends the DLP-scanned answer.

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
- **Orchestrator assembly** (per FOLD-1 — NOT a bare `build_orchestrator(settings)`
  call, which double-builds the broker + re-fires the process-global identity
  factories). DI-refactor `build_orchestrator` to accept the graph's already-built
  `broker`/`router`/`resolver`/`session_scope`, or add a daemon-side builder that
  reuses them and constructs `Orchestrator(...)` directly. For the conversational
  cutover the tool registry stays absent (empty); the tool-path `gate`/`outbound_dlp`
  ctor seams are the tools-on follow-up. Per FOLD-2 the assembly adds an
  `IOPlaneUnavailableError` (+ router-key `UnknownSecretError`) refuse-boot arm
  alongside the existing `SecretBrokerConfigError` guard (`_commands.py:638`).
- **`WorkingMemoryPool`** built at boot (`build_working_memory_pool`,
  `_bootstrap.py`) and injected into the adapter; the adapter brackets
  acquire/release per turn.
- **Identity widening:** `ResolvedInbound` (`inbound.py:83-99`) gains a
  `display_name` (populated by the identity bridge from the resolved `User`) so the
  adapter can build a full `UserLike`.

## 5. Resume-safety analysis

- **Direct path (TUI, `commit_at_dispatch_edge=False`):** commit-once at receipt →
  a mid-turn crash short-circuits on replay → the turn does **not** re-run
  (at-most-once; a lost turn is user-recoverable by resending). No egress ⇒ no
  ledger ⇒ mem-001 not reachable. **Fully safe under the existing oracle.**
- **Forwarded path (gateway-hosted, `commit_at_dispatch_edge=True`):** commit after
  successful dispatch. A turn/send failure (not just a narrow crash window — any
  outbound-send failure with the process alive) leaves the frame un-committed and
  replays it → the turn re-runs. **Correction (FOLD-4, was wrong in rev.1):** this is
  NOT side-effect-free even without egress tools. `handle_user_message` commits
  **episodic rows** in its own `session_scope` (`core.py:423`) — append-only
  `record`, no `inbound_id` dedup — and charges the **in-process budget**
  (`core.py:852`) BEFORE `dispatch`/`commit_once`. So a forwarded re-run
  double-writes the transcript (polluting the next rehydrate) and double-charges the
  budget, on top of the duplicate paid completion. Placing the turn in the
  `dispatch`-edge envelope (FOLD-3) bounds the replay to the poison ceiling and gives
  it an audited `dispatch_failed` trail, but does not de-duplicate the episodic/budget
  writes. **Disposition for #338:** accept as a bounded residual — the writes are
  bounded-to-≤-ceiling and never cross a user partition; a test pins "at most twice,
  same partition". The deterministic-replay **journal** (tools-on follow-up, §9) is
  the durable fix; an alternative in-scope hardening is to make the episodic write +
  budget charge `inbound_id`-idempotent (deferred unless plan-review escalates it).

Because egress tools are deferred, **this epic needs no journal ADR and no `temp=0`**
(both are mem-001-egress defenses); the episodic/budget double-apply above is the
residual that IS in play and is handled as stated.

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
| `UserLike.display_name` | `resolved.display_name` (the widened `ResolvedInbound`, PR1) |

`handle_user_message` gains an optional `egress_context: TurnEgressContext | None =
None`, threaded to `_handle_turn` and consumed at `core.py:762` instead of the
synthesis when provided. When `None` (alfred chat, fixtures, tests) it falls back to
`_synthesize_egress_context` — behaviour-neutral for every existing caller. Though
the egress context is functionally dead without tools, threading the real identity
now satisfies constraint 4 and future-proofs the tools-on wire.

## 8. PR decomposition

- **PR1 — core seams + assembly refactor (behaviour-neutral, no live caller).**
  (a) optional `egress_context` param on `handle_user_message`/`_handle_turn` with
  synthesis fallback (inert in #338 but forward-prep; PR1 test asserts branch
  selection, FOLD-8h); (b) `display_name` sourcing (widen `ResolvedInbound` + the
  bridge populates it + thread to `ingest` — FOLD-8b); (c) the FOLD-1 DI-refactor
  of `build_orchestrator` (accept pre-built broker/router/resolver/session_scope,
  defaulting to build — existing test callers unchanged). Proven by contract/unit
  tests. Daemon still echoes → `main` stays coherent (seam-first precedent: #339 PR1,
  G7-2a). *Plan-review may re-partition PR1/PR2.*
- **PR2 — the daemon cutover (behaviour change; security-reviewed; UAT).**
  `RealTurnOrchestratorAdapter` (`ingest` prepares: extract → gate-checked downgrade →
  tag T2 → build `user`/`egress`; `dispatch` runs the pool-bracketed
  `handle_user_message(egress_context=real)` + sends the DLP-scanned answer — FOLD-3),
  the error/refusal-leg audit contract (FOLD-5), swap into `_build_comms_boot_graph`
  using the reused-components assembly + boot `WorkingMemoryPool`, the
  `IOPlaneUnavailableError`/`UnknownSecretError` refuse-boot arms (FOLD-2), the
  provenance HARD#5 + cost-shape + bounded-residual resume tests (§10), and a
  real-message → real-answer UAT. Touches the dual-LLM boundary → security sign-off +
  adversarial suite + 100% boundary coverage are release-blocking.

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
- **PR2:** integration over real Postgres/Redis + the live echo quarantine child.
  - **HARD#5 — provenance-based, NOT a body-scan (FOLD-7).** The echo child echoes
    the body into `data.text`, so extracted T2 `text` == the raw T3 body; a
    whole-request scan would false-fail. Assert instead that the
    `downgrade_to_orchestrator` receipt (`downgrade_explicit=True`) was written
    before the planner request, plus a marker placed in a framing field the schema
    drops (proving the planner input came through the gate-checked seam, not a raw
    passthrough).
  - **Error/refusal legs (FOLD-5):** `TypedRefusal` → benign `t()` reply; downgrade
    gate-DENY (`AlfredError`) and BudgetError → the adapter's loud audit row + the
    turn halts (no reply leaked). Each asserts the audit row shape.
  - **Cost model:** the `orchestrator.turn` completed-row shape — `subject.turn_cost_usd`
    = turn total AND the negative assertion that `cost_actual_usd` is terminal-only
    (`core.py:1025-1048`).
  - Pool acquire/release symmetry incl. the release-in-`finally` exception path;
    resume tests for both idempotency edges with a forwarded-path crash-injection seam
    (assert episodic/budget double-apply is bounded to ≤twice, same partition);
    the `IOPlaneUnavailableError`/`UnknownSecretError` refuse-boot arms (FOLD-2).
  - **New adversarial corpus entry** (inbound real-turn injection + canary — first live
    downgrade consumer, FOLD-8c). Adversarial suite + **explicit 100% line+branch**
    on the boundary translator are release-blocking (dual-LLM boundary touched).
  - Real-provider behaviour is a **manual UAT** for #338 (the existing nightly smoke
    uses `http_client=None` + tools-on, so it does NOT cover the new proxied
    conversational chain, prov-003); #338 adds no per-commit paid calls.
- **TDD-first:** every leg lands failing-test-first.

## 11. ADRs

- **ADR-0027** is the exact ADR — it deferred this privileged-orchestrator bridge
  (FOLD-8d). #338 lands the dual-LLM *privileged half* in production for the first
  time, which arguably warrants a NEW ADR rather than an amendment; decide at plan
  time. Also reconcile the now-stale `core.py:1104-1111` comments that still call the
  replay journal "a hard #338 prerequisite" (FOLD-8e) — #338's narrowed scope moves it
  to the follow-up.
- The deterministic-replay journal ADR is authored in the **tools-on follow-up**,
  not here.
- CLAUDE.md / PRD edits remain human-gated.

## 12. Risks & residuals

- **Forwarded-path double-apply** on re-run — episodic double-write + budget
  double-charge (§5, FOLD-4), accepted as a bounded residual (≤twice, same partition,
  tested); the journal follow-up (or in-scope `inbound_id`-idempotent writes) is the
  durable fix.
- **`display_name` widening** touches the identity resolver seam — keep it additive,
  thread it to the `ingest` call, cover it with the identity tests.
- **Protocol-surface fit:** the adapter maps three methods onto one turn; per FOLD-3
  `ingest` prepares inputs and `dispatch` runs the turn + send, keeping the failure
  path inside the forwarded commit-after-dispatch envelope.
- **`build_orchestrator` is NOT sufficient as-is** (FOLD-1): a bare
  `build_orchestrator(settings)` call double-builds the broker + re-fires the
  process-global identity factories. The DI-refactor (or a component-reusing
  daemon-side builder) is required. The tool-path ctor seams
  (`tool_registry`/`gate`/`outbound_dlp`) stay deferred to the tools-on follow-up.
