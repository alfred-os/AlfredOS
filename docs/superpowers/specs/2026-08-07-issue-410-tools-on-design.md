# Issue #410 — Tools-on: egress tools for the live comms turn — design

Status: **DRAFT — brainstormed interactively with the requester (all three scoping
questions answered directly, no `/review-plan` fleet run yet).** Ready for the
`/review-plan` fleet pass called out in Testing §10, given this crosses comms,
orchestrator, egress, memory, and the trust boundary.

Date: 2026-08-07. Branch: not yet cut (off `main` @ `2e4fa72d`).
Related: epic #410 (this issue); closed-in-practice #338 (real-turn graduation —
see §0); closed-in-practice #340 (real quarantine child); ADR-0049 (#338 cutover,
amended by this design); ADR-0048 (broker authenticated-fetch forward gates,
deliberately NOT closed by this design — see §3); the Spec C egress-idempotency
ledger (`src/alfred/memory/egress_idempotency.py`, `src/alfred/egress/egress_id.py`).

---

## 0. Correction to the launch premise (why this doc exists instead of a #338 doc)

This session was launched to resume #338 ("Real-LLM turn graduation"). Verification
against `main` before any design work showed the premise was stale:

| Launch premise | Verified reality |
| --- | --- |
| Comms inbound runs a deterministic-ack placeholder | **False** — `src/alfred/cli/daemon/_comms_boot.py:813` constructs `RealTurnOrchestratorAdapter` |
| `Orchestrator.handle_user_message` has zero production callers | **False** — `src/alfred/comms_mcp/real_turn_adapter.py:393` is a live caller |
| Nobody has started #338 | **False** — PR1 (#407) + PR2 (#409) merged 2026-07-08/09; ADR-0049 Accepted |

`~/.claude/memory/projects/alfred/domain_338_mvp_gap_analysis.md` (written
2026-08-07, the same day, by a prior session) reached its conclusion by reading
`src/alfred/comms_mcp/daemon_runtime.py`'s docstrings — which describe the
**retained but no-longer-constructed** `CommsInboundOrchestratorAdapter` class —
without checking what the boot graph actually constructs. #340 (real quarantine
child) also shipped, via PR #464 on 2026-07-20 (ADR-0052 Accepted). **Both halves
of the dual-LLM split are live in production.**

The real next epic is **#410**, the tools-on follow-up #338's own spec §9
explicitly designated as the deferred second half. This document designs it. #338
and #340 are closed as part of this same body of work (§5, PR0).

## 1. Problem

The live comms turn (Discord + `alfred chat`) runs a real privileged LLM
conversation, but it cannot **act**: `build_orchestrator`
(`src/alfred/cli/_bootstrap.py:459`) constructs the `Orchestrator` with no
`tool_registry` / `gate` / `outbound_dlp`, so the Act loop's dispatch-seams guard
(`src/alfred/orchestrator/core.py:973`) is unreachable and every turn is exactly
one completion. `build_tool_registry` (`src/alfred/orchestrator/tool_assembly.py:68`)
and `build_web_fetch_egress_extractor`
(`src/alfred/plugins/web_fetch/assembly.py:107`) are fully built and tested but
have zero production callers.

This is the gap between a live chatbot and a live assistant.

## 2. Verified current-state anchors (confirmed against the tree, 2026-08-07)

- `src/alfred/cli/daemon/_comms_boot.py:747-766` — the tools-on seam is
  **already documented in production code**, left by the #338 PR2 author as
  explicit forward-instructions: call `build_web_fetch_egress_extractor` once at
  boot, reusing the existing `extractor`/`recorder`/gate/`outbound_dlp`, and call
  `build_tool_registry` as its first live caller.
- `src/alfred/orchestrator/core.py:973` — the all-three-or-none dispatch-seams
  guard (`registry`/`gate`/`outbound_dlp`), currently unreachable in production.
- `src/alfred/plugins/web_fetch/auth_allowlist.py:17` —
  `WEB_FETCH_AUTH_SECRET_ALLOWLIST: Final[frozenset[str]] = frozenset()`; every
  `{{secret:<name>}}` placeholder refuses at `fetch_dispatcher.py:455`. Unauthenticated
  fetch does not touch this path at all.
- `src/alfred/egress/egress_id.py:62` — `compute_egress_id` keys on
  `(adapter_id, inbound_id, session_id, call_index)`, positional only.
  `compute_egress_body_hash` (`:75`) additionally folds
  `(request_descriptor, headers, redacted_body)` into a ledger integrity hash;
  `src/alfred/memory/egress_idempotency.py:220` raises `EgressIdIntegrityError`
  when a replay at the same egress-id diverges in any of them. **mem-001 is
  therefore fail-loud today, not silent-wrong-replay** — see §5.
- `src/alfred/orchestrator/core.py` — four side-effecting calls inside
  `_handle_turn` fire **before** `dispatch`/`commit_once` on the forwarded path
  (`commit_at_dispatch_edge=True`, `src/alfred/comms_mcp/inbound.py:647,731,743`):
  `working_memory.append(role="user", ...)` (`:702`) + `episodic.record(role="user", ...)`
  (`:703`) at turn start; `self._budget.check_and_charge(...)` (`:863`) inside the
  Act loop; `working_memory.append(role="assistant", ...)` (`:1009`) +
  `episodic.record(role="assistant", ...)` (`:1021`) at turn end. ADR-0049
  accepted the episodic+budget half of this as a bounded residual (≤ twice, same
  partition) **only because tools were off**; it is reachable on the live
  Discord path today regardless of this epic. **`WorkingMemory.append`'s
  identical exposure was not named in ADR-0049 or the original draft of this
  spec** — see §3.4.
- `src/alfred/memory/working.py` — `WorkingMemory` is a plain in-process
  `deque` (not Redis-backed; the module docstring's "slice-3 Redis swap" has
  not happened). `src/alfred/memory/working_pool.py:124` `WorkingMemoryPool.acquire()`
  returns the **same live buffer** across a same-process retry — a forwarded-path
  resume that retries in-process (ADR-0049's own described scenario: "any
  outbound-send failure with the process alive") duplicates the user's message
  into the live conversation context the next completion reads back, not merely
  an audit-log duplicate.
- `src/alfred/orchestrator/core.py:745` — `tools = self._tool_registry.definitions()
  if self._tool_registry is not None else ()`. While `self._tool_registry is None`
  (true for the entire PR1 **and** PR2 window — tools only turn on in PR3), the
  completion always returns `stop_reason="end_turn"` on iteration 0 (per the
  existing comment at `:743`), so the Act loop runs **exactly one iteration**
  every time. This makes "skip if already applied for this `inbound_id`"
  idempotency sound for PR1 without depending on PR2's journal: each of the four
  calls above fires exactly once per attempt while PR1 is live, so there is no
  divergent-iteration-count case to under-cover.
- `src/alfred/orchestrator/loop_constants.py:17,22` —
  `MAX_TOOL_ITERATIONS = 8`, `MAX_TOOL_CALLS_PER_ITERATION = 8`. Already bound the
  Act loop; this epic adds no new iteration cap.
- `src/alfred/providers/base.py:235` — `temperature: float = 0.7` default, read at
  `deepseek.py:324` / `anthropic_native.py:315`. No `temp=0` seam exists yet for
  tool-bearing turns.

## 3. Scope decision (ratified interactively with the requester, 2026-08-07)

Three questions, answered directly rather than via a written proposal —recorded
here for the plan-review fleet and future readers:

1. **Sequencing: journal before tools-on, not combined, not direct-path-first.**
   The journal (§4, PR2) lands with no live consumer, following the seam-first
   precedent of #339 PR1 / G7-2a / #338 PR1. Tools flip on in a separate PR (PR3).
   `main` stays coherent at every commit; mem-001's failure mode is closed before
   it is ever reachable in production. Rejected: turning tools on for `alfred chat`
   first (the direct path is genuinely safe without the journal, since a single
   commit-once-at-receipt turn never re-runs — but it would split the tool surface
   across two paths for no durable reason) and a single combined PR (repeats the
   exact anti-pattern ADR-0027 and ADR-0049 were both written to avoid: two epics,
   one PR, the most security-sensitive path in the system).
2. **Authenticated `web.fetch` (the ADR-0048 forward gates) is explicitly OUT of
   scope — a follow-on issue.** With `WEB_FETCH_AUTH_SECRET_ALLOWLIST` empty,
   per-secret↔destination binding and the gateway re-scan positive-path residual
   are unreachable; building them now would be dangling, never-exercised
   construction (the same reasoning #338 PR2 used to defer `build_tool_registry`
   itself). **Correction (§5): the one-broker-instance invariant no longer binds
   in #410 at all** — PR3's scope narrowed (item 6 below) to `clock.now` only,
   which needs no broker/egress path. The invariant — and the concrete fix for
   it, already researched — is now a documented forward-note for whichever
   future PR first wires `web.fetch` for real.
3. **The forwarded-path episodic/working-memory double-apply is fixed in #410
   (PR1); the budget double-apply is deliberately left as ADR-0049 already
   accepted it.** ADR-0049's acceptance of the residual was conditioned on
   tools being off; #410 is exactly the change that removes that condition for
   episodic/working-memory. The #338 design spec named `inbound_id`-idempotent
   writes as the in-scope alternative to the journal; that is what PR1 builds
   for those two. Budget is different — see item 5 (corrected below) for why
   gating it turned out to be the wrong call. This is deliberately **not** left
   for the journal to subsume — the journal governs tool-dispatch replay, not
   the orchestrator's own transcript writes, and conflating the two would make
   PR2 responsible for a correctness property it doesn't own.
4. **PR1 also covers `WorkingMemory.append`'s double-apply (§2), found while
   writing PR1's implementation plan, after this spec's first review.** Neither
   ADR-0049 nor this spec's original draft named it — it has the identical
   exposure shape as the episodic writes (same call sites, same forwarded-path
   trigger) and is arguably worse: a live user-visible context duplication, not
   just an audit-log one. One idempotency guard covers both concerns (episodic,
   working-memory) since they sit at the same two points in `_handle_turn`
   (turn-start, turn-end) — see §5, and item 5 below for why budget is NOT a
   third gate on this same ledger. **Mechanism:** a new Postgres table,
   composite `(adapter_id, inbound_id)` primary key (found during the
   `/review-plan` fleet pass, 2026-08-07: a single-column `inbound_id` key
   would reintroduce the exact cross-adapter
   collision class the sibling `inbound_idempotency` / `forwarded_dispatch_attempts`
   tables composite-key against) + two boolean columns (`user_turn_applied` /
   `assistant_turn_applied`), written via idempotent try-insert/try-update.
   Chosen over an in-process-only guard (dict/set) because every other
   idempotency mechanism in this codebase (Spec A G0's
   `PostgresInboundIdempotencyStore`, #338 PR2's own
   `PostgresForwardedDispatchAttemptStore`) is Postgres-backed for the same
   reason: an in-process guard is silently lost on a daemon restart mid-poison-loop,
   re-exposing the exact bug it exists to fix on the very next resume.
5. **Correction (found during the `/review-plan` fleet pass, 2026-08-07): PR1
   does NOT gate the budget charge at all — the original plan to do so was
   wrong.** The episodic/working-memory writes fire exactly once per
   `_handle_turn` attempt regardless of tool-iteration count (both sit OUTSIDE
   the Act loop — turn-start before it, turn-end after it), so gating them is
   safe in every world, tools on or off. The budget charge is different: it
   fires INSIDE the Act loop, once per iteration. A single boolean gate on it is
   sound ONLY while tools are off (always exactly one iteration) — the instant a
   future PR wires a live `tool_registry`, that same gate would silently skip
   charging every iteration after the first, on the plain happy path, no replay
   needed. The fleet review's four-way-corroborated finding on PR3 traced the
   consequence precisely: PR1's own construction-time guard against this
   (`RuntimeError` if `side_effect_ledger` and `tool_registry` were ever
   combined) made the live daemon **fail to boot** the moment PR3 wired a real
   `tool_registry` into the same `build_orchestrator` call — the guard did its
   job, but the "job" itself was the wrong design. **The fix: leave the budget
   charge exactly as it was before #410 — unconditional, every attempt, every
   iteration.** This restores ADR-0049's ORIGINAL residual for budget alone
   (over-charge, bounded to the poison ceiling, safe direction for a cost cap)
   instead of PR1's proposed under-charge (unsafe direction). It also composes
   correctly with PR2's fast-forward design for free: a fast-forwarded tool
   call never re-invokes the provider (no charge to duplicate), so only
   genuinely NEW post-resume completions get charged — the sole remaining
   double-charge is the exact same "duplicate final paid completion" ADR-0049
   already named and accepted, nothing new or worse. This removes PR1's
   tools-combination construction-time guard entirely (nothing left for it to
   protect) and removes any PR3 obligation to make a budget gate
   iteration-aware — there is no budget gate to make aware.
6. **PR3 wires `build_tool_registry`'s machinery but the LIVE registry
   advertises `clock.now` only — `web.fetch` is NOT activated in #410.**
   Found while writing PR3: `src/alfred/cli/web.py:69`
   `_list_allowlist_entries()` unconditionally returns `[]` — its own
   docstring says "until PR-S3-7 wires the Postgres `web_allowlist`
   projection," and that work does not exist yet (not even as a tracked
   issue). `AllowlistIntersection` (`allowlist.py:167`) is a TRUE
   `manifest ∩ operator ∩ session` intersection — "the session never widens
   the surface" — so an always-empty operator side makes `web.fetch`
   PERMANENTLY, unconditionally denied in production, regardless of how
   correctly everything else is wired. Shipping `web.fetch` wired-but-denied
   was considered and rejected as indistinguishable from a bug to a reader.
   `clock.now` needs no broker/egress path at all
   (`build_clock_tool(*, now) -> InternalToolSpec`,
   `src/alfred/orchestrator/builtin_tools.py:33`), so PR3 does not call
   `build_tool_registry` (which always builds BOTH tools) — it constructs
   `ToolRegistry([build_clock_tool(...)])` directly. This also makes item 2's
   one-broker-instance invariant fully moot for #410. Activating `web.fetch` (needing BOTH the allowlist
   projection AND the one-broker-instance fix) is deferred to its own
   follow-up, tracked separately from the already-deferred authenticated-fetch
   follow-up (item 2) — unauthenticated activation should land BEFORE
   authenticated, not bundled with it.

## 4. The finding that reshapes the journal design

The issue text (#410, which names the #338 design spec §9 as its own scope
source) describes the journal as replaying "the committed ordered dispatch
sequence... not a fresh stochastic planner" to prevent a resume from re-planning
tool calls and firing different side effects at the same slot. Verifying the Spec C ledger
(`egress_id.py`, `egress_idempotency.py`) against that description found it
already **stronger** than assumed:

- `compute_egress_id` is positional — a resumed re-plan that diverges in content
  but lands the same `call_index` computes the **same** `egress_id`.
- But `compute_egress_body_hash` binds the full request identity
  (`request_descriptor` = `method`+`url`+`schema_id`, headers, redacted body).
  `egress_idempotency.py:220` compares the replay's hash against the ledger's
  stored hash and raises `EgressIdIntegrityError` on any divergence.

So today, without a journal, a resumed turn whose planner emits a different call
at the same slot does not silently get someone else's result (mem-001's classic
shape) — it **dies loudly** and the frame replays until the poison ceiling
(`ForwardedDispatchAttemptStore`, `src/alfred/memory/forwarded_dispatch_attempts.py`).
That is fail-safe but not fail-*useful*: a resumed turn can never complete if the
planner is even slightly non-deterministic between attempts.

**The journal's actual job is narrower than "prevent mem-001": make the resumed
plan converge**, so the existing ledger's memoize-and-replay succeeds instead of
raising. **Correction (found while writing PR2's implementation plan, after
this spec's first review):** the journal cannot reuse `compute_request_descriptor`
as first drafted — that function (`method`+`url`+`schema_id`) is internal to
`egress_response_extract.py`'s web.fetch-specific extraction path (its only
callers), one layer below `dispatch_tool`'s generic boundary
(`src/alfred/orchestrator/tool_dispatch.py:54`), and `clock.now` (the registry's
other tool, per `tool_assembly.py`'s docstring) has no method/URL/schema at all.
The journal instead stores `(adapter_id, inbound_id, call_index) → (iteration, ToolCall)` —
`ToolCall` (`id`, `name`, `arguments`, `src/alfred/providers/base.py:110`) is
the identity `dispatch_tool` already receives for ANY tool, generically;
`iteration` is additionally needed to reconstruct the transcript's tool-call/
tool-result message grouping faithfully on replay (see §5's corrected
mechanism). On a forwarded-path resume, the Act loop replays the journalled
`ToolCall`s in call_index order instead of re-planning that prefix, feeding
each into the SAME `dispatch_tool` call unchanged — which internally computes
whatever tool-specific identity it needs (e.g. web.fetch's own
`compute_request_descriptor` call, untouched by this journal). **It does not
store tool results**; result dedup is already the ledger's job.

## 5. Architecture

Four increments, each independently shippable:

**PR1 — `(adapter_id, inbound_id)`-idempotent turn-start / turn-end (§3.4,
budget deliberately NOT gated — §3.5).** A new `TurnSideEffectLedger`
(Postgres, composite `(adapter_id, inbound_id)` PK + two booleans) gates the
episodic/working-memory calls named in §2: `working_memory.append` and
`episodic.record` at turn start (`core.py:702-703`) and `working_memory.append`
and `episodic.record` at turn end (`:1009,1021`). Each gate is a no-op on a
replay of the same `(adapter_id, inbound_id)`. `self._budget.check_and_charge`
(mid-loop, `:863`) is deliberately left ungated — see §3.5 for why gating it
was the wrong call. No special-casing needed for the `egress_context is None`
path (direct `alfred chat` / fixtures, which synthesizes via
`_synthesize_egress_context`): `ctx.inbound_id` there is a fresh `uuid.uuid4()`
**every call** (`handle_user_message:420`), so the guard's try-insert always
succeeds on the first attempt and is a pure pass-through — the same code path
is correct and inert on both the direct and forwarded paths, with no branch on
which one is active.

**PR2 — deterministic-replay journal (no live consumer).** A new
`(adapter_id, inbound_id, call_index) → (iteration, ToolCall)` durable log.
**Second correction (found during the `/review-plan` fleet's regression pass on
this spec's revision):** the journal writes an iteration's ENTIRE `tool_calls`
list as one atomic transaction BEFORE dispatching any call in that iteration —
NOT one row per call inside the dispatch loop as first drafted. `call_index`
still stays globally monotonic across iterations exactly as today; the change
is only to WHEN the write commits relative to dispatch. This makes
`_fast_forward_journalled_calls`' per-iteration-group assumption sound: either
an iteration's full tool-call decision is durably recorded before any dispatch
begins, or none of it is, so a crash mid-iteration falls back to full
re-planning of that iteration on resume instead of silently dropping whichever
calls hadn't been journalled yet. **Corrected mechanism (found while writing
PR2's implementation plan, after this spec's first review, and after the
requester approved the general "journal replaces planning on resume"
direction):** the replay is a **fast-forward of the journalled PREFIX, then an
unmodified resumption of the existing Act loop** — NOT a single forced
"wrap-up" completion as first proposed. On a resume, the loop reads the
journalled entries for `ctx.inbound_id`, replays each via the SAME
`dispatch_tool` call the normal path uses (relying entirely on the existing
Spec C egress ledger's memoize-and-replay for the actual dispatch — no new
dedup logic), reconstructing the `local` transcript grouped by the journalled
`iteration` field so the tool-call/tool-result message shape is faithful, then
resumes the EXISTING `for iteration in range(...)` loop from
`max_journalled_iteration + 1` onward with `tool_choice="auto"` UNCHANGED. A
forced single wrap-up (`tool_choice="none"`) was rejected: if the original
attempt crashed BEFORE the planner decided to stop calling tools, forcing a
premature text-only answer on resume would truncate legitimate further tool
use the replay should still be free to take. `temperature=0` threads to both
provider adapters for genuinely fresh (post-fast-forward or never-replayed)
completions as defence-in-depth — trivial to wire since `CompletionRequest`
already has a `temperature` field (`base.py:235`, default `0.7`) that both
provider adapters already read; only the VALUE `core.py` passes needs to
change, no provider-adapter file needs touching.

**PR3 — the tools-on cutover, `clock.now` only (§3 item 6).** Wires a
`ToolRegistry([build_clock_tool(...)])` — deliberately NOT `build_tool_registry`,
which always builds `web.fetch` too — into `build_orchestrator` and the daemon
comms boot graph, following the forward-instructions already left in
`_comms_boot.py:747-766` (adapted: no `build_web_fetch_egress_extractor` call at
all in this PR). This is the only PR with a behaviour change visible to users —
Discord and `alfred chat` turns can now dispatch `clock.now`, the first genuinely
live, working tool call on the comms path. `web.fetch`'s activation is a
follow-up (§3 item 6), blocked on the untracked allowlist-projection gap.

**PR0 — bookkeeping**, parallel to the above, not gating them: close #338/#340,
correct the stale project memory, and note the two other unaddressed MVP gaps
(Telegram adapter, `alfred rollback`) on their existing epics.

Data flow for a tool-bearing forwarded turn (PR3, post-cutover):

```
Discord message -> gateway relay -> forwarded_inbound_receiver
  -> inbound.py (commit_at_dispatch_edge=True path)
  -> RealTurnOrchestratorAdapter.ingest (T3->T2 downgrade, unchanged since #338)
  -> RealTurnOrchestratorAdapter.dispatch
       -> Orchestrator.handle_user_message(egress_context=real)
            -> Act loop (core.py:775): planner emits tool_calls
                 -> PR2 journal: append (call_index, iteration, ToolCall) BEFORE dispatch
                 -> dispatch_tool (registry, gate, outbound_dlp trio, core.py:973-990)
                      -> web.fetch: EgressResponseExtractor over the relay,
                         egress_id = compute_egress_id(ctx, call_index)
                         (ledger memoize-and-replay handles a resume transparently)
            -> PR1: episodic record + budget charge, keyed on inbound_id
       -> DLP-scanned answer sent
  -> commit_once (Spec A G0)
```

On a crash between "tool dispatch committed" and "commit_once", the forwarded
frame replays. Post-PR2, the Act loop detects a journal entry for this
`(adapter_id, inbound_id)` and replays the journalled call sequence rather than
re-invoking the planner — each call reproduces its original `egress_id` and the
Spec C ledger short-circuits via memoize-and-replay (a genuine no-op re-fire, not
an `EgressIdIntegrityError`). Post-PR1, the episodic/budget writes on that same
replay are no-ops.

## 6. Error handling

- **`build_tool_registry` misconfiguration.** The `core.py:973` guard
  (`registry`/`gate`/`outbound_dlp` all-or-none) stays a loud `raise
  RuntimeError(t(...))`, never an `assert` — CLAUDE.md hard rule #7. PR3 is the
  first PR where this branch becomes reachable; it needs a positive test that
  drives it, not just the existing negative (all-`None`) coverage.
- **Journal write failure.** A failed journal append must not silently let the
  planner proceed un-journaled — that would defeat PR2's purpose on the next
  resume. It fails the turn the same way an audit-write failure does today
  (loud, no silent degrade).
- **`EgressIdIntegrityError` post-PR2.** Should become effectively unreachable on
  a normal resume (the journal makes the replay converge), but stays a hard raise
  for the genuine tamper/bug case — PR2 must not weaken or catch this error, only
  make it rarer.
- **One-broker-instance divergence.** If a future change ever passes a second
  `SecretBroker` instance into `build_tool_registry` (distinct from the one
  backing `outbound_dlp`), that is a construction-time bug per ADR-0048. This
  invariant is moot for PR3 (§3 item 6 — PR3 sidesteps `build_tool_registry`
  entirely, so no second broker instance is ever constructed) and PR3 ships no
  such test. The object-identity (`is`, not equality) test is owned by the
  web.fetch-activation follow-up issue (§9, "Authenticated `web.fetch`") once
  that work actually calls `build_tool_registry` for the first time in
  production.

## 7. Audit cost model

Unchanged from #338: no new cost aggregator. The `orchestrator.turn` `completed`
row shape (`subject.turn_cost_usd` = turn total; `cost_actual_usd` terminal-only)
is preserved. PR3 adds tool-dispatch audit rows (already specified by
`dispatch_tool`'s existing contract in `core.py:978-989`) — no new row shape,
just a newly-reachable code path.

## 8. PR decomposition

See §5 for the four-PR shape. **Correction (found during the `/review-plan`
fleet pass, 2026-08-07): PR1 and PR2 are NOT independent — PR2 depends on PR1
having landed first**, not merely "could run in parallel" as originally
claimed. Two concrete, verified dependencies: PR2's migration chains on PR1's
migration number, and PR2's `_fast_forward_journalled_calls` call site needs
`ctx` resolved at the point PR1's Task 4 moves that resolution to — on
unmodified `main`, `ctx` isn't assigned until several lines later, so PR2's
edit doesn't apply cleanly without PR1 first. Ordering is strictly PR1 → PR2 →
PR3: tools-on without the journal would reintroduce the very risk the
sequencing decision in §3.1 exists to avoid, and PR3 additionally needs PR1's
episodic/working-memory fix in place first.

## 9. Out of scope — recorded here so a follow-up inherits the gates

- **Unauthenticated `web.fetch` activation** (§3 item 6, new — must land BEFORE
  the authenticated follow-up below, not bundled with it): wire the operator
  web-fetch allowlist projection (`_list_allowlist_entries()`,
  `src/alfred/cli/web.py:69`, currently a stub always returning `[]` — no
  tracked issue exists for this yet, file one) and apply the one-broker-instance
  fix already researched here (§ item 2 correction): make `broker` /
  `secret_broker` OPTIONAL params on `_build_boot_outbound_dlp` and
  `_build_comms_boot_graph` (default: build internally, unchanged for every
  existing caller), then have `_commands.py`'s ONE production call site build
  the broker once and pass it to both — zero blast radius on the 6 existing
  integration test files that call either function directly.
- **Authenticated `web.fetch`** (§3.2): per-secret↔destination binding, populating
  `WEB_FETCH_AUTH_SECRET_ALLOWLIST`, the gateway re-scan positive-path residual.
  All three gates from the original #410 issue body carry forward unchanged to
  that follow-up issue.
- **Group/channel reply addressing** (#24) — the live turn stays DM/1:1 (the
  #338 spec's FOLD-6 boundary; `InboundMessageNotification` still carries no
  channel/thread target id).
- The remaining PRD §4 MVP gaps this session identified but did not scope work
  for: Telegram adapter (criterion 2, epic #37), `alfred rollback` (criterion 7,
  epic #61), persona handoff/group sessions (criterion 5, epic #22), the
  reviewer-gated self-improvement flow (criterion 4, epic #32 — no
  `src/alfred/reviewer/` exists at all today), first-run experience (epic #469).

## 10. Testing

- **PR1:** unit — `TurnSideEffectLedger`'s TWO gates (`try_apply_user_turn`,
  `try_apply_assistant_turn`) are each idempotent under a replayed
  `(adapter_id, inbound_id)` (working-memory content and episodic row count
  pin to exactly-once). Budget spend is deliberately NOT pinned to
  exactly-once — `test_budget_charge_always_fires_regardless_of_ledger_state`
  asserts `check_and_charge` fires on every attempt regardless of gate state,
  per §3.5's correction. The direct/fixture path (`egress_context is
  None`, fresh `inbound_id` per call) is byte-for-byte unchanged (regression-pin
  against #338 PR2's existing fixtures). A dedicated regression test for the
  working-memory case: assert `WorkingMemory.turns()` does not contain a
  duplicated user turn after a same-process replay of the same `inbound_id`
  (the bug this PR fixes that ADR-0049 did not name). Integration over real
  Postgres/Redis reusing the forwarded-path crash-injection seam #338 PR2 already
  built. New Alembic migration after `0024_audit_result_egress_relay_refused_values.py`.
- **PR2:** unit — journal write/read round-trip; a fast-forward replay
  dispatches the journalled prefix in call_index order via the same
  `dispatch_tool` call (no bespoke dedup logic — the existing Spec C ledger's
  memoize-and-replay is exercised, not re-implemented); the reconstructed
  `local` transcript groups tool-call/tool-result messages by the journalled
  `iteration` field faithfully; the loop resumes normal (`tool_choice="auto"`)
  planning from `max_journalled_iteration + 1`, still free to make further
  tool calls (the regression pin for the rejected forced-wrap-up design);
  `temperature=0` reaches both `deepseek.py` and `anthropic_native.py` via the
  one-line `CompletionRequest(..., temperature=...)` change (no provider-file
  edits). Property test (hypothesis): for any journalled call list, replay
  dispatch order always matches the original call_index order. Mutation-test
  every new guard. New Alembic migration; **ADR-0062** records the journal
  contract. Explicitly documents (not "fixes" — nothing to fix): `clock.now`
  (`InternalToolSpec`) has NO Spec C egress-ledger dedup protection on replay,
  unlike `web.fetch` (`ExternalToolSpec`) — low blast radius (no side effects)
  but must be named, not silently assumed covered.
- **PR3:** integration over real Postgres/Redis + the live quarantine child — a
  real inbound message drives a real `clock.now` dispatch and a real answer.
  `clock.now` needs no broker/egress path (§3 item 6), so there is no
  `build_web_fetch_egress_extractor` singleton or `build_tool_registry` broker
  to assert on in this PR — those checks belong to the future web.fetch-
  activation follow-up, not here. No new adversarial corpus entry: the
  unknown-tool-name-refused property is already covered at the `dispatch_tool`
  unit level by the existing `cap-2026-010` corpus entry (#339); PR3 extends
  that SAME property end-to-end through the newly-live boot graph instead of
  duplicating it. **Adversarial suite + explicit 100% line+branch on the
  boundary translator are release-blocking** (dual-LLM boundary touched, per
  CLAUDE.md hard rule). Real-provider behaviour is a **manual UAT**, not a
  per-commit paid call: real Discord message → real tool call → real answer.
- **Process:** three-amigos pass before implementing each PR; a full
  `/review-plan` fleet pass on this document before writing-plans, given the
  cross-subsystem span; subagent-driven TDD; full `/review-pr` fleet **and**
  CodeRabbit (`full review`, `--base origin/main`) on every PR — per project
  history these catch disjoint bugs, neither is a substitute for the other.
  `alfred-security-engineer` sign-off required on PR3 (dual-LLM boundary,
  first-ever live tool dispatch on the comms path).

## 11. ADRs

- **ADR-0062 (new)** — the deterministic-replay journal: contract, relationship
  to the Spec C egress-idempotency ledger, and why it journals call sequence
  rather than results (§4).
- **ADR-0049 (amend)** — supersede its "egress tools DEFERRED... empty tool
  registry" premise (Decision, §"Scope decision") once PR3 lands; retire its
  accepted episodic/budget double-apply residual once PR1 lands (§0/§8 there).
- **ADR-0048** — not touched by this design (§3.2); the follow-up issue inherits
  its forward gates verbatim.
- PRD / CLAUDE.md edits remain human-gated per repo policy.

## 12. Risks & residuals

- **Journal storage growth.** An unbounded per-turn journal table needs a
  retention/pruning story before this ships to a long-running deployment — not
  fully designed here; PR2's implementation plan should size a bound (e.g. prune
  on successful `commit_once`, since a committed frame never resumes again).
- **`temperature=0` is defence-in-depth, not the primary guarantee.** The journal
  (§4) is what makes convergence correct; `temp=0` only makes it *more likely*
  the planner would have converged unaided. Do not let PR2's implementation plan
  treat one as a substitute for the other.
- **PR3 is the first live consumer of `dispatch_tool` on the comms path** —
  everything in `tool_dispatch.py`/`tool_registry.py` was previously exercised
  only by tests and the (now-closed) #339 mechanism work. Expect integration
  friction that #339's test suite did not surface, since it never ran against a
  live boot graph.
- **`InternalToolSpec` tools have no Spec C egress-ledger dedup protection**
  (found during the `/review-plan` fleet pass, 2026-08-07). Only
  `ExternalToolSpec` (web.fetch) is wired to `compute_egress_id`/the
  memoize-and-replay ledger. `clock.now` — PR3's only live tool — is only safe
  to replay unprotected because it is side-effect-free by construction; that
  invariant is enforced by convention, not by any type/registry-level
  guarantee. A future `InternalToolSpec` with real side effects would inherit
  this gap silently unless a guard is added to `tool_registry.py` before then.
