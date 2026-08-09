# #410 PR1 — Ledger/episodic transactional-coupling fix — Design

> **Status:** approved by requester, 2026-08-08. Supersedes the session-ownership
> design in `TurnSideEffectLedger`'s Task 1 implementation and Task 4's wiring as
> already committed on the `410-pr1-turn-side-effect-ledger` worktree branch
> (commits through `fa13d3e8`). This is an addendum discovered during Task 4's
> code review, not a revision to the original
> `2026-08-07-issue-410-tools-on-design.md` spec (that document is unaffected —
> this fix is internal to PR1's own implementation, not a scope change to the
> #410 epic).
> **2026-08-08, later:** §3.1's one-transaction-spanning-the-provider-call
> mechanism is itself superseded by
> [ADR-0062](../../adr/0062-three-phase-turn-and-role-scoped-connection-pools.md)
> (empirically verified pool deadlock: 16 concurrent turns, 0 succeeded);
> §3.2 carries forward as gate-keyed conditional threading and §3.3/§3.4 as
> per-phase deferred appends + `commit_failed` telemetry, per
> `docs/superpowers/plans/2026-08-08-issue-410-pr1-pool-deadlock-fix.md`.
> Task-number key: §1/§5 below cite the ORIGINAL
> `2026-08-07-issue-410-pr1-turn-side-effect-ledger.md` plan's numbering.
> In the superseding pool-deadlock plan those land as — original Task 1
> (`turn_side_effects.py` rewrite) → its Task 3; original Task 3 (Postgres
> integration contract) → its Task 4; original Task 4 (orchestrator
> wiring) → its Task 6; original Task 5 (boot wiring / arming) → its
> Task 7; original Task 6 (crash-injection flip) → folded into its Task 7
> Step 4; original Task 7 (working-memory append tests) → its Task 6
> Step 6. Read §5's per-task impact notes through that mapping.

## 1. Problem

Task 4's code review (an Opus-tier task-reviewer, `/review-plan`-independent —
this was caught at implementation-review time, not by either of the two prior
full `/review-plan` fleet passes) found that `TurnSideEffectLedger`
(`src/alfred/memory/turn_side_effects.py`) commits its at-most-once gate via its
own, independent, immediately-committing `session_scope` — separate from the
per-turn `AsyncSession` that `Orchestrator._handle_turn`
(`src/alfred/orchestrator/core.py`) uses for the episodic write the gate
guards. `Orchestrator.handle_user_message` rolls back that per-turn session on
timeout, external cancel, and any other exception (`core.py:506,538,545`).

**Failure sequence (as implemented, pre-fix):** the ledger's gate commits
`TRUE` — durable, irreversible — before the episodic write it guards has even
been attempted. If the surrounding per-turn session then rolls back for any
reason (a transient provider failure being the most common), the episodic row
never lands, but the ledger row still says "applied". On a forwarded-path
replay — which a mid-turn failure is exactly what triggers — the gate now
denies, and the user's message is **permanently missing** from durable memory.
`WorkingMemoryPool._rehydrate` (`src/alfred/memory/working_pool.py:104-122`)
prefills from `episodic.recent(...)`, so it cannot recover what was never
written. This is worse than the pre-#410 bug (a duplicate row) that PR1
exists to fix.

A second, independent bug was found while designing the fix: because the
completion request is built purely from `working_memory.turns()`
(`core.py:759-761`), and the user's current message only enters that buffer
via the same gated append, a retry whose gate correctly denies (because the
prior attempt already committed and just failed to *send*) still makes a
fresh provider completion call — but with a prompt that ends on the *previous
assistant reply*, with no new user turn after it. Most provider APIs
(Anthropic included) treat a conversation ending on an assistant message as a
prefill continuation, not a fresh question — so the retry's own answer is a
garbled continuation fragment of the prior reply, which still gets returned
and sent to the user. This hits the **primary, common** retry scenario
(successful commit, outbound send fails, same-process retry), not an edge
case — pre-#410 this didn't happen, because the (buggy) unguarded duplicate
append meant the prompt always correctly ended on a fresh user turn.

Both bugs are latent, not live: `side_effect_ledger` is not yet wired into
production (`_bootstrap.py:459-467` doesn't accept it; PR1's own Task 5 is
what would arm it). Caught before deployment.

## 2. Investigation summary

Three rounds of Opus-tier investigation and self-verification (see
`~/.claude/projects/-Users-iandominey-projects-AlfredOS/memory/` for this
session's working notes if resuming — not committed here, this section is the
durable record):

1. **First pass** confirmed the failure sequence against the real code exactly
   as described above, checked the sibling `ForwardedDispatchAttemptStore`
   precedent (its independent-commit design is *correct* for what it guards —
   a retry counter, not a durability claim — so this is a mis-transferred
   pattern, not a second instance of the same bug), and proposed candidate
   fixes A (fold the ledger into the per-turn transaction), B (defer the
   ledger's commit until after the turn commits — rejected, reopens the
   concurrent-safety race Task 3 proves), C (make the episodic write itself
   idempotent via a partial unique index, eliminating the ledger table
   entirely — a stronger but much larger-blast-radius alternative, not
   pursued), and D (take `working_memory` off the durable ledger entirely).
   Initially recommended "A + D".
2. **Second pass** (this session, then verified by a fresh Opus dispatch)
   traced all four relevant cases (commit-ok+send-fail × same-process/restart;
   mid-turn-rollback × same-process/restart) through Option A alone and found
   it fully closes the catastrophic case on its own — D was justified by
   describing the *pre-fix* residual, not the *post-A* one, and would only
   reopen working-memory duplication on the primary scenario for no
   compensating benefit. **D rejected.**
3. **Third pass** investigated whether the one remaining residual under A
   alone (mid-turn-rollback + same-process retry → a transient working-memory
   duplicate, self-healing but not fully closed) could be closed rather than
   merely documented, by deferring the `working_memory.append` calls until
   after the per-turn transaction commits. Verified: yes, at low cost, with no
   PR2/PR3 forward-compatibility concerns (the Act loop never reads working
   memory mid-turn; multi-iteration turns build their transcript from an
   entirely separate ephemeral `local` list, `core.py:776`). Also surfaces a
   free bonus fix: `record_action_duration(action_outcome="success")`
   currently fires *before* the commit (`core.py:462-467`), so a commit
   failure would today record a spurious "success" — the restructure this fix
   requires naturally corrects that too.

## 3. Design

### 3.1 The ledger joins the per-turn transaction

`TurnSideEffectLedger`'s two methods stop owning an independent
`session_scope` and instead operate on the per-turn `AsyncSession`, mirroring
the existing `episodic_factory: Callable[[AsyncSession], EpisodicMemory]`
pattern already in `Orchestrator` (`core.py:698`,
`self._episodic_factory(session)`). The exact mechanism (constructor taking a
session directly vs. a `ledger_factory: Callable[[AsyncSession], ...]`
matching `episodic_factory`'s shape) is an implementation-plan decision, not a
design decision — either preserves the property this section requires: **the
ledger's `INSERT ... ON CONFLICT ... RETURNING` and the episodic write it
guards commit or roll back together, as one transaction.** The SQL itself
(`turn_side_effects.py:88-102`) is unchanged.

This closes the data-loss bug directly: a rollback now un-marks the gate in
lockstep with the write it guards, so a replay after any mid-turn failure
correctly sees "not yet applied" and retries the write — never "applied but
missing".

**Concurrency property, preserved:** the atomic `INSERT ... ON CONFLICT ...
DO UPDATE ... WHERE ... RETURNING` remains one statement inside the (now
shared) transaction. Under READ COMMITTED (this codebase's default), a
concurrent second attempt on the same key blocks on the row lock until the
first transaction resolves: if the first committed, the second's `DO UPDATE`
re-reads the committed row and the `WHERE ... = FALSE` guard correctly denies
it; if the first rolled back, the second's insert succeeds. Task 3's
`test_concurrent_first_applies_settle_to_exactly_one_winner` property holds
unchanged — the property under test moves from "8 independent immediately-
committing sessions" to "8 independent transactions that each commit or roll
back the guarded write together with the gate", which is the same shape, not
a weaker one.

**Accepted trade-off, named explicitly (found during `/review-plan`, 2026-08-08
— independently by two reviewers, `alfred-memory-engineer` and
`alfred-security-engineer`):** folding the ledger into the shared transaction
means a losing concurrent attempt's row-lock wait grows from a fast,
standalone statement (milliseconds, under the old independent-session design)
to up to the **full turn duration**, bounded only by the 30s action deadline —
since the loser now blocks until the winner's entire transaction (provider
call, tool dispatch, terminal audit write, and all) resolves, not just its own
UPSERT. Today this is masked entirely: `RealTurnOrchestratorAdapter._turn_locks`
(`src/alfred/comms_mcp/real_turn_adapter.py:193-203`) already serializes the
whole turn per `(persona, user_id)` in-process, so two genuinely concurrent
attempts on the same `(adapter_id, inbound_id)` key require two separate
processes to occur at all — not ruled out architecturally, just not exercised
by any test today. **Accepted as a deadline-bounded residual** (Option B, the
alternative that avoids this by not sharing the transaction, was already
rejected in §4 for reopening the concurrent-safety race this design closes) —
worth a dedicated ADR-0049 entry (Task 8) rather than three scattered notes,
and a test asserting the loser's wait is bounded and resolves promptly once
the winner's transaction concludes (Task 3).

**A second, related trade-off: no DB-side bound on an orphaned lock (found
during `/review-plan`, `alfred-security-engineer`, confirmed by
`alfred-memory-engineer`):** a genuine process crash mid-turn now leaves an
orphaned transaction holding the ledger row lock — nothing rolls it back,
since rollback is the connection's own job and the connection is gone.
`src/alfred/memory/db.py`'s engine construction sets no
`idle_in_transaction_session_timeout` (confirmed: no such override anywhere in
`src/alfred/memory/db.py` or the compose config), so Postgres itself imposes
no bound either — the crash-then-restart replay, the exact path this ledger
exists to protect, could block on that orphaned lock for however long the
OS-level TCP connection takes to be recognized as dead (commonly on the order
of hours under default keepalive settings), not the sub-second window the
"deadline-bounded" framing above implies for the live-contention case. **This
one needs an actual fix, not just documentation**: set
`idle_in_transaction_session_timeout` on the engine (via
`create_async_engine`'s `connect_args={"server_settings": {...}}}` — confirmed
mechanically sound against this codebase's SQLAlchemy version) to a bound at
least as generous as `action_deadline_seconds`, so Postgres itself reclaims an
orphaned transaction's locks within a known, short window regardless of
whether the crashed process's connection is ever recognized as dead. Task 3
needs an integration test that kills a connection mid-transaction and asserts
the replay's wait is bounded by this timeout, not by OS-level keepalive
defaults.

### 3.2 The current turn's own message always reaches the provider

`_handle_turn` threads the current attempt's own user input into the message
list used for *that attempt's* completion request explicitly, independent of
whether the durable gate allowed the append to the durable buffer. Read
history from `working_memory.turns()` as today; always add the current user
message to the *local*, per-attempt request-building list before calling the
provider, so the conversation sent to the provider always ends on a fresh
user turn regardless of gate outcome.

Because of §3.3 below, this is not merely a retry-path correction — under the
deferred-append design, working memory never contains the current turn's
append at prompt-construction time even on the happy path, so this mechanism
is load-bearing on **every** turn, not just retries. This needs its own direct
test (assert the completion request contains the current user text
independent of `working_memory.turns()`'s contents), not only a
retry-scenario test.

One residual cosmetic effect on a retry: the history read from
`working_memory.turns()` will already contain the prior committed attempt's
`[user, assistant]` pair (since the gate denied re-appending it), so the
provider sees that prior exchange once, plus the same question restated as
the new final turn. This is redundant context, not incorrect context — the
conversation still ends on a fresh user turn and produces a sensible answer.

### 3.3 Working-memory appends are deferred until after commit

Both `working_memory.append(...)` calls (`core.py:731`, `:1042`) move from
"immediately, inside the gated block, mid-transaction" to "after the
`async with self._session_scope()` block exits successfully — i.e., only once
the transaction has actually committed."

**Mechanism:** `_handle_turn` returns a small internal outcome carrying the
reply plus the staged working-memory appends (which turns to append, decided
by the gate results, not yet applied) instead of returning the reply string
directly. The pseudocode below is illustrative of control flow and ordering,
not final implementation code — but every element that matters (the outer
try/except, the telemetry call's exact position, the loop) must appear in the
implementation exactly as shown, not merely "be a natural consequence" of the
restructure (a `/review-plan` finding, 2026-08-08: an earlier draft of this
section showed the deferred-append loop without showing where the relocated
telemetry call goes, and the existing safety-net test
(`test_success_path_records_duration`, `test_core.py:1005-1024`) is an
unordered spy assertion that would not catch an implementer leaving the call
in its old, pre-commit position):

**Structure superseded by ADR-0062 (see the status block above):** the single
`async with` below is now TWO short-lived phase scopes with the provider call
between them. The telemetry positions and the deferred-append loop carry
forward per-phase; the enclosing transaction shape does not.

```python
outcome: _TurnOutcome | None = None
try:
    async with self._session_scope() as session:
        try:
            outcome = await self._deadline_wrapper.run(self._handle_turn, session, ...)
        except TimeoutError: ...      # existing rollback arms, unchanged, all re-raise
    # commit has succeeded here — session_scope.__aexit__ ran session.commit()
except Exception:
    # #410 PR1 fix (found during `/review-plan`, 2026-08-08): a commit
    # failure at __aexit__ happens AFTER the inner try/except above has
    # already exited cleanly, so none of the three existing rollback arms
    # ever see it — without this outer arm, a commit failure records NO
    # telemetry at all (worse than the pre-fix bug, which at least recorded
    # a wrongly-labeled "success"). Record before re-raising; never swallow.
    record_action_duration(action_outcome="commit_failed")
    raise
# Telemetry BEFORE the deferred-append loop, not after (found during
# `/review-plan`, 2026-08-08): if a deferred append itself ever raised and
# the metric fired afterward, this would reproduce the exact "records
# success for an incomplete turn" bug this fix exists to close, just moved
# one step later. Firing here means "success" means "the transaction
# committed" — the append loop below is best-effort in-process delivery,
# not part of the durability claim the metric makes.
record_action_duration(action_outcome="success")
for role, text in outcome.working_memory_appends:
    await working_memory.append(role=role, content=text)
return outcome.reply
```

`_TurnOutcome` is a frozen dataclass (`reply: str`,
`working_memory_appends: tuple[tuple[Role, str], ...]`). `DeadlineWrapper.run`
is already generic (`deadline.py:70`) and types through unchanged. No test
calls `_handle_turn` directly — every test goes through
`handle_user_message` — so this is an internal signature change with no
external contract impact. The implementation plan must add a forced-commit-
failure test (e.g. monkeypatching `session.commit` to raise) asserting the
`commit_failed` outcome is recorded and the exception still propagates —
`action_outcome="commit_failed"` is a new value; confirm it doesn't collide
with an existing enum/literal type constraining that field before landing it.

**Why not a SQLAlchemy `after_commit` hook:** rejected. `after_commit`
handlers are synchronous; `WorkingMemory.append` is async, and bridging would
need `asyncio.create_task`, which this codebase explicitly forbids
(`deadline.py:24-27`, "no fire-and-forget tasks"). There is no existing
precedent for `sqlalchemy.event`/`after_commit` anywhere in `src/`. The
codebase has already named the intended home for a future durability-signal
hookpoint (`episodic.py:334-335`: "a future `after_commit` hookpoint **owned
by `session_scope`**") — an ad-hoc listener in the orchestrator would pre-empt
that decision in the wrong module. Straight-line post-block code is honest
about ordering, typed, adds no new mechanism, and is what this design adopts.

**Verified this fully closes the remaining residual** (not merely narrows
it) across all four cases: commit-ok+send-fail (same-process and
after-restart) — unaffected, already correct; mid-turn-rollback,
after-restart — unaffected, already correct; **mid-turn-rollback,
same-process — now closed**: the append was only staged, never applied, so a
rollback discards it along with the ledger row and the episodic flush
together. A retry produces exactly one user turn and one assistant turn, not
a transient duplicate.

**New residual introduced by deferral, and why it's acceptable:** a genuine
process crash between the transaction's commit and the (now-deferred)
`working_memory.append` calls would lose the in-process append. This is
strictly *better* than the residual it replaces, not worse: the crash also
kills the in-process buffer regardless, and restart rehydrates from the
already-committed episodic row (`working_pool.py:113-122`), so net loss is
zero. Commit failure itself is naturally fail-closed under this design (see
the outer `except Exception` above) — the exception propagates, the
deferred-append loop never runs, no append happens — a property the current
(pre-fix) design does not have.

**This safety argument has a named, load-bearing external dependency — cite
it, don't just assert the property (found during `/review-plan`, 2026-08-08,
independently by `alfred-memory-engineer` and `alfred-security-engineer`):**
"cancellation between commit and append is not reachable today" is true only
because `RealTurnOrchestratorAdapter._turn_locks`
(`src/alfred/comms_mcp/real_turn_adapter.py:193-203`) — a DIFFERENT module,
not `Orchestrator` or `WorkingMemory`'s own contract — serializes the whole
turn per `(persona, user_id)`, so `WorkingMemory.append`'s lock acquisition is
always uncontended and its current implementation returns without ever
awaiting (a general property of an uncontended `asyncio.Lock` in this
codebase's Python version, not a version-specific "fast path" — the earlier
draft of this section over-attributed this to "CPython 3.14.6" specifically,
which mischaracterized a stable stdlib property and obscured the real
dependency). §6 already names the Slice-3 Redis swap as a future obligation
that would break this; this paragraph is the other half of that same
obligation — **if a future caller ever reaches `Orchestrator` without going
through `RealTurnOrchestratorAdapter`'s mutex**, the deferred-append region
(outside any try/except by design, since it's meant to be the "committed,
just delivering" tail) could raise or be cancelled uncaught: no audit row, no
error surfaced, reply potentially lost after the durable write already
succeeded — a CLAUDE.md hard-rule-#7 concern. Whoever removes or bypasses
that mutex inherits the obligation to re-derive this section's safety
argument, not just the Redis-swap one. The implementation plan should either
cross-reference `_turn_locks` by name in the deferred-append loop's own
comment (cheap, recommended), or wrap the loop in an `except
asyncio.CancelledError` that logs/audits a "committed but in-process delivery
raced a cancel" outcome before re-raising (more defensive, not required given
the current mutex, but worth considering if the mutex's scope ever changes).

### 3.4 Telemetry correctness, folded into §3.3's mechanism

`record_action_duration(action_outcome="success")` (`core.py:462-467`)
currently fires *before* the transaction's commit — a commit failure today
records a spurious "success" observation. **This is not a side effect that
falls out naturally from §3.3's restructure — it is an explicit part of the
mechanism, shown in §3.3's pseudocode** (a `/review-plan` finding, 2026-08-08:
an earlier draft called this a "natural consequence" without the pseudocode
actually showing it, which is exactly the kind of gap that lets an
implementer reproduce the bug one line later). The three requirements, all
visible in §3.3's code block:

1. The relocated `record_action_duration(action_outcome="success")` call
   fires immediately after the `async with` block exits successfully, before
   the deferred-append loop — not after it, and not left in its original
   pre-commit position.
2. A commit failure specifically (not just the three pre-existing rollback
   arms) is caught by an outer `except Exception` and recorded as its own
   outcome (`"commit_failed"`) before re-raising — today's code effectively
   has no path that reaches this state distinctly, so this is new coverage,
   not a relocation.
3. Verify `tests/unit/orchestrator/test_core.py:1020`
   (`action_outcome == "success"` assertion) still passes as an unordered spy
   check — it inspects kwargs only, so it is unaffected by the timing move —
   but add the forced-commit-failure test §3.3 calls for, since nothing
   today exercises requirement 2.

## 4. Rejected alternatives

- **Option B — defer the ledger's own commit until after the turn commits,
  keep the gate check-then-act as a single atomic step at the START of the
  turn.** Rejected: preserving the concurrent-safety property this way
  requires a two-phase claim/confirm protocol (a tri-state column, a claim
  lease with expiry), more machinery for a weaker guarantee than Option A,
  and introduces a fresh failure window (commit succeeded, confirm failed →
  gate unset → replay duplicates the durable row — the *original* #410 bug,
  merely narrowed).
- **Option C — make the episodic write itself idempotent** via a partial
  unique index on `episodes(adapter_id, inbound_id, role)` and `ON CONFLICT
  DO NOTHING`, eliminating `turn_side_effect_ledger` and migration 0025
  entirely. Not rejected outright — genuinely the stronger long-run answer
  if the team later wants inbound provenance on `episodes` for independent
  reasons — but a migration on the system's hottest table plus a
  schema-level assertion about future turn structure is much larger blast
  radius than Option A for the same correctness gain, on code written this
  week and not yet wired into production. Deferred, not chosen, for PR1.
- **Option D — take `working_memory` off the durable ledger entirely**
  (ungate it, rely on self-healing from episodic on restart). Rejected after
  the four-case trace showed Option A alone already eliminates the
  catastrophic case; D would only reopen working-memory duplication on the
  primary send-failure-retry scenario (Task 7's own headline goal) for no
  compensating benefit, since the case it was meant to rescue no longer
  exists once A is applied.

## 5. Impact on PR1's existing tasks (implementation-plan level, resolved by writing-plans)

This section is a map for the implementation plan, not the plan itself.

- **Task 1** (`turn_side_effects.py` + its unit tests): constructor changes
  from an owned `session_scope` factory to accepting the per-turn session
  (mirroring `episodic_factory`). Docstring rationale at `:52-67` and
  `:118-130` inverts and needs rewriting, not amending — it currently asserts
  the opposite of this design and is the direct cause of the bug. **Test
  fallout is larger than "constructor changes" implies** (found during
  `/review-plan`, 2026-08-08, `alfred-test-engineer`, confirmed by direct
  count): all 7/7 tests in `tests/unit/memory/test_turn_side_effect_ledger_store.py`
  currently construct via the doomed `session_scope=` kwarg and will fail
  with `TypeError` at construction, not just "the constructor" in the
  abstract — budget the implementation task for rewriting every one of them,
  not a subset.
- **Task 3** (Postgres integration test): **not signature-change-only** (a
  `/review-plan` finding, 2026-08-08, `alfred-architect`, confirmed against
  `test_turn_side_effect_ledger_postgres.py:36-43,82-90` — the fixture setup
  and every test body construct and pass a session-scope callable, all of
  which restructure, not just the constructor call site). The concurrent-race
  test's "exactly one winner" property is preserved per §3.1, restructured to
  model 8 concurrent transactions rather than 8 independent sessions. Three
  **new** tests are required here, none of which exist today: (1) a
  transaction that rolls back after the gate must leave the gate unset — the
  direct regression test for the bug this design fixes; (2) a connection
  killed mid-transaction (simulating a crash) must show the replay's wait is
  bounded by the new `idle_in_transaction_session_timeout` (§3.1), not by
  OS-level keepalive defaults; (3) a concurrent-attempt-plus-rollback
  intersection — §3.1's single-statement "exactly one winner" argument holds
  by inspection of the UPSERT alone, but the WIDER shared transaction this
  design introduces is new lock-footprint surface that inspection of the
  statement doesn't cover (found during `/review-plan`,
  `alfred-test-engineer`, confirmed by `alfred-security-engineer` as directly
  related to the lock-duration trade-off named in §3.1) — a concurrent
  variant of the rollback test closes this, or the "provable by inspection"
  claim in the eventual ADR-0049 entry should be scoped explicitly to the
  ledger statement alone, not the transaction's full lock footprint.
- **Task 4** (already implemented as committed, `0a75f1ba`..`fa13d3e8` on this
  worktree branch — needs revision, not a fresh implementation): the
  `_TurnOutcome` restructure, the deferred-append loop, and the
  prompt-construction fix (§3.2) all land here. `TestTurnSideEffectLedgerGating`'s
  existing assertions on final working-memory contents are unaffected (final
  state is unchanged by the restructure — only *when* the append happens
  moves) — verified, no edits needed to those specific assertions. **One
  existing test in this class goes silently stale, not merely
  "unaffected" — the most severe finding from `/review-plan`
  (2026-08-08, Critical, found independently by `alfred-core-engineer` and
  `alfred-test-engineer`):** `test_gate_is_awaited_before_the_guarded_write_starts`
  (`test_core.py:1173-1196`) asserts, via its docstring, that the accepted
  residual is "a crash between two adjacent awaits" (gate call, then
  immediate append) — under §3.3's restructure the append moves far
  downstream of the gate (past commit), so the residual's real scope changes
  materially, but the test's mechanical `call_order[:2] == ["gate","write"]`
  assertion keeps passing regardless, because `call_order` only ever records
  two labels no matter how much code now runs between them. It will silently
  stop proving the property its own docstring claims. This task must rewrite
  or replace it to pin the new §3.3-described commit-to-deferred-append
  window, not just leave it green.
  New tests needed: the rollback-leaves-no-append test (**assertion contract,
  found during `/review-plan`, `alfred-test-engineer`, confirmed by
  `alfred-security-engineer`, must be stated explicitly or this risks landing
  vacuous**: pre-fix, a mid-turn rollback already raises today — since the
  append is synchronous and inside the gated block — so a test asserting
  only exception-propagation would pass on BOTH the buggy and the fixed
  code, proving nothing; the implementation must force a mid-turn failure
  after gate-apply and assert `working_memory.append` was never invoked,
  spying on the real `WorkingMemory` object, not a convenience stub); the
  happy-path prompt-threading test (§3.2); the forced-commit-failure test
  (§3.3/§3.4); and a prefill-continuation test precise enough to distinguish
  "prompt ends on assistant" from "prompt ends on user" (not just turn counts
  — the existing Task 7 test design can't catch this class of bug). **Also
  in scope for this task, not a separate follow-up:**
  `tests/integration/comms_mcp/test_real_turn_inbound_boundary.py` (found
  during `/review-plan`, `alfred-test-engineer`) — traced the real
  construction path (`_boot_stack` → `_build_comms_boot_graph` →
  `build_orchestrator`, `src/alfred/cli/_bootstrap.py:459`) and confirmed
  Task 5 arms the real ledger there with no opt-out, so
  `test_forwarded_crash_injection_replays_exactly_twice_with_bounded_residual`'s
  current assertion of the pre-fix duplicate-append behavior becomes wrong
  the moment Task 5 lands. PR1's own Task 6 already names this file and
  commits to the flip (see below) — this design doc names it here explicitly
  too so the Task 4/5/6 sequencing dependency (Task 6's flip must not land
  before Task 5 arms the fix, or it asserts against unwired code) is visible
  in one place, not only in the original plan.
- **Task 5** (boot wiring): construction-site change matching Task 1's new
  constructor shape. No behavior change beyond that.
- **Task 6** (crash-injection test flip) and **Task 7** (new working-memory
  regression test): both get *simpler*, not more complex — the exactly-once
  assertion now holds unconditionally rather than needing to special-case the
  same-process-retry path.
- **Task 8** (ADR-0049 amendment): the residual panel needs **two** entries,
  not one. First, the data-loss window: narrower and stronger than originally
  drafted — no gate/write window remains at all; the only named residual is
  "genuine process crash between commit and the deferred in-process append",
  which costs nothing (§3.3) — worth stating plainly rather than hedging.
  Second — **consolidated from three independent `/review-plan` findings
  (2026-08-08: `alfred-memory-engineer`, `alfred-security-engineer` ×2) into
  one entry, not three scattered notes** — the lock-hold-duration trade-off
  (§3.1): a losing concurrent attempt's wait grows from milliseconds to up to
  the full deadline-bounded turn duration, masked today by
  `RealTurnOrchestratorAdapter._turn_locks`; plus the orphaned-lock case
  (crash mid-turn, no DB-side timeout without the `idle_in_transaction_session_timeout`
  fix §3.1 now specifies). Also record the sibling-pattern distinction from
  investigation round 1 (§2.1): `ForwardedDispatchAttemptStore`'s
  independent-commit design is correct for what it guards; the ledger's
  original copy of that pattern was a mis-transfer, not a second instance of
  a shared bug — worth naming so the deviation from the sibling reads as
  deliberate to a future reader, and so PR2's plan (§6) inherits the
  distinction rather than re-discovering it.

## 6. Non-goals

- This design does not touch PR2 (replay journal) or PR3 (tools-on cutover)
  scope. The Act loop's ephemeral `local` transcript (`core.py:776`) is
  entirely separate from `working_memory` and unaffected by any of the above.
  **Heads-up for whoever picks up PR2 next (found during `/review-plan`,
  2026-08-08, `alfred-architect`, confirmed by `alfred-memory-engineer`):**
  `docs/superpowers/plans/2026-08-07-issue-410-pr2-replay-journal.md:435-442`
  cites `PostgresTurnSideEffectLedger` and `PostgresForwardedDispatchAttemptStore`
  together as "same shape" architectural precedent for `PostgresReplayJournal`.
  This design just proved that grouping unsound for the ledger's specific use
  (§2.1's sibling-pattern distinction: `ForwardedDispatchAttemptStore`'s
  independent-commit design is correct for what IT guards — a retry counter,
  not a durability claim — the ledger's copy of that pattern was a
  mis-transfer). Cross-checked: PR2's plan doesn't currently *read* the
  ledger table, only cites it as a pattern to imitate, so there is no live
  impact on PR1 — but `ReplayJournal`'s own durability invariant needs to be
  re-derived from what IT actually guards, not inherited by citing a sibling
  whose independent-commit design turned out to be a mis-transfer once
  already.
- Option C (idempotent episodic write, retiring the ledger table) is recorded
  as a considered-but-deferred alternative, not adopted. Revisiting it is a
  future decision, not part of this fix.
- The Slice-3 Redis swap for `WorkingMemory` (`working.py:7-9`) is out of
  scope here. §3.3 notes that both this design's crash-safety argument and
  the *original* (pre-#410) self-healing argument depend on `WorkingMemory`
  staying in-process and non-durable — whoever lands the Redis swap inherits
  that constraint and should re-derive the safety argument then, under
  either design. This design doesn't make that future problem worse; it just
  doesn't solve it in advance.
- **External readers of `turn_side_effect_ledger` should expect a staleness
  window, not near-instant visibility** (found during `/review-plan`,
  `alfred-security-engineer`, confirmed) — §3.1's row-lock-until-commit
  behavior means a row's `TRUE` state isn't visible to a concurrent reader
  until the whole turn's transaction commits, not at the moment the gate
  itself logically "decides." Not a live concern for PR1 (nothing reads this
  table today; see the PR2 note above for the one plan that will).
