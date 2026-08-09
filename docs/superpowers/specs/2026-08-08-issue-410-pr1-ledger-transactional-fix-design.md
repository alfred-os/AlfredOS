# #410 PR1 — Ledger/episodic transactional-coupling fix — Design

> **Status:** approved by requester, 2026-08-08. Supersedes the session-ownership
> design in `TurnSideEffectLedger`'s Task 1 implementation and Task 4's wiring as
> already committed on the `410-pr1-turn-side-effect-ledger` worktree branch
> (commits through `fa13d3e8`). This is an addendum discovered during Task 4's
> code review, not a revision to the original
> `2026-08-07-issue-410-tools-on-design.md` spec (that document is unaffected —
> this fix is internal to PR1's own implementation, not a scope change to the
> #410 epic).

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
directly:

```python
outcome: _TurnOutcome | None = None
async with self._session_scope() as session:
    try:
        outcome = await self._deadline_wrapper.run(self._handle_turn, session, ...)
    except TimeoutError: ...      # existing rollback arms, unchanged, all re-raise
# commit has happened here — session_scope.__aexit__ ran session.commit()
for role, text in outcome.working_memory_appends:
    await working_memory.append(role=role, content=text)
return outcome.reply
```

`_TurnOutcome` is a frozen dataclass (`reply: str`,
`working_memory_appends: tuple[tuple[Role, str], ...]`). `DeadlineWrapper.run`
is already generic (`deadline.py:70`) and types through unchanged. No test
calls `_handle_turn` directly — every test goes through
`handle_user_message` — so this is an internal signature change with no
external contract impact.

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
zero. (Verified: cancellation between commit and append is not reachable
today — there is no suspension point between `__aexit__` returning and the
deferred-append loop running; `WorkingMemory.append`'s lock acquisition is
uncontended under the per-key turn mutex and returns without awaiting on
CPython 3.14.6's fast path.) Commit failure itself is naturally fail-closed
under this design — the exception propagates from the `async with` statement,
the post-block loop never runs, no append happens — a property the current
(pre-fix) design does not have.

### 3.4 Bonus fix, free with this restructure

`record_action_duration(action_outcome="success")` (`core.py:462-467`)
currently fires *before* the transaction's commit. A commit failure today
would record a spurious "success" observation. Moving the success
observation to after the `async with` block (a natural consequence of moving
`return` out of the block per §3.3) fixes this for free. Verify
`tests/unit/orchestrator/test_core.py:1020`
(`action_outcome == "success"` assertion) still passes — it inspects kwargs
only, so it should be unaffected by the timing move.

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
  the opposite of this design and is the direct cause of the bug.
- **Task 3** (Postgres integration test): signature change only: the
  concurrent-race test's "exactly one winner" property is preserved per §3.1,
  restructured to model 8 concurrent transactions rather than 8 independent
  sessions. A **new** integration test is required and does not exist today:
  a transaction that rolls back after the gate must leave the gate unset —
  nothing currently pins this, and it's the direct regression test for the
  bug this design fixes.
- **Task 4** (already implemented as committed, `0a75f1ba`..`fa13d3e8` on this
  worktree branch — needs revision, not a fresh implementation): the
  `_TurnOutcome` restructure, the deferred-append loop, and the
  prompt-construction fix (§3.2) all land here. `TestTurnSideEffectLedgerGating`'s
  existing assertions on final working-memory contents are unaffected (final
  state is unchanged by the restructure — only *when* the append happens
  moves) — verified, no edits needed to those specific assertions. New tests
  needed: the rollback-leaves-no-append test, the happy-path
  prompt-threading test, and a prefill-continuation test precise enough to
  distinguish "prompt ends on assistant" from "prompt ends on user" (not just
  turn counts — the existing Task 7 test design can't catch this class of
  bug).
- **Task 5** (boot wiring): construction-site change matching Task 1's new
  constructor shape. No behavior change beyond that.
- **Task 6** (crash-injection test flip) and **Task 7** (new working-memory
  regression test): both get *simpler*, not more complex — the exactly-once
  assertion now holds unconditionally rather than needing to special-case the
  same-process-retry path.
- **Task 8** (ADR-0049 amendment): the residual panel's new entry is
  narrower and stronger than originally drafted — no gate/write window
  remains at all; the only named residual is "genuine process crash between
  commit and the deferred in-process append", which costs nothing (§3.3) —
  worth stating plainly rather than hedging. Also record the sibling-pattern
  distinction from investigation round 1 (§2.1): `ForwardedDispatchAttemptStore`'s
  independent-commit design is correct for what it guards; the ledger's
  original copy of that pattern was a mis-transfer, not a second instance of
  a shared bug — worth naming so the deviation from the sibling reads as
  deliberate to a future reader.

## 6. Non-goals

- This design does not touch PR2 (replay journal) or PR3 (tools-on cutover)
  scope. The Act loop's ephemeral `local` transcript (`core.py:776`) is
  entirely separate from `working_memory` and unaffected by any of the above.
- Option C (idempotent episodic write, retiring the ledger table) is recorded
  as a considered-but-deferred alternative, not adopted. Revisiting it is a
  future decision, not part of this fix.
- The Slice-3 Redis swap for `WorkingMemory` (`working.py:6-8`) is out of
  scope here. §3.3 notes that both this design's crash-safety argument and
  the *original* (pre-#410) self-healing argument depend on `WorkingMemory`
  staying in-process and non-durable — whoever lands the Redis swap inherits
  that constraint and should re-derive the safety argument then, under
  either design. This design doesn't make that future problem worse; it just
  doesn't solve it in advance.
