# ADR-0062 — Three-phase turn and role-scoped connection pools

- **Status**: Accepted
- **Date**: 2026-08-08
- **Slice**: #410 PR1 (tools-on prerequisite work)
- **Relates to**: [ADR-0049](0049-real-privileged-turn-comms-inbound.md) (whose
  double-apply residual the turn-side-effect ledger narrows, and whose residual
  panel this ADR amends), issue #410, the design addendum
  `docs/superpowers/specs/2026-08-08-issue-410-pr1-ledger-transactional-fix-design.md`
  (whose §3.1 single-transaction mechanism this ADR supersedes)

## Context

`TurnSideEffectLedger` (the at-most-once gate for the turn's episodic /
working-memory side effects) originally committed its gate on an independent
session, separate from the per-turn transaction that performed the guarded
write — so a mid-turn rollback could strand the gate "applied" with the write
missing forever (permanent user-message loss on replay). The first fix design
(§3.1 of the 2026-08-08 addendum) folded the ledger into ONE per-turn
transaction spanning the whole turn — including the multi-second LLM provider
call. That mechanism is empirically wrong: the (previously unconfigured,
never-justified 15-connection) pool served every turn ONE held connection for
its full duration, while `AuditWriter.append()` demanded a SECOND independent
connection mid-turn for its durability guarantee (CLAUDE.md hard rule #7,
deliberately unchanged). N in-flight turns each holding one connection while
demanding another is hold-and-wait: verified with 16 concurrent turns — 0
succeeded, all timed out at 30 s. The real anti-pattern was never the shared
transaction per se; it was holding a database connection across slow external
I/O.

## Decision

- **The three-phase turn is a standing invariant: no database connection is
  ever held across external I/O.** `Orchestrator` runs Phase A (Observe:
  ledger user-gate + episodic user row, one sub-millisecond transaction),
  Phase B (Orient + Act: prompt construction, the provider call, the tool
  loop, every audit write — ZERO connections held), and Phase C (Persist:
  ledger assistant-gate + episodic assistant row, one sub-millisecond
  transaction). In-process working-memory appends are deferred until after
  their phase's commit; the terminal audit row fires after Phase C's scope
  has closed. The deadline wrapper encloses the whole sequence.
- **The ledger executes in its caller's transaction.** `try_apply_*` methods
  take the phase's `AsyncSession`; the gate and the guarded write commit or
  roll back together. The sibling `ForwardedDispatchAttemptStore` keeps its
  independent-commit design deliberately — it guards a retry counter, not a
  durability claim; the ledger's original copy of that pattern was a
  mis-transfer, not a second instance of a shared design.
- **Connections are acquired under a closed role vocabulary** (`TURN`,
  `SIDE_EFFECT`, `CONTROL`), one cached engine + pool per `(dsn, role)`,
  sized by budget-validated Settings fields
  (`DB_TURN_PLUS_SIDE_POOL_CONNECTION_BUDGET` documents the arithmetic
  against postgres:18's default `max_connections=100`). The acquisition
  hierarchy is enforced for **session-scope-mediated access** — every
  acquisition that flows through `alfred.memory.db.session_scope`, which is
  all TURN and SIDE_EFFECT traffic: while a `TURN` scope is held,
  `SIDE_EFFECT` is the ONLY role permitted to open a nested scope — and only
  because of hard rule #7 (audit durability); it is counted on
  `alfred_db_side_effect_scope_inside_turn_total`. A nested `TURN` or
  `CONTROL` scope raises `NestedTurnConnectionError` (fail loud, never
  wait). **Named exception:** the capability-gate `PostgresBackend` receives
  a CONTROL-role `session_factory` and opens sessions directly, without
  `session_scope` — the guard never sees those acquisitions. This is a
  known, currently-safe gap, not closure: the gate backend is the only
  CONTROL-role consumer reachable from turn handling, gate checks run in
  Phase B (which holds zero TURN connections), and nothing dispatches tools
  from inside Phase A/C. Any change that invokes the gate while a TURN scope
  is held must first route the backend through `session_scope` (or extend
  the guard) — the pool-starved integration tier is the behavioral backstop
  in the meantime. `alfred_db_side_effect_scope_inside_turn_total` is
  expected to read a constant ZERO in this PR: every in-turn audit write
  happens in Phase B (no TURN scope open) or after Phase C's scope closes.
  It is forward provisioning for the #410 PR2 replay journal and PR3
  tools-on writes that WILL acquire SIDE_EFFECT inside a TURN scope — a
  flat zero until those land is correct behavior, not broken
  instrumentation.
- **`idle_in_transaction_session_timeout` is set TIGHT (default 5 s) on the
  TURN and SIDE_EFFECT pools.** Safe only because of the phase split: the
  sole in-transaction work is Phase A/C, bounded by the episodic before-write
  hook chain (`HOOK_CHAIN_DEADLINE_SECONDS` 0.25 s x 2 hookpoints ~= 0.5 s
  worst case; 5 s = 10x). An orphaned crash-abandoned transaction's row locks
  are reclaimed in that window instead of OS TCP-keepalive timescales.
  CONTROL pools carry no idle bound (human-scale CLI/Alembic work). Every
  default-role consumer was audited against the bound at decision time
  (memory subsystem cleared by the memory-engineer cross-check;
  `state/dispatch_loop.py`, `cli/operator_session.py`, and
  `cli/supervisor.py` audited in the #410 PR1 plan revision — all
  back-to-back statement sequences with external I/O outside every scope,
  worst idle gap orders of magnitude under 5 s). The bound is load-bearing:
  a NEW consumer whose transaction can idle near it belongs on `CONTROL`,
  with the move recorded against this ADR.
- **Future DB consumers default to `SIDE_EFFECT`.** The #410 PR2 replay
  journal and any tool-dispatch fan-out state acquire under `SIDE_EFFECT`
  unless an ADR argues otherwise — `TURN` is reserved for the orchestrator's
  two phase transactions, and nothing new may nest inside them.

## Consequences

### Positive

- The 16-turn concurrency deadlock is structurally impossible: no turn holds
  a connection while waiting on the provider, and the audit path draws from
  its own pool.
- The §3.1 design's accepted "lock-hold-duration up to the full turn"
  residual is AVOIDED, not accepted: a losing concurrent attempt's row-lock
  wait is bounded by Phase A/C's sub-millisecond footprint, and an orphaned
  lock by the 5 s idle timeout (both proven by integration tests in
  `tests/integration/test_turn_side_effect_ledger_postgres.py`).
- Every pool size is a named, budget-checked number; the unconfigured "15"
  that caused the deadlock cannot recur silently. This claim was made TRUE
  before being written down: the last three unconfigured `create_engine`
  sites in the codebase (the `alfred supervisor` sync CLI readers) were
  routed onto the explicit CONTROL shape in the same PR, and an AST-level
  guard test (`tests/unit/cli/test_supervisor_control_engine.py`)
  default-denies any future bare `create_engine` call in that module.

### Negative

- **Accepted trade-off: any failure after Phase A's commit and before Phase
  C's commit — a Phase-B failure of any class, or a Phase-C write/commit
  failure — leaves an orphan user episodic row** (no paired assistant row)
  where the pre-split design rolled both back together. Strictly better
  than the alternative this fix exists to prevent (losing the user's
  message entirely): on replay the user gate correctly re-denies, the
  assistant gate allows, and the turn converges. Counted on
  `alfred_orchestrator_orphaned_user_turn_total` so the deliberate
  degradation has a production rate. The one degradation:
  `WorkingMemoryPool` rehydration may prefill ending on a USER turn, giving
  the next turn's prompt two consecutive user messages — degraded context,
  not incorrect, and NOT the prefill-continuation bug (that requires ending
  on an ASSISTANT turn, which the conditional current-message threading
  prevents).
- Two short transactions per turn instead of one — two commits' WAL flushes.
  Negligible against a multi-second provider call.
- **Accepted residuals: two distinct narrow cancellation windows inside
  `session_scope` itself** (pass-2 findings sec-101 / mem-p2-001 — separate
  windows; closing one does not close the other). (1) A second
  `task.cancel()` landing while the scope's own explicit
  `await session.rollback()` is in flight re-raises before the rollback
  completes, leaving connection teardown to `AsyncSession.close()` —
  relied on for that window, not independently proven. (2) A cancellation
  delivered during the ORIGINAL statement's in-flight asyncpg network I/O
  can wedge the connection protocol such that even an ordinary,
  uninterrupted `rollback()` itself raises `asyncpg.InterfaceError` — a
  real, still-open upstream driver/ORM interaction
  (sqlalchemy/sqlalchemy#6592, #8145, #11125, #12099;
  MagicStack/asyncpg#863, #258, #1310; read against the installed
  sqlalchemy 2.0.51 / asyncpg 0.31.0). Neither can strand the ledger gate
  — the transaction never commits, so the server aborts it (at the latest
  when the idle-in-transaction timeout reaps the backend) and a replay
  sees "not applied"; the worst case is one unclean pooled connection,
  bounded by `pool_pre_ping`/`pool_recycle`. Accepted WITHOUT new
  fault-injection infrastructure because the phase split shrinks the
  at-risk window to Phase A/C's sub-millisecond transactions — the
  pre-#410 design exposed the whole multi-second provider call to the
  same class of window.
- The nesting guard is per-task (`contextvars`); code that smuggles a scope
  across tasks defeats it. The pool-starved integration tier
  (`integration_pool_kwargs`) is the behavioral backstop.

## Alternatives considered

- **Keep the single per-turn transaction, grow the pool.** Rejected: sizing
  cannot fix hold-and-wait, only move the deadlock threshold; connections
  held across multi-second external I/O also pin server resources per
  in-flight turn.
- **Weaken `AuditWriter` to reuse the turn connection.** Rejected without
  discussion: CLAUDE.md hard rule #7 — audit rows must survive caller
  rollback.
- **Option C (idempotent episodic write, retiring the ledger).** Still
  deferred, unchanged from the design addendum §4.

## References

- Design addendum: `docs/superpowers/specs/2026-08-08-issue-410-pr1-ledger-transactional-fix-design.md`
  (§3.1 superseded by this ADR; §3.2 carried forward as gate-keyed
  conditional threading; §3.3/§3.4 carried forward as per-phase deferred
  appends + `commit_failed` telemetry)
- Plan: `docs/superpowers/plans/2026-08-08-issue-410-pr1-pool-deadlock-fix.md`
- Proof tests:
  `tests/integration/orchestrator/test_turn_pool_no_hold_across_provider.py`,
  `tests/integration/test_turn_side_effect_ledger_postgres.py`
