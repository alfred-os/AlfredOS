# 0011 — Per-user BudgetGuard (dict-keyed counter; `_spent`/`_day` never evict)

- **Status**: Accepted
- **Date**: 2026-05-27
- **Slice**: 2 — `docs/superpowers/plans/2026-05-26-slice-2-pr-B-budget-memory-orchestrator.md`
- **Supersedes**: —
- **Superseded by**: —

## Context

Slice 1 shipped a single-process, single-user `BudgetGuard` keyed on one
global `daily_usd` cap. The TUI's only caller was the operator, so a global
counter and a global cap were the same thing.

Slice 2 introduces multi-user Discord. The same orchestrator now serves
multiple authenticated users through one process. Three concrete problems
follow:

1. **Availability attack.** A single chatty (or hostile) user can exhaust
   the household's daily budget cap, denying every other user service for
   the rest of the UTC day. PRD §7.2 names per-user isolation as a
   non-negotiable invariant of the multi-user identity model.
2. **Cross-process cache invalidation.** `alfred-discord` and `alfred-core`
   are separate processes; the CLI mutates `users.daily_budget_usd` from a
   third. The Slice-1 global guard was process-internal; multi-process
   wiring needs an invalidation primitive.
3. **Eviction is a security hazard.** Any LRU policy that drops a user's
   running `_spent` recovers the full daily cap on the next request. An
   attacker who can sustain enough traffic to evict their own row resets
   themselves; in the limit, the cap stops working.

## Decision

Reshape `BudgetGuard` around a per-user store keyed on canonical `user_id`
(see [glossary: canonical user_id](../glossary.md#canonical-user-id)):

```python
self._user_budgets: dict[str, _UserBudget] = {}
```

Each entry holds `daily_usd`, `daily_usd_version`, `per_call_max_usd`,
`day` (UTC), and `spent`. Four interlocking invariants make the design
defensible:

1. **Per-call cap stays global.** Set once at constructor time. A
   user-specific per-call cap would let an attacker (or the operator
   themselves, accidentally) configure an unbounded per-call value via
   `alfred user add --per-call-max-usd inf`, pre-disabling the cap for
   that user. The cap is process-wide and finite — `BudgetGuard.__init__`
   refuses NaN, infinity, and negative values at construction.
2. **`_spent` and `day` are security-invariant source-of-truth and NEVER
   evict** under any in-process logic. The only legitimate way for a row
   to leave the store is the explicit
   `BudgetGuard.evict(user_id)` escape hatch called by
   `IdentityResolver.remove` on soft-delete. A chatty user's running spend
   does NOT reset because the dict happened to be touched.
3. **Only `daily_usd` is cache-able.** When the
   [`IdentityVersionCounter`](../glossary.md#identityversioncounter) bumps,
   the next `_load_or_get_user` refreshes `daily_usd` from the loader
   without touching `spent` or `day`. Cap changes propagate cross-process
   in ≤60 seconds (TTL backstop) and immediately on healthy Postgres
   `LISTEN/NOTIFY`, per [ADR-0010](0010-canonical-user-id-and-listen-notify.md).
4. **NaN / infinity / negative are rejected at every entry point.**
   `cost_usd` is validated before any mutation. `daily_budget_usd` loaded
   from the DB is re-validated in process: the DB CHECK
   `daily_budget_usd > 0` is the primary defence, and the in-process
   gate is defence-in-depth (SQLite, the unit-test backend, accepts NaN
   and +∞ through its CHECK).

`UnknownBudgetUserError(BudgetError)` is raised when the loader returns
`None` for a `user_id`. This is a defence-in-depth case — the resolver
should reject unknown ids first — but a caller that bypasses the resolver
(a programming error) surfaces loudly with the exact remediation command
(`alfred user add`) rather than silently no-op'ing a charge against a
phantom guard.

## Implementation reference

- `src/alfred/budget/guard.py` — full implementation. Module docstring
  enumerates the invariants verbatim.
- `tests/unit/budget/test_guard.py` — branch coverage of every per-user
  surface, including the NaN/∞ rejection paths on both `cost_usd` and
  the loader's `daily_budget_usd`.
- `tests/integration/budget/test_per_user_isolation.py` — proves Alice's
  charges do not move Bob's row across a real `IdentityVersionCounter`
  bump.

The constructor signature changed from
`BudgetGuard(daily_usd=, per_call_max_usd=)` to
`BudgetGuard(*, user_loader, per_call_max_usd, version_counter)`. Call
sites were updated in the same commit; there is no compatibility shim.

## Alternatives considered

- **Global cap with per-user accounting.** Trivially bypassable: any user
  can exhaust the global cap. No isolation. Rejected.
- **Per-user cap with periodic LRU eviction of inactive users' counters.**
  Re-acquires the full daily cap on cache miss — a security regression
  disguised as a memory optimisation. Rejected. The store cannot evict
  spend under any policy; the only legitimate eviction is operator-driven
  via `IdentityResolver.remove`.
- **Redis-backed shared counter.** Solves both the in-memory eviction
  question (Redis can hold state across restarts) and the cross-process
  invalidation question (Redis is the synchronisation point). Rejected
  for Slice 2 — it adds a new datastore in a slice already large enough.
  Deferred to Slice 5 when Redis joins the stack for the prompt cache.
  When that lands, this ADR will be revisited and likely superseded.

## Consequences

**Positive:**

- Per-user isolation. Alice's spend cannot impact Bob's available budget.
- The contract `BudgetGuard` exposes is type-clean for Slice 3+ work:
  trust-tier graduation and the dual-LLM split can layer on this without
  a budget refactor.
- Day-rollover is per-entry. Alice's running spend does not reset because
  Bob happened to charge first thing in the morning.

**Negative:**

- In-process state means an `alfred-discord` restart resets the in-memory
  `_spent` for the current UTC day. The `audit_log` is the durable
  source-of-truth — Slice 4 hydrates `_spent` from `SELECT
  SUM(cost_usd) FROM audit_log WHERE day = today` at startup so a
  restart no longer hands a fresh daily cap to every user. Documented as
  a Slice-2 risk because the daily window already accepts ~one reset/day
  per restart in single-operator deployments; multi-user deployments
  should keep `alfred-discord` running.
- The dict grows monotonically across a process lifetime. Each entry is
  ~100 bytes; even at 10⁵ users (orders of magnitude beyond AlfredOS's
  household-scale target) the footprint is ~10 MB. The growth rate is
  bounded by `alfred user add` invocations.

## References

- PRD §7.2 — multi-user identity + per-user partitioning.
- [ADR-0008](0008-llm-output-trust-tier.md) — slice-1 global budget.
- [ADR-0010](0010-canonical-user-id-and-listen-notify.md) —
  `IdentityVersionCounter` and the cross-process invalidation contract
  this guard subscribes to.
- [Glossary: canonical user_id](../glossary.md#canonical-user-id),
  [authorization role](../glossary.md#authorization-role),
  [IdentityVersionCounter](../glossary.md#identityversioncounter).
- [`docs/subsystems/identity.md`](../subsystems/identity.md) — full
  identity subsystem deep-doc; cross-process invalidation contract.
