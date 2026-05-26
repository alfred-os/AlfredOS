# 0011 — Per-user BudgetGuard (dict-keyed counter; `_spent`/`_day` never evict)

- **Status**: Accepted
- **Date**: 2026-05-27
- **Slice**: 2 — `docs/superpowers/plans/2026-05-26-slice-2-pr-A-identity.md`
- **Supersedes**: —
- **Superseded by**: —

## Decision (summary)

Slice 2 makes `BudgetGuard` per-user (`dict[str, _UserBudget]` keyed on canonical slug; per-call cap stays global; `_spent`/`_day` are the security-invariant source of truth and are NEVER evicted; only `daily_usd` cap is cache-able and refreshes on `IdentityVersionCounter` bump).

## Author

Full body lands in PR E. Placeholder reserves the ADR number so PR B's body can cite it without a forward-dangling reference.
