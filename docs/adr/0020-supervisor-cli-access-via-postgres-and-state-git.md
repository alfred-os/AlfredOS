# ADR-0020 — Supervisor CLI access: status via Postgres now, reset deferred

**Date:** 2026-06-05
**Status:** Accepted (revised after implementation discovery)
**Closes:** [#154](https://github.com/alfred-os/AlfredOS/issues/154) (status path only)
**Defers:** Reset path → [#171](https://github.com/alfred-os/AlfredOS/issues/171)
**Related:** [#149](https://github.com/alfred-os/AlfredOS/pull/149) (PR-S3-6 surfaced the gap), [ADR-0018](./0018-state-git-proposal-writer-consolidation.md) (state.git proposal writer)

## Context

CR-149 round-9 surfaced that the CLI's `alfred supervisor status` and `alfred supervisor reset` commands cannot reach the running supervisor process. The CLI is synchronous (Typer), the supervisor is async, and they live in different OS processes. The placeholder `_get_supervisor()` at `src/alfred/cli/supervisor.py:164` raises `RuntimeError("Supervisor.get_instance not yet available; wired in PR-S3-3b")`, so the operator surface is non-functional in production.

Three architectural paths were considered (issue body details):

1. **Process-level singleton.** Rejected — singleton lives in daemon process, not CLI process; `get_instance()` from CLI always returns `None`.
2. **IPC.** Rejected — heavyweight; inconsistent with AlfredOS's proposal-flow + state.git pattern; parallel operator-access surface needing its own auth model.
3. **Read-only path** — Postgres for status; state.git proposal for reset. Initial accept.

## Implementation discovery — premise invalidated

The initial accept of Option 3 with full reset support assumed "the supervisor's existing proposal-pickup cycle calls `Supervisor.reset_breaker(...)`". Implementation discovery (#154 first-attempt agent) found this **does not exist**:

- `grep -rn "state.git\|state_git\|proposal" src/alfred/supervisor/` → zero matches. The supervisor never touches state.git.
- The closest precedent is `RealGate.rebuild_from_state_git` + `_apply_grants` — a **declarative projection rebuild** (read `policies/grants/<id>.json` blobs; upsert into Postgres `plugin_grants`). NOT a dispatch table. NOT a side-effect handler.
- `WebAllowlistProposal` and `ConfigSetProposal` are **half-shipped**: CLI writes proposals, reviewer can merge, but `grep -rn "WebAllowlistProposal" src/alfred/` reveals zero runtime consumers reading merged branches back into effect.

There is no infrastructure for "on merged proposal branch, run handler X" — and a circuit-breaker reset is precisely a one-shot side-effect command, not a declarative state snapshot.

## Decision (revised)

**Ship the status path via Postgres now. Defer the reset path to [#171](https://github.com/alfred-os/AlfredOS/issues/171), which scopes the missing dispatch infrastructure.**

- **`alfred supervisor status`** uses a synchronous SQLAlchemy session to read the `circuit_breakers` Postgres table (migration 0010; populated by `CircuitBreaker.save_to_db` at `src/alfred/supervisor/breaker.py`). No supervisor handle. No new infrastructure.

- **`alfred supervisor reset`** continues to return a localised "not yet wired" hint, but the hint now points operators at #171 (clear forward path) instead of the obsolete PR-S3-3b reference. The `--confirm` flag still gates intent; the forensic-attempt audit row still emits per CR-149's pattern. The hint copy is updated to name the actual architectural blocker: "Merged-proposal-branch dispatch infrastructure not yet shipped — tracked at #171."

- **`_get_supervisor()` is removed.** Neither command needs a supervisor handle: status reads Postgres; reset emits an attempt-row + a hint and exits non-zero. The PR-S3-3b dependency the function was waiting on never needs to ship.

## Consequences

### Positive

- **Closes the higher-frequency operator pain.** Status during incident response is the canonical use case; reset is rarer and benefits from doing it right.
- **No new infrastructure.** Just removes a broken placeholder and wires the Postgres read.
- **No "half-baked" risk.** Refuses to perpetuate the `WebAllowlistProposal` / `ConfigSetProposal` half-shipped pattern by adding a third half-shipped proposal type.
- **Forward path is clear.** #171 owns the dispatch infrastructure question; the reset hint copy points operators there explicitly.
- **PR-S3-3b dependency drops** in any case.

### Negative

- **Reset stays non-functional.** Operators wanting to clear a tripped breaker mid-incident must either restart the supervisor (which `CircuitBreaker.load_from_db` honours per spec §10.6 — the breaker stays OPEN within the configured window) or manually intervene in Postgres (`UPDATE circuit_breakers SET state='CLOSED' WHERE component_id=...`). Runbook documents both workarounds + the #171 tracking link.

- **Two CLI commands with materially different shipping states.** Status works; reset returns a hint. The CLI surface is asymmetric until #171 lands.

- **Status data freshness contract.** Status reflects "circuit-breaker state as of the supervisor's last `save_to_db`". Typically lags by ≤1 supervisor cycle. Runbook documents this; identical staleness model to `alfred audit log` reading the audit Postgres projection.

### Out of scope (explicitly deferred)

- **Full reset path via state.git proposal.** Tracked at [#171](https://github.com/alfred-os/AlfredOS/issues/171). That issue scopes the merged-proposal-branch dispatch infrastructure + replay ledger + supervisor poll loop, then `BreakerResetProposal` lands as the first user of the registry.

- **`WebAllowlistProposal` and `ConfigSetProposal` runtime consumers** (the same half-shipped gap). Also closed by #171's infrastructure.

- **Authenticated CLI session for `operator_user_id`** — tracked at #153.

- **Real-time push notifications.** Operator polls `alfred supervisor status`.

## Alternatives considered (post-discovery)

### A1 — Implement the dispatch infrastructure in this PR (Option A in the redo)

Land breaker-resets as `policies/breaker-resets/<id>.json` blobs, add a parser, add a `processed_breaker_resets` Postgres ledger, add a supervisor-side polling loop. Rejected — this is material infrastructure that sets precedent for future side-effecting proposals (including the half-shipped `WebAllowlistProposal` / `ConfigSetProposal` consumers). Doing it inside #154's scope conflates "make the CLI surface work" with "design the side-effect-proposal architecture." The architectural piece deserves its own ADR + PR; #171 owns it.

### A2 — Postgres queue table + merge hook (Option B in the redo, A3 in the original ADR)

A `supervisor.requests` Postgres queue row written by the reviewer-gate merge action; supervisor drains it. Originally rejected on consistency grounds (bypasses state.git for the EFFECT). The discovery weakened the consistency argument (state.git pickup doesn't exist anywhere today) but introduces a new problem: the merge action is GitHub's, not AlfredOS's — wiring "on merge, write to Postgres" still needs new infrastructure (a GitHub Action, a polling loop, or a webhook). At similar weight to A1 without the architectural-consistency benefit. Rejected.

### A3 — Block #154 entirely on a precursor PR (Option C in the redo)

Ship the dispatch + ledger + polling-loop infrastructure first; then #154 lands as thin handler registration. Slowest but architecturally cleanest. Rejected because the status path is independently shippable today and operators benefit from it during the gap. #171's lead time becomes operator-pain time only for the reset path, not the status path.

### Original A1-A4 (singleton, IPC, direct-Postgres, auto-approve)

All rejected for their original reasons. The discovery doesn't change those rejections.

## Migration / amendment notes

- The original ADR-0020 named "the supervisor's existing proposal-pickup cycle" as the reset path's substrate. That cycle does not exist. The amendment defers the reset path to #171 and explicitly documents the gap.
- Runbook + subsystem doc + glossary updates reflect the revised scope.
- The implementation plan's Tasks 4-7 (BreakerResetProposal payload, supervisor proposal pickup handler, integration round-trip, adversarial proposal-pickup) are deleted; the plan now contains a status-only Task 4 that updates the reset command's hint copy to point at #171.
