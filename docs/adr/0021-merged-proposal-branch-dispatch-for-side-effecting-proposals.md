# ADR-0021 — Merged-proposal-branch dispatch for side-effecting proposals

**Date:** 2026-06-05
**Status:** Accepted
**Closes:** [#171](https://github.com/alfred-os/AlfredOS/issues/171) (the infrastructure); enables [#154 reset path](https://github.com/alfred-os/AlfredOS/issues/154) and the half-shipped `WebAllowlistProposal` / `ConfigSetProposal` runtime consumers
**Related:** [ADR-0018](./0018-state-git-proposal-writer-consolidation.md) (state.git proposal writer), [ADR-0020](./0020-supervisor-cli-access-via-postgres-and-state-git.md) (discovery that drove #171)

## Context

AlfredOS has two architectural patterns for "operator action affects runtime":

1. **Declarative projection** — `PluginGrantProposal` / `PluginRevokeProposal` write `policies/grants/<plugin_id>/<grant_id>.json` blobs. `RealGate.rebuild_from_state_git` reads the tree on cycle and projects the current state into Postgres `plugin_grants`. Each rebuild is a complete state snapshot.

2. **Side-effecting commands** — `BreakerResetProposal` (deferred from #154) wants "do this one-shot action when the operator's request is approved". The action is not declarative — it's an event. ADR-0020 §Discovery surfaced that no infrastructure exists for this pattern; `WebAllowlistProposal` and `ConfigSetProposal` are half-shipped as evidence.

The two patterns have materially different semantics:

- Declarative is **replayable** — re-running the projection produces the same Postgres state. The gate's rebuild can run on every cycle without harm.
- Side-effecting requires **replay-safe re-application** of side-effects. Concretely, the framework provides at-least-once dispatch with an idempotent-handler contract — handlers MUST be idempotent; the framework guarantees a re-applied effect produces no observable change. See §Atomicity model below for the recovery story.

This ADR establishes the dispatch infrastructure for the side-effecting pattern. The declarative pattern (gate's `rebuild_from_state_git`) is unchanged.

## Threat model

**Trust assumption.** The trust boundary is the conjunction of two controls: (1) filesystem ownership of `/var/lib/alfred/state.git` (only the operator's OS account can write to it), and (2) Git branch-protection on `main` in that repository (merges require a reviewer-gate pass — the PR-style review of the proposal branch). A blob present on `main` in state.git is treated as an approved operator instruction.

**Commit-author not verified.** The dispatch loop does not verify git commit author signatures, nor does it cross-reference `operator_user_id` (read from the blob payload) against the merge committer's identity. This is an explicit assumption: AlfredOS Slice 1–3 targets single-operator self-host deployments where the operator IS the merger.

**`operator_user_id` is self-claimed.** It is a forensic breadcrumb written by the CLI at proposal-write time, not an authentication artifact. It is useful for audit queries ("which operator submitted this?") but is repudiable. The `commit_sha` column (the merge-commit SHA from `git log`) is the non-repudiable forensic key — it binds the action to the git object, not to the blob's claim.

**Multi-operator deployments.** Future hardening for multi-operator or multi-host AlfredOS deployments — commit-signature verification, cross-referencing `operator_user_id` against committer email, enforcing per-user branch scopes — is tracked as a separate ADR. The current model is explicitly insufficient for that deployment shape.

## Decision

### Scope: side-effects only

`RealGate.rebuild_from_state_git` continues to handle declarative projection. The new dispatch infrastructure handles side-effecting proposals exclusively. A clean separation by semantic, not subsystem.

- `PluginGrantProposal`, `PluginRevokeProposal`, `WebAllowlistProposal`, `ConfigSetProposal` stay declarative — their effect is the projected Postgres state.
- `BreakerResetProposal` (and future side-effecting proposals) flow through the new infrastructure.

The existing half-shipped state of `WebAllowlistProposal` / `ConfigSetProposal` runtime consumers is addressed by giving each a declarative projection (separate work, tracked at follow-ups #172/#173 once this lands).

### Loop home: supervisor sub-loop

A new `_proposal_dispatch_loop` lives at `src/alfred/supervisor/core.py`, sibling to the existing `_capability_heartbeat_loop`. Reuses the supervisor's existing `TaskGroup`, lifecycle hooks, audit-writer, and shutdown discipline. The supervisor owns long-lived runtime loops by convention; this is the canonical home.

Alternative considered + rejected: separate `src/alfred/state/dispatcher.py` subsystem. Premature — dispatch volume is operator-action-cadence (handful per day at most). New subsystem cost (bootstrap wiring, health checks, additional state-corruption surface) not justified at current scale. Promote later if needed.

### Ledger: single `processed_proposals` Postgres table

Schema:

```python
class ProcessedProposal(Base):
    __tablename__ = "processed_proposals"

    # Composite primary key — discriminator + ID uniquely identifies a proposal.
    proposal_type: Mapped[str] = mapped_column(String(64), primary_key=True)
    proposal_id: Mapped[str] = mapped_column(String(64), primary_key=True)

    # Forensic + replay-safety metadata.
    blob_sha: Mapped[str] = mapped_column(String(40), nullable=False)
    commit_sha: Mapped[str] = mapped_column(String(40), nullable=False)  # merge-commit SHA, not blob SHA
    processed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    result: Mapped[str] = mapped_column(String(32), nullable=False)  # closed vocab
    handler_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    failure_kind: Mapped[str | None] = mapped_column(String(48), nullable=True)   # closed vocab
    failure_detail: Mapped[str | None] = mapped_column(String(512), nullable=True)  # DLP-redacted
    operator_user_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
```

`failure_reason` is replaced by two columns: `failure_kind` (closed vocab: `"handler_returned_failed"`, `"handler_uncaught_exception"`, `"payload_validation"`, `"unknown_proposal_type"`, `"blob_not_found"`, `"handler_timeout"`, enforced by `ck_processed_proposals_failure_kind` in addition to the dispatcher's `Literal`-narrowed call sites) and `failure_detail` (bounded to 512 chars; truncated only — DLP wiring is tracked at [#173](https://github.com/alfred-os/AlfredOS/issues/173)). Today's emit sites pass closed-vocab strings (`type(exc).__name__`, handler-returned reasons) so the realised leak surface is small; #173 wires `OutboundDlp.scan` at this boundary to close the surface for future emit sites. `commit_sha` records the dispatch-cycle HEAD captured at the HEAD-diff walk (the head that brought the blob into `main`) — the non-repudiable join key for forensic queries.

Closed vocab for `result`: `"applied"`, `"failed_handler"`, `"failed_parse"`, `"failed_unknown_type"`, `"skipped_already_processed"`.

Single table chosen over per-type tables because cross-type forensic queries ("show all proposals processed in the last hour") + audit-graph generation prefer single-source.

### Sentinel: nullable bootstrap, NULL-detecting first cycle

The `processed_proposals_head` sentinel table's `head_sha` column is `Mapped[str | None]` — nullable. The Alembic migration inserts the sentinel row with `head_sha = NULL`. On its first cycle the dispatch loop detects `NULL` and writes `git rev-parse origin/main` as the bootstrap value (forward-from-now semantics — blobs committed before bootstrap are not reprocessed). This avoids the unreliable subprocess-at-migration-time pattern.

## Architecture

### Detection: HEAD-diff walk

Each cycle:

1. Read `last_processed_head` from the sentinel `processed_proposals_head` table. If `NULL`, bootstrap: write `git rev-parse origin/main` as the new sentinel value, then proceed (nothing to diff on the bootstrap cycle).
2. `git diff <last_head>..origin/main --name-only --diff-filter=A` (added files only) restricted to `policies/<type>/...` paths owned by registered side-effecting proposal types.
3. For each new blob path, derive `(proposal_type, proposal_id)` from the path convention `policies/<type>/<id>.json`. (Side-effecting types live under their own subtree; declarative types' paths are ignored.)
4. Look up `(proposal_type, proposal_id)` in `processed_proposals`. If present, skip (replay safety).
5. Dispatch via the registry; record result in `processed_proposals`; update `last_processed_head`.

All git commands run via `asyncio.to_thread(subprocess.run, ...)` — not bare `subprocess.run` — to avoid blocking the supervisor's event loop. Precedent: `src/alfred/security/capability_gate/_gate.py:284`.

Choosing HEAD-diff over periodic full-tree-rescan: O(diff) per cycle vs O(blobs) — important when the policies/ tree grows.

### Handler registry

```python
DispatchOutcome = ...  # see dispatch_registry.py

ProposalHandler = Callable[[StateGitProposalPayload, ProposalContext], Awaitable[DispatchOutcome]]

PROPOSAL_HANDLERS: Final[Mapping[str, ProposalHandler]] = {
    "breaker-reset": _handle_breaker_reset,
    # Future side-effecting types register here.
}
```

Each handler:

- Receives the parsed typed payload (Pydantic v2 instance) + a `ProposalContext` (audit_writer, effects interface, structured logger).
- Performs the side effect.
- Returns `DispatchOutcome.applied()` or `DispatchOutcome.failed(reason)`.
- Raises only on framework-internal bugs (handlers MUST NOT raise on operator-caused failures; those are `DispatchOutcome.failed`).

The dispatcher verifies that the parsed payload's `proposal_type` ClassVar matches the path-derived type before calling the handler. Mismatch → audit row `state.proposal.dispatch_failed` + ledger entry `failure_kind="payload_validation"` + skip. This closes a type-confusion vector where a blob's JSON content claims a different type than its path.

The framework wraps the handler call in `try/except Exception` for safety, recording uncaught exceptions as `result="failed_handler"`, `failure_kind="handler_uncaught_exception"` with a DLP-redacted excerpt in `failure_detail`.

### `ProposalContext` and capability narrowing

`ProposalContext` threads framework-level dependencies into handlers without globals:

```python
@dataclass(frozen=True, slots=True)
class ProposalContext:
    audit_writer: AuditWriter
    effects: ProposalEffects   # Protocol: reset_breaker(component_id, operator_user_id) only
    logger: structlog.BoundLogger
```

`effects: ProposalEffects` is a Protocol that exposes only the methods handlers are allowed to call — currently `reset_breaker`. This is narrower than passing the full `Supervisor` instance; handlers cannot reach unrelated supervisor internals. The `Supervisor` implementation satisfies `ProposalEffects` structurally.

### Audit attribution

Two new closed-vocab audit events:

- `state.proposal.processed` — emitted on every dispatched proposal (success or handler failure). Carries `proposal_type`, `proposal_id`, `result`, `failure_kind` (if failure), `handler_version`, `processed_at`, `operator_user_id`, `commit_sha`.
- `state.proposal.dispatch_failed` — emitted on framework-level failures (unknown type, parse failure, ledger write failure). Carries the same fields plus `framework_error_kind`.
- `state.proposal.dispatch_cycle_skipped` — emitted when an entire cycle is skipped due to infrastructure failure (Postgres unreachable, git command failure). Carries `skip_reason`. No silent skips.

The field sets for all three events are declared as `frozenset` constants in `src/alfred/audit/audit_row_schemas.py` (the existing pattern for `QUARANTINE_EXTRACT_FIELDS`, etc.) — not in a separate `event_vocabulary.py` file (which does not exist). Event names are passed as the `event=` kwarg to `AuditWriter.append_schema`.

The proposal blob's content already carries `operator_user_id` (the CLI writer puts it there per ADR-0018). The dispatch framework reads it for attribution; no new wire-protocol change.

### First user: `BreakerResetProposal` handler

This PR ships:

1. The dispatch infrastructure (loop, registry, ledger).
2. `BreakerResetProposal` payload type at `src/alfred/state/proposal_payloads.py` (deferred from #154). On-disk path: `policies/breaker-resets/<proposal_id>.json`. The writer's `_on_disk_files_for` at `src/alfred/cli/_state_git.py:968+` currently dispatches on `proposal_type` only for `PluginGrantProposal`. This PR adds an explicit branch for `BreakerResetProposal` → `policies/breaker-resets/<proposal_id>.json`.
3. `_handle_breaker_reset` handler that calls `ctx.effects.reset_breaker(component_id, operator_user_id)`.
4. CLI rewire at `src/alfred/cli/supervisor.py`: `alfred supervisor reset --confirm` now writes a `BreakerResetProposal` instead of emitting the deferred hint. The `--confirm` gate is reinstated as a real gate (not a no-op) because reset now performs actual state mutation; this partially reverts #154's BLOCKER #6 no-op. The hint catalog key is tombstoned.

This closes #154's reset path inside the same PR — proves the infrastructure works end-to-end and gives operators the functional command.

### Failure handling

| Failure mode | Disposition | Audit emission |
|---|---|---|
| Unknown `proposal_type` (no handler registered) | Ledger `result="failed_unknown_type"`, `failure_kind="unknown_proposal_type"` | `state.proposal.dispatch_failed` |
| Payload parse failure (Pydantic ValidationError) | Ledger `result="failed_parse"`, `failure_kind="payload_validation"` | `state.proposal.dispatch_failed` |
| Path/body `proposal_type` mismatch | Ledger `result="failed_parse"`, `failure_kind="payload_validation"` | `state.proposal.dispatch_failed` |
| Handler raises uncaught | Ledger `result="failed_handler"`, `failure_kind="handler_uncaught_exception"`, DLP-redacted `failure_detail` | `state.proposal.dispatch_failed` |
| Handler returns `DispatchOutcome.failed(reason)` | Ledger `result="failed_handler"`, `failure_kind="handler_returned_failed"`, `failure_detail` from reason (DLP-redacted) | `state.proposal.processed` |
| Postgres unreachable mid-cycle | Log WARNING, emit `state.proposal.dispatch_cycle_skipped` audit row, skip cycle. Next cycle retries from same sentinel HEAD. | `state.proposal.dispatch_cycle_skipped` |
| State.git unreachable / git command failure | Same as Postgres unreachable — log WARNING + audit row + skip. | `state.proposal.dispatch_cycle_skipped` |

No silent skips. Every cycle that is aborted emits an audit row.

Failed proposals stay in the ledger; a CLI retry command is a follow-up. Operators can investigate via `alfred supervisor proposals --recent` (see §Operator visibility) or direct psql query.

### Atomicity model

The shipped guarantee is **at-least-once delivery with an idempotent-handler contract**. The framework's two transactional boundaries are still distinct, but the recovery story does not depend on bundling the handler side-effect into the framework's ledger commit — it depends on handler idempotency. Restated:

1. **Handler invocation** is the handler's own transactional concern. The handler picks its own session scope (`Supervisor.reset_breaker` opens a `_session_scope()` and commits the `circuit_breakers` UPDATE inside that scope). The framework awaits the handler's return value as the signal that the side-effect landed.
2. **Ledger insert** is the framework's transactional concern (`ProcessedProposal` row inside a framework-owned `_session_scope`).
3. **Sentinel bump** is a separate framework transaction at the end of the cycle, after all blobs in the diff have been processed.

**Handlers MUST be idempotent.** Re-applying the same payload produces the same observable outcome with no side-effect divergence. The breaker-reset handler is naturally idempotent because `CircuitBreaker.reset()` and the persisted `circuit_breakers` UPDATE both target an absolute end-state (CLOSED); a re-apply against an already-CLOSED breaker is a no-op for both the state machine and the persisted row.

Crash recovery (relies on idempotency):

- **Crash before handler return**: handler may have committed its side-effect OR may not have — the framework does not know. Ledger row is absent. Next cycle re-detects the blob via HEAD-diff and re-invokes the handler; the handler's idempotency keeps the observable state stable.
- **Crash after handler return; before ledger commit**: handler side-effect persisted; ledger row absent. Next cycle re-detects the blob, re-invokes the handler (idempotent → no observable change), and writes the ledger row.
- **Crash after ledger commit; before sentinel bump**: handler ran; ledger row `"applied"` present; sentinel old. Next cycle re-walks from old sentinel, sees the same blob, hits the composite PK, finds the row, short-circuits (no handler call). Safe.
- **Crash after sentinel bump**: clean restart. Next cycle picks up from the new sentinel. Safe.

The replay-safety pin (`test_dispatch_handler_replay_safety_on_idempotent_handler` in `tests/integration/state/test_dispatch_loop.py`) simulates the crash-between-handler-and-ledger case by patching the audit emit to fail post-handler; it asserts the next cycle re-invokes the handler exactly once and the observable state is unchanged.

### Operator visibility

Failed proposals are surfaced through two channels:

1. **`alfred supervisor status`** (already running per #154) gains a footer section: "Recent proposal dispatch (last hour)" — counts of applied, failed, and pending proposals. Queries `processed_proposals WHERE processed_at > NOW() - INTERVAL '1 hour'`. Until `alfred audit log` is operational (blocked on PR-S3-7), this is the primary operator signal.

2. **`alfred supervisor proposals`** subcommand: lists pending and recently-processed proposals with their dispatch result, `failure_kind`, and `processed_at`. Becomes Task 9 in the plan.

The `proposal_submitted` CLI message includes a follow-up line: `"Check dispatch status with: alfred supervisor proposals --recent"`.

**`alfred audit log` caveat.** `src/alfred/cli/audit.py:_query_audit_log` raises `AuditBackendUnavailable` until PR-S3-7 lands. Until then, the canonical direct query is:

```sql
SELECT proposal_type, proposal_id, result, failure_kind, failure_detail,
       operator_user_id, commit_sha, processed_at
FROM processed_proposals
ORDER BY processed_at DESC
LIMIT 50;
```

The runbook documents this path explicitly.

### Concurrency model

The supervisor `TaskGroup` already serialises the loops at the asyncio level. The `_proposal_dispatch_loop` runs once per cycle (30s default; configured via `Settings.proposal_dispatch_interval_s` at `src/alfred/config/settings.py`); only one instance exists per supervisor process. Postgres row-level locking on the `processed_proposals_head` sentinel row prevents a hypothetical second-supervisor-process race (out of scope today — Slice 5 multi-supervisor concern).

Within a cycle, proposals process sequentially. No parallel handler dispatch in this PR — sufficient for handful-per-cycle volume; promote to a bounded `asyncio.gather` if dispatch fan-out grows. A test pins the sequential guarantee: two blobs in one cycle; assert second handler start is ordered after first handler completion.

## Consequences

### Positive

- **Closes #154 reset path** in the same PR (operator-facing win).
- **Unblocks future side-effecting proposals** (operator-CLI shapes that need "approve then act").
- **Forensic continuity** — every dispatch leaves an audit row + a ledger row. `commit_sha` gives the non-repudiable join key to the git merge event. `operator_user_id` provides attribution context (self-claimed; see §Threat model).
- **Replay safety** — composite primary key on the ledger + HEAD-diff detection prevent double-execution on supervisor restart.
- **Clean separation** from declarative projection — gate continues to project; dispatcher continues to dispatch. Either can evolve independently.

### Negative

- **Dispatch latency** — operator action → cycle interval (default 30s) → effect. Acceptable for breaker-reset (an operator should not need sub-30s recovery) but documented in the runbook as a freshness contract.
- **Couples dispatch to supervisor uptime** — if the supervisor is down, proposals stack up in `policies/<type>/` but aren't processed. On restart, the HEAD-diff walks the backlog and processes them. Operationally OK; documented in the runbook.
- **One more long-lived loop in the supervisor** — incremental complexity. Mitigated by mirroring the existing `_capability_heartbeat_loop` pattern exactly.
- **Error discipline divergence** — the dispatch loop uses log+skip semantics on cycle failures; the heartbeat uses crash-into-TaskGroup semantics. The dispatch loop handles non-critical-path work (one skipped cycle delays a single operator action by 30s); the heartbeat is critical-path (missed cycle could mean undetected gate config drift). Different criticality justifies different error discipline. Both paths emit audit rows — neither is silent. A future reader encountering the divergence should read this ADR, not conclude it is inconsistency.
- **`--confirm` partial revert** — #154 made `--confirm` a no-op at `alfred supervisor reset` because the underlying reset was deferred. This PR reinstates `--confirm` as a real gate because reset now performs actual state mutation (writes a state.git proposal). The intent of #154's BLOCKER #6 fix (operator must explicitly confirm a destructive action) is preserved; only the no-op status is reverted.
- **`operator_user_id` is self-claimed** — not an authentication artifact (see §Threat model). Forensic value only. Multi-operator hardening is deferred.

### Out of scope (explicitly deferred)

- **Auto-approval for specific proposal types** (e.g. low-risk `BreakerResetProposal`). Tracked separately; doesn't block this work.
- **CLI retry surface** for failed proposals. Operator workaround today: investigate via `alfred supervisor proposals`, fix the underlying issue, re-push the proposal branch.
- **Parallel handler dispatch within a cycle.** Sequential is enough for current volumes.
- **Cross-process locking** for multi-supervisor deployments. Slice 5 concern.
- **Commit-signature verification / `operator_user_id` authentication** for multi-operator deployments. Separate ADR.
- **Wiring `WebAllowlistProposal` and `ConfigSetProposal` runtime consumers** through declarative projection. Separate PRs once this lands; the dispatch ADR doesn't change their shape.

## Alternatives considered

### A1 — Absorb declarative projection into the dispatcher

Replace `RealGate.rebuild_from_state_git` with a `policy-grant`-typed handler. Rejected: would touch the gate's well-tested rebuild path for a consistency benefit that doesn't pay back. The two patterns (declarative snapshot vs side-effect event) have materially different semantics; conflating them is a tax on every future maintainer reading either code path.

### A2 — Separate `dispatcher` subsystem

`src/alfred/state/dispatcher.py` as its own subsystem with its own task group, health check, and lifecycle. Rejected as premature — dispatch volume is operator-cadence, not request-cadence. Promote later if necessary.

### A3 — Triggered by capability heartbeat cycle

Add dispatch as a post-rebuild phase in `_capability_heartbeat_loop`. Rejected: couples two unrelated concerns (gate health monitoring + proposal dispatch) into one loop. Failure-mode interactions become harder to reason about — if dispatch raises, does heartbeat get skipped?

### A4 — Per-type ledger tables

One table per proposal type with type-specific columns. Rejected: N migrations + N tables + N query paths for no real benefit. Cross-type forensic queries (the common operator case) need UNION ALL.

### A5 — Periodic full-tree rescan

Walk `policies/<type>/*` on every cycle instead of diff-based detection. Rejected: O(N blobs) per cycle vs O(diff). N stays small today but grows over time.

### A6 — Subprocess bootstrap of sentinel at migration time

`git rev-parse origin/main` at alembic `upgrade` time. Rejected: `/var/lib/alfred/state.git` does not exist at fresh-install migration time (created later by `alfred plugin grant init`); subprocess calls at migration time are unprecedented in AlfredOS migrations and create a fragile ordering dependency. Chosen alternative: sentinel `head_sha` starts NULL; first dispatch cycle detects NULL and bootstraps to current `origin/main` HEAD (forward-from-now semantics).

## Migration

- Alembic migration adds the `processed_proposals` table + the `processed_proposals_head` sentinel table.
- Sentinel row is inserted with `head_sha = NULL` at migration time. The dispatch loop's first cycle detects NULL, reads `git rev-parse origin/main`, and writes that SHA as the bootstrap value. Existing blobs committed before that point are not reprocessed (forward-from-now semantics, not retroactive replay).
- Existing declarative proposals (`PluginGrantProposal`, etc.) continue to flow through the gate unchanged.
- `BreakerResetProposal` payload type added (was deferred from #154); the CLI rewire at `supervisor reset` swaps the deferred hint for the proposal-write path in this same PR.

## References

- ADR-0018 — State.git proposal writer consolidation (the writer this PR's consumers depend on).
- ADR-0020 — Supervisor CLI access (the discovery that motivated #171).
- Issue #154 — the deferred reset path this PR's first user closes.
- Issue #171 — this work.
- `src/alfred/security/capability_gate/_gate.py:229` — `rebuild_from_state_git` (the declarative pattern this PR doesn't touch).
- `src/alfred/security/capability_gate/_gate.py:284` — `asyncio.to_thread(subprocess.run, ...)` precedent for non-blocking git commands.
- `src/alfred/supervisor/core.py:260` — `_capability_heartbeat_loop` (the structural precedent for the new loop).
- `src/alfred/state/proposal_payloads.py` — existing payload types; `BreakerResetProposal` lands here.
- `src/alfred/cli/_state_git.py:968+` — `_on_disk_files_for` (the writer path convention switch this PR extends).
- `src/alfred/audit/audit_row_schemas.py` — closed-vocab field-set frozensets; `STATE_PROPOSAL_PROCESSED_FIELDS` etc. land here.
