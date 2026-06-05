# Merged-proposal-branch dispatch infrastructure — design

**Date:** 2026-06-05
**Closes:** [#171](https://github.com/alfred-os/AlfredOS/issues/171); enables [#154 reset path](https://github.com/alfred-os/AlfredOS/issues/154)
**ADR:** [`docs/adr/0021-merged-proposal-branch-dispatch-for-side-effecting-proposals.md`](../../adr/0021-merged-proposal-branch-dispatch-for-side-effecting-proposals.md)
**Plan:** [`docs/superpowers/plans/2026-06-05-merged-proposal-dispatch.md`](../plans/2026-06-05-merged-proposal-dispatch.md)

## 1. What this is for

Build the dispatch infrastructure for **side-effecting** state.git proposals (one-shot operator commands like `BreakerResetProposal`). Declarative projection (`PluginGrantProposal` via `RealGate.rebuild_from_state_git`) stays untouched per ADR-0021 §Scope.

First user lands in the same PR: `BreakerResetProposal` handler closes the deferred reset path of #154.

## 2. Architecture

### 2.1 New supervisor sub-loop

`src/alfred/supervisor/core.py` grows a sibling to `_capability_heartbeat_loop`:

```python
async def _proposal_dispatch_loop(self) -> None:
    """Polls state.git main for new side-effecting proposal blobs.

    Sibling to `_capability_heartbeat_loop`. Same TaskGroup membership;
    same cancellation discipline; same audit-writer access.

    One cycle = (a) read last-processed HEAD from sentinel table,
    (b) HEAD-diff to find new blobs in `policies/<side-effect-type>/`,
    (c) for each new blob, dispatch through PROPOSAL_HANDLERS,
    (d) record result in processed_proposals — two-phase: the handler
        commits in its own session, then the dispatcher commits the
        ledger insert in a separate session. Crash recovery is via
        composite-PK replay; handler idempotency is a hard contract.
        See §2.7 for the full at-least-once + idempotent-handler model.
    (e) bump sentinel in a separate transaction.

    Cycle interval: 30s default; controlled by
    `Settings.proposal_dispatch_interval_s` at `src/alfred/config/settings.py`.
    """
```

**Error discipline.** The dispatch loop uses log+skip semantics on cycle-level failures: a cycle that hits `OperationalError` (Postgres unreachable) or git command failure logs at WARNING, emits a `state.proposal.dispatch_cycle_skipped` audit row, and retries on the next tick. This diverges from the `_capability_heartbeat_loop` (which propagates into the TaskGroup). The divergence is intentional: dispatch is non-critical-path (one skipped cycle delays a single operator action by ≤30s); the heartbeat is critical-path (missed cycle could mean undetected gate config drift). No silent skips — every aborted cycle emits an audit row. See ADR-0021 §Consequences (Negative) for rationale.

Reuses the existing `_run_loop` retry / cancellation pattern from the heartbeat (see `core.py:260` for shape).

### 2.2 Handler registry

`src/alfred/state/dispatch_registry.py`:

```python
DispatchOutcome_kind = Literal["applied", "failed_handler"]


@dataclass(frozen=True, slots=True)
class DispatchOutcome:
    """Handler-reported outcome. Framework wraps uncaught exceptions separately."""
    kind: DispatchOutcome_kind
    reason: str | None = None  # populated only on "failed_handler"

    @classmethod
    def applied(cls) -> "DispatchOutcome":
        return cls(kind="applied")

    @classmethod
    def failed(cls, reason: str) -> "DispatchOutcome":
        return cls(kind="failed_handler", reason=reason)


@dataclass(frozen=True, slots=True)
class ProposalEffects:
    """Protocol: the narrow capability surface exposed to handlers.

    Handlers receive a ProposalEffects instance, not the full Supervisor.
    Currently exposes reset_breaker only. The Supervisor implementation
    satisfies this Protocol structurally.
    """
    # Implemented as a Protocol at runtime; this dataclass documents the shape.


class ProposalEffectsProtocol(Protocol):
    async def reset_breaker(
        self,
        component_id: str,
        operator_user_id: str,
    ) -> None: ...


@dataclass(frozen=True, slots=True)
class ProposalContext:
    """Threads framework-level dependencies into handlers without globals."""
    audit_writer: AuditWriter
    effects: ProposalEffectsProtocol   # narrow — not the full Supervisor
    logger: structlog.BoundLogger


ProposalHandler = Callable[
    [StateGitProposalPayload, ProposalContext],
    Awaitable[DispatchOutcome],
]

PROPOSAL_HANDLERS: Final[Mapping[str, ProposalHandler]] = {
    "breaker-reset": _handle_breaker_reset,
}
```

`StateGitProposalPayload` subclasses (Pydantic v2) carry their own `proposal_type` ClassVar; the dispatcher reads it via `type(payload).proposal_type`. Per ADR-0018 the same value drives the writer's branch naming.

**`DispatchOutcome` name.** Named `DispatchOutcome` (not `ProposalResult`) to avoid collision with the existing `ProposalResult` at `src/alfred/cli/_state_git.py:331`, which is threaded through every CLI proposal-write surface.

### 2.3 `BreakerResetProposal` payload (deferred from #154)

`src/alfred/state/proposal_payloads.py` gets:

```python
class BreakerResetProposal(StateGitProposalPayload):
    """Operator request to reset a circuit breaker (OPEN → CLOSED).

    Reviewer-gated per ADR-0021. The supervisor's _proposal_dispatch_loop
    picks up the merged branch on its next cycle and calls
    ctx.effects.reset_breaker(component_id, operator_user_id). The
    actual state mutation lives in Postgres (circuit_breakers); this
    proposal is the operator-intent + reviewer-gate record.
    """

    proposal_type: ClassVar[str] = "breaker-reset"

    component_id: str
    operator_user_id: str
    reason: Literal["operator_initiated"] = "operator_initiated"
```

On-disk path convention: `policies/breaker-resets/<proposal_id>.json`.

**Writer update required.** `_on_disk_files_for` at `src/alfred/cli/_state_git.py:968+` currently emits `policies/grants/<plugin_id>/<grant_id>.json` for `PluginGrantProposal` and defaults to `/proposal.json` root for unrecognised types. This PR adds an explicit branch for `BreakerResetProposal` → `policies/breaker-resets/<proposal_id>.json`. The update is in-scope and required (Task 2 in the plan).

### 2.4 Handler dispatch and path/body type verification

`src/alfred/state/dispatch_registry.py`:

```python
async def _handle_breaker_reset(
    payload: BreakerResetProposal,
    ctx: ProposalContext,
) -> DispatchOutcome:
    """Apply an approved BreakerResetProposal.

    Calls ctx.effects.reset_breaker(...) which emits the existing
    supervisor.breaker.reset audit row from its actual reset path.
    Returns applied() on success; failed(reason) on NoSuchComponentError
    (operator-supplied unknown component_id — not a framework bug).
    """
    try:
        await ctx.effects.reset_breaker(
            component_id=payload.component_id,
            operator_user_id=payload.operator_user_id,
        )
    except NoSuchComponentError:
        return DispatchOutcome.failed(reason="component_id_not_registered")
    return DispatchOutcome.applied()
```

**Path/body type verification.** Before calling the handler, the dispatcher verifies that `type(payload).proposal_type == path_derived_type`. If they differ, the dispatcher records `failure_kind="payload_validation"` and skips the handler — it does not call the handler with a mismatched payload. This closes the type-confusion vector and is tested explicitly (see §4.3).

### 2.5 Ledger schema

Two new tables; one alembic migration.

```python
class ProcessedProposal(Base):
    __tablename__ = "processed_proposals"

    proposal_type: Mapped[str] = mapped_column(String(64), primary_key=True)
    proposal_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    blob_sha: Mapped[str] = mapped_column(String(40), nullable=False)
    commit_sha: Mapped[str] = mapped_column(String(40), nullable=False)  # merge-commit SHA
    processed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    result: Mapped[str] = mapped_column(String(32), nullable=False)
    handler_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    failure_kind: Mapped[str | None] = mapped_column(String(48), nullable=True)
    failure_detail: Mapped[str | None] = mapped_column(String(512), nullable=True)
    operator_user_id: Mapped[str | None] = mapped_column(String(64), nullable=True)

    __table_args__ = (
        CheckConstraint(
            "result IN ('applied', 'failed_handler', 'failed_parse', "
            "'failed_unknown_type', 'skipped_already_processed')",
            name="ck_processed_proposals_result",
        ),
    )


class ProcessedProposalsHead(Base):
    """Sentinel: tracks last-processed state.git HEAD.

    Single-row table (enforced by CheckConstraint id=1).
    head_sha starts NULL after migration; the dispatch loop's
    first cycle detects NULL, writes git rev-parse origin/main,
    and proceeds (forward-from-now semantics — existing blobs not
    replayed).
    """
    __tablename__ = "processed_proposals_head"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    head_sha: Mapped[str | None] = mapped_column(String(40), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False,
        server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (
        CheckConstraint("id = 1", name="ck_processed_proposals_head_singleton"),
    )
```

**Column notes:**

- `failure_reason` (single Text column) is replaced by `failure_kind` (String(48), closed vocab pinned by `ck_processed_proposals_failure_kind` + a `Literal`-narrowed `_record_failure` call site) and `failure_detail` (String(512); truncated only, DLP wiring tracked at [#173](https://github.com/alfred-os/AlfredOS/issues/173)). Today's emit sites pass closed-vocab strings (`type(exc).__name__`, handler-returned reasons) so the realised leak surface is small; #173 wires `OutboundDlp.scan` at this boundary for future emit sites that would otherwise drop a Pydantic `ValidationError` message verbatim.
- `commit_sha` is the cycle's `current_head` at the time of the HEAD-diff walk — the head that brought the blob into `main`. Distinct from `blob_sha` (the content hash of the JSON file). Provides the non-repudiable forensic join key to the git history.
- `operator_user_id` is `String(64)` and bounded at the Pydantic model boundary (`Annotated[str, StringConstraints(max_length=64)]`) so an oversized payload cannot land in state.git and trigger a Postgres-side DataError at the ledger insert. Matches `PluginGrant.operator_user_id`, `AuditEntry.actor_user_id`, and the rest of the AlfredOS ledger schema. The self-claimed nature is documented in ADR-0021 §Threat model.

**git commands are non-blocking.** All git subprocess calls inside `dispatch_loop.py` use `asyncio.to_thread(subprocess.run, ...)`, not bare `subprocess.run`. Precedent: `src/alfred/security/capability_gate/_gate.py:284`. Either extend `_state_git.py` with async wrapper helpers (preferred for reusability) or inline the pattern in `dispatch_loop.py` — the choice is flagged in Task 6 of the plan.

### 2.6 CLI rewire (the #154 closure)

`src/alfred/cli/supervisor.py`: `alfred supervisor reset --confirm` no longer emits the deferred hint. It now:

1. Resolves the `operator_user_id` via the existing `_resolve_operator_user_id()` (OS-account attribution).
2. Constructs a `BreakerResetProposal` payload.
3. Writes it via the existing `StateGitProposalClient.queue_proposal_or_exit` (returns the `proposal_id`).
4. Prints `cli.supervisor.reset.proposal_submitted` (new catalog key) — format:

   ```
   Reset request for {component} submitted as proposal {proposal_id}.
   Branch: {branch}. Supervisor will process within {interval}s of reviewer merge.
   Check dispatch status with: alfred supervisor proposals --recent
   ```

5. Exits 0 (success — the request landed).

The `--confirm` gate is reinstated as a real gate (a no-op was introduced by #154 because reset did nothing; reset now writes a proposal, so confirmation is meaningful). The deferred hint catalog keys (`deferred_to_issue_171`, `reset.help.short` deferred-marker) tombstone.

The `proposal_submitted` catalog key shape matches the `cli.web.allowlist.add.submitted` precedent: includes `{proposal_id}`, `{branch}`, `{interval}`, and a `Check status with:` follow-up line pointing at `alfred supervisor proposals --recent`.

### 2.7 Atomicity model

The shipped semantics are **at-least-once delivery with an idempotent-handler contract**.

1. **Handler invocation** lives in the handler's own transactional concern. `Supervisor.reset_breaker` opens a `_session_scope()` and commits the `circuit_breakers` UPDATE inside that scope; the framework awaits the handler's return value as the signal that the side-effect landed.
2. **Ledger INSERT** is the framework's transactional concern (`processed_proposals` row inside a framework-owned `_session_scope`).
3. **Sentinel bump** is a separate framework transaction at the end of the cycle.

Handlers MUST be idempotent: re-applying the same payload produces the same observable outcome. The breaker-reset handler is naturally idempotent (`CircuitBreaker.reset()` and the persisted UPDATE both target the absolute end-state CLOSED). Future handlers MUST be designed similarly; the dispatcher's at-least-once guarantee depends on this contract.

Crash recovery by phase:

| Phase of crash | State on restart | Behaviour |
|---|---|---|
| Before handler return | Handler may have committed OR not — framework does not know; ledger row absent | Next cycle re-detects blob via HEAD-diff; re-invokes handler; idempotency keeps observable state stable. Safe. |
| After handler return; before ledger commit | Handler side-effect persisted; ledger row absent | Next cycle re-detects blob; re-invokes handler (no observable change); writes ledger row. Safe. |
| After ledger commit; before sentinel bump | Handler ran; ledger row present (`"applied"`) | Next cycle re-walks from old sentinel; sees same blob; checks ledger PK; finds existing row; short-circuits (no handler call). Safe. |
| After sentinel bump | Normal | Next cycle starts from new sentinel. Safe. |

The replay-safety test (`test_dispatch_handler_replay_safety_on_idempotent_handler` in `tests/integration/state/test_dispatch_loop.py`) simulates the crash-between-handler-and-ledger case by patching the audit emit to fail post-handler; it asserts the next cycle re-invokes the handler exactly once and the observable state is unchanged.

### 2.8 Operator visibility

**`alfred supervisor status`** (already running per #154) gains a "Recent proposal dispatch (last hour)" footer section. Queries `processed_proposals WHERE processed_at > NOW() - INTERVAL '1 hour'`, displays counts: N applied, N failed, N pending.

**`alfred supervisor proposals`** subcommand: lists pending and recently-processed proposals. Columns: `proposal_type`, `proposal_id`, `result`, `failure_kind`, `operator_user_id`, `processed_at`. Flags: `--since DURATION` (default `1h`; accepts `Nm` / `Nh` / `Nd` / `Nw`), `--limit N` (default 20), `--all` (forensic-export escape hatch). Renders a printed legend after the table decoding the closed-vocab `result` values. This becomes Task 9 in the plan.

**`alfred audit log` caveat.** `src/alfred/cli/audit.py:_query_audit_log` raises `AuditBackendUnavailable` until PR-S3-7. Until PR-S3-7 lands, the canonical direct query for proposal dispatch events is:

```sql
SELECT proposal_type, proposal_id, result, failure_kind, failure_detail,
       operator_user_id, commit_sha, processed_at
FROM processed_proposals
ORDER BY processed_at DESC
LIMIT 50;
```

The runbook documents this alongside `alfred supervisor proposals --recent`.

## 3. New types + files

| File | Status | Responsibility |
|---|---|---|
| `src/alfred/state/proposal_payloads.py` | Modify | Add `BreakerResetProposal` |
| `src/alfred/state/dispatch_registry.py` | Create | `DispatchOutcome`, `ProposalContext`, `ProposalEffectsProtocol`, `PROPOSAL_HANDLERS`, `_handle_breaker_reset` |
| `src/alfred/state/dispatch_loop.py` | Create | `_proposal_dispatch_cycle`, `_iter_new_proposal_blobs`, `_load_proposal_blob` |
| `src/alfred/supervisor/core.py` | Modify | Add `_proposal_dispatch_loop` to the supervisor's TaskGroup |
| `src/alfred/memory/models.py` | Modify | Add `ProcessedProposal`, `ProcessedProposalsHead` ORM models |
| `src/alfred/memory/migrations/versions/0011_processed_proposals.py` | Create | Alembic migration for both tables; sentinel row inserted with `head_sha = NULL` |
| `src/alfred/audit/audit_row_schemas.py` | Modify | Add `STATE_PROPOSAL_PROCESSED_FIELDS`, `STATE_PROPOSAL_DISPATCH_FAILED_FIELDS`, `STATE_PROPOSAL_DISPATCH_CYCLE_SKIPPED_FIELDS` frozensets |
| `src/alfred/cli/supervisor.py` | Modify | Rewrite `supervisor_reset` body — proposal write replaces deferred hint; add `supervisor_proposals` subcommand |
| `src/alfred/cli/_state_git.py` | Modify | Add explicit `BreakerResetProposal` branch in `_on_disk_files_for` → `policies/breaker-resets/<proposal_id>.json` |
| `src/alfred/config/settings.py` | Modify | Add `proposal_dispatch_interval_s: int = 30` field |
| `locale/en/LC_MESSAGES/alfred.po` | Modify | Add `cli.supervisor.reset.proposal_submitted`; tombstone `deferred_to_issue_171`, `reset.help.short` deferred marker |

Docs:

| File | Status | Responsibility |
|---|---|---|
| `docs/adr/0021-...md` | Created already | Architectural decision |
| `docs/superpowers/specs/2026-06-05-...md` | Created already | This file |
| `docs/superpowers/plans/2026-06-05-...md` | Created already | Implementation plan |
| `docs/subsystems/state.md` | Create or modify | State.git subsystem overview — proposal write, declarative projection, side-effect dispatch |
| `docs/runbooks/slice-3-supervisor.md` | Modify | Document the new dispatch cycle; replace the "reset deferred to #171" workaround; document psql fallback for audit queries until PR-S3-7; document `alfred supervisor proposals --recent` |
| `docs/glossary.md` | Modify | Add `DispatchOutcome`, `ProposalContext`, `processed_proposals` ledger |

## 4. Tests

### 4.1 Unit — dispatch registry + ledger

- `test_proposal_handlers_registry_contains_breaker_reset` — pin.
- `test_proposal_handler_protocol_signature` — handler accepts payload + ctx, returns awaitable `DispatchOutcome`.
- `test_dispatch_outcome_applied_and_failed_factories` — exact shapes.

### 4.2 Unit — `_handle_breaker_reset`

- `test_handle_breaker_reset_calls_effects_reset_breaker` — patch `ProposalEffectsProtocol`; assert `reset_breaker` called with payload fields.
- `test_handle_breaker_reset_returns_failed_on_unknown_component` — raises `NoSuchComponentError`; returns `DispatchOutcome.failed(reason="component_id_not_registered")`.
- `test_handle_breaker_reset_propagates_unexpected_exception` — effects raises `RuntimeError`; assert raises (framework will catch + record).

### 4.3 Unit — dispatch loop

- `test_dispatch_cycle_bootstraps_null_sentinel_to_origin_main_head` — sentinel is NULL; cycle writes `git rev-parse origin/main` as the new sentinel; no blobs processed on bootstrap cycle.
- `test_dispatch_cycle_skips_when_no_new_blobs`.
- `test_dispatch_cycle_processes_new_blob_records_ledger_bumps_sentinel`.
- `test_dispatch_cycle_skips_already_processed_blob` — replay safety; ledger row present; handler NOT called; `skipped_already_processed` in cycle-local state.
- `test_dispatch_cycle_records_failed_unknown_type_for_unregistered_handler`.
- `test_dispatch_cycle_records_failed_parse_for_malformed_blob_json`.
- `test_dispatch_cycle_records_failed_handler_for_handler_exception` — handler raises; ledger row `result="failed_handler"`, `failure_kind="handler_uncaught_exception"`.
- `test_dispatch_cycle_rejects_path_body_type_mismatch` — path says `breaker-reset`, payload ClassVar says `other-type`; `failure_kind="payload_validation"` + handler NOT called.
- `test_dispatch_cycle_sequential_execution_of_two_blobs` — two blobs in one cycle; assert second handler invocation is ordered after first completes (pins ADR-0021 §Concurrency sequential claim).
- `test_dispatch_cycle_emits_state_proposal_processed_audit_row_on_applied`.
- `test_dispatch_cycle_emits_state_proposal_dispatch_failed_audit_row_on_framework_error`.
- `test_dispatch_cycle_emits_dispatch_cycle_skipped_audit_row_on_postgres_outage`.
- `test_dispatch_cycle_postgres_outage_skips_cycle_loud` — `OperationalError` on ledger write logs WARNING + emits audit row + skips; next cycle retries.
- `test_dispatch_cycle_state_git_outage_skips_cycle_loud` — git subprocess fails; same treatment.
- `test_dispatch_cycle_atomicity_crash_after_ledger_before_sentinel` — ledger row present; sentinel old; re-run cycle; assert handler NOT called again; `skipped_already_processed`.

### 4.4 Unit — CLI rewire

- `test_supervisor_reset_writes_breaker_reset_proposal_on_confirm` — patch `StateGitProposalClient.queue_proposal_or_exit`; assert called with typed payload.
- `test_supervisor_reset_prints_proposal_submitted_hint_with_proposal_id_and_interval_and_exits_zero` — asserts message includes `{proposal_id}`, `{branch}`, `{interval}`, and `alfred supervisor proposals --recent` follow-up line.
- `test_supervisor_reset_propagates_state_git_errors` — patch client to raise `StateGitError(PATH_MISSING)`; assert localised error path.
- `test_supervisor_reset_audit_attempt_row_still_emits_before_proposal_write` — preserves the CR-149 forensic-row invariant.
- `test_supervisor_reset_without_confirm_does_not_write_proposal` — `--confirm` is a real gate; not passing it exits without writing; BLOCKER #6 semantic from #154 is preserved.

### 4.5 Integration — full round-trip

`tests/integration/state/test_breaker_reset_proposal_roundtrip.py`:

- Real Postgres + real state.git fixture repo (testcontainers + tmp_path).
- Insert a tripped `CircuitBreakerState(component_id="test.plugin", state="OPEN", trip_count=3, ...)`.
- Run `alfred supervisor reset test.plugin --confirm`. Assert proposal branch lands.
- Simulate reviewer merge (write the file directly to main's tree — match the existing precedent for grant proposals).
- Invoke `_proposal_dispatch_cycle` directly.
- Assert: (a) `processed_proposals` row landed with `result="applied"`; (b) `ctx.effects.reset_breaker` was called; (c) the `supervisor.breaker.reset` audit row was emitted; (d) `circuit_breakers.state` flipped to CLOSED; (e) re-running the dispatch cycle is a no-op (replay safety).
- **Failure path**: `_handle_breaker_reset` returns `DispatchOutcome.failed(reason="component_id_not_registered")` for an unregistered component_id; assert ledger row with `result="failed_handler"`, `failure_kind="handler_returned_failed"` + audit row emitted + handler NOT re-called on replay.

### 4.6 Adversarial

- `test_dispatch_does_not_replay_processed_proposal_on_supervisor_restart` — bootstrap the ledger; restart the supervisor; assert no replay.
- `test_dispatch_records_unknown_proposal_type_loud` — write a blob at `policies/unknown-type/abc.json`; assert ledger row + audit row.
- `test_dispatch_rejects_proposal_referencing_unknown_component_id` — handler returns `failed`; ledger records it; `supervisor.breaker.reset` audit row NOT emitted (reset never crossed the boundary).
- `test_dispatch_does_not_invoke_handler_for_declarative_proposal_types` — write a `policies/grants/...` blob; dispatch loop ignores it (declarative is the gate's job, not the dispatcher's).

## 5. Out of scope

- Auto-approval path for any proposal type (deferred — separate ADR).
- CLI retry for failed proposals (operator workaround documented; CLI command deferred).
- Parallel handler dispatch within a cycle (sequential is enough for current volume).
- Cross-process locking for multi-supervisor deployments (Slice 5 concern).
- Wiring `WebAllowlistProposal` / `ConfigSetProposal` runtime consumers (these are declarative; separate work to give each a projection).
- Push notifications when a proposal is processed (operator polls via `alfred supervisor proposals --recent`).

## 6. Coverage / quality bar

- 100% line + branch on the new code (`dispatch_registry.py`, `dispatch_loop.py`, `BreakerResetProposal`, `_handle_breaker_reset`, the rewritten `supervisor_reset` body, the new `supervisor_proposals` subcommand body).
- Integration round-trip green (happy path + one failure path).
- Adversarial tests green.
- All operator-facing strings via `t()` with real msgstrs.
- Migration tested via the existing testcontainers pattern.

## 7. Migration / backwards compat

- Alembic migration 0011 adds the two new tables. Sentinel row inserted with `head_sha = NULL`. First dispatch cycle detects `NULL`, bootstraps to `git rev-parse origin/main`, and proceeds — existing blobs are not reprocessed.
- `Supervisor.reset_breaker` signature unchanged.
- `StateGitProposalClient` API unchanged (the client is payload-agnostic per ADR-0018). `_on_disk_files_for` is extended — additive, not breaking.
- The CLI command `alfred supervisor reset --confirm` shifts from "deferred hint + exit 1" to "proposal write + exit 0". The output text changes; scripts grepping for the old hint catalog key (`deferred_to_issue_171`) need updating. Runbook documents this transition.

## 8. References

- ADR-0021 — this work's architectural decision.
- ADR-0018 — state.git proposal writer consolidation.
- ADR-0020 — supervisor CLI access (discovered the #171 gap).
- Issue #154 — the deferred reset path this PR closes.
- Issue #171 — this work.
- `src/alfred/supervisor/core.py:260` — `_capability_heartbeat_loop` (structural precedent).
- `src/alfred/security/capability_gate/_gate.py:229` — `rebuild_from_state_git` (the declarative pattern this PR does NOT change).
- `src/alfred/security/capability_gate/_gate.py:284` — `asyncio.to_thread` precedent for non-blocking git commands.
- `src/alfred/cli/_state_git.py:331` — existing `ProposalResult` (why the new outcome type is named `DispatchOutcome`).
- `src/alfred/cli/_state_git.py:968+` — `_on_disk_files_for` (the writer switch this PR extends).
- `src/alfred/audit/audit_row_schemas.py` — closed-vocab frozenset pattern; new field sets land here.
