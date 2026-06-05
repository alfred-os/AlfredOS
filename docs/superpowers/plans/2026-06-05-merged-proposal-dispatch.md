# Merged-proposal-branch dispatch — implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. New supervisor loop + new Postgres schema + new closed-vocab audit events + CLI rewire — TDD red/green per task is mandatory.

**Goal:** Build the dispatch infrastructure for side-effecting state.git proposals per ADR-0021 (loop, registry, ledger, audit events) and ship `BreakerResetProposal` as the first user — closing the deferred reset path of #154 in the same PR.

**Architecture:** New `_proposal_dispatch_loop` in the supervisor's TaskGroup polls main for new blobs under `policies/<side-effect-type>/`, dispatches each through `PROPOSAL_HANDLERS`, records outcome in `processed_proposals`. Replay-safe via composite primary key + sentinel HEAD. Declarative projection (gate's `rebuild_from_state_git`) untouched.

**Tech Stack:** Python 3.14.5 • SQLAlchemy 2.x async ORM • Alembic • Pydantic v2 • asyncio TaskGroup • structlog • pytest + testcontainers Postgres + tmp_path state.git fixture.

**Spec anchor:** [`docs/superpowers/specs/2026-06-05-merged-proposal-dispatch-design.md`](../specs/2026-06-05-merged-proposal-dispatch-design.md)
**ADR:** [`docs/adr/0021-merged-proposal-branch-dispatch-for-side-effecting-proposals.md`](../../adr/0021-merged-proposal-branch-dispatch-for-side-effecting-proposals.md)

**Depends on:** Nothing (all prereqs on `main`).
**Blocks:** Nothing in flight.
**Closes:** #171 (the infrastructure); #154 reset path (the first user).

---

## §1 Goal

After this PR:

1. The supervisor runs a new `_proposal_dispatch_loop` sibling to `_capability_heartbeat_loop`. Default interval 30s, configured via `Settings.proposal_dispatch_interval_s`.
2. The loop polls state.git main for new blobs under `policies/<side-effect-type>/<id>.json` (paths registered as side-effecting via `PROPOSAL_HANDLERS`).
3. Each new blob is parsed to a typed `StateGitProposalPayload`, dispatched through the registry, recorded in `processed_proposals` (replay-safe).
4. `BreakerResetProposal` is the first registered side-effect type. Operator flow: `alfred supervisor reset <id> --confirm` writes the proposal; reviewer approves; dispatch loop picks it up; `ctx.effects.reset_breaker` runs; breaker flips to CLOSED.
5. `alfred supervisor reset` no longer emits the deferred-to-#171 hint. Operators get the proposal-submitted confirmation + a working flow.
6. `alfred supervisor proposals` subcommand surfaces pending and recently-processed proposals.
7. 100% line + branch on the new code. Integration round-trip green (happy + failure path). Adversarial green.

---

## §2 File structure

| File | Status | Responsibility |
|---|---|---|
| `src/alfred/state/proposal_payloads.py` | Modify | Add `BreakerResetProposal` Pydantic v2 class |
| `src/alfred/state/dispatch_registry.py` | Create | `DispatchOutcome`, `ProposalContext`, `ProposalEffectsProtocol`, `PROPOSAL_HANDLERS`, `_handle_breaker_reset` |
| `src/alfred/state/dispatch_loop.py` | Create | `_proposal_dispatch_cycle`, `_iter_new_proposal_blobs`, `_load_proposal_blob` |
| `src/alfred/supervisor/core.py` | Modify | Add `_proposal_dispatch_loop` to TaskGroup |
| `src/alfred/memory/models.py` | Modify | Add `ProcessedProposal`, `ProcessedProposalsHead` |
| `src/alfred/memory/migrations/versions/0011_processed_proposals.py` | Create | Alembic migration; sentinel row inserted with `head_sha = NULL` |
| `src/alfred/audit/audit_row_schemas.py` | Modify | Add `STATE_PROPOSAL_PROCESSED_FIELDS`, `STATE_PROPOSAL_DISPATCH_FAILED_FIELDS`, `STATE_PROPOSAL_DISPATCH_CYCLE_SKIPPED_FIELDS` frozensets |
| `src/alfred/cli/supervisor.py` | Modify | Rewrite `supervisor_reset` body; add `supervisor_proposals` subcommand |
| `src/alfred/cli/_state_git.py` | Modify | Add `BreakerResetProposal` branch in `_on_disk_files_for` → `policies/breaker-resets/<proposal_id>.json` |
| `src/alfred/config/settings.py` | Modify | Add `proposal_dispatch_interval_s: int = 30` |
| `locale/en/LC_MESSAGES/alfred.po` | Modify | Add `cli.supervisor.reset.proposal_submitted`; tombstone `deferred_to_issue_171` + the `reset.help.short` deferred marker |
| `tests/unit/state/test_dispatch_registry.py` | Create | Registry + handler tests |
| `tests/unit/state/test_dispatch_loop.py` | Create | Loop cycle tests |
| `tests/unit/state/test_breaker_reset_proposal_payload.py` | Create | Payload Pydantic shape tests |
| `tests/unit/cli/test_supervisor_reset.py` | Modify | Replace deferred-hint tests with proposal-write tests |
| `tests/integration/state/test_breaker_reset_proposal_roundtrip.py` | Create | End-to-end: CLI write → fixture merge → loop pickup → breaker flips |
| `tests/adversarial/state/test_dispatch_replay_safety.py` | Create | Replay + unknown-type + handler-failure adversarial coverage |
| `docs/adr/0021-...md` | Created already | (this PR's docs commit) |
| `docs/superpowers/specs/2026-06-05-...md` | Created already | (this PR's docs commit) |
| `docs/superpowers/plans/2026-06-05-...md` | Created already | (this file) |
| `docs/subsystems/state.md` | Create or modify | State.git subsystem overview |
| `docs/runbooks/slice-3-supervisor.md` | Modify | Replace deferred-reset workaround section; document psql fallback; document `alfred supervisor proposals --recent` |
| `docs/glossary.md` | Modify | Add `DispatchOutcome`, `ProposalContext`, `processed_proposals` |

---

## §3 Definition of Done

- [ ] `uv run pytest tests/unit/state/ tests/unit/cli/ tests/integration/state/ tests/adversarial/state/ -v` → green.
- [ ] 100% line + branch on new code: `src/alfred/state/dispatch_registry.py`, `src/alfred/state/dispatch_loop.py`, `BreakerResetProposal` class, `_handle_breaker_reset`, rewritten `supervisor_reset` body, `supervisor_proposals` subcommand body.
- [ ] `uv run ruff check . && uv run ruff format --check .` → clean.
- [ ] `uv run mypy src/ && uv run pyright src/` → clean.
- [ ] `make check` → green.
- [ ] Alembic migration applies cleanly + downgrade reverts cleanly.
- [ ] Catalog keys added + tombstoned correctly; `pybabel compile` produces a fresh `.mo`.
- [ ] Conventional Commits + `#171` (and `#154` on the reset-rewire commits) in every subject; no `fixup!` survivors.
- [ ] User check-in before opening the PR.

---

## §4 Tasks

### Task 1 — Docs commit (ADR + spec + plan + runbook + subsystem + glossary)

**Files**:
- Already created: `docs/adr/0021-...md`, `docs/superpowers/specs/2026-06-05-...md`, `docs/superpowers/plans/2026-06-05-...md`.
- Create: `docs/subsystems/state.md` — high-level overview: state.git as proposal channel; declarative projection (gate's rebuild) vs side-effect dispatch (this PR's infrastructure); operator visibility via `alfred supervisor proposals`.
- Modify: `docs/runbooks/slice-3-supervisor.md` — replace the "reset deferred to #171" workaround section. New flow: `alfred supervisor reset` writes a proposal; reviewer approves; supervisor picks up on next cycle (≤30s). Document: `alfred supervisor proposals --recent` as the primary status-check surface. Document: `alfred audit log` is unavailable until PR-S3-7; include the canonical psql fallback query. Document: failure investigation path (check `failure_kind` + `failure_detail` in `processed_proposals`). Document the `--confirm` semantic reinstatement and the old `deferred_to_issue_171` catalog key tombstone (scripts grepping for it need updating).
- Modify: `docs/glossary.md` — add `DispatchOutcome`, `ProposalContext`, `processed_proposals` ledger.

- [ ] Write the runbook + subsystem + glossary updates.
- [ ] Commit:
  ```
  docs(state): ADR-0021 + spec + plan for merged-proposal dispatch (#171)
  ```

### Task 2 — `BreakerResetProposal` payload + `_on_disk_files_for` writer update

**Files**:
- Modify: `src/alfred/state/proposal_payloads.py`
- Modify: `src/alfred/cli/_state_git.py` — add explicit `BreakerResetProposal` branch in `_on_disk_files_for` (`src/alfred/cli/_state_git.py:968+`). This is **required**, not optional. The current switch only handles `PluginGrantProposal`; other payloads fall through to the root `/proposal.json` path, which is incorrect for `BreakerResetProposal`. The new branch emits `policies/breaker-resets/<proposal_id>.json`.
- Create: `tests/unit/state/test_breaker_reset_proposal_payload.py`

- [ ] **Step 1: Write failing tests.** Pin Pydantic shape. Pin that `_on_disk_files_for(BreakerResetProposal(...), proposal_id)` returns `policies/breaker-resets/<proposal_id>.json`. Pin that a `PluginGrantProposal` path is unchanged.
- [ ] **Step 2:** Implement payload + add the `_on_disk_files_for` branch.
- [ ] **Step 3:** Run; confirm green.
- [ ] **Step 4: Commit.** `feat(state): BreakerResetProposal payload + writer path convention (#171)`.

### Task 3 — Postgres schema (models + alembic)

**Files**:
- Modify: `src/alfred/memory/models.py`
- Create: `src/alfred/memory/migrations/versions/0011_processed_proposals.py`
- Modify: `tests/unit/memory/test_models.py` (or create a new file for the new models)

- [ ] **Step 1: Write failing model tests.** Pin shape + constraints (`ck_processed_proposals_result`, `ck_processed_proposals_head_singleton`). Pin `head_sha` is nullable. Pin `operator_user_id` is `String(64)`. Pin `failure_kind` is `String(48)`, `failure_detail` is `String(512)`. Pin `commit_sha` is `String(40)`, not nullable.
- [ ] **Step 2:** Implement ORM models.
- [ ] **Step 3:** Write the alembic migration. `upgrade` creates both tables + inserts the sentinel row with `head_sha = NULL`. `downgrade` drops both tables. **Do not call subprocess or git at migration time** — the sentinel starts NULL and the dispatch loop bootstraps it on first cycle.
- [ ] **Step 4:** Run alembic upgrade + downgrade via the testcontainers Postgres fixture.
- [ ] **Step 5: Commit.** `feat(state): processed_proposals ledger + sentinel migration (#171)`.

### Task 4 — Closed-vocab audit events

**Files**:
- Modify: `src/alfred/audit/audit_row_schemas.py` — add `STATE_PROPOSAL_PROCESSED_FIELDS`, `STATE_PROPOSAL_DISPATCH_FAILED_FIELDS`, `STATE_PROPOSAL_DISPATCH_CYCLE_SKIPPED_FIELDS` as `frozenset` constants (per the symmetric-key pattern of `QUARANTINE_EXTRACT_FIELDS` etc.).
- Modify: `tests/unit/audit/test_audit_row_schemas.py` to pin the new field sets.

Note: there is no `src/alfred/audit/event_vocabulary.py`. Audit event names (`state.proposal.processed`, `state.proposal.dispatch_failed`, `state.proposal.dispatch_cycle_skipped`) are free-form strings passed as the `event=` kwarg to `AuditWriter.append_schema`. The closed-vocab field-set frozensets are the only new addition to `audit_row_schemas.py`.

- [ ] **Step 1: Write failing schema tests.**
- [ ] **Step 2:** Add the three field-set frozensets.
- [ ] **Step 3:** Run; confirm green.
- [ ] **Step 4: Commit.** `feat(audit): closed-vocab field sets for state.proposal.* events (#171)`.

### Task 5 — `DispatchOutcome`, `ProposalContext`, `ProposalEffectsProtocol`, `_handle_breaker_reset`

**Files**:
- Create: `src/alfred/state/dispatch_registry.py`
- Create: `tests/unit/state/test_dispatch_registry.py`

- [ ] **Step 1: Write failing tests** per spec §4.1 + §4.2.
  - Use `DispatchOutcome` (not `ProposalResult`) throughout — `ProposalResult` already exists at `src/alfred/cli/_state_git.py:331`.
  - Pin that `ProposalContext.effects` is typed `ProposalEffectsProtocol`, not `Supervisor`.
  - Pin `_handle_breaker_reset` calls `ctx.effects.reset_breaker`, not `ctx.supervisor.reset_breaker`.
- [ ] **Step 2:** Implement `DispatchOutcome`, `ProposalContext`, `ProposalEffectsProtocol`, `PROPOSAL_HANDLERS`, `_handle_breaker_reset`.
- [ ] **Step 3:** Run; confirm green.
- [ ] **Step 4: Commit.** `feat(state): DispatchOutcome + ProposalEffectsProtocol + breaker-reset handler (#171)`.

### Task 6 — Dispatch cycle (`_proposal_dispatch_cycle`)

**Files**:
- Create: `src/alfred/state/dispatch_loop.py`
- Create: `tests/unit/state/test_dispatch_loop.py`

The cycle's pseudocode per spec §2.1 — break into composable helpers:

```python
async def _proposal_dispatch_cycle(ctx: ProposalContext, repo_path: Path) -> None:
    """One iteration of the dispatch loop.

    1. Read last-processed HEAD; if NULL, bootstrap from origin/main and return.
    2. HEAD-diff to enumerate new blobs in registered side-effect paths.
    3. For each new blob: verify path/body type match, check ledger, dispatch,
       record outcome (handler + ledger in one transaction), update sentinel.
    """


async def _iter_new_proposal_blobs(
    repo_path: Path,
    last_head_sha: str,
    current_head_sha: str,
    registered_types: set[str],
) -> AsyncIterator[ProposalBlobRef]:
    """Yield (proposal_type, proposal_id, blob_sha, commit_sha, content_path) tuples
    for new blobs under registered side-effect type paths.
    """


async def _load_proposal_blob(
    blob_ref: ProposalBlobRef,
) -> tuple[StateGitProposalPayload | None, str | None]:
    """Parse + validate blob JSON to a typed payload. Returns
    (payload, None) on success; (None, failure_kind) on failure where
    failure_kind is one of 'payload_validation' | 'unknown_proposal_type'.
    """
```

**Non-blocking git.** All `subprocess.run` calls MUST be wrapped in `asyncio.to_thread(subprocess.run, ...)`. Precedent: `src/alfred/security/capability_gate/_gate.py:284`. Prefer extending `_state_git.py` with async wrapper helpers (flag in commit message if you inline instead).

- [ ] **Step 1: Write failing tests** per spec §4.3. Cover:
  - `test_dispatch_cycle_bootstraps_null_sentinel_to_origin_main_head`
  - `test_dispatch_cycle_sequential_execution_of_two_blobs` (pins the sequential guarantee from ADR-0021)
  - `test_dispatch_cycle_rejects_path_body_type_mismatch` (pins type-confusion defence)
  - `test_dispatch_cycle_atomicity_crash_after_ledger_before_sentinel` (pins the atomicity model)
  - All other cases from spec §4.3.
- [ ] **Step 2:** Implement. Use `asyncio.to_thread(subprocess.run, ...)` for all git calls.
- [ ] **Step 3:** Run; confirm green. Coverage 100% on `dispatch_loop.py`.
- [ ] **Step 4: Commit.** `feat(state): proposal dispatch cycle with HEAD-diff detection (#171)`.

### Task 7 — Wire the loop into the supervisor TaskGroup + Settings field

**Files**:
- Modify: `src/alfred/supervisor/core.py`
- Modify: `src/alfred/config/settings.py`
- Modify: `tests/unit/supervisor/test_core.py` (or add a new test file for the new loop)

- [ ] **Step 1:** Add `proposal_dispatch_interval_s: int = 30` to `Settings` at `src/alfred/config/settings.py`. Remove any reference to `ALFRED_PROPOSAL_DISPATCH_INTERVAL_S` as a raw env var — it goes through `Settings`.

- [ ] **Step 2: Write failing tests.** Pin that:
  - The TaskGroup spawns `_proposal_dispatch_loop`.
  - The loop reads its interval from `Settings.proposal_dispatch_interval_s`.
  - Cancellation propagates correctly.
  - Cycle-level failures (e.g. Postgres `OperationalError`) skip the cycle, log WARNING, emit `state.proposal.dispatch_cycle_skipped` audit row, and do NOT crash the supervisor.

- [ ] **Step 3:** Implement `_proposal_dispatch_loop` per spec §2.1. Mirror the existing `_capability_heartbeat_loop` shape exactly (see `core.py:260`). Error discipline: log+skip, not propagate-into-TaskGroup (see ADR-0021 §Consequences for rationale).

- [ ] **Step 4:** Run; confirm green.

- [ ] **Step 5: Commit.** `feat(supervisor): wire proposal dispatch loop into TaskGroup (#171)`.

### Task 8 — CLI rewire: `alfred supervisor reset` writes the proposal

**Files**:
- Modify: `src/alfred/cli/supervisor.py`
- Modify: `locale/en/LC_MESSAGES/alfred.po`
- Modify: `tests/unit/cli/test_supervisor_reset.py`
- Modify: `tests/unit/cli/test_supervisor_reset_confirm.py`
- Modify: `tests/unit/cli/test_i18n_key_coverage.py`

- [ ] **Step 1: Write failing tests** per spec §4.4. Including:
  - `test_supervisor_reset_prints_proposal_submitted_hint_with_proposal_id_and_interval_and_exits_zero` — assert message contains `{proposal_id}` (from `queue_proposal_or_exit` return), `{branch}`, `{interval}` (from `Settings.proposal_dispatch_interval_s`), and `alfred supervisor proposals --recent` follow-up line.
  - `test_supervisor_reset_without_confirm_does_not_write_proposal` — `--confirm` is a real gate again; not passing it exits without writing.
- [ ] **Step 2:** Implement the rewire. Use the existing `StateGitProposalClient` (no new client work; per ADR-0018 the writer is payload-agnostic).
- [ ] **Step 3:** Add `cli.supervisor.reset.proposal_submitted` catalog key. Tombstone `deferred_to_issue_171` + the `reset.help.short` deferred marker. The new catalog key body follows the `cli.web.allowlist.add.submitted` precedent shape: includes `{proposal_id}`, `{branch}`, `{interval}`, and a `Check status with:` follow-up line.
- [ ] **Step 4:** Update `cli.supervisor.help` to reflect that reset now works: `"Inspect supervised components and reset tripped circuit breakers."`. Update `cli.supervisor.reset.help.short`: `"Reset a circuit breaker. Writes a reviewer-gated state.git proposal."`.
- [ ] **Step 5:** `pybabel extract` + `update` + `compile`.
- [ ] **Step 6:** Run; confirm green.
- [ ] **Step 7: Commit.** `feat(cli)!: supervisor reset writes BreakerResetProposal (#171, closes #154 reset path)`.

### Task 9 — `alfred supervisor proposals` subcommand

**Files**:
- Modify: `src/alfred/cli/supervisor.py`
- Modify: `locale/en/LC_MESSAGES/alfred.po`
- Modify: `tests/unit/cli/test_supervisor_proposals.py` (create)

The `alfred supervisor proposals` subcommand queries `processed_proposals` and displays pending + recently-processed proposals with their dispatch result, `failure_kind`, and `processed_at`. The `--recent` flag scopes to the last hour.

`alfred supervisor status` footer: add a "Recent proposal dispatch (last hour)" section showing counts of applied, failed, and pending proposals (counts from `processed_proposals WHERE processed_at > NOW() - INTERVAL '1 hour'`).

- [ ] **Step 1: Write failing tests.** Pin columns displayed (`proposal_type`, `proposal_id`, `result`, `failure_kind`, `operator_user_id`, `processed_at`). Pin `--recent` scoping. Pin the `status` footer addition.
- [ ] **Step 2:** Implement.
- [ ] **Step 3:** Add i18n catalog keys.
- [ ] **Step 4:** Run; confirm green.
- [ ] **Step 5: Commit.** `feat(cli): alfred supervisor proposals subcommand + status footer (#171)`.

### Task 10 — Integration round-trip + adversarial

**Files**:
- Create: `tests/integration/state/test_breaker_reset_proposal_roundtrip.py`
- Create: `tests/adversarial/state/test_dispatch_replay_safety.py`

- [ ] **Step 1: Write the integration round-trip** per spec §4.5. Include both the happy path and the failure path (unknown `component_id` returns `DispatchOutcome.failed`; verify ledger row + audit row + no re-dispatch on replay).
- [ ] **Step 2: Write the adversarial tests** per spec §4.6.
- [ ] **Step 3:** Run; confirm green.
- [ ] **Step 4: Commit.** `test(state): integration round-trip + adversarial for proposal dispatch (#171)`.

### Task 11 — Final QA + push + STOP

- [ ] **Step 1: Full quality bar.**
  ```bash
  cd "$(git rev-parse --show-toplevel)"
  uv run ruff check . && uv run ruff format --check .
  uv run mypy src/ && uv run pyright src/
  uv run pytest tests/unit/state/ tests/unit/cli/ tests/unit/supervisor/ tests/unit/audit/ tests/integration/state/ tests/adversarial/state/ -v
  uv run pytest tests/unit/ tests/integration/ \
    --cov=src/alfred/state/dispatch_registry \
    --cov=src/alfred/state/dispatch_loop \
    --cov=src/alfred/state/proposal_payloads \
    --cov=src/alfred/cli/supervisor \
    --cov-branch --cov-fail-under=100
  make check
  ```

- [ ] **Step 2: Commit log audit.** `git log --oneline main..HEAD`. Expected ~10 commits (one per task that produces commits, plus the docs commit).
- [ ] **Step 3: Push.** `git push -u origin issue-171-merged-proposal-dispatch`.
- [ ] **Step 4: STOP for user check-in.** Do NOT open the PR autonomously.

---

## §5 Post-PR follow-ups

- Auto-approval path for `BreakerResetProposal` (separate ADR).
- CLI retry command for failed proposals (`alfred state retry-proposal <type> <id>`).
- Wire `WebAllowlistProposal` / `ConfigSetProposal` runtime consumers through declarative projection (separate PR per type).
- Cross-process locking for multi-supervisor deployments (Slice 5).
- Multi-operator hardening: commit-signature verification, `operator_user_id` cross-check against committer email (separate ADR per ADR-0021 §Threat model).
- `alfred audit log` unblocked by PR-S3-7 — remove psql fallback from runbook once landed.
