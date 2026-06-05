# Supervisor CLI access — implementation plan (revised, status-only)

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. CLI surface + Postgres-read path — TDD red/green per task is mandatory.

**Goal (revised):** Make `alfred supervisor status` functional via a synchronous Postgres read against the `circuit_breakers` table. Remove `_get_supervisor()`. Update `alfred supervisor reset`'s "not yet wired" hint to point at #171 (the missing dispatch infrastructure) instead of the obsolete PR-S3-3b reference.

**The reset path is deferred to [#171](https://github.com/alfred-os/AlfredOS/issues/171).** Implementation discovery (#154 first-attempt agent) surfaced that no merged-proposal-branch dispatch infrastructure exists in the codebase. Doing the reset path half-baked would perpetuate the existing half-shipped `WebAllowlistProposal` / `ConfigSetProposal` pattern. ADR-0020 (revised) explains the rationale.

**Architecture:** Status path is a sync SQLAlchemy read against the existing `circuit_breakers` Postgres table. Reset path is a forensic-attempt audit row + a localised "deferred to #171" hint + exit 1. The placeholder `_get_supervisor()` is deleted; the CLI no longer imports `Supervisor`.

**Tech Stack:** Python 3.14.5 • Typer (CLI) • SQLAlchemy 2.x sync sessions • pytest + testcontainers for the Postgres integration test.

**Spec anchor:** [`docs/superpowers/specs/2026-06-05-supervisor-cli-access-design.md`](../specs/2026-06-05-supervisor-cli-access-design.md) (revised)
**ADR:** [`docs/adr/0020-supervisor-cli-access-via-postgres-and-state-git.md`](../../adr/0020-supervisor-cli-access-via-postgres-and-state-git.md) (revised)

**Depends on:** Nothing (Postgres `circuit_breakers` table + migration 0010 already on main).
**Blocks:** Nothing in flight.
**Blocked path:** Reset functionality blocked on [#171](https://github.com/alfred-os/AlfredOS/issues/171).

---

## §1 Goal

After this PR:

1. `alfred supervisor status` reads `circuit_breakers` directly from Postgres and renders the rows. No supervisor handle. The friendly "supervisor not running" / "read path unavailable" hints retire; replaced by `postgres_unavailable` / `no_components_yet`.
2. `alfred supervisor reset <id> --confirm` continues to fail closed (exit 1) but now prints `cli.supervisor.reset.deferred_to_issue_171` — a long-form hint naming the missing infrastructure + the two workarounds (supervisor restart, direct Postgres update). The forensic-attempt audit row still emits before the hint per CR-149's pattern. `--confirm` still gates intent.
3. `_get_supervisor()` deleted. CLI no longer imports `Supervisor`. The PR-S3-3b dependency drops.
4. 100% line + branch on the new and modified code. Integration round-trip green for the status path.

---

## §2 File structure (revised)

| File | Status | Responsibility |
|---|---|---|
| `src/alfred/cli/supervisor.py` | Modify | Delete `_get_supervisor()`. Rewrite `_list_breaker_states()` body (sync SQLAlchemy read). Rewrite `supervisor_reset` body: keep `--confirm` gate + forensic-attempt audit row; remove the `_get_supervisor`/`asyncio.run`/lazy-import blocks; print the deferred hint; exit 1. Drop now-unused error-handling arms in `supervisor_status`. |
| `locale/en/LC_MESSAGES/alfred.po` | Modify | Add `cli.supervisor.status.postgres_unavailable`, `cli.supervisor.status.no_components_yet`, `cli.supervisor.reset.deferred_to_issue_171`. Tombstone deprecated keys. |
| `tests/unit/cli/test_supervisor_status.py` | Modify | Replace `NotImplementedError`-asserting tests with new sync-Postgres-read tests. |
| `tests/unit/cli/test_supervisor_reset.py` | Modify | Add deferred-hint test; drop `_get_supervisor`-mock tests. |
| `tests/integration/cli/test_supervisor_status_postgres_roundtrip.py` | Create | Real Postgres via testcontainers; insert breaker rows; assert status renders them. |
| `docs/adr/0020-...md` | Created already | (this PR's docs commit) |
| `docs/superpowers/specs/2026-06-05-...md` | Created already | (this PR's docs commit) |
| `docs/superpowers/plans/2026-06-05-...md` | Created already | (this file) |
| `docs/runbooks/slice-3-supervisor.md` | Create | Document freshness contract + deferred-reset state + workarounds + #171 link. |
| `docs/subsystems/supervisor.md` | Create | Architecture overview; status via Postgres; reset deferred to #171. Cross-reference ADR-0020. |
| `docs/glossary.md` | Modify if applicable | Add an entry for "merged-proposal-branch dispatch infrastructure" if other architecture terms are listed. |

**Files NO LONGER modified (per Option E):**

- `src/alfred/state/proposal_payloads.py` — `BreakerResetProposal` moved to #171.
- `src/alfred/cli/_state_git.py` — no new proposal type registration.
- Any supervisor-side file — supervisor untouched.
- `src/alfred/audit/event_vocabulary.py` — no new audit-vocab entries.

---

## §3 Definition of Done

- [ ] `uv run pytest tests/unit/cli/ -q` → green.
- [ ] `uv run pytest tests/integration/cli/test_supervisor_status_postgres_roundtrip.py` → green.
- [ ] 100% line + branch on the rewritten code (`_list_breaker_states`, `_with_sync_session`, the modified `supervisor_status` arms, the rewritten `supervisor_reset` body).
- [ ] `uv run ruff check . && uv run ruff format --check .` → clean.
- [ ] `uv run mypy src/ && uv run pyright src/` → clean.
- [ ] `make check` → green.
- [ ] Catalog keys present in `locale/en/LC_MESSAGES/alfred.po` with real msgstrs; `pybabel compile` produces a fresh `.mo`.
- [ ] Conventional Commits + `#154` in every subject + no `fixup!` survivors.
- [ ] User check-in before opening the PR.

---

## §4 Tasks (revised — 4 tasks down from 8)

### Task 1 — Docs commit (ADR + spec + plan + runbook + subsystem)

**Files**:
- Created: `docs/adr/0020-supervisor-cli-access-via-postgres-and-state-git.md` (revised)
- Created: `docs/superpowers/specs/2026-06-05-supervisor-cli-access-design.md` (revised)
- Created: `docs/superpowers/plans/2026-06-05-supervisor-cli-access.md` (this file, revised)
- Create: `docs/runbooks/slice-3-supervisor.md`
- Create: `docs/subsystems/supervisor.md`
- Modify if applicable: `docs/glossary.md`

- [ ] **Step 1**: Write `docs/runbooks/slice-3-supervisor.md`. Cover:
  - The two-channel split: status via Postgres (works now); reset via state.git proposal (deferred to #171).
  - Status freshness contract: rows reflect supervisor's last `save_to_db` write; typically lags by ≤1 supervisor cycle.
  - Reset workarounds during incident response:
    - Restart the supervisor — `CircuitBreaker.load_from_db` honours the configured window per spec §10.6, so a previously-tripped breaker stays OPEN; the supervisor will probe HALF_OPEN on schedule.
    - Direct Postgres update — `UPDATE circuit_breakers SET state='CLOSED', last_reset_at=now(), last_reset_by='<operator>' WHERE component_id=...`. Document that this bypasses the `supervisor.breaker.reset` audit row; operators MUST manually log the action in the on-call channel for forensic continuity.
  - Cross-reference #171 explicitly: "Full `alfred supervisor reset` lands once #171 ships the merged-proposal-branch dispatch infrastructure."

- [ ] **Step 2**: Write `docs/subsystems/supervisor.md`. Architecture overview; status via Postgres; reset path deferred to #171; cross-reference ADR-0020.

- [ ] **Step 3**: Update `docs/glossary.md` if other architecture terms are listed. Add an entry for "merged-proposal-branch dispatch infrastructure" pointing at #171.

- [ ] **Step 4**: Commit.
  ```bash
  cd "$(git rev-parse --show-toplevel)"
  git add docs/
  git commit -m "docs(supervisor): ADR-0020 + spec + plan for CLI access via Postgres (status-only; #154)

  Implementation discovery surfaced that no merged-proposal-branch
  dispatch infrastructure exists in the codebase. ADR-0020 revised:
  ship status-only via Postgres now; defer reset path to #171 which
  scopes the dispatch + ledger + polling-loop infrastructure
  properly. Doing the reset path half-baked would perpetuate the
  existing half-shipped WebAllowlistProposal / ConfigSetProposal
  pattern.

  Refs: #154, #171

  MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
  ```

### Task 2 — `_list_breaker_states` sync Postgres read

**Files**:
- Modify: `src/alfred/cli/supervisor.py`
- Modify: `tests/unit/cli/test_supervisor_status.py`

- [ ] **Step 1: Write failing tests** per spec §5.1:
  - `test_list_breaker_states_returns_rows_from_postgres` — fixture inserts 2 rows; assert returned shape.
  - `test_list_breaker_states_returns_empty_on_empty_table`.
  - `test_list_breaker_states_raises_operational_error_on_postgres_unavailable` — patch sessionmaker to raise `OperationalError` on `__enter__`; assert propagation.
  - Delete every test that asserts `_list_breaker_states` raises `NotImplementedError`.

- [ ] **Step 2**: Run; confirm failure.

- [ ] **Step 3**: Implement `_list_breaker_states` body per spec §3.2. Add `_with_sync_session` helper. Add `_resolve_database_url` helper if not present (read from `DATABASE_URL` env var; raise `RuntimeError` with localised message if unset).

- [ ] **Step 4**: Update `supervisor_status` handler arms. Drop the `_get_supervisor` probe entirely. Drop the `NotImplementedError` arm for `_list_breaker_states`. Add `OperationalError` arm → `t("cli.supervisor.status.postgres_unavailable")`.

- [ ] **Step 5**: Add catalog keys `cli.supervisor.status.postgres_unavailable` + `cli.supervisor.status.no_components_yet` to `locale/en/LC_MESSAGES/alfred.po` with real msgstrs. Tombstone `cli.supervisor.status.no_supervisor_running` + `cli.supervisor.status.read_path_unavailable`. Run `pybabel update` + `pybabel compile`.

- [ ] **Step 6**: Run; confirm green. Coverage on `_list_breaker_states` should be 100%.

- [ ] **Step 7**: Commit.
  ```bash
  git add src/alfred/cli/supervisor.py tests/unit/cli/test_supervisor_status.py locale/
  git commit -m "feat(cli): supervisor status reads circuit_breakers directly from Postgres (#154)

  Replace the placeholder _list_breaker_states (NotImplementedError)
  with a sync SQLAlchemy read against the circuit_breakers table.
  No supervisor handle needed. Drop the _get_supervisor probe from
  supervisor_status. Add postgres_unavailable + no_components_yet
  catalog keys; tombstone the obsolete hints.

  Status freshness contract documented in runbook: rows reflect
  supervisor's last save_to_db write; typically lags by ≤1 cycle.

  Refs: #154

  MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
  ```

### Task 3 — `supervisor_reset` deferred-hint update + delete `_get_supervisor`

**Files**:
- Modify: `src/alfred/cli/supervisor.py`
- Modify: `tests/unit/cli/test_supervisor_reset.py`
- Modify: `locale/en/LC_MESSAGES/alfred.po`

- [ ] **Step 1: Write failing tests** per spec §5.2:
  - `test_supervisor_reset_emits_forensic_attempt_audit_row_then_prints_deferred_hint_and_exits_nonzero` — assert: (a) `_emit_breaker_reset_attempt_audit` ran, (b) the deferred-hint copy appears, (c) `exit code == 1`, (d) NO `_get_supervisor` call, (e) NO `asyncio.run` call.
  - `test_supervisor_reset_skips_audit_row_and_hint_without_confirm` — `--confirm` not set: existing confirm-prompt behaviour preserved.
  - Delete every test that mocks `_get_supervisor` for the reset path.

- [ ] **Step 2**: Run; confirm failure.

- [ ] **Step 3**: Rewrite `supervisor_reset` body. Keep:
  - The `--confirm` gate + the existing confirm-prompt / rerun-hint copy.
  - The forensic-attempt audit row emission via `_emit_breaker_reset_attempt_audit`.

  Remove:
  - The `_get_supervisor()` probe and its `except (RuntimeError, ConnectionError, TimeoutError)` arm.
  - The `from alfred.supervisor.errors import (NoSuchComponentError, SupervisorError)` lazy import block.
  - The `asyncio.run(supervisor.reset_breaker(...))` block + all its except arms.

  Replace with:
  ```python
  _emit_breaker_reset_attempt_audit(component_id=component_id)
  typer.echo(t("cli.supervisor.reset.deferred_to_issue_171", component=component_id), err=True)
  raise typer.Exit(code=1)
  ```

- [ ] **Step 4**: Add catalog key `cli.supervisor.reset.deferred_to_issue_171` to `locale/en/LC_MESSAGES/alfred.po`. Long-form copy per spec §2.2 (operator sees it once and learns the workaround). Tombstone the now-unused `cli.supervisor.reset.component_not_found` + `cli.supervisor.reset.unexpected_error` (per spec §4). Run `pybabel update` + `pybabel compile`.

- [ ] **Step 5**: Delete `_get_supervisor()` function from `src/alfred/cli/supervisor.py`. Delete `from alfred.supervisor.core import Supervisor` import (if not used elsewhere). Verify no remaining call sites: `grep -n "_get_supervisor" src/alfred/cli/supervisor.py` → zero.

- [ ] **Step 6**: Run; confirm green.

- [ ] **Step 7**: Commit.
  ```bash
  git add src/alfred/cli/supervisor.py tests/unit/cli/test_supervisor_reset.py locale/
  git commit -m "refactor(cli): supervisor reset now hints at #171 deferral; drop _get_supervisor (#154)

  The reset path was waiting on the never-shipped PR-S3-3b
  Supervisor.get_instance. Implementation discovery (ADR-0020 revised)
  surfaced that the merged-proposal-branch dispatch infrastructure
  required for the proposal-flow design also doesn't exist —
  tracked at #171.

  Until #171 lands, supervisor reset emits the forensic-attempt audit
  row, prints a long-form localised hint naming the workaround
  (supervisor restart or direct Postgres update), and exits 1. The
  --confirm gate is preserved.

  Delete the _get_supervisor placeholder and the now-unused lazy
  imports of NoSuchComponentError / SupervisorError. CLI no longer
  imports Supervisor.

  Refs: #154, #171

  MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
  ```

### Task 4 — Integration round-trip + final QA + push + STOP

**Files**:
- Create: `tests/integration/cli/test_supervisor_status_postgres_roundtrip.py`

- [ ] **Step 1: Integration round-trip test** per spec §5.3. Real Postgres via testcontainers; insert two `CircuitBreakerState` rows; assert `alfred supervisor status` renders them.

- [ ] **Step 2: Full quality bar.**
  ```bash
  cd "$(git rev-parse --show-toplevel)"
  uv run ruff check . && uv run ruff format --check .
  uv run mypy src/ && uv run pyright src/
  uv run pytest tests/unit/cli/ -v
  uv run pytest tests/integration/cli/test_supervisor_status_postgres_roundtrip.py -v
  uv run pytest tests/unit/cli/ --cov=src/alfred/cli/supervisor --cov-branch --cov-fail-under=100
  make check
  ```

- [ ] **Step 3: Commit + log audit.** `git log --oneline main..HEAD` — every commit Conventional, contains `#154`, no `fixup!` survivors. Expected 4 commits (Task 1 docs, Task 2 status, Task 3 reset/get_supervisor, Task 4 integration test).

- [ ] **Step 4: Push.** `git push -u origin issue-154-supervisor-cli-access`.

- [ ] **Step 5: STOP for user check-in.** Do NOT open the PR autonomously. Report branch + commit log + gate status.

---

## §5 Post-PR follow-ups (not in this PR's scope)

- **#171** — merged-proposal-branch dispatch infrastructure + replay ledger + supervisor poll loop. `BreakerResetProposal` lands as the first user of the registry once that infrastructure ships. Also closes the half-shipped `WebAllowlistProposal` / `ConfigSetProposal` runtime-consumer gap.
- **#153** — Authenticated CLI session for `operator_user_id`.
- IPC channel between CLI and supervisor (rejected per ADR-0020 alternatives).
- Real-time CLI push notifications (no current need).
