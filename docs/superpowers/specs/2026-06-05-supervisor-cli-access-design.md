# Supervisor CLI access — design (revised, status-only)

**Date:** 2026-06-05 (revised after implementation discovery)
**Closes:** [#154](https://github.com/alfred-os/AlfredOS/issues/154) (status path only)
**Defers:** Reset path → [#171](https://github.com/alfred-os/AlfredOS/issues/171)
**ADR:** [`docs/adr/0020-supervisor-cli-access-via-postgres-and-state-git.md`](../../adr/0020-supervisor-cli-access-via-postgres-and-state-git.md)
**Plan:** [`docs/superpowers/plans/2026-06-05-supervisor-cli-access.md`](../plans/2026-06-05-supervisor-cli-access.md)

## 1. What this is for

Make `alfred supervisor status` functional in production by routing it through a synchronous Postgres read against the `circuit_breakers` table. Removes the `_get_supervisor()` placeholder whose `RuntimeError` makes the operator surface non-functional today. Updates `alfred supervisor reset`'s "not yet wired" hint to point at #171 (the actual architectural blocker) instead of the obsolete PR-S3-3b reference.

**The full reset path is deferred to [#171](https://github.com/alfred-os/AlfredOS/issues/171)** — implementation discovery surfaced that AlfredOS has no infrastructure for "on merged proposal branch, run handler X" (see ADR-0020 §Discovery for evidence). Doing it half-baked would perpetuate the existing half-shipped `WebAllowlistProposal` / `ConfigSetProposal` pattern. #171 scopes the dispatch + ledger + polling infrastructure properly; `BreakerResetProposal` lands as the first user of that registry.

## 2. Architecture

### 2.1 `alfred supervisor status` — synchronous Postgres read

```
alfred supervisor status
    └─ _list_breaker_states()   ← sync SQLAlchemy session
       └─ SELECT * FROM circuit_breakers
          (live data — supervisor writes via CircuitBreaker.save_to_db)
```

- No supervisor handle.
- No async runtime in the CLI.
- Sync SQLAlchemy session created from the same `DATABASE_URL` the supervisor uses; closed before returning rows.
- Returns a list of `BreakerStateRow` dicts (typed via `TypedDict`); the existing rendering code at `supervisor_status` consumes them unchanged.

**Freshness contract** — Status reflects the supervisor's last `save_to_db` write. Typically lags by ≤1 supervisor cycle. Runbook documents this; same model as `alfred audit log`.

**Failure modes** (in order of probability):

| Condition | Disposition |
| --- | --- |
| `DATABASE_URL` unset / Postgres unreachable | `t("cli.supervisor.status.postgres_unavailable")` + `exit 1` |
| `circuit_breakers` table empty | `t("cli.supervisor.status.no_components_yet")` + `exit 0` |
| Row decode fails (schema drift) | propagate (programmer bug) |

The current "supervisor not running" + "read path unavailable" friendly hints both retire. New copy: "Postgres unavailable" (operator action: check stack) and "No components registered yet" (operator action: wait for supervisor to write first state).

### 2.2 `alfred supervisor reset` — hint update only (defer to #171)

The command continues to return a localised "not yet wired" hint, with:

- The `--confirm` flag still gating intent (unchanged).
- The forensic-attempt audit row still emitting BEFORE the deferred-hint print (preserves the CR-149 "operator attempted reset" forensic breadcrumb).
- The hint copy updated to name the actual architectural blocker:

> *"Circuit-breaker reset via state.git proposal is not yet wired. The supervisor needs merged-proposal-branch dispatch infrastructure (tracked at #171) to pick up the request. Workaround during incident response: restart the supervisor (the breaker stays OPEN within the configured window per spec §10.6) or update the `circuit_breakers` row directly. Runbook: docs/runbooks/slice-3-supervisor.md."*

(The exact copy lives in `locale/en/LC_MESSAGES/alfred.po` under `cli.supervisor.reset.deferred_to_issue_171`. Long-form hint; operator sees it once and learns the workaround.)

- Exit code: 1 (non-zero — the request is not fulfilled).
- The `_get_supervisor()` probe is REMOVED. The `asyncio.run(supervisor.reset_breaker(...))` block is REMOVED. The lazy import of `NoSuchComponentError` / `SupervisorError` is REMOVED. The reset command is now a forensic-attempt audit row + a hint + exit 1.

## 3. New types + modules (status only)

### 3.1 `BreakerStateRow` typed dict

Add to `src/alfred/cli/supervisor.py`:

```python
class BreakerStateRow(TypedDict):
    """The columns `supervisor_status` reads from `circuit_breakers`.

    Field set matches the rendering code's current shape so the change is
    a pure data-source swap (the renderer doesn't change). The renderer
    legacy key ``component`` maps to the Postgres column ``component_id``
    on the read path; the helper translates one to the other so the
    rendering code does not have to know whether the source is live
    Postgres rows, a mock, or a placeholder.
    """

    component: str
    state: str           # CLOSED | OPEN | HALF_OPEN
    trip_count: int
    last_trip_at: datetime | None
```

> CR-156 round-7 BLOCKER #2: an earlier draft of this spec named
> ``last_reset_at`` and ``last_reset_by`` columns. Those fields do NOT
> exist on the shipped ``circuit_breakers`` schema (migration 0010 — see
> ``src/alfred/memory/models.py:264-344`` for the canonical column set:
> ``component_id``, ``state``, ``trip_count``, ``last_trip_at``,
> ``last_failure_type``, ``breaker_state``, ``correlation_id``).
> Reset-metadata fields don't exist on the schema today; #171's work
> introduces them if needed when the dispatch-and-attribution path
> lands.

### 3.2 `_list_breaker_states` rewrite

Replace the `NotImplementedError`-raising body with a sync SQLAlchemy read. Connection management lives in `_with_sync_session()` (new helper):

```python
def _with_sync_session() -> Iterator[Session]:
    """Create a sync SQLAlchemy session against DATABASE_URL.

    The CLI runs without the async runtime, so we use synchronous
    sessionmaker bound to a sync engine constructed from the same URL the
    supervisor uses. Closed via `with`.
    """
    engine = create_engine(_resolve_database_url(), pool_pre_ping=True)
    Session_ = sessionmaker(bind=engine, expire_on_commit=False)
    with Session_() as session:
        yield session
    engine.dispose()
```

Failure modes funnel through narrow `except` arms: `OperationalError` → `postgres_unavailable`; row decode → propagate.

### 3.3 No new proposal payload, no new pickup handler

Both `BreakerResetProposal` (originally spec §3.1) and `_handle_breaker_reset` (originally spec §4) are **dropped from this PR**. They land in #171 alongside the dispatch infrastructure.

## 4. CLI rewrite — diff scope (revised)

Files modified (CLI side):

| File | Change |
| --- | --- |
| `src/alfred/cli/supervisor.py` | Remove `_get_supervisor()` entirely. Rewrite `_list_breaker_states()` body (sync SQLAlchemy read). Update `supervisor_status` handler arms to drop the probe + the `NotImplementedError` arm. Update `supervisor_reset` body to remove the `_get_supervisor`/`asyncio.run`/lazy-import blocks; keep the `--confirm` gate + forensic-attempt audit row; print the new `cli.supervisor.reset.deferred_to_issue_171` hint; exit 1. |
| `locale/en/LC_MESSAGES/alfred.po` | Add new catalog keys: `cli.supervisor.status.postgres_unavailable`, `cli.supervisor.status.no_components_yet`, `cli.supervisor.reset.deferred_to_issue_171`. Tombstone deprecated keys (`cli.supervisor.reset.confirm_prompt`, `cli.supervisor.reset.rerun_hint`, `cli.supervisor.reset.component_not_found`, `cli.supervisor.reset.unexpected_error`, and the `cli.supervisor.status.no_supervisor_running` + `cli.supervisor.status.read_path_unavailable` pair) per the existing tombstoning pattern. |

Files modified (supervisor side):

| File | Change |
| --- | --- |
| (none) | Supervisor side untouched. `Supervisor.reset_breaker` stays as-is (called from tests directly + by #171's dispatch infrastructure when that lands). |

Files modified (audit vocab):

| File | Change |
| --- | --- |
| (none likely) | No new audit-vocab entries — the existing forensic-attempt row stays unchanged. |

Docs / runbooks:

| File | Change |
| --- | --- |
| `docs/runbooks/slice-3-supervisor.md` | Document the freshness contract for `status` + the "reset deferred to #171" state + the two workarounds (supervisor restart, direct Postgres update). |
| `docs/subsystems/supervisor.md` | Architecture overview: read via Postgres now; reset path deferred to #171's dispatch infrastructure. Cross-reference ADR-0020. |
| `docs/glossary.md` | Add an entry naming the "merged-proposal-branch dispatch infrastructure" (the missing piece) if other architecture terms are listed. |

## 5. Tests

### 5.1 Unit — `_list_breaker_states` (Postgres read)

Replace existing tests that assert `NotImplementedError` from `_list_breaker_states` with:

- `test_list_breaker_states_returns_rows_from_postgres` — populated fixture: assert each row matches `BreakerStateRow` shape.
- `test_list_breaker_states_returns_empty_on_empty_table` — empty fixture.
- `test_list_breaker_states_raises_on_postgres_unavailable` — patch the session factory to raise `OperationalError`; assert the CLI handler catches it and emits the localised `postgres_unavailable` message.

### 5.2 Unit — `supervisor_reset` deferred hint

- `test_supervisor_reset_emits_forensic_attempt_audit_row_then_prints_deferred_hint_and_exits_nonzero` — assert: (a) the existing `_emit_breaker_reset_attempt_audit` runs, (b) the deferred hint copy appears, (c) `exit code == 1`, (d) NO `_get_supervisor` call, (e) NO `asyncio.run` call.
- `test_supervisor_reset_skips_audit_row_and_hint_without_confirm` — `--confirm` not set: existing behaviour (confirm prompt + rerun hint or its successor) preserved.
- Delete every test that mocks `_get_supervisor` for the reset path.

### 5.3 Integration — status round-trip (status only)

`tests/integration/cli/test_supervisor_status_postgres_roundtrip.py`:

- Set up a real Postgres via testcontainers.
- Insert two `CircuitBreakerState` rows: one CLOSED, one OPEN with `trip_count=3`.
- Run `alfred supervisor status`; capture stdout.
- Assert both rows appear with the expected state strings.
- Insert a third row mid-test (simulating supervisor write); re-run `alfred supervisor status`; assert it appears.

No integration test for the reset path (#171's scope).

### 5.4 Adversarial — none in this PR

The adversarial tests originally scoped for the proposal-pickup path move to #171. The status-only PR doesn't introduce a new trust surface to attack.

## 6. Out of scope (explicitly)

- **Full reset path via state.git proposal.** Tracked at #171.
- **`BreakerResetProposal` payload type.** Tracked at #171.
- **Supervisor proposal-pickup loop + replay ledger.** Tracked at #171.
- **`WebAllowlistProposal` and `ConfigSetProposal` runtime consumers** (the same half-shipped gap). Also tracked at #171.
- **Authenticated CLI session for `operator_user_id`.** Tracked at #153.
- **Real-time CLI push notifications.** Operator polls.

## 7. Coverage / quality bar

- 100% line + branch on `_list_breaker_states`, `_with_sync_session`, the rewritten `supervisor_status` handler arms, and the rewritten `supervisor_reset` body.
- Integration round-trip green.
- All operator-facing strings via `t()` with real msgstrs in `locale/en/LC_MESSAGES/alfred.po`.

## 8. Migration / backwards compat

- The `circuit_breakers` Postgres schema is unchanged. Migration 0010 already in production.
- `Supervisor.reset_breaker` signature unchanged.
- The CLI commands `alfred supervisor status` and `alfred supervisor reset` exist today but return errors:
  - Status: error → working (graceful enhancement).
  - Reset: error → different error (the new copy points at #171). Operators get a clearer forward path, but the command still doesn't succeed until #171 lands. Runbook documents the workaround.

## 9. References

- ADR-0018 — state.git proposal writer consolidation.
- ADR-0020 — revised decision (status-only; reset deferred).
- Issue #154 — original CR-149 round-9 finding.
- Issue #171 — merged-proposal-branch dispatch infrastructure (deferred reset path lives here).
- `src/alfred/cli/plugin.py` — proposal-writer precedent (the CLI side; runtime consumer is also half-shipped per #171).
- `src/alfred/supervisor/core.py:461+` — `Supervisor.reset_breaker` implementation (called from #171's dispatch infrastructure when that lands).
- `src/alfred/memory/models.py:264-344` — `CircuitBreakerState` ORM model.
- `src/alfred/security/capability_gate/_gate.py:229+` — `RealGate.rebuild_from_state_git` (the only existing state.git → runtime path; declarative projection only).
