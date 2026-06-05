# Runbook: alfred supervisor CLI (Slice 3)

**Status:** shipped in Slice 3 — `alfred supervisor status` reads Postgres
directly; `alfred supervisor reset` writes a reviewer-gated state.git
proposal (ADR-0021); `alfred supervisor proposals` lists recent dispatch
results.
**Spec:** [`docs/superpowers/specs/2026-06-05-supervisor-cli-access-design.md`](../superpowers/specs/2026-06-05-supervisor-cli-access-design.md)
**ADRs:** [ADR-0020](../adr/0020-supervisor-cli-access-via-postgres-and-state-git.md),
[ADR-0021](../adr/0021-merged-proposal-branch-dispatch-for-side-effecting-proposals.md)
**Subsystem:** [`docs/subsystems/supervisor.md`](../subsystems/supervisor.md)
**Glossary:** [CircuitBreaker / BreakerState / CircuitBreakerState](../glossary.md#circuitbreaker--breakerstate--circuitbreakerstate)

This runbook covers the operator surface for inspecting circuit-breaker state,
queuing a reset through the reviewer-gated dispatch loop, and auditing
dispatch results.

> **Slice-3 limitation — daemon boot wiring (#174).** The
> `_proposal_dispatch_loop` only runs when a `Supervisor` is
> constructed with a `state_git_path`. The daemon boot path that
> wires the production `state.git` location into the supervisor is
> tracked at [#174](https://github.com/alfred-os/AlfredOS/issues/174).
> Until #174 ships, the dispatch flow runs in tests and dev-local
> supervisor constructions but **NOT** in production deployments.
> Operators following this runbook on a production stack will queue
> proposals successfully, but the supervisor will not dispatch them
> until #174 lands.

## Three-channel architecture

`alfred supervisor` ships in Slice 3 with three commands. They reach the
running supervisor process via materially different mechanisms:

| Command | Channel | State |
|---|---|---|
| `alfred supervisor status` | Synchronous SQLAlchemy read against the `circuit_breakers` Postgres table | Working |
| `alfred supervisor reset <component> --confirm` | Writes a reviewer-gated `BreakerResetProposal` to state.git; the supervisor's `_proposal_dispatch_loop` picks up the merged branch on its next cycle (≤30s) and calls `Supervisor.reset_breaker` | Working (subject to #174 daemon boot wiring caveat above) |
| `alfred supervisor proposals [--since DURATION] [--limit N] [--all]` | Synchronous SQLAlchemy read against the `processed_proposals` Postgres table | Working |

The three commands all read or write Postgres or state.git; none acquires a
live `Supervisor` handle. See
[ADR-0020](../adr/0020-supervisor-cli-access-via-postgres-and-state-git.md)
and [ADR-0021](../adr/0021-merged-proposal-branch-dispatch-for-side-effecting-proposals.md)
for the channel design.

## `alfred supervisor status` — freshness contract

The rendered table reflects the supervisor's last `CircuitBreaker.save_to_db`
write to the `circuit_breakers` Postgres table. The CLI opens a sync
SQLAlchemy session against the same `DATABASE_URL` the supervisor uses, reads
the rows, closes the session, and renders the table — no IPC, no supervisor
handle.

Typical lag: **≤ 1 supervisor cycle** (i.e. the time between the supervisor's
last persisted breaker write and the operator's `status` invocation). This is
the same staleness model `alfred audit log` uses against the audit Postgres
projection. The CLI does NOT subscribe to a real-time push channel; operators
poll.

### Failure modes (in order of probability)

| Condition | Operator sees | Operator action |
|---|---|---|
| `DATABASE_URL` env var unset OR Postgres unreachable | `cli.supervisor.status.postgres_unavailable` + exit 1 | Check `alfred status`; verify the Postgres container is up; verify `DATABASE_URL` is exported to the CLI shell |
| `circuit_breakers` table empty | `cli.supervisor.status.no_components_yet` + exit 0 | Wait for the supervisor to register at least one component (the row appears on first `save_to_db`) |
| Row decode fails (schema drift) | Raw traceback | Programmer bug — file an issue; do NOT mask in the CLI surface |

The pre-#154 friendly hints `cli.supervisor.status.no_supervisor_running` and
`cli.supervisor.status.read_path_unavailable` retire — the CLI no longer
attempts to probe a supervisor handle, so the "supervisor not running"
disposition collapses into the `postgres_unavailable` disposition (the same
operator action applies).

## `alfred supervisor reset` — reviewer-gated proposal flow

`alfred supervisor reset <component> --confirm` queues a `BreakerResetProposal`
through the canonical state.git writer. The supervisor's
`_proposal_dispatch_loop` picks up the merged branch on its next cycle
(≤`proposal_dispatch_interval_s` seconds; default 30s) and calls
`Supervisor.reset_breaker(component_id, operator_user_id=...)`.

```bash
# Queue the reset.
alfred supervisor reset alfred.web-fetch --confirm
# Reviewer approves the proposal branch via the gh review flow.
# Wait one dispatch cycle.
alfred supervisor proposals --since 1h
```

The flow:

1. The CLI's `--confirm` gate enforces explicit operator intent (BLOCKER #6
   semantic preserved from #154).
2. The forensic-attempt audit row (`supervisor.breaker.reset.attempted`)
   fires BEFORE the proposal write so operator intent always lands in the
   audit graph — even if the state.git write fails mid-flight.
3. `BreakerResetProposal` lands at
   `policies/breaker-resets/<proposal_id>.json`. The reviewer-gate flow
   applies (reviewer agent + human approval on the proposal branch).
4. On merge, the supervisor's dispatch loop walks the diff, finds the new
   blob, calls `Supervisor.reset_breaker(...)`, emits the terminal
   `supervisor.breaker.reset` audit row, and inserts a
   `processed_proposals` ledger row with `result="applied"`.

### Failure investigation — `alfred supervisor proposals`

```bash
alfred supervisor proposals --since 24h
```

Renders the `processed_proposals` table for the chosen window. The
columns:

| Column | Meaning |
|---|---|
| `TYPE` | The `proposal_type` discriminator (`breaker-reset`, ...). |
| `ID` | The 16-hex `proposal_id` from the proposal branch. |
| `RESULT` | `applied` / `failed_handler` / `failed_parse` / `failed_unknown_type` (see legend printed after the table). |
| `FAILURE` | `failure_kind` discriminator on the failed rows. The six closed values are pinned at the storage layer by the ledger's `ck_processed_proposals_failure_kind` CHECK constraint and listed in spec [§2.5](../superpowers/specs/2026-06-05-merged-proposal-dispatch-design.md#25-ledger-schema) (`handler_returned_failed`, `handler_uncaught_exception`, `payload_validation`, `unknown_proposal_type`, `blob_not_found`, `handler_timeout`). |
| `OPERATOR` | Self-claimed `operator_user_id` from the proposal payload. |
| `PROCESSED AT` | Wall-clock timestamp of the dispatch cycle that processed the blob. |

The `failure_detail` column on the ledger holds the truncated reason
string (`type(exc).__name__` for an uncaught exception; the
closed-vocab reason for a handler-returned failure). DLP redaction of
this field is tracked at [#173](https://github.com/alfred-os/AlfredOS/issues/173);
today it is truncated only.

Flags:

* `--since DURATION` (default `1h`): accepts `Nm` / `Nh` / `Nd` / `Nw`.
* `--limit N` (default 20): bounds the row count.
* `--all`: forensic-export escape hatch; ignores `--since` and `--limit`.

### Workarounds during an active incident — tombstoned

The pre-Slice-3 workarounds (`docker compose restart alfred-supervisor` and
the direct `UPDATE circuit_breakers` Postgres mutation) are tombstoned. The
reviewer-gated path is the canonical surface; the Postgres mutation in
particular always leaves a gap in the audit graph because it bypasses both
the supervisor's in-memory state machine AND the `supervisor.breaker.reset`
audit row. Use `alfred supervisor reset --confirm`.

## Cross-references

- [ADR-0020](../adr/0020-supervisor-cli-access-via-postgres-and-state-git.md) — the architectural decision that initially scoped the supervisor CLI to status-only.
- [ADR-0021](../adr/0021-merged-proposal-branch-dispatch-for-side-effecting-proposals.md) — the merged-proposal-branch dispatch infrastructure that ships the active reset path.
- [#171](https://github.com/alfred-os/AlfredOS/issues/171) — the infrastructure work that landed the dispatch loop + replay ledger + `BreakerResetProposal`.
- [#174](https://github.com/alfred-os/AlfredOS/issues/174) — the deferred daemon boot wiring that supplies `state_git_path` to the production `Supervisor`.
- [#173](https://github.com/alfred-os/AlfredOS/issues/173) — the deferred DLP wiring on the dispatcher's `failure_detail` boundary.
- [`docs/subsystems/supervisor.md`](../subsystems/supervisor.md) — the supervisor's full architecture (breaker state machine, hookpoint registration, persistence model).
- [`PRD.md` §10.8](../../PRD.md) — operator-tier T1 commands and the forensic audit-row contract.
- Spec §10.6 — circuit-breaker persistence and the re-arm window flap-protection model.
