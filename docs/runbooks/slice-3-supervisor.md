# Runbook: alfred supervisor CLI (Slice 3, status-only)

**Status:** shipped in Slice 3 — `alfred supervisor status` reads Postgres
directly. `alfred supervisor reset` is deferred to [#171](https://github.com/alfred-os/AlfredOS/issues/171).
**Spec:** [`docs/superpowers/specs/2026-06-05-supervisor-cli-access-design.md`](../superpowers/specs/2026-06-05-supervisor-cli-access-design.md)
**ADR:** [ADR-0020](../adr/0020-supervisor-cli-access-via-postgres-and-state-git.md)
**Subsystem:** [`docs/subsystems/supervisor.md`](../subsystems/supervisor.md)
**Glossary:** [CircuitBreaker / BreakerState / CircuitBreakerState](../glossary.md#circuitbreaker--breakerstate--circuitbreakerstate)

This runbook covers the operator surface for inspecting circuit-breaker state
and the workaround for clearing a tripped breaker until the full reset path
ships in #171.

## Two-channel architecture

`alfred supervisor` ships in Slice 3 with two commands. They reach the running
supervisor process via materially different mechanisms:

| Command | Channel | State |
|---|---|---|
| `alfred supervisor status` | Synchronous SQLAlchemy read against the `circuit_breakers` Postgres table | Working |
| `alfred supervisor reset <component> --confirm` | Was originally scoped to a state.git proposal that the supervisor picks up; the dispatch infrastructure does not exist — deferred to [#171](https://github.com/alfred-os/AlfredOS/issues/171) | Returns a localised deferred-hint + exits 1; forensic-attempt audit row still emits |

The asymmetry is deliberate: the status path is independently shippable today
and operators benefit during incident response; the reset path needs the
missing merged-proposal-branch dispatch infrastructure to land properly. See
[ADR-0020](../adr/0020-supervisor-cli-access-via-postgres-and-state-git.md) for
the rationale that rejects shipping a half-baked reset path.

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

## `alfred supervisor reset` — deferred to #171

The command continues to ship the `--confirm` gate (operator intent is still
gated) and continues to emit the forensic-attempt audit row BEFORE printing
the deferred-hint — the CR-149 "operator attempted reset" forensic breadcrumb
still lands regardless of whether the reset itself proceeds.

After the audit row, the command prints
`cli.supervisor.reset.deferred_to_issue_171` and exits 1. The localised body
names the missing infrastructure (merged-proposal-branch dispatch), the two
workarounds, and the tracking issue. Exit code 1 reflects that the operator's
request was not fulfilled.

### Workarounds during an active incident

Operator wants to clear a tripped breaker NOW; #171 has not shipped. Two
options:

#### Option A — restart the supervisor

```bash
docker compose restart alfred-supervisor   # or whatever your deployment names it
```

`CircuitBreaker.load_from_db` honours the configured re-arm window per spec
§10.6. **A breaker tripped within the re-arm window stays OPEN after
restart** (flap protection). A breaker that has aged past the re-arm window
(default 1 h) transitions to HALF_OPEN at load and the supervisor's probe
scheduler exercises it. The audit-row symbol you see when the re-arm fires
inline is `supervisor.breaker.half_open`.

This is the lower-blast-radius option when the breaker is "stuck OPEN past
the re-arm window" rather than "tripped seconds ago and I need it back NOW".

#### Option B — direct Postgres update

```sql
UPDATE circuit_breakers
SET state = 'CLOSED'
WHERE component_id = '<component-id>';
```

This bypasses the `supervisor.breaker.reset` audit row that
`Supervisor.reset_breaker` emits via the hookpoint chain. **The operator
MUST manually log the action in the on-call channel for forensic
continuity** — including the timestamp, the component id, and the reason.
The PRD §10.8 forensic contract is the load-bearing invariant; the Postgres
mutation alone leaves a gap in the audit graph that only the operator's
manual log entry can fill. Operator attribution does not surface to a
column on the `circuit_breakers` schema today; #171 lands the attribution
path alongside the dispatch infrastructure (CR-156 round-7 BLOCKER #2 —
the SQL previously named `last_reset_at` and `last_reset_by` columns that
do not exist on the migration-0010 schema).

The supervisor's in-memory `CircuitBreaker` instance keeps its prior state
until it next reads from Postgres. The state machine reconciles on the next
`load_from_db` or supervisor restart, whichever comes first. If you need the
in-memory reconciliation now, combine Option B with Option A (update the
row, then restart).

## Cross-references

- [ADR-0020](../adr/0020-supervisor-cli-access-via-postgres-and-state-git.md) — the architectural decision that scoped this PR to status-only.
- [#171](https://github.com/alfred-os/AlfredOS/issues/171) — the deferred work: merged-proposal-branch dispatch + replay ledger + supervisor poll loop. `BreakerResetProposal` lands as the first user of that infrastructure.
- [`docs/subsystems/supervisor.md`](../subsystems/supervisor.md) — the supervisor's full architecture (breaker state machine, hookpoint registration, persistence model).
- [`PRD.md` §10.8](../../PRD.md) — operator-tier T1 commands and the forensic audit-row contract.
- Spec §10.6 — circuit-breaker persistence and the re-arm window flap-protection model.
