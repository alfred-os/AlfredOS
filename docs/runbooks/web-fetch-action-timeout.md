# Runbook: action-deadline timeout on `tool.dispatch` (`web.fetch`)

> **[2026-07-07 — #339 PR4b-audit, #347 blocker 2]** When a live `web.fetch` tool
> dispatch overruns its per-action deadline, the orchestrator writes a single
> **enriched, non-skippable** `tool.dispatch` audit row so the in-doubt side effect
> (the fetch may already have fired before the deadline) is forensically auditable
> (HARD rule #7). See the 2026-07-07 amendment to
> [ADR-0041](../adr/0041-web-fetch-fused-fetch-extract-contract.md) and
> [docs/subsystems/security.md](../subsystems/security.md#trust-boundary-contract).

> **Audit row signal:** `event="tool.dispatch"` with
> `subject.dispatch_outcome="timeout"` (enriched) or `"unexpected_timeout"`
> (defensive fallback), `result="refused"`. The enriched row uses the
> `TOOL_DISPATCH_TIMEOUT_FIELDS` schema and carries `egress_id`,
> `destination_host`, `in_doubt`, and `ledger_state`.

## What it means

A `web.fetch` call's fused fetch+extract exceeded `action_deadline_seconds`
(default 30s). Two outcomes distinguish the cause:

- **`dispatch_outcome="timeout"`** — the well-understood action-deadline overrun,
  raised as the typed `WebFetchActionTimeout`. This is the enriched row.
- **`dispatch_outcome="unexpected_timeout"`** — a bare `TimeoutError` from an
  *unexpected* source (not the web.fetch action-deadline path). This is a
  bug-shaped signal: it is still audited (HARD rule #7 totality) and emits a loud
  `structlog` warning (`orchestrator.tool_dispatch.unexpected_timeout`), but it
  carries none of the forensic fields (it stays on the generic
  `TOOL_DISPATCH_FIELDS` schema). Investigate the warning log.

## What `in_doubt` means for you

The action deadline wraps the whole fetch+extract. The gateway relay commits its
egress-idempotency intent **before** it fires the network call, so the ledger
state tells you whether the side effect may have happened:

| `in_doubt` | `ledger_state` | Meaning | Retry safety |
| --- | --- | --- | --- |
| `True` | `committed_no_response` | The call was committed and the network fire was attempted, but no response was recorded — **the fetch may have hit the origin.** | A retry is a *second* request to the origin. Safe only for an idempotent GET (web.fetch is GET-only today); treat as at-least-once. |
| `True` | `read_unavailable` | The deadline fired AND the post-timeout ledger read itself failed (correlated DB stress). Outcome unknown; **conservatively treated as maybe-fired.** | Same as above — assume the fetch may have fired. Check DB health (see the `web_fetch.timeout.ledger_read_failed` log). |
| `False` | `None` | The deadline fired before the call was ever committed — **the network was never touched.** | A retry is a fresh first attempt. Safe. |
| `False` | `committed_with_response` | The call completed (response recorded) but the deadline landed in a later phase. | The fetch succeeded; the timeout is downstream. |

## What it does NOT mean

- **Not a security event.** A canary trip surfaces as
  `dispatch_outcome="canary_tripped"` — different, and it halts the turn.
- **Not a per-user rate limit.** That is `dispatch_outcome="rate_limited"`
  (see [handle-cap-exceeded.md](handle-cap-exceeded.md)).
- **`unexpected_timeout` is not the normal web.fetch timeout** — the normal one is
  always the typed `WebFetchActionTimeout` → `dispatch_outcome="timeout"`.

## The action-deadline vs relay-timeout interaction

The enriched timeout row is produced **only when the action deadline is the
tighter bound.** The gateway relay client has its own per-call
`asyncio.timeout` (`_DEFAULT_PER_CALL_TIMEOUT = 30.0` in
`src/alfred/egress/relay_client.py`), the same default as
`action_deadline_seconds`. If an operator raises `action_deadline_seconds` **above**
the relay per-call timeout, the relay's timeout fires first and raises
`RelayIOPlaneUnavailableError` (a generic `unexpected_error`/`fault` row) — **not**
the enriched timeout row. So raise the relay per-call timeout **together with**
`action_deadline_seconds`, never on its own.

**Do not simply lower `action_deadline_seconds` to restore the enriched row.**
Since #340 PR2b-golive the value is bounded on BOTH sides and
`alfred config set action-deadline` refuses anything outside `29 < value < 50`:

| Bound | Value | Why |
| --- | --- | --- |
| Floor | `> 29` | broker preamble (4s) **+** host read-frame (25s) — they run sequentially, so a lower deadline tears a healthy extraction |
| Ceiling | `< 50` | `2 x` host read-frame — `read_frame` bounds header and body reads separately, and only this deadline caps a wedged child |

The floor (29) sits just below the relay default (30), so out of the box **30 is
the only value that satisfies both this window and the relay interaction** — which
is exactly why raising the deadline means raising the relay timeout too. Both
bounds are also documented at the `orchestrator.action_deadline_seconds` knob in
`config/policies.yaml`.

## How to inspect

The operator CLI (`alfred audit log` / `graph`) does not yet render
`dispatch_outcome` or the new forensic fields (a tracked follow-up — see
[security.md](../subsystems/security.md#trust-boundary-contract)); use a direct
audit-DB query today.

1. **Enriched timeout rows for a turn / user:**

   ```sql
   SELECT created_at,
          subject->>'dispatch_outcome' AS outcome,
          subject->>'destination_host' AS host,
          subject->>'in_doubt'         AS in_doubt,
          subject->>'ledger_state'     AS ledger_state,
          subject->>'egress_id'        AS egress_id,
          subject->>'correlation_id'   AS cid
   FROM audit_log
   WHERE event = 'tool.dispatch'
     AND subject->>'dispatch_outcome' IN ('timeout', 'unexpected_timeout')
     AND created_at > now() - interval '1 hour'
   ORDER BY created_at DESC;
   ```

2. **Correlate an `egress_id` to the ledger** (was the side effect committed?):

   ```sql
   SELECT egress_id, state, committed_at
   FROM egress_idempotency
   WHERE egress_id = '<egress_id from the audit row>';
   ```

   `state = 'committed_no_response'` confirms the in-doubt fire; a
   `'committed_with_response'` row means it actually completed.

3. **Ledger-read failures** (the `read_unavailable` case) surface a loud log:

   ```text
   web_fetch.timeout.ledger_read_failed  egress_id=... error_type=... correlation_id=...
   ```

   `error_type` distinguishes the failure class; investigate Postgres health
   (the read is bounded by `_LEDGER_READ_TIMEOUT_SECONDS`, default 5s).

## Common causes

| Cause | Signal | Remediation |
| --- | --- | --- |
| Slow origin exceeding the action deadline | `dispatch_outcome="timeout"`, `in_doubt=True`, `committed_no_response`, `fire` happened | Expected under a slow origin; if chronic, raise `action_deadline_seconds` AND the relay per-call timeout together (see the interaction section) |
| Action deadline raised above the relay timeout | Generic `unexpected_error`/`fault` rows instead of enriched timeout rows; `RelayIOPlaneUnavailableError` in logs | Raise the relay per-call timeout to match. Do NOT lower `action_deadline_seconds` below 30 — the CLI refuses anything ≤ 29 (see the interaction section) |
| Correlated DB stress at deadline time | `ledger_state="read_unavailable"`, `web_fetch.timeout.ledger_read_failed` log | Investigate Postgres health; the in-doubt fact is preserved conservatively |
| A stray bare `TimeoutError` from an unexpected code path | `dispatch_outcome="unexpected_timeout"` + `orchestrator.tool_dispatch.unexpected_timeout` warning | A latent bug — investigate the warning; not the normal web.fetch path |

## Audit vocabulary widening

This release widens the `tool.dispatch` outcome vocabulary and adds a forensic
field superset. Operators with downstream filters / SIEM rules MUST extend their
allow-lists:

- `ToolDispatchOutcome`: added `unexpected_timeout` (alongside the existing
  `timeout` and the other outcomes).
- New schema `TOOL_DISPATCH_TIMEOUT_FIELDS` (`TOOL_DISPATCH_FIELDS | {egress_id,
  destination_host, in_doubt, ledger_state}`) on the enriched timeout row.

Both are typed via `typing.Literal[...]` / `Final[frozenset[str]]` in
`src/alfred/audit/audit_row_schemas.py` (canonical source); type-check time
catches drift.

## Idempotent re-fire across a future #338 resume

The in-doubt `committed_no_response` ledger row is durable. On a future #338
resume, the same `egress_id` re-derives; because `web.fetch` builds its request
with `idempotent=True`, the relay forwards `egress_id` as the remote
`Idempotency-Key` and **re-fires** rather than refusing. One logical call can
therefore produce a second audit trail across the resume boundary — do not assume
a fired-once guarantee at the audit-row level. #338's replay-journaling design
owns this.

## Related runbooks

- [handle-cap-exceeded.md](handle-cap-exceeded.md) — the per-user concurrency cap
  (`rate_limited` / `handle_cap_exceeded`).
- [slice-3-operator-migration.md](slice-3-operator-migration.md)
