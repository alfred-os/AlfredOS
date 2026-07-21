# Runbook: quarantine capability revoked (`QuarantineCapabilityRevoked`)

> **[2026-07-20 — #340 PR2b-golive]** The quarantined-LLM child was torn down to
> revoke the gateway sockets it held over SCM_RIGHTS. This is fail-closed and
> correct, but it is **terminal for the quarantine path until `alfred-core` is
> restarted**. See
> [ADR-0052](../adr/0052-real-quarantine-child-golive.md) and
> [ADR-0050](../adr/0050-quarantine-child-scm-rights-reachability-broker.md).

> **Signals.** Metric `alfred_quarantine_capability_revoked_total` (alert rule
> `ops/alerts/quarantine.yml`); structlog event
> `security.quarantine_transport.capability_revoked`; audit rows
> `egress.broker.refused`.
>
> **[2026-07-21 — #472 finding 2]** The teardown is now cancellation-safe. Two extra
> structlog events flag the non-clean teardown paths:
> `security.quarantine_transport.revoke_cancelled` (the revoke was **cancelled
> mid-teardown** — any cancellation source: a daemon-stop force-cancel, a `TaskGroup`
> sibling failure, or an outer `action_deadline`; the SIGKILL was completed
> synchronously anyway, then the cancel re-raised) and
> `security.quarantine_transport.capability_abort_failed` (the synchronous last-resort
> kill's guard fired — because `abort()` **suppresses** `ProcessLookupError`/`OSError`,
> reaching this means the child-IO **seam itself is malformed** (a code/wiring bug, e.g.
> an `AttributeError`), **not** a mere OS hiccup; the child's liveness is then **unknown**
> — see the `capability_abort_failed` triage step below).

## ⚠ Read first: the alert cannot fire yet

`alfred_quarantine_capability_revoked_total` is registered in the **core**
process, and nothing scrapes the core — `ops/prometheus/prometheus.yml` has a
single job for `alfred-gateway:9464`, and `start_metrics_server` is called only
from `alfred gateway start`. The rule is correct and promtool-verified in CI, and
it starts firing the moment a core scrape target exists. **Tracked in
[#470](https://github.com/alfred-os/AlfredOS/issues/470).**

Until then, **use the audit-log detection path in "Detecting it today" below.**
This caveat is written down rather than glossed because an alert nobody can
receive is worse than a known gap: it invites the assumption that silence means
health.

## What it means

`QuarantineStdioTransport._revoke_child_capability` ran. The transport killed the
quarantined child, which atomically revokes every gateway socket already sitting
in the child's SCM_RIGHTS queue and discards the desynced queue — one step the
kernel guarantees.

It runs when a per-extraction broker operation fails (a gateway socket could not
be connected, or `sendmsg` failed) and the child may already hold sockets. Revoking
is the correct trade: leaving un-revoked gateway capability inside a process that
holds raw T3 content and a live provider key is the worse outcome.

## Why it is terminal

The quarantine child is spawned **exactly once**, at daemon boot
(`_build_comms_inbound_extractor`). **There is no respawn scheduler**
([#455](https://github.com/alfred-os/AlfredOS/issues/455)).

After a revoke, the path degrades gracefully but permanently for the process
lifetime: the control-parent socket is closed, so `_send_one` fails immediately
with `sendmsg_failed`, and every later dispatch returns the same
`provider_unavailable` typed refusal plus its own `egress.broker.refused` audit
row. Comms keeps accepting messages and keeps declining to extract from them.

Nothing recovers this except restarting `alfred-core`.

## Detecting it today

Both work without Prometheus.

```sh
# Audit rows — the durable signal on the COMMON path. A broker-failure revoke writes a row.
alfred audit log --since 1h | grep egress.broker.refused

# Or the structlog event in the core's container logs.
docker compose logs alfred-core | grep security.quarantine_transport.capability_revoked
```

**Caveat — a cancel-path revoke writes NO `egress.broker.refused` row.** When the revoke
is cancelled mid-teardown (#472 finding 2), it re-raises the cancel *before* the caller
reaches `record_broker_failure`, so the durable audit row is forgone — the child is still
SIGKILLed, but the audit-only detection above misses it. Also grep the structlog events
(the metric is still un-scrapeable, #470):

```sh
docker compose logs alfred-core | grep -E \
  'security.quarantine_transport.(capability_revoked|revoke_cancelled|capability_abort_failed)'
```

A run of `egress.broker.refused` rows with **no** interleaved successes is the
signature of the post-revoke state — as opposed to isolated failures, which are a
degraded gateway, not a revoked capability.

## Triage

1. **Confirm the revoke, and find what triggered it.** The revoke is a *response*;
   the first `egress.broker.refused` row before it names the cause.

   ```sh
   alfred audit log --since 24h | grep -E 'egress\.broker\.(refused|connected)' | head -40
   ```

2. **Check the gateway.** The overwhelmingly likely trigger is the gateway L7
   CONNECT proxy being unreachable or refusing.

   ```sh
   docker compose ps alfred-gateway
   alfred gateway egress          # inflight counts, deny-reason breakdown, allowlists
   ```

   A deny-reason breakdown showing `destination_not_allowlisted` for your
   quarantine provider's host means the allowlist, not the broker, is the fault —
   fix that first or the restart below just revokes again.

3. **Restart the core once the trigger is fixed.**

   ```sh
   docker compose up -d alfred-core     # recreates and re-spawns the child
   ```

   Confirm recovery: a fresh `egress.broker.connected` row, and an extraction that
   returns something other than `provider_unavailable`.

4. **If it revokes again immediately**, stop restarting. A revoke loop means the
   trigger is still live; go back to step 2. Restarting into a broken gateway
   burns a child spawn per attempt and adds nothing to the audit trail.

5. **A lingering bwrap `<defunct>` (zombie) PID after a `revoke_cancelled`.** When a
   revoke is cancelled mid-teardown (a shutdown racing an in-flight revoke), the child
   is SIGKILLed but may not be reaped, leaving a short-lived zombie. It holds **no**
   fds, memory or capability — only a process-table entry — and the OS reaps it when
   `alfred-core` exits. No action: it is harmless and clears on the next core restart
   (which you are doing anyway per step 3). Do **not** treat a **`<defunct>`** child PID
   as a live capability leak — the `<defunct>` marker is the discriminator.

6. **`capability_abort_failed` — the dangerous case: a `ps` child that is NOT
   `<defunct>`.** This event means the synchronous last-resort kill's guard fired, which
   (because `abort()` suppresses the benign `ProcessLookupError`/`OSError`) indicates a
   **code/wiring bug in the child-IO seam**, not an OS hiccup — so the child's liveness is
   **unknown** and it may still be running with brokered gateway sockets. Contain it
   manually:

   ```sh
   # Find the quarantined-child bwrap under alfred-core. A RUNNING entry (state R/S, no
   # <defunct>) after this event is the live-child case; a <defunct> entry is the harmless
   # zombie of step 5.
   docker compose exec alfred-core ps -eo pid,stat,cmd | grep -E 'bwrap|quarantine_child'
   # If a non-defunct child is present, kill it explicitly, then restart to re-establish
   # guaranteed containment:
   docker compose exec alfred-core kill -9 <pid>
   docker compose up -d alfred-core
   ```

   Then file the seam bug — `capability_abort_failed` firing in production is a defect in
   the `ChildIO` implementation, not an operational event.

## What NOT to do

- **Do not disable the revoke.** It is the containment for a T3-holding process
  with live gateway capability. A "just don't tear the child down" patch converts
  a fail-closed outage into an un-revoked capability leak.
- **Do not raise `action-deadline` to work around it.** The revoke is not a
  timeout. `alfred config set action-deadline` is window-guarded to `(29s, 50s)`
  and will refuse most attempts anyway.

## Related

- [#455](https://github.com/alfred-os/AlfredOS/issues/455) — the missing respawn
  scheduler. Implementing it turns this from an outage into a blip, and is the
  fast-follow the security lane conditioned this alert on.
- [#470](https://github.com/alfred-os/AlfredOS/issues/470) — core metrics are
  never scraped; the alert above is armed but not live.
- [#466](https://github.com/alfred-os/AlfredOS/issues/466) — fault-injection
  coverage for the revocation race.
- [#461](https://github.com/alfred-os/AlfredOS/issues/461) — unbounded audit-write
  awaits on this path.
