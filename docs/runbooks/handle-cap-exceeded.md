# Runbook: `handle_cap_exceeded` in the `tool.web.fetch` audit log

> **[2026-07-06 — #339 PR4a update, ADR-0047]** `web.fetch` DOES enforce the handle-cap
> again. ADR-0041 (G7-2.5) had detached `dispatch_web_fetch` from `HandleCap` because the
> fused fetch+extract model removed the Redis-parked `ContentHandle` the cap originally
> bounded. ADR-0047 re-attaches `HandleCap` as a pure per-user *concurrency* bound: the
> dispatcher mints a synthetic `handle_id` and reserves a slot on the per-user ZSET
> **before** the network fire, releasing it in a `finally` block on every exit path
> (success, refusal, canary trip, timeout, or transport fault). The reservation is no
> longer a parked response body — the T3 body now stages transiently in-memory — but the
> per-user in-flight-fetch bound (and this runbook) apply again.

> **Audit row signal:** `rate_limit_bucket="handle_cap"` + `dlp_scan_result="handle_cap_exceeded"` + `result="rate_limited"` on a `tool.web.fetch` event. Also raised as `WebFetchRateLimited(bucket="handle_cap")` at the dispatch call site.

## What it means

A user (`triggering_user_id`) issued a `web.fetch` call while already at
the per-user concurrent in-flight-fetch cap. The cap bounds how many
`web.fetch` calls the user can have reserved (pre-network through
release-on-exit) at one moment — its purpose is to prevent one user from
holding unbounded concurrent fetches against the shared gateway relay.

Default: 5 concurrent handles per user. The intended operator knob is
`web_fetch.max_concurrent_handles_per_user` in `config/policies.yaml`,
**reserved for the planned policies-loader (issue #159).** Until that
loader ships, the default (5) applies regardless of edits to the YAML —
see the "How to override" section below.

## What it does NOT mean

- **Not a security event.** A canary trip surfaces as `dlp_scan_result="canary_tripped"` — different.
- **Not a per-minute rate limit.** That's `rate_limit_bucket="per_user"`.
- **Not a malicious request indicator by itself.** A legitimate user with slow extracts can trip it.

## Why the default is 5

The cap value (`_DEFAULT_PER_USER_CAP = 5` in `handle_cap.py`) predates ADR-0047 and was
originally sized against parked `ContentHandle` response bodies in Redis: 5 × 5 MiB max body
= 25 MiB per user, worst-case fleet sizing 100 active users × 25 MiB ≈ 2.5 GiB — well within
commodity Redis sizing. ADR-0047 re-purposed the same cap as a pure per-user *concurrency*
bound instead — in-flight `web.fetch` reservations on a ZSET; no response body is parked in
Redis anymore, since the T3 body now stages transiently in-memory — but kept the inherited
default of 5 as the starting tuning point. There is no longer a Redis-memory sizing formula
to derive the value from (the resource being bounded is in-flight concurrency, not parked
bytes); operators with single-user / high-throughput deployments may still raise the cap,
and multi-tenant operators may still lower it, based on expected per-user fetch fan-out.

## Audit vocabulary widening

This release widens two closed audit-row vocabularies. Operators with
downstream filters or SIEM rules MUST extend their allow-lists:

- `WEB_FETCH_FIELDS["rate_limit_bucket"]`: added `handle_cap` (alongside
  existing `per_domain`, `per_user`, `daily_budget`).
- `WEB_FETCH_FIELDS["dlp_scan_result"]`: PR #160 added `handle_cap_exceeded`
  and `handle_id_mismatch`; PR #147 adds `dispatch_param_invalid` (host-side
  Pydantic validation failure — distinct fault class, not user input).

Both are typed via `typing.Literal[...]` in
`src/alfred/audit/audit_row_schemas.py` (canonical source). Type-check time
catches drift; downstream consumers should snapshot the literal at release
time.

## How to inspect

The cap value referenced below is **whatever cap is currently in effect**
(today: 5, per the built-in default — see "How to override").

1. **Audit log query** (preferred — CLI-first, matches peer Slice-3 runbooks):

   ```bash
   alfred audit log --event tool.web.fetch --since 1h \
     --filter "subject.rate_limit_bucket=handle_cap" \
     --filter "subject.triggering_user_id=<user_id>"
   ```

2. **Direct audit-DB query** (fallback / deep-dive when the CLI is
   unavailable or when ad-hoc SQL filters are needed):

   ```sql
   SELECT created_at, subject->'url' AS url, subject->'correlation_id' AS cid
   FROM audit_log
   WHERE event = 'tool.web.fetch'
     AND subject->>'rate_limit_bucket' = 'handle_cap'
     AND subject->>'triggering_user_id' = '<user_id>'
     AND created_at > now() - interval '1 hour'
   ORDER BY created_at DESC;
   ```

3. **Live handle count** for a user (direct Redis):

   ```bash
   redis-cli ZCARD alfred:handles:user:<user_id>
   redis-cli ZRANGE alfred:handles:user:<user_id> 0 -1 WITHSCORES
   ```

   The members are handle IDs; scores are expiry epoch-ms. If `ZCARD`
   equals the in-effect cap value (5 today), the user is at cap.

## Common causes

| Cause | Signal | Remediation |
| --- | --- | --- |
| Legitimate burst (e.g., research agent in parallel-fetch mode) | Cap-refusals stop after in-flight fetches drain; ZCARD drops naturally | None — system is working as designed |
| `release()`'s ZREM failed on a transient Redis error (fail-quiet by design — spec §7.10) | `web_fetch.handle_cap.release_failed` structlog event | Investigate Redis health; passive TTL will free the slot within ~120s regardless |
| A non-`RedisError` fault escaped `release()` (defensive `finally` guard in the dispatcher) | `web_fetch.handle_cap.release_unexpected` structlog event | Investigate the logged exception type; passive TTL still frees the slot within ~120s |
| Canary-trip quarantine I/O failed (delete failed) | `web_fetch.canary.quarantine_failed` / `web_fetch.handle_cap.eager_release_failed` structlog events | Investigate Redis health; cap slot held until passive TTL by design |
| Cap too tight for workload | Continuous cap-refusals for a known-legitimate user | Raise `web_fetch.max_concurrent_handles_per_user` in `policies.yaml` — note: knob is currently inert until the policies-loader lands (#159); the value applies at next process boot after that |

## How to override

> **Reserved — not currently wired.** The knob
> `web_fetch.max_concurrent_handles_per_user` in `config/policies.yaml`
> is read by no current code path. Issue #159 tracks wiring the
> policies-loader that will honour it. Until that loader lands, **the
> default of 5 applies regardless of edits to the YAML** — the host
> instantiates `HandleCapConfig()` with its built-in default and never
> reads `policies.yaml` today. Edit the file to document your intended
> value so the planned loader picks it up on first wire-up, but be
> aware the change is documentation-only at runtime.

The intended shape (once the loader ships) is:

```yaml
web_fetch:
  max_concurrent_handles_per_user: 10   # was 5
```

Save and restart the `alfred` process — when the loader is wired, the
new cap will take effect on the next plugin-host boot. Existing
reservations live in Redis (`alfred:handles:user:*`) and survive the
restart; the new cap value applies to subsequent reserve attempts.
(Future: mtime-polled hot-reload will make this restart-free — see
issue #159.)

**Refuses to load:** when the loader is eventually wired, a value of
`0` or negative will fail loud — `HandleCapConfig.__post_init__` raises
`ValueError` at config construction. Until then, edits to this value
are silently ignored (no `ValueError`, no warning) because the YAML is
not read; this is the inert-knob hazard the issue #159 wire-up
removes.

## Forensic correlation

Every cap-refusal audit row carries `correlation_id` (links to the
conversation turn) and `triggering_user_id`. The `content_handle_id` field
is `None` on cap-refusal rows — the pre-minted UUID was never written to
Redis (the refusal happens BEFORE the plugin call). The matching successful
fetch (the one currently occupying the slot) is found via `triggering_user_id`
and a recent `tool.web.fetch` row with `result='success'` (audit rows written
before #328 used the legacy `result='ok'`).

## Related runbooks

- `docs/runbooks/slice-3-operator-migration.md`
