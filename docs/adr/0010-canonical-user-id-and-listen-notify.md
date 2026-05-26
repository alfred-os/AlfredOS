# 0010 — Canonical user_id is a display-name slug; cross-process cache invalidation uses `LISTEN/NOTIFY` + TTL backstop

- **Status**: Accepted
- **Date**: 2026-05-27
- **Slice**: 2 — `docs/superpowers/plans/2026-05-26-slice-2-pr-A-identity.md`
- **Supersedes**: —
- **Superseded by**: —

## Context

Slice 2 introduces multi-user identity. PRD §7.2 promotes the `users` table
from a Slice-1 single-row stub to a first-class entity with display names,
locale, language, and binding rows for external identities (Discord member
IDs, future Slack user IDs).

Two design questions follow that the PRD does not pin down:

1. **What shape is the canonical `user_id`?** Every downstream subsystem
   (audit log, budget guard, memory partitioning, capability grants) keys
   on this value, so the choice is load-bearing.
2. **How do CLI mutations propagate to the long-running `alfred-discord`
   process?** The Discord adapter runs as its own process with in-process
   caches (`IdentityResolver`, future `BudgetGuard`). When `alfred user
   add` or `alfred user bind` runs in the CLI process, those caches must
   not serve stale rows — but the CLI cannot reach into another process's
   memory.

## Decision

### Canonical user_id is a slug derived from display name

`user_id` is a lowercase slug, derived from the operator-supplied display
name by a deterministic pipeline: NFKC normalize → `unidecode` transliterate
→ lowercase → regex-strip non-alphanumeric → trim to 63 chars → append a
numeric collision suffix on conflict. Not a UUID, not a ULID.

Operator-readable IDs in log lines (`alfred audit log --user bob`) and in
audit-graph node labels are worth the one-time collision check at `add`
time. UUIDs would force every operator query through a lookup table; slugs
read straight out of the rendered output.

### Cross-process cache invalidation uses PostgreSQL `LISTEN/NOTIFY`

Channel: `alfred_identity_changed`. Every mutating CLI command
(`add`/`set`/`remove`/`bind`/`unbind`) issues `NOTIFY` inside the same
transaction as the data write. The `alfred-discord` process runs a
background listener that bumps its local `IdentityVersionCounter` on
receipt; the next cache read sees the bumped version and refetches.

Payload is a small JSON `{"slug": "...", "op": "add|set|remove|bind|unbind"}`,
used **only as a hint**. The resolver does not trust the payload as the row
of record — it refetches from Postgres after the bump. This keeps the
`LISTEN/NOTIFY` path from becoming a covert write channel.

### Listener resilience: exponential-backoff reconnect supervisor

The listener task is supervised. On disconnect: backoff starts at 1s,
doubles on each failure, caps at 60s, resets on successful `LISTEN`. A
one-shot `WARN` log fires per disconnect (not per retry — avoids log
spam under sustained outage) and the
`discord_identity_listener_reconnects_total` Prometheus counter exposes
outage rate to alerts.

CLAUDE.md hard rule #7 (no silent failures in security paths) demands
this — a silently dead listener would let a soft-deleted user's cached
identity row keep authorizing requests indefinitely.

### 60s TTL backstop runs unconditionally

Listener-driven invalidation is the fast path; a 60s TTL is the
correctness backstop. On every `IdentityResolver.resolve()` and every
`BudgetGuard.consume()` (BudgetGuard lands in PR B), the resolver
compares `now() - entry.cached_at` against
`Settings.identity_cache_ttl_s` (default `60`). Expired entries refetch
regardless of listener health. `cached_at` is reset on both initial fill
and on NOTIFY-driven refresh.

This matters in two deployment shapes the listener cannot cover:

- **PgBouncer transaction-pooling.** `LISTEN/NOTIFY` does not work
  through transaction-mode poolers — the connection that issued `LISTEN`
  is returned to the pool after the transaction commits. Operators on
  PgBouncer get the same staleness ceiling (60s) via TTL alone.
- **Listener flapping.** During the backoff window, NOTIFYs are missed.
  The TTL bounds how long a stale row can serve under that scenario.

## Consequences

- Operator-readable `user_id` in every log line, audit row, and metric
  label. `alfred audit log --user bob` works without an ID lookup.
- One-time slug-collision-suffix cost on `alfred user add`. Documented
  in the user-facing CLI help.
- Deterministic invalidation contract every downstream cache can rely on:
  "you will see a mutation within 60s, sooner if `LISTEN/NOTIFY` is
  healthy." `BudgetGuard` (PR B) builds on this contract directly.
- Listener outages are observable (counter + warn log) rather than silent.

## Alternatives considered

- **UUID `user_id`.** Rejected — every operator-facing rendering needs a
  separate lookup to a human-readable label, doubling the surface that
  has to render correctly under i18n / Unicode user names. Debuggability
  cost outweighs the trivial collision-handling on the slug.
- **ULID `user_id`.** Same rejection as UUID, plus the temporal ordering
  ULID provides is already supplied by `created_at` on the row.
- **Polling `users.updated_at` from each process.** Rejected — every poll
  is a wasted DB round-trip when nothing has changed, and the worst-case
  staleness window (poll interval) is the same as the TTL backstop. TTL
  plus event-driven invalidation strictly dominates the polling design:
  it has lower steady-state cost AND lower update latency.

## References

- PRD §7.2 — `users` table, identity binding, per-user partitioning.
- `docs/superpowers/specs/2026-05-26-slice-2-discord-multiuser-design.md`
  §2 lines 156-168 — slug derivation pipeline.
- `docs/superpowers/specs/2026-05-26-slice-2-discord-multiuser-design.md`
  §4 lines 585-604 — `LISTEN/NOTIFY` channel design.
- `docs/superpowers/specs/2026-05-26-slice-2-discord-multiuser-design.md`
  §4 lines 767-772 — TTL backstop + PgBouncer compatibility.
- ADR-0011 — Per-user `BudgetGuard` (consumer of the invalidation contract).
