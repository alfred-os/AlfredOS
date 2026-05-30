# Identity subsystem

The identity subsystem owns "who is talking to AlfredOS, and what may they
do?" Every other subsystem that keys on a user — audit log, budget guard,
memory partitioning, rate limiter — depends on the identity layer for the
canonical `user_id` and the authorization tier.

This is the first entry under `docs/subsystems/`. The Slice-2 hub seeds
three subsystem deep-docs — identity, [comms](comms.md), and
[hooks](hooks.md) — the broader hub-and-spoke restructure of CLAUDE.md
is Slice-3's first docs-author dispatch.

## Overview

Identity in Slice 2 is a SQLAlchemy ORM (`User` + `PlatformIdentity`)
fronted by a single accessor class (`IdentityResolver`). Mutating
operations bump an in-process `IdentityVersionCounter` and emit a
`NOTIFY alfred_identity_changed` payload on Postgres so peer processes
(`alfred-discord`, `alfred-core`) invalidate their caches. A 60-second
TTL backstop on every cache entry bounds staleness on dialects that do
not support `LISTEN/NOTIFY` (SQLite for unit tests; PgBouncer in
transaction-pooling mode for some production deployments).

The CLI (`alfred user *`) is a thin imperative shell on top of the
resolver. Every CLI mutation writes one audit row attributed to the
current live operator (or the literal `<bootstrap>` for the very first
operator-add invocation).

## Key types

### `User` ORM (`src/alfred/identity/models.py`)

A row in the `users` table. Fields:

- `id` — autoincrement integer primary key.
- `slug` — the [canonical user_id](../glossary.md#canonical-user-id). Unique.
- `display_name` — what the operator typed at `alfred user add`.
- `authorization` — string column with a CHECK constraint enforcing one
  of `read_only`, `standard`, `trusted`, `operator`. The closed-domain
  enum lives in the schema permanently — dropping/re-adding across a
  Postgres CHECK is a destructive migration that breaks rollback
  symmetry. New tiers land via additive CHECK migrations.
- `daily_budget_usd` — float, DB CHECK `> 0`. Consumed by
  [`BudgetGuard`](../adr/0011-per-user-budget-guard.md).
- `language` — BCP-47 tag (`en-US`, `de-DE`, …). CLAUDE.md i18n rule #3
  requires every stored user-content row to carry a language tag;
  including the user row itself lets personas localise at the
  orchestrator boundary without a separate lookup.
- `rate_limit_per_min`, `rate_limit_per_day` — optional per-user
  overrides on the authorization-tier defaults. `NULL` means inherit.
- `created_at`, `deleted_at` — soft-delete model. Removing a user sets
  `deleted_at`; the row stays so audit-log foreign keys survive.

### `PlatformIdentity` ORM

The binding from a platform-native identifier (Discord snowflake, TUI
handle) to a `User`. Fields:

- `id`, `user_id` (FK with `ondelete=CASCADE`).
- `platform` — `tui` or `discord`. CHECK-constraint closed-domain enum.
- `platform_id` — the platform-native id (Discord snowflake as string,
  TUI handle as string).
- `created_at`, `deleted_at` — soft-delete.

Two uniqueness constraints:

- **`uq_platform_identity_platform_platform_id`** — global. The same
  Discord snowflake cannot point at two different users at once. A
  re-bind migrates the row; it does not insert a fresh one.
- **`uq_platform_identities_user_id_platform_active`** — per-user
  partial-unique on live rows (`WHERE deleted_at IS NULL`). A user can
  hold one active binding per platform plus any number of soft-deleted
  historical ones — audit history continues to join on them.

### `Authorization` (`StrEnum`)

Closed-domain enum: `READ_ONLY`, `STANDARD`, `TRUSTED`, `OPERATOR`.
Snake-case on the wire (DB column TEXT, Pydantic value); the CLI accepts
kebab-case too (`read-only` → `Authorization.READ_ONLY`) via a Typer
normaliser. See [glossary: authorization role](../glossary.md#authorization-role)
for tier semantics and rate-limit defaults.

### `Platform` (`StrEnum`)

`TUI`, `DISCORD`. Telegram lands in Slice 4 by extending this enum
(additive CHECK-constraint migration, no destructive rewrite).

### `IdentityError` hierarchy (`src/alfred/identity/errors.py`)

All errors root at `IdentityError(AlfredError)`. Concrete subtypes:

- `IdentityResolutionError` — fall-through bucket for resolve-time
  failures (e.g. `get_operator()` finding zero or >1 operator).
- `OperatorAlreadyExistsError` — `add(--authorization operator)` or
  `set(--authorization operator)` would produce a second concurrent
  operator. Carries `existing_slug` + `existing_display_name`.
- `LastOperatorRemovalRefusedError` — `remove(slug)` would leave the
  deployment with zero operators.
- `PlatformIdInUseError` (extends `IdentityResolutionError`) —
  `bind(platform, platform_id, ...)` collides with another user's live
  binding for the same `(platform, platform_id)` pair. Carries the
  colliding user's slug so the CLI can name them in the operator-facing
  error message.
- `UserAlreadyBoundError` (extends `IdentityResolutionError`) —
  `bind(user_slug, platform, ...)` called on a user who already has a
  live binding for the same platform.
- `OperatorSlugCollisionError` (extends `alembic.util.exc.CommandError`)
  — raised by migration 0004's slug pre-check if a literal `user_id` in
  the `episodes` or `audit_log` rows slug-collides with an existing
  non-operator users row.

### `IdentityResolver`

The only legitimate accessor for `User` + `PlatformIdentity`. Module
docstring at `src/alfred/identity/resolver.py` is the source of truth;
the surface is summarised below.

### `IdentityListener`

Background asyncio task that subscribes to the
`alfred_identity_changed` `LISTEN/NOTIFY` channel on Postgres. On every
received NOTIFY, the listener bumps the supplied `IdentityVersionCounter`,
which invalidates the per-process `IdentityResolver` LRU and (per
[ADR-0011](../adr/0011-per-user-budget-guard.md)) the `BudgetGuard`
cached `daily_usd`.

Wrapped in an **exponential-backoff reconnect supervisor**: a raised
`ConnectionError` triggers a sleep starting at `backoff_start_s`,
doubling on each failure, capped at `backoff_max_s` (defaults: 1s and
60s). Backoff resets after any iteration that returned cleanly. A
one-shot `WARN` log fires per disconnect — not per retry, to avoid log
spam under sustained outage. The Prometheus counter
`discord_identity_listener_reconnects_total` exposes outage rate to
alerts.

CLAUDE.md hard rule #7 ("no silent failures in security paths") is what
makes the supervisor load-bearing — a silently-dead listener would let a
soft-deleted user's cached authorization row keep granting requests
indefinitely.

### `IdentityVersionCounter`

Monotonic `threading.Lock`-guarded counter (`src/alfred/identity/version_counter.py`).
Starts at zero; `bump()` advances by one; `current()` reads. Two
guards (`BudgetGuard` and `IdentityResolver`'s LRU) subscribe; the
listener task and every successful resolver mutator call `bump()`.

## Primary flows

### Slug derivation pipeline (canonical user_id)

`src/alfred/identity/slug.py`. Pure, deterministic, side-effect-free.

1. **NFKC** — Unicode normalisation. Visually-equivalent codepoints
   (fullwidth `Ａ` / U+FF21 vs ASCII `A` / U+0041) collapse.
2. **`unidecode`** — ASCII transliteration. `José` → `Jose`; `田中` →
   `Tian Zhong`; emoji → `""`.
3. **lowercase** — slugs are case-insensitive.
4. **Non-alphanumeric → `-`** — any run of characters outside `[a-z0-9]`
   becomes a single hyphen.
5. **Trim** — leading and trailing hyphens removed; internal runs are
   already collapsed by step 4.
6. **Truncate to 63 chars** — `_SLUG_MAX = 63`, applied before any
   collision suffix.
7. **Empty fallback** — if the pipeline yields the empty string
   (emoji-only input, all-punctuation input), return `"user"`.

Collision detection and suffixing (`-2`, `-3`, …) live in
`IdentityResolver.add` because they need a DB session; the slug module
itself never does I/O. Collision suffixing consults *every* row including
soft-deleted, because `users.slug` is column-level UNIQUE — soft-deleted
rows continue to hold their slug.

### `IdentityResolver.resolve(platform, platform_id) -> User | None`

In-process LRU cache (default 256 entries, configurable) with a 60-second
TTL backstop and an `IdentityVersionCounter`-driven invalidation hook. A
hit is served iff:

- entry exists, AND
- `(now - cached_at) < cache_ttl_s` (TTL backstop, monotonic-clock-based),
  AND
- `entry.version_seen >= counter.current()` (no peer mutation since the
  fetch).

Either a TTL expiry or a counter bump triggers a re-fetch. A successful
unbind that returns `None` drops any stale entry — the cache never serves
ghost rows.

### `IdentityResolver` mutators

`add`, `bind`, `unbind`, `remove`, `set_`. Each mutator:

1. Opens a transaction (`session_factory.begin()`).
2. Validates inputs (BCP-47 language tag via Babel; budget finite + > 0).
3. Issues the mutation.
4. Emits `pg_notify(_NOTIFY_CHANNEL, "<event>:<slug>")` inside the same
   transaction — so the NOTIFY ships on COMMIT, matching Postgres
   LISTEN/NOTIFY semantics.
5. After commit, calls `version_counter.bump()`.

Two security upper bounds are enforced inside `add` and `set_`:

- **Operator upper bound.** At most one live `Authorization.OPERATOR`
  row at any time. Adding or promoting to operator refuses with
  `OperatorAlreadyExistsError` unless the caller passes
  `replace_operator=<existing-slug>`, in which case the existing operator
  is demoted to `TRUSTED` in the same transaction. Atomic demote-then-
  promote.
- **Last-operator removal refusal.** `remove(slug)` refuses to soft-delete
  the only remaining operator with `LastOperatorRemovalRefusedError`.

### `alfred user` CLI subcommands

`src/alfred/identity/cli.py`. Each subcommand resolves the live
`IdentityResolver`, normalises CLI-shaped values to resolver-shaped
kwargs, calls the resolver, and writes ONE audit row attributed to the
current live operator (or `<bootstrap>` for the very first
operator-add).

| Subcommand | Resolver method | What it does |
|---|---|---|
| `add` | `add` | Create a new user. Defaults: `daily_budget_usd = 5.0`, `language = "en-US"`. Operator-bootstrap is the first invocation. |
| `list` | `list_` | Print all live users (`--include-deleted` for history). |
| `show <slug>` | `show` | Print one user row (live or soft-deleted). |
| `remove <slug>` | `remove` | Soft-delete; refuses last operator. |
| `bind <slug> --platform <p> --id <pid>` | `bind` | Add a `(platform, platform_id)` binding. |
| `unbind <slug> --platform <p>` | `unbind` | Soft-delete the live binding. |
| `set <slug> [--display-name --authorization --language --daily-budget --rate-limit-per-min --rate-limit-per-day]` | `set_` | Mutate live user in place. `--rate-limit-per-min unset` clears the override (sentinel). |

`set_` has a trailing underscore because `set` shadows the built-in;
the CLI surface drops the underscore (`alfred user set`).

### Cross-process invalidation (`LISTEN/NOTIFY` + TTL)

Spec: `LISTEN alfred_identity_changed`. Payload shape:
`"<event>:<slug>"` (informational only — the bump is what invalidates
caches, not the payload contents). The listener's payload parser
(`_parse_notify_payload`) accepts both the colon-separated form and JSON
for future-shape flexibility, and never raises on a malformed payload
(silent-drop is acceptable here because the bump still happened).

Three deployment shapes have distinct staleness ceilings:

- **Postgres with healthy `LISTEN/NOTIFY`** — invalidation latency
  bounded by the listener's backoff state (typically <1s in steady
  state, ≤60s under disconnect storm).
- **Postgres behind PgBouncer in transaction-pooling mode** — `LISTEN`
  does not work through transaction-mode poolers (the connection that
  issued `LISTEN` is returned to the pool after the transaction
  commits). Staleness ceiling falls to the 60-second TTL.
- **SQLite (unit tests)** — `pg_notify` is a no-op. The in-process
  counter bump still invalidates the local cache; cross-process
  invalidation is not exercised at this layer.

## Error model

The `IdentityError` hierarchy is the full catalog. The CLI dispatch:

1. Catches the specific subtype (e.g. `OperatorAlreadyExistsError`).
2. Routes to a t()-localised error message.
3. Exits with code `2` (user-fixable error per the CLI exit-code
   convention).

Unexpected exceptions (programming errors, bare `RuntimeError`) escape
the catch and reach Typer's top-level handler — exit `1`, full
traceback. CLAUDE.md hard rule #7 forbids swallowing security-path
exceptions silently; the catch surface is intentionally narrow.

| Exception | CLI exit | Surface | Remediation |
|---|---|---|---|
| `OperatorAlreadyExistsError` | 2 | `cli.user.error.operator_already_exists` | Re-run with `--replace-operator <existing>` |
| `LastOperatorRemovalRefusedError` | 2 | `cli.user.error.last_operator_removal` | Promote another user to operator first |
| `PlatformIdInUseError` | 2 | `cli.user.error.platform_id_in_use` | `alfred user unbind <existing_slug> --platform <p>` first |
| `UserAlreadyBoundError` | 2 | `cli.user.error.user_already_bound` | Unbind first |
| `IdentityResolutionError` (other) | 2 | `cli.user.error.resolution_failed` | Message-specific |

## ADR cross-references

- [ADR-0010](../adr/0010-canonical-user-id-and-listen-notify.md) —
  canonical user_id is a display-name slug; cross-process invalidation
  uses `LISTEN/NOTIFY` + TTL backstop.
- [ADR-0011](../adr/0011-per-user-budget-guard.md) — per-user
  `BudgetGuard` subscribes to the `IdentityVersionCounter` exposed by
  this layer.
- [ADR-0013](../adr/0013-defer-t1-t3-and-dual-llm.md) — trust-tier
  T1/T3 and dual-LLM deferred to Slice 3; Slice 2 identity is
  T2-only.

## Open questions / forward-compat notes

- **`AsyncIdentityResolver` for Slice 3+.** The current resolver is
  synchronous. Async callers (the orchestrator from PR B, the Discord
  adapter from PR D2) wrap calls in `asyncio.to_thread`. Mixing sync +
  async sessions through the same factory was the failure mode that bit
  Slice 1's adversarial run. Slice 3 may introduce an
  `AsyncIdentityResolver` mirror once SQLAlchemy 2.0 async wiring is
  proven in the orchestrator; the Protocol surface is stable enough to
  add the async pair without changing the sync one.
- **Telegram in Slice 4.** Extending `Platform` is an additive
  CHECK-constraint migration. No identity-layer rewrite needed.
- **Operator-set + JWT auth in Slice 5+.** Slice 5 introduces
  authentication for the HTTP surface. The `User` row becomes the source
  of truth for the auth-server lookup; `authorization` becomes the JWT
  scope claim. The current resolver surface accommodates this without
  schema change.
