# Slice 2 — Discord adapter + multi-user identity + secret broker file backend

**Status:** Design — revised 2026-05-26 after `/review-plan` (55 findings folded in) and again after `/review-pr` on PR #93 (~30 findings folded in). Pending user approval, then `superpowers:writing-plans`.
**Date:** 2026-05-26
**Owner:** brainstorm output from the slice-1-followup session (post PR #89 / #91 / #92); revision dispatched to `alfred-docs-author`.
**Anchors:** [PRD §5](../../../PRD.md#5-architecture-overview) · [PRD §6.1](../../../PRD.md#61-multi-modal-comms) · [PRD §6.2](../../../PRD.md#62-multi-layered-memory) · [PRD §6.8](../../../PRD.md#68-persona-system) · [PRD §7.1](../../../PRD.md#71-security--prompt-injection-defense) · [PRD §7.2](../../../PRD.md#72-multi-user-identity--authorization) · [ADR-0008](../../adr/0008-llm-output-trust-tier.md)
**Slice-1 anchor plan:** [`docs/superpowers/plans/2026-05-24-slice-1-hello-alfred.md`](../plans/2026-05-24-slice-1-hello-alfred.md)

---

## 0. Slice-2 prerequisites (land before anything else)

Two items land at the very start of PR A, before any new feature work. Either one slipped becomes a correctness or paper-trail bug across the rest of the slice.

### 0.1 Promote `_active_lang` to `contextvars.ContextVar[str]`

Slice 1 Appendix C deferred this with the line *"safe under single-user; revisit when Slice 3+ introduces multi-user."* Slice 2 IS that point. The current module-global `_active_lang` in `src/alfred/i18n/translator.py` will cross-contaminate concurrent Discord DMs: Alice's `set_language("de-DE")` would persist into Bob's interleaved `t()` call inside the same event loop.

The fix is shape-only: declare `_active_lang: ContextVar[str] = ContextVar("alfred_active_lang", default="en-US")`. `set_language()` becomes `.set()`; `t()` becomes `.get()`. asyncio propagates ContextVars across `await` points automatically, so each coroutine sees its own language without any handler-side bookkeeping. Add `tests/unit/i18n/test_concurrent_language.py` that interleaves two `asyncio.gather`-driven coroutines and asserts each renders its own catalog string. This lands as PR-A commit 1 (and is a prerequisite for everything downstream that calls `set_language`).

### 0.2 ADR-0013 — supersede ADR-0008's Slice-2 commitment

ADR-0008 explicitly commits T1 (operator) + T3 (untrusted) + dual-LLM split to land in Slice 2. The revised Slice-2 scope defers all three to Slice 3. That contradiction must not sit silently on `main`. ADR-0013 ("Defer T1+T3+dual-LLM to Slice 3") amends ADR-0008's status to `Superseded in part by ADR-0013` and records the rescheduling rationale: the surface-area change (multi-user identity, comms adapter Protocol, file-backed secrets) is already large enough for one slice, and a dual-LLM split without the upstream MCP plugin transport is wasted scaffolding that Slice 3 rewrites.

ADR-0013 lands as PR-A commit 2 with a **functional placeholder body** so PRs B-D have an anchor immediately:

```markdown
# 0013 — Defer T1 operator tier, T3 untrusted ingestion, and dual-LLM split to Slice 3

- **Status**: Accepted
- **Date**: 2026-05-26
- **Slice**: 2 — `docs/superpowers/plans/2026-05-26-slice-2-…`
- **Supersedes**: ADR-0008 (in part)
- **Superseded by**: —

## Decision (summary)

Slice 2 ships multi-user identity (T2 only), Discord adapter, file-backed secret broker. T1, T3, and the
dual-LLM split — committed by ADR-0008 to land in Slice 2 — are rescheduled to Slice 3.

## Rationale (one-line)

The Slice-2 surface area (identity + Discord + file broker) is already large enough for one slice; the
dual-LLM split without the upstream MCP plugin transport (Slice 3) is wasted scaffolding that Slice 3 rewrites.

## Author

`alfred-docs-author` writes the full body in PR E from the [Slice 2 design spec §0](#0-slice-2-prerequisites-land-before-anything-else).
The placeholder above is sufficient for PRs B-D to cite. Long-form rationale, alternatives, and consequences
land in PR E.
```

The detailed analysis (alternatives, full consequences, references to PRD sections) is deferred to PR E so PRs A-D don't block on prose work, but the supersession edge to ADR-0008 is established immediately at PR-A merge.

---

## 1. Scope and outcome

### What ships when Slice 2 is done

1. **Slice-1 behavior preserved.** `bin/alfred-setup.sh` + `docker compose run --rm -it alfred-core chat` still works exactly as it does on `main` today (TUI experience is unchanged from the operator's perspective).
2. **New CLI surface under `alfred user`** for operator-pre-mapped identity binding:
    - `alfred user add --name <name> --discord-id <snowflake> [--authorization <standard|trusted|read-only|operator>] [--daily-budget-usd <float>] [--language <bcp47>] [--rate-limit-per-min <int>]`
    - `alfred user list [--json] [--include-deleted]`
    - `alfred user show <slug>`
    - `alfred user remove <slug> [--yes]` (soft-delete; audit history preserved; refuses to remove the last operator).
    - `alfred user bind <slug> --platform discord --id <platform-id>`
    - `alfred user unbind <slug> --platform discord`
    - `alfred user set <slug> [--display-name "…"] [--daily-budget-usd …] [--authorization …] [--language …] [--rate-limit-per-min …|unset]` (slug stays stable on `--display-name` change — slug is the canonical user_id; only the human-readable label changes, with an audit row recording the rename)
3. **The TUI keeps working but with a canonical user_id.** `episodes.user_id` and `audit_log.actor_user_id` carry the operator's canonical slug, not the literal `"operator"`. The setup script creates the operator's `users` row on first deploy.
4. **New service `alfred-discord` in `docker-compose.yaml`.** Long-running daemon (`up -d`, `restart: unless-stopped`) running the Discord adapter. Operator starts it after pre-mapping themselves and any friends.
5. **End-to-end Discord DM flow** for a pre-mapped Discord user:
    - DM arrives → resolver finds the user → orchestrator runs a turn → response posts back to the DM.
    - Audited with `actor_user_id=<slug>`, charged to that user's per-user budget, episodic memory rehydrates per-user across restarts.
6. **Unknown Discord ID → polite refusal + one audit row per first-contact snowflake, repeat refusals suppressed.** The operator must add the user via CLI before the bot will engage.
7. **`BudgetGuard` is per-user.** One user's daily cap doesn't affect another's. Operator inherits the slice-1 global cap as their per-user default.
8. **`SecretBroker` reads from a file backend AND env vars** (`~/.config/alfred/secrets.toml`, 0600 perms, plaintext for Slice 2; age encryption is Slice 3+). Env wins on conflict for backward-compat with slice-1 keys; new Slice-2+ keys (e.g. `discord_bot_token`) prefer file over env so the canonical store is one place.
9. **Slice-1 invariants hold.** Trust-tier tagging at every boundary (Discord DM body → T2; embeds/attachments/stickers → refuse, not silently inline). Audit log is append-only and survives rollback. i18n catalog-drift gated in CI. `make check` green. 100% line + branch coverage on `src/alfred/security/` enforced by a per-file `--cov-fail-under=100` gate in PRs C and D2.

### Out of scope (committed to later slices)

| Deferred capability | Lands in |
|---|---|
| Verification-phrase identity binding (interactive first-DM handshake) | Slice 3+ |
| Cross-platform binding (one-time code from an already-bound channel) | Slice 3+ |
| Discord server channels, threads, slash commands, embeds | Slice 4 (alongside persona registry) |
| Trust tier T1 (operator) + T3 (untrusted) + dual-LLM split + first real tool | Slice 3 (ADR-0013 records the supersession of ADR-0008's Slice-2 commitment) |
| `age`-encrypted secret broker | Slice 3+ |
| MCP plugin transport for the comms adapter | Slice 3+ (the in-process Protocol shipped here is a Slice-2-only artifact; see §2 + ADR-0009) |
| Persona-other-than-Alfred (Lucius, Oracle, Diana) | Slice 4+ |
| Telegram adapter | Slice 4 |
| Adversarial corpus *scaffolding* (directory tree + harness + per-category READMEs + CI job stub + one DLP payload fixture) | **Slice 2** (lands in PR E) |
| Adversarial corpus *payload population* (real prompt-injection / DLP / capability-bypass / canary / inter-persona fixtures + release-blocker activation) | Slice 3 |

---

## 2. Architectural changes

### The seam: `CommsAdapter` Protocol (Slice-2 artifact)

A new `src/alfred/comms/adapter.py` defines an in-process Protocol with explicit lifecycle:

```python
class CommsAdapter(Protocol):
    """In-process Slice-2 seam. ADR-0009 records that this Protocol shape
    will NOT survive the Slice-3 MCP-transport swap (which inverts polarity:
    the adapter becomes an RPC server, the orchestrator its client, and the
    boundary is a message envelope, not a Python object graph). Slice-3
    Protocol will grow `on_inbound(InboundMessage) -> None` + a separate
    `OrchestratorClient` Protocol the adapter calls outward."""

    name: str  # "tui" | "discord" | future "telegram" | "slack"

    async def start(self) -> None: ...   # one-shot init (login handshake, etc.)
    async def run(self) -> None: ...     # long-running event loop
    async def stop(self) -> None: ...    # graceful shutdown (signal-driven)
    def health(self) -> AdapterHealth: ...  # synchronous snapshot (Slice 5 metrics seed)
```

`AlfredTuiApp` grows a thin wrapper `TuiAdapter(CommsAdapter)` whose `run()` awaits `self._app.run_async()`; the resolve → rate-limit → dispatch → DLP flow lives inside `AlfredTuiApp`'s send handler with the same injects mirroring Discord. New `DiscordAdapter(CommsAdapter)` at `src/alfred/comms/discord.py`. Both adapters take the same constructor inject set (`orchestrator`, `identity_resolver`, `outbound_dlp`, `rate_limiter`, `broker`). The Discord adapter additionally takes a `client_factory: Callable[[discord.Intents], _DiscordClientLike] = discord.Client` so the gateway client can be mock-injected in unit tests; a separate `_DiscordClientLike` structural Protocol covers `event/start/close/is_ready`.

**Slice-3 deviation, bounded.** PRD §5 lists "Plugins are MCP servers (comms adapters, …)" as a non-negotiable invariant. Slice 2 deliberately ships in-process Python and explicitly relaxes the invariant; ADR-0009 records the deviation, bounds it to Slice 2, and requires Slice 3's reviewer-gate to re-check PRD §5 clean once the MCP transport lands. No call site outside `src/alfred/comms/` may import the in-process adapter classes directly — orchestrator code interacts with them only through the Protocol — so the Slice-3 swap is a single-module rewrite.

### CLI entrypoint for the Discord adapter

A new `alfred discord` Typer subcommand boots `DiscordAdapter.start() → run()`. `docker-compose.yaml`'s `alfred-discord` service sets `command: ["discord"]`, so the container's existing `alfred` entrypoint dispatches into the adapter loop. A sibling `alfred discord verify` subcommand (short-lived `discord.Client.start` with a 30s timeout) asserts `on_ready` fires, prints granted intent flags + the bot's identity, and exits with one of the codes below (devex-001 + err-004). The setup script invokes `alfred discord verify` immediately after the operator binds their snowflake so the operator gets a definite green/red signal before `up -d alfred-discord` daemonizes the loop.

**`alfred discord verify` exit codes (devex-001 + err-004):**

| Exit | Meaning (structlog event in italics) | Setup-script treatment |
|---|---|---|
| 0 | `on_ready` fired; identity + intents printed (*discord.verify.ok*) | Continue install |
| 1 | Unrecoverable upstream — gateway 5xx, repeated reconnect failure inside the 30s window (*discord.verify.upstream_unrecoverable*) | Soft warning; operator retries later |
| 2 | Config — bad token, intents off in the developer portal, missing perms, secrets file unreadable (*discord.verify.config_failed*). Intents-off message embeds the `https://discord.com/developers/applications/<bot-id>/bot` URL so first-time operators know where to toggle | Hard fail with remediation |
| 3 | `LoginFailure` (typed) (*discord.verify.login_failed*) | Hard fail (collapsed into config-class remediation) |
| 4 | Timeout — 30s elapsed without `on_ready`, gateway not yet 5xx (*discord.verify.timeout*) | Soft warning; operator retries |
| 130 | SIGINT (*discord.verify.interrupted*) | Setup script aborts |

Exit codes pinned in `tests/unit/comms/test_discord.py::test_discord_verify_exit_codes` (one branch per code).

### Three new modules under `src/alfred/identity/`

- **`models.py`** — SQLAlchemy ORM:
  - `User` — `(id, slug, display_name, authorization, daily_budget_usd, language, rate_limit_per_min, created_at, deleted_at)`. `authorization` (not `role`) avoids the name collision with `Episode.role` (the message-author Literal). `rate_limit_per_min` is nullable; `NULL` means "use authorization-derived default" (see [glossary: authorization role](../../glossary.md#authorization-role)).
  - `PlatformIdentity` — `(id, user_id FK CASCADE, platform, platform_id, created_at)` with composite `UNIQUE(platform, platform_id)` and a partial `UNIQUE(user_id, platform) WHERE deleted_at IS NULL` to prevent double-binding.
- **`resolver.py`** — `IdentityResolver`. Public API:
  - `resolve(platform: str, platform_id: str) -> User | None` — returns the user or `None`. Called per inbound message by adapters.
  - `add(name: str, …) -> User` — slug derivation + collision-handling; bumps the shared `IdentityVersionCounter` (see below).
  - `bind(slug: str, platform: str, platform_id: str) -> PlatformIdentity` — `add`+`bind` happen in one transaction so a UNIQUE conflict rolls back the User insert too.
  - `remove(slug: str) -> None` — soft-delete (`deleted_at = now()`); refuses if the target is the last `authorization='operator'` user.
  - `get_operator() -> User` — cached household-owner row used by the persona prompt; raises if zero or >1 operators exist (multi-operator deployments must explicitly elect one via a config knob deferred to Slice 4).
  - **Upper-bound operator guard (architect-001).** Symmetric to the last-operator-remove gate: `alfred user add --authorization operator` and `alfred user set <slug> --authorization operator` raise `OperatorAlreadyExistsError` (CLI exits 2; `cli.user.error.operator_already_exists`) **unless** the caller passes `--replace-operator <existing-slug>`, which demotes the existing operator to `trusted` and promotes the named user inside one SQL transaction (one audit row, both deltas). Prevents the resolver state where `get_operator()` would raise and wedge adapter startup.
- **`cli.py`** — `alfred user *` Typer subcommands wired into `src/alfred/cli/main.py`. CLI normalises kebab-vs-snake at the boundary (e.g. `--authorization read-only` and `--authorization read_only` both resolve to enum value `read_only`); help text and `user show` output use kebab-case.
- **`version_counter.py`** — `IdentityVersionCounter`: a single `int` bumped by every mutating resolver method. `BudgetGuard` and the resolver's in-process LRU subscribe; bump → next caller refetches from Postgres before serving cached data. Cross-process invalidation is handled separately (next paragraph).

### Cross-process cache invalidation (CLI ↔ `alfred-discord`)

The CLI process bumps the in-process counter when it mutates, but `alfred-discord` is a *different* process and won't see that bump. Slice 2 uses **PostgreSQL `LISTEN/NOTIFY`**: every mutating CLI command issues `NOTIFY alfred_identity_changed, '<payload>'` inside the same transaction as the data write; `alfred-discord` runs a background listener task that bumps its local counter on receipt. The payload is small (slug + op) and used only as a hint — the next resolver/budget call refetches the row of record.

ADR-0010 records both the notify channel name and the fallback: in deployments where `LISTEN/NOTIFY` is unavailable (e.g. PgBouncer in transaction-pooling mode), the resolver and `BudgetGuard` fall back to a bounded 60-second TTL on cached entries, and the CLI's success message for `user set` / `user remove` includes the caveat *"changes propagate to running adapters within 60 seconds."* The TTL is a `Settings.identity_cache_ttl_s` knob, default 60, so operators on PgBouncer can tune it.

**Listener task resilience (err-001).** A long-running listener task drops its connection on Postgres restart / network blip / PgBouncer recycle. Default fire-and-forget would mean a silent loss-of-invalidations window — soft-deleted users keep serving cached entries indefinitely, violating CLAUDE.md hard rule #7. The adapter wraps the listener in an **exponential-backoff reconnect supervisor** (1s → 60s cap; reset on successful `LISTEN`) and emits `discord_identity_listener_reconnects_total` + a one-shot `WARN` per disconnect. Exit-and-restart was rejected because mid-DM-turn termination loses in-flight conversation state. Unit test stub: `test_identity_listener_reconnect_on_connection_loss`. Documented in ADR-0010.

**TTL backstop is unconditional.** `identity_cache_ttl_s` (default 60s) runs *independently* of the LISTEN/NOTIFY path — it is NOT a "PgBouncer-only fallback" that disengages when the listener is healthy:

- **Checked on every cache read** — every `IdentityResolver.resolve()` and every `BudgetGuard.consume()` call compares `now() - entry.cached_at >= ttl_s` before serving; expired entries refetch from the row of record regardless of listener health.
- **Reset on entry creation OR refresh** — both the initial cache fill AND every NOTIFY-driven update reset the TTL timer, so a healthy listener + healthy cache means the TTL rarely fires (entries are evicted by NOTIFY first).
- **Maximum-staleness invariant** — during a listener outage (reconnect in progress, exponential backoff still climbing) maximum staleness equals `identity_cache_ttl_s` regardless of reconnect duration. `discord_identity_listener_reconnects_total` lets operators observe outage frequency; the TTL guarantees the staleness ceiling even when the metric spikes.

### `BudgetGuard` contract change

`src/alfred/budget/guard.py`:

- Slice-1 signature `check_and_charge(cost_usd: float)` becomes `check_and_charge(user_id: str, cost_usd: float)`. `would_exceed` and `estimate_for` change shape the same way.
- Internally `dict[str, _UserBudget]` keyed on canonical user_id. `_UserBudget` carries `(daily_usd, daily_usd_version, per_call_max_usd, day, spent)`.
- **Eviction rule (security invariant, not a perf knob).** `_UserBudget._spent` and `_UserBudget._day` are the in-process source of truth for the current UTC day's spend and **must not be evicted under any circumstance**: evicting them would reset the spend counter mid-day, letting the next `check_and_charge` re-acquire the full `daily_usd` budget — a trivial cap bypass for either an attacker or a bug. Only the `daily_usd` cap is cache-able (refetched when `IdentityVersionCounter` bumps past `daily_usd_version`). `IdentityResolver.remove()` calls `BudgetGuard.evict(user_id)` on soft-delete so dead users don't accumulate; tests assert validation raises *before* `_user_budgets` is mutated to prevent typo'd user_ids from leaking entries.
- Caps come from the `User.daily_budget_usd` field on first `check_and_charge` call; refreshed on counter bump.
- Operator's slice-1 `settings.daily_budget_usd` becomes the operator's per-user cap rather than a global ceiling.
- Per-call cap stays global (`settings.per_call_max_usd`).
- Unknown `user_id` → typed `UnknownBudgetUserError(BudgetError)` ("budget unknown for user_id=…; operator must add via `alfred user add`"). Defense-in-depth — the resolver should have caught it first, but a missed call site fails loudly through a catchable typed exception (orchestrator's `except BudgetError` arm handles it, DiscordAdapter's budget-blocked UX path handles it).
- NaN/inf cost or NaN/inf `User.daily_budget_usd` at load time → `ValueError` (slice-1 input-sanitisation semantics extended per-user).

### `SecretBroker` file backend

`src/alfred/security/secrets.py`:

- `SecretBroker.__init__` grows `secrets_file: Path | None` and `require_file: bool = False` kwargs. **Path resolution** follows a layered, explicit pipeline so host CLI and containerised services agree on intent without sharing a filesystem:

  | Layer | Setting | Resolves to | Used by |
  |---|---|---|---|
  | Host default | `Settings.secrets_file` (Pydantic) | `Path.home() / ".config/alfred/secrets.toml"` | `alfred` CLI run on the host |
  | Container default | `ALFRED_SECRETS_FILE` env var set in `docker-compose.yaml` | `/etc/alfred/secrets.toml` | `alfred`, `discord-bot`, persona workers inside containers |
  | Bind-mount | `docker-compose.yaml` volumes: `~/.config/alfred/secrets.toml:/etc/alfred/secrets.toml:ro` | Same file, two paths | Maps host secrets into container read-only |
  | Override | `--secrets-file <path>` CLI flag or constructor `secrets_file=` kwarg | Any caller-supplied path | Tests, dry-runs, alternate-tenant scripts |
  | Enforcement | `require_file=True` | Constructor raises `SecretBrokerFileMissingError` if the resolved path does not exist | Production services (slice-2 default in compose); host CLI passes `require_file=False` |

  Why two paths: per CLAUDE.md devops discipline, operator-writable config lives under `~/.config/alfred/` (XDG); container code does not assume `$HOME` is the operator's. The bind-mount is read-only because the broker only reads.
- On `get(name)`: env wins on conflict for slice-1 keys; new Slice-2+ keys (`discord_bot_token` and any future addition) prefer file over env. The `_PREFER_FILE` set is declared next to `SUPPORTED_SECRETS` so the precedence is explicit at the data-source level.
- File format:

  ```toml
  # ~/.config/alfred/secrets.toml — 0600 perms, plaintext (Slice 2)
  # Slice 3+ replaces this with age-encrypted equivalent.
  deepseek_api_key = "sk-..."
  anthropic_api_key = "sk-ant-..."
  discord_bot_token = "MTI..."
  ```

- `SUPPORTED_SECRETS` grows `discord_bot_token`. The redactor walks values from both backends; longer-value-first ordering (slice-1 fix from PR #89) preserved.
- **Permissions check is fail-closed.** `_validate_secrets_file_security` runs at init time and checks: file is not a symlink (block `O_NOFOLLOW`-style traversal), `st_uid == os.getuid()` (owned by the invoking user), `st_mode & 0o077 == 0` (not group/world readable), parent directory not group/world writable. Failure raises typed `SecretBrokerPermissionsError` with path + octal mode + remediation hint (`chmod 600 ~/.config/alfred/secrets.toml; chmod 700 ~/.config/alfred`); CLI top-level catches and exits 2; long-running services (`alfred discord`) do not start. ADR-0012 documents POSIX-ACL non-coverage as a known gap (defense-in-depth at the host level, not in-process).
- **Distinct exception subtypes (devex-002).** `SecretBrokerConfigError` is the base. Three subtypes distinguish operator-fixable root causes: `SecretBrokerFileMissingError` (path doesn't exist — `touch` + `chmod 600` remediation), `SecretBrokerNotAFileError` (path is a directory, typically the Compose bind-mount auto-creating one — points at the setup script's `mkdir -p + touch` fix), `SecretBrokerPermissionsError` (file present but perms check fails — names offending mode bits + chmod fix). All catchable as `SecretBrokerConfigError` for CLI top-level dispatch; the subtype differentiation matters only for human-readable error text and t()-key routing.
- **Silent-fallback closed.** If `secrets_file` is explicitly configured but the file is missing, the broker raises `SecretBrokerFileMissingError`. `require_file=True` (set by the `alfred discord` entrypoint) makes this the default behaviour even on the implicit-default path so the operator's `discord_bot_token` never silently degrades into a `discord.py` `LoginFailure` three layers downstream.
- **Broker construction timing across CLI commands (err-002).** Every `alfred` CLI command constructs the broker **eagerly** at bootstrap. `SecretBrokerPermissionsError` therefore surfaces uniformly for `alfred user list`, `alfred audit log`, `alfred discord verify`, etc. — exit 2 with the chmod hint on any of them. `SecretBrokerFileMissingError` is gated by `require_file`; only commands that pass `require_file=True` (currently `alfred discord` + `alfred discord verify`) treat a missing file as fatal at bootstrap. Other commands proceed; if any later call asks the broker for a secret that has no env override, the broker raises `SecretBrokerFileMissingError` on the `get()` path with the same exit-2 disposition. CLI UX is uniform: a perms problem fails any command identically; a missing file fails only the commands that actually need it.
- **No direct `os.environ` reads for SUPPORTED_SECRETS.** All agent paths read secrets via `broker.get`; direct env reads for any `ALFRED_*` name in `SUPPORTED_SECRETS` are release-blockers. PR C adds a grep-scan test (`tests/unit/security/test_no_direct_env_reads.py`) that fails the build on violations. Documented in ADR-0012.
- **`.gitignore` mandate.** `secrets.toml`, `secrets.*.toml`, `**/secrets.toml` land in `.gitignore` in PR C. The broker walks parent dirs at init and refuses if it finds a `.git` directory (configurable off for tests, but the production default is "if you're inside a working tree, you wrote your secrets in the wrong place"). Setup script prints a one-line "this file is local-only, do not commit" reminder on first creation. README + ADR-0012 enumerate the backup-vector risk (`restic backup ~/.config` will exfiltrate plaintext secrets unless the operator excludes the file; documented, not enforced).

### `User.authorization` enum

Slice 2 ships the column + the enforcement points where it currently matters:

- Operator-only CLI commands (`alfred user *`, `alfred audit`, etc.) stay TUI-gated and reject non-operator callers.
- Non-operator Discord users hit their per-user budget; operator inherits the slice-1 cap.
- `read_only` users are refused by an explicit security gate at the rate-limiter, **not** a tunable rate-limit default (architect-002). `RateLimiter.allow()` takes the full `User` and the first check is `if user.authorization == READ_ONLY: return False`. A future `--rate-limit-per-min 30` override on a `read_only` user does NOT unlock the tier — the security invariant is independent of the perf knob (mirrors `_UserBudget._spent`'s "never evict" callout). The enum value stays in the schema permanently; dropping/re-adding across a Postgres CHECK constraint is a destructive migration that breaks rollback symmetry.
- **`read_only` refusals are reply-suppressed (sec-002).** A `read_only` DM is audit-logged but never replied to. Reasoning: distinct reply text for "you are read-only" vs "I don't know who you are" leaks the operator's friend-list (an unknown-user response is text + bind hint; a read-only response would confirm a binding exists). Both refusal paths therefore share the observable shape: audit row written, no reply sent. The i18n catalog **omits** a `discord.rate_limited` key for the `read_only` case; the rate-limited reply still fires on the *non-read_only* token-bucket refusal (legitimate "slow down" UX). Deliberate identity-state-oracle hardening.

Authorization-mapped trust-tier graduation (operator → T1 on Slice 3) is **not** in this slice; the `authorization` enum is orthogonal to trust tiers for now.

### Database migration `0004`

`src/alfred/memory/migrations/versions/0004_users_and_identities.py` is explicit, idempotent, and atomic. Sketch (full SQL lives in the migration file when PR A lands; this is the spec-level contract):

```sql
BEGIN;
SET LOCAL statement_timeout = '60s';

CREATE TABLE users (...);                       -- full schema below
CREATE TABLE platform_identities (...);
ALTER TABLE episodes  ADD COLUMN language text;
ALTER TABLE audit_log ADD COLUMN language text;
ALTER TABLE episodes  ADD COLUMN persona_id text;   -- nullable; defaults to 'alfred' on write
ALTER TABLE audit_log ADD COLUMN persona_id text;

-- Pre-check: derive slugs for every distinct user_id in episodes + audit_log;
-- abort with a remediation message if any slug-collides with another row's slug.

INSERT INTO users (slug, display_name, authorization, daily_budget_usd, language, created_at)
VALUES (<slug-from-operator_name>, <operator_name>, 'operator', <settings.daily_budget_usd>,
        <settings.operator_language>, now())
ON CONFLICT (slug) DO NOTHING
RETURNING id;

INSERT INTO platform_identities (user_id, platform, platform_id, created_at)
VALUES (<that user id>, 'tui', <operator_name>, now())
ON CONFLICT (platform, platform_id) DO NOTHING;

UPDATE episodes  SET user_id       = <canonical-slug> WHERE user_id       != <canonical-slug>;
UPDATE audit_log SET actor_user_id = <canonical-slug> WHERE actor_user_id != <canonical-slug>;

COMMIT;
```

Notes:

- **Persona dimension lands now.** `episodes.persona_id` + `audit_log.persona_id` are nullable on Slice 2 with the orchestrator writing `'alfred'` for every new row; this avoids a destructive Slice 4 migration when Lucius/Oracle arrive. The `WorkingMemoryPool` key type is `tuple[str, str]` (persona, user_id) with `'alfred'` as the literal Slice-2 first component — zero cost now, only a constructor widening at Slice 4.
- **Idempotence.** The whole migration is one transaction with `ON CONFLICT DO NOTHING` on the operator insert. Re-running upgrade head is a no-op.
- **Downgrade.** `alembic downgrade -1` drops the new columns + tables but preserves any forward-shaped data in `display_name` (since the column doesn't exist after downgrade); the contract is *"downgrade discards Slice-2 additions, never mangles existing rows."*
- **Collision handling.** If a `users` row already exists at the target slug AND the existing row is not flagged operator, the migration raises `OperatorSlugCollisionError(alembic.util.exc.CommandError)` — a subclass so the Alembic migration runner reports it as a normal command failure (exit code 1) rather than a crash, and the `alembic upgrade head` CLI surfaces the message to the operator. The exception's `args[0]` includes the remediation: `'slug "<target>" already in use by non-operator user "<existing display_name>"; re-run with ALFRED_OPERATOR_NAME=<unique-name> alembic upgrade head'`. If the existing row IS the operator (re-run case), the `ON CONFLICT DO NOTHING` makes it a no-op (no exception raised).
- **Integration test coverage** (`tests/integration/test_migration_0004_backfill.py`): three explicit cases — (a) custom `ALFRED_OPERATOR_NAME` backfill happy path, (b) default `operator_name='operator'` no-op, (c) non-operator slug-collision refusal with remediation message.

### Compose changes

- New `alfred-discord` service in `docker-compose.yaml`. Same image as `alfred-core` (`docker/alfred-core.Dockerfile`), `command: ["discord"]`, `restart: unless-stopped`, `depends_on: alfred-postgres healthy`, `deploy.resources.limits.memory: 256M` (perf-003 — measured RSS for a DM-only workload with the spec'd `discord.Client` flags is ~90-150 MB; comment in the Compose file reads "bump to 512M if you see OOMKills under sustained load"). Run with `docker compose up -d alfred-discord` (not `run -d` — the run subcommand is for one-shot CLI invocations).
- Bind-mount `~/.config/alfred/secrets.toml` into the container read-only at `/etc/alfred/secrets.toml`; the broker resolves the in-container path. `user: "${UID:-1000}:${GID:-1000}"` so file ownership matches across the host/container boundary on Linux; README documents the macOS/Linux/WSL2 perm-propagation matrix.
- No new datastore. The only new third-party dep is `discord.py`.

---

## 3. Discord adapter detail

### Library choice: `discord.py`

- Original library (MIT, ~13K stars), actively maintained again post-Rapptz return.
- Pin: `discord.py>=2.4,<3` in `pyproject.toml` runtime deps. No `[voice]` extras, so PyNaCl is not pulled in. The dependency resolution verifies that wheels exist for `linux/amd64` and `linux/arm64`; if any sdist sneaks in, the slice adds a `build-essential` builder stage to the Dockerfile (current expectation: pure-wheel install with `aiohttp` already wheel-packaged).
- Dependabot watches via the existing `pip` ecosystem in `.github/dependabot.yml`.
- Library logs via stdlib `logging`, not structlog. The adapter bridges `logging.getLogger("discord")` through a structlog `ProcessorFormatter` whose chain includes the broker's redactor, so any token-leaking debug line the library emits passes through the same secret-walk the structlog path uses. `tests/unit/comms/test_discord.py` asserts a fake log record containing a known SUPPORTED_SECRETS value comes out redacted.

### Bot token sourcing

- `secrets.toml` holds `discord_bot_token`. Adapter calls `broker.get("discord_bot_token")` at startup (broker raises `SecretBrokerConfigError` early if missing because the adapter passes `require_file=True`).
- Operator workflow (documented in README + setup-script tail):

  ```
  1. Create a Discord app + bot at https://discord.com/developers/applications
  2. Decide whether the Message Content intent is required for your usage
     (Slice 2 = DM-only; the lib may not require it. The setup script
     prints the current requirement based on the pinned version.)
  3. Copy the bot token; edit ~/.config/alfred/secrets.toml — add
     discord_bot_token = "MTI..."
  4. Discover your own Discord snowflake (Settings → Advanced → Developer
     Mode → right-click your username → Copy ID).
  5. Pre-map yourself:
       docker compose run --rm alfred-core user bind operator --platform discord --id <your-snowflake>
  6. Sanity-check the connection:
       docker compose run --rm alfred-core discord verify
  7. docker compose up -d alfred-discord
  8. DM the bot from Discord.
  ```

### Trust tagging at the Discord boundary

DM body content is `T2` (authenticated user). The adapter calls `tag(T2, msg.content, source="comms.discord.dm", metadata={"author_id": msg.author.id, "channel_id": msg.channel.id})` and passes the resulting `TaggedContent[T2]` to the orchestrator. The orchestrator contract change accepts `TaggedContent[T2]`, not raw `str` — making the tier explicit at the type level so the Slice-3 dual-LLM split's T3 path is a type-level discriminant, not a documentation claim.

**Only `msg.content` is read in Slice 2; every other content-bearing field is asserted empty/None (sec-001).** A denylist is fragile: discord.py 2.4+ exposes `msg.poll`, `msg.components`, `msg.activity`, `msg.application` — attacker-controlled T3 prose that a denylist would silently inline into the T2 path. The adapter uses an **allowlist**: parse `msg.content` only; assert `msg.embeds`, `msg.attachments`, `msg.stickers`, `msg.reference`, `msg.poll`, `msg.components`, `msg.activity`, `msg.application` are all empty/None. Any non-empty value triggers the T3 refusal — send `t("discord.embed_unsupported")`, write one audit row (`event=discord.embed_refused`, `subject.refused_fields=[…]`), skip the orchestrator. PRD §6.1 classifies all of these as T3 (link-unfurled content is attacker-controlled); T3 handling lands with the Slice-3 dual-LLM split. The companion surface test (`tests/integration/test_discord_message_surface.py`) pins the existence of every allowlist field on `discord.Message` so minor-version drift trips the build immediately. Unit tests in `tests/unit/comms/test_discord.py` exercise every refusal branch including the four new fields.

### Adapter wiring shape (annotated pseudocode — implementation detail goes in the plan)

```python
class DiscordAdapter:
    """Slice 2 DM-only. CommsAdapter Protocol implementation."""

    name = "discord"

    def __init__(
        self,
        *,
        orchestrator: _OrchestratorLike,
        identity_resolver: IdentityResolver,
        broker: SecretBroker,
        outbound_dlp: OutboundDlp,
        rate_limiter: RateLimiter,            # async Protocol (see below)
        client_factory: Callable[[discord.Intents], _DiscordClientLike] = discord.Client,
    ) -> None: ...

    async def run(self) -> None:
        intents = self._compute_intents()    # logged + audited as adapter-startup row
        client = self._client_factory(intents)

        @client.event
        async def on_message(msg: discord.Message) -> None:
            if msg.author.bot or not isinstance(msg.channel, discord.DMChannel):
                return  # bot-ignored or non-DM (GroupChannel rejected explicitly;
                        # group persona sessions land Slice 4 via threads).
            await self._handle(msg)

        self._install_signal_handlers(client)
        await client.start(self._broker.get("discord_bot_token"), reconnect=True)

    async def _handle(self, msg: discord.Message) -> None:
        # 1. Trust-boundary allowlist (sec-001): parse msg.content only;
        #    every other content-bearing field MUST be empty/None.
        refused = _non_empty_content_fields(msg)   # checks embeds, attachments,
                                                    # stickers, reference, poll,
                                                    # components, activity, application
        if refused:
            await self._audit_and_send_refusal(msg, "discord.embed_refused",
                                               "discord.embed_unsupported",
                                               refused_fields=refused)
            return

        # 2. Identity resolution.
        user = self._resolver.resolve("discord", str(msg.author.id))
        if user is None:
            await self._handle_unknown_dm(msg)   # dedup + global cap; see Audit-DoS below.
            return

        # 3. Per-user rate limit (async — RateLimiter Protocol; see comms-006).
        if not await self._rate_limiter.allow(user.slug):
            await self._audit_and_send_refusal(msg, "discord.rate_limited",
                                               "discord.rate_limited", user=user)
            return

        # 4. Per-coroutine language (ContextVar — §0.1).
        set_language(user.language)

        # 5. Capture WM once at the top of the turn; never re-enter the pool mid-turn.
        wm = await self._working_pool.acquire(("alfred", user.slug))
        try:
            response = await self._orch.handle_user_message(
                user=user,                              # frozen value object (i18n-004)
                content=TaggedContent[T2](msg.content), # explicit tier (sec-007)
                working_memory=wm,
            )
        except BudgetExceededError as exc:
            # Typed exception carries spent_usd / cap_usd; template never interpolates str(exc).
            await self._send(t("discord.budget_blocked", spent=exc.spent_usd, cap=exc.cap_usd))
            return
        except UnknownBudgetUserError:
            # Defense-in-depth: resolver should have caught it. Loud audit + generic UX.
            await self._send(t("discord.alfred_error"))
            raise
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("discord.handler_failed", user_id=user.slug)
            await self._send(t("discord.alfred_error"))
            raise   # propagate so the gateway loop's error handler can decide reconnect
        finally:
            await self._working_pool.release(("alfred", user.slug), wm)

        # 6. All outbound goes through _send → OutboundDlp.scan → code-block-aware splitter.
        await self._send(response)

    async def _send(self, text: str) -> None:
        """Single chokepoint: every user-visible message passes through DLP scan
        and the markdown-aware splitter. Tests assert every exit branch of
        _handle calls _send (no msg.channel.send anywhere else)."""
        safe = self._outbound_dlp.scan(text)
        for chunk in _split_for_discord(safe, max_len=2000):
            await self._channel.send(chunk)
```

Three things in the pseudocode are load-bearing for the design:

- **Single `_send` chokepoint.** PR D2 includes a test that grep-asserts `msg.channel.send` appears in `discord.py` zero times outside `_send`. Every refusal/error/success path goes through the same DLP scan — closing the slice-1 bypass where `BudgetError`/`Exception` paths interpolated raw `str(exc)`.
- **No `str(exc)` in user-facing templates.** `discord.budget_blocked` and any other template that needs detail receives typed kwargs from a typed exception (`BudgetExceededError(spent_usd, cap_usd)`). The exception's English `__str__` only goes to structlog + audit subject. `discord.alfred_error` is a fixed phrase with no `{error}` placeholder. Convention line documented in §3 and enforced by a test that asserts no `t(...)` call site interpolates an `Exception` instance.
- **Audit-before-send.** Each refusal helper writes the audit row first; on audit-append failure (`AuditWriteError`), the helper logs ERROR with full structured context, bumps `alfred_audit_write_failures_total`, and propagates — mirroring the slice-1 "loud audit, re-raise" pattern. The user never sees a refusal that the audit log doesn't witness.
- **`_send`-internal failure audit semantics (err-003).** Three `_send` failure modes each get a distinct `result` value so the audit row distinguishes them from clean `success`: `result=dlp_failed` (OutboundDlp.scan raises; `subject.dlp_error=<class>`), `result=split_failed` (`_split_for_discord` raises on markdown-state corruption), `result=send_failed` (`channel.send` 5xx after one retry; `subject.delivered_chunk_count=<int>`, 0 if first chunk failed, non-zero on a torn multi-chunk reply). All three send the fixed `discord.alfred_error` to the user. The success audit row is written **after** `_send` returns OK, not before — eliminates the previous "audit claims success while user got silence" race. If the orchestrator already wrote a tentative `result=success` from its own happy-path (slice-1 pattern), a `_send` failure appends a follow-up `comms.discord.send_outcome` audit row with the corrected `result` and `delivered_chunk_count`; the audit-graph CLI joins them by trace_id. One unit test per branch in `tests/unit/comms/test_discord.py`.

### Orchestrator contract change

Slice-1: `handle_user_message(content: str) -> str`.
Slice-2: `handle_user_message(*, user: User, content: TaggedContent[T2], working_memory: WorkingMemory) -> str`.

Why the shape:

- **`user` is a frozen value object captured by the adapter once per turn.** The adapter calls `IdentityResolver.resolve()` once; the orchestrator never re-resolves mid-turn. `user.language`, `user.display_name`, `user.slug` are read off the object — no instance state, no cancellation-backstop race against `self._operator_*`.
- **`TaggedContent[T2]` makes the trust tier load-bearing at the type level**, not a comment claim. Slice 3's T3 path is a new type, not a flag.
- **`working_memory` is captured at top-of-turn and passed in.** The `WorkingMemoryPool` (see below) is owned by `src/alfred/memory/working.py`, not by the orchestrator. Pool's `acquire` returns the live `WorkingMemory`; orchestrator mutates it; pool's `release` records the in-use → idle transition. LRU eviction skips entries that haven't been released. Picks Option (c) from mem-001 — cheapest, aligns with single-instance pattern.

Internal effects:

- `episodic.record(user_id=user.slug, persona_id="alfred", language=user.language, ...)` — every stored row carries the language tag per CLAUDE.md i18n rule 3.
- `audit.append(actor_user_id=user.slug, persona_id="alfred", language=user.language, ...)` — same.
- `budget.check_and_charge(user.slug, cost_usd)`.
- `render_persona_prompt(persona=ALFRED_PERSONA, operator_name=<household-owner display_name>, requesting_user_name=user.display_name, language=user.language)` — the prompt is now persona-parametric (forward-compat for Slice 4) AND distinguishes household owner from current addressee. The household-owner row is fetched via `IdentityResolver.get_operator()` cached at orchestrator construction; if multiple operators exist or zero exist, that call raises and the adapter surfaces a friendly error. The persona template reads *"You are head butler in {operator_name}'s household. You are currently addressing {requesting_user_name}."* Wrong-semantics fix: Bob isn't the operator, Bob is the addressee.

**Audit-log language semantics (i18n-003).** `audit_log.language = user.language` per row tags the user turn for traceability (matches `episodes.language`); `audit_log.subject` JSONB stays operator-readable **English** (canonical keys + canonical values — `event=discord.embed_refused`, `result=refused`, etc., never translated). Verbatim user content embedded in `subject` (e.g. the unknown-DM body echoed for operator review) is **data** — it inherits the user's natural language unchanged. Human-rendered text *outside* the audit row (CLI / TUI / Discord replies) goes through `t()` in the active user's language. Rule prevents both (a) translating subject strings, which would break grep-auditing, and (b) dropping per-row language threading, which would break CLAUDE.md i18n rule 3.

**Prompt-cache-friendly layout (forward-compat for Slice 3+ Anthropic).** The system prompt is restructured so user-invariant character/behaviour content forms the prefix and per-user variables live in a clearly-bounded `<user_context>` XML tail block. Shape:

```text
<persona character + behaviour, identical for every user — cacheable prefix.
 References `<operator_name>`, `<addressed_user_name>`, `<addressed_user_language>`
 by name; instructs the model to respond in the BCP-47 language identified by
 `<addressed_user_language>`.>

<user_context>
  <operator_name>Bruce</operator_name>
  <addressed_user_name>Alice</addressed_user_name>
  <addressed_user_language>en-US</addressed_user_language>
</user_context>
```

**Language imperative is load-bearing (i18n-002).** The cacheable prefix MUST include the "Respond in the BCP-47 language tag identified by `<addressed_user_language>`" instruction — losing it would silently re-monolingual the bot under the prompt-cache restructure. Slice 1's persona prompt embedded this imperative inline with the user data; the Slice-2 rewrite preserves the imperative in the cacheable prefix (by name-reference to the `<user_context>` elements) so caching never invalidates on a language change AND the imperative travels with the persona character description. The persona-prompt unit test asserts the imperative phrase + each `<user_context>` element name appears in the rendered prefix. Slice 2 doesn't enable prompt caching (DeepSeek default), but the shape is the one Slice 3's Anthropic fallback will key on. Cheapest moment to lock in the prefix shape is now, while the prompt is already being broken for per-user threading.

### `WorkingMemoryPool` ownership and lifecycle

Lives in `src/alfred/memory/working.py` (owned by `alfred-memory-engineer`, not the orchestrator). Public surface:

- `async acquire(key: tuple[str, str]) -> WorkingMemory` — lazy-init under a per-key `asyncio.Lock` (registry of locks lives inside the pool; lazy-created on first key). Lazy-rehydrate from `EpisodicMemory.recent(persona=..., user_id=..., limit=20)` runs inside a pool-owned short-lived session (not the orchestrator's per-turn session — keeps locality clean per core-006).
- `async release(key, wm)` — marks the entry idle; LRU eviction sees only idle entries.
- `evict(key)` — explicit removal; `IdentityResolver.remove()` calls it for soft-deleted users.

Bound: `settings.working_memory_pool_max`, default `max(50, active_user_count * 2)` computed at startup. Magic-50 anchored to "small household + buffer" with the multiplier covering medium households without operator tuning. `working_memory_pool_evictions_total` Prometheus counter exposes pressure.

**Cap precedence (perf-002).** Operator override always wins: when `settings.working_memory_pool_max` is set to any int, it IS the cap and the auto-formula does NOT touch it. When unset (`None`), `max(50, active_user_count * 2)` applies and is recomputed (a) on `IdentityResolver.add()` inside the CLI process AND (b) on every `alfred_identity_changed` NOTIFY receipt in `alfred-discord` — the CLI mutation happened in a different process, so the in-process `add()` hook never fires there (perf-001). The NOTIFY recompute is one cheap `SELECT COUNT(*) FROM users WHERE deleted_at IS NULL` (µs latency, ~1× per CLI mutation); the formula's intent stays honest across process boundaries with no operator action.

Key type is `tuple[str, str]` (persona, user_id). Every Slice-2 key is `("alfred", user_id)`. Slice 4 widens the persona dimension with zero call-site change.

Note: `EpisodicMemory.recent()` does not filter by persona today (it can't — slice-1 schema has no `persona_id`). With migration 0004 adding `persona_id`, `recent()` grows a `persona=` kwarg that the pool passes through. Slice-2 callers always pass `"alfred"`; Slice 4 callers pass the active persona. The Slice-2 query is alfred-only-safe because every Slice-2 row's `persona_id` is `'alfred'`; the kwarg is the future-proofing seam.

### Per-user rate limiting

New `src/alfred/identity/rate_limit.py` defines a `RateLimiter` Protocol with `async def allow(user_id) -> bool`, `async def reset(user_id)`, and `def health() -> RateLimiterHealth`. Slice-2 ships `InProcessTokenBucketRateLimiter`; Slice 5 swaps to a Redis-backed implementation with one-line caller change (Redis ops are async, so the Protocol is async-from-the-start).

Authorization defaults (revised from ai-001):

| `authorization` | Messages/min | Day-cap default |
|---|---|---|
| `read_only` | 0 (refusal) | n/a |
| `standard` | 30 | none (BudgetGuard owns the cost ceiling) |
| `trusted` | 60 | none |
| `operator` | unlimited | none |

Day-caps are dropped by default because they're economically redundant with `BudgetGuard.daily_budget_usd`. The per-min defaults are raised so a legitimate emotional-support burst (~15 turns in 90s) doesn't trip the limiter. Operators who want a harder ceiling pass `--rate-limit-per-day N` on `alfred user add` / `set` — the column is nullable and the limiter treats `NULL` as "no day-cap." State is in-process for Slice 2; Redis-backed in Slice 5+.

### Outbound DLP

New `src/alfred/security/dlp.py` — minimal but PRD §7.1-floor-compliant. Two pluggable stages:

```python
class OutboundDlp:
    def scan(self, text: str) -> str:
        text = self._broker.redact(text)                 # stage 1: known live secrets
        text = self._pattern_scanner.redact(text)        # stage 2: generic API-key shape
        # stage 3 canary: stub for Slice 3 — must return input unchanged.
        return text
```

Stage 2 ships one generic regex: `\b(?:sk|pk|tok|key)[-_][A-Za-z0-9]{20,}\b` → `[REDACTED:api-key-shape]`. This is the model-fabricates-plausible-API-key failure mode — Slice 2 introduces the first non-operator broadcast surface, so the model hallucinating a real-looking key into a DM is a leak even when no real secret is in the value-corpus. Stage 3 is a literal `return text` with a test asserting it stays a no-op; Slice 3's broader regex pack + canary detection swap in without touching call-sites.

**Structlog leaf-string redaction routes through `OutboundDlp.scan` (sec-003).** Slice 1's `_redact_value` in `src/alfred/cli/main.py` calls `broker.redact` on each structlog leaf — covers stage 1 (known live secrets) but not stage 2 (generic-API-key regex), so the operator-console surface silently misses a model-hallucinated `sk-XXXXXXXXXXXXXXXXXXXX` in a `log.exception` traceback. PR D1 refactors `_redact_value` to call `OutboundDlp.scan` instead. New test `tests/unit/security/test_dlp_structlog_bridge.py` asserts a fabricated `sk-…` value emitted via `log.warning` renders as `[REDACTED:api-key-shape]`. Substitution happens once at structlog-processor registration; no call-site changes.

Modification is silent for Slice 2 (the user sees the redacted text; operator sees the modification in the audit subject's pre/post byte counts). The length-delta oracle that silent redaction creates is logged as a known Slice-2 risk in §7 — the Slice-3 mitigation menu (fixed banner, bucket-padding, or constant-time scan) is dispatched to `alfred-security-engineer` then.

### i18n per-user

New `User.language` column (BCP-47, default `settings.operator_language`). Set per-coroutine via `set_language(user.language)` (ContextVar — §0.1). `User.language` is validated at every ingress: a Pydantic `field_validator` on `User` and `Settings.operator_language` runs `babel.Locale.parse`, and the Typer `--language` callback runs the same check before mutation, surfacing `t("cli.user.error.invalid_language", value=…)` on rejection. At runtime, `IdentityResolver` WARN-logs once per user per process when the stored language has no shipped catalog, and `t()` falls back to English so user-visible messages never render as bare i18n keys — model output still goes to the model in the user's language, AlfredOS chrome stays English when the catalog is missing.

**Catalog-missing CLI warning (devex-003).** `babel.Locale.parse` accepts any well-formed BCP-47 tag, but Slice 2 ships English catalog only. On any `--language X` ingress, the Typer callback checks the shipped-catalog list; if missing, the CLI warns-with-confirm (interactive TTY) using `cli.user.warn.catalog_missing` and accepts `--no-warn-missing-catalog` as the non-interactive escape. `alfred user list` annotates a non-shipped language with `de-DE (no catalog)` via `cli.user.list.catalog_missing_annotation` so the drift is visible at inspection without grepping audit.

Catalog additions enumerated (full list — no wildcards in spec):

**Discord adapter keys:**

- `discord.unknown_user_first` — first-DM-since-startup variant. **Body (devex-004):** "I don't recognise this Discord ID yet (snowflake: `{snowflake}`). Ask your operator to run: `alfred user add --name <YourName> --discord-id {snowflake}`. The operator's audit log shows this DM." (`{snowflake}` is the only placeholder; `<YourName>` stays literal for the unknown user to fill in.)
- `discord.unknown_user_repeat` — subsequent variant, polite, no hint (suppressed entirely after the second hit per the dedup window).
- `discord.embed_unsupported` — embeds/attachments/stickers/poll/components/activity/application refusal (sec-001).
- `discord.rate_limited` — **non-`read_only`** token-bucket refusal only. `read_only` users get NO reply (sec-002 — no separate key, the read_only audit row is the only observable signal).
- `discord.budget_blocked` — typed kwargs `{spent}`/`{cap}`, never `{error}`.
- `discord.alfred_error` — fixed phrase, no interpolation.

**`alfred user` CLI keys (enumerated, not wildcarded — pybabel extract needs concrete names):**

- `cli.user.help.group` + per-subcommand `cli.user.help.<add|list|show|remove|bind|unbind|set>.short` + `.long` (14 keys).
- `cli.user.flag.<name>.<short|long>` for every option (`--name`, `--discord-id`, `--authorization`, `--daily-budget-usd`, `--language`, `--rate-limit-per-min`, `--rate-limit-per-day`, `--platform`, `--id`, `--json`, `--include-deleted`, `--yes`). ~24 keys.
- Success/confirmation: `cli.user.added`, `cli.user.bound`, `cli.user.unbound`, `cli.user.removed`, `cli.user.set.success`, `cli.user.remove.confirm`, `cli.user.remove.refused_last_operator`, `cli.user.operator_replaced`.
- Errors: `cli.user.error.not_found`, `.platform_id_in_use`, `.user_already_bound`, `.invalid_authorization`, `.invalid_language`, `.invalid_bcp47`, `.budget_must_be_positive`, `.no_operator`, `.no_tty_without_yes`, `.operator_already_exists` (architect-001 — names the existing operator + suggests `--replace-operator`).
- `alfred user list` table chrome (i18n-001 — `rich.Table` column headers go through `t()`): `cli.user.list.column.slug`, `.column.display_name`, `.column.authorization`, `.column.daily_budget_usd`, `.column.platforms`, `.column.language` (6 column-header keys), plus `cli.user.list.empty_hint`, `cli.user.list.deleted_marker`, `cli.user.list.no_platforms`, `cli.user.list.catalog_missing_annotation` (renders `de-DE (no catalog)` per devex-003).
- `alfred user show` annotations: `cli.user.show.override_indicator`, `.derived_indicator`, `.value.unset`, `.platforms_none`.
- BCP-47 catalog-missing warning (devex-003): `cli.user.warn.catalog_missing` (interactive confirm; `--no-warn-missing-catalog` escape).
- Setup script: `cli.setup.operator_added`, `cli.setup.operator_name_prompt`, `cli.setup.discord_bind_hint`.

**Secret-broker keys:** `secrets.file_perms_too_open` (perms error + chmod hint), `secrets.file_missing_required` (file missing + touch/chmod remediation), `secrets.path_is_directory` (path is a directory; explains Docker-bind-mount cause + setup-script fix).

PR A also drives by the slice-1 leak at `src/alfred/cli/main.py:54` (`typer.Typer(help="AlfredOS CLI")` not wrapped in `t()`) so the convention is uniform after Slice 2 ships. Every `typer.Option(help=...)` and Typer command `help=` MUST wrap in `t()` going forward — documented as a convention rule in PR A.

**`User.role` → `User.authorization` rename note for i18n:** the underlying enum value is `read_only` (snake_case in DB / Pydantic); CLI surface is `read-only` (kebab); normalisation happens at the Typer boundary. Both `--authorization read-only` and `--authorization read_only` work; help text and `user show` output use kebab. Documented as a CLI-naming convention block in §4.

### Audit-DoS mitigation (unknown-DM flood)

Snowflake-iterating spam bot can fill the append-only audit log unbounded if every unknown DM writes a row. Two layers:

1. **Per-snowflake LRU dedup** (`TTLCache(maxsize=1024, ttl=3600s)`): first unknown DM from snowflake X writes one audit row and replies once; repeat unknown DMs from X within the TTL are silently dropped — no reply, no audit row. The 1-hour TTL is a deliberate trade: short enough that a legitimate retry by the same user (~1h later) generates a fresh audit row + refusal (so the operator sees the re-contact), long enough to absorb a typical spam-burst window. **Semantics:** a re-DM at T+61m produces a *new* audit row and reply — by design. If the operator wants permanent "one audit row per snowflake ever" semantics they block the user at Discord (which prevents the DM reaching the bot at all). Implementation note: dedup state is in-process; if `alfred-discord` restarts within the TTL, the dedup window restarts. For persistent dedup (which Slice 2 does NOT ship), the source-of-truth would have to be `audit_log` itself.
2. **Global token-bucket cap** on `discord.unknown_user_dm` audit writes (default 60/min). Beyond the cap, the audit write is dropped and a `discord_unknown_dm_audit_dropped_total` counter bumps; operators see a single ERROR log row per minute summarising the drop volume.

Error-semantics table grows a `discord.unknown_user_dm_suppressed` row. Test: `test_unknown_dm_flood_writes_one_audit_row` (50 DMs from same snowflake → 1 audit row, 1 reply).

### Shutdown + failure modes

Adapter's `stop()` triggers `client.close()` and awaits pending sends; SIGTERM/SIGINT handlers installed in `run()` call it. `docker compose stop alfred-discord` sends SIGTERM with 10s grace.

`client.start(token, reconnect=True)` is explicit — `discord.py`'s built-in reconnect handles transient gateway disconnects. The adapter classifies known `discord.py` exceptions:

| Exception | Adapter action | User-visible | Audit |
|---|---|---|---|
| `LoginFailure` | log ERROR, exit 2 | n/a (no gateway up) | adapter-startup row with `result=login_failed` |
| `ConnectionClosed` (4xxx) | log WARN, library auto-reconnects | nothing | nothing |
| `HTTPException` 5xx mid-send | log WARN, retry once, then drop chunk + audit | error message (`discord.alfred_error`) | row with `result=send_failed` |
| Repeated reconnect failures (>10 in 60s) | log ERROR, exit 1 | nothing | `result=gateway_unhealthy` |

`AdapterHealth` snapshot exposes `gateway_connected`, `last_on_ready_at`, `recent_reconnect_count`. Seeds Slice-5 metrics; Slice-2 surface is `alfred discord verify` + log lines.

### Error semantics (mirror TUI, augmented for Discord)

| Event | Audit `result` | User-visible outcome |
|---|---|---|
| Embed/attachment/sticker | `refused` (event=`discord.embed_refused`) | One polite refusal message |
| Unknown Discord ID (first contact) | `refused` (event=`discord.unknown_user_dm`) | One polite refusal with snowflake echo + bind hint |
| Unknown Discord ID (dedup-suppressed) | `suppressed` (event=`discord.unknown_user_dm_suppressed`) | No reply |
| `read_only` user DM | `refused` (event=`discord.read_only_refused`) | **No reply** (sec-002 — reply-suppressed to deny the friend-list oracle) |
| Rate-limited (non-`read_only`) | `rate_limited` | Polite refusal (no `{error}` interpolation) |
| Budget blocked | `budget_blocked` (orchestrator-side) | Friendly typed-kwargs message (`{spent}/{cap}`) |
| Provider failed | `provider_failed` (orchestrator) | Generic `discord.alfred_error` (no exception string) |
| DLP modified output | logged INFO; pre/post bytes in audit subject | No user-visible difference (silent — known Slice-2 oracle, mitigated Slice 3) |
| Cancelled mid-turn | `cancelled` (orchestrator try/finally) | Nothing sent; budget refunded for undelivered tokens |
| Audit-append failure on refusal path | logged ERROR + counter bumped + re-raised | n/a — handler crashes (loud audit discipline) |

### Markdown-aware splitter

`_split_for_discord(text, max_len=2000)` is markdown-state-aware: when a 2000-char boundary lands inside an open ```` ``` ```` fence or inline-code span, the splitter closes the open delimiter at the chunk boundary and re-opens it (with the same language tag) at the top of the next chunk. Concatenation modulo close/re-open markers equals the original — asserted by hypothesis property tests. The helper is factored out as `src/alfred/comms/markdown_split.py` for reuse by Slice-4 Telegram (4096-char cap, similar markdown rules).

---

## 4. Identity model + CLI surface

### Canonical user_id: slug from name

- Normalisation pipeline (applied in this exact order):
  1. **NFKC normalise** the raw display name (Unicode canonical form).
  2. **ASCII-transliterate** non-ASCII characters via `unidecode` (e.g. `é → e`, `ł → l`, `中 → zhong`). Characters that cannot be transliterated are dropped.
  3. **Lowercase** the result.
  4. **Replace** every run of non-alphanumeric chars with a single `-`.
  5. **Trim** leading/trailing `-` and **collapse** any internal repeated `-` to one.

  Examples: `Alice O'Connor` → `alice-o-connor`; `José Núñez` → `jose-nunez`; `田中` → `tian-zhong`; `___bob---` → `bob`.
- **Edge cases:**
  - **Empty result** (e.g. raw name was `"🌟🎉"` or `"___"` — every char dropped or stripped): pipeline falls back to the literal string `user`, then collision suffixing applies (`user`, `user-2`, `user-3`, …). The CLI emits a warning (`cli.user.add.slug_fallback`) recommending `--slug-override` so the operator can pick a memorable handle.
  - **Length cap:** after step 5, the slug is **truncated to 63 chars**. Slugs are stored as `TEXT` (not as PostgreSQL identifiers, so the 63-char identifier limit doesn't bind us); 63 is chosen purely for **log-line readability and column-display width** in `alfred user list`. Truncation happens BEFORE collision suffixing so the suffix never gets cut off (a `bob-2` becoming `bob-` on truncation would silently collide).
  - **Homograph awareness:** ASCII transliteration is intentionally lossy — `José` and `Jose` produce the same slug, and visually-distinct Unicode that transliterates to the same string collapses to one canonical ID. This is the **intended behaviour** for canonical IDs (one human = one slug), but operators should be aware that the slug is not an authentication signal — the platform-side identity binding (Discord snowflake) is. The `alfred user add` CLI logs both the source name and the derived slug at INFO so any unexpected collapse is visible in `alfred audit log`.
- On collision (including against soft-deleted users — slugs survive `deleted_at`): append `-2`, `-3`, … `bob` → `bob-2` if `bob` exists.
- Slug is `users.slug` UNIQUE (with integer surrogate `id` for FK efficiency).
- Slug appears in `episodes.user_id` and `audit_log.actor_user_id` — operator-readable on log inspection.
- **CLI surfaces the adjustment explicitly.** When the derived slug differs from the base (i.e. a collision happened), `alfred user add` success output appends a one-line note: `Note: slug adjusted to 'bob-2' because 'bob' already exists (soft-deleted users retain their slug). Use this slug for follow-up commands.` Audit row's `subject` captures both the base-slug and the resolved slug. Same logic in the setup script's bootstrap step + the operator-onboarding section of the README.

**Why slug not UUID:** debuggability. `alfred audit log --user bob` is more natural than `--user 01HQX7...`. Collision-handling cost is one trip through `users` on `add`. (See [glossary: canonical user_id](../../glossary.md#canonical-user-id).)

### `User` ORM (full column list)

| Column | Type | Notes |
|---|---|---|
| `id` | int PK | autoincrement, surrogate for FK efficiency |
| `slug` | str UNIQUE NOT NULL | canonical user_id, slug from name |
| `display_name` | str NOT NULL | original `--name`, preserved with casing/spacing for persona prompt |
| `authorization` | enum NOT NULL CHECK | `read_only` / `standard` / `trusted` / `operator` (column renamed from `role` to avoid collision with `Episode.role`) |
| `daily_budget_usd` | float NOT NULL CHECK `> 0` | per-user daily cap |
| `language` | str NOT NULL | BCP-47, validated via `babel.Locale.parse` |
| `rate_limit_per_min` | int NULL CHECK `>= 0` | `NULL` → authorization-derived default; integer overrides |
| `rate_limit_per_day` | int NULL CHECK `>= 0` | opt-in hard ceiling above the BudgetGuard cost cap |
| `created_at` | timestamptz NOT NULL | |
| `deleted_at` | timestamptz NULL | soft-delete; `alfred user list` excludes by default |

### `PlatformIdentity` ORM

| Column | Type | Notes |
|---|---|---|
| `id` | int PK | |
| `user_id` | int FK → `users.id` ON DELETE CASCADE | |
| `platform` | enum NOT NULL CHECK | `tui` / `discord` (extends in Slice 4 for Telegram) |
| `platform_id` | str NOT NULL | Discord snowflake / TUI operator name |
| `created_at` | timestamptz NOT NULL | |
| `deleted_at` | timestamptz NULL | partial UNIQUE excludes soft-deleted rows |

Composite UNIQUE on `(platform, platform_id)` and partial `UNIQUE(user_id, platform) WHERE deleted_at IS NULL` — one Discord ID binds to one canonical user; one user binds to one identity per platform.

### CLI command details

All under `alfred user`, all writing audit rows on mutation. CLI exits 0 on success, 1 on internal error, 2 on misuse (incl. non-TTY without `--yes`), 130 on Ctrl-C.

```bash
# Add a new user, optionally binding a Discord ID. Atomic — bind failure rolls back the user insert.
alfred user add \
    --name "Bob" \
    [--discord-id 123456789012345678] \
    [--authorization standard|trusted|read-only|operator]  # default: standard
    [--daily-budget-usd 0.50]                              # default: 0.50 (raised from 0.10; see §7 note)
    [--language en-US]                                     # default: operator's language; validated BCP-47
    [--rate-limit-per-min 30]                              # default: authorization-derived
    [--rate-limit-per-day 1000]                            # optional opt-in ceiling
    [--output-slug]                                        # prints just the derived slug for scripting

# List active users (rich.table SIMPLE box; columns: slug, display_name, authorization,
# daily_budget_usd, platforms, language; sort by created_at ASC; soft-deleted strikethrough
# when --include-deleted; empty-state hint pointing at `user add`).
alfred user list                                       # plain table
alfred user list --json                                # JSON for scripting
alfred user list --include-deleted                     # show soft-deleted too

# Show one user. Indicates override-vs-derived for rate_limit_per_min.
alfred user show <slug>

# Soft-delete. Refuses if target is the last authorization='operator' user (architect-007).
alfred user remove <slug>                              # confirms by default; refuses under non-TTY without --yes (exit 2)
alfred user remove <slug> --yes                        # skip confirmation

# Bind / unbind. Bind refuses on existing user_id-platform conflict (use `unbind` first).
alfred user bind <slug> --platform discord --id 123456789012345678
alfred user unbind <slug> --platform discord

# Tune an existing user. `unset` reverts an override to authorization-derived default (rate-limit only).
# --replace-operator <slug> required to promote a second user to operator (architect-001);
# the named existing operator is demoted to `trusted` in the same audit-logged transaction.
alfred user set <slug> [--daily-budget-usd <float>] [--authorization <role>] \
                       [--language <bcp47>] [--rate-limit-per-min <int>|unset] \
                       [--replace-operator <existing-operator-slug>]
```

Every mutating command writes an audit row (`event="user.add"|"user.remove"|"user.bind"|…`, `actor_user_id=<operator's slug>`, `subject={"target_user": …, …diff…}`) and issues `NOTIFY alfred_identity_changed` in the same transaction.

### CLI naming convention block

- Enum values in DB and Pydantic models: snake_case (`read_only`).
- CLI-facing text (option help, output): kebab-case (`read-only`).
- Normalisation: Typer custom type accepts either input and resolves to the snake form.
- Tests assert both `--authorization read-only` and `--authorization read_only` produce equivalent DB rows.

### First-deploy operator-onboarding flow

The setup script (`bin/alfred-setup.sh`) gains a portable bootstrap step (devops-003 + devex-002 fixes folded in):

```bash
step "Bootstrapping operator identity"

# Prereqs (jq is new; brew/apt install hint printed on miss).
require_cmd jq

# Ensure the secrets file + parent dir exist with 0600/0700 BEFORE the first
# `docker compose run` (devex-002). The Compose bind-mount silently creates a
# *directory* at the host path if it's missing, which then surfaces as a
# confusing SecretBrokerPermissionsError rather than the real cause.
mkdir -p "$HOME/.config/alfred"
chmod 700 "$HOME/.config/alfred"
touch "$HOME/.config/alfred/secrets.toml"
chmod 600 "$HOME/.config/alfred/secrets.toml"

# Export UID/GID so the `${UID:-1000}:${GID:-1000}` substitution in
# docker-compose.yaml resolves to the host's real ids on macOS/non-1000-UID
# Linux. UID is exported automatically by some shells and silently absent in
# others; GID is almost always unexported. Both are needed for the bind-mount
# to read/write the secrets file. The README documents the same `export UID
# GID` line for operators who run `docker compose up` outside this script.
export UID GID

# Idempotency: capture exit code separately so an infra failure aborts cleanly.
if user_list_json="$(docker compose run --rm alfred-core user list --json)"; then
  has_operator="$(printf '%s' "$user_list_json" | jq -r '[.[] | select(.authorization=="operator")] | length')"
else
  fail "user list failed (postgres reachable?)"
fi

if [[ "$has_operator" -eq 0 ]]; then
  # Non-TTY: ALFRED_OPERATOR_NAME is the silent override.
  if [[ -t 0 ]]; then
    read -p "Operator display name [Operator]: " name
    name="${name:-Operator}"
  else
    name="${ALFRED_OPERATOR_NAME:-Operator}"
  fi

  # Safe env-read for the budget default (slice-1's read_env_var helper, not `source .env`).
  budget="$(read_env_var ALFRED_DAILY_BUDGET_USD || echo 1.0)"

  # Get the canonical slug back from the CLI (--output-slug), not shell guesswork.
  slug="$(docker compose run --rm alfred-core user add --name "$name" \
            --authorization operator --daily-budget-usd "$budget" --output-slug)"
  display_lower="$(printf '%s' "$name" | tr '[:upper:]' '[:lower:]')"   # bash 3.2 portable

  echo "Operator added as canonical user '${slug}' (display name: ${name})."
  [[ "$slug" != "$display_lower" ]] && \
    echo "  (Slug differs from display-lowercase; use '${slug}' in future CLI commands.)"

  # Optional Discord bind prompt — non-TTY skip.
  if [[ -t 0 ]]; then
    read -p "Discord snowflake to bind now (Settings > Advanced > Developer Mode > right-click > Copy ID; blank to skip): " snowflake
    if [[ -n "$snowflake" ]]; then
      docker compose run --rm alfred-core user bind "$slug" --platform discord --id "$snowflake"
      docker compose run --rm alfred-core discord verify  # green/red signal before daemonising
    fi
  fi
fi
```

The script's `tr` lowercasing replaces bash-4-only `${name,,}` (macOS ships bash 3.2). `read_env_var` is the slice-1 helper that grep-cut-trs out a key from `.env` without `source`-ing (which would execute any inline shell).

To enable Discord, the operator then runs (documented in README):

```bash
docker compose run --rm alfred-core user add --name Alice --discord-id 987654321 --daily-budget-usd 0.50
docker compose run --rm alfred-core user add --name Bob --discord-id 555444333 --daily-budget-usd 0.50 --language de-DE
docker compose up -d alfred-discord
```

### Slice-1-to-Slice-2 migration semantic

Migration `0004` (§2) inserts the operator from `settings.operator_name` automatically: slug-from-name, `authorization='operator'`, `daily_budget_usd` from `settings.daily_budget_usd`, language from `settings.operator_language`. One `platform_identities` row for `("tui", settings.operator_name)`. The migration also adds `episodes.persona_id`, `audit_log.persona_id`, `episodes.language`, `audit_log.language` as nullable columns; the orchestrator writes `'alfred'` + the active user's language for every new row.

Slice-1 episodes already use `settings.operator_name` as the literal `user_id`, so for the default deployment (operator_name lowercase `"operator"`) the backfill `UPDATE` is a no-op. If the operator customised `ALFRED_OPERATOR_NAME` (e.g. `"Bruce Wayne"`), the slug derivation runs deterministically (→ `bruce-wayne`) and the backfill updates `episodes.user_id` and `audit_log.actor_user_id` to the canonical slug. The pre-check (§2) refuses with remediation if any literal `user_id` slug-collides with a non-operator row's slug.

### `IdentityResolver` cache

- In-process LRU (max 256 users) keyed on `(platform, platform_id)`. Per-entry memory is ~200 B (User row + small metadata); pool size is generous because the resolver is hit per inbound message and a miss is a DB round-trip.
- Invalidation: every mutating resolver method bumps `IdentityVersionCounter` internally (no caller-side bump). On each `resolve`, compare the cached entry's `version` against the current counter; if stale, drop and refetch the single entry (selective invalidation, not pool-flush).
- Cross-process: PostgreSQL `LISTEN/NOTIFY` (§2 cross-process section) bumps the counter in `alfred-discord` on every CLI mutation. Fallback: 60s TTL when `LISTEN/NOTIFY` is unavailable.
- The 256-vs-50 cache-size asymmetry between resolver (256) and `WorkingMemoryPool` (default ~50) is intentional and documented: resolver entries are tiny structs; WM entries are heavyweight deques (10-50 KB).

### Operator's TUI session resolves to themselves

`TuiAdapter` calls `IdentityResolver.resolve("tui", settings.operator_name)` on start — same path Discord uses. If this fails (no operator row yet, e.g. fresh deploy that hasn't run setup), TUI exits with a friendly hint pointing at `alfred user add --authorization operator`. `IdentityResolver.get_operator()` caches the household-owner row at orchestrator construction so per-turn persona prompts don't hit Postgres for the operator's display name on every message.

---

## 5. Test strategy, ADRs, slice graduation

### Unit tests (`tests/unit/`)

The principle: **every new branch is covered, and `src/alfred/security/` is gated at 100% line + branch via per-file `--cov-fail-under=100`.** Concrete cases below are illustrative — the plan turns them into a complete enumeration; this spec commits to the principle.

- `tests/unit/i18n/test_concurrent_language.py` — ContextVar isolation under `asyncio.gather` (§0.1).
- `tests/unit/identity/test_resolver.py` — slug derivation, collision handling (`bob` → `bob-2`), `resolve` happy + miss + soft-deleted-user miss, LRU selective invalidation on counter bump, BCP-47 validation, `get_operator()` single/zero/multiple, version counter bump on every mutating method.
- `tests/unit/identity/test_cli.py` — every subcommand happy-path + slug-collision + double-bind rejection + last-operator-remove refusal + soft-delete preserves `episodes` rows + every mutating command writes the expected audit row + non-TTY behaviour + exit codes (0/1/2/130) + kebab/snake normalisation + `--output-slug` JSON contract. `--language wat-NOT-VALID` → non-zero exit with friendly i18n error.
- `tests/unit/identity/test_rate_limit.py` — token-bucket boundary (N-th allowed, N+1-th refused), 1-over recovery cadence, day-rollover independence from minute-bucket, authorization-default vs explicit-override priority (both branches), `read_only` as zero with no free starting token, operator-as-unlimited representation, per-user independence, soft-deleted-user short-circuit.
- `tests/unit/budget/test_guard.py` extensions — per-user counter isolation; per-call cap still global; day-rollover per-user; `UnknownBudgetUserError` raised loudly; NaN/inf rejected on per-user surface (`check_and_charge`, `would_exceed`, `estimate_for`, `User.daily_budget_usd` load-path); negative cost rejected per-user without touching other users' spend; cache-on-first-use; cache invalidation when `daily_budget_usd` changes via `alfred user set` (counter-bump path); `evict(user_id)` removes the entry on `IdentityResolver.remove()`; validation raises *before* dict mutation so typo'd user_ids cannot leak entries.
- `tests/unit/memory/test_working_pool.py` (new file, owned by `alfred-memory-engineer`) — acquire/release semantics; per-key `asyncio.Lock` registry; concurrent lazy-rehydrate doesn't double-load; LRU eviction skips in-use entries; mid-turn-eviction property test (asserts no in-flight WM can be evicted); persona-key tuple form; `evict(key)` from soft-delete path.
- `tests/unit/orchestrator/test_core.py` extensions — `handle_user_message(*, user, content, working_memory)` signature; persona prompt receives both `operator_name` and `requesting_user_name`; episodic + audit rows carry the active user's `language` and `persona_id='alfred'`; `CancelledError` triggers refund + audit row with `result=cancelled` and re-raises; 7 audit branches each write the spec'd `result` value (budget_blocked, provider_failed, success, budget_overrun, cancelled-inner, cancelled-outer, unknown-budget-user); `IdentityResolver.get_operator()` zero/multi cases surface as adapter errors.
- `tests/unit/security/test_secrets.py` extensions — file-backend load; env-wins-on-conflict for slice-1 keys; file-wins for `discord_bot_token` and new keys; `require_file=True` + missing file → `SecretBrokerConfigError`; missing-file warns even when not required; symlink rejection; wrong-owner rejection; group/world-writable parent rejection; world-readable file rejection; `.git`-in-parent rejection; redactor sees both backends with longer-value-first ordering preserved.
- `tests/unit/security/test_dlp.py` (new) — known-secret redaction; no-op on clean input; audit row emitted iff pre/post byte counts differ; generic-API-key regex matches each common prefix (`sk-`, `pk_`, `tok-`, `key_`); canary stub literally returns input unchanged (regression guard for Slice-3 expansion); multi-secret longer-first ordering; both backends feed redactor. Per-file `--cov-fail-under=100` gate.
- `tests/unit/security/test_no_direct_env_reads.py` (new) — grep-scan that fails the build if any `src/alfred/**.py` reads `os.environ["ALFRED_*"]` for a `SUPPORTED_SECRETS` key outside the broker module.
- `tests/unit/comms/test_discord.py` — `_handle` happy path with `discord.Message` mock + `IdentityResolver` mock; bot-author ignored; non-DM ignored; GroupChannel rejected (asserts zero orchestrator call, zero audit row, zero reply); embed/attachment/sticker/reference refusal (each variant); unknown-DM refusal with snowflake echo; unknown-DM flood writes one audit row; rate-limited path; budget-blocked path with typed kwargs; provider-failed path produces fixed `discord.alfred_error` with no `{error}`; `CancelledError` re-raised; 2000/2001/empty length split boundary; markdown-aware splitter property test; every exit branch invokes `_send` (and `_send` is the only `msg.channel.send` caller); discord.py logging-bridge redacts a fake log record carrying a known SUPPORTED_SECRETS value; reconnect-on-disconnect flow; `LoginFailure` exits 2; `HTTPException` 5xx surfaces `discord.alfred_error`. **No real Discord client** — `client_factory` is mock-injected.
- `tests/unit/comms/test_tui_adapter.py` — `TuiAdapter.run()` delegates to `app.run_async()`; resolve-fail at startup prints the friendly hint pointing at `alfred user add --authorization operator`.
- `tests/unit/comms/test_no_direct_adapter_imports.py` (new) — AST-scans every `.py` file outside `src/alfred/comms/` and `tests/`; fails if any imports `alfred.comms.tui`, `alfred.comms.discord`, or any future concrete adapter module / class directly. Modelled on `tests/unit/security/test_no_direct_env_reads.py` (also new in PR C — same grep-scan shape). Failure message names the violating file:line, the imported symbol, and points the contributor at `src/alfred/comms/adapter.py` (the `CommsAdapter` Protocol) + ADR-0009 (te-004). Both tests share a small `_remediation_message(...)` helper so the failure-message shape is uniform. Locks the `CommsAdapter` Protocol as the only legitimate import seam — when Slice 3 swaps the transport to MCP, every consumer is already going through the Protocol so no code outside `comms/` needs to change.

### Integration tests (`tests/integration/`)

- `tests/integration/test_users_postgres.py` (new) — `User` + `PlatformIdentity` CRUD against testcontainer Postgres; CHECK constraints on `authorization` / `platform`; CASCADE delete; UNIQUE rejection on double-bind; partial UNIQUE on `(user_id, platform) WHERE deleted_at IS NULL`; `LISTEN/NOTIFY` round-trip across two sessions (CLI session mutates, listener session observes counter bump).
- `tests/integration/test_audit_persistence.py` extension — audit rows for `user.*` events survive across rollback; per-user `result=budget_blocked` / `rate_limited` events; `language` and `persona_id` populated on every new row.
- `tests/integration/test_secrets_file_backend.py` (new) — broker loads from `tmp_path/secrets.toml`; env override for slice-1 keys; file precedence for `discord_bot_token`; 0600-perm requirement; broker refuses path with `.git` parent.
- `tests/integration/test_migration_0004_backfill.py` (new) — boot Postgres at `0003`, seed episodes + audit_log with literal `operator_name`, upgrade to `0004`, assert backfill correctness for four cases (te-001): (a) custom `ALFRED_OPERATOR_NAME` happy path; (b) default `"operator"` no-op; (c) non-operator slug-collision refusal with the expected remediation message; (d) ADD COLUMN coverage — pre-existing rows get `persona_id = NULL` + `language = NULL` (nullable, no destructive backfill); post-upgrade rows carry orchestrator-written `persona_id='alfred'` + `language=user.language`; column types match DDL (`text`, not `varchar`); `alembic downgrade -1` drops the four columns + two tables without mangling the `0003` row content. All four assert row counts preserved, audit append-only invariant holds, single-transaction atomicity (a forced mid-migration failure leaves the DB at `0003`).
- `tests/integration/test_discord_adapter_integration.py` (new — renamed from "smoke", per te-003) — boots Postgres testcontainer, runs `alfred user add` for a fake Discord ID, invokes `DiscordAdapter._handle(mock_message)` against a real orchestrator + a mocked provider router. Asserts episode + audit + budget side effects; covers the forgot-to-bind variant.
- `tests/integration/test_discord_message_surface.py` — imports real `discord.py` types and **pins the surface the adapter relies on** (te-002 + sec-001) via `inspect.signature` for callables + `hasattr` for attributes. Pinned set: `discord.Message.{content, author.id, author.bot, channel, embeds, attachments, stickers, reference, poll, components, activity, application}`; `discord.DMChannel` exists and is distinguishable from `discord.GroupChannel`; `discord.Client.start(token, reconnect=True)` and `discord.Client(max_messages=…, chunk_guilds_at_startup=…, member_cache_flags=…)` accept the adapter's kwargs. Failure messages name the missing attribute and the `>=2.4,<3` pin; the test trips immediately on a minor-version rename.

### Smoke tests (`tests/smoke/`)

- `test_hello_alfred.py` extension — instead of hardcoded `user_id="operator"`, creates a `User` row via the real `IdentityResolver.add` + drives the orchestrator with that canonical slug. The smoke fixture runs `alembic upgrade head` against the testcontainer; the assertion confirms the operator row was auto-populated from `settings.operator_name`.
- `tests/smoke/test_discord_gateway_smoke.py` (new — te-003 picks the automated path). Gated by `ALFRED_SMOKE_DISCORD_TOKEN` env var (skip when unset; CI populates it from a repo secret; local dev sets it from the operator's own throwaway bot token). Runs `alfred discord verify` against the real Discord gateway; asserts `on_ready` fires within 30s and the right intents are granted. PR E also ships `docs/runbooks/slice-2-discord-smoke.md` as the **complementary deployment runbook** (operator-facing walkthrough for a fresh deploy, including how to provision the bot token, set up Developer Mode, and read the structlog events). The runbook is *not* a smoke-test alternative — the smoke is the automated test; the runbook is the human-readable deployment story.

### Adversarial corpus scaffolding (Slice 3 activates)

PR E ships runnable scaffolding, not just a directory tree:

- `tests/adversarial/conftest.py` — YAML walker, schema validator, ID-uniqueness guard.
- `tests/adversarial/payload_schema.json` (or Pydantic model) matching the `alfred-adversarial-corpus` skill's required fields.
- Per-category subdirs (`prompt_injection/`, `dlp/`, `capability_bypass/`, `canary/`, `inter_persona/`) with a README stub each.
- `tests/adversarial/test_corpus_health.py` — schema and uniqueness checks; passes trivially on the empty corpus.
- CI workflow job stub that runs the suite (passes trivially in Slice 2; flips to release-blocker in Slice 3 by removing `continue-on-error: true`).
- One DLP payload-fixture lands in the scaffolding as wiring smoke (a known SUPPORTED_SECRETS value embedded in a model output → assert redaction happens).

### ADRs needed

| ADR | Title | Lands in |
|---|---|---|
| ADR-0013 | Defer T1+T3+dual-LLM to Slice 3; supersede ADR-0008's Slice-2 commitment | PR A commit 2 (placeholder body; full text in PR E) |
| ADR-0009 | `CommsAdapter` Protocol as Slice-2-only in-process seam; PRD §5 invariant bounded; Slice 3 rewrites for MCP transport | PR A |
| ADR-0010 | Canonical `user_id` as slug-from-name (not UUID); PostgreSQL `LISTEN/NOTIFY` for cross-process cache invalidation with bounded-TTL fallback | PR A |
| ADR-0011 | Per-user `BudgetGuard` (dict-keyed counter; operator inherits Slice-1 global cap; `_spent`/`_day` never evict) | PR A (placeholder — frontmatter + "TBD body, see PR E"); body in PR E |
| ADR-0012 | File-backed `SecretBroker` at `~/.config/alfred/secrets.toml`, plaintext-with-0600 for Slice 2; age-encryption deferred to Slice 3+; broker-only access invariant for SUPPORTED_SECRETS | PR A (placeholder — frontmatter + "TBD body, see PR E"); body in PR E |

**Two-dispatch plan for docs-author.** PR A invokes `alfred-docs-author` for ADR-0009 and ADR-0010 **bodies** (load-bearing for PRs B–D) plus **placeholder** files for ADR-0011, ADR-0012, ADR-0013 (frontmatter + a single "TBD body, see PR E"; ADR numbers reserved on `main` immediately so the supersession edge to ADR-0008 and the seats for per-user-budget / file-broker decisions exist before PRs B–D merge). PR E invokes docs-author for deep-docs bootstrap + ADR-0011/0012/0013 full bodies. Without the placeholders, PRs B-D would land without their design anchors for a slice's worth of merge window (architect-004).

### Slice graduation map (post Slice 2)

> *Slice-3+ columns are expected, not committed. Definite commitments live in `docs/superpowers/plans/<slice>.md` files.*

| Subsystem | Slice 1 (shipped) | Slice 2 (this slice) | Deferred to |
|---|---|---|---|
| Trust tiers | T0 + T2 | unchanged at runtime; `TaggedContent[T2]` becomes the orchestrator contract | Slice 3 (+T1 +T3 + dual-LLM, per ADR-0013) |
| Comms adapters | TUI in-process | TUI + Discord (DM-only), both behind in-process `CommsAdapter` Protocol; embeds/attachments refused | Slice 3 (MCP transport — rewrites Protocol shape) · Slice 4 (Telegram, server channels) |
| Identity | hardcoded `operator` | `User` + `PlatformIdentity` tables, `alfred user *` CLI, operator pre-map, `LISTEN/NOTIFY` cross-process | Slice 3 (verification phrase, cross-platform binding) |
| Authorization | none | `User.authorization` enum + per-user budget + per-user rate limit | Slice 3+ (authorization-mapped trust-tier graduation) |
| Memory | working + episodic, operator-only | working + episodic per-user (`WorkingMemoryPool` keyed on `(persona, user_id)`, lazy rehydrate, persona_id column ships now) | Slice 4 (summarised, semantic facts) |
| Persona | hardcoded Alfred | unchanged; prompt threads operator_name + requesting_user_name + language; prompt-cache-friendly layout (`<user_context>` tail); `render_persona_prompt(persona=…)` interface for Slice-4 forward-compat | Slice 4 (registry, Lucius, addressing modes) |
| Secret broker | env-var only | + file backend (plaintext-0600 at `~/.config/alfred/secrets.toml`); fail-closed permissions + missing-file errors; broker-only access invariant | Slice 3+ (age-encrypted) |
| DLP | redactor in structlog only | `OutboundDlp.scan` on every Discord outbound; broker.redact + generic-API-key regex stage | Slice 3 (manifest-bypass + canary trip enforcement; length-delta oracle mitigation) |
| Audit log | every orchestrator turn | + every `user.*` CLI command + `discord.*` events + per-row `language` + per-row `persona_id`; per-snowflake dedup + global cap on unknown-DM writes | Slice 6 (graph CLI) |
| i18n | operator-language at orchestrator | per-user `language` column (BCP-47 validated), ContextVar-backed per-coroutine isolation, full enumerated `cli.user.*` + `discord.*` catalogs | unchanged in scope |

---

## 6. Build sequence — 6 PRs (A, B, C, D1, D2, E)

PR D is split (per architect-006 / devops-004 / alfred-reviewer-002). The new `discord.py` dependency, the second new security-boundary module, and the compose change all land separately from the comms-Protocol extraction so each PR is reviewable in one pass and the 100%-coverage gate on `src/alfred/security/dlp.py` is enforced in isolation.

| PR | Scope | Key gates |
|---|---|---|
| **A** | Step 0 (ContextVar refactor); ADR-0009 + ADR-0010 **bodies** plus ADR-0011 + ADR-0012 + ADR-0013 **placeholders** (architect-004); identity layer: `users` + `platform_identities` migration 0004 + ORMs + `IdentityResolver` (incl. `OperatorAlreadyExistsError` upper-bound guard, architect-001) + `IdentityVersionCounter` + `LISTEN/NOTIFY` plumbing + listener reconnect-with-backoff (err-001) + `alfred user *` CLI subcommands (incl. `--replace-operator`, `--output-slug`) + i18n catalog entries (cli.user.*) + drive-by fix for `cli/main.py:54` `t()` leak. Tests for the identity layer + migration backfill (extended scenarios — te-001). **Plumbing only — no Discord, no DLP, no compose.** | smoke test passes against canonical-slug user; migration 0004 idempotent + atomic; ContextVar isolation test green; listener reconnect test green |
| **B** | `BudgetGuard` per-user refactor (typed `UnknownBudgetUserError`, `evict`, version-counter subscribe, NaN guards); `WorkingMemoryPool` in `src/alfred/memory/working.py` with `(persona, user_id)` key + per-key locks + acquire/release lifecycle; orchestrator contract change (`handle_user_message(*, user, content, working_memory)` accepting `TaggedContent[T2]`); persona-prompt rewording with `operator_name` + `requesting_user_name`; `render_persona_prompt(persona=…)` refactor; `episodic.record` + `audit.append` per-row `language` + `persona_id`. Slice-1 TUI continues working unchanged through `IdentityResolver.get_operator()`. **Atomic 18-call-site signature migration** is the default; **architect decides at plan time** whether to split, based on the criteria below. | TUI smoke test still passes; orchestrator audit branches each produce the spec'd `result` value; `WorkingMemoryPool` concurrent-rehydrate property test green |

**PR B atomic-vs-split decision criteria** (architect applies before writing the implementation plan):

- **Stay atomic if:** every one of the 18 call sites is a pure signature transform (add `user=…` kwarg, pass through), CI on a scratch branch goes green on first push, no call site needs a contextual behaviour change.
- **Split if any one of these is true:** more than 4 call sites need behavioural edits beyond the signature shape; any call site requires upstream context (e.g. user must be resolved by a separate path before the call); the scratch-branch CI surfaces test failures that aren't purely typing.
- **Subsplit naming and ordering** (when triggered): the PRs land in this exact order, each green before the next opens — **PR Bb** = `BudgetGuard` per-user refactor + call-site updates in `src/alfred/budget/` only; **PR Bm** = `WorkingMemoryPool` + call-site updates in `src/alfred/memory/` and `src/alfred/orchestrator/`; **PR Bo** = orchestrator contract change + persona prompts + episodic/audit fields + remaining call sites. Each sub-PR has its own audit-log fixture green and runs the full slice-1 smoke. Rollback for any sub-PR = `git revert` (each is self-contained).
- **Safety net for either path:** CI must pass on every call-site permutation before merge (no `--no-verify`), the slice-1 TUI smoke must stay green, and the PR description enumerates which call sites changed signature vs. which gained new behaviour.
| **C** | `SecretBroker` file backend + fail-closed permissions check + `require_file` + `SecretBrokerConfigError` (base) + `SecretBrokerPermissionsError` + `SecretBrokerFileMissingError` + `SecretBrokerNotAFileError` (devex-002) + `.gitignore` entry + `.git`-in-parent rejection + **new** `tests/unit/security/test_no_direct_env_reads.py` grep-scan (rev-001 — first ship in PR C, not a slice-1 file) + `discord_bot_token` in `SUPPORTED_SECRETS` (file-prefer) + i18n keys (`secrets.file_perms_too_open`, `secrets.file_missing_required`, `secrets.path_is_directory`). | `--cov-fail-under=100 --cov=src/alfred/security/secrets.py`; integration test for file backend |
| **D1** | `CommsAdapter` Protocol extraction (start/run/stop/health + `AdapterHealth`); `TuiAdapter` wrap (`TuiAdapter.run()` delegates to `app.run_async()`; resolve-fail friendly hint); `OutboundDlp` + generic-API-key regex stage + canary stub + audit-on-modification; `RateLimiter` Protocol + `InProcessTokenBucketRateLimiter`; markdown-aware splitter helper. **Backend-only — no external deps.** | `--cov-fail-under=100 --cov=src/alfred/security/dlp.py`; TUI smoke passes through the new Protocol seam; **adapter import-isolation test green** (`test_no_direct_adapter_imports.py` — every consumer outside `src/alfred/comms/` goes through the `CommsAdapter` Protocol, so the Slice-3 MCP transport swap touches zero call sites) |
| **D2** | `DiscordAdapter` (with `client_factory` mock seam, discord.py logging bridge, embed/attachment refusal, unknown-DM dedup + global cap, code-block-aware splitter use, single `_send` chokepoint, typed `BudgetExceededError`, reconnect classification table); `discord.py` dep; `alfred discord` + `alfred discord verify` Typer subcommands; `docker-compose.yaml` adds `alfred-discord` service (`up -d`, `restart: unless-stopped`, memory limit, `discord.Client(max_messages=100, chunk_guilds_at_startup=False, member_cache_flags=none)`); secrets bind-mount; setup script's portable operator-onboarding step (jq, `tr`, `read_env_var`, `--output-slug`, non-TTY guard, optional discord-bind prompt); README quickstart updated with Developer Mode walkthrough. | discord adapter integration test + minor-version surface test green; `alfred discord verify` returns 0 against a real bot in CI when secrets are present |
| **E** | Smoke test `test_discord_gateway_smoke.py` + companion `docs/runbooks/slice-2-discord-smoke.md` (te-003); adversarial corpus scaffolding (harness + schema + uniqueness guard + per-category READMEs + CI job stub + one DLP payload fixture); `docs/subsystems/identity.md` + `docs/subsystems/comms.md` + `docs/glossary.md` bootstrap via `alfred-docs-author` — glossary MUST include the two headings `Authorization role` (slug `authorization-role`) and `Canonical user_id` (slug `canonical-user-id`) so this spec's forward-references in §2 + §4 resolve (docs-002); ADR-0011, ADR-0012, ADR-0013 bodies written. | docs-reviewer pass clean; corpus harness runs trivially on empty corpus; glossary anchor existence checked by `make docs-check` (link-checker job stub if not already in CI) |

`/path-to-green` drives each PR. `alfred-architect` approves cross-PR coherence. `alfred-ai-expert` weighs in on rate-limit defaults + DLP-bypass-detection scope. `alfred-docs-author` produces the deep-docs in PR E (and ADR-0009/0010 bodies in PR A).

---

## 7. Open questions / risks for the review team

Resolved since the brainstorm (no longer open):

- **Bot token in env vs file** — resolved: file is canonical for Slice-2+ keys (`_PREFER_FILE` set); env wins for slice-1 keys; documented in §2.
- **DLP silent vs surfaced** — resolved: silent for Slice 2, length-delta oracle acknowledged as a Slice-3 mitigation task (§3, listed below).
- **Rate-limit defaults** — resolved: standard=30/min, trusted=60/min, operator=unlimited; day-caps dropped from default but `--rate-limit-per-day N` available as opt-in hard ceiling (§3, ai-001 resolution).
- **`authorization=read_only`** — resolved: stays in enum permanently; rate-limiter returns 0 messages/min (§2; ADR-0010 / migration discipline).
- **Episode.platform column** — resolved: NO. Platform is channel-of-origin (observability/audit), not memory partition (PRD §7.2 = per-persona-per-user). Episode `metadata` JSONB can carry it if telemetry ever needs it.
- **Operator slug-conflicts on migration** — resolved: pre-check refuses with remediation pointing at `ALFRED_OPERATOR_NAME=<unique-name> alembic upgrade head` (§2, three integration test cases).
- **Operator's Day-1 Discord ergonomics** — resolved: setup script optionally binds inline; `alfred discord verify` gives an immediate green/red signal.

Genuinely open (review-team or future-slice work):

- **Cross-process cache backstop on PgBouncer transaction-pooling** — `LISTEN/NOTIFY` doesn't work under transaction-pooling. The 60s TTL fallback is acceptable as documented but operators may prefer a different shape (e.g. file-watch on a touched sentinel file; per-row updated_at column polled by the listener). Defer the decision until a deployer reports the issue; spec the TTL fallback now.
- **Length-delta DLP oracle mitigation choice** — three options: fixed banner on any redaction, bucket-padding, or constant-time scan. All are Slice-3 work; the spec accepts the known Slice-2 risk. `alfred-security-engineer` picks the Slice-3 mitigation when planning Slice 3.
- **Multi-operator deployments** — Slice 2's `--replace-operator` flag covers the "one-at-a-time hand-off" case (architect-001). Slice 4's persona-registry work probably needs a config knob (`settings.household_operator_slug`) for genuine multi-operator deployments where two humans co-own a household. Out of scope for Slice 2.

### Punch list (Lows, deferred to plan where cheap to defer)

These are non-blocking polish items the plan picks up:

- discord.py internal cache flags + container memory limits on `alfred-discord` (perf-005 — folded into D2 compose block).
- `SecretBroker.redact` alternation regex caching + `MAX_REDACTOR_PATTERNS=256` overflow alert (perf-006 — **lands in PR C** alongside the file-backend work, so the broker arrives with both file storage and bounded redactor performance in one slice rather than dripping the perf piece into Slice 3).
- Chunked-send pipelining note for Slice 4 (perf-007 — note in spec; no Slice-2 work).
- 256-vs-50 cache-size asymmetry rationale (perf-004 — one-paragraph documentation; folded into §4).

---

## 8. Changelog from initial brainstorm (operator-readable)

Findings from the `/review-plan` pass on the 3142bf2 brainstorm were applied as follows. Each row links a finding ID to the section that absorbed it.

### Criticals applied to spec body

| Finding | Where | What changed |
|---|---|---|
| core-001 / i18n-001 / err-006 (T1) | §0.1 | ContextVar refactor promoted to Slice-2 prerequisite step in PR A commit 1. |
| architect-002 / docs-001 (T2) | §0.2, §5 ADR table | ADR-0013 added; supersedes ADR-0008's Slice-2 commitment; lands as PR-A commit 2. |
| architect-001 / docs-002 / sec-007 (T4) | §3 Trust tagging subsection, §3 Error semantics table, §5 unit tests | Embeds/attachments/stickers refused with audit + i18n key; `TaggedContent[T2]` in orchestrator contract. |
| architect-003 (PRD §5 deviation) | §2 ADR-0009 description, §5 graduation map | ADR-0009 bounds the PRD §5 invariant breach to Slice 2; Slice-3 reviewer-gate re-checks. |
| core-005 / alfred-persona-engineer-001 + 002 / i18n-004 (T3) | §3 Orchestrator contract, §5 persona row | `operator_name` (household owner) split from `requesting_user_name` (current turn); `IdentityResolver.get_operator()` caches household-owner; persona template reworded. |
| mem-001 + 002 / core-003 (T7) | §3 `WorkingMemoryPool` section | Pool moved to `src/alfred/memory/working.py`; acquire/release lifecycle; per-key `asyncio.Lock`; capture-at-top-of-turn; integration with orchestrator's session_scope clarified. |

### Highs applied to spec body

| Finding | Where | What changed |
|---|---|---|
| architect-004 / mem-007 / alfred-persona-engineer-004 (T8) | §2 migration 0004, §3 pool, §5 graduation | `episodes.persona_id` + `audit_log.persona_id` land in migration 0004; pool key is `(persona, user_id)` from day 1. |
| architect-005 / comms-001 / comms-004 / comms-006 (T11) | §2 Protocol shape, §3 failure-modes table | Protocol grows `start/run/stop/health` + `AdapterHealth`; `client_factory` injection; reconnect policy table; `RateLimiter` async Protocol. ADR-0009 admits Slice-3 rewrites the Protocol shape. |
| sec-001 / ai-002 (T5) | §3 OutboundDlp | Generic-API-key regex stage added; two-stage pluggable structure for Slice-3 swap; canary stub regression test. |
| sec-002 / err-002 / i18n-006 (T17) | §3 `_send` chokepoint, typed exceptions | Single `_send` wrapper; `BudgetExceededError(spent_usd, cap_usd)` typed kwargs; `discord.alfred_error` no `{error}` placeholder. |
| sec-003 / sec-005 / devops-002 / devops-005 / devex-004 (T10) | §2 SecretBroker section | Path moved to `~/.config/alfred/secrets.toml`; full perms check (symlink, owner, parent); `.gitignore` mandate; `.git`-in-parent rejection; bind-mount discipline; README backup-vector warning. |
| sec-004 / perf-003 (T12) | §3 Audit-DoS mitigation | Per-snowflake LRU dedup (1024 / 1h TTL) + global token-bucket cap on `discord.unknown_user_dm`. |
| te-002 / mem-003 / mem-004 / err-010 (T13) | §2 migration sketch, §5 integration tests | Migration 0004 SQL spelled out, idempotent, transactional, statement-timeout'd; downgrade policy; three integration test cases. |
| i18n-003 / err-006 (T14) | §3 i18n section, §4 CLI | `User.language` validated via `babel.Locale.parse` at Pydantic + CLI ingress; WARN-once-per-user on missing catalog. |
| i18n-002 / devex-009 / alfred-reviewer-005 (T15) | §3 catalog enumeration | Full enumerated `cli.user.*` keys (no wildcards); drive-by fix for `cli/main.py:54` leak in PR A. |
| err-005 / mem-005 / provider-001 (T16) | §2 cross-process invalidation | PostgreSQL `LISTEN/NOTIFY` (with 60s TTL fallback for PgBouncer); `BudgetGuard` subscribes to the shared `IdentityVersionCounter`. |
| provider-004 / perf-001 (T6) | §2 BudgetGuard | `_spent`/`_day` source-of-truth, never evict; only `daily_usd` cap is cache-able; `evict(user_id)` on soft-delete; validation-before-mutation. |
| architect-006 / alfred-reviewer-002 / devops-004 (T9) | §6 PR sequence | PR D split into D1 + D2 (6 PRs total). |
| ai-001 (T18) | §3 rate-limit table | standard=30, trusted=60, operator=unlimited; day-caps off by default, opt-in via `--rate-limit-per-day`. |
| devops-001 / devops-006 / err-009 (T22) | §2 compose, §3 entrypoint, §6 PR D2 | `up -d` (not `run -d`); `restart: unless-stopped`; `command: ["discord"]`; `alfred discord verify` subcommand; explicit failure-modes classification. |
| devops-003 / devex-002 (T25) | §4 setup script | Portable bootstrap step: `jq` prereq, `tr` for lowercasing, `read_env_var` for `.env` safety, non-TTY guard, `--output-slug`. |
| devex-001 / devex-005 / comms-005 (T30) | §3 unknown-DM split, §4 README | `discord.unknown_user_first` echoes snowflake + bind hint; `discord.unknown_user_repeat` quiet; setup script optionally binds Discord inline; Developer Mode walkthrough in README. |
| comms-002 | §2 client_factory | `client_factory` injected for unit-test mocking; minor-version surface test ships in PR D2. |
| sec-008 / te-001 (T55) | §5 unit tests | DLP test list expanded; per-file `--cov-fail-under=100` gate on `src/alfred/security/dlp.py` enforced in PR D1, on `src/alfred/security/secrets.py` in PR C. |
| core-002 | §6 PR B | 18-call-site signature flip migration enumerated as a PR-B checklist (with split-into-Bb/Bm/Bo as the fallback option). |
| core-004 / err-001 | §3 7-branch audit enumeration, audit-write-failure-loud rule | All 7 audit branches enumerated; refusal-path audit-write failure propagates per slice-1 discipline. |
| err-003 / err-004 | §2 SecretBroker | `secrets_file` silent None fallback closed with `SecretBrokerConfigError`; `SecretBrokerPermissionsError` fail-closed for long-running services. |
| sec-006 | §3 discord.py logging | Library logging bridged through structlog redactor; redaction test in PR D2. |
| alfred-reviewer-001 / architect-008 (T21) | §3 orchestrator contract | `episodic.record(language=…)` + `audit.append(language=…)` per-row threading. |
| alfred-reviewer-003 | §2 SecretBroker invariant | Broker-only access for SUPPORTED_SECRETS; `no_direct_env_reads` grep test in PR C. |
| alfred-reviewer-004 | §2 TuiAdapter shape | `TuiAdapter.run()` delegates to `app.run_async()`; resolve-fail friendly hint. |
| provider-002 | §2 BudgetGuard typed exception | `UnknownBudgetUserError(BudgetError)`. |
| comms-003 | §3 markdown splitter | Code-block-aware splitter factored as a reusable helper for Slice-4 Telegram. |
| devex-007 / architect-010 / mem-006 (T20) | §4 CLI naming convention block, §2 User column | `User.role` renamed to `User.authorization`; kebab vs snake normalised at CLI boundary; `read_only` stays in enum permanently. |
| devex-008 | §4 CLI atomicity | `add`+`bind` in one transaction; partial UNIQUE on `(user_id, platform) WHERE deleted_at IS NULL`. |
| ai-003 | §3 persona prompt layout | Prompt-cache-friendly: invariant prefix + `<user_context>` tail. |
| alfred-persona-engineer-003 | §3 orchestrator contract | `render_persona_prompt(persona=…)` interface for Slice-4 forward-compat. |
| docs-004 | §5 ADR two-dispatch plan | PR A: docs-author writes ADR-0009/0010; PR E: docs-author writes ADR-0011/0012/0013 + bootstrap. |
| te-003 | §5 test classification | `test_discord_dm_end_to_end.py` moved to `tests/integration/`; smoke variant gated by `ALFRED_SMOKE_DISCORD_TOKEN` or runbook alternative. |
| te-004 / te-005 / te-006 / te-007 / provider-003 | §5 test enumeration | Branch enumerations expanded; adversarial scaffolding made runnable. |
| architect-007 | §4 `alfred user remove` | Refuses to remove the last operator. |
| perf-002 | §3 WMP cap | Default `max(50, active_user_count * 2)`; `settings.working_memory_pool_max` override; `working_memory_pool_evictions_total` counter. |
| perf-005 | §6 D2 compose | discord.py internal cache flags + container memory limits. |

### Mediums applied or punched

| Finding | Disposition |
|---|---|
| docs-003 | §2 ADR-0009 explicitly admits PRD §5 deviation; architect amends PRD §6.1 in PR A. |
| docs-005 | §5 graduation map prefixed with "Slice-3+ columns are expected, not committed." |
| devex-003 | §4 `user list` columns + sort + empty-state spelled out; golden-output unit test. |
| devex-006 | §4 `alfred user set --rate-limit-per-min unset` reverts to authorization-derived default; `user show` indicates override-vs-derived. |
| devex-010 | §4 exit-code convention (0/1/2/130); `user remove` non-TTY behaviour. |
| i18n-005 | **Resolved.** Catalog-fallback policy ships as **warn-with-confirm at CLI ingress** (per devex-003 / §4 CLI block). The original §7 entry is closed; no open work remains. |
| err-007 | §3 cancellation row in error-semantics table + orchestrator try/finally for refund + audit. |
| err-008 | §7 length-delta oracle held as Slice-3 mitigation task. |
| comms-007 | §3 explicit GroupChannel rejection comment + unit test. |
| comms-008 | §3 setup script prints current intent requirement based on pinned version; intents logged in adapter-startup audit row. |
| perf-004 / perf-006 / perf-007 | Punched into §7 punch list (note in spec; folded into PR D2 or Slice-4 follow-up). |
| provider-005 | §4 daily-budget default raised to $0.50; rationale documented in CLI block. |

### Lows applied or punched

Most Lows fold into spec body without ceremony (CLI exit codes, intent decision comment, perf documentation). The remainder live in the §7 punch list to keep this revision under length budget.

### Not applied (deferred to plan or future slice)

- `mem-008` — confirms the Episode.platform NO answer; folded into the resolved-open-questions list.
- `ai-004` — verified-positive on the T2-only ingestion path; no spec change required.

### Changes from `/review-pr` pass on PR #93 (commit 49a71a8)

Second-pass review against the revised spec returned 0 Critical / 9 High / ~14 Medium / ~6 Low. None blocking. Highs and applicable Mediums folded in below.

| Finding | Section | What changed |
|---|---|---|
| err-001 (H) | §2 cross-process | Listener wrapped in exponential-backoff supervisor (1s→60s cap); 60s TTL backstop runs concurrently; reconnect test stub added. |
| perf-001 + perf-002 (H + M) | §3 WMP | NOTIFY-receipt recomputes the auto-formula cap in `alfred-discord`; explicit precedence: operator override wins, auto-formula only when unset. |
| sec-001 (H) | §3 trust-tagging + `_handle` + §5 surface test | Denylist → **allowlist**: parse `msg.content` only; assert `msg.poll`/`.components`/`.activity`/`.application` etc. are empty/None; surface test pins every allowlist field. |
| sec-002 (H) | §2 enum + §3 error table + §3 i18n | `read_only` refusals are **reply-suppressed** (audit only); `discord.rate_limited` no longer applies to `read_only`; eliminates the friend-list oracle. |
| architect-001 (H) | §2 resolver + §4 CLI + §3 i18n | Upper-bound operator guard via `--replace-operator <slug>`; otherwise `OperatorAlreadyExistsError`. Symmetric to last-operator-remove. |
| architect-002 (H) | §2 enum | `RateLimiter.allow()` takes full `User`; explicit `if authorization == READ_ONLY: return False` documented as security invariant, not perf default. |
| architect-004 (H) | §5 ADR table + dispatch plan + §6 PR A | PR A ships **placeholder** files for ADR-0011, ADR-0012, ADR-0013 (frontmatter + "TBD body, see PR E"). |
| devex-001 (H) + err-004 (L) | §2 verify | Full exit-code table (0/1/2/3/4/130) with structlog events; intents-off message embeds the developer-portal URL. |
| devex-002 (H) | §4 setup + §2 broker | Setup `mkdir -p + touch + chmod 600/700` before any `docker compose run`; `export UID GID`; broker grows `SecretBrokerFileMissingError` + `SecretBrokerNotAFileError` subtypes. |
| i18n-001 (H) | §3 i18n catalog | Full `cli.user.list.column.*` (6 keys) + empty/deleted/no-platforms/catalog-missing markers + `cli.user.show.*` annotations added; rich.Table headers restated as t()-required. |
| i18n-002 (H) | §3 prompt | Cacheable prefix references `<user_context>` element names AND carries the BCP-47 "respond in `<addressed_user_language>`" imperative; persona-prompt unit test asserts both. |
| sec-003 (M) | §3 OutboundDlp | structlog `_redact_value` now calls `OutboundDlp.scan` (both stages) instead of `broker.redact`; new `test_dlp_structlog_bridge.py`. |
| err-002 (M) | §2 broker | Broker is constructed eagerly at CLI bootstrap; perms errors exit 2 uniformly; `require_file` gates file-missing fatality to Discord commands. |
| err-003 (M) | §3 `_send` | Three distinct `result` values for `_send` failures (`dlp_failed`/`split_failed`/`send_failed`) + `delivered_chunk_count`; success row written after `_send` returns OK. |
| i18n-003 (M) | §3 audit semantics | One-paragraph rule: `audit_log.language` tags the user turn; `subject` JSONB stays operator-readable English; verbatim user content inside `subject` inherits user's language. |
| te-001 (M) | §5 migration test | Backfill test grows scenario (d): pre-existing rows get NULL for the four new columns; column types match DDL; downgrade drops cleanly. |
| te-002 (M) | §5 surface test | Concrete assertion shape pinned: `inspect.signature` + `hasattr` on every allowlist field + `discord.Client` perf kwargs + `client.start(token, reconnect=True)`. |
| te-003 (M) | §5 smoke + §6 PR E | Automated smoke (`ALFRED_SMOKE_DISCORD_TOKEN`-gated) is THE smoke deliverable; the runbook is complementary deployment doc, not an alternative. |
| devex-003 (M) | §3 i18n per-user + §7 | BCP-47 catalog-missing warn-with-confirm at CLI ingress; `--no-warn-missing-catalog` escape; `user list` annotation; open question removed. |
| devex-004 (M) | §3 i18n keys | `discord.unknown_user_first` body enumerated literally with snowflake + `alfred user add --name … --discord-id …`. |
| rev-001 (M) + te-004 (L) | §5 + §6 PR C | `test_no_direct_env_reads.py` re-noted as new-in-PR-C (not slice-1); failure messages share a `_remediation_message(...)` helper with the new adapter-imports test. |
| rev-002 / docs-003 | §4 CLI block | Stale `role=operator` comment → `authorization='operator'`. |
| perf-003 (L) | §2 Compose | `alfred-discord` memory cap 512M → 256M with "bump if OOMKills" comment. |
| docs-001 (H, docs-drift) | line 6 + §9 | Two PRD anchors fixed: `#5-architectural-invariants` → `#5-architecture-overview`; `#62-memory-subsystem` → `#62-multi-layered-memory`. |
| docs-002 (M) | §6 PR E | Glossary anchor slugs (`authorization-role`, `canonical-user-id`) pinned in the PR-E scope cell. |
| i18n-004 (L) | §3 enumeration | Existing call-site-mapping sentence is the contract; no additional change required. |

Not folded in: `rev-003` (commit-message reword — parent agent owns); `sec-004` (already addressed in the `/review-plan` pass under a different ID); `sec-005` (Lows — defer to the plan punch list).

---

## 9. References

- [PRD §5 Architecture Overview](../../../PRD.md#5-architecture-overview)
- [PRD §6.1 Multi-modal Comms](../../../PRD.md#61-multi-modal-comms)
- [PRD §6.2 Multi-layered Memory](../../../PRD.md#62-multi-layered-memory)
- [PRD §6.8 Persona System](../../../PRD.md#68-persona-system)
- [PRD §7.1 Security & Prompt Injection Defense](../../../PRD.md#71-security--prompt-injection-defense)
- [PRD §7.2 Multi-User Identity & Authorization](../../../PRD.md#72-multi-user-identity--authorization)
- [ADR-0008 LLM output is T2 in Slice 1 — superseded in part by ADR-0013](../../adr/0008-llm-output-trust-tier.md)
- [Slice 1 plan](../plans/2026-05-24-slice-1-hello-alfred.md)
- [`alfred-adversarial-corpus` skill](../../../.rulesync/skills/alfred-adversarial-corpus/SKILL.md)
- [`alfred-docs-author` agent](../../../.rulesync/subagents/alfred-docs-author.md)
- [`alfred-ai-expert` agent](../../../.rulesync/subagents/alfred-ai-expert.md)
- Review-plan findings: `${XDG_CACHE_HOME:-$HOME/.cache}/alfred-os/review-plan/2026-05-26-slice-2-discord-multiuser-design/` (local-only artifact — populated by `/review-plan`; not committed to the repo).
