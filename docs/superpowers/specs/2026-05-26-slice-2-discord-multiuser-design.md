# Slice 2 — Discord adapter + multi-user identity + secret broker file backend

**Status:** Design — pending review-team pass and user approval.
**Date:** 2026-05-26
**Owner:** brainstorm output from the slice-1-followup session (post PR #89 / #91 / #92).
**Anchors:** [PRD §6.1](../../../PRD.md#61-multi-modal-comms) · [PRD §6.8](../../../PRD.md#68-persona-system) · [PRD §7.1](../../../PRD.md#71-security--prompt-injection-defense) · [PRD §7.2](../../../PRD.md#72-multi-user-identity--authorization) · [ADR-0008](../../adr/0008-llm-output-trust-tier.md)
**Slice-1 anchor plan:** [`docs/superpowers/plans/2026-05-24-slice-1-hello-alfred.md`](../plans/2026-05-24-slice-1-hello-alfred.md)

---

## 1. Scope and outcome

### What ships when Slice 2 is done

1. **Slice-1 behavior preserved.** `bin/alfred-setup.sh` + `docker compose run --rm -it alfred-core chat` still works exactly as it does on `main` today (TUI experience is unchanged from the operator's perspective).
2. **New CLI surface under `alfred user`** for operator-pre-mapped identity binding:
    - `alfred user add --name <name> --discord-id <snowflake> [--role <role>] [--daily-budget-usd <float>] [--language <bcp47>] [--rate-limit-per-min <int>]`
    - `alfred user list [--json] [--include-deleted]`
    - `alfred user show <slug>`
    - `alfred user remove <slug> [--yes]` (soft-delete; audit history preserved)
    - `alfred user bind <slug> --platform discord --id <platform-id>`
    - `alfred user unbind <slug> --platform discord`
    - `alfred user set <slug> [--daily-budget-usd …] [--role …] [--language …] [--rate-limit-per-min …]`
3. **The TUI keeps working but with a canonical user_id.** `episodes.user_id` and `audit_log.actor_user_id` carry the operator's canonical slug, not the literal `"operator"`. The setup script creates the operator's `users` row on first deploy.
4. **New service `alfred-discord` in `docker-compose.yaml`.** In-process Python command-runner that runs the Discord adapter. Operator starts it with `docker compose run -d alfred-discord` after pre-mapping themselves and any friends.
5. **End-to-end Discord DM flow** for a pre-mapped Discord user:
    - DM arrives → resolver finds the user → orchestrator runs a turn → response posts back to the DM.
    - Audited with `actor_user_id=<slug>`, charged to that user's per-user budget, episodic memory rehydrates per-user across restarts.
6. **Unknown Discord ID → polite refusal + single audit row, no further interaction.** The operator must add the user via CLI before the bot will engage.
7. **`BudgetGuard` is per-user.** One user's daily cap doesn't affect another's. Operator inherits the slice-1 global cap as their per-user default.
8. **`SecretBroker` reads from a file backend AND env vars** (`/var/lib/alfred/secrets.toml`, 0600 perms, plaintext for Slice 2; age encryption is Slice 3+). Env wins on conflict for backward-compat.
9. **Slice-1 invariants hold.** Trust-tier tagging at every boundary (Discord DM body → T2, same as TUI input). Audit log is append-only and survives rollback. i18n catalog-drift gated in CI. `make check` green. 100% line + branch coverage on `src/alfred/security/`.

### Out of scope (committed to later slices)

| Deferred capability | Lands in |
|---|---|
| Verification-phrase identity binding (interactive first-DM handshake) | Slice 3+ |
| Cross-platform binding (one-time code from an already-bound channel) | Slice 3+ |
| Discord server channels, threads, slash commands, embeds | Slice 4 (alongside persona registry) |
| Trust tier T1 (operator) + T3 (untrusted) + dual-LLM split + first real tool | Slice 3 |
| `age`-encrypted secret broker | Slice 3+ |
| MCP plugin transport for the comms adapter | Slice 3+ (the adapter Protocol shipped here is the seam) |
| Persona-other-than-Alfred (Lucius, Oracle, Diana) | Slice 4+ |
| Telegram adapter | Slice 4 |
| Adversarial corpus payloads (the directory tree is scaffolded here) | Slice 3 (release-blocker activation) |

---

## 2. Architectural changes

### The seam: `CommsAdapter` Protocol

A new `src/alfred/comms/adapter.py` defines:

```python
class CommsAdapter(Protocol):
    """Slice-2 in-process; Slice-3+ swaps the transport (MCP RPC) without
    changing the orchestrator side. The Protocol is the trust boundary."""

    name: str  # "tui" | "discord" | future "telegram" | "slack"

    async def run(self) -> None:
        """Long-running loop: receive platform events, resolve user_id,
        dispatch to orchestrator, send response back. Exits cleanly on
        Ctrl+C / SIGTERM."""
        ...
```

`AlfredTuiApp` grows a thin wrapper `TuiAdapter(CommsAdapter)`. New `DiscordAdapter(CommsAdapter)` at `src/alfred/comms/discord.py`. Both adapters take the same constructor inject set as Slice 1's TUI (`orchestrator`, plus the new `identity_resolver`, `outbound_dlp`, `rate_limiter`, `broker`).

### Three new modules under `src/alfred/identity/`

- **`models.py`** — SQLAlchemy ORM:
  - `User` — `(id, slug, display_name, role, daily_budget_usd, language, rate_limit_per_min, created_at, deleted_at)`
  - `PlatformIdentity` — `(id, user_id FK CASCADE, platform, platform_id, created_at)` with composite `UNIQUE(platform, platform_id)`.
- **`resolver.py`** — `IdentityResolver`. Public API:
  - `resolve(platform: str, platform_id: str) -> User | None` — returns the user or `None`. Called per inbound message by adapters. In-process LRU cache (max 256 users) keyed on `(platform, platform_id)`; invalidated via a process-local version counter that mutating CLI commands bump.
  - `add(name: str, …) -> User` — slug derivation + collision-handling.
  - `bind(slug: str, platform: str, platform_id: str) -> PlatformIdentity`
  - `remove(slug: str) -> None` — soft-delete (`deleted_at = now()`).
- **`cli.py`** — `alfred user *` Typer subcommands wired into `src/alfred/cli/main.py`.

### `BudgetGuard` contract change

`src/alfred/budget/guard.py`:

- Slice-1 signature `check_and_charge(cost_usd: float)` becomes `check_and_charge(user_id: str, cost_usd: float)`.
- Internally `dict[str, _UserBudget]` keyed on canonical user_id. `_UserBudget` carries `(daily_usd, per_call_max_usd, day, spent)`.
- `would_exceed(user_id, cost_usd)` and `estimate_for(user_id, request)` change shape the same way.
- Caps come from the `User` row's `daily_budget_usd` field on first `check_and_charge` call for that user; cached in-process.
- Operator's slice-1 `settings.daily_budget_usd` becomes the operator's per-user cap rather than a global ceiling.
- Per-call cap stays global (`settings.per_call_max_usd`).
- Unknown `user_id` → `ValueError` ("budget unknown for user_id=…; operator must add via `alfred user add`"). Defense-in-depth — the resolver should have caught it first, but a missed call site fails loudly.

### `SecretBroker` file backend

`src/alfred/security/secrets.py`:

- `SecretBroker.__init__` grows an optional `secrets_file: Path | None` kwarg (default `/var/lib/alfred/secrets.toml`; falls back to None if file missing).
- On `get(name)`: env var wins if set; otherwise read from file.
- File format:

  ```toml
  # /var/lib/alfred/secrets.toml — 0600 perms, plaintext (Slice 2)
  # Slice 3+ replaces this with age-encrypted equivalent.
  deepseek_api_key = "sk-..."
  anthropic_api_key = "sk-ant-..."
  discord_bot_token = "MTI..."
  ```

- `SUPPORTED_SECRETS` grows `discord_bot_token`.
- The redactor walks all values from both backends; longer-value-first ordering (slice-1 fix from PR #89) preserved.
- On file load: enforce permissions check (`stat().st_mode & 0o077 == 0`). If file is world-readable, refuse with a friendly error pointing at `chmod 600 /var/lib/alfred/secrets.toml`.

### `User.role` enum

Slice 2 ships the column + the enforcement points where it currently matters:

- Operator-only CLI commands (`alfred user *`, `alfred audit`, etc.) stay TUI-gated and reject non-operator callers.
- Non-operator Discord users hit the per-user budget; operator-tier inherits the global Slice-1 cap.
- `read_only` users get a polite refusal at the rate-limiter (0 messages/min).

Role-mapped trust-tier graduation (operator → T1 on Slice 3) is **not** in this slice; the `role` enum is orthogonal to trust tiers for now.

### Database migration

`src/alfred/memory/migrations/versions/0004_users_and_identities.py`:

- `CREATE TABLE users` (full column list in §4).
- `CREATE TABLE platform_identities` with the composite UNIQUE.
- Data migration:
  - Insert one `users` row for the existing operator (slug from `settings.operator_name`, role=`operator`, daily_budget_usd from `settings.daily_budget_usd`, language from `settings.operator_language`).
  - Insert one `platform_identities` row for `("tui", settings.operator_name)`.
- Backfill `episodes.user_id` and `audit_log.actor_user_id` from literal name to canonical slug (no-op for default deployments where `operator_name == "operator"`; relevant only if the operator customized `ALFRED_OPERATOR_NAME`).

### Compose changes

- New `alfred-discord` service in `docker-compose.yaml`, depends on `alfred-postgres` health-check.
- Mount a host volume for `/var/lib/alfred/secrets.toml` so the operator edits the secrets file from the host.
- No new datastore. No new third-party SDK beyond a Discord library.

---

## 3. Discord adapter detail

### Library choice: `discord.py`

- Original library (MIT, ~13K stars), actively maintained again post-Rapptz return.
- Supports current Discord APIs (interactions, components, threads — Slice 2 only uses DMs but the lib is future-proof).
- Pin: `discord.py>=2.4,<3` in `pyproject.toml` runtime deps.
- Dependabot watches via the existing `pip` ecosystem in `.github/dependabot.yml`.

### Bot token sourcing

- `secrets.toml` holds `discord_bot_token`. Adapter calls `broker.get("discord_bot_token")` at startup.
- Operator workflow (documented in README + setup-script tail):

  ```
  1. Create a Discord app + bot at https://discord.com/developers/applications
  2. Enable the Message Content intent (privileged) on the bot's "Bot" page.
  3. Copy the bot token; edit /var/lib/alfred/secrets.toml — add discord_bot_token = "MTI..."
  4. Pre-map your own Discord ID:
       docker compose run --rm alfred-core user bind operator --platform discord --id <your-snowflake>
  5. docker compose run -d alfred-discord
  6. DM the bot from Discord.
  ```

### Adapter wiring shape (annotated pseudocode)

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
        rate_limiter: PerUserRateLimiter,
    ) -> None: ...

    async def run(self) -> None:
        intents = discord.Intents.default()
        intents.dm_messages = True
        intents.message_content = True
        client = discord.Client(intents=intents)

        @client.event
        async def on_message(msg: discord.Message) -> None:
            if msg.author.bot:
                return  # ignore other bots
            if not isinstance(msg.channel, discord.DMChannel):
                return  # DM-only; server-channel work lands Slice 4
            await self._handle(msg)

        # Signal handling: SIGTERM → client.close() → graceful exit
        self._install_signal_handlers(client)
        await client.start(self._broker.get("discord_bot_token"))

    async def _handle(self, msg: discord.Message) -> None:
        # 1. Identity resolution (per-message; in-resolver cache absorbs the cost)
        user = self._resolver.resolve("discord", str(msg.author.id))
        if user is None:
            await msg.channel.send(t("discord.unknown_user"))
            await self._audit_unknown_dm(msg)  # one audit row per refusal
            return

        # 2. Per-user rate limit
        if not self._rate_limiter.allow(user.slug):
            await msg.channel.send(t("discord.rate_limited"))
            await self._audit_rate_limited(user, msg)
            return

        # 3. Per-message language (BCP-47 from User row)
        set_language(user.language)

        # 4. Dispatch to orchestrator (per-user budget enforced inside)
        try:
            response = await self._orch.handle_user_message(
                user_id=user.slug,
                content=msg.content,
            )
        except BudgetError as exc:
            await msg.channel.send(t("discord.budget_blocked", error=str(exc)))
            return
        except asyncio.CancelledError:
            raise  # Textual-shutdown analogue; let it propagate
        except Exception as exc:
            await msg.channel.send(t("discord.alfred_error", error=str(exc)))
            return

        # 5. Outbound DLP scan + length-aware send
        safe = self._outbound_dlp.scan(response)
        for chunk in _split_for_discord(safe, max_len=2000):
            await msg.channel.send(chunk)
```

### Orchestrator contract change

Slice-1: `handle_user_message(content: str) -> str`.
Slice-2: `handle_user_message(*, user_id: str, content: str) -> str`.

Internal effects:

- `episodic.record(user_id=user_id, ...)` — already keyed on user_id, just no longer hardcoded.
- `audit.append(actor_user_id=user_id, ...)` — same.
- `budget.check_and_charge(user_id, cost_usd)`.
- `WorkingMemory` becomes a `dict[user_id, WorkingMemory]`-keyed pool inside the orchestrator (one bounded deque per user). Rehydrate from `episodes.recent(user_id=, limit=20)` lazily on first user-message.
- `alfred_system_prompt(operator_name=user.display_name, language=user.language)` — persona prompt now substitutes the active user's display name and language.

### Per-user rate limiting

New `src/alfred/identity/rate_limit.py`: in-process token-bucket per canonical user. Role defaults:

| Role | Messages/min | Messages/day |
|---|---|---|
| `read_only` | 0 (refusal) | 0 |
| `standard` | 10 | 100 |
| `trusted` | 30 | 500 |
| `operator` | unlimited | unlimited |

Tuneable via `alfred user add --rate-limit-per-min N`. State is in-process (Slice 2 single-instance); Redis-backed in Slice 5+.

### Outbound DLP

New `src/alfred/security/dlp.py` — minimal: `OutboundDlp.scan(text: str) -> str` runs `SecretBroker.redact(text)` plus a canary-token check (stub for Slice 3). Bypass-detection-by-manifest lands Slice 3 when plugins land. Modification is silent for Slice 2 — the user sees the redacted text; operator sees the modification in audit (`audit.append` records the pre-DLP and post-DLP byte counts if they differ).

### i18n per-user

New `User.language` column (BCP-47, default `settings.operator_language`). Set per-message via `alfred.i18n.set_language(user.language)` before the persona prompt is assembled. Catalog drift gate already handles new keys:

- `discord.unknown_user`
- `discord.rate_limited`
- `discord.budget_blocked`
- `discord.alfred_error`
- `cli.user.*` (CLI command help text + confirmations)

### Per-user `WorkingMemory` pool

`WorkingMemoryPool` wraps `dict[str, WorkingMemory]` and exposes:

- `get(user_id) -> WorkingMemory` — lazy-create; lazy-rehydrate from episodic on first access.
- Bounded total memory by capping the pool to N concurrent users (default 50; LRU-evict idle `WorkingMemory` instances on overflow).

### Shutdown

Adapter's `run()` installs asyncio signal handlers for SIGTERM + SIGINT. On signal: `client.close()`, await any pending response sends, return. Compose's `docker compose stop alfred-discord` triggers SIGTERM with a 10s grace period.

### Error semantics (mirror TUI)

| Event | Audit `result` | User-visible outcome |
|---|---|---|
| Unknown Discord ID | `refused` (event=`discord.unknown_user_dm`) | One polite refusal message |
| Rate-limited | `rate_limited` | Polite refusal |
| Budget blocked | `budget_blocked` (orchestrator-side) | Friendly error message |
| Provider failed | `provider_failed` (orchestrator) | Friendly error message |
| DLP modified output | logged INFO; pre/post bytes in audit subject | No user-visible difference (silent redaction) |

---

## 4. Identity model + CLI surface

### Canonical user_id: slug from name

- Lowercase, ASCII-NFKC-normalized, non-alphanumeric → `-`, trimmed/collapsed.
- On collision: append `-2`, `-3`, … `bob` → `bob-2` if `bob` exists.
- Slug is `users.slug` UNIQUE (with integer surrogate `id` for FK efficiency).
- Slug appears in `episodes.user_id` and `audit_log.actor_user_id` — operator-readable on log inspection.

**Why slug not UUID:** debuggability. `alfred audit log --user bob` is more natural than `--user 01HQX7...`. Collision-handling cost is one trip through `users` on `add`.

### `User` ORM (full column list)

| Column | Type | Notes |
|---|---|---|
| `id` | int PK | autoincrement, surrogate for FK efficiency |
| `slug` | str UNIQUE NOT NULL | canonical user_id, slug from name |
| `display_name` | str NOT NULL | original `--name`, preserved with casing/spacing for persona prompt |
| `role` | enum NOT NULL CHECK | `read_only` / `standard` / `trusted` / `operator` |
| `daily_budget_usd` | float NOT NULL CHECK `> 0` | per-user daily cap |
| `language` | str NOT NULL | BCP-47, default `settings.operator_language` |
| `rate_limit_per_min` | int NOT NULL CHECK `>= 0` | overrides role default if set |
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

Composite UNIQUE on `(platform, platform_id)` — one Discord ID can only bind to one canonical user.

### CLI command details

All under `alfred user`, all writing audit rows on mutation.

```bash
# Add a new user, optionally binding a Discord ID
alfred user add \
    --name "Bob" \
    [--discord-id 123456789012345678] \
    [--role standard|trusted|read-only|operator]      # default: standard
    [--daily-budget-usd 0.50]                          # default: 0.10
    [--language en-US]                                 # default: operator's language
    [--rate-limit-per-min 10]                          # default: role-derived

# List active users
alfred user list                                       # plain table
alfred user list --json                                # JSON for scripting
alfred user list --include-deleted                     # show soft-deleted too

# Show one user
alfred user show <slug>

# Soft-delete (preserves audit history; rejects future DMs)
alfred user remove <slug>                              # confirms by default
alfred user remove <slug> --yes                        # skip confirmation

# Bind / unbind additional platform identities
alfred user bind <slug> --platform discord --id 123456789012345678
alfred user unbind <slug> --platform discord

# Tune an existing user
alfred user set <slug> [--daily-budget-usd <float>] [--role <role>] \
                       [--language <bcp47>] [--rate-limit-per-min <int>]
```

Every mutating command writes an audit-log row (`event="user.add" | "user.remove" | "user.bind" | …`, `actor_user_id=<the operator's slug>`, `subject={"target_user": …, …diff…}`).

### First-deploy operator-onboarding flow

The setup script gains a step (`bin/alfred-setup.sh`):

```bash
step "Bootstrapping operator identity"
if ! docker compose run --rm alfred-core user list --json | jq -e '.[] | select(.role=="operator")' >/dev/null; then
  read -p "Operator display name [Operator]: " name
  name="${name:-Operator}"
  docker compose run --rm alfred-core user add --name "$name" --role operator \
    --daily-budget-usd "${ALFRED_DAILY_BUDGET_USD:-1.0}"
  echo "Operator added as canonical user '${name,,}'."
fi
```

To enable Discord, the operator then runs (documented in README):

```bash
docker compose run --rm alfred-core user bind operator --platform discord --id 123456789012345678
docker compose run --rm alfred-core user add --name Alice --discord-id 987654321 --daily-budget-usd 0.25
docker compose run --rm alfred-core user add --name Bob --discord-id 555444333 --daily-budget-usd 0.25 --language de-DE
docker compose run -d alfred-discord
```

### Slice-1-to-Slice-2 migration semantic

Migration `0004` inserts the operator from `settings.operator_name` automatically:
- slug-from-name, role=`operator`, daily_budget_usd from `settings.daily_budget_usd`, language from `settings.operator_language`.
- One `platform_identities` row for `("tui", settings.operator_name)`.

Slice-1 episodes already use `settings.operator_name` as the literal `user_id`, so if the operator hasn't customized `ALFRED_OPERATOR_NAME` (default `"operator"`), the migration is a clean no-op for existing data. If they HAVE customized, the slug derivation matches deterministically — `"Bruce Wayne"` → slug `bruce-wayne`, and the migration backfills `episodes.user_id` from literal name to canonical slug.

### `IdentityResolver` cache

- In-process LRU (max 256 users) keyed on `(platform, platform_id)`.
- Cache invalidation on `alfred user add` / `bind` / `unbind` / `remove` via a process-local version counter the resolver checks.
- Slice 5+ Redis-backed cross-process cache.

### Operator's TUI session resolves to themselves

`TuiAdapter` calls `IdentityResolver.resolve("tui", settings.operator_name)` on start — same path Discord uses. If this fails (no operator row yet, e.g. fresh deploy that hasn't run setup), TUI exits with a friendly hint pointing at `alfred user add --role operator`.

---

## 5. Test strategy, ADRs, slice graduation

### Unit tests (`tests/unit/`)

- **`tests/unit/identity/test_resolver.py`** — slug derivation, collision handling (`bob` → `bob-2`), `resolve` happy + miss + soft-deleted-user miss, LRU cache invalidation on version-counter bump.
- **`tests/unit/identity/test_cli.py`** — `user add` / `list` / `show` / `remove` / `bind` / `unbind` / `set` happy paths, slug-collision, double-bind rejection, soft-delete preserves `episodes` rows, every mutating command writes the expected audit row.
- **`tests/unit/identity/test_rate_limit.py`** — token-bucket per-user, role defaults, override via `User.rate_limit_per_min`, refusal returned at limit.
- **`tests/unit/budget/test_guard.py` extensions** — per-user counter isolation (Alice's spend doesn't touch Bob's), per-call cap still global, day-rollover per-user-independent, unknown-user-id raises loudly.
- **`tests/unit/orchestrator/test_core.py` extensions** — `handle_user_message(user_id=…, content=…)` threading; per-user `WorkingMemoryPool.get(user_id)` lazy-create + lazy-rehydrate.
- **`tests/unit/security/test_secrets.py` extensions** — file-backend load, env-wins-on-conflict, file-missing graceful fallback to env-only, permissions-check rejection on world-readable file, redactor sees both backends.
- **`tests/unit/security/test_dlp.py` (new)** — `OutboundDlp.scan` redacts known secrets, canary-token stub behaviour documented.
- **`tests/unit/comms/test_discord.py`** — `DiscordAdapter._handle` happy path with `discord.Message` mock + `IdentityResolver` mock; unknown-DM refusal path; rate-limited path; budget-blocked path; provider-failed path; 2000-char-split path. **No real Discord client** — the `discord.Client` is mock-injected.

### Integration tests (`tests/integration/`)

- **`tests/integration/test_users_postgres.py` (new)** — `User` + `PlatformIdentity` CRUD against testcontainer Postgres; CHECK constraints fire on invalid `role` / `platform`; CASCADE delete works; UNIQUE constraint rejects double-bind.
- **`tests/integration/test_audit_persistence.py` extension** — audit rows for `user.*` events survive across rollback; per-user `result=budget_blocked` / `rate_limited` events written truthfully.
- **`tests/integration/test_secrets_file_backend.py` (new)** — broker loads from `tmp_path/secrets.toml`, env still overrides, 0600-perm requirement check (friendly error if perms are too open).

### Smoke tests (`tests/smoke/`)

- **`test_hello_alfred.py` extension** — instead of hardcoded `user_id="operator"`, the smoke test creates a `User` row via the real `IdentityResolver.add` + drives the orchestrator with that canonical slug. Same single-turn assertion, but the path exercises the full identity + budget threading.
- **`test_discord_dm_end_to_end.py` (new)** — **mock-Discord** smoke. Boots Postgres testcontainer, `alfred user add` for a fake Discord ID, then directly invokes `DiscordAdapter._handle(mock_message)` against a real orchestrator + a mocked provider router. Asserts episode + audit + budget side effects. **No real Discord gateway connection** — that's only exercised in CI's nightly setup-script smoke or by an operator running `docker compose run alfred-discord` manually.

### Adversarial corpus scaffolding (Slice 3 activates)

- `tests/adversarial/` directory tree created with empty per-category subdirs (`prompt_injection/`, `dlp/`, `capability_bypass/`, `canary/`, `inter_persona/`) and a README pointing at the `alfred-adversarial-corpus` skill.
- Release-blocker enforcement begins Slice 3 when first payloads land.

### ADRs needed

- **ADR-0009: `CommsAdapter` Protocol as the in-process seam for the future MCP transport.** Records why we ship in-process for Slice 2 with the Protocol matched to the eventual MCP shape, instead of building the MCP plugin host now.
- **ADR-0010: Canonical `user_id` as slug-from-name (not UUID).** Records the debuggability tradeoff vs. the collision-handling cost; documents the slug derivation rules.
- **ADR-0011: Per-user `BudgetGuard` (dict-keyed counter; operator inherits Slice-1 global cap).** Records the contract change.
- **ADR-0012: File-backed `SecretBroker`, plaintext-with-0600 for Slice 2; age-encryption deferred to Slice 3+.** Records the threat model (file-on-disk is a privilege the operator already trusts; encryption is a defense-in-depth that lands once we have a key-management story for it).

Architect approves the decisions; `alfred-docs-author` writes the bodies. ADR-0009 and ADR-0011 are load-bearing for Slice 3.

### Slice graduation map (post Slice 2)

| Subsystem | Slice 1 (shipped) | Slice 2 (this slice) | Deferred to |
|---|---|---|---|
| Trust tiers | T0 + T2 | unchanged | Slice 3 (+T1 +T3) |
| Comms adapters | TUI in-process | TUI + Discord (DM-only), both behind `CommsAdapter` Protocol | Slice 3 (MCP transport) · Slice 4 (Telegram, server channels) |
| Identity | hardcoded `operator` | `User` + `PlatformIdentity` tables, `alfred user *` CLI, operator-pre-map | Slice 3 (verification phrase, cross-platform binding) |
| Authorization | none | `User.role` enum + per-user budget + per-user rate limit | Slice 3+ (role-mapped trust-tier graduation) |
| Memory | working + episodic, operator-only | working + episodic per-user (`WorkingMemoryPool`, lazy rehydrate) | Slice 4 (summarized, semantic facts) |
| Persona | hardcoded Alfred | unchanged, but prompt threads per-user display_name + language | Slice 4 (registry, Lucius, addressing modes) |
| Secret broker | env-var only | + file backend (plaintext-0600) | Slice 3+ (age-encrypted) |
| DLP | redactor in structlog only | `OutboundDlp.scan` on every Discord outbound | Slice 3 (manifest-bypass + canary trip enforcement) |
| Audit log | every orchestrator turn | + every `user.*` CLI command, + `discord.*` events | Slice 6 (graph CLI) |
| i18n | operator-language at orchestrator | per-user `language` column, `set_language(user.language)` per inbound message | unchanged in scope |

---

## 6. Build sequence (rough — for the plan)

1. ADR-0009 + ADR-0010 land first as design anchors.
2. `users` + `platform_identities` migration + ORMs + `IdentityResolver` + CLI subcommands + tests. **Plumbing only — no Discord yet.** Smoke test passes against canonical-slug user.
3. `BudgetGuard` per-user refactor + `WorkingMemoryPool` + orchestrator contract change. Slice-1 TUI continues working unchanged.
4. `SecretBroker` file backend + permissions check + tests. `discord_bot_token` added to `SUPPORTED_SECRETS`.
5. `CommsAdapter` Protocol extraction; `TuiAdapter` wraps `AlfredTuiApp`. CLI's `alfred chat` now calls the adapter Protocol. Slice-1 TUI behavior unchanged.
6. `DiscordAdapter` + `OutboundDlp` + per-user rate limiter + i18n catalog additions. Unit + integration tests.
7. `docker-compose.yaml` adds the `alfred-discord` service; setup script gains the operator-onboarding step; README quickstart updated.
8. Smoke `test_discord_dm_end_to_end.py` (mock-Discord) + adversarial scaffolding directory.
9. CLAUDE.md + `docs/subsystems/identity.md` + `docs/subsystems/comms.md` + `docs/glossary.md` bootstrapped via the new `alfred-docs-author` agent. ADR-0011 + ADR-0012 bodies written.

Each step is a separate PR per the small-PR discipline. Per the slice-1 plan's "Slice 2 plan will explicitly split into a 3–5 PR sequence", target **5 PRs** clustering these 9 steps:

- **PR A** — ADRs + identity layer (steps 1+2)
- **PR B** — budget + memory + orchestrator contract refactor (step 3)
- **PR C** — secret broker file backend (step 4)
- **PR D** — comms Protocol + TUI adapter + Discord adapter + DLP + setup-script onboarding + compose (steps 5+6+7)
- **PR E** — smoke + docs + adversarial scaffolding (steps 8+9)

`/path-to-green` drives each PR. `alfred-architect` approves cross-PR coherence. `alfred-ai-expert` weighs in on rate-limit defaults and DLP-bypass-detection scope. `alfred-docs-author` produces the deep-docs in PR E.

---

## 7. Open questions / risks for the review team

- **Bot token in env vs file:** the design supports both via the env-wins-on-conflict rule. Operator preference? The README defaults to file (cleaner for multi-key deployments) but slice-1 env-var pattern still works.
- **Operator's own Discord ID — first-deploy ergonomics:** the operator can use the TUI day-1 without binding a Discord identity. Discord-from-day-1 requires an extra `alfred user bind operator --platform discord --id …` step. Acceptable?
- **DLP silent vs surfaced:** Slice 2 silently redacts outbound. Should the user see "I redacted something sensitive from my reply" so they don't get a confusing message? Could add a `discord.dlp_redacted` i18n key + an in-band note. Default: silent (matches operator-facing structlog approach).
- **Rate-limit defaults:** the table in §3 is a starting point. Operator-tunability via CLI exists but the role defaults might be too tight / too loose. `alfred-ai-expert` should pressure-test the numbers.
- **`User.role=read_only`:** does this role have any path to becoming useful in Slice 2 (e.g. an explicit "alfred please help me — read-only" interaction), or is it dead weight until Slice 3+ when tools land? If dead weight, drop from the enum and re-introduce when needed.
- **Episodes table — should we add a `platform` column too?** Currently episodes are per-user (since `user_id` is canonical). A `platform` column would let queries answer "what did Bob say in Discord vs TUI?" Slice 4 / 5 telemetry would want it; Slice 2 can survive without.
- **What if the operator's `ALFRED_OPERATOR_NAME` slug-conflicts with an existing `User.slug`?** Edge case during migration if the operator post-slice-1 ran with a customized name. Migration should detect and refuse with a friendly error pointing at `alfred user remove <conflicting-slug>`. Tested in `test_users_postgres.py`.

---

## 8. References

- [PRD §6.1 Multi-modal Comms](../../../PRD.md#61-multi-modal-comms)
- [PRD §6.8 Persona System](../../../PRD.md#68-persona-system)
- [PRD §7.1 Security & Prompt Injection Defense](../../../PRD.md#71-security--prompt-injection-defense)
- [PRD §7.2 Multi-User Identity & Authorization](../../../PRD.md#72-multi-user-identity--authorization)
- [ADR-0008 LLM output is T2 in Slice 1](../../adr/0008-llm-output-trust-tier.md)
- [Slice 1 plan](../plans/2026-05-24-slice-1-hello-alfred.md)
- [`alfred-adversarial-corpus` skill](../../../.rulesync/skills/alfred-adversarial-corpus/SKILL.md)
- [`alfred-docs-author` agent](../../../.rulesync/subagents/alfred-docs-author.md)
- [`alfred-ai-expert` agent](../../../.rulesync/subagents/alfred-ai-expert.md)
