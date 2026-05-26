# Slice 2 — Discord adapter + multi-user identity + secret broker file backend

**Status:** Design — revised 2026-05-26 after the /review-plan pass (55 actionable findings folded in). Pending user approval, then `superpowers:writing-plans`.
**Date:** 2026-05-26
**Owner:** brainstorm output from the slice-1-followup session (post PR #89 / #91 / #92); revision dispatched to `alfred-docs-author`.
**Anchors:** [PRD §5](../../../PRD.md#5-architectural-invariants) · [PRD §6.1](../../../PRD.md#61-multi-modal-comms) · [PRD §6.2](../../../PRD.md#62-memory-subsystem) · [PRD §6.8](../../../PRD.md#68-persona-system) · [PRD §7.1](../../../PRD.md#71-security--prompt-injection-defense) · [PRD §7.2](../../../PRD.md#72-multi-user-identity--authorization) · [ADR-0008](../../adr/0008-llm-output-trust-tier.md)
**Slice-1 anchor plan:** [`docs/superpowers/plans/2026-05-24-slice-1-hello-alfred.md`](../plans/2026-05-24-slice-1-hello-alfred.md)

---

## 0. Slice-2 prerequisites (land before anything else)

Two items land at the very start of PR A, before any new feature work. Either one slipped becomes a correctness or paper-trail bug across the rest of the slice.

### 0.1 Promote `_active_lang` to `contextvars.ContextVar[str]`

Slice 1 Appendix C deferred this with the line *"safe under single-user; revisit when Slice 3+ introduces multi-user."* Slice 2 IS that point. The current module-global `_active_lang` in `src/alfred/i18n/translator.py` will cross-contaminate concurrent Discord DMs: Alice's `set_language("de-DE")` would persist into Bob's interleaved `t()` call inside the same event loop.

The fix is shape-only: declare `_active_lang: ContextVar[str] = ContextVar("alfred_active_lang", default="en-US")`. `set_language()` becomes `.set()`; `t()` becomes `.get()`. asyncio propagates ContextVars across `await` points automatically, so each coroutine sees its own language without any handler-side bookkeeping. Add `tests/unit/i18n/test_concurrent_language.py` that interleaves two `asyncio.gather`-driven coroutines and asserts each renders its own catalog string. This lands as PR-A commit 1 (and is a prerequisite for everything downstream that calls `set_language`).

### 0.2 ADR-0013 — supersede ADR-0008's Slice-2 commitment

ADR-0008 explicitly commits T1 (operator) + T3 (untrusted) + dual-LLM split to land in Slice 2. The revised Slice-2 scope defers all three to Slice 3. That contradiction must not sit silently on `main`. ADR-0013 ("Defer T1+T3+dual-LLM to Slice 3") amends ADR-0008's status to `Superseded in part by ADR-0013` and records the rescheduling rationale: the surface-area change (multi-user identity, comms adapter Protocol, file-backed secrets) is already large enough for one slice, and a dual-LLM split without the upstream MCP plugin transport is wasted scaffolding that Slice 3 rewrites.

ADR-0013 lands as PR-A commit 2. Its body is written by `alfred-docs-author` (see §5). The file lands as a placeholder ("body filled in PR E") if PR A is too tight, but the ADR number is reserved before any other ADR ships so the supersession edge is immediate.

---

## 1. Scope and outcome

### What ships when Slice 2 is done

1. **Slice-1 behavior preserved.** `bin/alfred-setup.sh` + `docker compose run --rm -it alfred-core chat` still works exactly as it does on `main` today (TUI experience is unchanged from the operator's perspective).
2. **New CLI surface under `alfred user`** for operator-pre-mapped identity binding:
    - `alfred user add --name <name> --discord-id <snowflake> [--authorization <role>] [--daily-budget-usd <float>] [--language <bcp47>] [--rate-limit-per-min <int>]`
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
| Adversarial corpus payloads (the directory tree + harness scaffolding ships here) | Slice 3 (release-blocker activation) |

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

A new `alfred discord` Typer subcommand boots `DiscordAdapter.start() → run()`. `docker-compose.yaml`'s `alfred-discord` service sets `command: ["discord"]`, so the container's existing `alfred` entrypoint dispatches into the adapter loop. A sibling `alfred discord verify` subcommand (short-lived `discord.Client.start` with a 30s timeout) asserts `on_ready` fires, prints granted intent flags + the bot's identity, and exits non-zero on failure. The setup script invokes `alfred discord verify` immediately after the operator binds their snowflake so the operator gets a definite green/red signal before `up -d alfred-discord` daemonizes the loop.

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
- **`cli.py`** — `alfred user *` Typer subcommands wired into `src/alfred/cli/main.py`. CLI normalises kebab-vs-snake at the boundary (e.g. `--authorization read-only` and `--authorization read_only` both resolve to enum value `read_only`); help text and `user show` output use kebab-case.
- **`version_counter.py`** — `IdentityVersionCounter`: a single `int` bumped by every mutating resolver method. `BudgetGuard` and the resolver's in-process LRU subscribe; bump → next caller refetches from Postgres before serving cached data. Cross-process invalidation is handled separately (next paragraph).

### Cross-process cache invalidation (CLI ↔ `alfred-discord`)

The CLI process bumps the in-process counter when it mutates, but `alfred-discord` is a *different* process and won't see that bump. Slice 2 uses **PostgreSQL `LISTEN/NOTIFY`**: every mutating CLI command issues `NOTIFY alfred_identity_changed, '<payload>'` inside the same transaction as the data write; `alfred-discord` runs a background listener task that bumps its local counter on receipt. The payload is small (slug + op) and used only as a hint — the next resolver/budget call refetches the row of record.

ADR-0010 records both the notify channel name and the fallback: in deployments where `LISTEN/NOTIFY` is unavailable (e.g. PgBouncer in transaction-pooling mode), the resolver and `BudgetGuard` fall back to a bounded 60-second TTL on cached entries, and the CLI's success message for `user set` / `user remove` includes the caveat *"changes propagate to running adapters within 60 seconds."* The TTL is a `Settings.identity_cache_ttl_s` knob, default 60, so operators on PgBouncer can tune it.

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

- `SecretBroker.__init__` grows `secrets_file: Path | None` and `require_file: bool = False` kwargs. Default path is `~/.config/alfred/secrets.toml` *on the host* — per CLAUDE.md devops discipline, operator-writable config goes under `~/.config/alfred/`, not `/var/lib/alfred/`. **Host vs container resolution:** the broker always resolves an *in-container* path; `docker-compose.yaml` bind-mounts the host's `~/.config/alfred/secrets.toml` (read-only) into the container at `/etc/alfred/secrets.toml`. Operators override either side via `Settings.secrets_file` (Pydantic, default `Path.home() / ".config/alfred/secrets.toml"`) or `ALFRED_SECRETS_FILE` env var (Compose sets this to `/etc/alfred/secrets.toml` for the containerised services; the host-side CLI inherits the Pydantic default). `require_file=True` enforces failure if the configured in-container path is missing.
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
- **Silent-fallback closed.** If `secrets_file` is explicitly configured but the file is missing, the broker raises `SecretBrokerConfigError`. `require_file=True` (set by the `alfred discord` entrypoint) makes this the default behaviour even on the implicit-default path so the operator's `discord_bot_token` never silently degrades into a `discord.py` `LoginFailure` three layers downstream.
- **No direct `os.environ` reads for SUPPORTED_SECRETS.** All agent paths read secrets via `broker.get`; direct env reads for any `ALFRED_*` name in `SUPPORTED_SECRETS` are release-blockers. PR C adds a grep-scan test (`tests/unit/security/test_no_direct_env_reads.py`) that fails the build on violations. Documented in ADR-0012.
- **`.gitignore` mandate.** `secrets.toml`, `secrets.*.toml`, `**/secrets.toml` land in `.gitignore` in PR C. The broker walks parent dirs at init and refuses if it finds a `.git` directory (configurable off for tests, but the production default is "if you're inside a working tree, you wrote your secrets in the wrong place"). Setup script prints a one-line "this file is local-only, do not commit" reminder on first creation. README + ADR-0012 enumerate the backup-vector risk (`restic backup ~/.config` will exfiltrate plaintext secrets unless the operator excludes the file; documented, not enforced).

### `User.authorization` enum

Slice 2 ships the column + the enforcement points where it currently matters:

- Operator-only CLI commands (`alfred user *`, `alfred audit`, etc.) stay TUI-gated and reject non-operator callers.
- Non-operator Discord users hit their per-user budget; operator inherits the slice-1 cap.
- `read_only` users get a polite refusal at the rate-limiter (0 messages/min). The enum value stays in the schema permanently — dropping and re-adding across a Postgres CHECK constraint is a destructive migration that breaks rollback symmetry, so the cost of keeping a presently-quiet enum value is preferred over the churn.

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
- **Collision handling.** If a `users` row already exists at the target slug AND the existing row is not flagged operator, abort with a typed Alembic error pointing the operator at `ALFRED_OPERATOR_NAME=<unique-name> alembic upgrade head`. If the existing row IS the operator (re-run case), the `ON CONFLICT DO NOTHING` makes it a no-op.
- **Integration test coverage** (`tests/integration/test_migration_0004_backfill.py`): three explicit cases — (a) custom `ALFRED_OPERATOR_NAME` backfill happy path, (b) default `operator_name='operator'` no-op, (c) non-operator slug-collision refusal with remediation message.

### Compose changes

- New `alfred-discord` service in `docker-compose.yaml`. Same image as `alfred-core` (`docker/alfred-core.Dockerfile`), `command: ["discord"]`, `restart: unless-stopped`, `depends_on: alfred-postgres healthy`, `deploy.resources.limits.memory: 512M`. Run with `docker compose up -d alfred-discord` (not `run -d` — the run subcommand is for one-shot CLI invocations).
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

**Embeds, attachments, stickers, and references are NOT read in Slice 2.** PRD §6.1 classifies them as T3 (link-unfurled content is attacker-controlled). The adapter refuses any DM with non-empty `msg.embeds`, `msg.attachments`, `msg.stickers`, or `msg.reference`: send `t("discord.embed_unsupported")`, write a single audit row (`event=discord.embed_refused`), do not call the orchestrator. T3 handling lands with the Slice-3 dual-LLM split. Unit test in `tests/unit/comms/test_discord.py` exercises every refusal branch.

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
        # 1. Embed/attachment/sticker refusal at the trust boundary.
        if msg.embeds or msg.attachments or msg.stickers or msg.reference:
            await self._audit_and_send_refusal(msg, "discord.embed_refused",
                                               "discord.embed_unsupported")
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

**Prompt-cache-friendly layout (forward-compat for Slice 3+ Anthropic).** The system prompt is restructured so user-invariant character/behaviour content forms the prefix and per-user variables live in a clearly-bounded `<user_context>` XML tail block. Shape:

```text
<persona character + behaviour, identical for every user — cacheable prefix>

<user_context>
  <operator_name>Bruce</operator_name>
  <addressed_user_name>Alice</addressed_user_name>
  <addressed_user_language>en-US</addressed_user_language>
</user_context>
```

Slice 2 doesn't enable prompt caching (DeepSeek default), but the shape is the one Slice 3's Anthropic fallback will key on. Cheapest moment to lock in the prefix shape is now, while the prompt is already being broken for per-user threading.

### `WorkingMemoryPool` ownership and lifecycle

Lives in `src/alfred/memory/working.py` (owned by `alfred-memory-engineer`, not the orchestrator). Public surface:

- `async acquire(key: tuple[str, str]) -> WorkingMemory` — lazy-init under a per-key `asyncio.Lock` (registry of locks lives inside the pool; lazy-created on first key). Lazy-rehydrate from `EpisodicMemory.recent(persona=..., user_id=..., limit=20)` runs inside a pool-owned short-lived session (not the orchestrator's per-turn session — keeps locality clean per core-006).
- `async release(key, wm)` — marks the entry idle; LRU eviction sees only idle entries.
- `evict(key)` — explicit removal; `IdentityResolver.remove()` calls it for soft-deleted users.

Bound: `settings.working_memory_pool_max`, default `max(50, active_user_count * 2)` computed at startup and recomputed on `IdentityResolver.add()`. Magic-50 anchored to "small household + buffer" with the multiplier covering medium households without operator tuning. `working_memory_pool_evictions_total` Prometheus counter exposes pressure.

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

Modification is silent for Slice 2 (the user sees the redacted text; operator sees the modification in the audit subject's pre/post byte counts). The length-delta oracle that silent redaction creates is logged as a known Slice-2 risk in §7 — the Slice-3 mitigation menu (fixed banner, bucket-padding, or constant-time scan) is dispatched to `alfred-security-engineer` then.

### i18n per-user

New `User.language` column (BCP-47, default `settings.operator_language`). Set per-coroutine via `set_language(user.language)` (ContextVar — §0.1). `User.language` is validated at every ingress: a Pydantic `field_validator` on `User` and `Settings.operator_language` runs `babel.Locale.parse`, and the Typer `--language` callback runs the same check before mutation, surfacing `t("cli.user.error.invalid_language", value=…)` on rejection. At runtime, `IdentityResolver` WARN-logs once per user per process when the stored language has no shipped catalog, and `t()` falls back to English so user-visible messages never render as bare i18n keys — model output still goes to the model in the user's language, AlfredOS chrome stays English when the catalog is missing.

Catalog additions enumerated (full list — no wildcards in spec):

**Discord adapter keys:**
- `discord.unknown_user_first` — first-DM-since-startup variant, echoes the sender's snowflake and names the operator's bind command so the user has a self-discovery path.
- `discord.unknown_user_repeat` — subsequent variant, polite, no hint (suppressed entirely after the second hit per the dedup window).
- `discord.embed_unsupported` — embeds/attachments/stickers refusal.
- `discord.rate_limited` — token-bucket refusal.
- `discord.budget_blocked` — typed kwargs `{spent}`/`{cap}`, never `{error}`.
- `discord.alfred_error` — fixed phrase, no interpolation.

**`alfred user` CLI keys (enumerated, not wildcarded — pybabel extract needs concrete names):**
- `cli.user.help.group` + per-subcommand `cli.user.help.<add|list|show|remove|bind|unbind|set>.short` + `.long` (14 keys).
- `cli.user.flag.<name>.<short|long>` for every option (`--name`, `--discord-id`, `--authorization`, `--daily-budget-usd`, `--language`, `--rate-limit-per-min`, `--rate-limit-per-day`, `--platform`, `--id`, `--json`, `--include-deleted`, `--yes`). ~24 keys.
- Success/confirmation: `cli.user.added`, `cli.user.bound`, `cli.user.unbound`, `cli.user.removed`, `cli.user.set.success`, `cli.user.remove.confirm`, `cli.user.remove.refused_last_operator`.
- Errors: `cli.user.error.not_found`, `.platform_id_in_use`, `.user_already_bound`, `.invalid_authorization`, `.invalid_language`, `.invalid_bcp47`, `.budget_must_be_positive`, `.no_operator`, `.no_tty_without_yes`.
- Setup script: `cli.setup.operator_added`, `cli.setup.operator_name_prompt`, `cli.setup.discord_bind_hint`.

**Secret-broker keys:**
- `secrets.file_perms_too_open` — friendly error with path + chmod hint.
- `secrets.file_missing_required` — `SecretBrokerConfigError` text.

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
| Rate-limited | `rate_limited` | Polite refusal (no `{error}` interpolation) |
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

- Lowercase, ASCII-NFKC-normalised, non-alphanumeric → `-`, trimmed/collapsed.
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

# Soft-delete. Refuses if target is the last role=operator user (architect-007).
alfred user remove <slug>                              # confirms by default; refuses under non-TTY without --yes (exit 2)
alfred user remove <slug> --yes                        # skip confirmation

# Bind / unbind. Bind refuses on existing user_id-platform conflict (use `unbind` first).
alfred user bind <slug> --platform discord --id 123456789012345678
alfred user unbind <slug> --platform discord

# Tune an existing user. `unset` reverts an override to authorization-derived default (rate-limit only).
alfred user set <slug> [--daily-budget-usd <float>] [--authorization <role>] \
                       [--language <bcp47>] [--rate-limit-per-min <int>|unset]
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
- `tests/unit/comms/test_no_direct_adapter_imports.py` (new) — AST-scans every `.py` file outside `src/alfred/comms/` and `tests/`; fails if any imports `alfred.comms.tui`, `alfred.comms.discord`, or any future concrete adapter module / class directly. Modelled on `tests/unit/security/test_no_direct_env_reads.py` (slice 1). Locks the `CommsAdapter` Protocol as the only legitimate import seam — when Slice 3 swaps the transport to MCP, every consumer is already going through the Protocol so no code outside `comms/` needs to change.

### Integration tests (`tests/integration/`)

- `tests/integration/test_users_postgres.py` (new) — `User` + `PlatformIdentity` CRUD against testcontainer Postgres; CHECK constraints on `authorization` / `platform`; CASCADE delete; UNIQUE rejection on double-bind; partial UNIQUE on `(user_id, platform) WHERE deleted_at IS NULL`; `LISTEN/NOTIFY` round-trip across two sessions (CLI session mutates, listener session observes counter bump).
- `tests/integration/test_audit_persistence.py` extension — audit rows for `user.*` events survive across rollback; per-user `result=budget_blocked` / `rate_limited` events; `language` and `persona_id` populated on every new row.
- `tests/integration/test_secrets_file_backend.py` (new) — broker loads from `tmp_path/secrets.toml`; env override for slice-1 keys; file precedence for `discord_bot_token`; 0600-perm requirement; broker refuses path with `.git` parent.
- `tests/integration/test_migration_0004_backfill.py` (new) — boot Postgres at `0003`, seed episodes + audit_log with literal `operator_name`, upgrade to `0004`, assert backfill correctness for three cases: custom `ALFRED_OPERATOR_NAME`, default `"operator"` no-op, non-operator slug-collision refusal with the expected remediation message. Asserts row counts preserved, audit append-only invariant holds, single-transaction atomicity (a forced failure mid-migration leaves the DB at `0003`).
- `tests/integration/test_discord_adapter_integration.py` (new — renamed from "smoke", per te-003) — boots Postgres testcontainer, runs `alfred user add` for a fake Discord ID, invokes `DiscordAdapter._handle(mock_message)` against a real orchestrator + a mocked provider router. Asserts episode + audit + budget side effects; covers the forgot-to-bind variant.
- `tests/integration/test_discord_message_surface.py` — imports real `discord.py` types (Message, DMChannel, Embed, Attachment) so a minor-version surface change fails the build before it surprises a release.

### Smoke tests (`tests/smoke/`)

- `test_hello_alfred.py` extension — instead of hardcoded `user_id="operator"`, creates a `User` row via the real `IdentityResolver.add` + drives the orchestrator with that canonical slug. The smoke fixture runs `alembic upgrade head` against the testcontainer; the assertion confirms the operator row was auto-populated from `settings.operator_name`.
- `tests/smoke/test_discord_gateway_smoke.py` (new) — gated by `ALFRED_SMOKE_DISCORD_TOKEN` env var (skip when unset). Runs `alfred discord verify` against a real Discord bot account; asserts `on_ready` fires within 30s and the right intents are granted. Alternative deliverable if the operator-side bot account is too friction: `docs/runbooks/slice-2-discord-smoke.md` as a release-checklist playbook. One of the two MUST be a PR-E deliverable — the current "or operator runs it manually" hedge is not enough.

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
| ADR-0011 | Per-user `BudgetGuard` (dict-keyed counter; operator inherits Slice-1 global cap; `_spent`/`_day` never evict) | PR E (body), placeholder in PR A |
| ADR-0012 | File-backed `SecretBroker` at `~/.config/alfred/secrets.toml`, plaintext-with-0600 for Slice 2; age-encryption deferred to Slice 3+; broker-only access invariant for SUPPORTED_SECRETS | PR E (body), placeholder in PR A |

**Two-dispatch plan for docs-author.** PR A invokes `alfred-docs-author` for ADR-0009 and ADR-0010 bodies (and the ADR-0013 placeholder) so PR A has the design anchors it commits to. PR E invokes `alfred-docs-author` for the deep-docs bootstrap + ADR-0011/0012 bodies + the ADR-0013 full body. ADR-0009 and ADR-0010 are load-bearing for PRs B–D; ADR-0011 and ADR-0012 record decisions already implemented.

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
| **A** | Step 0 (ContextVar refactor + ADR-0013 placeholder), ADR-0009 + ADR-0010 + ADR-0013 placeholder ADR files; identity layer: `users` + `platform_identities` migration 0004 + ORMs + `IdentityResolver` + `IdentityVersionCounter` + `LISTEN/NOTIFY` plumbing + `alfred user *` CLI subcommands + i18n catalog entries (cli.user.*) + drive-by fix for `cli/main.py:54` `t()` leak. Tests for the identity layer + migration backfill (three cases). **Plumbing only — no Discord, no DLP, no compose.** | smoke test passes against canonical-slug user; migration 0004 idempotent + atomic; ContextVar isolation test green |
| **B** | `BudgetGuard` per-user refactor (typed `UnknownBudgetUserError`, `evict`, version-counter subscribe, NaN guards); `WorkingMemoryPool` in `src/alfred/memory/working.py` with `(persona, user_id)` key + per-key locks + acquire/release lifecycle; orchestrator contract change (`handle_user_message(*, user, content, working_memory)` accepting `TaggedContent[T2]`); persona-prompt rewording with `operator_name` + `requesting_user_name`; `render_persona_prompt(persona=…)` refactor; `episodic.record` + `audit.append` per-row `language` + `persona_id`. Slice-1 TUI continues working unchanged through `IdentityResolver.get_operator()`. Atomic 18-call-site signature migration is enumerated in PR B's checklist (or split into Bb/Bm/Bo if the call-site sequencing turns out unsafe in one commit — architect's call at plan time). | TUI smoke test still passes; orchestrator audit branches each produce the spec'd `result` value; `WorkingMemoryPool` concurrent-rehydrate property test green |
| **C** | `SecretBroker` file backend + fail-closed permissions check + `require_file` + `SecretBrokerConfigError` + `SecretBrokerPermissionsError` + `.gitignore` entry + `.git`-in-parent rejection + `no_direct_env_reads` grep test + `discord_bot_token` in `SUPPORTED_SECRETS` (file-prefer) + i18n keys (`secrets.file_perms_too_open`, `secrets.file_missing_required`). | `--cov-fail-under=100 --cov=src/alfred/security/secrets.py`; integration test for file backend |
| **D1** | `CommsAdapter` Protocol extraction (start/run/stop/health + `AdapterHealth`); `TuiAdapter` wrap (`TuiAdapter.run()` delegates to `app.run_async()`; resolve-fail friendly hint); `OutboundDlp` + generic-API-key regex stage + canary stub + audit-on-modification; `RateLimiter` Protocol + `InProcessTokenBucketRateLimiter`; markdown-aware splitter helper. **Backend-only — no external deps.** | `--cov-fail-under=100 --cov=src/alfred/security/dlp.py`; TUI smoke passes through the new Protocol seam; **adapter import-isolation test green** (`test_no_direct_adapter_imports.py` — every consumer outside `src/alfred/comms/` goes through the `CommsAdapter` Protocol, so the Slice-3 MCP transport swap touches zero call sites) |
| **D2** | `DiscordAdapter` (with `client_factory` mock seam, discord.py logging bridge, embed/attachment refusal, unknown-DM dedup + global cap, code-block-aware splitter use, single `_send` chokepoint, typed `BudgetExceededError`, reconnect classification table); `discord.py` dep; `alfred discord` + `alfred discord verify` Typer subcommands; `docker-compose.yaml` adds `alfred-discord` service (`up -d`, `restart: unless-stopped`, memory limit, `discord.Client(max_messages=100, chunk_guilds_at_startup=False, member_cache_flags=none)`); secrets bind-mount; setup script's portable operator-onboarding step (jq, `tr`, `read_env_var`, `--output-slug`, non-TTY guard, optional discord-bind prompt); README quickstart updated with Developer Mode walkthrough. | discord adapter integration test + minor-version surface test green; `alfred discord verify` returns 0 against a real bot in CI when secrets are present |
| **E** | Smoke test `test_discord_gateway_smoke.py` (or the runbook alternative); adversarial corpus scaffolding (harness + schema + uniqueness guard + per-category READMEs + CI job stub + one DLP payload fixture); `docs/subsystems/identity.md` + `docs/subsystems/comms.md` + `docs/glossary.md` bootstrap via `alfred-docs-author`; ADR-0011, ADR-0012, ADR-0013 bodies written. | docs-reviewer pass clean; corpus harness runs trivially on empty corpus |

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
- **BCP-47 catalog-fallback at CLI time — warn or accept?** Should `alfred user add --language X` warn at CLI time when X parses as valid BCP-47 but has no shipped catalog? `babel.Locale.parse` accepts any well-formed tag; the catalog currently only ships `en`. Recommendation: warn-with-confirm at CLI ingress, with a `--no-warn-missing-catalog` escape for scripting. Dispatch to `alfred-i18n-reviewer` after PR A to confirm the UX.
- **Length-delta DLP oracle mitigation choice** — three options: fixed banner on any redaction, bucket-padding, or constant-time scan. All are Slice-3 work; the spec accepts the known Slice-2 risk. `alfred-security-engineer` picks the Slice-3 mitigation when planning Slice 3.
- **Multi-operator deployments** — `IdentityResolver.get_operator()` raises if more than one `authorization='operator'` user exists. Slice 4's persona-registry work probably needs a config knob (`settings.household_operator_slug`) to elect the canonical owner. Out of scope for Slice 2.

### Punch list (Lows, deferred to plan where cheap to defer)

These are non-blocking polish items the plan picks up:

- discord.py internal cache flags + container memory limits on `alfred-discord` (perf-005 — folded into D2 compose block).
- `SecretBroker.redact` alternation regex caching + `MAX_REDACTOR_PATTERNS=256` overflow alert (perf-006 — Slice-3 prep work; ships now).
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
| i18n-005 | Open question (catalog-fallback warn-or-not) explicitly held open in §7. |
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

---

## 9. References

- [PRD §5 Architectural Invariants](../../../PRD.md#5-architectural-invariants)
- [PRD §6.1 Multi-modal Comms](../../../PRD.md#61-multi-modal-comms)
- [PRD §6.2 Memory Subsystem](../../../PRD.md#62-memory-subsystem)
- [PRD §6.8 Persona System](../../../PRD.md#68-persona-system)
- [PRD §7.1 Security & Prompt Injection Defense](../../../PRD.md#71-security--prompt-injection-defense)
- [PRD §7.2 Multi-User Identity & Authorization](../../../PRD.md#72-multi-user-identity--authorization)
- [ADR-0008 LLM output is T2 in Slice 1 — superseded in part by ADR-0013](../../adr/0008-llm-output-trust-tier.md)
- [Slice 1 plan](../plans/2026-05-24-slice-1-hello-alfred.md)
- [`alfred-adversarial-corpus` skill](../../../.rulesync/skills/alfred-adversarial-corpus/SKILL.md)
- [`alfred-docs-author` agent](../../../.rulesync/subagents/alfred-docs-author.md)
- [`alfred-ai-expert` agent](../../../.rulesync/subagents/alfred-ai-expert.md)
- Review-plan findings: `/Users/iandominey/.cache/alfred-os/review-plan/2026-05-26-slice-2-discord-multiuser-design/`
