# Slice 2 — PR D2: DiscordAdapter + compose + setup + README — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax — tick them as you complete them so a resuming session can locate the next task without re-reading the world.

**Goal:** Ship the `DiscordAdapter` that completes Slice 2's end-to-end Discord DM flow. After this PR, an operator can pre-map a Discord ID via `alfred user add --discord-id …`, start `docker compose up -d alfred-discord`, DM the bot from Discord, and round-trip through the orchestrator with audit + budget + episodic memory + outbound DLP + per-user rate-limiting all in place. Embeds/attachments/stickers/poll/components/activity/application are refused at the boundary (allowlist trust-tagging — only `msg.content` is read). Unknown Discord IDs are politely refused with a snowflake echo + bind hint, deduplicated per-snowflake LRU and capped globally so a snowflake-iterating spam bot cannot flood the audit log. The `alfred discord verify` subcommand gives the operator a deterministic green/red signal before the long-running gateway loop daemonises.

**Spec:** [`/tmp/slice-2-spec.md`](/tmp/slice-2-spec.md) §2 (CLI entrypoint, compose changes), §3 (full Discord adapter detail — trust tagging, adapter wiring shape, orchestrator contract, audit-DoS mitigation, shutdown + failure modes, error semantics, markdown-aware splitter), §4 (first-deploy operator-onboarding flow), §5 (test rows for `test_discord`, `test_discord_adapter_integration`, `test_discord_message_surface`), §6 PR D2 row.

**Depends on (HARD — all merged to `main` before D2 opens):**

- **PR A** — `IdentityResolver`, `User` frozen value object, `IdentityVersionCounter`, `LISTEN/NOTIFY` listener with reconnect supervisor, `OperatorAlreadyExistsError`, `alfred user *` CLI, ADRs 0009/0010 (bodies) + 0011/0012/0013 (placeholders).
- **PR B** — `Orchestrator.handle_user_message(*, user, content, working_memory)` accepting `TaggedContent[T2]`; `WorkingMemoryPool.acquire/release` keyed on `(persona, user_id)`; `BudgetGuard.check_and_charge(user_id, …)` + `UnknownBudgetUserError` + typed `BudgetExceededError(spent_usd, cap_usd)`.
- **PR C** — `SecretBroker` file backend with `discord_bot_token` in `_PREFER_FILE`; `SecretBrokerConfigError` base + `SecretBrokerFileMissingError` / `SecretBrokerNotAFileError` / `SecretBrokerPermissionsError` subtypes; `tests/unit/security/test_no_direct_env_reads.py` grep-scan; eager bootstrap construction.
- **PR D1** — `CommsAdapter` Protocol + `AdapterHealth`; `_DiscordClientLike` structural Protocol; `OutboundDlp.scan` (broker-redact + generic-API-key regex + canary stub); async `RateLimiter` Protocol + `InProcessTokenBucketRateLimiter` with **read_only-first** invariant (`if user.authorization == READ_ONLY: return False` before any token math); `_split_for_discord` markdown-aware helper in `src/alfred/comms/markdown_split.py`; `TuiAdapter` wrap; `test_no_direct_adapter_imports.py` AST-scan locking the Protocol seam.

**Architecture:** New module `src/alfred/comms/discord.py` implements `DiscordAdapter(CommsAdapter)` from PR D1's Protocol. `discord.py>=2.4,<3` is the only new runtime dependency (no `[voice]` extras → no PyNaCl pull-in). A `client_factory: Callable[[discord.Intents], _DiscordClientLike] = discord.Client` constructor inject makes the gateway client mock-injectable so every adapter unit test runs without touching the real Discord network. A single private `_send` chokepoint funnels every outbound chunk through `OutboundDlp.scan → _split_for_discord → channel.send`; a grep-asserting unit test pins this invariant. Allowlist trust-tagging at the boundary: parse `msg.content` only; assert `msg.embeds`, `msg.attachments`, `msg.stickers`, `msg.reference`, `msg.poll`, `msg.components`, `msg.activity`, `msg.application` are all empty/None — any non-empty triggers an audit row + `discord.embed_unsupported` reply with zero orchestrator call. Per-snowflake LRU dedup (`TTLCache(maxsize=1024, ttl=3600s)`) + global token-bucket cap on `discord.unknown_user_dm` audit writes (default 60/min) keep a snowflake-iterating spam bot from flooding the append-only audit log. `discord.py`'s stdlib `logging` is bridged through a structlog `ProcessorFormatter` whose chain includes the broker's redactor, so any token-leaking library debug line is redacted before reaching disk. Two Typer subcommands wire the adapter into the CLI: `alfred discord` boots `DiscordAdapter.start() → run()` for the long-running daemon, and `alfred discord verify` runs a short-lived 30s probe with the exit-code table pinned in tests. The `alfred-discord` service in `docker-compose.yaml` runs the same image as `alfred-core` with `command: ["discord"]`, `restart: unless-stopped`, a 256M memory cap (perf-003), `discord.Client(max_messages=100, chunk_guilds_at_startup=False, member_cache_flags=none)` slim-cache flags (perf-005), the secrets bind-mount, and `user: "${UID:-1000}:${GID:-1000}"` for host/container UID parity on Linux. The setup script grows a portable operator-onboarding step (jq prereq, `tr` for bash-3.2-safe lowercasing, `read_env_var` for `.env` safety, `--output-slug` for canonical slug capture, non-TTY guard via `ALFRED_OPERATOR_NAME`, optional Discord-bind prompt followed by `alfred discord verify`). The README quickstart gains a Developer Mode walkthrough mirroring the spec's 1-8 operator workflow.

**Tech Stack:** Python 3.12+ • `discord.py>=2.4,<3` • `cachetools` (TTLCache for unknown-DM dedup) • asyncio • Typer • Pydantic v2 (frozen `User` value object from PR A) • structlog with `ProcessorFormatter` library-log bridge • pytest + pytest-asyncio • testcontainers (Postgres) • Docker Compose.

**Subagent owners:** `alfred-comms-engineer` owns `src/alfred/comms/discord.py` + the two Typer subcommands + the markdown-splitter call sites + the unit + integration tests. `alfred-security-engineer` reviews the trust-boundary allowlist (sec-001), the `_send` chokepoint discipline (sec-002 read_only-suppressed + the no-`str(exc)` rule), the discord.py logging-bridge redaction test, and the audit-DoS mitigation. `alfred-devops-engineer` owns `docker-compose.yaml`, `bin/alfred-setup.sh`, `pyproject.toml` (the `discord.py` + `cachetools` dep additions), and the README quickstart edits. `alfred-python-developer` enforces conventions across all three subagents' output.

---

## 0. Files this PR creates or modifies

**Created**

- `src/alfred/comms/discord.py` — `DiscordAdapter` implementation; `_DiscordClientLike` import from PR D1; module-private helpers `_non_empty_content_fields`, `_handle_unknown_dm`, `_audit_and_send_refusal`, `_send`, `_compute_intents`, `_install_signal_handlers`, `_classify_gateway_exception`, `_bridge_library_logging`.
- `src/alfred/cli/discord_cmd.py` — Typer subcommand module: `alfred discord` (boot) + `alfred discord verify` (probe). Wires into `src/alfred/cli/main.py` via the existing `app.add_typer(...)` shape from PR A's `alfred user *` precedent.
- `tests/unit/comms/test_discord.py` — every `_handle` branch + every `_send`-internal failure branch (`dlp_failed` / `split_failed` / `send_failed` + `delivered_chunk_count`) + audit-DoS dedup + global cap counter + reconnect classification table + library-logging-bridge redaction + `alfred discord verify` exit-code table (one branch per code 0/1/2/3/4/130) + grep-assertion pinning `msg.channel.send` to `_send` only + assertion that no `t(...)` call site interpolates an `Exception` instance.
- `tests/integration/test_discord_adapter_integration.py` — boots Postgres testcontainer, runs `alfred user add` for a fake Discord ID, invokes `DiscordAdapter._handle(mock_message)` against a real orchestrator + a mocked provider router, asserts episode + audit + budget side effects, covers the forgot-to-bind variant. (Renamed from "smoke" per te-003.)
- `tests/integration/test_discord_message_surface.py` — imports real `discord.py` types and pins the surface the adapter relies on (te-002 + sec-001) via `inspect.signature` for callables + `hasattr` for attributes. Pinned set: `discord.Message.{content, author.id, author.bot, channel, embeds, attachments, stickers, reference, poll, components, activity, application}`; `discord.DMChannel` exists and is distinguishable from `discord.GroupChannel`; `discord.Client.start(token, reconnect=True)` and `discord.Client(max_messages=…, chunk_guilds_at_startup=…, member_cache_flags=…)` accept the adapter's kwargs. Failure message names the missing attribute + the `>=2.4,<3` pin.

**Modified**

- `pyproject.toml` — add `"discord.py>=2.4,<3"` and `"cachetools>=5.3"` to runtime deps; assert no `[voice]` extra (no PyNaCl).
- `src/alfred/cli/main.py` — wire the new `discord_cmd` Typer group; ensure every existing `app.command(help=…)` and `typer.Option(help=…)` introduced by this PR wraps the string in `t()` (convention from PR A's drive-by fix).
- `src/alfred/locale/en/LC_MESSAGES/messages.po` — add the six Discord i18n keys enumerated in spec §3 (`discord.unknown_user_first`, `discord.unknown_user_repeat`, `discord.embed_unsupported`, `discord.rate_limited` — non-read_only only per sec-002, `discord.budget_blocked` with typed kwargs `{spent}/{cap}`, `discord.alfred_error` fixed-phrase) plus the `cli.discord.*` help keys for the two new subcommands and the `cli.discord.verify.*` strings for each exit-code structlog event narration that is operator-visible.
- `docker-compose.yaml` — add `alfred-discord` service per spec §2.
- `bin/alfred-setup.sh` — port the bash snippet from spec §4 verbatim, including `require_cmd jq`, `mkdir -p + touch + chmod 600/700` BEFORE any `docker compose run` (devex-002), `export UID GID`, idempotent operator-add via `--output-slug` + safe `read_env_var` for `.env`, non-TTY guard with `ALFRED_OPERATOR_NAME`, optional Discord-bind prompt followed by `alfred discord verify`. The `tr` lowercasing replaces bash-4-only `${name,,}` (macOS bash 3.2 portable).
- `README.md` — Developer Mode walkthrough (spec lines 290-307: operator workflow steps 1-8 verbatim) + the macOS/Linux/WSL2 perm-propagation matrix for the `~/.config/alfred/secrets.toml` bind-mount + the backup-vector reminder (`restic backup ~/.config` exfiltrates plaintext secrets unless excluded).

---

## 1. Task sequence

> Each task is a checkbox. Dispatch one subagent per task or per logical cluster (the indent shows clustering). Run `make check` after every cluster; a red bar is the immediate next task, not the next cluster.

### Cluster 1 — Dependency + library-surface smoke (so every later task runs against a working `discord.py` install)

- [ ] **1.1** Add `discord.py>=2.4,<3` and `cachetools>=5.3` to `pyproject.toml` runtime deps. Confirm no `[voice]` extra. Run `uv lock` and verify pure-wheel install for `linux/amd64` and `linux/arm64` — if any sdist sneaks in, add a `build-essential` builder stage to `docker/alfred-core.Dockerfile` (current expectation per spec line 283: pure-wheel install with `aiohttp` already wheel-packaged).
- [ ] **1.2** Write `tests/integration/test_discord_message_surface.py` first (TDD — the surface pin is the prerequisite contract; everything else assumes `discord.py` exposes what the adapter touches). Each assertion uses `inspect.signature` for callables and `hasattr` for attributes. Pinned set per spec line 807:
  - `discord.Message.content`, `.author.id`, `.author.bot`, `.channel`, `.embeds`, `.attachments`, `.stickers`, `.reference`, `.poll`, `.components`, `.activity`, `.application` all present (attribute existence).
  - `discord.DMChannel` exists and is `not isinstance(group, discord.DMChannel) and isinstance(dm, discord.DMChannel)` distinguishable from `discord.GroupChannel`.
  - `inspect.signature(discord.Client.start)` accepts `token, reconnect=True`.
  - `inspect.signature(discord.Client.__init__)` accepts `max_messages`, `chunk_guilds_at_startup`, `member_cache_flags`.
  - Failure messages name the missing attribute + cite the `>=2.4,<3` pin so a minor-version rename trips the build immediately with an actionable error.
- [ ] **1.3** `make check`. Surface test should pass on a fresh `uv sync`. Any failure here is a pinning issue; fix the pin or the test before proceeding.

### Cluster 2 — discord.py logging bridge (lands early so all downstream debug output is already redacted)

- [ ] **2.1** Implement `_bridge_library_logging(broker: SecretBroker) -> None` in `src/alfred/comms/discord.py`. The function attaches a structlog `ProcessorFormatter` to `logging.getLogger("discord")` whose processor chain includes the broker's redactor (the same one structlog uses in `src/alfred/cli/main.py` via the PR D1 refactor that routes leaf-string redaction through `OutboundDlp.scan`). Per spec line 285, also route through `OutboundDlp.scan` so the generic-API-key regex catches model-fabricated leaks in library debug output.
- [ ] **2.2** Write `tests/unit/comms/test_discord.py::test_library_logging_is_redacted`. Construct a fake `logging.LogRecord` with `msg=f"connecting with token {SUPPORTED_SECRETS_FIXTURE_VALUE}"`, route it through the bridged formatter, assert the output renders with the secret replaced by the broker's redaction marker (and a model-fabricated `sk-XXXXXXXXXXXXXXXXXXXX` value in the same record renders as `[REDACTED:api-key-shape]`).
- [ ] **2.3** `make check`. Bridge in place before any adapter code that might emit debug lines.

### Cluster 3 — `DiscordAdapter` skeleton + intents + adapter-startup audit row

- [ ] **3.1** Declare the class with `from __future__ import annotations`, full type hints, frozen Pydantic / dataclass discipline per `docs/python-conventions.md`. Constructor injects per spec line 323-332: `orchestrator`, `identity_resolver`, `broker`, `outbound_dlp`, `rate_limiter`, `client_factory: Callable[[discord.Intents], _DiscordClientLike] = discord.Client`. Class attribute `name = "discord"`. Implement `CommsAdapter` Protocol: `async def start`, `async def run`, `async def stop`, `def health() -> AdapterHealth`. Type-only import for `discord` types behind `if TYPE_CHECKING:` where it doesn't break runtime calls.
- [ ] **3.2** Implement `_compute_intents() -> discord.Intents`. Slice 2 is DM-only; per spec line 295-296, the setup script prints the current Message Content intent requirement based on the pinned version — the adapter mirrors that decision and logs the granted flags. The intent flags are logged + audited as an adapter-startup row (`event=discord.adapter.start`, `subject.intents=<flag list>`, `result=success` or `result=login_failed` when `LoginFailure` raises before `on_ready`).
- [ ] **3.3** Implement `_install_signal_handlers(client)`: SIGTERM and SIGINT call `await client.close()` (and `stop()` triggers the same via Compose's 10s SIGTERM grace per spec line 549).
- [ ] **3.4** Unit test: constructor accepts every keyword inject; `name == "discord"`; `_compute_intents()` returns the documented flag set; signal handlers install without error in a `try/finally`-cleaned event loop.

### Cluster 4 — `_handle` happy path with mock client (no allowlist, no rate-limit, no dedup yet — just the happy flow shape)

- [ ] **4.1** Write `tests/unit/comms/test_discord.py::test_handle_happy_path` first. Mock `discord.Message` with `content="hello"`, `author.id=12345`, `author.bot=False`, `channel=<discord.DMChannel mock>`, every other allowlist field empty/None. Mock `IdentityResolver.resolve("discord", "12345")` to return a `User` instance with `slug="alice"`, `language="en-US"`, `authorization=STANDARD`. Mock orchestrator to return `"hi alice"`. Mock `OutboundDlp.scan` to passthrough. Assert one `channel.send("hi alice")` happens.
- [ ] **4.2** Implement `_handle` skeleton matching spec lines 348-401: bot-author short-circuit, non-DM short-circuit (GroupChannel rejected), identity resolution call, orchestrator call inside `try/finally` with `working_memory` acquired from the pool at top-of-turn, response sent via `_send`. Re-running the test from 4.1 should now pass.
- [ ] **4.3** Add `tests/unit/comms/test_discord.py::test_bot_author_ignored` (zero orchestrator call, zero audit row) and `test_group_channel_rejected` (zero orchestrator call, zero audit row, zero reply — group persona sessions land in Slice 4 via threads per spec line 341-342).

### Cluster 5 — Allowlist trust-tagging at the boundary (sec-001)

- [ ] **5.1** Implement `_non_empty_content_fields(msg: discord.Message) -> list[str]` returning the names of any of `embeds`, `attachments`, `stickers`, `reference`, `poll`, `components`, `activity`, `application` that are non-empty/non-None. Truthiness check follows discord.py's container semantics (empty list `[]` → empty, `None` → empty; `discord.MessageReference()` → present).
- [ ] **5.2** Implement `_audit_and_send_refusal(msg, event_name, t_key, **subject_fields) -> None`. Writes the audit row FIRST (spec line 416 — audit-before-send). On `AuditWriteError` log ERROR with full structured context, bump `alfred_audit_write_failures_total`, and propagate (per slice-1 "loud audit, re-raise" discipline). On audit success call `_send(t(t_key, **subject_fields))`.
- [ ] **5.3** Wire the allowlist check at the top of `_handle` (after the bot/non-DM short-circuit, before identity resolution). One refusal call when any allowlist field is non-empty: `event=discord.embed_refused`, `subject.refused_fields=<list>`, t_key=`discord.embed_unsupported`. Skip the orchestrator.
- [ ] **5.4** Unit tests — one branch per refused field (8 tests total: embeds, attachments, stickers, reference, poll, components, activity, application). Each asserts: zero orchestrator call, one audit row with `event=discord.embed_refused` and the field name in `refused_fields`, one `_send` call with the `discord.embed_unsupported` rendered string. Plus `test_clean_message_passes_allowlist` confirming all-empty fields proceed to identity resolution.

### Cluster 6 — Identity resolution + unknown-DM dedup + global cap (audit-DoS mitigation, spec §3 lines 538-545)

- [ ] **6.1** Add `TTLCache(maxsize=1024, ttl=3600)` (per spec line 542) keyed on `str(msg.author.id)` (snowflake) for unknown-DM dedup, scoped to the adapter instance (state restarts on adapter restart, per the spec's explicit semantics note).
- [ ] **6.2** Add a token-bucket on `discord.unknown_user_dm` audit writes (default 60/min, configurable via `Settings.discord_unknown_dm_audit_cap_per_min`). Beyond the cap, drop the audit write and bump `discord_unknown_dm_audit_dropped_total` Prometheus counter. Emit a single ERROR log row per minute summarising the drop volume (use a rolling minute window so the log doesn't go silent on a sustained flood).
- [ ] **6.3** Implement `_handle_unknown_dm(msg)`: check dedup → first-contact branch writes the audit row + sends `discord.unknown_user_first` (with literal snowflake echo + bind hint per devex-004; `{snowflake}` is the only placeholder, `<YourName>` stays literal); repeat branch within TTL silently drops (no reply, no audit row, no counter bump per spec line 542). Beyond the global cap, drop the audit row but still send the first-DM reply if dedup said this is the first contact (the audit-DoS mitigation protects the *append-only log*, not the user-facing one-shot refusal).
- [ ] **6.4** Wire `_handle_unknown_dm` after `IdentityResolver.resolve(...) is None`. Confirm zero orchestrator call, zero rate-limit consult, zero language switch happens on the unknown branch.
- [ ] **6.5** Unit tests:
  - `test_unknown_dm_first_contact` — one audit row (`event=discord.unknown_user_dm`, `subject.snowflake=<id>`), one reply with the literal body per devex-004, zero orchestrator call.
  - `test_unknown_dm_dedup_within_ttl` — 50 DMs from same snowflake produce 1 audit row + 1 reply (per spec line 545's `test_unknown_dm_flood_writes_one_audit_row`).
  - `test_unknown_dm_global_cap` — 61 DMs from 61 distinct snowflakes within one minute produce ≤60 audit rows, the counter bumps to 1, and the per-minute ERROR log row summarising drop volume appears once.
  - `test_unknown_dm_replies_first_contact_even_when_audit_cap_reached` — even past the global audit cap, an actual first-contact snowflake gets one reply (the cap protects the audit log, not the user UX). The audit row is the only thing dropped.

### Cluster 7 — Per-user rate-limiting integration with PR D1's `RateLimiter`

- [ ] **7.1** Wire the `await self._rate_limiter.allow(user)` call AFTER identity resolution and BEFORE `set_language`. Per spec line 224 + architect-002, the rate-limiter takes the full `User` and its FIRST check is `if user.authorization == READ_ONLY: return False`. Slice 2's PR D1 `InProcessTokenBucketRateLimiter.allow()` enforces this invariant; the adapter just calls it.
- [ ] **7.2** On `allow() == False`:
  - `read_only` users: audit row (`event=discord.read_only_refused`, `result=refused`), NO reply (sec-002 reply-suppression — denies the friend-list oracle).
  - Non-`read_only` users: audit row (`event=discord.rate_limited`, `result=rate_limited`), one reply via `_send(t("discord.rate_limited"))` — no `{error}` interpolation per spec line 415.
- [ ] **7.3** Refusal-helper variant: extend `_audit_and_send_refusal` to take a `suppress_reply: bool = False` kwarg so the read_only branch writes the audit row without sending. (Or factor a `_audit_only(msg, event_name, **subject_fields)` helper — pick whichever keeps the call sites readable.)
- [ ] **7.4** Unit tests:
  - `test_read_only_user_refused_no_reply` — `allow()` returns False because of authorization; audit row written; zero `_send` call.
  - `test_standard_user_rate_limited_with_reply` — `allow()` returns False because of token bucket; audit row + one reply, no `{error}` interpolation.
  - `test_rate_limiter_called_with_full_user` — `allow()` receives the full `User` instance, not just a slug, so the read_only-FIRST invariant remains enforceable.

### Cluster 8 — Per-coroutine `set_language(user.language)` via ContextVar (PR A's §0.1 refactor)

- [ ] **8.1** Call `set_language(user.language)` immediately after the rate-limit gate, before `WorkingMemoryPool.acquire`. The ContextVar (`alfred_active_lang`) propagates across `await` points so the orchestrator + `_send` chain both render `t()` in the user's language without any handler-side bookkeeping.
- [ ] **8.2** Unit test `test_language_set_per_user` — two interleaved `asyncio.gather` coroutines with users in `en-US` and `de-DE`; each renders its budget-blocked reply (forced by a stubbed orchestrator that raises `BudgetExceededError`) in its own language.

### Cluster 9 — `WorkingMemoryPool.acquire/release/finally` lifecycle (PR B contract)

- [ ] **9.1** Wrap the orchestrator call in `try/finally` per spec lines 376-398: `wm = await self._working_pool.acquire(("alfred", user.slug))` before the call; `await self._working_pool.release(("alfred", user.slug), wm)` in the `finally`. The persona key is the literal `"alfred"` for every Slice-2 turn.
- [ ] **9.2** Confirm the pool is captured once at top-of-turn (no re-acquire mid-turn) — mem-001 is non-negotiable. The pool is owned by `src/alfred/memory/working.py` (PR B), so the adapter only calls into it.
- [ ] **9.3** Unit test `test_working_memory_released_on_orchestrator_error` — orchestrator raises a generic `Exception`, assert `release` is called exactly once, the exception re-propagates, and the entry is marked idle (verifiable via the pool's health snapshot).

### Cluster 10 — Orchestrator call site with typed exception handling

- [ ] **10.1** Call `await self._orch.handle_user_message(user=user, content=TaggedContent[T2](msg.content), working_memory=wm)`. The `TaggedContent[T2]` constructor makes the trust tier load-bearing at the type level (sec-007).
- [ ] **10.2** Exception arms per spec lines 383-396:
  - `BudgetExceededError as exc`: send `t("discord.budget_blocked", spent=exc.spent_usd, cap=exc.cap_usd)` — typed kwargs, never `str(exc)`. Return (no re-raise — user got the polite message; orchestrator already audited the budget-blocked row).
  - `UnknownBudgetUserError`: defense-in-depth — resolver should have caught it. Send `t("discord.alfred_error")` (fixed phrase, no interpolation), then `raise` so the loud audit propagates upward through the gateway loop's error path.
  - `asyncio.CancelledError`: bare `raise` (NEVER swallow cancellation).
  - `Exception`: `log.exception("discord.handler_failed", user_id=user.slug)`, send `t("discord.alfred_error")`, `raise` so the gateway loop's error handler can decide reconnect (per spec line 396).
- [ ] **10.3** Unit tests — one per arm:
  - `test_budget_blocked_uses_typed_kwargs` — assert reply matches `discord.budget_blocked` rendered with `spent=0.50, cap=0.50`; assert no part of `str(exc)` appears in the rendered string; assert no `{error}` placeholder in the catalog entry.
  - `test_unknown_budget_user_loud_re_raise` — assert friendly `discord.alfred_error` sent, then re-raised; structlog ERROR captured.
  - `test_cancelled_error_re_raised_bare` — `CancelledError` propagates; pool released in `finally`; no reply sent (consistent with `result=cancelled` orchestrator-side audit).
  - `test_unhandled_exception_logs_re_raises` — generic `Exception` logged via `log.exception`, `discord.alfred_error` sent, re-raised.
  - `test_no_exception_str_in_user_templates` — AST-walk every `t(...)` call site in `src/alfred/comms/discord.py`; fail if any keyword argument's source AST is `Call(func=Name('str'))` over an `Exception`-typed name OR a direct `Exception` instance.

### Cluster 11 — `_send` chokepoint with DLP scan + markdown-aware split + single `channel.send` caller

- [ ] **11.1** Implement `async def _send(self, text: str) -> None`:

  ```python
  safe = self._outbound_dlp.scan(text)
  for chunk in _split_for_discord(safe, max_len=2000):
      await self._channel.send(chunk)
  ```

  (Spec lines 403-409.)
- [ ] **11.2** Refactor every refusal/error/success path in `_handle` to go through `_send` — no direct `msg.channel.send` anywhere else in `src/alfred/comms/discord.py`.
- [ ] **11.3** Unit test `test_send_is_sole_channel_send_caller` — grep the source of `src/alfred/comms/discord.py`; assert `msg.channel.send` (and equivalent `.send(` patterns on channel-typed references) appear ZERO times outside the body of `_send`. Use AST inspection (walk for `Attribute(attr='send')` calls) rather than text grep so the test isn't fooled by a comment. Failure message names the offending line.
- [ ] **11.4** Unit test `test_send_2000_2001_empty_split_boundaries` — three inputs (exactly 2000 chars, exactly 2001 chars, empty string `""`) produce respectively (one chunk, two chunks, zero chunks — empty string is not sent at all per spec convention; verify behaviour with `_split_for_discord`'s contract).
- [ ] **11.5** Hypothesis property test `test_split_concat_modulo_fence_markers_equals_original` — for any markdown text up to 10k chars, splitting then re-concatenating modulo the close/re-open fence markers equals the original. (The splitter helper itself is from PR D1; this test confirms the adapter's call site preserves the property.)

### Cluster 12 — err-003 audit branches for `_send` internal failures

- [ ] **12.1** Wrap `_send` body in a try-block that catches:
  - `OutboundDlpError` (or whatever PR D1's scan raises) → audit `result=dlp_failed`, `subject.dlp_error=<exception class name>`.
  - `MarkdownSplitterError` → audit `result=split_failed`.
  - `discord.HTTPException` 5xx → retry once; on second failure audit `result=send_failed`, `subject.delivered_chunk_count=<int>` (0 if first chunk failed, non-zero on a torn multi-chunk reply).
- [ ] **12.2** All three failure paths send `t("discord.alfred_error")` to the user via a recursive `_send` call. **Stop the recursion** by passing `_recovery=True` to skip the DLP+split steps on the recovery message (which is a fixed-phrase t-key, guaranteed safe). If the recovery `_send` itself fails, log + audit + give up — never recurse forever.
- [ ] **12.3** The success audit row (`result=success`, `subject.delivered_chunk_count=<n>`) is written AFTER `_send` returns OK, not before. Per spec line 417: if the orchestrator already wrote a tentative `result=success` from its own happy-path, a `_send` failure appends a follow-up `comms.discord.send_outcome` audit row with the corrected `result` and `delivered_chunk_count`; the audit-graph CLI joins them by `trace_id`.
- [ ] **12.4** Unit tests — one per branch:
  - `test_send_audit_dlp_failed` — stub `OutboundDlp.scan` to raise; assert audit row with `result=dlp_failed` + `subject.dlp_error="OutboundDlpError"`; assert recovery `discord.alfred_error` sent.
  - `test_send_audit_split_failed` — stub `_split_for_discord` to raise; assert audit row with `result=split_failed`; recovery sent.
  - `test_send_audit_send_failed_zero_chunks` — first chunk's `channel.send` raises 5xx twice; audit row with `result=send_failed`, `subject.delivered_chunk_count=0`.
  - `test_send_audit_send_failed_torn_reply` — first chunk succeeds, second chunk raises 5xx twice; audit row with `result=send_failed`, `subject.delivered_chunk_count=1`.
  - `test_send_audit_success_written_after_return` — happy path; assert the `result=success` audit row's timestamp is AFTER the last `channel.send` returns.
  - `test_send_outcome_correction_row` — orchestrator wrote tentative success; `_send` fails; assert a follow-up `event=comms.discord.send_outcome` row exists with the corrected `result` and the same `trace_id` as the orchestrator's row.

### Cluster 13 — Reconnect classification table (spec §3 shutdown + failure modes)

- [ ] **13.1** Implement `_classify_gateway_exception(exc)` returning a `_GatewayDisposition` enum: `LOGIN_FAILED_EXIT_2`, `CONNECTION_CLOSED_AUTO_RECONNECT`, `HTTP_5XX_RETRY_ONCE_THEN_DROP`, `REPEATED_RECONNECT_EXIT_1`. Drive a small dataclass `_RecentReconnects(window_seconds=60, threshold=10)` to count and trigger the EXIT_1 branch.
- [ ] **13.2** Audit + log + exit per the table in spec line 553-559:
  - `LoginFailure` → log ERROR, audit `result=login_failed`, exit 2.
  - `ConnectionClosed (4xxx)` → log WARN, library auto-reconnects, no audit row.
  - `HTTPException` 5xx mid-send → log WARN, retry once, then drop chunk + audit `result=send_failed` (overlaps with cluster 12 — share the helper).
  - Repeated reconnect failures (>10 in 60s) → log ERROR, audit `result=gateway_unhealthy`, exit 1.
- [ ] **13.3** Unit tests:
  - `test_login_failure_exits_2_with_audit` — `client.start()` raises `LoginFailure`; assert audit row + exit code 2.
  - `test_connection_closed_4xxx_silent` — `ConnectionClosed` with a 4xxx code; assert WARN log + no audit row + library reconnect path engaged.
  - `test_http_5xx_retry_once_then_drop` — `HTTPException(status=503)` raised twice on `channel.send`; assert one retry, then drop + audit `result=send_failed`.
  - `test_repeated_reconnect_exits_1` — simulate 11 reconnect events in 60s (use a frozen-time fixture); assert ERROR log + audit `result=gateway_unhealthy` + exit 1.

### Cluster 14 — `alfred discord verify` subcommand with the exit-code table

- [ ] **14.1** Implement `verify(ctx: typer.Context) -> None` in `src/alfred/cli/discord_cmd.py`. Short-lived `discord.Client.start` with a 30s `asyncio.wait_for` timeout; asserts `on_ready` fires within the window; prints granted intent flags + the bot's identity on success.
- [ ] **14.2** Exit codes per spec lines 130-138 (structlog event in italics):
  - `0` *(discord.verify.ok)*: `on_ready` fired; identity + intents printed.
  - `1` *(discord.verify.upstream_unrecoverable)*: unrecoverable upstream — gateway 5xx, repeated reconnect failure inside the 30s window.
  - `2` *(discord.verify.config_failed)*: config — bad token, intents off in the developer portal, missing perms, secrets file unreadable. Intents-off message embeds the `https://discord.com/developers/applications/<bot-id>/bot` URL.
  - `3` *(discord.verify.login_failed)*: `LoginFailure` (typed).
  - `4` *(discord.verify.timeout)*: 30s elapsed without `on_ready`, gateway not yet 5xx.
  - `130` *(discord.verify.interrupted)*: SIGINT.
- [ ] **14.3** Use the `_classify_gateway_exception` helper from cluster 13 to map exceptions to exit codes; `discord.LoginFailure` → 3 (NOT 2, the table is precise — `LoginFailure` is the typed `LoginFailure`, exit 3; "bad token" not caught as `LoginFailure` falls into the config-class exit 2 via broker errors or `SecretBrokerFileMissingError` etc.).
- [ ] **14.4** Unit test `tests/unit/comms/test_discord.py::test_discord_verify_exit_codes` — one branch per code (0/1/2/3/4/130). Use the `client_factory` mock seam to inject exception-raising stubs; for SIGINT use `KeyboardInterrupt`; for timeout use a stub `on_ready` that never fires.
- [ ] **14.5** Integration sanity (deferred to cluster 19 / PR E smoke): the spec PR-D2 gate requires `alfred discord verify` to return 0 against a real bot in CI when secrets are present. The smoke test wiring lives in PR E (`tests/smoke/test_discord_gateway_smoke.py`); this PR contains the subcommand + the deterministic unit-test exit-code coverage.

### Cluster 15 — `alfred discord` boot subcommand

- [ ] **15.1** Implement `boot(ctx: typer.Context) -> None` (Typer doesn't allow `def discord` as a subcommand name without quoting; prefer the unambiguous internal name and bind via `@discord_app.command("discord")` or split into its own Typer app `discord_app` with `discord_app.command()` for `verify` and a default callback for the daemon). Verify the final CLI surface is exactly `alfred discord` (boot) and `alfred discord verify`.
- [ ] **15.2** Boot path: construct `SecretBroker(require_file=True)` (the entrypoint that gates file-missing fatality per PR C), construct `IdentityResolver`, `BudgetGuard`, `OutboundDlp`, `RateLimiter`, `WorkingMemoryPool`, `Orchestrator`, then `DiscordAdapter(...)` and await `adapter.start()` + `adapter.run()`. Install SIGTERM/SIGINT handlers via `_install_signal_handlers`.
- [ ] **15.3** Wire the new Typer group into `src/alfred/cli/main.py` (`app.add_typer(discord_app, name="discord")`). Every `help=` string wraps in `t()` per the PR A convention.
- [ ] **15.4** Unit test `test_discord_boot_constructs_dependencies` — patch the constructors, run the boot function under `asyncio.run`, assert each dependency was constructed exactly once and the adapter received them.

### Cluster 16 — `docker-compose.yaml` `alfred-discord` service

- [ ] **16.1** Add the `alfred-discord` service block per spec line 270-273:

  ```yaml
  alfred-discord:
    image: alfred-core:${ALFRED_IMAGE_TAG:-latest}
    command: ["discord"]
    restart: unless-stopped
    depends_on:
      alfred-postgres:
        condition: service_healthy
    deploy:
      resources:
        limits:
          memory: 256M    # bump to 512M if you see OOMKills under sustained load
    environment:
      ALFRED_SECRETS_FILE: /etc/alfred/secrets.toml
      # … inherit the rest from the shared env block
    volumes:
      - ~/.config/alfred/secrets.toml:/etc/alfred/secrets.toml:ro
    user: "${UID:-1000}:${GID:-1000}"
  ```

  (The exact YAML keys mirror PR A's existing `alfred-core` service for consistency.)
- [ ] **16.2** Run-shape: spec line 272 mandates `docker compose up -d alfred-discord` (NOT `run -d` — `run` is for one-shot CLI invocations). The setup-script's optional inline-bind path uses `docker compose run --rm alfred-core ...` for one-shot user mutations, then leaves `up -d alfred-discord` to the operator (or the script's final step).
- [ ] **16.3** Inline-comment the 256M memory cap rationale: "Measured RSS for a DM-only workload with the spec'd `discord.Client` flags is ~90-150 MB; bump to 512M if you see OOMKills under sustained load."
- [ ] **16.4** Smoke-verify the compose change locally: `docker compose config --quiet` parses; `docker compose up -d alfred-postgres alfred-discord` starts; `docker compose logs alfred-discord` shows the adapter-startup audit row + the intent flag list. (This is a local dev gate, not an automated test — the integration test in cluster 19 covers the in-process equivalent.)

### Cluster 17 — `bin/alfred-setup.sh` portable bootstrap step

- [ ] **17.1** Port the bash snippet from spec §4 lines 689-748 verbatim. Key invariants:
  - `require_cmd jq` (new prereq; the function already exists in the slice-1 script — extend with a `brew install jq` / `apt install -y jq` hint on miss).
  - `mkdir -p "$HOME/.config/alfred" && chmod 700 "$HOME/.config/alfred" && touch "$HOME/.config/alfred/secrets.toml" && chmod 600 "$HOME/.config/alfred/secrets.toml"` BEFORE the first `docker compose run` (devex-002 — Compose silently creates a *directory* at the bind-mount host path if it's missing, which then surfaces as a confusing `SecretBrokerPermissionsError`).
  - `export UID GID` (some shells export UID automatically, others don't; GID is almost always unexported; both are needed for the `user: "${UID:-1000}:${GID:-1000}"` substitution on macOS/non-1000-UID Linux).
  - `user_list_json="$(docker compose run --rm alfred-core user list --json)"` with a separate exit-code check so an infra failure aborts cleanly with `fail "user list failed (postgres reachable?)"`.
  - `has_operator` count via `jq -r '[.[] | select(.authorization=="operator")] | length'`.
  - Non-TTY guard: when `! -t 0`, use `ALFRED_OPERATOR_NAME:-Operator`.
  - `read_env_var ALFRED_DAILY_BUDGET_USD || echo 1.0` (slice-1 helper that grep-cut-trs out a key from `.env` without `source`-ing).
  - `slug="$(docker compose run --rm alfred-core user add --name "$name" --authorization operator --daily-budget-usd "$budget" --output-slug)"` — canonical slug captured from the CLI, not shell-guessed.
  - `display_lower="$(printf '%s' "$name" | tr '[:upper:]' '[:lower:]')"` — bash 3.2 portable (macOS); never `${name,,}` (bash 4+ only).
  - Slug-divergence note: `[[ "$slug" != "$display_lower" ]] && echo "  (Slug differs from display-lowercase; use '${slug}' in future CLI commands.)"`.
  - Optional Discord-bind prompt (TTY-only): "Discord snowflake to bind now (Settings > Advanced > Developer Mode > right-click > Copy ID; blank to skip): ". On non-empty answer, run `user bind` + immediately `alfred discord verify` so the operator gets a green/red signal before daemonising.
- [ ] **17.2** Add a `step "Bootstrapping operator identity"` header before the new block (mirrors the slice-1 script's step convention).
- [ ] **17.3** Smoke-verify the script locally on macOS bash 3.2 (the targeted compatibility floor) and on Linux bash 5.x. Both should produce identical operator-row outcomes.

### Cluster 18 — `README.md` Developer Mode walkthrough

- [ ] **18.1** Insert the operator workflow steps 1-8 verbatim from spec lines 292-307 into the Quickstart section. Headline: "Enable Discord (Developer Mode walkthrough)".
- [ ] **18.2** Add the perm-propagation matrix (macOS / Linux / WSL2):
  - **macOS:** Docker Desktop maps the host file's uid/gid to the container uid/gid directly; `chmod 600` on the host applies inside the container too. `export UID GID` is required because macOS bash 3.2 does not export `UID` by default.
  - **Linux:** `user: "${UID:-1000}:${GID:-1000}"` resolves to the operator's real uid/gid; the bind-mount's `chmod 600` is enforced by the kernel exactly as on the host.
  - **WSL2:** same as Linux, with the caveat that running `docker compose` from PowerShell (vs `wsl`) sees a different uid namespace; recommend running the script from within WSL to keep the perms consistent.
- [ ] **18.3** Backup-vector reminder (per spec line 215): "`~/.config/alfred/secrets.toml` is plaintext for Slice 2. If you back up your `~/.config` with `restic`, `borg`, or similar, exclude this file or the backup will contain plaintext API keys and Discord tokens. ADR-0012 documents this as a known Slice-2 risk; Slice 3 replaces the plaintext file with an age-encrypted equivalent."
- [ ] **18.4** Optional polish: link to `docs/runbooks/slice-2-discord-smoke.md` (lands in PR E) as the "operator-facing walkthrough for a fresh deploy" reference.

### Cluster 19 — `tests/integration/test_discord_adapter_integration.py` end-to-end happy path

- [ ] **19.1** Boot Postgres testcontainer with the migration `0004` applied. Construct the full dependency graph (real `IdentityResolver`, real `BudgetGuard`, real `WorkingMemoryPool`, real `OutboundDlp`, real `InProcessTokenBucketRateLimiter`, real `Orchestrator`, **mocked** provider router returning a fixed response, **mocked** discord client via `client_factory`).
- [ ] **19.2** Test cases (each a separate `async def test_…` per pytest-asyncio convention):
  - `test_known_user_dm_round_trips_with_audit_and_budget` — `alfred user add --name Alice --discord-id 987654321 --daily-budget-usd 0.50`; invoke `DiscordAdapter._handle(mock_message_from(987654321, "hello"))`; assert one `episodes` row with `user_id="alice"`, `persona_id="alfred"`, `language="en-US"`; assert audit row chain (`event=comms.discord.inbound`, `event=orchestrator.turn`, `event=comms.discord.send_outcome` with `result=success`); assert `BudgetGuard` charged the user; assert one `channel.send` happened.
  - `test_unknown_dm_writes_one_audit_row_and_replies` — no `user add`; invoke `_handle` with an unknown snowflake; assert one audit row + one reply; assert zero `episodes` rows.
  - `test_forgot_to_bind_user_added_without_discord_id` — `alfred user add --name Alice` (no `--discord-id`); DM from a snowflake; assert unknown-DM path (the bind is what links the snowflake; the user existing without a bind is observably the same as no user).
  - `test_embed_attachment_refusal_round_trip` — DM with `embeds=[discord.Embed(title="x")]`; assert `discord.embed_refused` audit + `discord.embed_unsupported` reply + zero orchestrator call.
  - `test_budget_exhausted_returns_typed_kwargs_message` — set the user's budget to $0.00; assert the reply matches `discord.budget_blocked` rendered with the real spent/cap from `BudgetExceededError`.
- [ ] **19.3** The provider mock returns a fixture response; LLM responses are NEVER live in integration tests (per CLAUDE.md "Tests" rule — LLM responses are recorded fixtures except in `tests/smoke/`).

### Cluster 20 — i18n catalog entries

- [ ] **20.1** Add to `src/alfred/locale/en/LC_MESSAGES/messages.po`:
  - `discord.unknown_user_first` — body per devex-004: `"I don't recognise this Discord ID yet (snowflake: \`{snowflake}\`). Ask your operator to run: \`alfred user add --name <YourName> --discord-id {snowflake}\`. The operator's audit log shows this DM."`(`{snowflake}` is the only placeholder; `<YourName>` stays literal).
  - `discord.unknown_user_repeat` — polite, no hint (suppressed entirely after the second hit within the dedup TTL per spec line 516; this key exists for completeness but the dedup branch never sends it — present so the catalog is self-documenting).
  - `discord.embed_unsupported` — embeds/attachments/stickers/poll/components/activity/application refusal text.
  - `discord.rate_limited` — non-`read_only` token-bucket refusal only (sec-002 — NO key for `read_only` because the read_only audit row is the only observable signal).
  - `discord.budget_blocked` — typed kwargs `{spent}` and `{cap}`; never `{error}` (sec-002).
  - `discord.alfred_error` — fixed phrase, no interpolation.
  - `cli.discord.help.group`, `cli.discord.help.verify.short`, `cli.discord.help.verify.long`, `cli.discord.help.boot.short`, `cli.discord.help.boot.long` (5 keys).
  - `cli.discord.verify.ok`, `cli.discord.verify.config_failed.intents_off`, `cli.discord.verify.config_failed.bad_token`, `cli.discord.verify.config_failed.secrets_unreadable`, `cli.discord.verify.login_failed`, `cli.discord.verify.timeout`, `cli.discord.verify.upstream_unrecoverable`, `cli.discord.verify.interrupted` (operator-visible narration for each exit-code event).
- [ ] **20.2** Run `uv run pybabel extract` (pre-commit will do this on every commit anyway). Run `uv run pybabel compile --check` to confirm catalog freshness. CI gate is already in place from slice 1.
- [ ] **20.3** Unit test `test_discord_i18n_keys_resolve` — for each new key, assert `t(key, **mock_kwargs)` returns a non-empty string and contains the expected placeholders.

---

## 2. Acceptance gates

Per spec §6 PR D2 row (line 873):

1. **Discord adapter integration test green.** `tests/integration/test_discord_adapter_integration.py` covers known-user round-trip, unknown-DM, forgot-to-bind, embed refusal, budget-exhausted with typed kwargs. Real `IdentityResolver` + `BudgetGuard` + `WorkingMemoryPool` + `OutboundDlp` + `InProcessTokenBucketRateLimiter` + `Orchestrator` against a testcontainer Postgres with mocked provider router + mocked `discord.Client` via `client_factory`.
2. **Minor-version surface test green.** `tests/integration/test_discord_message_surface.py` pins every allowlist `discord.Message` field and every `discord.Client` kwarg the adapter relies on. Failure trips immediately on a `discord.py` minor-version rename with a message naming the missing attribute and citing the `>=2.4,<3` pin.
3. **`alfred discord verify` returns 0 against a real bot in CI when secrets are present.** This gate's automated implementation lives in PR E's `tests/smoke/test_discord_gateway_smoke.py` (gated by `ALFRED_SMOKE_DISCORD_TOKEN`). PR D2 ships the subcommand + the deterministic unit-test exit-code coverage (one branch per code 0/1/2/3/4/130); PR E flips on the live-bot smoke.
4. **`make check` green.** `ruff check`, `ruff format --check`, `mypy --strict src/`, `pyright src/`, `pytest tests/unit tests/integration -q`, `pybabel compile --check`.
5. **Coverage invariants preserved.** `src/alfred/security/dlp.py` and `src/alfred/security/secrets.py` per-file `--cov-fail-under=100` gates from PRs D1 and C remain green (this PR doesn't touch those modules but a regression there fails the build).
6. **`_send` chokepoint enforced.** `test_send_is_sole_channel_send_caller` AST-walks the adapter source and confirms `msg.channel.send` appears zero times outside `_send`. Every refusal/error/success path goes through DLP scan + markdown-aware splitter.
7. **No `str(exc)` in user-facing templates.** `test_no_exception_str_in_user_templates` asserts no `t(...)` call site interpolates an `Exception` instance.
8. **discord.py logging bridge redacts.** `test_library_logging_is_redacted` confirms a fake log record carrying a known SUPPORTED_SECRETS value renders redacted via the broker's redactor + `OutboundDlp.scan` (catches model-fabricated `sk-…` too).
9. **Audit-DoS mitigation enforced.** `test_unknown_dm_dedup_within_ttl` (50 DMs from same snowflake → 1 audit row + 1 reply) and `test_unknown_dm_global_cap` (61 distinct snowflakes in 1 min → ≤60 audit rows + counter bump + one-per-minute ERROR drop-summary log row).
10. **Reconnect classification covered.** Four unit tests pin `LoginFailure → exit 2`, `ConnectionClosed 4xxx → silent`, `HTTPException 5xx → retry-once-then-drop`, `>10 reconnects in 60s → exit 1`.
11. **Compose change validates.** `docker compose config --quiet` parses; the `alfred-discord` service block contains all spec'd fields (image, command, restart, depends_on healthcheck, memory cap, bind-mount, user UID/GID, env).
12. **Setup script portable.** `bin/alfred-setup.sh` runs end-to-end on macOS bash 3.2 and Linux bash 5.x; the operator row is created idempotently with `--output-slug` capture; non-TTY runs honour `ALFRED_OPERATOR_NAME`; the optional Discord-bind prompt is skipped under non-TTY.

---

## 3. Open questions / decisions deferred to plan time

None. All architectural decisions are pinned by spec §3 (Discord adapter detail) and §4 (setup + onboarding). The atomic-vs-split decision the architect handled at PR B's plan time does not apply here — PR D2 is one logical scope.

The one judgment call inside this plan is **cluster 12.2's recovery-message recursion guard** — passing `_recovery=True` to `_send` to skip the DLP+split steps on the fixed-phrase recovery message. The risk is a stack overflow if `channel.send` itself raises on the recovery message; the mitigation is "log + audit + give up — never recurse forever." This shape is the conventional Python recursion-guard pattern and does not warrant an ADR.

---

## 4. References

- **PRD:** [`PRD.md`](../../../PRD.md) §6.1 (Multi-modal Comms), §7.1 (Security & Prompt Injection Defense), §7.2 (Multi-User Identity & Authorization).
- **Slice 2 spec:** `/tmp/slice-2-spec.md` §2 (CLI entrypoint, compose changes), §3 (full Discord adapter detail), §4 (first-deploy operator-onboarding flow), §5 (test rows for `test_discord`, `test_discord_adapter_integration`, `test_discord_message_surface`), §6 PR D2 row (line 873).
- **ADRs:** ADR-0008 (LLM output T2 in Slice 1 — superseded in part by ADR-0013); ADR-0009 (CommsAdapter Protocol as Slice-2-only in-process seam); ADR-0010 (canonical user_id slug + LISTEN/NOTIFY); ADR-0012 (file-backed SecretBroker + broker-only access invariant); ADR-0013 (defer T1+T3+dual-LLM to Slice 3).
- **Cross-PR contracts:** PR A's `IdentityResolver` + `User` + `IdentityVersionCounter` + LISTEN/NOTIFY listener + `OperatorAlreadyExistsError`. PR B's `Orchestrator.handle_user_message(*, user, content, working_memory)` + `WorkingMemoryPool.acquire/release` + `BudgetGuard.check_and_charge(user_id, …)` + `UnknownBudgetUserError` + `BudgetExceededError(spent_usd, cap_usd)`. PR C's `SecretBroker` file backend + four error subtypes + `_PREFER_FILE` for `discord_bot_token`. PR D1's `CommsAdapter` Protocol + `_DiscordClientLike` + `OutboundDlp.scan` + async `RateLimiter` + `InProcessTokenBucketRateLimiter` read_only-first invariant + `_split_for_discord` helper + `TuiAdapter` wrap + import-isolation test.
- **Convention doc:** [`docs/python-conventions.md`](../../python-conventions.md) — modern Python 3.12+ idioms, SOLID + FP, Pydantic v2, structlog with redaction, async-first, strong typing (mypy strict + pyright), hypothesis property tests.
- **CLAUDE.md hard rules:** rule #1 (i18n discipline — every operator-facing string through `t()`); rules #2-6 (trust-boundary discipline — T2 tagging at the Discord boundary, allowlist on `msg.content` only, secrets via `SecretBroker.get()`, no `os.environ` for credentials); rule #7 (no silent failures in security paths — every `_send`-internal failure audits with a distinct `result` value before the recovery message).
- **Skills:** `alfred-trust-tiers` (T0-T3 system + allowlist patterns at the Discord boundary); `alfred-audit-write` (audit-before-send discipline + append-only patterns + signing); `superpowers:subagent-driven-development` (this plan's execution discipline); `superpowers:test-driven-development` (cluster ordering — test first, implementation second).
