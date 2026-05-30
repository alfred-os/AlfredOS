# Comms subsystem

The comms subsystem owns "how does AlfredOS talk to humans?" Slice 2
ships two adapters (TUI carried over from Slice 1, Discord newly added)
behind one in-process `CommsAdapter` Protocol. The Protocol is a
deliberate, bounded deviation from PRD §5 (which requires plugins to
speak MCP); the deviation and the Slice-3 rewrite plan are documented in
[ADR-0009](../adr/0009-comms-adapter-protocol-slice2-only.md).

Sibling subsystem docs: [identity](identity.md), [hooks](hooks.md).

## Overview

Every comms adapter satisfies the same lifecycle contract: `start()`,
`run()`, `stop()`, `health()`. The orchestrator's supervisor drives each
adapter through that surface. Two concrete implementations live in
`src/alfred/comms/`:

- `TuiAdapter` (`src/alfred/comms/tui_adapter.py`) — wraps the Textual
  TUI app from Slice 1.
- `DiscordAdapter` (`src/alfred/comms/discord.py`) — DM-only Discord
  gateway client.

External callers consume the Protocol type. No call site outside
`src/alfred/comms/` may import the concrete adapter classes directly —
the AST-scan test `tests/unit/comms/test_no_direct_adapter_imports.py`
enforces this. The boundary is what makes Slice 3's MCP-transport
rewrite a single-module refactor rather than a cross-cutting one.

## Key types

### `CommsAdapter` Protocol (`src/alfred/comms/adapter.py`)

Runtime-checkable Protocol with four members:

- `name: str` — stable adapter identity (`"tui"`, `"discord"`). Must
  match the `Platform` enum value for adapters that bind to a
  platform-native id, so identity resolution and adapter routing share
  one vocabulary.
- `async start() -> None` — bring the adapter to a ready-to-serve state.
  Idempotent: a re-`start()` after a clean `stop()` returns the adapter
  to a runnable state. Raises on hard-failure configuration errors
  (e.g. operator row missing).
- `async run() -> None` — run the adapter's main loop until `stop()` is
  called. For the TUI this delegates to `AlfredTuiApp.run_async()`; for
  Discord this awaits the gateway connection forever.
- `async stop() -> None` — request a clean shutdown. Idempotent.
- `def health() -> AdapterHealth` — synchronous health snapshot for
  `alfred status`. Synchronous because the status table is not async;
  the snapshot is immutable so callers never see torn reads.

Two allowlisted factory functions live in the same module:
`build_tui_adapter` and `build_discord_adapter`. The CLI bootstrap calls
these factories rather than the concrete classes; the local imports
defer the heavy adapter dependencies (`textual`, `discord.py`) so
imports like `alfred status` stay light.

A third allowlisted seam, `run_discord_verify_probe`, lets
`alfred discord verify` run the 30-second readiness probe without
importing `alfred.comms.discord` directly — the import-isolation test
locks the allowlist to a small set of modules, and this seam keeps the
CLI on the right side of it.

### `TuiAdapter`

`src/alfred/comms/tui_adapter.py`. Wraps the Textual app from Slice 1.
The adapter feeds orchestrator turns into the renderable widget, runs
operator input through `t()` for localisation, and drives outbound
chunks through `OutboundDlp.scan` before rendering.

### `DiscordAdapter`

`src/alfred/comms/discord.py`. DM-only. Constructor takes the
orchestrator, identity resolver, broker, outbound DLP, rate limiter,
working memory pool, and audit writer; the long-running run loop awaits
the Discord gateway connection until `stop()` is called.

Two ingress invariants make the Slice-2 trust-tier exposure bounded:

- **Allowlist trust-tagging.** Only `msg.content` is read from a
  Discord `Message`. Every other content-bearing field (`embeds`,
  `attachments`, `stickers`, `reference`, `poll`, `components`,
  `activity`, `application`) is asserted empty/None at the boundary.
  Any non-empty field triggers an audit row + a polite
  `discord.embed_unsupported` reply with zero orchestrator invocation.
  Slice 3 introduces T3 tagging and the dual-LLM split; until then,
  refusal is the only safe response (see
  [ADR-0013](../adr/0013-defer-t1-t3-and-dual-llm.md)).
- **Unknown-snowflake refusal + audit-DoS guard.** A DM from a Discord
  snowflake that is not bound to any user receives a polite refusal
  echoing the snowflake and a bind hint. A per-snowflake LRU
  (`TTLCache(maxsize=1024, ttl=3600s)`) deduplicates repeat refusals,
  and a global token-bucket cap (default 60/min) on
  `discord.unknown_user_dm` audit writes prevents a snowflake-iterating
  spam bot from flooding the append-only audit log.

### `OutboundDlp` (`src/alfred/security/dlp.py`)

The chokepoint every outbound message string passes through. Three
pipeline stages:

1. **Broker redaction.** `SecretBroker.redact` replaces any value
   AlfredOS knows it owns (env-backed and file-backed secrets both).
   Patterns are processed in descending-length order so a longer secret
   whose suffix happens to be another live secret is fully redacted
   before the shorter one runs.
2. **Generic API-key regex.** Catches values shaped like a third-party
   API key (`\b(?:sk|pk|tok|key)[-_][A-Za-z0-9]{20,}\b`). Defends against
   the case where a secret leaked into a log line from a code path that
   never registered the value with the broker (a third-party SDK that
   exposed the key via its own exception `__repr__`, for instance).
3. **Canary stub.** Slice 2 is a literal no-op (`return text`). Slice 3
   expands this with the canary system; the stub is a regression guard
   against accidentally dropping the stage.

**Audit-on-modification.** When `scan()` modifies the text, exactly one
`dlp.outbound_redacted` audit row is written. The audit sink is
dependency-injected as a synchronous callable so DLP can run inside
structlog's synchronous processor chain. Failure to write the audit row
propagates per CLAUDE.md hard rule #7.

**Silent redaction is a documented Slice-2 known oracle.** Length-delta
between input and output is observable to the recipient, which is a
known oracle attack vector (the attacker probes which strings get
redacted by watching reply lengths). Slice 3 mitigates by padding to a
length-bucket boundary; Slice 2 accepts the risk because the alternative
(refusing to emit modified text at all) blocks legitimate provider
output.

DLP cannot be disabled per-call. The only legitimate bypass is a
pure-internal tool that declares "no DLP needed" in its manifest, and
the adversarial suite verifies that claim.

### `RateLimiter` Protocol (`src/alfred/identity/rate_limit.py`)

The per-user rate-limiting seam, declared in the identity module because
the limiter consults `User.authorization`. The Protocol surface:

- `async allow(user: User) -> bool` — return True iff the user may
  proceed. Implementations MUST return `False` unconditionally for
  `Authorization.READ_ONLY`. The full `User` is passed (not just a slug)
  so the limiter can read `user.authorization` without a resolver
  round-trip.
- `async reset(user_id: str) -> None` — clear accumulated state for the
  given slug.
- `def health() -> RateLimiterHealth` — point-in-time snapshot for
  `alfred status`.

Two implementations ship:

- `NullRateLimiter` — no-op, always allows. Production-acceptable for
  single-operator deployments where every authenticated caller is the
  operator. Used by the CLI bootstrap in slice-1-equivalent paths.
- `InProcessTokenBucketRateLimiter` — Slice-2 production limiter.
  Per-user token bucket keyed on `user.slug`, refilled at the
  authorization-tier default rate (`read_only` = 0/min, `standard` =
  30/min, `trusted` = 60/min, `operator` = unlimited) unless overridden
  per-user via `users.rate_limit_per_min` / `rate_limit_per_day`. The
  authorization-tier defaults are immutable
  (`MappingProxyType[Authorization, int | None]`).

`read_only` users have **reply-suppressed** rate-limiting: the limiter
refuses, the adapter audits the refusal, but no reply is sent to the
user. This is intentional — the read-only tier exists to let an
operator add a row without granting interactive access. See
[glossary: authorization role](../glossary.md#authorization-role).

### Markdown-aware splitter (`src/alfred/comms/markdown_split.py`)

Discord's 2000-character message cap forces long replies to split. A
naïve byte-count split breaks code blocks (the trailing half lands in a
follow-up message without its opening fence). The splitter is
code-block-aware: it finds the nearest safe boundary outside any fenced
code block, so multi-line code blocks render correctly across split
boundaries. Reusable for Slice-4 Telegram (4096-char cap).

## Primary flows

### Discord ingress: DM → audit row

1. `discord.py` delivers a `Message` to `_on_message`.
2. Allowlist check: every non-`content` field must be empty/None. Any
   non-empty field → audit row + `discord.embed_unsupported` reply,
   stop.
3. Resolve the author's snowflake via `IdentityResolver.resolve(Platform.DISCORD, str(msg.author.id))`.
4. If unknown: dedup-LRU + global-cap check on
   `discord.unknown_user_dm`, polite refusal with snowflake echo +
   bind hint.
5. If known: rate-limit check via `RateLimiter.allow(user)`. Refusal
   audits `discord.rate_limited` (no reply for `read_only`).
6. Budget pre-flight via `BudgetGuard.would_exceed(user.slug, estimate)`.
7. Orchestrator turn: `Orchestrator.handle(text, user=user, language=user.language)`.
8. Outbound: every chunk goes through `_send` → `OutboundDlp.scan` →
   `_split_for_discord` → `channel.send`. A single `_send` chokepoint
   funnels every outbound chunk; a grep-asserting unit test pins this
   invariant.

### `alfred discord verify` (operator readiness probe)

`src/alfred/cli/discord_cmd.py`. The verify subcommand:

1. Loads settings + broker (`_bootstrap.load_settings_or_die`,
   `build_broker`).
2. Constructs an `OutboundDlp` with a no-op audit sink (the probe does
   not need durable audit on its own activity).
3. Calls `run_discord_verify_probe(broker, outbound_dlp, timeout_s)`
   — the allowlisted seam in `alfred.comms.adapter`.
4. Maps the returned plain-int code onto `_VerifyExitCode` and emits
   the structlog event with the returned key + kwargs.

Exit-code table:

| Code | Enum | Meaning |
|---|---|---|
| 0 | `OK` | `on_ready` fired within `timeout_s` |
| 1 | `UPSTREAM_UNRECOVERABLE` | Gateway 5xx / repeated reconnect |
| 2 | `CONFIG_FAILED` | Bad token, intents off, missing perms, secrets file unreadable, operator row missing |
| 3 | `LOGIN_FAILED` | Token rejected at handshake (`discord.LoginFailure`) |
| 4 | `TIMEOUT` | `timeout_s` elapsed without `on_ready` (default 30s) |
| 130 | `INTERRUPTED` | SIGINT |

Each branch is pinned by a dedicated unit test in
`tests/unit/comms/test_discord.py` (cluster 14). The
[deployment runbook](../runbooks/slice-2-discord-smoke.md) maps each
code to remediation.

### Outbound DLP scan

```text
text ─► broker.redact ──► generic-API-key regex ──► canary stub (no-op) ──► text'
                              │
                              ▼
                       audit dlp.outbound_redacted
                       (one row per modification)
```

`stages_triggered` is a tuple of `{"broker", "api_key_shape"}`. Stage 3
never appears in Slice 2 (it is a no-op until Slice 3 wires the canary
system).

## Error model

| Source | Exception / event | Adapter behaviour |
|---|---|---|
| `discord.LoginFailure` | typed `LoginFailure` | `verify` exits `3`; long-running adapter exits `2` after log + audit |
| `discord.ConnectionClosed` | typed | Auto-reconnect via `discord.py`'s built-in supervisor; exponential backoff |
| `discord.HTTPException` 5xx | typed | Audit `discord.upstream_5xx` + single retry. Repeated → propagate, supervisor exits `1` |
| Repeated-reconnect failure | none — supervisor exhausts retries | `verify` exits `1`; long-running adapter exits `1` |
| `OutboundDlp.scan` raises | propagates | `_send` returns `dlp_failed` sentinel; outbound message never leaves the process; audit `discord.alfred_error` |
| Markdown splitter raises | propagates | `_send` returns `split_failed`; same audit |
| `channel.send` raises | propagates | `_send` returns `send_failed`; same audit |
| Allowlist non-`content` field present | n/a | Audit `discord.embed_unsupported` + polite refusal; orchestrator never invoked |
| Unknown snowflake | n/a | Dedup-LRU check + global-cap check; polite refusal echoing snowflake + bind hint |
| `Authorization.READ_ONLY` rate-check | `allow` returns False | Audit `discord.rate_limited`; **no reply** (reply-suppressed) |

The three distinct `_send` result sentinels (`dlp_failed`,
`split_failed`, `send_failed`) let the supervisor + observability layer
distinguish "outbound DLP refused the payload" from "splitting the
payload failed" from "Discord rejected the network call." Each maps to
a different remediation; collapsing them to a single `failed` would
make the audit log less actionable.

## ADR cross-references

- [ADR-0009](../adr/0009-comms-adapter-protocol-slice2-only.md) —
  `CommsAdapter` is an in-process Python Protocol for Slice 2 only;
  Slice 3 inverts the polarity to MCP transport.
- [ADR-0010](../adr/0010-canonical-user-id-and-listen-notify.md) —
  cross-process identity invalidation, consumed by the Discord adapter
  on every DM.
- [ADR-0013](../adr/0013-defer-t1-t3-and-dual-llm.md) — T3 deferred to
  Slice 3; the Discord allowlist is what bounds Slice-2 trust-tier
  exposure to T2 only.

## Open questions / forward-compat notes

- **Slice 3 MCP-transport rewrite.** The Protocol body in
  `adapter.py` will be rewritten. The polarity inverts: the adapter
  becomes the RPC server, the orchestrator becomes the client. Code
  that needs to outlive the rewrite should depend on the
  orchestrator-facing message contract, not on the adapter Protocol
  shape. Slice-3 reviewer gate re-checks PRD §5 compliance and
  transitions this ADR to "Superseded by".
- **Length-delta oracle mitigation.** Slice 3 pads outbound modified
  text to a length-bucket boundary so the recipient cannot probe which
  strings get redacted by watching reply lengths.
- **Voice / Telegram in Slice 4+.** The `CommsAdapter` Protocol
  surface is intentionally minimal so a voice adapter (microphone +
  TTS) and a Telegram adapter can land without altering the
  orchestrator's contract.
