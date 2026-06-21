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

## Slice 4: the Discord MCP adapter (PR-S4-9)

Slice 4 ships `plugins/alfred_discord/` as the first real comms-MCP adapter under
the ADR-0016 / ADR-0024 wire contract. The legacy `src/alfred/comms/discord.py`
stays dormant (an AST guard,
`tests/unit/comms/test_no_direct_adapter_imports.py`, forbids fresh imports) and
is deleted in PR-S4-10.

> **Wiring status (#235 primitive wiring).** PR-S4-9 shipped the adapter and these
> host primitives as TESTED but NOT-YET-WIRED: the five #235 primitives are wired
> onto the live daemon path one PR at a time. **The `SubPayloadPromoter` is now
> wired (PR-S4-235-1):** `_spawn_comms_adapter`
> (`src/alfred/cli/daemon/_commands.py`) builds a per-adapter promoter keyed on the
> wire `adapter_kind` — a configured promoter for a classifier-bearing kind
> (e.g. `discord`), `None` for an empty-set kind (the reference plugin / TUI
> plain-text path) — and injects it into the `InboundMessageHandler` so
> `process_inbound_message` promotes T3 sub-payloads BEFORE `quarantined_extract`.
> The promoters share a daemon-owned `ContentStore` (one Redis pool per process,
> reaped on every exit path). A classifier-bearing kind that would yield a `None`
> promoter REFUSES boot fail-closed (audited `comms_promoter_misconfigured`),
> mirroring the inbound M2 guard at boot. (That refusal is defence-in-depth: the
> factory is deterministic, so it cannot fire on a correct build — it guards against
> future `REQUIRED_CLASSIFIERS_BY_KIND` / factory drift.) STILL NOT-YET-WIRED (separate #235 PRs):
> the `BindingEmitter` (`plugins/alfred_discord/binding_emitter.py`, emitting
> `adapter.binding_request`), the [`OutboundQueue`](../glossary.md#outboundqueue)
> outbound-path wiring, and the comms-4 addressing-drift detector
> (`src/alfred/comms_mcp/addressing_drift.py`) +
> [`ThreadConversationLedger`](../glossary.md#threadconversationledger). Until those
> land, comms-4 + binding are NOT operationally enforced — the primitives exist and
> are unit/adversarially tested, but the daemon path does not invoke them. Tracking:
> **#235**. The present-tense prose below describes the fully-wired behaviour these
> primitives implement.

### Inbound: host-side T3 sub-payload promotion

The adapter is a thin marshaller — it ships the user's typed text plus the nine
Discord sub-payload kinds INLINE in the wire body and does NO T3 promotion
in-process. The host does the promotion: `process_inbound_message` runs the
[`SubPayloadPromoter`](../glossary.md#subpayloadpromoter) BEFORE
`quarantined_extract`, which scans the body via the
[`DiscordSubPayloadClassifier`](../glossary.md#discordsubpayloadclassifier),
writes each recognised sub-payload to the content store under a host-minted handle
id, and rewrites the body field to a `{"$content_handle_id": <id>}` reference. The
privileged orchestrator therefore never sees raw sub-payload bytes — only handle
references; the quarantined LLM dereferences them. The host-classified kind set
(not the plugin-asserted `sub_payload_refs`) populates the
`COMMS_INBOUND_T3_PROMOTION_FIELDS` audit row.

### Outbound: idempotency, DLP, and the OutboundQueue

Outbound replies are idempotency-keyed (host-minted `UUID`), DLP-scanned at the
wire boundary (`ScannedOutboundBody`), and flow through the
[`OutboundQueue`](../glossary.md#outboundqueue). On a Discord 429
(`adapter.rate_limit_signal`) the host pauses the queue for the platform's
`retry_after_seconds`; messages stay queued through the window and auto-resume. A
message that waited through a pause is re-scanned (comms-2) so a mid-pause DLP
hot-reload cannot leak a now-prohibited secret. Two threads in one conversation
bind to one `conversation_session_id` via the
[`ThreadConversationLedger`](../glossary.md#threadconversationledger) so a
follow-up resumes rather than forks.

### Sandbox posture and egress

The adapter manifest declares `[sandbox] kind = "full"` (sec-1): it ingests
adversary-controlled bytes and runs under bwrap fs/namespace containment mirroring
the quarantined LLM, plus a `/etc/ssl/certs` ro-bind for the Discord TLS chain.

Egress is NOT yet kernel-enforced: outbound is currently **UNRESTRICTED**
(release-blocker `#230`), mirroring `config/sandbox/README.md` and the EGRESS note
in `config/sandbox/discord-adapter.linux.bwrap.policy`. The policy does not yet
run `--unshare-net` because the sandbox schema cannot express a Discord-only
endpoint allowlist. The intended `#230` design — the mechanism this note will be
updated to describe once landed — is: a `network.outbound_allowlist` field on the
`kind = "full"` policy, enforced by running bwrap with `--unshare-net` plus a
slirp/pasta-style filtered forwarder pinned to the Discord endpoints, so the
kernel (not the manifest's advisory `[network] allowlist`) caps egress to
Discord-only. The manifest `[network] allowlist` documents the intended endpoints
today; `#230` makes the policy ENFORCE them at the kernel boundary. See
[ADR-0016](../adr/0016-slice4-discord-tui-comms-mcp-rewrite.md) and
[ADR-0015](../adr/0015-slice4-containerised-quarantined-llm.md).

### Daemon go-live flip + fail-closed dev-host behaviour (PR-S4-11c-2b)

The daemon's inbound quarantined extraction is **live in production**. When
`Settings.comms_enabled_adapters` is non-empty, `_build_comms_boot_graph`
(`src/alfred/cli/daemon/_commands.py`) builds the real
`QuarantineStdioTransport` over a **REAL bwrap-sandboxed quarantined child**
spawned via `spawn_quarantine_child_io` — the ADR-0027 fixture extractor is gone
(see the ADR-0027 PR-S4-11c-2b amendment). The boot-minted authorised T3 nonce
drives a real `T3BodyRecorder` that tags the inbound body `TaggedContent[T3]` and
stages it for the inline-over-wire content path (ADR-0029). The 2b child runs a
**deterministic-echo loop** — no real LLM, no network egress — so the open-egress
gap (`#230`, above) still contains nothing that can use it; the real LLM lands in
PR-S4-11c-2c.

**Fail-closed dev-host behaviour — operators read this before enabling a comms
adapter.** The quarantined child is `[sandbox] kind = "full"` (bwrap), so a daemon
with ANY comms adapter enabled **requires a Linux host with `bwrap` (bubblewrap)
installed and the launcher provisioned** (ADR-0030 bound interpreter). On a
non-Linux host (macOS), or a host where `bwrap` is unavailable or the bound
interpreter isn't provisioned, the boot-time child spawn raises
`QuarantineChildSpawnError` and the daemon **refuses to boot fail-closed** —
audited `quarantine_child_spawn_failed`, exit 2, with a
clear operator message pointing at the bwrap/provisioning requirement. There is
**no dev fixture fallback** (the fixture/echo-double path lives only in the test
tiers). To run the daemon without comms on such a host, leave
`ALFRED_COMMS_ENABLED_ADAPTERS` unset (the default) — a comms-disabled boot
constructs none of the quarantine graph and is unaffected.

The child's provider key is resolved from the secret broker by the fixed id
`quarantine_provider_api_key` (`config/routing.yaml [quarantine] secret_id`). When
unset it falls back to a documented placeholder with a loud `structlog` warning —
the 2b echo child reads, scrubs, and discards it without a provider call.
PR-S4-11c-2c flips the unset path to refuse-boot once the child makes a real
provider call.

### Spec B G6-3: the gateway adapter credential path (core-injects-at-spawn)

The always-up gateway hosts the comms adapter children (ADR-0036 inversion); the
core only observes. An adapter child needs its platform credential (e.g. the Discord
bot token) but the gateway holds **no vault key** — so the credential is
**core-injects-at-spawn over fd 3**, never the child's environment.

On each (re)spawn the gateway's `GatewayAdapterCredentialClient`
(`src/alfred/gateway/adapter_credential_client.py`) runs a request/response
round-trip over the trusted ADR-0031 core leg: it sends
`gateway.adapter.spawn_request` and awaits the matching `core.adapter.spawn_grant`
(the **first** core→gateway response frame on that leg — a new id-correlation
primitive on `GatewayCoreLink`). The core's `CoreAdapterCredentialResolver`
(`src/alfred/comms_mcp/adapter_credential_resolver.py`) is the **only** component
that decrypts a platform credential: it maps `adapter_id → secret_id` via a CLOSED
allowlist (`discord → discord_bot_token`; an unknown id is a typed refusal, never a
`broker.get(adapter_id)` passthrough), reads the broker, dedups on
`(adapter_id, host_restart_seq, epoch)` (a true replay decrypts **once**), and
returns the grant. The gateway verifies the grant echoes its outstanding request
`(request_id, adapter_id, host_restart_seq, epoch)` — a forged/stale grant is
refused (adversarial e) — then delivers the plaintext to the child's fd-3 write end
via the reused `supervisor/fd3_key_delivery.deliver_provider_key_via_fd3` (the lib
builds + zeroes its own buffer). The wire frames live in
`src/alfred/comms_mcp/adapter_credential_protocol.py`; the daemon wires the resolver
into the runner on the SOCKET (gateway) leg only.

Fail-closed everywhere: a link drop during the round-trip → `CredentialLegDownError`
→ the supervisor's **AWAITING_CORE** (a non-spin bounded-backoff re-probe with a
terminal ceiling that trips the breaker rather than parking dark forever); a grant
refusal / mismatch / fd-3 fault → a loud audited spawn-abort (no `up` frame). The
epoch is sourced **live** per spawn from `current_core_epoch()` so a core bounce
mints a fresh epoch. The credential is **structurally un-loggable** —
`SpawnGrant.credential_material` is `repr=False` with overridden `__repr__`/`__str__`
— and appears only on the fd-3 sink, never in an audit row, log line, frame repr, or
exception. See ADR-0036 "Credential contract realized (G6-3 annotation)". The
honest str-residency window (the credential is a `str`, not zeroable) and the
deferred `SecretBroker.get_bytes` hardening are recorded in that annotation.

### Rendering guidance for operator-facing audit rows (i18n-3)

When a comms audit row renders to an operator surface (CLI / TUI / dashboard),
datetimes (`received_at`, `recorded_at`) MUST render via
`babel.dates.format_datetime(dt, locale=operator.language)` and numeric fields
(`retry_after_seconds`) via `babel.numbers.format_decimal(n, locale=operator.language)`,
so an operator in `fr`/`ja` sees locale-correct dates and numbers rather than
machine ISO strings. The stored row stays machine-readable (ISO-8601 + raw
numbers); the locale formatting is a presentation-layer concern applied at render
time, not at write time.

This is a forward-dependency, not a narrative-only one. The same babel-formatting
contract is already enforced for the CLI surface by PR-S4-5's
`tests/unit/cli/test_whoami_command.py` (i18n-003 — `alfred whoami` asserts
`babel.dates.format_datetime(dt, locale=user.language)` parity for `en`/`ja`).
The comms audit-row rendering binds to the equivalent assertions on **PR-S4-10's
operator-facing TUI surface**: per the
[Slice-4 PR-S4-9 plan](../superpowers/plans/2026-06-07-slice-4-pr-s4-9-discord-mcp-adapter.md)
acceptance criterion #13 (i18n-3) and its §6 "Rendering guidance", PR-S4-10's TUI
formatting test(s) assert locale-correct rendering of `received_at` / `recorded_at`
(via `format_datetime`) and `retry_after_seconds` (via `format_decimal`). Those
TUI tests are the concrete check that closes this dependency.

## Crash de-dup + status snapshot (G6-2b-2b / #288)

Two adapter-crash signals coexist (Spec B §3): the gateway's process-level
`gateway.adapter.crashed` (authoritative for host-supervision/audit) and the
in-child `adapter.crashed` (a finer code-level diagnostic). A single physical
crash can produce **both**, which historically wrote two audit rows for one
crash. G6-2b-2b correlates them into **one incident per physical crash** —
**without dropping either loud signal** (hard rule #7).

- **The join.** A core-side `CrashIncidentReconciler`
  (`src/alfred/comms_mcp/crash_incident_reconciler.py`) is built **once** by the
  daemon's `_CommsBootGraph` and shared by **both** the gateway-fed
  `AdapterStatusObserver` (gateway arm) and every per-adapter `AdapterCrashHandler`
  (in-child arm) — they already meet in the same `AlfredPluginSession`, so no new
  cross-process plumbing is needed. Both arms still write their own audit row; the
  reconciler stamps each row with a stable `crash_incident_id` + a
  `crash_signal_source` (`gateway` / `child` / `both`), so a downstream reader
  counts one incident by distinct `crash_incident_id`.
- **Correlation key.** `adapter_id` + the gateway's `host_restart_seq` (the
  supervisor's per-adapter `restart_count` = which **incarnation** exited). The
  gateway frame carries the seq and is authoritative; the in-child frame carries
  no seq (the child cannot know the gateway counter) and is tagged to the
  adapter's **current incarnation**. The gateway `up` frame **advances** the
  current incarnation (it carries the incarnation being started), so the common
  order — the in-child crash fires as the child dies, *before* the gateway
  observes the exit — still folds onto the right incarnation rather than splitting
  one crash into two incidents.
- **Trust boundary.** Folding **never** elides an audit row. A duplicate/replayed
  crash for an already-seen incarnation is flagged `duplicate=true` and **still
  audited**, so a replay is visible, not silently dropped. A forged in-child crash
  opens a `child`-only incident (still loud) and cannot mask a later genuine
  gateway crash, which opens its own incident at its own seq.
- **`crash_signal_source == "both"` is NOT authenticated corroboration.** The
  in-child `CrashedNotification` has no epoch / anti-forgery binding (only the
  gateway frame is carrier-authenticated via the live leg's `0600` +
  `SO_PEERCRED` + per-boot-epoch envelope), so a forged in-child crash can upgrade
  a real gateway incident to `both`. Treat `both` as a diagnostic-coverage hint,
  not a security attestation.

### The daemon control plane — the live query seam (G6-2b-2c / ADR-0038)

The observer + reconciler live **inside the daemon process** (`_CommsBootGraph`), so the
CLI cannot read them directly. G6-2b-2c closes that gap with a **daemon control plane**: a
dedicated `0600` request/response unix socket at `~/.run/alfred/control.sock`
([ADR-0038](../adr/0038-daemon-control-socket.md)), separate from the comms wire
([ADR-0031](../adr/0031-comms-socket-transport-for-the-foreground-tui.md)).

`alfred daemon status` dials the control socket and sends one `status.query` request; the
daemon answers **live** from the observer (`all_latest()`) + reconciler
(`adapter_ids()` / `current_incarnation()` / `incidents()`), folded by
`build_daemon_status_result` into a `DaemonStatusResult`. The response is computed at query
time — there is **no snapshot, no staleness window, no `boot_id`**: the daemon answering the
`0600` + `SO_PEERCRED` socket is, by construction, the live daemon. The withdrawn
file-snapshot approach (PR #299) is retired.

Key properties (see ADR-0038 for the full reasoning):

- **Same security as the comms wire, shared not forked.** Peer-uid auth, owner-only bind,
  and call-time runtime-dir resolution live in `alfred.plugins._local_socket` and are reused
  by both sockets. A refused different-uid dial writes a loud `daemon.control.peer_uid_rejected`
  audit row (the control plane is daemon-global, so the row carries no `adapter_id`); a
  read-only `status.query` writes no audit row.
- **No secret/T3 on the wire.** The result carries only non-sensitive operational metadata
  (adapter_id, state, occurred_at, incarnation, incident count + the latest incident's
  seq/source/id). The field set is `extra="forbid"` and structurally locked.
- **SEC-02 unchanged.** `crash_signal_source == "both"` is rendered as informational origin
  only — a diagnostic-coverage hint, **not** authenticated corroboration.
- **The G6-5 substrate.** The method router takes `gateway.adapters` next; `alfred gateway
  adapters --wait-ready` is a live-ness consumer that reuses this exact channel (a client-side
  poll over repeated `status.query` keeps the server stateless — ADR-0038).

### Spec B G6-4: the per-adapter ingress gate, fair leg scheduler, and per-leg replay (global cap)

G6-4 makes the single gateway↔core link safe for **N hosted adapter legs plus the
foreground TUI leg** ([ADR-0036](../adr/0036-gateway-adapter-hosting-inversion.md)). Three
collaborators sit in the gateway process (never the core), all keyed only on the
gateway-known `adapter_id` — the gateway stays **payload-blind** for T3 bodies:

- **`PerAdapterIngressGate`** (`src/alfred/gateway/ingress_gate.py`) — a payload-blind,
  per-leg admission control: a two-tier token bucket (sustained rate, capped at a burst) plus
  an in-flight concurrency cap, plus a `max_frame_bytes` size tier. A trip back-pressures the
  leg (no silent drop), increments `gateway_ingress_throttled_total{adapter}`, and writes a
  closed-vocab ingress-refusal audit row. A held in-flight slot older than the TTL is reclaimed
  by an active per-gate sweeper so a stalled leg cannot wedge.
- **`GatewayLegScheduler`** (`src/alfred/gateway/leg_scheduler.py`) — fair round-robin egress
  of the registered legs over the single `core_link` writer, with a bounded per-leg send queue
  (in bytes). A chatty or large-payload leg cannot starve another adapter or the live TUI; the
  TUI leg gets a reserved minimum credit so interactive latency has a floor in N.
- **`GlobalReplayCap`** (`src/alfred/gateway/global_replay_cap.py`) — bounds the **sum** of all
  legs' `ReplayBuffer` resident bytes, so total pre-DLP T1 in the always-up SETUID process is
  bounded regardless of N. A reserve that would exceed the cap is refused (back-pressure, not a
  drop); every byte-reclaim path (`trim_to_ack`, `evict_expired`, `discard`,
  `reset_for_new_epoch`, hard-ceiling rollback) releases the cap.

A forged or unknown out-of-band `adapter_id` is **refused** by `leg_router.py` (loud
`unknown_adapter` audit row); it is never default-routed and never used as a metric label
value (a single `<unknown>` sentinel series absorbs the count, so a flood of distinct forged
ids cannot blow up metric cardinality).

#### Per-adapter metrics (`src/alfred/gateway/adapter_metrics.py`, `ingress_audit.py`)

Every series below carries **exactly** the label set `{adapter}` and is materialised at leg
construction (so a scrape sees the leg at 0 before its first event). They complement — and do
not replace — the unlabelled single-buffer Spec-A gauges (`gateway_core_link_up`,
`gateway_buffer_depth_{frames,bytes}`) from the one-leg era.

| Series | Type | Meaning |
| --- | --- | --- |
| `gateway_adapter_up{adapter}` | gauge | `1` while the leg is live, `0` while down. |
| `gateway_adapter_inflight{adapter}` | gauge | In-flight (admitted, not-yet-released) units for the leg. |
| `gateway_adapter_buffer_depth_frames{adapter}` | gauge | The leg's `ReplayBuffer` depth in frames. |
| `gateway_adapter_buffer_depth_bytes{adapter}` | gauge | The leg's `ReplayBuffer` depth in bytes. |
| `gateway_ingress_throttled_total{adapter}` | counter | Per-adapter ingress refusals (rate / in-flight / oversized / global-cap / unknown-adapter). |

The audit-row field set is allowlisted to `adapter_id`, the closed-vocab `reason`, and scalar
counters (`depth_frames`, `depth_bytes`, `inflight`, `cap_ratio`) — **never** a body,
body-hash, body-sample, or platform-id (hard rule #5). The closed-vocab reason set lives in
one place (`IngressRefusalReason`): `oversized`, `throttled_rate`, `throttled_inflight`,
`global_cap_refused`, `unknown_adapter`.

#### Sensible defaults

These bound a **real** hosted adapter leg (G6-5). In G6-4 the only live leg is the TUI dial-in,
whose gate is deliberately **non-binding** (the interactive path is never throttled) — the
values below are the recommended starting point an operator tunes per adapter once real legs
land.

| Setting | Default | Notes |
| --- | --- | --- |
| Ingress sustained rate | 5 / s per adapter | The token-bucket refill rate; the core's `_PreResolutionLimiter` (50 / min per platform-id, `_PRE_RESOLUTION_LIMIT_PER_MINUTE`) remains as additive per-id defence-in-depth. |
| Ingress burst | 20 | Token-bucket ceiling (a short spike is absorbed, then the sustained rate binds). |
| In-flight cap | 8 | Max concurrently-admitted units before back-pressure. |
| In-flight TTL | 30 s | A slot held longer is reclaimed by the sweeper (the wedge bound). |
| Ingress sweep interval | 30 s | How often the active per-gate sweep reclaims stalled slots. |
| `max_frame_bytes` | 1 MiB | Oversized frames are refused at admission (size is not content — payload-blind preserved). |
| Per-leg send-queue bytes | 1 MiB | Bounds pre-append working memory the `GlobalReplayCap` does not see. |
| Per-leg `ReplayBuffer` | soft cap 4096 frames / 8 MiB / 300 s TTL | The unchanged Spec-A buffer SOFT caps (one instance per leg); a breach trips the breaker but keeps the frame (no silent drop). The HARD ceiling is `_HARD_CAP_MULTIPLIER` (2×) the soft cap — 8192 frames / 16 MiB — a fail-closed OOM backstop that raises. |
| Global replay cap | ≥ the per-leg buffer hard ceiling × N | The aggregate-across-legs bound; set strictly above one leg's hard ceiling (16 MiB) so the per-leg buffer's own hard-cap fires first. Precedence: per-leg before global. |
