# PR-S4-9 — Discord MCP adapter implementation plan
>
> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. This is trust-boundary work (comms-MCP adapter relays adversary-authorable T3 content) — TDD is HARD here, not advisory.

**Goal:** Ship `plugins/alfred_discord/` as the first real comms-MCP adapter under the Slice-4 ADR-0016 / ADR-0024 wire contract; ship `DiscordSubPayloadClassifier` host-side under `src/alfred/comms_mcp/classifiers/discord.py` for the nine Discord sub-payload kinds enumerated in spec §8.6; introduce the `OutboundQueue.pause()` retry-after surface; introduce idempotency-keyed outbound with `OutboundMessageResult` discriminated union; introduce the persona-addressing four-mode mapping (`dm`/`mention`/`channel`/`thread` → PRD §6.8 concepts). The legacy `src/alfred/comms/discord.py` stays dormant — AST guard forbids fresh imports — and PR-S4-10 deletes it.

**Architecture:** `plugins/alfred_discord/` is a standalone MCP server subprocess spawned by `bin/alfred-plugin-launcher.sh` (Slice-3-shipped + PR-S4-6-extended); it implements four host→plugin requests (`lifecycle.start`, `lifecycle.stop`, `adapter.health`, `outbound.message`) and emits four plugin→host notifications (`inbound.message`, `adapter.binding_request`, `adapter.rate_limit_signal`, `adapter.crashed`). The plugin connects to Discord via `discord.py>=2.4,<3` (already in `pyproject.toml`), receives platform events, normalises them onto the ADR-0024 wire schemas defined in PR-S4-8's `src/alfred/comms_mcp/protocol.py`, and emits `inbound.message` notifications. The host-side `AlfredPluginSession._on_post_handshake_method` (verified at `src/alfred/plugins/session.py:347` per the slice-index's verification gate) dispatches notifications through PR-S4-8's `InboundHandler` / `BindingHandler` / `RateLimitHandler` / `CrashHandler`. The host-side `InboundContentScanner` (spec §8.5 — Slice-3-shipped baseline tags raw stdio frames; PR-S4-8 extends to data-driven classifier dispatch) runs PR-S4-9's new `DiscordSubPayloadClassifier` to emit `ContentHandle` instances for each Discord sub-payload kind. The orchestrator's view of inbound is: `body.text: str` at T2 carrier (the user's typed message body — note spec §8.2 says inbound body trust tier is T3 by default at `process_inbound_message`; the user's typed text passes through `quarantined_extract` and emerges as `T3DerivedData`; PR-S4-9 does not relax that) plus a sequence of T3 `ContentHandle` references for the sub-payloads. Outbound: the host generates a `UUID` `idempotency_key` per `outbound.message` request, runs `OutboundDlp.scan` against body + attachment metadata at the wire boundary (Slice-3 placement discipline per spec §2.1 row 2), serialises through `StdioTransport`, and consumes the `OutboundMessageResult` discriminated union (delivered / retryable_failure / terminal_failure). On `adapter.rate_limit_signal`, the host's `OutboundQueue.pause(adapter_id, retry_after_seconds)` (new in PR-S4-9 — verified absent in Slice-3 grep; honest new scope) suspends emit until the retry-after window elapses.

**Tech stack:** Python 3.12+ • `discord.py>=2.4,<3` (already in `pyproject.toml` — does NOT need adding) • Pydantic v2 frozen models • `mcp` / `model_context_protocol` SDK (Slice-3-shipped session shape) • `alfred.comms_mcp.protocol` (PR-S4-8) • `alfred.comms_mcp.inbound.process_inbound_message` (PR-S4-8) • `alfred.comms_mcp.classifier_registry.REQUIRED_CLASSIFIERS_BY_KIND` (PR-S4-8) • `alfred.security.quarantine.ContentHandle` (Slice-3 at `src/alfred/security/quarantine.py:168`) • `alfred.security.secrets.SecretBroker.get(name)` (Slice-3 at `src/alfred/security/secrets.py:396` — used for the `audit.hash_pepper` lookup; the pepper itself is bootstrapped in PR-S4-0b) • `alfred.hooks.registry.register_hookpoint` (Slice-2.5 surface at `src/alfred/hooks/registry.py:539`; PR-S4-3 extends with `carrier_tier=` kwarg — PR-S4-9 invokes with the new kwarg shape) • `alfred.audit.audit_row_schemas.COMMS_BINDING_REQUESTED_FIELDS` / `COMMS_RATE_LIMIT_SIGNAL_FIELDS` / `COMMS_ADAPTER_CRASHED_FIELDS` / `COMMS_INBOUND_T3_PROMOTION_FIELDS` / `COMMS_ADDRESSING_DRIFT_FIELDS` (constants shipped in PR-S4-0a; PR-S4-9 calls `append_schema(...)` host-side only — adapters never write audit) • pytest + testcontainers + recorded fixtures + `discord.py` test doubles • `structlog` • `t()` for every operator-facing string.

**Depends on:**

- **PR-S4-0a** (merged) — `audit_row_schemas.py` Slice-4 constants (`COMMS_*`); `payload_schema.py` Literal additions for the `cib` (`comms_identity_boundary`) prefix; `docs/glossary.md` Slice-4 entries (`DiscordSubPayloadClassifier`, `BODY_FIELD_BY_KIND`, `OutboundQueue`, `InboundT3Promotion`).
- **PR-S4-0b** (merged) — Alembic migrations 0011–0014 (the `audit_columns_slice_4` migration adds `sub_payload_kinds`, `addressing_signal`, etc. columns); `audit.hash_pepper` secret bootstrapped in broker (referenced via `SecretBroker.get("audit.hash_pepper")` per spec §8.10).
- **PR-S4-3** (merged) — `HookpointMeta.carrier_tier: TrustTier` + `HookpointMeta.allow_error_substitution: bool` required-field extension; PR-S4-9's `register_hookpoint(comms.adapter.binding_requested, carrier_tier=T3, ...)` and `register_hookpoint(comms.adapter.rate_limit_signal, carrier_tier=T0, ...)` calls MUST pass `carrier_tier=` (AST guard enforces).
- **PR-S4-5** (merged) — `_resolve_operator` helper (NOT consumed at runtime by PR-S4-9 since adapter callbacks are not operator-attributed CLI commands, but the host-side `IdentityResolver` consumed in `process_inbound_message` is wired by PR-S4-8 from the user/identity store; PR-S4-5 closure on this dependency is the broader identity-binding flow).
- **PR-S4-6** (merged) — `bin/alfred-plugin-launcher.sh` policy-resolving extension. PR-S4-9 declares `sandbox.kind: none` per spec §7.9 (first-party in-tree relay adapter; not a T3 consumer); the launcher's `sandbox.kind: none` codepath must accept this manifest shape without bypassing the production-refuse-without-policy check.
- **PR-S4-8** (merged) — `src/alfred/comms_mcp/protocol.py` (wire-format owner with all eight method-schema Pydantic models + `BODY_FIELD_BY_KIND` + `adapter_kind` Literal `Final[frozenset[str]]`); `src/alfred/comms_mcp/inbound.py:process_inbound_message`; `src/alfred/comms_mcp/classifier_registry.py:REQUIRED_CLASSIFIERS_BY_KIND` + the `@register_classifier(kind=…, name=…)` decorator + the AST guard at `tests/unit/comms_mcp/test_required_classifiers_complete.py`; `AlfredPluginSession._on_post_handshake_method` extension for notification dispatch + the per-adapter `asyncio.BoundedSemaphore(value=Settings.comms_max_in_flight_notifications)`; `BurstLimiter` at `src/alfred/orchestrator/burst_limiter.py`; `Supervisor.request_plugin_restart` + extended `Supervisor.trip_breaker` with `reason="comms_handler_repeated_failures"`.

**Blocks:**

- **PR-S4-10** (TUI flag-day + `src/alfred/comms/` deletion). PR-S4-10 cannot merge until the Discord plugin is the only Discord surface the daemon spawns; the legacy `src/alfred/comms/discord.py` is dormant through PR-S4-9 (AST guard forbids fresh imports) and deleted in PR-S4-10.
- **PR-S4-11** (graduation). The `test_discord_addressing_modes` + `test_discord_subpayload_promotion` required-status checks shipped here must be green on graduation.

**PR #205 round-2 review closures** (load-bearing corrections — apply at implementation time):

1. **i18n-1 CRITICAL (BCP-47 language field on Discord audit rows)**: every Discord inbound row (`COMMS_INBOUND_RECEIVED_FIELDS`, `COMMS_INBOUND_T3_PROMOTION_FIELDS`, `COMMS_BINDING_REQUESTED_FIELDS`) gains a `language: str` field carrying BCP-47 tags resolved via this precedence: (a) `discord.Message.guild.preferred_locale` for guild messages; (b) `discord.Message.author.locale` for DMs (if available); (c) the canonical `User.language` from the resolver; (d) fallback `"en"`. Stored on the inbound row at ingest time. `inbound_emitter.normalise(message)` populates the field; PR-S4-0a's `COMMS_*_FIELDS` constants gain the `language` entry (a coordinated delta — PR-S4-9's task list includes the PR-S4-0a constant extension as a precondition). Test `tests/unit/discord/test_language_field_populated.py` parametrizes guild_with_locale / dm_with_locale / dm_no_locale / fallback cases.

2. **sec-1 HIGH (sandbox.kind=full not none)**: Discord adapter manifest sets `sandbox.kind = "full"` (NOT `none`). The Discord WSS connection is established by the plugin INSIDE the bwrap sandbox with `policy_ref = "discord-adapter.toml"` (the policy ships in PR-S4-7's bundle, allowing only HTTPS to `gateway.discord.gg` and `discord.com/api`). The `kind: none` first-party-relay carve-out is dropped — the cost of bwrap is acceptable given the surface (Discord ingests adversary-controlled bytes from arbitrary users). The policy denies all filesystem reads except `/etc/ssl/certs`, all process-exec, all bindings except the broker socket for token fetch.

3. **sec-2 HIGH (in-plugin DLP-lite on outbound exception strings)**: `_OutboundTerminal.detail_redacted = _scrub_in_plugin(str(exc)[:256])` where `_scrub_in_plugin` runs a minimal Slice-4 DLP-lite scanner inside the plugin (regex-only; no broker fetch — uses bundled patterns shipped in the plugin manifest at install time). Host re-scans on receive for defense-in-depth. The plugin NEVER sends raw `str(exc)` over stdio. Test `tests/unit/discord/test_in_plugin_dlp_lite.py` plants a `sk-` API key in a synthetic exception and asserts neither the plugin's stdio frame nor the host's audit row contains it.

4. **sec-3 HIGH (wire-level T3 tag on body.content)**: the inbound wire frame carries `body.content_trust_tier: Literal["T3"]` as a REQUIRED field on every comms inbound. The host's `inbound_handler` REFUSES any frame whose `body.content_trust_tier != "T3"` with `INBOUND_REFUSED_FIELDS(reason="trust_tier_missing_or_wrong")`. The orchestrator's `_resolve_body_for_orchestration` REFUSES to consume body without first calling `quarantined_extract(body.content, expected_tier=T3)`. A new AST guard `tests/unit/comms/test_body_consumed_via_quarantined_extract.py` walks `_resolve_body_for_orchestration` callers in the repo and refuses any that touch `body.content` without going through `quarantined_extract`.

5. **comms-1 HIGH (channel_id_hash + guild_id_hash helpers)**: `src/alfred/comms/audit_hash.py` ships THREE helpers, all keyed on the HKDF-derived comms subkey (PR-S4-0b round-2 closure 3 ships the master pepper + HKDF; this PR derives `_COMMS_HASH_SUBKEY = hkdf_expand(pepper, info=b"comms.audit_hash.v1", length=32)`): `hash_platform_user_id(id_str) -> str`, `hash_channel_id(id_str) -> str`, `hash_guild_id(id_str) -> str`. All three use the SAME subkey but with PER-FIELD info-string suffixes (`...v1.platform_user`, `...v1.channel`, `...v1.guild`) so cross-field rainbow tables don't compose. New unit test asserts the three helpers produce different outputs for the same input.

6. **comms-2 HIGH (outbound DLP retry-path adversarial corpus)**: NEW Task F3: `OutboundQueue.pause()` and `resume()` MUST re-run `OutboundDlp.scan` on every queued message BEFORE re-emission (the queue stores `OutboundMessageRequest` instances with `ScannedOutboundBody` per PR-S4-8 closure 1; resume re-scans defensively to catch policy hot-reload changes). Corpus entry `cib-2026-004-outbound_queue_resume_dlp_bypass` plants a queued message with a planted secret, triggers pause→hot-reload-with-more-strict-policy→resume, asserts the message is refused with `OUTBOUND_REFUSED_FIELDS(reason="dlp_post_resume_block")` instead of being emitted.

7. **i18n-2 HIGH (t() on every operator/user-facing string)**: every operator-facing AND user-facing string routes through `t()`:
   - Binding instructions DM: `t("discord.binding.instructions", phrase=...)` — rendered in the operator's language (resolved via `User.language` lookup before the DM is sent).
   - Refusal messages to the user: `t("discord.refused.dlp_block")`, `t("discord.refused.rate_limited")`, etc.
   - structlog event messages stay English (operator-facing log lines route through `t()` only in the formatter — log structure remains English machine-readable).
   - `MissingAuditHashPepperError` body uses `t("daemon.boot.audit_hash_pepper_missing")` (key shipped in PR-S4-0b closure-1 list).
   New unit test `tests/unit/discord/test_user_facing_strings_localized.py` asserts the binding DM rendering for `en`/`fr`/`ja` languages produces 3 distinct strings (catalog stub provides the translations).

8. **test-1 HIGH (discord.py mock harness)**: NEW shared fixture in `tests/conftest.py:discord_mock_factory(monkeypatch)`. The factory returns typed `DiscordMockClient`, `DiscordMockGuild`, `DiscordMockUser`, `DiscordMockMessage` instances with type-checked construction. AST guard test `tests/unit/discord/test_no_ad_hoc_mocks.py` walks every test file under `tests/*/discord/` and asserts every Discord-prefixed type is constructed via the factory (no ad-hoc `Mock(spec=discord.Message)` patterns).

9. **test-2 HIGH (per-surface adversarial corpus)**: corpus expansion to 9 prompt-injection entries — one per Discord sub-payload surface (embed-title, embed-description, embed-field-name, embed-field-value, embed-footer, attachment-filename, attachment-description, message-content-with-mention, reply-target-content). Category retag from `identity-boundary` to `prompt_injection` per i18n-reviewer's note. Each entry asserts: (a) the planted injection reaches `quarantined_extract`; (b) the orchestrator never sees the raw injected text; (c) the per-surface promotion-to-ContentHandle audit row fires.

10. **comms-3 MEDIUM (RateLimitSignal ordering guarantee)**: when a 429 fires the Discord plugin MUST: (a) `await rate_limit_signal_handler.process(signal)` synchronously BEFORE; (b) ANY further outbound emit. The plugin's outbound emit loop awaits the signal-handler completion. No fire-and-forget. New unit test `tests/unit/discord/test_rate_limit_signal_blocks_outbound.py` plants a 429, asserts the handler is awaited, asserts no outbound emit fires between 429 and `pause()`.

11. **comms-4 MEDIUM (conversation-ledger thread-continuity test)**: NEW integration test `tests/integration/test_discord_thread_continuity.py` plants two messages in the same Discord thread, asserts the conversation_ledger row binds both messages to the same `conversation_session_id`, asserts the second message's orchestrator session is resumed (not freshly created). Addressing-drift corpus entry `cib-2026-005-thread_addressing_drift` plants a thread retitle attempt and asserts `COMMS_ADDRESSING_DRIFT_FIELDS` row fires.

12. **sec-4 MEDIUM (verification phrase replay/takeover)**: verification phrase is bound to `platform_user_id` at issuance time — DB row carries `(phrase_hash, platform_user_id, issued_at, expires_at_5min)`. Inbound binding attempt that uses a valid-shape phrase but FROM A DIFFERENT platform_user_id is refused with `COMMS_BINDING_REFUSED_FIELDS(reason="phrase_platform_user_mismatch")`. Phrase entropy bumped: `secrets.token_urlsafe(24)` (16-byte underlying entropy → 192 bits, NOT 64). Inbound rate-limit on binding attempts: 5/min/platform_user_id (refuses with `binding_rate_limit_exceeded` audit row).

13. **i18n-3 MEDIUM (babel formatting guidance)**: when audit rows render to operators (CLI/TUI/dashboard), the `received_at`/`recorded_at` datetimes use `babel.dates.format_datetime(dt, locale=operator.language)`. `retry_after_seconds` uses `babel.numbers.format_decimal(n, locale=...)`. Plan §6 adds a "Rendering guidance" subsection documenting this; tests for the operator-facing surfaces (PR-S4-10's TUI) assert the formatting.

14. **test-3 MEDIUM (opt-in real-gateway smoke)**: NEW Task J4: opt-in smoke test `tests/smoke/test_discord_real_gateway_plugin.py` guarded by `ALFRED_DISCORD_SMOKE_TOKEN` env var. Uses a budget-guarded throwaway Discord bot account; connects via the plugin path (NOT legacy Slice-2), sends a DM to itself, asserts the round-trip. Marked `@pytest.mark.real_discord` for opt-in CI run.

---

## §1 Goal

This PR delivers `plugins/alfred_discord/` — the first real comms-MCP adapter under the Slice-4 wire contract — plus the host-side `DiscordSubPayloadClassifier` that promotes Discord-shaped JSON sub-payloads to `ContentHandle` references at the transport boundary. After this PR merges:

1. The daemon (via `bin/alfred-plugin-launcher.sh`) can spawn `plugins/alfred_discord/` as an MCP plugin subprocess.
2. The plugin connects to Discord via `discord.py`, receives DM/mention/channel/thread events, normalises them onto `InboundMessageNotification` (per PR-S4-8's `src/alfred/comms_mcp/protocol.py`), and sends them to the host as JSON-RPC notifications over stdio.
3. The host-side `InboundContentScanner` runs the `discord_sub_payloads` required classifier set; the `DiscordSubPayloadClassifier` recognises nine sub-payload kinds and emits a `ContentHandle` for each, replacing the sub-payload field in the body so the orchestrator never sees raw bytes.
4. The host-side `process_inbound_message` (PR-S4-8) consumes the normalised notification, resolves the platform identity through the host's `IdentityResolver` (or emits `adapter.binding_request` on first contact), passes the body through `quarantined_extract`, and dispatches to the orchestrator.
5. Outbound messages are idempotency-keyed (host generates UUID per request, adapter dedupes across restarts), pass through `OutboundDlp.scan` at the wire boundary, and return an `OutboundMessageResult` discriminated union with `delivered` / `retryable_failure` / `terminal_failure` outcomes.
6. Discord rate-limit signals propagate up via `adapter.rate_limit_signal`; the host's new `OutboundQueue.pause(adapter_id, retry_after_seconds)` suspends emit until the window elapses; `OutboundQueue` auto-resumes.
7. The four wire methods + four notifications are typed-test-covered end-to-end.
8. Two new merge-blocking integration tests ship: `tests/integration/test_discord_addressing_modes.py` (the four addressing modes round-trip) and `tests/integration/test_discord_subpayload_promotion.py` (all nine sub-payload kinds promote to `ContentHandle`).
9. Two new hookpoints land: `comms.adapter.binding_requested` (carrier `T3`) and `comms.adapter.rate_limit_signal` (carrier `T0`).
10. The legacy `src/alfred/comms/discord.py` stays dormant; the existing AST guard at `tests/unit/comms/test_no_direct_adapter_imports.py` continues to forbid fresh imports.

Spec anchors: [§8.5 InboundContentScanner extension + REQUIRED_CLASSIFIERS_BY_KIND](../specs/2026-06-06-slice-4-design.md#85-inboundcontentscanner-extension-for-discord-sub-payloads), [§8.6 Discord adapter — embeds/attachments/polls T3 promotion + persona-addressing](../specs/2026-06-06-slice-4-design.md#86-discord-adapter--embeds--attachments--polls-t3-promotion--persona-addressing), [§8.10 audit row family](../specs/2026-06-06-slice-4-design.md#810-audit-row-family), [§10 hookpoint surface](../specs/2026-06-06-slice-4-design.md#10-hookpoint-surface-slice-4-additions), [§11.5 cross-fork integration test gate](../specs/2026-06-06-slice-4-design.md#115-cross-fork-integration-test-gate--adds-beyond-the-14-2-list), [§14 graduation criteria](../specs/2026-06-06-slice-4-design.md#14-slice-graduation-criteria), and the slice-index [§3 cross-PR contracts](2026-06-07-slice-4-index.md#3-cross-pr-contracts).

---

## §2 Architecture overview

```
                    Discord
                       │  gateway WSS
                       ▼
plugins/alfred_discord/  (MCP plugin subprocess; sandbox.kind=none)
   ├── discord_gateway.py        ─ discord.py wrapper; on_message handler
   ├── inbound_emitter.py        ─ Discord event → InboundMessageNotification
   │                               (addressing_signal: dm|mention|channel|thread)
   ├── outbound_handler.py       ─ OutboundMessageRequest → channel.send +
   │                               idempotency dedupe + OutboundMessageResult
   ├── rate_limit_emitter.py     ─ discord.HTTPException 429 →
   │                               adapter.rate_limit_signal notification
   ├── binding_emitter.py        ─ first-contact → adapter.binding_request
   ├── crash_emitter.py          ─ uncaught exception → adapter.crashed +
   │                               propagate via SystemExit
   ├── lifecycle.py              ─ lifecycle.start / lifecycle.stop /
   │                               adapter.health handlers
   ├── server.py                 ─ MCP server entry point; stdio JSON-RPC loop
   └── manifest.toml             ─ adapter_kind=discord; sandbox.kind=none
                       │
                       │  stdio JSON-RPC (frame-by-frame)
                       ▼
StdioTransport (Slice-3 host side)
                       │  InboundContentScanner.scan(frame_bytes) — extended
                       │  by PR-S4-8 to dispatch classifier registry; PR-S4-9
                       │  registers DiscordSubPayloadClassifier
                       ▼
src/alfred/comms_mcp/classifiers/discord.py — DiscordSubPayloadClassifier (NEW)
   ├── recognises 9 sub-payload kinds per spec §8.6:
   │     embed | attachment | poll | link_unfurl | sticker |
   │     voice_message | component | forwarded_ref | pinned_ref
   ├── emits ContentHandle (Slice-3 at quarantine.py:168) per sub-payload
   └── replaces the field in body so orchestrator never sees raw sub-payload
                       │
                       ▼
AlfredPluginSession._on_post_handshake_method  (Slice-3, PR-S4-8-extended)
                       │  notification dispatch via match on method name
                       │  guarded by per-adapter asyncio.BoundedSemaphore
                       ▼
PR-S4-8 handlers:  InboundHandler / BindingHandler / RateLimitHandler / CrashHandler
                       │
                       ▼
src/alfred/comms_mcp/inbound.py:process_inbound_message  (PR-S4-8)
                       │  identity_resolver.resolve → ResolvedIdentity | None
                       │  on None: _emit_binding_request + COMMS_BINDING_REQUESTED_FIELDS
                       │  on ResolvedIdentity: BurstLimiter.acquire (PR-S4-8) →
                       │  orchestrator.quarantined_extract(body, source_tier="T3")
                       │  → orchestrator.ingest + dispatch
                       ▼
            Orchestrator (privileged) holds T3DerivedData + ContentHandles


Outbound  (orchestrator → user reply):
            Orchestrator.send(persona_response, addressing_mode)
                       │  host generates idempotency_key: UUID
                       │  host runs OutboundDlp.scan(body + attachment_metadata)
                       │  serialises OutboundMessageRequest
                       ▼
            OutboundQueue (NEW in this PR; verified absent in Slice-3)
                       │  pause(adapter_id, retry_after_seconds) suspends emit
                       │  auto-resume after retry_after window
                       ▼
            StdioTransport → plugins/alfred_discord/outbound_handler.py
                       │  dedupe by idempotency_key (in-memory + disk-backed)
                       │  discord.py: channel.send / dm.send / thread.send
                       │  per addressing_mode
                       ▼
            OutboundMessageResult (delivered | retryable_failure | terminal_failure)
                       │
                       ▼
            Host consumes; on retryable_failure with retry_after_seconds →
            OutboundQueue requeues; on terminal_failure → audit + alert.
```

**Naming disambiguation (load-bearing).** Two scanners coexist:

1. `InboundContentScanner` (Slice-3 shipped at the stdio-transport boundary; PR-S4-8 extends to dispatch the host-side classifier registry). Per spec §8.5 its job is to identify sub-payloads and emit `ContentHandle` for each T3-promoted sub-payload.
2. `InboundCanaryScanner` (Slice-3 PR-S3-5 ships in `src/alfred/plugins/web_fetch/canary_scanner.py`). Distinct class, scans Redis content store for operator-registered canary tokens. PR-S4-9 does not touch this class.

PR-S4-9 ships `DiscordSubPayloadClassifier` — registered via PR-S4-8's `@register_classifier(kind="discord", name="discord_sub_payloads")` decorator — under `src/alfred/comms_mcp/classifiers/discord.py`. This is the *classifier* the *scanner* runs. The classifier never imports the canary scanner.

**Per-adapter-kind body field-name mapping (spec §8.6).** Discord delivers the user's free-text under `body.content`. PR-S4-8 ships `BODY_FIELD_BY_KIND: Final[Mapping[str, str]] = {"discord": "content", "tui": "content", "telegram": "text"}` in `src/alfred/comms_mcp/protocol.py`. PR-S4-9 must not duplicate or shadow this mapping; the adapter-kind Literal in PR-S4-8 already enumerates `discord`.

**Verification gate findings.** Before drafting this plan I `grep`-verified each cited Slice-3 surface against `main`:

| Cited symbol | Verification result | Plan response |
|---|---|---|
| `class OutboundQueue` in `src/alfred/` | **Absent** — grep returned no hits | PR-S4-9 introduces `OutboundQueue` at `src/alfred/comms_mcp/outbound_queue.py`. Treated as honest new Slice-4 scope. Documented in `docs/glossary.md` Slice-4 additions (spec §13.1 lists it). |
| `discord.py>=2.4,<3` in `pyproject.toml` | **Present** (line 29) | PR-S4-9 reuses; does NOT add. |
| `discord_bot_token` in `SecretBroker._PREFER_FILE` | **Present** (`src/alfred/security/secrets.py:76`) | Plugin reads via `SecretBroker.get("discord_bot_token")` at lifecycle.start — the Slice-2 surface still works. |
| `src/alfred/comms/discord/` directory | **Absent** — Slice 2 shipped a single file `src/alfred/comms/discord.py`, not a directory | Plan text refers to the file, not a directory. PR-S4-10 deletes the file. The AST guard at `tests/unit/comms/test_no_direct_adapter_imports.py` already forbids fresh imports from `alfred.comms`. |
| `tests/smoke/test_discord_gateway_smoke.py` | **Present** | Plan references the real filename. |
| `register_hookpoint` shape | **Present at `src/alfred/hooks/registry.py:539`** | Slice-3 keyword-only signature: `(name, subscribable_tiers, refusable_tiers, fail_closed)`. PR-S4-3 adds `carrier_tier=` + `allow_error_substitution=` required-by-AST-guard kwargs. PR-S4-9's `register_hookpoint(...)` calls pass both. |
| `ContentHandle` location | **Present at `src/alfred/security/quarantine.py:168`** | Plan imports `from alfred.security.quarantine import ContentHandle`. |
| `COMMS_*_FIELDS` constants | **Absent on `main`** (will land in PR-S4-0a) | Plan imports them; tests fail on a hypothetical PR-S4-9 branch unless PR-S4-0a/0b have merged. Captured in the `Depends on:` block. |
| `AlfredPluginSession._on_post_handshake_method` | **Slice-index §3 cross-PR contracts marks this verified at `src/alfred/plugins/session.py:347`** | PR-S4-9 does not touch this method; PR-S4-8 extends it; PR-S4-9 only registers notification handlers via PR-S4-8's surface. |
| `InboundContentScanner` location | Spec §8.5 marks it Slice-3-shipped; my grep against `src/alfred/plugins/transport.py` returned no hits | **MARKED — verification deferred to PR-S4-8.** PR-S4-9 consumes whatever PR-S4-8 has produced; if PR-S4-8's extension landed at a different module path than the spec implies, PR-S4-9's first task is a fresh grep before authoring the classifier registration site. |

---

## §3 File structure

| File | Status | Responsibility |
|---|---|---|
| `plugins/alfred_discord/__init__.py` | Create | Package marker |
| `plugins/alfred_discord/manifest.toml` | Create | MCP manifest: `adapter_kind: discord`; `sandbox.kind: none` (spec §7.9 first-party relay carve-out); `secrets = ["discord_bot_token", "audit.hash_pepper"]`; `classifiers_optional: []`; no `[[hooks]]` entries (adapter only emits notifications) |
| `plugins/alfred_discord/server.py` | Create | MCP server entry point — stdio JSON-RPC loop; constructs the four request handlers (`lifecycle.start`, `lifecycle.stop`, `adapter.health`, `outbound.message`); wires `discord_gateway.py` |
| `plugins/alfred_discord/lifecycle.py` | Create | `LifecycleStart` (authenticate via `SecretBroker.get("discord_bot_token")`, open Discord WSS, return `LifecycleStartResult(ok, plugin_version)`); `LifecycleStop` (close WSS, flush in-flight outbound, return `LifecycleStopResult(ok, flushed_messages)`); `AdapterHealth` (return queue depth + last inbound + error count) |
| `plugins/alfred_discord/discord_gateway.py` | Create | `discord.py` `commands.Bot` subclass; on_message / on_message_edit listeners; converts Discord event → `InboundMessageNotification` via `inbound_emitter.normalise`; exponential-backoff reconnect on gateway disconnect |
| `plugins/alfred_discord/inbound_emitter.py` | Create | `normalise(discord.Message) -> InboundMessageNotification` — fills `adapter_id`, `platform_user_id`, `body` (full Discord message JSON, nine sub-payloads inline), `received_at`, `addressing_signal` per the four-mode mapping spec §8.6 |
| `plugins/alfred_discord/outbound_handler.py` | Create | `handle_outbound(OutboundMessageRequest) -> OutboundMessageResult` — dedupes by `idempotency_key` against on-disk store (survives plugin restart); routes per `addressing_mode` (`dm` → user.send; `mention` → channel.send with `@user`; `channel` → channel.send; `thread` → thread.send); maps `discord.HTTPException` to `_OutboundRetryable` / `_OutboundTerminal`; returns `_OutboundDelivered(platform_message_id=str(sent.id))` on success |
| `plugins/alfred_discord/rate_limit_emitter.py` | Create | Intercepts `discord.HTTPException` with status 429; reads `retry_after`; emits `RateLimitSignal(adapter_id, retry_after_seconds, platform_endpoint)` notification; pauses local outbound emit |
| `plugins/alfred_discord/binding_emitter.py` | Create | Detects unrecognised platform user (host responds to inbound with binding-required side-channel — first-contact path); emits `BindingRequestNotification(adapter_id, platform_user_id, verification_phrase, platform_metadata)`; computes verification phrase via host-supplied randomness (NOT computed in-plugin — receives from host on first inbound resolution-failure callback) |
| `plugins/alfred_discord/crash_emitter.py` | Create | Top-level uncaught-exception handler; emits `CrashedNotification(adapter_id, error_class, detail)` with DLP-pre-redacted detail; `SystemExit(1)` after notification flush so supervisor's breaker triggers |
| `plugins/alfred_discord/idempotency_store.py` | Create | On-disk dedup store at `$XDG_RUNTIME_DIR/alfred/plugin-alfred.discord/idempotency.db` (SQLite); TTL=24h; survives plugin restart per spec §8.1 idempotency-key contract |
| `plugins/alfred_discord/addressing_inference.py` | Create | `infer_addressing_signal(discord.Message) -> Literal["dm","mention","channel","thread"]` per spec §8.6 table |
| `plugins/alfred_discord/conftest.py` | Create | Plugin-side test fixtures (recorded Discord events, `discord.py` test doubles, idempotency-store tmp dir) |
| `src/alfred/comms_mcp/classifiers/__init__.py` | Create | Package marker; re-exports `DiscordSubPayloadClassifier` |
| `src/alfred/comms_mcp/classifiers/discord.py` | Create | **Host-side** `DiscordSubPayloadClassifier` registered via PR-S4-8's `@register_classifier(kind="discord", name="discord_sub_payloads")`; recognises nine sub-payload kinds (`embed`, `attachment`, `poll`, `link_unfurl`, `sticker`, `voice_message`, `component`, `forwarded_ref`, `pinned_ref`); emits `ContentHandle` per sub-payload; replaces the field in the body so the orchestrator never sees raw sub-payload bytes |
| `src/alfred/comms_mcp/outbound_queue.py` | Create | **NEW Slice-4 host-side primitive.** `OutboundQueue` with per-adapter FIFO + `pause(adapter_id, retry_after_seconds)` + `resume(adapter_id)` + auto-resume after retry_after; manages backpressure via `asyncio.Semaphore`. Consumed by PR-S4-9 outbound dispatch + PR-S4-10 TUI outbound dispatch |
| `src/alfred/comms_mcp/discord_hookpoints.py` | Create | Module-init registers `comms.adapter.binding_requested` (carrier_tier=T3) and `comms.adapter.rate_limit_signal` (carrier_tier=T0) via PR-S4-3's extended `register_hookpoint`; AST guard refuses if `carrier_tier=` omitted |
| `src/alfred/comms_mcp/audit_hash.py` | Create | Reuses PR-S4-0b's `audit.hash_pepper` lookup; exposes `hash_platform_user_id(raw: str) -> str` and `hash_verification_phrase(raw: str) -> str` per spec §8.10 HMAC recipe; thin wrapper for `hmac.new(pepper_bytes, raw.encode(), hashlib.sha256).hexdigest()[:32]` |
| `tests/unit/comms_mcp/__init__.py` | Maybe-create | Package marker (already present if PR-S4-8 created it) |
| `tests/unit/comms_mcp/test_discord_sub_payload_classifier.py` | Create | Exhaustive per-sub-payload-kind classifier tests (one happy path + one synthetic-malformed-payload per kind = 9 × 2 = 18 cases) |
| `tests/unit/comms_mcp/test_outbound_queue_pause.py` | Create | `OutboundQueue.pause` suspends emit; `resume` resumes; auto-resume after retry_after elapsed; concurrent pause/resume race-condition tests |
| `tests/unit/comms_mcp/test_outbound_message_result_discriminated_union.py` | Create | Discriminated-union validation: each outcome carries the right fields and only those fields; Pydantic refuses cross-shape construction |
| `tests/unit/comms_mcp/test_audit_hash_pepper_lookup.py` | Create | `audit_hash.hash_platform_user_id` uses `SecretBroker.get("audit.hash_pepper")`; rotation invalidates correlation; missing pepper raises at first call (mirrors broker-side daemon-boot refusal) |
| `tests/unit/comms_mcp/test_discord_hookpoints_carrier_tier_passed.py` | Create | AST-walk test asserts the two `register_hookpoint` calls in `discord_hookpoints.py` pass `carrier_tier=` per PR-S4-3's required-field contract |
| `tests/unit/plugins/alfred_discord/test_addressing_inference.py` | Create | Four addressing-signal inferences from synthetic `discord.Message` fixtures: DM, mention, channel, thread |
| `tests/unit/plugins/alfred_discord/test_idempotency_store.py` | Create | Single-use idempotency contract; restart-survival; TTL expiry; concurrent-write race |
| `tests/unit/plugins/alfred_discord/test_outbound_handler.py` | Create | `OutboundMessageRequest` → `OutboundMessageResult` for each addressing_mode; `discord.HTTPException(429)` → `_OutboundRetryable`; `discord.Forbidden` → `_OutboundTerminal`; idempotency dedupe across restarts |
| `tests/unit/plugins/alfred_discord/test_inbound_emitter_normalises.py` | Create | Discord-event JSON → `InboundMessageNotification` for each addressing_signal value; body carries every sub-payload kind inline (classifier promotion happens host-side, NOT in adapter) |
| `tests/unit/plugins/alfred_discord/test_lifecycle_health.py` | Create | `lifecycle.start` opens WSS via mock; `lifecycle.stop` flushes outbound; `adapter.health` returns plausible health report |
| `tests/integration/test_discord_addressing_modes.py` | Create | **MERGE-BLOCKING.** Four addressing modes round-trip end-to-end via mock Discord gateway + real `AlfredPluginSession` + recorded `IdentityResolver` |
| `tests/integration/test_discord_subpayload_promotion.py` | Create | **MERGE-BLOCKING.** Nine sub-payload kinds promote to `ContentHandle` end-to-end |
| `tests/adversarial/comms_identity_boundary/cib-2026-001-forged-platform-metadata.yaml` | Create | Adversary plants `platform_metadata.canonical_user_id` field; assert host's `IdentityResolver` ignores it (resolution comes from host state, not notification) |
| `tests/adversarial/comms_identity_boundary/cib-2026-002-cross-adapter-id-collision.yaml` | Create | Two adapters return the same `platform_user_id` from different platforms; assert `IdentityResolver` keys on `(adapter_id, platform_user_id)` not `platform_user_id` alone |
| `tests/adversarial/comms_identity_boundary/cib-2026-003-discord-embed-injection.yaml` | Create | Discord embed contains apparent system-prompt injection text; assert `DiscordSubPayloadClassifier` promotes to `ContentHandle` (orchestrator never sees raw embed bytes) |

---

## §4 Cross-PR contracts that PR-S4-9 consumes

These are surfaces defined by upstream PRs; PR-S4-9 must consume them exactly and may not redefine them. Each row cites the defining PR + the consumer call-site in PR-S4-9.

| Contract | Defined in | PR-S4-9 consumer |
|---|---|---|
| `InboundMessageNotification` Pydantic model | PR-S4-8 `src/alfred/comms_mcp/protocol.py` | `plugins/alfred_discord/inbound_emitter.py:normalise` constructs this |
| `OutboundMessageRequest` Pydantic model | PR-S4-8 `src/alfred/comms_mcp/protocol.py` | `plugins/alfred_discord/outbound_handler.py` accepts this |
| `OutboundMessageResult` discriminated union | PR-S4-8 `src/alfred/comms_mcp/protocol.py` | `plugins/alfred_discord/outbound_handler.py` returns one of three variants |
| `BindingRequestNotification` / `RateLimitSignal` / `CrashedNotification` | PR-S4-8 `src/alfred/comms_mcp/protocol.py` | The three emitter modules construct these |
| `AlfredPluginSession._on_post_handshake_method` (notification dispatch) | PR-S4-8 extends Slice-3 `src/alfred/plugins/session.py:347` | PR-S4-9 only invokes; never edits |
| `process_inbound_message(notification, ...)` host entrypoint | PR-S4-8 `src/alfred/comms_mcp/inbound.py` | PR-S4-9 only invokes; never edits |
| `BurstLimiter` | PR-S4-8 `src/alfred/orchestrator/burst_limiter.py` | PR-S4-9 indirectly consumes via `process_inbound_message` |
| `REQUIRED_CLASSIFIERS_BY_KIND` mapping | PR-S4-8 `src/alfred/comms_mcp/classifier_registry.py` | PR-S4-9 verifies the `"discord"` key maps to a frozenset containing `"discord_sub_payloads"`; if absent, PR-S4-9's first task adds the entry per the AST guard |
| `@register_classifier(kind=…, name=…)` decorator | PR-S4-8 `src/alfred/comms_mcp/classifier_registry.py` | PR-S4-9 `src/alfred/comms_mcp/classifiers/discord.py` decorates `DiscordSubPayloadClassifier` |
| `BODY_FIELD_BY_KIND` mapping | PR-S4-8 `src/alfred/comms_mcp/protocol.py` | PR-S4-9 verifies the `"discord"` key maps to `"content"`; tests reference but do not redefine |
| `adapter_kind: Final[frozenset[str]]` literal | PR-S4-8 `src/alfred/comms_mcp/protocol.py` | PR-S4-9 verifies `"discord"` is in the frozenset; if absent, PR-S4-9's task list adds it (per the §8.5 AST-guard rule that new adapter kinds land with their REQUIRED_CLASSIFIERS_BY_KIND entry in the same PR) |
| `HookpointMeta.carrier_tier` + `allow_error_substitution` required fields | PR-S4-3 `src/alfred/hooks/registry.py:HookpointMeta` | PR-S4-9's `register_hookpoint(...)` calls pass both kwargs |
| `audit.hash_pepper` secret bootstrap | PR-S4-0b broker config migration | PR-S4-9's `audit_hash.py` calls `SecretBroker.get("audit.hash_pepper")`; daemon-boot refuses if missing per spec §8.10 |
| `COMMS_*_FIELDS` audit-row constants | PR-S4-0a `src/alfred/audit/audit_row_schemas.py` | Host emits via `AuditWriter.append_schema(...)`; adapters never write audit |
| `ContentHandle` frozen dataclass | Slice-3 `src/alfred/security/quarantine.py:168` | `DiscordSubPayloadClassifier` constructs one per sub-payload field replacement |
| `SecretBroker.get(name)` API | Slice-3 `src/alfred/security/secrets.py:396` | Plugin reads `discord_bot_token` at lifecycle.start; host reads `audit.hash_pepper` at AuditWriter init |
| `OutboundDlp.scan` placement at wire boundary | Slice-3 + spec §2.1 row 2 | Host invokes `OutboundDlp.scan` against body + attachment_metadata before serialising `OutboundMessageRequest`; redaction-on-success emits Slice-3 `OUTBOUND_REDACTED_FIELDS`; refusal emits `DLP_OUTBOUND_REFUSED_FIELDS` and aborts the outbound |

PR-S4-9 introduces these new contracts that PR-S4-10 will consume:

| New contract | Defined in this PR | Consumer |
|---|---|---|
| `OutboundQueue` class with `pause(adapter_id, retry_after_seconds)` / `resume(adapter_id)` / `submit(adapter_id, request)` | `src/alfred/comms_mcp/outbound_queue.py` | PR-S4-10 TUI adapter outbound; PR-S4-11 graduation runbook |
| `DiscordSubPayloadClassifier` registered under name `"discord_sub_payloads"` | `src/alfred/comms_mcp/classifiers/discord.py` | PR-S4-8's `REQUIRED_CLASSIFIERS_BY_KIND["discord"]` references; PR-S4-11 graduation glossary |
| Two new hookpoints `comms.adapter.binding_requested` (T3) + `comms.adapter.rate_limit_signal` (T0) | `src/alfred/comms_mcp/discord_hookpoints.py` | Operator subscribers; PR-S4-11 graduation hookpoint surface table |

---

## §5 Tasks

### Component A — Host-side primitives (consumed by adapter + later PRs)

These ship first so the adapter's tests have something to import. Each task follows TDD strictly: failing test → minimum implementation → green → commit.

- [ ] **Task A1 — `OutboundQueue` primitive (per-adapter FIFO + pause/resume).**

  Files: Create `src/alfred/comms_mcp/outbound_queue.py`; Create `tests/unit/comms_mcp/test_outbound_queue_pause.py`.

  **Failing test first.** Write `tests/unit/comms_mcp/test_outbound_queue_pause.py` covering:

  1. `submit(adapter_id, request)` round-trips a request through `consume(adapter_id)` in FIFO order.
  2. `pause(adapter_id, retry_after_seconds=2.0)` causes `consume(adapter_id)` to block until the retry-after window elapses, then auto-resumes.
  3. `pause(adapter_id, …)` followed by `resume(adapter_id)` returns control immediately (manual resume overrides the timer).
  4. Pausing adapter A does not affect adapter B's consume.
  5. Concurrent `submit` + `pause` race: every submitted request is delivered exactly once across the pause/resume boundary (use `asyncio.TaskGroup`).
  6. `pause` is idempotent: calling twice extends the retry-after to the later of the two windows; calling with a shorter window is a no-op.
  7. `__init__(*, max_in_flight_per_adapter: int = 32, audit_writer: AuditWriterProtocol)` — the audit writer is required so emission can be observed; the cap is per-adapter not process-wide.

  Run: `uv run pytest tests/unit/comms_mcp/test_outbound_queue_pause.py -q`
  Expected: `ImportError`.

  **Implementation.** Create `src/alfred/comms_mcp/outbound_queue.py`:

  - Class `OutboundQueue` with `asyncio.Queue[OutboundMessageRequest]` keyed by `adapter_id`.
  - Per-adapter `asyncio.Event` (`_resume_events[adapter_id]`). `pause` schedules `loop.call_later(retry_after, self._auto_resume, adapter_id)` and clears the event; `consume` awaits `event.wait()` before pulling from the queue.
  - Per-adapter `asyncio.Semaphore(max_in_flight_per_adapter)` enforces the cap (`async with sem:` around each `submit`).
  - Strict typing: `OutboundQueue` is generic in `OutboundMessageRequest`; mypy `--strict` clean.
  - Structlog observability event `comms.outbound_queue.paused` with `adapter_id` + `retry_after_seconds` (NOT an audit row — observability only; the audit row for the rate-limit signal is `COMMS_RATE_LIMIT_SIGNAL_FIELDS` emitted by the host's signal handler, not by the queue itself).

  Run: `uv run pytest tests/unit/comms_mcp/test_outbound_queue_pause.py -q`
  Expected: 7 passed.

  Run: `uv run mypy src/alfred/comms_mcp/outbound_queue.py && uv run pyright src/alfred/comms_mcp/outbound_queue.py`
  Expected: clean.

  Commit:

  ```
  git commit -m "feat(comms-mcp): OutboundQueue with per-adapter pause/resume + retry-after auto-resume (#TBD-slice4)"
  ```

- [ ] **Task A2 — `audit_hash` helper (HMAC-with-pepper wrapper).**

  Files: Create `src/alfred/comms_mcp/audit_hash.py`; Create `tests/unit/comms_mcp/test_audit_hash_pepper_lookup.py`.

  **Failing test first.** Write `tests/unit/comms_mcp/test_audit_hash_pepper_lookup.py`:

  1. `hash_platform_user_id("123456789")` returns a 32-char hex string.
  2. With pepper P1, `hash_platform_user_id(X)` is deterministic; with pepper P2 it differs.
  3. The helper calls `SecretBroker.get("audit.hash_pepper")` exactly once per process (cached) — verified via spy.
  4. Missing pepper raises `MissingAuditHashPepperError`.
  5. `hash_verification_phrase("alfred-foo-bar")` returns a 32-char hex string distinct from a platform-id with the same plaintext (the digest input includes a domain-separation prefix to prevent cross-field collision).

  Run: `uv run pytest tests/unit/comms_mcp/test_audit_hash_pepper_lookup.py -q`
  Expected: `ImportError`.

  **Implementation.** Create `src/alfred/comms_mcp/audit_hash.py`:

  ```text
  - Reads SecretBroker.get("audit.hash_pepper") once at module-level via a
    cached function; caches the bytes for the daemon lifetime.
  - hash_platform_user_id(raw: str) -> str:
      hmac.new(pepper, b"platform_user_id:" + raw.encode(), sha256).hexdigest()[:32]
  - hash_verification_phrase(raw: str) -> str:
      hmac.new(pepper, b"verification_phrase:" + raw.encode(), sha256).hexdigest()[:32]
  - Domain-separation prefixes prevent the same plaintext under two fields
    from colliding (defence-in-depth; the pepper would already make
    cross-row correlation hard, but the domain separator is cheap).
  - MissingAuditHashPepperError: AlfredError subclass with t() i18n key
    "audit.hash_pepper.missing".
  ```

  Run: `uv run pytest tests/unit/comms_mcp/test_audit_hash_pepper_lookup.py -q`
  Expected: 5 passed.

  Commit:

  ```
  git commit -m "feat(comms-mcp): audit_hash HMAC-with-pepper helper for platform-id + verification-phrase (#TBD-slice4)"
  ```

- [ ] **Task A3 — Discord hookpoint registrations.**

  Files: Create `src/alfred/comms_mcp/discord_hookpoints.py`; Create `tests/unit/comms_mcp/test_discord_hookpoints_carrier_tier_passed.py`.

  **Failing test first.** Write `tests/unit/comms_mcp/test_discord_hookpoints_carrier_tier_passed.py`:

  - AST-walks `src/alfred/comms_mcp/discord_hookpoints.py`; finds every `register_hookpoint(...)` call; asserts each carries `carrier_tier=` AND `subscribable_tiers=` AND `fail_closed=` per PR-S4-3's AST-guard contract.
  - Asserts the two hookpoint names are exactly `comms.adapter.binding_requested` and `comms.adapter.rate_limit_signal`.
  - Asserts `comms.adapter.binding_requested` carries `carrier_tier="T3"` + `subscribable_tiers=SYSTEM_OPERATOR_TIERS` + `fail_closed=False`.
  - Asserts `comms.adapter.rate_limit_signal` carries `carrier_tier="T0"` + `subscribable_tiers=SYSTEM_OPERATOR_TIERS` + `fail_closed=False`.

  Run: `uv run pytest tests/unit/comms_mcp/test_discord_hookpoints_carrier_tier_passed.py -q`
  Expected: collection error.

  **Implementation.** Create `src/alfred/comms_mcp/discord_hookpoints.py`:

  ```text
  from alfred.hooks.registry import register_hookpoint, SYSTEM_OPERATOR_TIERS
  from alfred.security.trust_tiers import TrustTier

  def register() -> None:
      register_hookpoint(
          name="comms.adapter.binding_requested",
          subscribable_tiers=SYSTEM_OPERATOR_TIERS,
          refusable_tiers=SYSTEM_OPERATOR_TIERS,
          fail_closed=False,
          carrier_tier=TrustTier("T3"),
          allow_error_substitution=True,
      )
      register_hookpoint(
          name="comms.adapter.rate_limit_signal",
          subscribable_tiers=SYSTEM_OPERATOR_TIERS,
          refusable_tiers=SYSTEM_OPERATOR_TIERS,
          fail_closed=False,
          carrier_tier=TrustTier("T0"),
          allow_error_substitution=True,
      )
  ```

  The `register()` function is called from the daemon's hookpoint-bootstrap site (existing Slice-2.5 pattern — the daemon calls each subsystem's `register()` at boot). PR-S4-1's daemon boot path adds the call; PR-S4-9 ships the registration site and its test.

  Run: `uv run pytest tests/unit/comms_mcp/test_discord_hookpoints_carrier_tier_passed.py -q`
  Expected: 4 passed.

  Run: `uv run mypy src/alfred/comms_mcp/discord_hookpoints.py`
  Expected: clean.

  Commit:

  ```
  git commit -m "feat(comms-mcp): comms.adapter.binding_requested + rate_limit_signal hookpoint registration (#TBD-slice4)"
  ```

### Component B — Host-side classifier

- [ ] **Task B1 — `DiscordSubPayloadClassifier` recognises nine sub-payload kinds.**

  Files: Create `src/alfred/comms_mcp/classifiers/__init__.py`; Create `src/alfred/comms_mcp/classifiers/discord.py`; Create `tests/unit/comms_mcp/test_discord_sub_payload_classifier.py`.

  **Failing test first.** Write `tests/unit/comms_mcp/test_discord_sub_payload_classifier.py`. Test cases (18 total = 9 kinds × {happy, malformed}):

  - Happy paths: For each of the nine kinds (`embed`, `attachment`, `poll`, `link_unfurl`, `sticker`, `voice_message`, `component`, `forwarded_ref`, `pinned_ref`), construct a synthetic Discord message JSON with one populated sub-payload of that kind, run `DiscordSubPayloadClassifier.classify(message_body)`, assert:
    - The returned `ScannedFrame` carries one `ContentHandle` whose `source_url` carries the field path (e.g. `"discord://embeds[0]"`).
    - The replaced body's corresponding field is a handle-reference dict `{"$content_handle_id": "<uuid>"}` not the raw sub-payload bytes.
    - The non-sub-payload fields (e.g. `content`, `id`, `author`) are unchanged.
  - Malformed paths: For each of the nine kinds, construct a synthetic message with a malformed sub-payload (wrong type, missing required nested field). Assert the classifier emits a `ClassifierMalformedPayloadEvent` (a structlog event, NOT an exception — malformed sub-payloads must NOT crash the scanner; they get logged and skipped because Discord's API surface evolves over time) and the field passes through unchanged. This is defensible per the spec §8.5 "future Discord variant ships with materially different sub-payloads" forward-compat note.
  - Edge cases:
    - Multiple sub-payloads of the same kind (two embeds) — each gets its own `ContentHandle`.
    - Empty sub-payload arrays (`embeds: []`) — no handles emitted; field untouched.
    - Missing optional sub-payload fields — no handles emitted.

  Run: `uv run pytest tests/unit/comms_mcp/test_discord_sub_payload_classifier.py -q`
  Expected: collection error.

  **Implementation.** Create `src/alfred/comms_mcp/classifiers/discord.py`:

  ```text
  - @register_classifier(kind="discord", name="discord_sub_payloads")
    class DiscordSubPayloadClassifier:
        SUB_PAYLOAD_FIELDS: Final[Mapping[str, str]] = MappingProxyType({
            "embed": "embeds",
            "attachment": "attachments",
            "poll": "poll",
            "link_unfurl": "embeds[].type=='link'",  # link-unfurl detection
            "sticker": "stickers",
            "voice_message": "attachments[].content_type^='audio/'",
            "component": "components",
            "forwarded_ref": "message_reference",
            "pinned_ref": "message_reference.message_id_in_pinned_set",
        })

        def classify(self, body: Mapping[str, Any]) -> ScannedFrame:
            """Walk body, emit ContentHandle per matched sub-payload kind."""
            handles: list[ContentHandle] = []
            replaced_body = dict(body)  # shallow; we replace fields, not nest
            for kind, field_spec in self.SUB_PAYLOAD_FIELDS.items():
                matched = self._match(body, field_spec)
                for path, sub_payload in matched:
                    try:
                        handle = self._content_store.write(
                            body=json.dumps(sub_payload).encode(),
                            source_url=f"discord://{path}",
                        )
                        handles.append(handle)
                        self._replace_field(replaced_body, path,
                                            {"$content_handle_id": handle.id})
                    except MalformedSubPayloadError as exc:
                        log.warning(
                            "comms_mcp.discord_classifier.malformed",
                            kind=kind, path=path, error=str(exc),
                        )
                        # Field stays as-is; forward-compat per spec §8.5.
            return ScannedFrame(body=replaced_body, handles=tuple(handles))

  - Helper _match walks dotted paths with [index] / [field=value] syntax —
    a small DSL for the SUB_PAYLOAD_FIELDS table. The DSL is intentionally
    narrow: no arbitrary code execution, no eval. Tested in
    test_discord_sub_payload_classifier.py:TestDSL.
  - _replace_field writes the {"$content_handle_id": …} dict into the body
    at the matched path.
  - SUB_PAYLOAD_FIELDS is keyed by the Literal sub_payload_kinds names
    from spec §8.10 — sub_payload_kinds: frozenset of
    Literal["embed","attachment","poll","link_unfurl","sticker",
            "voice_message","component","forwarded_ref","pinned_ref"]
    (load-bearing; the audit-row schema constant references this exact set).
  ```

  The classifier writes sub-payloads to the **Slice-3 Redis content store** (`alfred.plugins.web_fetch.content_store.ContentStore` — verified at `src/alfred/plugins/web_fetch/content_store.py`) so the same single-use semantics apply: orchestrator dereferences via the handle id; second extract raises `ContentHandleExpired`.

  Run: `uv run pytest tests/unit/comms_mcp/test_discord_sub_payload_classifier.py -q`
  Expected: 18 + DSL tests pass.

  Run: `uv run mypy src/alfred/comms_mcp/classifiers/discord.py && uv run pyright src/alfred/comms_mcp/classifiers/discord.py`
  Expected: clean.

  Commit:

  ```
  git commit -m "feat(comms-mcp): DiscordSubPayloadClassifier recognises 9 sub-payload kinds, emits ContentHandle (#TBD-slice4)"
  ```

- [ ] **Task B2 — Verify PR-S4-8's `REQUIRED_CLASSIFIERS_BY_KIND` entry + adapter-kind Literal.**

  Files: Read-only verification + optional edit.

  Pre-flight grep:

  ```bash
  grep -n "REQUIRED_CLASSIFIERS_BY_KIND\|discord_sub_payloads\|adapter_kind" \
      src/alfred/comms_mcp/classifier_registry.py \
      src/alfred/comms_mcp/protocol.py
  ```

  Assertions:

  - `REQUIRED_CLASSIFIERS_BY_KIND["discord"]` is a `frozenset[str]` containing `"discord_sub_payloads"`. If PR-S4-8 shipped it with just `frozenset({"discord_sub_payloads"})`, this PR is done. If PR-S4-8 left the entry empty pending PR-S4-9 (per the AST-guard "new kind + classifiers in same PR" rule), this PR adds it now in `src/alfred/comms_mcp/classifier_registry.py`.
  - `adapter_kind: Final[frozenset[str]]` in `src/alfred/comms_mcp/protocol.py` contains `"discord"`. Same rule.
  - `BODY_FIELD_BY_KIND["discord"] == "content"` per spec §8.6.

  If any addition is needed, follow TDD: write a unit test asserting the membership (or update PR-S4-8's existing `tests/unit/comms_mcp/test_required_classifiers_complete.py` AST guard if not already covered), then add the entry, then run `make check`.

  Commit (only if edits made):

  ```
  git commit -m "feat(comms-mcp): register discord adapter_kind + classifier in PR-S4-8 surfaces (#TBD-slice4)"
  ```

### Component C — Plugin scaffolding (manifest + lifecycle)

- [ ] **Task C1 — Plugin manifest with `adapter_kind: discord` + `sandbox.kind: none`.**

  Files: Create `plugins/alfred_discord/__init__.py` (empty); Create `plugins/alfred_discord/manifest.toml`.

  Manifest shape (consult `plugins/alfred_web_fetch/manifest.toml` for the established format; PR-S4-6 extends the manifest reader to require the `sandbox` block per spec §7.1):

  ```text
  alfred.manifest_version = 1

  [plugin]
  id = "alfred.discord"
  subscriber_tier = "system"

  [sandbox]
  # First-party in-tree relay adapter per spec §7.9 carve-out. Discord
  # adapter sees no T3 content (the platform-relayed text/sub-payloads
  # are tagged T3 at the host-side transport boundary, not in-plugin).
  # The plugin itself only marshals JSON-RPC frames and talks to the
  # Discord gateway over TLS — no T3 ingestion in-process. Therefore
  # kind=none is correct per the spec carve-out.
  kind = "none"

  [comms_mcp]
  adapter_kind = "discord"
  classifiers_optional = []

  [secrets]
  # Slice-3 PREFER_FILE — broker substitutes at the JSON-RPC dispatch
  # boundary; plugin never sees raw token bytes in env or argv.
  discord_bot_token = "*"

  [network]
  # Adapter talks to discord.com gateway WSS + REST.
  allowlist = ["discord.com", "gateway.discord.gg"]
  ```

  No test for the manifest content itself (it's TOML) but a `tests/unit/plugins/alfred_discord/test_manifest_shape.py` asserts:

  - The manifest parses.
  - `[sandbox].kind == "none"` (spec §7.9).
  - `[comms_mcp].adapter_kind == "discord"`.
  - `[secrets]` includes `discord_bot_token`.

  Commit:

  ```
  git commit -m "feat(discord): plugin manifest with adapter_kind=discord + sandbox.kind=none (#TBD-slice4)"
  ```

- [ ] **Task C2 — `lifecycle.start` / `lifecycle.stop` / `adapter.health` request handlers.**

  Files: Create `plugins/alfred_discord/lifecycle.py`; Create `tests/unit/plugins/alfred_discord/test_lifecycle_health.py`.

  **Failing test first.** Write `test_lifecycle_health.py`:

  1. `LifecycleStart(adapter_id, credentials_ref="secret:discord_bot_token", policies_snapshot_hash=…)` triggers `discord.Client.start(token)`; with a mock client, assert `start()` is called with the resolved token.
  2. `LifecycleStart` returns `LifecycleStartResult(ok=True, plugin_version=<pyproject version>)`.
  3. `LifecycleStop(adapter_id, reason="shutdown")` triggers `discord.Client.close()`; returns `LifecycleStopResult(ok=True, flushed_messages=<count>)`.
  4. `AdapterHealth(adapter_id)` returns `HealthReport(ok=True, last_inbound_at=…, queue_depth=…, error_count=…)`.
  5. Repeated `lifecycle.start` with the same `adapter_id` is idempotent: returns success without reopening the gateway.
  6. `lifecycle.start` failure modes: bad credentials → `LifecycleStartResult(ok=False, plugin_version=…)` + structlog `event="comms.lifecycle.start_failed"` + `error_class=…`.

  Run: `uv run pytest tests/unit/plugins/alfred_discord/test_lifecycle_health.py -q`
  Expected: collection error.

  **Implementation.** Create `plugins/alfred_discord/lifecycle.py`. Uses `discord.py` `commands.Bot` per the spec §15 open-question note that PR-S4-9 makes the library decision (verified `discord.py>=2.4,<3` already in `pyproject.toml`).

  Run: `uv run pytest tests/unit/plugins/alfred_discord/test_lifecycle_health.py -q`
  Expected: 6 passed.

  Commit:

  ```
  git commit -m "feat(discord): lifecycle.start / stop / adapter.health request handlers (#TBD-slice4)"
  ```

### Component D — Addressing inference

- [ ] **Task D1 — `infer_addressing_signal` maps Discord events to the four wire `Literal` values.**

  Files: Create `plugins/alfred_discord/addressing_inference.py`; Create `tests/unit/plugins/alfred_discord/test_addressing_inference.py`.

  **The four-mode mapping table** (spec §8.6 verbatim, reproduced for implementer reference):

  | Inbound Discord shape | Inferred `addressing_signal` | PRD §6.8 concept | Outbound rendering for `addressing_mode=…` |
  |---|---|---|---|
  | DM channel (`isinstance(channel, discord.DMChannel)`) | `"dm"` | direct (1:1) | `discord.User.send(body)` — ephemeral DM reply |
  | Guild channel + bot mentioned (`bot.user in message.mentions`) | `"mention"` | direct (1:N with explicit addressee) | `channel.send(f"<@{user_id}> {body}")` — channel reply with `@user` prefix |
  | Guild channel, no mention, channel in adapter's listen-set | `"channel"` | default (group, addressee not explicit) | `channel.send(body)` — bare channel reply |
  | Thread (`isinstance(channel, discord.Thread)`) | `"thread"` | group | `thread.send(body)` — reply in originating thread |
  | Guild channel, no mention, channel NOT in listen-set | `None` (skip) | n/a | n/a — bot ignores |
  | Bot's own message (`msg.author == bot.user`) | `None` (skip) | n/a | n/a — prevent feedback loop |

  The mapping is **inference-direction symmetric**: the inbound `addressing_signal` carries the platform's view; the outbound `addressing_mode` tells the adapter how to render. The host validates the round-trip and emits `COMMS_ADDRESSING_DRIFT_FIELDS` if the orchestrator routes a DM-signalled inbound into a channel-mode outbound (operator-visible drift but not refused — spec §8.1 explicitly allows this; some legitimate operator workflows route DMs into channels).

  **Failing test first.** Write `test_addressing_inference.py`. Each case constructs a synthetic `discord.Message` test double:

  1. Message in a `DMChannel` → `"dm"`.
  2. Message in a `TextChannel` that mentions the bot → `"mention"`.
  3. Message in a `TextChannel` configured in `plugin.manifest.channel_allowlist` without bot mention → `"channel"`.
  4. Message in a `Thread` (DM-thread or guild-thread) → `"thread"`.
  5. Edge: message in a `TextChannel` NOT configured and NOT mentioning the bot → returns `None` (the bot ignores; no notification emitted).
  6. Edge: bot's own outbound message (`msg.author == bot.user`) → returns `None` (do not feedback-loop).
  7. Edge: message in a `TextChannel` mentioning bot BUT channel is not in listen-set → returns `"mention"` (a mention always wins over channel-allowlist gating; the operator may want explicit `@bot` callouts in channels the bot doesn't otherwise listen to).
  8. Edge: message in a guild thread whose parent channel is in listen-set → returns `"thread"` (thread overrides channel-mode; reply goes to the thread, not the parent).
  9. Edge: message in a DM-thread (Discord's threaded DM feature) → returns `"thread"` (same precedence: thread overrides DM).
  10. Edge: message with bot mentioned via role-mention rather than user-mention — only direct user-mentions count; role-mentions return whatever the underlying channel/DM/thread context dictates (no `"mention"` boost).

  Run: `uv run pytest tests/unit/plugins/alfred_discord/test_addressing_inference.py -q`
  Expected: collection error.

  **Implementation.** Create `plugins/alfred_discord/addressing_inference.py`. The four-mode mapping precedence (high to low):

  1. `msg.author == bot.user` → `None` (no feedback).
  2. `isinstance(channel, discord.Thread)` → `"thread"` (overrides DM and channel; reply goes to the thread).
  3. `isinstance(channel, discord.DMChannel)` → `"dm"`.
  4. `bot.user in message.mentions` → `"mention"` (overrides channel-allowlist gating).
  5. `channel.id in adapter_config.channel_listen_set` → `"channel"`.
  6. Else → `None`.

  The precedence list is the load-bearing contract; tests 7-10 above pin each rung.

  Run: `uv run pytest tests/unit/plugins/alfred_discord/test_addressing_inference.py -q`
  Expected: 10 passed.

  Commit:

  ```
  git commit -m "feat(discord): addressing-signal inference (dm | mention | channel | thread) with explicit precedence (#TBD-slice4)"
  ```

### Component E — Inbound emitter (Discord event → `InboundMessageNotification`)

- [ ] **Task E1 — `inbound_emitter.normalise` constructs `InboundMessageNotification`.**

  Files: Create `plugins/alfred_discord/inbound_emitter.py`; Create `tests/unit/plugins/alfred_discord/test_inbound_emitter_normalises.py`.

  **Failing test first.** Write `test_inbound_emitter_normalises.py`:

  1. Plain DM with text body only → `InboundMessageNotification(addressing_signal="dm", body={"content": "<text>"}, sub_payload_refs=[])`.
  2. Channel message with one embed → notification body carries the embed under `body.embeds[0]` verbatim (classifier promotion happens host-side, NOT in adapter).
  3. Message with attachment → `body.attachments[0]` populated; adapter does NOT download the attachment bytes (host-side classifier promotes the URL to a `ContentHandle`).
  4. Message with poll → `body.poll` populated.
  5. Message with sticker → `body.stickers` populated.
  6. Voice-message (Discord's audio attachment with `content_type` starting `audio/`) → flagged in `body.attachments` with the content type so the host-side classifier picks it up as `voice_message`.
  7. Forwarded-message reference → `body.message_reference` populated.
  8. Pinned-message reference (the message is in the channel's pinned set) → `body.message_reference` plus `body._alfred_pinned_marker: true` (an adapter-side hint so the host-side classifier can disambiguate forwarded vs pinned). The marker name starts with `_alfred_` to prevent collision with future Discord field names.
  9. Message in unconfigured channel without bot mention → `normalise()` returns `None`; caller skips emission.
  10. Edit events — `on_message_edit` → adapter emits a fresh `InboundMessageNotification` with the new content; the original is treated as a separate notification (Discord edits don't generate `update.inbound.message` per ADR-0024 — only `inbound.message` exists, edits become new messages with the same `platform_message_id` for idempotency check).

  Run: `uv run pytest tests/unit/plugins/alfred_discord/test_inbound_emitter_normalises.py -q`
  Expected: collection error.

  **Implementation.** Create `plugins/alfred_discord/inbound_emitter.py`:

  - `normalise(message: discord.Message, *, adapter_id: str) -> InboundMessageNotification | None`.
  - Calls `addressing_inference.infer_addressing_signal(message)`; returns `None` if signal is `None`.
  - Builds `body` dict with `content`, `embeds`, `attachments`, `poll`, `stickers`, `components`, `message_reference`, `_alfred_pinned_marker` fields.
  - `platform_user_id = str(message.author.id)`.
  - `received_at = message.created_at` (already timezone-aware in discord.py).
  - Sub-payload promotion is NOT done in-plugin; the adapter ships the raw fields and the host-side `DiscordSubPayloadClassifier` does the promotion.

  Run: `uv run pytest tests/unit/plugins/alfred_discord/test_inbound_emitter_normalises.py -q`
  Expected: 10 passed.

  Commit:

  ```
  git commit -m "feat(discord): inbound emitter normalises Discord events to InboundMessageNotification (#TBD-slice4)"
  ```

### Component F — Outbound handler + idempotency

- [ ] **Task F1 — Idempotency store (SQLite-backed, restart-survivable).**

  Files: Create `plugins/alfred_discord/idempotency_store.py`; Create `tests/unit/plugins/alfred_discord/test_idempotency_store.py`.

  **Failing test first.** Write `test_idempotency_store.py`:

  1. `store.record(idempotency_key, platform_message_id)` then `store.lookup(idempotency_key)` returns the recorded `platform_message_id`.
  2. Second `record` call with same key + different `platform_message_id` raises `IdempotencyConflictError`.
  3. Restart simulation: close the store, reopen with same path, `lookup` still returns the recorded id.
  4. TTL expiry: records past `ttl_hours=24` are pruned by `vacuum_expired()`; a vacuumed key returns `None` from `lookup`.
  5. Concurrent `record` race: two `asyncio.TaskGroup` calls with the same key → exactly one succeeds, one raises.
  6. SQLite WAL mode is enabled (concurrent reader-writer correctness).

  Run: `uv run pytest tests/unit/plugins/alfred_discord/test_idempotency_store.py -q`
  Expected: collection error.

  **Implementation.** Create `plugins/alfred_discord/idempotency_store.py`:

  - Single-table SQLite at `$XDG_RUNTIME_DIR/alfred/plugin-alfred.discord/idempotency.db`.
  - Schema: `(idempotency_key TEXT PRIMARY KEY, platform_message_id TEXT NOT NULL, recorded_at TIMESTAMPTZ NOT NULL)`.
  - `record(key, msg_id)` uses `INSERT … ON CONFLICT(idempotency_key) DO NOTHING` and checks the `RETURNING` shape; mismatch on existing row raises `IdempotencyConflictError`.
  - WAL mode set at first connection.

  Run: `uv run pytest tests/unit/plugins/alfred_discord/test_idempotency_store.py -q`
  Expected: 6 passed.

  Commit:

  ```
  git commit -m "feat(discord): SQLite-backed idempotency store with restart-survival (#TBD-slice4)"
  ```

- [ ] **Task F2 — `outbound_handler.handle` produces `OutboundMessageResult` discriminated union.**

  Files: Create `plugins/alfred_discord/outbound_handler.py`; Create `tests/unit/plugins/alfred_discord/test_outbound_handler.py`.

  **Failing test first.** Write `test_outbound_handler.py`:

  1. Happy path `addressing_mode="dm"`: `discord.User.send` mock returns a `Message(id=42)`; handler returns `_OutboundDelivered(outcome="delivered", platform_message_id="42")`.
  2. Happy path `addressing_mode="mention"`: handler sends to channel with `@user` prefix; returns `_OutboundDelivered`.
  3. Happy path `addressing_mode="channel"`: bare channel send; returns `_OutboundDelivered`.
  4. Happy path `addressing_mode="thread"`: sends to `discord.Thread`; returns `_OutboundDelivered`.
  5. `discord.HTTPException(status=429, retry_after=2.5)` → `_OutboundRetryable(outcome="retryable_failure", retry_after_seconds=3, error_class="discord_rate_limited")` (retry_after rounded up to nearest integer second).
  6. `discord.HTTPException(status=500)` → `_OutboundRetryable(outcome="retryable_failure", retry_after_seconds=5, error_class="discord_server_error")`.
  7. `discord.Forbidden` → `_OutboundTerminal(outcome="terminal_failure", error_class="discord_forbidden", detail_redacted="<DLP-scanned, ≤256 chars>")`.
  8. `discord.NotFound` (channel deleted) → `_OutboundTerminal(outcome="terminal_failure", error_class="discord_not_found", ...)`.
  9. **Idempotency dedup**: same `idempotency_key` submitted twice → second call returns the same `_OutboundDelivered(platform_message_id=…)` without calling `discord.send` again. Verified by mock call-count.
  10. Idempotency dedup survives plugin restart: SQLite store records persist; first call after restart returns the dedup result without re-sending.
  11. Pydantic validation refuses a constructed `_OutboundDelivered(outcome="delivered", retry_after_seconds=2)` (cross-shape rejection — `retry_after_seconds` is only on `_OutboundRetryable`).
  12. `addressing_mode="thread"` against a TUI target (no threads) — host-side check refuses with `COMMS_ADDRESSING_DRIFT_FIELDS` (this is host-side, not adapter; the test asserts the adapter accepts the request unconditionally because the host is the gatekeeper).

  Run: `uv run pytest tests/unit/plugins/alfred_discord/test_outbound_handler.py -q`
  Expected: collection error.

  **Implementation.** Create `plugins/alfred_discord/outbound_handler.py`:

  - `async def handle(req: OutboundMessageRequest) -> OutboundMessageResult`.
  - Steps:
    1. `existing = idempotency_store.lookup(req.idempotency_key)` — if present, return cached `_OutboundDelivered`.
    2. Resolve `discord.User` / `discord.TextChannel` / `discord.Thread` per `target_platform_id` + `addressing_mode`.
    3. For `mention` mode, prefix the body with `<@{user_id}>` (Discord's mention syntax).
    4. `sent = await target.send(req.body, ...)` wrapped in try/except.
    5. On success: `idempotency_store.record(req.idempotency_key, str(sent.id))`; return `_OutboundDelivered`.
    6. On `discord.HTTPException` with `status==429`: read `retry_after`; return `_OutboundRetryable`.
    7. On other `HTTPException` 5xx: return `_OutboundRetryable` with `retry_after_seconds=5`.
    8. On `discord.Forbidden` / `discord.NotFound` / `discord.InvalidData`: return `_OutboundTerminal`.
  - `detail_redacted` field is NOT computed in-plugin (DLP scan is a host-side concern per spec §2.1); the plugin sets `detail_redacted = str(exc)[:256]` raw, and the host runs DLP against it when extracting from the JSON-RPC response. (Open question: should adapters carry an in-plugin DLP-lite that pre-redacts? Per spec, no — DLP placement is at wire boundaries and `_OutboundTerminal.detail_redacted` is sourced from the adapter side. Track this as a Slice-5 follow-up; for now the host re-scans on receive as defence-in-depth.)

  Run: `uv run pytest tests/unit/plugins/alfred_discord/test_outbound_handler.py -q`
  Expected: 12 passed.

  Commit:

  ```
  git commit -m "feat(discord): outbound handler emits OutboundMessageResult discriminated union with idempotency dedup (#TBD-slice4)"
  ```

### Component G — Notification emitters (rate-limit / binding / crash)

- [ ] **Task G1 — `rate_limit_emitter` emits `RateLimitSignal` on 429.**

  Files: Create `plugins/alfred_discord/rate_limit_emitter.py`; Create `tests/unit/plugins/alfred_discord/test_rate_limit_emitter.py`.

  **Failing test first.** Write `test_rate_limit_emitter.py`:

  1. `discord.HTTPException(status=429, retry_after=3.5)` raised inside an `outbound.message` handler → emitter writes one `RateLimitSignal` JSON-RPC notification to the stdout sink with `retry_after_seconds=4` (rounded up).
  2. The notification carries the correct `platform_endpoint` (e.g. `"discord.com:channel.send"`) derived from `exc.response.url`.
  3. Two rapid 429s within the same retry-after window emit only one signal (debounced via in-memory state to prevent storm).
  4. After a successful outbound following a 429, the emitter's debounce state clears so the next 429 emits a fresh signal.
  5. Signal emission does NOT block the `outbound.message` handler from returning its `_OutboundRetryable` — the signal is fire-and-forget on a separate `asyncio.Task` to avoid coupling the rate-limit observation latency to the outbound dispatch latency.

  Run: `uv run pytest tests/unit/plugins/alfred_discord/test_rate_limit_emitter.py -q`
  Expected: collection error.

  **Implementation.** Create `plugins/alfred_discord/rate_limit_emitter.py`:

  - `RateLimitEmitter` is constructed with a `notification_sink: NotificationSink` (a Protocol that takes a JSON-RPC notification dict and writes it to stdout for the host to read).
  - On 429 in `outbound_handler`, after returning `_OutboundRetryable`, the handler ALSO emits the `RateLimitSignal` notification with `platform_endpoint` from `exc.response.url`.
  - The signal is emitted FROM the adapter, not from the host's outbound dispatcher — the adapter has the raw 429 detail; the host's `OutboundQueue.pause(adapter_id, retry_after_seconds)` is keyed off the notification flowing host-ward.
  - Debounce: per-`platform_endpoint` last-signalled timestamp; if a new 429 hits within `last_retry_after_seconds`, suppress the second signal.

  Run: `uv run pytest tests/unit/plugins/alfred_discord/test_rate_limit_emitter.py -q`
  Expected: 5 passed.

- [ ] **Task G2 — `binding_emitter` emits `BindingRequestNotification` on first-contact unrecognised user.**

  Files: Create `plugins/alfred_discord/binding_emitter.py`; Create `tests/unit/plugins/alfred_discord/test_binding_emitter.py`.

  **First-contact mechanics (resolved at this PR — Open Question 5 below also flags this for reviewer confirmation).** Spec §8.2's `process_inbound_message` calls `_emit_binding_request(notification, audit_writer)` when `identity_resolver.resolve(...)` returns `None`. That host-side helper:

  1. Generates a fresh `verification_phrase` from host-side randomness (`secrets.token_urlsafe(8)`); the phrase is short, human-readable (e.g. `"alfred-fox-violet"`), and lives in a host-side `pending_bindings` table with a 10-minute TTL.
  2. Sends an outbound DM (via the same `outbound.message` request flow) to the unbound user containing the phrase + binding instructions ("Reply with this phrase to bind your Discord account to AlfredOS user `<canonical>`").
  3. Records the pending binding so a subsequent inbound containing the phrase can complete the binding.
  4. Once the user replies with the phrase, the host's `IdentityResolver` performs the bind, and the next inbound from that user resolves normally.
  5. The plugin's `binding_emitter` is the **receive-side**: it does NOT generate phrases. It exists to handle a separate inbound-side flow where the platform user *first* types a phrase the host has already issued out-of-band (e.g. via TUI: operator runs `alfred user bind --discord <snowflake>`, the TUI issues a phrase, operator pastes it into Discord, the plugin receives the inbound and the host's `inbound.message` handler recognises the phrase pattern and triggers the bind).

  **Failing test first.** Write `test_binding_emitter.py`:

  1. Inbound text matching the pending-binding regex (`^alfred-[a-z]+-[a-z]+$`) from an unbound `platform_user_id` → plugin emits `BindingRequestNotification(adapter_id, platform_user_id, verification_phrase=<the matched phrase>, platform_metadata={"username": ..., "discriminator": ...})`.
  2. Same regex match from an already-bound `platform_user_id` → no binding notification (regular inbound flow).
  3. Inbound text NOT matching the pattern → no binding notification.
  4. The notification's `platform_metadata` carries only the public-facing Discord profile fields (`username`, `display_name`, `avatar_hash`, `joined_at` of the relevant guild); private fields (`email`, `phone`) are never populated even if discord.py surfaces them.
  5. The emitted notification's `verification_phrase` matches the inbound text byte-exactly (the host correlates against its pending-bindings table).

  Per spec §8.10, `COMMS_BINDING_REQUESTED_FIELDS` carries `verification_phrase_hash` not the raw phrase — the hash is computed host-side using `audit_hash.hash_verification_phrase(...)` from Component A2.

  Run: `uv run pytest tests/unit/plugins/alfred_discord/test_binding_emitter.py -q`
  Expected: 5 passed.

- [ ] **Task G3 — `crash_emitter` emits `CrashedNotification` from a top-level except handler.**

  Files: Create `plugins/alfred_discord/crash_emitter.py`; Create `tests/unit/plugins/alfred_discord/test_crash_emitter.py`.

  **Failing test first.** Write `test_crash_emitter.py`:

  1. Synthetic exception raised inside the MCP server's main loop → emitter writes one `CrashedNotification(adapter_id, error_class="RuntimeError", detail="<redacted>")` to stdout, flushes, then `sys.exit(1)` runs.
  2. The `detail` field is `str(exc)[:512]` with a Slice-2-shipped DLP-lite redactor applied before truncation — secrets-shape patterns (e.g. `Bearer abc123`) are replaced with `[REDACTED]`. The redactor is a thin pre-scan; the host re-runs full DLP on receive as defence-in-depth.
  3. `KeyboardInterrupt` and `SystemExit` exceptions do NOT trigger the crash notification (they're operator-initiated shutdowns); the emitter re-raises them.
  4. If the notification write itself fails (broken pipe — host already gone), the emitter swallows the secondary exception and proceeds to `sys.exit(1)` regardless. A failed crash-notification is logged via structlog to a fallback file at `$XDG_RUNTIME_DIR/alfred/plugin-alfred.discord/crash-fallback.log` (best-effort).
  5. Multiple simultaneous crashes (e.g. exception during exception handling) emit only one `CrashedNotification` and exit; an `_emitter_lock` guards against re-entry.

  Run: `uv run pytest tests/unit/plugins/alfred_discord/test_crash_emitter.py -q`
  Expected: 5 passed.

  **Implementation.** Create `plugins/alfred_discord/crash_emitter.py`:

  - Wraps the MCP server's main loop in a try/except.
  - On uncaught exception:
    1. Acquire `_emitter_lock` (re-entrant guard).
    2. Pre-scan `str(exc)` with a Slice-2-shipped DLP-lite redactor (defence-in-depth — the host re-scans on receive).
    3. Emit `CrashedNotification(adapter_id, error_class=type(exc).__qualname__, detail=redacted)`.
    4. Flush stdio.
    5. `sys.exit(1)` so the host's supervisor breaker triggers (spec §8.4 `Supervisor.trip_breaker(..., reason="comms_handler_repeated_failures")` after 3-in-5min threshold; the breaker shape is consumed by PR-S4-8 but the trigger originates here).

  Commit:

  ```
  git commit -m "feat(discord): rate-limit + binding + crash notification emitters with debounce + DLP-lite + re-entry guard (#TBD-slice4)"
  ```

### Component H — Plugin server entry + Discord gateway

- [ ] **Task H1 — `discord_gateway.py` `commands.Bot` subclass with reconnect.**

  Files: Create `plugins/alfred_discord/discord_gateway.py`; Create `tests/unit/plugins/alfred_discord/test_discord_gateway_reconnect.py`.

  **Failing test first.** Write `test_discord_gateway_reconnect.py` (using `discord.py` test doubles and a fake event loop):

  1. `on_message(msg)` calls `inbound_emitter.normalise(msg)`; if non-None, the notification is enqueued for stdio emission via the test-injected sink. Mock call-count verifies one enqueue per non-None normalise.
  2. `on_message` from the bot's own user is ignored (no normalise call, no enqueue).
  3. `on_message_edit(before, after)` enqueues a notification with the `after` content (Discord edits become fresh notifications per spec §8.6).
  4. `on_disconnect` followed by `on_ready` increments a reconnect counter; the bot resets the counter to zero on the first inbound after reconnect.
  5. Exponential backoff schedule: `min(2 ** attempts, 60)` seconds with jitter ±20% to avoid thundering herd; verified via patched `asyncio.sleep`.
  6. `on_error(event, *args, **kwargs)` (discord.py's catch-all event-handler exception hook) forwards to `crash_emitter` if the exception is uncaught.

  Run: `uv run pytest tests/unit/plugins/alfred_discord/test_discord_gateway_reconnect.py -q`
  Expected: collection error.

  **Implementation.** Create `plugins/alfred_discord/discord_gateway.py`:

  - `AlfredDiscordBot(commands.Bot)` subclass.
  - Intents declared up-front:
    - `intents.guilds = True` (channel + thread metadata).
    - `intents.messages = True` + `intents.message_content = True` (required for `on_message`).
    - `intents.dm_messages = True` (DM support).
    - `intents.guild_messages = True` (mention + channel modes).
    - All other intents off (least-privilege; voice/presence/integration intents not consumed).
  - `on_message` / `on_message_edit` listeners enqueue normalised notifications.
  - `on_disconnect` / `on_ready` track reconnect attempts.
  - `on_error` forwards to `crash_emitter`.
  - Library decision (spec §15 Open Question 2): `discord.py>=2.4,<3` — verified already in `pyproject.toml:29` per the verification gate; this PR does not add a new dependency.

  Run: `uv run pytest tests/unit/plugins/alfred_discord/test_discord_gateway_reconnect.py -q`
  Expected: 6 passed.

  Commit:

  ```
  git commit -m "feat(discord): commands.Bot subclass with intent declarations + reconnect + crash forwarding (#TBD-slice4)"
  ```

- [ ] **Task H2 — `server.py` MCP server entry point ties everything together.**

  Files: Create `plugins/alfred_discord/server.py`; Create `tests/unit/plugins/alfred_discord/test_server_smoke.py`.

  **Failing test first.** Write `test_server_smoke.py`:

  1. `serve()` is invokable; calling it under a test-injected fake MCP transport completes initialisation without raising.
  2. The constructed `Session`'s request-method dispatch table maps four method names exactly: `lifecycle.start`, `lifecycle.stop`, `adapter.health`, `outbound.message`. No fifth method is registered. No method is missing.
  3. The constructed `Session` is wired to the four notification emitters from Component G.
  4. The `IdempotencyStore` is constructed at the path `$XDG_RUNTIME_DIR/alfred/plugin-alfred.discord/idempotency.db` (verified by patching `os.environ`).
  5. The `AlfredDiscordBot` is constructed but `start()` is NOT called from `serve()` directly — `start()` runs on the first `lifecycle.start` request (lazy boot per Component C2 test 1).
  6. Manifest is loaded and parsed at `serve()` time; missing manifest raises with a clear `ManifestNotFoundError` from `t("discord.manifest.missing")`.

  Run: `uv run pytest tests/unit/plugins/alfred_discord/test_server_smoke.py -q`
  Expected: collection error.

  **Implementation.** Create `plugins/alfred_discord/server.py`:

  ```text
  - if __name__ == "__main__": asyncio.run(serve())
  - serve() steps:
      1. Read manifest.toml from the plugin dir.
      2. Construct AlfredDiscordBot with the intent set from H1.
      3. Construct IdempotencyStore at $XDG_RUNTIME_DIR/alfred/plugin-alfred.discord/idempotency.db.
      4. Construct OutboundHandler(bot, store).
      5. Construct RateLimitEmitter / BindingEmitter / CrashEmitter (Component G)
         backed by a shared stdout NotificationSink.
      6. Construct Lifecycle(bot, secret_broker_proxy, manifest) where
         secret_broker_proxy is a thin client that asks the host for
         the resolved secret value at lifecycle.start (the broker
         substitutes at the JSON-RPC dispatch boundary per spec §7.8).
      7. Construct the MCP Session from the SDK with the request-method
         dispatch table.
      8. Wrap the Session's main loop in try/except via CrashEmitter.
      9. Run the Session until stdio closes (host-initiated shutdown)
         or an uncaught exception triggers CrashEmitter.
  ```

  Run: `uv run pytest tests/unit/plugins/alfred_discord/test_server_smoke.py -q`
  Expected: 6 passed.

  Commit:

  ```
  git commit -m "feat(discord): MCP server entry with lazy lifecycle.start + 4-method dispatch table (#TBD-slice4)"
  ```

### Component I — Adversarial corpus

- [ ] **Task I1 — Three new adversarial entries under `comms_identity_boundary`.**

  Files:

  - `tests/adversarial/comms_identity_boundary/cib-2026-001-forged-platform-metadata.yaml`
  - `tests/adversarial/comms_identity_boundary/cib-2026-002-cross-adapter-id-collision.yaml`
  - `tests/adversarial/comms_identity_boundary/cib-2026-003-discord-embed-injection.yaml`

  Each YAML follows the Slice-3 adversarial schema:

  ```yaml
  id: cib-2026-001
  title: Adversary plants forged canonical_user_id in platform_metadata
  category: comms_identity_boundary
  ingestion_path: comms_inbound_message
  payload: |
      {
          "method": "inbound.message",
          "params": {
              "adapter_id": "discord-alfred",
              "platform_user_id": "111111111111111111",
              "platform_metadata": {
                  "canonical_user_id": "user:operator"
              },
              "body": {"content": "hello"},
              "received_at": "2026-06-07T10:00:00Z",
              "addressing_signal": "dm"
          }
      }
  expected_outcome: boundary_refused
  expected_audit_constants:
      - COMMS_INBOUND_T3_PROMOTION_FIELDS
  assertions:
      - "The orchestrator's view of canonical_user_id MUST come from
         IdentityResolver.resolve(adapter_id, platform_user_id), NOT
         from notification.platform_metadata.canonical_user_id"
      - "The forged field MUST NOT appear in any audit row"
  ```

  Similar structure for `cib-2026-002` (two distinct adapters returning the same `platform_user_id` must resolve to two distinct canonical user IDs; the resolver keys on `(adapter_id, platform_user_id)`) and `cib-2026-003` (Discord embed with apparent injection text — must promote to `ContentHandle`, never reaches orchestrator as raw bytes).

  Run: `uv run pytest tests/adversarial -k cib -q`
  Expected: 3 passed (the adversarial harness from Slice-3 runs each YAML through the orchestrator and asserts the declared outcome).

  Commit:

  ```
  git commit -m "test(adversarial): cib-2026-001/002/003 comms identity boundary payloads (#TBD-slice4)"
  ```

### Component J — Merge-blocking integration tests

- [ ] **Task J1 — `tests/integration/test_discord_addressing_modes.py`.**

  Files: Create `tests/integration/test_discord_addressing_modes.py`.

  This test boots the plugin, mocks the Discord gateway (using `discord.py`'s test-double surface or a custom WSS mock), wires the host's `AlfredPluginSession` + `IdentityResolver` + reference `Orchestrator`, and round-trips one inbound + one outbound per addressing mode (4 modes × 2 directions = 8 sub-cases):

  1. DM inbound: synthetic DM event → `addressing_signal="dm"` → `process_inbound_message` resolves user → `orchestrator.ingest` records the canonical user.
  2. DM outbound: orchestrator emits reply with `addressing_mode="dm"` → adapter sends to `discord.User` → `_OutboundDelivered`.
  3. Mention inbound: synthetic channel message mentioning bot → `addressing_signal="mention"`.
  4. Mention outbound: orchestrator emits `addressing_mode="mention"` → adapter prefixes `<@user_id>` and sends.
  5. Channel inbound/outbound (configured channel, no mention).
  6. Thread inbound/outbound.
  7. **Assertion**: the captured stdio frames contain `addressing_signal` matching the mode in each case.
  8. **Assertion**: the captured `OutboundMessageResult` has `outcome="delivered"` in each case.

  Promoted to required-status-check via `gh api` per slice-index §3 (ops-007 — promotion happens in this PR, not bulked into PR-S4-11).

  Run: `uv run pytest tests/integration/test_discord_addressing_modes.py -q`
  Expected: 8 passed.

  Commit:

  ```
  git commit -m "test(integration): test_discord_addressing_modes — 4 modes × inbound + outbound round-trip (#TBD-slice4)"
  ```

- [ ] **Task J2 — `tests/integration/test_discord_subpayload_promotion.py`.**

  Files: Create `tests/integration/test_discord_subpayload_promotion.py`.

  This test exercises each of the nine sub-payload kinds end-to-end:

  - Synthetic Discord message constructed per sub-payload kind.
  - Plugin emits `InboundMessageNotification` carrying the raw sub-payload.
  - Host-side `InboundContentScanner` runs `DiscordSubPayloadClassifier`.
  - Assert one `ContentHandle` is emitted per sub-payload.
  - Assert the orchestrator's view has `{"$content_handle_id": "<uuid>"}` in place of the raw sub-payload.
  - Assert dereferencing the handle via the content store returns the original sub-payload JSON.
  - Assert `COMMS_INBOUND_T3_PROMOTION_FIELDS` audit row carries the correct `sub_payload_kinds` frozenset.

  Total: 9 sub-payload kinds × 4 assertions = 36 sub-assertions across 9 test cases.

  Promoted to required-status-check via `gh api` in this PR.

  Run: `uv run pytest tests/integration/test_discord_subpayload_promotion.py -q`
  Expected: 9 passed.

  Commit:

  ```
  git commit -m "test(integration): test_discord_subpayload_promotion — 9 kinds → ContentHandle round-trip (#TBD-slice4)"
  ```

### Component J3 — End-to-end fault-injection round-trip

- [ ] **Task J3 — `tests/integration/test_discord_rate_limit_pause_resume.py`.**

  Files: Create `tests/integration/test_discord_rate_limit_pause_resume.py`.

  This test exercises the full rate-limit honour path:

  1. Boot the plugin + host with mock Discord gateway.
  2. Submit five rapid outbound messages via the host's `OutboundQueue`.
  3. The mock Discord backend returns 429 on the third call with `retry_after=2.0`.
  4. Adapter emits `_OutboundRetryable(retry_after_seconds=2)` for the third call AND emits a `RateLimitSignal` notification.
  5. Host's `RateLimitHandler` calls `OutboundQueue.pause("discord-alfred", retry_after_seconds=2)`.
  6. Calls 4 and 5 are queued; the queue does NOT submit them during the 2-second pause window.
  7. After 2 seconds + jitter, the queue auto-resumes; calls 4 and 5 deliver successfully.
  8. Assert `COMMS_RATE_LIMIT_SIGNAL_FIELDS` audit row was emitted exactly once with `retry_after_seconds=2`.
  9. Assert the third call's `idempotency_key` is preserved on the retry (host's retry submits the same key; adapter's idempotency store dedupes — same `_OutboundDelivered.platform_message_id` returned both times after success).

  Run: `uv run pytest tests/integration/test_discord_rate_limit_pause_resume.py -q`
  Expected: 1 passed (single end-to-end test with 9 assertions).

  This integration test is NOT one of the two required-status-check gates from the spec, but it exercises the new `OutboundQueue.pause` surface end-to-end and is run by CI as part of the regular integration tier.

  Commit:

  ```
  git commit -m "test(integration): test_discord_rate_limit_pause_resume — full 429 → pause → resume cycle (#TBD-slice4)"
  ```

### Component K — Required-status-check promotion + AST guard updates

- [ ] **Task K1 — Promote both integration tests to required status checks.**

  Run, after the tests are green on the PR's CI:

  ```bash
  # Read the existing required-checks manifest
  cat required-checks.json

  # Add the two new gates
  gh api repos/MrReasonable/AlfredOS/branches/main/protection \
      --method PUT \
      --field required_status_checks[contexts][]=test_discord_addressing_modes \
      --field required_status_checks[contexts][]=test_discord_subpayload_promotion \
      --field required_status_checks[strict]=true
  ```

  Update `required-checks.json` to add the two new entries with the same shape as existing Slice-3 entries; commit the change in this PR per ops-007 closure (promotion happens in the shipping PR, not bulked into S4-11).

  Commit:

  ```
  git commit -m "ci: promote test_discord_addressing_modes + test_discord_subpayload_promotion to required (#TBD-slice4)"
  ```

- [ ] **Task K2 — AST guard updates for the new `comms.adapter.*` hookpoints.**

  Files: Update `tests/unit/hooks/test_carrier_tier_required.py` (PR-S4-3-shipped) — if the AST guard runs a list-of-expected-hookpoints discovery, add the two new hookpoint names.

  Files: Update `tests/unit/comms/test_no_direct_adapter_imports.py` — confirm the existing AST guard still catches fresh imports of `alfred.comms.discord` (so the dormancy claim holds through PR-S4-9).

  Run: `uv run pytest tests/unit/hooks/test_carrier_tier_required.py tests/unit/comms/test_no_direct_adapter_imports.py -q`
  Expected: all green.

  Commit (only if edits needed):

  ```
  git commit -m "test(hooks): AST guard recognises comms.adapter.binding_requested + rate_limit_signal (#TBD-slice4)"
  ```

### Component L — Documentation

- [ ] **Task L1 — Update `docs/glossary.md` for the new terms.**

  Files: Edit `docs/glossary.md`.

  Add entries for:

  - `DiscordSubPayloadClassifier` — host-side classifier; recognises nine Discord sub-payload kinds; emits `ContentHandle` for each; lives at `src/alfred/comms_mcp/classifiers/discord.py`; registered via `@register_classifier(kind="discord", name="discord_sub_payloads")`.
  - `OutboundQueue` — host-side per-adapter FIFO with `pause(adapter_id, retry_after_seconds)` / `resume(adapter_id)` / auto-resume after retry-after; lives at `src/alfred/comms_mcp/outbound_queue.py`; introduced in PR-S4-9 to honour `adapter.rate_limit_signal` notifications.
  - `addressing_signal` / `addressing_mode` — the inbound (signal) and outbound (mode) wire `Literal["dm","mention","channel","thread"]` values mapping onto PRD §6.8's three addressing concepts; the four wire values + three concepts mapping table is the load-bearing reference.

  Some of these are already in PR-S4-0a's `docs/glossary.md` Slice-4 additions (`DiscordSubPayloadClassifier`, `OutboundQueue` are explicitly named in spec §13.1). PR-S4-9 verifies the entries land with the correct file paths now that the code exists.

  Commit:

  ```
  git commit -m "docs(glossary): DiscordSubPayloadClassifier + OutboundQueue + addressing terms (#TBD-slice4)"
  ```

- [ ] **Task L2 — Issue-number reference for every commit.**

  Per AlfredOS conventional-commit gate (per #204's discovered requirement), every commit must reference an issue number. PR-S4-9 should land against issue `#TBD-slice4-pr-s4-9` (filed at PR creation time, mirroring the Slice-3 pattern). Replace `#TBD-slice4` placeholders with the real issue number once filed.

---

## §6 Quality gates before merge

PR-S4-9 must clear, in order:

1. `make check` — ruff + format + mypy strict + pyright + unit tests + AST guards. Mandatory. Run on every push; CI promotion of the gating jobs to required-status-check follows the `author-gating-workflow` discipline (least-privilege permissions, workflow-injection-safe env passing, concurrency caps).
2. `uv run pytest tests/adversarial -q` — full adversarial suite. **Required** because this PR touches multiple security boundaries:
   - Outbound DLP placement (the wire-boundary scan at `OutboundQueue.submit`).
   - Identity-resolver consultation (the `cib-2026-001` forged-platform-metadata defence).
   - Sub-payload promotion to `ContentHandle` (`cib-2026-003` Discord-embed injection defence).
   - Hookpoint registration with new `carrier_tier` field (PR-S4-3 AST guard).
   - The `audit.hash_pepper` lookup (broker access pattern; missing-pepper refusal).
3. `uv run pytest tests/integration/test_discord_addressing_modes.py tests/integration/test_discord_subpayload_promotion.py tests/integration/test_discord_rate_limit_pause_resume.py -q` — the two merge-blocking gates plus the supporting fault-injection round-trip.
4. **100% line + branch coverage** on these new trust-boundary files (per spec §14 criterion 11 + slice-index §5). Measurement runs as part of `make check`; failing coverage is a release blocker, not advisory:
   - `src/alfred/comms_mcp/classifiers/discord.py` — the host-side sub-payload classifier; trust-boundary because it decides what becomes a `ContentHandle` (T3) versus what flows verbatim to the orchestrator.
   - `src/alfred/comms_mcp/outbound_queue.py` — pause/resume is outbound rate-limit honour; a bug here is outbound-storm risk.
   - `src/alfred/comms_mcp/audit_hash.py` — the HMAC-with-pepper wrapper; a bug here breaks audit-row correlation invariants.
   - `plugins/alfred_discord/outbound_handler.py` — idempotency dedup is trust-boundary code (duplicate-send is a user-trust violation; under-send is a delivery-guarantee violation).
   - `plugins/alfred_discord/inbound_emitter.py` — the inbound wire-format adapter; a bug here mistags Discord events or strips sub-payloads silently.
5. Conventional-commit `#NNN` reference gate per #204 — every commit references the slice-4 issue.
6. Markdown lint via `.markdownlint-cli2.jsonc` — covers any spec/doc edits in this PR.
7. The two new integration tests (`test_discord_addressing_modes`, `test_discord_subpayload_promotion`) are promoted to required-status-check via `gh api` BEFORE the merge proceeds (per ops-007 closure — promotion is part of this PR, not deferred to PR-S4-11). Verified by re-reading `required-checks.json` after the `gh api` call and confirming both gate names are present.
8. `make docs-check` (Slice-3-shipped) — covers cross-link integrity for any glossary or runbook edits this PR makes.
9. `uv run pytest tests/unit/comms/test_no_direct_adapter_imports.py -q` — confirms the existing AST guard still catches fresh imports of `alfred.comms.discord`, so the legacy module's dormancy claim holds through this PR.

---

## §7 Rollback strategy

PR-S4-9 is independently revertable while it remains the most recent merge on `main`. The rollback playbook:

1. **Open a revert PR** against the SHA of PR-S4-9's merge commit. Standard `git revert -m 1 <sha>` produces a clean revert because PR-S4-9 ships no Alembic migrations and no `state.git` proposals.
2. **Remove the two new required-status-check gates** before the revert lands, because the revert deletes the integration test files and the still-required gates would block the revert PR itself. Run:

   ```bash
   gh api repos/MrReasonable/AlfredOS/branches/main/protection \
       --method PUT \
       --input <(jq '.required_status_checks.contexts -= ["test_discord_addressing_modes","test_discord_subpayload_promotion"]' \
                   required-checks.json)
   ```

3. **Update `required-checks.json`** to drop the two entries so the post-revert tracked manifest matches branch protection state. Commit the manifest update with the revert.
4. **PR-S4-10 dependency check.** PR-S4-10 (TUI flag-day) consumes `OutboundQueue` for its outbound dispatch and shares the comms-MCP surfaces this PR introduces. If PR-S4-10 has already merged, the revert must EITHER also revert PR-S4-10 OR stub `OutboundQueue` with a no-op pass-through in a follow-up PR. The escalation path: reverting PR-S4-9 alone with PR-S4-10 still on `main` breaks the TUI adapter at runtime.
5. **Verify the legacy `src/alfred/comms/discord.py` still works** as the operator's Discord surface (the AST-guard at `tests/unit/comms/test_no_direct_adapter_imports.py` continues to forbid fresh imports from new code, but the legacy module's existing wiring is undisturbed by this PR).

Per-component revert granularity:

- `plugins/alfred_discord/` deletion restores the absence of the plugin; the daemon's `bin/alfred-plugin-launcher.sh` simply does not spawn it (Discord adapter is opt-in per operator config; production environments without the plugin run fine).
- `src/alfred/comms_mcp/classifiers/discord.py` deletion removes the registered classifier; `REQUIRED_CLASSIFIERS_BY_KIND["discord"]` becomes a broken reference — PR-S4-9's revert must also revert PR-S4-8's `"discord"` entry (or stub the classifier with a no-op pass-through). The AST guard at `tests/unit/comms_mcp/test_required_classifiers_complete.py` will fail otherwise.
- `src/alfred/comms_mcp/outbound_queue.py` deletion removes the new primitive. PR-S4-10 (which also consumes `OutboundQueue` for the TUI adapter) depends on this PR; reverting PR-S4-9 with PR-S4-10 still on `main` forces reverting or no-op-stubbing PR-S4-10's queue consumption.
- The two new hookpoints (`comms.adapter.binding_requested` + `comms.adapter.rate_limit_signal`) are observation-only (`fail_closed=False`); removing them does not break any required production action — subscribers (operator dashboards, alerting) silently lose the events.
- Adversarial corpus entries `cib-2026-001/002/003` revert cleanly (YAML deletion); the `_PREFIX_TO_CATEGORY` `"cib"` prefix stays registered (PR-S4-0a shipped) so future Slice-5 corpus authors can reuse the category.
- `gh api` required-status-check promotions are reversible via the same `gh api` surface with the `contexts[]=` flag removed (step 2 above).
- `docs/glossary.md` entries for `DiscordSubPayloadClassifier` / `OutboundQueue` revert cleanly (PR-S4-0a's initial entries persist; only this PR's path-pointer updates revert).

**Non-revertable side-effects:** none. PR-S4-9 ships no Alembic migrations (those live in PR-S4-0b), no `state.git` proposals, no irreversible audit-log writes (the audit rows are forward-only, but reverting the code that emits them does not corrupt the existing log; the new audit-row schemas remain registered constants from PR-S4-0a).

**Forward-only side-effects to be aware of:**

- New entries in the `operator_sessions` table from any operator who exercises the Discord adapter during the PR's lifetime persist across the revert (PR-S4-5-shipped table; not modified by this PR).
- `audit.hash_pepper` once bootstrapped by PR-S4-0b remains in the broker's secret vault.
- The idempotency-store SQLite files at `$XDG_RUNTIME_DIR/alfred/plugin-alfred.discord/idempotency.db` persist on the operator's filesystem after revert; safe to leave (they're ephemeral state, not configuration).

---

## §8 Open questions for the reviewer

These are flagged for `/review-pr` at PR open time:

1. **`discord.py` library decision (spec §15 open question 2).** This PR commits to `discord.py>=2.4,<3` (already in `pyproject.toml`). Alternatives (`nextcord`, `disnake`, `pycord`) were considered; the existing dep tip the scale. Open if a reviewer surfaces a maintenance concern.
2. **In-plugin DLP-lite vs host-side-only DLP.** Spec §2.1 places DLP at wire boundaries (host-side). PR-S4-9 follows that discipline: the adapter's `_OutboundTerminal.detail_redacted` field carries raw `str(exc)[:256]` from the adapter, and the host re-runs DLP on receive. A defence-in-depth alternative is to add an in-plugin DLP-lite scan before the notification is emitted. Deferred to Slice 5 unless the reviewer surfaces a concrete leak risk; tracked in the Slice-5 backlog.
3. **`outbound.message` ordering across pause/resume.** If the host submits messages A→B→C and `OutboundQueue.pause` lands between B and C, on resume the order is A→B→C (FIFO). But if the adapter completes A→B during the pause window (the pause was server-side, not adapter-side), the order observed by Discord is A→B (during pause window) →C (after resume). This matches Discord's "send order in channel" expectation. Reviewer: confirm this matches PRD §6.8's group-mode ordering invariant.
4. **`comms.outbound.send` hookpoint (spec §15 open question 9).** Spec §15 flags this as a Plan-time decision at PR-S4-8. PR-S4-9 inherits PR-S4-8's choice; if PR-S4-8 deferred it, PR-S4-9 should NOT add it speculatively.
5. **First-contact binding flow ownership split between PR-S4-8 (host orchestration) and PR-S4-9 (adapter wire-up).** Component G2 flags an ambiguity: the spec §8.1 wire schema carries `verification_phrase` on the notification but doesn't explicitly state which side computes it. PR-S4-9's implementation assumes the host computes (since the host owns identity state) and the adapter relays. If the reviewer prefers adapter-side phrase generation, the wire is unchanged but the responsibility table shifts.
6. **`_alfred_pinned_marker` body-field name (Component E1, sub-payload kind 8 — pinned-ref).** Discord doesn't natively flag pinned vs forwarded references in `message_reference`; the adapter sets a marker. The name uses a leading underscore + `_alfred_` namespace to avoid collision with future Discord field names. If a reviewer prefers a different namespace convention (e.g. `__alfred__.pinned: true` to mirror Python's dunder namespace), the rename is mechanical.

---

## §9 References

- Spec: [`docs/superpowers/specs/2026-06-06-slice-4-design.md`](../specs/2026-06-06-slice-4-design.md) — §8.5, §8.6, §8.10, §10, §11.5, §14.
- Slice index: [`docs/superpowers/plans/2026-06-07-slice-4-index.md`](2026-06-07-slice-4-index.md) — §3 cross-PR contracts, §4 integration test gate, §5 quality gates.
- ADR-0016 (status flips at PR-S4-11 graduation) — Discord+TUI comms-MCP rewrite.
- ADR-0024 (status: Accepted at PR-S4-0a) — Comms-MCP wire contract; full body lives in PR-S4-0a.
- PR-S4-8 plan: [`2026-06-07-slice-4-pr-s4-8-comms-mcp-foundations.md`](2026-06-07-slice-4-pr-s4-8-comms-mcp-foundations.md) — defines the wire schemas, handlers, classifier registry, `process_inbound_message`, `BurstLimiter`, and the `Supervisor.request_plugin_restart` / `Supervisor.trip_breaker` surfaces consumed here.
- PR-S4-10 plan: [`2026-06-07-slice-4-pr-s4-10-tui-mcp-adapter-flag-day.md`](2026-06-07-slice-4-pr-s4-10-tui-mcp-adapter-flag-day.md) — consumes `OutboundQueue` for the TUI; deletes legacy `src/alfred/comms/`.
- Template: [`2026-05-31-slice-3-pr-s3-5-web-fetch.md`](2026-05-31-slice-3-pr-s3-5-web-fetch.md) — TDD task discipline, file-table shape, adversarial corpus pattern.

---

## §10 Slice-5 backlog seeded from this PR

To open as tracking issues when Slice 5 kicks off:

- **In-plugin DLP-lite for `_OutboundTerminal.detail_redacted`** — defence-in-depth at the adapter side before the host's wire-boundary DLP runs (Open Question 2).
- **`comms.outbound.send` hookpoint** — if PR-S4-8 deferred, revisit when an operator surfaces a need for outbound observation beyond the existing `OutboundDlp` audit-emit path (Open Question 4).
- **Adapter-side `--cleanup` mode** — `plugins/alfred_discord/server.py --cleanup` mode that flushes idempotency store of expired entries on-demand (currently a TTL-based vacuum runs at process start).
- **Multi-bot support per Discord adapter** — current shape: one `discord_bot_token` per adapter instance. Multi-bot (one adapter, many bot identities) is a Slice-5+ shape requiring secret-broker changes.
- **Outbound queue persistence** — `OutboundQueue` is in-memory FIFO; a daemon crash loses queued outbounds. SQLite-backed persistence is a Slice-5+ enhancement; tracked as Issue #TBD.
- **Discord intent profiles per spec §8.5 (comms-010 closure)** — current shape: one fixed intent set. Future Discord variants with materially different sub-payloads (voice-only bots) would land as a new `adapter_kind: discord_voice` with its own `REQUIRED_CLASSIFIERS_BY_KIND` entry; revisit when concrete use case arises.
- **`alfred discord verify` Slice-4 equivalent** — Slice-2 shipped a CLI probe at `src/alfred/cli/discord_cmd.py`. Once PR-S4-10 deletes the legacy adapter, the new Slice-4 equivalent (`alfred plugin verify alfred_discord` or similar) should replace it. Track as a Slice-5 follow-up; current operator workflow uses `bin/alfred-plugin-launcher.sh alfred_discord` for ad-hoc verification.
- **Container-per-adapter deployment shape (spec §15 Open Question 14)** — Slice 4 runs adapters as in-process subprocesses spawned by the daemon. The post-MVP container-per-adapter shape (PRD §6.7 sketch) is deferred. PR-S4-9 ships only the in-tree plugin code, not container infrastructure. Revisit when multi-tenant deployments require per-adapter resource isolation beyond sandbox-kind.

---

## §11 PR open checklist

When opening the PR:

- [ ] PR title: `feat(comms-mcp): Discord MCP adapter + sub-payload classifier + OutboundQueue (PR-S4-9)`
- [ ] PR body references slice plan + the four blocking dependencies (PR-S4-3, PR-S4-5, PR-S4-6, PR-S4-8) and confirms they've merged.
- [ ] PR body links to the two new required-status-check gates and notes the `gh api` promotion happens in this PR per ops-007.
- [ ] CodeRabbit cloud review trigger — append `@coderabbitai full review` on the first revision to flip the initial pass.
- [ ] `/review-pr` panel run before opening for human review — feeds back any architectural concerns from the architect / reviewer / security-engineer / test-engineer / comms-adapter-engineer subagents.
- [ ] Slice-5 backlog items (§10) opened as draft GitHub issues with `slice-5-backlog` label, linked from the PR description.

---
