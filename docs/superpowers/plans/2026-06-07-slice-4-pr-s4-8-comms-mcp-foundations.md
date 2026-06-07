# PR-S4-8: Comms-MCP Foundations — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. This is a trust-boundary PR — TDD is HARD here, not advisory. Every audit-emit site, every notification dispatch arm, and the `BurstLimiter` primitive must have a failing test FIRST.

**Goal:** Ship the host-side comms-MCP infrastructure that PR-S4-9 (Discord) and PR-S4-10 (TUI) plug into. After this PR merges: the host can spawn a comms-adapter plugin via the launcher, hand it the ADR-0024 eight-method wire contract, route inbound `inbound.message` / `adapter.binding_request` / `adapter.rate_limit_signal` / `adapter.crashed` notifications through `AlfredPluginSession._on_post_handshake_method`, run identity resolution + burst-budget gate + quarantined T3 extraction host-side, and emit the new comms audit-row family with peppered hashes. The reference plugin at `plugins/alfred_comms_test/` exercises the full lifecycle. Closes #152.

**Architecture:** New module path `src/alfred/comms_mcp/` (deliberately distinct from `src/alfred/comms/` — that directory is dormant through this PR and is deleted in PR-S4-10; see spec §8.8). `protocol.py` is the wire-format owner — Pydantic v2 models for the eight ADR-0024 methods, the `OutboundMessageResult` discriminated union (comms-008), `adapter_kind: Final[frozenset[str]]`, and `BODY_FIELD_BY_KIND: Final[Mapping[str, str]]` (comms-011). `classifier_registry.py` owns `REQUIRED_CLASSIFIERS_BY_KIND` host-side (sec-002 round-3 — plugins cannot opt out). `inbound.py` holds the single `process_inbound_message` entrypoint that enforces the load-bearing order **resolution → burst-limit gate → quarantined_extract → ingest → dispatch**. `src/alfred/orchestrator/burst_limiter.py` is the new per-(canonical_user_id, persona) token-bucket primitive (sec-008 round-3 — honest Slice-4 scope, not a Slice-2 BudgetGuard citation). `Orchestrator.quarantined_extract(...)` is added as a thin orchestrator-side wrapper that funnels into the Slice-3 quarantined extractor returning `ExtractionResult(data: T3DerivedData, schema_version=1)` with `source_tier="T3"` preserved verbatim (sec-001 round-3 — no T3→T2 silent promotion). `AlfredPluginSession._on_post_handshake_method` at `src/alfred/plugins/session.py:347` is **extended** (NOT a fabricated `_read_loop` or `_on_notification` — those do not exist; core-011 round-4 lesson). The extension adds a match block dispatching the four notification methods, wraps the whole block in `async with self._dispatch_semaphore` (per-adapter `asyncio.BoundedSemaphore(value=Settings.comms_max_in_flight_notifications, default=32)`; core-008 + perf-003), and emits `COMMS_HANDLER_FAILED_FIELDS` + counter increment + breaker trip on 3 failures/5min before re-raising (err-007). Two new `Supervisor` methods are added: `request_plugin_restart(adapter_id, reason)` and `trip_breaker(component_id, reason)` with the new Literal `reason="comms_handler_repeated_failures"` (core-006). The reference plugin at `plugins/alfred_comms_test/` is upgraded from a Slice-3 one-shot stub into a full-lifecycle harness. The new hookpoints `comms.inbound.t3_promoted` (carrier_tier=T3) and `comms.adapter.crashed` (carrier_tier=T0) register here using PR-S4-3's `HookpointMeta.carrier_tier` required field. `#152` closes via the new `tests/integration/test_comms_mcp_identity_boundary_real.py` whose seven assertions are enumerated in spec §8.9.

**Tech Stack:** Python 3.12+ · Pydantic v2 (frozen models throughout; discriminated unions via `Annotated[U, Field(discriminator=...)]`) · asyncio (`BoundedSemaphore`, `TaskGroup`, `wait_for`) · `alfred.plugins.session.AlfredPluginSession` (extension, Slice-3 shipped) · `alfred.security.quarantine.ExtractionResult` + `T3DerivedData` (Slice-3, `src/alfred/security/quarantine.py:145`/`:298`) · `alfred.identity.resolver.IdentityResolver` (Slice-3, `src/alfred/identity/resolver.py:115`) · `alfred.supervisor.core.Supervisor` (Slice-3, `src/alfred/supervisor/core.py:146`) · `alfred.hooks.registry.register_hookpoint` (Slice-3 + PR-S4-3 `carrier_tier` extension) · `alfred.audit.audit_row_schemas` (PR-S4-0a-shipped constants) · `alfred.security.secrets.SecretBroker.get` (Slice-3, `src/alfred/security/secrets.py:396`) — for `audit.hash_pepper` · `alfred.security.dlp.OutboundDlp.scan` · `structlog` · `t()` for every operator-facing string · pytest + testcontainers · `coverage --fail-under=100` on every trust-boundary file (the four new modules + the `_on_post_handshake_method` extension).

**Depends on (must be merged):**

- **PR-S4-0a** — `audit_row_schemas.py` constants (`COMMS_INBOUND_T3_PROMOTION_FIELDS`, `COMMS_BINDING_REQUESTED_FIELDS`, `COMMS_ADAPTER_CRASHED_FIELDS`, `COMMS_RATE_LIMIT_SIGNAL_FIELDS`, `COMMS_UNKNOWN_NOTIFICATION_FIELDS`, `COMMS_HANDLER_FAILED_FIELDS`, `COMMS_ADDRESSING_DRIFT_FIELDS`, `COMMS_INBOUND_BUDGET_CAPPED_FIELDS`, `SUPERVISOR_PLUGIN_RESTART_REQUESTED_FIELDS`); `payload_schema.py` adversarial Literal additions (`cib` prefix → `comms_identity_boundary`); ADR-0024 body.
- **PR-S4-0b** — `audit.hash_pepper` secret bootstrap in broker config; `alfred-core` Docker image (used by the integration test).
- **PR-S4-3** — `HookpointMeta.carrier_tier` required field; this PR's two new hookpoints register with that field.
- **PR-S4-6** — `bin/alfred-plugin-launcher.sh` policy-resolution rewrite + plugin-manifest `sandbox.kind` declaration; the reference plugin declares `kind: none`.

**Blocks:**

- **PR-S4-9** (Discord adapter) — implements the wire contract on the plugin side; consumes `REQUIRED_CLASSIFIERS_BY_KIND["discord"]` and `BODY_FIELD_BY_KIND["discord"]`; registers `comms.adapter.binding_requested` / `comms.adapter.rate_limit_signal` hookpoints.
- **PR-S4-10** (TUI adapter + `src/alfred/comms/` deletion) — consumes the same wire contract for TUI; this PR's `_on_post_handshake_method` extension is the dispatcher both adapter PRs rely on.

**Out of scope (explicitly deferred):**

- The Discord adapter implementation (`plugins/alfred_discord/`) — PR-S4-9.
- The TUI adapter implementation (`plugins/alfred_tui/`) — PR-S4-10.
- Deletion of `src/alfred/comms/` — PR-S4-10 (flag day).
- Adapter-kind entries for `discord` and `tui` in the Literal — PR-S4-9 and PR-S4-10 each add their own entry (with the matching `REQUIRED_CLASSIFIERS_BY_KIND` entry + `BODY_FIELD_BY_KIND` entry); PR-S4-8 ships `adapter_kind` as a *frozenset* extension-shaped contract with **only the placeholder entry** `"alfred_comms_test"` so the reference plugin can register.
- Slice-3 in-process `CommsAdapter` Protocol callers — PR-S4-10 migrates them. PR-S4-8 leaves `src/alfred/comms/` strictly untouched.
- Telegram adapter — post-MVP (the `BODY_FIELD_BY_KIND` table includes `"telegram": "text"` as a comment-marked future entry; the corresponding Literal entry does NOT ship here).
- `alfred chat` CLI rewire to launcher spawn — PR-S4-10 (§8.7).
- ADR-0009 caveat narrowing — PR-S4-10 (docs-001).

**PR #205 round-2 review closures** (load-bearing corrections — apply at implementation time):

1. **sec-001 CRITICAL + comms-002 HIGH (OutboundMessageRequest.body DLP-mandatory invariant)**: `OutboundMessageRequest.body: str` is REPLACED with `OutboundMessageRequest.body: ScannedOutboundBody`. `ScannedOutboundBody` is a NewType wrapping `tuple[str, OutboundDlpScanResult]` (carries the redacted text + dlp_redactions_count + canary_tripped). The ONLY constructor is `OutboundDlp.scan_for_outbound(raw_body: str) -> ScannedOutboundBody` (lives at `src/alfred/security/dlp.py`). Any code path that constructs `OutboundMessageRequest` MUST first call `scan_for_outbound`. A new AST-guard test `tests/unit/comms/test_outbound_request_constructed_via_scan.py` walks every `OutboundMessageRequest(...)` constructor call site in the repo and refuses any whose `body=` argument is not the return value of `scan_for_outbound(...)` (verified via static dataflow within the same function scope). Coverage gate enforces 100% of construction sites pass through scan.

2. **sec-002 HIGH (peppered hashes bypassed by detail_redacted / method_redacted_params)**: a NEW comms-specific scrubber `src/alfred/comms/_audit_scrub.py:scrub_for_comms_audit(text: str, *, inbound: InboundMessage, pepper: bytes) -> str` runs BEFORE `OutboundDlp.scan` on every `detail_redacted` and `method_redacted_params` value. The scrubber substitutes raw `platform_user_id` with `_peppered_hash(inbound.platform_user_id, pepper)`, raw bot/channel/guild IDs with their hashed forms, and raw verification phrases with `[REDACTED:verification_phrase]`. A new property-test `tests/unit/comms/test_platform_user_id_never_in_audit.py` plants 1000 random platform_user_ids in synthetic exception messages and asserts the raw value never appears in the final audit-row bytes regardless of exception content.

3. **sec-003 HIGH (resolver-before-burst-gate DoS)**: a NEW pre-resolution coarse limiter `_PreResolutionLimiter` keyed on `(adapter_id, platform_user_id_hash)` runs BEFORE `IdentityResolver.resolve`. Default 50 requests/min/key; configurable via `BurstLimiterPolicy.pre_resolution_per_platform_user_per_minute`. On hit: emit `COMMS_INBOUND_BUDGET_CAPPED_FIELDS(phase="pre_resolution", platform_user_id_hash=...)` and refuse without calling resolver. The pre-resolution hash uses the same pepper as the post-resolution per-user limiter so cardinality stays bounded.

4. **sec-004 MEDIUM (ContentRef sha256 binding)**: `ContentRef` adds `content_sha256: bytes` (32-byte SHA-256). Broker substitution (PR-S4-9 owns the wire) MUST verify `sha256(broker.fetch_attachment(handle_id)) == content_sha256` and refuse with `ContentRefShaSizeMismatch` on mismatch. The audit-recorded sha256 is the peppered version `_peppered_hash(content_sha256.hex(), pepper)` to prevent rainbow-table reidentification of canary tokens. New corpus entry `cib-2026-006-attachment-swap-toctou` plants a swap attempt.

5. **arch-001 HIGH (BurstLimiterPolicy ownership)**: rename `BurstLimitConfig` → `BurstLimiterPolicy`. The model SHIPS in PR-S4-0a (PR-S4-0a's task list expands to include a NEW Component **A.6** that adds `src/alfred/policies/models.py:BurstLimiterPolicy` with all the field defaults per ADR-0023). PR-S4-4 and PR-S4-8 both `from alfred.policies.models import BurstLimiterPolicy` — single source of truth. The `BurstLimiterPolicy` model lives in `alfred.policies.models` (a shared lightweight module that PR-S4-0a creates).

6. **arch-002 MEDIUM (depends_on includes PR-S4-4)**: `depends_on:` block adds **PR-S4-4** — Task 19 reads `PoliciesSnapshotRef.current()` for per-iteration deref, requiring PR-S4-4 to ship the snapshot-ref machinery first.

7. **arch-003 MEDIUM (hookpoint split symmetry with PR-S4-9)**: PR-S4-8 registers ALL the comms hookpoints (`comms.binding.requested`, `comms.binding.completed`, `comms.binding.refused`, `comms.outbound.refused`, `comms.outbound.dispatched`, `comms.rate_limit.signal_received`). PR-S4-9's adapter wires its own emits to these hookpoints. The split was incorrectly placing 2 hookpoints in PR-S4-9; PR-S4-8 now owns all 6. Operator subscribers see consistent surface from PR-S4-8 onwards.

8. **arch-004 LOW (Supervisor.trip_breaker Literal)**: `Supervisor.trip_breaker` does NOT exist in Slice-3 (verified earlier — only `reset_breaker` + `get_or_create_breaker` exist). The plan's reference to it is replaced with the actual `Supervisor.get_or_create_breaker(name).trip(reason=Literal[...])` shape. The Literal enumerates exhaustively: `Literal["comms.adapter.refused", "comms.adapter.unhealthy", "comms.rate_limit.exhausted"]` (no `...` placeholder).

9. **comms-001 HIGH (RateLimitSignal handler contract)**: `RateLimitSignal` carries `(adapter_id, retry_after_ms, scope: Literal["per_user", "per_channel", "global"], scope_key: str)`. `_rate_limit_handler.process(signal)` MUST: (a) update the relevant `BurstLimiter` bucket via `burst_limiter.absorb_external_signal(adapter_id=signal.adapter_id, scope=signal.scope, scope_key=signal.scope_key, retry_after_ms=signal.retry_after_ms)`; (b) if `signal.scope == "global"` AND `signal.retry_after_ms > 30000`, trip the comms-adapter breaker via `supervisor.get_or_create_breaker(f"comms.{adapter_id}").trip(reason="comms.rate_limit.exhausted")`; (c) emit `COMMS_RATE_LIMIT_SIGNAL_FIELDS` audit row. PR-S4-9's Discord 429 handler emits the signal; PR-S4-8's handler defines the contract.

10. **perf-001 HIGH (BurstLimiter bucket eviction)**: `_per_user_buckets: dict[tuple[CanonicalUserId, PersonaId], TokenBucket]` adds LRU eviction. Implementation: `collections.OrderedDict` with a max-size cap of `BurstLimiterPolicy.max_tracked_buckets` (default 10_000). On insert past the cap, evict the LRU bucket. Eviction is logged at INFO; if eviction rate exceeds 100/min for >5min, emit `COMMS_BURST_LIMITER_DEGRADED_FIELDS(reason="eviction_rate_excessive")`. The `asyncio.Lock` dict for per-bucket locks uses the same eviction discipline (locks are evicted with their buckets).

11. **comms-003 MEDIUM (token-bucket monotonic time)**: token-bucket math uses `time.monotonic()` for elapsed-time deltas. `datetime.now(UTC)` is used only for audit-row timestamps and `bucket_empty_since` display values. NTP step or DST shift cannot corrupt refill math. Same for SlidingWindowCounter. New unit test `tests/unit/comms/test_token_bucket_monotonic.py` mocks `time.monotonic()` jumps and asserts bucket state stays consistent.

12. **comms-004 MEDIUM (enforcing factory for adapter spawn)**: NEW factory `AlfredPluginSession.for_comms_adapter(adapter_id: str, *, inbound_handler: InboundHandler, outbound_handler: OutboundHandler, binding_handler: BindingHandler, rate_limit_handler: RateLimitHandler) -> AlfredPluginSession`. All four handlers are REQUIRED kwargs (no Optional, no `_NoopSemaphore` default). PR-S4-9 + PR-S4-10 adapter launchers MUST go through this factory. The Slice-3 in-process `AlfredPluginSession.__init__` retains Optional kwargs for back-compat but emits a deprecation warning when accessed without the factory.

13. **perf-002 MEDIUM (pepper-fetch contract)**: `_peppered_hash` accepts `pepper: bytes` (NOT a broker). Pepper is fetched ONCE at AuditWriter construction (`comms.audit_writer.__init__` calls `secret_broker.get("audit.hash_pepper").encode()` and stashes the bytes). New unit test `tests/unit/comms/test_audit_pepper_fetched_once.py` constructs the writer and asserts `secret_broker.get` was called exactly once.

14. **perf-003 MEDIUM (validation before semaphore)**: a fast pre-check helper `_inbound_message_cheap_validate(raw: dict) -> bool` runs BEFORE `BoundedSemaphore.acquire`: validates only `(platform_user_id, body)` are non-empty strings of bounded length (cheap; no Pydantic). On fail → refuse immediately. Full Pydantic `InboundMessage.model_validate` runs AFTER `burst_limiter.acquire` so validation cost isn't paid for dropped messages.

This PR delivers the host-side foundations of the comms-MCP rewrite — spec §8.1 through §8.5, §8.9, §8.10 — plus the new `comms.inbound.t3_promoted` and `comms.adapter.crashed` hookpoints from spec §10. After this PR merges:

1. Any MCP-stdio comms adapter plugin can be spawned via `bin/alfred-plugin-launcher.sh` and connect to the host through `AlfredPluginSession`.
2. The host accepts the four plugin→host notifications (`inbound.message`, `adapter.binding_request`, `adapter.rate_limit_signal`, `adapter.crashed`) and routes them to the four `Handler` callbacks via the new dispatch arm in `_on_post_handshake_method`.
3. `process_inbound_message` enforces the load-bearing order: identity resolution → burst-budget acquire → quarantined T3 extraction → ingest → dispatch. The canonical `user_id` never appears in any stdio frame the host writes to the plugin (spec §8.2 last paragraph; verified by the integration test).
4. The new `BurstLimiter` (5 tokens, 1/5s refill default; configurable via `PoliciesV1.rate_limits.quarantined_extract_per_user_persona`) caps sub-second bursts per (canonical_user_id, persona) and either applies backpressure (emit `COMMS_INBOUND_BUDGET_CAPPED_FIELDS`) or drops after 30s (`comms.inbound.dropped` audit row).
5. The eight comms audit-row constants emit at the right call sites with peppered hashes (`platform_user_id_hash`, `verification_phrase_hash`) sourced from `secret_broker.get("audit.hash_pepper")`.
6. The reference plugin at `plugins/alfred_comms_test/` round-trips a manufactured inbound notification through the host and observes the resulting outbound delivery — the merge-blocking integration test `tests/integration/test_comms_mcp_identity_boundary_real.py` runs against it.
7. Issue #152 closes (the seven-assertion test enumerated in spec §8.9).

Spec anchors: [§8.1](../specs/2026-06-06-slice-4-design.md#81-wire-contract--methods--schemas), [§8.2](../specs/2026-06-06-slice-4-design.md#82-host-side-process_inbound_message-entrypoint), [§8.3](../specs/2026-06-06-slice-4-design.md#83-identityresolver-callback-wire-type), [§8.4](../specs/2026-06-06-slice-4-design.md#84-alfredpluginsession-inbound-notification-handler), [§8.5](../specs/2026-06-06-slice-4-design.md#85-inboundcontentscanner-extension-for-discord-sub-payloads), [§8.9](../specs/2026-06-06-slice-4-design.md#89-adr-0009-caveat-narrowing--152-closure), [§8.10](../specs/2026-06-06-slice-4-design.md#810-audit-row-family), [§9 audit-row table rows for the new constants](../specs/2026-06-06-slice-4-design.md#9-audit-row-schemas-slice-4-additions), [§10 hookpoint surface](../specs/2026-06-06-slice-4-design.md#10-hookpoint-surface-slice-4-additions), [§11 adversarial corpus additions](../specs/2026-06-06-slice-4-design.md#11-adversarial-corpus-additions).

---

## §2 Architecture overview

```
        Plugin process (e.g. plugins/alfred_comms_test/)
        │
        │   inbound.message notification JSON-RPC frame
        ▼
StdioTransport (Slice-3 shipped)
        │   ① InboundContentScanner.scan(frame)      [Slice-3]
        │   ② frame body — full Discord/TUI/Telegram JSON
        ▼
AlfredPluginSession._on_post_handshake_method(method)
        │   PR-S4-8 EXTENSION HERE
        │   async with self._dispatch_semaphore:     [core-008]
        │     try:
        │       match method:
        │         case "inbound.message":
        │           payload = InboundMessageNotification.model_validate(params)
        │           await self._inbound_handler.process(payload)
        │         case "adapter.binding_request":
        │           payload = BindingRequestNotification.model_validate(params)
        │           await self._binding_handler.process(payload)
        │         case "adapter.rate_limit_signal":
        │           payload = RateLimitSignal.model_validate(params)
        │           await self._rate_limit_handler.process(payload)
        │         case "adapter.crashed":
        │           payload = CrashedNotification.model_validate(params)
        │           await self._crash_handler.process(payload)
        │         case _:
        │           emit COMMS_UNKNOWN_NOTIFICATION_FIELDS
        │           await self._supervisor.request_plugin_restart(...)
        │     except Exception as exc:
        │       emit COMMS_HANDLER_FAILED_FIELDS
        │       counter.increment()
        │       if counter.exceeds(3, 5min):
        │         await self._supervisor.trip_breaker(...,
        │             reason="comms_handler_repeated_failures")
        │       raise                                [err-007 — loud]
        │
        ▼
process_inbound_message(notification, identity_resolver, orchestrator, audit_writer)
        │   ① resolved = await identity_resolver.resolve(adapter_id, platform_user_id)
        │      if None: emit COMMS_BINDING_REQUESTED + return                 [binding flow]
        │   ② await burst_limiter.acquire(canonical_user_id, persona)
        │      if drained > 30s: emit comms.inbound.dropped + return          [hard drop]
        │      else if capped:    emit COMMS_INBOUND_BUDGET_CAPPED_FIELDS
        │   ③ extracted = await orchestrator.quarantined_extract(
        │         notification.body, canonical_user_id, source_tier="T3"
        │      )  -> ExtractionResult(data: T3DerivedData, schema_version=1)
        │   ④ emit COMMS_INBOUND_T3_PROMOTION_FIELDS                          [observability]
        │   ⑤ ingested = await orchestrator.ingest(notification, body=extracted.data, ...)
        │   ⑥ await orchestrator.dispatch(ingested)
        │
        ▼
Orchestrator (Slice-3 + new quarantined_extract wrapper)

BurstLimiter (src/alfred/orchestrator/burst_limiter.py)
        │   per-(canonical_user_id, persona) bucket
        │   capacity=5, refill 1 token / 5s (configurable via PoliciesV1)
        │   acquire() blocks up to 30s; returns Acquired | Dropped
        │   emits COMMS_INBOUND_BUDGET_CAPPED_FIELDS on backpressure
        │   emits `comms.inbound.dropped` audit row on hard drop

InboundContentScanner (src/alfred/comms_mcp/inbound_scanner.py)
        │   consults BODY_FIELD_BY_KIND[adapter_kind] for body-text field path
        │   runs the host-owned REQUIRED_CLASSIFIERS_BY_KIND set per adapter_kind
        │   plugin manifests may opt in to additional registered classifiers
        │       but cannot opt out of the required set
```

The canonical `user_id` never crosses the stdio boundary outward. `IdentityResolver.resolve(adapter_id, platform_user_id) -> ResolvedIdentity | None` runs host-side; resolution result stays host-side. The plugin sees only `target_platform_id` in outbound frames.

**Per-adapter semaphore invariant (perf-003).** The `_dispatch_semaphore` is a constructor parameter on `AlfredPluginSession`, allocated freshly per session. Two adapter sessions hold two distinct `BoundedSemaphore` instances. Adapter A's rate-limit storm cannot starve adapter B because the semaphore is not process-wide. The cap defaults to 32 via the new `Settings.comms_max_in_flight_notifications` field. Exceeding the cap applies backpressure into the stdio reader's pending queue, then into kernel-pipe backpressure once the read buffer is full.

**Catch-and-continue invariant (err-007 + core-011 round-4).** The Slice-3 `StdioTransport` reader logs via structlog (`event="comms.transport.method_failed"`) and continues to the next frame when a method raises. The session is not torn down by a single bad notification. PR-S4-8 inherits this; it adds the new `try` block inside `_on_post_handshake_method` so the audit row + counter + breaker trip happen before re-raise, **but the original exception still propagates** to the transport reader.

**Hookpoint registration invariant.** Both new hookpoints register via `register_hookpoint(carrier_tier=T3, fail_closed=True, allow_error_substitution=False)` for `comms.inbound.t3_promoted` and `carrier_tier=T0` for `comms.adapter.crashed`. PR-S4-3 must have shipped the `HookpointMeta.carrier_tier` required field before this PR merges.

---

## §3 File structure

| File | Status | Responsibility |
|---|---|---|
| `src/alfred/comms_mcp/__init__.py` | Create | Package marker; re-exports `protocol`, `inbound`, `classifier_registry`, `inbound_scanner` public surface |
| `src/alfred/comms_mcp/protocol.py` | Create | Pydantic v2 wire schemas for the 8 ADR-0024 methods; `OutboundMessageResult` discriminated union (`_OutboundDelivered`, `_OutboundRetryable`, `_OutboundTerminal`); `adapter_kind: Final[frozenset[str]]`; `BODY_FIELD_BY_KIND: Final[Mapping[str, str]]`; `PersonaAddressingMode = Literal["dm","mention","channel","thread"]` |
| `src/alfred/comms_mcp/inbound.py` | Create | `process_inbound_message(notification, identity_resolver, orchestrator, audit_writer)` host-side entrypoint enforcing resolution → burst-gate → quarantined_extract → ingest → dispatch ordering |
| `src/alfred/comms_mcp/inbound_scanner.py` | Create | `InboundContentScanner` extension consulting `BODY_FIELD_BY_KIND[adapter_kind]` for body-field path + running `REQUIRED_CLASSIFIERS_BY_KIND[adapter_kind]` classifier set host-side; emits `ContentHandle` per sub-payload |
| `src/alfred/comms_mcp/classifier_registry.py` | Create | `REQUIRED_CLASSIFIERS_BY_KIND: Final[Mapping[str, frozenset[str]]]` host-owned table; `@register_classifier(kind=..., name=...)` decorator import-time registration |
| `src/alfred/comms_mcp/handlers.py` | Create | Protocols + concrete handler classes: `InboundHandler`, `BindingHandler`, `RateLimitHandler`, `CrashHandler` — each `async def process(self, notification) -> None` |
| `src/alfred/comms_mcp/errors.py` | Create | `CommsMcpError(AlfredError)` root; `UnknownAdapterKindError`, `InboundBurstDroppedError`, `CommsHandlerFailedError` |
| `src/alfred/orchestrator/burst_limiter.py` | Create | `BurstLimiter` per-(canonical_user_id, persona) token-bucket primitive; capacity=5, 1/5s refill default; `acquire()` returns `Acquired \| Dropped`; emits `COMMS_INBOUND_BUDGET_CAPPED_FIELDS`; drops after 30s of bucket-empty (emits `comms.inbound.dropped`) |
| `src/alfred/orchestrator/core.py` | Modify | Add `Orchestrator.quarantined_extract(body, *, canonical_user_id, source_tier) -> ExtractionResult` thin wrapper funneling into Slice-3 extractor with `source_tier="T3"` preserved |
| `src/alfred/plugins/session.py` | Modify | Extend `_on_post_handshake_method` at line 347 with the four-arm match block + try/except + semaphore + handler fan-out; add four `Handler` constructor params + `_dispatch_semaphore` instance state; add `_error_counter: SlidingWindowCounter` |
| `src/alfred/supervisor/core.py` | Modify | Add `Supervisor.request_plugin_restart(adapter_id, reason)` — writes `SUPERVISOR_PLUGIN_RESTART_REQUESTED_FIELDS`, marks adapter unhealthy, returns; add `Supervisor.trip_breaker(component_id, reason)` accepting the new Literal `reason="comms_handler_repeated_failures"` |
| `src/alfred/config/settings.py` | Modify | Add `comms_max_in_flight_notifications: int = 32` field with `Field(ge=1, le=1024)` validator |
| `src/alfred/policies/models.py` | Modify | Add `rate_limits.quarantined_extract_per_user_persona: BurstLimitConfig` nested model carrying `capacity_tokens: int = 5`, `refill_seconds: float = 5.0`, `drop_after_seconds: float = 30.0` |
| `src/alfred/hooks/registrations.py` | Modify | Register `comms.inbound.t3_promoted` (carrier_tier=T3, fail_closed=True, allow_error_substitution=False) and `comms.adapter.crashed` (carrier_tier=T0, fail_closed=True) hookpoints |
| `src/alfred/utils/sliding_window_counter.py` | Create | `SlidingWindowCounter` reusable primitive: `increment()`, `exceeds(threshold, window)` — used by the dispatcher's error-rate breaker trigger |
| `plugins/alfred_comms_test/__init__.py` | Modify | Slice-3 one-shot stub → full lifecycle adapter implementing the 8 wire methods |
| `plugins/alfred_comms_test/main.py` | Modify | Plugin process entrypoint; manifest-handshake; handles `lifecycle.start/stop`, `adapter.health`, `outbound.message`; emits `inbound.message`, `adapter.binding_request`, `adapter.rate_limit_signal`, `adapter.crashed` on test triggers |
| `plugins/alfred_comms_test/manifest.toml` | Modify | `adapter_kind = "alfred_comms_test"`; `sandbox.kind = "none"`; `subscriber_tier = "T2"` (the plugin process is T2; inbound bodies are T3 host-side) |
| `tests/unit/comms_mcp/__init__.py` | Create | Test package marker |
| `tests/unit/comms_mcp/test_protocol_schemas.py` | Create | Pydantic schema round-trip for the 8 methods; `OutboundMessageResult` discriminator routing (`outcome="delivered"` → `_OutboundDelivered`, etc.); `frozen=True` enforced; `idempotency_key` is `UUID` not `str` |
| `tests/unit/comms_mcp/test_outbound_message_result_union.py` | Create | Discriminated union forbids field coupling: `_OutboundDelivered` has no `retry_after_seconds`; `_OutboundRetryable` requires it; `_OutboundTerminal` requires `detail_redacted` ≤256 chars |
| `tests/unit/comms_mcp/test_adapter_kind_literal.py` | Create | `adapter_kind` is `frozenset` not `set`; mutation raises; `BODY_FIELD_BY_KIND.keys() == adapter_kind` (every kind has a body-field entry) |
| `tests/unit/comms_mcp/test_required_classifiers_complete.py` | Create | AST guard: every `adapter_kind` member has an entry in `REQUIRED_CLASSIFIERS_BY_KIND`; empty entry refused unless module-level `MARKER_NO_CLASSIFIERS_NEEDED` constant is defined (TUI-style exception per §8.5) |
| `tests/unit/comms_mcp/test_inbound_resolution_first.py` | Create | `process_inbound_message` consults `identity_resolver.resolve` BEFORE any `orchestrator.*` call; `None` return triggers `COMMS_BINDING_REQUESTED_FIELDS` + early return (no `quarantined_extract`, no `dispatch`) |
| `tests/unit/comms_mcp/test_inbound_burst_gate_before_extract.py` | Create | `BurstLimiter.acquire` is called BEFORE `orchestrator.quarantined_extract` (spec §8.2 ordering); spy on both; assert acquire-call precedes extract-call |
| `tests/unit/comms_mcp/test_inbound_quarantined_extract_source_tier.py` | Create | `Orchestrator.quarantined_extract` invoked with `source_tier="T3"` literally — not `"T2"`, not silently absent; result is `ExtractionResult` with `data: T3DerivedData` |
| `tests/unit/comms_mcp/test_inbound_t3_promotion_audit_row.py` | Create | `COMMS_INBOUND_T3_PROMOTION_FIELDS` audit row fires exactly once per successful inbound; carries `platform_user_id_hash` (peppered), `sub_payload_kinds` frozenset, `addressing_signal` |
| `tests/unit/comms_mcp/test_inbound_canonical_id_never_leaves_host.py` | Create | Outbound stdio frames captured during an inbound→outbound round trip; assert `canonical_user_id` string never appears in any captured frame |
| `tests/unit/comms_mcp/test_session_dispatch_semaphore.py` | Create | `_dispatch_semaphore` acquired via `async with`; released on exception path; per-adapter — two `AlfredPluginSession` instances hold distinct semaphores; cap honoured |
| `tests/unit/comms_mcp/test_session_unknown_notification.py` | Create | Unknown method emits `COMMS_UNKNOWN_NOTIFICATION_FIELDS`, calls `supervisor.request_plugin_restart(adapter_id, reason="unknown_notification")`, does NOT raise (handled in match `case _:`) |
| `tests/unit/comms_mcp/test_session_handler_failure_loud.py` | Create | A failing handler emits `COMMS_HANDLER_FAILED_FIELDS` + increments counter + re-raises original exception (not silently swallowed) |
| `tests/unit/comms_mcp/test_session_breaker_trips_on_3_failures.py` | Create | 3 handler exceptions inside 5min window → `Supervisor.trip_breaker(component_id=adapter_id, reason="comms_handler_repeated_failures")` called once on the 3rd failure; 2 failures does not trip |
| `tests/unit/comms_mcp/test_session_handler_fan_out_ordering.py` | Create | Handlers are awaited sequentially per notification (no concurrent fan-out for a single message); two notifications can proceed concurrently up to semaphore cap |
| `tests/unit/comms_mcp/test_inbound_scanner_body_field_per_kind.py` | Create | Scanner consults `BODY_FIELD_BY_KIND[adapter_kind]` — Discord uses `"content"`, TUI uses `"content"`, Telegram uses `"text"` (parameterised) |
| `tests/unit/comms_mcp/test_classifier_registry_import_registration.py` | Create | `@register_classifier(kind=..., name=...)` decorator adds entries to a private module-level dict; importing the module twice does not double-register |
| `tests/unit/orchestrator/test_burst_limiter_basic.py` | Create | `BurstLimiter` capacity=5, 1/5s refill — burst of 5 acquires succeed; 6th waits; refill restores token after 5s |
| `tests/unit/orchestrator/test_burst_limiter_emits_capped_audit.py` | Create | Backpressure event (acquire took >0s) emits `COMMS_INBOUND_BUDGET_CAPPED_FIELDS` with `tokens_available`, `wait_seconds`, `dropped=False` |
| `tests/unit/orchestrator/test_burst_limiter_drop_after_30s.py` | Create | Bucket empty for 30s → next `acquire()` returns `Dropped`; emits `comms.inbound.dropped` audit row + `COMMS_INBOUND_BUDGET_CAPPED_FIELDS(dropped=True)` |
| `tests/unit/orchestrator/test_burst_limiter_per_user_persona.py` | Create | Acquires for `(user_a, alfred)` do not deplete the bucket for `(user_b, alfred)` or for `(user_a, oracle)`; per-key buckets independent |
| `tests/unit/orchestrator/test_burst_limiter_policies_v1_config.py` | Create | `PoliciesV1.rate_limits.quarantined_extract_per_user_persona` overrides default capacity/refill; values < 1 or > 100 capacity refused at validation |
| `tests/unit/orchestrator/test_quarantined_extract_preserves_source_tier.py` | Create | `Orchestrator.quarantined_extract(body, source_tier="T3")` calls underlying quarantine extractor with `source_tier="T3"` preserved; result `ExtractionResult.data` is typed `T3DerivedData` |
| `tests/unit/orchestrator/test_quarantined_extract_refuses_silent_promotion.py` | Create | Caller passing `source_tier="T2"` for an inbound body coming from a comms adapter is refused with `ValueError` ("comms inbound must be T3"); enforces sec-001 round-3 invariant |
| `tests/unit/supervisor/test_request_plugin_restart.py` | Create | `Supervisor.request_plugin_restart(adapter_id, reason)` writes `SUPERVISOR_PLUGIN_RESTART_REQUESTED_FIELDS`; marks adapter unhealthy in breaker; returns; idempotent under repeat calls within a tick |
| `tests/unit/supervisor/test_trip_breaker_comms_reason.py` | Create | `Supervisor.trip_breaker(component_id, reason="comms_handler_repeated_failures")` accepted; unknown reason rejected at runtime; breaker transitions to OPEN; emits supervisor audit row |
| `tests/unit/config/test_settings_comms_max_in_flight.py` | Create | Default 32; constrained `Field(ge=1, le=1024)`; env-override `ALFRED_COMMS_MAX_IN_FLIGHT_NOTIFICATIONS=64` honoured |
| `tests/unit/policies/test_burst_limit_config.py` | Create | `BurstLimitConfig` Pydantic model frozen; defaults match `BurstLimiter` defaults; PoliciesV1 round-trips through YAML |
| `tests/unit/hooks/test_comms_hookpoints_registered.py` | Create | `comms.inbound.t3_promoted` carrier_tier=T3, fail_closed=True, allow_error_substitution=False; `comms.adapter.crashed` carrier_tier=T0 |
| `tests/unit/audit/test_comms_audit_rows_emit_with_pepper.py` | Create | `platform_user_id_hash` derived from `hmac(pepper, raw).hexdigest()[:32]`; `verification_phrase_hash` likewise; raw value never appears in audit row dict |
| `tests/unit/plugins/test_session_constructor_handler_params.py` | Create | `AlfredPluginSession.__init__` accepts four new params (`inbound_handler`, `binding_handler`, `rate_limit_handler`, `crash_handler`) + `dispatch_semaphore` + `error_counter`; backwards-compatible with Slice-3 callers via `None`-defaulted optional params |
| `tests/unit/utils/test_sliding_window_counter.py` | Create | `SlidingWindowCounter.exceeds(threshold=3, window=timedelta(minutes=5))` returns True after the 3rd `increment()` inside the window; entries outside the window age out |
| `tests/integration/test_comms_mcp_identity_boundary_real.py` | Create | **Merge-blocking** (cross-fork integration test gate per spec §11.5). Spec §8.9's 7-point assertion list against the reference plugin. Promoted to required-status check on merge of THIS PR. |
| `tests/integration/test_comms_mcp_reference_plugin_lifecycle.py` | Create | Reference plugin spawns via launcher → `lifecycle.start` → manufactured `inbound.message` → host emits `outbound.message` → `lifecycle.stop` → `flushed_messages` count returned |
| `tests/integration/test_comms_mcp_unknown_method_restarts_plugin.py` | Create | Plugin emits `unknown.method` notification; host emits `COMMS_UNKNOWN_NOTIFICATION_FIELDS`, calls `request_plugin_restart`, supervisor spawns fresh plugin on next tick |
| `tests/integration/test_comms_mcp_handler_failure_breaker_trip.py` | Create | Reference plugin emits 3 inbound notifications all crafted to fail the handler within 5min; on the 3rd failure, supervisor breaker for the adapter trips OPEN; subsequent inbound is refused |
| `tests/integration/test_comms_mcp_burst_drop_after_30s.py` | Create | Plugin emits 10 inbound notifications/sec for 35s; host drains tokens, applies backpressure (`COMMS_INBOUND_BUDGET_CAPPED_FIELDS` rows accumulate), and ultimately drops with `comms.inbound.dropped` after 30s of bucket-empty |
| `tests/adversarial/comms_identity_boundary/cib-2026-001-forged-canonical-id-in-platform-metadata.yaml` | Create | Forged `platform_metadata.canonical_user_id` in `adapter.binding_request` — must be ignored; resolver-state canonical_id used instead |
| `tests/adversarial/comms_identity_boundary/cib-2026-002-inter-persona-relay-t2-as-t3.yaml` | Create | Inter-persona forgery variant from spec §8.9 #7: relay-message carrying T3 content tagged as T2 source — refused at `quarantined_extract` |
| `tests/adversarial/comms_identity_boundary/cib-2026-003-canonical-id-leakage-on-outbound.yaml` | Create | Adversary attempts to coerce host into echoing the canonical_id back over outbound — captured stdio frames asserted not to contain the canonical id |
| `tests/adversarial/comms_identity_boundary/cib-2026-004-empty-classifier-set-bypass.yaml` | Create | PR-shaped attack: adding `adapter_kind` with an empty `REQUIRED_CLASSIFIERS_BY_KIND` entry; AST guard refuses (covered by `test_required_classifiers_complete.py` but mirrored in adversarial corpus per spec §11) |
| `tests/adversarial/comms_identity_boundary/cib-2026-005-handler-exception-silenced.yaml` | Create | Handler swallows exception silently (returns None instead of raising) — pytest asserts `COMMS_HANDLER_FAILED_FIELDS` NOT emitted in that case AND that the dispatcher path that DOES emit re-raises the original exception (positive control) |

---

## §4 Cross-PR contracts (this PR's owned surfaces)

### `src/alfred/comms_mcp/protocol.py` (NEW)

The wire-format module. Path is **deliberately `comms_mcp`, not `comms`** (Critical 1 round-1 closure — the soon-to-be-deleted `src/alfred/comms/` is unrelated). PR-S4-10's deletion leaves this module untouched.

Exposed public symbols:

```python
PersonaAddressingMode = Literal["dm", "mention", "channel", "thread"]

adapter_kind: Final[frozenset[str]] = frozenset({
    "alfred_comms_test",   # reference plugin — this PR
    # "discord"  — added by PR-S4-9
    # "tui"      — added by PR-S4-10
})

BODY_FIELD_BY_KIND: Final[Mapping[str, str]] = MappingProxyType({
    "alfred_comms_test": "content",
    # "discord":   "content",   # PR-S4-9
    # "tui":       "content",   # PR-S4-10
    # "telegram":  "text",      # post-MVP
})

class LifecycleStartRequest(BaseModel): ...
class LifecycleStartResult(BaseModel): ...
class LifecycleStopRequest(BaseModel): ...
class LifecycleStopResult(BaseModel): ...
class AdapterHealthRequest(BaseModel): ...
class HealthReport(BaseModel): ...
class OutboundMessageRequest(BaseModel): ...
class _OutboundDelivered(BaseModel): ...
class _OutboundRetryable(BaseModel): ...
class _OutboundTerminal(BaseModel): ...

OutboundMessageResult = Annotated[
    _OutboundDelivered | _OutboundRetryable | _OutboundTerminal,
    Field(discriminator="outcome"),
]

class InboundMessageNotification(BaseModel): ...
class BindingRequestNotification(BaseModel): ...
class RateLimitSignal(BaseModel): ...
class CrashedNotification(BaseModel): ...
```

Every model uses `model_config = ConfigDict(frozen=True, extra="forbid")`. Every Literal-typed field is `Literal[...]` not `str`.

### `src/alfred/comms_mcp/classifier_registry.py` (NEW)

```python
REQUIRED_CLASSIFIERS_BY_KIND: Final[Mapping[str, frozenset[str]]] = MappingProxyType({
    "alfred_comms_test": frozenset(),  # plain-text only — see MARKER below
    # "discord": frozenset({"discord_sub_payloads"}),  # PR-S4-9
    # "tui":     frozenset(),                          # PR-S4-10
})

# Per spec §8.5 — empty entries must justify; the reference plugin is plain-text.
MARKER_NO_CLASSIFIERS_NEEDED: Final[Mapping[str, str]] = MappingProxyType({
    "alfred_comms_test": "reference plugin emits plain-text only; no sub-payloads possible",
})

def register_classifier(*, kind: str, name: str) -> Callable[[type], type]: ...
```

The AST guard test refuses to import this module if any `adapter_kind` member lacks both a non-empty entry AND a `MARKER_NO_CLASSIFIERS_NEEDED` entry.

### `src/alfred/comms_mcp/inbound.py` (NEW)

```python
async def process_inbound_message(
    notification: InboundMessageNotification,
    *,
    identity_resolver: IdentityResolver,
    orchestrator: Orchestrator,
    burst_limiter: BurstLimiter,
    audit_writer: AuditWriter,
) -> None: ...
```

Order is load-bearing and tested per-step.

### `src/alfred/orchestrator/burst_limiter.py` (NEW)

```python
@dataclass(frozen=True)
class Acquired:
    tokens_remaining: int
    waited_seconds: float

@dataclass(frozen=True)
class Dropped:
    waited_seconds: float
    bucket_empty_since: datetime

class BurstLimiter:
    def __init__(
        self,
        *,
        capacity_tokens: int = 5,
        refill_seconds: float = 5.0,
        drop_after_seconds: float = 30.0,
        audit_writer: AuditWriter,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None: ...

    async def acquire(
        self, *, canonical_user_id: UserId, persona: PersonaId,
    ) -> Acquired | Dropped: ...
```

### `src/alfred/orchestrator/core.py` (extension)

```python
async def quarantined_extract(
    self,
    body: bytes | str | Mapping[str, object],
    *,
    canonical_user_id: UserId,
    source_tier: Literal["T3"],
) -> ExtractionResult:
    """Thin wrapper into the Slice-3 quarantined extractor.

    The wrapper enforces source_tier == "T3" — comms inbound bodies cannot
    silently promote to T2 (sec-001 round-3 closure). Passing source_tier="T2"
    raises ValueError.
    """
    if source_tier != "T3":
        raise ValueError(...)
    return await self._quarantined_extractor.extract(
        body, canonical_user_id=canonical_user_id, source_tier="T3",
    )
```

### `src/alfred/supervisor/core.py` (extension)

Two new methods. Both write through the existing breaker / audit primitives.

```python
async def request_plugin_restart(
    self, *, adapter_id: PluginId, reason: Literal[
        "unknown_notification",
        "handler_repeated_failures",
        "manifest_handshake_failure",
    ],
) -> None: ...

async def trip_breaker(
    self, *, component_id: ComponentId, reason: Literal[
        "comms_handler_repeated_failures",
        "plugin_lifecycle_crash",
        ...   # other Slice-3 reasons stay valid
    ],
) -> None: ...
```

Implementation note: `Supervisor` already holds `_breakers: dict[str, CircuitBreaker]` (verified at `src/alfred/supervisor/core.py:189`); `trip_breaker` calls into the existing breaker's `trip(reason)`. The new method is the public, reason-checked façade. `reset_breaker` already exists; `trip_breaker` is the symmetric counterpart for failure-driven transitions.

### `src/alfred/plugins/session.py` (extension at line 347)

`_on_post_handshake_method` is **extended in place**. The existing SIGKILL-on-disallowed-method behaviour for `alfred/hooks.register` (Slice-3, lines 366–417) stays. The new behaviour adds the four-arm dispatch arm BEFORE the `_DISALLOWED_POST_HANDSHAKE_METHODS` short-circuit returns to the no-op tail. Pseudocode:

```python
async def _on_post_handshake_method(
    self, method: str, params: Mapping[str, object] | None = None,
) -> None:
    if method in _DISALLOWED_POST_HANDSHAKE_METHODS:
        # Existing Slice-3 SIGKILL path — unchanged.
        ...
        return

    # PR-S4-8 EXTENSION — dispatch comms notifications.
    if method in _COMMS_NOTIFICATION_METHODS:
        async with self._dispatch_semaphore:
            try:
                match method:
                    case "inbound.message":
                        ...
                    case "adapter.binding_request":
                        ...
                    case "adapter.rate_limit_signal":
                        ...
                    case "adapter.crashed":
                        ...
            except Exception as exc:
                await self._emit_handler_failed(method, exc)
                self._error_counter.increment()
                if self._error_counter.exceeds(
                    threshold=3, window=timedelta(minutes=5),
                ):
                    await self._supervisor.trip_breaker(
                        component_id=self._adapter_id,
                        reason="comms_handler_repeated_failures",
                    )
                raise   # propagates to StdioTransport reader; caught & continued there
        return

    # Unknown method.
    await self._emit_unknown_notification(method, params)
    await self._supervisor.request_plugin_restart(
        adapter_id=self._adapter_id, reason="unknown_notification",
    )
```

`method: str` is the only Slice-3 parameter; the extension adds `params` as an optional named parameter with a default of `None` to preserve Slice-3 callers (the Slice-3 disallowed-method path does not use `params`).

The signature change is **additive and backwards-compatible** — every Slice-3 caller passing positional `method` still works.

### `src/alfred/config/settings.py` (extension)

```python
comms_max_in_flight_notifications: int = Field(
    default=32,
    ge=1,
    le=1024,
    description=(
        "Per-adapter cap on concurrent inbound notification handlers. "
        "Higher values trade memory for throughput; backpressure begins at this cap."
    ),
)
```

Env override: `ALFRED_COMMS_MAX_IN_FLIGHT_NOTIFICATIONS`.

### `src/alfred/policies/models.py` (extension)

```python
class BurstLimitConfig(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    capacity_tokens: int = Field(default=5, ge=1, le=100)
    refill_seconds: float = Field(default=5.0, gt=0.0, le=3600.0)
    drop_after_seconds: float = Field(default=30.0, ge=1.0, le=600.0)

class RateLimitsV1(BaseModel):
    quarantined_extract_per_user_persona: BurstLimitConfig = Field(
        default_factory=BurstLimitConfig,
    )
    ...   # other Slice-3 rate-limit groups stay

class PoliciesV1(BaseModel):
    rate_limits: RateLimitsV1 = Field(default_factory=RateLimitsV1)
    ...
```

### Hookpoint registrations (added to `src/alfred/hooks/registrations.py`)

```python
register_hookpoint(
    name="comms.inbound.t3_promoted",
    fail_closed=True,
    allow_error_substitution=False,
    carrier_tier="T3",                          # PR-S4-3 required field
    subscribable_tiers=frozenset({"T0", "T1"}),  # quarantined subscribers refused
    payload_schema_name="COMMS_INBOUND_T3_PROMOTION_FIELDS",
)
register_hookpoint(
    name="comms.adapter.crashed",
    fail_closed=True,
    allow_error_substitution=False,
    carrier_tier="T0",
    subscribable_tiers=frozenset({"T0", "T1", "T2"}),
    payload_schema_name="COMMS_ADAPTER_CRASHED_FIELDS",
)
```

The `comms.inbound.dropped` audit event is **not** a hookpoint (it's an audit row emitted by `BurstLimiter`). The `comms.adapter.binding_requested` and `comms.adapter.rate_limit_signal` hookpoints belong to **PR-S4-9** per the index §3 table; this PR leaves them unregistered.

---

## §5 Tasks

Tasks follow TDD: write failing test → confirm FAIL → implement → confirm PASS → commit. All commits use `(#152, #TBD-slice4-pr-s4-8)`. Each section's tasks must complete before the next section.

---

### Component A — Wire-format module (`src/alfred/comms_mcp/protocol.py`)

- [ ] **Task 1 — Package skeleton.**

  Files: Create `src/alfred/comms_mcp/__init__.py` (empty for now), `src/alfred/comms_mcp/protocol.py` (skeleton), `tests/unit/comms_mcp/__init__.py`.

  **Failing test** at `tests/unit/comms_mcp/test_protocol_schemas.py`:

  ```python
  def test_module_imports() -> None:
      from alfred.comms_mcp import protocol
      assert hasattr(protocol, "LifecycleStartRequest")
      assert hasattr(protocol, "OutboundMessageResult")
      assert hasattr(protocol, "InboundMessageNotification")
      assert hasattr(protocol, "adapter_kind")
      assert hasattr(protocol, "BODY_FIELD_BY_KIND")
  ```

  Run: `uv run pytest tests/unit/comms_mcp/test_protocol_schemas.py -q` → ImportError.

  **Implementation**: create the skeleton module with stub class definitions. No fields yet; just the class names so the import succeeds. Confirm PASS, commit.

- [ ] **Task 2 — `adapter_kind` frozenset + immutability test.**

  Failing test in `tests/unit/comms_mcp/test_adapter_kind_literal.py`:

  ```python
  from alfred.comms_mcp.protocol import adapter_kind, BODY_FIELD_BY_KIND

  def test_adapter_kind_is_frozenset() -> None:
      assert isinstance(adapter_kind, frozenset)

  def test_adapter_kind_immutable() -> None:
      with pytest.raises((AttributeError, TypeError)):
          adapter_kind.add("malicious")  # type: ignore[attr-defined]

  def test_adapter_kind_contains_reference_plugin() -> None:
      assert "alfred_comms_test" in adapter_kind

  def test_adapter_kind_does_not_contain_discord_yet() -> None:
      # discord lands in PR-S4-9
      assert "discord" not in adapter_kind

  def test_body_field_by_kind_keys_match_adapter_kind() -> None:
      # Every adapter_kind must have a body-field entry (comms-011 closure).
      assert set(BODY_FIELD_BY_KIND.keys()) == adapter_kind
  ```

  Run → expect AttributeError (constants not defined).

  **Implementation**: add `adapter_kind: Final[frozenset[str]] = frozenset({"alfred_comms_test"})` and `BODY_FIELD_BY_KIND: Final[Mapping[str, str]] = MappingProxyType({"alfred_comms_test": "content"})` to `protocol.py`. Confirm PASS, commit.

- [ ] **Task 3 — `LifecycleStartRequest` / `LifecycleStartResult` schemas.**

  Failing tests cover: required fields (`adapter_id`, `credentials_ref`, `policies_snapshot_hash`), frozen model (mutation raises), extra fields rejected (`extra="forbid"`), invalid `adapter_id` rejected (must be in `adapter_kind` set — validator).

  **Implementation**: add Pydantic v2 models with `ConfigDict(frozen=True, extra="forbid")`. `adapter_id` is `Annotated[str, AfterValidator(_check_adapter_kind)]`. Confirm PASS, commit.

- [ ] **Task 4 — `LifecycleStopRequest` / `LifecycleStopResult` schemas.**

  Failing tests cover: required `adapter_id` + `reason: Literal["operator", "supervisor", "config_reload", "shutdown"]`; result carries `ok: bool` + `flushed_messages: int` (`ge=0`); frozen; extra forbidden.

  **Implementation**: as above. Confirm PASS, commit.

- [ ] **Task 5 — `AdapterHealthRequest` / `HealthReport` schemas.**

  Failing tests cover: `last_inbound_at: datetime | None` (None when no inbound yet); `queue_depth: int` (`ge=0`); `error_count: int` (`ge=0`); `ok: bool`; aware-timestamp validator on `last_inbound_at` (reject naive datetimes).

  **Implementation**: include `model_validator(mode="after")` that calls a shared `_assert_aware_or_none` helper. Confirm PASS, commit.

- [ ] **Task 6 — `OutboundMessageRequest` schema.**

  Failing tests cover: `idempotency_key: UUID` (not `str` — Pydantic should reject `"abc"` as not-a-UUID); `target_platform_id: str` (`min_length=1`); `body: str` (the post-DLP body — caller is responsible; field is plain `str`); `attachments_refs: tuple[ContentRef, ...]` (tuple, not list — frozen-friendly); `addressing_mode: PersonaAddressingMode` (Literal); `adapter_id` validator (same `_check_adapter_kind` as Task 3).

  **Implementation**: Pydantic v2 with `frozen=True`. `ContentRef` is a small Pydantic model — `class ContentRef(BaseModel): handle_id: UUID; kind: Literal["embed","attachment","poll","link_unfurl","sticker","voice_message","component","forwarded_ref","pinned_ref"]; model_config = ConfigDict(frozen=True, extra="forbid")`. Confirm PASS, commit.

- [ ] **Task 7 — `OutboundMessageResult` discriminated union (comms-008).**

  Failing tests at `tests/unit/comms_mcp/test_outbound_message_result_union.py`:

  ```python
  def test_delivered_has_no_retry_after() -> None:
      delivered = _OutboundDelivered(outcome="delivered", platform_message_id="m1")
      with pytest.raises(AttributeError):
          delivered.retry_after_seconds  # noqa: B018

  def test_retryable_requires_retry_after() -> None:
      with pytest.raises(ValidationError):
          _OutboundRetryable(outcome="retryable_failure", error_class="rate_limited")
      ok = _OutboundRetryable(
          outcome="retryable_failure", retry_after_seconds=30, error_class="rate_limited",
      )
      assert ok.retry_after_seconds == 30

  def test_terminal_requires_detail_redacted_le_256() -> None:
      _OutboundTerminal(
          outcome="terminal_failure", error_class="forbidden",
          detail_redacted="x" * 256,
      )
      with pytest.raises(ValidationError):
          _OutboundTerminal(
              outcome="terminal_failure", error_class="forbidden",
              detail_redacted="x" * 257,
          )

  def test_discriminator_routes_by_outcome() -> None:
      adapter = TypeAdapter(OutboundMessageResult)
      result = adapter.validate_python({"outcome": "delivered", "platform_message_id": "m1"})
      assert isinstance(result, _OutboundDelivered)
      result = adapter.validate_python({
          "outcome": "retryable_failure", "retry_after_seconds": 5, "error_class": "rl",
      })
      assert isinstance(result, _OutboundRetryable)
      result = adapter.validate_python({
          "outcome": "terminal_failure", "error_class": "forbidden", "detail_redacted": "x",
      })
      assert isinstance(result, _OutboundTerminal)

  def test_discriminator_rejects_unknown_outcome() -> None:
      adapter = TypeAdapter(OutboundMessageResult)
      with pytest.raises(ValidationError):
          adapter.validate_python({"outcome": "weird", "platform_message_id": "m1"})

  def test_all_variants_frozen() -> None:
      d = _OutboundDelivered(outcome="delivered", platform_message_id="m1")
      with pytest.raises(ValidationError):
          d.platform_message_id = "m2"  # type: ignore[misc]
  ```

  **Implementation**: define the three variants and the `Annotated[U, Field(discriminator="outcome")]` alias. `detail_redacted: str = Field(max_length=256)`. Confirm PASS, commit.

- [ ] **Task 8 — Plugin → host notification schemas.**

  Failing tests at `tests/unit/comms_mcp/test_inbound_notification_schemas.py`:

  ```python
  def test_inbound_message_required_fields() -> None:
      n = InboundMessageNotification(
          adapter_id="alfred_comms_test",
          platform_user_id="discord:123",
          body={"content": "hello"},
          sub_payload_refs=(),
          received_at=datetime.now(UTC),
          addressing_signal="dm",
      )
      assert n.addressing_signal == "dm"

  def test_inbound_message_rejects_naive_received_at() -> None:
      with pytest.raises(ValidationError):
          InboundMessageNotification(
              ..., received_at=datetime(2026, 6, 7, 12, 0, 0),  # naive
          )

  def test_binding_request_required_fields() -> None:
      n = BindingRequestNotification(
          adapter_id="alfred_comms_test",
          platform_user_id="discord:123",
          verification_phrase="banana phone 7",
          platform_metadata={"username": "alice"},
      )
      assert n.verification_phrase == "banana phone 7"

  def test_rate_limit_signal_retry_after_ge_0() -> None:
      RateLimitSignal(
          adapter_id="alfred_comms_test",
          retry_after_seconds=0,
          platform_endpoint="gateway",
      )
      with pytest.raises(ValidationError):
          RateLimitSignal(
              adapter_id="alfred_comms_test",
              retry_after_seconds=-1,
              platform_endpoint="gateway",
          )

  def test_crashed_notification_required_fields() -> None:
      c = CrashedNotification(
          adapter_id="alfred_comms_test",
          error_class="ConnectionResetError",
          detail="redacted by plugin",
      )
      assert c.error_class == "ConnectionResetError"
  ```

  **Implementation**: define the four notification models with `frozen=True`, `extra="forbid"`, and aware-datetime validators where applicable. The `body: Mapping[str, object]` field — Pydantic v2 accepts `dict` and freezes via `model_config`. Confirm PASS, commit.

- [ ] **Task 9 — Pydantic schema roundtrip + JSON contract test.**

  Failing test asserting `model_dump_json()` → `model_validate_json()` round-trip for every model in §4. This catches accidental breakage when adding fields in PR-S4-9/10.

  **Implementation**: parametrised test over `[LifecycleStartRequest, ..., CrashedNotification]`. Confirm PASS, commit.

---

### Component B — Classifier registry (`src/alfred/comms_mcp/classifier_registry.py`)

- [ ] **Task 10 — `REQUIRED_CLASSIFIERS_BY_KIND` table + `MARKER_NO_CLASSIFIERS_NEEDED`.**

  Failing test at `tests/unit/comms_mcp/test_required_classifiers_complete.py`:

  ```python
  import ast
  import pathlib

  from alfred.comms_mcp.classifier_registry import (
      REQUIRED_CLASSIFIERS_BY_KIND,
      MARKER_NO_CLASSIFIERS_NEEDED,
  )
  from alfred.comms_mcp.protocol import adapter_kind

  def test_every_adapter_kind_has_an_entry() -> None:
      # sec-002 round-3: no kind may be missing from REQUIRED_CLASSIFIERS_BY_KIND.
      missing = adapter_kind - set(REQUIRED_CLASSIFIERS_BY_KIND.keys())
      assert missing == set(), f"Adapter kinds without classifier entry: {missing}"

  def test_empty_entry_requires_marker() -> None:
      # Empty classifier set must justify with MARKER_NO_CLASSIFIERS_NEEDED.
      for kind, classifiers in REQUIRED_CLASSIFIERS_BY_KIND.items():
          if not classifiers:
              assert kind in MARKER_NO_CLASSIFIERS_NEEDED, (
                  f"Adapter kind {kind!r} has empty classifier set but no "
                  f"MARKER_NO_CLASSIFIERS_NEEDED justification."
              )

  def test_registry_is_mapping_proxy() -> None:
      from types import MappingProxyType
      assert isinstance(REQUIRED_CLASSIFIERS_BY_KIND, MappingProxyType)
  ```

  **Implementation**: write the module per §4 schema. Confirm PASS, commit.

- [ ] **Task 11 — AST guard against empty-set bypass (PR-shaped adversarial mirror).**

  This is the structural test mirrored from spec §11 corpus (`cib-2026-004`). It scans the registry source file with `ast` and asserts no adapter-kind addition lands without either a non-empty classifier set OR a `MARKER_NO_CLASSIFIERS_NEEDED` entry.

  **Failing test** uses `ast.parse` over `src/alfred/comms_mcp/classifier_registry.py` and a tiny synthetic patch fixture. The synthetic patch adds `"malicious": frozenset()` without a marker; the test asserts the guard raises.

  **Implementation**: write the guard as a pytest test that parses the live file with `ast.parse`, extracts the assignments, and computes the missing-marker set. Confirm PASS, commit.

- [ ] **Task 12 — `register_classifier` decorator.**

  Failing test at `tests/unit/comms_mcp/test_classifier_registry_import_registration.py`:

  ```python
  def test_decorator_registers_class() -> None:
      from alfred.comms_mcp.classifier_registry import register_classifier, get_classifier

      @register_classifier(kind="alfred_comms_test", name="noop_classifier")
      class NoopClassifier:
          ...

      assert get_classifier(kind="alfred_comms_test", name="noop_classifier") is NoopClassifier

  def test_decorator_idempotent_on_reimport() -> None:
      # Importing the module twice must not raise "double registration".
      import importlib, alfred.comms_mcp.classifier_registry as r
      importlib.reload(r)
      importlib.reload(r)  # second reload must not error
  ```

  **Implementation**: module-level private dict keyed by `(kind, name)`; decorator returns the class unchanged; `get_classifier` looks up; reload-safe via `setdefault`. Confirm PASS, commit.

---

### Component C — `BurstLimiter` (`src/alfred/orchestrator/burst_limiter.py`)

This is **honest new Slice-4 scope** per sec-008 round-3 — not a citation of a non-existent Slice-3 primitive. The Slice-2 `BudgetGuard` exists but caps USD-per-day; it cannot stop sub-second token-extract bursts.

- [ ] **Task 13 — `Acquired` / `Dropped` dataclasses.**

  Failing test at `tests/unit/orchestrator/test_burst_limiter_basic.py`:

  ```python
  def test_acquired_is_frozen() -> None:
      a = Acquired(tokens_remaining=4, waited_seconds=0.0)
      with pytest.raises(FrozenInstanceError):
          a.tokens_remaining = 0  # type: ignore[misc]

  def test_dropped_carries_bucket_empty_since() -> None:
      now = datetime.now(UTC)
      d = Dropped(waited_seconds=30.0, bucket_empty_since=now)
      assert d.bucket_empty_since == now
  ```

  **Implementation**: `@dataclass(frozen=True)` for both. Confirm PASS, commit.

- [ ] **Task 14 — Single-key bucket: capacity + refill.**

  Failing test asserts:
  1. 5 sequential `acquire` calls succeed instantly (`waited_seconds == 0`).
  2. The 6th `acquire` waits `~5s` until refill.
  3. After waiting 5s, refill restores exactly 1 token.
  4. `tokens_remaining` is honest.

  Use a monkey-patched clock + `asyncio.sleep` so the test runs in subsecond wall time.

  **Implementation**: token-bucket algorithm. State per key: `tokens: float`, `last_refill_at: datetime`. On each `acquire`, refill = `(now - last_refill_at) / refill_seconds`; cap at `capacity`. If `tokens >= 1`, consume; else wait `(1 - tokens) * refill_seconds`. Confirm PASS, commit.

- [ ] **Task 15 — Per-(canonical_user_id, persona) independence.**

  Failing test at `tests/unit/orchestrator/test_burst_limiter_per_user_persona.py`:

  ```python
  async def test_independent_buckets() -> None:
      limiter = BurstLimiter(capacity_tokens=5, refill_seconds=5.0, audit_writer=spy)
      for _ in range(5):
          assert isinstance(
              await limiter.acquire(canonical_user_id="u_a", persona="alfred"),
              Acquired,
          )
      # u_a/alfred is drained, but u_b/alfred is fresh.
      r = await limiter.acquire(canonical_user_id="u_b", persona="alfred")
      assert isinstance(r, Acquired)
      # u_a/oracle is also independent.
      r = await limiter.acquire(canonical_user_id="u_a", persona="oracle")
      assert isinstance(r, Acquired)
  ```

  **Implementation**: bucket key = `(canonical_user_id, persona)`; use `dict[tuple[UserId, PersonaId], _BucketState]` with an `asyncio.Lock` per key (lazily created). Confirm PASS, commit.

- [ ] **Task 16 — `COMMS_INBOUND_BUDGET_CAPPED_FIELDS` emit on backpressure.**

  Failing test at `tests/unit/orchestrator/test_burst_limiter_emits_capped_audit.py`:

  ```python
  async def test_emits_capped_audit_row_when_waited() -> None:
      audit = SpyAuditWriter()
      limiter = BurstLimiter(
          capacity_tokens=1, refill_seconds=0.1, audit_writer=audit,
      )
      await limiter.acquire(canonical_user_id="u", persona="alfred")  # consumes token
      result = await limiter.acquire(canonical_user_id="u", persona="alfred")  # waits ~0.1s
      assert isinstance(result, Acquired)
      assert result.waited_seconds > 0
      capped_rows = audit.rows_with_schema("COMMS_INBOUND_BUDGET_CAPPED_FIELDS")
      assert len(capped_rows) == 1
      assert capped_rows[0]["dropped"] is False
      assert capped_rows[0]["wait_seconds"] == pytest.approx(result.waited_seconds, rel=0.1)
  ```

  **Implementation**: emit the audit row whenever `waited_seconds > 0`. Field values per spec §9 (`tokens_available`, `wait_seconds`, `dropped`, `persona`, `canonical_user_id`, `adapter_id`). Confirm PASS, commit.

- [ ] **Task 17 — Drop after 30s of bucket-empty (`comms.inbound.dropped`).**

  Failing test at `tests/unit/orchestrator/test_burst_limiter_drop_after_30s.py`:

  ```python
  async def test_drops_after_drop_after_seconds() -> None:
      audit = SpyAuditWriter()
      limiter = BurstLimiter(
          capacity_tokens=1, refill_seconds=300.0, drop_after_seconds=0.5,
          audit_writer=audit,
      )
      await limiter.acquire(canonical_user_id="u", persona="alfred")  # consumes; bucket empty
      result = await limiter.acquire(canonical_user_id="u", persona="alfred")
      assert isinstance(result, Dropped)
      assert result.waited_seconds >= 0.5
      capped_rows = audit.rows_with_schema("COMMS_INBOUND_BUDGET_CAPPED_FIELDS")
      assert capped_rows[-1]["dropped"] is True
      # Distinct audit event (NOT a hookpoint per §3) for the hard drop.
      dropped_rows = audit.rows_with_event("comms.inbound.dropped")
      assert len(dropped_rows) == 1
  ```

  **Implementation**: when projected wait exceeds `drop_after_seconds`, return `Dropped` with `waited_seconds == drop_after_seconds`. Emit BOTH the capped row (with `dropped=True`) and the `comms.inbound.dropped` audit event. Confirm PASS, commit.

- [ ] **Task 18 — `PoliciesV1.rate_limits.quarantined_extract_per_user_persona` config.**

  Failing test at `tests/unit/policies/test_burst_limit_config.py`:

  ```python
  def test_burst_limit_config_defaults_match_limiter_defaults() -> None:
      c = BurstLimitConfig()
      assert c.capacity_tokens == 5
      assert c.refill_seconds == 5.0
      assert c.drop_after_seconds == 30.0

  def test_burst_limit_config_validates_bounds() -> None:
      with pytest.raises(ValidationError):
          BurstLimitConfig(capacity_tokens=0)
      with pytest.raises(ValidationError):
          BurstLimitConfig(capacity_tokens=101)
      with pytest.raises(ValidationError):
          BurstLimitConfig(refill_seconds=0)

  def test_policies_v1_yaml_roundtrip() -> None:
      yaml_str = """
      rate_limits:
        quarantined_extract_per_user_persona:
          capacity_tokens: 10
          refill_seconds: 2.0
          drop_after_seconds: 60.0
      """
      policies = PoliciesV1.model_validate(yaml.safe_load(yaml_str))
      assert policies.rate_limits.quarantined_extract_per_user_persona.capacity_tokens == 10
  ```

  **Implementation**: per §4 schema. Confirm PASS, commit.

- [ ] **Task 19 — `BurstLimiter` reads config from `PoliciesSnapshotRef`.**

  Failing test asserts the limiter dereferences the snapshot per `acquire` call (PR-S4-4 invariant — no captured-cap idiom).

  ```python
  async def test_limiter_observes_hot_reloaded_capacity() -> None:
      snapshot_ref = PoliciesSnapshotRef(initial=PoliciesV1(
          rate_limits=RateLimitsV1(
              quarantined_extract_per_user_persona=BurstLimitConfig(capacity_tokens=1, ...),
          ),
      ))
      limiter = BurstLimiter.from_snapshot_ref(snapshot_ref, audit_writer=audit)
      await limiter.acquire(canonical_user_id="u", persona="alfred")  # uses cap=1
      snapshot_ref.set(PoliciesV1(
          rate_limits=RateLimitsV1(
              quarantined_extract_per_user_persona=BurstLimitConfig(capacity_tokens=10, ...),
          ),
      ))
      # Next acquire on a fresh key uses cap=10.
      for _ in range(10):
          await limiter.acquire(canonical_user_id="v", persona="alfred")
  ```

  **Implementation**: store `PoliciesSnapshotRef`; per-acquire deref. Confirm PASS, commit.

---

### Component D — `Orchestrator.quarantined_extract` wrapper

`Orchestrator.quarantined_extract` does NOT yet exist (verified by fabricated-surfaces gate). This PR adds it.

- [ ] **Task 20 — Wrapper method on `Orchestrator`.**

  Failing test at `tests/unit/orchestrator/test_quarantined_extract_preserves_source_tier.py`:

  ```python
  async def test_calls_underlying_extractor_with_source_tier_t3() -> None:
      extractor = SpyQuarantinedExtractor()
      orch = Orchestrator(..., quarantined_extractor=extractor)
      result = await orch.quarantined_extract(
          body={"content": "hi"}, canonical_user_id="u", source_tier="T3",
      )
      assert extractor.called_with["source_tier"] == "T3"
      assert isinstance(result, ExtractionResult)
      assert result.data.__class__.__name__ == "dict"  # T3DerivedData runtime is dict
  ```

  **Implementation**: thin async method delegating to `self._quarantined_extractor.extract(body, canonical_user_id=..., source_tier="T3")`. Existing `QuarantinedExtractor` in `src/alfred/security/quarantine.py` returns `ExtractionResult` (verified). Confirm PASS, commit.

- [ ] **Task 21 — Refuse silent T2 promotion.**

  Failing test at `tests/unit/orchestrator/test_quarantined_extract_refuses_silent_promotion.py`:

  ```python
  async def test_refuses_t2_for_comms_inbound() -> None:
      orch = Orchestrator(...)
      with pytest.raises(ValueError, match="comms inbound must be T3"):
          await orch.quarantined_extract(
              body={"content": "hi"}, canonical_user_id="u",
              source_tier="T2",  # type: ignore[arg-type]
          )
  ```

  **Implementation**: explicit `if source_tier != "T3": raise ValueError(t("orchestrator.quarantined_extract.source_tier_must_be_t3"))`. The `source_tier: Literal["T3"]` annotation also catches static violations under mypy; runtime check guards dynamic abuse. Confirm PASS, commit.

---

### Component E — `process_inbound_message` entrypoint

- [ ] **Task 22 — Resolution-first ordering.**

  Failing test at `tests/unit/comms_mcp/test_inbound_resolution_first.py`:

  ```python
  async def test_resolution_consulted_before_orchestrator() -> None:
      resolver = SpyIdentityResolver(returns=None)  # first-contact
      orch = SpyOrchestrator()
      audit = SpyAuditWriter()
      await process_inbound_message(
          notification, identity_resolver=resolver,
          orchestrator=orch, burst_limiter=spy_limiter,
          audit_writer=audit,
      )
      assert resolver.resolve_calls == 1
      assert orch.quarantined_extract_calls == 0
      assert orch.ingest_calls == 0
      assert orch.dispatch_calls == 0
      # COMMS_BINDING_REQUESTED emitted instead.
      assert len(audit.rows_with_schema("COMMS_BINDING_REQUESTED_FIELDS")) == 1
  ```

  **Implementation**: per §4 + spec §8.2 pseudocode. Resolver called first; `None` → emit binding row + early return. Confirm PASS, commit.

- [ ] **Task 23 — Burst-gate BEFORE quarantined_extract.**

  Failing test at `tests/unit/comms_mcp/test_inbound_burst_gate_before_extract.py`:

  ```python
  async def test_burst_limiter_acquire_precedes_extract() -> None:
      call_order: list[str] = []
      limiter = SpyBurstLimiter(on_acquire=lambda: call_order.append("burst"))
      orch = SpyOrchestrator(
          on_extract=lambda: call_order.append("extract"),
      )
      await process_inbound_message(
          notification, identity_resolver=resolver_returning_resolved,
          orchestrator=orch, burst_limiter=limiter, audit_writer=audit,
      )
      assert call_order.index("burst") < call_order.index("extract")
  ```

  Per spec §8.2: "the bucket refuses to call quarantined_extract when empty."

  **Implementation**: in `process_inbound_message`, call `await burst_limiter.acquire(canonical_user_id, persona)` BEFORE `await orchestrator.quarantined_extract(...)`. On `Dropped`, return early without calling the extractor. Confirm PASS, commit.

- [ ] **Task 24 — `Orchestrator.quarantined_extract` invoked with `source_tier="T3"`.**

  Failing test at `tests/unit/comms_mcp/test_inbound_quarantined_extract_source_tier.py`:

  ```python
  async def test_extract_called_with_t3() -> None:
      orch = SpyOrchestrator()
      await process_inbound_message(...)
      assert orch.quarantined_extract_calls == 1
      assert orch.last_extract_kwargs["source_tier"] == "T3"
  ```

  **Implementation**: explicit `source_tier="T3"` keyword at the call site. Confirm PASS, commit.

- [ ] **Task 25 — `COMMS_INBOUND_T3_PROMOTION_FIELDS` emit.**

  Failing test at `tests/unit/comms_mcp/test_inbound_t3_promotion_audit_row.py`:

  ```python
  async def test_t3_promotion_audit_row_emitted_after_extract() -> None:
      audit = SpyAuditWriter()
      await process_inbound_message(..., audit_writer=audit)
      rows = audit.rows_with_schema("COMMS_INBOUND_T3_PROMOTION_FIELDS")
      assert len(rows) == 1
      r = rows[0]
      assert r["adapter_id"] == notification.adapter_id
      assert "platform_user_id_hash" in r
      assert r["canonical_user_id"] == resolved.canonical_user_id
      assert isinstance(r["sub_payload_kinds"], frozenset)
      assert r["addressing_signal"] == notification.addressing_signal
      assert r["language"] == resolved.language
      # The raw platform_user_id must NOT appear.
      assert notification.platform_user_id not in str(r)
  ```

  **Implementation**: after a successful extract, emit the row with `platform_user_id_hash = _peppered_hash(notification.platform_user_id)` and the full field set. Confirm PASS, commit.

- [ ] **Task 26 — Peppered-hash helper.**

  Failing test at `tests/unit/audit/test_comms_audit_rows_emit_with_pepper.py`:

  ```python
  def test_peppered_hash_uses_broker_pepper() -> None:
      broker = SpySecretBroker(secrets={"audit.hash_pepper": "test-pepper-32-bytes"})
      h = _peppered_hash("discord:123", broker=broker)
      expected = hmac.new(
          key=b"test-pepper-32-bytes", msg=b"discord:123", digestmod=hashlib.sha256,
      ).hexdigest()[:32]
      assert h == expected
      assert len(h) == 32
      assert "discord:123" not in h
  ```

  **Implementation**: `def _peppered_hash(raw: str, *, broker: SecretBroker) -> str` per spec §8.10 recipe. Pepper fetched **once at construction** of `AuditWriter` (PR-S4-0b bootstrap, this PR consumes); the helper takes the bytes directly, not the broker. Confirm PASS, commit.

- [ ] **Task 27 — Ingest + dispatch ordering.**

  Failing test:

  ```python
  async def test_ingest_then_dispatch_after_extract() -> None:
      call_order: list[str] = []
      orch = SpyOrchestrator(
          on_extract=lambda: call_order.append("extract"),
          on_ingest=lambda: call_order.append("ingest"),
          on_dispatch=lambda: call_order.append("dispatch"),
      )
      await process_inbound_message(...)
      assert call_order == ["extract", "ingest", "dispatch"]
  ```

  Per spec §8.2: order is `resolution → tier-classify → ingest → dispatch`. Tier-classify maps to `quarantined_extract`.

  **Implementation**: per spec §8.2 pseudocode. `orchestrator.ingest(notification, body=extracted.data, addressing_signal=...)` then `await orchestrator.dispatch(ingested)`. Confirm PASS, commit.

- [ ] **Task 28 — Canonical id never leaves the host (positive + negative assertion).**

  Failing test at `tests/unit/comms_mcp/test_inbound_canonical_id_never_leaves_host.py`:

  ```python
  async def test_canonical_id_not_in_outbound_frames() -> None:
      captured_frames: list[bytes] = []
      session = build_test_session(outbound_frame_sink=captured_frames.append)
      await process_inbound_message(
          notification, identity_resolver=resolver_returns_resolved,
          orchestrator=orch_that_dispatches_outbound,
          burst_limiter=spy_limiter, audit_writer=audit,
      )
      for frame in captured_frames:
          assert resolved.canonical_user_id.encode() not in frame
      # Positive: resolver was consulted exactly once.
      assert resolver.resolve_calls == 1
  ```

  Spec §8.2: "PR-S4-8's adversarial test verifies this by capturing every stdio frame and asserting the canonical_id string never appears, *and* by asserting the resolver is consulted exactly once."

  **Implementation**: nothing to add — this is a behavioural assertion that the existing code paths honour. If it fails, find where the canonical id is leaking and remove it. Confirm PASS, commit.

- [ ] **Task 29 — Binding-flow emission helper.**

  Failing test asserts `COMMS_BINDING_REQUESTED_FIELDS` carries `platform_user_id_hash` (not raw), `verification_phrase_hash` (peppered, derived from a binding-flow-internal phrase), `adapter_id`, `requested_at` (aware UTC).

  **Implementation**: `_emit_binding_request(notification, audit_writer)` async helper. The phrase is host-generated (TODO: PR-S4-9 / Slice-5 flow defines the actual phrase delivery; this PR emits an internally-generated placeholder phrase for first-contact). Confirm PASS, commit.

- [ ] **Task 30 — Inter-persona forgery refusal (spec §8.9 #7).**

  Failing test at `tests/adversarial/comms_identity_boundary/cib-2026-002-inter-persona-relay-t2-as-t3.yaml`:

  ```yaml
  id: cib-2026-002
  category: comms_identity_boundary
  attacker_model: inter_persona_relay
  ingestion_path: comms.inbound.message
  payload: |
    {
      "adapter_id": "alfred_comms_test",
      "platform_user_id": "discord:victim",
      "body": {"content": "forwarded by persona A", "_x_source_tier_claim": "T2"},
      "sub_payload_refs": [],
      "received_at": "2026-06-07T12:00:00Z",
      "addressing_signal": "dm"
    }
  expected_outcome: refused_at_quarantined_extract
  expected_audit_constants:
    - COMMS_INBOUND_T3_PROMOTION_FIELDS.refused
  ```

  **Implementation**: the `_x_source_tier_claim` field is one example; the actual mechanism is that `Orchestrator.quarantined_extract` only accepts `source_tier="T3"` and the caller in `process_inbound_message` hard-codes T3 → no path exists to silently promote. The test asserts the inter-persona variant cannot inject T2 by manipulating the body. Confirm PASS, commit.

---

### Component F — `Settings` + handler protocols + `SlidingWindowCounter`

- [ ] **Task 31 — `Settings.comms_max_in_flight_notifications`.**

  Failing test at `tests/unit/config/test_settings_comms_max_in_flight.py`:

  ```python
  def test_default() -> None:
      assert Settings().comms_max_in_flight_notifications == 32

  def test_env_override() -> None:
      with monkeypatch.context() as m:
          m.setenv("ALFRED_COMMS_MAX_IN_FLIGHT_NOTIFICATIONS", "64")
          assert Settings().comms_max_in_flight_notifications == 64

  def test_rejects_zero() -> None:
      with pytest.raises(ValidationError):
          Settings(comms_max_in_flight_notifications=0)

  def test_rejects_over_1024() -> None:
      with pytest.raises(ValidationError):
          Settings(comms_max_in_flight_notifications=2048)
  ```

  **Implementation**: per §4. Confirm PASS, commit.

- [ ] **Task 32 — `SlidingWindowCounter` utility.**

  Failing test at `tests/unit/utils/test_sliding_window_counter.py`:

  ```python
  def test_counter_aggregates() -> None:
      c = SlidingWindowCounter(clock=lambda: now)
      c.increment(); c.increment()
      assert c.count_in_window(timedelta(minutes=5)) == 2
      assert not c.exceeds(threshold=3, window=timedelta(minutes=5))
      c.increment()
      assert c.exceeds(threshold=3, window=timedelta(minutes=5))

  def test_entries_age_out() -> None:
      clock_value = [datetime(2026, 6, 7, 12, 0, 0, tzinfo=UTC)]
      c = SlidingWindowCounter(clock=lambda: clock_value[0])
      c.increment()
      clock_value[0] += timedelta(minutes=6)
      assert c.count_in_window(timedelta(minutes=5)) == 0
  ```

  **Implementation**: deque-of-timestamps; `exceeds` aged-out lazily. Confirm PASS, commit.

- [ ] **Task 33 — Handler `Protocol` definitions.**

  Failing test asserting `InboundHandler`, `BindingHandler`, `RateLimitHandler`, `CrashHandler` each declare an `async def process(self, notification) -> None` Protocol method (structural).

  **Implementation**: `src/alfred/comms_mcp/handlers.py` per §4. Each Protocol uses `@runtime_checkable`. Confirm PASS, commit.

- [ ] **Task 34 — Concrete handler classes.**

  Failing test instantiates each handler with mocks; calls `.process(notification)`; verifies handler delegates to `process_inbound_message`, `_emit_binding_request`, `OutboundQueue.pause`, or `_emit_crashed_audit` respectively.

  **Implementation**:
  - `InboundHandler.process` → `await process_inbound_message(...)`.
  - `BindingHandler.process` → `await _emit_binding_request(...)`; subsequent flow (out-of-band phrase delivery) is Slice-5 scope.
  - `RateLimitHandler.process` → `await self._outbound_queue.pause(adapter_id, retry_after_seconds)` + emit `COMMS_RATE_LIMIT_SIGNAL_FIELDS`.
  - `CrashHandler.process` → emit `COMMS_ADAPTER_CRASHED_FIELDS` + fire `comms.adapter.crashed` hookpoint.

  Confirm PASS, commit.

---

### Component G — `AlfredPluginSession._on_post_handshake_method` extension

This is the **REAL method at `src/alfred/plugins/session.py:347`** (core-011 round-4 lesson — not a fabricated `_read_loop` or `_on_notification`). Extension only, backwards-compatible signature.

- [ ] **Task 35 — Constructor extension: handler params + semaphore + counter.**

  Failing test at `tests/unit/plugins/test_session_constructor_handler_params.py`:

  ```python
  def test_constructor_accepts_new_handlers() -> None:
      session = AlfredPluginSession(
          ...,
          inbound_handler=Mock(spec=InboundHandler),
          binding_handler=Mock(spec=BindingHandler),
          rate_limit_handler=Mock(spec=RateLimitHandler),
          crash_handler=Mock(spec=CrashHandler),
          dispatch_semaphore=asyncio.BoundedSemaphore(value=32),
          error_counter=SlidingWindowCounter(),
          supervisor=Mock(spec=Supervisor),
      )
      assert session._dispatch_semaphore is not None

  def test_constructor_backwards_compatible() -> None:
      # Slice-3 callers pass no comms args; the session still constructs.
      session = AlfredPluginSession(... existing-Slice-3-args ...)
      assert session._inbound_handler is None  # no-op if absent
  ```

  **Implementation**: extend `__init__` with the six new keyword-only params defaulting to `None`. The existing positional/keyword signature is preserved. `self._dispatch_semaphore = dispatch_semaphore or _NoopSemaphore()` where `_NoopSemaphore` is an async-context-manager no-op for the Slice-3 disallowed-method path (which is the only path Slice-3 callers hit). Confirm PASS, commit.

- [ ] **Task 36 — Match arm for `inbound.message`.**

  Failing test at `tests/unit/comms_mcp/test_session_inbound_dispatch.py`:

  ```python
  async def test_inbound_message_routed_to_inbound_handler() -> None:
      handler = AsyncMock(spec=InboundHandler)
      session = build_session(inbound_handler=handler)
      await session._on_post_handshake_method(
          method="inbound.message",
          params={
              "adapter_id": "alfred_comms_test",
              "platform_user_id": "discord:123",
              "body": {"content": "hi"},
              "sub_payload_refs": [],
              "received_at": "2026-06-07T12:00:00Z",
              "addressing_signal": "dm",
          },
      )
      handler.process.assert_awaited_once()
      call_arg = handler.process.await_args.args[0]
      assert isinstance(call_arg, InboundMessageNotification)
      assert call_arg.platform_user_id == "discord:123"
  ```

  **Implementation**: add the match arm + `InboundMessageNotification.model_validate(params)` + handler delegate. Confirm PASS, commit.

- [ ] **Task 37 — Match arms for the other three notifications.**

  Failing tests parameterised over the three:
  - `adapter.binding_request` → `binding_handler.process(BindingRequestNotification(...))`.
  - `adapter.rate_limit_signal` → `rate_limit_handler.process(RateLimitSignal(...))`.
  - `adapter.crashed` → `crash_handler.process(CrashedNotification(...))`.

  **Implementation**: add the three arms. Confirm PASS, commit.

- [ ] **Task 38 — Unknown method emits row + restart.**

  Failing test at `tests/unit/comms_mcp/test_session_unknown_notification.py`:

  ```python
  async def test_unknown_method_audits_and_restarts() -> None:
      supervisor = AsyncMock(spec=Supervisor)
      audit = SpyAuditWriter()
      session = build_session(supervisor=supervisor, audit_writer=audit)
      await session._on_post_handshake_method(
          method="some.unknown.thing",
          params={"x": 1},
      )
      assert len(audit.rows_with_schema("COMMS_UNKNOWN_NOTIFICATION_FIELDS")) == 1
      supervisor.request_plugin_restart.assert_awaited_once_with(
          adapter_id=session._adapter_id, reason="unknown_notification",
      )
  ```

  **Implementation**: the `case _:` arm. Drop is NOT silent — typed audit row first, then supervisor call. Per spec §8.4 — and the unknown path does NOT raise; it handles the case directly.

  Critical 6: ensure the audit row carries `method_redacted_params` (the params dict with `redact()` applied to all string values). Confirm PASS, commit.

- [ ] **Task 39 — `async with` semaphore wraps the whole block.**

  Failing test at `tests/unit/comms_mcp/test_session_dispatch_semaphore.py`:

  ```python
  async def test_semaphore_acquired_and_released_on_success() -> None:
      sem = asyncio.BoundedSemaphore(value=2)
      session = build_session(dispatch_semaphore=sem)
      await session._on_post_handshake_method("inbound.message", params)
      # Sem fully restored.
      for _ in range(2):
          assert sem.acquire_nowait()

  async def test_semaphore_released_on_exception() -> None:
      sem = asyncio.BoundedSemaphore(value=1)
      handler = AsyncMock(side_effect=RuntimeError("boom"))
      session = build_session(dispatch_semaphore=sem, inbound_handler=handler)
      with pytest.raises(RuntimeError):
          await session._on_post_handshake_method("inbound.message", params)
      assert sem.acquire_nowait()  # released

  async def test_two_sessions_independent_semaphores() -> None:
      sem_a = asyncio.BoundedSemaphore(value=1)
      sem_b = asyncio.BoundedSemaphore(value=1)
      session_a = build_session(dispatch_semaphore=sem_a)
      session_b = build_session(dispatch_semaphore=sem_b)
      # A's storm cannot starve B.
      slow_handler = make_slow_handler(duration_s=0.5)
      session_a._inbound_handler = slow_handler
      asyncio.create_task(session_a._on_post_handshake_method("inbound.message", params))
      # B proceeds immediately.
      start = time.monotonic()
      await session_b._on_post_handshake_method("inbound.message", params)
      assert time.monotonic() - start < 0.2
  ```

  **Implementation**: `async with self._dispatch_semaphore:` wrapping the match block. Per spec §8.4 — `async with` (not `acquire`/`release`) guarantees release on exception (core-008 closure). Confirm PASS, commit.

- [ ] **Task 40 — Handler failure: loud audit + counter + re-raise.**

  Failing test at `tests/unit/comms_mcp/test_session_handler_failure_loud.py`:

  ```python
  async def test_handler_exception_emits_audit_and_raises() -> None:
      handler = AsyncMock(side_effect=RuntimeError("downstream broke"))
      audit = SpyAuditWriter()
      session = build_session(inbound_handler=handler, audit_writer=audit)
      with pytest.raises(RuntimeError, match="downstream broke"):
          await session._on_post_handshake_method("inbound.message", params)
      rows = audit.rows_with_schema("COMMS_HANDLER_FAILED_FIELDS")
      assert len(rows) == 1
      assert rows[0]["error_class"] == "RuntimeError"
      assert rows[0]["notification_method"] == "inbound.message"
      assert "broke" in rows[0]["detail_redacted"]
  ```

  Per err-007 round-3: handler exceptions are loud, not silent.

  **Implementation**: `except Exception as exc:` block — emit `COMMS_HANDLER_FAILED_FIELDS`, increment counter, then `raise` (NOT `pass`, NOT `return`). The `detail_redacted` field passes the exception's `str()` through `OutboundDlp.scan` truncated to 512 chars per spec §8.4 pseudocode. Confirm PASS, commit.

- [ ] **Task 41 — Breaker trips on 3 failures in 5 minutes.**

  Failing test at `tests/unit/comms_mcp/test_session_breaker_trips_on_3_failures.py`:

  ```python
  async def test_two_failures_does_not_trip() -> None:
      supervisor = AsyncMock(spec=Supervisor)
      handler = AsyncMock(side_effect=RuntimeError())
      session = build_session(supervisor=supervisor, inbound_handler=handler)
      for _ in range(2):
          with pytest.raises(RuntimeError):
              await session._on_post_handshake_method("inbound.message", params)
      supervisor.trip_breaker.assert_not_awaited()

  async def test_third_failure_trips_breaker() -> None:
      supervisor = AsyncMock(spec=Supervisor)
      handler = AsyncMock(side_effect=RuntimeError())
      session = build_session(supervisor=supervisor, inbound_handler=handler)
      for _ in range(3):
          with pytest.raises(RuntimeError):
              await session._on_post_handshake_method("inbound.message", params)
      supervisor.trip_breaker.assert_awaited_once_with(
          component_id=session._adapter_id,
          reason="comms_handler_repeated_failures",
      )

  async def test_failures_outside_5min_window_do_not_count() -> None:
      clock = [datetime.now(UTC)]
      counter = SlidingWindowCounter(clock=lambda: clock[0])
      session = build_session(error_counter=counter)
      with pytest.raises(RuntimeError):
          await session._on_post_handshake_method("inbound.message", params)
      clock[0] += timedelta(minutes=6)
      with pytest.raises(RuntimeError):
          await session._on_post_handshake_method("inbound.message", params)
      # First failure aged out; only 1 in window.
      assert not counter.exceeds(threshold=3, window=timedelta(minutes=5))
  ```

  **Implementation**: after `_error_counter.increment()`, check `_error_counter.exceeds(threshold=3, window=timedelta(minutes=5))` and call `await self._supervisor.trip_breaker(...)`. The trip happens BEFORE re-raise. Confirm PASS, commit.

- [ ] **Task 42 — Handler fan-out is sequential per notification (perf-003 clarification).**

  Failing test at `tests/unit/comms_mcp/test_session_handler_fan_out_ordering.py`:

  ```python
  async def test_single_notification_does_not_fan_out_concurrently() -> None:
      # The session dispatches each notification to exactly one handler.
      # A single notification does not concurrently fire two handlers.
      handler = AsyncMock(spec=InboundHandler)
      session = build_session(inbound_handler=handler)
      await session._on_post_handshake_method("inbound.message", params)
      assert handler.process.await_count == 1
  ```

  Per spec §8.4 last paragraph: "Handler callbacks are awaited sequentially per notification (no concurrent fan-out for a single message)."

  **Implementation**: structural — already true given the match block. The test pins the invariant. Confirm PASS, commit.

---

### Component H — `Supervisor` extensions

- [ ] **Task 43 — `Supervisor.request_plugin_restart`.**

  Failing test at `tests/unit/supervisor/test_request_plugin_restart.py`:

  ```python
  async def test_writes_restart_requested_audit_row() -> None:
      audit = SpyAuditWriter()
      supervisor = Supervisor(..., audit_writer=audit)
      await supervisor.request_plugin_restart(
          adapter_id="alfred_comms_test",
          reason="unknown_notification",
      )
      rows = audit.rows_with_schema("SUPERVISOR_PLUGIN_RESTART_REQUESTED_FIELDS")
      assert len(rows) == 1
      assert rows[0]["plugin_id"] == "alfred_comms_test"
      assert rows[0]["reason"] == "unknown_notification"
      assert rows[0]["requester"] == "AlfredPluginSession"

  async def test_marks_adapter_unhealthy() -> None:
      breaker_spy = SpyBreaker()
      supervisor = Supervisor(..., breakers={"alfred_comms_test": breaker_spy})
      await supervisor.request_plugin_restart(
          adapter_id="alfred_comms_test", reason="unknown_notification",
      )
      assert breaker_spy.mark_unhealthy_calls == 1

  async def test_invalid_reason_rejected() -> None:
      with pytest.raises(ValueError):
          await supervisor.request_plugin_restart(
              adapter_id="alfred_comms_test", reason="bogus",  # type: ignore[arg-type]
          )
  ```

  **Implementation**: per §4. Reason is a Literal-typed param with three accepted values. Emits the row using the new `SUPERVISOR_PLUGIN_RESTART_REQUESTED_FIELDS` constant (PR-S4-0a-shipped). The supervisor's existing breaker loop spawns a fresh adapter on next tick — this method only requests, doesn't itself spawn. Confirm PASS, commit.

- [ ] **Task 44 — `Supervisor.trip_breaker` extension.**

  Failing test at `tests/unit/supervisor/test_trip_breaker_comms_reason.py`:

  ```python
  async def test_trip_breaker_accepts_comms_reason() -> None:
      supervisor = Supervisor(...)
      breaker = supervisor._breakers["alfred_comms_test"] = CircuitBreaker(...)
      await supervisor.trip_breaker(
          component_id="alfred_comms_test",
          reason="comms_handler_repeated_failures",
      )
      assert breaker.state == BreakerState.OPEN

  async def test_trip_breaker_unknown_reason_rejected() -> None:
      with pytest.raises(ValueError):
          await supervisor.trip_breaker(
              component_id="alfred_comms_test", reason="bogus",  # type: ignore[arg-type]
          )
  ```

  **Implementation**: `Supervisor.trip_breaker` is a NEW method (the verb appears in PR-S4-3 prose but no `Supervisor.trip_breaker` method exists in Slice 3 — only `CircuitBreaker.trip(reason)` does). The new method's Literal `reason` union accepts `comms_handler_repeated_failures` plus the Slice-3 enumerable reasons (`plugin_lifecycle_crash`, etc.). It delegates to the per-component breaker's existing `trip(reason)`. Emits the existing `supervisor.breaker.tripped` audit row. Confirm PASS, commit.

- [ ] **Task 45 — Idempotency.**

  Failing test asserts double calls to `request_plugin_restart` within a single supervisor tick don't emit two rows (defensive against handler-failure storms causing audit spam).

  **Implementation**: per-tick dedup set keyed by `(adapter_id, reason)`; cleared at tick boundary. Confirm PASS, commit.

---

### Component I — `InboundContentScanner` extension

- [ ] **Task 46 — `BODY_FIELD_BY_KIND` consultation.**

  Failing test at `tests/unit/comms_mcp/test_inbound_scanner_body_field_per_kind.py`:

  ```python
  @pytest.mark.parametrize("kind,field,body", [
      ("alfred_comms_test", "content", {"content": "hi"}),
      # Discord / TUI / Telegram added by PR-S4-9 / PR-S4-10 / post-MVP.
  ])
  def test_scanner_extracts_body_field_per_kind(kind, field, body) -> None:
      scanner = InboundContentScanner(...)
      scanned = scanner.scan(adapter_kind=kind, body=body)
      assert scanned.body_text == body[field]
  ```

  **Implementation**: `InboundContentScanner.scan(adapter_kind, body)` looks up `BODY_FIELD_BY_KIND[adapter_kind]` and extracts the field. Missing field → emit empty string + emit `comms.scanner.body_field_missing` structlog event (advisory). Confirm PASS, commit.

- [ ] **Task 47 — Classifier dispatch (host-side, plugin-opaque).**

  Failing test asserts:
  - For `adapter_kind="alfred_comms_test"`, no classifiers run (empty required set + marker).
  - The plugin's `classifiers_optional` list cannot override the required set.

  **Implementation**: `scan` reads the required set + optional set (from plugin manifest, parsed earlier by `AlfredPluginSession`), unions them with `required` being authoritative, and dispatches each. For the reference plugin in this PR, the result is a single body and zero sub-payloads. The Discord-specific classifier ships in PR-S4-9. Confirm PASS, commit.

---

### Component J — Hookpoint registrations

- [ ] **Task 48 — Register `comms.inbound.t3_promoted` and `comms.adapter.crashed`.**

  Failing test at `tests/unit/hooks/test_comms_hookpoints_registered.py`:

  ```python
  def test_t3_promoted_hookpoint_carrier_tier_t3() -> None:
      registry = HookRegistry.instance()
      meta = registry.get_meta("comms.inbound.t3_promoted")
      assert meta.carrier_tier == "T3"
      assert meta.fail_closed is True
      assert meta.allow_error_substitution is False
      # Quarantined subscribers refused.
      assert "T3" not in meta.subscribable_tiers
      assert "T0" in meta.subscribable_tiers and "T1" in meta.subscribable_tiers

  def test_crashed_hookpoint_carrier_tier_t0() -> None:
      registry = HookRegistry.instance()
      meta = registry.get_meta("comms.adapter.crashed")
      assert meta.carrier_tier == "T0"
      assert meta.fail_closed is True
  ```

  **Implementation**: per §4 registrations. The `carrier_tier` field is a PR-S4-3 dependency — if absent at import, the registration itself fails. Confirm PASS, commit.

---

### Component K — Reference plugin (`plugins/alfred_comms_test/`)

The Slice-3 stub one-shot becomes a full-lifecycle adapter.

- [ ] **Task 49 — Manifest update.**

  File: `plugins/alfred_comms_test/manifest.toml`.

  ```toml
  [plugin]
  plugin_id = "alfred_comms_test"
  manifest_version = 1
  subscriber_tier = "T2"   # the plugin process is T2; inbound bodies become T3 host-side

  [comms_mcp]
  adapter_kind = "alfred_comms_test"
  classifiers_optional = []

  [sandbox]
  kind = "none"   # comms relay; PR-S4-6 invariant for relay adapters

  [entrypoint]
  executable = "python"
  args = ["-m", "plugins.alfred_comms_test.main"]
  ```

  Failing test at `tests/unit/comms_mcp/test_reference_plugin_manifest.py` asserts manifest parses + declares `adapter_kind: alfred_comms_test` + `sandbox.kind: none`.

  **Implementation**: write the manifest. Confirm PASS, commit.

- [ ] **Task 50 — Plugin process implementation.**

  File: `plugins/alfred_comms_test/main.py`. Uses the `model_context_protocol` SDK as a server. Implements:
  - `lifecycle.start` → returns `LifecycleStartResult(ok=True, plugin_version="0.1.0")`.
  - `lifecycle.stop` → flushes any in-flight outbound, returns `LifecycleStopResult(ok=True, flushed_messages=...)`.
  - `adapter.health` → returns `HealthReport(ok=True, last_inbound_at=..., queue_depth=0, error_count=0)`.
  - `outbound.message` → records the message in an in-memory buffer; returns `_OutboundDelivered`.
  - On a test-trigger stdin command (an internal protocol — `alfred_comms_test/inject_inbound`), emits an `inbound.message` notification to the host.
  - Similar test triggers for `binding_request`, `rate_limit_signal`, `crashed`.

  Failing test at `tests/integration/test_comms_mcp_reference_plugin_lifecycle.py` (sketch):

  ```python
  async def test_full_lifecycle(launched_reference_plugin) -> None:
      session = await launched_reference_plugin.handshake()
      await session.request("lifecycle.start", LifecycleStartRequest(...))
      await launched_reference_plugin.inject_inbound({"content": "hello"})
      await wait_for_outbound_audit_row("OUTBOUND_DELIVERED_FIELDS")
      stop_result = await session.request("lifecycle.stop", LifecycleStopRequest(...))
      assert stop_result.flushed_messages == 0
  ```

  **Implementation**: write the plugin module. Use `asyncio` + `stdio`. Confirm PASS, commit.

- [ ] **Task 51 — Reference plugin healthcheck integration.**

  Failing test: host calls `adapter.health` every 30s; reference plugin responds with `HealthReport`; on three missed responses, supervisor marks adapter unhealthy.

  **Implementation**: supervisor-side periodic health probe (already exists in Slice-3 for transport health; this test wires the comms-MCP-specific request). Confirm PASS, commit.

---

### Component L — Cross-fork integration test (merge-blocking)

- [ ] **Task 52 — `tests/integration/test_comms_mcp_identity_boundary_real.py` — spec §8.9 seven assertions.**

  This test is **merge-blocking** per spec §11.5 / index §4. It is promoted to a required-status check as part of this PR's merge. Setup: real Postgres via testcontainers + real reference plugin spawned via launcher + planted forged-canonical-id payload.

  ```python
  @pytest.mark.integration
  async def test_152_closure_seven_assertions(
      postgres_container, audit_writer, launched_reference_plugin,
  ) -> None:
      # 1) Notification reaches process_inbound_message exactly once.
      counter = SpyCounter()
      orig = process_inbound_message
      async def wrapper(*args, **kwargs):
          counter.increment()
          return await orig(*args, **kwargs)
      monkeypatch.setattr("alfred.comms_mcp.inbound.process_inbound_message", wrapper)

      # 2) IdentityResolver.resolve consulted exactly once with platform identifiers.
      resolver_spy = SpyIdentityResolver(wrapped=real_resolver)

      # Plant forged canonical_user_id in platform_metadata.
      forged_payload = {
          "adapter_id": "alfred_comms_test",
          "platform_user_id": "discord:victim",
          "body": {"content": "attack"},
          "sub_payload_refs": [],
          "received_at": datetime.now(UTC).isoformat(),
          "addressing_signal": "dm",
          "platform_metadata": {"canonical_user_id": "u_attacker_forged"},
      }
      await launched_reference_plugin.inject_inbound(forged_payload)
      await wait_for_audit_row("COMMS_INBOUND_T3_PROMOTION_FIELDS")

      assert counter.count == 1   # (1)
      assert resolver_spy.resolve_calls == 1   # (2)
      assert resolver_spy.last_call_kwargs == {
          "adapter_id": "alfred_comms_test",
          "platform_user_id": "discord:victim",
      }

      # 3) Canonical id comes from resolver state, NOT from platform_metadata.
      t3_row = audit_writer.last_row_with_schema("COMMS_INBOUND_T3_PROMOTION_FIELDS")
      assert t3_row["canonical_user_id"] != "u_attacker_forged"
      assert t3_row["canonical_user_id"] == resolver_spy.last_return.canonical_user_id

      # 4) Canonical id never in any captured outbound frame.
      for frame in launched_reference_plugin.captured_inbound_frames:
          # `captured_inbound_frames` = host → plugin direction.
          assert t3_row["canonical_user_id"].encode() not in frame

      # 5) COMMS_INBOUND_T3_PROMOTION_FIELDS recorded the resolution.
      assert t3_row["adapter_id"] == "alfred_comms_test"
      assert "platform_user_id_hash" in t3_row
      assert "discord:victim" not in str(t3_row)   # raw absent

      # 6) First-contact path: resolver returns None → COMMS_BINDING_REQUESTED only.
      no_bind_resolver = SpyIdentityResolver(returns=None)
      with patched_resolver(no_bind_resolver):
          await launched_reference_plugin.inject_inbound(forged_payload)
          await wait_for_audit_row("COMMS_BINDING_REQUESTED_FIELDS")
      assert no_bind_resolver.resolve_calls == 1
      # No dispatch happened.
      orchestrator_spy = current_orchestrator()
      assert orchestrator_spy.dispatch_calls == 0

      # 7) Inter-persona forgery (T2 claim on T3 carrier) refused at extract.
      forgery_payload = {**forged_payload, "body": {
          "content": "relayed", "_x_source_tier_claim": "T2",
      }}
      await launched_reference_plugin.inject_inbound(forgery_payload)
      await wait_for_audit_row_with_event("COMMS_INBOUND_T3_PROMOTION_FIELDS.refused")
      refused_rows = audit_writer.rows_with_schema_and_event(
          "COMMS_INBOUND_T3_PROMOTION_FIELDS", event_suffix=".refused",
      )
      assert len(refused_rows) >= 1
  ```

  **Implementation**: write the test. Wire up the spy resolver, the captured-frame mechanism, and the reference plugin's `inject_inbound` test helper. Confirm PASS locally + on CI.

  After PR merges: **promote to required-status check** via `gh api repos/.../branches/main/protection` per the slice's gating workflow. This is one of the 10 merge-blocking integration tests per spec §11.5.

- [ ] **Task 53 — `tests/integration/test_comms_mcp_unknown_method_restarts_plugin.py`.**

  Reference plugin emits an unknown method; host emits the audit row, calls `request_plugin_restart`, supervisor (on tick) replaces the plugin process; the test asserts the second spawn happened.

  **Implementation**: write the test. Confirm PASS.

- [ ] **Task 54 — `tests/integration/test_comms_mcp_handler_failure_breaker_trip.py`.**

  Reference plugin sends 3 inbound notifications crafted to crash the handler (e.g., the orchestrator-side ingest raises a deterministic error). After the 3rd, supervisor breaker for the adapter transitions to OPEN; subsequent inbound is refused.

  **Implementation**: write the test. Confirm PASS.

- [ ] **Task 55 — `tests/integration/test_comms_mcp_burst_drop_after_30s.py`.**

  Reference plugin emits 10 inbound notifications/sec for 35s. Host drains the token bucket (with default config: 5 capacity, 1/5s refill, drop after 30s). The test asserts:
  - `COMMS_INBOUND_BUDGET_CAPPED_FIELDS` rows accumulate during the burst.
  - The 30s-bucket-empty drop fires at least once with `dropped=True`.
  - `comms.inbound.dropped` audit event records.
  - The host does NOT crash or stop accepting eventually-legitimate traffic after the burst ends.

  **Implementation**: write the test using a faster-clock fixture so total runtime is bounded. Confirm PASS.

---

### Component M — Adversarial corpus entries

- [ ] **Task 56 — `cib-2026-001-forged-canonical-id-in-platform-metadata.yaml`.**

  YAML per spec §11.2/§11.3 schema. Attacker model: `inbound_message_forgery`. Ingestion path: `comms.inbound.message`. Expected outcome: `refused_via_resolver_state_takes_precedence`. Audit constants: `COMMS_INBOUND_T3_PROMOTION_FIELDS`. Adversarial harness runs the YAML against `process_inbound_message` and asserts the canonical id used is the resolver's, not the planted one.

- [ ] **Task 57 — `cib-2026-002-inter-persona-relay-t2-as-t3.yaml`.**

  Already drafted in Task 30. Final commit ties this into the corpus runner.

- [ ] **Task 58 — `cib-2026-003-canonical-id-leakage-on-outbound.yaml`.**

  Adversarial harness captures all outbound stdio frames during a round-trip; asserts no canonical id substring present.

- [ ] **Task 59 — `cib-2026-004-empty-classifier-set-bypass.yaml`.**

  PR-shaped attack: a malicious diff adds `adapter_kind = "evil"` with `REQUIRED_CLASSIFIERS_BY_KIND["evil"] = frozenset()` and no `MARKER_NO_CLASSIFIERS_NEEDED["evil"]`. AST guard `tests/unit/comms_mcp/test_required_classifiers_complete.py` (Task 10) refuses. The corpus entry mirrors the structural protection.

- [ ] **Task 60 — `cib-2026-005-handler-exception-silenced.yaml`.**

  Failing test ensures: if a handler swallows an exception silently (returns None instead of raising), the dispatcher does NOT emit `COMMS_HANDLER_FAILED_FIELDS` — this is correct because the dispatcher cannot observe the swallowed exception. The corpus entry codifies that **the only place to fix this is at the handler level**; the dispatcher's contract is: handlers MUST raise. A separate AST guard (`tests/unit/comms_mcp/test_handlers_never_swallow.py`) scans each handler's `process` method body for bare `except: pass` patterns and refuses.

---

### Component N — Coverage gate + observability

- [ ] **Task 61 — 100% line + branch coverage on trust-boundary files.**

  Per CLAUDE.md: "Every security boundary must have 100% line and branch coverage."

  Trust-boundary files for this PR (spec §14 criterion 11):
  - `src/alfred/comms_mcp/protocol.py`
  - `src/alfred/comms_mcp/inbound.py`
  - `src/alfred/comms_mcp/inbound_scanner.py`
  - `src/alfred/comms_mcp/classifier_registry.py`
  - `src/alfred/comms_mcp/handlers.py`
  - `src/alfred/orchestrator/burst_limiter.py`
  - `src/alfred/plugins/session.py` (the `_on_post_handshake_method` extension delta)

  Add to `.coveragerc` `[report]` section + the existing `make check` coverage gate. Confirm `coverage run --source=... --fail-under=100` passes.

- [ ] **Task 62 — Prometheus histograms (perf-002 / perf-009 precedent).**

  Add four histograms:
  - `alfred_comms_inbound_dispatch_seconds` — wall time of `_on_post_handshake_method` call.
  - `alfred_comms_quarantined_extract_seconds` — wall time of `Orchestrator.quarantined_extract`.
  - `alfred_comms_burst_limiter_wait_seconds` — `Acquired.waited_seconds`.
  - `alfred_comms_handler_failures_total` — counter of `COMMS_HANDLER_FAILED_FIELDS` emits.

  Failing test asserts each metric exists and observes after a successful round-trip.

- [ ] **Task 63 — Update `make check`.**

  - Add `tests/unit/comms_mcp/` to default unit run.
  - Add `tests/integration/test_comms_mcp_identity_boundary_real.py` to the integration run.
  - Add coverage gate for the trust-boundary files above.
  - Wire `tests/adversarial/comms_identity_boundary/` into the adversarial runner.

---

## §6 Audit-emit-site map

Every emit site in this PR (each must use `await self._audit.append_schema(fields, **kwargs)` — no inlined field-list literals):

| Site | Constant | Trigger |
|---|---|---|
| `process_inbound_message` (after extract) | `COMMS_INBOUND_T3_PROMOTION_FIELDS` | Successful inbound that passed the burst gate + extract |
| `process_inbound_message.refused_path` | `COMMS_INBOUND_T3_PROMOTION_FIELDS` with `.refused` event suffix | Inter-persona forgery / T2 claim refused at extract |
| `_emit_binding_request` | `COMMS_BINDING_REQUESTED_FIELDS` | `IdentityResolver.resolve` returned None (first-contact) |
| `BurstLimiter.acquire` (backpressure) | `COMMS_INBOUND_BUDGET_CAPPED_FIELDS(dropped=False)` | `waited_seconds > 0` and acquire eventually succeeded |
| `BurstLimiter.acquire` (hard drop) | `COMMS_INBOUND_BUDGET_CAPPED_FIELDS(dropped=True)` + `comms.inbound.dropped` event | Bucket empty for `drop_after_seconds` |
| `_on_post_handshake_method.case _` | `COMMS_UNKNOWN_NOTIFICATION_FIELDS` | Unknown method name |
| `_on_post_handshake_method.except` | `COMMS_HANDLER_FAILED_FIELDS` | Handler raised |
| `Supervisor.request_plugin_restart` | `SUPERVISOR_PLUGIN_RESTART_REQUESTED_FIELDS` | Either unknown method or repeated failures |
| `Supervisor.trip_breaker` | existing `supervisor.breaker.tripped` row | Counter exceeds 3/5min |
| `RateLimitHandler.process` | `COMMS_RATE_LIMIT_SIGNAL_FIELDS` | Plugin signalled platform-side rate limit |
| `CrashHandler.process` | `COMMS_ADAPTER_CRASHED_FIELDS` | Plugin crashed (notification ahead of process exit) |
| Outbound emit path (host → plugin) | `COMMS_ADDRESSING_DRIFT_FIELDS` | Outbound `addressing_mode` doesn't match the prior inbound `addressing_signal` for the same conversation; non-refusing observability emit |

`COMMS_ADDRESSING_DRIFT_FIELDS` ships in this PR as the audit-emit site but the call site is in the outbound path (not in `process_inbound_message`). The outbound queue lives elsewhere (Slice-3); the integration with `addressing_mode` validation is added here as a small extension.

---

## §7 Spec coverage map

| Spec section | Implementing task(s) |
|---|---|
| §8.1 Wire-method tables (8 methods) | Tasks 3–9 |
| §8.1 `OutboundMessageResult` discriminated union (comms-008) | Task 7 |
| §8.1 `addressing_mode` Literal mapping to PRD §6.8 (comms-012) | Tasks 6, plus outbound-drift emit-site in §6 above |
| §8.1 `comms_mcp/protocol.py` path (Critical 1) | Task 1 |
| §8.2 `process_inbound_message` order: resolution → extract → ingest → dispatch | Tasks 22, 23, 24, 27 |
| §8.2 BurstLimiter primitive (sec-008 round-3) | Tasks 13–19 |
| §8.2 Canonical id never crosses the wire | Tasks 28, 52 |
| §8.3 `IdentityResolver` callback wire type (`ResolvedIdentity \| None`) | Task 22 + reference resolver wiring |
| §8.4 `_on_post_handshake_method` extension at `src/alfred/plugins/session.py:347` (core-011 round-4 lesson) | Tasks 35–42 |
| §8.4 `async with self._dispatch_semaphore` (core-008 + perf-003) | Task 39 |
| §8.4 Unknown method emits typed row + `request_plugin_restart` (Critical 6) | Task 38 |
| §8.4 Try/except + counter + breaker trip on 3/5min (err-007) | Tasks 40, 41 |
| §8.4 `Supervisor.request_plugin_restart` + `Supervisor.trip_breaker` (core-006) | Tasks 43, 44, 45 |
| §8.5 `InboundContentScanner` extension + `REQUIRED_CLASSIFIERS_BY_KIND` host-owned (sec-002 round-3) | Tasks 10, 11, 46, 47 |
| §8.5 `BODY_FIELD_BY_KIND` per-kind body field (comms-011) | Task 2 |
| §8.5 AST guard `test_required_classifiers_complete.py` | Tasks 10, 11 |
| §8.9 ADR-0009 caveat narrowing | **Deferred to PR-S4-10** (docs-001 closure) |
| §8.9 #152 closure 7-point assertions | Task 52 |
| §8.10 Audit row family (8 new constants) | All emit-site tasks; constants from PR-S4-0a |
| §8.10 Peppered hash recipe (sec-010 round-3) | Task 26 |
| §10 Hookpoints `comms.inbound.t3_promoted` (T3) + `comms.adapter.crashed` (T0) | Task 48 |
| §11 Adversarial corpus entries `cib-2026-001..005` | Tasks 56–60 |

---

## §8 Pre-flight verification (fabricated-surfaces gate)

Per CLAUDE.md surgical-changes rule + Slice-3 lesson (`AlfredPluginSession._read_loop` did not exist; `_on_post_handshake_method` does). Grep results captured at plan-write time:

| Cited symbol | Status | Source |
|---|---|---|
| `AlfredPluginSession._on_post_handshake_method` | **EXISTS** at `src/alfred/plugins/session.py:347` | `grep "_on_post_handshake_method" src/alfred/plugins/session.py` |
| `class AlfredPluginSession.__init__` | **EXISTS** at `src/alfred/plugins/session.py:145` | as above |
| `class Orchestrator` | **EXISTS** at `src/alfred/orchestrator/core.py:189` | `grep "class Orchestrator" src/alfred/orchestrator/core.py` |
| `Orchestrator.quarantined_extract` | **DOES NOT EXIST** — this PR adds it (Task 20). The verb appears only in docstrings inside `src/alfred/security/quarantine.py`. | `grep -rn "quarantined_extract" src/alfred/` — only doc hits |
| `ExtractionResult` | **EXISTS** at `src/alfred/security/quarantine.py:274` (defined via `@dataclass`) | `grep "class ExtractionResult" src/alfred/security/quarantine.py` |
| `T3DerivedData` | **EXISTS** at `src/alfred/security/quarantine.py:145` (NewType) | as above |
| `class Supervisor` | **EXISTS** at `src/alfred/supervisor/core.py:146` | `grep "class Supervisor" src/alfred/supervisor/core.py` |
| `Supervisor.reset_breaker` | **EXISTS** (Slice-3) | `grep "reset_breaker" src/alfred/supervisor/core.py` |
| `Supervisor.trip_breaker` | **DOES NOT EXIST** — this PR adds it (Task 44). The verb refers conceptually to `CircuitBreaker.trip(reason)` which exists on the breaker class but not on the supervisor public surface. | `grep "def trip_breaker" src/alfred/supervisor/core.py` — empty |
| `Supervisor.request_plugin_restart` | **DOES NOT EXIST** — this PR adds it (Task 43). | `grep "request_plugin_restart" src/alfred/` — empty |
| `class IdentityResolver` | **EXISTS** at `src/alfred/identity/resolver.py:115` | `grep "class IdentityResolver" src/alfred/identity/resolver.py` |
| `SecretBroker.get` | **EXISTS** at `src/alfred/security/secrets.py:396` (verified by index §3 reference + sec-010 round-3 closure) | index §3 |
| `Settings.comms_max_in_flight_notifications` | **DOES NOT EXIST** — this PR adds it (Task 31). | `grep "comms_max_in_flight_notifications" src/alfred/` — empty |
| `BurstLimiter` / `src/alfred/orchestrator/burst_limiter.py` | **DOES NOT EXIST** — this PR creates it (Tasks 13–19). Honest Slice-4 scope expansion per sec-008 round-3. | `grep -rn "BurstLimiter" src/alfred/` — empty |
| `src/alfred/comms_mcp/` | **DOES NOT EXIST** — this PR creates it. The unrelated `src/alfred/comms/` exists (deletion in PR-S4-10, not here). | `ls src/alfred/comms_mcp` — missing; `ls src/alfred/comms` — exists |
| `COMMS_*_FIELDS` constants | **DO NOT EXIST** in current `audit_row_schemas.py` — they land in **PR-S4-0a**, which is a dependency of this PR. | `grep "COMMS_INBOUND_T3_PROMOTION_FIELDS" src/alfred/audit/audit_row_schemas.py` — empty |
| `HookpointMeta.carrier_tier` | **DOES NOT EXIST** in current `src/alfred/hooks/registry.py:HookpointMeta` (Slice-3 baseline). Added by **PR-S4-3**, which is a dependency of this PR. | `grep "carrier_tier" src/alfred/hooks/registry.py` — empty |
| `PoliciesV1.rate_limits.quarantined_extract_per_user_persona` | **DOES NOT EXIST** — this PR adds it (Task 18). | `grep "quarantined_extract_per_user_persona" src/alfred/` — empty |
| `register_hookpoint(...)` | **EXISTS** at `src/alfred/hooks/registry.py:539` (Slice-3) | `grep "def register_hookpoint" src/alfred/hooks/registry.py` |
| `OutboundDlp.scan` | **EXISTS** (Slice-3) | precedent — used by PR-S3-3a |

**No cited symbol in the plan body is fabricated.** Every "extension" task targets a real method; every "new" task is honestly flagged as new and explains the cross-PR origin where applicable.

---

## §9 Implementation order recap

Sequential dependency order (each task block builds on the previous):

1. **Wire format first** (Tasks 1–9, 10–12) — schemas + classifier registry are pure data; consumers depend on them.
2. **Primitives** (Tasks 13–19, 32) — `BurstLimiter`, `SlidingWindowCounter`; pure logic; independent of comms wiring.
3. **Orchestrator wrapper** (Tasks 20–21) — `quarantined_extract` thin façade.
4. **Inbound entrypoint** (Tasks 22–30) — composes the primitives + orchestrator + identity resolver.
5. **Configuration + handlers** (Tasks 31, 33, 34) — handler protocols + Settings field.
6. **Session extension** (Tasks 35–42) — the dispatcher at `_on_post_handshake_method`.
7. **Supervisor extensions** (Tasks 43–45) — `request_plugin_restart` + `trip_breaker`.
8. **Scanner + hookpoints** (Tasks 46–48) — depends on classifier registry from step 1.
9. **Reference plugin** (Tasks 49–51) — depends on the wire format + dispatcher being live.
10. **Integration tests** (Tasks 52–55) — merge-blocking #152 closure + lifecycle / unknown / breaker / burst.
11. **Adversarial corpus** (Tasks 56–60) — codifies the security invariants.
12. **Coverage + observability** (Tasks 61–63) — final gate.

Each step's tests pass before the next step starts. The merge-blocking integration test (Task 52) is the last functional gate; coverage + observability (Tasks 61–63) is the quality gate.

---

## §10 Risks + mitigations

| Risk | Mitigation |
|---|---|
| `AlfredPluginSession._on_post_handshake_method` signature change breaks Slice-3 callers | Additive `params` kwarg with default `None`; Task 35 includes backwards-compat assertion |
| `Orchestrator.quarantined_extract` accidentally drifts from the Slice-3 `QuarantinedExtractor.extract` contract | Task 20 wires through the existing extractor; Task 21 enforces `source_tier="T3"` at the wrapper level |
| `BurstLimiter` deadlock when bucket is contested across many keys | `asyncio.Lock` is per-key (lazy); never global; `acquire()` uses `asyncio.wait_for(..., drop_after_seconds)` to bound wait |
| Audit pepper missing at daemon boot crashes the host | PR-S4-0b adds the secret bootstrap and `daemon.boot.failed(failure_reason="audit_hash_pepper_missing")` refusal; this PR's tests assume the pepper is present (CI provisions it via testcontainers env) |
| `SUPERVISOR_PLUGIN_RESTART_REQUESTED_FIELDS` row spam under failure storms | Task 45 idempotency per-tick; the supervisor's existing tick cadence (Slice-3) bounds the per-second emit rate |
| Discord-specific classifier shape changes between this PR and PR-S4-9 | PR-S4-9 adds the entry — the `REQUIRED_CLASSIFIERS_BY_KIND` table is set-typed; addition is a Mapping update only |
| Reference plugin's `inject_inbound` test trigger leaks into production | The injection command is gated by `ALFRED_ENV=test`; production refuses with `comms.test_injection_refused` audit row + raise. Asserted by Task 51. |
| Coverage gate becomes flaky on the `_on_post_handshake_method` extension because some branches only fire under specific timing | Each branch has a deterministic unit test (Tasks 36–42); integration tests are stricter, unit tests fill in the coverage holes |
| AST guard test for empty-classifier-set bypass false-positives on legitimate marker entries | Task 10 + Task 11 explicitly test both the positive case (marker present) and the rejection case |

---

## §11 Findings applied (round-by-round)

These are the spec-level closures this plan honours, captured here so reviewers can trace each invariant to its enforcing task:

| Finding | Closure | Task(s) |
|---|---|---|
| Critical 1 | `src/alfred/comms_mcp/protocol.py` path (not `src/alfred/comms/`) | Task 1 |
| Critical 6 | Unknown notification → typed audit row + `request_plugin_restart` (no silent drop) | Task 38, 43 |
| comms-008 | `OutboundMessageResult` discriminated union (no field coupling) | Task 7 |
| comms-011 | `BODY_FIELD_BY_KIND` per-kind body-field mapping | Task 2 |
| comms-012 round-3 | `addressing_mode` Literal mapping to PRD §6.8; `COMMS_ADDRESSING_DRIFT_FIELDS` | Task 6 + §6 outbound site |
| sec-001 round-3 | `quarantined_extract` returns `T3DerivedData`; no T3→T2 silent promotion | Tasks 20, 21, 24 |
| sec-002 round-3 | `REQUIRED_CLASSIFIERS_BY_KIND` host-owned; empty entries require marker | Tasks 10, 11 |
| sec-008 round-3 | `BurstLimiter` is honest new Slice-4 scope; documented as such | Tasks 13–19 + this plan §10 note |
| sec-010 round-3 | Peppered hash via `SecretBroker.get("audit.hash_pepper")` | Task 26 |
| core-006 | New `Supervisor.request_plugin_restart` + extended `trip_breaker` | Tasks 43, 44 |
| core-008 | `async with self._dispatch_semaphore` (guaranteed release) | Task 39 |
| core-010 round-3 | `SUPERVISOR_PLUGIN_RESTART_REQUESTED_FIELDS` enumerated | Spec §9 row + Task 43 |
| core-011 round-4 | Extend the REAL `_on_post_handshake_method` at line 347 | Tasks 35–42 + §8 verification |
| perf-003 | Per-adapter semaphore (not process-wide) | Task 39 + §2 architecture invariant |
| err-007 | Handler exceptions are loud; original propagates after audit | Task 40 |
| test-004 | 7-point assertion test for #152 closure | Task 52 |
| docs-001 | ADR-0009 caveat narrowing deferred to PR-S4-10 | Out-of-scope statement in header |

---

## §12 Out-of-scope (explicit deferrals)

For reviewer clarity — the following do NOT land in this PR even though the topic touches comms-MCP:

| Item | Owning PR |
|---|---|
| Discord adapter (`plugins/alfred_discord/`) + `adapter_kind: discord` Literal entry + `REQUIRED_CLASSIFIERS_BY_KIND["discord"]` + `BODY_FIELD_BY_KIND["discord"]` | PR-S4-9 |
| TUI adapter (`plugins/alfred_tui/`) + `adapter_kind: tui` Literal entry + body-field entry | PR-S4-10 |
| `src/alfred/comms/` deletion (the entire in-process adapter directory) | PR-S4-10 |
| ADR-0009 caveat narrowing (remove "for new adapters" qualifier) | PR-S4-10 |
| `alfred chat` CLI rewire to launcher spawn | PR-S4-10 |
| `comms.adapter.binding_requested` and `comms.adapter.rate_limit_signal` hookpoint registrations | PR-S4-9 |
| Telegram adapter — `adapter_kind: telegram`, `BODY_FIELD_BY_KIND["telegram"] = "text"`, Telegram-specific classifier set | post-MVP |
| Out-of-band verification phrase delivery for binding flow | Slice-5 |
| `alfred user bind --code` cross-platform identity binding | Slice-5 |
| `OutboundQueue.pause(adapter_id, retry_after_seconds)` Slice-3 integration is consumed here via `RateLimitHandler` but the underlying queue is Slice-3 surface | n/a — Slice-3 |
| Per-secret access logging on `SecretBroker` | Slice-5 broker-hardening backlog |
| `alfred cost report --by adapter_id` | Slice-5 |

---

## §13 Done definition

This PR is complete when:

1. Every task in §5 ships with a passing test (failing-first → passing → committed).
2. `make check` is green locally and in CI: lint + format + mypy strict + pyright + unit + integration + coverage gate.
3. `tests/integration/test_comms_mcp_identity_boundary_real.py` passes locally with testcontainers Postgres + the reference plugin.
4. The 7 assertions of spec §8.9 each have a discrete passing assertion in Task 52.
5. The adversarial suite under `tests/adversarial/comms_identity_boundary/` is green.
6. Coverage on the 7 trust-boundary files in Task 61 is 100% line + 100% branch.
7. The four new Prometheus histograms appear under `/metrics` from the integration-test daemon.
8. The reference plugin at `plugins/alfred_comms_test/` round-trips a manufactured inbound through the host → handler → orchestrator → outbound queue → captured outbound delivery.
9. `tests/integration/test_comms_mcp_identity_boundary_real.py` is promoted to a required-status check on `main` (per the slice's cross-fork integration test gate — index §4; this is one of 10).
10. #152 referenced as `Closes #152` in the PR description; the issue's seven assertions cross-link to Task 52's seven sub-assertions.
11. PR description lists the new audit-row constants consumed (8) and the new hookpoints registered (2).
12. PR description explicitly notes that `src/alfred/comms/` is **untouched** (deletion is PR-S4-10).

---

## §14 References

- **Spec:** [docs/superpowers/specs/2026-06-06-slice-4-design.md](../specs/2026-06-06-slice-4-design.md) — §8 in full; §9 audit-row table rows; §10 hookpoint surface; §11 corpus additions.
- **Index:** [docs/superpowers/plans/2026-06-07-slice-4-index.md](./2026-06-07-slice-4-index.md) — §3 Comms-MCP wire contract; §3 `REQUIRED_CLASSIFIERS_BY_KIND` registry; §3 `BurstLimiter` primitive; §4 cross-fork integration test gate.
- **Template:** [docs/superpowers/plans/2026-05-31-slice-3-pr-s3-3a-mcp-plugin-transport.md](./2026-05-31-slice-3-pr-s3-3a-mcp-plugin-transport.md) — Slice-3 plan structure inherited here.
- **ADRs (new in Slice 4):**
  - ADR-0024 — Comms-MCP wire contract (full body in PR-S4-0a; this PR implements it).
  - ADR-0016 — Slice-4 Discord+TUI comms-MCP rewrite (status flip Proposed → Accepted in PR-S4-11, not here).
- **Closes:** #152 (ADR-0009 caveat narrowing closes in PR-S4-10).
- **PRD anchors:** PRD §6.8 (addressing concepts); PRD §7.4 (BudgetGuard daily cap — *not* the BurstLimiter primitive defined here); PRD §5 (plugin isolation invariants — referenced by `register_classifier` import-time discipline).
