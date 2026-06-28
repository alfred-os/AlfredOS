# Plugins subsystem — MCP transport, session lifecycle, and content store

**Status:** shipped in Slice 3
**Owner:** `alfred-plugins-engineer`
**Code:** `src/alfred/plugins/`
**PRD:** [§5 Architecture Overview](../../PRD.md#5-architecture-overview) — "Plugins are MCP servers" invariant; hybrid-isolation invariant
**ADRs:** [ADR-0009](../adr/0009-comms-adapter-protocol-slice2-only.md), [ADR-0017](../adr/0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md), [ADR-0015](../adr/0015-slice4-containerised-quarantined-llm.md)

## Purpose

The plugins subsystem owns the boundary between the privileged
orchestrator and external plugin subprocesses. Its job is to enforce
that T3 bytes never cross into orchestrator-readable memory directly,
to apply DLP and canary-scan on every JSON-RPC frame, and to manage the
full lifecycle (manifest parse, capability-gate check, subprocess spawn,
quarantine on violation, circuit-break on crash) of each plugin.

PRD §5 names "Plugins are MCP servers" as a non-negotiable architectural
invariant. Slice 2 held the comms adapters as an in-process deviation
([ADR-0009](../adr/0009-comms-adapter-protocol-slice2-only.md)). Slice 3
ships the first real plugin transport — the stdio subprocess — and the
quarantined LLM is the first plugin that runs under it.

## Public surface

### Transport Protocol (`src/alfred/plugins/transport.py`)

- `PluginTransport` — `@runtime_checkable` Protocol; surface:
  `async dispatch(method, params) -> DispatchResult` and `async close()`.
  The supervisor holds a `PluginTransport` reference; it does not import
  the concrete class.
- `DispatchResult = ContentHandle | ExtractionResult | ControlResult` —
  call sites branch by `isinstance`; no Pydantic discriminator field
  (the three shapes share no tag field).
- `ControlResult` — lifecycle / config / health-check response;
  `method: str`, `payload: dict[str, object]`; frozen Pydantic model.

### StdioTransport (`src/alfred/plugins/stdio_transport.py`)

The sole Slice-3 `PluginTransport` implementation. Manages one
subprocess per instance; wraps the `model_context_protocol` SDK. The
constructor takes `inbound_t3_nonce: CapabilityGateNonce` directly
(no module global; injected at session-create time).

**Outbound pipeline** (arch-001 / sec-010):

1. Serialise the JSON-RPC frame with `{{secret:*}}` placeholders intact.
2. `OutboundDlp.scan(placeholder_frame)` — DLP passes on placeholder
   strings; no real secrets are visible at this stage.
3. `SecretBroker.substitute(params)` — substitute real secrets AFTER DLP
   to avoid routing plaintext secrets through the DLP rule engine
   (CLAUDE.md hard rules #1 + #5).
4. Build the final frame with substituted values and write length-prefixed
   to subprocess stdin.

**Inbound pipeline**:

1. Length-prefixed read (4-byte BE header, max 10 MB).
2. `InboundContentScanner.scan(frame)` in `asyncio.to_thread` (perf-012).
3. Branch: content-bearing → `tag_t3_with_nonce(decoded, caller_token=nonce)`
   → `content_store.put(handle, tagged)` → return `ContentHandle`;
   control-plane → `ControlResult` (no T3 tagging, no store write).

**Subprocess hardening** (spec §5.3):

- Env scrubbing: subprocess inherits only `PATH` + i18n vars.
- fd-3 provider-key delivery: 4-byte big-endian length + N key bytes;
  pipe fds closed in `finally` on any spawn failure.
- `kill()` returns `bool` (did SIGKILL land?); the quarantine audit row
  records `kill_succeeded` so operators can distinguish.

### AlfredPluginSession (`src/alfred/plugins/session.py`)

Lifecycle owner for one plugin subprocess.

- `await AlfredPluginSession.create(manifest_raw=..., audit_writer=..., gate=...)` —
  the only public constructor. Parses the manifest, emits
  `plugin.lifecycle.load_refused` on any `ManifestError`, then runs
  the capability gate check. All call sites must use this factory.
- `__init__(manifest, audit_writer, gate, transport=None)` — internal;
  skips the load-refused audit emit on failure.
- `_on_handshake_complete()` — runs the gate `check_plugin_load()`
  check and emits `plugin.lifecycle.loaded` on success.
- `_on_post_handshake_method(method)` — routes post-handshake JSON-RPC
  methods; `alfred/hooks.register` is in `_DISALLOWED_POST_HANDSHAKE_METHODS`
  (spec §4.6). On a disallowed method: SIGKILL the subprocess first,
  then emit `plugin.lifecycle.quarantined` in a `try/finally` so the
  audit row lands regardless of kill outcome.

The SIGKILL-before-audit ordering is a security invariant (sec-013 /
core-007): the `signal='SIGKILL'` claim in the audit row is only made
when the kill actually landed. An operator reading the log cannot be
misled about the actual subprocess state.

### Manifest (`src/alfred/plugins/manifest.py`)

- `PluginManifest` — frozen Pydantic model. Fields:
  `manifest_version: Literal[1]`, `plugin_id: str`, `subscriber_tier: str`,
  `sandbox_profile: str`, `platform: str | None` (reserved Slice-4).
- `parse_manifest(raw: str) -> PluginManifest` — TOML parser. Raises
  `ManifestVersionError` before constructing the model if
  `alfred.manifest_version != 1`. Raises `ManifestTierError` if
  `subscriber_tier` is `T0`–`T3` (two-axis naming guard). Both checks
  happen before the Pydantic model construction so the exception classes
  surface un-wrapped.

### Error hierarchy (`src/alfred/plugins/errors.py`)

Rooted at `PluginError(AlfredError)`. Three orthogonal axes:

- `ManifestError` — manifest rejected at handshake.
  Leaves: `ManifestVersionError` (`manifest_version != 1`),
  `ManifestTierError` (content tier supplied as `subscriber_tier`).
- `PluginTransportError` — wire-level failure post-handshake.
  Leaves: `PluginProtocolViolation` (disallowed JSON-RPC method),
  `DlpOutboundRefusedError` (DLP refused an outbound frame).
- `PluginInvocationError` — plugin returned an application-level error
  response (the wire was healthy; the plugin failed the call).
- `QuarantinedUnavailable` — quarantined LLM subprocess unreachable.
  Defined here per [ADR-0017 Decision 6](../adr/0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md);
  `src/alfred/supervisor/errors.py` re-exports it for ergonomic import.

Error constructors deliberately cannot carry T3 content (spec §5.6):
they accept `plugin_id`, `method`, `rule_matched`, `reason` — closed
vocabulary, safe for audit rows.

### InboundContentScanner (`src/alfred/plugins/inbound_scanner.py`)

Scans raw JSON-RPC frame bytes for operator-registered canary tokens.

- `InboundContentScanner(canary_tokens=frozenset())` — constructor;
  compiles patterns as `bytes`-mode regexes (so `CanaryTrip.frame_offset`
  is a true byte offset, correct for multi-byte UTF-8 content).
- `scan(frame: bytes) -> CanaryTrip | None` — synchronous; run in
  `asyncio.to_thread` by `StdioTransport.dispatch`.
- `CanaryTrip` — frozen dataclass; fields: `matched_token: str`,
  `frame_offset: int`. A `CanaryTrip` is a security event — quarantine
  trigger — never a recoverable error.

The disposition difference from `OutboundDlp`: outbound DLP is
redact-and-continue (secrets must not exfiltrate but the call still
completes); inbound canary scanner is always a security event (a canary
in plugin output means the plugin was prompted with the canary — a
prompt-injection indicator).

### ContentStoreBase (`src/alfred/plugins/content_store_base.py`)

Protocol for T3 content stores. Three methods: `put(handle, tagged_content)`,
`get(handle_id) -> TaggedContent[T3] | None`, `delete(handle_id)`.

The store persists `TaggedContent[T3]` wrappers (nonce + provenance
included), not raw bytes — persisting raw bytes would lose the nonce
and silently downgrade T3 → untagged on retrieval (rvw-004 / CR R3).

Slice 3 ships `InMemoryContentStore` (no TTL, no single-use, no
cross-process visibility). The Redis-backed production store with atomic
single-use `DEL` on first extract ships in PR-S3-5.

## Internal model

### The manifest version pin

`alfred.manifest_version = 1` is a `Literal[1]` field on `PluginManifest`.
Any other integer (or a non-integer, or the string `"1"`) raises
`ManifestVersionError` before any capability-gate work. The integer is the
sole evolution lever: minor compatible changes (like the reserved `platform`
field added in Slice 3 for Slice-4 use) do not bump it. A bump to 2
requires a schema change that breaks backward compatibility.

### T3 byte isolation across the transport boundary

The `StdioTransport` inbound pipeline ensures T3 bytes never reach the
orchestrator directly:

1. Raw bytes arrive from the subprocess.
2. `InboundContentScanner.scan(frame)` checks for canary tokens.
3. `tag_t3_with_nonce(decoded, caller_token=nonce)` wraps the decoded
   string as `TaggedContent[T3]`.
4. `content_store.put(handle, tagged)` stores the wrapper; a
   `ContentHandle` (opaque id + source url + timestamp) is returned.
5. The orchestrator receives the `ContentHandle` from `dispatch()`.

> **[2026-06-28 — G7-2.5]** The `web.fetch` tool no longer follows this path. Post-G7-2.5,
> `dispatch_web_fetch` returns a T2 `EgressExtractOutcome` (fused fetch+extract, ADR-0041)
> rather than a T3 `ContentHandle`. The steps above describe the `StdioTransport`
> inbound pipeline; `ContentHandle` remains valid for other content plugins.

At no point does the orchestrator see the content string itself; it holds
only the opaque handle. The only way to get structured data from the
handle is `quarantined_to_structured()` in `src/alfred/security/quarantine.py`,
which (when fully wired in PR-S3-4) runs the quarantined LLM subprocess,
DLP-post-scans the extraction, writes an audit row, and returns
`T3DerivedData`.

### Post-handshake security gate

After `_on_handshake_complete()` completes successfully, any JSON-RPC
method in `_DISALLOWED_POST_HANDSHAKE_METHODS` (currently:
`alfred/hooks.register`) triggers the following sequence:

1. `await transport.kill()` — SIGKILL the subprocess. Returns `bool`.
2. Emit `plugin.lifecycle.quarantined` audit row in `try/finally`.
   `kill_succeeded` field reflects the actual kill outcome.
3. The `breaker_state` field in the audit row is `"OPEN"`.

This sequence runs even if the kill raises — the audit row always lands
(CLAUDE.md hard rule #7). A future PR-S3-3b circuit-breaker supervisor
will act on the `OPEN` breaker state.

## Failure modes

| Trigger | Behaviour | Observable signal |
| --- | --- | --- |
| `manifest_version != 1` | `ManifestVersionError`; `plugin.lifecycle.load_refused` audit row | audit log |
| `subscriber_tier = "T3"` in manifest | `ManifestTierError`; `plugin.lifecycle.load_refused` audit row | audit log |
| Malformed TOML in manifest | `ManifestError`; `plugin.lifecycle.load_refused` audit row | audit log |
| Capability gate denies at handshake | `PluginError`; `plugin.lifecycle.load_refused` audit row | audit log |
| `alfred/hooks.register` post-handshake | SIGKILL; `plugin.lifecycle.quarantined` audit row | audit log |
| Canary trip in inbound frame | `CanaryTrip` returned to `dispatch()`; orchestrator raises security event | structlog error + audit row (PR-S3-4) |
| DLP refuses outbound frame | `DlpOutboundRefusedError`; `plugin.transport.dlp_outbound_refused` audit row | audit log |
| Plugin RPC returns application error | `PluginInvocationError` | exception propagates to caller |
| Quarantined LLM subprocess unreachable | `QuarantinedUnavailable` | exception; orchestrator degrades gracefully |
| `dispatch()` called before `_spawn()` | `RuntimeError` (err-013 guard survives `python -O`) | exception |

## Trust-boundary contract

This subsystem is on the T3 side of the dual-LLM boundary. Content enters
via `StdioTransport` tagged T3 and stays tagged T3 in the content store.
The capability gate checks at every dispatch call ensure no plugin can
subscribe to hookpoints or access content tiers that were not explicitly
granted. See [docs/subsystems/security.md](security.md) for the gate
internals.

## Performance characteristics

- Cold-start subprocess spawn: < 500 ms per spec §7a.1.
- `InboundContentScanner.scan()`: synchronous; run in `asyncio.to_thread`
  to keep the event loop responsive on large (up to 10 MB) frames.
- `PluginTransport.dispatch()`: round-trip latency dominated by subprocess
  inference time, not transport overhead.
- `InMemoryContentStore`: O(1) put/get/delete. No TTL; in-process only.

## Slice graduation map

| Subsystem | Slice 3 (this slice) | Deferred to | Anchor |
| --- | --- | --- | --- |
| Plugins | `PluginTransport` Protocol; `StdioTransport`; `AlfredPluginSession`; `PluginManifest` + error hierarchy; `InboundContentScanner`; `ContentStoreBase` + `InMemoryContentStore`; `DispatchResult` union; `CapabilityGateNonce` injection | Slice 3 (remaining PRs): circuit-breaker supervisor (PR-S3-3b); quarantined LLM host (PR-S3-4); Redis content store (PR-S3-5); state.git rebuild wiring (PR-S3-6); `DevGate` flag-day removal (PR-S3-7). Slice 4: comms adapters migrated to MCP (ADR-0016); container isolation (ADR-0015). Slice 5+: HTTP transport. | [ADR-0017](../adr/0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md), [ADR-0015](../adr/0015-slice4-containerised-quarantined-llm.md) |

## Cross-references

- PRD §5 — "Plugins are MCP servers"; hybrid-isolation invariant.
- PRD §7.1 — dual-LLM split; T3 isolation.
- [ADR-0009](../adr/0009-comms-adapter-protocol-slice2-only.md) — bounded Slice-2 deviation; status updated to superseded-for-new-adapters.
- [ADR-0017](../adr/0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md) — Decision 2 (stdio transport), Decision 5 (PR split), Decision 6 (QuarantinedUnavailable location), Decision 7 (manifest version pin).
- [ADR-0015](../adr/0015-slice4-containerised-quarantined-llm.md) — Slice-4 container isolation commitment.
- Sibling subsystems: [security.md](security.md), [hooks.md](hooks.md), [comms.md](comms.md).
- Glossary: [StdioTransport](../glossary.md#stdiotransport), [AlfredPluginSession](../glossary.md#alfredpluginsession), [PluginManifest](../glossary.md#pluginmanifest), [ManifestError](../glossary.md#manifesterror), [DispatchResult](../glossary.md#dispatchresult), [PluginTransport](../glossary.md#plugintransport), [InboundContentScanner](../glossary.md#inboundcontentscanner), [ContentStoreBase](../glossary.md#contentstorebase), [quarantine (process)](../glossary.md#quarantine-process), [dual-LLM split](../glossary.md#dual-llm-split).
