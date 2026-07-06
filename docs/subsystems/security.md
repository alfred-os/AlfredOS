# Security subsystem — trust tiers, nonce gate, and capability gate

**Status:** shipped in Slice 3
**Owner:** `alfred-security-engineer`
**Code:** `src/alfred/security/`
**PRD:** [§7.1 Security & Prompt Injection Defense](../../PRD.md#71-security--prompt-injection-defense)
**ADRs:** [ADR-0008](../adr/0008-llm-output-trust-tier.md), [ADR-0017](../adr/0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md)

## Purpose

The security subsystem enforces two orthogonal but complementary
invariants. The first is **content provenance**: every string the system
processes carries a type-level [trust tier](../glossary.md#trust-tier)
from the moment it enters the process boundary to the moment it exits.
The second is **capability enforcement**: every plugin interaction and
every hook subscription passes through a `CapabilityGate` that consults
an operator-approved grant set before allowing dispatch.

These two invariants together implement PRD §7.1's load-bearing
promise: the privileged orchestrator never processes raw T3 content,
and no plugin can acquire capabilities that were not explicitly granted.

## Public surface

### Trust tiers (`src/alfred/security/tiers.py`)

- `TrustTier` — abstract base class. Subclasses set `name` as a class
  attribute so the label survives into audit log rows and DB columns.
- `T0`, `T1`, `T2`, `T3` — the four approved tier classes.
  `_APPROVED_TIERS: frozenset` at line 301 holds the closed allowlist;
  any subclass outside this set is rejected.
- `tag(tier, content, *, source, **metadata)` — the public factory.
  Routes `tag(T3, ...)` through the nonce gate and always raises; all
  other tiers construct `TaggedContent` directly.
- `tag_t3_with_nonce(content, source, *, caller_token, **metadata)` —
  the capability-gated T3 factory. Raises `ValueError` (i18n key
  `security.tag_t3_unauthorized`) unless `caller_token is _AUTHORIZED_T3_NONCE`.
- `TaggedContent[TierT]` — frozen Pydantic model carrying `content`,
  `source`, `tier`, and `metadata`. Validates the tier against
  `_APPROVED_TIERS` and rejects cross-tier wire payloads.
- `AnyTaggedContent` — read-only Protocol for observer code.
- `CapabilityGateNonce` — per-process opaque token; `__slots__ = ()`.

### Capability gate (`src/alfred/security/capability_gate/`)

- `RealGate` (`_gate.py`) — production gate. Three keyword-only check
  methods: `check(plugin_id, hookpoint, requested_tier)`,
  `check_plugin_load(plugin_id, manifest_tier)`,
  `check_content_clearance(plugin_id, hookpoint, content_tier)`. Factory:
  `await RealGate.create(backend=..., audit_sink=..., start_heartbeat=...)`.
- `GatePolicy` (`policy.py`) — immutable in-memory grant snapshot.
  `check*` methods are O(n) over `frozenset[GrantRow]`; n is bounded
  at low hundreds in a busy deployment.
- `GrantRow` (`policy.py`) — frozen dataclass. Fields: `plugin_id`,
  `subscriber_tier`, `hookpoint`, `content_tier`, `proposal_branch`.
  `__post_init__` validates both tier axes against their closed
  vocabularies at construction.
- `StorageBackend` Protocol + `PostgresBackend` (`backend.py`) — Postgres
  I/O surface: `load_grants()`, `upsert_grant()`, `revoke_grant()`,
  `get_sync_hash()`, `set_sync_hash()`, `ping()`.

### Quarantine boundary (`src/alfred/security/quarantine.py`)

- `ContentHandle` — opaque frozen reference to T3 bytes in the content
  store. Fields: `id`, `source_url`, `fetch_timestamp` (must be
  timezone-aware).
- `T3DerivedData` — `NewType` over `dict[str, object]`. Type-level
  provenance marker for data extracted from T3 content.
- `QuarantinedExtractor` — `src/alfred/security/quarantine.py:327` —
  orchestrator-side client of the quarantined-LLM plugin. The only object
  that dispatches `quarantine.extract` JSON-RPC calls and lifts
  `ControlResult` payloads into typed `ExtractionResult` shapes. Takes
  a `PluginTransport` and `AuditWriter` at construction; the capability
  gate is consulted by `quarantined_to_structured`, not the extractor.
  Shipped in PR-S3-4 (#TBD).
- `ExtractionMode` — `src/alfred/security/quarantine.py:225` — closed
  `Literal` of three dispatch-path labels: `"native_constrained"`,
  `"json_object_unconstrained"`, `"prompt_embedded_fallback"`. Drives
  which provider code path the quarantined-LLM plugin uses and appears
  verbatim in `quarantine.extract` audit rows. Shipped in PR-S3-4 (#TBD).
- `TypedRefusalReason` — `src/alfred/security/quarantine.py:212` — closed
  `Literal` vocabulary for `TypedRefusal.reason`. Eight values:
  `cannot_extract`, `refused_by_safety`, `ambiguous_input`,
  `provider_refused`, `provider_unavailable`, `dlp_outbound_refused`
  (tombstone — no live emit site), `post_stage_refused` (any post-stage
  subscriber refusal, with refusing-subscriber identity on the audit
  row's `refusing_hook_id` field), `nonce_check_failed`. Free-form
  refusal text cannot appear in audit rows; this is the structural
  enforcement. Shipped in PR-S3-4 (#TBD); `post_stage_refused` added
  in #168.
- `ProviderCapability` — `src/alfred/providers/base.py:22` — `StrEnum`
  whose values steer the quarantined-LLM extraction mode selection:
  `NATIVE_CONSTRAINED_GENERATION` → Anthropic tool-use shape;
  `JSON_OBJECT_MODE` → DeepSeek json_object path; neither → fallback.
  Also pre-declares `TOOL_USE`, `VISION`, `LONG_CONTEXT_1M` for future
  routing. Shipped in PR-S3-4 (#TBD).
- `quarantined_to_structured(handle, schema, *, extractor, gate)` —
  `src/alfred/security/quarantine.py:637` — the ONLY path by which
  T3-derived content reaches orchestrator-readable structured form.
  Gate-first: calls `gate.check_content_clearance(hookpoint=
  "quarantine.dereference", content_tier="T3")` before invoking the
  extractor. Shipped in PR-S3-4 (#TBD).
- `downgrade_to_orchestrator(data, *, gate, audit_writer)` —
  `src/alfred/security/quarantine.py:693` — gate-checked crossing of
  `T3DerivedData` into a plain `dict` the orchestrator may inject into
  privileged prompts. Writes a `quarantine.t3_derived_downgrade` audit row
  with `T3_DERIVED_DOWNGRADE_FIELDS` on every allowed call; raises
  `AlfredError` without an audit row on denial (the gate's own refusal
  accounting handles that). Shipped in PR-S3-4 (#TBD).
- `T3_DERIVED_DOWNGRADE_FIELDS` — `src/alfred/audit/audit_row_schemas.py:243`
  — `frozenset[str]` naming the audit fields for every
  `quarantine.t3_derived_downgrade` row. Payload values are never
  serialised into these rows — only provenance metadata (source/target
  tier, `correlation_id`, closed-vocabulary `downgrade_reason`).
  Shipped in PR-S3-4 (#TBD).
- `ExtractionResult = Extracted | TypedRefusal` — `src/alfred/security/quarantine.py:293`
  — plain union (no Pydantic discriminator wrapper at the alias level;
  dispatch sites branch by `isinstance`). Shipped in PR-S3-4 (#TBD).
- `Extracted` — `src/alfred/security/quarantine.py:232` — frozen Pydantic
  model for successful extraction; carries `data: T3DerivedData`,
  `extraction_mode: ExtractionMode`, and `kind: Literal["extracted"]`.
  Shipped in PR-S3-4 (#TBD).
- `TypedRefusal` — `src/alfred/security/quarantine.py:263` — frozen Pydantic
  model for quarantined-LLM refusals; carries `reason: TypedRefusalReason`
  and `kind: Literal["typed_refusal"]`. Shipped in PR-S3-4 (#TBD).

### Per-user concurrent ContentHandle cap (`src/alfred/plugins/web_fetch/handle_cap.py`)

**Per-user concurrent ContentHandle cap (slice-3 spec §7.10).** A
per-user Redis-backed counter (`HandleCap`) bounds how many `ContentHandle`
instances a single user can have alive in Redis at one moment. Default 5;
override is planned via `web_fetch.max_concurrent_handles_per_user` in
`policies.yaml` (reserved/inert until policies-loader issue #159 lands).
Cap-refused fetches emit `tool.web.fetch` audit rows
with `dlp_scan_result="handle_cap_exceeded"`. See
[docs/runbooks/handle-cap-exceeded.md](../runbooks/handle-cap-exceeded.md)
for the operator-facing runbook.

> **[2026-06-28 — G7-2.5 PR1 update]** For `web.fetch`, the per-user cap is now
> **detached**: `dispatch_web_fetch` no longer reserves or releases a `HandleCap` slot.
> The inbound-canary property moved to the C2 pre-extract seam; the per-user
> resource-exhaustion-refusal bound is deferred to issues #339 and #347 (see ADR-0041).
> The `handle_cap.py` module remains in-tree for its `canary_scanner.py` consumer;
> the runbook below applies to any remaining non-`web.fetch` consumers of `HandleCap`.

**Audit vocabulary widening (handle-cap + dispatch-params PRs).** Closed
vocabularies on `WEB_FETCH_FIELDS` widened across two trust-boundary PRs —
operators with SIEM filters MUST extend their allow-lists:

- `rate_limit_bucket`: added `handle_cap` (alongside existing
  `per_domain`, `per_user`, `daily_budget`) — handle-cap PR.
- `dlp_scan_result`: added `handle_cap_exceeded` and `handle_id_mismatch`
  (handle-cap PR) and `dispatch_param_invalid` (#147 — host-side
  Pydantic validation of `web.fetch` JSON-RPC params; emitted when a
  dispatcher bug surfaces as a `pydantic.ValidationError` host-side,
  releasing the cap before crossing the transport boundary).

Both promoted to `typing.Literal[...]` in
`src/alfred/audit/audit_row_schemas.py` (canonical source). A project-
level `CHANGELOG.md` is a deferred follow-up; until then this section
IS the canonical changelog entry for the widening.

### DLP (`src/alfred/security/dlp.py`)

See [glossary: OutboundDlp](../glossary.md#outbounddlp). The inbound
analog lives in the plugins subsystem — see
[InboundContentScanner](../glossary.md#inboundcontentscanner).

- **DLP placement — state.git dispatch `failure_detail` (#173, PR-S4-2):**
  `alfred.state.dispatch_loop._record_failure` runs `OutboundDlp.scan` over
  the proposal-dispatch `failure_detail` before the 512-char truncation, so
  a secret/canary cannot reach `processed_proposals.failure_detail`. The
  wire emits **two disjoint** audit rows (spec §2.1):
  `state.proposal.failure_detail_redacted` on success (clean/redacted) and
  the Slice-3 `security.dlp_outbound_refused` on a canary-trip refusal
  (which aborts the ledger write). A non-`HookRefusal` scan fault emits
  `state.proposal.dispatch_dlp_scan_failed` and likewise aborts. Full
  subsystem write-up lands in PR-S4-11.

### Secret broker (`src/alfred/security/secrets.py`)

See [glossary: SecretBroker](../glossary.md#secretbroker).

## Internal model

### The nonce gate

`_AUTHORIZED_T3_NONCE: CapabilityGateNonce | None` is a module-level slot
set exactly once by `alfred.bootstrap.nonce_factory.create_and_register_t3_nonce()`.
The bootstrap factory constructs the nonce, registers it in the module via
`_set_authorized_t3_nonce()`, and distributes it via dependency injection to
exactly two call sites: `StdioTransport` and `quarantine_host`.

The gate check in `tag_t3_with_nonce` is `caller_token is not authorized`
— Python identity (`is`), not equality (`==`). A re-constructed or
imported-copy nonce is a different object and fails the gate. This closes
import-time forgery attacks. The `gc.get_objects()` traversal attack (heap
enumeration) is labeled out-of-scope in the adversarial corpus
(`tl_gc_traversal_out_of_scope`): an adversary who can enumerate the process
heap already has full process compromise and the nonce gate's threat model
stops at the process boundary.

### The capability gate state machine

`RealGate` has two hot-path states: **open** (normal) and **fail-closed**
(backing store unreachable). Transitions:

- **Open → fail-closed**: `_missed_heartbeats` reaches
  `_MAX_MISSED_HEARTBEATS` (6 misses × 10 s interval = 60 s window). The
  flag flips *before* the audit row is emitted — if the audit sink is also
  wedged, subsequent `check*` calls still deny (CLAUDE.md hard rule #7).
- **Fail-closed → open**: the next successful `backend.ping()` resets the
  counter and emits the `exiting_fail_closed` audit row with the cumulative
  `denied_dispatch_count`.

`GatePolicy` is replaced atomically: `_apply_grants()` assigns a new
frozen instance under the single-threaded asyncio event loop. Hot-path
checks see either the old or new snapshot atomically, never a partially
rebuilt state.

### Two-axis naming invariant

The manifest `subscriber_tier` field (subscriber-capability axis:
`system` / `operator` / `user-plugin`) and the content `tier` field in
`TaggedContent` (provenance axis: `T0`–`T3`) are orthogonal. They share
the word "tier" only. Conflating them is the tier-laundering bug class.
The enforcement points are:

1. `PluginManifest._validate_subscriber_tier` raises `ManifestTierError`
   if a T0–T3 string appears as `subscriber_tier`.
2. `parse_manifest` in `src/alfred/plugins/manifest.py` checks this
   before constructing the model.
3. `GrantRow.__post_init__` validates `subscriber_tier` against
   `{"system", "operator", "user-plugin"}` and `content_tier` against
   `{"T0", "T1", "T2", "T3", None}` at construction time.

## Failure modes

| Trigger | Behaviour | Observable signal |
| --- | --- | --- |
| `tag(T3, content)` called directly | `ValueError` with i18n key `security.tag_t3_unauthorized`; structlog `security.t3_boundary.refused` | log line |
| Unknown tier on wire (`"TX"`) | `ValueError` from `_resolve_tier_from_wire` | exception at parse boundary |
| Cross-tier wire payload (`T3` payload parsed as `TaggedContent[T2]`) | `ValueError` from `_validate_tier` | exception at field validation |
| Plugin manifest `alfred.manifest_version != 1` | `ManifestVersionError`; `plugin.lifecycle.load_refused` audit row | audit log |
| Plugin manifest `subscriber_tier = "T3"` | `ManifestTierError`; `plugin.lifecycle.load_refused` audit row | audit log |
| Capability gate denied at load | `PluginError`; `plugin.lifecycle.load_refused` audit row | audit log |
| Backing store unreachable for 60 s | Gate trips fail-closed; all `check*` → `False`; `supervisor.capability_gate_unavailable` audit row | audit log + Prometheus `alfred_capability_gate_fail_closed` |
| Backing store recovers | Gate re-opens; `exiting_fail_closed` audit row with `denied_dispatch_count` | audit log |
| `GrantRow` constructed with invalid tier | `ValueError` at construction; no audit row (policy-rebuild boundary, pre-load) | exception |

## Trust-boundary contract

This subsystem is the trust boundary. Content enters with a tier tag
attached at the ingestion point (`tag(T2, ...)` in the comms adapter,
`tag_t3_with_nonce(...)` in `StdioTransport`). The tag travels with the
content through the orchestrator. The tier on a `TaggedContent` object is
never writable after construction (frozen model). The orchestrator's
invariant is:

- Tier `T0` and `T2`: pass directly to the privileged orchestrator.
- Tier `T1`: pass directly to the privileged orchestrator (operator
  sessions only).
- Tier `T3`: the orchestrator holds a `ContentHandle` only; the bytes live
  in the content store; only the quarantined LLM subprocess can dereference
  them via `quarantined_to_structured()`.

**Tool-result flow (#339 PR2).** `dispatch_tool`
(`src/alfred/orchestrator/tool_dispatch.py`) is the analogous chokepoint on the
*output* side of a tool call: a T3 tool result crosses `downgrade_to_orchestrator`
(a second, distinct `check_content_clearance` call, `hookpoint=
"t3.downgrade_to_orchestrator"`) and an `OutboundDlp.scan` pass before it reaches
the privileged orchestrator's next completion request. `result_tier` defaults to
T3 for every tool; only a hardcoded first-party allowlist may claim ≤T2 and skip
both crossings. See [ADR-0046](../adr/0046-dual-llm-tool-result-flow.md) for the
full invariant.

**Live driver (#339 PR3).** The agentic act-phase loop
(`src/alfred/orchestrator/`) is the live driver of the ADR-0046 invariant above —
each iteration's tool dispatch runs through this same `dispatch_tool` chokepoint.
The three first-party grants this flow needs (`tool.dispatch`,
`quarantine.dereference`, `t3.downgrade_to_orchestrator`) are seeded at boot by
`src/alfred/security/capability_gate/_bootstrap_grants.py`.

See [docs/subsystems/plugins.md](plugins.md) for the quarantined LLM
transport and process isolation contract.

## Performance characteristics

The `tag()` path is synchronous and allocation-only (one frozen Pydantic
model). The hot-path `RealGate.check*` methods are synchronous O(n) over
the in-memory `frozenset[GrantRow]`; Postgres is not touched on the hot
path. The `_heartbeat_loop` pings Postgres every 10 seconds in a
background task. The `InboundContentScanner.scan()` runs in
`asyncio.to_thread` (perf-012) so it does not block the event loop on
large frames.

## Slice graduation map

| Subsystem | Slice 3 (this slice) | Deferred to | Anchor |
| --- | --- | --- | --- |
| Security | Full T0–T3 type system; nonce-gated `tag_t3_with_nonce`; `TaggedContent` wire format; `RealGate` + `GatePolicy` + `GrantRow`; `ContentHandle` + `T3DerivedData`; `QuarantinedExtractor` + `ExtractionMode` + `TypedRefusalReason` + `ProviderCapability`; full `quarantined_to_structured` + `downgrade_to_orchestrator` + `T3_DERIVED_DOWNGRADE_FIELDS` (all shipped in PR-S3-4 #TBD) | Slice 4+: `RealGate.rebuild_from_state_git` full impl (PR-S3-6); container isolation for quarantined LLM (ADR-0015) | [ADR-0017](../adr/0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md) |

## Egress planes

The gateway is the **sole external egress plane** (Spec C G7-3, ADR-0042). The security
subsystem interacts with three distinct egress consumers, all routed through the gateway:

1. **Provider egress** — the core's `EgressClient` builds provider SDK clients with a
   proxied `httpx.AsyncClient`; the gateway L7 CONNECT forward-proxy enforces the
   destination allowlist and audits every connection (mode a, TLS-passthrough).
2. **Tool egress relay** — gateway inspecting relay for mode-(b) tool calls (web-fetch);
   the gateway re-runs `OutboundDlp` as an independent second pass over the
   DLP-redacted body, providing two-layer content enforcement.
3. **Discord-adapter egress** — the gateway-hosted Discord bwrap child (Spec C G7-4,
   ADR-0043) runs `--unshare-net` (empty netns); its sole egress path is a bind-mounted
   AF_UNIX socket on the gateway-only `alfred_discord_egress` volume, served by a second
   `EgressForwardProxy` instance with a Discord-only allowlist. The AF_UNIX socket is
   never reachable from the connectivity-free core (it is on a volume mounted into
   `alfred-gateway` only — not `alfred_run`).

See [ADR-0043](../adr/0043-discord-adapter-egress-l7-proxy-netns-bridge.md) for the
Discord egress bridge decision record.

## Cross-references

- PRD §7.1 — dual-LLM split as the load-bearing prompt-injection defence.
- [ADR-0008](../adr/0008-llm-output-trust-tier.md) — established the trust-tier discriminant in Slice 1; superseded by ADR-0017.
- [ADR-0013](../adr/0013-defer-t1-t3-and-dual-llm.md) — deferred T1+T3+dual-LLM to Slice 3; superseded by ADR-0017.
- [ADR-0017](../adr/0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md) — Decision 1 (nonce gate), Decision 3 (two-axis naming), Decision 7 (wire-format versioning anchors).
- [ADR-0015](../adr/0015-slice4-containerised-quarantined-llm.md) — Slice-4 containerised quarantined LLM commitment.
- [ADR-0046](../adr/0046-dual-llm-tool-result-flow.md) — the tool-result-flow trust boundary: `dispatch_tool`'s downgrade + DLP crossing for T3 tool results, and the `result_tier`-defaults-to-T3 rule.
- Spec C G7-2c (#333) — the §4.3 tool-egress response path (in-core `EgressResponseExtractor`) routes T3 upstream tool-response bodies through the SAME gate-checked `quarantined_to_structured` seam — never a parallel extractor — and the dedup ledger stores only the post-extraction T2, never raw T3. See the [Spec C egress control-plane design](../superpowers/specs/2026-06-25-spec-c-egress-control-plane-design.md).
- Sibling subsystems: [plugins.md](plugins.md), [identity.md](identity.md), [hooks.md](hooks.md).
- Glossary: [trust tier](../glossary.md#trust-tier), [T3 (untrusted-ingestion tier)](../glossary.md#t3-untrusted-ingestion-tier), [CapabilityGateNonce](../glossary.md#capabilitygatenonce), [dual-LLM split](../glossary.md#dual-llm-split), [RealGate](../glossary.md#realgate), [GatePolicy](../glossary.md#gatepolicy), [GrantRow](../glossary.md#grantrow), [QuarantinedExtractor](../glossary.md#quarantinedextractor), [ExtractionMode](../glossary.md#extractionmode), [TypedRefusalReason](../glossary.md#typedrefusalreason), [ProviderCapability](../glossary.md#providercapability), [alfred_quarantined_llm](../glossary.md#alfred_quarantined_llm), [quarantine.ingest](../glossary.md#quarantineingest), [quarantine.extract](../glossary.md#quarantineextract), [Extracted](../glossary.md#extracted), [TypedRefusal](../glossary.md#typedrefusal), [ExtractionResult](../glossary.md#extractionresult).
