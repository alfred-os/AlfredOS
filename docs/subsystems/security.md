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
- `quarantined_to_structured(handle, schema, *, extractor, gate)` — the
  ONLY path by which T3-derived content reaches orchestrator-readable
  structured form. *Stub in Slice 3; full implementation PR-S3-4.*
- `downgrade_to_orchestrator(data, *, audit_row)` — gate for injecting
  `T3DerivedData` into privileged prompts. *Stub in Slice 3; full
  implementation PR-S3-4.*
- `ExtractionResult = Extracted | TypedRefusal` — extraction outcome union.
- `Extracted` — successful extraction; carries `data: T3DerivedData` and
  `handle: ContentHandle`.
- `TypedRefusal` — quarantine LLM declined extraction; carries `reason`
  (closed vocabulary) and `handle`.

### DLP (`src/alfred/security/dlp.py`)

See [glossary: OutboundDlp](../glossary.md#outbounddlp). The inbound
analog lives in the plugins subsystem — see
[InboundContentScanner](../glossary.md#inboundcontentscanner).

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
|---|---|---|
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
|---|---|---|---|
| Security | Full T0–T3 type system; nonce-gated `tag_t3_with_nonce`; `TaggedContent` wire format; `RealGate` + `GatePolicy` + `GrantRow`; `ContentHandle` + `T3DerivedData`; `ExtractionResult` stubs | Slice 4+: `quarantined_to_structured` full impl (PR-S3-4); `downgrade_to_orchestrator` full impl (PR-S3-4); `RealGate.rebuild_from_state_git` full impl (PR-S3-6); container isolation for quarantined LLM (ADR-0015) | [ADR-0017](../adr/0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md) |

## Cross-references

- PRD §7.1 — dual-LLM split as the load-bearing prompt-injection defence.
- [ADR-0008](../adr/0008-llm-output-trust-tier.md) — established the trust-tier discriminant in Slice 1; superseded by ADR-0017.
- [ADR-0013](../adr/0013-defer-t1-t3-and-dual-llm.md) — deferred T1+T3+dual-LLM to Slice 3; superseded by ADR-0017.
- [ADR-0017](../adr/0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md) — Decision 1 (nonce gate), Decision 3 (two-axis naming), Decision 7 (wire-format versioning anchors).
- [ADR-0015](../adr/0015-slice4-containerised-quarantined-llm.md) — Slice-4 containerised quarantined LLM commitment.
- Sibling subsystems: [plugins.md](plugins.md), [identity.md](identity.md), [hooks.md](hooks.md).
- Glossary: [trust tier](../glossary.md#trust-tier), [T3 (untrusted-ingestion tier)](../glossary.md#t3-untrusted-ingestion-tier), [CapabilityGateNonce](../glossary.md#capabilitygatenonce), [dual-LLM split](../glossary.md#dual-llm-split), [RealGate](../glossary.md#realgate), [GatePolicy](../glossary.md#gatepolicy), [GrantRow](../glossary.md#grantrow).
