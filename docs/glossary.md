# Glossary

Single vocabulary source for AlfredOS. Every system-specific term has
one definition here; the rest of the docs link to it
(`[trust tier](../glossary.md#trust-tier)`) rather than repeat the
definition. Repetition is rot's seed.

Headings use the GitHub slugifier convention: lowercased,
non-alphanumeric collapsed to `-`. The slugs `authorization-role` and
`canonical-user-id` are load-bearing — `docs/superpowers/specs/*.md`
forward-references resolve here and `make docs-check` enforces the
anchors exist.

## Authorization role

A per-user closed-domain enum (`Authorization`, `StrEnum` in
[`src/alfred/identity/models.py`](../src/alfred/identity/models.py))
naming the four authorization tiers AlfredOS supports. Snake-case on
the wire (`read_only`, `standard`, `trusted`, `operator`); the CLI
also accepts kebab-case (`read-only`) via a Typer normaliser. The
enum lives in the DB schema as a CHECK constraint, not a Postgres
ENUM type — new tiers land via additive CHECK migrations to keep
rollback symmetry.

| Role | Default rate limit / min | Reply on refusal? | Notes |
|---|---|---|---|
| `read_only` | `0` (no requests) | **No — reply-suppressed** | Operator can add a row without granting interactive access |
| `standard` | `30` | Yes | Default for newly-added users |
| `trusted` | `60` | Yes | Elevated tier; no semantic difference beyond rate limits in Slice 2 |
| `operator` | unlimited (`None`) | Yes | At most one live operator per deployment |

The `read_only` reply-suppression is the security-sensitive bit: a
read-only user's DM is audited but the bot does not reply, so the
absence of a reply does not signal a malformed message — it signals
deliberate refusal. Defaults live in `AUTH_DEFAULT_PER_MIN`
(`MappingProxyType` in `src/alfred/identity/rate_limit.py`).

See [ADR-0010](adr/0010-canonical-user-id-and-listen-notify.md),
[`docs/subsystems/identity.md`](subsystems/identity.md), and
[`docs/subsystems/comms.md`](subsystems/comms.md) (RateLimiter
Protocol).

## Canonical user id

The slug-form identifier AlfredOS uses as the primary key for every
user-keyed subsystem (audit log, budget guard, memory partitioning,
capability grants). Derived deterministically from the operator-supplied
display name by a six-step pipeline (`src/alfred/identity/slug.py`):

1. **NFKC** Unicode normalisation.
2. **`unidecode`** ASCII transliteration.
3. **Lowercase.**
4. **Non-alphanumeric → `-`** (any run becomes a single hyphen).
5. **Strip leading/trailing hyphens; truncate to 63 chars.**
6. **Empty fallback** — if the pipeline yields `""`, return `"user"`.

Collision detection and `-2`/`-3` suffixing live in
`IdentityResolver.add` because they need a DB session; the slug
module itself never does I/O. Truncation happens **before** the
collision suffix so the suffix budget is independent of the seed
length.

Operator-readable IDs in log lines and audit-graph node labels are
worth the one-time collision check at `add` time. UUIDs would force
every operator query through a lookup table; slugs read straight out
of the rendered output. Homograph awareness (Cyrillic `а` vs Latin
`a`) is intentional-not-bug — `unidecode` collapses both to ASCII
`a`, so the slug is the same; the `display_name` preserves the
original.

See [ADR-0010](adr/0010-canonical-user-id-and-listen-notify.md) and
[`docs/subsystems/identity.md`](subsystems/identity.md).

## Trust tier

A type-level discriminant carried by every content blob inside
AlfredOS, indicating how much the system trusts the content's
provenance. Slice 3 ships the full closed T0–T3 model per
[ADR-0017](adr/0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md),
superseding [ADR-0013](adr/0013-defer-t1-t3-and-dual-llm.md).

| Tier | Source | Slice |
|---|---|---|
| `T0` | System-internal synthetic content (the system created it) | All |
| `T1` | Operator-tier — TUI ingress + operator-attributable outbound | Slice 3 |
| `T2` | Authenticated user — Discord DM from a bound snowflake | Slice 2 |
| `T3` | Untrusted external ingestion — web fetch, email, file, MCP tool output | Slice 3 |

Each tier is a Python `TrustTier` subclass with a `name` class attribute
(`"T0"`–`"T3"`). The closed allowlist `_APPROVED_TIERS` in
`src/alfred/security/tiers.py` rejects any subclass outside the four
approved tiers at both the `tag()` call site and the `TaggedContent`
field validator. See [T1 (operator tier)](#t1-operator-tier) and
[T3 (untrusted-ingestion tier)](#t3-untrusted-ingestion-tier) for the
tier-specific entries.

**Not to be confused with [hook tier](#hook-tier)** — `system` /
`operator` / `user-plugin` are dispatch-order + capability gates on
hook subscribers, an entirely separate axis from content provenance.

See [ADR-0017](adr/0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md),
[ADR-0008](adr/0008-llm-output-trust-tier.md), and
[docs/subsystems/security.md](subsystems/security.md).

## T1 (operator tier)

The `T1` `TrustTier` subclass (`src/alfred/security/tiers.py`). Marks
content that originates from the TUI adapter when the authenticated user
holds the `operator` authorization role. T1 is the ingress tier for
operator-interactive sessions — it is trusted above T2 (authenticated
user) because the operator configures the system and therefore the system
extends elevated provenance to their inputs.

T1 is NOT applied to Discord messages: Discord is broadcast-shaped and
every Discord DM reaches the orchestrator as T2 regardless of the sender's
authorization role. T1 applies to TUI stdout only in Slice 3; the ingest
path is `src/alfred/identity/_ingest.py::_ingest_tier()`. See spec §3.1
and §3.6.

See [trust tier](#trust-tier) and
[ADR-0017](adr/0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md).

## T3 (untrusted-ingestion tier)

The `T3` `TrustTier` subclass (`src/alfred/security/tiers.py`). Marks
content arriving from fully untrusted sources: web fetches, email, file
ingest, and MCP tool output. T3 is the load-bearing tier for the
dual-LLM split: the privileged orchestrator never sees raw T3 bytes;
only the quarantined LLM subprocess processes them, and only via the
structured-extraction path that emits `T3DerivedData` back to the
orchestrator.

Constructing `TaggedContent[T3]` is capability-gated. The public `tag(T3,
...)` function always raises; authorised call sites use
`tag_t3_with_nonce(content, caller_token=<nonce>)` with a
`CapabilityGateNonce` injected at bootstrap. This is the nonce gate that
closes import-time forgery attacks.

See [trust tier](#trust-tier), [CapabilityGateNonce](#capabilitygatenonce),
[tag_t3_with_nonce](#tag_t3_with_nonce), [dual-LLM split](#dual-llm-split),
and [ADR-0017](adr/0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md).

## TaggedContent[T]

The generic Pydantic model (`src/alfred/security/tiers.py`) that carries
content alongside its [trust tier](#trust-tier). Type parameter `T` is a
`TrustTier` subclass; the model is frozen (`model_config = ConfigDict(frozen=True)`)
so a caller cannot rebind the `tier` field after construction. The `tier`
field serialises to its `name` string on the wire and resolves back via
`_resolve_tier_from_wire` on parse. Cross-tier wire attacks — a payload
claiming `T2` but constructed as `T3` — are rejected by the
`_validate_tier` field validator that compares the resolved tier against
the generic parameter.

See [trust tier](#trust-tier), [AnyTaggedContent](#anytaggedcontent), and
[docs/subsystems/security.md](subsystems/security.md).

## AnyTaggedContent

The `@runtime_checkable` Protocol (`src/alfred/security/tiers.py`)
exposing a read-only view of any `TaggedContent[T]` regardless of the
tier type parameter. Observer code — audit writers, DLP scanners, logging
paths — accepts `AnyTaggedContent` rather than a concrete
`TaggedContent[T]` to avoid `cast()` proliferation. Mutators accept the
concrete generic. The four Protocol members (`content`, `source`, `tier`,
`metadata`) are all read-only `@property` declarations; `metadata` returns
`Mapping[str, Any]` (not `dict`) so observers cannot statically mutate the
metadata. See spec §3.3.

See [TaggedContent[T]](#taggedcontentt) and
[docs/subsystems/security.md](subsystems/security.md).

## CapabilityGateNonce

A per-process opaque object (`src/alfred/security/tiers.py`,
`class CapabilityGateNonce`). Constructed once at process start by
`alfred.bootstrap.nonce_factory.create_and_register_t3_nonce()` and
distributed via dependency injection to exactly two authorised call sites:
`StdioTransport` and `quarantine_host`. The `tag_t3_with_nonce` gate
compares by Python `is` (identity), not `==` (equality), so a caller who
copies or reconstructs the object cannot forge the nonce. The
`gc.get_objects()` traversal attack is acknowledged as out-of-scope in the
adversarial corpus (`tl_gc_traversal_out_of_scope`) — an adversary with
heap access already has full process compromise.

See [T3 (untrusted-ingestion tier)](#t3-untrusted-ingestion-tier),
[tag_t3_with_nonce](#tag_t3_with_nonce), and
[ADR-0017 Decision 1](adr/0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md).

## tag_t3_with_nonce

The capability-gated factory (`src/alfred/security/tiers.py`) for
constructing `TaggedContent[T3]`. The caller must pass the exact
`CapabilityGateNonce` registered at bootstrap; the module-level
`_AUTHORIZED_T3_NONCE` slot holds the single authorised instance.
Passing `None` or a different object raises `ValueError` with i18n key
`security.tag_t3_unauthorized` and emits a structlog warning
`security.t3_boundary.refused`. A forensic frame-derived caller label
appears in the warning; it is NOT a security gate (frame introspection is
forgeable via `sys.modules` manipulation), only a forensic aid.

See [CapabilityGateNonce](#capabilitygatenonce),
[T3 (untrusted-ingestion tier)](#t3-untrusted-ingestion-tier), and
[docs/subsystems/security.md](subsystems/security.md).

## ContentHandle

A frozen opaque reference (`src/alfred/security/quarantine.py`) to T3
content held in the plugin host's content store. Fields: `id` (UUID
string), `source_url` (audit attribution only — not the fetched bytes),
`fetch_timestamp` (timezone-aware `datetime`; naive datetimes are
rejected at construction). The orchestrator holds `ContentHandle`
references; it never dereferences the bytes directly — there is
intentionally no `.content` field. The quarantined-LLM plugin
dereferences via `ContentStoreBase.get(handle.id)`. Each `id` is
single-use; the Redis-backed production store atomically deletes on first
successful extract; a second extract raises `ContentHandleExpired`.

See [T3DerivedData](#t3deriveddata), [ContentStoreBase](#contentstorebase),
and [docs/subsystems/security.md](subsystems/security.md).

## T3DerivedData

A `NewType` over `dict[str, object]` (`src/alfred/security/quarantine.py`).
Type-level provenance marker for structured data that originated from T3
content and was extracted by the quarantined LLM. At runtime it is a plain
dict; at type-check time mypy treats it as distinct, so `cast(dict, ...)` on
a `T3DerivedData` value triggers the CI `check_tag_t3.py` grep rule.
Callers must pass `T3DerivedData` through `downgrade_to_orchestrator()`
before injecting into privileged prompts; that function holds the
capability-gate check and audit row write.

See [ContentHandle](#contenthandle), [dual-LLM split](#dual-llm-split),
and [docs/subsystems/security.md](subsystems/security.md).

## StdioTransport

The sole Slice-3 implementation of the `PluginTransport` Protocol
(`src/alfred/plugins/stdio_transport.py`). Wraps the `model_context_protocol`
SDK; manages the subprocess lifecycle; applies the outbound DLP +
secret-substitution pipeline and the inbound canary-scan pipeline on every
JSON-RPC frame. Content-bearing inbound frames produce a `ContentHandle`
(T3 bytes go to the content store; the orchestrator never sees them).
Control-plane frames produce a `ControlResult`. The subprocess is launched
with a scrubbed env (only `PATH` + i18n vars) and receives the provider key
over fd-3 rather than via env.

See [PluginTransport](#plugintransport), [AlfredPluginSession](#alfredpluginsession),
and [docs/subsystems/plugins.md](subsystems/plugins.md).

## AlfredPluginSession

The lifecycle owner for a single plugin subprocess
(`src/alfred/plugins/session.py`). Public construction is via the
`async classmethod create(manifest_raw=..., audit_writer=..., gate=...)`
factory — `__init__` is internal and skips the `plugin.lifecycle.load_refused`
audit row on manifest failure. The session parses the manifest, runs the
capability gate at handshake, emits `plugin.lifecycle.loaded` on success,
and enforces post-handshake method restrictions — a plugin sending
`alfred/hooks.register` post-handshake is SIGKILLed (kill lands before
the audit row so the `signal='SIGKILL'` claim is always true).

See [StdioTransport](#stdiotransport), [PluginManifest](#pluginmanifest),
and [docs/subsystems/plugins.md](subsystems/plugins.md).

## PluginManifest

The validated TOML manifest model (`src/alfred/plugins/manifest.py`).
Fields: `manifest_version: Literal[1]`, `plugin_id: str`, `subscriber_tier: str`,
`sandbox_profile: str`, `platform: str | None` (reserved for Slice-4
comms-MCP rewrite). The `subscriber_tier` field is the subscriber-capability
axis (`system` / `operator` / `user-plugin`) and is explicitly NOT the
content trust tier — passing `T0`–`T3` as `subscriber_tier` raises
`ManifestTierError`. A manifest presenting `manifest_version != 1` raises
`ManifestVersionError` before any capability-gate check.

See [ManifestError](#manifesterror), [subscriber_tier](#subscriber_tier),
and [docs/subsystems/plugins.md](subsystems/plugins.md).

## ManifestError

The error hierarchy root for every plugin manifest rejection
(`src/alfred/plugins/errors.py`). Leaf subtypes: `ManifestVersionError`
(`alfred.manifest_version` ≠ 1), `ManifestTierError` (content trust tier
supplied as `subscriber_tier`), and plain `ManifestError` (malformed TOML,
missing required field, unknown subscriber_tier label). All three produce a
`plugin.lifecycle.load_refused` audit row before propagating to the
supervisor.

See [PluginManifest](#pluginmanifest) and
[docs/subsystems/plugins.md](subsystems/plugins.md).

## RealGate

The production `CapabilityGate` implementation
(`src/alfred/security/capability_gate/_gate.py`). Backed by Postgres +
state.git (spec §8.1). Three check methods: `check()` (subscriber-tier
dispatch gate), `check_plugin_load()` (handshake gate), and
`check_content_clearance()` (content-tier axis). A 10-second heartbeat
loop pings the backing store; after 6 missed heartbeats (60 seconds) the
gate trips to fail-closed and emits a
`supervisor.capability_gate_unavailable` audit row. Production code does
not import `RealGate` directly; `alfred.bootstrap.gate_factory` selects
between `RealGate` and `DevGate` based on `ALFRED_ENV`.

See [GatePolicy](#gatepolicy), [GrantRow](#grantrow),
[capability gate](glossary.md#capability-gate), and
[docs/subsystems/security.md](subsystems/security.md).

## GatePolicy

The immutable in-memory grant snapshot for the capability gate
(`src/alfred/security/capability_gate/policy.py`). A frozen dataclass
holding a `frozenset[GrantRow]`. Hot-path `check*` methods on `RealGate`
dispatch through `GatePolicy` without touching Postgres. Rebuilt
atomically on every state.git HEAD change; the empty default snapshot
denies all checks (fail-closed bootstrap state). The matching algorithm
is O(n) over the grant set — the expected n is low hundreds for a busy
deployment.

See [RealGate](#realgate), [GrantRow](#grantrow), and
[docs/subsystems/security.md](subsystems/security.md).

## GrantRow

A frozen dataclass (`src/alfred/security/capability_gate/policy.py`)
representing one capability grant row. Fields: `plugin_id`,
`subscriber_tier` (subscriber-capability axis — NOT content trust tier),
`hookpoint` (dotted action name or `"*"` wildcard), `content_tier` (T0–T3
or `None`), `proposal_branch` (state.git branch that approved this grant).
`GrantRow.__post_init__` validates `subscriber_tier` against the closed
vocabulary `{"system", "operator", "user-plugin"}` and `content_tier`
against `{"T0", "T1", "T2", "T3", None}` at construction time to prevent
upstream parser bugs from smuggling non-PRD tiers into the in-memory
snapshot.

See [GatePolicy](#gatepolicy) and
[docs/subsystems/security.md](subsystems/security.md).

## PluginGrant

The SQLAlchemy ORM model for the `plugin_grants` Postgres table
(`src/alfred/memory/models.py`). Column-for-column mirror of `GrantRow`
(migration `0008_plugin_grants`, PR-S3-0b). `RealGate._apply_grants()`
reads from this table at startup and after every state.git HEAD change;
`StorageBackend.upsert_grant` / `revoke_grant` writes back to it.

See [GrantRow](#grantrow) and [docs/subsystems/security.md](subsystems/security.md).

## CapabilityGateSync

*Alias for the `CapabilityGateSyncRow` ORM and `capability_gate_sync`
table.* The Postgres table that persists the last-applied state.git commit
hash so `RealGate` can skip a rebuild when the HEAD has not changed. One
row per process; `StorageBackend.get_sync_hash()` / `set_sync_hash()`
access it.

See [RealGate](#realgate) and [docs/subsystems/security.md](subsystems/security.md).

## InboundContentScanner

The inbound DLP analog for plugin subprocesses
(`src/alfred/plugins/inbound_scanner.py`). Scans raw JSON-RPC frames (as
bytes, not decoded strings) for operator-registered canary tokens. Distinct
from `OutboundDlp`: the disposition is always a `CanaryTrip` security event
(quarantine trigger), never redact-and-continue. `StdioTransport.dispatch`
wraps calls in `asyncio.to_thread` to keep the event loop responsive on
large frames. The scanner matches bytes patterns — compiled with
`re.escape` — so `CanaryTrip.frame_offset` is always a true byte offset,
correct even for multi-byte UTF-8 content.

See [OutboundDlp](glossary.md#outbounddlp) and
[docs/subsystems/plugins.md](subsystems/plugins.md).

## ContentStoreBase

The Protocol for T3 content stores (`src/alfred/plugins/content_store_base.py`).
Methods: `put(handle, tagged_content)`, `get(handle_id)`, `delete(handle_id)`.
The store persists the full `TaggedContent[T3]` wrapper (not raw bytes) so
the nonce and provenance are preserved on retrieval; persisting raw bytes
would silently downgrade T3 → untagged on read-back (tier-laundering
vulnerability). Slice-3 ships `InMemoryContentStore` for unit tests and
pre-Redis bootstrap; the Redis-backed production store lands in PR-S3-5.

See [ContentHandle](#contenthandle) and
[docs/subsystems/plugins.md](subsystems/plugins.md).

## DispatchResult

The return-type union of `StdioTransport.dispatch()`
(`src/alfred/plugins/transport.py`). Three shapes, branched by `isinstance`
at call sites (no Pydantic discriminator field):

- `ContentHandle` — content-bearing tools (e.g. `web.fetch`); T3 bytes
  are in the content store, the caller receives the opaque handle only.
- `ExtractionResult` — `quarantine.extract` calls; itself a union of
  `Extracted` and `TypedRefusal`.
- `ControlResult` — lifecycle, config, health-check methods; no T3 content.

See [StdioTransport](#stdiotransport) and
[docs/subsystems/plugins.md](subsystems/plugins.md).

## PluginTransport

The `@runtime_checkable` Protocol (`src/alfred/plugins/transport.py`) every
plugin transport implements. Surface: `async dispatch(method, params) ->
DispatchResult` and `async close()`. Slice 3 ships `StdioTransport` as the
sole implementation. HTTP transport is deferred to Slice 5+; in-process
`MemoryTransport` is permanently excluded (would collapse process-boundary
isolation). The supervisor and orchestrator hold a `PluginTransport`
reference and do not import the concrete class.

See [StdioTransport](#stdiotransport) and
[docs/subsystems/plugins.md](subsystems/plugins.md).

## CircuitBreaker / BreakerState / CircuitBreakerState

*Slice 3+ terms.* The circuit-breaker pattern governing quarantined-LLM
subprocess restarts in the plugin supervisor. `BreakerState` is the enum
of states: `CLOSED` (normal), `OPEN` (tripped — quarantine in effect),
`HALF_OPEN` (recovery probe). `CircuitBreakerState` is the frozen
dataclass tracking `trip_count`, `last_trip_at`, and the current
`BreakerState`. The full supervisor with circuit-breaker logic ships in
PR-S3-3b; the audit schema fields `breaker_state` and `trip_count` are
defined in PR-S3-0a's `PLUGIN_LIFECYCLE_QUARANTINED_FIELDS`.

See [docs/subsystems/plugins.md](subsystems/plugins.md).

## subscriber_tier

The subscriber-capability axis on hook subscriptions and plugin manifests.
Closed vocabulary: `system` / `operator` / `user-plugin`. Determines
dispatch order (system → operator → user-plugin) and is the grant axis
the `CapabilityGate` checks. **Not the same as content trust tier
(T0–T3).** Conflating the two is the tier-laundering bug class that
`ManifestTierError` and the `GatePolicy` validation guard against. See
[ADR-0017 Decision 3](adr/0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md).

See [hook tier](#hook-tier) and [GrantRow](#grantrow).

## quarantine (process)

The subprocess isolation mechanism for the quarantined LLM in Slice 3.
The quarantined LLM runs as an MCP stdio subprocess under a dedicated
`alfred-quarantine` OS user with a scrubbed environment (only `PATH` + i18n
vars). The provider key is delivered over fd-3 rather than via env. This is
*hybrid isolation* — process-level UID separation without container
isolation. Container isolation (via `bwrap` policy) ships in Slice 4 per
[ADR-0015](adr/0015-slice4-containerised-quarantined-llm.md). The
`ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED=1` guard in `bin/alfred-plugin-launcher.sh`
enforces `$XDG_RUNTIME_DIR/alfred/plugin-<id>/` as the write root until the
Slice-4 sandbox policy lands.

See [dual-LLM split](#dual-llm-split),
[ADR-0017 Decision 4](adr/0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md),
and [docs/subsystems/plugins.md](subsystems/plugins.md).

## dual-LLM split

The architectural invariant (PRD §7.1) that divides LLM inference into two
roles: the **privileged orchestrator** (sees T0–T2 content only, issues tool
calls, manages personas) and the **quarantined LLM** (the sole legitimate
processor of T3 content, runs as an MCP stdio subprocess, emits structured
`ExtractionResult` only — never tool calls, never free text fed back as
instructions). The split makes T3 isolation a process boundary rather than
a taint annotation. The quarantined LLM cannot exfiltrate secrets because
its subprocess env is scrubbed and it cannot call tools directly.

Without the dual-LLM split, T3-tagging is taint annotation only and
provides no actual isolation guarantee — the reason
[ADR-0013](adr/0013-defer-t1-t3-and-dual-llm.md) deferred T3 rather
than shipping it without the split. The split ships in Slice 3 together
with the MCP transport that makes it possible (see
[ADR-0017](adr/0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md)).

See [quarantine (process)](#quarantine-process), [T3 (untrusted-ingestion tier)](#t3-untrusted-ingestion-tier),
and [docs/subsystems/security.md](subsystems/security.md).

## Action

A named unit of work the core or a plugin dispatches: a tool call, a
provider call, a memory write, a comms outbound, an audit write, a
persona-to-persona message, a skill invocation. Distinct from a *tool
call*, which is one kind of action. Every action that wants to be
hookable threads its lifecycle through the same five-stage primitive
(`pre` → body → `post` / `error` / `cancel`) so subscribers across all
actions register against one uniform contract.

See [ADR-0014](adr/0014-pluggable-hooks-for-every-action.md) and
[`docs/subsystems/hooks.md`](subsystems/hooks.md).

## Hookpoint

A named, string-keyed extension point declared at a point in some
code's execution. Any code — core or plugin — may both publish
(call `invoke(name, ctx, kind=...)` at the stage) and subscribe
(register a handler against `(name, kind)`); spec §9.1's "no
asymmetry" point pins this. Slice-2.5 PR-A's in-process dispatch keys
on the LOCAL stem name the publisher passes to `invoke()`
(`"before_db_write"`, `"after_flush"`, etc.). The dotted form
(`memory.episodic.record.before_db_write`) is the canonical
threat-model identifier the Slice-3 MCP transport will normalise to —
but a Slice-2.5 subscriber MUST use the stem to fire against the
in-process publisher. See the "Hookpoint naming" callout in
[`docs/subsystems/hooks.md`](subsystems/hooks.md) for the same
Slice-2.5 caveat.

Hookpoints are PUBLISHER-DECLARED: the action that emits the hookpoint
calls `register_hookpoint(name=..., subscribable_tiers=...,
refusable_tiers=..., fail_closed=...)` at module init. Subscribers
register against the declared metadata; mismatched tiers are refused
at registration time and audited as `hooks.tier_rejected` (#119).

See spec §3,
[`docs/subsystems/hooks.md`](subsystems/hooks.md), and
[ADR-0014](adr/0014-pluggable-hooks-for-every-action.md).

## Hook kind

One of `pre` / `post` / `error` / `cancel`. The routing axis on a hook
invocation; each kind has a distinct subscriber contract (spec §3.5,
§4):

- **`pre`** — runs before the action body; subscribers may mutate the
  input or refuse via [`HookRefusal`](#hookrefusal).
- **`post`** — runs after the action body succeeds; observe-or-rewrite
  for downstream observers; refusal is meaningless.
- **`error`** — runs when the action body raised a non-cancellation
  exception; swallow-and-substitute via returning a `HookContext`.
- **`cancel`** — runs on `asyncio.CancelledError`; cleanup-only,
  return values ignored, original cancellation always re-raises.

See [`docs/subsystems/hooks.md`](subsystems/hooks.md).

## Hook tier

One of `system` / `operator` / `user-plugin`. The deterministic
dispatch-order axis on hook subscribers (system → operator →
user-plugin, then registration order within tier) and a **requested
capability** the operator-side `CapabilityGate` must grant (spec §6.1).
Tier is a request, not a self-declaration: the publisher's
`subscribable_tiers` allow-list and the registry's capability gate
together decide whether a registered subscriber actually runs.

**Not to be confused with [trust tier](#trust-tier)** — trust tier
(T0-T3) is the type-level provenance discriminant on content blobs;
hook tier is the dispatch + authorization axis on subscribers. They
share the word "tier" only.

See spec §6.1, [`docs/subsystems/hooks.md`](subsystems/hooks.md), and
[ADR-0014](adr/0014-pluggable-hooks-for-every-action.md).

## HookRefusal

The exception a `pre` subscriber raises to short-circuit the chain
(`src/alfred/hooks/errors.py`). The action body does not run, a
`hooks.refusal` audit row is written, and the exception propagates to
the caller — provided the subscriber's tier is in the hookpoint's
`refusable_tiers` allow-list. An **unauthorized** refusal (subscriber's
tier NOT in `refusable_tiers`) is audited as
`hooks.unauthorized_refusal`, the would-be mutation is discarded, and
NO exception is raised to the caller; the audit row IS the
loud-failure escape (CLAUDE.md hard rule #7). This is spec §6.5.

`HookRefusal` is `pre`-only; raising it from a `post`, `error`, or
`cancel` subscriber propagates uncaught with no refusal audit row.

See [`docs/subsystems/hooks.md`](subsystems/hooks.md).

## PoC

Proof-of-concept. In the Slice 2.5 hooks context, the single
instrumented action — `memory.episodic.record` in
[`src/alfred/memory/episodic.py`](../src/alfred/memory/episodic.py) —
that exercises the hook contract end-to-end across all four
[hook kinds](#hook-kind) (`pre`, `post`, `error`, `cancel`). The PoC
proves the publisher / subscriber / dispatcher / capability-gate
contract on real action infrastructure before the rest of the
codebase migrates.

See spec §7 and [`docs/subsystems/hooks.md`](subsystems/hooks.md).

## CommsAdapter Protocol

The Slice-2-only in-process Python `Protocol` (`@runtime_checkable`)
that every comms adapter satisfies. Surface: `name`, `async start()`,
`async run()`, `async stop()`, `def health() -> AdapterHealth`. The
orchestrator's supervisor drives every adapter through this surface.

Bounded deviation from PRD §5 ("plugins are MCP servers"): the
deviation is documented in [ADR-0009](adr/0009-comms-adapter-protocol-slice2-only.md),
and an AST-scan test prevents the concrete adapters from being imported
outside `src/alfred/comms/` so the Slice-3 MCP-transport rewrite stays
a single-module refactor.

See [`docs/subsystems/comms.md`](subsystems/comms.md).

## IdentityResolver

The only legitimate accessor for `User` and `PlatformIdentity` ORMs
(`src/alfred/identity/resolver.py`). Owns an in-process LRU cache with a
60-second TTL backstop and an `IdentityVersionCounter`-driven
invalidation hook. Surfaces five mutating methods (`add`, `bind`,
`unbind`, `remove`, `set_`) plus read-only `resolve`, `get_operator`,
`show`, `list_`. Every mutating method bumps the version counter exactly
once and emits a Postgres `NOTIFY alfred_identity_changed` payload
inside the same transaction.

See [ADR-0010](adr/0010-canonical-user-id-and-listen-notify.md) and
[`docs/subsystems/identity.md`](subsystems/identity.md).

## IdentityVersionCounter

A monotonic `threading.Lock`-guarded integer counter
(`src/alfred/identity/version_counter.py`). Bumped on every successful
identity mutation. Subscribed by `BudgetGuard` and the resolver's LRU;
when `current()` advances, downstream caches invalidate and re-fetch
on the next access.

The counter is purely in-process. Cross-process invalidation is
delivered by `IdentityListener` (subscribed to the Postgres
`alfred_identity_changed` LISTEN channel), which bumps the local
counter on every NOTIFY. The 60-second TTL backstop on every cache
entry bounds staleness on dialects that do not support `LISTEN/NOTIFY`.

See [ADR-0010](adr/0010-canonical-user-id-and-listen-notify.md) and
[ADR-0011](adr/0011-per-user-budget-guard.md).

## BudgetGuard

The per-user cost gate keyed on canonical user_id
(`src/alfred/budget/guard.py`). Holds a `dict[str, _UserBudget]` where
each entry stores `daily_usd`, `daily_usd_version`, `per_call_max_usd`,
`day` (UTC), and `spent`. Three security invariants:

- `_spent` and `day` are source-of-truth and NEVER evict under any
  in-process logic. The only legitimate eviction is the explicit
  `BudgetGuard.evict(user_id)` escape hatch.
- Only `daily_usd` is cache-able; `IdentityVersionCounter` bumps
  refresh the cached cap without touching `spent` or `day`.
- NaN / infinity / negative values are rejected at every cost entry
  point and at the `daily_budget_usd` load path (defence-in-depth on
  top of the DB CHECK).

See [ADR-0011](adr/0011-per-user-budget-guard.md).

## SecretBroker

The sole legitimate consumer of `ALFRED_*` environment variables and
the `~/.config/alfred/secrets.toml` file for any value listed in
`SUPPORTED_SECRETS`. Every other module reads secrets via
`SecretBroker.get` — the AST-scan test
`tests/unit/security/test_no_direct_env_reads.py` enforces this.

Two backends:

- **Env backend** (Slice 1): reads `ALFRED_<UPPERSECRET>` from
  `os.environ`.
- **File backend** (Slice 2): reads the TOML file at
  `~/.config/alfred/secrets.toml` (XDG default) or wherever
  `ALFRED_SECRETS_FILE` points. Fail-closed at construction:
  permissions must be `0600`, owned by the invoking user, parent
  directory must not be group/world-writable, the file must not be a
  symlink, and no `.git/` may appear in any of the first 12 ancestor
  directories.

Per-secret precedence is controlled by `_PREFER_FILE`. The broker
exposes `redact()` for the outbound DLP's stage-1 redaction.

See [ADR-0005](adr/0005-env-backed-secret-broker-slice1.md) and
[ADR-0012](adr/0012-file-backed-secret-broker.md).

## SUPPORTED_SECRETS

The broker's allowlist of registered secret names
(`frozenset[str]` in `src/alfred/security/secrets.py`). Slice 2:
`{deepseek_api_key, anthropic_api_key, discord_bot_token}`. Anything
not in this set raises `UnknownSecretError` on `get()`. Adding a new
secret name requires editing this set plus, if the secret is
file-preferred, adding it to `_PREFER_FILE` too.

See [ADR-0012](adr/0012-file-backed-secret-broker.md).

## \_PREFER_FILE

A strict subset of `SUPPORTED_SECRETS` whose file-backend value wins
over the env-backend value
(`frozenset[str]` in `src/alfred/security/secrets.py`). Slice 2:
`{discord_bot_token}`. For names NOT in this subset, env wins for
backward compatibility with Slice-1 deployments. The subset invariant
is asserted at import time.

See [ADR-0012](adr/0012-file-backed-secret-broker.md).

## OutboundDlp

The three-stage outbound scanner every outbound message string passes
through (`src/alfred/security/dlp.py`):

1. **Broker redaction** — `SecretBroker.redact` replaces any known
   secret value with `[REDACTED:<name>]`. Patterns are processed in
   descending-length order so a longer secret whose suffix is another
   live secret is fully redacted before the shorter one runs.
2. **Generic API-key regex** —
   `\b(?:sk|pk|tok|key)[-_][A-Za-z0-9]{20,}\b` → `[REDACTED:api-key-shape]`.
3. **Canary stub** — Slice 2 is a literal no-op. Slice 3 expands.

On modification, exactly one `dlp.outbound_redacted` audit row is
written with byte deltas + `stages_triggered`. Silent redaction is a
documented Slice-2 known oracle; Slice 3 pads to a length-bucket
boundary.

See [`docs/subsystems/comms.md`](subsystems/comms.md) and
[ADR-0012](adr/0012-file-backed-secret-broker.md).

## RateLimiter

The per-user rate-limiting Protocol (`src/alfred/identity/rate_limit.py`).
Implementations decide policy (token bucket, leaky bucket, sliding
window); consumers depend only on the Protocol surface. MUST return
`False` unconditionally for `Authorization.READ_ONLY`. Slice 2 ships
`NullRateLimiter` (no-op for single-operator deployments) and
`InProcessTokenBucketRateLimiter` (per-user token bucket keyed on
slug, refilled at the authorization-tier default rate).

See [`docs/subsystems/comms.md`](subsystems/comms.md) (RateLimiter
Protocol) and the `authorization-role` entry above for tier defaults.

## WorkingMemoryPool

The `(persona, user_id)`-keyed pool of in-process working memory
buffers (`src/alfred/memory/working_pool.py`, PR-B). Per-key locks
serialise access; eviction skips entries that are currently in use
(an active orchestrator turn holding the lock). Lazy-rehydrate from
the episodic store fires on cache miss, so a `WorkingMemoryPool`
entry for a returning user reconstitutes their context without an
explicit prompt.

See [ADR-0011](adr/0011-per-user-budget-guard.md) (consumer of the
same `IdentityVersionCounter` invalidation contract).

## Audit log

Append-only event log of every tool call, memory write, config change,
reviewer decision, and persona-coordination message. Rows carry
attribution (`actor_user_id`, `actor_persona`, `language`), event-type,
and event-specific subject fields. Stored in the `audit_log` Postgres
table; the audit-graph CLI renders cross-row joins for forensic queries.
Failure to write an audit row in a security path propagates (CLAUDE.md
hard rule #7).

## Capability gate

The runtime enforcement surface for plugin permissions. Every tool call
passes through the capability gate, which consults the plugin's
manifest, the per-user grant table, and the current request context.
Slice 3 lands the full surface alongside the MCP plugin transport;
Slice 2 ships only the data-model placeholders.

## DLP

Data Loss Prevention. In AlfredOS, DLP is the chokepoint discipline:
every outbound message string passes through `OutboundDlp.scan` (the
three-stage scanner above) before reaching the recipient. DLP cannot be
disabled per-call; only manifest-declared pure-internal tools can
bypass, and the adversarial suite verifies that claim. See the
`OutboundDlp` entry above.

## Persona

A named LLM-driven actor with its own system prompt, memory partition,
and authorization scope. The default persona is **Alfred**. Operators
can enable additional personas (Lucius, Oracle, Diana, …). Personas
honour `{user.language}` so the same persona renders different
operator-facing strings in different languages without a code change
(CLAUDE.md i18n rule #2).

## Skill

A procedural plugin in `skills/` that AlfredOS itself invokes at
runtime. Distinct from a Claude Code skill (which lives in
`~/.claude/skills/` and is invoked by Claude Code agents working on
this repo). Runtime skills go through the reviewer gate before
landing.

## MCP

Model Context Protocol. The transport AlfredOS uses for first-party
and third-party plugins (Slice 3+). Comms adapters speak in-process
Python in Slice 2 (see CommsAdapter Protocol above) and convert to
MCP transport in Slice 3 per [ADR-0009](adr/0009-comms-adapter-protocol-slice2-only.md).

## OODA loop

Observe-Orient-Decide-Act. The cognitive loop AlfredOS personas run
on every conversational turn. Observe: ingest the user's message +
working memory + relevant episodic recall. Orient: identify which
skill / tool / response shape fits. Decide: choose one. Act: emit the
response, audit the action.

## Slug

The canonical-user-id form (see `canonical-user-id` above). Also used
generically for "URL-safe lowercased name" in adjacent contexts (e.g.
`docs/adr/NNNN-<slug>.md` filenames).

## Snowflake

A Discord-native 64-bit identifier (e.g. `123456789012345678`).
AlfredOS stores snowflakes as strings in `platform_identities.platform_id`
because some Discord clients round 64-bit integers in JSON-decoder
defaults; round-tripping as strings preserves precision.

## ContextVar

Python's `contextvars.ContextVar` primitive. AlfredOS uses one
`_active_language: ContextVar[str | None]` to thread the active
user's BCP-47 language tag through `t()` calls without passing it
explicitly down the call stack. Each persona turn sets the
`ContextVar` to the user's language at the orchestrator boundary;
asyncio.TaskGroup copies the context per child, so concurrent turns
do not leak language state across users.
