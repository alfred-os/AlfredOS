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

Slice 3 introduces first-class `TaggedContent[T1]` and
`TaggedContent[T3]` type parameters:

- **`TaggedContent[T1]`** — operator-tier content. `T1` values are the
  ingress tier for operator-interactive sessions (e.g. the TUI adapter
  when the authenticated user holds the `operator` authorization role).
  The type enforces that T1 content came from an operator-authenticated
  source. `IdentityResolver` is the canonical producer for
  authenticated-platform-identity content — verified platform identities
  emit `TaggedContent[T2]` (authenticated-user tier), distinct from T1
  (operator tier). See [T1 (operator tier)](#t1-operator-tier) and the
  trust-tier model below.
- **`TaggedContent[T3]`** — external-untrusted content. `T3` values are
  produced only via the capability-gated `tag(T3, ...)` factory at the
  [`StdioTransport`](#stdiotransport) boundary and in
  `plugins/quarantine_host.py`. Any other call site raises `ValueError`
  (spec §3.2).

See [T1 (operator tier)](#t1-operator-tier),
[T3 (untrusted-ingestion tier)](#t3-untrusted-ingestion-tier),
[tag_t3_with_nonce](#tag_t3_with_nonce),
[ADR-0017](adr/0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md),
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

The sole production `CapabilityGate` implementation
(`src/alfred/security/capability_gate/_gate.py`). Backed by Postgres +
state.git (spec §8.1). Three check methods: `check()` (subscriber-tier
dispatch gate), `check_plugin_load()` (handshake gate), and
`check_content_clearance()` (content-tier axis). A 10-second heartbeat
loop pings the backing store; after 6 missed heartbeats (60 seconds) the
gate trips to fail-closed and emits a
`supervisor.capability_gate_unavailable` audit row.

`alfred.bootstrap.gate_factory` exposes two callables — `build_dev_gate()`
and `build_real_gate()` — that both return a `RealGate`. The two-factory
shape predates the PR-S3-7 flag-day; post-flag-day both branches
construct the same `RealGate` class with different dependency wiring:

- `build_dev_gate()` returns a fail-closed `RealGate` with an empty
  grant snapshot, an in-process backend stub (no Postgres connection),
  and the heartbeat disabled. Every `check*` call denies; developers
  who need granted-system semantics for local iteration use the
  helpers in `tests/helpers/gates/`.
- `build_real_gate()` returns the production-wired `RealGate` with the
  real Postgres `StorageBackend`, the production `AuditWriter`, and
  the heartbeat enabled.

The lazy-default at the `HookRegistry` boundary is `_DenyAllGate`
(`src/alfred/hooks/registry.py`) — a separate fail-closed sentinel that
serves any `@hook` decorator registering before the bootstrap installs
the real gate via `set_registry()`. Both fail-closed paths preserve
CLAUDE.md hard rule #7: no silent authorisation at boundary
mis-sequencing.

See [GatePolicy](#gatepolicy), [GrantRow](#grantrow),
[capability gate](#capability-gate), and
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

See [OutboundDlp](#outbounddlp) and
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

## ExtractionResult

The plain union `Extracted | TypedRefusal` (`src/alfred/security/quarantine.py:293`).
The return type of `QuarantinedExtractor.extract()` and
`quarantined_to_structured()`. Dispatch sites branch by `isinstance` — no
Pydantic discriminator wrapper at the alias level (core-011). A
`TypedRefusal` is a legitimate orchestrator outcome, not an exception; the
caller is expected to branch on it. The transport-layer `DispatchResult`
union (see [DispatchResult](#dispatchresult)) embeds `ExtractionResult` as
one of its three branches.

See [Extracted](#extracted), [TypedRefusal](#typedrefusal),
[QuarantinedExtractor](#quarantinedextractor), and
[docs/subsystems/security.md](subsystems/security.md).

## Extracted

Frozen Pydantic model for a successful structured extraction from T3 content
(`src/alfred/security/quarantine.py:232`). Fields: `kind: Literal["extracted"]`
(discriminator), `data: T3DerivedData`, `extraction_mode: ExtractionMode`.
`extra="forbid"` prevents transport-boundary typos from silently surviving.
The `data` field is a `T3DerivedData` `NewType` — at type-check time mypy
refuses to widen it to `dict`, so callers must go through
`downgrade_to_orchestrator()` before injecting the value into privileged
prompts. Shipped in PR-S3-4 (#TBD).

See [T3DerivedData](#t3deriveddata), [ExtractionMode](#extractionmode),
[ExtractionResult](#extractionresult), and
[docs/subsystems/security.md](subsystems/security.md).

## TypedRefusal

Frozen Pydantic model for a quarantined-LLM refusal (`src/alfred/security/quarantine.py:263`).
Fields: `kind: Literal["typed_refusal"]` (discriminator), `reason:
TypedRefusalReason`. The closed `reason` vocabulary is the structural
enforcement that prevents provider-supplied free-form text (which is
T3-derived) from entering audit-row fields. A `TypedRefusal` is not
translated to an exception — it is a legitimate orchestrator outcome the
caller branches on. Shipped in PR-S3-4 (#TBD).

See [TypedRefusalReason](#typedrefusalreason), [ExtractionResult](#extractionresult),
and [docs/subsystems/security.md](subsystems/security.md).

## QuarantinedExtractor

The orchestrator-side client of the quarantined-LLM plugin
(`src/alfred/security/quarantine.py:327`). Dispatches `quarantine.extract`
JSON-RPC calls via a `PluginTransport`, validates the response is a
`ControlResult` with a recognised `kind`, and lifts the payload into the
typed `Extracted | TypedRefusal` shape. Emits a `quarantine.extract` or
`quarantine.protocol_violation` audit row on every call — the audit row
lands before any raise so an operator reading the log sees the failure even
if the caller swallows the exception (CLAUDE.md hard rule #7). The
capability gate is consulted by the higher-level `quarantined_to_structured`
function, not by the extractor — this keeps transport + audit-row
concerns separate from gate concerns. Shipped in PR-S3-4 (#TBD).

See [ExtractionResult](#extractionresult), [PluginTransport](#plugintransport),
[alfred_quarantined_llm](#alfred_quarantined_llm),
[ADR-0017 Decision 7](adr/0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md),
and [docs/subsystems/security.md](subsystems/security.md).

## ExtractionMode

Closed `Literal` of three dispatch-path labels
(`src/alfred/security/quarantine.py:225`): `"native_constrained"` (Anthropic
tool-use, schema-constrained by the provider), `"json_object_unconstrained"`
(DeepSeek `json_object` mode, validated post-hoc by Pydantic), and
`"prompt_embedded_fallback"` (schema embedded in the user prompt, parsed and
validated by the host). The quarantined-LLM plugin selects the mode based
on `ProviderCapability` flags. The mode appears verbatim in the
`quarantine.extract` audit row's `extraction_mode` field, enabling forensic
queries that break down extraction costs by dispatch path. Shipped in
PR-S3-4 (#TBD).

See [ProviderCapability](#providercapability), [QuarantinedExtractor](#quarantinedextractor),
[ADR-0017 Decision 7](adr/0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md),
and [docs/subsystems/security.md](subsystems/security.md).

## TypedRefusalReason

Closed `Literal` vocabulary for `TypedRefusal.reason`
(`src/alfred/security/quarantine.py:212`). Seven values: `cannot_extract`
(retries exhausted), `refused_by_safety` (provider safety filter),
`ambiguous_input` (schema-incompatible input), `provider_refused` (structured
provider refusal), `provider_unavailable` (circuit breaker / supervisor down),
`dlp_outbound_refused` (outbound DLP blocked the result), `nonce_check_failed`
(handle-id nonce mismatch, enforced in PR-S3-5). Adding a new reason is a
deliberate audit-schema migration — free-form text cannot appear here because
provider-supplied error messages are T3-derived and would bypass DLP if
echoed into audit rows. Shipped in PR-S3-4 (#TBD).

See [TypedRefusal](#typedrefusal), [QuarantinedExtractor](#quarantinedextractor),
[docs/subsystems/security.md](subsystems/security.md), and spec §6.7.

## ProviderCapability

`StrEnum` declared at `src/alfred/providers/base.py:22`. Closed set of
capabilities a provider may declare, consulted by the quarantined-LLM
dispatch path (spec §6.2) to select the `ExtractionMode`. Values:
`NATIVE_CONSTRAINED_GENERATION` (Anthropic tool-use, schema-valid by
construction), `JSON_OBJECT_MODE` (DeepSeek `json_object`, validated
post-hoc), `TOOL_USE`, `VISION`, `LONG_CONTEXT_1M` (pre-declared for
future routing per PRD §6.6). Every concrete `Provider` implementation
declares its capabilities via the `capabilities() -> frozenset[ProviderCapability]`
Protocol method; `register_provider` enforces this at decoration time.
Shipped in PR-S3-4 (#TBD).

See [ExtractionMode](#extractionmode),
[ADR-0017](adr/0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md),
and [docs/subsystems/security.md](subsystems/security.md).

## alfred_quarantined_llm

The quarantined-LLM MCP plugin package at `plugins/alfred_quarantined_llm/`.
Runs as an MCP stdio subprocess under the `alfred-quarantine` OS user
(spec §5.2); the provider key is delivered over fd 3 rather than via env
(spec §5.3). The plugin declares `subscriber_tier = "system"` and
`sandbox_profile = "user-plugin"` in its manifest — subscriber tier grants
orchestrator-internal hookpoints; the OS sandbox limits blast radius if the
LLM provider's response-parsing path is compromised. Exposes two JSON-RPC
methods: `quarantine.ingest` and `quarantine.extract`. The plugin id on the
wire is `"alfred.quarantined-llm"`. Shipped in PR-S3-4 (#TBD).

See [quarantine.ingest](#quarantineingest), [quarantine.extract](#quarantineextract),
[quarantine (process)](#quarantine-process),
[ADR-0017 Decision 4](adr/0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md),
and [docs/subsystems/security.md](subsystems/security.md).

## quarantine.ingest

JSON-RPC method exposed by the `alfred_quarantined_llm` plugin
(`plugins/alfred_quarantined_llm/quarantine_plugin.py`). Signature:
`quarantine.ingest(handle_id: str, context: str)`. Accepts T3 bytes from
the plugin host and caches them under `handle_id` for a single subsequent
`quarantine.extract` call. The single-use invariant is enforced by the
content store (PR-S3-5 introduces the Redis-backed production store with
atomic `GETDEL` semantics; the Slice-3 skeleton uses an in-process dict).
Shipped in PR-S3-4 (#TBD).

See [quarantine.extract](#quarantineextract), [alfred_quarantined_llm](#alfred_quarantined_llm),
[ContentHandle](#contenthandle), and [docs/subsystems/security.md](subsystems/security.md).

## quarantine.extract

JSON-RPC method exposed by the `alfred_quarantined_llm` plugin
(`plugins/alfred_quarantined_llm/quarantine_plugin.py`). Signature:
`quarantine.extract(handle_id: str, schema_json: str, schema_version: int)`.
Dereferences the T3 bytes stored under `handle_id`, calls the configured
provider using the `ExtractionMode` that matches its `ProviderCapability`,
and returns a discriminated-union JSON object whose `kind` is `"extracted"`
or `"typed_refusal"`. Raw provider response bytes never cross back to the
orchestrator process — only the typed result. Protocol violations (unexpected
`kind`, non-`ControlResult` response) are a `quarantine.protocol_violation`
audit event, not a `TypedRefusal`. Shipped in PR-S3-4 (#TBD).

See [quarantine.ingest](#quarantineingest), [QuarantinedExtractor](#quarantinedextractor),
[ExtractionResult](#extractionresult), [alfred_quarantined_llm](#alfred_quarantined_llm),
and [docs/subsystems/security.md](subsystems/security.md).

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

**Orthogonality with content trust tier:** A `system`-tier plugin
(subscriber tier) can process T3 content (content trust tier) — these
two axes are independent. Using `subscriber_tier="T3"` in a plugin
manifest is a security error refused at handshake with
[`ManifestTierError`](#manifesterror) → a `plugin.lifecycle.load_refused`
audit row (T3 is not a valid subscriber tier; the valid values are
`system`, `operator`, `user-plugin`).

See [trust tier](#trust-tier) for the content-provenance axis and
[Capability gate](#capability-gate) for the orthogonal
`check_content_clearance` method that gates content-tier access.

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
Slice 3 lands the full surface alongside the MCP plugin transport. The
Protocol gains two sibling methods alongside `check()` (all shipped by
PR-S3-2):

- `check_plugin_load(*, plugin_id, manifest_tier) -> bool` — gates
  plugin load at handshake time; called by
  [`AlfredPluginSession`](#alfredpluginsession) before any capability
  grants are consulted.
- `check_content_clearance(*, plugin_id, hookpoint, content_tier) -> bool`
  — gates content-tier access: T3 content must not reach T2-only paths.
  Orthogonal to subscriber [hook tier](#hook-tier)
  (`system` / `operator` / `user-plugin`) — a `system`-tier plugin can
  process T3 content; these two axes are independent.

When Postgres is unavailable, all three methods return `False`
(fail-closed). The 60-second heartbeat window bounds staleness before
in-process subscribers also see fail-closed.

The PR-S3-7 flag-day removed `DevGate` from `src/` entirely.
`RealGate` is now the sole concrete gate; the dev-vs-prod selection
in `alfred.bootstrap.gate_factory` chooses between a fail-closed
no-Postgres `RealGate` (development) and the production-wired
`RealGate` (production) — never between two different classes. The
`_DenyAllGate` fail-closed sentinel at the `HookRegistry` lazy default
serves the bootstrap-ordering edge case where an `@hook` decorator
runs before the bootstrap installs the real gate. Pre-flag-day
`DevGate` returned `True` (fail-open) for new methods; that behaviour
no longer exists in any code path.

See [RealGate](#realgate), spec §8.2,
[ADR-0017](adr/0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md),
and [docs/subsystems/plugins.md](subsystems/plugins.md).

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

## Supervisor

The top-level coordinator that owns plugin process lifecycle, the
per-component [circuit breaker](#circuitbreaker--breakerstate--circuitbreakerstate) map, and the
[CapabilityGateMonitor](#capabilitygatemonitor). Implemented at
`src/alfred/supervisor/core.py::Supervisor`. The supervisor holds an
`asyncio.TaskGroup` open for its entire lifetime via a long-lived
internal `_run()` coroutine; every supervised plugin stdio-reader
task lives inside this group, so a `stop()` call cascade-cancels all
reader tasks cleanly. The supervisor exposes `reset_breaker()` as the
operator API for manual CLOSED-state recovery; the CLI surface
(`alfred supervisor reset <component>`) wires to this method in
PR-S3-6. Breaker state survives restarts via Postgres persistence
(`load_all_breakers()` at bootstrap). The supervisor's own audit rows
carry `trust_tier_of_trigger="T0"` and `actor_persona="supervisor"`.

See [ADR-0017](adr/0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md),
spec §4.8 and §10, and [docs/subsystems/supervisor.md](subsystems/supervisor.md).

## DeadlineWrapper

`asyncio.timeout` wrapper for orchestrator action paths
(`src/alfred/supervisor/deadline.py::DeadlineWrapper`). Construction
takes `deadline_seconds` (default 30 s per spec §10.5). Each
`DeadlineWrapper.run()` call wraps the target async callable in its own
`asyncio.timeout` block; only `asyncio.TimeoutError` is taken as "deadline
exceeded" — a genuine `CancelledError` from an operator or system shutdown
propagates unchanged (core-002). The wrapper itself is side-effect-free: it
emits no audit rows. The `supervisor.action_timeout` audit row is the
orchestrator's responsibility, written via an autocommit writer (independent
of the session-bound transaction that the timeout rolls back), per the
CR-S3-2 R3 lesson on autocommit-vs-session-bound audit write attribution.

See [docs/subsystems/supervisor.md](subsystems/supervisor.md) and
[ADR-0017](adr/0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md).

## CapabilityGateMonitor

Supervisor-side health monitor for the capability gate
(`src/alfred/supervisor/capability_monitor.py::CapabilityGateMonitor`).
Polls `gate.is_backing_store_available()` once per heartbeat cycle and
emits `supervisor.capability_gate_unavailable` audit rows on state
transitions only: `entering_fail_closed` when the backing store first
becomes unreachable, `exiting_fail_closed` when it recovers. Both rows
share a per-outage `_outage_correlation_id` (err-014) so the audit graph
can answer "how long did this outage last" with a simple `GROUP BY` join.
Distinct from `RealGate`'s internal heartbeat (which owns the 60-second
fail-closed window enforcement): the monitor adds the transition-only rows
the operator dashboard joins on. Emits carry `trust_tier_of_trigger="T0"`,
`actor_persona="supervisor"`, and `actor_user_id=None` — no human actor
initiates a self-healing probe.

See [RealGate](glossary.md#realgate),
[docs/subsystems/supervisor.md](subsystems/supervisor.md), and
spec §8.1 / §10.4.

## PluginLifecycle

Thin orchestrator that wires the `CircuitBreaker` state machine and audit
row emission together for plugin load and crash events
(`src/alfred/supervisor/plugin_lifecycle.py::PluginLifecycle`). Two public
methods: `start_plugin()` (gate-check at load; emits `plugin.lifecycle.loaded`
or `plugin.lifecycle.load_refused`) and `on_crash()` (records failure in the
breaker; emits `plugin.lifecycle.crashed` when the breaker stays CLOSED, or
`plugin.lifecycle.quarantined` when the breaker trips to OPEN). Subprocess
spawning, SIGKILL, and hookpoint invocation are NOT `PluginLifecycle`
responsibilities — they belong to `Supervisor` and the breaker hookpoint
helpers respectively, keeping the call graph one-directional:
`Supervisor → PluginLifecycle → CircuitBreaker / AuditWriter`.

See [CircuitBreaker / BreakerState / CircuitBreakerState](#circuitbreaker--breakerstate--circuitbreakerstate),
[docs/subsystems/supervisor.md](subsystems/supervisor.md), and spec §10.3.

## supervisor.action_timeout hookpoint

Fires when an orchestrator action exceeds its deadline (as enforced by
[`DeadlineWrapper`](#deadlinewrapper)). `subscribable_tiers={"system"}`;
`refusable_tiers=frozenset()` (the deadline has already fired; refusal has
no effect on the timed-out action); `fail_closed=False` (a crashing
subscriber is observability noise, not a security regression). Registered
by `Supervisor.__init__` from the `_register_hookpoints()` method
(`src/alfred/supervisor/core.py`) per core-010's rule against import-time
module-level hookpoint registration. The orchestrator emits this hookpoint
via an autocommit audit writer, independent of the rolled-back turn session.

See [`Hookpoint`](glossary.md#hookpoint),
[docs/subsystems/supervisor.md](subsystems/supervisor.md), and spec §14.

## supervisor.breaker.tripped / supervisor.breaker.reset hookpoints

Two hookpoints that fire on circuit breaker state transitions
(`src/alfred/supervisor/core.py`, `_register_hookpoints()`).

- `supervisor.breaker.tripped` — fires after `CircuitBreaker._trip()`
  transitions the breaker to OPEN. `subscribable_tiers={"system"}`;
  `refusable_tiers=frozenset()` (the breaker has already tripped);
  `fail_closed=False`.
- `supervisor.breaker.reset` — fires after an operator-triggered
  `Supervisor.reset_breaker()` call completes. `subscribable_tiers={"system",
  "operator"}` (operator dashboards may subscribe); `refusable_tiers=frozenset()`
  (refusal would defeat the operator override); `fail_closed=False`.

Neither hookpoint spawns fire-and-forget tasks. Both are awaited inside the
supervisor's `TaskGroup` so subscriber exceptions surface (err-001 /
core-004). Hookpoint invocation is the `PluginLifecycle` / `Supervisor`
caller's responsibility, not the `CircuitBreaker` state machine's — keeping
the breaker a pure domain object.

See [`Hookpoint`](glossary.md#hookpoint),
[CircuitBreaker / BreakerState / CircuitBreakerState](#circuitbreaker--breakerstate--circuitbreakerstate),
and [docs/subsystems/supervisor.md](subsystems/supervisor.md).

## supervisor.capability_gate_unavailable audit event

**Audit row, not a hookpoint.** Subscriber surface is the audit log itself —
no `subscribable_tiers` exist because no hookpoint is registered for this
event (the supervisor's spec §14 hookpoint table is the six entries
declared by `Supervisor._register_hookpoints()`).

Emitted by `CapabilityGateMonitor._emit_transition()` via
`AuditWriter.append_schema(event="supervisor.capability_gate_unavailable",
fields=SUPERVISOR_CAPABILITY_GATE_UNAVAILABLE_FIELDS, ...)` on gate
fail-closed entry and exit transitions. The `state_transition` subject
field is `"entering_fail_closed"` or `"exiting_fail_closed"`; the
`correlation_id` field links the two rows of the same outage window
(err-014). Attribution: `actor_persona="supervisor"`,
`actor_user_id=None`, `trust_tier_of_trigger="T0"`.

The outage timeline the operator dashboard renders is derived from these
rows via a `GROUP BY correlation_id` join on the `audit_log` table —
no hookpoint subscription needed because the row IS the surface.

See [`CapabilityGateMonitor`](#capabilitygatemonitor),
[docs/subsystems/supervisor.md](subsystems/supervisor.md), and spec §10.4.

## Sandbox profile

The per-plugin OS-level sandbox configuration declared in the plugin
manifest (`sandbox_profile` field, e.g. `"user-plugin"`). Declared
independently of [`subscriber_tier`](#subscriber_tier) — the
quarantined-LLM plugin has `subscriber_tier=system` (it processes T3
content on behalf of the system) but runs in the `user-plugin`-class
sandbox profile (no `ALFRED_*` env vars, fs writes restricted to
`$XDG_RUNTIME_DIR/alfred/plugin-<id>/`, network allowlist only).
Per-OS sandbox policy files (Linux `bwrap`, macOS `sandbox-exec`) ship
in Slice 4 alongside [ADR-0015](adr/0015-slice4-containerised-quarantined-llm.md).
In Slice 3, `bin/alfred-plugin-launcher.sh` fails closed when no policy
file is present; `ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED=1` unlocks Slice-3
subprocess plugins in `ALFRED_ENV=development` only. The sandbox profile
is orthogonal to both the subscriber-capability axis (see
[hook tier](#hook-tier)) and the content trust tier (see
[trust tier](#trust-tier)) — it constrains *what the plugin process
can do*, not *what the plugin is trusted to receive*.

See spec §4.3, §4.8, and
[docs/subsystems/plugins.md](subsystems/plugins.md).

## JSON_OBJECT_MODE

A [`ProviderCapability`](#providercapability) enum value indicating the
provider supports `response_format={"type": "json_object"}` but does
NOT enforce a schema. DeepSeek-chat is the Slice-3 `JSON_OBJECT_MODE`
provider; [`QuarantinedExtractor`](#quarantinedextractor) routes it
through the same retry-and-validate path as the
`prompt_embedded_fallback` [`ExtractionMode`](#extractionmode). The
selected mode is recorded in the audit row as
`extraction_mode="json_object_unconstrained"` to distinguish
best-effort post-hoc validation (DeepSeek) from true schema enforcement
(Anthropic, OpenAI). The distinction is forensic-load-bearing:
extraction failures in `JSON_OBJECT_MODE` are weighted toward
schema-incompatibility rather than provider-side malformation.

See spec §6.2, [ExtractionMode](#extractionmode), and
[docs/subsystems/security.md](subsystems/security.md).

## WebFetchError

The exception hierarchy for `web.fetch` failures
(`src/alfred/plugins/web_fetch/errors.py`, shipped PR-S3-5).
Subclasses: `WebFetchDomainNotAllowed`, `WebFetchTlsError`,
`WebFetchRateLimited`, `WebFetchMimeTypeNotAllowed`,
`WebFetchSizeLimitExceeded`. All user-facing error strings route
through `t()` (CLAUDE.md i18n rule #1). The hierarchy is fail-loud —
no `except Exception: pass` is permitted on a `WebFetchError`; the
plugin surfaces the typed subclass and the orchestrator translates it
to a `t()` message at the user boundary. `WebFetchCanaryTripped` is
explicitly NOT a subclass of `WebFetchError` — it is a separate
security-event hierarchy (see below) because a canary trip is a DLP
*event*, not a fetch *failure*.

See [WebFetchCanaryTripped](#webfetchcanarytripped), spec §7.10, and
[docs/subsystems/plugins.md](subsystems/plugins.md).

## WebFetchCanaryTripped

A distinct `AlfredError` subclass (NOT a [`WebFetchError`](#webfetcherror)
subclass) that signals a canary token was detected in fetched T3
content (`src/alfred/plugins/web_fetch/errors.py`, shipped PR-S3-5).
This is a SECURITY EVENT, not a fetch failure: it emits a
`tool.web.fetch.canary_tripped` audit row, quarantines the content
handle, and raises with `t("security.canary_tripped", url=source_url)`.
There is no silent-degradation path; the user receives an error and
the operator sees the audit event (CLAUDE.md hard rule #7 — no silent
failures in security paths). The separation from `WebFetchError`
prevents `except WebFetchError` blocks from accidentally swallowing
canary trips.

See [WebFetchError](#webfetcherror),
[InboundContentScanner](#inboundcontentscanner), spec §7.6, §7.10, and
[docs/subsystems/plugins.md](subsystems/plugins.md).

## QuarantinedUnavailable

The exception the orchestrator catches when the quarantined-LLM plugin
is unavailable (`src/alfred/plugins/errors.py`, shipped PR-S3-3b). A
distinct top-level exception, NOT a subclass of `HookSubscriberError`
or [`WebFetchError`](#webfetcherror) — its lifecycle is
supervisor-state, not subscriber-dispatch. The orchestrator responds
with `t("orchestrator.quarantine_unavailable")` — "I can't process
external content right now; please retry in a few minutes." There is
no silent T3-self-processing fallback; the user-visible message is a
hard invariant (CLAUDE.md hard rule #7). The
[`CircuitBreaker`](#circuitbreaker--breakerstate--circuitbreakerstate)
in `src/alfred/supervisor/` raises this when the quarantined-LLM
breaker state is `OPEN`; the [`Supervisor`](#supervisor)
re-emits on `HALF_OPEN` probes that fail.

See [Supervisor](#supervisor),
[CircuitBreaker / BreakerState / CircuitBreakerState](#circuitbreaker--breakerstate--circuitbreakerstate),
spec §5.5, §10.2, and
[docs/subsystems/supervisor.md](subsystems/supervisor.md).

## CommsAdapterMCP

The MCP-shaped `Protocol` for comms adapters, defined in
`src/alfred/comms/mcp_protocol.py` (shipped PR-S3-6). Distinct from the
in-process [`CommsAdapter Protocol`](#commsadapter-protocol) (which
remains for `DiscordAdapter` / `TuiAdapter` through Slice 3). The
Slice-3 stub validates transport and handshake only — four wire
methods: `lifecycle.start`, `lifecycle.stop`, `inbound.message`,
`adapter.health`. The full message-contract definition is co-defined
in [ADR-0016](adr/0016-slice4-discord-tui-comms-mcp-rewrite.md) when
Slice 4 implements the Discord rewrite. Two Protocols coexisting is a
deliberate Slice-3 bounded deviation — the in-process Protocol owns
runtime behaviour, the MCP Protocol owns the future wire contract so
implementer subagents have a stable surface to target.

See [CommsAdapter Protocol](#commsadapter-protocol),
[ADR-0009](adr/0009-comms-adapter-protocol-slice2-only.md),
[ADR-0016](adr/0016-slice4-discord-tui-comms-mcp-rewrite.md), and
[docs/subsystems/comms.md](subsystems/comms.md).

## quarantined_to_structured

The single legitimate crossing point where T3-derived data enters
orchestrator-readable form (`src/alfred/security/quarantine.py`,
shipped PR-S3-4). Any other path that claims to convert T3 content is
a security violation detectable by grepping for callers outside
[`QuarantinedExtractor`](#quarantinedextractor). The caller must hold
`check_content_clearance(hookpoint="quarantine.dereference",
content_tier="T3")` on the capability gate — distinct from the
`tag.T3` clearance, which is plugin-host-internal. Raw provider
response bytes never cross back to the orchestrator process untyped;
the return type is [`ExtractionResult`](#extractionresult) only. The
function emits the `quarantine.extract` audit row before returning, so
the audit trail captures the dereference even if a downstream caller
swallows the result (CLAUDE.md hard rule #7).

See [QuarantinedExtractor](#quarantinedextractor),
[ExtractionResult](#extractionresult),
[T3DerivedData](#t3deriveddata), spec §3.4, and
[docs/subsystems/security.md](subsystems/security.md).

## Provenance

The lineage metadata that survives [`quarantined_to_structured`](#quarantined_to_structured)
and identifies the content-trust origin of a value. In Slice 3,
provenance is expressed as the [`T3DerivedData`](#t3deriveddata)
`NewType`: a value carrying `T3DerivedData` originated from T3
(external, untrusted) content and must pass through
`downgrade_to_orchestrator()` before reaching privileged prompts.
Slice 4 promotes provenance to a full type-parameter axis on
`TaggedContent[T, Provenance]`. Distinct from [trust tier](#trust-tier)
— trust tier describes the *source* of data at ingestion time;
provenance follows the data through transformation steps and survives
the dual-LLM split.

See [T3DerivedData](#t3deriveddata),
[quarantined_to_structured](#quarantined_to_structured),
[trust tier](#trust-tier),
[dual-LLM split](#dual-llm-split), spec §3.7, and
[docs/subsystems/security.md](subsystems/security.md).
