# Quarantine subsystem — dual-LLM split and T3 structured extraction

**Status:** shipped in Slice 3
**Owner:** `alfred-security-engineer`
**Code:** `src/alfred/security/quarantine.py` · `src/alfred/security/quarantine_child/`
**PRD:** [§7.1 Security & Prompt-Injection Defense](../../PRD.md#71-security--prompt-injection-defense)
**ADRs:** [ADR-0017](../adr/0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md) (supersedes [ADR-0013](../adr/0013-defer-t1-t3-and-dual-llm.md)), [ADR-0015](../adr/0015-slice4-containerised-quarantined-llm.md) (Slice-4 containerisation commitment)
**Spec:** §3.4 (boundary), §3.7 (provenance), §6.2 (extraction modes), §6.4 (extractor), §6.7 (result union), §7.1 (canary), §7.3 (handle store)

## Purpose

The quarantine subsystem enforces the dual-LLM split: the privileged
orchestrator never processes raw T3 content, and the quarantined LLM
never emits free-form text the orchestrator interprets as instructions.
These two invariants together close the prompt-injection attack surface
that motivates the entire trust-tier system. An adversary who plants
instructions in a web page the system fetches reaches only the
quarantined LLM, which can only emit a validated Pydantic model drawn
from a schema the orchestrator chose in advance.

The subsystem is the concrete realisation of
[ADR-0013](../adr/0013-defer-t1-t3-and-dual-llm.md)'s deferred
commitment — Slice 2 tracked the gap; Slice 3 closes it via
[ADR-0017](../adr/0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md).
The architectural shape — a separate process under a dedicated UID
with env-scrubbing, a content-store boundary, and a single grep anchor
for every T3-to-orchestrator handoff — makes the isolation enforcement
structural rather than policy-only.

`src/alfred/security/quarantine.py` is the single grep anchor for all
T3-to-orchestrator handoffs. Placing the boundary here (not in
`providers/`) keeps it inside the security review surface; the
adversarial corpus (`tests/adversarial/tier_laundering/`) treats this
file as a policy invariant per CLAUDE.md §Security rules — any code
outside this module that claims to convert T3 content to
orchestrator-readable form is a security violation.

## Public surface

### `quarantined_to_structured` (`src/alfred/security/quarantine.py`)

The single legitimate crossing point from `ContentHandle` (opaque T3
reference) to `ExtractionResult` (orchestrator-readable typed value).

```python
async def quarantined_to_structured(
    handle: ContentHandle,
    schema: type[ExtractionSchema],
    *,
    extractor: QuarantinedExtractor,
    gate: CapabilityGate,
) -> ExtractionResult: ...
```

Gate-first ordering:
`gate.check_content_clearance(plugin_id="alfred.quarantined-llm", hookpoint="quarantine.dereference", content_tier="T3")`
is consulted BEFORE the extractor runs. A denial raises `AlfredError`
without invoking the extractor — the gate's refusal accounting handles
denied calls; this function's audit emission (via the extractor) is
reserved for granted calls. `plugin_id` is REQUIRED on every
`check_content_clearance` call (the parameter is keyword-only on the
Protocol — see [Capability gate](../glossary.md#capability-gate)); the
quarantined-LLM plugin id is pinned as `ClassVar` on
[`QuarantinedExtractor`](#quarantinedextractor-srcalfredsecurityquarantinepy)
so the join key never drifts across audit rows.

`gate` is REQUIRED — no default, no `| None` (CR-138 R3): a
trust-boundary function whose gate can be elided through a default arg
is a function with a bypass path codified in its signature.

A `TypedRefusal` is NOT translated to an exception — refusal is a
legitimate orchestrator outcome the caller branches on. The orchestrator
must `isinstance(result, Extracted)` to switch behaviour.

### `ContentHandle` (`src/alfred/security/quarantine.py`)

Opaque reference to T3 content held in the plugin host's content store.

```python
@dataclass(frozen=True, slots=True)
class ContentHandle:
    id: str
    source_url: str
    fetch_timestamp: datetime
```

The orchestrator holds this; the quarantined-LLM plugin dereferences
it. The orchestrator NEVER calls `.content` — that field does not
exist by design. `source_url` is for audit attribution only; the
orchestrator cannot act on it as a content source. `fetch_timestamp`
MUST be timezone-aware (CR-138 #4): a naive datetime silently encodes
the producer's local clock and breaks forensic ordering when audit rows
from different hosts are correlated. `__post_init__` enforces this at
construction.

Single-use invariant: each `id` UUID is used for exactly one
`quarantine.extract` call. The Redis content store (shipped PR-S3-5)
enforces this via atomic `DEL` on first successful extract. A second
extract against the same id receives `TypedRefusal(reason="cannot_extract")`
with `result="content_expired"` in the audit row.

### `ExtractionSchema` (`src/alfred/security/quarantine.py`)

Abstract base class every quarantined-extraction schema MUST subclass.

```python
class ExtractionSchema(BaseModel):
    schema_version: ClassVar[Literal[1]] = 1
```

`__init_subclass__` enforces the invariant at class-construction time,
not at extraction-call time: a typo'd `schema_version = 2` fails at
import, not at runtime. Both the `Literal[1]` (type-level) and the
runtime equality check are mandatory — defence-in-depth that survives
`# type: ignore` and `python -O` (which strips asserts but not class
bodies). `QuarantinedExtractor._validate_schema_class` is the runtime
backstop for callers that bypass the type system.

### `ExtractionResult` discriminated union

```python
ExtractionResult = Extracted | TypedRefusal
```

Both branches are frozen Pydantic models with `extra="forbid"`. The
discriminator is the `kind` Literal field — `Pydantic.TypeAdapter`
callers wrap the alias with `Annotated[..., Field(discriminator="kind")]`
at parse time; `isinstance` is the runtime branch.

`Extracted.data` is annotated `T3DerivedData`. `TypedRefusal.reason`
is drawn from the closed `TypedRefusalReason` Literal:

```python
TypedRefusalReason = Literal[
    "cannot_extract",
    "refused_by_safety",
    "ambiguous_input",
    "provider_refused",
    "provider_unavailable",
    "dlp_outbound_refused",  # tombstone — see below
    "post_stage_refused",
    "nonce_check_failed",
]
```

A new refusal cause requires a deliberate addition to the Literal and a
matching reviewer-gated audit-schema migration. Free-form reasons would
leak provider-supplied (potentially T3-derived) text into
orchestrator-readable fields.

`dlp_outbound_refused` is retained as a tombstone for forensic-history
continuity; no live emit site uses it. Post-stage refusals (including the
DLP subscriber's canary trip) now record `post_stage_refused` and carry
the refusing subscriber's identity on `QUARANTINE_EXTRACT_FIELDS.refusing_hook_id`.
That row is the only forensic surface for the attribution because
`alfred.hooks.invoke._run_post` does NOT emit `HOOKS_REFUSAL` for
post-stage refusals — §6.5's refusal-authorisation contract is
pre-stage-only by design.

### `T3DerivedData` (`src/alfred/security/quarantine.py`)

```python
T3DerivedData = NewType("T3DerivedData", dict[str, object])
```

Type-level provenance marker on `Extracted.data`. At runtime a plain
dict; at type-check time mypy treats it as distinct so callers that
attempt `cast(dict, t3_data)` trigger the CI ruff/grep rule in
`scripts/check_tag_t3.py`. Callers MUST call `downgrade_to_orchestrator`
before injecting `T3DerivedData` values into privileged prompts — that
function holds the capability-gate check and writes the
`quarantine.t3_derived_downgrade` audit row.

Slice 4 promotes this to a full type parameter on `TaggedContent` (a
provenance axis alongside the tier axis). See spec §3.7.

### `QuarantinedExtractor` (`src/alfred/security/quarantine.py`)

Orchestrator-side MCP client of the quarantined-LLM plugin. Single
public surface:

```python
async def extract(
    self,
    handle: ContentHandle,
    schema: type[ExtractionSchema],
) -> ExtractionResult: ...
```

Raw provider response bytes never cross back to the orchestrator
process — only `ExtractionResult`. The dispatch carries only the opaque
`handle.id`, the schema JSON, and `schema_version`; `source_url` never
crosses the wire (forensic-attribution data held orchestrator-side).

The plugin id `alfred.quarantined-llm` is pinned as a `ClassVar` so
the audit-graph join keys never drift. Construction takes a
`PluginTransport` (the structural Protocol — see
[plugins.md](plugins.md#stdiotransport-srcalfredpluginsstdio_transportpy))
and an `AuditWriter`.

### `downgrade_to_orchestrator` (`src/alfred/security/quarantine.py`)

```python
async def downgrade_to_orchestrator(
    data: T3DerivedData,
    *,
    gate: CapabilityGate,
    audit_writer: AuditWriter,
) -> dict[str, object]: ...
```

The only legitimate path from `T3DerivedData` to a plain dict. Gate
hookpoint is `t3.downgrade_to_orchestrator`; the gate is consulted with
`content_tier="T3"` (the PRD §7.1 closed tier vocabulary). The audit
row emits `quarantine.t3_derived_downgrade` against
`T3_DERIVED_DOWNGRADE_FIELDS` — distinct from `identity.t1_downgrade`
(rvw-003): T1→T2 and T3-derived→T2 are separate trust transitions with
separate forensic attribution.

The audit row carries provenance attribution only (`source_tier`,
`target_tier`, closed-vocabulary `downgrade_reason`). The payload
values themselves are NEVER serialised into the audit row — that would
bypass DLP and let downstream log consumers observe raw T3-derived
content outside the privileged-orchestrator path.

## Internal model

### Quarantined-LLM plugin shape

The quarantined LLM runs as `src/alfred/security/quarantine_child/` under
the `alfred-quarantine` OS user — a dedicated system UID distinct from
the `alfred` orchestrator UID. The OS-level UID separation means the
subprocess literally cannot read the orchestrator's secrets file
(CLAUDE.md hard rule #6; `src/alfred/security/secrets.py` validates
ownership against `os.getuid()`).

The manifest carries the deliberate two-axis declaration (spec §4.3):

```toml
[alfred]
manifest_version = 1

[plugin]
id = "alfred.quarantined-llm"
subscriber_tier = "system"
sandbox_profile = "user-plugin"
```

`subscriber_tier = "system"` because the quarantined LLM is a
privileged-host subprocess that subscribes to orchestrator-internal
hookpoints (`security.quarantined.extract`) the user-plugin tier never
sees. `sandbox_profile = "user-plugin"` because even with the system
hook tier, the subprocess runs under the user-plugin OS sandbox so a
compromise in the LLM provider's response-parsing path cannot
escalate beyond the supervisor's own privileges. The two axes are
deliberately independent — conflating `subscriber_tier` with the
content trust tier (T0–T3) is the classic shape of a tier-laundering
bug, and `parse_manifest` refuses any T0–T3 string in
`subscriber_tier` with `ManifestTierError`.

The plugin exposes exactly two JSON-RPC methods:

- `quarantine.ingest(handle: str, context: str)` — fetches T3 content
  from the content store by handle id.
- `quarantine.extract(handle_id: str, schema_json: str, schema_version: int)`
  — structured extraction against that specific handle. Per-call handle
  lookup prevents the TOCTOU race where concurrent extraction in
  conversation B operates against conversation A's content.

The quarantined LLM has no `tool_calls` capability and emits no
free-form text the orchestrator consumes as instructions.

### Production sandbox boundary (AppArmor + seccomp + bound interpreter)

The `bwrap` `kind=full` quarantine child builds an **unprivileged user
namespace**. In the production `alfred-core` posture (non-root `alfred` +
`cap_add: [SETUID]`, no `--privileged`) two container-level confinement layers
otherwise block that, and the fix (#290, [ADR-0037](../adr/0037-production-quarantine-sandbox-boundary.md))
applies two custom least-privilege profiles. They are carried by exactly the
`bwrap`-spawning services: `alfred-core` (the quarantine child), and — since
Spec B G6-1 ([ADR-0036](../adr/0036-gateway-adapter-hosting-inversion.md)) —
`alfred-gateway` (which spawns the sandboxed comms-adapter children; the
capability is granted there but dormant until the G6-2 supervisor uses it). The
two profiles:

- **`docker/apparmor/alfred-bwrap`** (`security_opt: apparmor=alfred-bwrap`) —
  `flags=(unconfined) { userns, }`, replacing `docker-default` to grant the
  `userns,` permission Ubuntu 23.10+ kernels require for unprivileged
  `unshare(CLONE_NEWUSER)`. AppArmor is deliberately NOT the load-bearing
  containment here — the kernel-enforced **bwrap policy**
  (`config/sandbox/quarantined-llm.linux.bwrap.policy`) is.
- **`docker/seccomp/alfred-bwrap.json`** (`security_opt:
  seccomp=docker/seccomp/alfred-bwrap.json`) — Docker's default profile plus an
  unconditional ALLOW for exactly the eight namespace syscalls bwrap needs
  (`clone`/`clone3`/`unshare`/`setns`/`mount`/`umount2`/`pivot_root`/`keyctl`).
  Every other default deny is preserved — NOT `seccomp=unconfined`. It is a
  generated artifact (`scripts/gen_alfred_seccomp.py`, drift-guarded by
  `scripts/gen_alfred_seccomp.py --check` + `tests/unit/test_seccomp_profile_drift.py`).

The child execs the image's bound python-build-standalone interpreter under
`/opt/alfred-python` with `alfred` installed non-editable into it
([ADR-0030](../adr/0030-first-party-kind-full-plugin-ships-in-wheel-under-bound-prefix.md)),
so both the interpreter and `alfred.security.quarantine_child` resolve from one
bound, cache-independent prefix inside the sandbox.

**Host-load requirement.** The named AppArmor profile must be loaded into the
host kernel before the container starts (`bin/alfred-setup.sh` does it; running
compose directly needs `sudo apparmor_parser -r docker/apparmor/alfred-bwrap`
first), and `docker compose` must run from the repository root (the seccomp
`security_opt` path is CWD-relative). macOS and non-AppArmor Linux hosts need
neither (the `security_opt` lines are runtime no-ops there). The end-to-end proof
is `.github/workflows/bwrap-userns-validation.yml` (restrictive host, non-root,
with a non-vacuous control arm).

### Provider routing and `ProviderCapability`

`Provider.capabilities() -> frozenset[ProviderCapability]` governs
which extraction path `QuarantinedExtractor` dispatches:

| Provider | Mechanism | Capability |
| --- | --- | --- |
| Anthropic | Tool-use shape | `NATIVE_CONSTRAINED_GENERATION` |
| OpenAI | Strict structured-outputs (`strict: true` mandatory) | `NATIVE_CONSTRAINED_GENERATION` |
| DeepSeek-chat | JSON mode (declared, not dispatch-selected) | `JSON_OBJECT_MODE` |

Dispatch is two-way, closed on `NATIVE_CONSTRAINED_GENERATION` alone
(#340 fork b): a provider declaring it uses the `native_constrained`
tool-use path; every other provider — including DeepSeek-chat, which
declares `JSON_OBJECT_MODE` but not `NATIVE_CONSTRAINED_GENERATION` —
uses `prompt_embedded_fallback`. The DeepSeek-style JSON-object-mode
runtime branch is REMOVED: no shipped provider is JSON-object-only, and
every constrained-capable provider declares a native tool-use path. The
closed `ExtractionMode` Literal:

```python
ExtractionMode = Literal[
    "native_constrained",
    # RESERVED (not selected at runtime since #340 fork b): retained for
    # audit-row continuity + a future response_format seam extension.
    "json_object_unconstrained",
    "prompt_embedded_fallback",
]
```

`json_object_unconstrained` is RESERVED, not selected at runtime —
deepseek-chat audit rows record
`extraction_mode="prompt_embedded_fallback"`. Drift on this Literal
breaks audit-row continuity, so the closed set is enforced at the type
level.

### Retry-guidance hygiene

When the quarantined provider produces invalid output against a schema,
the retry turn contains ONLY the validator error category (a label
drawn from a closed `ValidatorErrorCategory` set) + the schema JSON —
NEVER the LLM's prior malformed JSON body verbatim.

```python
ValidatorErrorCategory = Literal[
    "schema_mismatch",
    "json_parse_error",
    "missing_required_field",
    "unknown",
]
```

This is a hard invariant: a malformed output could contain injected
instructions; echoing it into the retry prompt would close the
laundering loop. The structural defence is the absence of any
`prior_response`-shaped parameter from `_build_retry_prompt`'s
signature — pinned by `inspect.signature`-based tests (prov-002 /
err-009). The module-level `_build_retry_prompt` is shared with the
plugin-side dispatcher so both sides of the boundary observe identical
retry text; drift between them would let a misbehaving plugin observe
different prompts than the orchestrator's tests pin.

A `TypedRefusal` with `reason="ambiguous_input"` is the correct
response to ambiguous input, NOT a prompt that includes the adversary's
text. Max retries: 2 (configurable in `config/policies.yaml` as
`quarantine.extraction_max_retries`). After 2 failures:
`TypedRefusal(reason="cannot_extract")`.

The adversarial corpus (`tests/adversarial/tier_laundering/`) includes
a retry-guidance hygiene payload that replays a malformed-output corpus
through the fallback path and asserts the second-turn prompt token set
is a subset of `{validator-error tokens} ∪ {schema-JSON tokens} ∪
{fixed-instruction-template tokens}` (spec §12.3).

### Protocol-violation handling

`QuarantinedExtractor.extract` distinguishes three response paths:

1. **Granted typed result** — `ControlResult` with `payload.kind in
   ("extracted", "typed_refusal")`, schema-validated, lifted into the
   typed shape. Audit: `quarantine.extract` with `result="extracted"`
   or `result="refused"`.
2. **Transport-layer crash** — `dispatch` raises (broken pipe, framing
   error, premature subprocess death). Audit:
   `quarantine.transport_failed` with `result="transport_failed"`,
   emitted BEFORE the exception re-raises so the operator log carries
   the failure even if the caller swallows it.
3. **Protocol violation** — non-`ControlResult` response, missing/wrong
   `kind`, missing `data` dict, `extraction_mode` outside the closed
   Literal, `reason` outside `TypedRefusalReason`, or Pydantic
   `model_validate` rejection of `data` against the caller's schema.
   Audit: `quarantine.protocol_violation` with
   `result="protocol_violation"`, then `PluginProtocolViolation` raised.

Collapsing transport failures or protocol violations into
`TypedRefusal` outcomes would let a misbehaving plugin silently disguise
wire-format failures as orchestrator outcomes, breaking the dual-LLM
split's structural guarantee that `Extracted` means "the schema you
asked for was satisfied by the quarantined LLM".

### `schema_version: Literal[1]` mandatory

Every Pydantic model passed to `QuarantinedExtractor.extract` must
subclass `ExtractionSchema`, which pins `schema_version: ClassVar[Literal[1]]
= 1`. The runtime `_validate_schema_class` check raises `TypeError` if
the schema is not a subclass. A subclass that rebinds the value to
anything but 1 fails at `__init_subclass__` time. The audit row's
`schema_version` field is populated from this pinned value — a Slice-4
author who attempts to ship a schema with no version or with version 2
is refused at import, not at run-time.

Slice 4+: when the schema vocabulary evolves beyond v1, lift the
`Literal[1]` to `Literal[1, 2]` and migrate the
`audit_row_schemas.QUARANTINE_EXTRACT_FIELDS` field to a discriminated
union per version. Until then, the closed set keeps the audit-side
consumer's deserialisation single-branched.

### T3 provenance survival

The `T3DerivedData` `NewType` is a Slice-3 lightweight discriminant —
a **static-typing construct** whose guarantees are enforced at call
sites (mypy / pyright surfaces a tag-confusion bug at type-check time)
rather than as a runtime type. `NewType` is a no-op at runtime: the
underlying object remains a plain `dict`, so `type(result.data) is
T3DerivedData` is **false** at runtime — there is no separate class to
compare against.

The adversarial corpus's `tier_laundering` payload therefore pins
provenance two ways, both at call-site boundaries rather than via
`type()`:

1. **Static typing** — `quarantined_to_structured`'s return signature
   binds `result.data: T3DerivedData`. A call site that passes the
   value to a function expecting plain `dict[str, object]` without
   going through `downgrade_to_orchestrator` (the only sanctioned
   `T3DerivedData → dict` boundary) fails type-check.
2. **DB write/read round-trip** — the audit-row + episodic-write paths
   preserve the underlying dict-shape across serialisation, and the
   read-side `isinstance(value, dict)` + `provenance == "T3_derived"`
   audit attribution survive. The round-trip fixture confirms the
   provenance tag is pinned through the storage boundary even though
   `NewType` itself doesn't add a runtime class marker.

Slice 4 promotes this to a full type parameter on `TaggedContent` and
the survival check graduates to a structural runtime type assertion
(`isinstance(..., TaggedContent)` against a concrete generic carrier).

### `quarantined_to_structured` correlation

`QuarantinedExtractor.extract` mints TWO correlation ids per call:

1. **`chain_correlation_id`** (a UUID minted at chain entry, before
   the pre-stage dispatch). This is the **shared trace key** for the
   call. Every `quarantine.*` audit row this extractor emits — both
   the deferred `quarantine.extract` row at the post-stage boundary
   AND the inline `quarantine.transport_failed` /
   `quarantine.protocol_violation` rows the body emits before raising
   — carries this value as its top-level `trace_id`. The pre/post/error
   hook-chain dispatch rows that `alfred.hooks.invoke.invoke` writes
   for `security.quarantined.extract` carry the same value as their
   correlation id. Forensic queries joining on `trace_id` see a single
   coherent trace covering every dispatch and audit emission for one
   extraction call (CR-158 round 4).
2. **`correlation_id`** (a per-invocation UUID minted inside
   `_extract_body`). Finer-grained than `chain_correlation_id` —
   lives as a field inside the row's `subject` payload, not as the
   top-level `trace_id`. Filtering on `subject.correlation_id` narrows
   a trace bucket to a specific body invocation. Never shared across
   calls (prov-012); cross-process audit consumers that have not
   adopted the `trace_id` join key can still group on this field
   within a single forensic export window.

## Audit row families

All audit rows below carry `trust_tier_of_trigger="T3"` because the
trigger is T3-derived content reaching a structured-extraction
boundary. Schema constants live in
`src/alfred/audit/audit_row_schemas.py`.

### Extraction-path rows (`QUARANTINE_EXTRACT_FIELDS`)

| Event | `result` | Emitted when |
| --- | --- | --- |
| `quarantine.extract` | `extracted` | Granted: payload validated, lifted to `Extracted` |
| `quarantine.extract` | `refused` | Granted: payload lifted to `TypedRefusal` |
| `quarantine.transport_failed` | `transport_failed` | Transport `dispatch()` raised (broken pipe, framing error, subprocess death) — emitted BEFORE re-raise |
| `quarantine.protocol_violation` | `protocol_violation` | Wire-format mismatch (non-`ControlResult`, wrong `kind`, schema-invalid `data`, out-of-vocab `reason`/`extraction_mode`) — emitted BEFORE `PluginProtocolViolation` raise |

Subject fields: `extraction_mode`, `provider="quarantined-llm"`,
`schema_name`, `schema_version`, `retry_count`,
`trust_tier_of_trigger="T3"`, `result`, `correlation_id`.

### Downgrade row (`T3_DERIVED_DOWNGRADE_FIELDS`)

| Event | `result` | Emitted when |
| --- | --- | --- |
| `quarantine.t3_derived_downgrade` | `allowed` | Gate granted T3-derived→T2 downgrade via `downgrade_to_orchestrator` |

Subject fields: `extraction_id`, `quarantined_llm_invocation_id`,
`source_tier="T3_derived"`, `target_tier="T2"`,
`downgrade_reason` (closed Literal `structured_extraction_consumed`),
`trust_tier_of_trigger="T3"`, `trust_tier_of_response="T2"`,
`downgrade_explicit=True`, `correlation_id`. The closed downgrade
reason is the audit-graph boundary that ties the downgrade row back to
the extraction that produced it; the payload values are NEVER
serialised here.

## Failure modes

| Trigger | Behaviour | Observable signal |
| --- | --- | --- |
| Schema not an `ExtractionSchema` subclass | `TypeError` at `_validate_schema_class` before any MCP call | exception propagates; no audit row |
| Schema subclass with `schema_version != 1` | `TypeError` at `__init_subclass__` (import-time) | exception at module import; no audit row |
| Gate denies `quarantine.dereference` | `AlfredError(t("security.quarantine.dereference_denied"))` | gate-side `security.capability_gate.*` audit row |
| Gate denies `t3.downgrade_to_orchestrator` | `AlfredError(t("security.quarantine.downgrade_denied"))` | gate-side `security.capability_gate.*` audit row |
| Transport `dispatch()` crashes | `quarantine.transport_failed` audit row, then re-raise | audit log + propagated exception |
| Non-`ControlResult` response | `quarantine.protocol_violation` audit + `PluginProtocolViolation` | audit log + exception |
| Payload `kind` outside `{extracted, typed_refusal}` | `quarantine.protocol_violation` audit + `PluginProtocolViolation` | audit log + exception |
| Payload `data` missing or non-dict | `quarantine.protocol_violation` audit + `PluginProtocolViolation` | audit log + exception |
| Payload `data` fails `schema.model_validate` | `quarantine.protocol_violation` audit + `PluginProtocolViolation` (raised `from None` to drop the `ValidationError` chain) | audit log + exception |
| Payload `extraction_mode` outside `ExtractionMode` Literal | `quarantine.protocol_violation` audit + `PluginProtocolViolation` | audit log + exception |
| Payload `reason` outside `TypedRefusalReason` Literal | `quarantine.protocol_violation` audit + `PluginProtocolViolation` | audit log + exception |
| Content handle TTL expired mid-extraction | `TypedRefusal(reason="cannot_extract")` | `quarantine.extract` audit row with `result="refused"` |
| Second `quarantine.extract` on same handle id | `TypedRefusal(reason="cannot_extract")` (single-use UUID enforced by Redis `DEL`) | `quarantine.extract` audit row with `result="refused"` |
| `tag(T3, ...)` called from unauthorised caller | `ValueError` + security event in [security.md](security.md) — out of this subsystem | gate-side `security.tag_t3_unauthorized` event |
| Quarantined provider refused content on safety grounds | `TypedRefusal(reason="refused_by_safety")` | `quarantine.extract` audit row with `result="refused"` |
| Post-DLP scan of `model_dump_result` detects canary | `security.canary_tripped` raised by transport | `security.canary_tripped` audit row in [plugins.md](plugins.md#failure-modes) |
| Naive `fetch_timestamp` passed to `ContentHandle` | `ValueError` at `__post_init__` | exception; handle never constructed |

## Trust-boundary contract

The quarantine subsystem owns the crossing point between T3 (untrusted
external content) and T2 (authenticated-user-trusted structured data).
The crossing is `quarantined_to_structured` — one function, one file,
one grep anchor. The [capability gate](../glossary.md#capability-gate)
enforces two orthogonal clearances:

- **`tag(T3, ...)` clearance** — held by `StdioTransport` and the
  quarantined-LLM host site only (the call sites that can produce
  `TaggedContent[T3]`; see
  [plugins.md](plugins.md#t3-byte-isolation-across-the-transport-boundary)).
- **`quarantine.dereference` clearance** — held by call sites of
  `quarantined_to_structured` only. The gate consults this clearance
  before the extractor runs.

`downgrade_to_orchestrator` adds a third clearance —
`t3.downgrade_to_orchestrator` — that the orchestrator must hold
before injecting `T3DerivedData` into a privileged prompt. The audit
row's `downgrade_explicit=True` flag is the receipt that the gate
consented to the crossing.

See [docs/subsystems/plugins.md](plugins.md) for the T3 tagging
boundary at the transport, [docs/subsystems/security.md](security.md)
for the capability gate implementation, and
[docs/glossary.md#trust-tier](../glossary.md#trust-tier) for the tier
definitions.

## Performance characteristics

| Path | Budget |
| --- | --- |
| `security.quarantined.extract` 5-subscriber hook chain | ≤ 100 µs + provider RTT |
| End-to-end quarantined extraction chain | ≤ 5 s (generous for subprocess hop; spec §12.4) |
| `quarantined_to_structured` gate check | < 5 ms (Postgres clearance lookup) |
| `downgrade_to_orchestrator` gate + audit write | < 10 ms |

Provider RTT is provider-owned; the 5 ms `StdioTransport.dispatch()`
budget is the local transport overhead (spec §7a.1). The advisory
latency test at `tests/integration/test_quarantined_chain_latency.py`
validates the 5 s ceiling per recorded provider fixtures.

## Slice graduation map

| Subsystem | Slice 3 (shipped) | Deferred to | Anchor |
| --- | --- | --- | --- |
| Quarantine | `quarantined_to_structured`; `QuarantinedExtractor`; `T3DerivedData` `NewType`; `ContentHandle` (frozen, slotted, timezone-aware); `ExtractionResult = Extracted / TypedRefusal` with `extra="forbid"`; `ExtractionSchema` ABC with `schema_version: ClassVar[Literal[1]]`; `_build_retry_prompt` closed-vocabulary builder; `quarantine.extract` / `quarantine.transport_failed` / `quarantine.protocol_violation` audit rows; `downgrade_to_orchestrator` with `T3_DERIVED_DOWNGRADE_FIELDS`; dual-LLM split under `alfred-quarantine` UID | Slice 4+: full containerisation ([ADR-0015](../adr/0015-slice4-containerised-quarantined-llm.md)); `TaggedContent` provenance axis (Slice-4 design); T3 promotion for Discord embeds/attachments; `schema_version` Literal widening + audit-row discriminated union | [ADR-0017](../adr/0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md), [ADR-0015](../adr/0015-slice4-containerised-quarantined-llm.md) |

## Cross-references

- PRD [§7.1](../../PRD.md#71-security--prompt-injection-defense) —
  dual-LLM split invariant; the privileged orchestrator never processes
  raw T3 content.
- [ADR-0017](../adr/0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md)
  — Slice-3 realisation; Decision 7 pins `schema_version: Literal[1]`.
- [ADR-0013](../adr/0013-defer-t1-t3-and-dual-llm.md) — the deferred
  commitment this slice closes.
- [ADR-0015](../adr/0015-slice4-containerised-quarantined-llm.md) —
  Slice-4 containerisation commitment for the quarantined-LLM
  subprocess.
- Sibling subsystems: [plugins.md](plugins.md) (the transport that
  delivers `ContentHandle` into the orchestrator),
  [supervisor.md](supervisor.md) (the `QuarantinedUnavailable` /
  circuit-breaker boundary that protects the quarantined-LLM dispatch),
  [security.md](security.md) (the `tag(T3, ...)` nonce gate and
  `CapabilityGate` implementation), [hooks.md](hooks.md) (the
  `security.quarantined.extract` hookpoint).
- Glossary:
  [T3DerivedData](../glossary.md#t3deriveddata),
  [ContentHandle](../glossary.md#contenthandle),
  [QuarantinedExtractor](../glossary.md#quarantinedextractor),
  [ExtractionResult](../glossary.md#extractionresult),
  [TypedRefusal](../glossary.md#typedrefusal),
  [TypedRefusalReason](../glossary.md#typedrefusalreason),
  [quarantined_to_structured](../glossary.md#quarantined_to_structured),
  [JSON_OBJECT_MODE](../glossary.md#json_object_mode),
  [QuarantinedUnavailable](../glossary.md#quarantinedunavailable),
  [Trust tier](../glossary.md#trust-tier),
  [AnyTaggedContent](../glossary.md#anytaggedcontent),
  [Sandbox profile](../glossary.md#sandbox-profile),
  [Hook tier](../glossary.md#hook-tier),
  [Capability gate](../glossary.md#capability-gate),
  [Provenance](../glossary.md#provenance).
