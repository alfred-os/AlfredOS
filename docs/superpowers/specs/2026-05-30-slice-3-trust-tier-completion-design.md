# AlfredOS Slice 3 — Trust-Tier Completion + MCP Plugin Transport + Dual-LLM Split

> **Date:** 2026-05-30
> **Slice:** 3 (closes the trust-tier story ADR-0013 committed to during Slice 2)
> **Implements:** [ADR-0013](../../adr/0013-defer-t1-t3-and-dual-llm.md), completes [ADR-0008](../../adr/0008-llm-output-trust-tier.md), supersedes [ADR-0009](../../adr/0009-comms-adapter-protocol-slice2-only.md) (in part)
> **Supersedes ADR-0008 and ADR-0013:** via **ADR-0017** — Slice 3 trust-tier completion + MCP plugin transport + dual-LLM split (co-merged with PR-S3-0a; ADR-0008 and ADR-0013 status fields flip to "Superseded by ADR-0017" in that same PR)
> **Forward-references:** ADR-0015 co-merged committing containerised quarantined LLM (Slice 4); ADR-0016 committing Discord/TUI comms-MCP migration (Slice 4)
> **Anchors:** [PRD §5](../../../PRD.md#5-architecture-overview) · [PRD §5.1](../../../PRD.md#51-hookable-actions) · [PRD §6.3](../../../PRD.md#63-agentic-skills--mcp-integration) · [PRD §6.4](../../../PRD.md#64-self-improvement-with-reviewer-gate) · [PRD §7.1](../../../PRD.md#71-security--prompt-injection-defense) · [PRD §7.2](../../../PRD.md#72-multi-user-identity--authorization) · [PRD §7.3](../../../PRD.md#73-self-healing--auto-recovery) · [PRD §7.4](../../../PRD.md#74-audit-trail--rollback)

---

## 0. Summary

[ADR-0013](../../adr/0013-defer-t1-t3-and-dual-llm.md) committed Slice 3 to delivering the full trust-tier stack — T1, T3, and the privileged/quarantined dual-LLM split — deferred from Slice 2 when multi-user identity and the Discord adapter consumed the available review bandwidth. This spec resolves all 11 design forks (5 original + 6 surfaced by the completeness critic): T1+T3 type-system extension, MCP stdio plugin transport, dual-LLM boundary, quarantined structured output, `web.fetch` as the first T3 tool, real `CapabilityGate`, ADR-0009 comms-MCP contract, adversarial corpus, supervisor, and operator configuration surface. The strongest design choice in the slice: the dual-LLM split lands as an MCP stdio subprocess — process-level + type-level isolation — with type-level T3 sealing via the existing phantom-type generic, a capability-gated `tag(T3, ...)` factory (nonce-token identity check, not value comparison), and a `ContentHandle` (opaque id) as the only T3 representation the privileged orchestrator ever holds.

PR-S3-0 establishes foundations: schema constants, Alembic migrations (`0007`-`0009`), i18n keys, ADR-0017, PRD §5 amendment, Docker + Redis + state.git infrastructure. PR-S3-3 is pre-committed to split into PR-S3-3a (transport) and PR-S3-3b (supervisor) per ADR-0017. The slice ships 10 PRs total (PR-S3-0a, PR-S3-0b, PR-S3-1 through PR-S3-7).

---

## 1. Scope and out-of-scope

### 1.1 In-scope (all 11 forks)

1. **Fork 3 + 6 — Trust-tier type system:** `T1` and `T3` `TrustTier` subclasses added to `_APPROVED_TIERS` (`src/alfred/security/tiers.py`); `TaggedContent[T1]` and `TaggedContent[T3]` as type-level discriminants per ADR-0013's literal spelling; `Protocol AnyTaggedContent` read-only view; capability-gated `tag(T3, ...)` overload; wire-format serializer; `quarantined_to_structured` boundary fn in `src/alfred/security/quarantine.py`; T1 ingress via `IdentityResolver` (role × adapter).
2. **Fork 2 — MCP plugin transport:** `PluginTransport` Protocol + `StdioTransport` sole implementation; plugin manifest schema; host-side secret-broker substitution; DLP-wrapped transport surface; SIGKILL on protocol violation; lifecycle audit family; `bin/alfred-plugin-launcher` stub; manifest version pin.
3. **Fork 1 — Dual-LLM split:** quarantined-LLM as MCP stdio subprocess; dedicated `alfred-quarantine` UID; env scrubbing + stdin handshake for provider key; different provider from privileged; `QuarantinedUnavailable` exception; audit-field discipline; co-merged ADR-0015 Slice-4 containerisation commitment.
4. **Fork 5 — Quarantined structured output:** `Provider.capabilities() -> frozenset[ProviderCapability]`; native constrained-generation per provider with prompt-embedded fallback; `QuarantinedExtractor` as orchestrator-side MCP client; hookpoint `security.quarantined.extract`; `schema_version: Literal[1]` mandatory; discriminated-union `ExtractionResult`; audit row fields.
5. **Fork 4 — `web.fetch`:** in-tree MCP plugin; `ContentHandle` return to orchestrator; three-way allowlist intersection; `tool.web.fetch` hookpoint (all four kinds) restricted to system-only; `InboundCanaryScanner` as system-tier hook subscriber; Redis rate-limits; cookie policy; per-conversation depth=1; `WebFetchError` hierarchy; audit row.
6. **Fork 7 — Real `CapabilityGate`:** hybrid storage (state.git source of truth + Postgres runtime cache); Protocol surface extension; reviewer-gated proposal flow for high-blast grants; `DevGate`/`RealGate` co-existence + flag-day.
7. **Fork 8 — ADR-0009 comms-MCP rewrite:** MCP `CommsAdapter` Protocol stub + reference test plugin; existing Discord+TUI adapters keep working in-process; ADR-0009 status flip.
8. **Fork 9 — Adversarial corpus:** three attack-family categories (`prompt_injection`, `tier_laundering`, `dlp_egress`); `payload_schema.py` closed-set edit as first PR; per-provider recorded fixtures; cross-fork integration test gates slice merge.
9. **Fork 10 — Supervisor:** `src/alfred/supervisor/` module; quarantined-LLM circuit breaker; MCP plugin lifecycle; capability-gate backing-store fail-closed; per-orchestrator-action 30s deadline; breaker state in Postgres; `alfred supervisor reset` command.
10. **Fork 11 — Operator configuration surface:** high-blast in state.git (reviewer-gated); low-blast in `config/policies.yaml` (hot-reload); CLI surface; per-user daily fetch budget; i18n catalog-additions PR shipped first.
11. **Cross-cutting:** single wire-format ADR section; `audit_row_schemas.py` constants module; `docs/glossary.md` additions; hookpoint surface enumeration table; `make docs-check` stays green.

### 1.2 Out-of-scope (explicitly deferred)

- **Slice 4:** containerised quarantined LLM (ADR-0015, co-merged); Discord+TUI comms-MCP rewrite (ADR-0016, co-merged); T3-promotion for Discord embeds/attachments/references/polls; persona examples Lucius/Oracle/Diana; inter-persona bus; memory layers 3-6 (summarized episodes, semantic facts, vector, graph) ([PRD §6.2](../../../PRD.md#62-multi-layered-memory)); cross-channel T1 outbound for operator Discord-DM; Discord operator-DM install-time capability-grant prompt.
- **Slice 5+:** HTTP MCP transport; provider tiered routing + 4 caching layers ([PRD §6.5](../../../PRD.md#65-token-caching--cost-control)); OpenAI provider; Telegram adapter; skill-creation loop (full [PRD §6.4](../../../PRD.md#64-self-improvement-with-reviewer-gate) flow) — [PRD §9](../../../PRD.md) post-MVP roadmap.
- **Never shipped:** in-process `MemoryTransport` for plugins (deliberately excluded; would collapse process-boundary isolation).

PRD §5 architectural invariants asserted by this slice (lines 116-121 of `PRD.md`):

- "Plugins are MCP servers" — `StdioTransport` delivers this for the quarantined LLM and `web.fetch` in Slice 3.
- "Dual-LLM split" — the privileged orchestrator never processes raw T3 content; quarantined LLM emits only structured data.
- "The LLM never holds secrets" — host-side secret-broker substitution before bytes cross the pipe.

### 1.3 Scope budget

Slice 3 ships eight coordinated PRs (PR-S3-0 through PR-S3-7), splittable to ten if review bandwidth demands it. If any one PR exceeds the Slice-2 PR-D size budget (roughly 600 lines of substantive implementation + tests), the architect re-decomposes before further work lands. PR-S3-3 bundles the MCP transport package and the supervisor module — two packages, two subsystems — and is **pre-committed to split into PR-S3-3a (transport-only) and PR-S3-3b (supervisor-only)** per ADR-0017; this removes the architect-call-at-implementation-time variable from the slice's critical path. PR-S3-6 bundles the operator CLI surface and the comms-MCP Protocol stub — also splittable. This spec defines the deliverables, not the exact PR-to-deliverable mapping for the optional splits.

**PR-S3-0 is pre-committed to split into PR-S3-0a and PR-S3-0b** per the architect's scope-budget review (round 2): the PR as scoped in §17 carries five ADRs (ADR-0017 full + ADR-0008/ADR-0013 status flips + ADR-0009 flip + ADR-0015/ADR-0016 stubs), the PRD §5 amendment, three Alembic migrations, SQLAlchemy models, i18n catalog additions, and Docker/Redis/state.git infrastructure. That exceeds the ~600-line budget on prose alone. The pre-committed split:

- **PR-S3-0a — Docs-only:** ADR-0017, ADR-0008/ADR-0013/ADR-0009 status flips, ADR-0015/ADR-0016 stubs, PRD §5 amendment, `audit_row_schemas.py` constants module, `tests/adversarial/payload_schema.py` Literal additions.
- **PR-S3-0b — Schema/infra:** Alembic migrations `0007`–`0009`, SQLAlchemy models, i18n catalog additions, Docker/Redis/state.git infrastructure.

PR-S3-0b is gated on PR-S3-0a merging. All downstream PRs (PR-S3-1 through PR-S3-7) are unblocked by PR-S3-0b; the §17 PR breakdown entry for PR-S3-0 is updated to reflect this split.

---

## 2. Cross-cutting wire-format ADR section

Three independent versioning schemes land in one slice and must be reconciled now to prevent wire-format drift between PRs.

**`TrustTier` wire format (§3.5):** `tier` serialized as `tier.name` string (e.g. `"T3"`) and re-resolved via `_APPROVED_TIERS` registry on parse. Cross-tier confusion on the wire (payload labelled T2 but containing `tier: "T3"`) is rejected at deserialisation with a loud `ValueError`. The string form is a stable, human-readable identifier; the class reference is the runtime discriminant.

**`alfred.manifest_version` (§4.3):** A single integer pinned to `1` for Slice 3. Any plugin presenting `alfred.manifest_version != 1` is rejected at handshake with exactly one `plugin.load_refused` audit row. No semver tolerance, no negotiation. The integer increments only when the manifest schema adds or removes fields that break backward compatibility; N+1 refusal is enforced at the `AlfredPluginSession` handshake before any capability-gate check.

**`schema_version` on extraction schemas (§6.6):** `Literal[1]` is mandatory on every extraction schema passed to `QuarantinedExtractor`. A schema without this field is rejected before the quarantined LLM is invoked. Slice 4 increments to `2` if the schema shape changes.

**Coordination rule:** `audit_row_schemas.py` (§13) ships before any fork's implementation PR and defines constants for all three versioning fields. The three fields never share a namespace: `alfred.manifest_version` lives in the MCP manifest; `schema_version` lives in extraction schema models; `tier.name` lives in `TaggedContent` serialisation. No aliasing, no shared field names.

### 2.1 DLP placement on every Slice-3 wire

Cross-fork risk §3 required an explicit DLP-placement table. Every Slice-3 wire and its scanner:

| Wire | Direction | Scanner | Scan shape | Disposition on fail |
|---|---|---|---|---|
| `StdioTransport` → subprocess stdin (outbound JSON-RPC) | Outbound | `OutboundDlp.scan(frame)` | Full frame (concatenated) | Refuse dispatch; `security.dlp_outbound_refused` audit row |
| subprocess stdout → `StdioTransport` (inbound JSON-RPC) | Inbound | `InboundContentScanner.scan(frame)` | Full frame; per-field for structured responses | SECURITY EVENT on canary trip; `security.canary_tripped` audit row |
| `web.fetch` outbound request (URL + headers) | Outbound | `OutboundDlp.scan_fields({"url": url, "headers": headers})` | Per-field (see §7.9b; cross-field deferral to Slice 4) | Refuse request |
| `web.fetch` inbound response body | Inbound | `InboundContentScanner.scan(body)` | Full body | SECURITY EVENT on canary trip |
| `security.quarantined.extract` → orchestrator (`.model_dump()`) | Outbound from quarantine | `OutboundDlp.scan(model_dump_result)` | Full serialised dict | Refuse extraction result; `security.canary_tripped` |
| In-process comms outbound (Discord/TUI — unchanged Slice-3) | Outbound | Existing `OutboundDlp.scan` in `DiscordAdapter`/`TuiAdapter` | Per Slice-2 contract | Per Slice-2 contract |

Cookies flow through the secret broker substitution (§7.8) — they do not appear in the DLP wire scan because they are substituted at the broker boundary, not carried as plaintext. The stdlib key delivery on fd 3 (§5.3) is framed binary and does not pass through DLP — it never contains user content.

---

## 3. Trust tiers — T1 + T3 type system (Forks 3 + 6)

### 3.1 Type-system shape

The shipped `TaggedContent[TierT: TrustTier]` phantom-type generic (`src/alfred/security/tiers.py:34`) extends additively. Two new `TrustTier` subclasses join the module:

```python
class T1(TrustTier):
    """Operator tier: TUI ingress + operator-attributable outbound."""
    name = "T1"

class T3(TrustTier):
    """Untrusted ingestion tier: web fetch, email, file, MCP tool output."""
    name = "T3"
```

`_APPROVED_TIERS` grows from `frozenset({T0, T2})` to `frozenset({T0, T1, T2, T3})`. The existing `tag()` overload pattern (`src/alfred/security/tiers.py:94-104`) gains two new `@overload` signatures — `tag(T1, ...) -> TaggedContent[T1]` and `tag(T3, ...) -> TaggedContent[T3]` — with the T3 overload capability-gated (§3.2).

The existing `orchestrator/core.py:231,325` `TaggedContent[T2]` contract widens additively to `TaggedContent[T1] | TaggedContent[T2]`; the T3 path never reaches the orchestrator's input contract (T3 stays inside the quarantined-LLM plugin).

### 3.2 `tag(T3, ...)` — capability-gated factory

`tag(T3, content, ...)` is not openly callable. The `T3` overload in `src/alfred/security/tiers.py` calls `CapabilityGate.check_content_clearance(plugin_id=caller_id, hookpoint="tag.T3", content_tier="T3")` before constructing `TaggedContent[T3]`. The authorized caller set for `tag.T3` is: (1) the quarantined-LLM plugin host, and (2) any registered T3-producing plugin transport (`StdioTransport.dispatch()` on inbound payloads). Any other caller gets a `ValueError` with the `t("security.tag_t3_unauthorized", caller=caller_id)` message and emits a `security.t3_boundary.refused` audit row.

The capability check is backed by a caller token, not by frame introspection. The `tag(T3, ...)` call sites are exactly two: `src/alfred/plugins/stdio_transport.py` (inbound plugin payloads) and `src/alfred/plugins/quarantine_host.py` (quarantined-LLM plugin host). Each call site holds a caller token that is a **per-process random nonce** (`secrets.token_bytes(32)`) generated by `CapabilityGate` at construction time and distributed via dependency injection to exactly the two authorised modules. The `tag()` T3 overload compares tokens by identity (Python `is`, not `==`) — a copied value fails the check. This prevents the `import _CALLER_TOKEN from stdio_transport` attack (a constant can be imported; an identity-compared object reference cannot be forged by import alone).

Frame-inspection (`sys._getframe`) is NOT used for the security gate — it is forgeable via `sys.modules` manipulation and provides no real caller identity. The T3_BOUNDARY_REFUSAL_FIELDS audit row carries `caller_module_unverified` (a best-effort frame-derived label, not an authenticated identity; documented in the audit-row schema constants) rather than `caller_module`.

The adversarial corpus (§12) includes a `tier_laundering` payload "import the caller token from the approved module and call `tag(T3)` from orchestrator context" — asserts `ValueError` + `security.t3_boundary.refused` audit row, confirming that import of a nonce object does not confer the identity the gate checks.

When `caller_token` is missing (interpreters without the token mechanism in test stubs), the call refuses by default and emits the `security.t3_boundary.refused` audit row.

A ruff/grep CI rule (`scripts/check_tag_t3.py`) rejects any non-test file in `src/` containing `tag(T3` at a non-approved call site. The adversarial corpus (§12) includes a `tier_laundering` payload that attempts `tag(T3, ...)` from orchestrator context and a `tier_laundering` payload that exercises the frame-introspection-bypass attack (monkey-patching `sys.modules` to forge an authorized `__name__`).

**Threat model limits of the caller-token check.** The `is`-comparison nonce defends against *import-time forgery* — a module that `import`s the token object from an approved call site cannot forge the identity because importing creates a new binding, not the same object reference. It does not defend against an attacker with **arbitrary in-process code execution** in the orchestrator process. An attacker at that privilege level can locate the live token object via `gc.get_objects()` and pass the live reference back, satisfying the identity check. That attack is outside the T3 gate's threat model: an adversary with arbitrary code execution in the privileged orchestrator process is already a full compromise — no T3 tagging gate can help. The threat this gate is designed to close is *plugin code that attempts to call `tag(T3, ...)` on behalf of the orchestrator* across the process boundary (i.e., import-side forgery, not runtime GC traversal). The adversarial corpus payload for `gc.get_objects()`-style retrieval is labelled `tier_laundering / gc_traversal_out_of_scope` and asserts that this vector is acknowledged as out-of-scope with an explicit rationale — it is not marked as an unresolved gap.

### 3.3 `Protocol AnyTaggedContent`

Observer code — audit writers, logging, DLP scanners — must not require `cast()` to read tier and content. A `Protocol AnyTaggedContent` lands in `src/alfred/security/tiers.py`:

```python
class AnyTaggedContent(Protocol):
    """Read-only view of any TaggedContent regardless of tier parameter.

    Observer code (audit, logging, DLP) takes AnyTaggedContent; mutators
    take the concrete TaggedContent[T]. Prevents cast() proliferation that
    variance gap would otherwise force.
    """
    @property
    def content(self) -> str: ...
    @property
    def source(self) -> str: ...
    @property
    def tier(self) -> type[TrustTier]: ...
    @property
    def metadata(self) -> dict[str, object]: ...
```

A ruff/grep CI rule rejects `cast(TaggedContent[` and `# type: ignore` on `TaggedContent` in non-test `src/` files.

### 3.4 `quarantined_to_structured` boundary in `src/alfred/security/quarantine.py`

The single legitimate crossing point where T3-derived data enters an orchestrator-readable form:

```python
# src/alfred/security/quarantine.py

async def quarantined_to_structured(
    handle: ContentHandle,
    schema: type[BaseModel],
    *,
    extractor: QuarantinedExtractor,
    gate: CapabilityGate,
) -> ExtractionResult:
    """Convert an opaque ContentHandle into a validated Pydantic model.

    This is the ONLY path by which T3-derived content reaches
    orchestrator-readable structured form. Any other path that claims to
    convert T3 content is a security violation.

    The caller must hold check_content_clearance(plugin_id, hookpoint=
    "quarantine.dereference", content_tier="T3") — a clearance that is
    distinct from the tag.T3 clearance (which is plugin-host-internal).
    The orchestrator-side caller of quarantined_to_structured does NOT
    hold tag.T3 clearance; it holds the dereference clearance granted to
    the QuarantinedExtractor. The extractor communicates with the
    quarantined-LLM MCP plugin; raw provider response bytes never cross
    back to this process untyped.
    """
```

The file `src/alfred/security/quarantine.py` is the single grep anchor for all T3-to-orchestrator handoffs. Adversarial-corpus testers grep this file per CLAUDE.md §Security rules; placing the boundary in the `providers/` tree would route it outside the security review surface.

### 3.5 Wire-format serializer

`TaggedContent` gains a `model_serializer` that emits `tier` as `tier.name` (e.g. `"T3"`) and a `model_validator` that consults `_APPROVED_TIERS` on parse. Cross-tier confusion — a payload with `"tier": "T2"` but whose Python type is `TaggedContent[T3]` — is caught at the validator boundary and raises `ValueError` with the audit-row-safe message `t("security.tier_mismatch", wire_tier=..., expected_tier=...)`. The wire validator also rejects any `tier` string not in `{t.name for t in _APPROVED_TIERS}`.

### 3.6 T1 ingress via `IdentityResolver` (role × adapter)

`IdentityResolver.resolve()` (`src/alfred/identity/resolver.py`) already returns a `User` with an `Authorization` role. The ingress trust-tier derivation lives in `src/alfred/identity/` (specifically `src/alfred/identity/_ingest.py`), NOT in `src/alfred/orchestrator/core.py`. The orchestrator's module docstring (`core.py:13-17`) and `_handle_turn` (`core.py:339-340`) already establish that external input arrives already-tagged by the time it reaches the orchestrator — placing `_ingest_tier` in `orchestrator/core.py` would violate this boundary. Each `CommsAdapter` calls `_ingest_tier` at the ingress boundary before passing the tagged content to the orchestrator; the orchestrator's input contract widens only as a type-signature change (`TaggedContent[T1] | TaggedContent[T2]`), not as new ingress logic inside `core.py`.

```python
# src/alfred/identity/_ingest.py
def _ingest_tier(user: User, adapter_name: str) -> type[TrustTier]:
    """Derive ingress trust tier from role × adapter pair.

    TUI + operator role -> T1.
    Discord + operator role -> T2 (Discord is broadcast-shaped, never T1).
    Any role + any adapter -> T2 otherwise.
    Slice 3: T1 outbound is TUI stdout only.
    """
    if adapter_name == "tui" and user.authorization == Authorization.OPERATOR.value:
        return T1  # User.authorization is Mapped[str]; compare against .value per resolver.py:183
    return T2
```

The per-adapter name is the `CommsAdapter.name` field already on the in-process Protocol (`src/alfred/comms/` implements `name: str`). No new credential surface; no new ingress path.

T1 assistant output follows the at-most-as-trusted-as carry-over (`src/alfred/orchestrator/core.py:75-77`): a T1-triggered turn produces T1 outbound. Explicit downgrade to T2 (for broadcast-safe responses) requires `downgrade_explicit=True` on the audit row.

T1 outbound channel = user-facing response on TUI stdout only (Slice 3). Audit log entries, structlog logs, Prometheus metrics, and Grafana dashboards are internal observability surfaces — they are NOT "outbound" in the T1-routing sense. Operator content that reaches those surfaces is handled by the audit subsystem's own trust-tier pipeline, not by the T1 outbound channel definition.

T1-default CLI commands: `alfred user`, `alfred memory rollback`, `alfred plugin grant`, `alfred web allowlist`, `alfred audit`, `alfred supervisor reset`.
T2-default CLI commands: `alfred chat`, `alfred status`.

### 3.7 `ExtractionResult` type-level T3-provenance discriminant

`Extracted.data` (§6.7) is a `dict[str, object]` — a plain orchestrator-readable dict. Without a type-level marker, a future contributor who writes `prompt = f"The article title was: {result.data['title']}"` silently regresses ADR-0013.

To prevent this, `Extracted` carries a type-level provenance marker: the `data` field is typed as `T3DerivedData` — a `NewType("T3DerivedData", dict[str, object])`. Any orchestrator-output path that consumes `T3DerivedData` must call `downgrade_to_orchestrator(data, *, audit_row=...)` before injecting the value into a privileged prompt. `downgrade_to_orchestrator` is gated on `CapabilityGate.check_content_clearance(hookpoint="t3.downgrade_to_orchestrator", content_tier="T3_derived")` and writes an audit row with `downgrade_explicit=True`.

This is a Slice-3 type-level discriminant. A full `TaggedContent[T2_DerivedFromT3]` parameterisation (the architect's ideal shape) is deferred to Slice 4 alongside the full containerisation ADR; it requires the phantom-type generic to carry a provenance axis in addition to the tier axis, and that design belongs in ADR-0015. Slice 3 uses `T3DerivedData` as the lightweight discriminant; Slice 4 migrates to the full parameterisation. The residual risk: `T3DerivedData` is a `NewType` over `dict`, so `cast()` can erase it — the same ruff/grep CI rule that rejects `cast(TaggedContent[T2]` also rejects `cast(dict,` applied to a `T3DerivedData` binding.

### 3.8 Cast-bypass policy + adversarial coverage

The `tier_laundering` adversarial category (§12.2) includes:

- `cast(TaggedContent[T2], t3_value)` bypass — asserts the orchestrator raises rather than accepting the cast result.
- Wire-format tier confusion — a JSON payload with `"tier": "T2"` but a T3-constructed `content` field; asserts validation rejection.
- `tag(T3, ...)` from orchestrator module context — asserts `ValueError` before construction.
- Frame-introspection-bypass — monkey-patches `sys.modules` to forge an authorized `__name__`; asserts refusal + `security.t3_boundary.refused` audit row.
- `cast(dict, t3_derived_data)` erasure of `T3DerivedData` NewType — asserts the ruff/grep CI rule fires.

---

## 4. MCP plugin transport (Fork 2)

### 4.1 `PluginTransport` Protocol

```python
# src/alfred/plugins/transport.py
from typing import Annotated
from alfred.security.quarantine import ExtractionResult

class ControlResult(BaseModel):
    """Plain JSON-deserialisable result from a non-content, non-extraction RPC call."""
    model_config = ConfigDict(frozen=True)
    method: str
    payload: dict[str, object]

DispatchResult = ContentHandle | ExtractionResult | ControlResult

class PluginTransport(Protocol):
    """Structural Protocol every plugin transport implementation honours.

    Slice 3 ships StdioTransport as the sole implementation.
    HTTP deferred to Slice 5+. In-process MemoryTransport deliberately
    never shipped (would collapse process-boundary isolation).
    """
    async def dispatch(
        self,
        method: str,
        params: dict[str, object],
    ) -> DispatchResult:
        """Dispatch a JSON-RPC call to the plugin subprocess.

        Returns one of three discriminated shapes:
        - ContentHandle: content-bearing tools (web.fetch); T3 bytes held
          in content store, not in the return value.
        - ExtractionResult: structured-extraction calls (quarantine.extract);
          validated Pydantic model.
        - ControlResult: all other RPC calls (lifecycle, config).

        TaggedContent[T3] is plugin-host-INTERNAL — it exists inside
        StdioTransport between the subprocess boundary and the content store
        write; it never exits dispatch() as the return value. See §3.1, §7.3.
        DLP wraps this method — callers receive the post-DLP result.
        """
        ...

    async def close(self) -> None: ...
```

### 4.2 `StdioTransport` implementation

`StdioTransport` wraps the `model_context_protocol` SDK's `ClientSession` in `src/alfred/plugins/stdio_transport.py`. Every outbound JSON-RPC frame the host writes to a subprocess's stdin passes through `OutboundDlp.scan` before the bytes cross the pipe. Every inbound frame from stdout is tagged `TaggedContent[T3]` via the capability-gated `tag(T3, ...)` factory **internally**, stored in the content store, and returned to the orchestrator as a `ContentHandle` — the T3-tagged value never exits the host as the dispatch() return value. This is the two-layer model that reconciles §4.1 with §3.1 and §7.3: `TaggedContent[T3]` is plugin-host-internal; `ContentHandle` is what the orchestrator holds. For QuarantinedExtractor's `quarantine.extract()` call, the return is a validated `ExtractionResult` (a plain Pydantic model), not a ContentHandle or TaggedContent[T3].

`AlfredPluginSession` wraps `ClientSession` with the manifest handshake, version check, and capability-gate consult.

### 4.3 Manifest schema (tier-only, no provenance/transport fields)

```toml
# Slice-3 manifest shape (TOML or JSON — TOML shown)
alfred.manifest_version = 1          # integer; N+1 refused at handshake

[plugin]
id = "alfred.quarantined-llm"
subscriber_tier = "system"           # system | operator | user-plugin (SUBSCRIBER axis)
sandbox_profile = "user-plugin"      # OS-level sandbox profile, declared independently of subscriber_tier

[[hooks]]
action = "security.quarantined.extract"
kind = "pre"
subscriber_tier = "system"           # SUBSCRIBER axis — must not be confused with content trust tier (T0-T3)
```

**Two-axis naming rule:** `subscriber_tier` in the manifest refers to the subscriber capability tier (system/operator/user-plugin) — the axis governing who may register hook subscribers and what capabilities a plugin holds. `tier` as a value in `TaggedContent` and audit rows refers to the content trust tier (T0/T1/T2/T3). These two axes are orthogonal (see `docs/glossary.md`). The manifest uses `subscriber_tier` exclusively to prevent confusion. A manifest declaring `subscriber_tier = "T3"` is refused at handshake with `plugin.load_refused` (T3 is not a valid subscriber tier).

`transport` and `provenance` fields are NOT present in Slice 3 — they appear when HTTP transport ships (Slice 5+). `sandbox_profile` is declared independently of `subscriber_tier` so the quarantined LLM (`subscriber_tier=system`, because it processes T3 content for the system) runs in the `user-plugin`-class sandbox profile (no `ALFRED_*` env vars, fs writes restricted to `$XDG_RUNTIME_DIR/alfred/plugin-<id>/`, network allowlist only) per the security requirement that sandbox profile must be derivable from content touched, not just subscriber tier.

**Reserved for Slice 4 (comms-MCP manifest extension):** a `[plugin] platform` field (string; e.g. `"discord"`) is reserved in the Slice-3 schema spec even though no Slice-3 plugin uses it. Reserving it now prevents a manifest_version bump when Slice 4 ships the comms-MCP adapter — the field is optional in version 1 and present-but-mandatory in version 2. This avoids the audit-consumer rename hazard where Slice-2 `name="discord"` becomes Slice-4 `plugin.id="alfred.discord-comms"` without a migration path for existing audit rows.

### 4.4 Host-side secret-broker substitution

Before any outbound JSON-RPC frame crosses the pipe, the host scans `params` for `{{secret:*}}` references and substitutes them via `SecretBroker.get()`. No `{{secret:*}}` reference ever reaches the subprocess. This enforces CLAUDE.md hard rule #6 structurally at the process boundary.

### 4.5 DLP wraps the transport (typed dispatch surface)

`StdioTransport.dispatch()` uses two distinct scanners:

- **Outbound:** `OutboundDlp.scan(frame)` on every JSON-RPC frame before `asyncio.subprocess` writes it to stdin. This scanner's rule set covers user-facing text redaction and secret-pattern detection in content destined for the subprocess.
- **Inbound:** `InboundContentScanner.scan(frame)` on every frame read from stdout before it is stored or returned. This is a distinct class from `OutboundDlp` — the rule sets differ (canary-token detection + secret detection in untrusted ingress, disposition: SECURITY EVENT on canary trip, not redact-and-continue), and the audit row families differ. Using `OutboundDlp.scan` on inbound bytes conflates two different threat models.

The T3-tagging of inbound payloads happens at this boundary — the subprocess produces JSON; the host passes the bytes through `InboundContentScanner`, then tags the result `TaggedContent[T3]` via the capability-gated `tag(T3, ...)` factory.

### 4.6 Wire-protocol surface (no dynamic hook registration)

The wire protocol rejects any JSON-RPC call with method `alfred/hooks.register` received after the initial handshake. Hook registration is manifest-at-handshake only. A compromised plugin attempting post-grant hook registration on (e.g.) `comms.discord.send` receives no grant and the host emits `plugin.lifecycle.quarantined` and SIGKILL. This prevents a compromise-then-escalate attack where a plugin grabs a new hookpoint after capability-gate approval.

### 4.7 Lifecycle audit family (`plugin.lifecycle.*`)

Audit row event names (defined in `audit_row_schemas.py` §13):

- `plugin.lifecycle.loaded` — successful handshake + capability grant.
- `plugin.lifecycle.load_refused` — any handshake failure (parse, version, tier, signature).
- `plugin.lifecycle.crashed` — subprocess exited unexpectedly.
- `plugin.lifecycle.quarantined` — circuit breaker tripped (§10.2) or protocol violation.
- `plugin.lifecycle.reloaded` — successful restart after a crash.

One audit row per `(action, kind, tier)` hook-registration tuple, not one row per plugin listing all tuples (selective revocation and downstream alerting require 1:1 correspondence).

### 4.8 `bin/alfred-plugin-launcher` stub

`bin/alfred-plugin-launcher` is a shell stub that fails with exit code 1 and `t("plugin.launcher_no_sandbox_policy", plugin_id=...)` when no sandbox policy is configured. This prevents silent degradation to unsandboxed `exec`. The stub's fail-closed behaviour is tested: a subprocess spawned via the launcher without a policy file exits 1, and the supervisor marks the plugin `load_refused`.

**Per-OS sandbox implementation is Slice 4.** The Linux `bwrap` policy (the AlfredOS Docker default deployment uses Linux) ships in Slice 4 alongside the containerised quarantined LLM (ADR-0015). macOS `sandbox-exec` and Windows stub policies also land in Slice 4.

Without a policy file, `bin/alfred-plugin-launcher` refuses any plugin start (fail-closed). To bootstrap Slice-3 subprocess plugins before Slice-4 policy files exist, the launcher accepts `ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED=1`. This flag:

- Is **refused** when `ALFRED_ENV != development` — a production deployment that attempts `ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED=1` emits a loud startup error and refuses to launch.
- When accepted, emits a `supervisor.config_insecure` audit row at **every plugin start** (not just once at boot), so the unsandboxed mode is continuously visible in the operator's audit stream.
- Is listed in the `alfred status` output with a prominent warning.

Slice 3 does NOT claim to provide runtime isolation beyond UID separation and env scrubbing (§5.2, §5.3) until Slice-4 policy files land. The stop condition: Slice 4's ADR-0015 must name which OS sandbox policies ship and mark the others as dev-only-forever or future-slice.

### 4.9 Manifest version pin (single integer, N+1 refused)

`alfred.manifest_version = 1` for all Slice-3 plugins. Any plugin presenting version != 1 receives exactly one `plugin.load_refused` audit row with `t("plugin.manifest_version_mismatch", got=..., expected=1)` and the subprocess is not started. The check occurs at the handshake stage, before any capability-gate consult.

---

## 5. Dual-LLM split — boundary placement (Fork 1)

### 5.1 Quarantined-LLM plugin shape

The quarantined LLM ships as `plugins/alfred-quarantined-llm/` — an in-tree MCP plugin loaded by the plugin host (`AlfredPluginSession`, §4, the class that owns the subprocess lifecycle) via `StdioTransport`. It exposes exactly two JSON-RPC methods:

- `quarantine.ingest(handle: str, context: str) -> void` — accepts a `ContentHandle` id + brief context; fetches the T3 content from the content store internally by handle ID.
- `quarantine.extract(handle_id: str, schema_json: str, schema_version: int) -> ExtractionResultJSON` — takes the `handle_id` explicitly and runs structured extraction against that specific content. The subprocess looks up T3 content per call from the content store using the ID; it does NOT operate against "most-recently ingested" state. This prevents a TOCTOU race where a concurrent extract in conversation B operates against conversation A's ingested content.

The quarantined LLM has no `tool_calls` capability and emits no free-form text that the orchestrator consumes as instructions. PRD §7.1 invariant: emits structured data only.

### 5.2 Dedicated `alfred-quarantine` UID

The subprocess runs under the `alfred-quarantine` OS user, distinct from the `alfred` user running the orchestrator. `src/alfred/security/secrets.py:228-279` already validates secret-file ownership against `os.getuid()`. Because the subprocess runs under a different UID, it literally cannot read the secrets file — the broker boundary is load-bearing by OS-level enforcement, not just policy.

**Container provisioning (Slice 3):** `docker/alfred-core.Dockerfile` adds `useradd --system --no-create-home alfred-quarantine` so the UID exists in the runtime image. `bin/alfred-plugin-launcher` is the UID-drop site: it is the setuid shim that calls `runuser -u alfred-quarantine -- <plugin-executable>`. The compose service `alfred-core` (which runs the orchestrator) requires `--cap-add SETUID` in `docker-compose.yaml` so the launcher's setuid bit is honoured at container start. The quarantined-LLM plugin host runs **only in `alfred-core`** — never in `alfred-discord` (which uses an overriding `user:` directive that would defeat UID separation).

### 5.3 Env scrubbing + stdin handshake for provider key

`asyncio.subprocess.create_subprocess_exec` is called with an explicit minimal env: `{"PATH": ..., "LLM_ENDPOINT": ...}`. No `ALFRED_*` variables, no API keys in env. The LLM provider key is delivered via a dedicated pipe (fd 3, not fd 0/stdin) immediately after subprocess start, before the MCP handshake begins. Using a dedicated fd prevents a malformed key (no trailing newline, embedded `\x00`) from leaving residual bytes in the fd 0 buffer that the MCP reader could misparse as the first JSON-RPC frame — a parser-confusion vulnerability that could expose key fragments in a structlog-logged "malformed handshake" event (violating CLAUDE.md hard rule #1).

Wire framing on fd 3: the host writes a 4-byte big-endian length prefix followed by exactly N bytes of key. The subprocess reads exactly 4 bytes, parses the length, reads exactly N bytes, validates that the fd 3 buffer is then empty, and enters the MCP server loop on fd 0/1. Any read error on fd 3 causes subprocess exit 1 before the MCP loop starts.

The existing AST-scan at `tests/unit/security/test_no_direct_env_reads.py` is extended to cover `src/alfred/plugins/stdio_transport.py` (the subprocess spawn site), asserting that `os.environ` is not read and that the `env=` argument to `create_subprocess_exec` is always an explicit dict, never `None` (which would inherit parent env).

### 5.4 Different provider from privileged (defence-in-depth)

The quarantined LLM uses a different provider from the privileged orchestrator by default (PRD §6.4 reviewer-agent requirement: "Different provider from primary by default"). `alfred config quarantined-provider <provider>` proposals go through state.git reviewer-gate (§11.1). Default: if privileged uses DeepSeek (ADR-0001), quarantined uses Anthropic Claude Haiku; if privileged uses Anthropic, quarantined uses DeepSeek.

**Config file anchor:** quarantined-provider binding lives in `config/routing.yaml` under a new `[quarantine]` block:

```yaml
quarantine:
  provider: "anthropic"          # or "deepseek" — reviewer-gated
  model: "claude-haiku-3-5"
  secret_id: "quarantine_provider_api_key"   # resolved by SecretBroker at spawn
```

The `secret_id` value is resolved by the SecretBroker before subprocess spawn (§5.3 fd-3 handshake): the host reads `routing.yaml[quarantine][secret_id]`, fetches the value from the broker, and frames it on fd 3. The plugin manifest's declared `quarantine.provider` field must match `routing.yaml[quarantine][provider]`; a mismatch emits `plugin.load_refused` at handshake.

**Single-provider failure mode:** If only one provider is configured (e.g., an air-gapped deployment with a single local model), AlfredOS refuses to bootstrap with a loud startup error: `t("bootstrap.quarantined_provider_same_as_privileged")` pointing the operator to `alfred config quarantined-provider`. Running both LLMs on the same provider is allowed only with explicit reviewer-gated approval (`alfred config quarantined-provider <same-provider>` goes through state.git as a security-policy change); when approved, the supervisor emits a recurring `supervisor.config_insecure` audit row at each restart to signal the defence-in-depth invariant is relaxed.

### 5.5 `QuarantinedUnavailable` distinct exception

`QuarantinedUnavailable` (in `src/alfred/plugins/errors.py`) is a distinct top-level exception, not a subclass of `HookSubscriberError`. The orchestrator catches it explicitly and refuses the user request with `t("orchestrator.quarantine_unavailable")` — "I can't process external content right now; please retry in a few minutes." No silent T3-self-processing fallback; the user-visible message is a hard invariant (CLAUDE.md hard rule #5).

### 5.6 Audit-field discipline

Subprocess crash audit rows carry ONLY: `plugin_id`, `exit_code`, `signal`, `restart_count`, `breaker_state`. The `exception_type` field is the Python type name (e.g. `"SubprocessExitedError"`) but never `str(exc)` or `exc.args`, because a misbehaving subprocess can carry T3 fragments into its crash trace. This matches the `_SUBSCRIBER_ERROR_AUDIT_FIELDS` pattern from Slice 2.5.

### 5.7 Co-merged Slice-4 containerisation ADR commitment + PRD §5 amendment

ADR-0015 is co-merged with the first Slice-3 implementation PR. It records: "Slice 3 ships the quarantined LLM as an MCP stdio subprocess under a dedicated UID (ADR-0013 intent). This is a deliberate, time-bounded relaxation of PRD §5 line 117 ('containerized with declared capabilities'). Slice 4 migrates the quarantined LLM to a container with full kernel-namespace isolation. Without this commitment, the §5 invariant silently decays."

PR-S3-0 also ships a **PRD §5 line 117 amendment** — co-merged with ADR-0017 — updating PRD §5's isolation invariant to read: "hybrid isolation: containerized OR dedicated-UID-with-env-scrub during Slice 3, fully containerized from Slice 4 per ADR-0015." This makes the relaxation explicit in the PRD rather than buried in a spec subsection; any future reader sees the invariant as a dated, authored commitment rather than architectural drift.

---

## 6. Quarantined structured output (Fork 5)

### 6.1 `Provider.capabilities() -> frozenset[ProviderCapability]`

The PRD §6.6 routing surface pre-flagged at `src/alfred/providers/base.py:68` for Slice-2 deferral now ships. `ProviderCapability` is a closed-set enum:

```python
class ProviderCapability(str, Enum):
    NATIVE_CONSTRAINED_GENERATION = "native_constrained_generation"  # Slice 3: used
    TOOL_USE = "tool_use"          # Pre-declared per PRD §6.6 line 290; no Slice-3 consumer
    VISION = "vision"              # Pre-declared per PRD §6.6 line 290; no Slice-3 consumer
    LONG_CONTEXT_1M = "long_context_1m"  # Pre-declared per PRD §6.6 line 290; no Slice-3 consumer
```

Only `NATIVE_CONSTRAINED_GENERATION` has a Slice-3 consumer. `TOOL_USE`, `VISION`, and `LONG_CONTEXT_1M` are pre-declared per PRD §6.6 line 290 (the routing surface design calls them out) with no Slice-3 consumers. They are closed-set Literals with no dispatch paths in Slice 3; Slice 4+ adds consumers additively.

Each provider adapter implements `capabilities() -> frozenset[ProviderCapability]` as a module-level constant. Validation at construction uses `__init_subclass__` runtime check: the `Provider` abstract base asserts that any concrete subclass returns a `frozenset` of known `ProviderCapability` members (NOT runtime SDK-introspection — SDK shape drift would silently degrade capability detection; NOT a Pydantic `field_validator` since `Provider` is a `typing.Protocol`, not a Pydantic model). A smoke test per provider (`tests/smoke/test_provider_capabilities.py`, using recorded fixtures — no live API calls) exercises the declared capability by invoking the extraction path it gates and fails the smoke gate if the provider's response shape drifts from the declared capability. The smoke test is wired in CI for every PR that touches `src/alfred/providers/`.

PR-S3-4 includes an explicit line item: "add `capabilities()` to `Provider` Protocol at `src/alfred/providers/base.py:68` + implement on `AnthropicProvider` and `DeepSeekProvider`." The three PRD §6.6 provider methods deferred from Slice 3 (`embed`, `cost`, `cache_marker`) are explicitly out of scope for all Slice-3 PRs — they land in Slice 5+ alongside the tiered routing and caching layer.

### 6.2 Native constrained-generation per provider

| Provider | Mechanism | Capability |
|---|---|---|
| Anthropic | Tool-use shape (tool with `input_schema`) | `NATIVE_CONSTRAINED_GENERATION` |
| OpenAI | Structured outputs (`response_format={"type": "json_schema", "json_schema": {"name": ..., "schema": ..., "strict": true}}`) | `NATIVE_CONSTRAINED_GENERATION` |
| DeepSeek-chat | JSON mode (`response_format={"type": "json_object"}`) | `JSON_OBJECT_MODE` (NOT `NATIVE_CONSTRAINED_GENERATION`) |

**DeepSeek reclassification:** `response_format={"type": "json_object"}` produces valid JSON but enforces no schema. DeepSeek-chat's `capabilities()` returns `frozenset({JSON_OBJECT_MODE})` — it does NOT include `NATIVE_CONSTRAINED_GENERATION`. `QuarantinedExtractor` dispatches DeepSeek via the same retry-and-validate path as `prompt_embedded_fallback` (schema embedded in prompt, Pydantic validation on response). The extraction mode is recorded in the audit row as `extraction_mode: Literal['native_constrained', 'json_object_unconstrained', 'prompt_embedded_fallback']`, where `json_object_unconstrained` labels DeepSeek's JSON-mode path. This preserves forensic traceability: an operator can distinguish true schema-enforcement (Anthropic, OpenAI) from best-effort validation (DeepSeek) in the audit log.

`ProviderCapability` gains a third value: `JSON_OBJECT_MODE = "json_object_mode"`. `QuarantinedExtractor` dispatches: `NATIVE_CONSTRAINED_GENERATION` → native path; `JSON_OBJECT_MODE` → JSON-mode path with Pydantic validation; neither → `prompt_embedded_fallback` path.

**OpenAI `strict: true` is mandatory.** The `response_format` shape must include `"strict": true` inside the `json_schema` wrapper to activate schema enforcement. Without it, OpenAI degrades to best-effort JSON output — functionally the same as DeepSeek's JSON mode. The smoke test per provider (§6.1) asserts the exact `response_format` shape is present.

`QuarantinedExtractor` dispatches to the appropriate mechanism based on `Provider.capabilities()`.

### 6.3 Prompt-embedded fallback

When the quarantined provider lacks `NATIVE_CONSTRAINED_GENERATION` (or has only `JSON_OBJECT_MODE`), `QuarantinedExtractor` sends the schema embedded in the prompt and validates the response with Pydantic. On validation failure, the retry-guidance turn contains ONLY the validator error message + the schema JSON — **never** the LLM's prior malformed JSON body verbatim. This is a hard invariant enforced by the adversarial corpus (§12): a malformed-output corpus is replayed through the fallback path and the second-turn prompt is asserted using **token-set membership**, not substring absence — the retry prompt's token set must be a subset of `{validator-error tokens} ∪ {schema-JSON tokens} ∪ {fixed-instruction-template tokens}`. Substring absence is brittle (a one-character substring of arbitrary HTML is almost certainly in any error text); token-set membership is the correct invariant shape.

Max retries: 2 (configurable in `config/policies.yaml`). After 2 failures, returns `TypedRefusal(reason="cannot_extract")`.

### 6.4 `QuarantinedExtractor` as orchestrator-side MCP client

`QuarantinedExtractor` (`src/alfred/plugins/quarantine_extractor.py`) is the orchestrator's client of the quarantined-LLM plugin. It calls `quarantine.extract()` via `StdioTransport.dispatch()` and deserialises the returned JSON into `ExtractionResult`. Raw provider response bytes never cross back to the orchestrator process untyped — the quarantined-LLM plugin sees the provider response; the orchestrator sees only the validated `ExtractionResult`.

### 6.5 Hookpoint `security.quarantined.extract`

Published by `QuarantinedExtractor` via the standard `register_hookpoint` + `invoking` pattern:

```python
registry.register_hookpoint(
    name="security.quarantined.extract",
    subscribable_tiers=SYSTEM_OPERATOR_TIERS,  # src/alfred/hooks/registry.py:309
    refusable_tiers=SYSTEM_ONLY_TIERS,
    fail_closed=True,
)
```

The `kind` is passed as a separate argument to `invoke()` per the Slice-2.5 contract at `src/alfred/hooks/registry.py`. User-plugin subscribers attempting to register on this hookpoint are refused at registration time with `HOOKS_TIER_REJECTED` audit row. `fail_closed=True` means a timed-out DLP scan refuses the extraction.

All kinds (pre/post/error) share the hookpoint's `fail_closed=True`. The current registry stores one `fail_closed` scalar per hookpoint and applies it to every kind; the §14 column reflects what the registry represents. A per-kind `fail_closed` override (the "error stage rewinds on subscriber crash; pre/post fail-close" semantic the spec previously implied at §14 row 1159) would require a registry refactor and is **not implemented**. Tracked at [#167](https://github.com/alfred-os/AlfredOS/issues/167).

A subscriber on the `security.quarantined.extract` hookpoint with `kind="post"` runs `OutboundDlp.scan` on the validated instance's `.model_dump()`, refusing on canary trip. Without this, a typed-extraction schema with a free-text `str` field is an exfiltration channel.

### 6.6 `schema_version: Literal[1]` mandatory

Every Pydantic model passed to `QuarantinedExtractor.extract()` must carry `schema_version: Literal[1]` as a class attribute. The extractor validates this before constructing the schema payload. An extraction schema missing `schema_version` raises `ValueError` with `t("quarantine.schema_version_missing", schema_name=...)` before any MCP call.

### 6.7 Discriminated-union `ExtractionResult`

```python
class Extracted(BaseModel):
    model_config = ConfigDict(frozen=True)
    kind: Literal["extracted"] = "extracted"
    data: T3DerivedData  # T3DerivedData = NewType("T3DerivedData", dict[str, object])
                         # type-level provenance marker; callers must use
                         # downgrade_to_orchestrator() before injecting into
                         # privileged prompts (see §3.7)
    extraction_mode: Literal["native_constrained", "json_object_unconstrained", "prompt_embedded_fallback"]

class TypedRefusal(BaseModel):
    model_config = ConfigDict(frozen=True)
    kind: Literal["typed_refusal"] = "typed_refusal"
    reason: Literal["cannot_extract", "refused_by_safety", "ambiguous_input"]

ExtractionResult = Annotated[Extracted | TypedRefusal, Field(discriminator="kind")]
```

`kind="malformed_output"` is NEVER returned to the orchestrator — a malformed output triggers a retry; exhausted retries become `TypedRefusal(reason="cannot_extract")`. The `metadata` on `HookContext` carries `extraction_mode` and `reason` so DLP, operator-attribution, and per-user budget-decrementer hook subscribers can react differently.

### 6.8 Audit row fields

`quarantine.extract` audit row (constants in `audit_row_schemas.py`):
`extraction_mode`, `provider`, `schema_name`, `schema_version`, `retry_count`, `trust_tier_of_trigger="T3"`, `result` (`"extracted"` | `"refused"` | `"malformed_exhausted"` | `"content_expired"`), `correlation_id`.

---

## 7. `web.fetch` (Fork 4)

### 7.1 In-tree MCP plugin under Slice-3 host

`plugins/alfred-web-fetch/` is an in-tree MCP plugin loaded by the plugin host (`AlfredPluginSession`, §4) via `StdioTransport`. It is a separate subprocess from the quarantined LLM. It exposes one JSON-RPC method: `web.fetch(url: str, headers: dict) -> ContentHandleJSON`.

### 7.2 Output flows into quarantined-LLM plugin's stdio

`web.fetch` output does NOT flow into the orchestrator as `TaggedContent[T3]`. The orchestrator calls `web.fetch`, receives a `ContentHandle` (§7.3), then passes that handle to the quarantined-LLM plugin for extraction. The fetched HTML bytes are stored in a per-request content store (Redis, keyed by `ContentHandle.id`) accessible only by the plugin host.

Content-store TTL = `action_deadline_seconds + (max_extraction_retries × per_retry_budget_seconds) + 30s` slack (default: 30 + 2×10 + 30 = 80s). This formula ensures the handle outlives the worst-case retry path without the TTL growing silently when the operator raises the action deadline for unrelated reasons. Alternatively, the plugin host refreshes the TTL at `quarantine.extract` start; the spec commits to the formula as the default and TTL refresh as an opt-in once Redis `GETEX` semantics are confirmed. When TTL fires mid-extraction, the content store returns a typed error (`ContentHandleExpired`) that the quarantined LLM propagates back as `TypedRefusal(reason="cannot_extract")` — no silent failure. The audit row for this case carries `result="content_expired"` (distinguishable from `result="refused"`) so operators can detect a slow-fetch DoS pattern where an adversary controls fetch latency to force every `web.fetch` to silently degrade to `cannot_extract`. The plugin host explicitly deletes content on successful extraction completion or on supervisor SIGKILL; TTL is the safety net, not the primary eviction path.

**Single-extract-per-handle invariant.** `handle_id` values are single-use UUIDs. The content store enforces this: on the first successful `quarantine.extract` call, the store atomically deletes the entry (`DEL alfred:content:{handle_id}`) before returning the result to the caller. A second `quarantine.extract` against the same `handle_id` receives a `ContentHandleExpired` typed error (same error as TTL expiry), not a second extraction. This closes the concurrent-extract race: if an attacker induces two orchestrator turns to race on the same handle_id, the first extract wins and the second gets `ContentHandleExpired` — there is no race window where both extracts see live content. The audit row for either case carries `result="content_expired"`, so a pattern of double-extract attempts is visible to the operator. This invariant is tested in `tests/unit/security/test_content_handle_single_use.py`.

The orchestrator never dereferences the handle to readable bytes.

### 7.3 `ContentHandle` as orchestrator-side return

```python
@dataclass(frozen=True, slots=True)
class ContentHandle:
    """Opaque reference to T3 content held in the plugin host's content store.

    The orchestrator holds this; the quarantined-LLM plugin dereferences it.
    The orchestrator NEVER calls .content — that field does not exist.
    """
    id: str  # UUID keyed to the content store
    source_url: str  # for audit attribution only; not readable content
    fetch_timestamp: datetime
```

`dereference_to_quarantined_llm(handle)` lives in the quarantined-LLM plugin's call interface, not as an orchestrator method. Any attempt to read the fetched bytes from the orchestrator side is a type error: `ContentHandle` has no `.content` field.

### 7.4 Three-way allowlist intersection (manifest ∩ operator config ∩ per-session)

A URL is reachable if and only if ALL THREE allowlists permit it:

1. Plugin manifest's declared `allowed_domains` list.
2. Operator's `config/policies.yaml` `web_fetch.allowed_domains`.
3. Per-session grant (capability-gate check at dispatch time, re-checked on every call — not cached).

Per-session grant takes precedence for narrowing (cannot be wider than operator config). Operator config takes precedence for narrowing (cannot be wider than manifest). A manifest broadening relative to operator config is capped to the operator config — the broader manifest domain is not activated. This is NOT silent: when the effective allowlist is narrower than the manifest's declared `allowed_domains`, the host emits a `web.allowlist.manifest_broadening_capped` audit row on every manifest load. Operators need to see this: a plugin update that declares a wider allowlist than the operator permits is a security-relevant event (the plugin author intends a wider surface; the operator's policy has refused it). An adversarial-corpus payload in `dlp_egress` asserts this audit row fires when a malicious manifest update tries to widen allowed_domains beyond the operator config.

Allowlist granularity: `(domain, path-prefix)` tuples (e.g. `"example.com/public/"`) stored in `config/policies.yaml` for low-blast operator overrides and in state.git for domain-level changes.

### 7.5 `tool.web.fetch` hookpoint (all kinds) — `subscribable_tiers=frozenset({"system"})`

```python
registry.register_hookpoint(
    name="tool.web.fetch",
    subscribable_tiers=SYSTEM_ONLY_TIERS,
    refusable_tiers=SYSTEM_ONLY_TIERS,
    fail_closed=True,
)
```

`kind` (`"pre"`, `"post"`, `"error"`, `"cancel"`) is passed as a separate argument to `invoke()` per the Slice-2.5 contract at `src/alfred/hooks/registry.py`. One `register_hookpoint` call covers all four kinds; the tier policy applies to all kinds uniformly. `SYSTEM_ONLY_TIERS` from `src/alfred/hooks/registry.py:320`. Operator- and user-plugin-tier subscribers are refused at registration time. ADR-0014 flagged `web.fetch` as the canonical case for tier restriction; URLs fetched on behalf of the quarantined LLM may carry operator-tier credentials or T3-injected content.

Response body size: 5MB default, configurable per manifest. MIME-type allowlist: `text/html`, `text/plain`, `application/json`, `application/xml`, `text/markdown`; PDF, archive, executable refused by default.

### 7.6 `InboundCanaryScanner` as system-tier hook subscriber on `tool.web.fetch` (kind=`post`)

`InboundCanaryScanner` registers as a system-tier subscriber on the `tool.web.fetch` hookpoint with `kind="post"`. It does NOT run in the orchestrator process — it runs on the plugin-host side (where the T3 bytes live in the content store), because the orchestrator never dereferences `ContentHandle` to bytes (§7.3). The scanner's `scan(handle)` method reads from the content store internally and emits a typed `CanaryTrip` event back to the orchestrator-side hook dispatcher; the orchestrator-side subscriber receives the `CanaryTrip` event, not the raw bytes.

This is NOT plugin-internal. ADR-0014 cured the "patch each tool individually" anti-pattern; placing the scanner as a hook subscriber means `email.read`, `mcp.tool.output`, and future RAG retrievers inherit canary scanning by virtue of the system-tier subscriber existing on their respective hookpoints with `kind="post"`.

The `CanaryTrip` event typed as a `WebFetchCanaryTripped` signal flows to the orchestrator hook dispatcher; the orchestrator treats this as a SECURITY EVENT (see §7.10).

Canary trip disposition: `WebFetchCanaryTripped` (a distinct `AlfredError` subclass, NOT a subclass of `WebFetchError`). The canary trip is a SECURITY EVENT: it emits `tool.web.fetch.canary_tripped` audit row, quarantines the content handle, and raises `WebFetchCanaryTripped` with `t("security.canary_tripped", url=source_url)` to the orchestrator. CLAUDE.md hard rule #7: no silent failure.

### 7.7 Rate-limits in Redis from day one

Per-domain: 10 requests/minute (operator override in `config/policies.yaml`). Per-user: 30 requests/minute (operator override). Per-user daily budget: 100 fetches/day for user-tier, unlimited for operator-tier (default; override in `config/policies.yaml`).

State lives in Redis using sliding-window counters:

- Per-domain rate: `alfred:rate:{domain}` key.
- Per-user rate: `alfred:rate:user:{user_id}` key.
- Per-user daily fetch budget counter: `alfred:fetch_budget:{user_id}:{YYYY-MM-DD}` key, TTL=48h.

The daily budget *limit* lives in `config/policies.yaml` (read-only config) and is cached in-process with file-mtime invalidation — this avoids one YAML parse per fetch on the hot path without risking staleness beyond the mtime polling interval (1s). The per-user-per-day *counter* is mutable state in Redis — it cannot live in an in-process dict per PRD §7.6 stateless-alfred-core path (in-process counters do not survive worker recycling and cannot be shared across replicas). TTL=48h (not 24h) to handle midnight-boundary edge cases.

**Redis memory bound:** `maxmemory-policy=volatile-lru` (evicts TTL-bearing keys under memory pressure). Per-user concurrent `ContentHandle` cap: 5 active handles per user (operator override in `config/policies.yaml`). A sixth `web.fetch` call from the same user while 5 handles are live receives `WebFetchRateLimited` and emits a `tool.web.fetch` audit row with `dlp_scan_result="handle_cap_exceeded"`. This prevents a single user from filling Redis with large response bodies.

### 7.8 Cookie policy (no cookies by default; granted via secret broker)

No cookies are sent by default. A session grant for a domain-keyed cookie flows through the secret broker: the plugin requests `{{secret:cookie:example.com}}`; the broker substitutes at the transport boundary. The orchestrator never sees the cookie value. Cookie grants are operator-tier-only.

### 7.9 Per-conversation max fetch depth = 1

The quarantined LLM cannot call `web.fetch` directly — it emits structured data, no tool calls. The orchestrator may choose to call `web.fetch` (via a fresh capability-gated grant) based on URLs the quarantined LLM returns in structured output. That is depth 1. The orchestrator does not recursively pass newly-fetched content back into `web.fetch` within the same conversation turn. Explicit depth=1 prevents a future contributor from reading "first T3 tool" and assuming a more permissive contract.

### 7.9b OutboundDlp on the `web.fetch` request path

When the orchestrator dispatches `web.fetch(url, headers)`, the outbound request has three fields that can carry secrets: `url`, `headers`, and (if cookies are granted) the substituted cookie value. The synthesis (cross-fork risk §3) required an explicit decision on per-field vs concatenated scanning.

**Slice 3 decision: per-field scan.** `OutboundDlp.scan_fields({"url": url, "headers": headers})` is called before the request crosses the wire. Each field is scanned independently. The cookie value is substituted by the secret broker (§7.8) and does NOT flow through DLP — the broker handles it as a secret reference, not plaintext.

**Cross-field secret leak acknowledged as Slice-4 TODO.** A secret split across two fields (e.g., half in a header value, half in the URL path) is not detected by per-field scanning. Full cross-field leak detection requires `OutboundDlp.scan_concatenated(fields) -> ScanResult` operating on a concatenated representation. This is deferred to Slice 4 with an explicit tracking note: once `OutboundDlp` gains `scan_concatenated`, the `web.fetch` dispatch path must migrate to it. Until then, the per-field scan catches the common cases; the cross-field gap is documented here as a known residual risk.

### 7.10 `WebFetchError` hierarchy + `WebFetchCanaryTripped` SECURITY EVENT

```python
class WebFetchError(AlfredError): ...
class WebFetchDomainNotAllowed(WebFetchError): ...
class WebFetchTlsError(WebFetchError): ...
class WebFetchRateLimited(WebFetchError): ...
class WebFetchMimeTypeNotAllowed(WebFetchError): ...
class WebFetchSizeLimitExceeded(WebFetchError): ...

# NOT a WebFetchError subclass — a separate security-event hierarchy
class WebFetchCanaryTripped(AlfredError): ...
```

All error strings route through `t()` per CLAUDE.md i18n rule #1.

### 7.11 TLS verification fail-closed (no operator override for production)

TLS chain verification against the system CA bundle is non-negotiable. A verification error writes a `tool.web.fetch` audit row with `dlp_scan_result="tls_verification_failed"` before raising `WebFetchTlsError`. This ensures MITM probe attempts are observable in the audit stream. There is no operator-level override to disable TLS verification for production deployments — a MITM injecting prompt-injection payloads is the canonical T3 ingestion attack; disabled TLS verification is the bypass. `localhost` and loopback addresses are allowed without TLS (for test fixtures and local integrations). The config key `web_fetch.skip_tls_verify` is accepted in `config/policies.yaml` but only in deployments where `ALFRED_ENV=development` — a production deployment with `skip_tls_verify=true` emits a loud startup warning and a `supervisor.config_insecure` audit row.

### 7.12 Audit row fields (incl. `manifest_commit_hash`)

`tool.web.fetch` audit row (constants in `audit_row_schemas.py`):
`url`, `domain`, `status_code`, `content_handle_id`, `fetch_depth`, `rate_limit_bucket`, `manifest_commit_hash`, `trust_tier_of_result="T3"`, `dlp_scan_result`, `canary_tripped` (bool), `triggering_user_id` (canonical_user_id of the user whose conversation turn caused the fetch — for PRD §7.4 per-user forensic attribution), `correlation_id`.

`manifest_commit_hash` enables forensic correlation: if the web-fetch plugin is updated between a fetch and a security investigation, the hash identifies the exact plugin version that handled the request.

---

## 7a. Performance budgets

Slice 3 introduces three new hot paths — the subprocess transport round-trip, the `web.fetch` pre-request gate, and the per-action deadline. All three have concrete p99 commitments below; PR-S3-3 ships the metrics alongside the code (not as a Slice-4 follow-up).

### 7a.1 Transport and scan budgets

| Path | p99 budget | Notes |
|---|---|---|
| `StdioTransport.dispatch()` empty-payload round-trip | < 5ms | Excludes provider call inside subprocess |
| `OutboundDlp.scan` 1 KB frame | < 200µs | |
| `InboundContentScanner.scan` 1 MB body | < 50ms | Scanner runs in `asyncio.to_thread()` — not on the event loop |
| Subprocess spawn cold-start | < 500ms | Relevant to circuit-breaker `HALF_OPEN` probe |
| `tool.web.fetch` 5-subscriber chain | ≤ 100µs + transport hop ≤ 5ms | Hookchain budget from Slice-2.5 + subprocess hop |
| `security.quarantined.extract` 5-subscriber chain | ≤ 100µs + provider call | Provider RTT is provider-owned; transport overhead budget is the 5ms above |

`InboundContentScanner.scan` runs in `asyncio.to_thread()` to avoid blocking the event loop on regex-heavy 5 MB bodies.

### 7a.2 `web.fetch` pre-request gate budget

The per-`web.fetch` hot path adds: capability-gate Postgres check + 3 Redis rate-limit checks + allowlist intersection. All three Redis checks execute as a **single Lua script** (atomic check-and-increment) — not three sequential round-trips. This prevents race conditions (a user racing past the per-domain limit via concurrent requests) and bounds the gate to one Redis RTT.

Budget: combined gate (capability check + 3 rate-limits + allowlist intersection) p99 < 10ms.

The capability gate exposes `alfred_capability_gate_check_seconds` Prometheus histogram. When the gate's Postgres backing store is unavailable, the histogram records the fail-closed transition time (entering and exiting the fail-closed window).

### 7a.3 Per-action observability

`alfred_orchestrator_action_duration_seconds` histogram, labelled `(user_id_bucket, action_outcome, breaker_state)`. The supervisor's `deadline.py` emits duration on **every** action (success, timeout, and cancelled), not only on timeout. Per-phase OpenTelemetry sub-spans: `tool.web.fetch`, `security.quarantined.extract`, `hookchain_total`. This lets operators see the 30s budget consumed asymmetrically and tune `orchestrator.action_deadline_seconds` against observed p99.

---

## 8. Real `CapabilityGate` (Fork 7)

### 8.1 Hybrid storage (state.git source of truth + Postgres runtime cache)

Grant proposals land in state.git (`proposal/policy-grant-<id>` branches) and are reviewed by the reviewer agent. Approved grants are merged to `main`; the Postgres `plugin_grants` table is a derived projection rebuilt from state.git on commit-hash change.

Hot-path capability checks consult Postgres (millisecond latency). When Postgres is unavailable, the gate fails closed for ALL dispatches — `check()`, `check_plugin_load()`, `check_content_clearance()` all return `False`. No new plugin dispatches succeed during a backing-store outage. Previously-loaded in-process subscribers are also denied: the staleness window for revocations is bounded at 60s; after 60s without a successful backing-store heartbeat, the gate transitions to fail-closed for all dispatches including in-process ones. This satisfies the Fork-4 security requirement that capability grants are re-checked at every tool dispatch, not cached at session start — the 60s window is explicit and auditable, not an unbounded staleness hole.

This is not silent. Audit cardinality is bounded: one `supervisor.capability_gate_unavailable` row per outage **state-transition** (entering fail-closed AND exiting fail-closed — two rows per outage event). Per-dispatch denied rows use the family `plugin.grant.denied_backing_store_unavailable`, rate-limited at the audit writer to 1/sec/plugin_id; the per-dispatch counter is rolled into the next state-transition row so operators see cumulative denied-dispatch counts without log flooding. The user-facing message at the first deny within a 30s window is `t("capability_gate.unavailable")`; subsequent denies within the same window are silent at the user layer but the audit row counter increments.

The commit-hash at last sync is stored in a Postgres row (`capability_gate_sync`). On AlfredOS startup, the host checks if state.git HEAD differs from the cached hash; if so, it rebuilds `plugin_grants` from state.git. The rebuild is idempotent.

### 8.2 Protocol surface extension

`CapabilityGate` Protocol (`src/alfred/hooks/capability.py:56`) gains two sibling methods alongside `check`:

```python
class CapabilityGate(Protocol):
    def check(self, *, plugin_id: str, hookpoint: str, requested_tier: str) -> bool: ...

    def check_plugin_load(self, *, plugin_id: str, manifest_tier: str) -> bool:
        """Gate plugin load at handshake time. Called by AlfredPluginSession."""
        ...

    def check_content_clearance(
        self, *, plugin_id: str, hookpoint: str, content_tier: str
    ) -> bool:
        """Gate content-tier access: T3 content must not reach T2-only paths.
        Orthogonal to subscriber tier (system/operator/user-plugin).
        """
        ...
```

Content trust tier (T0-T3) and subscriber hook tier (system/operator/user-plugin) are orthogonal axes — both documented in `docs/glossary.md` (§3.1 and existing entries). `check_content_clearance` enforces the content-tier axis; `check` enforces the subscriber-tier axis. `DevGate` implements the two new methods to fail-open (returning `True`) for backward compatibility in Slice 2.5 tests — they are toggled off for the flag-day migration.

### 8.3 Reviewer-gated proposal flow for high-blast grants

Granting `system` tier requires:

1. A state.git proposal branch `proposal/policy-grant-<id>`.
2. Reviewer agent review (per PRD §6.4 — security policy changes).
3. Explicit human approval (per PRD §6.4 #4 — plugin install/remove).

`alfred plugin grant <plugin-id> system <hookpoint>` creates the proposal branch; it does NOT grant immediately. The TUI prompts the operator with the security implication (the `t("plugin.grant_prompt", plugin_id=..., tier=..., hookpoint=..., blast_radius=...)` key) and opens the reviewer-gate flow.

### 8.4 `DevGate`/`RealGate` co-existence + flag-day at end of slice

`DevGate` and `RealGate` coexist through Slice 3. `RealGate` is constructed at bootstrap when `ALFRED_ENV != development` (production default).

**Bootstrap module constraint:** `src/alfred/hooks/capability.py` is under the `test_no_direct_env_reads` AST-scan that forbids `import os` in that module. The `ALFRED_ENV` read and the `RealGate`/`DevGate` selection therefore live in `src/alfred/bootstrap/gate_factory.py` — a sibling bootstrap module that is explicitly listed as an allowed env-read site in the AST scan, with rationale. `capability.py` continues to be import-os-forbidden; it receives a constructed gate instance via dependency injection.

Slice-2.5 PR-A deny-path security tests are migrated to `RealGate` fixtures at the end of Slice 3 (the flag-day PR). `DevGate` is removed from `src/` in that same flag-day PR; its import is removed from `alfred.hooks.__init__`.

### 8.5 Grant lifecycle audit family

`plugin.grant.{requested, approved, denied, revoked}` audit rows (constants in `audit_row_schemas.py`), each carrying: `plugin_id`, `subscriber_tier`, `hookpoint`, `operator_user_id`, `proposal_branch`, `correlation_id`. (Field name is `subscriber_tier`, not `tier`, to match the manifest naming rule in §4.3.)

---

## 9. ADR-0009 comms-MCP rewrite (Fork 8)

### 9.1 MCP `CommsAdapter` Protocol + reference test plugin in Slice 3

A new `src/alfred/comms/mcp_protocol.py` defines the MCP-shaped `CommsAdapterMCP` Protocol (as distinct from the in-process `CommsAdapter` Protocol at `src/alfred/comms/`). This validates the MCP comms contract against the transport without forcing the Discord/TUI rewrite this slice.

The Slice-3 stub validates transport + handshake only. The minimum wire shape the test plugin pins:

| Direction | Method | Payload | Notes |
|---|---|---|---|
| Orchestrator → adapter | `lifecycle.start` | `{}` | Initiates adapter loop |
| Orchestrator → adapter | `lifecycle.stop` | `{}` | Graceful shutdown |
| Adapter → orchestrator | `inbound.message` | `{content: str, platform_user_id: str, language: str}` | User message event |
| Orchestrator → adapter | `adapter.health` | `{}` → `{status: "ok" \| "degraded", detail: str}` | Called by `alfred status` |

The message-contract definition (full field schema, error shapes, rate-limit signalling) is co-defined in ADR-0016 at the point Slice-4 implements the Discord rewrite; it is NOT finalized in this spec. The Slice-3 test plugin contracts only the four methods above.

**Identity-resolver placement (Slice 3):** comms-MCP plugins send raw `(platform, platform_user_id)` over the wire via `inbound.message`; the orchestrator resolves identity before invoking `_ingest_tier`. The host-side `identity.resolve` callback (where a future adapter could call the orchestrator-side resolver over MCP) is Slice 4+. This decision is explicit: keeping resolution in-process to the orchestrator in Slice 3 avoids introducing a new callback wire type before ADR-0016 is finalized.

A reference test plugin (`plugins/alfred_comms_test/`) exercises the contract: it is an MCP plugin that emits a one-shot `inbound.message` startup notification after the host's `lifecycle.start` call lands, proving the spec §9.1 `lifecycle.start` → `inbound.message` notification path. It does NOT implement a general request/response echo surface — the Slice-3 contract the integration test in `tests/integration/test_comms_mcp_contract.py` pins is "startup notification round-trip", not "every host message gets echoed back". (Renamed from `alfred-comms-test` to `alfred_comms_test` so mypy's package-discovery walker treats the directory as an importable Python package — hyphens make it invisible.)

### 9.2 Existing Discord+TUI adapters keep working in-process

`DiscordAdapter` and `TuiAdapter` (`src/alfred/comms/`) remain in-process through Slice 3, untouched. Their T2-refusal allowlists (Discord embeds/attachments/references/polls refused per ADR-0013) are unchanged.

### 9.3 T3-promotion for Discord embeds/attachments deferred to Slice 4

The current `_ALLOWLIST_FIELDS` tuple in `src/alfred/comms/discord.py` refuses eight field types: `embeds`, `attachments`, `stickers`, `reference`, `poll`, `components`, `activity`, `application`. Through Slice 3, all eight remain refused.

T3-promotion in Slice 4 covers the rich-media subset: `embeds`, `attachments`, `stickers`, `references`, `polls`, `components` — these carry user content that the quarantined LLM can extract structured data from when the Discord-adapter MCP rewrite ships alongside DLP at the transport boundary. `activity` and `application` remain **permanently refused** — they carry RPC-game payloads (Discord Rich Presence data, Application command structures) that are outside the comms-content surface and have no NL-extraction semantics.

### 9.4 ADR-0009 status flip

ADR-0009's status transitions from "Accepted" to "Superseded by ADR-0016 for new adapters; in-process adapters live through Slice 3 unchanged." The status flip lands as a single commit in the first Slice-3 PR (alongside the ADR-0009 reference update). ADR-0016 is co-merged and records: "Slice 4 rewrites TUI and Discord adapters as MCP plugins under the Slice-3 transport. This ADR records that commitment; implementation is Slice 4."

---

## 10. Supervisor (Fork 10)

### 10.1 `src/alfred/supervisor/` module shape

```
src/alfred/supervisor/
├── __init__.py        # public exports: Supervisor, BreakState, QuarantinedUnavailable
├── core.py            # Supervisor class: orchestrates all breaker instances
├── breaker.py         # CircuitBreaker: state machine + Postgres persistence
├── plugin_lifecycle.py # plugin load/crash/reload coordination
├── deadline.py        # per-orchestrator-action 30s deadline enforcement
└── errors.py          # SupervisorError, BreakStateError
```

### 10.2 Quarantined-LLM circuit breaker (3 failures / 5 min → quarantine, exponential-backoff restart)

Per PRD §6.7 Self-healing (line 324): "Plugin supervisor in `alfred-core` restarts crashed plugin subprocesses with exponential backoff and a circuit breaker (3 crashes in 5 min → quarantine + notify)." PRD §7.3 also names the supervisor (plugin supervisor restarts crashed subprocesses with exponential backoff; quarantines repeat offenders) but the 3/5min specific numbers are from §6.7.

`CircuitBreaker` state machine: `CLOSED` → (3 failures in 300s) → `OPEN` → (re-arm after 1h or operator reset) → `HALF_OPEN` → (probe succeeds) → `CLOSED`.

In `OPEN` state, quarantined-LLM invocations raise `QuarantinedUnavailable` immediately without attempting the subprocess. The orchestrator's user-facing message: `t("orchestrator.quarantine_unavailable")`.

Exponential backoff for `HALF_OPEN` restart attempts: initial 5s, multiplier 2, max 5 minutes.

### 10.3 MCP plugin lifecycle

The supervisor owns the `plugin.lifecycle.*` audit family. Every subprocess spawn, crash, and restart emits the appropriate row. The supervisor's `start_plugin()` method calls `CapabilityGate.check_plugin_load()` before spawning; a gate refusal emits `plugin.lifecycle.load_refused` and the supervisor's `plugin_id → REFUSED` state is final until the operator re-grants.

### 10.4 Capability-gate backing-store fail-closed

When the state.git or Postgres backing store is unavailable (network partition, disk failure), `RealGate` fails closed per §8.1: `check()`, `check_plugin_load()`, `check_content_clearance()` all return `False` for new dispatches immediately, and transition to fail-closed for in-process subscribers after a 60s heartbeat window. No plugin loads during a backing-store outage. Any in-flight subscriber on a revoked grant has its current dispatch denied with a `plugin.grant.revoked_inflight` audit row. The supervisor emits `supervisor.capability_gate_unavailable` and the operator-facing alert fires. An adversarial-corpus payload in `tier_laundering` covers the race between grant revocation and in-flight dispatch (compromised plugin's grant revoked mid-execution — assert dispatch denied + `plugin.grant.revoked_inflight` row).

### 10.5 Per-orchestrator-action 30s deadline

Slice 2.5's chain-deadline (250ms) is per-hookpoint chain, not per-orchestrator-action. Slice 3 introduces a per-action deadline via `asyncio.timeout(30.0)` wrapping the entire `handle_user_message` turn. The deadline is configurable in `config/policies.yaml` (`orchestrator.action_deadline_seconds`; default 30). On timeout, the supervisor emits `supervisor.action_timeout` and the orchestrator responds with `t("orchestrator.action_timeout")`.

**Timeout placement:** `asyncio.timeout(30.0)` wraps **inside** `session_scope` (the existing DB transaction context at `core.py:255-283`). When the deadline fires, the rollback arm sees `CancelledError` and audits `phase="turn_cancelled"` per the existing path at `core.py:264`. The `supervisor.action_timeout` audit row is IN ADDITION TO the existing `orchestrator.turn result="cancelled"` row — this pair distinguishes deadline-exceeded from user-cancel. The catch site for `QuarantinedUnavailable` (§5.5) also lives in `Orchestrator.handle_user_message`, at the same try/except level as the `asyncio.timeout` wrapper, ensuring the user-facing message `t("orchestrator.quarantine_unavailable")` reaches the user rather than a raw exception.

**TaskGroup ownership:** `Supervisor.start()` opens an `asyncio.TaskGroup`. Each plugin's stdio reader task joins that group. On supervisor shutdown, cancelling the group cascade-cancels all reader tasks, which SIGTERM each subprocess with a bounded grace period (5s) then SIGKILL. This follows CLAUDE.md structured-concurrency requirement and prevents task leaks when multiple plugin subprocesses (quarantined-LLM, web-fetch, comms-test) are running concurrently.

### 10.6 Breaker state persistence (Postgres, 1h re-arm)

`CircuitBreaker` state (`CLOSED`, `OPEN`, `HALF_OPEN`) + `last_trip_at` + `trip_count` is persisted to the `circuit_breakers` Postgres table. On restart: if `last_trip_at` was >1h ago, state is re-armed to `CLOSED`; otherwise stays `OPEN`. This prevents flap on rolling restarts — a quarantined LLM that tripped 30 minutes ago does not auto-clear on process restart.

### 10.7 User-facing `quarantine_unavailable` i18n key

`t("orchestrator.quarantine_unavailable")` — "I can't process external content right now; please retry in a few minutes." Added to the i18n catalog in the catalog-additions PR (§11.5) shipped as the first Slice-3 PR. Never a silent T3-self-processing fallback; the message is the hard invariant.

### 10.8 `alfred supervisor reset` operator-tier T1 command

`alfred supervisor reset <component>` is an operator-tier T1 CLI command. It calls `Supervisor.reset_breaker(component_id)`, which transitions the named circuit breaker from `OPEN` to `CLOSED` and emits `supervisor.breaker.reset` audit row with `operator_user_id` attribution. The command is gated on T1 ingress (§3.6): it requires TUI + operator role.

---

## 11. Operator configuration surface (Fork 11)

### 11.1 High-blast in state.git (reviewer-gated)

The following changes require state.git proposal + reviewer-gate + human approval (PRD §6.4):

- Web-fetch domain allowlist additions (`alfred web allowlist add <domain>`).
- Plugin capability grants (`alfred plugin grant <plugin-id> <tier> <hookpoint>`).
- Quarantined-provider choice (`alfred config quarantined-provider <provider>`).

These are security-policy changes per PRD §6.4 #3; they widen the trust surface and must not be operator-direct.

### 11.2 Low-blast in `config/policies.yaml` (hot-reload)

The following changes land in `config/policies.yaml` and hot-reload without a reviewer gate:

- User-Agent string (`web_fetch.user_agent`; default: `AlfredOS/<version>`).
- Per-domain rate-limit overrides (`web_fetch.rate_limits.<domain>`).
- Per-user daily fetch budget (`web_fetch.user_daily_budget`; default 100).
- Operator daily fetch budget (`web_fetch.operator_daily_budget`; default unlimited).
- Extraction max retries (`quarantine.extraction_max_retries`; default 2).
- Per-orchestrator-action deadline (`orchestrator.action_deadline_seconds`; default 30).

These narrow or tune within the existing trust surface; they cannot widen it.

### 11.3 CLI surface

| Command | Blast radius | Storage |
|---|---|---|
| `alfred plugin grant <id> <tier> <hookpoint>` | High | state.git (reviewer-gated) |
| `alfred plugin grant status <id>` | Read-only | state.git + Postgres |
| `alfred plugin grant list --pending` | Read-only | state.git + Postgres |
| `alfred plugin list` | Read-only | Postgres projection |
| `alfred plugin show <id>` | Read-only | Postgres projection |
| `alfred web allowlist add <domain>` | High | state.git (reviewer-gated) |
| `alfred web allowlist remove <domain>` | High | state.git (reviewer-gated) |
| `alfred web allowlist list` | Read-only | Postgres projection |
| `alfred config quarantined-provider <provider>` | High | state.git (reviewer-gated) |
| `alfred config web-fetch-budget <user> <n>` | Low | `config/policies.yaml` |
| `alfred supervisor status` | Read-only | Postgres (breaker states) |
| `alfred supervisor reset <component> --confirm` | Operator T1 | Postgres + audit |
| `alfred audit graph --tier T3 --since 24h` | Read-only | Postgres audit log |
| `alfred audit graph --tier T1 --since 24h` | Read-only | Postgres audit log |

All command output strings route through `t()` (CLAUDE.md i18n rule #1).

**Reviewer-gated command async UX:** `alfred plugin grant`, `alfred web allowlist add`, and `alfred config quarantined-provider` are asynchronous — they queue a proposal and do NOT apply immediately. On success, they:

1. Print the proposal branch name: `Proposal queued at proposal/policy-grant-<id>.`
2. Print the follow-up discovery command: `Run 'alfred plugin grant status <id>' to track approval.`
3. Use the i18n key `cli.plugin.grant.pending_review` (not `cli.plugin.grant.success` — the grant is not yet active). Reserve `cli.plugin.grant.success` for when a previously-queued grant is approved (i.e., the reviewer-gate merges the proposal).

The same pattern applies to `alfred web allowlist add` (`cli.web.allowlist.pending_review`) and `alfred config quarantined-provider` (`cli.config.quarantined_provider_pending_review`).

**`alfred supervisor reset` confirmation gate:** the command requires `--confirm` (or interactive prompt for TTY invocations) before clearing a circuit breaker. The confirm prompt uses `cli.supervisor.reset.confirm_prompt` showing trip count + last-trip-at. The `alfred supervisor status` command lists all supervisor-managed components and their breaker states, giving operators the discovery path: `quarantine_unavailable` error → `alfred supervisor status` → `quarantined-llm: OPEN (12 trips, last 15m ago)` → `alfred supervisor reset quarantined-llm --confirm`.

### 11.4 Per-user daily fetch budget defaults

User-tier default: 100 fetches/day. Operator-tier default: unlimited. Both configurable in `config/policies.yaml` (low-blast). Per-user override: `alfred config web-fetch-budget <user> <n>` writes to `config/policies.yaml`. Extending this to per-user-per-day tokens (PRD §6.5 pattern) is deferred to Slice 4.

### 11.5 i18n catalog-additions PR shipped first

The i18n catalog-additions PR ships as the first Slice-3 PR, adding all new `t()` keys used across all 11 forks. Each key ships with its canonical English body + `Translators:` context comments where placeholder names are ambiguous.

**Action keys:**

- `cli.plugin.grant.{pending_review, denied, confirm_prompt}` — async-UX keys; `success` reserved for reviewer-approved path (not Slice-3)
- `cli.plugin.grant.status.{pending, approved, denied, expired}`
- `cli.web.allowlist.{pending_review, added, removed}`
- `cli.config.{quarantined_provider_pending_review, web_fetch_budget_set}`
- `cli.supervisor.reset.{confirm_prompt, success, component_not_found}`

**List/table column keys (per `cli.user.list.column.*` precedent):**

- `cli.plugin.list.column.{plugin_id, subscriber_tier, status, manifest_version}` + `cli.plugin.list.empty_hint`
- `cli.plugin.show.field.{plugin_id, manifest_version, sandbox_profile, hookpoints, grants, last_lifecycle_event}`
- `cli.web.allowlist.list.column.{domain, path_prefix, granted_by, granted_at}` + `cli.web.allowlist.list_empty`
- `cli.supervisor.status.column.{component, state, trip_count, last_trip_at}` + `cli.supervisor.status.empty_hint`
- `cli.supervisor.status.breaker_state.{open, closed, half_open}`

**WebFetchError message keys (§7.10 — "All error strings route through `t()`"):**

- `web.fetch.error.domain_not_allowed`
- `web.fetch.error.tls_failure`
- `web.fetch.error.rate_limited`
- `web.fetch.error.mime_type_not_allowed`
- `web.fetch.error.size_limit_exceeded`

**System / bootstrap keys:**

- `bootstrap.quarantined_provider_same_as_privileged`
- `orchestrator.quarantine_unavailable`
- `orchestrator.action_timeout`
- `security.tag_t3_unauthorized`
- `security.tier_mismatch`
- `security.canary_tripped`
- `capability_gate.unavailable`
- `plugin.manifest_version_mismatch`
- `plugin.launcher_no_sandbox_policy`
- `plugin.grant_prompt`
- `quarantine.schema_version_missing`
- `bootstrap.capability_gate_unseeded` — shown when state.git/Postgres backing not yet seeded; includes next-step text pointing to `alfred plugin grant init`

**Quarantined-LLM system prompt and `{user.language}`:** The quarantined-LLM system prompt is an extraction-worker prompt (not a persona prompt); it drives structured JSON extraction, not user-facing NL generation. The prompt does NOT honour `{user.language}` — its output is structured data (`T3DerivedData`), not user-facing text, so language injection is not applicable. The orchestrator's persona prompt (which IS user-facing) re-stringifies structured output fields in the user's language when rendering the final response. This is an explicit decision: quarantined-LLM system prompt is out of scope for CLAUDE.md i18n rule #2.

The catalog-additions PR is a prerequisite for all fork implementation PRs. It runs `pybabel extract` + `pybabel compile --check` as its sole quality gate; CI enforces this on every subsequent PR. The catalog-additions PR ships the listed keys with canonical English copy; copy editorial review happens in the implementing fork PR, not the gate-PR.

---

## 11a. Coverage commitments

Every PR that touches a trust-boundary file enforces 100% line+branch coverage on that file via `coverage --fail-under` in the per-file allowlist (mirroring the Slice-2.5 `coverage --fail-under` pattern). The trust-boundary files and their owning PRs:

| File | Owning PR |
|---|---|
| `src/alfred/security/tiers.py` — `tag(T3, ...)` gate | PR-S3-1 |
| `src/alfred/security/quarantine.py` — `quarantined_to_structured` | PR-S3-4 |
| `src/alfred/hooks/capability.py` — `CapabilityGate.check_plugin_load`, `check_content_clearance` | PR-S3-2 |
| `src/alfred/plugins/stdio_transport.py` — `StdioTransport.dispatch` outbound/inbound DLP | PR-S3-3a |
| `src/alfred/plugins/inbound_scanner.py` — `InboundContentScanner.scan` | PR-S3-3a |
| `src/alfred/plugins/inbound_canary_scanner.py` — `InboundCanaryScanner.scan` | PR-S3-5 |
| `src/alfred/security/quarantine.py` — `downgrade_to_orchestrator` | PR-S3-4 |

The cross-fork integration test (§12.4) is a separate gate — it asserts chain behavior, not line coverage.

---

## 12. Adversarial corpus (Fork 9)

### 12.1 Adversarial category additions

The existing `payload_schema.py` ships `prompt_injection` (prefix `pi`) and `dlp` (prefix `dlp`). Slice 3 reuses the existing `prompt_injection` category and adds two new categories:

| Category | Status | Attack family | Forward-compat |
|---|---|---|---|
| `prompt_injection` | Existing (reused) | Injected instructions in fetched T3 content | Email, RAG retrievers add payloads in Slice 4+ |
| `tier_laundering` | New (prefix `tl`) | T3 content posing as T2 / cast-bypass | New T3 ingesters add payloads in Slice 4+ |
| `dlp_egress` | New (prefix `de`) | T3-origin credential exfiltration paths | New channels add payloads as they ship |

The existing `dlp` category covers DLP-scan mechanics broadly; `dlp_egress` is a distinct sibling covering T3-specific exfiltration (canary propagation through quarantined LLM into structured output, cross-field secret leak, env-leak via misconfigured launcher). Category-per-attack-family (not per-surface) is forward-compat-correct: when `email.read` lands in Slice 4, it adds payloads to `prompt_injection` and `tier_laundering`, not a new category.

### 12.2 `payload_schema.py` closed-set Literal edit

The closed-set `Category` literal in `tests/adversarial/payload_schema.py` gains two new members (`tier_laundering`, `dlp_egress`). The `_PREFIX_TO_CATEGORY` and `_ID_PATTERN` dicts gain `tl` (tier_laundering) and `de` (dlp_egress) prefixes. The existing `pi` (prompt_injection) prefix is already present and is not re-added. The `.rulesync/skills/alfred-adversarial-corpus/SKILL.md` is updated with one row per new category. This PR ships first in Slice 3 (before any fork's implementation PR), establishing the schema that implementation PRs' adversarial tests reference.

**Explicit schema field additions (all required in PR-S3-0):**

`Category` Literal additions: `tier_laundering`, `dlp_egress`.

`IngestionPath` Literal extensions (new values, existing values preserved):

- `stdio_transport.outbound` — frames written to subprocess stdin
- `stdio_transport.inbound` — frames read from subprocess stdout
- `cast_bypass` — `cast(TaggedContent[T2], t3_value)` type-level attack
- `wire_format_deser` — malformed JSON-RPC tier field on the wire
- `capability_gate` — capability-gate bypass attempt
- `secret_broker` — secret leaked via env or manifest

`ExpectedOutcome` Literal additions:

- `boundary_refused` — the `tag(T3, ...)` from unauthorised caller disposition
- `audit_row_emitted` — asserts a specific named audit row exists (used for manifest-broadening-capped checks)

**Fixture-vs-pytest allocation:** The following adversarial assertions ship as **pytest modules** under `tests/adversarial/tier_laundering/test_*.py` (not YAML payloads), because they require Python-level code execution that YAML payloads cannot express:

- `cast(TaggedContent[T2], t3_value)` bypass — tests Python type system
- Frame-introspection bypass (monkey-patch `sys.modules`) — requires import manipulation
- Post-handshake hook registration attack — requires a live subprocess

All other `tier_laundering` and `dlp_egress` cases ship as YAML payloads with `payload: str | dict`.

**Category disambiguation:** `dlp_egress` = T3-origin exfiltration paths; `dlp` = T0/T1/T2-origin DLP mechanics. Future contributors adding T3-origin exfiltration cases use `dlp_egress`; non-T3 DLP tests use the existing `dlp` category.

### 12.3 Per-provider recorded fixtures for `prompt_injection`

`prompt_injection` payloads include:

- Fetched HTML with injected instructions in `<meta>`, JS comments, `display:none` CSS, alt-text, and microformats.
- Per-provider variants (DeepSeek/Anthropic/OpenAI) as recorded LLM fixtures (not live calls), matching the existing `tests/adversarial/` pattern.
- Assertion: the structured `ExtractionResult` data field does not contain the injected instruction string.

`tier_laundering` payloads include:

- Schema-valid but semantically poisoned structured output (a valid `Title` field containing instructions).
- `T3DerivedData` provenance marker survival test (verifying `type(result.data)` is `T3DerivedData`, not plain `dict`, through `quarantined_to_structured` and through a DB write/read roundtrip — the NewType must survive serialisation).
- Wire-format tier confusion (`TaggedContent` JSON with mismatched `tier` field).
- `cast(TaggedContent[T2], t3_value)` bypass attempt — pytest module, not YAML (§12.2 fixture allocation).
- Capability-gate bypass: a plugin manifesting `subscriber_tier=user-plugin` requesting `system` tier on a T3-carrying hookpoint.
- Post-handshake hook registration attack: a compromised plugin sends `alfred/hooks.register` after the handshake completes — assert SIGKILL + `plugin.lifecycle.quarantined` audit row, and that no hook gets registered. Pytest module.
- In-flight revocation race: a plugin's grant is revoked mid-execution — assert dispatch denied + `plugin.grant.revoked_inflight` audit row.
- Retry-guidance hygiene: replay a malformed-output corpus through the prompt-embedded fallback path; assert the second-turn prompt token set is a subset of `{validator-error tokens} ∪ {schema-JSON tokens} ∪ {fixed-instruction-template tokens}`. References `QuarantinedExtractor._build_retry_prompt()` directly. Pytest module.

`dlp_egress` payloads include:

- Canary token planted in T3 web content propagating through quarantined LLM into structured output → DLP scan → audit row.
- Cross-field secret leak via headers + cookies in a web request.
- Subprocess env-leak via misconfigured launcher (missing explicit `env=` dict).
- Manifest allowlist broadening: malicious manifest update declares wider `allowed_domains` — assert `web.allowlist.manifest_broadening_capped` audit row fires and the broadened domain is not reachable.

### 12.4 Cross-fork integration tests gate slice merge

The cross-fork chain is exercised by **two separate test files** with distinct gate statuses:

**`tests/integration/test_quarantined_chain_security.py`** — merge-blocking security assertions:

- `hasattr(ContentHandle, 'content') is False` — orchestrator cannot dereference handle to bytes.
- A T3 fragment from the recorded fixture does NOT appear verbatim in `Extracted.data` values (prompt-injection neutralisation, per §6.3 and §12.3 invariant at the integration layer).
- The audit row for the chain carries `trust_tier_of_trigger="T3"` per §6.8.
- `type(result.data)` is `T3DerivedData` at runtime (not plain `dict`) — §3.7 NewType survives through the chain.
- A recorded canary-token fixture triggers `WebFetchCanaryTripped` BEFORE `quarantine.extract` is invoked (not after, not alongside).

**`tests/integration/test_quarantined_chain_latency.py`** — performance gate (advisory, not merge-blocking in Slice 3):

- End-to-end latency for the quarantined extraction chain ≤ 5s (generous for the subprocess hop; the Slice-2.5 perf gate's 1ms five-chain budget is for the hook dispatcher only).
- Extraction mode recorded correctly in audit row.

Only the security test (`test_quarantined_chain_security.py`) gates the Slice-3 merge. Both tests must pass across all three provider-fixture variants.

---

## 13. Audit row schemas

`src/alfred/audit/audit_row_schemas.py` ships as a standalone module (in PR-S3-0a) before any fork's implementation PR. It defines field-list constants for all Slice-3 audit row families. **Placement rationale:** Slice 3 introduces five emitter subsystems (`plugins/`, `supervisor/`, `security/`, `orchestrator/`, `identity/`). Centralising constants in `src/alfred/audit/` provides a single import surface that prevents field-name drift across subsystems; the Slice-2.5 co-located-with-emitter pattern is superseded here because the emitter count crossed the threshold where mirroring becomes rot. The `alfred.audit` package's `__init__.py` re-exports: `audit_row_schemas`, `AuditWriter`, and `AuditEntry` — no subsystem needs to import deeper than `from alfred.audit import audit_row_schemas`.

**Alembic migrations (all named; assigned to owning PRs):**

| Migration | Table / domain | PR |
|---|---|---|
| `0007_audit_result_slice3_values.py` | Extends `ck_audit_log_result` CHECK constraint with new `result` values | PR-S3-0b |
| `0008_plugin_grants.py` | Creates `plugin_grants` table (Postgres projection of state.git grants) | PR-S3-0b |
| `0009_capability_gate_sync.py` | Creates `capability_gate_sync` table (commit-hash cache for RealGate) | PR-S3-0b |
| `0010_circuit_breakers.py` | Creates `circuit_breakers` table (breaker state + trip history) | PR-S3-3b |

Migration `0007` extends `ck_audit_log_result` with: `extracted`, `malformed_exhausted`, `load_refused`, `crashed`, `quarantined`, `reloaded`, `requested`, `approved`, `denied`, `revoked`, `tripped`, `reset`, `content_expired`. Downgrade for `0007`: revert the CHECK constraint to the Slice-2.5 result-value list (remove the 13 values added above). Downgrade semantics for `0008`/`0009`: DROP TABLE (data is rebuildable from state.git or can be re-derived). Downgrade for `0010`: DELETE all circuit_breakers rows then DROP TABLE (breaker state is transient; downgrade forgets trips, which is safe — the next run re-discovers failures). SQLAlchemy 2.0 typed models for all three tables land in `src/alfred/memory/models.py` alongside the migrations, following the existing `Episode` + `AuditEntry` declarative convention.

```python
# src/alfred/audit/audit_row_schemas.py
from typing import Final

# plugin.lifecycle.* family — union over loaded/refused/crashed/quarantined/reloaded
# crashed rows additionally carry exception_type (Python type name only, never str(exc))
PLUGIN_LIFECYCLE_FIELDS: Final = frozenset({
    "plugin_id", "manifest_subscriber_tier", "manifest_version",
    "sandbox_profile", "exit_code", "signal", "restart_count",
    "breaker_state", "correlation_id",
})
# crashed-specific additions (§5.6):
PLUGIN_LIFECYCLE_CRASHED_FIELDS: Final = PLUGIN_LIFECYCLE_FIELDS | frozenset({
    "exception_type",  # Python type name only — never str(exc) or exc.args (T3 fragment risk)
})

# plugin.grant.* family
PLUGIN_GRANT_FIELDS: Final = frozenset({
    "plugin_id", "subscriber_tier", "hookpoint", "operator_user_id",
    "proposal_branch", "correlation_id",
})

# quarantine.extract family
QUARANTINE_EXTRACT_FIELDS: Final = frozenset({
    "extraction_mode", "provider", "schema_name", "schema_version",
    "retry_count", "trust_tier_of_trigger", "result", "correlation_id",
})

# tool.web.fetch family
WEB_FETCH_FIELDS: Final = frozenset({
    "url", "domain", "status_code", "content_handle_id",
    "fetch_depth", "rate_limit_bucket", "manifest_commit_hash",
    "trust_tier_of_result", "dlp_scan_result", "canary_tripped",
    "triggering_user_id",  # canonical_user_id of conversation turn; for per-user audit attribution
    "correlation_id",
})

# supervisor.breaker.reset family (sibling SUPERVISOR_BREAKER_TRIPPED_FIELDS
# covers the breaker.tripped event — distinct hookpoints per §14)
SUPERVISOR_BREAKER_RESET_FIELDS: Final = frozenset({
    "component_id", "old_state", "new_state", "trip_count",
    "operator_user_id", "correlation_id",
})

# T3 boundary refusals
T3_BOUNDARY_REFUSAL_FIELDS: Final = frozenset({
    "caller_module_unverified",  # heuristic frame-derived label; NOT an authenticated identity (see §3.2)
    "attempted_tier", "hookpoint", "correlation_id",
})

# T1 ingress — emitted at identity.t1_ingress hookpoint (role × adapter classification)
T1_INGRESS_FIELDS: Final = frozenset({
    "user_id", "adapter_name", "trust_tier_of_trigger", "correlation_id",
})

# T1 downgrade — emitted at identity.t1_downgrade hookpoint (explicit T1 → T2 broadcast-safe conversion)
T1_DOWNGRADE_FIELDS: Final = frozenset({
    "user_id", "trust_tier_of_trigger",
    "trust_tier_of_response", "downgrade_explicit", "correlation_id",
})

# plugin.grant.revoked_inflight — grant revoked while dispatch in-flight
PLUGIN_GRANT_REVOKED_INFLIGHT_FIELDS: Final = frozenset({
    "plugin_id", "hookpoint", "operator_user_id",
    "in_flight_dispatch_id", "correlation_id",
})

# supervisor.capability_gate_unavailable — one row per state-transition (entering/exiting fail-closed)
SUPERVISOR_CAPABILITY_GATE_UNAVAILABLE_FIELDS: Final = frozenset({
    "state_transition",   # "entering_fail_closed" | "exiting_fail_closed"
    "denied_dispatch_count",   # cumulative count since entering fail-closed (on exit row only)
    "backing_store_error_type",
    "correlation_id",
})

# supervisor.config_insecure — emitted at every plugin start when ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED=1
SUPERVISOR_CONFIG_INSECURE_FIELDS: Final = frozenset({
    "insecure_config_key",   # e.g. "ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED", "web_fetch.skip_tls_verify"
    "plugin_id",             # present for per-plugin-launch rows; absent for startup warnings
    "correlation_id",
})

# supervisor.action_timeout — one row per turn that exceeds orchestrator.action_deadline_seconds
SUPERVISOR_ACTION_TIMEOUT_FIELDS: Final = frozenset({
    "user_id", "action_duration_seconds", "deadline_seconds",
    "phase_at_timeout",   # "web_fetch" | "quarantine_extract" | "hookchain" | "unknown"
    "correlation_id",
})

# web.allowlist.manifest_broadening_capped — on every manifest load where effective allowlist < manifest allowlist
WEB_ALLOWLIST_MANIFEST_BROADENING_CAPPED_FIELDS: Final = frozenset({
    "plugin_id", "manifest_domains", "operator_allowed_domains",
    "capped_domains",   # domains in manifest but not in operator config
    "correlation_id",
})

# security.dlp_outbound_refused — outbound DLP scan failure
DLP_OUTBOUND_REFUSED_FIELDS: Final = frozenset({
    "wire", "direction", "scan_rule_matched", "field_name",
    "correlation_id",
})

# supervisor.breaker.tripped — distinct from breaker.reset (§14 hookpoint table)
SUPERVISOR_BREAKER_TRIPPED_FIELDS: Final = frozenset({
    "component_id", "trip_count", "last_failure_type",
    "breaker_state",   # always "OPEN" at trip time
    "correlation_id",
})
```

The `_SUBSCRIBER_ERROR_AUDIT_FIELDS` pattern from Slice 2.5 is reused: each audit row family carries only the explicitly enumerated fields. `str(exc)` and `exc.args` are never included (they may carry T3 fragments per §5.6).

---

## 14. Hookpoint surface (cross-cutting table)

Every new Slice-3 hookpoint declared via `register_hookpoint`. All hookpoints use dotted-action-name form (the Slice-2.5 convention — e.g. `tool.web.fetch`, not `pre.web.fetch`). `kind` (`pre`, `post`, `error`, `cancel`) is passed as a separate argument to `invoke()` — it is NOT encoded into the hookpoint name. All hookpoints are invoked via the Slice-2.5 `invoke()` primitive at `src/alfred/hooks/invoke.py`.

| Action (hookpoint name) | Applicable kinds | `subscribable_tiers` | `refusable_tiers` | `fail_closed` |
|---|---|---|---|---|
| `tool.web.fetch` | pre, post, error, cancel | `SYSTEM_ONLY_TIERS` | `SYSTEM_ONLY_TIERS` (pre/post only) | `True` |
| `security.quarantined.extract` | pre, post, error | `SYSTEM_OPERATOR_TIERS` | `SYSTEM_ONLY_TIERS` (pre/post only) | `True` |
| `plugin.lifecycle.loaded` | post | `SYSTEM_ONLY_TIERS` | — | `False` |
| `plugin.lifecycle.crashed` | error | `SYSTEM_ONLY_TIERS` | — | `False` |
| `plugin.lifecycle.quarantined` | post | `SYSTEM_ONLY_TIERS` | — | `False` |
| `plugin.grant.requested` | post | `SYSTEM_ONLY_TIERS` | — | `False` |
| `plugin.grant.approved` | post | `SYSTEM_ONLY_TIERS` | — | `False` |
| `plugin.grant.denied` | post | `SYSTEM_ONLY_TIERS` | — | `False` |
| `plugin.grant.revoked` | post | `SYSTEM_ONLY_TIERS` | — | `False` |
| `supervisor.breaker.tripped` | post | `SYSTEM_ONLY_TIERS` | — | `False` |
| `supervisor.breaker.reset` | post | `SYSTEM_OPERATOR_TIERS` | — | `False` |
| `supervisor.action_timeout` | error | `SYSTEM_ONLY_TIERS` | — | `False` |
| `security.t3_boundary.refused` | post | `SYSTEM_ONLY_TIERS` | — | `False` |
| `identity.t1_ingress` | post | `SYSTEM_OPERATOR_TIERS` | — | `False` |
| `identity.t1_downgrade` | post | `SYSTEM_OPERATOR_TIERS` | — | `False` |

`SYSTEM_ONLY_TIERS` and `SYSTEM_OPERATOR_TIERS` are the named constants from `src/alfred/hooks/registry.py:320,309`. Every hookpoint is declared in the module that owns the action; no cross-module hookpoint declarations. The `fail_closed` column reflects the **single scalar** the registry stores per hookpoint (§6.5): `invoke()` applies that scalar uniformly to every kind. A per-kind `fail_closed` override — distinguishing e.g. pre/post fail-closed from error/cancel fail-open on the same hookpoint — would require a registry refactor and is **not implemented**. Tracked at [#167](https://github.com/alfred-os/AlfredOS/issues/167).

---

## 15. Migration / flag-day strategy

### 15.1 `DevGate` → `RealGate` at end of slice

`DevGate` and `RealGate` coexist through Slice 3. The final Slice-3 PR (the flag-day PR) removes `DevGate` from `src/`, migrates Slice-2.5 deny-path security tests to `RealGate` fixtures, removes `DevGate` from `alfred.hooks.__init__`, and updates the Slice-2.5 spec §6.2 reference to `DevGate` with a "see §8.4 for migration" note. The flag-day PR must pass all existing deny-path coverage.

### 15.2 ADR-0009 status flip

ADR-0009 transitions to "Superseded by ADR-0016 for new adapters; in-process adapters unchanged through Slice 3." (ADR-0016 is co-merged with the first Slice-3 PR; the file does not yet exist at spec-write time.) The flip lands in the first Slice-3 PR as a single ADR header edit.

### 15.3 Slice-2.5 §6.10 §6.11 tracking issues retired

The Slice-2.5 spec §6.10 "Deferred to Slice 3" items:

- Real manifest-driven `CapabilityGate` + install prompt → delivered in §8 (Fork 7) of this spec.
- MCP-transport hook registration → delivered in §4 (Fork 2) of this spec.
- Data-classification tags per hookpoint → delivered in §3 (Fork 3/6) via `check_content_clearance`.

The Slice-2.5 spec §6.11 "Out of scope" items (supply-chain signing, ContextVar guards) remain out of scope. The tracking issues for §6.10 items are retired in the first Slice-3 PR.

### 15.4 Operator migration runbook (Slice 2 → Slice 3)

**Upgrade order:**

1. Run `docker compose pull && docker compose build`.
2. Run `alfred plugin grant init` — seeds `/var/lib/alfred/state.git` (idempotent: `git init --bare` if no HEAD, empty `main` branch with initial commit). Skipping this step causes every plugin load to fail with `t("bootstrap.capability_gate_unseeded")`.
3. Run `uv run alembic upgrade head` — applies migrations `0007` through `0010`.
4. Run `alfred status` — should show `gate: RealGate (state.git: ok, postgres: ok)`.
5. Run `alfred supervisor status` — should show all registered plugins in `CLOSED` state.

**What `alfred status` shows in each mode:**

| Condition | `alfred status` line |
|---|---|
| `ALFRED_ENV=development`, `DevGate` active | `gate: DevGate (development mode — not for production)` |
| `ALFRED_ENV=production`, `RealGate`, backing store ok | `gate: RealGate (state.git: ok, postgres: ok)` |
| `ALFRED_ENV=production`, backing store unavailable | `gate: RealGate (FAIL-CLOSED — backing store unavailable)` |
| state.git not seeded | `gate: RealGate (UNSEEDED — run 'alfred plugin grant init')` |

**If the operator skips `alfred plugin grant init`:** every plugin start (quarantined-LLM, web-fetch) emits `plugin.lifecycle.load_refused` with `t("bootstrap.capability_gate_unseeded")`. The user-facing message on `alfred chat` is `t("capability_gate.unavailable")`. The fix is `alfred plugin grant init` followed by `alfred supervisor reset quarantined-llm --confirm`.

---

## 16. Open questions resolved

All open questions from the synthesis (`.slice-3-synthesis.md §2`) are resolved here.

**Fork 1:** Provider for quarantined LLM: **different provider from privileged** (defence-in-depth; PRD §6.4 reviewer-agent requirement). `QuarantinedUnavailable` is distinct from `HookSubscriberError`. Audit-field discipline: name + type only, never `str(exc)`. Quarantined system prompt versioning: in the plugin manifest.

**Fork 2:** `bin/alfred-plugin-launcher` ADR: follow-on ADR (OS-dependent sandbox); stub fail-closes when policy absent. Plugin lifecycle audit family: confirmed as `plugin.lifecycle.{loaded, load_refused, crashed, quarantined, reloaded}`.

**Fork 3:** Wire-format serializer: `tier.name` string, re-resolved via `_APPROVED_TIERS` on parse. `cast()` escape-hatch policy: ruff/grep CI rule enforced.

**Fork 4:** Response body size: 5MB default. MIME allowlist: text/html, text/plain, application/json, application/xml, text/markdown. Caching: respect HTTP cache headers + Redis semantic cache. Robots.txt TTL: 24h. Per-domain rate-limit default: 10/min. User-Agent: `AlfredOS/<version>`. Egress allowlist granularity: `(domain, path-prefix)` tuples.

**Fork 5:** `schema_version: Literal[1]` mandatory. Typed refusal: `ExtractionResult = Annotated[Extracted | TypedRefusal, Field(discriminator='kind')]` with `reason: Literal['cannot_extract' | 'refused_by_safety' | 'ambiguous_input']`.

**Fork 6:** T1-default commands: `alfred user`, `alfred memory rollback`, `alfred plugin grant`, `alfred web allowlist`, `alfred audit`, `alfred supervisor reset`. T2-default: `alfred chat`, `alfred status`. `alfred cost report` is Slice 4+ per existing slice schedule — not in Slice 3's T2-default list. T1 outbound: TUI stdout only for Slice 3. Audit-row carry-over: a T1-triggered turn that produces a T2 outbound (explicit downgrade) writes `trust_tier_of_trigger="T1"`, `trust_tier_of_response="T2"`, `downgrade_explicit=True` (see §3.6 + §13 T1_INGRESS_FIELDS). `alfred audit graph` gains `--tier T1` and `--tier T3` filters (accepting uniform tier values) alongside the existing time filter; the T3 audit swimlane is in §11.3; the T1 swimlane is the same command with `--tier T1`.

**Fork 7:** Grant lifecycle audit: `plugin.grant.{requested, approved, denied, revoked}`. `DevGate` migration: co-exist through Slice 3, flag-day removes at end. High-blast grants: reviewer-gated proposal + explicit human approval.

**Fork 8:** Slice 3 ships MCP `CommsAdapter` Protocol stub + reference test plugin. ADR-0009 status flips to Superseded.

**Fork 9:** Per-provider `prompt_injection` variants: recorded fixtures. Cross-fork integration test: `tests/integration/` (performance contract, not security boundary).

**Fork 10:** `web.fetch` unavailability: refuse loudly (user-visible error; degraded-knowledge fallback deferred to Slice 5+). Operator-clear command: `alfred supervisor reset <component>` — T1 command, `supervisor.breaker.reset` audit row.

**Fork 11:** Per-user daily fetch budget: 100 fetches/day user-tier default, unlimited operator. CLI i18n keys: `cli.plugin.grant.*`, `cli.web.allowlist.*`, etc. (§11.5).

---

## 17. PR breakdown (preview)

The `superpowers:writing-plans` skill owns the formal plan suite. This section is a preview to bound scope expectations.

1. **PR-S3-0a — Docs-only foundations (first PR, unblocks PR-S3-0b and PR-S3-1):**
   - **ADR-0017** (`docs/adr/0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md`) — the load-bearing Slice-3 ADR that supersedes ADR-0008 and ADR-0013. Pre-commits PR-S3-0 split into PR-S3-0a/0b and PR-S3-3 split into PR-S3-3a/3b.
   - ADR-0008 and ADR-0013 status fields updated to "Superseded by ADR-0017".
   - ADR-0009 status flip ("Superseded by ADR-0016 for new adapters").
   - ADR-0015 + ADR-0016 stubs co-merged.
   - **PRD §5 line 117 amendment** co-merged with ADR-0017 (hybrid isolation language per §5.7).
   - `src/alfred/audit/audit_row_schemas.py` constants module (all Slice-3 audit row families + migration table per §13).
   - `tests/adversarial/payload_schema.py` Literal additions (`tier_laundering`, `dlp_egress`; `prompt_injection` already exists). Includes `IngestionPath` + `ExpectedOutcome` Literal extensions per §12.2.

2. **PR-S3-0b — Schema/infra foundations (gated on PR-S3-0a; unblocks all implementation PRs):**
   - Alembic migrations `0007_audit_result_slice3_values.py`, `0008_plugin_grants.py`, `0009_capability_gate_sync.py` + SQLAlchemy 2.0 typed models in `src/alfred/memory/models.py`.
   - i18n catalog-additions (all Slice-3 `t()` keys per §11.5).
   - **Infrastructure additions:** `docker/alfred-core.Dockerfile` — add `git` package + `useradd alfred-quarantine`; `docker-compose.yaml` — named volume `alfred_state_git` at `/var/lib/alfred` + `alfred-redis` service (Redis 7, internal-only, `volatile-lru`, AOF persistent, healthcheck `redis-cli ping`); `bin/alfred-setup.sh` — idempotent `git init --bare` + seed `main` branch step (per §15.4).
   - Redis key-pattern registry (added to §7.7): `alfred:content:{handle_id}` (TTL per §7.2), `alfred:rate:{domain}`, `alfred:rate:user:{user_id}`, `alfred:fetch_budget:{user_id}:{YYYY-MM-DD}` (TTL=48h), `alfred:robots:{domain}` (TTL=24h). `maxmemory-policy=volatile-lru`.

3. **PR-S3-1 — Trust tiers T1+T3 + wire format:**
   - `T1`, `T3` classes in `src/alfred/security/tiers.py`; `_APPROVED_TIERS` update.
   - `AnyTaggedContent` Protocol.
   - Wire-format serializer + cross-tier rejection.
   - `tag(T3, ...)` capability-gated overload (per-process nonce token shape per §3.2).
   - `src/alfred/security/quarantine.py` stub with `quarantined_to_structured` signature.
   - Adversarial corpus payloads for `tier_laundering`.

3. **PR-S3-2 — Real `CapabilityGate`:**
   - `RealGate` implementation; `CapabilityGate.check_plugin_load` + `check_content_clearance` additions.
   - `DevGate` co-existence (no flag-day yet).

4. **PR-S3-3a — MCP plugin transport (transport-only split per §1.3):**
   - `src/alfred/plugins/` package: `PluginTransport` Protocol, `StdioTransport`, `AlfredPluginSession`, `DispatchResult` discriminated union.
   - `bin/alfred-plugin-launcher` stub (fail-closed + `ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED=1` dev escape hatch).
   - `src/alfred/identity/_ingest.py` — `_ingest_tier()` function.

5. **PR-S3-3b — Supervisor (supervisor-only split per §1.3):**
   - `src/alfred/supervisor/` package: `Supervisor`, `CircuitBreaker`, `plugin_lifecycle`, `deadline`.
   - Alembic migration `0010_circuit_breakers.py` + SQLAlchemy 2.0 typed model.
   - Per-action deadline (`asyncio.timeout` inside `session_scope`) + `asyncio.TaskGroup` subprocess lifecycle per §10.5.
   - `alfred_orchestrator_action_duration_seconds` Prometheus histogram + OTel sub-spans.
   - Plugin lifecycle audit rows wired.

6. **PR-S3-4 — Dual-LLM split (quarantined-LLM plugin):**
   - `plugins/alfred-quarantined-llm/` in-tree MCP plugin.
   - `QuarantinedExtractor` + `Provider.capabilities()` routing (adds `capabilities()` to `AnthropicProvider` + `DeepSeekProvider`).
   - `quarantined_to_structured` full implementation.
   - `JSON_OBJECT_MODE` capability + `json_object_unconstrained` extraction mode.
   - Adversarial corpus payloads for `prompt_injection`.

7. **PR-S3-5 — `web.fetch` plugin:**
   - `plugins/alfred-web-fetch/` in-tree MCP plugin.
   - `ContentHandle` + content store (Redis, key `alfred:content:{handle_id}`).
   - `InboundCanaryScanner` as system-tier hook subscriber.
   - `WebFetchError` hierarchy.
   - Adversarial corpus payloads for `dlp_egress`.

8. **PR-S3-6 — Operator CLI surface + ADR-0009 comms-MCP contract:**
   - All `alfred plugin`, `alfred web allowlist`, `alfred config`, `alfred supervisor reset`, `alfred supervisor status` CLI commands.
   - `src/alfred/comms/mcp_protocol.py` + `plugins/alfred_comms_test/` reference plugin.
   - `alfred audit graph --tier T3` extension.

9. **PR-S3-7 — Flag-day: `DevGate` removal + integration test gate:**
   - `DevGate` removed from `src/`; deny-path tests migrated to `RealGate` fixtures.
   - Cross-fork integration tests `test_quarantined_chain_security.py` + `test_quarantined_chain_latency.py` pass (per §12.4).
   - Slice-2.5 §6.10 tracking issues retired.
   - Docs: `docs/glossary.md` additions, `docs/subsystems/` updates (target files: `docs/subsystems/plugins.md`, `docs/subsystems/supervisor.md`, `docs/subsystems/quarantine.md`).

---

## 18. References

**PRD sections:**

- [PRD §5](../../../PRD.md#5-architecture-overview) — architectural invariants (lines 116-121): plugins are MCP servers; hybrid isolation; dual-LLM split; every action hookable.
- [PRD §5.1](../../../PRD.md#51-hookable-actions) — hookable actions contract.
- [PRD §6.3](../../../PRD.md#63-agentic-skills--mcp-integration) — MCP plugin contract + capability manifest.
- [PRD §6.4](../../../PRD.md#64-self-improvement-with-reviewer-gate) — reviewer gate: high-blast change types, proposal flow.
- [PRD §6.6](../../../PRD.md#66-ai-platform-integration) — `Provider.capabilities()` routing surface (line 287-292).
- [PRD §7.1](../../../PRD.md#71-security--prompt-injection-defense) — trust tiers, dual-LLM split, secret broker, canary tokens.
- [PRD §7.2](../../../PRD.md#72-multi-user-identity--authorization) — multi-user identity, authorization roles.
- [PRD §6.7](../../../PRD.md#67-deployment--setup) — Self-healing: plugin supervisor, circuit breaker 3/5min spec (line 324).
- [PRD §7.3](../../../PRD.md#73-self-healing--auto-recovery) — supervisor, plugin lifecycle (no 3/5min numbers — those are in §6.7).
- [PRD §7.4](../../../PRD.md#74-audit-trail--rollback) — audit log, CLI.

**ADRs:**

- [ADR-0001](../../adr/0001-deepseek-as-primary-provider-slice1.md) — DeepSeek as primary provider.
- [ADR-0008](../../adr/0008-llm-output-trust-tier.md) — LLM output trust tier; superseded by ADR-0017.
- [ADR-0009](../../adr/0009-comms-adapter-protocol-slice2-only.md) — CommsAdapter Protocol; superseded for new adapters by ADR-0016.
- [ADR-0013](../../adr/0013-defer-t1-t3-and-dual-llm.md) — deferred T1+T3+dual-LLM; superseded by ADR-0017.
- [ADR-0014](../../adr/0014-pluggable-hooks-for-every-action.md) — every action is hookable; Slice 3 builds on the shipped contract.
- **ADR-0017** (co-merged in PR-S3-0) — Slice-3 trust-tier completion + MCP plugin transport + dual-LLM split; the load-bearing Slice-3 ADR that supersedes ADR-0008 and ADR-0013.
- ADR-0015 (co-merged) — Slice-4 containerised quarantined LLM commitment.
- ADR-0016 (co-merged) — Slice-4 Discord+TUI comms-MCP migration commitment.

**Code:**

- `src/alfred/security/tiers.py` — `TrustTier`, `TaggedContent`, `_APPROVED_TIERS`, `tag()`.
- `src/alfred/hooks/registry.py` — `HookRegistry`, `HookpointMeta`, `SYSTEM_ONLY_TIERS`, `SYSTEM_OPERATOR_TIERS`.
- `src/alfred/hooks/capability.py` — `CapabilityGate` Protocol, `DevGate`.
- `src/alfred/hooks/invoke.py` — `invoke()` primitive.
- `src/alfred/orchestrator/core.py:75-77` — at-most-as-trusted-as carry-over; `231,325` — `TaggedContent[T2]` contract.
- `src/alfred/identity/resolver.py` — `IdentityResolver.resolve()`.
- `src/alfred/security/secrets.py:228-279` — UID ownership validation.
- `src/alfred/providers/base.py:68` — `capabilities()` pre-flagged for Slice-2 deferral.

**Glossary entries to add in Slice 3 (via `docs/glossary.md`):**

- `ContentHandle` — opaque id for T3 content held in the plugin host's content store; the orchestrator holds this and never dereferences it to bytes.
- `QuarantinedExtractor` — orchestrator-side client of the quarantined-LLM MCP plugin; raw provider response bytes never cross back to the orchestrator untyped.
- `PluginTransport` — Protocol for subprocess communication; `StdioTransport` is the Slice-3 sole implementation.
- `Supervisor` — `src/alfred/supervisor/` module owning plugin lifecycle, circuit breakers, and per-action deadlines.
- `AnyTaggedContent` — read-only Protocol view of any `TaggedContent` regardless of tier parameter; observer code takes this to prevent `cast()` proliferation.
- `sandbox_profile` — per-plugin OS-level sandbox configuration, declared independently of manifest subscriber tier.
- `quarantined_to_structured` — the single grep anchor in `src/alfred/security/quarantine.py` for all T3-to-orchestrator handoffs; the only legitimate crossing point.
- `provenance` — the lineage metadata that survives `quarantined_to_structured`: in Slice 3, expressed as the `T3DerivedData` NewType on `Extracted.data`, signalling that the data originated from a T3 source. Slice 4 promotes this to a full type-parameter on `TaggedContent`. See §3.7.
- `RealGate` — the production `CapabilityGate` implementation backed by state.git + Postgres; constructed at bootstrap when `ALFRED_ENV != development`. See §8.4.
- `T3DerivedData` — `NewType("T3DerivedData", dict[str, object])`; the Slice-3 type-level provenance discriminant on `Extracted.data`. Callers must use `downgrade_to_orchestrator()` before injecting into privileged prompts. See §3.7.
- `AlfredPluginSession` — the orchestrator-side class that owns the subprocess lifecycle, manifest handshake, version check, and capability-gate consult for a single plugin. See §4.2.

**Glossary entries to UPDATE in Slice 3 (update existing entries, do NOT add duplicates):**

- `## Capability gate` (existing entry) — update to include `check_plugin_load` and `check_content_clearance` method descriptions. Fold into the existing entry rather than adding separate top-level entries.
- `## Hook tier` (existing entry) — update with §3.x orthogonality language: "A system-tier plugin (subscriber tier) can process T3 content (content trust tier); these two axes are orthogonal. Using `subscriber_tier='T3'` in a manifest is a security error refused at handshake." Do NOT create a separate `subscriber tier` entry — the existing `## Hook tier` entry covers the same concept.

**Sibling docs:**

- [docs/subsystems/hooks.md](../../subsystems/hooks.md) — hooks subsystem deep-doc; §3.1 publisher-side contract.
- [docs/glossary.md](../../glossary.md) — trust-tier and hook-tier orthogonality warning.
- [docs/superpowers/specs/2026-05-27-slice-2.5-hooks-design.md](2026-05-27-slice-2.5-hooks-design.md) — shipped Slice-2.5 contract this slice builds on.
