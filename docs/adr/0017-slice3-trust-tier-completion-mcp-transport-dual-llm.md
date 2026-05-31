# ADR-0017 — Slice 3: trust-tier completion, MCP plugin transport, dual-LLM split

- **Status**: Accepted
- **Date**: 2026-05-31
- **Slice**: 3 — `docs/superpowers/specs/2026-05-30-slice-3-trust-tier-completion-design.md`
- **Supersedes**: [ADR-0008](0008-llm-output-trust-tier.md) (in full), [ADR-0013](0013-defer-t1-t3-and-dual-llm.md) (in full)
- **Superseded by**: —

## Context

[ADR-0008](0008-llm-output-trust-tier.md) established the AlfredOS trust-tier discriminant in Slice 1 and committed three surfaces — T1 operator-tier marking, T3 untrusted-ingestion tagging, and the privileged ↔ quarantined dual-LLM split — for delivery in Slice 2. [ADR-0013](0013-defer-t1-t3-and-dual-llm.md) revised that commitment during Slice 2 planning: the identity + Discord + secret broker + per-user budget scope already consumed the available review bandwidth, so all three surfaces were deferred. ADR-0013's Consequences section states the binding obligation that governs this ADR: "**Slice 3 commits the full stack.**" (ADR-0013, Consequences §, line 99.) Slice 3 therefore cannot close without T1, T3, and the dual-LLM split all shipping together as one coherent unit.

The first of the three forces binding these decisions together is ADR-0013's commitment itself. Slice 2 ships T2-only (authenticated user); the full trust-tier story — T0 system, T1 operator, T2 authenticated user, T3 untrusted ingestion — cannot be regarded as closed until Slice 3 delivers T1 tagging on TUI ingress, T3 tagging at every external-ingestion boundary, and the quarantined-LLM structure that makes T3 isolation meaningful rather than cosmetic. PRD §7.1 names the dual-LLM split as the load-bearing prompt-injection defence: the privileged orchestrator sees only T0–T2; the quarantined LLM is the sole consumer of T3 content and emits only structured data, never tool calls and never free text fed back as instructions. Without the dual-LLM split, T3-tagging is taint annotation only, providing no actual isolation guarantee — exactly the constraint ADR-0013 §Alternatives c identified as insufficient.

The second force is a dependency edge that dictates sequencing within the slice: the quarantined LLM runs as an MCP stdio subprocess. That deployment model is not incidental — it is the mechanism by which process-level isolation is achieved in Slice 3 before full containerisation lands in Slice 4 (ADR-0015, co-merged). The MCP plugin transport must therefore land in the same slice as the dual-LLM split; the quarantined LLM cannot be deployed as a plugin under a transport that does not yet exist. PRD §5 (line 116) names "Plugins are MCP servers" as a non-negotiable architectural invariant: comms adapters, skills, memory backends, integrations, and the reviewer agent are all MCP servers — stdio for in-process, HTTP for remote. That invariant has been deliberately relaxed since Slice 1: [ADR-0009](0009-comms-adapter-protocol-slice2-only.md) records the bounded deviation for `CommsAdapter`, noting that the MCP plugin host is a Slice-3 deliverable. The quarantined LLM is the first plugin that actually demands the host; it cannot be shoehorned into the in-process Protocol the way the comms adapters were.

The third force is the hybrid-isolation invariant stated at PRD §5 line 117: "Official plugins run as in-process subprocesses; third-party or agent-authored plugins run containerised with declared capabilities (network allowlist, fs mounts, secret IDs)." Slice 3 runs the quarantined LLM as a subprocess under a dedicated `alfred-quarantine` UID with env scrubbing — process-level isolation, not container isolation. That is a scoped, deliberate deviation from the container half of the invariant, taken because full containerisation (ADR-0015) belongs in Slice 4 when the orchestration infrastructure for container lifecycle exists. The deviation must be named in a load-bearing ADR — not left as a silent relaxation while `docker run` wrappers are absent from the codebase — so that a Slice-4 reader can find the commitment and verify it was honoured.

These three forces require one coherent ADR rather than three separate records because they are not independent decisions. The transport cannot land without a plugin that needs it; the dual-LLM split cannot land without the transport; T1+T3 cannot close the trust-tier story without the dual-LLM split making T3 isolation real. A reviewer asking "why is the MCP transport in this slice?" cannot be answered without naming the quarantined-LLM dependency; a reviewer asking "why is the quarantined LLM a subprocess and not a container?" cannot be answered without naming the hybrid-isolation invariant and ADR-0015's Slice-4 commitment. The ADR that commits Slice 3 must hold all three force lines visibly together.

## Decision

**Decision 1 — T1+T3 type system + nonce-gated `tag(T3, ...)`.** T1 and T3 `TrustTier` subclasses extend `_APPROVED_TIERS`. The `tag(T3, ...)` factory is capability-gated via a per-process random nonce compared by identity (`is`, not `==`) — not by frame introspection, which is forgeable via `sys.modules` manipulation. This nonce gate closes import-time forgery attacks without defending against arbitrary in-process code execution (which is outside the threat model; the adversarial corpus labels the `gc.get_objects()` vector `tier_laundering/gc_traversal_out_of_scope` with explicit rationale rather than treating it as an unresolved gap). Spec §3.2.

**Decision 2 — MCP stdio subprocess as the plugin transport.** `StdioTransport` wraps the `model_context_protocol` SDK. The subprocess boundary provides process-level isolation without requiring container infrastructure in Slice 3. The quarantined LLM and `web.fetch` are both in-tree MCP plugins under this transport. `PluginTransport` is a `Protocol`; `StdioTransport` is the sole Slice-3 implementation; HTTP transport is deferred to Slice 5+; in-process `MemoryTransport` is permanently excluded (would collapse process-boundary isolation). Spec §4.1, §4.2.

**Decision 3 — Two-axis naming: `subscriber_tier` ≠ content trust tier.** The manifest uses `subscriber_tier` (system/operator/user-plugin) for the capability-grant axis; `tier` in `TaggedContent` and audit rows refers to the content trust tier (T0-T3). The two axes are orthogonal; conflating them is a security error (`subscriber_tier="T3"` in a manifest is refused at handshake). This naming rule is enforced in the manifest schema, in `docs/glossary.md`, and by the manifest-handshake validation code. Spec §4.3.

**Decision 4 — Hybrid-isolation relaxation with Slice-4 commitment.** Slice 3 ships the quarantined LLM as a subprocess under a dedicated `alfred-quarantine` UID with env scrubbing and fd-3 key delivery. This is a time-bounded relaxation of PRD §5 line 117, which requires (paraphrase) containerised plugins with declared capabilities. PRD §5 line 117 is amended (co-merged with this ADR) to read (paraphrase): hybrid isolation — containerised or dedicated-UID-with-env-scrub during Slice 3, fully containerised from Slice 4 per ADR-0015. ADR-0015 is co-merged as the Slice-4 commitment record. Spec §5.7.

**Decision 5 — PR-S3-0 pre-committed split into PR-S3-0a and PR-S3-0b; PR-S3-3 pre-committed split into PR-S3-3a and PR-S3-3b.** The original PR-S3-0 scope (five ADRs + three Alembic migrations + i18n + Docker infra) exceeded the ~600-line budget on prose alone. PR-S3-0a carries docs-only deliverables; PR-S3-0b carries schema/infra. PR-S3-3 splits transport (PR-S3-3a) from supervisor (PR-S3-3b). Both splits are pre-committed so implementors do not re-open the split decision at implementation time. Spec §1.3.

**Decision 6 — `QuarantinedUnavailable` lives in `src/alfred/plugins/errors.py`.** Spec §5.5 says `QuarantinedUnavailable` is "a distinct top-level exception" in `src/alfred/plugins/errors.py`. Spec §10.1 lists it as a public export of the supervisor module — a direct contradiction. Resolution: `QuarantinedUnavailable` lives in `src/alfred/plugins/errors.py` (spec §5.5 wins because it is the plugin-transport module that raises this error when the quarantined LLM is unavailable — the supervisor observes it but does not own it). `src/alfred/supervisor/errors.py` imports and re-exports it for ergonomic import in supervisor code, satisfying spec §10.1's "supervisor exposes it" requirement without placing the definition in the wrong module. The `ExtractionResult` `ImportError` (sec-002) is eliminated because `from alfred.plugins.errors import QuarantinedUnavailable` no longer fails with a circular import. Every Slice-3 PR that raises `QuarantinedUnavailable` imports it from `alfred.plugins.errors`.

**Decision 7 — Wire-format versioning anchors (three schemes, three namespaces, zero aliasing).** Slice 3 lands three independent versioning schemes on three different wires, and spec §2 ("Cross-cutting wire-format ADR section") requires this ADR to reconcile them so a reviewer reading any single PR can find the canonical anchor without re-deriving it. The three anchors are:

*TrustTier wire format.* `TaggedContent` serialises `tier` as the literal string form of `tier.name` — exactly one of `"T0"`, `"T1"`, `"T2"`, `"T3"` — re-resolved against `_APPROVED_TIERS` on parse. There is **no version field on the tier itself**; the class registry is the versioning mechanism. Cross-tier confusion on the wire (payload labelled with one tier but constructed from another) is rejected at the `model_validator` boundary with a loud `ValueError` carrying the `t("security.tier_mismatch", …)` message — never at a later business-logic seam. The validator also rejects any `tier` string not in `{t.name for t in _APPROVED_TIERS}`, so a forged `"T4"` is refused before reaching the orchestrator's type contract. Spec §2 paragraph 1, §3.5.

*Plugin manifest version.* Every Slice-3 MCP plugin manifest carries `alfred.manifest_version = 1` as a single integer — typed as `Literal[1]` in the manifest model. A plugin presenting `alfred.manifest_version != 1` is refused at the `AlfredPluginSession` handshake with exactly one `plugin.load_refused` audit row before any capability-gate check runs. The integer is the **sole** manifest-evolution lever: no semver tolerance, no negotiation, no minor-version forgiveness. The integer increments only when the manifest schema adds or removes fields that break backward compatibility; the reserved-for-Slice-4 `[plugin] platform` field is the explicit mechanism by which the Slice-4 comms-MCP rewrite avoids forcing the bump to 2. Spec §2 paragraph 2, §4.3, §4.9.

*Extraction handoff schema version.* Every Pydantic model passed to `QuarantinedExtractor.extract()` carries `schema_version: Literal[1]` as a class attribute. The extractor validates this before constructing the schema payload for the quarantined-LLM plugin call; an extraction schema without `schema_version` raises `ValueError` with `t("quarantine.schema_version_missing", …)` before any MCP RPC is dispatched. This anchor governs the QuarantinedExtractor → privileged-orchestrator handoff specifically — it is **not** the same field as `alfred.manifest_version` (which governs the plugin handshake) and **not** the same field as the wire-format `tier` string (which governs `TaggedContent` serialisation). The three fields never share a namespace: `alfred.manifest_version` lives in the MCP manifest TOML/JSON, `schema_version` lives on extraction schema Pydantic models, and `tier.name` lives in `TaggedContent` serialisation. The cost of aliasing them — silent cross-version acceptance, drift between PRs, breakage during Slice 4's first bump — is paid up-front in this Decision rather than discovered at integration time. Spec §2 paragraph 3, §5.5, §6.6, §7a.1.

## Consequences

### Positive

- The trust-tier story closes in one slice: T1+T3+dual-LLM are inseparable (T3 without the quarantined LLM is taint-tagging only; T1 without T3 provides no discriminator payoff), so completing them together eliminates the partial-implementation window that ADR-0013 held open.
- Process-level isolation lands from day one of the dual-LLM split. The `alfred-quarantine` UID boundary is enforced by the OS; a misbehaving quarantined LLM subprocess literally cannot read the orchestrator's secrets file (`src/alfred/security/secrets.py:228-279` validates ownership against `os.getuid()`).
- The `PluginTransport` Protocol is future-proof: HTTP transport (Slice 5+) implements the same surface without touching the orchestrator.

### Negative

- The subprocess transport adds cold-start latency (< 500ms per spec §7a.1). Operators with a single cold deployment will feel this on first restart.
- The hybrid-isolation relaxation (no container isolation in Slice 3) means the `alfred-quarantine` UID's filesystem isolation is UID-separation only — the quarantined LLM can write to any UID-permitted path on the host. `bin/alfred-plugin-launcher` enforces `$XDG_RUNTIME_DIR/alfred/plugin-<id>/` as the write root via the `ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED=1` guard; Slice 4's `bwrap` policy hardens this.
- The `DevGate` → `RealGate` flag-day migration (PR-S3-7) is a final-slice mandatory step. Skipping it leaves the nonce-token gate without a production backing store.

### Neutral

- The `manifest_version = 1` pin means any future manifest schema change that breaks backward compatibility requires incrementing to 2. This is intentional (explicit versioning discipline) rather than semver tolerance.
- ADR-0009 status flips to superseded-for-new-adapters; existing Discord+TUI adapters are untouched through Slice 3.

## Alternatives considered

### Option A — Ship T3-tagging at the comms boundary without the dual-LLM split

Rejected per ADR-0013's §c analysis: T3 without the quarantined LLM is taint-tagging only; the PRD §7.1 invariant ("the privileged orchestrator never processes raw T3 content") is unmet.

### Option B — HTTP plugin transport instead of stdio subprocess

Rejected for Slice 3: HTTP requires TLS cert management, service discovery, and a separate network policy in Docker Compose — a materially larger infrastructure surface than stdio subprocess. The `PluginTransport` Protocol keeps HTTP available as a Slice-5+ option without coupling to it in Slice 3.

### Option C — Frame introspection for `tag(T3, ...)` call-site enforcement

Rejected per spec §3.2: `sys._getframe` is forgeable via `sys.modules` manipulation and provides no real caller identity. The nonce-token approach (`is`-comparison per-process random nonce) closes import-time forgery without the forgeable-via-modules vulnerability.

### Option D — Keep DevGate and remove the flag-day

Rejected: `DevGate` fails open for `operator`/`user-plugin` without a backing store, which is incompatible with the real `CapabilityGate` requirement from spec §8.4. The flag-day is the mechanism that ensures every production deployment migrates.

## References

- [PRD §5 Architecture Overview](../../PRD.md#5-architecture-overview) — "Plugins are MCP servers" invariant; hybrid-isolation invariant at line 117.
- [PRD §7.1 Security & Prompt Injection Defense](../../PRD.md#71-security--prompt-injection-defense) — dual-LLM split as the load-bearing prompt-injection defence; T0–T3 trust tier definitions.
- [ADR-0008](0008-llm-output-trust-tier.md) — established the trust-tier discriminant in Slice 1; superseded in full by this ADR.
- [ADR-0009](0009-comms-adapter-protocol-slice2-only.md) — bounded deviation for `CommsAdapter`; MCP plugin host named as Slice-3 deliverable; status updated to superseded-for-new-adapters.
- [ADR-0013](0013-defer-t1-t3-and-dual-llm.md) — deferred T1+T3+dual-LLM to Slice 3; binding "Slice 3 commits the full stack" obligation; superseded in full by this ADR.
- [ADR-0015](0015-slice4-containerised-quarantined-llm.md) — Slice-4 containerised quarantined LLM commitment
- [ADR-0016](0016-slice4-discord-tui-comms-mcp-rewrite.md) — Slice-4 Discord/TUI comms-MCP migration commitment
- [Design spec](../superpowers/specs/2026-05-30-slice-3-trust-tier-completion-design.md) — complete Slice-3 design; §§1.3, 3.2, 4.1, 4.2, 4.3, 5.5, 5.7, 7a.1, 8.4, 10.1 govern the decisions above.
- Code anchors: `src/alfred/security/secrets.py:228-279` (UID ownership check), `src/alfred/hooks/capability.py` (existing capability gate seam).
