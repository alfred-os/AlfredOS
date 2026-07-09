# ADR-0027 — Daemon comms runtime first cut: fixture-extractor inbound, deferred privileged orchestrator

- **Status**: Proposed (accepted at Slice-4 graduation, per the ADR-0015/0016/0025/0026 precedent)
- **Date**: 2026-06-11
- **Slice**: 4 — `docs/superpowers/specs/2026-06-06-slice-4-design.md`
- **Relates to**: [ADR-0025](0025-comms-stdio-transport-line-delimited-and-thin.md) (the comms transport substrate), [ADR-0026](0026-first-party-system-bootstrap-grants-and-boot-hook-registry.md) (the extractor boot infra this builds on), [ADR-0015](0015-slice4-containerised-quarantined-llm.md) (the containerised quarantined-LLM this defers to), [ADR-0017](0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md) (the dual-LLM split), issues #235 / #237 (the daemon comms-MCP runtime epic)
- **Supersedes**: —
- **Superseded by**: [ADR-0049](0049-real-privileged-turn-comms-inbound.md) (in part, 2026-07-08) — Decision 2/3's `CommsInboundOrchestratorAdapter` echo bridge; the tier-ceiling, single-adapter-ceiling, and grant-seeding decisions below remain in effect

## Context

[ADR-0025](0025-comms-stdio-transport-line-delimited-and-thin.md) shipped the host comms transport + serve-loop substrate, and [ADR-0026](0026-first-party-system-bootstrap-grants-and-boot-hook-registry.md) wired the boot infrastructure a production `QuarantinedExtractor` needs. PR-S4-11b is the step that finally makes the daemon a live comms runtime: when `Settings.comms_enabled_adapters` is non-empty, `_start_async` constructs a comms inbound graph and spawns each named plugin through the supervisor TaskGroup, running an inbound platform message through the real trust-boundary path (identity resolution → burst limit → quarantined extraction → peppered audit hashing) for the first time in production.

Two facts shape how far 11b can honestly go. First, the comms inbound seam `_OrchestratorLike` (`comms_mcp/inbound.py`) requires `ingest()` + `dispatch()` — a surface **no production class implements**; only the test `HarnessOrchestrator` does. The real `Orchestrator` (`orchestrator/core.py`) speaks `handle_user_message`, and nothing bridges `quarantined_extract → handle_user_message`. Standing up the privileged orchestrator graph (the `WorkingMemory` pool, `BudgetGuard`, `EpisodicMemory`, the dual-LLM-split provider) is a body of work in its own right. Second, a *real* `QuarantinedExtractor` dispatches T3 content to the **quarantined-LLM as a second spawned plugin** over a `PluginTransport` — that is [ADR-0015](0015-slice4-containerised-quarantined-llm.md) (containerised quarantined-LLM) territory, not a comms-spawn concern.

Wiring both at once would conflate "the daemon spawns comms plugins and runs the inbound boundary" with "the privileged orchestrator and the dual-LLM split are live" — two epics in one PR, on the most security-sensitive path in the system. The PRD §5 / DEC-007 dual-LLM invariant (the privileged orchestrator never sees raw T3; the quarantined LLM is the sole T3 consumer) must not be weakened under the pressure to "make the daemon live".

## Decision

**Decision 1 — Ship the daemon comms inbound runtime against a fixture-transport extractor.** PR-S4-11b makes the daemon spawn the enabled comms plugins (the reference adapter in this cut) and run the **real** inbound trust-boundary path — real `IdentityResolver`, real `BurstLimiter`, the real `QuarantinedExtractor.extract(handle, schema)` surface, real peppered audit rows — with the quarantined-LLM response supplied by a **recorded-fixture transport** (the CLAUDE.md-sanctioned non-smoke pattern). The dual-LLM invariant stays intact: the privileged side is *absent*, not fed raw T3; the fixture extractor is the sole T3 consumer, exactly as in the integration harness. *(PR-S4-11b first cut — **superseded by the PR-S4-11c-2b amendment below**: the daemon now spawns the REAL bwrap quarantined child, which is the sole T3 consumer.)*

**Decision 2 — A thin `CommsInboundOrchestratorAdapter` satisfies the `_OrchestratorLike` seam; the privileged orchestrator is deferred.** A new `comms_mcp/daemon_runtime.py` adapter delegates `quarantined_extract` to the real `CommsExtractorBridge` and routes `ingest`/`dispatch` to a deterministic outbound ack via a late-bound `OutboundSenderLike` (loud `RuntimeError` if dispatch fires before the sender is bound — no silent failure). It does **not** call `handle_user_message`. The real privileged-orchestrator reply is deferred to PR-S4-11c.
*(Retired on the production path by [ADR-0049](0049-real-privileged-turn-comms-inbound.md), #338 PR2, 2026-07-08: `RealTurnOrchestratorAdapter` now satisfies the same `_OrchestratorLike` seam and calls the real `handle_user_message`. `CommsInboundOrchestratorAdapter` is retained only as the documented rollback fallback per Decision 3 below — see ADR-0049's Negative consequences.)*

**Decision 3 — The adapter is a deliberate, recorded throwaway bridge.** The `_OrchestratorLike` `ingest`/`dispatch` seam was authored for the test harness stub and has never been satisfied by a production class. PR-S4-11c may collapse that seam into `handle_user_message` when the privileged orchestrator lands — in which case `CommsInboundOrchestratorAdapter` is replaced, not extended. This ADR records that intent so 11c does not ossify the bridge.

**Decision 4 — No real provider key or LLM call at boot.** Because the inbound path uses the fixture extractor and the stub dispatch, no privileged-provider round-trip happens; the required `deepseek_api_key` Settings field need only be present (non-placeholder) for `Settings()` to construct. Spawning the real quarantined-LLM plugin (ADR-0015) and a real conversational turn (graduation criterion #7) are PR-S4-11c.

**Decision 5 — Fail-closed enumeration, default-empty.** `comms_enabled_adapters` defaults to empty so an existing daemon boot is byte-for-byte unchanged. An operator who opts an adapter in expects it running, so a broken manifest / spawn / not-ok handshake **refuses the boot** (exit 2, audited `comms_adapter_spawn_failed`) via a boot-time readiness probe — never a silent skip.

**Decision 6 — First-party comms-adapter LOAD grants are seeded from reviewer-gated config (config-is-authorization), NOT the operator proposal flow.** A comms adapter's handshake calls `gate.check_plugin_load(plugin_id, manifest_tier)`, which fails closed unless an `approved` `GrantRow(plugin_id=<manifest [plugin] id>, subscriber_tier=<manifest tier>, hookpoint="*", content_tier=None)` exists. With only [ADR-0026](0026-first-party-system-bootstrap-grants-and-boot-hook-registry.md)'s static DLP-subscriber grant seeded, a real `alfred daemon start` with `comms_enabled_adapters` set correctly fail-closes at the handshake (`plugin_load_refused_gate`) — right per CLAUDE.md hard rule #7, but the operator-enabled adapter can never load.

The resolution is the **exact parallel** of ADR-0026's static seed: at boot, derive ONE plugin-LOAD grant per enabled adapter and seed it directly into `plugin_grants` ALONGSIDE the static first-party grants, BEFORE `RealGate.create` loads the in-memory policy. This is legitimate because the enabled set is **config-is-authorization for first-party adapters**: every entry in `Settings.comms_enabled_adapters` is validated at construction to (a) match a path-safe charset and (b) name a real in-repo `plugins/<id>/manifest.toml`, so the enabled adapters are all first-party, source-controlled code the operator explicitly opted into via reviewer-gated deployment config. The grant's `plugin_id` and `subscriber_tier` are read from that in-repo manifest (`parse_manifest`); the grant carries the distinct sentinel `proposal_branch="bootstrap:first-party-comms-adapter"` so an audit-graph query can tell a config-sourced comms-adapter load grant apart from both the static DLP seed (`bootstrap:first-party-system`) and any operator/reviewer proposal grant.

**Tier ceiling (FIX 1, PR-S4-11b review BLOCKER).** Because the seed copies the manifest `subscriber_tier` VERBATIM into the wildcard `GrantRow`, the `config-is-authorization` reasoning above only holds for the postures it was written around — `operator` and `user-plugin`. A comms manifest declaring `subscriber_tier="system"` would otherwise auto-receive a `system`-tier wildcard load grant from config alone: a self-escalation to the OS trust tier riding the boot seed (distinct from `cap-2026-003`'s "trust by name" bypass). A comms adapter is `operator` or `user-plugin` **by construction**; `system` is not a comms-adapter posture. The builder therefore **refuses** any enabled comms adapter whose manifest declares `subscriber_tier="system"`, raising `CommsAdapterSystemTierError` (a `ManifestError` subclass, so the daemon boot maps it to the audited `boot_infra_install_failed` refusal — exit 2, fail-closed). `operator` and `user-plugin` are seeded normally. Adversarial corpus `cap-2026-004` pins that a manifest-declared-`system` comms adapter is refused, proving no self-escalation rides the config seed.

The gate stays a **pure grant evaluator** — `check_plugin_load` is NOT special-cased to "trust first-party by name" (the anti-pattern ADR-0026 Decision 1/2 exists to avoid). The seed lands a real ROW and the same hot-path `GatePolicy.check` evaluates it; a non-enabled / non-first-party plugin_id is denied (adversarial corpus `cap-2026-003`, the comms-load analogue of `cap-2026-002`). The derivation lives in a pure, independently-unit-tested builder `comms_adapter_load_grants(settings) -> tuple[GrantRow, ...]`; the boot path (`build_boot_real_gate(..., extra_grants=...)`) only threads its result. A broken manifest for an enabled adapter — or a `system`-tier manifest — raises out of the builder (fail-closed) → the daemon's existing audited `boot_infra_install_failed` / grant-assertion refusal path. The sandbox, DLP, and T3 boundary all still apply at runtime; this grant ONLY clears the manifest-tier handshake for an adapter the operator explicitly enabled.

**Single-adapter ceiling (FIX 4).** This cut builds ONE shared inbound orchestrator whose outbound sender is bound per-adapter (last-writer-wins), so with two enabled adapters one adapter's inbound turn would dispatch its ack through the other adapter's runner. Until per-adapter inbound routing lands (PR-S4-11c), the daemon **refuses boot** (audited `comms_multi_adapter_unsupported`, exit 2) when `len(comms_enabled_adapters) > 1`. The pure builder still derives one grant per enabled adapter (unaffected); the guard lives at the boot wiring where the cross-route exists.

**Third-party / agent-authored adapters are out of scope for this cut** and would route through the reviewer-gate proposal flow, never this seed. Config-is-authorization is sound precisely because the enabled set is restricted to in-repo first-party manifests the operator opted into.

## Amendment — PR-S4-11c-2b (2026-06-12): the daemon now spawns the REAL bwrap quarantined child

Decision 1's recorded-fixture transport was the **first cut**. PR-S4-11c-2b reverses
that specific choice: the daemon's `_build_comms_inbound_extractor`
(`comms_mcp/daemon_runtime.py`) now constructs the production
`QuarantineStdioTransport` (ADR-0029) driving a **REAL bwrap-sandboxed quarantined
child** spawned via `spawn_quarantine_child_io` (ADR-0030), not the
`_RecordedExtractTransport` (now deleted). `_build_comms_boot_graph` became `async`
to host the spawn, and CONSUMES the boot-minted authorised T3 nonce (it was
threaded-but-inert in 11b/2a): the nonce now drives a real `T3BodyRecorder` that
tags the inbound body `TaggedContent[T3]` and stages it in the single-use
`QuarantineStagingMap` the transport drains — the inline-over-wire content path
(ADR-0029) is exercised in production.

What is unchanged: the 2b child runs a **deterministic-echo loop** — NO real LLM,
NO network egress. Decision 4 still holds in spirit: there is no privileged-provider
round-trip and no quarantined-LLM provider call. The child's provider key is
resolved from the secret broker by the fixed id `quarantine_provider_api_key`
(`config/routing.yaml [quarantine] secret_id`); when unset it falls back to a
documented placeholder with a loud `structlog` warning (the echo child reads,
scrubs, and discards it). PR-S4-11c-2c flips that unset path to refuse-boot once the
child makes a real provider call, and lands the real LLM + its egress allowlist
behind release-blocker #230. Graduation criterion #7 (a real `alfred chat` turn)
still awaits 2c's real privileged orchestrator + real LLM.

**Fail-closed dev-host posture.** The quarantined child is `sandbox.kind="full"`
(bwrap), so a daemon with a comms adapter enabled now REQUIRES a Linux host with
bwrap + the ADR-0030 bound interpreter to boot. On a non-Linux / unprovisioned host
the spawn raises `QuarantineChildSpawnError`, which the boot path converts into an
audited refusal (exit 2, `quarantine_child_spawn_failed`) with a clear operator
message — there is **no dev fixture fallback**. The fixture path now lives only in
the test tiers (in-proc echoing child doubles).

## Amendment — #364 (2026-07-04): sink-local containment defense-in-depth

The tier ceiling (FIX 1) re-checks the manifest `subscriber_tier` at the builder's read sink rather than trusting the construction-time validator — "the tool layer is the perimeter". This amendment extends that same posture to the **path-traversal** property.

`comms_adapter_load_grants` turns each `comms_enabled_adapters` id into a `plugins/<id>/manifest.toml` path and reads it. Path-traversal safety otherwise rests entirely on the construction-time `_validate_comms_enabled_adapters` Settings validator (charset regex, `.`/`..` rejection, containment-under-`plugins/`, `is_file`). The builder's parameter is typed as the `CommsAdapterGrantsConfig` Protocol; typing it `Settings` never implied "validated" — `model_construct` bypasses validators. A validator-bypassing construction of the real `Settings` type carrying a traversal-shaped id (e.g. `"../../../../etc"`) would otherwise route it to the `read_text()` sink.

The builder now RE-CHECKS at the sink that the resolved manifest path stays under `plugins/` (`manifest_path.resolve().is_relative_to((_REPO_ROOT / "plugins").resolve())`) before reading, and **refuses** fail-closed with a dedicated `CommsAdapterManifestEscapeError` (a `ManifestError` subclass, so the daemon boot maps it to the audited `boot_infra_install_failed` refusal — exit 2, identical parentage/rationale to `CommsAdapterSystemTierError`). This is the **single containment property**, NOT the 4-check validator copied into the builder. `.resolve()` follows symlinks, so a symlinked `plugins/<id>` escaping the tree resolves outside `plugins/` and is refused (not passed) — the semantics are byte-identical to the Settings validator's own containment check, deliberate consistency rather than a shared blind spot.

This is **defense-in-depth**: in production the sole caller passes a real, validated `Settings`, so the check never fires (zero behavioral change); the attack requires developer-authored code (a `model_construct` / stub Config), outside the external-content threat model. No coded invariant is weakened. Adversarial corpus `cap-2026-005` drives the real builder with a `model_construct` traversal id (validator bypass) plus a real-adapter positive control, pinning the sink-local defense; a symlink-escape unit test pins `.resolve()`'s symlink-following independently of the lexical case. The refusal message discloses only that the path is "outside the `plugins/` directory" — never the resolved host path.

## Consequences

### Positive

- For the first time, a real inbound platform message traverses plugin → wire → runner → session → `process_inbound_message` → audit in production; the daemon comms runtime is provably live (real-Postgres integration + a real-spawn smoke).
- The dual-LLM invariant is preserved honestly: the privileged orchestrator is absent rather than mis-fed; the fixture extractor is the only T3 consumer. *(First cut — superseded by PR-S4-11c-2b: the live bwrap child is now the sole T3 consumer; the invariant is preserved more strongly, since the real child reads the wire rather than the host fabricating a response.)*
- The work is incremental and reviewable — the spawn/lifecycle/outbound/audit machinery is de-risked before the much larger privileged-orchestrator + quarantined-LLM epic.

### Negative / accepted

- 11b does not yet produce a real conversational reply; graduation criterion #7 (a real `alfred chat` turn) remains open until PR-S4-11c lands the privileged orchestrator + the quarantined-LLM spawn.
- `CommsInboundOrchestratorAdapter` may be replaced wholesale in 11c (Decision 3) — accepted as the cost of shipping the runtime incrementally rather than blocking on two epics.

### Scope boundary

PR-S4-11b ships the daemon comms inbound runtime (fixture extractor + stub dispatch + outbound ack) for the reference adapter, on top of [ADR-0026](0026-first-party-system-bootstrap-grants-and-boot-hook-registry.md)'s boot infra. **PR-S4-11c** wires the #235 deferred primitives (`SubPayloadPromoter` for Discord, `OutboundQueue`, `BindingEmitter`, `addressing_drift`, `ThreadConversationLedger`), the live Discord spawn, and — gated on [ADR-0015](0015-slice4-containerised-quarantined-llm.md) — the real privileged orchestrator + the quarantined-LLM plugin that close graduation criterion #7.
