# Slice 3 — Implementation Plan Index

> **Slice 3 = trust-tier completion + MCP plugin transport + dual-LLM split.**
> Spec: [`docs/superpowers/specs/2026-05-30-slice-3-trust-tier-completion-design.md`](../specs/2026-05-30-slice-3-trust-tier-completion-design.md) — reviewed and CR-approved.
> Load-bearing ADR: [`docs/adr/0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md`](../../adr/0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md) — co-merged with PR-S3-0a.
> Plans below are sequenced; each PR's plan states what the next may assume.

---

## §1 Scope

### ADR-0013 commitment

[ADR-0013](../../adr/0013-defer-t1-t3-and-dual-llm.md) committed Slice 3 to delivering the full trust-tier stack — T1, T3, and the privileged/quarantined dual-LLM split — deferred from Slice 2 when multi-user identity and the Discord adapter consumed the available review bandwidth. Slice 3 closes that commitment entirely. [ADR-0017](../../adr/0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md) supersedes ADR-0008 and ADR-0013 on merge of PR-S3-0a; both ADRs' status fields flip to "Superseded by ADR-0017" in that same PR.

### 11-fork synthesis

The spec resolves all 11 design forks surfaced by the architecture review. Together they deliver:

1. **T1 + T3 type system (Forks 3 + 6)** — `T1` and `T3` `TrustTier` subclasses; `TaggedContent[T1]` and `TaggedContent[T3]` type-level discriminants; capability-gated `tag(T3, ...)` factory; `AnyTaggedContent` Protocol; `quarantined_to_structured` boundary; `T3DerivedData` NewType; T1 ingress via `IdentityResolver`.
2. **MCP plugin transport (Fork 2)** — `PluginTransport` Protocol + `StdioTransport`; plugin manifest schema (`alfred.manifest_version = 1`); host-side secret-broker substitution; DLP-wrapped transport; `AlfredPluginSession`; `bin/alfred-plugin-launcher` stub; lifecycle audit family.
3. **Dual-LLM split (Fork 1)** — quarantined LLM as MCP stdio subprocess under dedicated `alfred-quarantine` UID; env scrubbing + fd-3 provider key delivery; `QuarantinedUnavailable` exception; audit-field discipline; co-merged ADR-0015 (Slice-4 containerisation commitment).
4. **Quarantined structured output (Fork 5)** — `Provider.capabilities()` Protocol; native constrained-generation per provider; `QuarantinedExtractor`; `JSON_OBJECT_MODE` third mode; `ExtractionResult` discriminated union; `schema_version: Literal[1]` mandatory.
5. **`web.fetch` (Fork 4)** — in-tree MCP plugin; `ContentHandle` return; three-way allowlist intersection; `tool.web.fetch` hookpoint system-only; `InboundCanaryScanner`; Redis rate-limits; TLS fail-closed; depth=1; `WebFetchError` hierarchy.
6. **Real `CapabilityGate` (Fork 7)** — `RealGate` backed by state.git + Postgres; `check_plugin_load` + `check_content_clearance` Protocol extension; reviewer-gated proposal flow for high-blast grants; `DevGate`/`RealGate` co-existence + flag-day removal.
7. **ADR-0009 comms-MCP contract (Fork 8)** — `CommsAdapterMCP` Protocol stub + reference test plugin; existing Discord+TUI adapters untouched; ADR-0009 status flip.
8. **Adversarial corpus (Fork 9)** — `tier_laundering` + `dlp_egress` categories added to `payload_schema.py`; per-provider recorded fixtures; cross-fork integration test gate.
9. **Supervisor (Fork 10)** — `src/alfred/supervisor/` module; quarantined-LLM circuit breaker (3 failures / 5 min → `OPEN`); plugin lifecycle; per-action 30s deadline; breaker state persistence.
10. **Operator configuration surface (Fork 11)** — high-blast in state.git (reviewer-gated); low-blast in `config/policies.yaml` (hot-reload); full CLI surface; per-user daily fetch budget; i18n catalog additions.
11. **Cross-cutting** — `audit_row_schemas.py` constants module; `docs/glossary.md` additions; hookpoint surface table; `make docs-check` stays green.

### §17 PR breakdown — 10 PRs

Spec §1.3 pre-commits two splits: PR-S3-0 → PR-S3-0a + PR-S3-0b (scope budget, see §7 below); PR-S3-3 → PR-S3-3a + PR-S3-3b (transport vs supervisor). The slice ships as **10 PRs** (PR-S3-0a through PR-S3-7).

| PR | Slug | What it delivers |
| --- | --- | --- |
| PR-S3-0a | docs-adrs-foundations | ADR-0017 + status flips (ADR-0008/0009/0013) + ADR-0015/0016 stubs + PRD §5 amendment + `audit_row_schemas.py` + `payload_schema.py` Literal additions |
| PR-S3-0b | migrations-infra-i18n | Alembic migrations 0007–0009 + SQLAlchemy models + i18n catalog + Docker/Redis/state.git infra |
| PR-S3-1 | trust-tier-types | T1+T3 classes + `AnyTaggedContent` + wire-format serializer + `tag(T3)` capability-gated factory + `quarantined_to_structured` stub + `_ingest_tier` |
| PR-S3-2 | real-capability-gate | `RealGate` implementation + `check_plugin_load` + `check_content_clearance` + proposal flow |
| PR-S3-3a | mcp-plugin-transport | `PluginTransport` + `StdioTransport` (returns `DispatchResult` discriminated union) + `AlfredPluginSession` + `bin/alfred-plugin-launcher` stub + DLP wiring |
| PR-S3-3b | supervisor | `src/alfred/supervisor/` + circuit breaker + per-action deadline + `asyncio.TaskGroup` lifecycle + migration 0010 — **supervisor CLI omitted** (owned by PR-S3-6) |
| PR-S3-4 | quarantined-llm-extractor | `plugins/alfred_quarantined_llm/` + `QuarantinedExtractor` + `Provider.capabilities()` + `quarantined_to_structured` full impl |
| PR-S3-5 | web-fetch | `plugins/alfred-web-fetch/` + `ContentHandle` + `InboundCanaryScanner` + `WebFetchError` hierarchy + Redis rate-limits |
| PR-S3-6 | cli-comms-mcp-stub | All `alfred plugin/web/config/supervisor/audit` CLI commands + `CommsAdapterMCP` stub + reference test plugin |
| PR-S3-7 | docs-glossary-runbook | `docs/subsystems/{plugins,supervisor,quarantine}.md` + `docs/glossary.md` additions + operator migration runbook + `DevGate` flag-day removal |

---

## §2 PR ordering and dependencies

```
PR-S3-0a  ──────────────────────────────────────────────────────────────────┐
   │                                                                          │
   ▼                                                                          │
PR-S3-0b ──┬───────────────────────────────────────────────────────┐         │
   │        │                                                         │         │
   ▼        ▼                                                         │         │
PR-S3-1   PR-S3-2                                                    │         │
   │    \    │                                                        │         │
   │     \   │                                                        │         │
   ▼      \  ▼                                                        │         │
PR-S3-3a  (both S3-1 + S3-2 must merge)                             │         │
   │                                                                  │         │
   ▼                                                                  │         │
PR-S3-3b                                                             │         │
   │                                                                  │         │
   ▼                                                                  │         │
PR-S3-4                                                              │         │
   │                                                                  ▼         ▼
   ▼                                                               PR-S3-6   PR-S3-7*
PR-S3-5                                                              │         │
   │                                                                  ▼         │
   └─────────────────────────────────────────────────────────────► PR-S3-7 ◄──┘

* PR-S3-7 waits on ALL prior PRs (S3-0a through S3-6).
```

> The right-side arrow from PR-S3-0a directly to PR-S3-6/PR-S3-7 in the diagram represents transitive ancestry, not a direct dependency; the `depends_on` table below is authoritative.

Explicit `depends_on` per PR:

| PR | Depends on | Blocks |
| --- | --- | --- |
| PR-S3-0a | — (first PR) | S3-0b, S3-1, S3-2, S3-3a, S3-3b, S3-4, S3-5, S3-6, S3-7 |
| PR-S3-0b | S3-0a | S3-1, S3-2, S3-3a, S3-3b, S3-4, S3-5, S3-6, S3-7 |
| PR-S3-1 | S3-0a, S3-0b | S3-3a, S3-4, S3-5, S3-6 |
| PR-S3-2 | S3-0a, S3-0b | S3-3a, S3-4, S3-5, S3-6 |
| PR-S3-3a | S3-0a, S3-0b, S3-1, S3-2 | S3-3b, S3-4, S3-5, S3-6 |
| PR-S3-3b | S3-0a, S3-0b, S3-3a | S3-4, S3-5 |
| PR-S3-4 | S3-0a, S3-0b, S3-1, S3-2, S3-3a, S3-3b | S3-5 |
| PR-S3-5 | S3-0a, S3-0b, S3-1, S3-2, S3-3a, S3-3b, S3-4 | S3-6, S3-7 |
| PR-S3-6 | S3-0a, S3-0b, S3-1, S3-2, S3-3a | S3-7 |
| PR-S3-7 | ALL prior PRs (S3-0a through S3-6) | — (final PR) |

PR-S3-1 and PR-S3-2 depend on the same foundations (S3-0a + S3-0b) and do not depend on each other — they may be worked in parallel. PR-S3-6 can begin once PR-S3-3a merges, before S3-3b/S3-4/S3-5 merge.

---

## §3 Cross-PR contracts

These surfaces are defined in one PR and consumed by later PRs. Drift between PRs is a release blocker.

### `AuditWriter.append_schema` helper (defined in PR-S3-0a)

PR-S3-0a adds `AuditWriter.append_schema(fields: frozenset[str], **kwargs) -> None` to `src/alfred/audit/log.py`. This helper validates that `kwargs` matches the named fields in the `frozenset` and writes the audit row. **Every Slice-3 audit-emit site** (PR-S3-2, PR-S3-3a, PR-S3-3b, PR-S3-4, PR-S3-5) must use `await self._audit.append_schema(fields, **kwargs)` — no PR may call the raw `append()` signature with `fields=` as an ad-hoc kwarg. The existing raw `append()` signature (required kwargs: `subject`, `result`, `cost_estimate_usd`, `trace_id`, `actor_user_id`, `trust_tier_of_trigger`) remains unchanged; `append_schema` is an additive layer on top. PR-S3-0a's test for `audit_row_schemas.py` constants must also assert that every field name in every constant is a valid column in `AuditEntry` (no orphan fields).

### `audit_row_schemas.py` constants (defined in PR-S3-0a)

`src/alfred/audit/audit_row_schemas.py` ships before any implementation PR and is the single import surface for all audit row field constants. Each implementation PR imports the named constant; no PR defines its own field list.

| Constant | Consuming PRs |
| --- | --- |
| `PLUGIN_LIFECYCLE_FIELDS` / `PLUGIN_LIFECYCLE_CRASHED_FIELDS` | S3-3a, S3-3b |
| `PLUGIN_LIFECYCLE_QUARANTINED_FIELDS` | S3-3a, S3-3b |
| `PLUGIN_GRANT_FIELDS` / `PLUGIN_GRANT_REVOKED_INFLIGHT_FIELDS` | S3-2, S3-6 (CLI emits `plugin.grant.*` audit rows), S3-7 |
| `QUARANTINE_EXTRACT_FIELDS` | S3-4 |
| `WEB_FETCH_FIELDS` / `WEB_ALLOWLIST_MANIFEST_BROADENING_CAPPED_FIELDS` | S3-5 |
| `SUPERVISOR_BREAKER_RESET_FIELDS` / `SUPERVISOR_BREAKER_TRIPPED_FIELDS` | S3-3b, S3-6 (CLI `alfred supervisor reset`) |
| `SUPERVISOR_CAPABILITY_GATE_UNAVAILABLE_FIELDS` | S3-2, S3-3b |
| `SUPERVISOR_CONFIG_INSECURE_FIELDS` | S3-3a, S3-5 |
| `SUPERVISOR_ACTION_TIMEOUT_FIELDS` | S3-3b |
| `T3_BOUNDARY_REFUSAL_FIELDS` | S3-1, S3-2 |
| `T1_INGRESS_FIELDS` / `T1_DOWNGRADE_FIELDS` | S3-1, S3-3a |
| `DLP_OUTBOUND_REFUSED_FIELDS` | S3-3a, S3-5 |

### Hookpoint surface from spec §14 (which PR declares each hookpoint)

| Hookpoint name | Declared in | Consumed by |
| --- | --- | --- |
| `tool.web.fetch` | PR-S3-5 | S3-5, S3-6 (CLI audit filter), S3-7 (docs) |
| `security.quarantined.extract` | PR-S3-4 | S3-4, S3-7 (docs) |
| `plugin.lifecycle.loaded` | PR-S3-3a | S3-3a, S3-3b, S3-7 (docs) |
| `plugin.lifecycle.crashed` | PR-S3-3a | S3-3b, S3-7 (docs) |
| `plugin.lifecycle.quarantined` | PR-S3-3b | S3-3b, S3-7 (docs) |
| `plugin.grant.requested` | PR-S3-2 | S3-2, S3-6 (CLI), S3-7 (docs) |
| `plugin.grant.approved` | PR-S3-2 | S3-2, S3-6, S3-7 |
| `plugin.grant.denied` | PR-S3-2 | S3-2, S3-6, S3-7 |
| `plugin.grant.revoked` | PR-S3-2 | S3-2, S3-6, S3-7 |
| `supervisor.breaker.tripped` | PR-S3-3b | S3-3b, S3-7 |
| `supervisor.breaker.reset` | PR-S3-3b | S3-3b, S3-6 (CLI command) |
| `supervisor.action_timeout` | PR-S3-3b | S3-3b, S3-7 |
| `security.t3_boundary.refused` | PR-S3-1 | S3-1, S3-7 |
| `identity.t1_ingress` | PR-S3-1 | S3-1, S3-3a |
| `identity.t1_downgrade` | PR-S3-1 | S3-1, S3-3a |

All hookpoints use `SYSTEM_ONLY_TIERS` or `SYSTEM_OPERATOR_TIERS` from `src/alfred/hooks/registry.py:320,309`. No PR may declare a hookpoint tier policy that contradicts the §14 table.

### `payload_schema.py` Literal additions (defined in PR-S3-0a)

`tests/adversarial/payload_schema.py` gains `tier_laundering` and `dlp_egress` category Literals, plus `IngestionPath` extensions (`stdio_transport.outbound`, `stdio_transport.inbound`, `cast_bypass`, `wire_format_deser`, `capability_gate`, `secret_broker`) and `ExpectedOutcome` extensions (`boundary_refused`, `audit_row_emitted`). All adversarial tests in implementation PRs reference these constants — no PR defines its own inline Literals.

### `config/routing.yaml` `[quarantine]` block

- **Schema** lands in PR-S3-0b: the `quarantine:` key is added to the config schema with `provider`, `model`, `secret_id` fields.
- **Proposal-flow plumbing** lands in PR-S3-2: `alfred config quarantined-provider` creates the state.git proposal.
- **Consumed** in PR-S3-4: `QuarantinedExtractor` reads `routing.yaml[quarantine]` at construction; the manifest's declared provider must match or the plugin receives `plugin.load_refused` at handshake.

### `DevGate` → `RealGate` flag-day

PR-S3-2 ships `RealGate` alongside `DevGate`; `DevGate` remains for development and Slice-2.5 test compatibility. PR-S3-7 is the flag-day: `DevGate` is removed from `src/`, Slice-2.5 deny-path security tests are migrated to `RealGate` fixtures, and `DevGate` is removed from `alfred.hooks.__init__`. No PR between S3-2 and S3-7 may remove `DevGate` ahead of the flag-day.

### `StdioTransport.dispatch` return type: `DispatchResult` discriminated union (defined in PR-S3-3a)

`StdioTransport.dispatch()` returns the `DispatchResult` discriminated union (`ContentHandle | ExtractionResult | ControlResult`), not `ContentHandle` unconditionally. Inbound JSON-RPC control responses are deserialised and returned as `ControlResult(payload=…)`; only payloads from declared `content-producing` plugin methods are tagged T3 and stored as `ContentHandle`. Every consuming PR (PR-S3-4, PR-S3-5) must pattern-match on `DispatchResult` — no PR may assume the return is always `ContentHandle`.

### `ContentHandle` canonical home (defined in PR-S3-1)

`ContentHandle` is defined once in `src/alfred/security/quarantine.py` (shipped by PR-S3-1). All other PRs import from that path. `plugins/alfred-web-fetch/` (PR-S3-5) re-exports `ContentHandle` from `alfred.security.quarantine` for namespace convenience but does not redefine it. The `content_store_base.py` module (PR-S3-3a) uses `ContentHandle` as an opaque handle; it does not own the class. The single-use Redis-DEL invariant test lives in PR-S3-5, not PR-S3-1, because it depends on the Redis content store shipped there.

### `InboundCanaryScanner` vs `InboundContentScanner` (two distinct classes)

These are two different classes with related but non-overlapping roles:

- `InboundCanaryScanner` — a system-tier hook subscriber for the `tool.web.fetch` hookpoint; ships in PR-S3-5; scans web-fetch response bodies for canary tokens.
- `InboundContentScanner` — the stdio-transport inbound frame scanner inside `StdioTransport`; ships in PR-S3-3a; scans raw MCP stdio frames for injection patterns before T3 tagging.

No PR may import one when it intends the other. PR-S3-7's glossary adds entries for both classes side-by-side.

### fd-3 key-delivery wire framing (defined in PR-S3-3a, consumed in PR-S3-4)

`StdioTransport` writes the provider key to fd 3 using a 4-byte big-endian length prefix followed by the key bytes, then closes the write end. PR-S3-3a ships a host-side framing test (`test_fd3_key_delivery_framing.py`) that verifies the length-prefix-then-key contract against a stub subprocess. PR-S3-4's quarantined-LLM plugin reads fd 3 using the same framing; any divergence from the 4-byte big-endian prefix is a protocol error that must raise `PluginProtocolError`. Neither PR may change the wire format without updating both sides and the test.

### `identity._ingest_tier` ownership (defined in PR-S3-1)

`src/alfred/identity/_ingest.py` and the `_ingest_tier()` function are created by PR-S3-1 (they depend on the T1+T3 type system shipped there). PR-S3-3a only registers the `identity.t1_ingress` and `identity.t1_downgrade` hookpoints and consumes `_ingest_tier()`; it does not create the module. PR-S3-3a's §3 file-structure table lists `_ingest.py` as "consume only — created in PR-S3-1".

### ADR-0009 status flip ownership (PR-S3-0a only)

The ADR-0009 status header flip ("Superseded by ADR-0016 for new adapters; in-process adapters unchanged through Slice 3") lands **once** in PR-S3-0a Task 6, atomically with ADR-0017 per spec §15.2. PR-S3-6 Task 18 must not re-flip the same header; doing so creates a guaranteed merge conflict and a no-op second commit in the supersession graph. PR-S3-6 Task 18 is changed to a verify-only step (assert the flip is already present, do not write).

---

## §4 Cross-fork integration test gate

Two test files gate the slice merge, both owned by PR-S3-4 (the quarantined-LLM extractor PR that first makes the full chain exercisable end-to-end):

**`tests/integration/test_quarantined_chain_security.py`** — **merge-blocking.** Assertions:

- `hasattr(ContentHandle, 'content') is False` — orchestrator cannot dereference handle to bytes.
- A T3 fragment from a recorded fixture does NOT appear verbatim in `Extracted.data` values (prompt-injection neutralisation).
- The audit row for the chain carries `trust_tier_of_trigger="T3"`.
- `type(result.data)` is `T3DerivedData` at runtime (NewType survives through the chain).
- A recorded canary-token fixture triggers `WebFetchCanaryTripped` BEFORE `quarantine.extract` is invoked.

**`tests/integration/test_quarantined_chain_latency.py`** — **advisory only in Slice 3** (not merge-blocking). End-to-end latency for the quarantined extraction chain ≤ 5s. Both tests must pass across all three provider-fixture variants (Anthropic, DeepSeek, OpenAI).

The security test is wired as a required check in the PR-S3-7 merge gate (the slice graduation PR). Implementation PRs S3-4 through S3-6 carry it as a required passing test in their own CI configs.

---

## §5 Slice merge order + rollback

### Merge order

PRs must merge in strict dependency order. The critical path through the dependency graph:

```
S3-0a → S3-0b → S3-1 → S3-3a → S3-3b → S3-4 → S3-5 → S3-7
                  ↑
              S3-2 (parallel with S3-1; required before S3-3a)
```

PR-S3-6 (CLI surface) can merge any time after S3-3a; it does not gate S3-4 or S3-5. Merge order for S3-6 relative to S3-4 and S3-5 is a scheduling decision for the implementer.

### Quality gates before any PR merges

Every PR in the slice must clear:

1. `make check` (lint + format + type + unit tests) — mandatory.
2. The adversarial suite (`uv run pytest tests/adversarial`) — mandatory for every PR touching `src/alfred/security/`.
3. 100% line + branch coverage on every trust-boundary file the PR introduces or modifies (per spec §11a).
4. `make docs-check` (no broken cross-links) — mandatory for PR-S3-0a and PR-S3-7.

### Rollback strategy

Each PR is independently revertable because:

- `DevGate` coexists with `RealGate` through S3-6; reverting S3-2 re-enables `DevGate` as the only gate.
- Alembic migrations 0007–0010 each carry a `downgrade()` path (spec §13: DROP TABLE or constraint revert).
- `plugin_grants` and `capability_gate_sync` tables are rebuildable from state.git.
- `circuit_breakers` rows are transient; downgrade forgets trips (safe — next run re-discovers failures).

If S3-4 or S3-5 regresses the security gate (`test_quarantined_chain_security.py`), revert the regressing PR, fix, and re-submit. Do not merge a subsequent PR over a regressed security gate.

The `DevGate` flag-day (PR-S3-7) is the one irreversible step in the slice. If a post-flag-day regression requires `DevGate` re-insertion, that is a new PR on `main`, not a revert of S3-7.

---

## §6 References

### Spec

- [docs/superpowers/specs/2026-05-30-slice-3-trust-tier-completion-design.md](../specs/2026-05-30-slice-3-trust-tier-completion-design.md) — the authoritative design source.

### Per-PR plans

| PR | Plan file |
| --- | --- |
| PR-S3-0a | [2026-05-31-slice-3-pr-s3-0a-docs-adrs-foundations.md](./2026-05-31-slice-3-pr-s3-0a-docs-adrs-foundations.md) |
| PR-S3-0b | [2026-05-31-slice-3-pr-s3-0b-migrations-infra-i18n.md](./2026-05-31-slice-3-pr-s3-0b-migrations-infra-i18n.md) |
| PR-S3-1 | [2026-05-31-slice-3-pr-s3-1-trust-tier-types.md](./2026-05-31-slice-3-pr-s3-1-trust-tier-types.md) |
| PR-S3-2 | [2026-05-31-slice-3-pr-s3-2-real-capability-gate.md](./2026-05-31-slice-3-pr-s3-2-real-capability-gate.md) |
| PR-S3-3a | [2026-05-31-slice-3-pr-s3-3a-mcp-plugin-transport.md](./2026-05-31-slice-3-pr-s3-3a-mcp-plugin-transport.md) |
| PR-S3-3b | [2026-05-31-slice-3-pr-s3-3b-supervisor.md](./2026-05-31-slice-3-pr-s3-3b-supervisor.md) |
| PR-S3-4 | [2026-05-31-slice-3-pr-s3-4-quarantined-llm-extractor.md](./2026-05-31-slice-3-pr-s3-4-quarantined-llm-extractor.md) |
| PR-S3-5 | [2026-05-31-slice-3-pr-s3-5-web-fetch.md](./2026-05-31-slice-3-pr-s3-5-web-fetch.md) |
| PR-S3-6 | [2026-05-31-slice-3-pr-s3-6-cli-comms-mcp-stub.md](./2026-05-31-slice-3-pr-s3-6-cli-comms-mcp-stub.md) |
| PR-S3-7 | [2026-05-31-slice-3-pr-s3-7-docs-glossary-runbook.md](./2026-05-31-slice-3-pr-s3-7-docs-glossary-runbook.md) |

### ADRs

| ADR | Title | Relation |
| --- | --- | --- |
| [ADR-0008](../../adr/0008-llm-output-trust-tier.md) | LLM output trust tier | Superseded by ADR-0017 in PR-S3-0a |
| [ADR-0009](../../adr/0009-comms-adapter-protocol-slice2-only.md) | CommsAdapter Protocol | Status flip to "Superseded by ADR-0016 for new adapters" in PR-S3-0a |
| [ADR-0013](../../adr/0013-defer-t1-t3-and-dual-llm.md) | Defer T1/T3/dual-LLM to Slice 3 | Superseded by ADR-0017 in PR-S3-0a — the commitment this slice fulfils |
| [ADR-0014](../../adr/0014-pluggable-hooks-for-every-action.md) | Pluggable hooks for every action | Load-bearing precedent; Slice 3 adds hookpoints on top of the Slice-2.5 contract |
| ADR-0015 | Slice-4 containerised quarantined LLM commitment | Co-merged with PR-S3-0a as a stub; implementation is Slice 4 |
| ADR-0016 | Slice-4 Discord+TUI comms-MCP migration commitment | Co-merged with PR-S3-0a as a stub; implementation is Slice 4 |
| ADR-0017 | Slice-3 trust-tier completion + MCP plugin transport + dual-LLM split | Co-merged with PR-S3-0a; the load-bearing Slice-3 ADR |

---

## §7 PR-S3-0 split rationale (0a vs 0b)

Per spec §1.3, the original PR-S3-0 scope carried five ADRs (ADR-0017 full + ADR-0008/ADR-0013 status flips + ADR-0009 flip + ADR-0015/ADR-0016 stubs), the PRD §5 amendment, three Alembic migrations, SQLAlchemy models, i18n catalog additions, and Docker/Redis/state.git infrastructure. On the architect's scope-budget review (round 2), this exceeded the ~600-line substantive-implementation budget on prose alone, before a single line of Python was counted.

The pre-committed split separates two concerns that have different review profiles:

**PR-S3-0a (docs-only)** is pure text: ADR prose, PRD amendment, the `audit_row_schemas.py` constants module (a Python file whose content is `Final` frozensets — no runtime dispatch paths), and the `payload_schema.py` Literal additions. A security reviewer can read the ADR and constants in one pass; no schema migration tools or container builds are needed to review them. This PR unblocks all downstream PRs to begin design and test stubs immediately after merge — PR-S3-1 and PR-S3-2 can start from the audit constants as soon as S3-0a is on `main`.

**PR-S3-0b (schema/infra)** is executable: Alembic migrations (each needing `alembic revision` verification), SQLAlchemy models (needing mypy strict), i18n catalog (needing `pybabel extract` + `pybabel compile --check`), and Docker/Redis/state.git infrastructure changes (needing `docker compose build` smoke). These require a running Postgres instance and the testcontainers harness; mixing them with ADR prose in one PR makes the review harder for no benefit. PR-S3-0b is gated on PR-S3-0a so the migration table in `audit_row_schemas.py` (the source of truth for migration assignment) exists before the migration files do.

The split has no architectural implication — it is a review-bandwidth decision. All downstream PRs (S3-1 through S3-7) are unblocked by PR-S3-0b merging.

---

## §8 Slice-4 backlog seeded from Slice-3

**Slice-4 broker hardening (from Slice-3 plan-review DLP-ordering escalation):**

- Typed `SecretRef` objects in place of `{{secret:*}}` string templating (eliminates string-replace bugs by construction).
- Broker-side post-substitution invariant check: assert zero remaining `{{secret:*}}` placeholders + no cross-placement of values (caller's IDs match the substituted values).
- Per-secret-ID canary tokens woven into the post-substitution bytes by the broker itself; egress logger verifies presence on the wire.
- Audit-log assertion that substituted secret-IDs match the manifest's declared set.
- Open as `slice-4-broker-hardening` tracking issue when Slice 4 kicks off.
