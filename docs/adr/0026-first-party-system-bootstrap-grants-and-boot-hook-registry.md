# ADR-0026 — First-party system grants are seeded at boot; the daemon installs a fully-declared boot HookRegistry

- **Status**: Proposed (accepted at Slice-4 graduation, per the ADR-0015/0016 precedent)
- **Date**: 2026-06-11
- **Slice**: 4 — `docs/superpowers/specs/2026-06-06-slice-4-design.md`
- **Relates to**: [ADR-0019](0019-test-helper-gate-shim.md) (test/production gate-double split), [ADR-0014](0014-pluggable-hooks-for-every-action.md) (hook capability + tier model), [ADR-0022](0022-recoverable-carrier-semantic-for-error-stage-hookpoint-dispatch.md) (hookpoint declaration semantics), issues #235 / #237 (the daemon comms-MCP runtime epic)
- **Supersedes**: —

## Context

Post-PR-S3-7 (spec §15.1 flag-day) the only process-wide `HookRegistry` in production was the lazy `alfred.hooks.registry.get_registry` fallback, constructed over the fail-closed `_DenyAllGate` that **denies every subscriber registration**. That is the correct *bootstrap* default — a call site that lands on it has skipped the bootstrap install, and denying loudly surfaces the mis-sequencing rather than silently authorising a dispatch (CLAUDE.md hard rule #7). But it is not a *runtime* posture: nothing in `src/alfred/` ever replaced it with a real gate.

This blocks the Slice-4 daemon comms runtime (#235 / #237). The privileged orchestrator's quarantined-extraction path is mediated by `QuarantinedExtractor`, whose `__init__` registers the system-tier `security.quarantined.extract` post-chain DLP subscriber (spec §6.5, issue #158) via `register_extract_dlp_subscriber`. That helper consults the active registry's capability gate and — since CR-156 round 7 — **raises `HookError` on a deny** rather than fail-soft, because a half-wired extractor (one whose post-stage DLP scan never landed) is an active trust-boundary violation. Against the `_DenyAllGate` default, the registration is always denied, so a production `QuarantinedExtractor` **cannot construct at all**. The daemon needs a real, granted gate AND a registry that has the `security.quarantined.extract` hookpoint declared, installed before it builds the extractor.

Two sub-problems hide inside "give the daemon a granted gate":

1. **Who grants the host's own defences?** The `security.quarantined.extract` DLP subscriber is AlfredOS's own first-party defence. Grants normally flow through the reviewer-gated state.git proposal flow (ADR-0021). But the proposal flow runs *inside the same daemon* whose extractor needs the grant to construct — routing a first-party defence through it is circular. There is no operator and no reviewer at the moment the extractor must come up.

2. **The lazy registry was never re-declared against a real gate.** Each subsystem's module-bottom `declare_hookpoints()` call runs at import time against whatever singleton was active *then* — the `_DenyAllGate` lazy default. A freshly-built production registry has none of those declarations, so `strict_declarations=True` (the security-critical default) would refuse every subscriber registration with "hookpoint not declared".

## Decision

**Decision 1 — First-party system grants are SEEDED, not reviewer-gated.** A small, fixed `FIRST_PARTY_SYSTEM_GRANTS` tuple in `src/alfred/security/capability_gate/_bootstrap_grants.py` is the single source of truth for the in-tree defences the host seeds at boot. Today it is exactly one `GrantRow`: `(plugin_id="alfred.security._extract_dlp_subscriber", subscriber_tier="system", hookpoint="security.quarantined.extract", content_tier=None, proposal_branch="bootstrap:first-party-system")`. The sentinel `proposal_branch` distinguishes a host-seeded defence from an operator/reviewer grant in the audit graph. `PostgresBackend.seed_first_party_grants` upserts each row as `state='approved'` in ONE transaction; it is additive-only — it never runs the revoke-diff a state.git rebuild does, so a seed can never revoke an operator grant.

**This is NOT a fail-open.** The gate still denies every registration not covered by an `approved` grant; the same hot-path `GatePolicy.check` evaluates the seeded row. The ONLY thing seeding changes is that the in-tree DLP subscriber is among the approved rows — exactly as if an operator had issued the grant, but without the circular dependency. We explicitly do NOT special-case the gate to "trust first-party by module name" — that anti-pattern (a register-time bypass keyed on a module string) is precisely what this seeded-grant design exists to avoid. The seed lands a real row; the gate stays a pure grant evaluator.

**Decision 2 — Seed-then-load ordering is encapsulated in one factory.** `alfred.bootstrap.gate_factory.build_boot_real_gate` seeds (`await backend.seed_first_party_grants(FIRST_PARTY_SYSTEM_GRANTS)`) BEFORE `RealGate.create` reads the grant snapshot via `load_grants`. The ordering is load-bearing: the daemon constructs a `QuarantinedExtractor` immediately after this gate, and its DLP-subscriber registration is denied unless the seeded grant is already in the loaded policy. Doing the seed AFTER `create` would load an empty policy and deny the extractor. Encapsulating the ordering in one factory means it is tested once and cannot be re-sequenced wrong at a call site. A `SQLAlchemyError` from the seed propagates loud (boot refuses) — never a gate over an unseeded policy.

**Decision 3 — The daemon installs a fully-declared boot HookRegistry via `set_registry`.** `src/alfred/hooks/boot.py` provides `build_boot_hook_registry(gate, *, sink)` — a fresh `HookRegistry(gate=gate, sink=sink)` with EVERY subsystem's `declare_hookpoints` re-run against it — and `install_boot_hook_registry(...)`, which additionally `set_registry`s it. This is the ONE intentional production `set_registry` swap (the install site the `EpisodicAuditSink` docstring flagged as "deferred to Slice 3"). The signature takes a raw `CapabilityGate`: the daemon must pass the RAW `RealGate` (whose `check` consults the grant policy), NOT the `_SupervisorBootGate` wrapper (which exposes only `is_backing_store_available`); the typed parameter rejects the wrapper, closing a fail-open smell. The registry sink is the durable boot `AuditWriter` wrapped in `EpisodicAuditSink` so a DLP-subscriber-deny refusal row lands in the audit log — NOT the gate's no-op sink.

**Decision 4 — A fail-closed boot grant-assertion.** After install, the daemon asserts the seeded grant is live by calling `RealGate.check` for every row in `FIRST_PARTY_SYSTEM_GRANTS` — the SAME constant that drove the seed, so the seed and the liveness check can never drift. A `False` result means seed-then-load did not project the grant into the in-memory policy: a structurally-broken trust boundary where the extractor could not wire its DLP scan. The daemon refuses boot via the existing `_refuse_boot` path — a new `QuarantineGrantMissingFailure` (`failure_reason="quarantine_grant_missing"`) member of the `DaemonBootFailure` union, an i18n refusal string, a `daemon.boot.failed` audit row, and exit 2. The assertion is placed AFTER probe (c) so Postgres is known-reachable; a failed seed raises `SQLAlchemyError` out of the gate build and propagates loud rather than being swallowed.

## Consequences

### Positive

- A production `QuarantinedExtractor` can finally construct: the boot registry has the hookpoint declared and the gate grants the DLP subscriber. This is the precursor #237 needs before it can spawn comms plugins.
- The first-party defence is enforced fail-closed at boot: if seeding or grant-load breaks for any reason, the daemon refuses rather than running a quarantine path with no DLP scan.
- No fail-open was introduced. The gate remains a pure grant evaluator; the only newly-authorised registration is the one seeded row, audit-tagged with a distinguishing sentinel.
- The seed/assertion drift class is eliminated by construction — both read `FIRST_PARTY_SYSTEM_GRANTS`.
- Re-declaring all hookpoints has zero dispatch-authority blast radius: `alfred.hooks.invoke.invoke` does not consult the capability gate (only the metadata-only `_enforce_subscribable_tiers` check), so re-declaration cannot widen any dispatch authority, and the boot registry's subscriber buckets are empty until a real subscriber registers.

### Negative / trade-offs

- A second category of grants now exists (host-seeded vs reviewer-issued). The `proposal_branch` sentinel keeps them distinguishable in the audit graph, and seeding is additive-only so the two categories cannot interfere, but operators auditing the grant table must know the sentinel exists.
- The boot seed **re-promotes a manually-`revoked` first-party row back to `approved`** (the `ON CONFLICT DO UPDATE` restores `state='approved'`). This is intended — the first-party DLP subscriber is a mandatory defence and the boot grant-assertion (Decision 4) refuses to boot without it, so a persisted manual revoke would otherwise wedge every boot. An operator who revokes the first-party DLP grant and reboots will see it `approved` again, by design. State the behaviour so an operator auditing the table is not surprised; it applies **only** to the first-party rows in `FIRST_PARTY_SYSTEM_GRANTS` — operator grants are never re-promoted (the seed runs no revoke-diff and only upserts the fixed first-party set).
- `hooks/boot.py` hard-codes the list of subsystem `declare_hookpoints` publishers. A new publisher that forgets to wire itself here would leave its hookpoints undeclared at boot. A completeness guard test AST-scans `src/alfred` for `declare_hookpoints` and asserts each is referenced by the boot aggregator, so the drift fails CI rather than surfacing at runtime.

### Neutral

- `build_boot_real_gate` coexists with `build_real_gate` (the un-seeded production factory) and `build_dev_gate`. The seeded factory is the daemon-boot path; the un-seeded one remains for callers that manage grants by other means.

## Amendment 2026-07-06 (#339 PR3) — tool-dispatch grants added

`FIRST_PARTY_SYSTEM_GRANTS` gains three rows so the live agentic tool-dispatch
T3 path clears its gate boundaries at boot (previously it would fail loud with
`downgrade_denied`):

| plugin_id | hookpoint | subscriber_tier | content_tier | axis |
| --- | --- | --- | --- | --- |
| `alfred.orchestrator.tool_dispatch` | `tool.dispatch` | `system` | — | `check` |
| `alfred.quarantined-llm` | `quarantine.dereference` | `system` | `T3` | `check_content_clearance` |
| `t3.downgrade_to_orchestrator` | `t3.downgrade_to_orchestrator` | `system` | `T3` | `check_content_clearance` |

These realize the ADR-0046 dual-LLM tool-result flow. The boot grant-assertion
(`_first_party_grant_live`) now verifies each grant on its correct axis. This is
a factual amendment (grant list); the ADR-0026 seed-then-load mechanism and the
mandatory-defence posture are unchanged.
