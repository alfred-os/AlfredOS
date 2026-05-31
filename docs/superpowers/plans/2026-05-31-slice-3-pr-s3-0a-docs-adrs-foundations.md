# Slice 3 — PR S3-0a: Docs + ADRs + audit_row_schemas.py + adversarial corpus Literals — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Establish the shared vocabulary, schema constants, and corpus structure that every downstream Slice-3 PR depends on — specifically: ADR-0017 (the load-bearing Slice-3 ADR), status-flip edits to ADR-0008/ADR-0013/ADR-0009, Slice-4 commitment stubs ADR-0015/ADR-0016, a PRD §5 line 117 amendment for hybrid isolation, `src/alfred/audit/audit_row_schemas.py` with all 18 field-list constants (17 spec §13 constants + `T3_DERIVED_DOWNGRADE_FIELDS` added per rvw-003 for PR-S3-4 consumption), updated `src/alfred/audit/__init__.py`, and `tests/adversarial/payload_schema.py` extended with the two new categories (`tier_laundering`, `dlp_egress`) plus `IngestionPath`/`ExpectedOutcome` extensions with new stubs.

**Architecture:** This PR is pure docs-and-schema — no runtime code ships other than `audit_row_schemas.py` and the updated `payload_schema.py`. ADR-0017 records the structural decisions that govern how all 11 forks compose; the audit-row-schemas module centralises field-list constants so that five emitter subsystems (`plugins/`, `supervisor/`, `security/`, `orchestrator/`, `identity/`) share one import surface, preventing field-name drift across PRs. The adversarial schema additions establish the two new attack-family categories before any implementation PR ships a test that references them, so later PRs can write YAML payloads without touching the schema.

**Tech Stack:** Markdown (ADRs, PRD amendment) · Python 3.12+ (Pydantic v2, PEP 604 unions, `typing.Final`, `frozenset` literals in `audit_row_schemas.py`) · `make docs-check` (cross-link validation) · `uv run pytest tests/adversarial -q` (schema round-trip) · `pybabel extract` (catalog drift check, no new keys in this PR — keys are PR-S3-0b).

---

## §1 Goal

PR-S3-0a is the first Slice-3 PR and the prerequisite for everything else. It delivers:

1. **ADR-0017** — the full prose ADR committing Slice 3's trust-tier completion, MCP plugin transport, and dual-LLM split decisions. This is the architectural contract downstream implementors cite when they question why the quarantined-LLM is a subprocess, why the manifest uses `subscriber_tier` not `tier`, why `tag(T3, ...)` is nonce-gated, and why `ContentHandle` is opaque. Spec anchors: §0, §1, §2, §3, §4, §5, §6, §7, §8, §9, §10, §11, §14, §15, §17, §18.

2. **ADR status flips** — ADR-0008, ADR-0013 both flip to "Superseded by ADR-0017". ADR-0009 flips to "Superseded by ADR-0016 for new adapters; in-process adapters unchanged through Slice 3." These three edits land atomically with ADR-0017 so the supersession graph is never in a transient invalid state (spec §15.2, §1.3).

3. **ADR-0015 + ADR-0016 stubs** — co-merged per spec §5.7 and §9.4. ADR-0015 commits Slice 4 to containerising the quarantined LLM. ADR-0016 commits Slice 4 to the Discord/TUI comms-MCP rewrite. Both ship as stubs with "Status: Proposed" — the prose is a commitment record, not a full design.

4. **PRD §5 line 117 amendment** — the hybrid-isolation invariant text, co-merged with ADR-0017 per spec §5.7. Changes "containerized with declared capabilities" to "hybrid isolation: containerized OR dedicated-UID-with-env-scrub during Slice 3, fully containerized from Slice 4 per ADR-0015." This is a docs edit to `PRD.md`; no separate proposal flow because this is the explicit relaxation record.

5. **`src/alfred/audit/audit_row_schemas.py`** — 18 `Final[frozenset[str]]` constants covering all Slice-3 audit row families: 17 constants verbatim from spec §13, plus `T3_DERIVED_DOWNGRADE_FIELDS` added here per rvw-003 (consumed by PR-S3-4's `downgrade_to_orchestrator`; this PR is the canonical home so the field-list is defined exactly once and imported across PRs). This module is the single import surface — downstream PRs may import the module (`from alfred.audit import audit_row_schemas`) and access constants as `audit_row_schemas.PLUGIN_LIFECYCLE_FIELDS`, or import specific constants directly (`from alfred.audit.audit_row_schemas import PLUGIN_LIFECYCLE_FIELDS`). Both forms are valid. Tests assert the field lists are frozen sets and that each constant name matches its spec §13 entry (the rvw-003 addition has its own assertion).

6. **`src/alfred/audit/__init__.py`** — exports `audit_row_schemas`, `AuditWriter`, and `AuditEntry` so downstream PRs can `from alfred.audit import audit_row_schemas` without a deeper import path.

7. **`tests/adversarial/payload_schema.py`** — two new `Category` values (`tier_laundering`, `dlp_egress`), two prefix entries (`tl`, `de`), six new `IngestionPath` values, and two new `ExpectedOutcome` values per spec §12.2. README stubs for both new categories (`payloads.yaml` deferred to the PRs that populate the categories — empty-category-dir convention).

8. **`AuditWriter.append_schema()` helper** — typed method on `AuditWriter` that validates `subject` keys against a `fields` constant before forwarding to `append()`. Lands here so all five downstream emitter PRs (S3-3a, S3-4, S3-2, S3-3b, S3-5) use a single typed entry point. Cross-reference: rvw-001 (Critical), Cluster 4.

9. **Catalog infrastructure pointers** — ADR-0017 Decision §6 names `plugin.transport.dlp_outbound_refused` as a new catalog key that PR-S3-3a raises via `DlpOutboundRefusedError`. The key itself (msgstr + `_KEY_REQUIRED_PLACEHOLDERS` entry) lands in PR-S3-0b; this PR records the architectural decision that the DLP-outbound refusal path uses a typed exception and a distinct catalog key (not the `plugin.launcher_no_sandbox_policy` misuse in the original plan). Cross-reference: arch-006 / rvw-009 / sec-006 / err-011 (all four specialists converged on this).

10. **`QuarantinedUnavailable` placement decision** — ADR-0017 records the resolution of the spec §5.5 vs §10.1 contradiction: definition in `src/alfred/plugins/errors.py`, re-exported from `src/alfred/supervisor/errors.py`. Cross-reference: arch-004 (High).

---

## §2 Architecture overview

### ADR-0017 as the load-bearing hub

Every downstream PR (S3-1 through S3-7) cites ADR-0017 as authority for its design choices. ADR-0017 must therefore ship in the first PR, before any implementation, so reviewers can verify implementation choices against the ADR rather than the spec. The ADR is not a summary of the spec; it is a decision record containing the five key decisions the spec makes (§2 cross-cutting wire format, §3.2 nonce-token T3 gate, §4.3 manifest naming two-axis rule, §5.7 hybrid-isolation relaxation, §15.1 DevGate flag-day) plus the rationale for each.

### `audit_row_schemas.py` as a drift barrier

Slice 3 introduces five emitter subsystems. Without a central constants module, each subsystem implements field names independently — the `plugin_id` in `PLUGIN_LIFECYCLE_FIELDS` drifts to `plugin_identifier` in a supervisor module in a different PR. The spec §13 rationale is explicit: this file ships before any fork's implementation PR. The module has no imports beyond `typing.Final`; it cannot import from other `alfred.*` modules and thereby trigger circular imports.

Downstream PRs may use either import form — `from alfred.audit import audit_row_schemas` (module reference) or `from alfred.audit.audit_row_schemas import <CONSTANT>` (specific constant). Both are valid: `__init__.py` re-exports the module, making the module reference available at the shorter path, while direct constant imports avoid the `audit_row_schemas.` prefix in call sites with many constants. Implementers pick whichever is more readable at the call site; the contract is that the constant name matches the spec §13 entry, regardless of how it is imported.

### Adversarial schema first

`payload_schema.py` ships before any adversarial payloads because the schema is the contract that `conftest.py` uses to validate every YAML file at collection time. If `dlp_egress` payloads ship in PR-S3-5 before the schema is updated, collection fails loudly — the fail-closed property of the schema makes ordering enforcement automatic.

```
PR-S3-0a (this PR)
├── docs/adr/0017-...  ← cited by all downstream ADRs
├── ADR status flips   ← supersession graph valid before any code
├── PRD §5 amendment   ← hybrid-isolation relaxation documented
├── audit_row_schemas.py  ← imported by S3-1, S3-2, S3-3a, S3-3b, S3-4, S3-5, S3-6
└── payload_schema.py  ← schema contract S3-1, S3-4, S3-5 write payloads against
          ↓
PR-S3-0b (gated on this PR)
├── Alembic migrations
├── i18n catalog additions
└── Docker/Redis/state.git infra
          ↓
PR-S3-1 through PR-S3-7 (each cites ADR-0017, imports audit_row_schemas)
```

---

## §3 File structure

| File | Status | 1-sentence responsibility |
|---|---|---|
| `docs/adr/0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md` | Create | Load-bearing ADR for all Slice-3 design decisions; supersedes ADR-0008 + ADR-0013. |
| `docs/adr/0015-slice4-containerised-quarantined-llm.md` | Create | Slice-4 commitment stub: containerises the quarantined-LLM subprocess per PRD §5. |
| `docs/adr/0016-slice4-discord-tui-comms-mcp-rewrite.md` | Create | Slice-4 commitment stub: rewrites Discord + TUI adapters as MCP plugins. |
| `docs/adr/0008-llm-output-trust-tier.md` | Modify | Status header only: `Superseded by ADR-0017`. |
| `docs/adr/0013-defer-t1-t3-and-dual-llm.md` | Modify | Status header only: `Superseded by ADR-0017`. |
| `docs/adr/0009-comms-adapter-protocol-slice2-only.md` | Modify | Status header only: `Superseded by ADR-0016 for new adapters; in-process adapters unchanged through Slice 3`. |
| `PRD.md` | Modify | Line 117 amendment: hybrid-isolation invariant text updated to reflect Slice-3 relaxation. |
| `src/alfred/audit/audit_row_schemas.py` | Create | All 18 Slice-3 audit row field-list `Final[frozenset[str]]` constants (17 from spec §13 + `T3_DERIVED_DOWNGRADE_FIELDS` per rvw-003). |
| `src/alfred/audit/__init__.py` | Modify | Re-exports `audit_row_schemas`, `AuditWriter`, `AuditEntry` from the audit package. |
| `src/alfred/audit/log.py` | Modify | Adds `AuditWriter.append_schema(fields, **kwargs)` helper that validates subject keys against the field-list constant before forwarding to `append()`. |
| `tests/unit/audit/test_audit_row_schemas.py` | Create | Asserts every field-list constant is a `frozenset`, matches its spec §13 entry, and that nothing from `typing` leaks into the frozenset values. |
| `tests/unit/audit/test_log.py` | Modify | Adds `append_schema` tests: happy path, subject-missing-field rejection, field-name snake_case guard. |
| `tests/adversarial/payload_schema.py` | Modify | Adds `tier_laundering` + `dlp_egress` categories, `tl` + `de` prefixes, six `IngestionPath` additions, two `ExpectedOutcome` additions. |
| `tests/adversarial/tier_laundering/README.md` | Create | Category description for `tier_laundering` attack family (README-only stub; `payloads.yaml` deferred to PR-S3-1+ per the empty-category-dir convention). |
| `tests/adversarial/dlp_egress/README.md` | Create | Category description for `dlp_egress` attack family (README-only stub; `payloads.yaml` deferred to PR-S3-5 per the empty-category-dir convention). |
| `tests/adversarial/test_payload_schema.py` | Modify | Extend existing schema round-trip tests to cover `tier_laundering` + `dlp_egress` categories. |

---

## §4 Tasks

### Component A — ADR-0017 (the load-bearing Slice-3 ADR)

- [ ] **Task 1 — Write ADR-0017: context section.**

  Files: Create `docs/adr/0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md`.

  Steps:
  - [ ] Write the ADR header and status block:
    ```markdown
    # ADR-0017 — Slice 3: trust-tier completion, MCP plugin transport, dual-LLM split

    ## Status

    Accepted

    **Date:** 2026-05-31

    ## Context
    ```
  - [ ] Write the Context section (no test step for docs; verification is `make docs-check` at end of component A):

    The context section explains the forces that drove three interlocked decisions that Slice 3 must resolve as a unit. Cite: ADR-0013 committed Slice 3 to delivering T1+T3+dual-LLM (line: "Slice 3 commits the full stack"); ADR-0008 made the original Slice-1 commitment; PRD §7.1 names the dual-LLM split as the load-bearing prompt-injection defence; PRD §5 names "Plugins are MCP servers" as a non-negotiable architectural invariant. The three forces are: (a) T1+T3+dual-LLM from ADR-0013's commitment; (b) the MCP transport must land before the dual-LLM split (the quarantined LLM runs as an MCP plugin — this dependency forces the transport into the same slice); (c) the PRD §5 hybrid-isolation invariant cannot stay silently relaxed while Slice 3 runs a subprocess plugin without container isolation. These three forces require one coherent ADR, not three separate records.

  Commit:
  ```
  docs(adr-0017): context section for trust-tier completion + MCP transport + dual-LLM (#TBD-slice3)
  ```

- [ ] **Task 2 — Write ADR-0017: Decision section (the five key decisions).**

  Files: Modify `docs/adr/0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md`.

  Steps:
  - [ ] Write the Decision section documenting the five structural decisions. Each sub-decision is a paragraph, not a bullet, to preserve the rationale:

    **Decision 1 — T1+T3 type system + nonce-gated `tag(T3, ...)`.** T1 and T3 `TrustTier` subclasses extend `_APPROVED_TIERS`. The `tag(T3, ...)` factory is capability-gated via a per-process random nonce compared by identity (`is`, not `==`) — not by frame introspection, which is forgeable via `sys.modules` manipulation. This nonce gate closes import-time forgery attacks without defending against arbitrary in-process code execution (which is outside the threat model; the adversarial corpus labels the `gc.get_objects()` vector `tier_laundering/gc_traversal_out_of_scope` with explicit rationale rather than treating it as an unresolved gap). Cite spec §3.2.

    **Decision 2 — MCP stdio subprocess as the plugin transport.** `StdioTransport` wraps the `model_context_protocol` SDK. The subprocess boundary provides process-level isolation without requiring container infrastructure in Slice 3. The quarantined LLM and `web.fetch` are both in-tree MCP plugins under this transport. `PluginTransport` is a `Protocol`; `StdioTransport` is the sole Slice-3 implementation; HTTP transport is deferred to Slice 5+; in-process `MemoryTransport` is permanently excluded (would collapse process-boundary isolation). Cite spec §4.1, §4.2.

    **Decision 3 — Two-axis naming: `subscriber_tier` ≠ content trust tier.** The manifest uses `subscriber_tier` (system/operator/user-plugin) for the capability-grant axis; `tier` in `TaggedContent` and audit rows refers to the content trust tier (T0-T3). The two axes are orthogonal; conflating them is a security error (`subscriber_tier="T3"` in a manifest is refused at handshake). This naming rule is enforced in the manifest schema, in `docs/glossary.md`, and by the manifest-handshake validation code. Cite spec §4.3.

    **Decision 4 — Hybrid-isolation relaxation with Slice-4 commitment.** Slice 3 ships the quarantined LLM as a subprocess under a dedicated `alfred-quarantine` UID with env scrubbing and fd-3 key delivery. This is a time-bounded relaxation of PRD §5 line 117 ("containerized with declared capabilities"). PRD §5 line 117 is amended (co-merged with this ADR) to read "hybrid isolation: containerized OR dedicated-UID-with-env-scrub during Slice 3, fully containerized from Slice 4 per ADR-0015." ADR-0015 is co-merged as the Slice-4 commitment record. Cite spec §5.7.

    **Decision 5 — PR-S3-0 pre-committed split into PR-S3-0a and PR-S3-0b; PR-S3-3 pre-committed split into PR-S3-3a and PR-S3-3b.** The original PR-S3-0 scope (five ADRs + three Alembic migrations + i18n + Docker infra) exceeded the ~600-line budget on prose alone. PR-S3-0a carries docs-only deliverables; PR-S3-0b carries schema/infra. PR-S3-3 splits transport (PR-S3-3a) from supervisor (PR-S3-3b). Both splits are pre-committed so implementors do not re-open the split decision at implementation time. Cite spec §1.3.

  Commit:
  ```
  docs(adr-0017): decision section — five structural Slice-3 decisions (#TBD-slice3)
  ```

- [ ] **Task 3 — Write ADR-0017: Consequences + Alternatives + References sections.**

  Files: Modify `docs/adr/0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md`.

  Steps:
  - [ ] Write Consequences (positive, negative, neutral):

    Positive:
    - The trust-tier story closes in one slice: T1+T3+dual-LLM are inseparable (T3 without the quarantined LLM is taint-tagging only; T1 without T3 provides no discriminator payoff), so completing them together eliminates the partial-implementation window that ADR-0013 held open.
    - Process-level isolation lands from day one of the dual-LLM split. The `alfred-quarantine` UID boundary is enforced by the OS; a misbehaving quarantined LLM subprocess literally cannot read the orchestrator's secrets file (`src/alfred/security/secrets.py:228-279` validates ownership against `os.getuid()`).
    - The `PluginTransport` Protocol is future-proof: HTTP transport (Slice 5+) implements the same surface without touching the orchestrator.

    Negative:
    - The subprocess transport adds cold-start latency (< 500ms per spec §7a.1). Operators with a single cold deployment will feel this on first restart.
    - The hybrid-isolation relaxation (no container isolation in Slice 3) means the `alfred-quarantine` UID's filesystem isolation is UID-separation only — the quarantined LLM can write to any UID-permitted path on the host. `bin/alfred-plugin-launcher` enforces `$XDG_RUNTIME_DIR/alfred/plugin-<id>/` as the write root via the `ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED=1` guard; Slice 4's `bwrap` policy hardens this.
    - The `DevGate` → `RealGate` flag-day migration (PR-S3-7) is a final-slice mandatory step. Skipping it leaves the nonce-token gate without a production backing store.

    Neutral:
    - The `manifest_version = 1` pin means any future manifest schema change that breaks backward compatibility requires incrementing to 2. This is intentional (explicit versioning discipline) rather than semver tolerance.
    - ADR-0009 status flips to superseded-for-new-adapters; existing Discord+TUI adapters are untouched through Slice 3.

  - [ ] Write Alternatives considered:

    **Option A — Ship T3-tagging at the comms boundary without the dual-LLM split.** Rejected per ADR-0013's §c analysis: T3 without the quarantined LLM is taint-tagging only; the PRD §7.1 invariant ("the privileged orchestrator never processes raw T3 content") is unmet.

    **Option B — HTTP plugin transport instead of stdio subprocess.** Rejected for Slice 3: HTTP requires TLS cert management, service discovery, and a separate network policy in Docker Compose — a materially larger infrastructure surface than stdio subprocess. The `PluginTransport` Protocol keeps HTTP available as a Slice-5+ option without coupling to it in Slice 3.

    **Option C — Frame introspection for `tag(T3, ...)` call-site enforcement.** Rejected per spec §3.2: `sys._getframe` is forgeable via `sys.modules` manipulation and provides no real caller identity. The nonce-token approach (`is`-comparison per-process random nonce) closes import-time forgery without the forgeable-via-modules vulnerability.

    **Option D — Keep DevGate and remove the flag-day.** Rejected: `DevGate` fails open for `operator`/`user-plugin` without a backing store, which is incompatible with the real `CapabilityGate` requirement from spec §8.4. The flag-day is the mechanism that ensures every production deployment migrates.

  - [ ] In Decision section, add a sixth structural decision block (arch-004 resolution):

    **Decision 6 — `QuarantinedUnavailable` lives in `src/alfred/plugins/errors.py`.** Spec §5.5 says `QuarantinedUnavailable` is "a distinct top-level exception" in `src/alfred/plugins/errors.py`. Spec §10.1 lists it as a public export of the supervisor module — a direct contradiction. Resolution: `QuarantinedUnavailable` lives in `src/alfred/plugins/errors.py` (spec §5.5 wins because it is the plugin-transport module that raises this error when the quarantined LLM is unavailable — the supervisor observes it but does not own it). `src/alfred/supervisor/errors.py` imports and re-exports it for ergonomic import in supervisor code, satisfying spec §10.1's "supervisor exposes it" requirement without placing the definition in the wrong module. The `ExtractionResult` `ImportError` (sec-002) is eliminated because `from alfred.plugins.errors import QuarantinedUnavailable` no longer fails with a circular import. Every Slice-3 PR that raises `QuarantinedUnavailable` imports it from `alfred.plugins.errors`.

  - [ ] Write References section linking PRD §5, PRD §7.1, ADR-0008, ADR-0013, ADR-0009, ADR-0015, ADR-0016, spec file, and code anchors.

  - [ ] Run `make docs-check` to confirm the file has no broken links:
    ```bash
    cd <repo-root> && make docs-check
    ```
    Expected: exits 0, last 3 lines show no errors.

  Commit:
  ```
  docs(adr-0017): consequences, alternatives, references (#TBD-slice3)
  ```

### Component B — ADR status flips

- [ ] **Task 4 — Flip ADR-0008 to Superseded by ADR-0017.**

  Files: Modify `docs/adr/0008-llm-output-trust-tier.md`.

  Steps:
  - [ ] Update the header block. Current Status line:
    ```
    - **Status**: Accepted (superseded in part by ADR-0013 — Slice-2 commitment to T1+T3+dual-LLM rescheduled to Slice 3)
    ```
    New Status line:
    ```
    - **Status**: Superseded by [ADR-0017](0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md) — Slice 3 delivers the full trust-tier stack this ADR committed to in Slice 1/2
    ```
    Also update the `- **Superseded by**: —` line:
    ```
    - **Superseded by**: [ADR-0017](0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md) (2026-05-31)
    ```
  - [ ] Run `make docs-check`.

  Commit:
  ```
  docs(adr-0008): status flip — superseded by ADR-0017 (#TBD-slice3)
  ```

- [ ] **Task 5 — Flip ADR-0013 to Superseded by ADR-0017.**

  Files: Modify `docs/adr/0013-defer-t1-t3-and-dual-llm.md`.

  Steps:
  - [ ] Update header block. Current:
    ```
    - **Status**: Accepted
    - **Superseded by**: —
    ```
    New:
    ```
    - **Status**: Superseded by [ADR-0017](0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md) — Slice 3 delivers the full stack this ADR committed to
    - **Superseded by**: [ADR-0017](0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md) (2026-05-31)
    ```
  - [ ] Add a one-paragraph note at the bottom of the Consequences section (before References): "ADR-0013 deferred T1+T3+dual-LLM to Slice 3. Slice 3 delivered all three per this commitment. ADR-0017 supersedes this ADR and records the five structural decisions that govern the implementation. The Slice-3 tracking issues for §6.10 deferred items are retired in PR-S3-7."
  - [ ] Run `make docs-check`.

  Commit:
  ```
  docs(adr-0013): status flip — superseded by ADR-0017 (#TBD-slice3)
  ```

- [ ] **Task 6 — Flip ADR-0009 status for new adapters.**

  Files: Modify `docs/adr/0009-comms-adapter-protocol-slice2-only.md`.

  Steps:
  - [ ] Update header block. Current:
    ```
    - **Status**: Accepted
    - **Superseded by**: —
    ```
    New:
    ```
    - **Status**: Superseded by [ADR-0016](0016-slice4-discord-tui-comms-mcp-rewrite.md) for new adapters; in-process Discord + TUI adapters unchanged through Slice 3
    - **Superseded by**: [ADR-0016](0016-slice4-discord-tui-comms-mcp-rewrite.md) (2026-05-31, for new adapters only)
    ```
  - [ ] Add a note at the bottom of the Consequences section: "Slice 3 ships a `CommsAdapterMCP` Protocol stub (`src/alfred/comms/mcp_protocol.py`) and a reference test plugin (`plugins/alfred-comms-test/`) that validates the MCP comms transport contract. The existing `DiscordAdapter` and `TuiAdapter` remain in-process through Slice 3, untouched. ADR-0016 commits Slice 4 to the full rewrite."
  - [ ] Run `make docs-check`.

  Commit:
  ```
  docs(adr-0009): status flip — superseded by ADR-0016 for new adapters (#TBD-slice3)
  ```

### Component B.1 — Slice-2.5 tracking issue retirement (spec §15.3)

**Why this lands in S3-0a:** Spec §15.3 explicitly assigns Slice-2.5 tracking issue retirement to "the first Slice-3 PR." PR-S3-7 previously claimed this task (docs-003, High). Moving it here keeps the supersession graph and issue-lifecycle in sync — when reviewers merge S3-0a they see the closed Slice-2.5 loop, not a dangling reference. The PR-S3-7 plan must remove its Task 16 in its own fixup pass.

- [ ] **Task 6a — Retire Slice-2.5 tracking issues in PR-S3-0a.**

  Files: Modify `docs/adr/0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md` (References section) and add a note to the ADR-0013 status flip (Task 5).

  Steps:
  - [ ] In ADR-0017's References section (Task 3), add a subsection:

    ```markdown
    ### Slice-2.5 issue retirement (spec §15.3)

    Per spec §15.3, the following Slice-2.5 deferral tracking issues are retired
    in this PR (the first Slice-3 PR):

    - Issue #122 — Slice-2.5: hooks perf-gate CI calibration (PR-S3-7 perf-gate
      hardens with host-load guard; no remaining open action).
    - Issue #123 — Slice-2.5: dotted-form hookpoint normalisation (open; tracked
      as Slice-3 follow-on in PR-S3-7 Task N per §6.10 deferred list).
    - Issue #124 — Slice-2.5: `subscribable_tiers` registration-time enforcement
      (shipped in PR #129; closed).
    - Issue #125 — Slice-2.5: post-UAT polish (shipped in PR #121; closed).

    Issues #122 (perf-gate calibration) and #123 (dotted-form) remain open at
    the GitHub level pending their Slice-3 work; the retirement here means the
    Slice-2.5 planning epoch ends and ownership transfers to the Slice-3 plan
    suite.
    ```

  - [ ] In ADR-0013's note paragraph added in Task 5, extend the last sentence:
    "The Slice-3 tracking issues for §6.10 deferred items are retired in PR-S3-0a (the first Slice-3 PR) per spec §15.3."

  - [ ] Run `make docs-check`.

  Commit:
  ```
  docs(adr-0017): retire Slice-2.5 tracking issues per spec §15.3 (#TBD-slice3)
  ```

### Component C — Slice-4 commitment stubs (ADR-0015 + ADR-0016)

- [ ] **Task 7 — Write ADR-0015 stub: Slice-4 containerised quarantined LLM.**

  Files: Create `docs/adr/0015-slice4-containerised-quarantined-llm.md`.

  Steps:
  - [ ] Write the full ADR stub (≤ 60 lines per the 100-line ADR rule):

    ```markdown
    # ADR-0015 — Slice 4: containerise the quarantined-LLM subprocess

    ## Status

    Proposed

    **Date:** 2026-05-31

    ## Context

    Slice 3 ships the quarantined LLM as an MCP stdio subprocess under the
    `alfred-quarantine` OS user with env scrubbing and fd-3 key delivery
    (ADR-0017 §5). This is a deliberate, time-bounded relaxation of PRD §5
    line 117 ("containerized with declared capabilities"). The UID-separation
    boundary prevents the subprocess from reading the orchestrator's secrets
    file; it does NOT prevent arbitrary filesystem writes to `alfred-quarantine`-
    owned paths or outbound network calls to any reachable destination.

    PRD §5 line 117's full invariant requires kernel-namespace isolation: no
    view of the host filesystem except declared mounts; network restricted to
    the declared allowlist; no capability to spawn further subprocesses. Without
    this commitment, the relaxation introduced in Slice 3 silently persists.

    ## Decision

    Slice 4 migrates the quarantined-LLM subprocess to a container with full
    kernel-namespace isolation using Linux `bwrap` (AlfredOS Docker default),
    macOS `sandbox-exec`, and a Windows stub policy. The `bin/alfred-plugin-launcher`
    receives the per-OS sandbox policy files in Slice 4; `ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED=1`
    becomes a development-only escape hatch that refuses in production.

    ## Consequences

    ### Positive
    - PRD §5 line 117 invariant fully satisfied from Slice 4 onwards.
    - Outbound network calls from the quarantined LLM are kernel-enforced against
      the declared allowlist, not just policy-checked.

    ### Negative
    - Per-OS sandbox policy files must be maintained and tested. The Linux policy
      is the AlfredOS primary target; macOS and Windows policies are best-effort.
    - The `bwrap` cold-start overhead adds ~50-100ms to the subprocess spawn
      path (within the < 500ms cold-start budget from spec §7a.1).

    ### Neutral
    - `StdioTransport` and `AlfredPluginSession` are unchanged; the container
      boundary is below the transport layer.

    ## References

    - [PRD §5](../../PRD.md#5-architecture-overview) — hybrid-isolation invariant (line 117).
    - [ADR-0017](0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md) — Slice-3 hybrid-isolation decision.
    - [Spec §5.7](../superpowers/specs/2026-05-30-slice-3-trust-tier-completion-design.md#57-co-merged-slice-4-containerisation-adr-commitment--prd-5-amendment) — co-merged commitment rationale.
    ```

  - [ ] Run `make docs-check`.

  Commit:
  ```
  docs(adr-0015): Slice-4 containerised quarantined-LLM commitment stub (#TBD-slice3)
  ```

- [ ] **Task 8 — Write ADR-0016 stub: Slice-4 Discord/TUI comms-MCP rewrite.**

  Files: Create `docs/adr/0016-slice4-discord-tui-comms-mcp-rewrite.md`.

  Steps:
  - [ ] Write the full ADR stub (≤ 60 lines):

    ```markdown
    # ADR-0016 — Slice 4: rewrite Discord and TUI adapters as MCP plugins

    ## Status

    Proposed

    **Date:** 2026-05-31

    ## Context

    ADR-0009 shipped Discord and TUI adapters as in-process Python Protocols,
    explicitly noting that "the rewrite is intentional" and that "the Slice-3
    reviewer gate re-checks PRD §5 compliance." Slice 3 ships the `PluginTransport`
    Protocol and `StdioTransport` implementation (ADR-0017 §4) plus a
    `CommsAdapterMCP` Protocol stub and a reference test plugin
    (`plugins/alfred-comms-test/`). The in-process adapters remain unchanged
    through Slice 3.

    PRD §5 requires all comms surfaces to speak MCP. The MCP transport is now
    shipped. The remaining gap is the adapter implementations themselves.

    ## Decision

    Slice 4 rewrites `DiscordAdapter` and `TuiAdapter` as MCP plugins under the
    Slice-3 `StdioTransport`. The message-contract definition (full field schema,
    error shapes, rate-limit signalling) co-defined with this ADR at Slice-4
    implementation time. The four wire methods contracted in the Slice-3
    reference test plugin (`lifecycle.start`, `lifecycle.stop`,
    `inbound.message`, `adapter.health`) are the seed; Slice 4 extends this
    contract with Discord-specific fields (embeds T3-promotion, attachment
    handling) and finalises the ADR-0009 polarity-inversion note.

    ## Consequences

    ### Positive
    - PRD §5 "Plugins are MCP servers" invariant fully satisfied for comms adapters.
    - T3-promotion for Discord embeds/attachments/polls lands naturally alongside
      the MCP rewrite — the DLP scan is at the transport boundary, not in-adapter.

    ### Negative
    - The `CommsAdapter` in-process Protocol (`src/alfred/comms/`) is removed.
      Any external code (custom personas, third-party skills) that imported
      concrete adapter classes directly rather than using the Protocol type will
      break. The import-isolation AST test (`tests/unit/comms/test_no_direct_adapter_imports.py`)
      already enforces this invariant, so breakage is restricted to code that
      bypasses the test gate.

    ### Neutral
    - The `IdentityResolver` placement (host-side in Slice 3, per §9.1) is
      revisited when the full host-side callback wire type is designed for Slice 4.

    ## References

    - [PRD §5](../../PRD.md#5-architecture-overview) — "Plugins are MCP servers."
    - [ADR-0009](0009-comms-adapter-protocol-slice2-only.md) — in-process Protocol; superseded by this ADR for new adapters.
    - [ADR-0017](0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md) — Slice-3 transport decision.
    - [Spec §9](../superpowers/specs/2026-05-30-slice-3-trust-tier-completion-design.md#9-adr-0009-comms-mcp-rewrite-fork-8) — ADR-0009 comms-MCP rewrite scope.
    ```

  - [ ] Run `make docs-check`.

  Commit:
  ```
  docs(adr-0016): Slice-4 Discord/TUI comms-MCP rewrite commitment stub (#TBD-slice3)
  ```

### Component D — PRD §5 line 117 amendment

- [ ] **Task 9 — Amend PRD §5 line 117 hybrid-isolation invariant.**

  Files: Modify `PRD.md`.

  Steps:
  - [ ] Locate line 117 in `PRD.md`. Current text:
    ```
    - **Hybrid isolation.** Plugins declare a trust tier; official → in-process subprocess; third-party or agent-authored → containerized with declared capabilities (network allowlist, fs mounts, secret IDs).
    ```
    New text:
    ```
    - **Hybrid isolation.** Plugins declare a trust tier; official → in-process subprocess; third-party or agent-authored → containerized with declared capabilities (network allowlist, fs mounts, secret IDs). **Slice 3 relaxation:** the quarantined-LLM plugin runs as a dedicated-UID subprocess with env scrubbing rather than a container — a time-bounded deviation recorded in [ADR-0017](docs/adr/0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md). Full containerisation lands in Slice 4 per [ADR-0015](docs/adr/0015-slice4-containerised-quarantined-llm.md).
    ```
  - [ ] Run `make docs-check` to confirm the new ADR links resolve.

  Commit:
  ```
  docs(prd): §5 line 117 hybrid-isolation amendment — Slice-3 relaxation + Slice-4 commitment (#TBD-slice3)
  ```

### Component E — `audit_row_schemas.py`

- [ ] **Task 10 — Write failing test for `audit_row_schemas.py`.**

  Files: Create `tests/unit/audit/test_audit_row_schemas.py`.

  Steps:
  - [ ] Write the test module:

    ```python
    """Tests for src/alfred/audit/audit_row_schemas.py.

    Each constant is a Final[frozenset[str]] per spec §13. Tests assert:
    - Every exported name is a frozenset of strings.
    - The frozenset values are non-empty plain strings (no typing constructs leaked in).
    - The exact field lists match the spec §13 tables (regression against accidental field removal).
    - Nothing from `typing` leaks into the frozenset values (frozenset members are str, not type objects).
    """

    from __future__ import annotations

    from typing import Final
    import pytest

    from alfred.audit import audit_row_schemas


    CONSTANT_NAMES: Final[tuple[str, ...]] = (
        "PLUGIN_LIFECYCLE_FIELDS",
        "PLUGIN_LIFECYCLE_CRASHED_FIELDS",
        "PLUGIN_LIFECYCLE_QUARANTINED_FIELDS",
        "PLUGIN_GRANT_FIELDS",
        "QUARANTINE_EXTRACT_FIELDS",
        "WEB_FETCH_FIELDS",
        "SUPERVISOR_BREAKER_RESET_FIELDS",
        "T3_BOUNDARY_REFUSAL_FIELDS",
        "T1_INGRESS_FIELDS",
        "T1_DOWNGRADE_FIELDS",
        "T3_DERIVED_DOWNGRADE_FIELDS",
        "PLUGIN_GRANT_REVOKED_INFLIGHT_FIELDS",
        "SUPERVISOR_CAPABILITY_GATE_UNAVAILABLE_FIELDS",
        "SUPERVISOR_CONFIG_INSECURE_FIELDS",
        "SUPERVISOR_ACTION_TIMEOUT_FIELDS",
        "WEB_ALLOWLIST_MANIFEST_BROADENING_CAPPED_FIELDS",
        "DLP_OUTBOUND_REFUSED_FIELDS",
        "SUPERVISOR_BREAKER_TRIPPED_FIELDS",
    )


    @pytest.mark.parametrize("name", CONSTANT_NAMES)
    def test_constant_is_frozenset_of_strings(name: str) -> None:
        """Every audit row field-list constant is a frozenset[str]."""
        value = getattr(audit_row_schemas, name)
        assert isinstance(value, frozenset), f"{name} must be frozenset, got {type(value)}"
        assert len(value) > 0, f"{name} must be non-empty"
        for field in value:
            assert isinstance(field, str), f"{name} member {field!r} is not str"
            assert not field.startswith("_"), f"{name} member {field!r} looks private; field names are public"


    def test_crashed_fields_is_superset_of_lifecycle_fields() -> None:
        """PLUGIN_LIFECYCLE_CRASHED_FIELDS must be a superset of PLUGIN_LIFECYCLE_FIELDS (spec §5.6)."""
        assert audit_row_schemas.PLUGIN_LIFECYCLE_FIELDS.issubset(
            audit_row_schemas.PLUGIN_LIFECYCLE_CRASHED_FIELDS
        ), "crashed fields must include all lifecycle fields plus exception_type"
        assert "exception_type" in audit_row_schemas.PLUGIN_LIFECYCLE_CRASHED_FIELDS


    def test_correlation_id_present_in_all_constants() -> None:
        """Every audit row family includes correlation_id per spec §13 audit-row discipline."""
        for name in CONSTANT_NAMES:
            value = getattr(audit_row_schemas, name)
            assert "correlation_id" in value, f"{name} is missing correlation_id"


    def test_plugin_lifecycle_fields_exact() -> None:
        """PLUGIN_LIFECYCLE_FIELDS exact field list per spec §13."""
        assert audit_row_schemas.PLUGIN_LIFECYCLE_FIELDS == frozenset({
            "plugin_id", "manifest_subscriber_tier", "manifest_version",
            "sandbox_profile", "exit_code", "signal", "restart_count",
            "breaker_state", "correlation_id",
        })


    def test_plugin_grant_fields_exact() -> None:
        """PLUGIN_GRANT_FIELDS exact field list per spec §13."""
        assert audit_row_schemas.PLUGIN_GRANT_FIELDS == frozenset({
            "plugin_id", "subscriber_tier", "hookpoint", "operator_user_id",
            "proposal_branch", "correlation_id",
        })


    def test_quarantine_extract_fields_exact() -> None:
        """QUARANTINE_EXTRACT_FIELDS exact field list per spec §13."""
        assert audit_row_schemas.QUARANTINE_EXTRACT_FIELDS == frozenset({
            "extraction_mode", "provider", "schema_name", "schema_version",
            "retry_count", "trust_tier_of_trigger", "result", "correlation_id",
        })


    def test_web_fetch_fields_exact() -> None:
        """WEB_FETCH_FIELDS exact field list per spec §13."""
        assert audit_row_schemas.WEB_FETCH_FIELDS == frozenset({
            "url", "domain", "status_code", "content_handle_id",
            "fetch_depth", "rate_limit_bucket", "manifest_commit_hash",
            "trust_tier_of_result", "dlp_scan_result", "canary_tripped",
            "triggering_user_id",
            "correlation_id",
        })


    def test_no_typing_constructs_leaked() -> None:
        """Frozenset members must be plain strings; no typing.Final, type objects, or annotations leaked."""
        import typing
        for name in CONSTANT_NAMES:
            value = getattr(audit_row_schemas, name)
            for field in value:
                assert not isinstance(field, type), f"{name} member {field!r} is a type, not a string"
                assert not hasattr(typing, field), f"{name} member {field!r} looks like a typing name"


    def test_quarantine_extract_result_values_subset_of_migration_domain() -> None:
        """QUARANTINE_EXTRACT_FIELDS includes 'result'; guard against drift with migration domain.

        Migration 0005 (base) allows: refused.
        Migration 0007 (Slice 3) adds: extracted, malformed_exhausted, content_expired,
        load_refused, crashed, quarantined, reloaded, requested, approved, denied, revoked,
        tripped, reset.

        This test verifies that the four quarantine.extract result values documented in
        spec §13 are a subset of the combined allowed domain from migrations 0005 + 0007.
        It does NOT import the migration module (avoids circular imports) but hardcodes
        the migration-defined domain, with a comment to update both when a new migration
        extends the domain. (mem-008: result-value Literal drift guard.)
        """
        # Combined allowed domain from migration 0005 (base) + 0007 (Slice 3).
        # Update this set when a future migration extends AuditEntry.result allowed values.
        _MIGRATION_ALLOWED_RESULTS: frozenset[str] = frozenset({
            # migration 0005 base set:
            "refused",
            # migration 0007 Slice-3 additions:
            "extracted", "malformed_exhausted", "content_expired",
            "load_refused", "crashed", "quarantined", "reloaded",
            "requested", "approved", "denied", "revoked",
            "tripped", "reset",
        })
        # The four quarantine.extract result values (spec §13):
        _QUARANTINE_EXTRACT_RESULTS: frozenset[str] = frozenset({
            "extracted", "refused", "malformed_exhausted", "content_expired",
        })
        assert "result" in audit_row_schemas.QUARANTINE_EXTRACT_FIELDS, (
            "QUARANTINE_EXTRACT_FIELDS must contain 'result' field"
        )
        orphans = _QUARANTINE_EXTRACT_RESULTS - _MIGRATION_ALLOWED_RESULTS
        assert not orphans, (
            f"quarantine.extract result values {orphans!r} are not in the migration-allowed "
            f"domain {_MIGRATION_ALLOWED_RESULTS!r}. Update migration 0007 or fix the constant."
        )
    ```

  - [ ] Run the test expecting FAIL (module does not yet exist):
    ```bash
    cd <repo-root> && uv run pytest tests/unit/audit/test_audit_row_schemas.py -q 2>&1 | head -20
    ```
    Expected: `ModuleNotFoundError` or `ImportError` — test collection fails because `audit_row_schemas` does not exist yet.

- [ ] **Task 11 — Implement `src/alfred/audit/audit_row_schemas.py`.**

  Files: Create `src/alfred/audit/audit_row_schemas.py`.

  Steps:
  - [ ] Write the module (verbatim from spec §13, extended with the full constant set):

    ```python
    """Audit row field-list constants for all Slice-3 audit row families.

    Every constant is a ``Final[frozenset[str]]`` naming the fields an audit
    row in that family carries. Placement rationale: Slice 3 introduces five
    emitter subsystems (plugins/, supervisor/, security/, orchestrator/,
    identity/). Centralising constants here provides a single import surface
    that prevents field-name drift; the Slice-2.5 co-located-with-emitter
    pattern is superseded because the emitter count crossed the threshold
    where mirroring becomes rot (spec §13).

    Usage::

        from alfred.audit import audit_row_schemas
        assert "plugin_id" in audit_row_schemas.PLUGIN_LIFECYCLE_FIELDS

    **Never include ``str(exc)`` or ``exc.args`` in audit row fields** — they
    may carry T3 content fragments. Only the Python type name (``type(exc).__name__``)
    is safe per spec §5.6 and the ``_SUBSCRIBER_ERROR_AUDIT_FIELDS`` pattern
    from Slice 2.5.
    """

    from __future__ import annotations

    from typing import Final

    # ---------------------------------------------------------------------------
    # plugin.lifecycle.* family
    # ---------------------------------------------------------------------------

    # Fields common to loaded / load_refused / crashed / quarantined / reloaded.
    # crashed rows additionally carry exception_type (see PLUGIN_LIFECYCLE_CRASHED_FIELDS).
    PLUGIN_LIFECYCLE_FIELDS: Final = frozenset({
        "plugin_id",
        "manifest_subscriber_tier",
        "manifest_version",
        "sandbox_profile",
        "exit_code",
        "signal",
        "restart_count",
        "breaker_state",
        "correlation_id",
    })

    # crashed-specific superset — Python type name only, never str(exc) or exc.args
    # (a misbehaving subprocess can carry T3 fragments into its crash trace; see spec §5.6)
    PLUGIN_LIFECYCLE_CRASHED_FIELDS: Final = PLUGIN_LIFECYCLE_FIELDS | frozenset({
        "exception_type",
    })

    # quarantined-specific superset — emitted when circuit breaker trips or post-handshake
    # hook-registration attack detected (SIGKILL path, spec §4.6, §10.2).
    PLUGIN_LIFECYCLE_QUARANTINED_FIELDS: Final = PLUGIN_LIFECYCLE_FIELDS | frozenset({
        "quarantine_reason",   # "circuit_breaker_open" | "protocol_violation"
        "trip_count",
    })

    # ---------------------------------------------------------------------------
    # plugin.grant.* family
    # ---------------------------------------------------------------------------

    # Fields for requested / approved / denied / revoked rows.
    # Note: field is "subscriber_tier" not "tier" — the subscriber-capability axis
    # (system/operator/user-plugin), orthogonal to content trust tier (T0-T3).
    # See spec §4.3 two-axis naming rule and docs/glossary.md.
    PLUGIN_GRANT_FIELDS: Final = frozenset({
        "plugin_id",
        "subscriber_tier",
        "hookpoint",
        "operator_user_id",
        "proposal_branch",
        "correlation_id",
    })

    # ---------------------------------------------------------------------------
    # quarantine.extract family
    # ---------------------------------------------------------------------------

    # Fields for every quarantine.extract audit row (extracted / refused / malformed_exhausted
    # / content_expired result values — see migration 0007_audit_result_slice3_values).
    QUARANTINE_EXTRACT_FIELDS: Final = frozenset({
        "extraction_mode",   # "native_constrained" | "json_object_unconstrained" | "prompt_embedded_fallback"
        "provider",
        "schema_name",
        "schema_version",
        "retry_count",
        "trust_tier_of_trigger",   # always "T3" for quarantine.extract rows
        "result",                  # "extracted" | "refused" | "malformed_exhausted" | "content_expired"
        "correlation_id",
    })

    # ---------------------------------------------------------------------------
    # tool.web.fetch family
    # ---------------------------------------------------------------------------

    # Fields for every tool.web.fetch audit row.
    # manifest_commit_hash: forensic correlation for plugin version at fetch time (spec §7.12).
    # triggering_user_id: canonical_user_id of conversation turn — per-user forensic attribution (spec §7.12).
    WEB_FETCH_FIELDS: Final = frozenset({
        "url",
        "domain",
        "status_code",
        "content_handle_id",
        "fetch_depth",
        "rate_limit_bucket",
        "manifest_commit_hash",
        "trust_tier_of_result",    # always "T3" for web.fetch rows
        "dlp_scan_result",
        "canary_tripped",          # bool
        "triggering_user_id",
        "correlation_id",
    })

    # ---------------------------------------------------------------------------
    # supervisor.breaker.* family
    # ---------------------------------------------------------------------------

    # Fields for supervisor.breaker.reset rows (operator-initiated circuit-breaker reset).
    # See also SUPERVISOR_BREAKER_TRIPPED_FIELDS for the tripped event.
    SUPERVISOR_BREAKER_RESET_FIELDS: Final = frozenset({
        "component_id",
        "old_state",
        "new_state",
        "trip_count",
        "operator_user_id",
        "correlation_id",
    })

    # supervisor.breaker.tripped — distinct event from breaker.reset (spec §14 hookpoint table)
    SUPERVISOR_BREAKER_TRIPPED_FIELDS: Final = frozenset({
        "component_id",
        "trip_count",
        "last_failure_type",
        "breaker_state",   # always "OPEN" at trip time
        "correlation_id",
    })

    # ---------------------------------------------------------------------------
    # security.t3_boundary.refused family
    # ---------------------------------------------------------------------------

    # Fields for security.t3_boundary.refused audit rows.
    # caller_module_unverified: heuristic frame-derived label; NOT an authenticated identity (spec §3.2).
    T3_BOUNDARY_REFUSAL_FIELDS: Final = frozenset({
        "caller_module_unverified",
        "attempted_tier",
        "hookpoint",
        "correlation_id",
    })

    # ---------------------------------------------------------------------------
    # identity.t1_ingress family
    # ---------------------------------------------------------------------------

    # Fields emitted at the identity.t1_ingress hookpoint (role × adapter classification).
    T1_INGRESS_FIELDS: Final = frozenset({
        "user_id",
        "adapter_name",
        "trust_tier_of_trigger",
        "correlation_id",
    })

    # identity.t1_downgrade — explicit T1 → T2 broadcast-safe conversion.
    # downgrade_explicit=True required on the audit row; see spec §3.6.
    T1_DOWNGRADE_FIELDS: Final = frozenset({
        "user_id",
        "trust_tier_of_trigger",
        "trust_tier_of_response",
        "downgrade_explicit",
        "correlation_id",
    })

    # ---------------------------------------------------------------------------
    # quarantine.t3_derived_downgrade family (rvw-003 — cross-PR constant)
    # ---------------------------------------------------------------------------

    # Fields for quarantine.t3_derived_downgrade audit rows — emitted by
    # src/alfred/security/quarantine.py::downgrade_to_orchestrator (PR-S3-4) when
    # T3DerivedData is gate-checked and converted to a plain dict for orchestrator
    # consumption (spec §3.7). Defined here (PR-S3-0a) rather than PR-S3-4 so the
    # field-list lives in the single import surface; the constant is consumed by
    # PR-S3-4 once that PR ships.
    #
    # Distinct trust transition from T1 → T2 (T1_DOWNGRADE_FIELDS), so the audit
    # schema family is also distinct — see rvw-003 in spec §13.
    T3_DERIVED_DOWNGRADE_FIELDS: Final = frozenset({
        "trust_tier_of_trigger",   # always "T3" — the originating tier of the T3DerivedData
        "trust_tier_of_response",  # always "T2" — the post-downgrade tier
        "downgrade_explicit",      # always True — gate check enforces this is deliberate
        "correlation_id",
    })

    # ---------------------------------------------------------------------------
    # plugin.grant.revoked_inflight family
    # ---------------------------------------------------------------------------

    # Fields for in-flight dispatch denial rows (grant revoked while dispatch in progress).
    PLUGIN_GRANT_REVOKED_INFLIGHT_FIELDS: Final = frozenset({
        "plugin_id",
        "hookpoint",
        "operator_user_id",
        "in_flight_dispatch_id",
        "correlation_id",
    })

    # ---------------------------------------------------------------------------
    # supervisor.capability_gate_unavailable family
    # ---------------------------------------------------------------------------

    # One row per state-transition: entering_fail_closed AND exiting_fail_closed.
    # denied_dispatch_count: cumulative count since entering fail-closed (exit row only; spec §8.1).
    SUPERVISOR_CAPABILITY_GATE_UNAVAILABLE_FIELDS: Final = frozenset({
        "state_transition",           # "entering_fail_closed" | "exiting_fail_closed"
        "denied_dispatch_count",
        "backing_store_error_type",
        "correlation_id",
    })

    # ---------------------------------------------------------------------------
    # supervisor.config_insecure family
    # ---------------------------------------------------------------------------

    # Emitted at every plugin start when ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED=1 (spec §4.8).
    # plugin_id may be absent for startup-level rows (not per-plugin-launch).
    SUPERVISOR_CONFIG_INSECURE_FIELDS: Final = frozenset({
        "insecure_config_key",   # e.g. "ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED", "web_fetch.skip_tls_verify"
        "plugin_id",
        "correlation_id",
    })

    # ---------------------------------------------------------------------------
    # supervisor.action_timeout family
    # ---------------------------------------------------------------------------

    # One row per turn that exceeds orchestrator.action_deadline_seconds (spec §10.5).
    # phase_at_timeout: best-effort label for the phase in progress at deadline.
    SUPERVISOR_ACTION_TIMEOUT_FIELDS: Final = frozenset({
        "user_id",
        "action_duration_seconds",
        "deadline_seconds",
        "phase_at_timeout",    # "web_fetch" | "quarantine_extract" | "hookchain" | "unknown"
        "correlation_id",
    })

    # ---------------------------------------------------------------------------
    # web.allowlist.manifest_broadening_capped family
    # ---------------------------------------------------------------------------

    # Emitted on every manifest load where the effective allowlist is narrower
    # than the manifest's declared allowed_domains (spec §7.4).
    WEB_ALLOWLIST_MANIFEST_BROADENING_CAPPED_FIELDS: Final = frozenset({
        "plugin_id",
        "manifest_domains",
        "operator_allowed_domains",
        "capped_domains",
        "correlation_id",
    })

    # ---------------------------------------------------------------------------
    # security.dlp_outbound_refused family
    # ---------------------------------------------------------------------------

    # Fields for security.dlp_outbound_refused audit rows (outbound DLP scan failure).
    DLP_OUTBOUND_REFUSED_FIELDS: Final = frozenset({
        "wire",
        "direction",
        "scan_rule_matched",
        "field_name",
        "correlation_id",
    })
    ```

  - [ ] Run the test expecting PASS:
    ```bash
    cd <repo-root> && uv run pytest tests/unit/audit/test_audit_row_schemas.py -v 2>&1 | tail -20
    ```
    Expected: all tests pass.

  - [ ] Run mypy + pyright:
    ```bash
    cd <repo-root> && uv run mypy src/alfred/audit/audit_row_schemas.py && uv run pyright src/alfred/audit/audit_row_schemas.py
    ```
    Expected: no errors.

  Commit:
  ```
  feat(audit): audit_row_schemas.py — 18 Final frozenset constants for Slice-3 audit row families (17 spec §13 + T3_DERIVED_DOWNGRADE_FIELDS) (#TBD-slice3)
  ```

### Component F — `src/alfred/audit/__init__.py` public surface update

- [ ] **Task 12 — Update `src/alfred/audit/__init__.py` to re-export `audit_row_schemas`.**

  Files: Modify `src/alfred/audit/__init__.py`.

  Steps:
  - [ ] **Verify existing import paths** (mem-006: dependency paths must exist before the re-export is written):
    ```bash
    cd <repo-root> && uv run python -c \
      'from alfred.audit.log import AuditWriter; from alfred.memory.models import AuditEntry; print("OK", AuditWriter, AuditEntry)'
    ```
    Expected: prints `OK` with both class references. If either fails, update the import path in the `__init__.py` body below to match the actual module location before proceeding.

  - [ ] Write failing test for the public surface:

    ```python
    # tests/unit/audit/test_audit_init.py
    """Verify alfred.audit public surface includes audit_row_schemas per spec §13."""

    from alfred import audit
    from alfred.audit import audit_row_schemas, AuditWriter, AuditEntry


    def test_audit_row_schemas_importable_from_package() -> None:
        """audit_row_schemas is directly importable from alfred.audit (spec §13)."""
        assert hasattr(audit, "audit_row_schemas")


    def test_audit_writer_importable() -> None:
        """AuditWriter remains accessible from alfred.audit after the update."""
        assert AuditWriter is not None


    def test_audit_entry_importable() -> None:
        """AuditEntry remains accessible from alfred.audit after the update."""
        assert AuditEntry is not None
    ```

    Run expecting FAIL (`audit_row_schemas` not yet in `__init__.py`):
    ```bash
    cd <repo-root> && uv run pytest tests/unit/audit/test_audit_init.py -q 2>&1 | head -10
    ```

  - [ ] Implement: update `src/alfred/audit/__init__.py` to:
    ```python
    """Alfred audit package.

    Public surface (spec §13):
    - audit_row_schemas: Final[frozenset[str]] constants for all Slice-3 audit row families.
    - AuditWriter: the append-only audit log writer.
    - AuditEntry: the SQLAlchemy audit log row model.

    Downstream PRs import: ``from alfred.audit import audit_row_schemas``
    No subsystem needs to import deeper than this package.
    """

    from alfred.audit import audit_row_schemas as audit_row_schemas
    from alfred.audit.log import AuditWriter as AuditWriter
    from alfred.memory.models import AuditEntry as AuditEntry

    __all__ = ["audit_row_schemas", "AuditWriter", "AuditEntry"]
    ```

  - [ ] Run tests expecting PASS:
    ```bash
    cd <repo-root> && uv run pytest tests/unit/audit/ -v 2>&1 | tail -15
    ```

  - [ ] Run mypy + pyright on the updated `__init__.py`:
    ```bash
    cd <repo-root> && uv run mypy src/alfred/audit/__init__.py && uv run pyright src/alfred/audit/__init__.py
    ```

  Commit:
  ```
  feat(audit): re-export audit_row_schemas from alfred.audit public surface (#TBD-slice3)
  ```

### Component G — `AuditWriter.append_schema()` helper (Cluster 4)

**Why this lands in S3-0a:** All Slice-3 audit-emit call sites in PR-S3-3a, PR-S3-4, PR-S3-2, PR-S3-3b, and PR-S3-5 pass `fields=audit_row_schemas.X_FIELDS` plus ad-hoc kwargs and omit every `AuditWriter.append()` required kwarg (`subject`, `result`, `cost_estimate_usd`, `trace_id`, `actor_user_id`, `trust_tier_of_trigger`). They also drop the coroutine (no `await`). Adding the helper here — before any implementation PR ships — gives downstream PRs a single typed entry point and prevents the signature mismatch from propagating. Cross-references: rvw-001 (Critical, corroborated by memory-engineer), Cluster 4.

- [ ] **Task 12a — Write failing test for `AuditWriter.append_schema()`.**

  Files: Modify `tests/unit/audit/test_log.py`.

  Steps:
  - [ ] Add the following test cases to `tests/unit/audit/test_log.py` (after existing tests):

    ```python
    # --- append_schema helper (Cluster 4, rvw-001) ---

    import inspect
    from unittest.mock import AsyncMock, MagicMock
    from alfred.audit.log import AuditWriter
    from alfred.audit import audit_row_schemas


    def _make_writer() -> tuple[AuditWriter, AsyncMock]:
        """Return (writer, session_mock) for testing."""
        session_mock = AsyncMock()
        session_mock.add = MagicMock()
        session_mock.flush = AsyncMock()
        cm = AsyncMock()
        cm.__aenter__ = AsyncMock(return_value=session_mock)
        cm.__aexit__ = AsyncMock(return_value=False)
        factory = MagicMock(return_value=cm)
        return AuditWriter(session_factory=factory), session_mock


    @pytest.mark.asyncio
    async def test_append_schema_accepts_fields_kwarg() -> None:
        """append_schema() forwards all required append() kwargs plus field set."""
        writer, session_mock = _make_writer()
        await writer.append_schema(
            fields=audit_row_schemas.PLUGIN_LIFECYCLE_FIELDS,
            event="plugin.lifecycle.loaded",
            actor_user_id=None,
            subject={"plugin_id": "alfred-web-fetch", "manifest_subscriber_tier": "system",
                     "manifest_version": 1, "sandbox_profile": "unsandboxed",
                     "exit_code": None, "signal": None, "restart_count": 0,
                     "breaker_state": "CLOSED", "correlation_id": "trace-abc"},
            trust_tier_of_trigger="T0",
            result="loaded",
            cost_estimate_usd=0.0,
            trace_id="trace-abc",
        )
        assert session_mock.add.called


    @pytest.mark.asyncio
    async def test_append_schema_rejects_subject_missing_field() -> None:
        """append_schema() raises ValueError when subject dict is missing a declared field."""
        writer, _ = _make_writer()
        with pytest.raises(ValueError, match="missing required fields"):
            await writer.append_schema(
                fields=audit_row_schemas.PLUGIN_LIFECYCLE_FIELDS,
                event="plugin.lifecycle.loaded",
                actor_user_id=None,
                subject={"plugin_id": "alfred-web-fetch"},  # missing all other fields
                trust_tier_of_trigger="T0",
                result="loaded",
                cost_estimate_usd=0.0,
                trace_id="trace-abc",
            )


    def test_all_audit_row_schema_fields_live_in_known_subject_space() -> None:
        """Every field name in every constant is a non-empty string with no whitespace.

        This is the AuditEntry column-space guard (Cluster 4): no constant may
        introduce a field name that is empty, contains whitespace (would break
        SQL/JSON key hygiene), or starts with an underscore (private convention).
        It cannot verify against the JSON subject dict at import time — that
        verification is the append_schema() runtime check — but it guards against
        typo-introduced field names that would fail silently.
        """
        import re
        valid_field = re.compile(r"^[a-z][a-z0-9_]*$")
        constant_names = [
            name for name in dir(audit_row_schemas)
            if name.isupper() and isinstance(getattr(audit_row_schemas, name), frozenset)
        ]
        assert len(constant_names) >= 18, f"Expected ≥18 constants, got {len(constant_names)}"
        for name in constant_names:
            for field in getattr(audit_row_schemas, name):
                assert valid_field.match(field), (
                    f"{name} member {field!r} fails snake_case field-name rule; "
                    "all audit subject dict keys must be lowercase snake_case"
                )
    ```

  - [ ] Run tests expecting FAIL (`append_schema` does not yet exist):
    ```bash
    cd <repo-root> && uv run pytest tests/unit/audit/test_log.py -q -k "append_schema" 2>&1 | head -15
    ```
    Expected: `AttributeError: 'AuditWriter' object has no attribute 'append_schema'`.

- [ ] **Task 12b — Implement `AuditWriter.append_schema()` in `src/alfred/audit/log.py`.**

  Files: Modify `src/alfred/audit/log.py`.

  Steps:
  - [ ] Add the `append_schema` method to `AuditWriter` after the existing `append` method:

    ```python
    async def append_schema(
        self,
        *,
        fields: frozenset[str],
        event: str,
        actor_user_id: str | None,
        subject: dict[str, Any],
        trust_tier_of_trigger: str,
        result: str,
        cost_estimate_usd: float,
        trace_id: str,
        actor_persona: str = "alfred",
        persona_id: str | None = None,
        cost_actual_usd: float | None = None,
        language: str = "en-US",
    ) -> None:
        """Record a single audit entry, validating subject keys against ``fields``.

        ``fields`` is a ``Final[frozenset[str]]`` constant from
        ``alfred.audit.audit_row_schemas`` naming every key the audit row in
        that family carries. This method validates that ``subject`` contains all
        declared fields before writing — surfacing field-name drift at the emit
        site rather than silently producing a malformed row.

        All other parameters forward directly to ``append()``. See ``append()``
        docstring for parameter semantics.

        Raises:
            ValueError: If ``subject`` is missing one or more fields declared in
                ``fields``. The message names the missing fields so callers can
                fix the emit site without reading the constant definition.

        This method lands in PR-S3-0a so every downstream Slice-3 PR (S3-3a,
        S3-4, S3-2, S3-3b, S3-5) that emits an audit row can use the typed
        helper rather than constructing the ``append()`` signature manually.
        Cross-reference: rvw-001 (Critical), Cluster 4 in plan-review fixup.
        """
        missing = fields - subject.keys()
        if missing:
            sorted_missing = sorted(missing)
            msg = (
                f"append_schema for event={event!r}: subject dict missing required fields "
                f"{sorted_missing!r}; declare all fields in {fields!r}"
            )
            raise ValueError(msg)
        await self.append(
            event=event,
            actor_user_id=actor_user_id,
            subject=subject,
            trust_tier_of_trigger=trust_tier_of_trigger,
            result=result,
            cost_estimate_usd=cost_estimate_usd,
            trace_id=trace_id,
            actor_persona=actor_persona,
            persona_id=persona_id,
            cost_actual_usd=cost_actual_usd,
            language=language,
        )
    ```

  - [ ] Run tests expecting PASS:
    ```bash
    cd <repo-root> && uv run pytest tests/unit/audit/ -v 2>&1 | tail -20
    ```

  - [ ] Run mypy + pyright:
    ```bash
    cd <repo-root> && uv run mypy src/alfred/audit/log.py && uv run pyright src/alfred/audit/log.py
    ```

  - [ ] Update the §3 file structure table to reflect the new `log.py` modification:

    Add a row: `src/alfred/audit/log.py` | Modify | Adds `append_schema()` helper that validates `subject` keys against a `fields` constant and forwards to `append()`.

  Commit:
  ```
  feat(audit): AuditWriter.append_schema() — typed helper validates subject keys against field-list constant (#TBD-slice3)
  ```

### Component H — `tests/adversarial/payload_schema.py` extensions

- [ ] **Task 13 — Write failing test for the extended `payload_schema.py`.**

  Files: Modify `tests/adversarial/test_payload_schema.py`.

  Steps:
  - [ ] Add the following test cases to the existing `test_payload_schema.py` (after the existing tests; do not modify existing cases):

    ```python
    # --- New Slice-3 category tests ---

    def test_tier_laundering_category_valid() -> None:
        """tier_laundering is a valid Category value after Slice-3 schema update."""
        payload = AdversarialPayload(
            id="tl-2026-001",
            category="tier_laundering",
            threat="T3 content posing as T2 via cast bypass",
            ingestion_path="cast_bypass",
            payload={"attack": "cast(TaggedContent[T2], t3_value)"},
            expected_outcome="boundary_refused",
            provenance="spec §12.2 tier_laundering payloads",
            references=("spec §3.8",),
        )
        assert payload.category == "tier_laundering"


    def test_dlp_egress_category_valid() -> None:
        """dlp_egress is a valid Category value after Slice-3 schema update."""
        payload = AdversarialPayload(
            id="de-2026-001",
            category="dlp_egress",
            threat="Canary token propagation through quarantined LLM into structured output",
            ingestion_path="stdio_transport.inbound",
            payload="<html>CANARY_TOKEN_XYZ</html>",
            expected_outcome="audit_row_emitted",
            provenance="spec §12.3 dlp_egress payloads",
            references=("spec §7.6",),
        )
        assert payload.category == "dlp_egress"


    def test_tier_laundering_prefix_enforced() -> None:
        """Payload with tl- prefix must declare tier_laundering category."""
        with pytest.raises(ValidationError):
            AdversarialPayload(
                id="tl-2026-002",
                category="dlp_egress",   # wrong category for tl- prefix
                threat="mismatch test",
                ingestion_path="cast_bypass",
                payload="test",
                expected_outcome="boundary_refused",
                provenance="test",
                references=("test",),
            )


    def test_dlp_egress_prefix_enforced() -> None:
        """Payload with de- prefix must declare dlp_egress category."""
        with pytest.raises(ValidationError):
            AdversarialPayload(
                id="de-2026-002",
                category="tier_laundering",   # wrong category for de- prefix
                threat="mismatch test",
                ingestion_path="stdio_transport.outbound",
                payload="test",
                expected_outcome="boundary_refused",
                provenance="test",
                references=("test",),
            )


    @pytest.mark.parametrize("path", [
        "stdio_transport.outbound",
        "stdio_transport.inbound",
        "cast_bypass",
        "wire_format_deser",
        "capability_gate",
        "secret_broker",
    ])
    def test_new_ingestion_paths_valid(path: str) -> None:
        """Six new IngestionPath values are valid after Slice-3 schema update."""
        payload = AdversarialPayload(
            id="tl-2026-003",
            category="tier_laundering",
            threat="ingestion path test",
            ingestion_path=path,
            payload="test",
            expected_outcome="boundary_refused",
            provenance="spec §12.2",
            references=("spec §12",),
        )
        assert payload.ingestion_path == path


    @pytest.mark.parametrize("outcome", ["boundary_refused", "audit_row_emitted"])
    def test_new_expected_outcomes_valid(outcome: str) -> None:
        """Two new ExpectedOutcome values are valid after Slice-3 schema update."""
        payload = AdversarialPayload(
            id="tl-2026-004",
            category="tier_laundering",
            threat="outcome test",
            ingestion_path="cast_bypass",
            payload="test",
            expected_outcome=outcome,
            provenance="spec §12.2",
            references=("spec §12",),
        )
        assert payload.expected_outcome == outcome
    ```

  - [ ] Run tests expecting FAIL (`ValidationError` imports needed; `tl` prefix unrecognised):
    ```bash
    cd <repo-root> && uv run pytest tests/adversarial/test_payload_schema.py -q 2>&1 | head -15
    ```
    Expected: failures on `tier_laundering`/`dlp_egress` category tests and `tl`/`de` prefix tests.

- [ ] **Task 14 — Implement `payload_schema.py` extensions.**

  Files: Modify `tests/adversarial/payload_schema.py`.

  Steps:
  - [ ] Update `_PREFIX_TO_CATEGORY` dict — add two entries:
    ```python
    _PREFIX_TO_CATEGORY: dict[str, str] = {
        "pi": "prompt_injection",
        "dlp": "dlp",
        "cap": "capability_bypass",
        "cnry": "canary",
        "ipp": "inter_persona",
        "hk": "hooks",
        "tl": "tier_laundering",   # Slice 3 — T3 content posing as T2, cast bypasses
        "de": "dlp_egress",        # Slice 3 — T3-origin credential exfiltration paths
    }
    ```

  - [ ] Update `_ID_PATTERN` regex to include `tl` and `de` prefixes:
    ```python
    _ID_PATTERN = re.compile(r"^(pi|dlp|cap|cnry|ipp|hk|tl|de)-\d{4}-\d{3}$")
    ```

  - [ ] Update `Category` Literal:
    ```python
    Category = Literal[
        "prompt_injection",
        "dlp",
        "capability_bypass",
        "canary",
        "inter_persona",
        "hooks",
        "tier_laundering",   # Slice 3: T3→T2 cast bypasses, wire-format confusion, nonce forgery
        "dlp_egress",        # Slice 3: T3-origin exfiltration (distinct from dlp — see spec §12.1)
    ]
    ```

  - [ ] Update `IngestionPath` Literal — add six new values after existing values:
    ```python
    IngestionPath = Literal[
        "web.fetch",
        "email.read",
        "mcp.tool.output",
        "file.read",
        "inter_persona.relay",
        # Slice 3 additions (spec §12.2):
        "stdio_transport.outbound",   # frames written to subprocess stdin
        "stdio_transport.inbound",    # frames read from subprocess stdout
        "cast_bypass",                # cast(TaggedContent[T2], t3_value) type-level attack
        "wire_format_deser",          # malformed JSON-RPC tier field on the wire
        "capability_gate",            # capability-gate bypass attempt
        "secret_broker",              # secret leaked via env or manifest
    ]
    ```

  - [ ] Update `ExpectedOutcome` Literal — add two new values:
    ```python
    ExpectedOutcome = Literal[
        "neutralized",
        "caught_by_dlp",
        "refused",
        "quarantined",
        # Slice 3 additions (spec §12.2):
        "boundary_refused",    # tag(T3, ...) from unauthorised caller disposition
        "audit_row_emitted",   # asserts a specific named audit row exists (e.g. manifest-broadening-capped)
    ]
    ```

  - [ ] Add `ValidationError` import to `test_payload_schema.py` (it's used in the new tests):
    ```python
    from pydantic import ValidationError
    ```

  - [ ] Run tests expecting PASS:
    ```bash
    cd <repo-root> && uv run pytest tests/adversarial/test_payload_schema.py -v 2>&1 | tail -20
    ```

  - [ ] Run full adversarial suite to confirm no regressions:
    ```bash
    cd <repo-root> && uv run pytest tests/adversarial -q 2>&1 | tail -10
    ```

  Commit:
  ```
  feat(adversarial): extend payload_schema.py — tier_laundering + dlp_egress categories, 6 IngestionPath + 2 ExpectedOutcome additions (#TBD-slice3)
  ```

### Component I — Adversarial corpus stubs

> **Plan amended 2026-05-31:** `payloads.yaml` is omitted to match the existing
> empty-category-dir convention; `conftest.py` would reject the `payloads: []`
> wrapper per `AdversarialPayload.model_validate`. PR-S3-1 onwards add
> `payloads.yaml` when there are payloads to put in it. Tasks 15 and 16 below
> are amended to create README-only; the `payloads.yaml` step is struck.

- [ ] **Task 15 — Create `tests/adversarial/tier_laundering/` stub (README only).**

  Files: Create `tests/adversarial/tier_laundering/README.md`.

  Steps:
  - [ ] Write `tests/adversarial/tier_laundering/README.md`:

    ```markdown
    # Tier-laundering adversarial corpus

    Attacks that attempt to make T3 content (untrusted ingestion) appear as T2
    (authenticated-user) or T0 (system) content — bypassing the type-level
    discriminants AlfredOS uses to keep the privileged orchestrator from ever
    processing raw T3. The defence under test is the full T3 boundary: the
    nonce-gated `tag(T3, ...)` factory (spec §3.2), the wire-format serialiser's
    cross-tier rejection (spec §3.5), the `cast(TaggedContent[T2], t3_value)`
    ruff/grep CI rule (spec §3.7-3.8), and the capability-gate's
    `check_content_clearance` method (spec §8.2).

    Attack vectors covered:
    - `cast(TaggedContent[T2], t3_value)` bypass — pytest module (requires Python-level
      code execution; spec §12.2 fixture-vs-pytest allocation).
    - Wire-format tier confusion — JSON payload with `"tier": "T2"` but T3-constructed
      content; YAML payload.
    - `tag(T3, ...)` from orchestrator module context — pytest module.
    - Frame-introspection bypass — monkey-patch `sys.modules` to forge `__name__`; pytest module.
    - Capability-gate bypass via `subscriber_tier=user-plugin` on a T3-carrying hookpoint — YAML payload.
    - Post-handshake hook registration attack — pytest module (requires live subprocess).
    - In-flight grant revocation race — YAML payload.
    - Retry-guidance hygiene — malformed-output corpus through prompt-embedded fallback; pytest module.
    - `gc.get_objects()`-style T3 token retrieval — pytest module labelled `out_of_scope`; asserts
      explicit rationale rather than treating as unresolved gap (spec §3.2 threat model limits).

    Outcome: **boundary_refused** (type-system refusal), or **audit_row_emitted** (specific
    named audit row asserted). ID prefix: `tl-`.

    Implementations land in PR-S3-1 (type-system payloads), PR-S3-2 (capability-gate payloads),
    PR-S3-3a (post-handshake attack payload), PR-S3-4 (retry-guidance payload),
    and PR-S3-7 (integration test gate).

    See [`.rulesync/skills/alfred-adversarial-corpus/SKILL.md`](../../../.rulesync/skills/alfred-adversarial-corpus/SKILL.md)
    for naming, schema, and the "Adding a new payload" procedure.
    ```

  - [ ] ~~Write `tests/adversarial/tier_laundering/payloads.yaml`.~~ **Struck per plan amendment above.** No `payloads.yaml` ships in this PR; the empty-category-dir convention is README-only, and `conftest.py` would reject a `payloads: []` wrapper. PR-S3-1 onwards add the YAML when populating it.

  - [ ] Run adversarial suite to confirm the empty category dir is tolerated:
    ```bash
    cd <repo-root> && uv run pytest tests/adversarial -q 2>&1 | tail -5
    ```

  Commit:
  ```
  feat(adversarial): tier_laundering corpus stub — README-only matches existing empty-category convention (#TBD-slice3)
  ```

- [ ] **Task 16 — Create `tests/adversarial/dlp_egress/` stub (README only).**

  Files: Create `tests/adversarial/dlp_egress/README.md`.

  Steps:
  - [ ] Write `tests/adversarial/dlp_egress/README.md`:

    ```markdown
    # DLP-egress adversarial corpus

    Attacks where T3-origin content carries or enables exfiltration of secrets,
    credentials, or canary tokens through an AlfredOS output channel. Distinct
    from the existing `dlp` category (which covers T0/T1/T2-origin DLP mechanics)
    — `dlp_egress` is specifically for exfiltration vectors where untrusted T3
    ingestion is the attack entry point (spec §12.1 category disambiguation:
    "dlp_egress = T3-origin exfiltration paths; dlp = T0/T1/T2-origin DLP mechanics").

    Attack vectors covered:
    - Canary token planted in T3 web content propagating through quarantined LLM
      into structured output → DLP scan → audit row.
    - Cross-field secret leak via headers + cookies in a web request.
    - Subprocess env-leak via misconfigured launcher (missing explicit `env=` dict).
    - Manifest allowlist broadening: malicious manifest update declares wider
      `allowed_domains` — asserts `web.allowlist.manifest_broadening_capped` audit row
      fires and the broadened domain is not reachable.

    Outcome: **audit_row_emitted** (specific canary/DLP audit row asserted), or
    **boundary_refused** (DLP scan refuses the exfiltration path). ID prefix: `de-`.

    Implementations land in PR-S3-5 (`web.fetch` + `InboundCanaryScanner` payloads).

    See [`.rulesync/skills/alfred-adversarial-corpus/SKILL.md`](../../../.rulesync/skills/alfred-adversarial-corpus/SKILL.md)
    for naming, schema, and the "Adding a new payload" procedure.
    ```

  - [ ] ~~Write `tests/adversarial/dlp_egress/payloads.yaml`.~~ **Struck per plan amendment above.** Same rationale as Task 15 — README-only matches the existing empty-category-dir convention; PR-S3-5 adds the YAML when populating it with `de-` payloads.

  - [ ] Run adversarial suite:
    ```bash
    cd <repo-root> && uv run pytest tests/adversarial -q 2>&1 | tail -5
    ```

  Commit:
  ```
  feat(adversarial): dlp_egress corpus stub — README-only matches existing empty-category convention (#TBD-slice3)
  ```

### Component J — Final quality gate

- [ ] **Task 17 — Run `make check` + `make docs-check` + adversarial suite.**

  Steps:
  - [ ] Run the full quality gate:
    ```bash
    cd <repo-root> && make check 2>&1 | tail -20
    ```
    Expected: exits 0. Ruff + format + mypy strict + pyright all pass.

  - [ ] Run docs check:
    ```bash
    cd <repo-root> && make docs-check 2>&1 | tail -3
    ```
    Expected: exits 0.

  - [ ] Run adversarial suite:
    ```bash
    cd <repo-root> && uv run pytest tests/adversarial -q 2>&1 | tail -5
    ```
    Expected: all existing tests pass; new `tier_laundering` + `dlp_egress` stubs collected without errors.

  - [ ] Run all unit tests:
    ```bash
    cd <repo-root> && uv run pytest tests/unit -q 2>&1 | tail -5
    ```
    Expected: all pass, including new `tests/unit/audit/` tests.

  No additional commit for this task — it is the verification step before the PR is opened.

---

## §5 Spec Coverage Map

| Spec section | Task(s) that implement it |
|---|---|
| §0 Summary — PR-S3-0a pre-committed split rationale | Tasks 1–3 (ADR-0017 records the split decision) |
| §1.3 PR-S3-0 pre-committed split + PR-S3-3 pre-committed split | Task 2 (ADR-0017 Decision §5) |
| §2 Cross-cutting wire-format ADR section | Tasks 1–3 (ADR-0017 records the three versioning schemes) |
| §3.2 `tag(T3, ...)` nonce-gated factory decision | Task 2 (ADR-0017 Decision §1) |
| §3.8 Cast-bypass policy documented | Tasks 1–3 (ADR-0017 Alternatives §C) |
| §4.3 Manifest two-axis naming rule | Task 2 (ADR-0017 Decision §3) |
| §5.7 Co-merged Slice-4 containerisation ADR + PRD §5 amendment | Tasks 7–9 (ADR-0015, PRD edit); Task 2 (ADR-0017 Decision §4) |
| §9.4 ADR-0009 status flip | Task 6 |
| §11.5 i18n catalog keys (cited in plan — PR-S3-0b owns catalog) | Tasks 1–3 (ADR-0017 cites §11.5 scope; keys themselves are PR-S3-0b) |
| §12.1 Adversarial category additions (tier_laundering, dlp_egress) | Tasks 14–16 |
| §12.2 `payload_schema.py` closed-set Literal edit | Task 14 |
| §12.2 `tier_laundering/README.md` (stub) | Task 15 |
| §12.2 `dlp_egress/README.md` (stub) | Task 16 |
| §13 `audit_row_schemas.py` constants module | Tasks 10–12 |
| §13 `alfred.audit.__init__.py` public surface update | Task 12 |
| §13 `AuditWriter.append_schema()` typed emit helper | Tasks 12a–12b (Cluster 4, rvw-001) |
| §15.2 ADR-0009 status flip | Task 6 |
| §15.3 Slice-2.5 §6.10 tracking issues retirement | Task 6a (B.1) — moved from PR-S3-7 per spec §15.3 and docs-003 |
| §17 PR-S3-0a scope deliverables | Tasks 1–17 + Tasks 6a, 12a, 12b (all tasks) |
| §18 ADR-0008 status flip | Task 4 |
| §18 ADR-0013 status flip | Task 5 |
| §18 ADR-0015 co-merged | Task 7 |
| §18 ADR-0016 co-merged | Task 8 |
| arch-004 resolution: `QuarantinedUnavailable` placement | Task 2 (ADR-0017 Decision §6) |
| arch-006 / rvw-009 / sec-006 / err-011: `plugin.transport.dlp_outbound_refused` pointer | Tasks 1–3 (ADR-0017); catalog key itself lands in PR-S3-0b |

---

## §6 Quality gates

Run these commands in order before opening the PR:

```bash
# 1. Lint + format check + type check + all tests
cd <repo-root> && make check

# 2. Cross-link validation (broken ADR links, broken PRD section links)
cd <repo-root> && make docs-check

# 3. Adversarial suite (new stubs must be collected without errors)
cd <repo-root> && uv run pytest tests/adversarial -q

# 4. Unit tests for the new audit module
cd <repo-root> && uv run pytest tests/unit/audit/ -v

# 5. Confirm no ruff violations in the two new Python files
cd <repo-root> && uv run ruff check src/alfred/audit/audit_row_schemas.py tests/adversarial/payload_schema.py

# 6. Confirm pybabel extract finds no new catalog keys (this PR adds no t() calls)
cd <repo-root> && pybabel extract -F babel.cfg -o /tmp/s3-0a-check.pot . && diff <(grep ^msgid locale/en/LC_MESSAGES/alfred.po | sort) <(grep ^msgid /tmp/s3-0a-check.pot | sort) && echo "No new catalog keys — correct for PR-S3-0a"
```

All six commands must exit 0 before the PR is opened.

---

## §7 References

**Spec sections:**
- [Spec §0](../specs/2026-05-30-slice-3-trust-tier-completion-design.md#0-summary) — PR-S3-0a scope summary.
- [Spec §1.3](../specs/2026-05-30-slice-3-trust-tier-completion-design.md#13-scope-budget) — pre-committed PR splits.
- [Spec §2](../specs/2026-05-30-slice-3-trust-tier-completion-design.md#2-cross-cutting-wire-format-adr-section) — cross-cutting wire format (ADR-0017 records this).
- [Spec §5.7](../specs/2026-05-30-slice-3-trust-tier-completion-design.md#57-co-merged-slice-4-containerisation-adr-commitment--prd-5-amendment) — hybrid-isolation relaxation + Slice-4 commitment.
- [Spec §12.1-12.2](../specs/2026-05-30-slice-3-trust-tier-completion-design.md#12-adversarial-corpus-fork-9) — adversarial category additions + schema edits.
- [Spec §13](../specs/2026-05-30-slice-3-trust-tier-completion-design.md#13-audit-row-schemas) — `audit_row_schemas.py` specification (verbatim constants).
- [Spec §15.2](../specs/2026-05-30-slice-3-trust-tier-completion-design.md#152-adr-0009-status-flip) — ADR-0009 flip.
- [Spec §17](../specs/2026-05-30-slice-3-trust-tier-completion-design.md#17-pr-breakdown-preview) — PR-S3-0a deliverable list.

**ADRs this PR creates or modifies:**
- `docs/adr/0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md` (created)
- `docs/adr/0015-slice4-containerised-quarantined-llm.md` (created)
- `docs/adr/0016-slice4-discord-tui-comms-mcp-rewrite.md` (created)
- `docs/adr/0008-llm-output-trust-tier.md` (status flip)
- `docs/adr/0013-defer-t1-t3-and-dual-llm.md` (status flip + note)
- `docs/adr/0009-comms-adapter-protocol-slice2-only.md` (status flip + note)

**PRD sections:**
- [PRD §5 line 117](../../PRD.md#5-architecture-overview) — hybrid-isolation invariant (amended by Task 9).
- [PRD §7.1](../../PRD.md#71-security--prompt-injection-defense) — dual-LLM split + T3 trust tier.

**Predecessor plans this PR depends on:**
- None — this is the first Slice-3 PR.

**Plans gated on this PR:**
- `docs/superpowers/plans/2026-05-31-slice-3-pr-s3-0b-schema-infra.md` — gated directly on this PR.
- All implementation plans (PR-S3-1 through PR-S3-7) — import `audit_row_schemas` and write adversarial corpus payloads against the schema established here.

**Sister spec:**
- [Slice 2.5 spec](../specs/2026-05-27-slice-2.5-hooks-design.md) — shipped Slice-2.5 contract this slice builds on.
- [Slice 2.5 PR-A plan](./2026-05-27-slice-2.5-pr-A-hook-registry.md) — template for this plan's structure.
