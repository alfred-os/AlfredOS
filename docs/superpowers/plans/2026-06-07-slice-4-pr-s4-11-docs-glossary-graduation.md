# Slice 4 — PR S4-11: Docs, Glossary, and Slice-4 Graduation — Implementation Plan

> **For agentic workers:** Use `superpowers:subagent-driven-development` (recommended) or
> `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`)
> syntax for tracking.

**Goal:** Ship the four Slice-4 subsystem deep-doc updates (`security.md`, `comms.md`,
`supervisor.md`, `policies.md`); author the 12-section `docs/runbooks/slice-4-graduation.md`;
add the final batch of Slice-4 glossary terms to `docs/glossary.md`; update `CLAUDE.md`'s
tree and commands table for Slice-4 surfaces; update `README.md`'s quickstart for the
daemon-required `alfred chat` flow; flip ADR-0015 and ADR-0016 from Proposed → Accepted;
update `docs/ci/required-checks.md` with the 10 new merge-blocking gates; and verify all
12 Slice-4 graduation criteria hold. This PR has no downstream consumer — it is the final
Slice-4 PR.

**Architecture:** PR-S4-11 is documentation-only plus two ADR status edits. Every doc
claim must be anchored in code that landed in prior PRs (S4-0a through S4-10). No new
runtime code ships here. The subsystem docs explain why each Slice-4 subsystem has the
shape it does — the strategic layer that per-PR docstring suggestions and code review
cannot produce.

**Spec:** [docs/superpowers/specs/2026-06-06-slice-4-design.md](../specs/2026-06-06-slice-4-design.md)
— §13 (PR-S4-11 scope), §13.1 (glossary enumeration), §13.2 (runbook 12 sections), §14
(graduation criteria 12 items).

**Index:** [docs/superpowers/plans/2026-06-07-slice-4-index.md](./2026-06-07-slice-4-index.md)
— §3 (one-time ownership rules: ADR status flips happen HERE and nowhere else).

**Depends on:** ALL prior Slice-4 PRs — PR-S4-0a through PR-S4-10, each merged to `main`.
PR-S4-11 opens only after all eleven prior PRs are green on `main`.

**Blocks:** Nothing. This is the graduation PR.

---

## §0 Pre-tasks

Before starting Task 1, confirm the following on `main`:

- [ ] All 11 prior PRs (S4-0a through S4-10) appear in `git log --oneline main` with
  their merge commits.
- [ ] `make check` is green.
- [ ] `make docs-check` is green.
- [ ] `uv run pytest tests/adversarial` passes.
- [ ] `src/alfred/comms/` does not exist (`ls src/alfred/comms/` → "No such file or
  directory"). Confirms PR-S4-10 flag-day landed.
- [ ] `src/alfred/comms_mcp/` exists and contains at least `protocol.py`, `inbound.py`,
  `classifier_registry.py`. Confirms PR-S4-8 landed.
- [ ] `plugins/alfred_discord/` exists. Confirms PR-S4-9 landed.
- [ ] `plugins/alfred_tui/` exists. Confirms PR-S4-10 landed.
- [ ] `bin/alfred-plugin-launcher.sh` exists. Confirms PR-S4-6 landed.
- [ ] ADR-0015 status header currently reads `Proposed` (this PR flips it).
- [ ] ADR-0016 status header currently reads `Proposed` (this PR flips it).

Create a GitHub tracking issue for PR-S4-11 (or reuse the Slice-4 epic) and substitute
the real issue number for every `#TBD-slice4` token in the commit messages below before
committing. The placeholder token must not land in committed history.

**PR #205 round-2 review closures** (load-bearing corrections — apply at implementation time):

1. **docs-1 CRITICAL (ADR-0022/0023/0024 author attribution)**: VERIFIED via `ls docs/adr/` — repository tops at ADR-0021 at PR-S4-plans-branch HEAD. ADR-0022 (carrier substitution) MUST be authored by PR-S4-3 as part of its Component G. ADR-0023 (mtime-polled hot-reload) MUST be authored by PR-S4-4 as part of its Component A. ADR-0024 (perf-gate hardware budget) MUST be authored by PR-S4-1 alongside its perf-test budget assertions. Each of those prior PRs' plans gains a new task `Component_X.Y: Author ADR-NNNN with Proposed status + spec reference`. PR-S4-11's §2 fabricated-surfaces gate verifies all three ADRs exist BEFORE PR-S4-11's Task 1 begins (the gate is `[ -f docs/adr/0022-*.md ] && [ -f docs/adr/0023-*.md ] && [ -f docs/adr/0024-*.md ] || exit 1`). PR-S4-11's Task 12 then flips their status from Proposed → Accepted. The cross-PR contracts table in §7 adds three new rows: ADR-0022 author = PR-S4-3; ADR-0023 author = PR-S4-4; ADR-0024 author = PR-S4-1.

2. **rev-1 HIGH (#TBD-slice4 audit)**: Task 15 audit step expands to:

   ```bash
   # Final commit-history scan — refuses any unresolved tokens.
   if git log --pretty=%s main..HEAD | grep -q '#TBD-slice4'; then
     echo "REFUSED: unresolved #TBD-slice4 in commit history"; exit 1; fi
   if git log --pretty=%s main..HEAD | grep -q '\[VERIFY:'; then
     echo "REFUSED: unresolved [VERIFY:] marker in commit history"; exit 1; fi
   ```

   Both refusals are merge-blocking on PR-S4-11's CI.

3. **rev-2 HIGH (operator-facing strings via t())**: Task 8 runbook + README's quoted error strings ALL route through `t()` keys defined in earlier Slice-4 PRs (the catalog was filled in PR-S4-0b + PR-S4-1 + PR-S4-5). The runbook's "Error: daemon is not running..." references the EN-locale rendering of `t("chat.refused.daemon_not_running")` (key shipped in PR-S4-10 closure 3). The 7 `daemon.boot.failed` strings reference `t("daemon.boot.<failure_reason>")` keys (shipped in PR-S4-0b closure 1 + PR-S4-1 closures). The runbook explicitly notes: "Error strings below are rendered in the operator's locale; English shown for documentation purposes. Catalog keys are: ...". A new test `tests/unit/docs/test_runbook_strings_match_catalog.py` parses the runbook's quoted error blocks, extracts the catalog-key annotations, and asserts each key exists in `locale/en/LC_MESSAGES/alfred.po`.

4. **docs-2 HIGH (CLAUDE.md 200-line cap)**: Task 9 explicitly extracts the "Commands you should know" section (lines 64-90 in current CLAUDE.md) to a new `docs/cli-commands.md` deep-doc and replaces it with a one-line pointer. The §9 task body commits the extraction as a single commit BEFORE the 6-command additions; after the extraction, CLAUDE.md is well under the 200-line cap and the new commands fit. The target file `docs/cli-commands.md` is created in PR-S4-11 (NOT deferred to a later slice).

5. **docs-3 HIGH (README quickstart includes alfred login)**: Task 10 README rewrite explicitly adds `alfred login` between `daemon start` and `chat`:

   ```bash
   alfred daemon start
   alfred login              # NEW — required since Slice 4
   alfred chat
   ```

   The README's narrative explains: "AlfredOS now requires an operator session before interactive commands. Run `alfred login` once per machine; the session persists 12h (configurable up to 7d)."

6. **docs-4 MEDIUM (per-gate idempotent loop on required-checks.md)**: Task 13's 10-row block is REPLACED with a per-row idempotent loop:

   ```bash
   for gate in "${SLICE_4_GATES[@]}"; do
     if grep -q "^| \`${gate}\`" "${REQ_CHECKS_FILE}"; then
       echo "Skipping ${gate} (already in Currently-required)"; continue; fi
     date_added=$(date -u +%Y-%m-%d)
     # Append row preserving prior Active-since dates for already-promoted gates.
     ...
   done
   ```

   The "all dated 2026-06-07" blanket pattern is dropped.

7. **arch-1 HIGH (graduation gate FAIL branch)**: Task 14 graduation gate adds explicit decision tree:

   ```
   IF any PR-S4-* required check fails:
     → BLOCK PR-S4-11 merge
     → File fix-PR in the OWNING PR's repository (e.g., PR-S4-3 carrier-substitution fails → fix-PR against PR-S4-3 branch)
     → PR-S4-11 sits open until ALL prior PR-S4-* PRs are green again
     → No Slice-5 deferral of any Slice-4 gate failure (Slice 4 has hard graduation gates)
   IF graduation runbook smoke fails:
     → BLOCK PR-S4-11 merge
     → File fix-PR against PR-S4-11 itself (graduation-runbook ownership is this PR)
   IF Slice-5 backlog enumeration incomplete:
     → BLOCK PR-S4-11 merge until Architect signs off the backlog list
   ```

8. **arch-2 MEDIUM (Slice-5 backlog consolidation)**: NEW Task 17 (preceding graduation Task 14): consolidate every "Slice 5+" deferred item from the per-subsystem graduation-map tables into a single `docs/superpowers/specs/2026-06-07-slice-5-backlog.md` file. Each row carries: (a) deferred item; (b) owning PR-S4-* that decided to defer; (c) reason for deferral; (d) blocking-pre-Slice-5 vs nice-to-have classification. The Architect signs off the file as part of graduation.

9. **arch-3 MEDIUM (Slice-4 retrospective)**: NEW Task 18 (post-graduation): `docs/superpowers/specs/2026-06-07-slice-4-retrospective.md` documenting: (a) one-time-ownership rule effectiveness; (b) ADR status-flip discipline; (c) the wave-migration two-stage pattern (PR-S4-3); (d) the in-plan round-2 closure-block pattern (PR #205 review). Architect + Security engineer co-sign. Slice-5 planning references this retrospective in its kickoff.

10. **rev-3 MEDIUM (anchor by heading, not line)**: every line-number reference (`PRD §5 line 117`, `README.md lines 26-36`, `CLAUDE.md lines 13-53/74-90`) is REPLACED with section-heading anchors (`PRD §5 "Trust Tiers"`, `README "Quick start"`, `CLAUDE.md "Where things live"` and `"Commands you should know"`). Line numbers shift with every edit; headings are stable.

---

## §1 Goal

This PR closes the Slice-4 documentation loop. Its three distinct jobs:

1. **Subsystem deep-doc updates** — `security.md`, `comms.md`, `supervisor.md` each gain a
   Slice-4 section documenting the new surface. `policies.md` is created (if PR-S4-4 did not
   create it) or completed (if PR-S4-4 created a stub). Each doc explains *why* each subsystem
   has the Slice-4 shape it does — the strategic layer no automator can produce.

2. **Runbook + glossary** — `docs/runbooks/slice-4-graduation.md` is the operator's upgrade
   guide from Slice 3 to Slice 4 (12 sections per spec §13.2). `docs/glossary.md` gains the
   final Slice-4 terms not already landed by PR-S4-0a (spec §13.1 residual items plus any
   surfaced during implementation, especially `BODY_FIELD_BY_KIND`, `OperatorSessionTimeout`,
   `T3DerivedData` (Slice-3 re-listing for visibility), `BurstLimiter`).

3. **Hub updates + ADR flips** — `CLAUDE.md` tree and commands table reflect Slice-4 new
   paths and commands. `README.md` quickstart states the daemon requirement for `alfred chat`.
   ADR-0015 and ADR-0016 flip Proposed → Accepted (arch-003 closure — one-time ownership,
   this PR only, matching the Slice-3 precedent).

---

## §2 Fabricated-surfaces verification gate

**Every cited file, symbol, and path below was verified against HEAD before this plan was
written.** The table records what exists so implementers know what to update vs create.

| Surface | Status at plan-write time | Action |
| --- | --- | --- |
| `docs/subsystems/security.md` | EXISTS — Slice-3 deep-doc | Update: add Slice-4 section |
| `docs/subsystems/comms.md` | EXISTS — Slice-2 deep-doc | Update: add comms-MCP rewrite section |
| `docs/subsystems/supervisor.md` | EXISTS — Slice-3 deep-doc | Update: add Slice-4 daemon + plugin-restart section |
| `docs/subsystems/policies.md` | ABSENT at plan-write time | Create (or complete PR-S4-4 stub if it exists at implementation time) |
| `docs/runbooks/slice-4-graduation.md` | ABSENT | Create (12 sections) |
| `docs/glossary.md` | EXISTS | Append Slice-4 final terms |
| `docs/ci/required-checks.md` | EXISTS at `docs/ci/required-checks.md` | Append 10 new rows; move from Pending → Currently Required |
| `README.md` | EXISTS — quickstart at lines 26–36 | Update quickstart for daemon requirement |
| `CLAUDE.md` | EXISTS — tree at lines 13–53; commands at lines 74–90 | Update tree + commands table |
| `.rulesync/rules/CLAUDE.md` | EXISTS (rulesync source) | Edit here, then `rulesync generate -t claude-code -f '*'` |
| `docs/adr/0015-slice4-containerised-quarantined-llm.md` | EXISTS — status: `Proposed` | Flip to `Accepted` |
| `docs/adr/0016-slice4-discord-tui-comms-mcp-rewrite.md` | EXISTS — status: `Proposed` | Flip to `Accepted` |
| `docs/adr/0009-comms-adapter-protocol-slice2-only.md` | EXISTS — caveat already narrowed by PR-S4-10 | Verify caveat is narrowed; no further edit needed here |
| `plugins/alfred_discord/` | Must exist (PR-S4-9) | Grep for presence before anchoring claims |
| `plugins/alfred_tui/` | Must exist (PR-S4-10) | Grep for presence before anchoring claims |
| `src/alfred/comms_mcp/` | Must exist (PR-S4-8) | Grep for presence before anchoring claims |
| `bin/alfred-plugin-launcher.sh` | Must exist (PR-S4-6) | Grep for presence before anchoring claims |
| `src/alfred/comms/` | Must NOT exist (PR-S4-10 deleted it) | Confirm absence before writing comms.md claims |

**Hard rule:** Before writing prose in any task below that anchors a claim to a file or
function name, run `Read` or `Bash grep` to confirm the symbol exists in `src/` or
`plugins/` at HEAD. Do not describe what prior PRs were *supposed* to ship — describe
what is *actually there*.

---

## §3 File structure

| File | Action |
| --- | --- |
| `docs/subsystems/security.md` | Modify — append Slice-4 section |
| `docs/subsystems/comms.md` | Modify — rewrite for comms-MCP shape |
| `docs/subsystems/supervisor.md` | Modify — append Slice-4 daemon + plugin-restart section |
| `docs/subsystems/policies.md` | Create (or complete stub) — PoliciesV1 + hot-reload + blast partitioning |
| `docs/runbooks/slice-4-graduation.md` | Create — 12 sections |
| `docs/glossary.md` | Modify — append Slice-4 final terms |
| `docs/ci/required-checks.md` | Modify — append 10 new rows |
| `.rulesync/rules/CLAUDE.md` | Modify — tree + commands table; regenerate CLAUDE.md after |
| `CLAUDE.md` | Regenerate via rulesync (not edited directly) |
| `README.md` | Modify — quickstart daemon requirement |
| `docs/adr/0015-slice4-containerised-quarantined-llm.md` | Modify — status Proposed → Accepted |
| `docs/adr/0016-slice4-discord-tui-comms-mcp-rewrite.md` | Modify — status Proposed → Accepted |

---

## §4 Tasks

### Component A: Glossary additions

- [ ] **Task 1 — Glossary: add PolicyWatcher, PoliciesV1, PoliciesSnapshot, PoliciesSnapshotRef, HighBlastPolicies**

  Files: Modify `docs/glossary.md`.

  Steps:

  1. Confirm baseline: `make docs-check` green before any edits.

  2. Read the current tail of `docs/glossary.md` to find the insertion point (append after
     last existing `##` entry, maintaining alphabetical order within the file).

  3. Verify the source files exist before writing:
     - `grep -r "class PolicyWatcher" src/alfred/` → should find `src/alfred/policies/watcher.py`
     - `grep -r "class PoliciesV1" src/alfred/` → should find `src/alfred/policies/`
     - `grep -r "class PoliciesSnapshotRef" src/alfred/` → should find `src/alfred/policies/snapshot_ref.py`

  4. Append entries to `docs/glossary.md`:

     ```markdown
     ### BurstLimiter

     Per-(canonical_user_id, persona) token-bucket primitive shipped in PR-S4-8
     (`src/alfred/orchestrator/burst_limiter.py`). Default: 5-token capacity,
     1 token / 5 seconds refill. Configurable via
     `PoliciesV1.rate_limits.quarantined_extract_per_user_persona`. Emits
     `COMMS_INBOUND_BUDGET_CAPPED_FIELDS` when a request is capped; drops the
     message with `comms.inbound.dropped` after 30 seconds of bucket-empty.
     Distinct from `BudgetGuard` (per-user-USD-daily) — `BurstLimiter` prevents
     sub-second bursts within a single conversation, which a USD cap cannot.

     See [ADR-0024](adr/0024-comms-mcp-wire-contract.md),
     spec §8 comms-MCP foundations, and
     [docs/subsystems/security.md](subsystems/security.md).

     ### BODY_FIELD_BY_KIND

     Per-adapter body-field-name mapping defined at
     `src/alfred/comms_mcp/classifier_registry.py`. Maps `adapter_kind` strings
     to the field name that carries the human-readable message body within a
     platform payload: `"discord": "content"`, `"tui": "content"`,
     `"telegram": "text"` (post-MVP). The host uses this mapping to extract the
     body field for DLP scanning without adapter-specific logic leaking into the
     host. Plugins cannot override this mapping — it is host-owned and enforced
     by `REQUIRED_CLASSIFIERS_BY_KIND` (comms-011 round-3 closure).

     See [docs/subsystems/comms.md](subsystems/comms.md) and the
     `REQUIRED_CLASSIFIERS_BY_KIND` registry entry.

     ### HighBlastPolicies

     The `PoliciesV1` sub-model whose fields refuse hot-reload and require a
     reviewer-gate change to update (`src/alfred/policies/models.py`). Fields
     in this block — `quarantined_provider_url`, `secret_broker_config_ref` —
     have blast radii that make live-reload dangerous: swapping the quarantined
     provider mid-flight would leave in-flight extractions talking to a different
     backend. `PolicyWatcher` validates any reload candidate against the active
     snapshot's `HighBlastPolicies`; any diff triggers
     `CONFIG_RELOAD_REJECTED_FIELDS` with `reason="high_blast_change"`.

     Contrast with low-blast keys (`rate_limits`, `handle_caps`) which
     hot-reload safely. See [docs/subsystems/policies.md](subsystems/policies.md)
     and [ADR-0023](adr/0023-mtime-polled-hot-reload-policies-yaml.md).

     ### OperatorSessionTimeout

     The exception raised by `_resolve_operator` when the 250 ms hard timeout
     fires (`src/alfred/identity/operator_session.py`). Distinct from
     `OperatorSession` expiry (which is a business-logic condition, not a timeout)
     and from `asyncio.TimeoutError` (which is not caught at the call site).
     Every CLI command that calls `_resolve_operator` catches this exception and
     renders a localised error via `t("operator.session.resolve_timeout")`.

     See [docs/subsystems/supervisor.md](subsystems/supervisor.md#operator-session-integration)
     and [ADR-0020](adr/0020-supervisor-cli-access-via-postgres-and-state-git.md).

     ### PoliciesSnapshot

     An immutable, frozen Pydantic v2 model capturing the active `PoliciesV1`
     plus metadata about when and from where it was loaded
     (`src/alfred/policies/models.py`). Fields: `policies: PoliciesV1`,
     `loaded_at: datetime`, `file_mtime: float`, `file_sha256: str`. The SHA256
     is the watcher's idempotency key — if the file has not changed since the
     last successful swap, the watcher short-circuits and emits no audit row.

     See [PoliciesSnapshotRef](#policiessnapshotref) and
     [docs/subsystems/policies.md](subsystems/policies.md).

     ### PoliciesSnapshotRef

     The lock-free, atomically swappable pointer to the active `PoliciesSnapshot`
     (`src/alfred/policies/snapshot_ref.py`). `current()` returns the active
     snapshot synchronously — GIL-atomic single-attribute load, p99 < 1 µs.
     `swap(new)` is a two-phase commit: emit `CONFIG_RELOAD_FIELDS` audit row
     first; only on successful audit, assign the new snapshot. A failed audit
     write aborts the swap (err-004 closure — audit-then-swap, not
     swap-then-audit). Long-lived loops must call `ref.current()` per iteration,
     not once before the loop body.

     See [PolicyWatcher](#policywatcher), [HighBlastPolicies](#highblastpolicies),
     and [docs/subsystems/policies.md](subsystems/policies.md).

     ### PolicyWatcher

     The mtime-polled `config/policies.yaml` watcher (`src/alfred/policies/watcher.py`).
     Polls at 1 s default (configurable via `Settings.policy_poll_interval_seconds`,
     range `[0.5, 10.0]`). Runs inside the daemon's `asyncio.TaskGroup`. On mtime
     change, reads and validates the YAML into `PoliciesV1`; checks the new snapshot
     against the active `HighBlastPolicies`; if safe, calls `PoliciesSnapshotRef.swap`.
     On three consecutive `os.stat()` failures, escalates to `supervisor.config_watcher.degraded`
     and reduces polling frequency to 10× the configured interval until recovery.

     See [ADR-0023](adr/0023-mtime-polled-hot-reload-policies-yaml.md) and
     [docs/subsystems/policies.md](subsystems/policies.md).
     ```

  5. Run `make docs-check` — must pass.

  6. Commit:

     ```
     git commit -m "docs(glossary): add PolicyWatcher, PoliciesSnapshot/Ref, HighBlastPolicies, BurstLimiter, BODY_FIELD_BY_KIND, OperatorSessionTimeout (#TBD-slice4)"
     ```

- [ ] **Task 2 — Glossary: add OperatorSession, SandboxPolicy/Kind, CarrierSubstitution, ErrorOutcome**

  Files: Modify `docs/glossary.md`.

  Steps:

  1. Verify source before writing:
     - `grep -r "class OperatorSession" src/alfred/` → should find `src/alfred/identity/operator_session.py`
     - `grep -r "class SandboxKind\|SandboxKind" src/alfred/` → confirm location
     - `grep -r "class ErrorOutcome\|ErrorOutcome" src/alfred/hooks/` → confirm
       `src/alfred/hooks/invoke.py` or similar

  2. Append entries to `docs/glossary.md`:

     ```markdown
     ### CarrierSubstitution

     The Slice-4 semantic by which an error-stage hook subscriber may return a
     substitute payload (`SubstituteResult`) rather than letting the original
     exception propagate. The substitute must carry a `source_tier` that is
     equal to or lower than the surrounding carrier's declared tier in the total
     order `T0 < T1 < T2 < T3` — any upward step is a trust upgrade and is
     refused with `CARRIER_SUBSTITUTION_REFUSED_FIELDS`. The mechanism lands in
     `src/alfred/hooks/invoke.py:_run_error` (PR-S4-3); see
     [ADR-0022](adr/0022-recoverable-carrier-semantic-error-stage-dispatch.md).

     Not to be confused with [trust tier](#trust-tier) downgrade paths
     (`downgrade_to_orchestrator`) — carrier substitution happens at the hook
     dispatch layer, not at the quarantine boundary.

     ### ErrorOutcome

     The discriminated union returned by `_run_error[T]`
     (`src/alfred/hooks/invoke.py`, PR-S4-3):

     ```python
     type ErrorOutcome[T] = ReRaise | SubstituteResult[T]
     ```

     `ReRaise` signals the original exception propagates. `SubstituteResult[T]`
     carries a `payload: T`, `source_tier`, and `subscriber_id`. The caller
     pattern-matches exhaustively; `mypy --strict` enforces coverage. The `T`
     parameter lets each hookpoint type its substitute (e.g., `ExtractionResult`
     for `security.quarantined.extract`).

     See **CarrierSubstitution** (this glossary) and
     [ADR-0022](adr/0022-recoverable-carrier-semantic-error-stage-dispatch.md).

     ### OperatorSession

     The session model written to `~/.config/alfred/session` by `alfred login`
     (`src/alfred/identity/operator_session.py`, PR-S4-5). Mode `0600` mandatory.
     Fields: short-lived token hash, canonical `user_id`, 12 h expiry (configurable
     via `--expires-in`), per-OS machine-id binding. Load discipline is
     TOCTOU-safe: `open(O_RDONLY | O_NOFOLLOW)` → `fstat` validates mode + uid +
     gid → read. Expired or machine-id-mismatched sessions are refused with
     `OPERATOR_SESSION_REFUSED_FIELDS`.

     See **OperatorSessionTimeout** (this glossary),
     [docs/subsystems/supervisor.md](subsystems/supervisor.md), and
     [ADR-0020](adr/0020-supervisor-cli-access-via-postgres-and-state-git.md).

     ### SandboxKind

     A three-value discriminant in the plugin manifest `sandbox.kind` field:
     `full` — kernel-namespace isolation via bwrap (Linux) or sandbox-exec
     (macOS); `none` — no OS sandbox (first-party in-tree relay adapters like
     Discord and TUI that do not process T3 content directly); `stub` — Windows
     placeholder that refuses in production. The quarantined-LLM plugin migrates
     from `kind: none` (Slice-3 UID-separation baseline) to `kind: full` in
     PR-S4-6/PR-S4-7.

     See [docs/subsystems/security.md](subsystems/security.md#sandbox-model)
     and [ADR-0015](adr/0015-slice4-containerised-quarantined-llm.md).

     ### SandboxPolicy

     The per-OS kernel-namespace policy file declared in a plugin manifest's
     `sandbox.policy_refs` block. Keys: `linux` (path to bwrap `.bwrap.policy`),
     `macos` (path to `.sb` sandbox-exec profile), `windows` (path to
     `.windows.stub.policy`). Required when `sandbox.kind = full`. The
     `bin/alfred-plugin-launcher.sh` resolves the per-OS policy via the Python
     manifest reader at `src/alfred/plugins/manifest_reader.py` before spawning
     the subprocess. Missing or unreadable policy files emit `SANDBOX_REFUSED_FIELDS`
     and abort the spawn.

     See [SandboxKind](#sandboxkind), [docs/subsystems/security.md](subsystems/security.md),
     and [ADR-0015](adr/0015-slice4-containerised-quarantined-llm.md).

     ### T3DerivedData

     `NewType("T3DerivedData", dict[str, object])` — the type-level provenance
     discriminant on `Extracted.data` (Slice-3, re-listed here for Slice-4
     visibility). Signals that the dictionary's values originated from a T3 source
     and must not be injected into privileged prompts without calling
     `downgrade_to_orchestrator()`. In Slice 4, `Orchestrator.quarantined_extract`
     returns `ExtractionResult` with `data: T3DerivedData` and `source_tier="T3"`
     invariantly (sec-001 round-3 closure). A ruff/grep CI rule rejects
     `cast(dict, ...)` applied to a `T3DerivedData` binding.

     Defined in `src/alfred/security/quarantine.py`. See
     [docs/subsystems/quarantine.md](subsystems/quarantine.md),
     [ExtractionResult](glossary.md#extractionresult), and
     [trust tier](glossary.md#trust-tier).

     ```

  3. Run `make docs-check` — must pass.

  4. Commit:

     ```
     git commit -m "docs(glossary): add OperatorSession, SandboxKind/Policy, CarrierSubstitution, ErrorOutcome, T3DerivedData (#TBD-slice4)"
     ```

- [ ] **Task 3 — Glossary: add comms-MCP notification handler terms**

  Files: Modify `docs/glossary.md`.

  Steps:

  1. Verify handler names exist in `src/alfred/`:
     - `grep -r "InboundHandler\|BindingHandler\|RateLimitHandler\|CrashHandler" src/alfred/` →
       confirm the names and their module path.
     - `grep -r "InboundT3Promotion\|T3Promotion" src/alfred/` → confirm constant/class name.
     - `grep -r "class OutboundQueue" src/alfred/` → confirm path (likely
       `src/alfred/comms_mcp/` or `src/alfred/plugins/`).

  2. Append entries to `docs/glossary.md`:

     ```markdown
     ### DiscordSubPayloadClassifier

     The host-side classifier for Discord-shaped JSON sub-payloads
     (`src/alfred/comms_mcp/classifiers/discord.py`, PR-S4-9). Covers nine
     Discord sub-payload kinds: plain message, embed, attachment, poll,
     sticker, reaction, reply, pinned-message-reference, and system event.
     Each kind is promoted to T3 at `StdioTransport.InboundContentScanner`
     before it reaches the orchestrator. The classifier is host-owned — Discord
     plugin code cannot substitute or override it.

     See [REQUIRED_CLASSIFIERS_BY_KIND](#required_classifiers_by_kind),
     [InboundT3Promotion](#inboundt3promotion), and
     [docs/subsystems/comms.md](subsystems/comms.md).

     ### InboundHandler

     One of four `AlfredPluginSession` notification handlers added in PR-S4-8,
     dispatched by `_on_post_handshake_method` when an `inbound.message`
     notification arrives from a comms adapter plugin. The four handlers are:
     `InboundHandler` (`inbound.message`), `BindingHandler`
     (`adapter.binding_requested`), `RateLimitHandler`
     (`adapter.rate_limit_signal`), and `CrashHandler` (`adapter.crashed`).
     Each handler is a coroutine registered in `AlfredPluginSession.__init__`
     and called through a `asyncio.BoundedSemaphore(32)` to bound in-flight
     concurrency. Adapters never write audit rows directly — all audit emission
     is host-side.

     See [docs/subsystems/comms.md](subsystems/comms.md) and
     [ADR-0024](adr/0024-comms-mcp-wire-contract.md).

     ### InboundT3Promotion

     The transport-boundary tagging step that wraps every inbound platform
     payload in `TaggedContent[T3]` before the host processes it. Happens at
     `StdioTransport.InboundContentScanner.scan` — the content is tagged T3
     at entry, stored as a `ContentHandle`, and never reaches the orchestrator
     as raw bytes. The audit row `COMMS_INBOUND_T3_PROMOTION_FIELDS` records
     every promotion. No comms adapter may bypass this step — the classifier
     registry enforcement ensures every `adapter_kind` has at least one required
     classifier.

     See [DiscordSubPayloadClassifier](#discordsubpayloadclassifier),
     [ContentHandle](glossary.md#contenthandle), and
     [docs/subsystems/comms.md](subsystems/comms.md).

     ### OutboundQueue

     The host-side outbound message queue (Slice-3-shipped, extended in PR-S4-9).
     Slice-4 extension adds `pause(adapter_id, retry_after_seconds)` — when an
     adapter signals rate-limiting via `adapter.rate_limit_signal`, the host
     pauses the queue for that adapter for the declared interval and emits
     `COMMS_RATE_LIMIT_SIGNAL_FIELDS`. Messages queued during the pause are
     delivered after the interval expires. The pause is per-adapter-id, not
     global — other adapters continue unaffected.

     See [docs/subsystems/comms.md](subsystems/comms.md#outbound-queue) and
     [ADR-0024](adr/0024-comms-mcp-wire-contract.md).

     ### REQUIRED_CLASSIFIERS_BY_KIND

     The host-side required-classifier set per `adapter_kind`, defined at
     `src/alfred/comms_mcp/classifier_registry.py` (PR-S4-8). Plugins cannot
     opt out via an empty classifier list — the host enforces the minimum
     classifier set regardless of what the adapter declares. An AST guard
     (`tests/unit/comms_mcp/test_required_classifiers_complete.py`) refuses
     adding a new `adapter_kind` without a matching entry. This closes the
     sec-002 finding that an adapter could present an empty classifier list
     to bypass T3 promotion.

     See [BODY_FIELD_BY_KIND](#body_field_by_kind),
     [InboundT3Promotion](#inboundt3promotion), and
     [docs/subsystems/comms.md](subsystems/comms.md).
     ```

  3. Run `make docs-check` — must pass.

  4. Commit:

     ```
     git commit -m "docs(glossary): add comms-MCP notification handler terms (InboundHandler, InboundT3Promotion, OutboundQueue, DiscordSubPayloadClassifier, REQUIRED_CLASSIFIERS_BY_KIND) (#TBD-slice4)"
     ```

---

### Component B: Subsystem deep-doc updates

- [ ] **Task 4 — Update docs/subsystems/security.md for Slice-4 surface**

  Files: Modify `docs/subsystems/security.md`.

  Steps:

  1. Read the full current file to understand its section structure.

  2. Verify the Slice-4 security surfaces exist:
     - `grep -r "class SandboxKind\|sandbox.kind" src/alfred/` — confirm sandbox model location.
     - `grep -r "SANDBOX_REFUSED_FIELDS\|SANDBOX_STUB_USED_FIELDS" src/alfred/` — confirm audit constants.
     - `grep -r "_run_error\|ErrorOutcome" src/alfred/hooks/` — confirm carrier substitution location.
     - `grep -r "audit.hash_pepper\|hash_pepper" src/alfred/` — confirm pepper usage.

  3. Update the `**Status:**` line from `shipped in Slice 3` to `shipped in Slice 3; extended in Slice 4`.

  4. Update `**ADRs:**` to add ADR-0015, ADR-0022.

  5. Append a `## Slice-4 extensions` section (H2, before the existing Cross-references):

     ```markdown
     ## Slice-4 extensions

     **Status:** shipped in Slice 4 (PR-S4-3, PR-S4-6, PR-S4-7).

     Slice 4 adds three security surfaces to this subsystem: sandbox
     containerisation for the quarantined-LLM plugin, carrier substitution for
     error-stage hookpoints, and audit-row HMAC peppered hashing.

     ### Sandbox model

     Every plugin now declares a `sandbox.kind` in its manifest:
     `full` (kernel-namespace isolation), `none` (first-party relay adapters),
     or `stub` (Windows placeholder). The quarantined-LLM plugin migrates from
     `kind: none` (Slice-3 UID-separation baseline) to `kind: full` in
     PR-S4-6/PR-S4-7.

     `bin/alfred-plugin-launcher.sh` reads the per-OS policy ref via
     `src/alfred/plugins/manifest_reader.py` before spawning. Missing or
     unreadable policy emits `SANDBOX_REFUSED_FIELDS` and aborts. The
     `ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED` escape hatch is accepted only when
     `Settings.environment == "development"`; in production the daemon refuses
     to boot if the env var is set (err-005 closure).

     | Platform | Mechanism | Policy path |
     |---|---|---|
     | Linux | `bwrap` kernel namespaces | `config/sandbox/<name>.linux.bwrap.policy` |
     | macOS | `sandbox-exec` profile | `config/sandbox/<name>.macos.sb` |
     | Windows | stub (no enforcement) | `config/sandbox/<name>.windows.stub.policy` |

     The macOS integration test (`test_sandbox_escape_kernel_enforced.py` on
     `macos-latest`) is advisory (CI topology): Linux is merge-blocking.

     See [ADR-0015](../adr/0015-slice4-containerised-quarantined-llm.md),
     [SandboxKind](../glossary.md#sandboxkind), and
     [SandboxPolicy](../glossary.md#sandboxpolicy).

     ### Carrier substitution for error-stage hookpoints

     `_run_error[T]` in `src/alfred/hooks/invoke.py` now returns
     `ErrorOutcome[T] = ReRaise | SubstituteResult[T]` (PR-S4-3, ADR-0022).
     A substitute is accepted only if its `source_tier` is equal to or lower than
     the surrounding carrier's declared tier (strict total order: T0 < T1 < T2 < T3).
     Any upward step is a trust upgrade and is refused with
     `CARRIER_SUBSTITUTION_REFUSED_FIELDS(reason="tier_upgrade_refused")` + re-raise.

     The meta-hookpoints `hooks.carrier_substituted` and
     `hooks.carrier_substitution_refused` are observation-only (`fail_closed=False`);
     subscribers may not themselves substitute on these hookpoints — registration-time
     guard in `register_hookpoint` enforces this.

     See [ADR-0022](../adr/0022-recoverable-carrier-semantic-error-stage-dispatch.md),
     [CarrierSubstitution](../glossary.md#carriersubstitution), and
     [ErrorOutcome](../glossary.md#erroroutcome).

     ### Audit-row HMAC pepper

     `*_hash` fields in comms audit rows (e.g., platform identity hashes) are
     computed via `hmac.new(secret_broker.get("audit.hash_pepper"), ...).hexdigest()[:32]`
     (PR-S4-8, PR-S4-9). The pepper is bootstrapped by the PR-S4-0b Alembic
     migration; the daemon refuses to boot if `"audit.hash_pepper"` is absent from
     the broker (`daemon.boot.failed(failure_reason="audit_hash_pepper_missing")`).
     This closes the forensic-traceability gap where platform snowflakes were stored
     in plaintext in audit rows.

     See [docs/subsystems/comms.md](comms.md#audit-row-hashing).
     ```

  6. Update the `## Slice graduation map` table to add a Slice-4 row, or extend the existing
     row if the table only has one row per subsystem:

     ```markdown
     | security | Slice 4: sandbox containerisation (`kind: full` for quarantined LLM); carrier-substitution tier guard; audit-row HMAC pepper | Slice 5+: typed `SecretRef`; broker-side post-substitution invariant check; per-secret-ID canaries | [ADR-0015](../adr/0015-slice4-containerised-quarantined-llm.md), [ADR-0022](../adr/0022-recoverable-carrier-semantic-error-stage-dispatch.md) |
     ```

  7. Update the `## Cross-references` section to add ADR-0015, ADR-0022,
     [SandboxKind](../glossary.md#sandboxkind), [CarrierSubstitution](../glossary.md#carriersubstitution).

  8. Run `make docs-check` — must pass.

  9. Commit:

     ```
     git commit -m "docs(subsystems/security): add Slice-4 sandbox, carrier-substitution, and audit-pepper extensions (#TBD-slice4)"
     ```

- [ ] **Task 5 — Update docs/subsystems/comms.md for comms-MCP rewrite**

  This is the most substantial doc update in the PR. The existing file describes the
  Slice-2 in-process adapter shape. Slice 4 deleted `src/alfred/comms/` and replaced it
  with `src/alfred/comms_mcp/` plus two plugin directories. The doc must reflect this
  factual change while preserving the historical Slice-2 record where useful for operators.

  Files: Modify `docs/subsystems/comms.md`.

  Steps:

  1. Read the full current `docs/subsystems/comms.md`.

  2. Verify Slice-4 comms surfaces:
     - `ls src/alfred/comms_mcp/` — list files to anchor public-surface claims.
     - `ls plugins/alfred_discord/` — confirm adapter plugin exists.
     - `ls plugins/alfred_tui/` — confirm TUI plugin exists.
     - `grep -r "process_inbound_message" src/alfred/comms_mcp/` — confirm entrypoint.
     - `grep -r "REQUIRED_CLASSIFIERS_BY_KIND" src/alfred/comms_mcp/` — confirm registry.
     - `grep -r "OutboundQueue\|pause" src/alfred/comms_mcp/` — confirm queue extension.
     - Confirm `src/alfred/comms/` does NOT exist: `ls src/alfred/comms/` should fail.

  3. Update the header block:

     - `**Status:**` → `shipped in Slice 2 (in-process adapters); rewritten in Slice 4 (comms-MCP)`
     - `**ADRs:**` → add ADR-0016, ADR-0024; keep ADR-0009 with note that it is superseded
       for new adapters and caveat narrowed in PR-S4-10.

  4. Replace (or prepend before) the current `## Overview` section with a brief historical
     note, then add a `## Slice-4 comms-MCP architecture` H2:

     ```markdown
     ## Historical note (Slice 2)

     Slice 2 shipped Discord and TUI as in-process `CommsAdapter` Protocol implementations.
     ADR-0009 documented this as a bounded deviation from PRD §5 (which requires MCP). The
     in-process adapters were deleted in Slice 4 PR-S4-10. The remainder of this file
     describes the Slice-4 comms-MCP architecture.

     ## Slice-4 comms-MCP architecture

     Every comms adapter is now an MCP stdio plugin spawned by `bin/alfred-plugin-launcher.sh`.
     The host (`src/alfred/comms_mcp/`) owns the wire contract, classifier registry, inbound
     routing, and outbound queuing. Adapters own only platform I/O and JSON-RPC framing; they
     never write audit rows, never tag content trust tiers, and never consult the capability gate.

     This separation enforces three invariants from PRD §5:

     1. **T3 tagging happens at the host transport boundary** — inbound platform payloads are
        tagged `TaggedContent[T3]` by `StdioTransport.InboundContentScanner` before any host
        code processes them. Adapters do not decide trust tiers.
     2. **Adapter-kind classifiers are host-owned** — the `REQUIRED_CLASSIFIERS_BY_KIND` registry
        at `src/alfred/comms_mcp/classifier_registry.py` ensures every adapter_kind has a minimum
        required classifier set the adapter cannot bypass.
     3. **Outbound DLP runs at the host transport boundary** — `OutboundDlp.scan` wraps every
        outbound JSON-RPC frame before it reaches the adapter subprocess.
     ```

  5. Add a `## Public surface` H2 anchored to Slice-4 code:

     ```markdown
     ## Public surface

     - `process_inbound_message(notification, session) -> None` —
       `src/alfred/comms_mcp/inbound.py` — host-side entrypoint called by
       `AlfredPluginSession._on_post_handshake_method` on every `inbound.message`
       notification. Tags body T3 by default; routes through
       `Orchestrator.quarantined_extract(..., source_tier="T3")`.
     - `REQUIRED_CLASSIFIERS_BY_KIND` — `src/alfred/comms_mcp/classifier_registry.py` —
       per-adapter required-classifier set. Host-owned; plugin cannot override.
     - `BODY_FIELD_BY_KIND` — `src/alfred/comms_mcp/classifier_registry.py` —
       per-adapter body-field name. Drives DLP scan field extraction.
     - `OutboundQueue.pause(adapter_id, retry_after_seconds)` — host-side rate-limit honour.
       Pauses outbound for the named adapter; delivers queued messages after interval.
     - `plugins/alfred_discord/` — Discord adapter MCP plugin. Wire methods per ADR-0024.
       Declares `sandbox.kind = none` (relay adapter; does not process T3 content directly).
     - `plugins/alfred_tui/` — TUI adapter MCP plugin. Preserves the Textual rendering layer.
       Spawned by `alfred chat` via `bin/alfred-plugin-launcher.sh`.
     - `DISCORD_BOT_TOKEN` — secret broker key `discord_bot_token`. Never in env vars;
       delivered via the broker at subprocess spawn.
     ```

  6. Add a `## Adapter-kind registry` H2 describing the four notification methods (ADR-0024
     wire contract) and the handler dispatch.

  7. Add an `## Audit-row hashing` H2 covering the HMAC pepper pattern introduced in PR-S4-9.

  8. Add a `## Failure modes` table covering: adapter crash, rate-limit signal, unknown
     notification, handler failure, addressing drift, budget cap.

  9. Add/update `## Slice graduation map` row:

     ```markdown
     | comms | Slice 4: MCP plugin rewrite; `src/alfred/comms/` deleted; Discord + TUI adapters as plugins; host-side classifier registry; `InboundT3Promotion` at transport boundary; `OutboundQueue.pause` | Slice 5+: HTTP transport adapters; container-per-adapter deployment shape; Telegram adapter; `comms.outbound.send` hookpoint | [ADR-0016](../adr/0016-slice4-discord-tui-comms-mcp-rewrite.md), [ADR-0024](../adr/0024-comms-mcp-wire-contract.md) |
     ```

  10. Update `## Cross-references` to add ADR-0016, ADR-0024, and new glossary links.

  11. Run `make docs-check` — must pass.

  12. Commit:

      ```
      git commit -m "docs(subsystems/comms): rewrite for Slice-4 comms-MCP architecture (#TBD-slice4)"
      ```

- [ ] **Task 6 — Update docs/subsystems/supervisor.md for Slice-4 daemon + plugin-restart**

  Files: Modify `docs/subsystems/supervisor.md`.

  Steps:

  1. Read the full current `docs/subsystems/supervisor.md`.

  2. Verify Slice-4 supervisor surfaces:
     - `grep -r "daemon start\|daemon_start\|alfred daemon" src/alfred/cli/` — confirm
       `alfred daemon start` CLI subcommand location.
     - `grep -r "request_plugin_restart\|SUPERVISOR_PLUGIN_RESTART_REQUESTED" src/alfred/supervisor/` —
       confirm the Slice-4 method (PR-S4-8 adds `Supervisor.request_plugin_restart`).
     - `grep -r "policies_ref\|operator_session_resolver" src/alfred/supervisor/` —
       confirm new Slice-4 constructor kwargs.
     - `grep -r "DAEMON_BOOT_FIELDS\|daemon.boot.completed" src/alfred/` — confirm audit constants.
     - `grep -r "_resolve_operator\|OperatorSessionTimeout" src/alfred/identity/` —
       confirm operator session resolver.

  3. Update `**Status:**` → `shipped in Slice 3; extended in Slice 4`.

  4. Update `**ADRs:**` → add ADR-0020, ADR-0021, ADR-0023.

  5. Update the `## Public surface` section to add Slice-4 entries:

     ```markdown
     - `alfred daemon start` — CLI subcommand (PR-S4-1) that constructs
       `Supervisor(state_git_path=settings.state_git_path, policies_ref=...,
       operator_session_resolver=...)` after three pre-`TaskGroup` probes:
       launcher policy-resolving, snapshot-ref initialisation, and capability-gate
       handshake. Emits `daemon.boot.completed` on success. Seven failure reasons
       emit `daemon.boot.failed` with `failure_reason=` (see Failure modes table).
     - `alfred daemon stop` — graceful SIGTERM + 5s grace + SIGKILL to the TaskGroup.
     - `alfred daemon status` — boot-process subset: PID, uptime, boot_id, last
       `daemon.boot.completed` audit row, current TaskGroup stack. Cross-reference
       in `--help`: "For general health see `alfred status`."
     - `Supervisor.request_plugin_restart(plugin_id)` — `src/alfred/supervisor/core.py`
       (PR-S4-8) — triggers a supervised restart of the named plugin. Emits
       `SUPERVISOR_PLUGIN_RESTART_REQUESTED_FIELDS`. Called by the comms-MCP handler
       on repeated handler failures.
     - `policies_ref: PoliciesSnapshotRef` — Slice-4 constructor kwarg. Consumers inside
       `Supervisor` call `policies_ref.current()` per iteration (not once before the loop).
     - `operator_session_resolver: OperatorResolver` — Slice-4 constructor kwarg. DI
       Protocol; every operator-attributed CLI command calls `_resolve_operator(ctx)` which
       has a 5ms p99 budget and a 250ms hard timeout via `asyncio.wait_for`.
     ```

  6. Extend the `## Failure modes` table with Slice-4 daemon boot failures:

     | Trigger | Behaviour | Observable signal |
     | --- | --- | --- |
     | `Settings.environment` unset or unrecognised | Boot refused before TaskGroup opens | `daemon.boot.failed(failure_reason="environment_not_set")` |
     | `ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED=1` in production | Boot refused | `daemon.boot.failed(failure_reason="unsandboxed_env_in_production")` |
     | Launcher policy-resolving probe fails | Boot refused | `daemon.boot.failed(failure_reason="launcher_not_policy_resolving")` |
     | `policies.yaml` initial parse fails | Boot refused | `daemon.boot.failed(failure_reason="snapshot_ref_init_failed")` |
     | `RealGate` cannot reach Postgres/state.git at boot | Boot refused | `daemon.boot.failed(failure_reason="capability_gate_handshake_failed")` |
     | `audit.hash_pepper` absent from broker | Boot refused | `daemon.boot.failed(failure_reason="audit_hash_pepper_missing")` |
     | `_resolve_operator` exceeds 250ms | `OperatorSessionTimeout` raised | `t("operator.session.resolve_timeout")` |

  7. Add an `## Operator-session integration` H3 inside the Internal model section, briefly
     explaining `_resolve_operator` and its DI injection pattern.

  8. Update `## Slice graduation map` row to cover Slice-4 additions.

  9. Update `## Cross-references` to add ADR-0020, ADR-0021, ADR-0023, and glossary links
     for `PolicyWatcher`, `OperatorSession`, `OperatorSessionTimeout`.

  10. Run `make docs-check` — must pass.

  11. Commit:

      ```
      git commit -m "docs(subsystems/supervisor): add Slice-4 daemon boot, plugin-restart, and operator-session extensions (#TBD-slice4)"
      ```

- [ ] **Task 7 — Create (or complete) docs/subsystems/policies.md**

  Files: Create `docs/subsystems/policies.md` if it does not exist; or complete the PR-S4-4
  stub if it was created there. Check first: `ls docs/subsystems/policies.md`.

  Steps:

  1. Check whether PR-S4-4 created a stub:
     - `ls /path/to/docs/subsystems/policies.md` — if it exists, read it first.

  2. If absent, write the full file. If a stub exists, complete it to match the template.
     Use the subsystem deep-doc template from the agent definition.

  3. Verify code anchors before writing:
     - `grep -r "class PoliciesV1" src/alfred/` → confirm module.
     - `grep -r "class PolicyWatcher" src/alfred/` → confirm `src/alfred/policies/watcher.py`.
     - `grep -r "class PoliciesSnapshotRef" src/alfred/` → confirm `src/alfred/policies/snapshot_ref.py`.
     - `grep -r "HighBlastPolicies\|high_blast" src/alfred/policies/` → confirm structure.

  4. Write/complete the file following the template (header, Purpose, Public surface, Internal
     model, Failure modes, Trust-boundary contract, Performance characteristics, Slice graduation
     map, Cross-references). Key prose anchors:

     **Purpose:** The policies subsystem manages the single mutable configuration surface the
     operator can change without a full daemon restart. It answers: "how does AlfredOS let an
     operator tune rate limits and handle caps live without restarting, while refusing live
     changes to high-blast keys like the quarantined-provider URL that would affect in-flight
     requests?" The answer is the `HighBlastPolicies` partition — keys above the blast-radius
     threshold require a full reviewer-gate cycle to change; keys below it can be reloaded by
     an mtime-polling watcher while the daemon is running.

     **Internal model — low/high blast partitioning:** Explain the `PoliciesV1` Pydantic v2
     model; `HighBlastPolicies` sub-model; the watcher's SHA short-circuit idempotency; the
     two-phase audit-then-swap commit; per-iteration deref discipline for long-lived loops.

     **Failure modes table:**

     | Trigger | Behaviour | Observable signal |
     | --- | --- | --- |
     | File vanishes mid-poll | Active snapshot unchanged; watcher continues | `CONFIG_RELOAD_REJECTED_FIELDS(reason="file_vanished")` |
     | `os.stat()` raises | Watcher continues; alert on 3 consecutive failures | `CONFIG_RELOAD_REJECTED_FIELDS(reason="stat_failed")` |
     | 3+ consecutive stat failures | Watcher degrades; poll frequency 10× configured | `supervisor.config_watcher.degraded` hookpoint; audit row |
     | Recovery (3 consecutive successful stats) | Normal cadence resumes | `supervisor.config_watcher.recovered` hookpoint + audit row |
     | High-blast key diff in new snapshot | Swap refused; active snapshot unchanged | `CONFIG_RELOAD_REJECTED_FIELDS(reason="high_blast_change")` |
     | Audit write fails during swap | Swap aborted; active snapshot unchanged | `CONFIG_RELOAD_REJECTED_FIELDS(reason="audit_write_failed")` |
     | Same SHA as active snapshot | Watcher short-circuits; no swap, no audit row | (none — idempotent skip) |

     **Trust-boundary contract:** The watcher reads only `config/policies.yaml` — no external
     network calls, no user-controlled input. The file is operator-owned and lives inside the
     repo tree. The `HighBlastPolicies` partition is the boundary: values above it are
     reviewer-gate-only; values below it are hot-reloadable. The partition is enforced by
     model structure (not runtime policy), so a new field cannot accidentally land in the
     wrong bucket — it must be explicitly placed in `HighBlastPolicies` or a low-blast block.

  5. Run `make docs-check` — must pass.

  6. Commit:

     ```
     git commit -m "docs(subsystems): add policies.md — PoliciesV1 hot-reload deep-doc (#TBD-slice4)"
     ```

---

### Component C: Graduation runbook

- [ ] **Task 8 — Write docs/runbooks/slice-4-graduation.md**

  Files: Create `docs/runbooks/slice-4-graduation.md`.

  Follow the 12-section structure from spec §13.2. Mirror the shape of
  `docs/runbooks/slice-2-discord-smoke.md` for section ordering and prose density.

  Steps:

  1. Read `docs/runbooks/slice-2-discord-smoke.md` to confirm current shape.

  2. Verify all commands exist before documenting them:
     - `grep -r "daemon start\|daemon_start" src/alfred/cli/` — confirm `alfred daemon start`.
     - `grep -r '"login"\|def login' src/alfred/cli/` — confirm `alfred login`.
     - `grep -r '"logout"\|def logout' src/alfred/cli/` — confirm `alfred logout`.
     - `grep -r '"whoami"\|def whoami' src/alfred/cli/` — confirm `alfred whoami`.

  3. Write `docs/runbooks/slice-4-graduation.md` with the following 12 sections:

     **Section 1 — What changed since Slice 3**

     High-level inventory of the four tracks: daemon boot wiring, hot-reload policies,
     CLI operator session, and comms-MCP rewrite. One paragraph each. Link to the
     relevant ADRs (ADR-0015, ADR-0016, ADR-0022, ADR-0023) and subsystem docs.

     **Section 2 — Pre-flight: operator-session setup**

     ```
     alfred user list                           # find your operator username
     alfred login --as <your-operator-user>     # creates ~/.config/alfred/session (mode 0600)
     alfred whoami                              # verify session is active
     ```

     Explain the 12 h expiry default. Note `alfred login --refresh` to extend. Note that
     every subsequent operator CLI command (daemon, supervisor, audit) requires an active
     session.

     **Section 3 — Pre-flight: production environment declaration**

     `ALFRED_ENVIRONMENT=production` must be set in the daemon's environment (or via
     `/etc/alfred/environment`). Absence is a hard error — the daemon refuses to boot with
     a clear message. Options: systemd `Environment=` directive, Docker Compose `environment:`
     key, or `/etc/alfred/environment` plain-text file.

     **Section 4 — Pre-flight: sandbox prerequisites**

     Linux:

     ```sh
     apt-get install bubblewrap    # Debian/Ubuntu
     dnf install bubblewrap        # Fedora/RHEL
     bwrap --version               # verify ≥ 0.6.0
     ```

     macOS: `sandbox-exec` is bundled with macOS 10.15+; no install required.

     Windows: WSL2 only. Sandbox is a stub in production — the daemon emits
     `SANDBOX_STUB_USED_FIELDS` per plugin spawn. PRD §5 quarantined-LLM
     containerisation is not satisfied on Windows; production deployments require Linux.

     **Section 5 — First boot: `alfred daemon start`**

     Expected output on success:

     ```
     [INFO] daemon.boot.completed boot_id=<uuid> slice_version=4 state_git_head_sha=<sha>
     ```

     Seven failure modes with exact error text + fix for each:
     1. `environment_not_set` — set `ALFRED_ENVIRONMENT`.
     2. `unsandboxed_env_in_production` — unset `ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED`.
     3. `launcher_not_policy_resolving` — confirm PR-S4-6 landed; check launcher version.
     4. `snapshot_ref_init_failed` — validate `config/policies.yaml` parses as `PoliciesV1`.
     5. `capability_gate_handshake_failed` — check Postgres reachability; confirm state.git accessible.
     6. `audit_hash_pepper_missing` — run broker bootstrap: `alfred secrets bootstrap audit.hash_pepper`.
     7. `session_not_found` — run `alfred login --as <user>` first.

     **Section 6 — First chat: `alfred chat`**

     In Slice 4, `alfred chat` spawns the TUI adapter plugin via
     `bin/alfred-plugin-launcher.sh`. The daemon must be running. If the daemon is not
     running, `alfred chat` exits immediately with:

     ```
     Error: daemon is not running. Start it with `alfred daemon start`.
     ```

     Success: the Textual TUI loads, shows the active persona, and prompts for input. A
     round-trip message reaches the orchestrator and returns a response.

     **Section 7 — First Discord: configure adapter**

     ```sh
     alfred secrets set discord_bot_token <token>   # stores via secret broker
     alfred daemon start                             # daemon spawns Discord adapter on start
     ```

     The Discord adapter (`plugins/alfred_discord/`) connects to the Discord gateway. Inbound
     DMs appear in the audit log as `COMMS_INBOUND_T3_PROMOTION_FIELDS` rows. Verify:

     ```sh
     alfred audit log --event comms.inbound.t3_promoted --since 5m
     ```

     **Section 8 — Hot-reload UX**

     Edit `config/policies.yaml` (a low-blast key such as `rate_limits.web_fetch_per_user_per_hour`).
     Within ≤1 s (polling interval), the watcher detects the mtime change and reloads. Verify:

     ```sh
     alfred audit log --event supervisor.config_reload --since 30s
     ```

     Attempting to change a high-blast key (`quarantined_provider_url`) produces:

     ```sh
     alfred audit log --event supervisor.config_reload_rejected --since 30s
     # reason: high_blast_change
     ```

     The active snapshot is unchanged. To change high-blast keys: update via the reviewer-gate
     proposal flow and restart the daemon.

     **Section 9 — Operator-session expiry + refresh**

     Sessions expire after 12 h by default. `alfred whoami` shows the expiry time. To refresh:

     ```sh
     alfred login --refresh                    # extends expiry from now
     alfred login --as <user> --expires-in 4h  # create new short-lived session
     ```

     On expiry, all operator-attributed CLI commands fail with:

     ```
     Error: operator session expired. Run `alfred login --as <user>` to refresh.
     ```

     **Section 10 — Troubleshooting**

     Table of common issues → diagnostic command → fix:

     | Symptom | Diagnostic | Fix |
     | --- | --- | --- |
     | `sandbox_refused` in audit log | `alfred audit log --event supervisor.plugin.sandbox_refused` | Check `sandbox.kind` in plugin manifest; confirm policy file exists |
     | `config_reload_rejected(reason=high_blast_change)` | `alfred audit log --event supervisor.config_reload_rejected` | Change only via reviewer-gate + daemon restart |
     | `operator.session.refused` | `alfred whoami` | Re-run `alfred login --as <user>` |
     | Daemon boot fails with `snapshot_ref_init_failed` | `python -c "import yaml; yaml.safe_load(open('config/policies.yaml'))"` | Fix YAML syntax; validate against `PoliciesV1` schema |
     | `COMMS_HANDLER_FAILED_FIELDS` in audit | `alfred audit log --event comms.handler_failed` | Check plugin logs; consider `alfred supervisor reset <adapter>` |
     | Circuit breaker OPEN for quarantined LLM | `alfred supervisor status` | `alfred supervisor reset quarantined-llm --confirm` |

     Each operator-facing term in this section links to its first-use glossary entry.

     **Section 11 — Rollback paths**

     Per-PR-revertable matrix (matches spec §5 rollback strategy):

     | PR | What reverts | Side effect |
     | --- | --- | --- |
     | PR-S4-1 | `alfred daemon start` CLI; daemon boot audit rows | Daemon can no longer be started via CLI; must start Supervisor manually |
     | PR-S4-4 | `PolicyWatcher` hot-reload | Config changes require daemon restart |
     | PR-S4-5 | `alfred login/logout/whoami`; all operator sessions revoked | Operators re-login after revert |
     | PR-S4-6/7 | Sandbox policy files; launcher policy-resolving | Quarantined LLM falls back to UID-separation baseline (dev escape hatch) |
     | PR-S4-9 | Discord MCP adapter | Discord falls back to legacy in-process adapter (still in `src/alfred/comms/` on the reverted commit) |
     | PR-S4-10 | TUI MCP adapter + `src/alfred/comms/` deletion | **Irreversible** — `src/alfred/comms/` deletion cannot be reverted to a live state; requires a new forward PR |
     | PR-S4-11 | This runbook, glossary additions, ADR status flips | Documentation only; no runtime effect |

     **Section 12 — Vocabulary**

     Short one-line definitions for the operator-facing terms used in this runbook, with a
     pointer to `docs/glossary.md` for full definitions. Terms to cover: `PolicyWatcher`,
     `PoliciesSnapshot`, `policies_snapshot_hash`, `HighBlastPolicies`, `OperatorSession`,
     `SandboxKind`, `SandboxPolicy`, `daemon.boot.completed`, `carrier substitution`,
     `BurstLimiter`, `InboundT3Promotion`, `OutboundQueue`.

     Each term: one sentence definition + `→ [glossary](../glossary.md#<anchor>)`.

  4. Run `make docs-check` — must pass.

  5. Commit:

     ```
     git commit -m "docs(runbooks): add slice-4-graduation.md — 12-section operator runbook (#TBD-slice4)"
     ```

---

### Component D: CLAUDE.md + README updates

- [ ] **Task 9 — Update `.rulesync/rules/CLAUDE.md` tree + commands; regenerate CLAUDE.md**

  Files: Modify `.rulesync/rules/CLAUDE.md`; regenerate `CLAUDE.md` via rulesync.

  Steps:

  1. Read `.rulesync/rules/CLAUDE.md` to confirm the current tree and commands table.

  2. In the `## Where things live` tree section, add the four new Slice-4 paths inside the
     appropriate parent entries:

     Under `├── bin/`:

     ```
     │   ├── alfred-plugin-launcher.sh          # plugin sandbox launcher (extended Slice 4)
     ```

     Under `├── plugins/`:

     ```
     │   ├── alfred_discord/                     # Discord comms-MCP adapter (Slice 4)
     │   └── alfred_tui/                         # TUI comms-MCP adapter (Slice 4)
     ```

     Under `├── src/alfred/`:

     ```
     │   ├── comms_mcp/                          # comms-MCP wire contract, classifier registry, inbound routing
     │   ├── policies/                            # PoliciesV1, PolicyWatcher, PoliciesSnapshotRef
     ```

     Also update the `docs/subsystems/` tree block to add `policies.md`:

     ```
     │   ├── policies.md             # PoliciesV1 / PolicyWatcher / hot-reload / blast partitioning
     ```

  3. In the `## Commands you should know` table, add the following rows:

     ```markdown
     | Start daemon | `alfred daemon start` (boots full Slice-4 stack: supervisor, comms-MCP, hot-reload) |
     | Stop daemon | `alfred daemon stop` |
     | Daemon boot status | `alfred daemon status` (see also `alfred status` for general health) |
     | Operator login | `alfred login --as <user>` (writes `~/.config/alfred/session`, 12 h expiry) |
     | Operator logout | `alfred logout` |
     | Show active session | `alfred whoami` |
     ```

     Also update the existing `| TUI conversation |` row to note the daemon requirement:

     ```markdown
     | TUI conversation | `alfred chat` (requires daemon running — see `alfred daemon start`) |
     ```

     Also correct `bin/dev-setup.sh` → `bin/alfred-setup.sh` in the "Set up dev environment"
     row (ops-005 correction; the canonical name is `alfred-setup.sh` per the actual file in
     `bin/`).

  4. Run `rulesync generate -t claude-code -f '*'` to regenerate `CLAUDE.md` from the
     updated rules file. The generated `CLAUDE.md` must not exceed 200 lines — if the update
     pushes it over, extract a non-essential paragraph to its subsystem deep-doc and link instead.

  5. Run `make docs-check` — must pass.

  6. Commit:

     ```
     git commit -m "docs(claude-md): add Slice-4 paths and commands to tree and commands table (#TBD-slice4)"
     ```

- [ ] **Task 10 — Update README.md quickstart for daemon requirement**

  Files: Modify `README.md`.

  Steps:

  1. Read the current `README.md` quickstart section (around lines 26–80).

  2. Update the Quickstart code block. Currently:

     ```sh
     alfred chat                 # start a TUI conversation
     ```

     Replace with:

     ```sh
     alfred daemon start         # start the AlfredOS daemon (required before chat)
     alfred chat                 # start a TUI conversation (daemon must be running)
     ```

  3. Add a one-sentence note below the code block:

     > Slice 4 requires the daemon to be running before `alfred chat`. See
     > [`docs/runbooks/slice-4-graduation.md`](docs/runbooks/slice-4-graduation.md)
     > for the full operator upgrade guide.

  4. Update the "Enable Discord" section header and prose to note that Discord now runs as
     an MCP plugin (not an in-process adapter). Keep the operator workflow steps but add after
     step 3 (copy the bot token):

     > **Slice 4:** The Discord adapter runs as an MCP subprocess plugin. Start the daemon
     > with `alfred daemon start` — it spawns the Discord plugin automatically. The
     > `DISCORD_BOT_TOKEN` must be in the secret broker (step 4) before daemon start.

  5. Run `make docs-check` — must pass.

  6. Commit:

     ```
     git commit -m "docs(readme): update quickstart for Slice-4 daemon requirement and Discord MCP adapter (#TBD-slice4)"
     ```

---

### Component E: ADR status flips (one-time ownership — this PR only)

- [ ] **Task 11 — Flip ADR-0015 status Proposed → Accepted**

  Files: Modify `docs/adr/0015-slice4-containerised-quarantined-llm.md`.

  This is one of the two one-time ownership actions specified in `docs/superpowers/plans/2026-06-07-slice-4-index.md`
  §3. No other PR may perform this flip.

  Steps:

  1. Read `docs/adr/0015-slice4-containerised-quarantined-llm.md` in full to confirm the
     current status header reads exactly `Proposed`.

  2. Replace the `## Status` block:

     Before:

     ```markdown
     ## Status

     Proposed

     **Date:** 2026-05-31
     ```

     After:

     ```markdown
     ## Status

     Accepted

     **Date:** 2026-05-31
     **Accepted:** 2026-06-07
     **Implemented in:** PR-S4-6 (sandbox launcher foundations), PR-S4-7 (sandbox policy bytes)
     ```

  3. Append to the ADR's existing "Consequences" section (or add if absent):

     ```markdown
     ### Implementation note (Slice 4)

     The quarantined-LLM plugin manifest migrated from `kind: none` (Slice-3 UID-separation
     baseline) to `kind: full` in PR-S4-6. Linux bwrap policy, macOS sandbox-exec policy,
     and Windows stub shipped in PR-S4-7. The macOS integration test is advisory; Linux
     is merge-blocking. Per-OS policy files live under `config/sandbox/`.
     ```

  4. Run `make docs-check` — must pass.

  5. Commit:

     ```
     git commit -m "docs(adr): flip ADR-0015 status Proposed → Accepted — sandbox containerisation implemented in Slice 4 (#TBD-slice4)"
     ```

- [ ] **Task 12 — Flip ADR-0016 status Proposed → Accepted**

  Files: Modify `docs/adr/0016-slice4-discord-tui-comms-mcp-rewrite.md`.

  Steps:

  1. Read `docs/adr/0016-slice4-discord-tui-comms-mcp-rewrite.md` in full to confirm the
     current status header reads exactly `Proposed`.

  2. Replace the `## Status` block:

     Before:

     ```markdown
     ## Status

     Proposed

     **Date:** 2026-05-31
     ```

     After:

     ```markdown
     ## Status

     Accepted

     **Date:** 2026-05-31
     **Accepted:** 2026-06-07
     **Implemented in:** PR-S4-8 (comms-MCP foundations), PR-S4-9 (Discord adapter),
     PR-S4-10 (TUI adapter + `src/alfred/comms/` deletion)
     ```

  3. Append to the ADR's "Consequences" section:

     ```markdown
     ### Implementation note (Slice 4)

     `src/alfred/comms/` was deleted in PR-S4-10 (one-shot, irreversible per the slice index
     §3 one-time ownership rule). `src/alfred/comms_mcp/` houses the wire-format owner,
     classifier registry, and inbound routing. Discord (`plugins/alfred_discord/`) and TUI
     (`plugins/alfred_tui/`) are MCP stdio plugins spawned by `bin/alfred-plugin-launcher.sh`.
     ADR-0009's caveat "for new adapters" was narrowed in PR-S4-10 — the in-process adapter
     Protocol no longer exists in any form.
     ```

  4. Run `make docs-check` — must pass.

  5. Commit:

     ```
     git commit -m "docs(adr): flip ADR-0016 status Proposed → Accepted — comms-MCP rewrite implemented in Slice 4 (#TBD-slice4)"
     ```

---

### Component F: Required-checks manifest update

- [ ] **Task 13 — Update docs/ci/required-checks.md with 10 Slice-4 gates**

  Files: Modify `docs/ci/required-checks.md`.

  Steps:

  1. Read the current `docs/ci/required-checks.md`. Confirm the "Pending required" section
     at the bottom contains the Slice-4 gates (they were each promoted by their owning PR
     per ops-007 — verify this before writing; if the gates are already in "Currently required"
     because the owning PRs already promoted them, skip this task and add a note in the PR
     description).

  2. If any Slice-4 gates remain in "Pending required" (they should not, per ops-007), move
     them to "Currently required" with today's date.

  3. For each of the 10 gates, confirm the row format matches the table headers
     (`Check name | Workflow | Job key | Active since | Rationale`):

     | Check name | Workflow | Job key | Active since | Rationale |
     | --- | --- | --- | --- | --- |
     | `test_error_chain_substitution_propagates` | `.github/workflows/ci.yml` | `integration` | 2026-06-07 | Carrier-substitution tier-guard correctness is a security boundary; merge-blocking enforces it. |
     | `test_hot_reload_high_blast_refusal` | `.github/workflows/ci.yml` | `integration` | 2026-06-07 | High-blast key refusal is a security invariant — a policy bug could swap the quarantined provider URL mid-flight. |
     | `test_operator_session_lifecycle` | `.github/workflows/ci.yml` | `integration` | 2026-06-07 | Session TOCTOU-safe load and machine-id binding are security boundaries. |
     | `test_launcher_policy_resolver` | `.github/workflows/ci.yml` | `integration` | 2026-06-07 | Sandbox policy resolution is a trust boundary — a resolver bug could spawn unsandboxed. |
     | `test_sandbox_escape_kernel_enforced` | `.github/workflows/ci.yml` | `integration` | 2026-06-07 | Kernel-level sandbox enforcement is the primary isolation guarantee for the quarantined LLM. |
     | `test_comms_mcp_identity_boundary_real` | `.github/workflows/ci.yml` | `integration` | 2026-06-07 | Identity-boundary enforcement on the comms-MCP inbound path closes #152. |
     | `test_discord_addressing_modes` | `.github/workflows/ci.yml` | `integration` | 2026-06-07 | Discord persona-addressing modes (DM/mention/channel/thread) are the primary user-visible routing contract. |
     | `test_discord_subpayload_promotion` | `.github/workflows/ci.yml` | `integration` | 2026-06-07 | Sub-payload T3 promotion for all nine Discord kinds is a security boundary. |
     | `test_tui_round_trip` | `.github/workflows/ci.yml` | `integration` | 2026-06-07 | TUI plugin round-trip confirms the comms-MCP rewrite is end-to-end functional. |
     | `test_slice4_graduation` | `.github/workflows/ci.yml` | `smoke` | 2026-06-07 | Compose-up + login + chat smoke pins the full Slice-4 stack. Promoted in PR-S4-10 (ops-006 closure). |

  4. Run `make docs-check` — must pass.

  5. Commit:

     ```
     git commit -m "docs(ci): record 10 Slice-4 merge-blocking gates in required-checks manifest (#TBD-slice4)"
     ```

---

### Component G: Graduation verification

- [ ] **Task 14 — Verify all 12 Slice-4 graduation criteria**

  This task is a verification checklist, not an authoring task. Run each check and
  record the result. If any criterion fails, hold PR-S4-11 and open a targeted fix PR.

  Steps:

  1. **Criterion 1 — All 12 PRs merged.**

     ```bash
     git log --oneline main | grep -E "S4-0a|S4-0b|S4-1|S4-2|S4-3|S4-4|S4-5|S4-6|S4-7|S4-8|S4-9|S4-10"
     ```

     Must show 12 merge entries. If any are missing, PR-S4-11 holds.

  2. **Criterion 2 — 2 anchor integration tests green on main CI.**

     On the merge-base CI for `main`:
     - `tests/integration/test_sandbox_escape_kernel_enforced.py` — green.
     - `tests/integration/test_comms_mcp_identity_boundary_real.py` — green.

     Verify via `gh pr checks <main-branch-sha>` or the GitHub Actions UI.

  3. **Criterion 3 — Adversarial suite passes.**

     ```bash
     uv run pytest tests/adversarial -q
     ```

     Must exit 0. Every Slice-4 corpus entry (`sbx-*`, `crf-*`, `csb-*`, `osf-*`, `cib-*`)
     must be in the passing set.

  4. **Criterion 4 — `make check` green.**

     ```bash
     make check
     ```

     Must exit 0. Includes ruff lint, ruff format, mypy --strict, pyright, unit tests.

  5. **Criterion 5 — `make docs-check` green.**

     ```bash
     make docs-check
     ```

     Must exit 0. No broken cross-links in PRD, CLAUDE.md, ADRs, runbooks, glossary.

  6. **Criterion 6 — Required-check manifest updated.**

     Confirm `docs/ci/required-checks.md` "Currently required" section contains all 10
     Slice-4 gates (Task 13 above). Count the rows — must be 10 new entries relative to
     the Slice-3 baseline.

  7. **Criterion 7 — Scripted graduation smoke passes.**

     ```bash
     docker compose up -d
     alfred login --as <test_user>
     uv run pytest tests/smoke/test_slice4_graduation.py -q
     ```

     Must pass within 240 s hard budget (perf-007 closure).

  8. **Criterion 8 — Discord smoke passes against MCP plugin shape.**

     ```bash
     uv run pytest tests/smoke/test_discord_gateway_smoke.py -q
     ```

     The smoke was rewritten in PR-S4-9 for the MCP plugin shape. Must pass.

  9. **Criterion 9 — `src/alfred/comms/` absent; AST guard green; `src/alfred/comms_mcp/` present.**

     ```bash
     ls src/alfred/comms/ 2>&1 | grep -q "No such file" && echo "PASS" || echo "FAIL"
     ls src/alfred/comms_mcp/protocol.py src/alfred/comms_mcp/inbound.py src/alfred/comms_mcp/classifier_registry.py
     uv run pytest tests/unit/comms_mcp/test_required_classifiers_complete.py -q
     ```

  10. **Criterion 10 — ADR-0015/0016 status headers read "Accepted"; ADR-0009 caveat narrowed.**

      ```bash
      grep -A2 "^## Status" docs/adr/0015-slice4-containerised-quarantined-llm.md | grep "Accepted"
      grep -A2 "^## Status" docs/adr/0016-slice4-discord-tui-comms-mcp-rewrite.md | grep "Accepted"
      grep "for new adapters" docs/adr/0009-comms-adapter-protocol-slice2-only.md && echo "FAIL — caveat not narrowed" || echo "PASS — caveat narrowed"
      ```

  11. **Criterion 11 — 100% line + branch coverage on 9 trust-boundary files.**

      ```bash
      uv run pytest tests/unit tests/integration --cov=src/alfred/identity/operator_session.py \
        --cov=src/alfred/cli/operator_session.py \
        --cov=src/alfred/comms_mcp/inbound.py \
        --cov=src/alfred/comms_mcp/classifier_registry.py \
        --cov=src/alfred/policies/watcher.py \
        --cov=src/alfred/policies/snapshot_ref.py \
        --cov=src/alfred/hooks/invoke.py \
        --cov=src/alfred/orchestrator/burst_limiter.py \
        --cov-fail-under=100
      ```

      For `bin/alfred-plugin-launcher.sh`: confirm `bashcov` coverage is ≥ 100% line + 95%
      branch (sec-004 / test-008 closure). For `src/alfred/plugins/manifest_reader.py`:
      confirm 100% line + 100% branch via `coverage.py`.

  12. **Criterion 12 — 10 required-status-check promotions recorded.**

      ```bash
      # Count Slice-4 gates in branch protection (requires gh CLI and repo admin access):
      gh api repos/alfred-os/AlfredOS/branches/main/protection/required_status_checks \
        --jq '.contexts | length'
      ```

      Count must have increased by exactly 10 since Slice-3 graduation. Alternatively,
      count the new rows in `docs/ci/required-checks.md` "Currently required" table.

  Commit after all 12 pass:

  ```
  git commit -m "docs(graduation): verify all 12 Slice-4 graduation criteria — PR-S4-11 (#TBD-slice4)"
  ```

  This commit is the slice sign-off. Include a brief summary in the commit body:
  criteria 1–12 all PASS, no deferrals.

---

### Component H: Final audit + PR

- [ ] **Task 15 — Final cross-link and VERIFY-marker audit**

  Steps:

  1. Run a grep to confirm no `[VERIFY:]` markers remain in any committed doc file:

     ```bash
     grep -r "\[VERIFY:" docs/ README.md CLAUDE.md
     ```

     Must return empty. `[VERIFY:]` markers are an in-draft handshake only; they are a
     release blocker if they appear in committed files.

  2. Run a grep to confirm all new glossary terms are linked from the subsystem docs that
     use them:

     - Every term added in Tasks 1–3 appears at least once as a markdown link in the four
       subsystem docs updated in Tasks 4–7.

  3. Confirm the CLAUDE.md hub is ≤ 200 lines:

     ```bash
     wc -l CLAUDE.md
     ```

     If over 200 lines, extract the longest non-hub paragraph to the appropriate subsystem
     deep-doc and replace with a 2-line summary + link.

  4. Run `make docs-check` one final time — must pass.

  5. Run `make check` — must pass.

- [ ] **Task 16 — Open PR and release note**

  Steps:

  1. Push the branch.

  2. Open a PR with:
     - Title: `docs(slice-4): graduation — subsystem docs, runbook, glossary, ADR status flips`
     - Body: reference spec §13, §14; list the 12 graduation criteria with PASS/FAIL status;
       link `docs/runbooks/slice-4-graduation.md` as the operator upgrade guide;
       note the two one-time ownership actions (ADR-0015 + ADR-0016 status flips per
       index §3).

  3. Add a release note candidate comment on the PR (or in `CHANGELOG.md` if it exists):

     ```
     Slice 4 — graduation (PR-S4-11):
     - Sandbox containerisation for quarantined LLM (ADR-0015, Linux bwrap + macOS sandbox-exec)
     - Discord and TUI adapters rewritten as MCP plugins (ADR-0016)
     - Hot-reload for config/policies.yaml low-blast keys (ADR-0023)
     - Recoverable-carrier semantic for error-stage hookpoints (ADR-0022)
     - CLI operator session (alfred login/logout/whoami)
     - alfred daemon start/stop/status
     - 10 new merge-blocking integration test gates
     ```

---

## §5 Slice graduation criteria checklist

These are the 12 criteria from spec §14. Task 14 verifies each; this checklist is the
PR description reference.

| # | Criterion | Verified by |
| --- | --- | --- |
| 1 | All 12 PRs (S4-0a through S4-10) merged to `main` | `git log --oneline main` |
| 2 | 2 anchor integration tests green on merge-base CI | GH Actions; Task 14 step 2 |
| 3 | Adversarial suite passes | `uv run pytest tests/adversarial` |
| 4 | `make check` green | `make check` |
| 5 | `make docs-check` green | `make docs-check` |
| 6 | Required-check manifest updated | `docs/ci/required-checks.md` row count |
| 7 | `tests/smoke/test_slice4_graduation.py` scripted smoke passes | compose-up + login + chat |
| 8 | Discord smoke passes against MCP plugin shape | `tests/smoke/test_discord_gateway_smoke.py` |
| 9 | `src/alfred/comms/` absent; AST guard green; `src/alfred/comms_mcp/` present | `ls` + pytest |
| 10 | ADR-0015/0016 read "Accepted"; ADR-0009 caveat narrowed | `grep` |
| 11 | 100% line+branch on 9 trust-boundary files | `pytest --cov` + bashcov |
| 12 | 10 required-status-check promotions recorded | `gh api` or manifest row count |

---

## §6 One-time ownership actions (from index §3)

These actions must happen in this PR and no other:

- **ADR-0015 status flip Proposed → Accepted.** Task 11.
- **ADR-0016 status flip Proposed → Accepted.** Task 12.

These actions must NOT be in this PR (they were owned by prior PRs):

- `src/alfred/comms/` deletion — PR-S4-10 only.
- ADR-0009 caveat narrowing — PR-S4-10 only.
- PRD §5 line 117 amendment — PR-S4-0a only (human-gated).
- `bin/alfred-plugin-launcher.sh` policy-resolution rewrite — PR-S4-6 only.

---

## §7 Cross-PR contracts assumed (all defined upstream)

PR-S4-11 consumes the following surfaces defined in prior PRs. Each must exist at HEAD
before the corresponding task runs:

| Surface | Defined in | Used in task |
| --- | --- | --- |
| `src/alfred/policies/watcher.py` (`PolicyWatcher`) | PR-S4-4 | Tasks 1, 7 |
| `src/alfred/policies/models.py` (`PoliciesV1`, `HighBlastPolicies`) | PR-S4-4 | Tasks 1, 7 |
| `src/alfred/policies/snapshot_ref.py` (`PoliciesSnapshotRef`) | PR-S4-4 | Tasks 1, 7 |
| `src/alfred/identity/operator_session.py` (`OperatorSession`, `_resolve_operator`) | PR-S4-5 | Tasks 2, 6 |
| `src/alfred/hooks/invoke.py` (`_run_error`, `ErrorOutcome`) | PR-S4-3 | Tasks 2, 4 |
| `src/alfred/orchestrator/burst_limiter.py` (`BurstLimiter`) | PR-S4-8 | Tasks 1, 4 |
| `src/alfred/comms_mcp/protocol.py` | PR-S4-8 | Tasks 3, 5 |
| `src/alfred/comms_mcp/inbound.py` (`process_inbound_message`) | PR-S4-8 | Tasks 3, 5 |
| `src/alfred/comms_mcp/classifier_registry.py` (`REQUIRED_CLASSIFIERS_BY_KIND`, `BODY_FIELD_BY_KIND`) | PR-S4-8 | Tasks 1, 3, 5 |
| `src/alfred/comms_mcp/classifiers/discord.py` (`DiscordSubPayloadClassifier`) | PR-S4-9 | Tasks 3, 5 |
| `plugins/alfred_discord/` | PR-S4-9 | Tasks 5, 8, 10 |
| `plugins/alfred_tui/` | PR-S4-10 | Tasks 5, 9, 10 |
| `src/alfred/plugins/manifest_reader.py` | PR-S4-6 | Tasks 2, 4 |
| `bin/alfred-plugin-launcher.sh` (policy-resolving) | PR-S4-6 | Tasks 2, 4, 9 |
| `tests/smoke/test_slice4_graduation.py` | PR-S4-10 | Task 14 criterion 7 |
| `tests/smoke/test_discord_gateway_smoke.py` (MCP-shape rewrite) | PR-S4-9 | Task 14 criterion 8 |

---

## §8 Quality gates before merge

1. `make check` — mandatory.
2. `make docs-check` — mandatory (this PR is docs-only, so this is the primary gate).
3. No `[VERIFY:]` markers in any committed file (Task 15 step 1).
4. CLAUDE.md ≤ 200 lines (Task 15 step 3).
5. Conventional-commit `#NNN` reference in every commit subject.
6. Markdown lint (`markdownlint-cli2`) green.
7. All 12 graduation criteria pass (Task 14).
8. PR description references spec §13, §14 and the two one-time ownership actions.
