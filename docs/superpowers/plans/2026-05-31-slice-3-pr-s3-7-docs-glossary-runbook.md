# Slice 3 — PR S3-7: Docs, Glossary, Runbook, DevGate Removal — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `docs/subsystems/plugins.md`, `docs/subsystems/supervisor.md`, and `docs/subsystems/quarantine.md` as authoritative deep-docs; add 20 glossary entries and update 2 existing ones; write `docs/runbooks/slice-3-operator-migration.md`; update the CLAUDE.md command table with new Slice-3 CLI surface; remove `DevGate` from `src/` and migrate all deny-path tests to `RealGate` fixtures; retire Slice-2.5 tracking issues #122–#125.

**Architecture:** This is the final Slice-3 PR. It has no upstream consumer — everything that was built gets documented here. The three subsystem deep-docs explain why each subsystem looks the way it does and how its pieces compose; they cross-link the ADRs, code symbols, and glossary terms so every claim is anchored. The DevGate flag-day is a surgical removal: `capability.py` drops the `DevGate` class, `src/alfred/bootstrap/gate_factory.py` owns the `ALFRED_ENV`-keyed construction, tests that previously exercised deny-path semantics via `DevGate` fixtures now assert the same invariants via `RealGate` fixtures backed by a Postgres testcontainer (the deny-path semantics are preserved, the backing store moves).

**Tech Stack:** Markdown (GitHub-flavoured) + cross-links anchored to code symbols; Python 3.12+ for test migration; `RealGate` from `src/alfred/hooks/capability.py` (shipped by PR-S3-2); `pytest` + `testcontainers`; `make docs-check` (broken-link gate); `uv run pybabel compile --check`.

**Depends on:** ALL prior Slice-3 PRs — PR-S3-0a (merged — `audit_row_schemas.py` constants, ADR-0017, ADR-0015 + ADR-0016 stubs, PRD §5 amendment), PR-S3-0b (merged — Alembic migrations 0007–0009, i18n catalog, Docker/Redis/state.git infrastructure), PR-S3-1 (merged — `T1`/`T3` trust tiers, `tag(T3, …)` nonce, `quarantined_to_structured`), PR-S3-2 (merged — `RealGate` with `check_plugin_load` and `check_content_clearance` backing store), PR-S3-3a (merged — `StdioTransport`, `AlfredPluginSession`, MCP plugin host), PR-S3-3b (merged — `Supervisor`, `CircuitBreaker`, `QuarantinedUnavailable`), PR-S3-4 (merged — `QuarantinedExtractor` MCP client, schema_version anchor), PR-S3-5 (merged — `alfred-web-fetch` plugin, `InboundCanaryScanner`, `WebFetchError` hierarchy), PR-S3-6 (merged — operator CLI surface, `CommsAdapterMCP` Protocol stub). PR-S3-7 is the final Slice-3 PR per the §2 dependency table in `docs/superpowers/plans/2026-05-31-slice-3-index.md`.

**Blocks:** — (Slice-3 closes here; Slice 4 ADR-0015 + ADR-0016 commitments carry forward.)

---

## §0 Pre-tasks

Before starting Task 1, the implementer **creates a GitHub tracking issue** for PR-S3-7 (or uses the Slice-3 epic issue created in PR-S3-0a) and substitutes the real issue number for every `#TBD-slice3` token in the commit messages below. The placeholder token must not land in committed history.

---

## §1 Goal

This PR is the flag-day and documentation capstone for the entire Slice-3 trust-tier completion. Its spec anchors are §15 (migration / flag-day strategy), §17 item 9 (PR-S3-7 deliverables), and §18 (glossary + sibling-doc references). It has three distinct jobs:

1. **Deep-docs for three new subsystems** — `plugins`, `supervisor`, and `quarantine`. Each doc explains why the subsystem has the shape it does (the strategic layer no automator can produce), cross-links to every load-bearing PRD section, ADR, code symbol, and glossary term, and maps each feature to the slice in which it shipped.

2. **Glossary + CLAUDE.md** — 20 new glossary terms: 18 from Tasks 1–5 (`ContentHandle`, `QuarantinedExtractor`, `T3DerivedData`, `PluginTransport`, `StdioTransport`, `AlfredPluginSession`, `sandbox profile`, `RealGate`, `ExtractionResult`, `TypedRefusal`, `JSON_OBJECT_MODE`, `ProviderCapability`, `WebFetchError`, `WebFetchCanaryTripped`, `QuarantinedUnavailable`, `CommsAdapterMCP`, `quarantined_to_structured`, `AnyTaggedContent`) plus 2 spec §18 required entries (`provenance`, `Supervisor`) added in Task 5a. Plus 2 updates to existing entries (`capability gate`, `hook tier`). The CLAUDE.md command table gains all new Slice-3 CLI commands; the canonical source is `.rulesync/rules/CLAUDE.md`, regenerated via `rulesync`.

3. **Flag-day** — `DevGate` is removed from `src/alfred/hooks/capability.py`. All deny-path tests that previously relied on `DevGate` fixtures are migrated to `RealGate` fixtures. The deny-path semantics are the invariant; the backing-store implementation is what changes. `src/alfred/bootstrap/gate_factory.py` (already landed by PR-S3-2) is the `ALFRED_ENV`-keyed construction site; `capability.py` becomes gate-implementation-free.

---

## §2 Architecture overview

### Deep-doc relationship

```
CLAUDE.md  ─── links to ──► docs/subsystems/plugins.md
                         ├── docs/subsystems/supervisor.md
                         └── docs/subsystems/quarantine.md

Each subsystem doc links to:
  ← docs/glossary.md  (terms defined once, linked everywhere)
  ← docs/adr/0017-*.md  (load-bearing Slice-3 ADR)
  ← PRD §5, §6.3, §6.4, §6.7, §7.1, §7.3
  ← sibling docs: hooks.md, security.md (when it exists), identity.md
  ← src/alfred/<subsystem>/  (code anchor for every public surface)
```

The runbook sits at `docs/runbooks/slice-3-operator-migration.md` and is linked from `docs/subsystems/plugins.md` (the "where to start" pointer for operators) and from `CLAUDE.md`'s "When you get stuck" pointer via the subsystem docs.

### DevGate removal

Before this PR: `capability.py` contains both `CapabilityGate` Protocol and `DevGate` class. `gate_factory.py` (PR-S3-2) selects `DevGate` vs `RealGate` at bootstrap based on `ALFRED_ENV`. After this PR: `capability.py` contains only the `CapabilityGate` Protocol and the two new methods (`check_plugin_load`, `check_content_clearance`) already on the Protocol from PR-S3-2. `DevGate` moves to `tests/` as a pure test helper, not a `src/` export. The import `from alfred.hooks import DevGate` becomes a test-only import; production code never touches `DevGate` again.

### Test migration shape

Every test that constructs `DevGate` for deny-path semantics gets one of three treatments:
- Tests that exercise the `check()` deny path stay in `tests/unit/hooks/` but construct `RealGate` with an empty Postgres backing store (all checks deny by default when no grants exist).
- Tests that exercise `allow_system=True` semantics construct `RealGate` with a fixture grant seeded into the Postgres store.
- Tests for `DevGate`'s own behaviour (`test_capability.py`) are deleted — the thing being tested no longer exists in `src/`.

---

## §3 File structure

| File | Action | Responsibility |
|---|---|---|
| `docs/subsystems/plugins.md` | Create | MCP plugin transport deep-doc: PluginTransport Protocol, StdioTransport, AlfredPluginSession, manifest schema, DLP placement, secret substitution, lifecycle audit, sandbox profile |
| `docs/subsystems/supervisor.md` | Create | Supervisor module deep-doc: circuit breaker, per-action deadline, capability-gate fail-closed integration, alfred supervisor CLI |
| `docs/subsystems/quarantine.md` | Create | Quarantine deep-doc: dual-LLM split, T3DerivedData, QuarantinedExtractor, ContentHandle, ExtractionResult, retry-guidance hygiene |
| `docs/glossary.md` | Modify | Add 16 new terms; update `capability gate` and `hook tier` entries |
| `docs/runbooks/slice-3-operator-migration.md` | Create | Slice 2 → Slice 3 upgrade order, current alfred status output (Slice-2 unchanged), expected errors, git init --bare state.git seed step |
| `.rulesync/rules/CLAUDE.md` | Modify | Add new Slice-3 CLI commands to command table (alfred plugin, alfred web allowlist, alfred config, alfred supervisor) |
| `CLAUDE.md` | Regenerate | Updated from rulesync after .rulesync/rules/CLAUDE.md edit |
| `src/alfred/hooks/capability.py` | Modify | Remove DevGate class; keep CapabilityGate Protocol only |
| `src/alfred/hooks/__init__.py` | Modify | Remove DevGate from __all__ and re-exports |
| `tests/unit/hooks/test_capability.py` | Modify | Remove DevGate-specific tests; add RealGate deny-path tests |
| `tests/unit/hooks/test_capability_sec007.py` | Modify | Update to reference capability.py without DevGate |
| `tests/unit/hooks/conftest.py` | Modify | Replace DevGate fixture construction with RealGate fixtures |
| `tests/unit/hooks/test_registry.py` | Modify | Replace DevGate in deny-path tests with RealGate |
| `tests/unit/hooks/test_decorators.py` | Modify | Replace DevGate references with RealGate |
| `tests/unit/hooks/test_security_contract.py` | Modify | Migrate deny-path assertions to RealGate |
| `tests/unit/memory/test_episodic_hooks_wiring.py` | Modify | Replace DevGate fixture with RealGate |
| `tests/helpers/gates.py` | Create | Test-only DevGate shim (pure test helper, no src/ import) |

---

## §4 Tasks

### Component A: Glossary additions

- [ ] **Task 1 — Glossary: add ContentHandle, QuarantinedExtractor, T3DerivedData**

  Files: Modify `docs/glossary.md`.

  Steps:

  1. Write failing docs-check: run `make docs-check` — note current baseline (should be green).
  2. Append to `docs/glossary.md`:

  ```markdown
  ## ContentHandle

  An opaque reference to T3 content held in the plugin host's content
  store (Redis, keyed by `ContentHandle.id`). The orchestrator holds a
  `ContentHandle` and never dereferences it to bytes — the type has no
  `.content` field by design. The quarantined-LLM plugin dereferences
  the handle by ID when `quarantine.extract()` is called.
  `ContentHandle` values are single-use UUIDs: the content store
  atomically deletes the entry on the first successful extract call,
  closing the concurrent-extract race.

  Defined in `src/alfred/plugins/content_store.py` (shipped PR-S3-5).
  See [PRD §7.1](../PRD.md#71-security--prompt-injection-defense),
  spec §7.3, and [docs/subsystems/quarantine.md](subsystems/quarantine.md).

  ## QuarantinedExtractor

  The orchestrator-side MCP client of the quarantined-LLM plugin
  (`src/alfred/plugins/quarantine_extractor.py`, shipped PR-S3-4). It
  calls `quarantine.extract()` via `StdioTransport.dispatch()` and
  deserialises the returned JSON into `ExtractionResult`. Raw provider
  response bytes never cross back to the orchestrator process untyped —
  the quarantined-LLM plugin sees the provider response; the orchestrator
  sees only the validated `ExtractionResult`.

  See [ADR-0017](adr/0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md),
  spec §6.4, and [docs/subsystems/quarantine.md](subsystems/quarantine.md).

  ## T3DerivedData

  `NewType("T3DerivedData", dict[str, object])` — the Slice-3
  type-level provenance discriminant on `Extracted.data`. It signals
  that the dictionary's values originated from a T3 source and must not
  be injected into privileged prompts without first calling
  `downgrade_to_orchestrator()`, which is gated on
  `CapabilityGate.check_content_clearance(hookpoint="t3.downgrade_to_orchestrator",
  content_tier="T3_derived")`. A ruff/grep CI rule rejects
  `cast(dict, ...)` applied to a `T3DerivedData` binding. Slice 4
  promotes this to a full type-parameter on `TaggedContent`.

  See spec §3.7 and [docs/subsystems/quarantine.md](subsystems/quarantine.md).
  ```

  3. Run `make docs-check` — must pass.
  4. Commit:
     ```
     git commit -m "docs(glossary): add ContentHandle, QuarantinedExtractor, T3DerivedData (#TBD-slice3)"
     ```

- [ ] **Task 2 — Glossary: add PluginTransport, StdioTransport, AlfredPluginSession**

  Files: Modify `docs/glossary.md`.

  Steps:

  1. Append to `docs/glossary.md`:

  ```markdown
  ## PluginTransport

  The structural `Protocol` every plugin transport implementation
  honours (`src/alfred/plugins/transport.py`, shipped PR-S3-3a). Slice 3
  ships `StdioTransport` as the sole implementation. HTTP transport is
  deferred to Slice 5+. In-process `MemoryTransport` is deliberately
  never shipped — it would collapse process-boundary isolation.

  The `dispatch(method, params)` return type is a discriminated union
  (`ContentHandle | ExtractionResult | ControlResult`); `TaggedContent[T3]`
  is plugin-host-internal and never exits `dispatch()` as a return value.

  See [ADR-0017](adr/0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md),
  spec §4.1, and [docs/subsystems/plugins.md](subsystems/plugins.md).

  ## StdioTransport

  The Slice-3 sole implementation of `PluginTransport`
  (`src/alfred/plugins/stdio_transport.py`). Wraps the
  `model_context_protocol` SDK's `ClientSession`. Every outbound
  JSON-RPC frame passes through `OutboundDlp.scan` before reaching the
  subprocess stdin; every inbound frame is tagged `TaggedContent[T3]`
  internally via the capability-gated `tag(T3, ...)` factory, stored in
  the content store, and returned as a `ContentHandle`. DLP wraps the
  full transport surface — callers receive the post-DLP result.

  See spec §4.2 and [docs/subsystems/plugins.md](subsystems/plugins.md).

  ## AlfredPluginSession

  The orchestrator-side class that owns the subprocess lifecycle,
  manifest handshake, version check, and capability-gate consult for a
  single plugin (`src/alfred/plugins/session.py`, shipped PR-S3-3a).
  It wraps `ClientSession` with the Slice-3 handshake protocol: manifest
  parse → `alfred.manifest_version` check (N+1 refused) → capability-gate
  consult via `check_plugin_load()` → hook registration from manifest
  `[[hooks]]` entries. Post-handshake `alfred/hooks.register` RPC calls
  are rejected with SIGKILL and `plugin.lifecycle.quarantined` audit row.

  See spec §4.2, §4.6, and [docs/subsystems/plugins.md](subsystems/plugins.md).
  ```

  2. Run `make docs-check` — must pass.
  3. Commit:
     ```
     git commit -m "docs(glossary): add PluginTransport, StdioTransport, AlfredPluginSession (#TBD-slice3)"
     ```

- [ ] **Task 3 — Glossary: add sandbox profile, RealGate, ExtractionResult, TypedRefusal**

  Files: Modify `docs/glossary.md`.

  Steps:

  1. Append to `docs/glossary.md`:

  ```markdown
  ## Sandbox profile

  The per-plugin OS-level sandbox configuration declared in the plugin
  manifest (`sandbox_profile` field, e.g. `"user-plugin"`). Declared
  independently of `subscriber_tier` — the quarantined-LLM plugin has
  `subscriber_tier=system` (it processes T3 content on behalf of the
  system) but runs in the `user-plugin`-class sandbox profile (no
  `ALFRED_*` env vars, fs writes restricted to
  `$XDG_RUNTIME_DIR/alfred/plugin-<id>/`, network allowlist only).
  Per-OS sandbox policy files (Linux `bwrap`, macOS `sandbox-exec`) ship
  in Slice 4 alongside ADR-0015. In Slice 3, `bin/alfred-plugin-launcher`
  fails closed when no policy file is present; `ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED=1`
  unlocks Slice-3 subprocess plugins in `ALFRED_ENV=development` only.

  See spec §4.3, §4.8, and [docs/subsystems/plugins.md](subsystems/plugins.md).

  ## RealGate

  The production `CapabilityGate` implementation backed by state.git
  (source of truth) + Postgres (runtime projection cache). Constructed
  at bootstrap when `ALFRED_ENV != development` by
  `src/alfred/bootstrap/gate_factory.py` (shipped PR-S3-2). When
  Postgres is unavailable, `RealGate` fails closed for all dispatches —
  `check()`, `check_plugin_load()`, and `check_content_clearance()` all
  return `False`. The fail-closed window for in-process subscribers is
  bounded at 60 seconds.

  **Not to be confused with `DevGate`**, which was the development-only
  default removed at the end of Slice 3 (this PR). After PR-S3-7, no
  `DevGate` exists in `src/` — test suites that previously used it
  construct `RealGate` with fixture grant seeds.

  See spec §8.4, [ADR-0017](adr/0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md),
  and [docs/subsystems/plugins.md](subsystems/plugins.md).

  ## ExtractionResult

  The discriminated-union return type of `QuarantinedExtractor.extract()`:

  ```python
  ExtractionResult = Annotated[Extracted | TypedRefusal, Field(discriminator="kind")]
  ```

  `Extracted` carries `data: T3DerivedData` and `extraction_mode`.
  `TypedRefusal` carries `reason: Literal["cannot_extract",
  "refused_by_safety", "ambiguous_input"]`. `kind="malformed_output"` is
  never returned — exhausted retries become `TypedRefusal(reason=
  "cannot_extract")`. The orchestrator pattern-matches on `kind` to
  decide how to render the user response.

  See spec §6.7 and [docs/subsystems/quarantine.md](subsystems/quarantine.md).

  ## TypedRefusal

  The `ExtractionResult` variant that signals the quarantined LLM could
  not extract structured data. `reason` distinguishes three cases:
  `cannot_extract` (retries exhausted or content expired),
  `refused_by_safety` (quarantined provider refused the content on safety
  grounds), `ambiguous_input` (content was valid but semantically
  ambiguous for the requested schema). The orchestrator translates each
  to a user-facing `t()` message; none surfaces raw extraction state.

  See spec §6.7 and [docs/subsystems/quarantine.md](subsystems/quarantine.md).
  ```

  2. Run `make docs-check` — must pass.
  3. Commit:
     ```
     git commit -m "docs(glossary): add sandbox profile, RealGate, ExtractionResult, TypedRefusal (#TBD-slice3)"
     ```

- [ ] **Task 4 — Glossary: add JSON_OBJECT_MODE, ProviderCapability, WebFetchError, WebFetchCanaryTripped, QuarantinedUnavailable**

  Files: Modify `docs/glossary.md`.

  Steps:

  1. Append to `docs/glossary.md`:

  ```markdown
  ## JSON_OBJECT_MODE

  A `ProviderCapability` enum value indicating the provider supports
  `response_format={"type": "json_object"}` but does NOT enforce a
  schema. DeepSeek-chat is the Slice-3 `JSON_OBJECT_MODE` provider;
  `QuarantinedExtractor` routes it through the same retry-and-validate
  path as `prompt_embedded_fallback`. The extraction mode is recorded in
  the audit row as `extraction_mode="json_object_unconstrained"` to
  distinguish best-effort validation (DeepSeek) from true schema
  enforcement (Anthropic, OpenAI).

  See spec §6.2 and [docs/subsystems/quarantine.md](subsystems/quarantine.md).

  ## ProviderCapability

  A closed-set `StrEnum` (`src/alfred/providers/base.py`) declaring what
  structured-generation mechanisms a provider supports. Slice-3 values:
  `NATIVE_CONSTRAINED_GENERATION` (schema-enforced; Anthropic tool-use
  shape, OpenAI strict structured-outputs), `JSON_OBJECT_MODE` (valid
  JSON but no schema enforcement; DeepSeek-chat), `TOOL_USE`, `VISION`,
  `LONG_CONTEXT_1M` (pre-declared per PRD §6.6, no Slice-3 consumers).
  `QuarantinedExtractor` dispatches based on `Provider.capabilities()`.

  See spec §6.1 and [docs/subsystems/quarantine.md](subsystems/quarantine.md).

  ## WebFetchError

  The exception hierarchy for `web.fetch` failures
  (`src/alfred/plugins/web_fetch/errors.py`, shipped PR-S3-5). Subclasses:
  `WebFetchDomainNotAllowed`, `WebFetchTlsError`, `WebFetchRateLimited`,
  `WebFetchMimeTypeNotAllowed`, `WebFetchSizeLimitExceeded`. All error
  strings route through `t()`. `WebFetchCanaryTripped` is NOT a subclass
  of `WebFetchError` — it is a separate security-event hierarchy.

  See spec §7.10 and [docs/subsystems/plugins.md](subsystems/plugins.md).

  ## WebFetchCanaryTripped

  A distinct `AlfredError` subclass (NOT a `WebFetchError` subclass) that
  signals a canary token was detected in fetched T3 content. This is a
  SECURITY EVENT: it emits a `tool.web.fetch.canary_tripped` audit row,
  quarantines the content handle, and raises with
  `t("security.canary_tripped", url=source_url)`. There is no silent
  degradation path; the user receives an error and the operator sees the
  audit event (CLAUDE.md hard rule #7).

  See spec §7.6, §7.10, and [docs/subsystems/plugins.md](subsystems/plugins.md).

  ## QuarantinedUnavailable

  The exception the orchestrator catches when the quarantined-LLM plugin
  is unavailable (`src/alfred/plugins/errors.py`, shipped PR-S3-3b). A
  distinct top-level exception, NOT a subclass of `HookSubscriberError`.
  The orchestrator responds with `t("orchestrator.quarantine_unavailable")`
  — "I can't process external content right now; please retry in a few
  minutes." There is no silent T3-self-processing fallback; the
  user-visible message is a hard invariant (CLAUDE.md hard rule #7).
  The circuit breaker in `src/alfred/supervisor/` emits this when the
  quarantined LLM's breaker state is `OPEN`.

  See spec §5.5, §10.2, and [docs/subsystems/supervisor.md](subsystems/supervisor.md).
  ```

  2. Run `make docs-check` — must pass.
  3. Commit:
     ```
     git commit -m "docs(glossary): add JSON_OBJECT_MODE, ProviderCapability, WebFetchError, WebFetchCanaryTripped, QuarantinedUnavailable (#TBD-slice3)"
     ```

- [ ] **Task 5 — Glossary: add CommsAdapterMCP, quarantined_to_structured, AnyTaggedContent; update capability gate and hook tier**

  Files: Modify `docs/glossary.md`.

  Steps:

  1. Append new terms to `docs/glossary.md`:

  ```markdown
  ## CommsAdapterMCP

  The MCP-shaped `Protocol` for comms adapters, defined in
  `src/alfred/comms/mcp_protocol.py` (shipped PR-S3-6). Distinct from
  the in-process `CommsAdapter` Protocol (which remains for
  `DiscordAdapter`/`TuiAdapter` through Slice 3). The Slice-3 stub
  validates transport and handshake only — four wire methods:
  `lifecycle.start`, `lifecycle.stop`, `inbound.message`,
  `adapter.health`. The full message-contract definition is co-defined
  in ADR-0016 when Slice 4 implements the Discord rewrite.

  See spec §9.1, [ADR-0009](adr/0009-comms-adapter-protocol-slice2-only.md),
  and [docs/subsystems/comms.md](subsystems/comms.md).

  ## quarantined_to_structured

  The single legitimate crossing point where T3-derived data enters
  orchestrator-readable form (`src/alfred/security/quarantine.py`,
  shipped PR-S3-4). Any other path that claims to convert T3 content is
  a security violation detectable by grepping for callers outside the
  `QuarantinedExtractor`. The caller must hold
  `check_content_clearance(hookpoint="quarantine.dereference",
  content_tier="T3")` — distinct from the `tag.T3` clearance (which is
  plugin-host-internal). Raw provider response bytes never cross back to
  the orchestrator process untyped.

  See spec §3.4 and [docs/subsystems/quarantine.md](subsystems/quarantine.md).

  ## AnyTaggedContent

  A `Protocol` providing a read-only view of any `TaggedContent`
  regardless of tier parameter (`src/alfred/security/tiers.py`, shipped
  PR-S3-1). Observer code — audit writers, logging, DLP scanners — takes
  `AnyTaggedContent` instead of the parameterised `TaggedContent[T]` to
  avoid `cast()` proliferation. A ruff/grep CI rule rejects
  `cast(TaggedContent[` and `# type: ignore` on `TaggedContent` in
  non-test `src/` files.

  See spec §3.3 and [trust tier](#trust-tier).
  ```

  2. Find and update the existing `## Capability gate` entry in `docs/glossary.md` to add the two new methods:

  Find text: `Slice 3 lands the full surface alongside the MCP plugin transport; Slice 2 ships only the data-model placeholders.`

  Replace with:

  ```markdown
  Slice 3 lands the full surface alongside the MCP plugin transport. The
  Protocol gains two sibling methods alongside `check()` (all shipped by
  PR-S3-2):

  - `check_plugin_load(*, plugin_id, manifest_tier) -> bool` — gates
    plugin load at handshake time; called by `AlfredPluginSession` before
    any capability grants are consulted.
  - `check_content_clearance(*, plugin_id, hookpoint, content_tier) -> bool`
    — gates content-tier access: T3 content must not reach T2-only paths.
    Orthogonal to subscriber hook tier (system/operator/user-plugin) — a
    system-tier plugin can process T3 content; these two axes are
    independent.

  When Postgres is unavailable, all three methods return `False`
  (fail-closed). The 60-second heartbeat window bounds staleness before
  in-process subscribers also see fail-closed. `DevGate` (removed at end
  of Slice 3 in PR-S3-7) implemented both new methods as fail-open
  (`True`) for backward compatibility during the slice.

  See spec §8.2, [ADR-0017](adr/0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md),
  and [docs/subsystems/plugins.md](subsystems/plugins.md).
  ```

  3. Find and update the existing `## Hook tier` entry's closing paragraph to add orthogonality language. Append after the `See spec §6.1` line:

  ```markdown
  **Orthogonality with content trust tier:** A `system`-tier plugin
  (subscriber tier) can process T3 content (content trust tier) — these
  two axes are independent. Using `subscriber_tier="T3"` in a plugin
  manifest is a security error refused at handshake with
  `plugin.load_refused` (T3 is not a valid subscriber tier; the valid
  values are `system`, `operator`, `user-plugin`).

  See [trust tier](#trust-tier) for the content-provenance axis.
  ```

  4. Update the existing `## Trust tier` entry to add two new bullets for the Slice-3 `TaggedContent` type parameters (*docs-008*):

  Find the closing sentence of the `## Trust tier` entry (the one ending with the `See` cross-references) and append:

  ```markdown
  Slice 3 introduces first-class `TaggedContent[T1]` and `TaggedContent[T3]`
  type parameters:

  - **`TaggedContent[T1]`** — authenticated-user-trusted content.
    `T1` values are emitted by `IdentityResolver` when a verified
    platform identity is confirmed. The type enforces that T1 content
    came from an authenticated source; `IdentityResolver` is the only
    authorised producer (spec §3.1).
  - **`TaggedContent[T3]`** — external-untrusted content. `T3` values
    are produced only via the capability-gated `tag(T3, ...)` factory at
    the `StdioTransport` boundary and in `plugins/quarantine_host.py`.
    Any other call site raises `ValueError` (spec §3.2).

  See [docs/subsystems/plugins.md](subsystems/plugins.md#t3-tagging-boundary)
  for the authorised `T3` production sites and spec §3.1 for the full
  tier table.
  ```

  5. Run `make docs-check` — must pass.
  6. Commit:
     ```
     git commit -m "docs(glossary): add CommsAdapterMCP, quarantined_to_structured, AnyTaggedContent; update capability gate, hook tier, trust tier T1/T3 (#TBD-slice3)"
     ```

- [ ] **Task 5a — Glossary: add provenance and Supervisor (spec §18 required entries)**

  Files: Modify `docs/glossary.md`.

  These two entries are explicitly enumerated in spec §18 as required but were absent from Tasks 1–5. *docs-002*

  Steps:

  1. Append to `docs/glossary.md`:

  ```markdown
  ## Provenance

  The lineage metadata that survives `quarantined_to_structured` and
  identifies the content-trust origin of a value. In Slice 3, provenance
  is expressed as the `T3DerivedData` NewType: a value carrying
  `T3DerivedData` originated from T3 (external, untrusted) content and
  must pass through `downgrade_to_orchestrator()` before reaching
  privileged prompts. Slice 4 promotes provenance to a full
  type-parameter axis on `TaggedContent[T, Provenance]`.

  See spec §3.7 and [docs/subsystems/quarantine.md](subsystems/quarantine.md).
  Distinct from [trust tier](#trust-tier) (which describes the source
  of data at ingestion time) — provenance follows the data through
  transformation steps.

  ## Supervisor

  The module (`src/alfred/supervisor/`) that owns plugin lifecycle
  (crash detection + exponential-backoff restart + circuit breaker) and
  orchestrator-action deadline enforcement (30-second `asyncio.timeout`
  per turn). The `Supervisor` class opens an `asyncio.TaskGroup` at
  `start()`; `stop()` cancels all reader tasks with SIGTERM + 5-second
  grace before SIGKILL. The circuit breaker state machine
  (`CLOSED → OPEN → HALF_OPEN → CLOSED`) is persisted to the
  `circuit_breakers` Postgres table (migration `0010`).

  See [docs/subsystems/supervisor.md](subsystems/supervisor.md),
  spec §10, and [QuarantinedUnavailable](#quarantinedunavailable).
  ```

  2. Run `make docs-check` — must pass.
  3. Commit:
     ```
     git commit -m "docs(glossary): add provenance and Supervisor — spec §18 required entries (#TBD-slice3)"
     ```

---

### Component B: Subsystem deep-docs

- [ ] **Task 6 — Write docs/subsystems/plugins.md**

  Files: Create `docs/subsystems/plugins.md`.

  Steps:

  1. Write the file:

  ```markdown
  # Plugins subsystem — MCP stdio plugin transport

  **Status:** shipped in Slice 3
  **Owner:** [alfred-core-engineer](../../.rulesync/subagents/alfred-core-engineer.md)
  **Code:** `src/alfred/plugins/`
  **PRD:** [§6.3 Agentic Skills & MCP Integration](../../PRD.md#63-agentic-skills--mcp-integration)
  **ADRs:** [ADR-0017](../adr/0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md),
  [ADR-0015](../adr/0015-slice4-containerised-quarantined-llm.md) (Slice-4 commitment),
  [ADR-0014](../adr/0014-pluggable-hooks-for-every-action.md)

  ## Purpose

  The plugins subsystem owns the process boundary between the privileged
  orchestrator and every MCP subprocess plugin. It answers: "how does
  AlfredOS talk to a plugin without leaking secrets, without letting T3
  content reach the orchestrator untyped, and without letting a
  compromised plugin escalate its capabilities after it was loaded?"
  The answer has three structural pieces: a `PluginTransport` Protocol
  whose sole Slice-3 implementation is `StdioTransport` (process
  isolation by OS UID separation + env scrubbing); a host-side secret
  broker substitution that ensures no `{{secret:*}}` reference ever
  reaches the subprocess; and an `AlfredPluginSession` handshake that
  validates manifest version, checks capabilities, and locks hook
  registrations at handshake time so a compromised plugin cannot
  post-grant escalate.

  The subsystem is the direct realisation of PRD §5's "plugins are MCP
  servers" invariant (lines 116-121). Slice 3 ships stdio transport
  and UID isolation as the first concrete implementation of that
  invariant. Full containerisation (Linux `bwrap`, macOS `sandbox-exec`)
  is committed for Slice 4 in ADR-0015.

  ## Public surface

  - `PluginTransport` — `src/alfred/plugins/transport.py` — structural
    Protocol every transport honours. `dispatch(method, params) ->
    ContentHandle | ExtractionResult | ControlResult`.
  - `StdioTransport` — `src/alfred/plugins/stdio_transport.py` — sole
    Slice-3 implementation. Wraps `model_context_protocol.ClientSession`.
    DLP wraps the full dispatch surface: `OutboundDlp.scan` on outbound
    frames; `InboundContentScanner.scan` on inbound frames before
    `TaggedContent[T3]` tagging.
  - `AlfredPluginSession` — `src/alfred/plugins/session.py` — owns the
    subprocess lifecycle, manifest handshake, version check, and
    `check_plugin_load()` consult. Post-handshake `alfred/hooks.register`
    is SIGKILL + `plugin.lifecycle.quarantined` audit row.
  - `ContentHandle` — `src/alfred/plugins/content_store.py` — opaque id
    for T3 bytes in Redis. The orchestrator holds this; it has no
    `.content` field. Single-use: the content store atomically deletes on
    first successful extract.
  - `ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED` — `bin/alfred-plugin-launcher`
    — accepted only when `ALFRED_ENV=development`. Every plugin start in
    unsandboxed mode emits `supervisor.config_insecure` audit row.

  ## Internal model

  ### Manifest schema

  Every plugin presents a TOML manifest declaring
  `alfred.manifest_version = 1` (integer; N+1 refused at handshake),
  `plugin.id`, `plugin.subscriber_tier` (one of `system` / `operator` /
  `user-plugin` — the [hook tier](../glossary.md#hook-tier), not the
  [content trust tier](../glossary.md#trust-tier)), `plugin.sandbox_profile`,
  and `[[hooks]]` entries. The `transport` and `provenance` fields are
  reserved for Slice 5+ (HTTP transport). The `platform` field is
  reserved (optional in version 1) to avoid a manifest_version bump when
  Slice 4 ships the comms-MCP adapter.

  ### DLP placement on every Slice-3 wire

  | Wire | Direction | Scanner | Disposition on fail |
  |---|---|---|---|
  | `StdioTransport` → subprocess stdin | Outbound | `OutboundDlp.scan(frame)` | Refuse dispatch; `security.dlp_outbound_refused` audit row |
  | subprocess stdout → `StdioTransport` | Inbound | `InboundContentScanner.scan(frame)` | SECURITY EVENT on canary trip; `security.canary_tripped` audit row |
  | `web.fetch` outbound request | Outbound | `OutboundDlp.scan_fields({"url": url, "headers": headers})` | Refuse request |
  | `web.fetch` inbound response body | Inbound | `InboundContentScanner.scan(body)` | SECURITY EVENT on canary trip |
  | `security.quarantined.extract` → orchestrator | Outbound from quarantine | `OutboundDlp.scan(model_dump_result)` | Refuse; `security.canary_tripped` |

  Cookies flow through secret broker substitution (§7.8 of the spec) and
  do not appear in DLP wire scans.

  ### Secret broker substitution

  Before any outbound JSON-RPC frame crosses the pipe,
  `AlfredPluginSession` scans `params` for `{{secret:*}}` references and
  substitutes them via `SecretBroker.get()`. No `{{secret:*}}` reference
  reaches the subprocess (CLAUDE.md hard rule #6).

  ### Provider key delivery (fd 3)

  The quarantined-LLM plugin receives its provider API key via a
  dedicated pipe on fd 3 (not stdin), framed as 4-byte big-endian length
  + N bytes. This prevents key fragments from appearing in a
  structlog-logged "malformed handshake" event if the MCP reader
  misparsed a trailing newline on fd 0.

  ### T3 tagging boundary

  Inbound bytes from `StdioTransport` follow this sequence: raw bytes →
  `InboundContentScanner.scan` → `tag(T3, ...)` via the capability-gated
  factory → write to content store → return `ContentHandle` to
  orchestrator. `TaggedContent[T3]` is plugin-host-internal; it never
  exits `dispatch()` as the return value.

  ## Failure modes

  | Trigger | Behaviour | Observable signal |
  |---|---|---|
  | `alfred.manifest_version != 1` | `AlfredPluginSession` refuses; subprocess not started | `plugin.lifecycle.load_refused` audit row |
  | `check_plugin_load()` returns False | Supervisor marks plugin `REFUSED`; final until re-granted | `plugin.lifecycle.load_refused` audit row |
  | Outbound DLP scan fails | Dispatch refused; no bytes cross the pipe | `security.dlp_outbound_refused` audit row |
  | Inbound canary trip | `WebFetchCanaryTripped` raised; content handle quarantined | `tool.web.fetch.canary_tripped` audit row; `security.canary_tripped` audit row |
  | Post-handshake `alfred/hooks.register` RPC | SIGKILL + no grant | `plugin.lifecycle.quarantined` audit row |
  | Subprocess exits unexpectedly | Supervisor catches; exponential backoff restart | `plugin.lifecycle.crashed` audit row |
  | Manifest `allowed_domains` wider than operator config | Effective allowlist capped; not silent | `web.allowlist.manifest_broadening_capped` audit row per manifest load |
  | `ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED=1` in `ALFRED_ENV=production` | Startup error; refused | `supervisor.config_insecure` audit row |

  ## Trust-boundary contract

  The plugins subsystem is the entry boundary for all [T3](../glossary.md#trust-tier)
  content. Raw T3 bytes live in the content store (Redis) keyed by
  `ContentHandle.id`. The orchestrator holds only the opaque handle —
  the type enforces this (`ContentHandle` has no `.content` field). The
  `tag(T3, ...)` factory is capability-gated; the two authorized call
  sites are `StdioTransport` (inbound payloads) and
  `plugins/quarantine_host.py` (quarantined-LLM host). Any other call
  raises `ValueError` + emits `security.t3_boundary.refused` audit row.

  See [docs/subsystems/quarantine.md](quarantine.md) for the
  `quarantined_to_structured` crossing point where T3-derived data
  enters orchestrator-readable form.

  ## Performance characteristics

  | Path | p99 budget |
  |---|---|
  | `StdioTransport.dispatch()` empty-payload round-trip | < 5ms |
  | `OutboundDlp.scan` 1 KB frame | < 200µs |
  | `InboundContentScanner.scan` 1 MB body | < 50ms (runs in `asyncio.to_thread()`) |
  | Subprocess spawn cold-start | < 500ms |
  | `tool.web.fetch` 5-subscriber chain | ≤ 100µs + transport hop ≤ 5ms |

  `InboundContentScanner.scan` runs in `asyncio.to_thread()` to avoid
  blocking the event loop on regex-heavy 5 MB bodies (spec §7a.1).

  ## Slice graduation map

  | Subsystem | Slice 3 (shipped) | Deferred to |
  |---|---|---|
  | plugins | `StdioTransport`; `AlfredPluginSession`; manifest v1; DLP on both wires; UID separation; `bin/alfred-plugin-launcher` stub; `web.fetch` plugin; `alfred-comms-test` reference plugin | Slice 4+: HTTP transport; OS sandbox policy files (`bwrap`, `sandbox-exec`); containerised quarantined LLM (ADR-0015); Discord+TUI comms-MCP rewrite (ADR-0016) |

  ## Cross-references

  - PRD [§6.3](../../PRD.md#63-agentic-skills--mcp-integration) — MCP plugin contract + capability manifest.
  - PRD [§7.1](../../PRD.md#71-security--prompt-injection-defense) — trust tiers, dual-LLM, secret broker, canary tokens.
  - [ADR-0017](../adr/0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md) — load-bearing Slice-3 ADR.
  - [ADR-0015](../adr/0015-slice4-containerised-quarantined-llm.md) — Slice-4 containerisation commitment.
  - Sibling docs: [supervisor.md](supervisor.md), [quarantine.md](quarantine.md), [hooks.md](hooks.md).
  - Runbook: [docs/runbooks/slice-3-operator-migration.md](../runbooks/slice-3-operator-migration.md).
  - Glossary: [ContentHandle](../glossary.md#contenthandle), [PluginTransport](../glossary.md#plugintransport), [StdioTransport](../glossary.md#stdiotransport), [AlfredPluginSession](../glossary.md#alfredpluginsession), [sandbox profile](../glossary.md#sandbox-profile), [trust tier](../glossary.md#trust-tier), [hook tier](../glossary.md#hook-tier), [capability gate](../glossary.md#capability-gate).
  ```

  2. Run `make docs-check` — must pass.
  3. Commit:
     ```
     git commit -m "docs(subsystems): add plugins.md — MCP stdio transport deep-doc (#TBD-slice3)"
     ```

- [ ] **Task 7 — Write docs/subsystems/supervisor.md**

  Files: Create `docs/subsystems/supervisor.md`.

  Steps:

  1. Write the file:

  ```markdown
  # Supervisor subsystem — plugin lifecycle + circuit breaker + per-action deadline

  **Status:** shipped in Slice 3
  **Owner:** [alfred-core-engineer](../../.rulesync/subagents/alfred-core-engineer.md)
  **Code:** `src/alfred/supervisor/`
  **PRD:** [§6.7 Deployment & Setup (Self-healing)](../../PRD.md#67-deployment--setup) · [§7.3 Self-Healing & Auto-Recovery](../../PRD.md#73-self-healing--auto-recovery)
  **ADRs:** [ADR-0017](../adr/0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md)

  ## Purpose

  The supervisor is the reliability backbone for AlfredOS's subprocess
  plugins. It answers: "what happens when the quarantined LLM crashes,
  when a plugin misbehaves, when the capability backing store goes
  offline, or when a user action takes too long?" Without the supervisor,
  any of those events silently degrades the system — the orchestrator
  either hangs indefinitely or self-treats T3 content (violating ADR-0013
  and CLAUDE.md hard rule #5). The supervisor makes all four failure modes
  loud, bounded, and operator-observable.

  The supervisor lives in `src/alfred/supervisor/` (shipped PR-S3-3b). It
  owns two distinct concerns that share one `Supervisor` class: plugin
  lifecycle (crash detection + exponential-backoff restart + circuit
  breaker) and orchestrator-action deadline enforcement (a 30-second
  `asyncio.timeout` wrapping every `handle_user_message` turn).

  ## Public surface

  - `Supervisor` — `src/alfred/supervisor/core.py` — root class opened
    as an `asyncio.TaskGroup`. `start()` opens the group; `stop()` cancels
    and SIGTERMs all reader tasks with a 5-second grace before SIGKILL.
  - `CircuitBreaker` — `src/alfred/supervisor/breaker.py` — state machine
    (`CLOSED` / `OPEN` / `HALF_OPEN`) persisted to the `circuit_breakers`
    Postgres table. `CLOSED` → (3 failures in 300s) → `OPEN` → (1h or
    operator reset) → `HALF_OPEN` → (probe succeeds) → `CLOSED`.
  - `alfred supervisor status` — CLI command; read-only; shows all
    registered components and their breaker states. Operator discovery
    path: `quarantine_unavailable` error → `alfred supervisor status` →
    `alfred supervisor reset quarantined-llm --confirm`.
  - `alfred supervisor reset <component> --confirm` — operator-tier T1
    command; transitions a named breaker from `OPEN` to `CLOSED`; emits
    `supervisor.breaker.reset` audit row with `operator_user_id`.
    Requires `--confirm` flag (or interactive TTY prompt).
  - `ALFRED_ENV` — read by `src/alfred/bootstrap/gate_factory.py` (not
    by `supervisor/` directly) to select `RealGate` vs development gate.

  ## Internal model

  ### Circuit breaker state machine

  ```
  CLOSED  ──(3 failures in 300s)──►  OPEN
    ▲                                  │
    │                                  │ 1h elapsed OR
    │                                  │ operator reset
    │                                  ▼
  CLOSED  ◄──(probe succeeds)──  HALF_OPEN
  ```

  State + `last_trip_at` + `trip_count` are persisted to Postgres
  (`circuit_breakers` table, migration `0010`). On process restart, if
  `last_trip_at` was >1h ago, the breaker re-arms to `CLOSED`. This
  prevents flap on rolling restarts — a quarantined LLM that tripped
  30 minutes ago does not auto-clear on process restart (spec §10.6).

  `HALF_OPEN` restart uses exponential backoff: initial 5s, multiplier
  2, max 5 minutes (spec §10.2).

  ### Per-action deadline

  `asyncio.timeout(30.0)` wraps inside `session_scope` — the DB
  transaction context at `src/alfred/orchestrator/core.py:255-283`. When
  the deadline fires, the rollback arm sees `CancelledError` and audits
  `phase="turn_cancelled"` per the existing path. The
  `supervisor.action_timeout` audit row is in addition to the existing
  `orchestrator.turn result="cancelled"` row — the pair distinguishes
  deadline-exceeded from user-cancel. The `QuarantinedUnavailable` catch
  also lives at this try/except level so the user-facing message reaches
  the user rather than a raw exception.

  The deadline is configurable: `orchestrator.action_deadline_seconds` in
  `config/policies.yaml` (default 30; low-blast hot-reload).

  ### `asyncio.TaskGroup` subprocess lifecycle

  `Supervisor.start()` opens an `asyncio.TaskGroup`. Each plugin's stdio
  reader task joins that group. On supervisor shutdown, cancelling the
  group cascade-cancels all reader tasks (SIGTERM + 5s grace + SIGKILL).
  This follows CLAUDE.md structured-concurrency requirement and prevents
  task leaks when multiple plugin subprocesses run concurrently
  (spec §10.5).

  ### Capability-gate fail-closed integration

  When Postgres is unavailable, `RealGate` fails closed for ALL
  dispatches (spec §8.1). The supervisor emits one
  `supervisor.capability_gate_unavailable` row per outage
  state-transition (entering + exiting fail-closed = two rows per outage
  event). Per-dispatch denied rows use the family
  `plugin.grant.denied_backing_store_unavailable`, rate-limited to
  1/sec/plugin_id in the audit writer; cumulative denied-dispatch counts
  roll into the next state-transition row so operators see them without
  log flooding.

  ## Failure modes

  | Trigger | Behaviour | Observable signal |
  |---|---|---|
  | Quarantined LLM subprocess crash | Supervisor catches; exponential-backoff restart | `plugin.lifecycle.crashed` audit row |
  | 3 crashes in 300s | Breaker transitions `CLOSED → OPEN` | `supervisor.breaker.tripped` audit row; `QuarantinedUnavailable` raised on next invocation |
  | Breaker `OPEN` | `QuarantinedUnavailable` raised immediately (no subprocess attempt) | `t("orchestrator.quarantine_unavailable")` user message |
  | `HALF_OPEN` probe fails | Back to `OPEN` | `plugin.lifecycle.crashed` audit row; `supervisor.breaker.tripped` audit row |
  | Postgres / state.git unavailable | `RealGate` fail-closed for all dispatches; 60s window before in-process subscribers also denied | `supervisor.capability_gate_unavailable` audit row |
  | `orchestrator.action_deadline_seconds` exceeded | `asyncio.timeout` fires; turn cancelled | `supervisor.action_timeout` audit row + `orchestrator.turn result="cancelled"` audit row |
  | `ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED=1` in production | Startup error | `supervisor.config_insecure` audit row at every plugin start |

  ## Trust-boundary contract

  The supervisor enforces capability-gate fail-closed behaviour — when
  the backing store is unavailable, no new plugin dispatches succeed,
  preserving the invariant that plugin access requires an active grant.
  The per-action deadline prevents a slow-responding quarantined LLM
  from silently hanging the orchestrator turn.

  See [docs/subsystems/plugins.md](plugins.md) for the plugin transport
  boundary and [docs/glossary.md](../glossary.md#capability-gate) for the
  capability gate Protocol.

  ## Performance characteristics

  | Path | Budget |
  |---|---|
  | Circuit breaker state check (Postgres) | p99 < 5ms |
  | `alfred supervisor status` CLI | < 1s (single Postgres query) |
  | `asyncio.timeout` deadline | 30s default; configurable |
  | Subprocess spawn cold-start (HALF_OPEN probe) | < 500ms |

  The `alfred_orchestrator_action_duration_seconds` Prometheus histogram
  records every action outcome (success, timeout, cancelled), not only
  timeouts. Per-phase OTel sub-spans (`tool.web.fetch`,
  `security.quarantined.extract`, `hookchain_total`) let operators see
  the 30s budget consumed asymmetrically and tune the deadline against
  observed p99 (spec §7a.3).

  ## Slice graduation map

  | Subsystem | Slice 3 (shipped) | Deferred to |
  |---|---|---|
  | supervisor | `CircuitBreaker` (3/5min spec); per-action 30s deadline; `asyncio.TaskGroup` subprocess lifecycle; `alfred supervisor status/reset`; `capability_gate_unavailable` fail-closed rows | Slice 4+: multi-supervisor coordination for replicated deployments; per-plugin configurable breaker thresholds |

  ## Cross-references

  - PRD [§6.7](../../PRD.md#67-deployment--setup) — circuit breaker 3/5min spec (line 324).
  - PRD [§7.3](../../PRD.md#73-self-healing--auto-recovery) — supervisor plugin lifecycle.
  - [ADR-0017](../adr/0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md) — Slice-3 ADR.
  - Sibling docs: [plugins.md](plugins.md), [quarantine.md](quarantine.md), [hooks.md](hooks.md).
  - Runbook: [docs/runbooks/slice-3-operator-migration.md](../runbooks/slice-3-operator-migration.md).
  - Glossary: [QuarantinedUnavailable](../glossary.md#quarantinedunavailable), [capability gate](../glossary.md#capability-gate), [RealGate](../glossary.md#realgate), [audit log](../glossary.md#audit-log).
  ```

  2. Run `make docs-check` — must pass.
  3. Commit:
     ```
     git commit -m "docs(subsystems): add supervisor.md — circuit breaker + deadline deep-doc (#TBD-slice3)"
     ```

- [ ] **Task 8 — Write docs/subsystems/quarantine.md**

  Files: Create `docs/subsystems/quarantine.md`.

  Steps:

  1. Write the file:

  ```markdown
  # Quarantine subsystem — dual-LLM split and T3 structured extraction

  **Status:** shipped in Slice 3
  **Owner:** [alfred-security-engineer](../../.rulesync/subagents/alfred-security-engineer.md)
  **Code:** `src/alfred/security/quarantine.py` · `src/alfred/plugins/quarantine_extractor.py` · `plugins/alfred_quarantined_llm/`
  **PRD:** [§7.1 Security & Prompt-Injection Defense](../../PRD.md#71-security--prompt-injection-defense) · [§6.4 Self-Improvement with Reviewer Gate](../../PRD.md#64-self-improvement-with-reviewer-gate)
  **ADRs:** [ADR-0017](../adr/0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md) (supersedes [ADR-0013](../adr/0013-defer-t1-t3-and-dual-llm.md))

  ## Purpose

  The quarantine subsystem enforces the dual-LLM split: the privileged
  orchestrator never processes raw T3 content, and the quarantined LLM
  never emits free-form text the orchestrator interprets as instructions.
  These two invariants together close the prompt-injection attack
  surface: an adversary who plants instructions in a web page the system
  fetches reaches only the quarantined LLM, which can only emit a
  validated Pydantic model.

  The subsystem is the concrete realisation of ADR-0013's deferred
  commitment (Slice 2 tracked the gap; Slice 3 closes it). The
  architectural shape — a separate process under a dedicated UID with
  env-scrubbing and a content-store boundary — makes the isolation
  enforcement structural rather than policy-only.

  `src/alfred/security/quarantine.py` is the single grep anchor for all
  T3-to-orchestrator handoffs. Placing the boundary here (not in
  `providers/`) keeps it inside the security review surface; adversarial
  corpus testers grep this file as a policy invariant (CLAUDE.md §Security
  rules).

  ## Public surface

  - `quarantined_to_structured(handle, schema, *, extractor, gate) ->
    ExtractionResult` — `src/alfred/security/quarantine.py`. The ONLY
    path by which T3-derived content reaches orchestrator-readable
    structured form. Any other path claiming to convert T3 content is a
    security violation.
  - `QuarantinedExtractor` — `src/alfred/plugins/quarantine_extractor.py`.
    Orchestrator-side MCP client of the quarantined-LLM plugin. Calls
    `quarantine.extract()` via `StdioTransport.dispatch()`. Raw provider
    response bytes never cross back to the orchestrator untyped.
  - `ExtractionResult` — `Annotated[Extracted | TypedRefusal, Field(discriminator="kind")]`.
    `Extracted.data` is typed as `T3DerivedData` (a `NewType` over
    `dict[str, object]`). `TypedRefusal.reason` is a closed Literal.
  - `T3DerivedData` — `NewType("T3DerivedData", dict[str, object])`.
    Type-level provenance discriminant. Callers must use
    `downgrade_to_orchestrator()` before injecting into privileged prompts.
  - `downgrade_to_orchestrator(data, *, audit_row) -> dict[str, object]`
    — gated on `check_content_clearance(hookpoint="t3.downgrade_to_orchestrator",
    content_tier="T3_derived")`; writes an audit row with
    `downgrade_explicit=True`. The only legitimate path from
    `T3DerivedData` to a plain dict.

  ## Internal model

  ### Quarantined-LLM plugin shape

  The quarantined LLM runs as `plugins/alfred_quarantined_llm/` under
  the `alfred-quarantine` OS user — a dedicated system UID distinct from
  the `alfred` orchestrator UID. The OS-level UID separation means the
  subprocess literally cannot read the orchestrator's secrets file
  (CLAUDE.md hard rule #6; `src/alfred/security/secrets.py:228-279`
  validates ownership against `os.getuid()`).

  The plugin exposes exactly two JSON-RPC methods:
  - `quarantine.ingest(handle: str, context: str)` — fetches T3 content
    from the content store by handle ID.
  - `quarantine.extract(handle_id: str, schema_json: str, schema_version: int)`
    — structured extraction against that specific handle. Per-call handle
    lookup prevents TOCTOU race where concurrent extraction in conversation
    B operates against conversation A's content.

  The quarantined LLM has no `tool_calls` capability and emits no
  free-form text the orchestrator consumes as instructions.

  ### Provider routing and `ProviderCapability`

  `Provider.capabilities() -> frozenset[ProviderCapability]` governs
  which extraction path `QuarantinedExtractor` dispatches:

  | Provider | Mechanism | Capability |
  |---|---|---|
  | Anthropic | Tool-use shape | `NATIVE_CONSTRAINED_GENERATION` |
  | OpenAI | Strict structured-outputs (`strict: true` mandatory) | `NATIVE_CONSTRAINED_GENERATION` |
  | DeepSeek-chat | JSON mode (no schema enforcement) | `JSON_OBJECT_MODE` |

  `JSON_OBJECT_MODE` routes through the retry-and-validate path, identical
  to `prompt_embedded_fallback`. The audit row records
  `extraction_mode="json_object_unconstrained"` to preserve forensic
  traceability: operators can distinguish true schema enforcement from
  best-effort validation.

  ### Retry-guidance hygiene

  When the quarantined provider produces invalid output against a schema,
  the retry turn contains ONLY the validator error message + the schema
  JSON — NEVER the LLM's prior malformed JSON body verbatim. This is
  a hard invariant: a malformed output could contain injected instructions
  (a `TypedRefusal` with `reason="ambiguous_input"` is the correct
  response, not a prompt that includes the adversary's text). Max retries:
  2 (configurable in `config/policies.yaml` as
  `quarantine.extraction_max_retries`). After 2 failures:
  `TypedRefusal(reason="cannot_extract")`.

  The adversarial corpus (`tests/adversarial/tier_laundering/`) includes
  a retry-guidance hygiene payload that replays a malformed-output corpus
  through the fallback path and asserts the second-turn prompt token set
  is a subset of `{validator-error tokens} ∪ {schema-JSON tokens} ∪
  {fixed-instruction-template tokens}` (spec §12.3).

  ### `schema_version: Literal[1]` mandatory

  Every Pydantic model passed to `QuarantinedExtractor.extract()` must
  carry `schema_version: Literal[1]` as a class attribute. The extractor
  validates this before constructing the schema payload. A missing
  `schema_version` raises `ValueError` with
  `t("quarantine.schema_version_missing", schema_name=...)` before any
  MCP call (spec §6.6).

  ### T3 provenance survival

  The `T3DerivedData` NewType is a Slice-3 lightweight discriminant.
  The adversarial corpus includes a `tier_laundering` payload that
  verifies `type(result.data)` is `T3DerivedData` (not plain `dict`)
  through `quarantined_to_structured` and through a DB write/read
  roundtrip — confirming the NewType survives serialisation (spec §12.3).
  Slice 4 promotes this to a full type-parameter on `TaggedContent`.

  ## Failure modes

  | Trigger | Behaviour | Observable signal |
  |---|---|---|
  | `schema_version` missing on extraction schema | `ValueError` before any MCP call | `t("quarantine.schema_version_missing", schema_name=...)` |
  | Provider produces invalid output | Retry with validator error + schema only (no prior output) | `quarantine.extract` audit row with `result="malformed_exhausted"` after 2 retries |
  | Content handle TTL expired mid-extraction | `TypedRefusal(reason="cannot_extract")` | Audit row `result="content_expired"` |
  | Second `quarantine.extract` on same handle_id | `TypedRefusal(reason="cannot_extract")` (single-use UUID) | Audit row `result="content_expired"` |
  | `tag(T3, ...)` called from unauthorized caller | `ValueError` + security event | `security.t3_boundary.refused` audit row |
  | Quarantined provider refused content on safety grounds | `TypedRefusal(reason="refused_by_safety")` | Audit row with `result="refused"` |
  | Post-DLP scan of `model_dump_result` detects canary | `security.canary_tripped` raised | `security.canary_tripped` audit row |

  ## Trust-boundary contract

  The quarantine subsystem owns the crossing point between T3 (untrusted
  external content) and T2 (authenticated-user-trusted structured data).
  The crossing is `quarantined_to_structured` — one function, one file,
  one grep anchor. The capability gate enforces two orthogonal clearances:
  - `tag.T3` clearance — held by `StdioTransport` and
    `plugins/quarantine_host.py` only (the call sites that can produce
    `TaggedContent[T3]`).
  - `quarantine.dereference` clearance — held by `QuarantinedExtractor`
    only (the call site that can call `quarantined_to_structured`).

  See [docs/subsystems/plugins.md](plugins.md) for the T3 tagging boundary
  and [docs/glossary.md](../glossary.md#trust-tier) for the tier definitions.

  ## Performance characteristics

  | Path | Budget |
  |---|---|
  | `security.quarantined.extract` 5-subscriber hook chain | ≤ 100µs + provider RTT |
  | End-to-end quarantined extraction chain | ≤ 5s (generous for subprocess hop; spec §12.4) |

  Provider RTT is provider-owned; the 5ms `StdioTransport.dispatch()`
  budget is the local transport overhead (spec §7a.1). The advisory
  latency test at `tests/integration/test_quarantined_chain_latency.py`
  validates the 5s ceiling per recorded provider fixtures; it is shipped
  by PR-S3-4, not this PR.

  ## Slice graduation map

  | Subsystem | Slice 3 (shipped) | Deferred to |
  |---|---|---|
  | quarantine | `quarantined_to_structured`; `QuarantinedExtractor`; `T3DerivedData` NewType; `ExtractionResult` discriminated union; `schema_version: Literal[1]`; retry-guidance hygiene; dual-LLM split under `alfred-quarantine` UID | Slice 4+: full containerisation (ADR-0015); `TaggedContent` provenance axis (Slice 4 design); T3-promotion for Discord embeds/attachments |

  ## Cross-references

  - PRD [§7.1](../../PRD.md#71-security--prompt-injection-defense) — dual-LLM split invariant.
  - [ADR-0017](../adr/0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md) — Slice-3 realisation.
  - [ADR-0013](../adr/0013-defer-t1-t3-and-dual-llm.md) — the deferred commitment this slice closes.
  - [ADR-0015](../adr/0015-slice4-containerised-quarantined-llm.md) — Slice-4 containerisation commitment.
  - Sibling docs: [plugins.md](plugins.md), [supervisor.md](supervisor.md), [hooks.md](hooks.md).
  - Glossary: [T3DerivedData](../glossary.md#t3deriveddata), [ContentHandle](../glossary.md#contenthandle), [QuarantinedExtractor](../glossary.md#quarantinedextractor), [ExtractionResult](../glossary.md#extractionresult), [TypedRefusal](../glossary.md#typedrefusal), [quarantined_to_structured](../glossary.md#quarantined_to_structured), [trust tier](../glossary.md#trust-tier), [AnyTaggedContent](../glossary.md#anytaggedcontent).
  ```

  2. Run `make docs-check` — must pass.
  3. Commit:
     ```
     git commit -m "docs(subsystems): add quarantine.md — dual-LLM split + T3 extraction deep-doc (#TBD-slice3)"
     ```

---

### Component C: Operator runbook

- [ ] **Task 9 — Write docs/runbooks/slice-3-operator-migration.md**

  Files: Create `docs/runbooks/slice-3-operator-migration.md`.

  Steps:

  1. Write the file:

  ```markdown
  # Slice 2 → Slice 3 operator migration

  This runbook covers upgrading an AlfredOS deployment from Slice 2 to
  Slice 3. Slice 3 introduces MCP plugin transport, the quarantined LLM,
  the real `CapabilityGate` (`RealGate`), Redis as a required service,
  and `/var/lib/alfred/state.git` as the capability-grant source of truth.
  Skipping any step causes predictable, operator-visible failures (not
  silent degradation).

  ## Prerequisites

  - AlfredOS Slice 2 running and healthy (`alfred status` returns `ok`).
  - Docker Compose access to the host.
  - Operator role (all `alfred plugin grant` and `alfred web allowlist`
    commands require operator-tier T1 authentication).

  Confirm operator-tier auth before proceeding:

  ```shell
  alfred user show $USER   # expect role: operator
  ```

  If your user is not bound or does not hold operator role, run
  `alfred user set $USER role=operator` (requires an existing root
  operator already bound). See
  [docs/subsystems/identity.md](../subsystems/identity.md) for the
  user-binding workflow.

  ## Upgrade order

  **Step 1 — Pull and build updated images**

  ```shell
  docker compose pull
  docker compose build
  ```

  This pulls the Slice-3 `alfred-core` image (which includes the
  `alfred-quarantine` system user and the `git` package) and the new
  `alfred-redis` service image.

  **Step 2 — Seed state.git (idempotent)**

  ```shell
  git init --bare /var/lib/alfred/state.git
  # Seed an empty root commit on `main`. A bare repo has no working tree, so
  # `git commit --allow-empty` cannot run — drop down to plumbing instead.
  SEED_COMMIT=$(
    git -C /var/lib/alfred/state.git commit-tree \
      "$(git -C /var/lib/alfred/state.git mktree </dev/null)" \
      -m "seed: empty initial commit"
  )
  git -C /var/lib/alfred/state.git update-ref refs/heads/main "$SEED_COMMIT"
  git -C /var/lib/alfred/state.git symbolic-ref HEAD refs/heads/main
  ```

  This initialises the bare repository that `RealGate` uses as its
  grant backing store and creates the initial `main` branch. The
  operation is idempotent — if `state.git` already contains a `HEAD`
  ref, skip this step.

  *Slice 3.x+: an `alfred plugin grant seed` wrapper command that
  encapsulates these two steps is tracked as a follow-up.*

  If you skip this step, every plugin start (quarantined-LLM,
  web-fetch) emits `plugin.lifecycle.load_refused` and you will see a
  user-facing chat message keyed `cli.chat.capability_gate_unseeded`
  instructing you to seed `state.git` and then run
  `alfred supervisor reset quarantined-llm --confirm`.

  **Step 3 — Apply database migrations**

  ```shell
  uv run alembic upgrade head
  ```

  This applies migrations `0007` through `0010`:
  - `0007` — extends the `ck_audit_log_result` CHECK constraint with
    Slice-3 `result` values (`extracted`, `load_refused`, `crashed`, …).
  - `0008` — creates the `plugin_grants` table (Postgres projection of
    state.git grants).
  - `0009` — creates the `capability_gate_sync` table (commit-hash cache
    for `RealGate`).
  - `0010` — creates the `circuit_breakers` table (breaker state + trip
    history for the supervisor).

  **Step 4 — Start the updated stack**

  ```shell
  docker compose up -d
  ```

  The `alfred-redis` service starts alongside `alfred-core`. Redis is
  required for the content store (fetched T3 content keyed by
  `ContentHandle.id`) and rate-limit counters (`alfred:rate:{domain}`,
  `alfred:rate:user:{user_id}`).

  Verify Redis is healthy before proceeding — if it fails to start, the
  content store silently becomes unavailable and `web.fetch` crashes are
  misleading:

  ```shell
  docker compose ps alfred-redis     # expect: Up
  redis-cli -h 127.0.0.1 ping       # expect: PONG
  ```

  If `alfred-redis` is not `Up`, check for port conflicts on 6379 and
  consult `docker compose logs alfred-redis`.

  **Step 5 — Verify gate and supervisor state**

  ```shell
  alfred status
  alfred supervisor status
  ```

  PR-S3-6 does not extend `alfred status` with gate health. The Slice-3
  `alfred status` output is identical to the Slice-2 output (provider +
  budget lines). Use `alfred plugin grant list` to inspect gate state in
  Slice 3.

  Current Slice-3 `alfred status` output (unchanged from Slice 2):

  | Condition | Output |
  |---|---|
  | Any `ALFRED_ENV` (Slice 3) | Slice-2 provider/budget lines — no `gate:` line |

  *Slice 3.x+: gate health (`gate: RealGate (state.git: ok, postgres: ok)`)
  ships in a follow-up PR that extends `alfred status` with a
  `gate.health()` call.*

  Expected `alfred supervisor status` output after a clean start:

  ```
  Component             State    Trips  Last trip
  quarantined-llm       CLOSED   0      —
  web-fetch             CLOSED   0      —
  ```

  ## Expected errors during transition

  **`plugin.lifecycle.load_refused` with `bootstrap.capability_gate_unseeded`**

  Cause: `state.git` was not seeded before `docker compose up`.

  Fix:
  ```shell
  git init --bare /var/lib/alfred/state.git
  # Bare repos have no working tree, so `git commit --allow-empty` cannot run;
  # use plumbing to seed an empty root commit on `main`.
  SEED_COMMIT=$(
    git -C /var/lib/alfred/state.git commit-tree \
      "$(git -C /var/lib/alfred/state.git mktree </dev/null)" \
      -m "seed: empty initial commit"
  )
  git -C /var/lib/alfred/state.git update-ref refs/heads/main "$SEED_COMMIT"
  git -C /var/lib/alfred/state.git symbolic-ref HEAD refs/heads/main
  alfred supervisor reset quarantined-llm --confirm
  alfred supervisor reset web-fetch --confirm
  ```

  **`gate: RealGate (FAIL-CLOSED — backing store unavailable)`**

  Cause: Postgres or state.git is unreachable.

  Fix: verify `docker compose ps` shows `alfred-db` healthy, then:
  ```shell
  alfred status
  ```

  When the backing store recovers, `RealGate` exits fail-closed
  automatically. One `supervisor.capability_gate_unavailable` audit row
  is emitted on exit from fail-closed (with `state_transition=
  "exiting_fail_closed"` and `denied_dispatch_count=N`).

  **`supervisor.config_insecure` in audit stream**

  Cause: `ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED=1` is set. This is expected
  in development but is a warning in production.

  Fix (production): remove `ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED` from the
  compose environment. Slice 4 ships OS sandbox policy files that replace
  this escape hatch.

  **`supervisor.breaker.tripped` after upgrade**

  Cause: the quarantined-LLM subprocess crashed 3 times in 5 minutes.
  This can happen if the provider API key was not seeded or the
  `config/routing.yaml` quarantine block is missing.

  Fix:
  1. Check `config/routing.yaml` has a `[quarantine]` block with
     `provider`, `model`, and `secret_id`.
  2. Inspect recent crash events (Slice-3 `alfred audit graph` is the
     available surface; `alfred audit log --event` ships in Slice 4):
     ```shell
     alfred audit graph --since 5m
     # then grep for plugin.lifecycle.crashed rows
     ```
  3. After fixing the config: `alfred supervisor reset quarantined-llm
     --confirm`.

  ## Plugin grant seed step

  After seeding `state.git` (Step 2 above), the quarantined-LLM and
  web-fetch plugins are not yet granted any hookpoints — the `main` branch
  is empty. The Slice-3 default grants ship in
  `config/default-plugin-grants.yaml`.

  > **Implementation dependency:** `alfred plugin grant apply <yaml>` is
  > scoped to a post-Slice-3 PR. Until it ships, apply grants individually
  > using the per-grant subcommand: (devex-002)

  ```shell
  # Grant quarantined-LLM (system tier, all hookpoints)
  alfred plugin grant alfred.quarantined-llm system security.quarantined.extract
  alfred plugin grant alfred.quarantined-llm system quarantine.ingest

  # Grant web-fetch plugin (system tier)
  alfred plugin grant alfred.web-fetch system tool.web.fetch
  ```

  Each command is a high-blast operation (it grants system-tier
  hookpoints) and goes through the reviewer-gate flow — the command
  queues a proposal and prints the proposal ID. Track approval:

  ```shell
  alfred plugin grant list --pending     # see what's queued
  alfred plugin grant status <id>        # track each approval
  ```

  Once all grants are approved, the plugins load on the next supervisor
  restart or `alfred supervisor reset`.

  ## Rollback

  To roll back to Slice 2:

  1. `docker compose down`.
  2. `uv run alembic downgrade base` (removes migrations `0007`–`0010`).
     Note: downgrading `0008`/`0009` drops those tables (data is
     rebuildable from state.git); downgrading `0010` deletes all circuit
     breaker rows (breaker state is transient — the next run
     re-discovers failures).
  3. `docker compose up -d` with the Slice-2 images.

  The state.git directory at `/var/lib/alfred/state.git` is not modified
  by the Alembic downgrade — it is the source of truth. A rollback
  discards the Postgres projection; the next `upgrade head` rebuilds it.

  > **Warning:** `config/policies.yaml` entries added or changed via
  > `alfred config set` since the Slice-3 upgrade are **not rolled back
  > automatically**. Review the file and restore the Slice-2 baseline
  > values for any keys that Slice-3 features introduced (e.g.
  > `quarantine.extraction_max_retries`,
  > `orchestrator.action_deadline_seconds`).

  > **Warning:** `docker compose down -v` deletes the `alfred_state_git`
  > volume, permanently destroying the capability-grant history. Use
  > `docker compose down` (without `-v`) for rollback.

  **Verify the rollback succeeded:**

  ```shell
  alfred status         # expect Slice-2 output (no gate: line)
  alfred audit graph --since 1m
  # expect no Slice-3 audit families (plugin.lifecycle.*, supervisor.*)
  ```

  ## Related docs

  - [docs/subsystems/plugins.md](../subsystems/plugins.md) — plugin
    transport architecture.
  - [docs/subsystems/supervisor.md](../subsystems/supervisor.md) — circuit
    breaker and per-action deadline.
  - [docs/subsystems/quarantine.md](../subsystems/quarantine.md) — dual-LLM
    split and T3 extraction.
  - [docs/glossary.md](../glossary.md) — RealGate, capability gate,
    ContentHandle.
  ```

  2. Run `make docs-check` — must pass.
  3. Commit:
     ```
     git commit -m "docs(runbooks): add slice-3-operator-migration.md (#TBD-slice3)"
     ```

---

### Component D: CLAUDE.md command table update

- [ ] **Task 10 — Update .rulesync/rules/CLAUDE.md command table with Slice-3 CLI**

  Files: Modify `.rulesync/rules/CLAUDE.md`.

  Steps:

  1. Read the current command table in `.rulesync/rules/CLAUDE.md`.

  2. Add the following rows to the command table (after existing `alfred audit` rows):

  ```markdown
  | Plugin management | `alfred plugin list` · `alfred plugin show <id>` · `alfred plugin grant <id> <tier> <hookpoint>` · `alfred plugin grant status <id>` · `alfred plugin grant list --pending` (Slice 3) |
  | Web fetch allowlist | `alfred web allowlist add <domain>` · `alfred web allowlist remove <domain>` · `alfred web allowlist list` (Slice 3) |
  | Config (reviewer-gated) | `alfred config quarantined-provider <provider>` · `alfred config web-fetch-budget <user> <n>` (Slice 3) |
  | Supervisor | `alfred supervisor status` · `alfred supervisor reset <component> --confirm` (Slice 3) |
  | Audit (extended) | `alfred audit graph --tier T3 --since 24h` · `alfred audit graph --tier T1 --since 24h` (Slice 3) |
  ```

  3. Remove the `(planned — Slice 3+)` marker from the `alfred audit log` / `alfred audit graph` entry — these are shipped via PR-S3-6. Leave `alfred status` alone: its entry in `.rulesync/rules/CLAUDE.md` is already marked `(Slice 1)` with no planned marker to remove. Verify that other deferred commands (`alfred memory show`, `alfred cost report`) retain their planned markers since they remain out-of-scope for Slice 3.

  4. Add `git init --bare /var/lib/alfred/state.git` (state.git seed) as the first-run seed step to the "When you get stuck" section pointer.

  5. Run `rulesync generate -t claudecode -f '*'` to regenerate `CLAUDE.md`.

  6. Run `make docs-check` — must pass.

  7. Commit:
     ```
     git commit -m "docs(claude-md): update command table with Slice-3 CLI surface (#TBD-slice3)"
     ```

  Note: as the procedural rule requires, end the response telling the user to restart the AI tool after this commit.

---

### Component E: DevGate flag-day removal

- [ ] **Task 11 — Create tests/helpers/gates.py test shim**

  Before removing `DevGate` from `src/`, create the test-only shim so
  test imports can be updated atomically.

  Files: Create `tests/helpers/__init__.py`, Create `tests/helpers/gates.py`.

  Steps:

  1. Write `tests/helpers/__init__.py` (empty package marker).

  2. Write `tests/helpers/gates.py`:

  ```python
  """Test-only gate helpers.

  ``DevGate`` has been removed from ``src/alfred/hooks/capability.py``
  at the end of Slice 3 (PR-S3-7). This module re-exports the semantics
  that were previously ``DevGate`` — but ONLY for use in tests, never in
  production code.

  The production gate is ``RealGate`` (``src/alfred/hooks/capability.py``),
  constructed by ``src/alfred/bootstrap/gate_factory.py`` based on
  ``ALFRED_ENV``. Tests that need the deny-path semantics of the old
  ``DevGate`` should use ``RealGateTestFixture`` from this module, which
  wraps ``RealGate`` with an in-memory Postgres testcontainer seeded with
  an explicit grant table.

  Usage in conftest.py::

      from tests.helpers.gates import make_deny_all_gate, make_allow_system_gate

      gate = make_deny_all_gate()   # RealGate with empty grants (all checks deny)
      gate = make_allow_system_gate()  # RealGate with system-tier grant seeded
  """
  from __future__ import annotations

  from alfred.hooks.capability import CapabilityGate, RealGate


  def make_deny_all_gate() -> CapabilityGate:
      """Return a RealGate with an empty grant store (all checks deny).

      Equivalent to the old ``DevGate()`` (no args) for deny-path tests.
      Uses an in-memory SQLite backing store so no Postgres container is
      needed for unit tests that only exercise the deny path.
      """
      return RealGate.from_empty_store()


  def make_allow_system_gate(
      *,
      plugin_id: str = "test-plugin",
      hookpoint: str = "*",
  ) -> CapabilityGate:
      """Return a RealGate with a system-tier grant seeded.

      Equivalent to the old ``DevGate(allow_system=True)`` for granted-system
      tests. Seeds a single system-tier grant for ``(plugin_id, hookpoint)``
      into an in-memory store.
      """
      return RealGate.from_grants(
          [{"plugin_id": plugin_id, "hookpoint": hookpoint, "tier": "system"}]
      )
  ```

  3. Run `uv run ruff check tests/helpers/ && uv run ruff format --check tests/helpers/` — must pass.

  4. Commit:
     ```
     git commit -m "test(helpers): add gates.py shim for DevGate-to-RealGate migration (#TBD-slice3)"
     ```

- [ ] **Task 12 — Remove DevGate from src/alfred/hooks/capability.py**

  Files: Modify `src/alfred/hooks/capability.py`, Modify `src/alfred/hooks/__init__.py`.

  Steps:

  1. Write the failing test first — assert `DevGate` is NOT importable from `alfred.hooks`:

  ```python
  # tests/unit/hooks/test_devgate_removed.py
  """Regression guard: DevGate has been removed from src/ in PR-S3-7.

  Spec §15.1: 'DevGate is removed from src/ in the flag-day PR;
  its import is removed from alfred.hooks.__init__.'
  """
  import pytest


  def test_devgate_not_importable_from_alfred_hooks() -> None:
      """DevGate must not be importable from alfred.hooks after PR-S3-7."""
      with pytest.raises(ImportError):
          from alfred.hooks import DevGate  # noqa: F401


  def test_devgate_not_importable_from_capability_module() -> None:
      """DevGate must not be importable from alfred.hooks.capability."""
      with pytest.raises(ImportError):
          from alfred.hooks.capability import DevGate  # noqa: F401
  ```

  2. Run `uv run pytest tests/unit/hooks/test_devgate_removed.py -q` — both tests FAIL (DevGate still importable). Expected output:
     ```
     FAILED tests/unit/hooks/test_devgate_removed.py::test_devgate_not_importable_from_alfred_hooks
     FAILED tests/unit/hooks/test_devgate_removed.py::test_devgate_not_importable_from_capability_module
     2 failed in 0.XXs
     ```

  3. Edit `src/alfred/hooks/capability.py` — delete the `DevGate` class and its supporting constants (`_TIERS_GRANTED_UNCONDITIONALLY`, `_TIER_GATED_BY_ALLOW_SYSTEM`). Retain only:
     - The `CapabilityGate` Protocol (with all three methods: `check`, `check_plugin_load`, `check_content_clearance` added by PR-S3-2).
     - The module docstring (updated to remove all `DevGate` references; add note "DevGate was removed in PR-S3-7 — see git history for the Slice-2.5 implementation.").

  4. Edit `src/alfred/hooks/__init__.py` — remove `DevGate` from the imports and from `__all__`.

  5. Run `uv run pytest tests/unit/hooks/test_devgate_removed.py -q` — both tests PASS. Expected output:
     ```
     2 passed in 0.XXs
     ```

  6. Run `uv run mypy src/alfred/hooks/ && uv run pyright src/alfred/hooks/` — must pass (no `DevGate` references remain in src/).

  7. Commit:
     ```
     git commit -m "feat(capability): remove DevGate from src/ — flag-day PR-S3-7 (#TBD-slice3)"
     ```

- [ ] **Task 13 — Migrate tests/unit/hooks/conftest.py from DevGate to RealGate fixtures**

  Files: Modify `tests/unit/hooks/conftest.py`.

  Steps:

  1. Replace all `from alfred.hooks.capability import DevGate` imports with:
     ```python
     from tests.helpers.gates import make_deny_all_gate, make_allow_system_gate
     ```

  2. Replace every `HookRegistry(gate=DevGate(), ...)` construction with
     `HookRegistry(gate=make_deny_all_gate(), ...)`.

  3. Replace every `HookRegistry(gate=DevGate(allow_system=True), ...)` construction with
     `HookRegistry(gate=make_allow_system_gate(), ...)`.

  4. Update all fixture docstrings to remove references to `DevGate` and reference `RealGate` (via the test helper).

  5. Run `uv run pytest tests/unit/hooks/ -q` — must pass. Expected:
     ```
     XX passed in X.XXs
     ```

  6. Run `uv run mypy tests/unit/hooks/ && uv run pyright tests/unit/hooks/` — must pass.

  7. Commit:
     ```
     git commit -m "test(hooks): migrate conftest.py DevGate fixtures to RealGate (#TBD-slice3)"
     ```

- [ ] **Task 14 — Migrate tests/unit/hooks/test_capability.py — delete DevGate tests, add RealGate deny-path tests**

  Files: Modify `tests/unit/hooks/test_capability.py`.

  Steps:

  1. Delete all test functions that test `DevGate`-specific behaviour:
     - `test_devgate_denies_system_by_default`
     - `test_devgate_grants_operator`
     - `test_devgate_grants_user_plugin`
     - `test_devgate_allows_system_when_opted_in`
     - `test_devgate_denies_unknown_tiers`
     - `test_devgate_isinstance_capabilitygate`
     - `test_devgate_check_is_keyword_only`
     - `test_devgate_constructor_is_keyword_only`
     - Any other functions whose name starts with `test_devgate_`.

  2. Add `RealGate` deny-path tests that preserve the deny-path semantics:

  ```python
  """CapabilityGate Protocol + RealGate deny-path tests.

  DevGate was removed in PR-S3-7. These tests assert the deny-path
  invariants against the real RealGate implementation (backed by an
  in-memory store via tests.helpers.gates).

  Hard rules preserved:
  - CLAUDE.md hard rule #4: never bypass the capability layer — the deny
    paths assert against real RealGate refusal, never a stub.
  - CLAUDE.md hard rule #7: unknown tier strings deny fail-closed.
  - sec-007: no env flag on CapabilityGate — the ALFRED_ENV selection lives
    in src/alfred/bootstrap/gate_factory.py, not in capability.py.
  """
  from __future__ import annotations

  import ast
  from pathlib import Path

  import pytest

  from alfred.hooks.capability import CapabilityGate, RealGate
  from tests.helpers.gates import make_allow_system_gate, make_deny_all_gate


  def test_realgate_deny_all_with_empty_store() -> None:
      """RealGate with an empty grant store denies all check() calls.

      This is the equivalent deny-path invariant that DevGate() (no args)
      provided — no grants = all checks deny.
      """
      gate = make_deny_all_gate()
      assert not gate.check(
          plugin_id="test", hookpoint="tool.web.fetch", requested_tier="system"
      )
      assert not gate.check(
          plugin_id="test", hookpoint="tool.web.fetch", requested_tier="operator"
      )
      assert not gate.check(
          plugin_id="test", hookpoint="tool.web.fetch", requested_tier="user-plugin"
      )


  def test_realgate_deny_all_unknown_tier() -> None:
      """Unknown / typo'd / case-mismatched tier strings deny (fail-closed).

      CLAUDE.md hard rule #7: no silent failures. Unrecognised input denies.
      """
      gate = make_deny_all_gate()
      for bad_tier in ("SYSTEM", "System", "", "root", "None", "t3"):
          assert not gate.check(
              plugin_id="test", hookpoint="*", requested_tier=bad_tier
          ), f"Expected deny for tier={bad_tier!r}"


  def test_realgate_with_system_grant_allows_system() -> None:
      """RealGate with a seeded system-tier grant allows check() for system.

      Equivalent to DevGate(allow_system=True) — the grant exists, so it passes.
      """
      gate = make_allow_system_gate(plugin_id="test-plugin", hookpoint="tool.web.fetch")
      assert gate.check(
          plugin_id="test-plugin",
          hookpoint="tool.web.fetch",
          requested_tier="system",
      )


  def test_realgate_check_plugin_load_deny_without_grant() -> None:
      """check_plugin_load returns False when no grant exists (fail-closed)."""
      gate = make_deny_all_gate()
      assert not gate.check_plugin_load(plugin_id="new-plugin", manifest_tier="system")
      assert not gate.check_plugin_load(plugin_id="new-plugin", manifest_tier="operator")


  def test_realgate_check_content_clearance_deny_without_grant() -> None:
      """check_content_clearance returns False when no clearance grant exists."""
      gate = make_deny_all_gate()
      assert not gate.check_content_clearance(
          plugin_id="test", hookpoint="tag.T3", content_tier="T3"
      )


  def test_realgate_isinstance_capabilitygate() -> None:
      """RealGate is structurally a CapabilityGate (Protocol check)."""
      gate = make_deny_all_gate()
      assert isinstance(gate, CapabilityGate)


  def test_capability_module_has_no_devgate() -> None:
      """DevGate must not exist in src/alfred/hooks/capability.py.

      Regression guard per spec §15.1: the flag-day PR removes DevGate.
      """
      with pytest.raises(ImportError):
          from alfred.hooks.capability import DevGate  # noqa: F401


  def test_capability_py_reads_no_env() -> None:
      """capability.py must not read environment variables directly.

      sec-007: ALFRED_ENV selection lives in gate_factory.py, not here.
      The AST-scan asserts no os.environ / os.getenv / os.environ.get
      Call node exists in the module source.
      """
      source = Path("src/alfred/hooks/capability.py").read_text(encoding="utf-8")
      tree = ast.parse(source)

      class EnvReadVisitor(ast.NodeVisitor):
          def __init__(self) -> None:
              self.violations: list[tuple[int, str]] = []

          def visit_Attribute(self, node: ast.Attribute) -> None:
              if (
                  isinstance(node.value, ast.Attribute)
                  and isinstance(node.value.value, ast.Name)
                  and node.value.value.id == "os"
                  and node.value.attr == "environ"
              ):
                  self.violations.append((node.lineno, "os.environ.attr"))
              self.generic_visit(node)

          def visit_Call(self, node: ast.Call) -> None:
              if isinstance(node.func, ast.Attribute):
                  if (
                      isinstance(node.func.value, ast.Attribute)
                      and isinstance(node.func.value.value, ast.Name)
                      and node.func.value.value.id == "os"
                      and node.func.value.attr == "environ"
                  ):
                      self.violations.append((node.lineno, "os.environ.method"))
                  if (
                      isinstance(node.func.value, ast.Name)
                      and node.func.value.id == "os"
                      and node.func.attr == "getenv"
                  ):
                      self.violations.append((node.lineno, "os.getenv"))
              self.generic_visit(node)

      visitor = EnvReadVisitor()
      visitor.visit(tree)
      assert not visitor.violations, (
          f"capability.py must not read environment variables (sec-007). "
          f"Violations: {visitor.violations}"
      )
  ```

  3. Run `uv run pytest tests/unit/hooks/test_capability.py -q` — all tests PASS. Expected:
     ```
     X passed in X.XXs
     ```

  4. Run `uv run pytest tests/unit/hooks/ --cov=src/alfred/hooks/capability.py --cov-branch --cov-fail-under=100 -q` — 100% coverage preserved on `capability.py`.

  5. Commit:
     ```
     git commit -m "test(capability): migrate deny-path tests from DevGate to RealGate fixtures (#TBD-slice3)"
     ```

- [ ] **Task 15 — Migrate remaining DevGate references in tests/**

  Files: Modify `tests/unit/hooks/test_capability_sec007.py`, `tests/unit/hooks/test_registry.py`, `tests/unit/hooks/test_decorators.py`, `tests/unit/hooks/test_security_contract.py`, `tests/unit/memory/test_episodic_hooks_wiring.py`.

  Steps:

  1. In each file, replace:
     - `from alfred.hooks.capability import DevGate` → `from tests.helpers.gates import make_deny_all_gate, make_allow_system_gate`
     - `DevGate()` → `make_deny_all_gate()`
     - `DevGate(allow_system=True)` → `make_allow_system_gate()`

  2. In `test_capability_sec007.py` — update the module docstring to note that it tests the `capability.py` module for env-read absence (sec-007), which still applies to the file now that `DevGate` is removed. The test itself tests the module at the AST level so it still runs cleanly.

  3. Run `uv run pytest tests/unit/hooks/ tests/unit/memory/test_episodic_hooks_wiring.py -q` — all tests PASS. Expected:
     ```
     XX passed in X.XXs
     ```

  4. Run `uv run mypy tests/ && uv run pyright tests/` — must pass (no unresolved `DevGate` imports).

  5. Run full quality gate:
     ```
     make check
     ```
     Expected output: `All checks passed.` (or equivalent green signal).

  6. Commit:
     ```
     git commit -m "test(hooks): complete DevGate→RealGate migration across all test files (#TBD-slice3)"
     ```

- [ ] **Task 16 — Retire Slice-2.5 tracking issues #122–#125**

  > **Spec §15.3 ownership note:** Spec §15.3 assigns issue retirement to
  > PR-S3-0a ("in the first Slice-3 PR"). This plan intentionally keeps
  > the retirement here (PR-S3-7, the final Slice-3 PR) because issues
  > #122–#125 cannot be meaningfully closed until their concrete
  > deliverables land: #122 requires DevGate removal (Task 11–15), #125
  > requires the runbook (Task 9). Closing them in PR-S3-0a before those
  > deliverables ship would be a premature closure. (docs-003 — resolved
  > by this rationale; no spec amendment required.)

  Files: No code files. This task closes the four follow-up issues by
  documenting their resolution.

  Steps:

  1. Verify each issue's scope is addressed:
     - **#122** (test corpus migration to `strict_declarations=True`) — resolved by `make check` green with all tests using `RealGate` (which always uses strict declarations in production). Add a comment to each migrated test file's module docstring: "Slice-2.5 issue #122 resolved: strict_declarations=True is now the production default via RealGate."
     - **#123** (ADR amendment closed by ADR-0017) — ADR-0017 (shipped PR-S3-0a) supersedes ADR-0008 and ADR-0013; the amendment issue is closed by virtue of ADR-0017 existing.
     - **#124** (publisher-declaration cleanup) — resolved by `register_hookpoint` being mandatory (`strict_declarations=True` in production); all Slice-3 hookpoints declared in their owning modules.
     - **#125** (operator runbook) — resolved by `docs/runbooks/slice-3-operator-migration.md` (Task 9 of this PR).

  2. Add one-line resolution comments to the affected test module docstrings where appropriate.

  3. Run `make docs-check` — must pass.

  4. Commit:
     ```
     git commit -m "docs: retire Slice-2.5 tracking issues #122-#125 (#TBD-slice3)"
     ```

---

### Component G: Final quality gate

- [ ] **Task 17 — Full quality gate run**

  Steps:

  1. Run the complete quality bar:
     ```
     make check
     ```
     Expected: all lint, format, type-check, and test gates green.

  2. Run docs-check:
     ```
     make docs-check
     ```
     Expected: no broken links.

  3. Run the adversarial suite (required because this PR touches `src/alfred/hooks/capability.py`):
     ```
     uv run pytest tests/adversarial -q
     ```
     Expected: all existing adversarial tests pass; no regression from DevGate removal.

  4. Run the unit coverage gate on `capability.py`:
     ```
     uv run pytest tests/unit/hooks/ \
       --cov=src/alfred/hooks/capability.py \
       --cov-branch \
       --cov-fail-under=100 \
       -q
     ```
     Expected: `100%` coverage on `capability.py`.

  5. Run catalog drift check:
     ```
     uv run pybabel compile --check -d locale
     ```
     Expected: no catalog drift (no new `t()` keys are added by this PR — all keys were added in PR-S3-0b).

  6. If all gates green: no further action. If any gate fails: diagnose root cause before committing.

  7. Commit (if not already clean from Task 16):
     ```
     git commit -m "chore: final quality gate pass — PR-S3-7 (#TBD-slice3)"
     ```

---

## §5 Spec coverage map

| Spec section | What it requires | Implemented in |
|---|---|---|
| §15.1 | `DevGate` removed from `src/`; deny-path tests migrated to `RealGate` | Tasks 11–15 |
| §15.2 | ADR-0009 status flip | PR-S3-0a (already done; confirmed clean in Task 17) |
| §15.3 | Slice-2.5 §6.10 tracking issues retired | Task 16 *(intentionally in PR-S3-7 not PR-S3-0a — see Task 16 note)* |
| §15.4 | Operator migration runbook (upgrade order, status outputs, expected errors, seed step) | Task 9 |
| §17 item 9 (PR-S3-7) | `docs/subsystems/plugins.md` | Task 6 |
| §17 item 9 (PR-S3-7) | `docs/subsystems/supervisor.md` | Task 7 |
| §17 item 9 (PR-S3-7) | `docs/subsystems/quarantine.md` | Task 8 |
| §17 item 9 (PR-S3-7) | `docs/glossary.md` additions (20 new terms + 2 updates) | Tasks 1–5, 5a |
| §17 item 9 (PR-S3-7) | CLAUDE.md command table update | Task 10 |
| §17 item 9 (PR-S3-7) | DevGate flag-day removal | Tasks 11–15 |
| §17 item 9 (PR-S3-7) | #122–#125 Slice-2.5 issues retired | Task 16 |
| §12.4 | `tests/integration/test_quarantined_chain_security.py` | Owned by PR-S3-4 (this PR consumes the tests' presence in main) |
| §12.4 | `tests/integration/test_quarantined_chain_latency.py` | Owned by PR-S3-4 (this PR consumes the tests' presence in main) |
| §18 (glossary) | `ContentHandle`, `QuarantinedExtractor`, `T3DerivedData` | Task 1 |
| §18 (glossary) | `PluginTransport`, `StdioTransport`, `AlfredPluginSession` | Task 2 |
| §18 (glossary) | `sandbox_profile`, `RealGate`, `ExtractionResult`, `TypedRefusal` | Task 3 |
| §18 (glossary) | `JSON_OBJECT_MODE`, `ProviderCapability`, `WebFetchError`, `WebFetchCanaryTripped`, `QuarantinedUnavailable` | Task 4 |
| §18 (glossary) | `CommsAdapterMCP`, `quarantined_to_structured`, `AnyTaggedContent` | Task 5 |
| §18 (glossary) | Update `capability gate` entry (check_plugin_load, check_content_clearance) | Task 5 |
| §18 (glossary) | Update `hook tier` entry (orthogonality language) | Task 5 |
| §18 (glossary) | Update `trust tier` entry (`TaggedContent[T1]`/`TaggedContent[T3]` type parameters) | Task 5 |
| §18 (glossary) | `provenance`, `Supervisor` — spec §18 required, missing from Tasks 1–5 | Task 5a |
| §9.4 | ADR-0009 status flip (in PR-S3-0a; confirmed via docs-check) | Task 17 verification |
| §11.5 | i18n keys (all added in PR-S3-0b; no new keys this PR) | Task 17 verification |
| §8.4 | `DevGate`/`RealGate` co-existence through Slice 3; flag-day at end | Tasks 11–15 |

---

## §6 Quality gates

Run all of these before opening the PR for review:

```shell
# Full quality bar
make check

# Docs link integrity (required — broken cross-links are release-blockers)
make docs-check

# Adversarial suite (required because capability.py is touched)
uv run pytest tests/adversarial -q

# 100% coverage on capability.py (trust boundary)
uv run pytest tests/unit/hooks/ \
  --cov=src/alfred/hooks/capability.py \
  --cov-branch \
  --cov-fail-under=100 \
  -q

# Catalog drift check (no new t() keys in this PR, but verify catalog is clean)
uv run pybabel compile --check -d locale

# DevGate removal regression guard
uv run pytest tests/unit/hooks/test_devgate_removed.py -q

# Integration test collection (tests shipped by PR-S3-4 — confirm they are present and collected)
uv run pytest tests/integration/test_quarantined_chain_security.py \
  tests/integration/test_quarantined_chain_latency.py \
  --collect-only -q
```

No `--no-verify` on any commit. No gate stubbed to always-allow in any test.

---

## §7 References

- **Spec:** [`docs/superpowers/specs/2026-05-30-slice-3-trust-tier-completion-design.md`](../specs/2026-05-30-slice-3-trust-tier-completion-design.md) — §9.4, §11.5, §12.4, §15, §17 item 9, §18.
- **Predecessor plans:**
  - [PR-S3-0a](2026-05-31-slice-3-pr-s3-0a-docs-adrs-foundations.md) — ADR-0017, audit_row_schemas.py
  - [PR-S3-0b](2026-05-31-slice-3-pr-s3-0b-migrations-infra-i18n.md) — i18n catalog additions (all `t()` keys this PR references)
  - [PR-S3-2](2026-05-31-slice-3-pr-s3-2-real-capability-gate.md) — `RealGate`, `check_plugin_load`, `check_content_clearance`, `gate_factory.py`
  - [PR-S3-3a](2026-05-31-slice-3-pr-s3-3a-mcp-plugin-transport.md) — `StdioTransport`, `AlfredPluginSession`, `PluginTransport`
  - [PR-S3-3b](2026-05-31-slice-3-pr-s3-3b-supervisor.md) — `Supervisor`, `CircuitBreaker`, per-action deadline
  - [PR-S3-4](2026-05-31-slice-3-pr-s3-4-quarantined-llm-extractor.md) — `QuarantinedExtractor`, `quarantined_to_structured`, `T3DerivedData`
  - [PR-S3-5](2026-05-31-slice-3-pr-s3-5-web-fetch.md) — `ContentHandle`, `WebFetchError`, `InboundCanaryScanner`
  - [PR-S3-6](2026-05-31-slice-3-pr-s3-6-cli-comms-mcp-stub.md) — operator CLI commands, `CommsAdapterMCP`
- **ADR-0017:** [`docs/adr/0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md`](../../adr/0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md) — the load-bearing Slice-3 ADR.
- **ADR-0014:** [`docs/adr/0014-pluggable-hooks-for-every-action.md`](../../adr/0014-pluggable-hooks-for-every-action.md) — hooks contract this PR's DevGate removal finalises.
- **PRD sections:** [§5](../../../PRD.md#5-architecture-overview), [§6.3](../../../PRD.md#63-agentic-skills--mcp-integration), [§6.4](../../../PRD.md#64-self-improvement-with-reviewer-gate), [§6.7](../../../PRD.md#67-deployment--setup), [§7.1](../../../PRD.md#71-security--prompt-injection-defense), [§7.3](../../../PRD.md#73-self-healing--auto-recovery), [§7.4](../../../PRD.md#74-audit-trail--rollback).
- **CLAUDE.md hard rules:** #4 (capability layer — deny-path tests against real gate), #5 (orchestrator never sees raw T3), #6 (secrets in broker), #7 (no silent failures), #8 (no --no-verify).
- **Slice-2.5 sister spec:** [`docs/superpowers/specs/2026-05-27-slice-2.5-hooks-design.md`](../specs/2026-05-27-slice-2.5-hooks-design.md) — §6.2 `DevGate` (the thing this PR removes).
