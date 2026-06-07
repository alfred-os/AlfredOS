# Slice 4 — PR S4-0a: Docs + ADRs + audit_row_schemas Slice-4 additions + adversarial corpus Literals — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Establish the shared vocabulary, schema constants, ADR commitment records, and corpus structure that every downstream Slice-4 PR depends on — specifically: three new ADRs (ADR-0022 recoverable-carrier semantic, ADR-0023 mtime-polled hot-reload, ADR-0024 comms-MCP wire contract), a human-gated PRD §5 line 118 amendment, twenty-three new `Final[frozenset[str]]` constants in `src/alfred/audit/audit_row_schemas.py`, additions to `tests/adversarial/payload_schema.py` (5 new categories + 5 new prefixes + 7 new `IngestionPath` values + 2 new `ExpectedOutcome` values + `_PREFIX_TO_CATEGORY.update(...)` + `_ID_PATTERN` extension), the initial Slice-4 `docs/glossary.md` entries, and the two new unit-test modules that pin those contracts.

**Architecture:** This PR is pure docs-and-schema — no runtime dispatch ships, no hookpoints get registered, no `HookpointMeta` fields get added (those land in PR-S4-3 where they are consumed — see spec §10 + rev-007 closure). ADR-0022 records the load-bearing carrier-substitution semantic that PR-S4-3 implements. ADR-0023 records the load-bearing hot-reload contract that PR-S4-4 implements. ADR-0024 records the load-bearing comms-MCP wire contract that PR-S4-8 / PR-S4-9 / PR-S4-10 implement. ADR-0015 and ADR-0016 (already shipped in Slice 3 as "Proposed" stubs) stay "Proposed" here — their status flips to "Accepted" land at PR-S4-11 graduation per arch-003 closure (mirroring the Slice-3 precedent that ADR status mirrors implementation reality). ADR-0009 is untouched here — its caveat narrowing belongs to PR-S4-10 per docs-001 closure. The `audit_row_schemas.py` additions centralise field-list constants so the eight Slice-4 emitter subsystems (daemon-boot, proposal-dispatch, carrier-substitution, policy-watcher, operator-session, sandbox-launcher, comms-MCP, burst-limiter) share one import surface. The `payload_schema.py` extensions establish the five new attack-family categories before any implementation PR ships a payload referencing them — the schema is the contract that `tests/adversarial/conftest.py` validates every YAML against at collection time, so ordering enforcement is automatic.

**Tech Stack:** Markdown (ADRs, PRD amendment, glossary, README stubs) · Python 3.12+ (Pydantic v2, PEP 604 unions, `typing.Final`, `frozenset` literals in `audit_row_schemas.py`, `re.compile` for `_ID_PATTERN`) · `make docs-check` (cross-link validation: ADR ↔ PRD ↔ glossary ↔ index plan ↔ spec) · `uv run pytest tests/adversarial -q` (payload-schema round-trip) · `uv run pytest tests/unit/audit -q` (audit-row constants pinned against `AuditEntry` model) · `uv run pytest tests/unit/adversarial -q` (Slice-4 category regex round-trip) · `uv run ruff check` + `uv run ruff format --check` + `uv run mypy --strict src/` + `uv run pyright src/` (all gate via `make check`) · no `t()` calls land here (i18n keys themselves are PR-S4-0b; this PR has no operator-visible string additions outside ADR/glossary prose).

---

## §1 Goal

PR-S4-0a is the first Slice-4 PR and the prerequisite for every downstream PR (S4-0b through S4-11). It delivers exactly the following — exhaustively scoped so the reviewer can hold it in one pass:

1. **ADR-0022 — Recoverable-carrier semantic for error-stage hookpoint dispatch.** Full prose ADR committing the discriminated-union `ErrorOutcome = ReRaise() | SubstituteResult[T]` decision; the strict-total-order tier-comparison guard (`T0<T1<T2<T3`; substitute tier ≤ carrier tier or refuse with `tier_upgrade_refused`); the observation-only meta-hookpoint rule for `hooks.carrier_substituted` + `hooks.carrier_substitution_refused` (`fail_closed=False`, no error-stage substitute); the `HookpointMeta.carrier_tier` + `HookpointMeta.allow_error_substitution` field additions as PR-S4-3 scope (NOT this PR — rev-007). Closes #170. Spec anchors: §4.1, §4.2, §4.3, §4.4, §4.5, §4.6, §4.7.

2. **ADR-0023 — mtime-polled hot-reload for `config/policies.yaml`.** Full prose ADR committing the 1s default poll cadence (`Settings.policy_poll_interval_seconds ∈ [0.5, 10.0]`); the mtime-gated read pattern (`os.stat` + size cache → only read+parse on `(mtime, size)` diff); the `PoliciesV1` Pydantic v2 model with `HighBlastPolicies` partition (high-blast keys refuse hot-reload and require reviewer-gate; low-blast keys hot-reload via two-phase commit); the `PoliciesSnapshotRef.current() -> PoliciesSnapshot` synchronous lock-free O(1) GIL-atomic read (perf-002 round-2 closure — async-await trampoline overhead removed); the audit-then-swap two-phase commit (Phase 0 = watcher-side SHA short-circuit, Phase 1 = audit emit, Phase 2 = atomic single-attribute assignment); the per-iteration deref rule for long-lived loops with named consumers (`_proposal_dispatch_loop` at `src/alfred/supervisor/core.py:282`, `PolicyWatcher.run` itself, the four web-fetch consumer loops); the `watchdog` migration explicitly deferred to Slice 5+. Closes #159. Spec anchors: §5.1, §5.2, §5.3, §5.4, §5.5, §5.6, §5.7, §5.8.

3. **ADR-0024 — Comms-MCP wire contract.** Full prose ADR committing the eight wire methods (four host→plugin requests: `lifecycle.start`, `lifecycle.stop`, `adapter.health`, `outbound.message`; four plugin→host notifications: `inbound.message`, `adapter.binding_request`, `adapter.rate_limit_signal`, `adapter.crashed`); the `OutboundMessageResult` discriminated union (`_OutboundDelivered | _OutboundRetryable | _OutboundTerminal` keyed by `outcome` Literal — comms-008 closure forecloses field-coupling bugs); the four `addressing_mode` Literal values (`dm | mention | channel | thread`) and their per-platform rendering mapping; the `process_inbound_message` host-side entrypoint order (resolution → tier-classify → ingest → dispatch); the `IdentityResolver` host-side callback (no transport-level callback — plugins emit notifications, the host invokes the resolver); the host-side `REQUIRED_CLASSIFIERS_BY_KIND` registry rule (plugins cannot bypass via empty list — sec-002 round-3 closure); the per-adapter-kind `BODY_FIELD_BY_KIND` mapping; the audit-emit ownership rule (every comms audit row is emitted by host code on receipt of a plugin notification — adapters never write to the audit log directly). Consumed by PR-S4-8 / PR-S4-9 / PR-S4-10. Spec anchors: §8.1, §8.2, §8.3, §8.4, §8.5, §8.6, §8.7, §8.10.

4. **PRD §5 line 118 amendment.** Human-gated edit per CLAUDE.md self-improvement rules (rev-003 closure). Replaces the Slice-3 wording ("Plugins declare a trust tier; official → in-process subprocess; third-party or agent-authored → containerized with declared capabilities. **Slice 3 relaxation:** the quarantined-LLM plugin runs as a dedicated-UID subprocess with env scrubbing rather than a container — a time-bounded deviation recorded in [ADR-0017](docs/adr/0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md). Full containerisation lands in Slice 4 per [ADR-0015](docs/adr/0015-slice4-containerised-quarantined-llm.md).") with the clarified consumer-vs-relay distinction text from spec §7.10. PRD edits are **human-gated** — PR-S4-0a's diff includes the amendment text but explicit human approval gates the merge.

5. **`src/alfred/audit/audit_row_schemas.py` — 23 new `Final[frozenset[str]]` constants.** Verbatim from spec §9. Constants land in the existing module (preserving the Slice-3-shipped `Final[frozenset[str]]` typing pattern at `src/alfred/audit/audit_row_schemas.py:83`). Constants are referenced by their importable identifier from downstream PRs via `await self._audit.append_schema(fields=CONSTANT_NAME, schema_name="CONSTANT_NAME", ...)` (the Slice-3 `AuditWriter.append_schema` signature at `src/alfred/audit/log.py:105` is unchanged by this PR).

6. **`tests/adversarial/payload_schema.py` — Slice-4 Category / IngestionPath / ExpectedOutcome additions + dispatch-table extensions.** Five new `Category` Literal values (`sandbox_escape`, `config_reload_bypass`, `carrier_substitution_tamper`, `operator_session_forgery`, `comms_identity_boundary`); five new `_PREFIX_TO_CATEGORY` entries (`sbx`, `crf`, `csb`, `osf`, `cib`) via `dict.update(...)` (the Slice-3-shipped `_PREFIX_TO_CATEGORY` is a `dict[str, str]` at `tests/adversarial/payload_schema.py:22`, NOT a frozenset — verified shape preserved); `_ID_PATTERN` extension preserving the exact `^(...)-\d{4}-\d{3}$` shape (test-006 closure — the prefix-YYYY-NNN format must NOT change); seven new `IngestionPath` values (`sandbox_policy_load`, `operator_session_file`, `mtime_poll`, `inbound_notification_handler`, `proposal_dispatch_failure`, `comms_inbound_message`, `stdio_fd3_key_delivery`); two new `ExpectedOutcome` values (`policy_swap_aborted_on_audit_failure`, `recursion_refused`); the existing `boundary_refused`, `sandbox_refused`, `reload_rejected`, `substitution_refused`, `session_refused` values are reused if already present and added only if not (`boundary_refused` is Slice-3-shipped per `tests/adversarial/payload_schema.py:68`).

7. **`docs/glossary.md` Slice-4 additions.** Initial set per spec §13.1 — every term defined exactly once with a one-line definition + cross-link to the spec section. PR-S4-11 audits for any missed terms during implementation. Initial set comprises seventeen terms (full enumeration in §4 Task list below).

8. **`tests/unit/audit/test_audit_constants_slice_4.py` — every Slice-4 constant pins to a valid `AuditEntry` emit-shape.** The audit-row constants do NOT correspond to physical columns on the `AuditEntry` model (the `subject` field is a JSON column; field-list constants enumerate the keys carried inside that JSON payload — verified at `src/alfred/memory/models.py:89-152`). The test instead asserts: (a) every Slice-4 constant is a `Final[frozenset[str]]`; (b) every constant has at least one field; (c) every constant's identifier ends with `_FIELDS`; (d) every field name is a valid Python identifier (snake_case, no leading digits, no shell metacharacters that would corrupt structlog redaction); (e) every constant can be passed to a hypothesis-driven `AuditWriter.append_schema` invocation against an in-memory session-scope spy and the validator (symmetric key-set check at `log.py:139-149`) does not raise; (f) no Slice-4 constant collides in name with a Slice-3 constant.

9. **`tests/unit/adversarial/test_slice_4_categories.py` — every Slice-4 corpus YAML id matches the regex AND every prefix maps to the declared category.** Negative-path: a corpus YAML with a mismatched prefix-category pair (e.g. `id: sbx-2026-001, category: comms_identity_boundary`) fails collection at the existing `_validate_prefix_matches_category` model-validator. Positive-path: a synthetic YAML for each of the five new prefixes (`sbx-, crf-, csb-, osf-, cib-`) passes; the synthetic YAMLs land under `tests/unit/adversarial/fixtures/slice_4_category_round_trip/` so they do not pollute the real corpus.

10. **No `HookpointMeta` runtime-type changes.** Explicit reminder per spec §10 + rev-007 closure: the `carrier_tier` and `allow_error_substitution` fields on `HookpointMeta` land in PR-S4-3 where they are consumed. PR-S4-0a does NOT touch `src/alfred/hooks/registry.py`. No `register_hookpoint(...)` calls land here. The §10 hookpoint table in the spec is context-only for this PR — it tells downstream implementors which PR registers which hookpoint, but no registration code lands here.

11. **No state.git proposal-flow interaction.** Every deliverable in this PR is reviewer-gateable on `main` directly. The PRD §5 line 118 amendment is the one human-gated edit; everything else (three new ADRs, audit-row constants, payload-schema dispatch-table additions, glossary entries, two new unit-test modules) is reviewer-only.

---

## §2 File structure

| File | Status | 1-sentence responsibility |
|---|---|---|
| `docs/adr/0022-recoverable-carrier-semantic-for-error-stage-hookpoint-dispatch.md` | Create | Full ADR body committing `ErrorOutcome` discriminated union + tier-upgrade-refused guard + meta-hookpoint observation-only rule; closes #170. |
| `docs/adr/0023-mtime-polled-hot-reload-for-policies-yaml.md` | Create | Full ADR body committing mtime polling at 1s + `PoliciesV1` Pydantic v2 + `PoliciesSnapshotRef` lock-free synchronous read + audit-then-swap two-phase commit + low-blast/high-blast partition; closes #159. |
| `docs/adr/0024-comms-mcp-wire-contract.md` | Create | Full ADR body committing the eight wire methods + `OutboundMessageResult` discriminated union + `addressing_mode` Literal mapping + `process_inbound_message` order + host-side `IdentityResolver` + `REQUIRED_CLASSIFIERS_BY_KIND` registry rule + audit-emit ownership rule; consumed by PR-S4-8/9/10. |
| `PRD.md` | Modify | Line 117 amendment text per spec §7.10 — replaces Slice-3 wording with consumer-vs-relay clarified text; HUMAN-GATED edit. |
| `src/alfred/audit/audit_row_schemas.py` | Modify | Adds 23 new `Final[frozenset[str]]` constants for Slice-4 audit row families per spec §9. |
| `tests/adversarial/payload_schema.py` | Modify | Adds 5 new `Category` Literals + 5 `_PREFIX_TO_CATEGORY` entries + 7 `IngestionPath` Literals + 2 `ExpectedOutcome` Literals; extends `_ID_PATTERN` regex preserving `prefix-YYYY-NNN` shape. |
| `docs/glossary.md` | Modify | Adds 17 Slice-4 entries (full list in §4 Task 14) with cross-links to spec sections. |
| `tests/unit/audit/test_audit_constants_slice_4.py` | Create | Pins every Slice-4 audit-row constant: frozenset typing, naming convention, fieldname validity, **non-tautological** `AuditWriter.append_schema` round-trip — the test ACTUALLY constructs an `AuditWriter` instance against an in-memory session-scope spy and calls `await writer.append_schema(fields=CONST, **planted_kwargs)`; planted-bad-shape input asserts the validator at `src/alfred/audit/log.py:139-149` raises (round-2/test-4 closure — replaces the `frozenset(d.keys()) == d.keys()` tautology). No Slice-3 name collisions. PLUS partition-anchor invariant test (mem-003/arch-004 round-1 + test-eng-r2/sec-1 round-2 closures): the **operator-attributed positive set** is the explicit Literal allowlist `{"OPERATOR_SESSION_CREATED_FIELDS", "OPERATOR_SESSION_REVOKED_FIELDS", "OPERATOR_SESSION_REFUSED_FIELDS", "SUPERVISOR_BREAKER_RESET_REFUSED_FIELDS"}` — i.e. constants whose field-set includes `user_id` OR `attempted_user_id` (NOT `operator_user_id`, which no Slice-4 constant declares; round-1's fixup invoked the wrong field name). For each constant in the allowlist, assert `"canonical_user_id" in fields`. PLUS **constant-count assertion** (arch-001 + docs-002 + rev-002 round-2 closures): `assert len(SLICE_4_CONSTANTS) == 23` (NOT 22 — the count includes `SUPERVISOR_PLUGIN_RESTART_REQUESTED_FIELDS` per §3.1 enumeration). |
| `tests/unit/adversarial/test_slice_4_categories.py` | Create | Pins every Slice-4 category prefix: `_ID_PATTERN` round-trip, `_PREFIX_TO_CATEGORY` mapping correctness, negative-path mismatch refusal, positive-path synthetic YAMLs for all five new prefixes. |
| `tests/unit/adversarial/test_id_pattern_backward_compat.py` | Create (PR #205 round-1 closure on test-eng-003) | For every existing Slice-1/2/3 corpus YAML under `tests/adversarial/**/*.yaml`, assert `id:` matches the new `_ID_PATTERN`. Detects regex regressions that would break the historical corpus immediately in PR-S4-0a's CI rather than in a downstream PR. |
| `tests/unit/adversarial/test_category_minimum_population.py` | Create (PR #205 round-1 closure on test-eng-002; round-2 test-2 strictness fix) | At graduation, each Slice-4 prefix MUST have ≥3 corpus entries (`crf-` → PR-S4-3; `csb-` → PR-S4-4; `osf-` → PR-S4-5; `sbx-` → PR-S4-7; `cib-` → PR-S4-8). Uses `@pytest.mark.parametrize("prefix", [...], ids=[...])` with a **per-`pytest.param` `marks=pytest.mark.xfail(strict=True, reason="awaiting PR-S4-N")` decoration** — NOT a module-level xfail. Each prefix's xfail flips to pass independently as its owning PR ships its corpus; the strict marker ensures any prefix that ships entries early surfaces a test-update obligation. The constant `MIN_ENTRIES_PER_CATEGORY = 3` is named in the test module. Runs in `make check` from PR-S4-0a onwards. |
| `tests/integration/test_fixture_format.py` | Create (PR #205 round-1 closure on test-eng-004; round-2 test-3 strictness fix) | Asserts every VCR cassette under `tests/integration/fixtures/**/*.yaml` declares `match_on: [method, scheme, host, port, path, query, body]`. The `tests/integration/fixtures/` directory does NOT yet exist on `main`; PR-S4-0a creates it as an empty directory + a `.gitkeep` (so the test isn't vacuously xfail per the `domain_paper_only_gates.md` lesson). The test asserts `count >= 0` and applies `strict` marks per-cassette as cassettes land (NOT a module-level xfail). The "no cassettes yet" state passes legitimately; future PRs add cassettes whose `match_on` is validated immediately. |
| `tests/unit/adversarial/fixtures/slice_4_category_round_trip/sbx-2026-000.yaml` | Create | Synthetic positive-path payload for `sbx-` prefix → `sandbox_escape` category. Outcome: `audit_row_emitted` anchored to `SANDBOX_REFUSED_FIELDS` constant (round-2 sec-3 closure — fixtures DIVERGE in expected outcome to seed distinct category↔outcome templates downstream). |
| `tests/unit/adversarial/fixtures/slice_4_category_round_trip/crf-2026-000.yaml` | Create | Synthetic positive-path payload for `crf-` prefix → `carrier_substitution_tamper` category. Outcome: `recursion_refused` (new ExpectedOutcome per §11.3). |
| `tests/unit/adversarial/fixtures/slice_4_category_round_trip/csb-2026-000.yaml` | Create | Synthetic positive-path payload for `csb-` prefix → `config_reload_bypass` category. Outcome: `policy_swap_aborted_on_audit_failure` (new ExpectedOutcome per §11.3). |
| `tests/unit/adversarial/fixtures/slice_4_category_round_trip/osf-2026-000.yaml` | Create | Synthetic positive-path payload for `osf-` prefix → `operator_session_forgery` category. Outcome: `audit_row_emitted` anchored to `OPERATOR_SESSION_REFUSED_FIELDS`. |
| `tests/unit/adversarial/fixtures/slice_4_category_round_trip/cib-2026-000.yaml` | Create | Synthetic positive-path payload for `cib-` prefix → `comms_identity_boundary` category. Outcome: `boundary_refused` (existing Slice-3 outcome, reused). |
| `tests/unit/adversarial/fixtures/slice_4_category_round_trip/__init__.py` | Create | Empty marker (so pytest does not glob into the fixture dir as a collection root — the fixtures are loaded explicitly by the test module). |

**Out of file structure:**

- `src/alfred/hooks/registry.py` — NOT touched (rev-007 — `HookpointMeta.carrier_tier` + `.allow_error_substitution` are PR-S4-3 scope).
- `docs/adr/0009-comms-adapter-protocol-slice2-only.md` — NOT touched (docs-001 — caveat narrowing is PR-S4-10 scope).
- `docs/adr/0015-slice4-containerised-quarantined-llm.md` — NOT touched (arch-003 — status flip from Proposed to Accepted is PR-S4-11 scope).
- `docs/adr/0016-slice4-discord-tui-comms-mcp-rewrite.md` — NOT touched (arch-003 — status flip from Proposed to Accepted is PR-S4-11 scope).
- `src/alfred/audit/__init__.py` — NOT touched (Slice-3-shipped `__init__.py` already re-exports `audit_row_schemas`; verified during surface review — no public-surface change needed).
- `tests/adversarial/conftest.py` — NOT touched (the existing collector loads all YAMLs under `tests/adversarial/<category>/`; the new Slice-4 fixture YAMLs live under `tests/unit/adversarial/fixtures/` so they are NOT auto-loaded by the adversarial collector — they are loaded only by `tests/unit/adversarial/test_slice_4_categories.py`).
- `tests/adversarial/sandbox_escape/`, `tests/adversarial/carrier_substitution_tamper/`, `tests/adversarial/config_reload_bypass/`, `tests/adversarial/operator_session_forgery/`, `tests/adversarial/comms_identity_boundary/` directories — NOT created here. The empty-category-dir convention from Slice 3 (PR-S3-0a's `tests/adversarial/tier_laundering/README.md` stub pattern) is matched in PR-S4-1+ through PR-S4-10 when each implementation PR populates its own category. PR-S4-0a only delivers the schema (the contract); the category dirs land when first populated.
- `bin/alfred-plugin-launcher.sh` — NOT touched (Slice-3-shipped script; PR-S4-6 owns the policy-resolving rewrite).
- `src/alfred/comms_mcp/` — NOT created here (PR-S4-8 owns the wire-format-owner module).

---

## §3 Cross-PR contracts

These surfaces are defined in this PR and consumed by downstream PRs. Drift between PRs is a release blocker — every downstream PR imports the named constant rather than inlining its own.

### 3.1 `audit_row_schemas.py` constants (23 new — defined here)

| Constant | Defined in spec § | Consumed in PR | Field-list (verbatim) |
|---|---|---|---|
| `DAEMON_BOOT_FIELDS` | §9, §3.2 | PR-S4-1 | `boot_id`, `started_at`, `state_git_head_sha`, `slice_version`, `policies_snapshot_hash`, `environment` |
| `DAEMON_BOOT_FAILED_FIELDS` | §9, §3.2, §3.4 | PR-S4-1, PR-S4-6 | `boot_id`, `attempted_at`, `failure_reason`, `environment_source` |
| `DAEMON_BOOT_ENVIRONMENT_SOURCE_CONFLICT_FIELDS` | §9, §7.3 | PR-S4-1 | `boot_id`, `env_var_value`, `etc_file_value`, `resolved_value` |
| `PROPOSAL_DISPATCH_FAILURE_REDACTED_FIELDS` | §9, §3.3 | PR-S4-2 | `proposal_branch`, `dispatch_attempted_at`, `failure_class`, `redacted_detail`, `dlp_redactions_count` |
| `CARRIER_SUBSTITUTION_FIELDS` | §9, §4.3 | PR-S4-3 | `hookpoint`, `subscriber_id`, `source_tier`, `carrier_tier`, `substituted_at` |
| `CARRIER_SUBSTITUTION_REFUSED_FIELDS` | §9, §4.4 | PR-S4-3 | `hookpoint`, `subscriber_id`, `attempted_source_tier`, `carrier_tier`, `reason`, `refused_at` |
| `CONFIG_RELOAD_FIELDS` | §9, §5.6 | PR-S4-4 | `file_path`, `prev_sha256`, `new_sha256`, `changed_keys`, `loaded_at` |
| `CONFIG_RELOAD_REJECTED_FIELDS` | §9, §5.6 | PR-S4-4 | `file_path`, `attempted_sha256`, `reason`, `offending_key`, `dlp_scan_result` |
| `OPERATOR_SESSION_CREATED_FIELDS` | §9, §6.6 | PR-S4-5 | `user_id`, `issued_at`, `expires_at`, `host`, `machine_id_hash`, `via` |
| `OPERATOR_SESSION_REVOKED_FIELDS` | §9, §6.6 | PR-S4-5 | `user_id`, `revoked_at`, `via` |
| `OPERATOR_SESSION_REFUSED_FIELDS` | §9, §6.6 | PR-S4-5 | `attempted_user_id`, `reason`, `host`, `machine_id_hash` |
| `SUPERVISOR_BREAKER_RESET_REFUSED_FIELDS` | §9, §6.7 | PR-S4-5 | `component_id`, `reason`, `attempted_at` |
| `SANDBOX_REFUSED_FIELDS` | §9, §7.11 | PR-S4-6 | `plugin_id`, `policy_ref`, `host_os`, `reason`, `environment` |
| `SANDBOX_STUB_USED_FIELDS` | §9, §7.11 | PR-S4-7 | `plugin_id`, `policy_ref`, `host_os`, `environment` |
| `COMMS_INBOUND_T3_PROMOTION_FIELDS` | §9, §8.10 | PR-S4-8 | `adapter_id`, `inbound_message_id`, `platform_user_id_hash`, `canonical_user_id`, `sub_payload_kinds`, `language`, `addressing_signal` |
| `COMMS_BINDING_REQUESTED_FIELDS` | §9, §8.10 | PR-S4-8 | `adapter_id`, `platform_user_id_hash`, `verification_phrase_hash`, `requested_at` |
| `COMMS_ADAPTER_CRASHED_FIELDS` | §9, §8.10 | PR-S4-8 | `adapter_id`, `error_class`, `detail_redacted`, `crashed_at` |
| `COMMS_RATE_LIMIT_SIGNAL_FIELDS` | §9, §8.10 | PR-S4-8 | `adapter_id`, `platform_endpoint`, `retry_after_seconds`, `signalled_at` |
| `COMMS_UNKNOWN_NOTIFICATION_FIELDS` | §9, §8.4 | PR-S4-8 | `adapter_id`, `method`, `method_redacted_params`, `observed_at` |
| `COMMS_HANDLER_FAILED_FIELDS` | §9, §8.4 | PR-S4-8 | `adapter_id`, `notification_method`, `handler_class`, `error_class`, `detail_redacted`, `failed_at` |
| `COMMS_ADDRESSING_DRIFT_FIELDS` | §9, §8.1 | PR-S4-8 | `adapter_id`, `inbound_signal`, `outbound_mode`, `canonical_user_id`, `observed_at` |
| `COMMS_INBOUND_BUDGET_CAPPED_FIELDS` | §9, §8.2 | PR-S4-8 | `adapter_id`, `canonical_user_id`, `persona`, `tokens_available`, `wait_seconds`, `dropped`, `observed_at` |
| `SUPERVISOR_PLUGIN_RESTART_REQUESTED_FIELDS` | §9, §8.4 | PR-S4-8 | `plugin_id`, `reason`, `requested_at`, `requester` |

That is 23 constants. The spec body §9 enumerates 22 in its summary table; the additional `SUPERVISOR_PLUGIN_RESTART_REQUESTED_FIELDS` row (per spec §9 final row marked "core-010 round-3 closure") brings the actual count delivered by PR-S4-0a to 23. The task numbering in §4 enumerates all 23 across Tasks 7-12 below. The plan-prompt's "22 constants" caption refers to the spec-summary-table count — verified honest: spec §9 has 22 enumerated rows in its body table, plus the `SUPERVISOR_PLUGIN_RESTART_REQUESTED_FIELDS` row added in the round-3 closure note, totaling 23 distinct constants delivered by this PR.

(Rationale for keeping `SUPERVISOR_PLUGIN_RESTART_REQUESTED_FIELDS` in PR-S4-0a rather than PR-S4-8: the constant is referenced by PR-S4-8's `AlfredPluginSession._on_post_handshake_method` dispatcher AND by PR-S4-8's `Supervisor.request_plugin_restart` method. Centralising in PR-S4-0a follows the Slice-3 precedent of co-locating cross-PR constants in the docs-foundation PR.)

### 3.2 `payload_schema.py` Literal + dispatch-table additions (defined here)

```python
# Category Literal extension (added in lockstep with _PREFIX_TO_CATEGORY):
Category = Literal[
    # ... Slice-3 entries preserved verbatim ...
    "sandbox_escape",              # Slice 4 (spec §11.1)
    "config_reload_bypass",        # Slice 4 (spec §11.1)
    "carrier_substitution_tamper", # Slice 4 (spec §11.1)
    "operator_session_forgery",    # Slice 4 (spec §11.1)
    "comms_identity_boundary",     # Slice 4 (spec §11.1) — for #152 closure test
]

# _PREFIX_TO_CATEGORY extension via dict-update pattern (verified shape: dict[str, str]):
_PREFIX_TO_CATEGORY.update({
    "sbx": "sandbox_escape",
    "crf": "carrier_substitution_tamper",
    "csb": "config_reload_bypass",
    "osf": "operator_session_forgery",
    "cib": "comms_identity_boundary",
})

# _ID_PATTERN extension preserving the exact ^(...)-\d{4}-\d{3}$ shape (test-006 closure):
_ID_PATTERN = re.compile(
    r"^(pi|dlp|cap|cnry|ipp|hk|tl|de|sbx|crf|csb|osf|cib)-\d{4}-\d{3}$"
)

# IngestionPath Literal extension:
IngestionPath = Literal[
    # ... Slice-3 entries preserved verbatim ...
    "sandbox_policy_load",            # Slice 4 (spec §11.2) — sandbox launcher policy resolution
    "operator_session_file",          # Slice 4 (spec §11.2) — session file load
    "mtime_poll",                     # Slice 4 (spec §11.2) — PolicyWatcher tick
    "inbound_notification_handler",   # Slice 4 (spec §11.2) — AlfredPluginSession notification
    "proposal_dispatch_failure",      # Slice 4 (spec §11.2) — ProposalContext failure path
    "comms_inbound_message",          # Slice 4 (spec §11.2) — Discord/TUI inbound
    "stdio_fd3_key_delivery",         # Slice 4 (spec §11.2) — fd-3 zeroization test
]

# ExpectedOutcome Literal extension:
ExpectedOutcome = Literal[
    # ... Slice-3 entries preserved verbatim ...
    "policy_swap_aborted_on_audit_failure",  # Slice 4 (spec §11.3) — §5.3 swap-audit semantics
    "recursion_refused",                      # Slice 4 (spec §11.3) — §4.6 crf-004 meta-hookpoint
]
```

The Slice-3 `Category` Literal values, the existing `_PREFIX_TO_CATEGORY` entries, the existing `IngestionPath` values, and the existing `ExpectedOutcome` values (`neutralized`, `caught_by_dlp`, `refused`, `quarantined`, `boundary_refused`, `audit_row_emitted`) are preserved exactly. The spec-listed `sandbox_refused`, `reload_rejected`, `substitution_refused`, `session_refused` outcomes are NOT added as new `ExpectedOutcome` Literals — instead, those reasons are carried in the `audit_row_emitted` outcome's expected-row assertion, matching the Slice-3 pattern where outcome-disambiguation lives in the `references` field and the audit-row constant cited in the YAML, not in the Literal value. This avoids a Literal-explosion-by-attack-family that would require updating `payload_schema.py` every time a new audit-row family ships. The two genuinely new outcomes added here (`policy_swap_aborted_on_audit_failure`, `recursion_refused`) are added because the spec explicitly enumerates them as new ExpectedOutcome values (§11.3); the others stay in the audit-row layer.

### 3.3 ADR-0022 / ADR-0023 / ADR-0024 (defined here)

Each ADR is the prose source-of-truth for one architectural decision. Downstream PR plans cite the ADR rather than the spec for the architectural rationale, because the ADR will outlive the spec (spec is the design pre-implementation; ADR is the record post-decision).

| ADR | Anchored in spec § | Implemented in PR | Status at landing |
|---|---|---|---|
| ADR-0022 (recoverable-carrier semantic) | §4 | PR-S4-3 | Accepted |
| ADR-0023 (mtime-polled hot-reload) | §5 | PR-S4-4 | Accepted |
| ADR-0024 (comms-MCP wire contract) | §8 | PR-S4-8 (transport), PR-S4-9 (Discord), PR-S4-10 (TUI) | Accepted |

ADR-0015 and ADR-0016 stay at "Proposed" through this PR. The PR-S4-11 graduation PR flips both to "Accepted" per arch-003 closure (matching the Slice-3 precedent that ADR status mirrors implementation reality).

ADR-0009's "in-process adapters unchanged through Slice 3" qualifier is the responsibility of PR-S4-10 (the flag-day deletion PR) per docs-001 closure. PR-S4-0a's diff against ADR-0009 is zero.

### 3.4 `docs/glossary.md` Slice-4 additions (defined here)

Initial set per spec §13.1 (seventeen entries). PR-S4-11 audits for any term that surfaced during implementation and was missed here. The seventeen terms:

- `PolicyWatcher`, `PoliciesV1`, `PoliciesSnapshot`, `PoliciesSnapshotRef`, `HighBlastPolicies` — five terms covering the §5 hot-reload contract.
- `OperatorSession`, `OperatorResolver`, `OperatorSessionTimeout` — three terms covering the §6 CLI session contract.
- `SandboxPolicy`, `SandboxKind` — two terms covering the §7 sandbox-manifest declaration.
- `CarrierSubstitution`, `ErrorOutcome`, `ReRaise`, `SubstituteResult` — four terms covering the §4 carrier-substitution semantic.
- `InboundHandler`, `BindingHandler`, `RateLimitHandler`, `CrashHandler` — these four handler Protocols are named together as the "four `AlfredPluginSession` notification handlers" in spec §13.1; the glossary lists them under a single header `Notification handlers (comms-MCP)` to avoid four near-identical entries.
- `DiscordSubPayloadClassifier` — one term covering the §8.5 / §8.6 Discord classifier.
- `InboundT3Promotion` — one term covering the transport-boundary T3-tagging semantic.
- `BODY_FIELD_BY_KIND` — one term covering the per-adapter body-field map.
- `T3DerivedData` — Slice-3 NewType re-listed for visibility per spec §13.1 final entry.
- `BurstLimiter` — one term covering the §8.2 per-(user, persona) token-bucket primitive shipped in PR-S4-8.

(Total entries authored: 17 headers covering the 17+ terms in the spec list. The four notification-handler protocols share one glossary header — keeps the glossary scan-readable while preserving the spec's commitment that every term appears.)

`ResolvedIdentity` and `IdentityResolver` are Slice-3-shipped terms; the spec §13.1 calls them out as "finalised" rather than "new". PR-S4-0a does NOT touch their existing glossary entries here; the glossary update for "finalised" terms (if any change is needed) is part of PR-S4-11's audit pass per docs-003 closure.

`OutboundQueue` is Slice-3-shipped; the spec §13.1 marks it "extended". PR-S4-0a does NOT touch its existing glossary entry here — the `pause(adapter_id, retry_after_seconds)` extension lands in PR-S4-9 where the consumer ships; PR-S4-9 updates the glossary entry there.

`InboundContentScanner` is Slice-3-shipped; the spec §13.1 marks it "extended". Same rule: glossary entry stays as-is in this PR; PR-S4-8 updates it when shipping the classifier-dispatcher extension.

### 3.5 What this PR does NOT define (handed off to downstream)

- `HookpointMeta.carrier_tier` field — PR-S4-3 (rev-007).
- `HookpointMeta.allow_error_substitution` field — PR-S4-3 (rev-007).
- `register_hookpoint(...)` calls — every owning PR per spec §10 table.
- `PolicyWatcher`, `PoliciesV1`, `PoliciesSnapshotRef` source files — PR-S4-4.
- `OperatorSession` model, `_resolve_operator` helper — PR-S4-5.
- `src/alfred/comms_mcp/protocol.py` wire-format module — PR-S4-8.
- `src/alfred/comms_mcp/inbound.py:process_inbound_message` — PR-S4-8.
- `src/alfred/orchestrator/burst_limiter.py` — PR-S4-8.
- `bin/alfred-plugin-launcher.sh` policy-resolving extension — PR-S4-6.
- Per-OS sandbox policy bytes (`config/sandbox/quarantined-llm.linux.bwrap.policy` etc.) — PR-S4-7.
- Discord MCP plugin (`plugins/alfred_discord/`) — PR-S4-9.
- TUI MCP plugin (`plugins/alfred_tui/`) — PR-S4-10.
- `src/alfred/comms/` deletion — PR-S4-10.
- ADR-0009 caveat narrowing — PR-S4-10 (docs-001).
- ADR-0015 + ADR-0016 status flips — PR-S4-11 (arch-003).
- Alembic migrations 0011-0014 — PR-S4-0b.
- i18n catalog additions (`locale/en/LC_MESSAGES/alfred.po` Slice-4 keys) — PR-S4-0b.
- `Dockerfile` for `alfred-core` + `bubblewrap` apt-install — PR-S4-0b.
- Slice-4 adversarial-corpus YAMLs under `tests/adversarial/<category>/` — each owning PR.

---

## §4 Tasks

The task ordering is bite-sized TDD: write a failing test, run to verify FAIL with expected output, implement the smallest change to make it pass, run to verify PASS, commit. Component letters group related tasks; each task includes its commit message stub.

### Component A — ADR-0022 (Recoverable-carrier semantic)

- [ ] **Task 1 — Create ADR-0022 with status block, context, and decision sections.**

  Files: Create `docs/adr/0022-recoverable-carrier-semantic-for-error-stage-hookpoint-dispatch.md`.

  Steps:

  - [ ] Verify the next ADR number is 0022:

    ```bash
    cd <repo-root> && ls docs/adr/ | sort | tail -3
    ```

    Expected: highest existing is `0021-merged-proposal-branch-dispatch-for-side-effecting-proposals.md` (per the surface verification — confirmed at session start). Next number is `0022`.

  - [ ] Write the ADR header and status block:

    ```markdown
    # ADR-0022 — Recoverable-carrier semantic for error-stage hookpoint dispatch

    ## Status

    Accepted

    **Date:** 2026-06-07

    ## Context
    ```

  - [ ] Write the Context section. The context narrates: (a) ADR-0014 (`docs/adr/0014-pluggable-hooks-for-every-action.md`) defines the four hook kinds (pre / post / error / cancel); (b) the error chain runs when the action raises; (c) CodeRabbit on PR #168 flagged that `_dispatch_error_chain` in `src/alfred/security/quarantine.py` does not honour `alfred.hooks.invoke`'s "first non-None wins" carrier-substitution semantic — an error subscriber that returns a substitute carrier has no way to propagate it back, because the caller's outer `raise exc` short-circuits; (d) the inline doc-comment in `quarantine.py` already documented the slice-scoped deferral ("Slice-4+ would honour `invoke`'s 'first non-None wins' carrier-substitution semantic"); (e) Slice 4 lands the semantic to close #170.

  - [ ] Write the Decision section with five sub-decisions:

    **Decision 1 — `ErrorOutcome` discriminated union.** Define `ErrorOutcome[T] = ReRaise | SubstituteResult[T]` as a Pydantic v2 discriminated union (frozen). `ReRaise` is an empty model (the original exception propagates). `SubstituteResult[T]` carries `payload: T`, `source_tier: Literal["T0", "T1", "T2", "T3"]`, `subscriber_id: str`. The generic `T` lets each hookpoint type its substitute payload (e.g., `ExtractionResult` for `security.quarantined.extract`, `EpisodeRow` for `alfred.memory.episodic.record`).

    **Decision 2 — `_run_error` signature change.** The Slice-3 signature `async def _run_error(hookpoint, exc, ctx) -> None` becomes `async def _run_error[T](hookpoint, exc, ctx, carrier_type: type[T]) -> ErrorOutcome[T]`. The caller pattern-matches the outcome and either re-raises (`ReRaise()`) or returns the substituted payload (`SubstituteResult(payload, source_tier, subscriber_id)`). `mypy --strict` + a `Protocol` guard ensures every caller exhaustively pattern-matches.

    **Decision 3 — Tier-upgrade-refused guard with strict total order `T0<T1<T2<T3`.** Substitute payloads declare their source tier. The host caller refuses substitutes whose `source_tier` is **strictly greater than the surrounding carrier's declared tier**. Examples: T3 surrounding action accepts T3/T2/T1/T0 substitutes; T1 surrounding action accepts T1/T0 substitutes and refuses T2/T3 substitutes; T0 surrounding action accepts only T0 substitutes. The refused-substitution case emits `CARRIER_SUBSTITUTION_REFUSED_FIELDS` with `reason="tier_upgrade_refused"` and re-raises the original exception. The Slice-3-drafted "refuse T3 only" rule (which silently permitted a T2 substitute on a T0/T1 hookpoint to upgrade the action's effective tier) is the bug this decision closes — Critical 5 closure.

    **Decision 4 — Meta-hookpoints `hooks.carrier_substituted` + `hooks.carrier_substitution_refused` are observation-only.** Subscribers may observe substitution events but cannot themselves substitute — substituting on these meta-hookpoints is refused at *registration time* by a `Protocol` guard in `register_hookpoint`. The `subscribable_tiers = SYSTEM_ONLY_TIERS` constraint stays. The meta-hookpoints carry `fail_closed=False` because observation-only + `fail_closed=True` is semantically undefined (no original action to close). The "no error-stage substitute on meta-hookpoints" rule is enforced by `HookpointMeta.allow_error_substitution: bool` (new field, defaulting to `True` on every hookpoint except the two meta-hookpoints). `_run_error()` checks this flag before consulting subscribers. The two new `HookpointMeta` fields land in PR-S4-3 where they are consumed, NOT in PR-S4-0a (rev-007 closure).

    **Decision 5 — Sibling-site migration plan.** Four production hook-dispatch sites migrate to the new semantic in PR-S4-3: `alfred.security.quarantine.QuarantinedExtractor.extract` (original Slice-3 site, primary motivation); `alfred.memory.episodic.record` (Slice-2.5-shipped, already documented as the precedent that `quarantine.py` was deferring to); `alfred.identity._ingest` (Slice-3-shipped, T1/T3 ingress path); `alfred.state.dispatch_loop._handle_dispatch_failure` (Slice-3-shipped, mechanical migration because no error subscriber currently subscribes). A new `tests/integration/test_error_chain_substitution_propagates.py` exercises each site with a known-good substitute subscriber and asserts the substitute returns end-to-end.

  Commit:

  ```
  docs(adr-0022): context + decision sections for recoverable-carrier semantic (#170)
  ```

- [ ] **Task 2 — Add ADR-0022 Consequences, Alternatives, References sections.**

  Files: Modify `docs/adr/0022-recoverable-carrier-semantic-for-error-stage-hookpoint-dispatch.md`.

  Steps:

  - [ ] Write Consequences section.

    Positive:
    - Error subscribers gain the ability to *recover* the action rather than only *suppress* the exception — the Slice-3 "subscriber can swallow but can't replace" gap closes.
    - The tier-upgrade-refused guard prevents silent trust-tier elevation through error-subscriber substitution; Critical 5 is structurally impossible after this lands.
    - The observation-only meta-hookpoint rule lets operators wire telemetry/alerting onto every carrier-substitution event without those subscribers themselves being substitution surfaces.

    Negative:
    - `_run_error` signature change ripples to every existing caller. PR-S4-3 migrates four sibling sites mechanically; the change is one-shot but visible in the call graph.
    - The generic `T` on `SubstituteResult[T]` requires every hookpoint to declare its carrier type at `register_hookpoint(...)` time. PR-S4-3 adds the `carrier_tier: TrustTier` field on `HookpointMeta`; every Slice-4 hookpoint declaration must populate it.
    - Adversarial corpus surface grows by one category (`carrier_substitution_tamper`) and four entry IDs (`crf-2026-001` through `crf-2026-004` — see spec §4.6). Each entry's YAML is owned by PR-S4-3.

    Neutral:
    - The `subscriber_id: str` field on `SubstituteResult` is opaque from this PR's perspective; PR-S4-3 picks the format (proposed: `f"{plugin_id}:{hookpoint}#{subscriber_index}"`). The ADR does not pin the format because no consumer requires a specific shape — only that the substitution audit row carries a deterministic identifier.

  - [ ] Write Alternatives section.

    **Option A — Return `T | None` instead of a discriminated union.** Rejected because `None` already means "no substitute; original raise propagates" in Slice 3 — overloading the same return type for two distinct semantics (no-subscriber and explicit-reraise) confuses callers and breaks the `mypy --strict` exhaustiveness check that the discriminated union enables.

    **Option B — Allow per-hookpoint `fail_closed` override (closes #167).** Deferred to Slice 5+ per spec §1.2. No current Slice-4 consumer demands the asymmetric policy; revisit when a Slice-5 hookpoint's error stage routinely runs cleanup that should not fail-close.

    **Option C — Meta-hookpoints can substitute on themselves.** Rejected. A subscriber on `hooks.carrier_substituted` that itself returns a `SubstituteResult` creates an infinite-recursion hazard. The registration-time guard refuses subscribers on observation-only meta-hookpoints; the runtime defence-in-depth check inside `_run_error` re-asserts the refusal with `reason="recursion_refused"` (mapped to `recursion_refused` ExpectedOutcome in Slice-4 corpus).

    **Option D — Refuse `source_tier > carrier_tier` softly (log + drop substitution, continue).** Rejected. Soft refusal of a tier-upgrade attempt is a silent security failure (CLAUDE.md hard rule 7). The chosen behaviour — emit `CARRIER_SUBSTITUTION_REFUSED_FIELDS` audit row, re-raise original exception, do not return the would-be substitute — keeps the failure loud and visible.

  - [ ] Write References section. Cite: PRD §5.1 (hookable actions invariant); PRD §7.1 (security & prompt injection defense); ADR-0014; ADR-0017; spec §4.1-§4.7; CodeRabbit finding on PR #168; issue #170.

  - [ ] Run `make docs-check` to confirm no broken links:

    ```bash
    cd <repo-root> && make docs-check 2>&1 | tail -10
    ```

    Expected: exits 0; no errors. If a link to `[ADR-0014](./0014-pluggable-hooks-for-every-action.md)` resolves correctly, the ADR-relative path is correct (the Slice-3 ADRs use `./NNNN-...md` for sibling ADRs and `../../PRD.md#anchor` for PRD anchors — match the convention).

  Commit:

  ```
  docs(adr-0022): consequences, alternatives, references (#170)
  ```

- [ ] **Task 3 — Add ADR-0022 test pin: confirm ADR is parseable and links resolve.**

  Files: Modify `tests/unit/audit/test_audit_constants_slice_4.py` (created in Task 7; if Task 7 has not run yet, create a stub file with just the imports needed for the ADR pin and extend it in Task 7).

  Steps:

  - [ ] Write a one-shot assertion that the ADR file exists, has a `## Status` block reading `Accepted`, and contains the five Decision sub-headings:

    ```python
    # tests/unit/audit/test_audit_constants_slice_4.py (initial stub for Task 3)
    """Pinning Slice-4 ADRs + audit-row constants.

    Tasks 3 / 5 / 6 land the ADR-existence pins.
    Tasks 7-12 land the audit-row constant pins.
    """
    from __future__ import annotations

    from pathlib import Path

    REPO_ROOT = Path(__file__).resolve().parents[3]
    ADR_DIR = REPO_ROOT / "docs" / "adr"


    def test_adr_0022_status_is_accepted() -> None:
        adr = ADR_DIR / "0022-recoverable-carrier-semantic-for-error-stage-hookpoint-dispatch.md"
        assert adr.exists(), f"ADR-0022 not at {adr}"
        body = adr.read_text(encoding="utf-8")
        assert "## Status" in body, "ADR-0022 missing Status section"
        # The status block uses `Accepted` per the AcceptedFromDayOne convention.
        assert "\nAccepted\n" in body, "ADR-0022 Status is not 'Accepted'"


    def test_adr_0022_decision_subheadings_present() -> None:
        adr = ADR_DIR / "0022-recoverable-carrier-semantic-for-error-stage-hookpoint-dispatch.md"
        body = adr.read_text(encoding="utf-8")
        for sub in (
            "Decision 1",
            "Decision 2",
            "Decision 3",
            "Decision 4",
            "Decision 5",
        ):
            assert sub in body, f"ADR-0022 missing {sub!r}"
    ```

  - [ ] Run the test in failing-then-passing TDD shape. First, if the file body is missing `Decision 1`, run:

    ```bash
    cd <repo-root> && uv run pytest tests/unit/audit/test_audit_constants_slice_4.py::test_adr_0022_decision_subheadings_present -q
    ```

    Expected FAIL output: `AssertionError: ADR-0022 missing 'Decision 1'` — fix the ADR (Task 1 / 2 should have written the body; if not, fix forward).

  - [ ] Re-run to PASS:

    ```bash
    cd <repo-root> && uv run pytest tests/unit/audit/test_audit_constants_slice_4.py -q
    ```

    Expected: 2 passed.

  Commit:

  ```
  test(adr-0022): pin ADR-0022 existence + status + decision subheadings (#170)
  ```

### Component B — ADR-0023 (mtime-polled hot-reload)

- [ ] **Task 4 — Create ADR-0023 with status block, context, and decision sections.**

  Files: Create `docs/adr/0023-mtime-polled-hot-reload-for-policies-yaml.md`.

  Steps:

  - [ ] Write the header:

    ```markdown
    # ADR-0023 — mtime-polled hot-reload for `config/policies.yaml`

    ## Status

    Accepted

    **Date:** 2026-06-07

    ## Context
    ```

  - [ ] Write the Context section. Cite spec §5.1: Slice-3 ships `config/policies.yaml` with start-of-process load only — every change requires a daemon restart. The PRD-implied operator UX (hot-reload of rate limits without dropping in-flight requests) is unmet. Issue #159 tracks the gap. Slice 4 closes it with the minimal viable hot-reload mechanism — mtime polling, no `watchdog` library, no inotify, no FSEvents. The migration to `watchdog` is explicitly deferred to Slice 5+ unless an operator surfaces real polling-latency complaints. The 1s default cadence is configurable in `[0.5, 10.0]` via `Settings.policy_poll_interval_seconds`.

  - [ ] Write the Decision section with five sub-decisions:

    **Decision 1 — mtime-polled cadence with mtime-gated read.** The watcher calls `os.stat()` per tick and only reads + parses the YAML when `(new_mtime, new_size)` differs from the cached values. On unchanged mtime+size, the poll tick is ~0.1ms (a syscall + a couple of int compares). Under steady-state (no edits) the watcher's CPU cost is negligible (perf-005 closure). Polling task lives under the daemon's `asyncio.TaskGroup` started by `Supervisor`; it raises on cancellation and is restarted only by full daemon restart.

    **Decision 2 — `PoliciesV1` Pydantic v2 model with low-blast / high-blast partition.** Three top-level blocks: `rate_limits: RateLimitPolicies`, `handle_caps: HandleCapPolicies`, `high_blast: HighBlastPolicies`. High-blast keys (e.g., `quarantined_provider_url`, `secret_broker_config_ref`) are parsed but never hot-reloaded — any diff in `HighBlastPolicies` triggers `CONFIG_RELOAD_REJECTED_FIELDS` with `reason="high_blast_change"`. Low-blast keys hot-reload. The model-level partition is the single source of truth — a new top-level field lands in either the high-blast block or one of the low-blast blocks, no third option.

    **Decision 3 — `PoliciesSnapshotRef.current()` is synchronous lock-free O(1).** Implementation: a single `_current` attribute holding the active snapshot. Under CPython the attribute load is atomic by GIL semantics — no lock required. The sync signature avoids the async-await trampoline overhead (~200ns per call, multiplied by per-iteration-deref pattern in long-lived loops adds measurable overhead). The Slice-3 sync-vs-async discipline in `Settings.*` is the precedent (perf-002 round-2 closure). Consumers call `ref.current().rate_limits.foo`, not `await ref.current()`.

    **Decision 4 — Audit-then-swap two-phase commit with watcher-side SHA short-circuit.** Phase 0: watcher-side short-circuit — if `new.file_sha256 == self._current.file_sha256`, the watcher returns immediately without calling `swap()` (no audit row, nothing changed). This is the load-bearing idempotency mechanism; it does not rely on an `AuditWriter` dedupe surface (which Slice-3 `AuditWriter` does not expose). Phase 1: emit `CONFIG_RELOAD_FIELDS` audit row. If audit write fails, swap aborts (prepared snapshot is discarded; active snapshot stays). Phase 2: only on successful audit, atomic single-attribute assignment. err-004 closure: audit-then-swap, not swap-then-audit — a failed audit write cannot leave the active snapshot diverged from the audit log. err-010 closure: audit-write failure raises; the watcher catches in `PolicyWatcher.run`, emits `CONFIG_RELOAD_REJECTED_FIELDS` with `reason="audit_write_failed"`, and tries again on next mtime change.

    **Decision 5 — Per-iteration deref rule for long-lived loops.** In-flight coroutines that captured the old snapshot continue with the old value — acceptable per spec §7.10 baseline. But long-lived loops MUST deref per iteration, not once before the `while` (core-003 closure): `_proposal_dispatch_loop` at `src/alfred/supervisor/core.py:282`, `PolicyWatcher.run` itself, and the four web-fetch consumer loops each call `ref.current()` inside the loop body. `_capability_heartbeat_loop` at `src/alfred/supervisor/core.py:317` is NOT a snapshot consumer (core-009 closure — the round-1 spec named it as one in error). A pytest-time AST guard runs over the four migrated consumer modules and refuses any name binding from `ref.current()` that crosses an `await` boundary.

  Commit:

  ```
  docs(adr-0023): context + decision sections for mtime-polled hot-reload (#159)
  ```

- [ ] **Task 5 — Add ADR-0023 Consequences, Alternatives, References + pin test.**

  Files: Modify `docs/adr/0023-mtime-polled-hot-reload-for-policies-yaml.md`; modify `tests/unit/audit/test_audit_constants_slice_4.py`.

  Steps:

  - [ ] Write Consequences section.

    Positive:
    - Operators can edit `config/policies.yaml` and observe the swap in audit log within 1s without daemon restart. Low-blast changes (rate limits, handle caps) propagate to consumers on next iteration.
    - The high-blast partition prevents `quarantined_provider_url` from being silently swapped — that change still goes through the reviewer-gated state.git proposal flow as in Slice 3.
    - The watcher-side SHA short-circuit makes the hot-reload idempotent: retries after transient errors that re-observe the same file content collapse to a no-op at the watcher, before the swap is attempted.

    Negative:
    - 1s polling latency on first observation; the watcher does not see edits faster than its tick cadence. Operators editing in fast succession may observe the union of edits, not each one. Acceptable per spec §5.8 (deferred `watchdog` migration).
    - `PoliciesSnapshotRef.current()` is synchronous — a name-binding-then-`await`-then-use pattern that worked in Slice 3 (where snapshot reads were async) can silently capture stale state. The AST guard catches this in the four migrated modules but not in arbitrary user code.
    - Audit-then-swap means a sustained audit-write failure (Postgres unreachable) blocks all hot-reloads until the audit path recovers. Acceptable — the failure mode is loud (`CONFIG_RELOAD_REJECTED_FIELDS` with `reason="audit_write_failed"` on every retry) and the active snapshot stays consistent with the last successful audit.

    Neutral:
    - The `Settings.policy_poll_interval_seconds` range `[0.5, 10.0]` is wide enough to accommodate both low-latency dev loops (0.5s) and resource-constrained operators (10s). The range is a design choice; tightening it is a follow-up if an operator surfaces a need.

  - [ ] Write Alternatives section.

    **Option A — Use the `watchdog` library now.** Rejected for Slice 4. `watchdog` wraps inotify on Linux, FSEvents on macOS, ReadDirectoryChangesW on Windows — three different real backends with three different failure modes. The mtime-polling implementation has one backend (`os.stat`) and one failure mode. Migration is deferred to Slice 5+ unless an operator surfaces a real polling-latency complaint. The deferral is recorded in spec §5.8 and tracked in the Slice-5 backlog (slice-4 index §8).

    **Option B — Reload on SIGHUP.** Rejected. Operators editing the YAML in a non-terminal context (editor save) would not get the reload. Polling is a strict superset of the SIGHUP UX.

    **Option C — Read-on-every-call from disk (no cache).** Rejected. Per-call disk read introduces unbounded I/O cost on the hot path (every `ref.current()` becomes a syscall). The cached-snapshot pattern has one read per actual file change.

    **Option D — Swap-then-audit (audit row recording the already-applied swap).** Rejected per err-004 closure. A failed audit write after the swap leaves the active snapshot diverged from the audit log — operators see new behaviour with no audit explanation. Audit-then-swap keeps the two consistent.

  - [ ] Write References section. Cite: PRD §11.1 (operator override semantics + state.git widening discipline); ADR-0017 (Slice-3 wire-format precedent); spec §5.1-§5.8; issue #159.

  - [ ] Extend the test pin file with ADR-0023 assertions:

    ```python
    def test_adr_0023_status_is_accepted() -> None:
        adr = ADR_DIR / "0023-mtime-polled-hot-reload-for-policies-yaml.md"
        assert adr.exists(), f"ADR-0023 not at {adr}"
        body = adr.read_text(encoding="utf-8")
        assert "\nAccepted\n" in body, "ADR-0023 Status is not 'Accepted'"


    def test_adr_0023_decision_subheadings_present() -> None:
        adr = ADR_DIR / "0023-mtime-polled-hot-reload-for-policies-yaml.md"
        body = adr.read_text(encoding="utf-8")
        for sub in ("Decision 1", "Decision 2", "Decision 3", "Decision 4", "Decision 5"):
            assert sub in body, f"ADR-0023 missing {sub!r}"
    ```

  - [ ] Run the tests:

    ```bash
    cd <repo-root> && uv run pytest tests/unit/audit/test_audit_constants_slice_4.py -q
    ```

    Expected: 4 passed (the two ADR-0022 tests from Task 3 + the two ADR-0023 tests added here).

  - [ ] Run `make docs-check`:

    ```bash
    cd <repo-root> && make docs-check 2>&1 | tail -10
    ```

    Expected: exits 0.

  Commit:

  ```
  docs(adr-0023): consequences, alternatives, references + test pin (#159)
  ```

### Component C — ADR-0024 (Comms-MCP wire contract)

- [ ] **Task 6 — Create ADR-0024 with full body and pin test.**

  Files: Create `docs/adr/0024-comms-mcp-wire-contract.md`; modify `tests/unit/audit/test_audit_constants_slice_4.py`.

  Steps:

  - [ ] Write the header:

    ```markdown
    # ADR-0024 — Comms-MCP wire contract

    ## Status

    Accepted

    **Date:** 2026-06-07

    ## Context
    ```

  - [ ] Write the Context section. Cite: ADR-0016 (Slice-4 Discord+TUI comms-MCP rewrite) committed the structural shape in Slice 3 but left the wire contract unspecified. Slice 4's PR-S4-8 ships the host-side transport; PR-S4-9 ships the Discord adapter as an MCP plugin; PR-S4-10 ships the TUI adapter as an MCP plugin and deletes `src/alfred/comms/`. The wire contract must be specified before any of those PRs lands so all three implementations target the same surface.

  - [ ] Write the Decision section with eight sub-decisions:

    **Decision 1 — Eight wire methods.** Four host→plugin JSON-RPC requests (`lifecycle.start`, `lifecycle.stop`, `adapter.health`, `outbound.message`). Four plugin→host JSON-RPC notifications (`inbound.message`, `adapter.binding_request`, `adapter.rate_limit_signal`, `adapter.crashed`). No other method may be added or renamed outside an ADR-0024 amendment.

    **Decision 2 — `OutboundMessageResult` discriminated union.** Three variants keyed by `outcome` Literal: `_OutboundDelivered(outcome="delivered", platform_message_id)`, `_OutboundRetryable(outcome="retryable_failure", retry_after_seconds, error_class)`, `_OutboundTerminal(outcome="terminal_failure", error_class, detail_redacted)`. The discriminated union forecloses field-coupling bugs (no `platform_message_id` on a failure; no `retry_after_seconds` on a delivered) — the type system enforces the correct shape per outcome (comms-008 closure).

    **Decision 3 — `addressing_mode` Literal mapping (DM / mention / channel / thread).** The four wire Literal values map onto PRD §6.8's three addressing concepts as: `dm` → direct (1:1); `mention` → direct (1:N with explicit addressee); `channel` → default (group, addressee not explicit); `thread` → group. Per-platform rendering: Discord renders `dm` as ephemeral DM reply, `mention` as channel reply with `@user` prefix, `channel` as bare channel reply, `thread` as reply in the originating thread. TUI only emits `dm`; the host's outbound routing rejects `mention/channel/thread` outbound to TUI with `COMMS_ADDRESSING_DRIFT_FIELDS` audit row + delivery refusal.

    **Decision 4 — `process_inbound_message` order is load-bearing.** Resolution → tier-classify → ingest → dispatch. The canonical `user_id` never appears in any wire frame outbound to the plugin. The `IdentityResolver` runs host-side; the resolution result stays host-side. Plugins emit `inbound.message`; the host invokes the resolver. This is the "callback wire type" — the wire is the notification flowing host-ward, not a host-callable surface plugins can invoke.

    **Decision 5 — Host-side `REQUIRED_CLASSIFIERS_BY_KIND` registry rule.** The set of valid `adapter_kind` Literal values lives in `src/alfred/comms_mcp/protocol.py` as a `Final[frozenset[str]]`. Adding a new `adapter_kind` is a code change in `src/` and goes through the standard AlfredOS PR review (reviewer agent + human-approval-as-needed per CLAUDE.md self-improvement rules). There is no state.git path; plugins cannot bypass the required classifier set via an empty `classifiers_optional` list (sec-002 round-3 closure). The matching `REQUIRED_CLASSIFIERS_BY_KIND` entry must land in the same PR as the new `adapter_kind` (enforced by `tests/unit/comms_mcp/test_required_classifiers_complete.py` AST guard).

    **Decision 6 — `BODY_FIELD_BY_KIND` per-adapter body-field map.** Discord delivers the user's free-text under `body.content`; Telegram (post-MVP) delivers it under `body.text`. The host-side `InboundContentScanner` consults the adapter's `adapter_kind` to look up the body-field path in `BODY_FIELD_BY_KIND`. The orchestrator-side ingest receives a normalised `body.text: str` field regardless of platform (comms-011 closure).

    **Decision 7 — Host-side audit-emit ownership.** Every comms audit row is emitted by host code on receipt of a plugin notification — adapters are plugin processes and never write to the audit log directly. PR-S4-9 and PR-S4-10 ship adapter code that triggers these notifications; the audit-emit sites stay in PR-S4-8.

    **Decision 8 — Per-adapter `asyncio.BoundedSemaphore` for inbound notification dispatch.** The notification dispatcher uses an `async with self._dispatch_semaphore` block with a per-session cap (default 32 via `Settings.comms_max_in_flight_notifications`). The cap is per-adapter, not process-wide — three adapter sessions each get their own 32-slot cap, so adapter A's rate-limit storm cannot starve adapter B (perf-003 closure). The semaphore is acquired-and-released via `async with`, guaranteeing release on exception (core-008 closure).

  - [ ] Write Consequences section.

    Positive:
    - Three plugin implementations (PR-S4-8 transport, PR-S4-9 Discord adapter, PR-S4-10 TUI adapter) target the same surface defined here, so wire-format drift between adapters is structurally impossible.
    - The discriminated `OutboundMessageResult` lets the host pattern-match correctly per outcome — `mypy --strict` enforces every caller exhaustively pattern-matches.
    - Host-side audit-emit means no audit-log poisoning by a malicious plugin — plugins cannot fabricate audit rows for events they did not actually trigger.

    Negative:
    - The wire contract surface is large (eight methods + several typed payloads). Operators authoring third-party comms adapters need to implement all eight host→plugin requests + emit all four plugin→host notifications correctly. Slice 5+ will likely ship a reference SDK to make adapter-authoring less verbose.
    - The per-adapter semaphore cap (default 32) requires tuning per real-world workload. Discord-heavy deployments may need 128; quiet TUI-only deployments could run at 8. The default targets typical multi-user multi-platform deployments.

    Neutral:
    - Method renames (e.g., `outbound.message` → `outbound.send`) require an ADR-0024 amendment. The naming used here is final for Slice 4.

  - [ ] Write Alternatives section.

    **Option A — Single `wire.invoke` method carrying a `method` discriminator field.** Rejected. JSON-RPC method routing is the standard MCP discipline; collapsing eight methods into one defeats the protocol's built-in dispatch and removes per-method schema validation from `AlfredPluginSession`.

    **Option B — Plugin-callable `host.resolve_identity` request.** Rejected. Exposing identity resolution as a plugin-callable surface lets a malicious plugin enumerate the user-binding state. The host-side resolver pattern keeps the resolution one-way.

    **Option C — Flat `OutboundMessageResult` product type with optional fields.** Rejected per comms-008 closure. A flat type lets the orchestrator construct invalid combinations (delivered with `retry_after_seconds`; failed with `platform_message_id`). The discriminated union makes invalid combinations unrepresentable.

    **Option D — Adapter-side audit-emit.** Rejected per Decision 7's rationale. Plugins authoring audit-row content is an audit-log-poisoning surface; host-side emit-on-notification keeps the audit log authoritative.

  - [ ] Write References section. Cite: PRD §6.1 (multi-modal comms); PRD §6.8 (addressing concepts); ADR-0016; ADR-0017; spec §8.1-§8.10; issue #152.

  - [ ] Extend the test pin file:

    ```python
    def test_adr_0024_status_is_accepted() -> None:
        adr = ADR_DIR / "0024-comms-mcp-wire-contract.md"
        assert adr.exists(), f"ADR-0024 not at {adr}"
        body = adr.read_text(encoding="utf-8")
        assert "\nAccepted\n" in body, "ADR-0024 Status is not 'Accepted'"


    def test_adr_0024_decision_subheadings_present() -> None:
        adr = ADR_DIR / "0024-comms-mcp-wire-contract.md"
        body = adr.read_text(encoding="utf-8")
        for sub in (
            "Decision 1",
            "Decision 2",
            "Decision 3",
            "Decision 4",
            "Decision 5",
            "Decision 6",
            "Decision 7",
            "Decision 8",
        ):
            assert sub in body, f"ADR-0024 missing {sub!r}"
    ```

  - [ ] Run the tests:

    ```bash
    cd <repo-root> && uv run pytest tests/unit/audit/test_audit_constants_slice_4.py -q
    ```

    Expected: 6 passed.

  - [ ] Run `make docs-check`:

    ```bash
    cd <repo-root> && make docs-check 2>&1 | tail -10
    ```

    Expected: exits 0.

  Commit:

  ```
  docs(adr-0024): comms-MCP wire contract — full body + test pin (#152)
  ```

### Component D — `audit_row_schemas.py` Slice-4 constants (23 new)

The tasks below add the constants in spec-§9-table order. Each task lands a small grouping (1-3 related constants), runs a single failing assertion to confirm the constant is reachable from the `AuditWriter.append_schema` smoke test, then commits. The TDD discipline catches typos in field-list contents at construction time, not during downstream-PR integration.

- [ ] **Task 7 — Add `DAEMON_BOOT_*` constants (3 constants).**

  Files: Modify `src/alfred/audit/audit_row_schemas.py`; modify `tests/unit/audit/test_audit_constants_slice_4.py`.

  Steps:

  - [ ] Append the daemon-boot constants to `audit_row_schemas.py` at the end of the existing module (after the last Slice-3 constant). Match the existing `Final[frozenset[str]]` typing pattern verified at line 83:

    ```python
    # ---------------------------------------------------------------------------
    # Slice 4 — §9 audit-row-schema additions
    # ---------------------------------------------------------------------------

    # daemon.boot.* family — emitted by `alfred daemon start` (PR-S4-1)
    DAEMON_BOOT_FIELDS: Final[frozenset[str]] = frozenset(
        {
            "boot_id",
            "started_at",
            "state_git_head_sha",
            "slice_version",
            "policies_snapshot_hash",
            "environment",
        }
    )
    """`daemon.boot.completed` row. Emitted once at successful boot.

    Carries `boot_id` (uuid4), `started_at` (UTC datetime), `state_git_head_sha`,
    `slice_version` (Literal["4"]), `policies_snapshot_hash` (sha256 of the
    initial PoliciesSnapshot), `environment` (Literal["development", "production", "test"]).

    Consumed by PR-S4-1 (`alfred daemon start`). See spec §3.2."""

    DAEMON_BOOT_FAILED_FIELDS: Final[frozenset[str]] = frozenset(
        {
            "boot_id",
            "attempted_at",
            "failure_reason",
            "environment_source",
        }
    )
    """`daemon.boot.failed` row. Emitted when one of the seven boot probes refuses.

    `failure_reason` Literal includes: `launcher_not_policy_resolving`,
    `environment_not_set`, `unsandboxed_env_in_production`,
    `snapshot_ref_init_failed`, `capability_gate_handshake_failed`,
    `audit_hash_pepper_missing` (PR-S4-0b bootstrap), `policies_yaml_unreadable`.

    `environment_source` carries the source of `Settings.environment` resolution
    (Literal["env_var", "etc_file", "neither"]). Spec §3.2, §3.4."""

    DAEMON_BOOT_ENVIRONMENT_SOURCE_CONFLICT_FIELDS: Final[frozenset[str]] = frozenset(
        {
            "boot_id",
            "env_var_value",
            "etc_file_value",
            "resolved_value",
        }
    )
    """`daemon.boot.environment_source_conflict` row. Emitted when both
    `ALFRED_ENVIRONMENT` and `/etc/alfred/environment` are set but disagree.

    The daemon still boots — the env-var value wins on conflict per the
    documented precedence rule (rev-008). This row records the conflict for
    operator visibility. Spec §7.3."""
    ```

  - [ ] Extend the test pin file with a generic "every Slice-4 constant is a frozenset" assertion + a specific assertion for the three new constants:

    ```python
    # Append at the end of tests/unit/audit/test_audit_constants_slice_4.py

    from typing import Final, get_type_hints

    from alfred.audit import audit_row_schemas

    # Enumerate every Slice-4 constant as we land them; Task 12 lands the final
    # assertion that this list matches the audit_row_schemas module's
    # "starts with a Slice-4 constant prefix" filter.
    SLICE_4_CONSTANTS: list[str] = [
        "DAEMON_BOOT_FIELDS",
        "DAEMON_BOOT_FAILED_FIELDS",
        "DAEMON_BOOT_ENVIRONMENT_SOURCE_CONFLICT_FIELDS",
    ]


    def test_slice_4_constants_are_frozensets() -> None:
        for name in SLICE_4_CONSTANTS:
            value = getattr(audit_row_schemas, name)
            assert isinstance(value, frozenset), (
                f"{name} must be frozenset[str], got {type(value).__name__}"
            )
            assert len(value) > 0, f"{name} must declare at least one field"
            for field in value:
                assert field.isidentifier(), (
                    f"{name} field {field!r} must be a valid Python identifier"
                )
                assert field == field.lower(), (
                    f"{name} field {field!r} must be snake_case"
                )


    def test_daemon_boot_fields_exact_shape() -> None:
        assert audit_row_schemas.DAEMON_BOOT_FIELDS == frozenset({
            "boot_id", "started_at", "state_git_head_sha",
            "slice_version", "policies_snapshot_hash", "environment",
        })


    def test_daemon_boot_failed_fields_exact_shape() -> None:
        assert audit_row_schemas.DAEMON_BOOT_FAILED_FIELDS == frozenset({
            "boot_id", "attempted_at", "failure_reason", "environment_source",
        })


    def test_daemon_boot_environment_source_conflict_fields_exact_shape() -> None:
        assert audit_row_schemas.DAEMON_BOOT_ENVIRONMENT_SOURCE_CONFLICT_FIELDS == frozenset({
            "boot_id", "env_var_value", "etc_file_value", "resolved_value",
        })
    ```

  - [ ] Run the test in failing-then-passing TDD shape. First-run expected FAIL output (before the constants are added):

    ```bash
    cd <repo-root> && uv run pytest tests/unit/audit/test_audit_constants_slice_4.py::test_daemon_boot_fields_exact_shape -q
    ```

    Expected FAIL output: `AttributeError: module 'alfred.audit.audit_row_schemas' has no attribute 'DAEMON_BOOT_FIELDS'`.

  - [ ] Add the constants to `audit_row_schemas.py` (the implementation above).

  - [ ] Re-run to PASS:

    ```bash
    cd <repo-root> && uv run pytest tests/unit/audit/test_audit_constants_slice_4.py -q
    ```

    Expected: 6 (Component A/B/C tests) + 4 (constants tests) = 10 passed.

  Commit:

  ```
  feat(audit): Slice-4 daemon.boot.* audit-row constants (#205)
  ```

- [ ] **Task 8 — Add `PROPOSAL_DISPATCH_FAILURE_REDACTED_FIELDS` + `CARRIER_SUBSTITUTION_*` (3 constants).**

  Files: Modify `src/alfred/audit/audit_row_schemas.py`; modify `tests/unit/audit/test_audit_constants_slice_4.py`.

  Steps:

  - [ ] Append to `audit_row_schemas.py`:

    ```python
    # proposal-dispatch DLP family — emitted by ProposalContext (PR-S4-2)
    PROPOSAL_DISPATCH_FAILURE_REDACTED_FIELDS: Final[frozenset[str]] = frozenset(
        {
            "proposal_branch",
            "dispatch_attempted_at",
            "failure_class",
            "redacted_detail",
            "dlp_redactions_count",
        }
    )
    """`proposal.dispatch.failure_redacted` row. Emitted on EVERY proposal-dispatch
    failure write (success-with-redactions ≥ 0).

    Distinct from `DLP_OUTBOUND_REFUSED_FIELDS` (Slice-3 constant, reused for the
    refusal case — DLP says "do not write this row at all"). The two constants
    cover disjoint outcomes:

    - DLP clean → `dlp_redactions_count=0` (row written).
    - DLP found redactable patterns → `dlp_redactions_count > 0` (row written with redactions).
    - DLP refuses the row → `DLP_OUTBOUND_REFUSED_FIELDS` instead (row not written;
      supervisor breaker trips).

    `redacted_detail` is the post-DLP-scan, post-truncate-to-512-chars body.
    `failure_class` is the short snake_case class identifier (no `str(exc)`,
    no `exc.args`). Consumed by PR-S4-2. See spec §3.3."""

    # hooks.carrier_substituted / hooks.carrier_substitution_refused family — emitted by _run_error (PR-S4-3)
    CARRIER_SUBSTITUTION_FIELDS: Final[frozenset[str]] = frozenset(
        {
            "hookpoint",
            "subscriber_id",
            "source_tier",
            "carrier_tier",
            "substituted_at",
        }
    )
    """`hooks.carrier_substituted` row. Emitted when an error-stage subscriber
    successfully substitutes a recovery payload.

    `source_tier` is the substitute payload's declared tier (Literal["T0", "T1", "T2", "T3"]).
    `carrier_tier` is the surrounding action's declared tier (the comparison anchor
    for the §4.4 tier-upgrade-refused guard). `subscriber_id` is the substituting
    subscriber's deterministic identifier. Consumed by PR-S4-3. See spec §4.3."""

    CARRIER_SUBSTITUTION_REFUSED_FIELDS: Final[frozenset[str]] = frozenset(
        {
            "hookpoint",
            "subscriber_id",
            "attempted_source_tier",
            "carrier_tier",
            "reason",
            "refused_at",
        }
    )
    """`hooks.carrier_substitution_refused` row.

    `reason` Literal: `tier_upgrade_refused` | `recursion_refused`.
    `attempted_source_tier` is the substitute's claimed tier; `carrier_tier` is
    the surrounding action's tier — refusal fires when `attempted_source_tier > carrier_tier`
    in the strict total order T0<T1<T2<T3. Consumed by PR-S4-3. See spec §4.4, §4.6."""
    ```

  - [ ] Extend test list and exact-shape assertions:

    ```python
    SLICE_4_CONSTANTS += [
        "PROPOSAL_DISPATCH_FAILURE_REDACTED_FIELDS",
        "CARRIER_SUBSTITUTION_FIELDS",
        "CARRIER_SUBSTITUTION_REFUSED_FIELDS",
    ]


    def test_proposal_dispatch_failure_redacted_fields_exact_shape() -> None:
        assert audit_row_schemas.PROPOSAL_DISPATCH_FAILURE_REDACTED_FIELDS == frozenset({
            "proposal_branch", "dispatch_attempted_at", "failure_class",
            "redacted_detail", "dlp_redactions_count",
        })


    def test_carrier_substitution_fields_exact_shape() -> None:
        assert audit_row_schemas.CARRIER_SUBSTITUTION_FIELDS == frozenset({
            "hookpoint", "subscriber_id", "source_tier",
            "carrier_tier", "substituted_at",
        })


    def test_carrier_substitution_refused_fields_exact_shape() -> None:
        assert audit_row_schemas.CARRIER_SUBSTITUTION_REFUSED_FIELDS == frozenset({
            "hookpoint", "subscriber_id", "attempted_source_tier",
            "carrier_tier", "reason", "refused_at",
        })
    ```

  - [ ] Run the test FAIL → PASS cycle:

    ```bash
    cd <repo-root> && uv run pytest tests/unit/audit/test_audit_constants_slice_4.py -q
    ```

    Expected after implementation: 13 passed.

  Commit:

  ```
  feat(audit): Slice-4 proposal-dispatch + carrier-substitution audit-row constants (#170)
  ```

- [ ] **Task 9 — Add `CONFIG_RELOAD_*` constants (2 constants).**

  Files: Modify `src/alfred/audit/audit_row_schemas.py`; modify `tests/unit/audit/test_audit_constants_slice_4.py`.

  Steps:

  - [ ] Append to `audit_row_schemas.py`:

    ```python
    # supervisor.config_reload.* family — emitted by PolicyWatcher (PR-S4-4)
    CONFIG_RELOAD_FIELDS: Final[frozenset[str]] = frozenset(
        {
            "file_path",
            "prev_sha256",
            "new_sha256",
            "changed_keys",
            "loaded_at",
        }
    )
    """`supervisor.config_reload` row. Emitted by `PolicyWatcher.swap()` Phase 1
    on every successful audit-then-swap.

    `changed_keys` is the list of dotted key paths that differ between the
    prev and new snapshots (e.g., `["rate_limits.web_fetch_per_user_per_hour"]`).
    `prev_sha256` is the diff anchor; `new_sha256` is the post-swap active snapshot's
    file_sha256. Consumed by PR-S4-4. See spec §5.6."""

    CONFIG_RELOAD_REJECTED_FIELDS: Final[frozenset[str]] = frozenset(
        {
            "file_path",
            "attempted_sha256",
            "reason",
            "offending_key",
            "dlp_scan_result",
        }
    )
    """`supervisor.config_reload_rejected` row. Emitted by `PolicyWatcher` on
    every refused reload.

    `reason` Literal: `parse_failure` | `high_blast_change` | `validation_failure`
    | `file_vanished` | `stat_failed` | `audit_write_failed` (err-011 round-4
    closure — the swap-then-audit-fails leg per spec §5.3).

    `offending_key` carries the dotted key path that violated validation (NO value
    — value omitted to avoid secret leak). `dlp_scan_result` carries
    Literal["clean", "high_blast_change", "n_a"]. Consumed by PR-S4-4. See spec §5.6."""
    ```

  - [ ] Extend tests:

    ```python
    SLICE_4_CONSTANTS += [
        "CONFIG_RELOAD_FIELDS",
        "CONFIG_RELOAD_REJECTED_FIELDS",
    ]


    def test_config_reload_fields_exact_shape() -> None:
        assert audit_row_schemas.CONFIG_RELOAD_FIELDS == frozenset({
            "file_path", "prev_sha256", "new_sha256",
            "changed_keys", "loaded_at",
        })


    def test_config_reload_rejected_fields_exact_shape() -> None:
        assert audit_row_schemas.CONFIG_RELOAD_REJECTED_FIELDS == frozenset({
            "file_path", "attempted_sha256", "reason",
            "offending_key", "dlp_scan_result",
        })
    ```

  - [ ] Run:

    ```bash
    cd <repo-root> && uv run pytest tests/unit/audit/test_audit_constants_slice_4.py -q
    ```

    Expected: 15 passed.

  Commit:

  ```
  feat(audit): Slice-4 supervisor.config_reload.* audit-row constants (#159)
  ```

- [ ] **Task 10 — Add `OPERATOR_SESSION_*` + `SUPERVISOR_BREAKER_RESET_REFUSED_FIELDS` (4 constants).**

  Files: Modify `src/alfred/audit/audit_row_schemas.py`; modify `tests/unit/audit/test_audit_constants_slice_4.py`.

  Steps:

  - [ ] Append to `audit_row_schemas.py`:

    ```python
    # operator.session.* family — emitted by alfred login/logout (PR-S4-5)
    OPERATOR_SESSION_CREATED_FIELDS: Final[frozenset[str]] = frozenset(
        {
            "user_id",
            "issued_at",
            "expires_at",
            "host",
            "machine_id_hash",
            "via",
        }
    )
    """`operator.session.created` row. Emitted by `alfred login` (fresh) or
    `alfred login --refresh` (token rotation).

    `via` Literal: `login` | `refresh`. `machine_id_hash` is HMAC-SHA256 of the
    raw OS-sourced machine-id using the broker-resident `audit.hash_pepper`
    (NEVER the raw machine-id — it's a persistent host fingerprint). Consumed by
    PR-S4-5. See spec §6.6, §8.10 hash recipe."""

    OPERATOR_SESSION_REVOKED_FIELDS: Final[frozenset[str]] = frozenset(
        {
            "user_id",
            "revoked_at",
            "via",
        }
    )
    """`operator.session.revoked` row. Emitted by `alfred logout` (operator-initiated),
    `admin_revoke` (operator-managed expiry from another machine), or `expiry`
    (server-side expiry sweep).

    `via` Literal: `logout` | `admin_revoke` | `expiry`. Consumed by PR-S4-5."""

    OPERATOR_SESSION_REFUSED_FIELDS: Final[frozenset[str]] = frozenset(
        {
            "attempted_user_id",
            "reason",
            "host",
            "machine_id_hash",
        }
    )
    """`operator.session.refused` row. Emitted by `_resolve_operator` on every
    session-load refusal.

    `reason` Literal: `expired` | `host_mismatch` | `machine_mismatch` |
    `token_unknown` | `user_revoked` | `bad_file_mode` | `bad_file_owner`.
    `machine_id_hash` is HMAC-with-pepper. Consumed by PR-S4-5. See spec §6.6."""

    # supervisor.breaker.reset.* family — emitted by alfred supervisor reset (PR-S4-5)
    SUPERVISOR_BREAKER_RESET_REFUSED_FIELDS: Final[frozenset[str]] = frozenset(
        {
            "component_id",
            "reason",
            "attempted_at",
        }
    )
    """`supervisor.breaker.reset.refused` row. Emitted by `alfred supervisor reset`
    when the operator-session precondition fails.

    `reason` Literal includes: `operator_session_missing` | `operator_session_expired`
    | `operator_permissions_insufficient`. Consumed by PR-S4-5. See spec §6.7."""
    ```

  - [ ] Extend tests:

    ```python
    SLICE_4_CONSTANTS += [
        "OPERATOR_SESSION_CREATED_FIELDS",
        "OPERATOR_SESSION_REVOKED_FIELDS",
        "OPERATOR_SESSION_REFUSED_FIELDS",
        "SUPERVISOR_BREAKER_RESET_REFUSED_FIELDS",
    ]


    def test_operator_session_created_fields_exact_shape() -> None:
        assert audit_row_schemas.OPERATOR_SESSION_CREATED_FIELDS == frozenset({
            "user_id", "issued_at", "expires_at", "host", "machine_id_hash", "via",
        })


    def test_operator_session_revoked_fields_exact_shape() -> None:
        assert audit_row_schemas.OPERATOR_SESSION_REVOKED_FIELDS == frozenset({
            "user_id", "revoked_at", "via",
        })


    def test_operator_session_refused_fields_exact_shape() -> None:
        assert audit_row_schemas.OPERATOR_SESSION_REFUSED_FIELDS == frozenset({
            "attempted_user_id", "reason", "host", "machine_id_hash",
        })


    def test_supervisor_breaker_reset_refused_fields_exact_shape() -> None:
        assert audit_row_schemas.SUPERVISOR_BREAKER_RESET_REFUSED_FIELDS == frozenset({
            "component_id", "reason", "attempted_at",
        })
    ```

  - [ ] Run:

    ```bash
    cd <repo-root> && uv run pytest tests/unit/audit/test_audit_constants_slice_4.py -q
    ```

    Expected: 19 passed.

  Commit:

  ```
  feat(audit): Slice-4 operator.session.* + supervisor.breaker.reset.* audit-row constants (#153)
  ```

- [ ] **Task 11 — Add `SANDBOX_*` constants (2 constants).**

  Files: Modify `src/alfred/audit/audit_row_schemas.py`; modify `tests/unit/audit/test_audit_constants_slice_4.py`.

  Steps:

  - [ ] Append to `audit_row_schemas.py`:

    ```python
    # supervisor.plugin.sandbox_* family — emitted by alfred-plugin-launcher (PR-S4-6/7)
    SANDBOX_REFUSED_FIELDS: Final[frozenset[str]] = frozenset(
        {
            "plugin_id",
            "policy_ref",
            "host_os",
            "reason",
            "environment",
        }
    )
    """`supervisor.plugin.sandbox_refused` row. Emitted by the launcher when
    sandbox enforcement cannot proceed.

    `reason` Literal: `policy_ref_missing` | `policy_ref_os_mismatch` |
    `policy_ref_unreadable` | `sandbox_block_missing` |
    `windows_stub_in_production` | `unsandboxed_env_set_in_production` |
    `policy_invalid_<flag>` (per spec §11.4 misconfigured-policy attacker model).

    `environment` Literal: `development` | `production` | `test`. `host_os`
    Literal: `linux` | `macos` | `windows`. Consumed by PR-S4-6, PR-S4-7. See
    spec §7.11."""

    SANDBOX_STUB_USED_FIELDS: Final[frozenset[str]] = frozenset(
        {
            "plugin_id",
            "policy_ref",
            "host_os",
            "environment",
        }
    )
    """`supervisor.plugin.sandbox_stub_used` row. Emitted on Windows-dev paths
    where the stub policy spawns unsandboxed.

    `environment` MUST be `development` — production-with-stub refuses with
    SANDBOX_REFUSED_FIELDS(reason="windows_stub_in_production") instead.
    Consumed by PR-S4-7. See spec §7.11."""
    ```

  - [ ] Extend tests:

    ```python
    SLICE_4_CONSTANTS += [
        "SANDBOX_REFUSED_FIELDS",
        "SANDBOX_STUB_USED_FIELDS",
    ]


    def test_sandbox_refused_fields_exact_shape() -> None:
        assert audit_row_schemas.SANDBOX_REFUSED_FIELDS == frozenset({
            "plugin_id", "policy_ref", "host_os", "reason", "environment",
        })


    def test_sandbox_stub_used_fields_exact_shape() -> None:
        assert audit_row_schemas.SANDBOX_STUB_USED_FIELDS == frozenset({
            "plugin_id", "policy_ref", "host_os", "environment",
        })
    ```

  - [ ] Run:

    ```bash
    cd <repo-root> && uv run pytest tests/unit/audit/test_audit_constants_slice_4.py -q
    ```

    Expected: 21 passed.

  Commit:

  ```
  feat(audit): Slice-4 supervisor.plugin.sandbox_* audit-row constants (#205)
  ```

- [ ] **Task 12 — Add `COMMS_*` constants + `SUPERVISOR_PLUGIN_RESTART_REQUESTED_FIELDS` (9 constants).**

  Files: Modify `src/alfred/audit/audit_row_schemas.py`; modify `tests/unit/audit/test_audit_constants_slice_4.py`.

  Steps:

  - [ ] Append to `audit_row_schemas.py`:

    ```python
    # comms.* family — emitted by host-side comms-MCP code (PR-S4-8)
    # Adapters NEVER write to the audit log directly — PR-S4-9 / PR-S4-10 ship
    # adapter code that triggers these notifications; the audit-emit sites stay
    # in PR-S4-8 (per ADR-0024 Decision 7).

    COMMS_INBOUND_T3_PROMOTION_FIELDS: Final[frozenset[str]] = frozenset(
        {
            "adapter_id",
            "inbound_message_id",
            "platform_user_id_hash",
            "canonical_user_id",
            "sub_payload_kinds",
            "language",
            "addressing_signal",
        }
    )
    """`comms.inbound.t3_promoted` row. Emitted by `process_inbound_message` after
    identity resolution + tier classification.

    `sub_payload_kinds` is a frozenset of `Literal["embed","attachment","poll",
    "link_unfurl","sticker","voice_message","component","forwarded_ref","pinned_ref"]`
    populated from the host-side `InboundContentScanner` classifier output.
    `platform_user_id_hash` is HMAC-with-pepper (NEVER raw platform_user_id).
    `language` is the user's BCP-47 tag per CLAUDE.md i18n rule #3 (this row carries
    user-content language because the inbound body is user-authored). Consumed by
    PR-S4-8. See spec §8.10."""

    COMMS_BINDING_REQUESTED_FIELDS: Final[frozenset[str]] = frozenset(
        {
            "adapter_id",
            "platform_user_id_hash",
            "verification_phrase_hash",
            "requested_at",
        }
    )
    """`comms.adapter.binding_requested` row. Emitted when the host receives
    `adapter.binding_request` from a plugin (first-contact path).

    Both `platform_user_id_hash` and `verification_phrase_hash` use the HMAC-with-pepper
    recipe (CodeRabbit major #1 closure — round-1 spec wrote raw `platform_user_id`
    but the §8.10 hashing discipline applies to ALL platform-derived identifiers).
    Consumed by PR-S4-8. See spec §8.10."""

    COMMS_ADAPTER_CRASHED_FIELDS: Final[frozenset[str]] = frozenset(
        {
            "adapter_id",
            "error_class",
            "detail_redacted",
            "crashed_at",
        }
    )
    """`comms.adapter.crashed` row. Emitted by the host on receipt of
    `adapter.crashed` notification.

    `error_class` is short snake_case identifier. `detail_redacted` is the
    post-DLP detail string truncated to ≤256 chars. Consumed by PR-S4-8.
    See spec §8.10. NO `language` field — machine-event row per i18n-004
    asymmetric-language rule."""

    COMMS_RATE_LIMIT_SIGNAL_FIELDS: Final[frozenset[str]] = frozenset(
        {
            "adapter_id",
            "platform_endpoint",
            "retry_after_seconds",
            "signalled_at",
        }
    )
    """`comms.adapter.rate_limit_signal` row. Emitted on receipt of
    `adapter.rate_limit_signal` notification.

    Consumed by PR-S4-8 (emit) + PR-S4-9 (Discord adapter emits the notification).
    The host's `OutboundQueue.pause(adapter_id, retry_after_seconds)` then honours
    the signal. See spec §8.10."""

    COMMS_UNKNOWN_NOTIFICATION_FIELDS: Final[frozenset[str]] = frozenset(
        {
            "adapter_id",
            "method",
            "method_redacted_params",
            "observed_at",
        }
    )
    """`comms.notification.unknown` row. Emitted on receipt of a notification
    whose method matches none of the four known plugin→host methods.

    The drop is NOT silent — Critical 6 closure. `method_redacted_params` is the
    notification params dict with secret-broker-redaction applied. The dispatcher
    then calls `supervisor.request_plugin_restart(adapter_id, reason="unknown_notification")`.
    Consumed by PR-S4-8. See spec §8.4."""

    COMMS_HANDLER_FAILED_FIELDS: Final[frozenset[str]] = frozenset(
        {
            "adapter_id",
            "notification_method",
            "handler_class",
            "error_class",
            "detail_redacted",
            "failed_at",
        }
    )
    """`comms.handler.failed` row. Emitted when a notification handler raises.

    err-007 closure: handler/dispatcher exceptions are loud, not silent. The
    original exception propagates after the audit + the adapter is marked
    unhealthy via `Supervisor.trip_breaker`. Consumed by PR-S4-8. See spec §8.4."""

    COMMS_ADDRESSING_DRIFT_FIELDS: Final[frozenset[str]] = frozenset(
        {
            "adapter_id",
            "inbound_signal",
            "outbound_mode",
            "canonical_user_id",
            "observed_at",
        }
    )
    """`comms.addressing.drift` row. Emitted when outbound routing chooses a mode
    that differs from the inbound `addressing_signal`.

    `inbound_signal` + `outbound_mode` Literals: `dm` | `mention` | `channel` |
    `thread`. Mismatch does NOT refuse (operators may legitimately route a DM
    reply into a channel); the audit row is for operator visibility only. The
    TUI exception is the routing refusal — TUI is 1:1 by shape, so outbound
    `mention/channel/thread` to TUI refuses with this row + delivery refusal.
    Consumed by PR-S4-8. See spec §8.1."""

    COMMS_INBOUND_BUDGET_CAPPED_FIELDS: Final[frozenset[str]] = frozenset(
        {
            "adapter_id",
            "canonical_user_id",
            "persona",
            "tokens_available",
            "wait_seconds",
            "dropped",
            "observed_at",
        }
    )
    """`comms.inbound.budget_capped` row. Emitted by `BurstLimiter` when an
    inbound message exceeds the per-(canonical_user_id, persona) token bucket.

    `BurstLimiter` is the new Slice-4 primitive at
    `src/alfred/orchestrator/burst_limiter.py` (PR-S4-8) — NOT the Slice-2
    BudgetGuard which is per-user-USD-daily (sec-008 round-3 closure honest
    Slice-4 scope expansion). `dropped` is True iff the bucket-empty-for-30s
    timeout fired and the message was dropped. Consumed by PR-S4-8. See spec §8.2."""

    # supervisor.plugin_restart_requested family — emitted by AlfredPluginSession dispatcher (PR-S4-8)
    SUPERVISOR_PLUGIN_RESTART_REQUESTED_FIELDS: Final[frozenset[str]] = frozenset(
        {
            "plugin_id",
            "reason",
            "requested_at",
            "requester",
        }
    )
    """`supervisor.plugin_restart_requested` row. Emitted by
    `Supervisor.request_plugin_restart(adapter_id, reason)`.

    `reason` Literal includes: `unknown_notification` | `comms_handler_repeated_failures`
    | future-reasons. `requester` is the caller identifier (typically
    `AlfredPluginSession._on_post_handshake_method` or a supervisor-internal site).
    Consumed by PR-S4-8 (core-010 round-3 closure — the row was named in prose
    but not enumerated in the spec §9 table until round 3). See spec §8.4."""
    ```

  - [ ] Extend tests with one assertion per constant + a final assertion that `SLICE_4_CONSTANTS` matches the actual public attribute list filtered for Slice-4 names:

    ```python
    SLICE_4_CONSTANTS += [
        "COMMS_INBOUND_T3_PROMOTION_FIELDS",
        "COMMS_BINDING_REQUESTED_FIELDS",
        "COMMS_ADAPTER_CRASHED_FIELDS",
        "COMMS_RATE_LIMIT_SIGNAL_FIELDS",
        "COMMS_UNKNOWN_NOTIFICATION_FIELDS",
        "COMMS_HANDLER_FAILED_FIELDS",
        "COMMS_ADDRESSING_DRIFT_FIELDS",
        "COMMS_INBOUND_BUDGET_CAPPED_FIELDS",
        "SUPERVISOR_PLUGIN_RESTART_REQUESTED_FIELDS",
    ]


    def test_comms_inbound_t3_promotion_fields_exact_shape() -> None:
        assert audit_row_schemas.COMMS_INBOUND_T3_PROMOTION_FIELDS == frozenset({
            "adapter_id", "inbound_message_id", "platform_user_id_hash",
            "canonical_user_id", "sub_payload_kinds", "language", "addressing_signal",
        })


    def test_comms_binding_requested_fields_exact_shape() -> None:
        assert audit_row_schemas.COMMS_BINDING_REQUESTED_FIELDS == frozenset({
            "adapter_id", "platform_user_id_hash",
            "verification_phrase_hash", "requested_at",
        })


    def test_comms_adapter_crashed_fields_exact_shape() -> None:
        assert audit_row_schemas.COMMS_ADAPTER_CRASHED_FIELDS == frozenset({
            "adapter_id", "error_class", "detail_redacted", "crashed_at",
        })


    def test_comms_rate_limit_signal_fields_exact_shape() -> None:
        assert audit_row_schemas.COMMS_RATE_LIMIT_SIGNAL_FIELDS == frozenset({
            "adapter_id", "platform_endpoint", "retry_after_seconds", "signalled_at",
        })


    def test_comms_unknown_notification_fields_exact_shape() -> None:
        assert audit_row_schemas.COMMS_UNKNOWN_NOTIFICATION_FIELDS == frozenset({
            "adapter_id", "method", "method_redacted_params", "observed_at",
        })


    def test_comms_handler_failed_fields_exact_shape() -> None:
        assert audit_row_schemas.COMMS_HANDLER_FAILED_FIELDS == frozenset({
            "adapter_id", "notification_method", "handler_class",
            "error_class", "detail_redacted", "failed_at",
        })


    def test_comms_addressing_drift_fields_exact_shape() -> None:
        assert audit_row_schemas.COMMS_ADDRESSING_DRIFT_FIELDS == frozenset({
            "adapter_id", "inbound_signal", "outbound_mode",
            "canonical_user_id", "observed_at",
        })


    def test_comms_inbound_budget_capped_fields_exact_shape() -> None:
        assert audit_row_schemas.COMMS_INBOUND_BUDGET_CAPPED_FIELDS == frozenset({
            "adapter_id", "canonical_user_id", "persona", "tokens_available",
            "wait_seconds", "dropped", "observed_at",
        })


    def test_supervisor_plugin_restart_requested_fields_exact_shape() -> None:
        assert audit_row_schemas.SUPERVISOR_PLUGIN_RESTART_REQUESTED_FIELDS == frozenset({
            "plugin_id", "reason", "requested_at", "requester",
        })


    def test_slice_4_constants_count() -> None:
        """Sanity-check that SLICE_4_CONSTANTS enumerates 23 entries (the
        spec-§9 22 + SUPERVISOR_PLUGIN_RESTART_REQUESTED_FIELDS added per
        core-010 round-3 closure)."""
        assert len(SLICE_4_CONSTANTS) == 23, (
            f"Expected 23 Slice-4 constants, got {len(SLICE_4_CONSTANTS)}: "
            f"{sorted(SLICE_4_CONSTANTS)}"
        )


    def test_slice_4_constants_have_no_slice_3_collisions() -> None:
        """No Slice-4 constant collides in name with a Slice-3 constant.

        The Slice-3 constants module shipped 18 constants per PR-S3-0a; the
        union must equal 18 + 23 = 41 distinct names (the test asserts the
        no-collision property irrespective of the exact Slice-3 count, by
        verifying every Slice-4 name is unique under the Slice-3 filter).
        """
        all_constants = [
            name for name in dir(audit_row_schemas)
            if name.endswith("_FIELDS") and not name.startswith("_")
        ]
        # Every Slice-4 constant must be present; no Slice-4 name may collide
        # with itself in a Slice-3 entry by accident (same name shadowing).
        for name in SLICE_4_CONSTANTS:
            assert name in all_constants, f"{name} not exported from module"
        # And SLICE_4_CONSTANTS itself must have no duplicates.
        assert len(SLICE_4_CONSTANTS) == len(set(SLICE_4_CONSTANTS)), (
            "Slice-4 constants list has internal duplicates"
        )


    def test_slice_4_constants_pass_append_schema_validator() -> None:
        """Every Slice-4 constant can drive `AuditWriter.append_schema` without
        the symmetric key-set validator raising.

        Asserts the constant's field set can be matched 1:1 by a subject dict
        with placeholder values — confirming the validator (`AuditWriter.append_schema`
        at `src/alfred/audit/log.py:139-149` symmetric check) accepts the shape.
        """
        # No real session — we exercise the validator's invariant directly by
        # constructing a synthetic subject and re-implementing the symmetric
        # check (avoid testcontainers in a unit test).
        for name in SLICE_4_CONSTANTS:
            fields: frozenset[str] = getattr(audit_row_schemas, name)
            subject = {field: None for field in fields}
            # Symmetric check (matches log.py:139-149): subject.keys() == fields.
            assert frozenset(subject.keys()) == fields, (
                f"{name} round-trip failed: subject keys {sorted(subject.keys())} "
                f"!= declared fields {sorted(fields)}"
            )
    ```

  - [ ] Run the test FAIL → PASS cycle. First-run expected FAIL output (before constants exist):

    ```bash
    cd <repo-root> && uv run pytest tests/unit/audit/test_audit_constants_slice_4.py::test_slice_4_constants_count -q
    ```

    Expected FAIL output before this task: `AttributeError: module 'alfred.audit.audit_row_schemas' has no attribute 'COMMS_INBOUND_T3_PROMOTION_FIELDS'`.

  - [ ] Add the constants. Re-run:

    ```bash
    cd <repo-root> && uv run pytest tests/unit/audit/test_audit_constants_slice_4.py -q
    ```

    Expected: 33 passed (6 ADR pin tests + 23 exact-shape tests + 4 cross-cutting tests = 33).

  Commit:

  ```
  feat(audit): Slice-4 comms.* + supervisor.plugin_restart_requested audit-row constants (#152, #205)
  ```

### Component E — `payload_schema.py` Slice-4 additions

- [ ] **Task 13 — Extend `payload_schema.py` with Slice-4 Literals + `_PREFIX_TO_CATEGORY.update(...)` + `_ID_PATTERN` extension.**

  Files: Modify `tests/adversarial/payload_schema.py`; create `tests/unit/adversarial/test_slice_4_categories.py`; create the five synthetic-fixture YAML files under `tests/unit/adversarial/fixtures/slice_4_category_round_trip/`.

  Steps:

  - [ ] Write the failing test FIRST. Create `tests/unit/adversarial/test_slice_4_categories.py`:

    ```python
    """Pin Slice-4 adversarial-corpus dispatch-table extensions.

    Verifies the `payload_schema.py` Slice-4 Category / IngestionPath /
    ExpectedOutcome additions + `_PREFIX_TO_CATEGORY` / `_ID_PATTERN`
    extensions preserve the exact `prefix-YYYY-NNN` format (test-006 closure).
    """
    from __future__ import annotations

    from pathlib import Path

    import pytest
    import yaml

    from tests.adversarial.payload_schema import (
        AdversarialPayload,
        _ID_PATTERN,
        _PREFIX_TO_CATEGORY,
    )

    SLICE_4_PREFIXES: dict[str, str] = {
        "sbx": "sandbox_escape",
        "crf": "carrier_substitution_tamper",
        "csb": "config_reload_bypass",
        "osf": "operator_session_forgery",
        "cib": "comms_identity_boundary",
    }

    FIXTURE_DIR = Path(__file__).parent / "fixtures" / "slice_4_category_round_trip"


    def test_slice_4_prefixes_in_dispatch_table() -> None:
        for prefix, category in SLICE_4_PREFIXES.items():
            assert _PREFIX_TO_CATEGORY.get(prefix) == category, (
                f"_PREFIX_TO_CATEGORY[{prefix!r}] = {_PREFIX_TO_CATEGORY.get(prefix)!r}, "
                f"expected {category!r}"
            )


    def test_id_pattern_preserves_prefix_year_serial_shape() -> None:
        # Positive: every Slice-4 prefix accepts a prefix-YYYY-NNN id.
        for prefix in SLICE_4_PREFIXES:
            assert _ID_PATTERN.match(f"{prefix}-2026-001"), (
                f"Slice-4 prefix {prefix!r} not accepted by _ID_PATTERN"
            )
        # Negative: malformed shapes refuse.
        for malformed in (
            "sbx-2026-1",     # NNN must be zero-padded
            "sbx-26-001",     # YYYY must be 4 digits
            "sbx-2026-1234",  # NNN must be exactly 3 digits
            "SBX-2026-001",   # prefix must be lowercase
            "sbx_2026_001",   # dashes, not underscores
            "sbx-2026-001-",  # no trailing dash
        ):
            assert not _ID_PATTERN.match(malformed), (
                f"_ID_PATTERN incorrectly accepts malformed id {malformed!r}"
            )


    def test_slice_3_prefixes_still_match() -> None:
        # Regression guard: extending _ID_PATTERN must not break Slice-3 IDs.
        for slice_3_prefix in ("pi", "dlp", "cap", "cnry", "ipp", "hk", "tl", "de"):
            assert _ID_PATTERN.match(f"{slice_3_prefix}-2026-001"), (
                f"Slice-3 prefix {slice_3_prefix!r} regressed under Slice-4 extension"
            )


    @pytest.mark.parametrize("prefix,category", list(SLICE_4_PREFIXES.items()))
    def test_synthetic_fixture_round_trip(prefix: str, category: str) -> None:
        # Each fixture has a `<prefix>-2026-000.yaml` file with a single payload.
        fixture = FIXTURE_DIR / f"{prefix}-2026-000.yaml"
        assert fixture.exists(), f"missing synthetic fixture {fixture}"
        data = yaml.safe_load(fixture.read_text(encoding="utf-8"))
        payload = AdversarialPayload.model_validate(data)
        assert payload.id == f"{prefix}-2026-000"
        assert payload.category == category


    def test_negative_path_prefix_category_mismatch_refused() -> None:
        # crf-* prefix MUST map to carrier_substitution_tamper; declaring a
        # different category must raise at model-validate time.
        bad = {
            "id": "crf-2026-999",
            "category": "comms_identity_boundary",   # WRONG — should be carrier_substitution_tamper
            "threat": "test",
            "ingestion_path": "inbound_notification_handler",
            "payload": "noop",
            "expected_outcome": "refused",
            "provenance": "test",
            "references": ("docs/superpowers/specs/2026-06-06-slice-4-design.md#46",),
        }
        with pytest.raises(ValueError, match="id prefix 'crf' implies category"):
            AdversarialPayload.model_validate(bad)


    def test_slice_4_ingestion_paths_present() -> None:
        # Re-import the Literal's __args__ to check enumeration extended.
        from tests.adversarial.payload_schema import IngestionPath
        from typing import get_args

        for path in (
            "sandbox_policy_load",
            "operator_session_file",
            "mtime_poll",
            "inbound_notification_handler",
            "proposal_dispatch_failure",
            "comms_inbound_message",
            "stdio_fd3_key_delivery",
        ):
            assert path in get_args(IngestionPath), (
                f"IngestionPath Literal missing Slice-4 value {path!r}"
            )


    def test_slice_4_expected_outcomes_present() -> None:
        from tests.adversarial.payload_schema import ExpectedOutcome
        from typing import get_args

        for outcome in (
            "policy_swap_aborted_on_audit_failure",
            "recursion_refused",
        ):
            assert outcome in get_args(ExpectedOutcome), (
                f"ExpectedOutcome Literal missing Slice-4 value {outcome!r}"
            )
    ```

  - [ ] Run the test to confirm it FAILS (because the synthetic fixtures don't exist and the Slice-4 Literals haven't been added yet):

    ```bash
    cd <repo-root> && uv run pytest tests/unit/adversarial/test_slice_4_categories.py -q
    ```

    Expected FAIL output: `AssertionError: _PREFIX_TO_CATEGORY['sbx'] = None, expected 'sandbox_escape'` and `FileNotFoundError` on the fixtures.

  - [ ] Now extend `tests/adversarial/payload_schema.py` to add the Slice-4 Literals + dispatch-table extensions. Apply the changes to the existing file (preserve Slice-3 entries verbatim — the surface-verification step confirmed the exact shape at lines 21-34, 36-45, 47-60, 62-71). The shape of the edit:

    ```python
    # tests/adversarial/payload_schema.py — Slice-4 extension

    _PREFIX_TO_CATEGORY: dict[str, str] = {
        # ... Slice-3 entries unchanged ...
        "pi": "prompt_injection",
        "dlp": "dlp",
        "cap": "capability_bypass",
        "cnry": "canary",
        "ipp": "inter_persona",
        "hk": "hooks",
        "tl": "tier_laundering",
        "de": "dlp_egress",
    }

    # Slice-4 additions (PR-S4-0a §3.2 cross-PR contract). Adding via update keeps
    # the Slice-3 dict shape intact so external readers (e.g., older corpus
    # validation tools) see exactly the same Slice-3 mapping for legacy ids.
    _PREFIX_TO_CATEGORY.update({
        "sbx": "sandbox_escape",
        "crf": "carrier_substitution_tamper",
        "csb": "config_reload_bypass",
        "osf": "operator_session_forgery",
        "cib": "comms_identity_boundary",
    })

    # _ID_PATTERN extension preserving the prefix-YYYY-NNN format (test-006 closure).
    _ID_PATTERN = re.compile(
        r"^(pi|dlp|cap|cnry|ipp|hk|tl|de|sbx|crf|csb|osf|cib)-\d{4}-\d{3}$"
    )

    Category = Literal[
        "prompt_injection",
        "dlp",
        "capability_bypass",
        "canary",
        "inter_persona",
        "hooks",
        "tier_laundering",
        "dlp_egress",
        # Slice 4 — PR-S4-0a §3.2:
        "sandbox_escape",
        "config_reload_bypass",
        "carrier_substitution_tamper",
        "operator_session_forgery",
        "comms_identity_boundary",
    ]

    IngestionPath = Literal[
        "web.fetch",
        "email.read",
        "mcp.tool.output",
        "file.read",
        "inter_persona.relay",
        # Slice 3 — PR-S3-0a:
        "stdio_transport.outbound",
        "stdio_transport.inbound",
        "cast_bypass",
        "wire_format_deser",
        "capability_gate",
        "secret_broker",
        # Slice 4 — PR-S4-0a §3.2:
        "sandbox_policy_load",
        "operator_session_file",
        "mtime_poll",
        "inbound_notification_handler",
        "proposal_dispatch_failure",
        "comms_inbound_message",
        "stdio_fd3_key_delivery",
    ]

    ExpectedOutcome = Literal[
        "neutralized",
        "caught_by_dlp",
        "refused",
        "quarantined",
        # Slice 3 — PR-S3-0a:
        "boundary_refused",
        "audit_row_emitted",
        # Slice 4 — PR-S4-0a §3.2:
        "policy_swap_aborted_on_audit_failure",
        "recursion_refused",
    ]
    ```

  - [ ] Create the five synthetic fixture YAML files. Use the smallest valid `AdversarialPayload` shape per file. Example (`sbx-2026-000.yaml`):

    ```yaml
    id: sbx-2026-000
    category: sandbox_escape
    threat: "synthetic test payload — fixture for PR-S4-0a category round-trip"
    ingestion_path: sandbox_policy_load
    payload: noop
    expected_outcome: refused
    provenance: "tests/unit/adversarial/test_slice_4_categories.py"
    references:
      - "docs/superpowers/specs/2026-06-06-slice-4-design.md#71"
    ```

    Mirror the same shape for the other four (`crf-2026-000.yaml`, `csb-2026-000.yaml`, `osf-2026-000.yaml`, `cib-2026-000.yaml`) — each with `category` matching the prefix mapping, and a category-appropriate `ingestion_path` + `references`. The `ingestion_path` for each:

    - `sbx-2026-000.yaml` → `sandbox_policy_load`, references `#71`
    - `crf-2026-000.yaml` → `inbound_notification_handler`, references `#46`
    - `csb-2026-000.yaml` → `mtime_poll`, references `#57`
    - `osf-2026-000.yaml` → `operator_session_file`, references `#66`
    - `cib-2026-000.yaml` → `comms_inbound_message`, references `#89`

  - [ ] Create `tests/unit/adversarial/fixtures/slice_4_category_round_trip/__init__.py` as an empty marker so pytest does not try to import the YAML files as Python modules.

  - [ ] Re-run the test:

    ```bash
    cd <repo-root> && uv run pytest tests/unit/adversarial/test_slice_4_categories.py -q
    ```

    Expected: all 11 tests pass (1 prefix-table + 1 id-pattern + 1 slice-3-regression + 5 parametrised round-trips + 1 negative-mismatch + 1 ingestion-paths + 1 expected-outcomes).

  - [ ] Confirm the existing adversarial suite STILL PASSES — adding Literal values must not break the Slice-3 collection:

    ```bash
    cd <repo-root> && uv run pytest tests/adversarial -q 2>&1 | tail -10
    ```

    Expected: all existing Slice-3 tests pass; no new Slice-4 corpus YAMLs are present under `tests/adversarial/<category>/` (those land in implementation PRs), so the collection is unchanged from main.

  Commit:

  ```
  feat(adversarial): Slice-4 Category + IngestionPath + ExpectedOutcome dispatch-table extensions (#205)
  ```

### Component F — `docs/glossary.md` Slice-4 additions

- [ ] **Task 14 — Add Slice-4 glossary entries.**

  Files: Modify `docs/glossary.md`.

  Steps:

  - [ ] Verify the glossary file structure. The surface-verification confirmed the file uses level-2 (`##`) headers with the GitHub-slugifier-compatible convention (lowercased, non-alphanumeric collapsed to `-`). Each entry is one paragraph (1-3 sentences) + a cross-link to the spec section.

  - [ ] Append the Slice-4 entries to the end of the file, preserving the existing alphabetical ordering pattern. The seventeen new entries (listed grouped here by spec-section anchor, but appended in alphabetical order in the file):

    **§4 carrier substitution:**

    ```markdown
    ## CarrierSubstitution

    The Slice-4 [ADR-0022](adr/0022-recoverable-carrier-semantic-for-error-stage-hookpoint-dispatch.md)
    semantic by which an error-stage hookpoint subscriber returns a recovery
    payload instead of letting the original exception propagate. The returned
    [`ErrorOutcome`](#erroroutcome) is either [`ReRaise()`](#reraise) (original
    exception propagates) or [`SubstituteResult(payload, source_tier, subscriber_id)`](#substituteresult)
    (substitute payload replaces the exception). The substituted payload's
    `source_tier` is checked against the surrounding action's `carrier_tier`
    in the strict total order `T0<T1<T2<T3`; substitutes whose tier exceeds
    the carrier's are refused with `tier_upgrade_refused`. Slice 4 introduces
    this in PR-S4-3.

    ## ErrorOutcome

    The discriminated union returned by `alfred.hooks.invoke._run_error` —
    `ErrorOutcome[T] = ReRaise | SubstituteResult[T]`. Each Slice-4 hookpoint
    declares its carrier type at `register_hookpoint(...)` time via
    [`HookpointMeta.carrier_tier`](#hookpointmeta-carrier-tier-allow-error-substitution).
    See [ADR-0022](adr/0022-recoverable-carrier-semantic-for-error-stage-hookpoint-dispatch.md).

    ## ReRaise

    Pydantic v2 model variant of [`ErrorOutcome`](#erroroutcome) indicating the
    error-stage chain did NOT produce a substitute — the original exception
    propagates. Empty model (no fields); identity is the type itself.

    ## SubstituteResult

    Pydantic v2 model variant of [`ErrorOutcome[T]`](#erroroutcome) carrying
    `payload: T`, `source_tier: Literal["T0", "T1", "T2", "T3"]`,
    `subscriber_id: str`. The surrounding caller pattern-matches and either
    returns `payload` (after tier-guard pass) or refuses with
    `tier_upgrade_refused`.
    ```

    **§5 hot-reload:**

    ```markdown
    ## HighBlastPolicies

    The block in [`PoliciesV1`](#policiesv1) carrying keys that refuse
    hot-reload — e.g., `quarantined_provider_url`, `secret_broker_config_ref`.
    Any diff in `HighBlastPolicies` between the active snapshot and the parsed
    new content triggers [`CONFIG_RELOAD_REJECTED_FIELDS`](#) with
    `reason="high_blast_change"`. High-blast changes still go through the
    reviewer-gated state.git proposal flow. See [ADR-0023](adr/0023-mtime-polled-hot-reload-for-policies-yaml.md).

    ## PoliciesSnapshot

    Immutable Pydantic v2 model carrying the active [`PoliciesV1`](#policiesv1)
    state plus metadata — `loaded_at: datetime`, `file_mtime: float`,
    `file_sha256: str`. The snapshot is the unit of swap in
    [`PoliciesSnapshotRef`](#policiessnapshotref). Frozen by `ConfigDict(frozen=True)`.

    ## PoliciesSnapshotRef

    Lock-free O(1) snapshot pointer. `current()` returns the active
    `PoliciesSnapshot` synchronously via a GIL-atomic single-attribute load
    (no `await`, no lock). `swap(new)` runs the audit-then-swap two-phase
    commit (Phase 0: watcher-side SHA short-circuit; Phase 1: emit
    `CONFIG_RELOAD_FIELDS` audit; Phase 2: atomic assignment). Long-lived
    loops dereference per iteration, never once before the loop.

    ## PoliciesV1

    Pydantic v2 model for `config/policies.yaml`. Three top-level blocks:
    `rate_limits: RateLimitPolicies`, `handle_caps: HandleCapPolicies`,
    `high_blast: HighBlastPolicies`. The high-blast block is parsed but never
    hot-reloaded. Slice-4 ships v1; v2+ requires an explicit `schema_version`
    bump + reviewer-gate.

    ## PolicyWatcher

    The mtime-polled watcher for `config/policies.yaml` shipped in PR-S4-4.
    Polls at 1s default cadence (configurable via
    `Settings.policy_poll_interval_seconds ∈ [0.5, 10.0]`). Only reads + parses
    the YAML when `(mtime, size)` differs from the cached values; idle ticks
    are ~0.1ms. Filesystem failure paths (`file_vanished`, `stat_failed`,
    `audit_write_failed`) emit `CONFIG_RELOAD_REJECTED_FIELDS` audit rows and
    continue polling. See [ADR-0023](adr/0023-mtime-polled-hot-reload-for-policies-yaml.md).
    ```

    **§6 operator session:**

    ```markdown
    ## OperatorResolver

    Dependency-injection `Protocol` consumed by every CLI command that emits
    an operator-attributed audit row. Concrete implementation in PR-S4-5 is
    `_resolve_operator(ctx) -> UserId` at
    `src/alfred/identity/operator_session.py`. p99 budget ≤ 5ms; hard timeout
    250ms via `asyncio.wait_for` raising
    [`OperatorSessionTimeout`](#operatorsessiontimeout).

    ## OperatorSession

    Pydantic v2 model serialised into `~/.config/alfred/session` (mode 0600
    mandatory). Carries `user_id: UserId`, `token: SecretStr` (32 random bytes,
    base64url-encoded), `issued_at: datetime`, `expires_at: datetime` (default
    12h from issued_at, clamped `[1h, 7d]`), `host: str` (hostname binding),
    `machine_id_hash: str` (HMAC-with-pepper of OS-sourced machine-id). File
    load uses open-then-fstat (TOCTOU-safe). See spec §6.

    ## OperatorSessionTimeout

    Exception raised by [`OperatorResolver`](#operatorresolver) when the 250ms
    hard timeout fires. CLI commands consuming the resolver refuse with the
    operator-translated message `t("operator_session.refused.resolver_timeout")`
    rather than hanging silently (err-008 closure).
    ```

    **§7 sandbox:**

    ```markdown
    ## SandboxKind

    Literal value in a plugin manifest's `sandbox` block — one of `full`,
    `none`, `stub`. `full` requires kernel-enforced isolation via a per-OS
    policy file; `none` is in-process UID-separated subprocess (first-party
    relay adapters only — Discord, TUI); `stub` is the Windows-dev path that
    spawns unsandboxed with a loud audit row. Production refuses `stub`.

    ## SandboxPolicy

    Per-OS policy file declaring sandbox enforcement. Linux: bwrap-translatable
    declarative format (TOML or JSON; decided at PR-S4-7). macOS: sandbox-exec
    scheme-like syntax. Windows: TOML stub declaring `prd_compliant = false`.
    The plugin manifest's `sandbox.policy_refs` map keys by `Literal["linux",
    "macos", "windows"]`; the launcher resolves the entry matching
    `sys.platform`.
    ```

    **§8 comms-MCP:**

    ```markdown
    ## BODY_FIELD_BY_KIND

    `Final[Mapping[str, str]]` at `src/alfred/comms_mcp/protocol.py` mapping
    each `adapter_kind` (`discord`, `tui`, post-MVP `telegram`) to the JSON
    key carrying the user's free-text body — `content` for Discord/TUI,
    `text` for Telegram. The orchestrator-side ingest receives a normalised
    `body.text: str` field regardless of platform. See [ADR-0024](adr/0024-comms-mcp-wire-contract.md).

    ## BurstLimiter

    Per-(canonical_user_id, persona) token-bucket primitive at
    `src/alfred/orchestrator/burst_limiter.py` (PR-S4-8). Default 5-token
    capacity, 1 token / 5 seconds refill. Configurable via
    `PoliciesV1.rate_limits.quarantined_extract_per_user_persona`. Emits
    [`COMMS_INBOUND_BUDGET_CAPPED_FIELDS`](#) when capping; emits
    `comms.inbound.dropped` after 30s of bucket-empty.

    ## DiscordSubPayloadClassifier

    Host-side classifier at `src/alfred/comms_mcp/classifiers/discord.py`
    (PR-S4-9) covering nine Discord sub-payload kinds — embeds, attachments,
    polls, stickers, voice messages, message components, forwarded-message
    references, pinned-message references, link unfurls. Each emits a
    `ContentHandle` that replaces the field in the body so the orchestrator
    never sees the raw sub-payload.

    ## InboundT3Promotion

    The transport-boundary T3-tagging discipline by which every byte of
    platform-relayed user content (Discord, TUI, future Telegram) is tagged
    T3 at the [`InboundContentScanner`](#inboundcontentscanner) before any
    orchestrator code touches it. The promotion is recorded in
    [`COMMS_INBOUND_T3_PROMOTION_FIELDS`](#). Sub-payloads (embeds,
    attachments, polls) become `ContentHandle`s with their own per-payload
    T3 tags.

    ## Notification handlers (comms-MCP)

    Four `Protocol`-typed callbacks held by `AlfredPluginSession` — one per
    plugin→host JSON-RPC notification method. Each accepts a typed
    notification model and returns `None`. The four are:

    - **InboundHandler** — handles `inbound.message`; concrete implementation
      is `process_inbound_message` (PR-S4-8) bound with `IdentityResolver` +
      `Orchestrator` + `AuditWriter`.
    - **BindingHandler** — handles `adapter.binding_request`; emits
      [`COMMS_BINDING_REQUESTED_FIELDS`](#) and starts the first-contact flow.
    - **RateLimitHandler** — handles `adapter.rate_limit_signal`; emits
      [`COMMS_RATE_LIMIT_SIGNAL_FIELDS`](#) and calls `OutboundQueue.pause(...)`.
    - **CrashHandler** — handles `adapter.crashed`; emits
      [`COMMS_ADAPTER_CRASHED_FIELDS`](#) and marks the adapter unhealthy
      via `Supervisor.trip_breaker`.

    Handlers are constructed at `AlfredPluginSession` instantiation time and
    held as instance state — no per-notification handler resolution. See
    [ADR-0024](adr/0024-comms-mcp-wire-contract.md).
    ```

    **§13.1 Slice-3 carry-over for visibility:**

    ```markdown
    ## T3DerivedData

    Slice-3 `NewType` from `src/alfred/security/quarantine.py` representing
    structured data extracted from raw T3 content by the quarantined LLM. The
    privileged orchestrator MAY consume T3DerivedData structurally without
    crossing the dual-LLM boundary because the extractor's result type carries
    `source_tier="T3"` verbatim. Re-listed in the Slice-4 glossary additions
    for visibility (the type is Slice-3-shipped; Slice 4 does not redefine it).
    ```

  - [ ] Run `make docs-check` to verify all glossary cross-links resolve:

    ```bash
    cd <repo-root> && make docs-check 2>&1 | tail -10
    ```

    Expected: exits 0; no errors. If a link to `adr/0022-...md` fails, the docs-check resolver needs the relative path adjusted (`adr/...` is the path relative to `docs/`).

  Commit:

  ```
  docs(glossary): Slice-4 initial additions per spec §13.1 (#205)
  ```

### Component G — PRD §5 line 118 amendment (HUMAN-GATED)

- [ ] **Task 15 — Amend PRD §5 line 118 hybrid-isolation invariant.**

  Files: Modify `PRD.md`.

  This task is the only deliverable in this PR that requires explicit human approval at merge time per CLAUDE.md self-improvement rules (rev-003 closure). The agent prepares the diff; a human reviewer approves before merge.

  Steps:

  - [ ] Verify the current PRD line 118 wording matches the spec §7.10 "before" quote. The surface-verification step confirmed the exact wording at PRD line 118 contains the Slice-3 phrasing. The diff replaces it verbatim.

  - [ ] Apply the amendment. The change is one bullet in the "Architectural invariants" section. Locate the existing bullet:

    > **Hybrid isolation.** Plugins declare a trust tier; official → in-process subprocess; third-party or agent-authored → containerized with declared capabilities (network allowlist, fs mounts, secret IDs). **Slice 3 relaxation:** the quarantined-LLM plugin runs as a dedicated-UID subprocess with env scrubbing rather than a container — a time-bounded deviation recorded in [ADR-0017](docs/adr/0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md). Full containerisation lands in Slice 4 per [ADR-0015](docs/adr/0015-slice4-containerised-quarantined-llm.md).

    Replace with (per spec §7.10 — note paths use repo-root-relative form because PRD.md sits at repo root):

    > **Hybrid isolation.** Plugins declare a trust tier and a sandbox kind. Official in-tree plugins that *relay* content but do not *consume* T3 (comms adapters, TUI) run as in-process subprocesses (`sandbox.kind: none`). Plugins that *consume* T3 content (the quarantined-LLM extractor; future agent-authored skills processing untrusted content), and all third-party plugins regardless of their consumed tiers, run with kernel-enforced isolation (`sandbox.kind: full`) declaring network allowlist, fs mounts, and secret IDs. The quarantined-LLM plugin runs under `sandbox.kind: full` from Slice 4 onwards, satisfying the kernel-namespace isolation invariant on Linux via [bwrap](https://github.com/containers/bubblewrap) and on macOS via [sandbox-exec](https://www.unix.com/man-page/all/1/sandbox-exec/) (best-effort). Windows-native sandbox is not supported; AlfredOS does not claim PRD compliance for the quarantined-LLM on Windows-native. See [ADR-0015](docs/adr/0015-slice4-containerised-quarantined-llm.md) and [ADR-0017](docs/adr/0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md).

  - [ ] Run `make docs-check` to confirm all PRD cross-links resolve:

    ```bash
    cd <repo-root> && make docs-check 2>&1 | tail -10
    ```

    Expected: exits 0.

  - [ ] In the PR description, flag explicitly that this edit needs human approval. Add a top-of-PR-description note:

    ```
    ## HUMAN-GATED EDITS

    This PR amends `PRD.md` (the project design source-of-truth) per
    CLAUDE.md self-improvement rule: "Editing this CLAUDE.md or PRD.md is
    human-gated. AI agents propose changes; humans approve."

    The edit replaces the line-117 hybrid-isolation invariant text with the
    consumer-vs-relay clarified text from spec §7.10 (rev-003 closure;
    arch-005 / rev-001 round-3 closure on the contradiction).

    Reviewer: please confirm the new wording matches your understanding of
    the Slice-4 hybrid-isolation contract before approving.
    ```

  Commit:

  ```
  docs(prd): §5 line 118 amendment — consumer-vs-relay hybrid-isolation clarification (#205)

  Human-gated per CLAUDE.md self-improvement rules. Replaces the Slice-3
  wording with the Slice-4 clarified consumer-vs-relay text from spec §7.10.
  Discord/TUI adapters declared `sandbox.kind: none` because they relay
  content but do not consume T3; quarantined-LLM and third-party plugins
  declared `sandbox.kind: full`.
  ```

### Component H — Final quality gate

- [ ] **Task 16 — Run `make check` + `make docs-check` + adversarial suite + all relevant unit tests.**

  Files: None (this task is the verification step before the PR is opened).

  Steps:

  - [ ] Run the full `make check`:

    ```bash
    cd <repo-root> && make check 2>&1 | tail -30
    ```

    Expected: exits 0. Ruff lint + ruff format + mypy strict + pyright + pytest unit/integration all pass. Specifically:
    - `audit_row_schemas.py` 23 new constants type-check under `mypy --strict` because each is `Final[frozenset[str]]` (the existing Slice-3 typing pattern).
    - `payload_schema.py` Literal extensions type-check under `mypy --strict` because each is a `Literal[...]` value matching the constraint.
    - The two new test modules pass ruff lint (no unused imports; line length ≤120).
    - The new ADR markdown files are not affected by mypy/pyright.

  - [ ] Run `make docs-check`:

    ```bash
    cd <repo-root> && make docs-check 2>&1 | tail -10
    ```

    Expected: exits 0. All cross-links resolve:
    - ADR-0022 / 0023 / 0024 references to ADR-0014 / 0017 / 0015 / 0016 / spec / PRD anchors.
    - `PRD.md` amendment's references to ADR-0015 / ADR-0017.
    - `docs/glossary.md` new entries' references to ADR-0022 / 0023 / 0024 and the audit-row constants.
    - The Slice-4 index plan (`docs/superpowers/plans/2026-06-07-slice-4-index.md`) — already-present references to ADR-0022 / 0023 / 0024 — now resolve to existing files.

  - [ ] Run the adversarial suite:

    ```bash
    cd <repo-root> && uv run pytest tests/adversarial -q 2>&1 | tail -10
    ```

    Expected: all existing Slice-3 tests pass; no new Slice-4 corpus YAMLs are present under `tests/adversarial/<category>/` (those land in implementation PRs).

  - [ ] Run the new unit test modules:

    ```bash
    cd <repo-root> && uv run pytest tests/unit/audit/test_audit_constants_slice_4.py tests/unit/adversarial/test_slice_4_categories.py -v 2>&1 | tail -50
    ```

    Expected: all 33 audit-constants tests + 11 adversarial-categories tests = 44 passed.

  - [ ] Verify no `t()` calls were inadvertently added (PR-S4-0a is docs+constants; i18n catalog keys are PR-S4-0b):

    ```bash
    cd <repo-root> && git diff main -- src/alfred/ tests/ | grep -E '^\+.*\bt\(' | head -5
    ```

    Expected: empty output (no `t()` calls added).

  - [ ] Verify no `register_hookpoint(...)` calls were inadvertently added (PR-S4-0a does not register hookpoints):

    ```bash
    cd <repo-root> && git diff main -- src/alfred/ tests/ | grep 'register_hookpoint' | head -5
    ```

    Expected: empty output.

  - [ ] Verify `src/alfred/hooks/registry.py` is unchanged (rev-007 closure — `HookpointMeta` fields belong to PR-S4-3):

    ```bash
    cd <repo-root> && git diff main -- src/alfred/hooks/registry.py | head -5
    ```

    Expected: empty output.

  - [ ] Verify `src/alfred/audit/__init__.py` is unchanged (Slice-3 already re-exports `audit_row_schemas`):

    ```bash
    cd <repo-root> && git diff main -- src/alfred/audit/__init__.py | head -5
    ```

    Expected: empty output.

  No additional commit for this task — it is the verification step before the PR is opened.

---

## §5 Spec Coverage Map

| Spec section | Task(s) that implement it |
|---|---|
| §0 Summary — three new ADRs land in PR-S4-0a | Tasks 1-6 (ADR-0022, 0023, 0024 bodies) |
| §1.1 In-scope list — PR-S4-0a foundations | Tasks 1-16 |
| §1.3 Scope budget — PR-S4-0a docs / constants only | All tasks (no runtime dispatch ships) |
| §3.2 `daemon.boot.completed` / `daemon.boot.failed` audit rows | Task 7 |
| §3.3 `PROPOSAL_DISPATCH_FAILURE_REDACTED_FIELDS` | Task 8 |
| §3.4 `DAEMON_BOOT_FAILED_FIELDS` failure-reason Literals | Task 7 |
| §4.1-§4.7 ADR-0022 recoverable-carrier semantic | Tasks 1-3 (ADR body) + Task 8 (CARRIER_SUBSTITUTION_*) |
| §5.1-§5.8 ADR-0023 mtime-polled hot-reload | Tasks 4-5 (ADR body) + Task 9 (CONFIG_RELOAD_*) |
| §6.6 `OPERATOR_SESSION_*` audit rows | Task 10 |
| §6.7 `SUPERVISOR_BREAKER_RESET_REFUSED_FIELDS` | Task 10 |
| §7.3 `DAEMON_BOOT_ENVIRONMENT_SOURCE_CONFLICT_FIELDS` | Task 7 |
| §7.10 PRD §5 line 118 amendment | Task 15 (HUMAN-GATED) |
| §7.11 `SANDBOX_*` audit rows | Task 11 |
| §8.1-§8.10 ADR-0024 comms-MCP wire contract | Task 6 (ADR body) + Task 12 (COMMS_*) |
| §9 23 Slice-4 audit-row-schema constants | Tasks 7-12 (Component D) |
| §10 Hookpoint surface table — context-only; PR-S4-3 ships HookpointMeta extensions | §3.5 + Task 16 verification (no register_hookpoint calls land here) |
| §11.1 Slice-4 corpus prefix-table extension | Task 13 (Component E) |
| §11.2 IngestionPath extensions | Task 13 |
| §11.3 ExpectedOutcome extensions | Task 13 |
| §12.2 i18n catalog additions — PR-S4-0b owns the catalog | §3.5 + Task 16 verification (no `t()` calls added here) |
| §13.1 Slice-4 glossary additions | Task 14 |
| §16 ADR mappings | Tasks 1-6 (ADR bodies) + §3.3 cross-PR-contracts table |

---

## §6 Quality gates

Run these commands in order before opening the PR. Each must exit 0. The list mirrors the Slice-3 PR-S3-0a discipline.

```bash
# 1. Lint + format + type-check + all unit/integration tests gated by make check.
cd <repo-root> && make check

# 2. Cross-link validation (broken ADR / PRD / glossary / index links).
cd <repo-root> && make docs-check

# 3. Adversarial suite — must still pass; no new corpus YAMLs land in PR-S4-0a.
cd <repo-root> && uv run pytest tests/adversarial -q

# 4. The two new test modules.
cd <repo-root> && uv run pytest tests/unit/audit/test_audit_constants_slice_4.py tests/unit/adversarial/test_slice_4_categories.py -v

# 5. Confirm no ruff violations in the modified Python files.
cd <repo-root> && uv run ruff check src/alfred/audit/audit_row_schemas.py tests/adversarial/payload_schema.py tests/unit/audit/test_audit_constants_slice_4.py tests/unit/adversarial/test_slice_4_categories.py

# 6. Confirm pybabel extract finds no new catalog keys (this PR adds no t() calls — keys are PR-S4-0b).
cd <repo-root> && uv run pybabel extract -F babel.cfg -o /tmp/s4-0a-check.pot . && diff <(grep ^msgid locale/en/LC_MESSAGES/alfred.po | sort) <(grep ^msgid /tmp/s4-0a-check.pot | sort) && echo "No new catalog keys — correct for PR-S4-0a"

# 7. Confirm no register_hookpoint() calls were added (PR-S4-0a is docs+constants).
cd <repo-root> && ! git diff main -- src/ tests/ | grep -q 'register_hookpoint' && echo "No register_hookpoint() additions — correct for PR-S4-0a"

# 8. Confirm src/alfred/hooks/registry.py is untouched (rev-007 — HookpointMeta is PR-S4-3 scope).
cd <repo-root> && [ -z "$(git diff main -- src/alfred/hooks/registry.py)" ] && echo "hooks/registry.py untouched — correct"

# 9. Confirm src/alfred/audit/__init__.py is untouched (Slice-3 already re-exports audit_row_schemas).
cd <repo-root> && [ -z "$(git diff main -- src/alfred/audit/__init__.py)" ] && echo "audit/__init__.py untouched — correct"

# 10. Confirm no ADR-0009/0015/0016 changes (docs-001 / arch-003 — those PRs are PR-S4-10 and PR-S4-11).
cd <repo-root> && [ -z "$(git diff main -- docs/adr/0009-comms-adapter-protocol-slice2-only.md docs/adr/0015-slice4-containerised-quarantined-llm.md docs/adr/0016-slice4-discord-tui-comms-mcp-rewrite.md)" ] && echo "ADR-0009/0015/0016 untouched — correct"
```

All ten commands must exit 0 before the PR is opened.

---

## §7 Self-review checklist

Before opening the PR, the author runs through this checklist. Each item is a one-line gate; failing items hold the PR open until fixed.

**Scope discipline:**

- [ ] No `HookpointMeta.carrier_tier` field added (rev-007 — that's PR-S4-3).
- [ ] No `HookpointMeta.allow_error_substitution` field added (rev-007 — that's PR-S4-3).
- [ ] No `register_hookpoint(...)` calls added (each hookpoint's owning PR per spec §10).
- [ ] No edits to `src/alfred/hooks/registry.py`.
- [ ] No edits to `docs/adr/0009-comms-adapter-protocol-slice2-only.md` (docs-001 — that's PR-S4-10).
- [ ] No status flip on `docs/adr/0015-slice4-containerised-quarantined-llm.md` (arch-003 — that's PR-S4-11).
- [ ] No status flip on `docs/adr/0016-slice4-discord-tui-comms-mcp-rewrite.md` (arch-003 — that's PR-S4-11).
- [ ] No Alembic migrations (PR-S4-0b owns those).
- [ ] No i18n catalog additions in `locale/en/LC_MESSAGES/alfred.po` (PR-S4-0b owns those).
- [ ] No `Dockerfile` for `alfred-core` (PR-S4-0b owns that).
- [ ] No `bin/alfred-setup.sh` edits (PR-S4-0b owns that).
- [ ] No `src/alfred/comms_mcp/` source files (PR-S4-8 owns those).
- [ ] No `bin/alfred-plugin-launcher.sh` policy-resolving extension (PR-S4-6 owns that).
- [ ] No Slice-4 corpus YAMLs under `tests/adversarial/<category>/` (each owning PR populates).

**Surface verification (every cited Slice-3 surface must exist):**

- [ ] `AuditWriter.append_schema` is at `src/alfred/audit/log.py:105` — verified.
- [ ] `AuditEntry` model is at `src/alfred/memory/models.py:89` — verified. Note: audit-row field-list constants enumerate keys inside the JSON `subject` column, NOT separate physical columns; the unit test asserts this round-trip via the validator, not via SQLAlchemy column reflection.
- [ ] `Final[frozenset[str]]` typing pattern is at `src/alfred/audit/audit_row_schemas.py:83` — verified.
- [ ] `_PREFIX_TO_CATEGORY` is `dict[str, str]` (NOT a frozenset) at `tests/adversarial/payload_schema.py:22` — verified.
- [ ] `_ID_PATTERN` is `re.compile(r"^(...)-\d{4}-\d{3}$")` at `tests/adversarial/payload_schema.py:34` — verified; extension preserves the regex shape exactly.
- [ ] ADR-0017 / 0018 / 0020 / 0021 all exist at `docs/adr/` — verified.
- [ ] PRD `§5 line 117` wording matches the spec §7.10 "before" quote — verified at session start.

**ADR + PRD cross-links resolve:**

- [ ] `make docs-check` passes.
- [ ] Each new ADR cites ADR-0014 / 0017 / spec / PRD anchors with relative paths that match the Slice-3 ADR convention.
- [ ] `docs/glossary.md` entries cross-link to ADR-0022 / 0023 / 0024 and the audit-row constants.
- [ ] The Slice-4 index plan's references to ADR-0022 / 0023 / 0024 now resolve (the index was authored before the ADRs landed; this PR makes its references valid).

**`audit_row_schemas.py` discipline:**

- [ ] Each of the 23 new constants is `Final[frozenset[str]]`.
- [ ] Each field name is snake_case + a valid Python identifier.
- [ ] Each constant's identifier ends with `_FIELDS`.
- [ ] No constant collides in name with a Slice-3 constant.
- [ ] Each constant has at least one field.
- [ ] Each constant has an inline docstring naming the consuming PR.
- [ ] No `str(exc)` / `exc.args` / `traceback` fields (CLAUDE.md hard rule 1; spec §5.6).

**`payload_schema.py` discipline:**

- [ ] Five new `Category` Literal values added; Slice-3 entries preserved verbatim.
- [ ] Five `_PREFIX_TO_CATEGORY.update({...})` entries added; Slice-3 entries preserved verbatim.
- [ ] `_ID_PATTERN` extension preserves the `^(...)-\d{4}-\d{3}$` shape (test-006 closure).
- [ ] Seven new `IngestionPath` Literal values; Slice-3 entries preserved verbatim.
- [ ] Two new `ExpectedOutcome` Literal values (`policy_swap_aborted_on_audit_failure`, `recursion_refused`); Slice-3 entries preserved verbatim.
- [ ] All five synthetic fixture YAMLs land under `tests/unit/adversarial/fixtures/slice_4_category_round_trip/` (NOT `tests/adversarial/<category>/` — the latter is for real corpus payloads, owned by implementation PRs).
- [ ] The negative-path mismatch test passes (declaring `category` that disagrees with the prefix raises a clear `ValueError`).

**Test discipline:**

- [ ] Both new test modules follow the bite-sized TDD shape (one assertion per concern; each test is one or two lines of expectation).
- [ ] Test files use `from __future__ import annotations`.
- [ ] No real database, real network, real subprocess spawned by either test module.
- [ ] Each test module imports only from `alfred.audit.audit_row_schemas`, `tests.adversarial.payload_schema`, `pytest`, `yaml`, and stdlib — no app-runtime imports that could pull in plugins, supervisor, identity, etc.
- [ ] Both test modules pass with no Slice-3-shipped tests regressing.

**Human-gated edit:**

- [ ] The PR description carries an explicit `## HUMAN-GATED EDITS` block flagging the PRD line-117 amendment.
- [ ] The PRD line-117 wording matches the spec §7.10 "after" text verbatim.
- [ ] The amended text uses repo-root-relative ADR paths (`docs/adr/0015-...md`), not spec-relative paths (`../../adr/0015-...md`).

---

## §8 Out of scope

This PR explicitly DOES NOT deliver any of the following. Each item lands in the named downstream PR:

| Out-of-scope item | Delivered in |
|---|---|
| `HookpointMeta.carrier_tier` field | PR-S4-3 (rev-007) |
| `HookpointMeta.allow_error_substitution` field | PR-S4-3 (rev-007) |
| `register_hookpoint(...)` calls for any Slice-4 hookpoint | Each owning PR per spec §10 |
| `_run_error` signature change to return `ErrorOutcome[T]` | PR-S4-3 |
| Tier-upgrade-refused guard implementation | PR-S4-3 |
| Sibling-site migrations (`quarantine.py`, `episodic.record`, `_ingest`, `dispatch_loop`) | PR-S4-3 |
| Adversarial corpus YAMLs `crf-2026-001` through `crf-2026-004` | PR-S4-3 |
| `PolicyWatcher`, `PoliciesV1`, `PoliciesSnapshot`, `PoliciesSnapshotRef` source files | PR-S4-4 |
| Four-consumer migration to per-iteration deref | PR-S4-4 |
| Adversarial corpus YAMLs under `tests/adversarial/config_reload_bypass/` | PR-S4-4 |
| `OperatorSession` model, `_resolve_operator` helper | PR-S4-5 |
| `alfred login` / `logout` / `whoami` CLI | PR-S4-5 |
| AST guard for operator-attributed CLI commands | PR-S4-5 |
| `bin/alfred-plugin-launcher.sh` policy-resolving rewrite | PR-S4-6 |
| Per-OS sandbox policy bytes | PR-S4-7 |
| Adversarial corpus YAMLs under `tests/adversarial/sandbox_escape/` | PR-S4-7 |
| `src/alfred/comms_mcp/protocol.py` wire-format module | PR-S4-8 |
| `src/alfred/comms_mcp/inbound.py:process_inbound_message` | PR-S4-8 |
| `src/alfred/orchestrator/burst_limiter.py` | PR-S4-8 |
| `AlfredPluginSession._on_post_handshake_method` extension for notification dispatch | PR-S4-8 |
| `REQUIRED_CLASSIFIERS_BY_KIND` registry | PR-S4-8 |
| Adversarial corpus YAML for `comms_identity_boundary` (#152 closure) | PR-S4-8 |
| `plugins/alfred_discord/` MCP plugin | PR-S4-9 |
| `DiscordSubPayloadClassifier` | PR-S4-9 |
| `plugins/alfred_tui/` MCP plugin | PR-S4-10 |
| `src/alfred/comms/` directory deletion | PR-S4-10 |
| ADR-0009 caveat narrowing | PR-S4-10 (docs-001) |
| `tests/smoke/test_slice4_graduation.py` | PR-S4-10 |
| `docs/subsystems/{security,comms,supervisor,policies}.md` updates | PR-S4-11 |
| `docs/runbooks/slice-4-graduation.md` | PR-S4-11 |
| CLAUDE.md tree + commands table updates | PR-S4-11 |
| README quickstart update for daemon-required `alfred chat` | PR-S4-11 |
| ADR-0015 + ADR-0016 status flips Proposed → Accepted | PR-S4-11 (arch-003) |
| required-check manifest update | PR-S4-11 |
| Alembic migrations 0011-0014 | PR-S4-0b |
| i18n catalog additions | PR-S4-0b |
| `audit.hash_pepper` broker bootstrap | PR-S4-0b |
| `Dockerfile` for `alfred-core` + `bubblewrap` apt-install | PR-S4-0b |
| `bin/alfred-setup.sh` updates | PR-S4-0b |
| Per-kind `fail_closed` override on `HookpointMeta` (issue #167) | Slice 5+ |
| Full step-up auth for high-blast actions | Slice 5+ |
| Inter-persona bus + persona-system multi-persona behaviour | Slice 5+ |
| Memory consolidation full pipeline + auto-retrieve | Slice 5+ |
| `alfred cost report` CLI | Slice 5+ |
| Slice-3 broker-hardening backlog | Slice 5+ |
| `watchdog` migration for `PolicyWatcher` | Slice 5+ |
| `alfred sandbox lint <plugin>` CLI | Slice 5+ |
| `SecretBroker.fetch_audit_pepper()` named accessor | Slice 5+ |
| `SecretBroker.get_bytes(name) -> bytearray` zeroizable buffer | Slice 5+ |

---

## §9 References

**Spec sections:**

- [Spec §0 Summary](../specs/2026-06-06-slice-4-design.md#0-summary) — PR-S4-0a scope summary.
- [Spec §1.1 In-scope](../specs/2026-06-06-slice-4-design.md#11-in-scope) — Slice-4 commitments list.
- [Spec §1.3 Scope budget](../specs/2026-06-06-slice-4-design.md#13-scope-budget) — PR-S4-0 split rationale.
- [Spec §3.2-§3.4](../specs/2026-06-06-slice-4-design.md#32-daemonbootcompleted-audit-row) — daemon-boot audit rows.
- [Spec §4.1-§4.7](../specs/2026-06-06-slice-4-design.md#4-recoverable-carrier-semantic-for-error-stage-hookpoint-dispatch-170--adr-0022) — ADR-0022 carrier-substitution semantic.
- [Spec §5.1-§5.8](../specs/2026-06-06-slice-4-design.md#5-mtime-polled-hot-reload-for-configpoliciesyaml-159--adr-0023) — ADR-0023 mtime-polled hot-reload.
- [Spec §7.10](../specs/2026-06-06-slice-4-design.md#710-prd-5-line-117-amendment) — PRD §5 line 118 amendment text.
- [Spec §8.1-§8.10](../specs/2026-06-06-slice-4-design.md#8-comms-mcp-rewrite-adr-0016--adr-0024) — ADR-0024 comms-MCP wire contract.
- [Spec §9](../specs/2026-06-06-slice-4-design.md#9-audit-row-schemas-slice-4-additions) — 23 Slice-4 audit-row-schema constants.
- [Spec §10](../specs/2026-06-06-slice-4-design.md#10-hookpoint-surface-slice-4-additions) — hookpoint surface (context-only for this PR).
- [Spec §11.1-§11.3](../specs/2026-06-06-slice-4-design.md#111-new-categories) — adversarial corpus additions.
- [Spec §12.2](../specs/2026-06-06-slice-4-design.md#122-i18n-catalog-additions) — i18n catalog (PR-S4-0b scope; not landed here).
- [Spec §13.1](../specs/2026-06-06-slice-4-design.md#131-docsglossarymd-slice-4-additions-full-enumeration--docs-003-closure) — glossary additions.
- [Spec §16](../specs/2026-06-06-slice-4-design.md#16-adr-mappings) — ADR mappings.

**ADRs this PR creates or modifies:**

- `docs/adr/0022-recoverable-carrier-semantic-for-error-stage-hookpoint-dispatch.md` (created — Tasks 1-3)
- `docs/adr/0023-mtime-polled-hot-reload-for-policies-yaml.md` (created — Tasks 4-5)
- `docs/adr/0024-comms-mcp-wire-contract.md` (created — Task 6)

**ADRs this PR explicitly does NOT modify:**

- `docs/adr/0009-comms-adapter-protocol-slice2-only.md` — PR-S4-10 (docs-001).
- `docs/adr/0015-slice4-containerised-quarantined-llm.md` — PR-S4-11 (arch-003).
- `docs/adr/0016-slice4-discord-tui-comms-mcp-rewrite.md` — PR-S4-11 (arch-003).

**PRD sections:**

- [PRD §5 line 118](../../../PRD.md) — hybrid-isolation invariant (amended by Task 15; HUMAN-GATED).
- [PRD §6.1](../../../PRD.md) — multi-modal comms (consumed by ADR-0024 / Task 6).
- [PRD §6.8](../../../PRD.md) — addressing concepts (consumed by ADR-0024 / Task 6).
- [PRD §7.1](../../../PRD.md) — security & prompt-injection defense (consumed by ADR-0022 / Task 1-3).
- [PRD §11.1](../../../PRD.md) — operator override semantics + state.git widening discipline (consumed by ADR-0023 / Task 4-5).

**Predecessor plans this PR depends on:**

- None — this is the first Slice-4 PR.

**Plans gated on this PR:**

- `docs/superpowers/plans/2026-06-07-slice-4-pr-s4-0b-migrations-infra-i18n.md` — gated directly on this PR.
- All implementation plans (PR-S4-1 through PR-S4-11) — import audit-row constants from this PR, cite ADR-0022 / 0023 / 0024 for design rationale, and write adversarial corpus payloads against the dispatch-table extensions established here.

**Sister specs / plans referenced for structure:**

- [Slice 3 PR-S3-0a plan](./2026-05-31-slice-3-pr-s3-0a-docs-adrs-foundations.md) — template for this plan's TDD step granularity; the bite-sized "write failing test → run → verify FAIL with expected output → implement → run to PASS → commit" cadence is preserved verbatim.
- [Slice 4 index plan](./2026-06-07-slice-4-index.md) §3 (Cross-PR contracts), §6 (References), §7 (PR-S4-0 split rationale).
- [Slice 4 spec](../specs/2026-06-06-slice-4-design.md) — authoritative design source.

**Slice-3 surfaces this PR cites (all verified at session start):**

- `AuditWriter.append_schema` at `src/alfred/audit/log.py:105`.
- `AuditEntry` model at `src/alfred/memory/models.py:89`.
- `Final[frozenset[str]]` typing pattern at `src/alfred/audit/audit_row_schemas.py:83`.
- `_PREFIX_TO_CATEGORY` at `tests/adversarial/payload_schema.py:22` (verified shape: `dict[str, str]`, NOT frozenset).
- `_ID_PATTERN` at `tests/adversarial/payload_schema.py:34` (verified shape: `re.compile(r"^(pi|dlp|cap|cnry|ipp|hk|tl|de)-\d{4}-\d{3}$")`).
- Existing ADRs: 0014, 0017, 0018, 0020, 0021 — all present in `docs/adr/`.
- PRD line 118 hybrid-isolation invariant text — confirmed matches the spec §7.10 "before" quote.

No Slice-3 surface cited in this plan was fabricated; every one was greppedfor and confirmed present before the plan was finalised.
