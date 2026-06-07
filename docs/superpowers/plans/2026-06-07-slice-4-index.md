# Slice 4 — Implementation Plan Index

> **Slice 4 = PRD §5 line 117 hybrid-isolation closure + Discord+TUI comms-MCP rewrite + Slice-3 carryover closure.**
> Spec: [`docs/superpowers/specs/2026-06-06-slice-4-design.md`](../specs/2026-06-06-slice-4-design.md) — reviewed across 4 `/review-pr` rounds (61 → 38 → 16 → 8 findings) and merged in #204.
> Load-bearing ADRs landing at PR-S4-0a: ADR-0022 (recoverable-carrier semantic), ADR-0023 (mtime-polled hot-reload), ADR-0024 (comms-MCP wire contract).
> Status-flipping ADRs landing at PR-S4-11 graduation: ADR-0015 (sandbox containerisation), ADR-0016 (comms-MCP rewrite) — both Proposed → Accepted.
> Plans below are sequenced; each PR's plan states what the next may assume.

---

## §1 Scope

### Slice-4 commitments

[Spec §1.1](../specs/2026-06-06-slice-4-design.md#11-in-scope) carries the in-scope list. In summary, the slice ships:

1. **Daemon boot + production dispatch** (#174) — `alfred daemon start` constructs `Supervisor(state_git_path=…)` with pre-`TaskGroup` probes (launcher policy-resolving, snapshot-ref init, capability-gate handshake). PR-S4-1.
2. **`OutboundDlp.scan` into `processed_proposals.failure_detail`** (#173) — threads `OutboundDlpProtocol` through `ProposalContext`; renames `_truncated_detail` → `_redacted_detail`; emits `PROPOSAL_DISPATCH_FAILURE_REDACTED_FIELDS` on every write (success-with-redactions ≥0); `DLP_OUTBOUND_REFUSED_FIELDS` aborts on refusal. PR-S4-2.
3. **Recoverable-carrier semantic** (#170 / ADR-0022) — `_run_error` returns `ErrorOutcome = ReRaise() | SubstituteResult[T]`. Tier-upgrade guard: refuse if `substitute_tier > carrier_tier` in strict total order. `HookpointMeta.carrier_tier` + `HookpointMeta.allow_error_substitution` field additions. PR-S4-3.
4. **mtime-polled hot-reload** (#159 / ADR-0023) — `PolicyWatcher` (mtime-gated read, ~0.1ms idle tick), `PoliciesV1` Pydantic v2, `PoliciesSnapshotRef.current()` lock-free O(1) **sync** read, audit-then-swap two-phase commit, watcher-side SHA short-circuit for idempotency. PR-S4-4.
5. **CLI operator session** — `alfred login/logout/whoami` with TOFU session file (mode 0600, open-then-fstat-validate), per-OS system-owned machine-id, `_resolve_operator` with 5ms p99 budget + 250ms hard timeout via `asyncio.wait_for`, `babel.dates` locale formatting for whoami timestamps. Closes #153. PR-S4-5.
6. **Sandbox launcher foundations** (ADR-0015) — `bin/alfred-plugin-launcher.sh` (bash) extended with policy-resolving behaviour via a pre-launcher Python manifest reader. `Settings.environment` mandatory (no fallback). Dev escape hatch refuses in production with operator-visible stderr message. Provider key handled via fd-3 inheritance pattern (`bwrap --keep-fd 3`); Supervisor side holds key in `str` briefly then `gc.collect()`s. PR-S4-6.
7. **Sandbox policy bytes** (ADR-0015) — Linux bwrap policy (primary target — kernel-enforced), macOS sandbox-exec policy (best-effort second-class per ADR-0015 — Apple deprecated the framework but it still works; spec §7.6 notes this; verification only on best-effort basis), Windows stub policy. Quarantined-LLM manifest migrates `kind: none` → `kind: full` with `policy_refs` per-OS map. Insider-author + runtime-compromised + misconfigured-policy attacker models (≥5 flags + schema-downgrade variant). PR-S4-7.
8. **Comms-MCP foundations** (ADR-0016 / ADR-0024) — `src/alfred/comms_mcp/protocol.py` (wire-format owner); `src/alfred/comms_mcp/inbound.py:process_inbound_message` (host-side entrypoint); host-side `REQUIRED_CLASSIFIERS_BY_KIND` registry (sec-002 closure — plugins cannot bypass via empty list); `AlfredPluginSession._on_post_handshake_method` extended to dispatch notifications (NOT a fabricated `_read_loop` — see verification-gate discipline below); `BurstLimiter` (new Slice-4 primitive at `src/alfred/orchestrator/burst_limiter.py`) gates per-(canonical_user_id, persona) RPS. Closes #152. PR-S4-8.
9. **Discord adapter as MCP plugin** (ADR-0016 Discord) — `plugins/alfred_discord/`; nine sub-payload kinds covered by `DiscordSubPayloadClassifier`; persona-addressing modes (DM/mention/channel/thread); idempotency-keyed outbound; rate-limit honour via `OutboundQueue.pause(adapter_id, retry_after_seconds)`. PR-S4-9.
10. **TUI adapter as MCP plugin + flag-day** (ADR-0016 TUI) — `plugins/alfred_tui/` keeps the Textual rendering layer; `src/alfred/comms/` directory deletion (one shot, no path collision with `src/alfred/comms_mcp/`); ADR-0009 *caveat narrowed* (the "for new adapters" qualifier removed, not a status flip); `tests/smoke/test_slice4_graduation.py` ships here (`alfred chat` is the TUI plugin). PR-S4-10.
11. **Graduation** — `docs/subsystems/{security,comms,supervisor,policies}.md` updates; `docs/runbooks/slice-4-graduation.md` (12 sections including Vocabulary signposting glossary terms — devex-007); CLAUDE.md tree + commands table updates; README quickstart update for `alfred chat` daemon-required behaviour; ADR-0015/0016 status flips Proposed → Accepted (arch-003 closure — flipping at graduation matches slice-3 precedent). PR-S4-11.

### Explicit out-of-scope (deferred to Slice 5+)

- **#167 per-kind `fail_closed` override** on `HookpointMeta` — no current consumer demands the asymmetric policy.
- **Full step-up auth** (PRD §7.1 out-of-band DM confirmation) — the minimal CLI session-file login lands here; step-up needs the comms-MCP rewrite in production first.
- **Inter-persona bus + persona-system multi-persona behaviour**.
- **Memory consolidation full pipeline + auto-retrieve**.
- **`alfred cost report` CLI**.
- **Slice-3 broker-hardening backlog** (typed `SecretRef`, broker-side post-substitution invariant check, per-secret-ID canaries, audit-log secret-ID match assertion, `SecretBroker.get_bytes(name) -> bytearray` for zeroizable secrets).
- **`watchdog` migration for `PolicyWatcher`** (inotify/FSEvents/ReadDirectoryChangesW).
- **`alfred sandbox lint <plugin>` CLI**.

### 12-PR breakdown

Spec §1.3 commits Slice 4 to ship as 12 PRs mirroring Slice 3's foundations-first + max-parallelism shape.

| PR | Slug | What it delivers |
|---|---|---|
| PR-S4-0a | docs-adrs-foundations | ADR-0022/0023/0024 full bodies; `audit_row_schemas.py` Slice-4 additions; `payload_schema.py` Slice-4 Literal + `_PREFIX_TO_CATEGORY` + `_ID_PATTERN` additions (preserving `prefix-YYYY-NNN` format); `docs/glossary.md` initial additions. ADR-0015/0016 stay Proposed (status flips deferred to PR-S4-11). |
| PR-S4-0b | migrations-infra-i18n | Alembic **0012–0015** (the chain starts at 0012 because `0011_processed_proposals.py` already exists on `main` from Slice-3 carryover — mem-001 closure) + SQLAlchemy models; i18n catalog enumeration; **`docker/alfred-core.Dockerfile` already exists** and `docker-compose.yaml` already uses `build:` since Slice 2 (devops closure) — PR-S4-0b's work is `apt-get install -y bubblewrap` in the existing Dockerfile base layer, NOT a build-flip; `bin/alfred-setup.sh` gets a bubblewrap presence-check + apt-install (Linux) / no-op (macOS) / WSL2-hint (Windows). Bootstraps `audit.hash_pepper` secret in broker. |
| PR-S4-1 | daemon-boot-dispatch | `alfred daemon start/stop/status` subcommands; pre-`TaskGroup` probe orchestration **at CLI layer** (not in `Supervisor.start()`); `daemon.boot.*` audit-row emit; smoke test. Launcher probe is a no-op stub until PR-S4-6. |
| PR-S4-2 | dlp-failure-detail | `OutboundDlpProtocol` through `ProposalContext`; rename + body rewrite emitting two disjoint constants; adversarial entries `dispatch_loop_failure_detail_leak` + `dispatch_loop_failure_detail_canary_refused`. |
| PR-S4-3 | carrier-substitution | ADR-0022 implementation; `_run_error` signature change; strict-total-order tier-comparison guard; four sibling-site migrations (`alfred.security.quarantine`, `alfred.memory.episodic`, `alfred.identity._ingest`, `alfred.state.dispatch_loop`); adversarial entries `crf-2026-001` … `crf-2026-004` including meta-hookpoint recursion; **`HookpointMeta.carrier_tier` + `HookpointMeta.allow_error_substitution` field additions** (PR-S4-3 ships these; rev-007 closure). |
| PR-S4-4 | policy-hot-reload | ADR-0023 implementation; `PolicyWatcher` + `PoliciesV1` + `PoliciesSnapshotRef`; four-consumer migration; audit + adversarial entries; runbook back-patches. `_capability_heartbeat_loop` is NOT a snapshot consumer (core-009). |
| PR-S4-5 | cli-operator-session | `alfred login` (with bare-`alfred login` discoverability flow) / `logout` / `whoami`; `OperatorSession` model + open-then-fstat TOCTOU-safe load; per-OS system-owned machine-id; `_resolve_operator` with 5ms p99 + 250ms timeout; AST guard. Closes #153. |
| PR-S4-6 | sandbox-launcher | `bin/alfred-plugin-launcher.sh` policy-resolving extension (bash, not Python — sec-004 honest); mandatory `Settings.environment`; dev-escape-hatch operator-visible stderr; quarantined-LLM manifest update; `bwrap --keep-fd 3` fd-3 inheritance pattern. |
| PR-S4-7 | sandbox-policies | Linux bwrap policy; macOS sandbox-exec policy; Windows stub policy; per-OS integration tests with 3 attacker models; adversarial sandbox-escape corpus (`sbx-2026-*`); CI runner topology (ubuntu-latest merge-blocking, macos-latest advisory). |
| PR-S4-8 | comms-mcp-foundations | ADR-0024 wire-contract implementation; `AlfredPluginSession._on_post_handshake_method` extended to dispatch notifications (verification-gate confirmed: this method exists at `src/alfred/plugins/session.py:347`) **preserving the SIGKILL-before-audit branch as the first match arm** so the pre-extension security invariant is unchanged (comms-001 closure); per-adapter `asyncio.BoundedSemaphore` with `async with`; `process_inbound_message` with T3-default body + `quarantined_extract` chain; host-side classifier registry; **`BurstLimiter`** at `src/alfred/orchestrator/burst_limiter.py`; real identity-boundary test with positive resolver-consulted-once assertion + binding-flow case + inter-persona forgery variant. Adds new `Supervisor.request_plugin_restart` AND new `Supervisor.trip_breaker(component_id, reason)` — neither exists on Slice-3 `Supervisor` (verified: `src/alfred/supervisor/core.py` exposes only `reset_breaker` + `get_or_create_breaker`; core-engineer finding from `/review-plan` round 1). Closes #152. |
| PR-S4-9 | discord-mcp-adapter | `plugins/alfred_discord/`; `DiscordSubPayloadClassifier` at `src/alfred/comms_mcp/classifiers/discord.py`; nine sub-payload kinds; persona-addressing four-mode mapping (DM/mention/channel/thread → PRD §6.8 concepts); idempotency-keyed outbound with `OutboundMessageResult` discriminated union (3 variants); rate-limit honour via `OutboundQueue.pause`; HMAC-with-pepper hash recipe using `SecretBroker.get("audit.hash_pepper")`. |
| PR-S4-10 | tui-mcp-adapter-flag-day | `plugins/alfred_tui/` (Textual rendering layer preserved); `alfred chat` rewires to launcher spawn; consumer-break migrations (real filenames: `tests/smoke/test_tui_e2e.py`, `tests/smoke/test_discord_gateway_smoke.py`, `src/alfred/identity/_ingest.py`, `src/alfred/cli/main.py`, `tests/unit/comms/test_no_direct_adapter_imports.py`); `src/alfred/comms/` deletion (one shot); ADR-0009 caveat narrowing (not a status flip); `tests/smoke/test_slice4_graduation.py` ships here (`alfred chat` exercises the TUI plugin); `bin/alfred-setup.ps1` Windows WSL2 redirect. |
| PR-S4-11 | docs-glossary-graduation | `docs/subsystems/{security,comms,supervisor,policies}.md` updates; `docs/runbooks/slice-4-graduation.md` (12 sections); CLAUDE.md tree + commands table updates (`plugins/alfred_discord/`, `plugins/alfred_tui/`, `src/alfred/comms_mcp/`, `bin/alfred-plugin-launcher.sh`, `alfred daemon`, `alfred login/logout/whoami`); README quickstart `alfred chat` update; **ADR-0015 + ADR-0016 status flips Proposed → Accepted**; required-check manifest update; slice sign-off. |

---

## §2 PR ordering and dependencies

```
                ┌──► PR-S4-1 ──► PR-S4-2 ─────────────────────────────┐
                │                                                       │
                │    ┌──► PR-S4-4 ──────────────────────────────────────┤
                │    │                                                  │
PR-S4-0a ─► 0b ─┤    │    ┌──► PR-S4-7 ────────────────────────────────┐│
                │    │    │                                            ││
                └─► S4-3 ─┼──► PR-S4-6 ──► PR-S4-7 (above) ────────────┤│
                         │                                             ││
                         └──► PR-S4-5 ──► PR-S4-8 ──► PR-S4-9 ──► PR-S4-10 ──► PR-S4-11

  Critical path (depth 8): 0a → 0b → 3 → 5 → 8 → 9 → 10 → 11.

  PR-S4-3 is ancestor of every other hookpoint-registering PR
  (S4-1, S4-4, S4-5, S4-6, S4-7, S4-8, S4-9) because their
  `register_hookpoint(...)` calls must populate the new
  `carrier_tier` field that PR-S4-3 adds to `HookpointMeta`.
  See spec §4.7 + rev-009 round-3 closure + sec-idx-001/core-eng-004
  closures (the `HookpointMeta` migration ships as Optional → tighten
  inside PR-S4-3 itself, see §3).

  Diagram simplified from round-1 wider form per arch-003 closure.
```

Explicit `depends_on` per PR:

| PR | Depends on | Blocks |
|---|---|---|
| PR-S4-0a | — (first PR) | all downstream |
| PR-S4-0b | S4-0a | all downstream |
| PR-S4-3 | S4-0a, S4-0b | S4-1, S4-4, S4-5, S4-6, S4-7, S4-8, S4-9 (hookpoint-registration dep — rev-009) |
| PR-S4-1 | S4-0a, S4-0b, **S4-3** | S4-2, S4-11 |
| PR-S4-2 | S4-0a, S4-0b, **S4-3**, S4-1 | S4-11 |
| PR-S4-4 | S4-0a, S4-0b, **S4-3** | S4-11 |
| PR-S4-5 | S4-0a, S4-0b, **S4-3** | S4-8, S4-11 |
| PR-S4-6 | S4-0a, S4-0b, **S4-3** | S4-7, S4-9, S4-10 |
| PR-S4-7 | S4-0a, S4-0b, **S4-3**, S4-6 | S4-11 |
| PR-S4-8 | S4-0a, S4-0b, **S4-3**, S4-5 | S4-9, S4-10 |
| PR-S4-9 | S4-0a, S4-0b, **S4-3**, S4-5, S4-6, S4-8 | S4-10, S4-11 |
| PR-S4-10 | S4-0a, S4-0b, **S4-3**, S4-5, S4-6, S4-8, S4-9 | S4-11 |
| PR-S4-11 | ALL prior PRs (S4-0a through S4-10) | — (final PR) |

**Parallelism notes.** After PR-S4-3 lands (which depends only on S4-0a/S4-0b), five threads can begin in parallel: PR-S4-1, PR-S4-4, PR-S4-5, PR-S4-6, plus (later) PR-S4-2 (trails S4-1 + S4-3 — arch-002 closure: PR-S4-2 touches the dispatch-loop error path that PR-S4-3 owns) and PR-S4-7 (trails S4-6). The critical path is `0a → 0b → 3 → 5 → 8 → 9 → 10 → 11` (**8 PRs**; the prior wording of "seven" reflected the spec §1.3 narrative pre-rev-009 when PR-S4-3 was a peer of S4-1/S4-4/S4-5/S4-6 — the rev-009 round-3 fix promoted S4-3 to ancestor of every hookpoint-registering PR, adding one hop to the critical path. The spec §1.3 reads "seven PRs deep" for historical reasons; the implementation-side critical path is 8 — arch-001 closure). Slice-4's HookpointMeta extension serializes more downstream PRs behind PR-S4-3 than the prior slice.

---

## §3 Cross-PR contracts

These surfaces are defined in one PR and consumed by later PRs. Drift between PRs is a release blocker.

### `audit_row_schemas.py` constants (defined in PR-S4-0a)

Spec §9 lists 22 Slice-4 audit-row-schema constants. Each implementation PR imports the named constant; no PR may inline a field-list literal at the call site. Every audit emit site uses `await self._audit.append_schema(fields, **kwargs)`.

| Constant | Consuming PRs |
|---|---|
| `DAEMON_BOOT_FIELDS` / `DAEMON_BOOT_FAILED_FIELDS` / `DAEMON_BOOT_ENVIRONMENT_SOURCE_CONFLICT_FIELDS` | S4-1, S4-6 (env-source check), S4-11 (docs) |
| `PROPOSAL_DISPATCH_FAILURE_REDACTED_FIELDS` | S4-2 (always emit, redactions ≥0) |
| `CARRIER_SUBSTITUTION_FIELDS` / `CARRIER_SUBSTITUTION_REFUSED_FIELDS` | S4-3 (and 4 sibling-site migrations) |
| `CONFIG_RELOAD_FIELDS` / `CONFIG_RELOAD_REJECTED_FIELDS` | S4-4 (`reason` Literal includes `audit_write_failed` — err-011 round-4 closure) |
| `OPERATOR_SESSION_CREATED/REVOKED/REFUSED_FIELDS` / `SUPERVISOR_BREAKER_RESET_REFUSED_FIELDS` (the latter is **intentional Slice-4 scope** per arch-005 closure — it covers the `alfred supervisor reset` refusal path when no operator session is present, which is the #153 closure surface defined by ADR-0020) | S4-5 |
| `SANDBOX_REFUSED_FIELDS` / `SANDBOX_STUB_USED_FIELDS` | S4-6, S4-7 |
| `COMMS_INBOUND_T3_PROMOTION_FIELDS` / `COMMS_BINDING_REQUESTED_FIELDS` / `COMMS_ADAPTER_CRASHED_FIELDS` / `COMMS_RATE_LIMIT_SIGNAL_FIELDS` / `COMMS_UNKNOWN_NOTIFICATION_FIELDS` / `COMMS_HANDLER_FAILED_FIELDS` / `COMMS_ADDRESSING_DRIFT_FIELDS` / `COMMS_INBOUND_BUDGET_CAPPED_FIELDS` | S4-8 (host-side emit — adapters never write audit) |
| `SUPERVISOR_PLUGIN_RESTART_REQUESTED_FIELDS` | S4-8 (core-010 round-3 closure) |

PR-S4-0a's test `tests/unit/audit/test_audit_constants_slice_4.py` asserts every field name in every constant is a valid column in the `AuditEntry` model (at `src/alfred/memory/models.py:89`). PR-S4-0b's Alembic migrations add the new columns if any.

**Partition-anchor invariant** (mem-003 + arch-004 closure): every audit-row constant whose field-set includes operator-attribution (`OPERATOR_SESSION_*_FIELDS`, `SUPERVISOR_BREAKER_RESET_*_FIELDS`, every `*` row that emits with `operator_user_id`) MUST also carry the `canonical_user_id` partition-anchor field. PR-S4-0a's `tests/unit/audit/test_audit_constants_slice_4.py` adds a positive assertion: for every constant in the operator-attributed set, `"canonical_user_id" in fields`. The `AuditEntry` model's `canonical_user_id NOT NULL` invariant is the partition key Postgres consults; an emit that lands without it would create a partition-leak class defect (CLAUDE.md hard rule #2 on per-user scoping). The Slice-3 `DAEMON_BOOT_FIELDS` and `proposal.dispatch.*` rows are exempt because they are pre-session events; the test's positive set excludes them by explicit Literal allowlist.

**Trust-boundary guarantee for `quarantined_extract`** (rev-idx-002 + sec + mem closures): when the host calls `Orchestrator.quarantined_extract(notification.body, source_tier="T3")`, the **privileged orchestrator NEVER reads `notification.body`**. The orchestrator's role is purely to construct the call, hand it to the quarantined-LLM plugin via the Slice-3 MCP transport, and receive a typed `ExtractionResult(data: T3DerivedData, schema_version=1)` whose `.data` field is the only thing that crosses the dual-LLM boundary. `T3DerivedData` is a `NewType` (Slice-3 at `src/alfred/security/quarantine.py:145`) that carries `source_tier="T3"` invariantly — no silent T3→T2 promotion (sec-001 round-3 closure). PR-S4-8's merge-blocking `tests/integration/test_comms_mcp_identity_boundary_real.py` plants T3-tier prompt-injection payloads in `notification.body` AND asserts they never appear in any privileged-orchestrator call log; PR-S4-3's adversarial corpus `crf-2026-001 malicious_error_subscriber_attempts_tier_upgrade` then re-verifies the §4.4 strict-total-order guard refuses any error-stage substitute that would silently widen the body's tier.

### Hookpoint surface (Spec §10 table — single source of truth)

Each row's "Declared in PR" column is authoritative (arch-007 round-4 closure — round-2/3 had triple-claim that's collapsed to a single rule). Highlights:

| Hookpoint | Declared in | Carrier tier |
|---|---|---|
| `daemon.boot.completed` / `daemon.boot.failed` / `proposal.dispatch.failed` | PR-S4-1 | T0 |
| `hooks.carrier_substituted` / `hooks.carrier_substitution_refused` | PR-S4-3 (the only PR-S4-3-registered hookpoints) | n/a (observation-only) |
| `supervisor.config_reload` / `supervisor.config_reload_rejected` / `supervisor.config_watcher.recovered` | PR-S4-4 | T0 |
| `operator.session.created/revoked/refused` | PR-S4-5 | T1 |
| `supervisor.plugin.sandbox_refused` | PR-S4-6 | T0 |
| `supervisor.plugin.sandbox_stub_used` | PR-S4-7 | T0 |
| `comms.inbound.t3_promoted` / `comms.adapter.crashed` | PR-S4-8 | T3 / T0 |
| `comms.adapter.binding_requested` / `comms.adapter.rate_limit_signal` | PR-S4-9 | T3 / T0 |

`hooks.carrier_substituted` and `hooks.carrier_substitution_refused` carry `fail_closed=False` (observation-only) per spec §4.7. Every other Slice-4 hookpoint carries `fail_closed=True` uniformly across all kinds (#167 deferred).

### `payload_schema.py` Literal + dispatch-table additions (defined in PR-S4-0a)

```python
SLICE_4_CATEGORIES = frozenset({
    "sandbox_escape", "config_reload_bypass", "carrier_substitution_tamper",
    "operator_session_forgery", "comms_identity_boundary",
})

# Slice-4 ADDITIONS to existing _PREFIX_TO_CATEGORY (test-006 closure — preserve prefix-YYYY-NNN format):
_PREFIX_TO_CATEGORY.update({
    "sbx": "sandbox_escape",
    "crf": "carrier_substitution_tamper",
    "csb": "config_reload_bypass",
    "osf": "operator_session_forgery",
    "cib": "comms_identity_boundary",
})

_ID_PATTERN = re.compile(
    r"^(pi|dlp|cap|cnry|ipp|hk|tl|de|sbx|crf|csb|osf|cib)-\d{4}-\d{3}$"
)
```

All adversarial tests in implementation PRs reference these constants — no PR inlines its own Literal. PR-S4-0a's test `tests/unit/adversarial/test_slice_4_categories.py` asserts every Slice-4 corpus YAML's `id:` matches the regex and that each prefix maps to the declared category.

### `HookpointMeta.carrier_tier` + `allow_error_substitution` (defined in PR-S4-3)

PR-S4-3 extends `src/alfred/hooks/registry.py:HookpointMeta` with two new fields. PR-S4-0a does NOT touch HookpointMeta (rev-007 closure — runtime-type changes belong with the carrier-substitution PR). **The fields ship with a coordinated migration plan** (sec-idx-001 + core-eng-004 + mem-002 closures from `/review-plan` round 1):

1. `carrier_tier: TrustTier | None = None` ships as **Optional with `None` default** so PR-S4-3 lands without breaking the ~6 existing Supervisor hookpoints + every Slice-2.5/3 publisher.
2. Every existing `register_hookpoint(...)` call in `src/` is migrated in PR-S4-3 itself to pass an explicit `carrier_tier=` value (the wave migration the index promised; not deferred).
3. After PR-S4-3 lands, **a second-stage tightening** in the SAME PR flips the field to required (`carrier_tier: TrustTier`) once all in-tree call sites carry the value. Final commit of PR-S4-3.
4. **Dynamic / runtime-registered hookpoints** (plugins, runtime skills via `HookpointMeta(carrier_tier=…)`) are caught by a Pydantic field-validator on `HookpointMeta` itself — NOT only by the AST guard. The AST guard catches in-tree `register_hookpoint(...)` calls in `make check`; the runtime validator catches plugin/skill registrations at the moment of construction. Both layers ship in PR-S4-3.
5. **`alfred.memory.episodic.record` carrier_tier** must be computed per-call from `EpisodicRecordInput.trust_tier` at `src/alfred/memory/episodic.py:177` — NOT hardcoded T2 (mem-002 closure: episodic record handles T2 *and* T3 inbound bodies from PR-S4-8 comms; hardcoded T2 would refuse legitimate T3 substitutes via §4.4 tier-upgrade guard).

### `PoliciesSnapshotRef` lock-free O(1) sync read (defined in PR-S4-4)

`PoliciesSnapshotRef.current()` returns `PoliciesSnapshot` **synchronously** (perf-002 round-2 closure — round-1's async-await trampoline overhead was unnecessary; GIL-atomic single-attribute load is the implementation). Forbidden idiom: `cap = ref.current().handle_caps.foo; await something(); use(cap)` (snapshot may have swapped). Required idiom: per-iteration deref inside long-lived loops. Slice-3-shipped consumer loops that migrate (**`_proposal_dispatch_loop`** in `src/alfred/supervisor/core.py` — PR-S4-4's plan must `grep`-confirm the actual line at PR-time; round-1's `:282` line reference was wrong per core-eng-003 closure (L282 is the heartbeat loop, not the dispatch loop), and the dispatch loop reads no policy values today, so PR-S4-4's plan must enumerate WHICH new values the dispatch loop must deref before adding the migration), `PolicyWatcher.run` itself, and the four `src/alfred/plugins/web_fetch/` consumer loops (note: the consumer modules live under `src/alfred/plugins/web_fetch/`, NOT `src/alfred/web_fetch/` as the spec sometimes implies) all gain per-iteration deref. AST guard runs over the four migrated consumer modules.

### `OperatorSession` model + file-load contract (defined in PR-S4-5)

Spec §6 carries the full model. File at `~/.config/alfred/session`, mode `0600` mandatory. Load discipline (sec-006 round-2 closure):

1. `open(path, O_RDONLY | O_NOFOLLOW)` — refuse symlinks.
2. `fstat(fd)` on the open fd — validate `st_mode == 0600`, `st_uid == os.getuid()`, `st_gid == os.getgid()`.
3. Only after `fstat` passes, read contents.

Per-OS machine-id sources (sec-006 round-2 closure):

- Linux: `/etc/machine-id` then `/var/lib/dbus/machine-id`. Both unreadable → refuse with `login.no_machine_id`.
- macOS: `IOPlatformUUID` cached at `/var/db/alfred/machine-id`.
- Windows: `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\MachineGuid`.

`_resolve_operator` budget: 5ms p99 with `uq_operator_sessions_token_hash` index; 250ms hard timeout via `asyncio.wait_for` raising `OperatorSessionTimeout`. The list of operator-attributed audit-row constants (every constant whose field-set includes `operator_user_id`) is enumerable from `audit_row_schemas.py`; PR-S4-5 plumbs `_resolve_operator` through every CLI command that emits one.

### Sandbox plugin-manifest declaration + launcher contract (defined in PR-S4-6, consumed by PR-S4-7/8/9/10)

Every plugin manifest gains:

```yaml
sandbox:
  kind: full | none | stub
  policy_refs:                  # required when kind=full
    linux: config/sandbox/<name>.linux.bwrap.policy
    macos: config/sandbox/<name>.macos.sb
    windows: config/sandbox/<name>.windows.stub.policy
```

`bin/alfred-plugin-launcher.sh` (bash — Slice-3 shipped, PR-S4-6 extends; sec-004 round-3 honest) resolves the per-OS policy by calling a pre-launcher Python helper at `src/alfred/plugins/manifest_reader.py`. Production refuse modes (each emits `SANDBOX_REFUSED_FIELDS`):

- `policy_ref_missing` / `policy_ref_os_mismatch` / `policy_ref_unreadable`
- `sandbox_block_missing`
- `windows_stub_in_production`
- `unsandboxed_env_set_in_production`

Quarantined-LLM plugin migrates `kind: none` → `kind: full` in PR-S4-6 (manifest change is a single atomic edit; PR-S4-7 ships the policy bytes). Discord and TUI declare `kind: none` (first-party in-tree relay adapters, not T3 consumers — see spec §7.9 + §7.10 PRD amendment).

### Comms-MCP wire contract (ADR-0024, defined in PR-S4-0a, implemented in PR-S4-8)

Spec §8.1 carries the four host→plugin requests + four plugin→host notifications. PR-S4-8 ships:

- The wire-format owner at `src/alfred/comms_mcp/protocol.py` (NOT `src/alfred/comms/protocol.py` — Critical 1 round-1 closure).
- Inbound notification dispatch via `AlfredPluginSession._on_post_handshake_method(method: str)` extension. **This method exists at `src/alfred/plugins/session.py:347`** — verified, NOT a fabricated surface (core-011 round-4 closure was the lesson).
- Per-adapter `asyncio.BoundedSemaphore(value=Settings.comms_max_in_flight_notifications, default=32)` via `async with` block (core-008 + perf-003 closures).
- Host-side `process_inbound_message` at `src/alfred/comms_mcp/inbound.py` with T3-default body routing through `Orchestrator.quarantined_extract(..., source_tier="T3")` returning `ExtractionResult(data: T3DerivedData)` (sec-001 round-3 closure).

Discord (PR-S4-9) and TUI (PR-S4-10) implement the wire methods. No method may be added or renamed outside an ADR-0024 amendment.

### `REQUIRED_CLASSIFIERS_BY_KIND` registry (defined in PR-S4-8, consumed by PR-S4-9 / PR-S4-10)

Host owns the per-`adapter_kind` required-classifier set at `src/alfred/comms_mcp/classifier_registry.py` (sec-002 round-3 closure — plugins cannot opt out via empty classifier list). Adapter-kind registration is a code change reviewer-gated through normal AlfredOS PR review (NOT state.git — that earlier claim was wrong). An AST guard (`tests/unit/comms_mcp/test_required_classifiers_complete.py`) refuses adding a new `adapter_kind` without a matching `REQUIRED_CLASSIFIERS_BY_KIND` entry.

Per-`adapter_kind` `BODY_FIELD_BY_KIND` mapping (defined in PR-S4-8, consumed by PR-S4-9 / PR-S4-10 — comms-011 round-3 closure):

```python
BODY_FIELD_BY_KIND: Final[Mapping[str, str]] = {
    "discord": "content", "tui": "content", "telegram": "text",  # post-MVP
}
```

**`BODY_FIELD_BY_KIND` names the PRIMARY user-authored body field only** (comms-002 + sec corroborated closure). For Discord, `content` is the human-typed text. The nine Discord sub-payload kinds (embeds, attachments, polls, link unfurls, stickers, voice messages, message components, forwarded refs, pinned refs) are **NOT** in `BODY_FIELD_BY_KIND` — they are handled by `REQUIRED_CLASSIFIERS_BY_KIND` (above) which tags each sub-payload `T3` with a `ContentHandle` *before* the body reaches `process_inbound_message`. The orchestrator-side body only ever sees the primary `content` field (T3, then `quarantined_extract`-derived), never the raw sub-payload bytes. PR-S4-9's `tests/integration/test_discord_subpayload_promotion.py` asserts every sub-payload in the test corpus is promoted to `ContentHandle` before the body is dispatched.

**Discord/TUI `kind:none` threat-model precision** (sec-idx-002 closure): Discord adapter parses raw gateway bytes pre-host-dispatch — but those bytes are **T3 from the moment they cross the WebSocket boundary**. The first-party Discord adapter at `plugins/alfred_discord/` doesn't ingest into the privileged orchestrator directly; it only forwards platform JSON to the comms-MCP transport, where `REQUIRED_CLASSIFIERS_BY_KIND` runs host-side and tags sub-payloads as `ContentHandle(T3)`. The adapter's `kind: none` declaration means "no kernel sandbox" *not* "trusted with T3 content" — the comms-MCP wire contract is what protects the orchestrator from the adapter's parsing logic. PR-S4-9's threat model and acceptance criteria (codified in `plugins/alfred_discord/THREAT_MODEL.md` shipped in PR-S4-9) make this explicit, and the merge-blocking `test_comms_mcp_identity_boundary_real.py` (PR-S4-8) verifies it end-to-end.

### Audit pepper bootstrap (defined in PR-S4-0b / consumed by PR-S4-8 / PR-S4-9)

PR-S4-0b migration adds the `audit.hash_pepper` secret to the operator's broker config; if missing at daemon boot, the daemon refuses to start with `daemon.boot.failed(failure_reason="audit_hash_pepper_missing")`. PR-S4-8 + PR-S4-9 emit-sites compute `*_hash` fields via `secret_broker.get("audit.hash_pepper")` + `hmac.new(...).hexdigest()[:32]` (sec-010 round-3 closure — uses real Slice-3 `SecretBroker.get(name)` API at `src/alfred/security/secrets.py:396`).

**Pepper rotation + persistence + threat model** (sec-idx-004 closure): the pepper is a 32-byte random value stored in the broker like any other secret. **Rotation policy**: operator-driven only — the broker exposes a CLI command to rotate any secret; rotating the pepper invalidates all existing `*_hash` cross-row correlation, which is a deliberate trade-off (the rotation key event itself is what an attacker would target if they wanted to retroactively de-anonymise the audit log). **Persistence**: the broker persists the pepper across daemon restarts; AlfredOS does not regenerate it. **Threat model**: the truncated 32-hex-char HMAC is **NOT a cryptographic commitment** — it is a correlation token to let auditors group rows by attacker-controlled platform identity without storing the raw identity. A rainbow-table attack on the 128-bit output against known-low-entropy platform IDs (e.g., Discord snowflakes) is feasible given the truncation; the pepper compensates only against precomputed tables. **Implication**: audit logs that leak alongside the pepper are correlatable; treat the pepper as a tier-T1 secret (operator-only access) per ADR-0012.

**`SecretBroker.fetch_audit_pepper()` deferral** — Slice-5 backlog (already listed in §8) ships a per-fetch audit-logged accessor; Slice 4 uses generic `.get(name)` and the `AuditWriter` holds the pepper in-memory for the daemon's lifetime. **fd-3 writer path** (prov-002 closure): the Supervisor opens `os.pipe2()`, `dup2()`s the read end to fd 3 of the launcher subprocess, writes the secret + closes the write end, and `gc.collect()`s after the write to expedite the immutable `str` reclaim per spec §7.5's documented Python-`str` residency window. PR-S4-6's plan pins the exact sequence in `src/alfred/supervisor/spawn.py` (or equivalent — verify the actual Slice-3 spawn site at PR-time).

### `BurstLimiter` primitive (new in Slice 4 — defined in PR-S4-8)

`src/alfred/orchestrator/burst_limiter.py` ships a per-(canonical_user_id, persona) token-bucket primitive (sec-008 round-3 closure — honest Slice-4 scope expansion, NOT a Slice-2 BudgetGuard which is per-user-USD-daily and cannot stop sub-second bursts).

**Default**: 5-token capacity, 1 token / 5 seconds refill = 12 inbound msgs/minute sustained per (user, persona). **Threat-model anchor for the defaults** (rev-idx-005 closure): Discord channels see ~1-3 inbound msgs/minute from a typical engaged user; 12/minute leaves 4× headroom over baseline while capping pathological bursts (paste-bombs, copy-pasted instructions, off-by-1-second loops). Site-tunable via `PoliciesV1.rate_limits.quarantined_extract_per_user_persona` (low-blast, hot-reloadable per §3 PoliciesSnapshotRef).

**Pre-binding inbound bucket** (sec-idx-003 closure): inbound notifications from unbound platform identities (the first-contact path before `IdentityResolver` returns a `canonical_user_id`) key the bucket on `(adapter_id, platform_user_id_hash)` instead of `(canonical_user_id, persona)`. The pre-binding bucket is **tighter** — 2 tokens capacity, 1 token / 30s refill = 2 msgs/minute — because unauthenticated senders cannot be cost-attributed and are a higher-priority denial-of-wallet vector. The bucket is keyed by the *hash* of the platform identifier so the host never persists the raw platform user id pre-binding. After binding completes, future notifications use the bound `(canonical_user_id, persona)` bucket.

**No-cost accounting on refused path** (prov-003 closure): a bucket-empty refusal emits `COMMS_INBOUND_BUDGET_CAPPED_FIELDS` AND does NOT increment the Slice-2 `BudgetGuard` USD-daily counter — the inbound message was never sent to the quarantined LLM, so there is no token cost to attribute. The metrics pipeline must not double-count refused inbound as both a budget-cap event and a USD debit; PR-S4-8's `tests/unit/orchestrator/test_burst_limiter_no_budget_debit.py` asserts the BudgetGuard counter is unchanged across a bucket-refusal cycle. Emits `comms.inbound.dropped` after 30s of bucket-empty.

### One-time ownership rules (no PR may re-do these)

- **`src/alfred/comms/` deletion.** PR-S4-10 only. PR-S4-9 leaves the directory dormant (AST-test forbids imports).
- **ADR-0015 + ADR-0016 status flips Proposed → Accepted.** PR-S4-11 only (arch-003 closure — flipping at graduation matches slice-3 precedent).
- **ADR-0009 caveat narrowing** (removing "for new adapters" qualifier). PR-S4-10 only (docs-001 closure — it is *not* a status flip; the supersession was already set in Slice 3).
- **PRD §5 line 117 amendment.** PR-S4-0a only. Human-gated per CLAUDE.md self-improvement rules (rev-003 closure). **Audit trail discipline** (rev-idx-001 closure): PR-S4-0a's PR description must reference a sign-off — either (a) an issue link to the operator who reviewed and approved the PRD amendment text verbatim, OR (b) the `Co-Authored-By:` trailer naming the human reviewer in the PRD-amendment commit. The PR cannot merge without one or the other. PR-S4-0a's reviewer-gate checklist (the `review-pr` skill panel) reads this requirement and fails the gate if the trail is absent.
- **`bin/alfred-plugin-launcher.sh` policy-resolution rewrite.** PR-S4-6 only. PR-S4-7 ships policy bytes; does not modify launcher resolution logic.

---

## §4 Cross-fork integration test gate

Spec §11.5 lists 10 merge-blocking integration tests owned across the slice, **each promoted to required-status-check in the PR that ships it** (ops-007 closure — not bulked into PR-S4-11):

| Test | Owning PR | Topology |
|---|---|---|
| `tests/integration/test_error_chain_substitution_propagates.py` | PR-S4-3 | ubuntu-latest |
| `tests/integration/test_hot_reload_high_blast_refusal.py` | PR-S4-4 | ubuntu-latest (promoted from advisory) |
| `tests/integration/test_operator_session_lifecycle.py` | PR-S4-5 | ubuntu-latest |
| `tests/integration/test_launcher_policy_resolver.py` | PR-S4-6 | ubuntu-latest |
| `tests/integration/test_sandbox_escape_kernel_enforced.py` | PR-S4-7 | ubuntu-latest (merge-blocking); macos-latest advisory |
| `tests/integration/test_comms_mcp_identity_boundary_real.py` | PR-S4-8 | ubuntu-latest |
| `tests/integration/test_discord_addressing_modes.py` + `tests/integration/test_discord_subpayload_promotion.py` | PR-S4-9 | ubuntu-latest |
| `tests/integration/test_tui_round_trip.py` + `tests/smoke/test_slice4_graduation.py` (compose-up + login + chat — ops-006 closure) | PR-S4-10 | ubuntu-latest |

**Total: 10 merge-blocking gates** = 9 integration tests + the `tests/smoke/test_slice4_graduation.py` smoke test (rev-idx-003 closure: the smoke counts as its own required-status row in the manifest; PR-S4-10 promotes both `test_tui_round_trip.py` AND `test_slice4_graduation.py` via separate `gh api` calls so each appears as a distinct row in `docs/ci/required-checks.md`). The spec §14 and §12 lists and this table now match exactly.

**macOS-advisory channel scaffolding** (devops closure): the `test_sandbox_escape_kernel_enforced.py` macos-advisory variant ships in PR-S4-7 alongside a new `.github/workflows/sandbox-macos-advisory.yml` workflow file. The workflow is **NOT** added to `required-checks.json`; it runs on `macos-latest`, reports green/red, but doesn't gate merge. PR-S4-7's plan ships the workflow file + a one-paragraph `docs/ci/macos-advisory.md` note explaining "advisory means visible-but-not-blocking; investigate failures but don't auto-revert." Adding a second macOS advisory check (e.g., a future Telegram adapter) follows the same pattern: a new `<feature>-macos-advisory.yml`, not added to required-checks.

**Persona-mode routing coverage gap** (comms-003 closure surfacing — `alfred-persona-engineer` was not in the `/review-plan` Phase A roster): PR-S4-9's plan SHALL include a mapping table between the four Slice-4 `Literal` addressing modes (DM/mention/channel/thread) and the **three canonical PRD §6.8 persona modes** (default/direct/group). The mapping per spec §8.1: `dm → direct (1:1)`, `mention → direct (1:N with explicit addressee)`, `channel → default (group, addressee implicit)`, `thread → group`. PR-S4-9's `tests/integration/test_discord_addressing_modes.py` asserts each Literal routes to the matching persona mode via the existing Slice-2.5 persona-router (verify the router's actual call signature at PR-time). The /review-plan persona-engineer gap on this index plan is recorded as a known limitation; the per-PR /review-plan invocation on PR-S4-9's plan must dispatch `alfred-persona-engineer` explicitly to close the gap.

**AST guard activation window** (comms-004 closure): the AST guard at `tests/unit/comms/test_no_direct_adapter_imports.py` that asserts `src/alfred/comms/` package absence currently asserts only "imports forbidden" (Slice-2 baseline). PR-S4-10 rewires it to assert directory absence. **PR-S4-9 ships an interim version** of the same test that uses the stricter Slice-2 "imports forbidden" check against `plugins/alfred_discord/` only (the new plugin must not import from the to-be-deleted `src/alfred/comms/`), closing the import-window between Discord-adapter ship (PR-S4-9) and directory deletion (PR-S4-10). PR-S4-10 then promotes to the full directory-absence assertion atomically with the deletion.

---

## §5 Slice merge order + rollback

### Merge order

Critical path through the dependency graph: `0a → 0b → 3 → 5 → 8 → 9 → 10 → 11` (eight PRs deep). PR-S4-1 / S4-2 / S4-4 / S4-6 / S4-7 run in parallel after PR-S4-3 lands.

### Quality gates before any PR merges

Every Slice-4 PR must clear:

1. `make check` — mandatory.
2. The adversarial suite (`uv run pytest tests/adversarial`) — mandatory for every PR touching `src/alfred/security/`, `src/alfred/hooks/`, `src/alfred/policies/`, `src/alfred/orchestrator/burst_limiter.py`, or `bin/alfred-plugin-launcher.sh`.
3. 100% line + branch coverage on every trust-boundary file (spec §14 criterion 11 — 9 files; see per-file owning-PR mapping below).
4. `make docs-check` — mandatory for PR-S4-0a, PR-S4-4 (runbook back-patches), PR-S4-10 (ADR-0009 caveat narrowing), PR-S4-11.
5. The conventional-commit `#NNN` reference gate (per #204's discovered requirement during merge).
6. Markdown lint (per #204's discovered requirement during merge; the markdownlint-cli2 config at `.markdownlint-cli2.jsonc` applies).

**Per-file 100%-coverage owning-PR mapping** (test-engineer closure on coverage-gate ownership — same ops-007 discipline applied to integration tests, now extended to per-file coverage thresholds):

| Trust-boundary file | Owning PR (CI enforces 100% line + branch threshold) |
|---|---|
| `src/alfred/hooks/registry.py` (HookpointMeta extensions) | PR-S4-3 |
| `src/alfred/hooks/invoke.py` (`_run_error` carrier-substitution dispatch) | PR-S4-3 |
| `src/alfred/policies/watcher.py` (PolicyWatcher) | PR-S4-4 |
| `src/alfred/policies/snapshot_ref.py` (PoliciesSnapshotRef) | PR-S4-4 |
| `src/alfred/identity/operator_session.py` (`_resolve_operator`) | PR-S4-5 |
| `bin/alfred-plugin-launcher.sh` + `src/alfred/plugins/manifest_reader.py` | PR-S4-6 |
| `src/alfred/comms_mcp/inbound.py` (process_inbound_message) | PR-S4-8 |
| `src/alfred/comms_mcp/classifier_registry.py` | PR-S4-8 |
| `src/alfred/orchestrator/burst_limiter.py` (BurstLimiter) | PR-S4-8 |

Each PR's `Coverage gates` CI job uses `pytest --cov` with `--cov-fail-under=100 --cov-branch` against the file glob it owns. Promoted via `gh api` in the PR that ships it (same ops-007 promotion-per-PR pattern as integration tests). The required-checks manifest carries a row per file at slice graduation.

**Recorded-LLM-fixture policy for the 10 merge-blocking integration tests** (test-eng-004 closure — several tests touch `quarantined_extract`, which calls a real LLM provider; without a recorded-fixture commitment they become flaky-required gates):

- All 10 merge-blocking integration tests SHALL use **recorded VCR fixtures** for any LLM provider call, NOT live API calls. Live calls happen only in the nightly e2e suite (PRD §8 baseline).
- Fixtures live at `tests/integration/fixtures/<test_name>/<scenario>.yaml`. Cassettes are checked in. Re-recording is a deliberate, reviewer-approved act (the test author updates the cassette and the PR description names the LLM API change that prompted it).
- The fixture-format check at `tests/integration/test_fixture_format.py` (PR-S4-3 ships this; runs in `make check`) refuses cassettes lacking `match_on: [method, scheme, host, port, path, query, body]` to prevent silent drift.

**`_ID_PATTERN` backward-compat test** (test-engineer round-1 closure on test-eng-003): PR-S4-0a ships `tests/unit/adversarial/test_id_pattern_backward_compat.py` asserting that **every Slice-1/2/3 corpus YAML id under `tests/adversarial/*/`** still matches the new `_ID_PATTERN`. An accidental regex regression that breaks the historical corpus surfaces immediately in PR-S4-0a's CI, not in a downstream PR.

**Adversarial-corpus minimum entries per category, per PR** (test-engineer round-1 closure on test-eng-002): each owning PR (`crf-` → PR-S4-3; `csb-` → PR-S4-4; `osf-` → PR-S4-5; `sbx-` → PR-S4-7; `cib-` → PR-S4-8) ships **≥3 corpus entries** in its prefix. `tests/unit/adversarial/test_category_minimum_population.py` (PR-S4-0a ships this) asserts the count per category at every PR's CI, not only at PR-S4-11 graduation.

### Rollback strategy

Each PR is independently revertible through PR-S4-9 because:

- Alembic migrations **0012–0015** each carry a `downgrade()` path (renumbered from 0011-0014 per mem-001 closure to avoid collision with the existing `0011_processed_proposals.py`).
- `operator_sessions` rows are session tokens — reverting `cli-operator-session` revokes all sessions (acceptable; operators re-login).
- `policies_snapshot_history` is optional rollback log; reverting hot-reload reverts to start-of-process-config-load behaviour (Slice-3 baseline).
- Sandbox policies revert to UID-separated (Slice-3 baseline) under the dev escape hatch in development; production refuses to launch the quarantined-LLM without the policy resolved (correct fail-closed posture during rollback investigation).
- Carrier substitution reverts to "subscriber suppression allowed but raise short-circuits" (Slice-3 documented baseline in `quarantine.py`).
- Discord MCP plugin reverts to legacy in-process adapter (still resident in `src/alfred/comms/discord/` through PR-S4-9).

**Irreversible step:** PR-S4-10 deletes `src/alfred/comms/`. A post-PR-S4-10 regression that requires the in-process adapter back is a new PR on `main`, not a revert. PR-S4-11 verifies the deletion is clean.

**Operator-recourse window between PR-S4-10 and PR-S4-11** (rev-idx-004 closure): the period after PR-S4-10 merges and before PR-S4-11 ships the graduation runbook + ADR-0015/0016 status flips is a documentation gap. Operators encountering issues in this window have no slice-4-runbook to consult and ADR-0015/0016 still read "Proposed". **Discipline**:

1. PR-S4-10 lands `docs/runbooks/slice-4-graduation-PRELIM.md` as a stub-runbook covering only the failure modes its own PR introduces (TUI launcher spawn failure, residual `comms.` import attempts, ADR-0009 narrowed-caveat read). The stub is a placeholder + a one-line "full runbook lands at PR-S4-11; for now, see `docs/subsystems/comms.md`".
2. A **48-hour soak window** between PR-S4-10 merge and PR-S4-11 open (operator-driven; not enforced by CI). If a regression surfaces during soak, PR-S4-11 inherits its closure.
3. Carrier-substitution revert discipline (sec-idx-005 closure): a revert of PR-S4-3 *after* downstream hookpoint-registering PRs have merged silently weakens the trust boundary because `HookpointMeta.carrier_tier` becomes Optional again. **Coordinated revert rule**: any PR-S4-3 revert REQUIRES a coordinated revert of every dependent PR's hookpoint registration (PR-S4-1, S4-4, S4-5, S4-6, S4-7, S4-8, S4-9). PR-S4-3's plan ships the revert script (`scripts/revert-pr-s4-3-cascade.sh`) so the discipline is mechanically enforced.

A regression in any of the 10 merge-blocking integration tests requires reverting the regressing PR, fixing, and re-submitting.

---

## §6 References

### Spec

- [docs/superpowers/specs/2026-06-06-slice-4-design.md](../specs/2026-06-06-slice-4-design.md) — authoritative design source.

### Per-PR plans

| PR | Plan file |
|---|---|
| PR-S4-0a | [2026-06-07-slice-4-pr-s4-0a-docs-adrs-foundations.md](./2026-06-07-slice-4-pr-s4-0a-docs-adrs-foundations.md) |
| PR-S4-0b | [2026-06-07-slice-4-pr-s4-0b-migrations-infra-i18n.md](./2026-06-07-slice-4-pr-s4-0b-migrations-infra-i18n.md) |
| PR-S4-1 | [2026-06-07-slice-4-pr-s4-1-daemon-boot-dispatch.md](./2026-06-07-slice-4-pr-s4-1-daemon-boot-dispatch.md) |
| PR-S4-2 | [2026-06-07-slice-4-pr-s4-2-dlp-failure-detail.md](./2026-06-07-slice-4-pr-s4-2-dlp-failure-detail.md) |
| PR-S4-3 | [2026-06-07-slice-4-pr-s4-3-carrier-substitution.md](./2026-06-07-slice-4-pr-s4-3-carrier-substitution.md) |
| PR-S4-4 | [2026-06-07-slice-4-pr-s4-4-policy-hot-reload.md](./2026-06-07-slice-4-pr-s4-4-policy-hot-reload.md) |
| PR-S4-5 | [2026-06-07-slice-4-pr-s4-5-cli-operator-session.md](./2026-06-07-slice-4-pr-s4-5-cli-operator-session.md) |
| PR-S4-6 | [2026-06-07-slice-4-pr-s4-6-sandbox-launcher.md](./2026-06-07-slice-4-pr-s4-6-sandbox-launcher.md) |
| PR-S4-7 | [2026-06-07-slice-4-pr-s4-7-sandbox-policies.md](./2026-06-07-slice-4-pr-s4-7-sandbox-policies.md) |
| PR-S4-8 | [2026-06-07-slice-4-pr-s4-8-comms-mcp-foundations.md](./2026-06-07-slice-4-pr-s4-8-comms-mcp-foundations.md) |
| PR-S4-9 | [2026-06-07-slice-4-pr-s4-9-discord-mcp-adapter.md](./2026-06-07-slice-4-pr-s4-9-discord-mcp-adapter.md) |
| PR-S4-10 | [2026-06-07-slice-4-pr-s4-10-tui-mcp-adapter-flag-day.md](./2026-06-07-slice-4-pr-s4-10-tui-mcp-adapter-flag-day.md) |
| PR-S4-11 | [2026-06-07-slice-4-pr-s4-11-docs-glossary-graduation.md](./2026-06-07-slice-4-pr-s4-11-docs-glossary-graduation.md) |

### ADRs

| ADR | Title | Relation |
|---|---|---|
| [ADR-0009](../../adr/0009-comms-adapter-protocol-slice2-only.md) | CommsAdapter Protocol | Already "Superseded by ADR-0016 (for new adapters)" since 2026-05-27; PR-S4-10 narrows the caveat to remove "for new adapters" — not a status flip |
| [ADR-0014](../../adr/0014-pluggable-hooks-for-every-action.md) | Pluggable hooks for every action | Load-bearing precedent; ADR-0022 layers carrier-substitution onto it |
| ADR-0015 | Slice-4 containerised quarantined-LLM | Status flips Proposed → Accepted in PR-S4-11 |
| ADR-0016 | Slice-4 Discord+TUI comms-MCP rewrite | Status flips Proposed → Accepted in PR-S4-11 |
| [ADR-0017](../../adr/0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md) | Slice-3 trust-tier completion | Slice-3 ADR; Slice-4 inherits the wire-format precedent |
| [ADR-0018](../../adr/0018-state-git-proposal-writer-consolidation.md) | state.git proposal writer | Slice-3 ADR; Slice-4 daemon construction wires the writer in production |
| [ADR-0020](../../adr/0020-supervisor-cli-access-via-postgres-and-state-git.md) | Supervisor CLI access | Slice-3 ADR; Slice-4's `alfred supervisor reset` updates close operator-attribution gap |
| [ADR-0021](../../adr/0021-merged-proposal-branch-dispatch-for-side-effecting-proposals.md) | Merged-proposal branch dispatch | Slice-3 ADR; Slice-4 daemon construction wires dispatch in production |
| ADR-0022 (new, PR-S4-0a) | Recoverable-carrier semantic for error-stage hookpoint dispatch | Full ADR body in PR-S4-0a; closes #170 |
| ADR-0023 (new, PR-S4-0a) | mtime-polled hot-reload for `config/policies.yaml` | Full ADR body in PR-S4-0a; closes #159 |
| ADR-0024 (new, PR-S4-0a) | Comms-MCP wire contract | Full ADR body in PR-S4-0a; consumed by PR-S4-8/9/10 |

---

## §7 PR-S4-0 split rationale (0a vs 0b)

Same shape as Slice-3 §7. PR-S4-0a is docs-only: three full ADR bodies (0022/0023/0024), the PRD §5 line 117 amendment text, eight `audit_row_schemas.py` constants, `payload_schema.py` Literal + `_PREFIX_TO_CATEGORY` + `_ID_PATTERN` additions, `docs/glossary.md` initial entries. By line count this is substantial prose but a security reviewer can hold it in one pass.

PR-S4-0b is executable: four Alembic migrations **0012–0015** (`operator_sessions`, `policies_snapshot_history`, audit-row schema additions, `sandbox_policy_registry` — numbering starts at 0012 because 0011 is the existing `processed_proposals` migration), SQLAlchemy 2.0 typed models, i18n catalog enumeration, `bubblewrap` apt-install added to the existing `docker/alfred-core.Dockerfile` (the file already exists; `docker-compose.yaml` already uses `build:`), `bin/alfred-setup.sh` updates, and the `audit.hash_pepper` secret bootstrap. These need `alembic revision` verification + running Postgres + mypy strict + `pybabel compile --check` + `docker compose build` smoke.

The split has no architectural implication. All downstream PRs (S4-1 through S4-11) are unblocked by PR-S4-0b merging.

PR-S4-0a's scope was contested by rev-007 round-2 (it had grown to include HookpointMeta runtime-type fields); the round-3 fixup moved those to PR-S4-3 where they're consumed. PR-S4-0a stays pure prose + `Final` frozensets.

---

## §8 Slice-5 backlog seeded from Slice 4

To open as tracking issues when Slice 5 kicks off:

- **#167 per-kind `fail_closed` override** on `HookpointMeta` — deferred from this slice; revisit when a consumer hookpoint demands the asymmetric policy.
- **Full step-up auth for high-blast actions** (PRD §7.1) — the minimal CLI session-file login lands in Slice 4; full step-up requires out-of-band DM confirmation via Discord/Telegram.
- **Inter-persona bus + persona-system multi-persona** — PRD §6.8.
- **Memory consolidation full pipeline + auto-retrieve** — Slice 2.5's episodic POC remains current.
- **`alfred cost report` CLI**.
- **Slice-3 broker-hardening backlog** (carried unchanged): typed `SecretRef`, broker-side post-substitution invariant check, per-secret-ID canaries woven into substituted bytes, audit-log substituted-secret-IDs match the manifest declared set.
- **Slice-4 broker enhancements**:
  - `SecretBroker.fetch_audit_pepper()` named accessor + per-fetch audit logging (currently uses generic `.get("audit.hash_pepper")`).
  - `SecretBroker.get_bytes(name) -> bytearray` returning a zeroizable buffer (currently `get` returns immutable `str` with brief residency window in launcher Supervisor — see spec §7.5 honest limitation).
- **`watchdog` migration for `PolicyWatcher`** — Slice 4 ships mtime polling at 1s; future inotify/FSEvents/ReadDirectoryChangesW migration once an operator surfaces polling-latency concerns.
- **`alfred sandbox lint <plugin>` CLI** — validates a third-party plugin's declared `sandbox.policy_ref` against the resolver without spawning.
- **`Settings.operator_session_default_expires_in_hours`** (devex-006 round-3 deferral) — site-wide configurable default for `alfred login --expires-in` (currently 12h hardcoded with `[1h, 7d]` clamp).
- **CodeRabbit cloud silence on docs-only PRs** (observed during #204 merge) — the existing `domain_cr_cloud_silent_on_docs_only_prs` memory holds; revisit if pattern persists.
- **Fabricated-surfaces watchlist for writing-plans** — captured in #204 round-4 fixup comment. Each per-PR plan dispatched in Slice-4 implementation must `grep`-verify every cited Slice-3 surface before invoking it. The pattern (round-2 invented `secret_broker.fetch_audit_pepper`, `AuditWriter.dedupe_surface`, `Python launcher`, `AlfredPluginSession._read_loop`) is reflexive enough to need explicit guard rails.
- **Persona-engineer not in `/review-plan` Phase A roster for cross-cutting plans** — captured during the Slice-4 index review (PR #205 round 1). For Slice-5 indexes, add `alfred-persona-engineer` to Phase A when the plan touches addressing-mode routing OR persona-router invocation. Recorded as a `/review-plan` skill-improvement candidate.
- **`/review-plan` coordinator-to-specialist Phase C dispatch** — the coordinator's Agent-tool unavailability in this session left Phase C cross-checks unrun (manually compensated by filesystem verification of the Critical). Slice 5 should retry the workflow once the coordinator's Agent access is restored, OR the `/review-plan` skill should be updated to delegate cross-check dispatch back to the parent skill in this case.
- **PR-S4-9 / PR-S4-10 import-window AST guard interim** — the comms-004 closure ships an interim "imports forbidden against `plugins/alfred_discord/`" check; Slice-5 should generalise this pattern into a reusable test helper for any future cross-PR deletion + replacement flow.
- **Discord adapter `THREAT_MODEL.md`** — per sec-idx-002 closure, PR-S4-9 ships a per-plugin threat-model markdown alongside the implementation. Slice 5 should formalise this into a per-plugin manifest field (`threat_model_ref:`) so every kind:none first-party plugin carries a documented threat model the reviewer-gate can verify exists.
- **`host` field unhashed in operator-session audit rows** (PR-S4-0a `/review-plan` round-2 sec-2 finding): `OPERATOR_SESSION_*_FIELDS` carry `host` (raw hostname) alongside `machine_id_hash` (HMAC-peppered). The asymmetry leaks persistent host identity into the immutable audit log. Slice 5 changes the field to `host_hash` and adds a matching `host` column to the `operator_sessions` table for binding-check forensics (the raw value stays in the broker-resident DB row; the audit log gets only the hash). Migration `00NN_operator_session_host_hash` handles the rename; the partition-anchor invariant test extension follows.

---
