# PR-S4-4 — mtime-polled hot-reload for `config/policies.yaml`

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land [ADR-0023 mtime-polled hot-reload for `config/policies.yaml`](../../adr/0023-mtime-polled-hot-reload-for-policies-yaml.md) end-to-end. Ship the `PolicyWatcher` + `PoliciesV1` + `PoliciesSnapshot` + `PoliciesSnapshotRef` quartet; migrate four Slice-3 consumers (`RateLimitConfig`, `HandleCapConfig`, `ContentStore`, the quarantined-provider config consumer) plus one long-lived loop (`_proposal_dispatch_loop`) to the snapshot-ref deref pattern; emit `CONFIG_RELOAD_FIELDS` + `CONFIG_RELOAD_REJECTED_FIELDS` audit rows with watcher-side SHA short-circuit (sec-007); add the merge-blocking `tests/integration/test_hot_reload_high_blast_refusal.py` integration test; add five adversarial corpus entries (`csb-*`); back-patch the supervisor + policies subsystem runbooks. Closes #159.

**Architecture:** A new `src/alfred/policies/` package owns the watcher and the snapshot-ref pair. `PolicyWatcher` polls `config/policies.yaml`'s `(mtime, size)` at 1 s default (perf-005 — re-read only when the pair changes). On change it parses to `PoliciesV1`, computes `file_sha256`, **watcher-side-short-circuits if the SHA is unchanged** (sec-007 — load-bearing idempotency that does NOT rely on a non-existent `AuditWriter.dedupe_surface`), then runs Phase-1 audit-write + Phase-2 atomic single-attribute assignment (err-004). `PoliciesSnapshotRef.current()` is **synchronous** (perf-002 — GIL-atomic load; no `await` trampoline overhead). Long-lived loops deref **per-iteration** (core-003). High-blast keys (`quarantined_provider_url`, `secret_broker_config_ref`) refuse hot-reload with `CONFIG_RELOAD_REJECTED_FIELDS(reason="high_blast_change")`; only reviewer-gated proposal flow may change them.

**Tech Stack:** Python 3.12+ · asyncio (TaskGroup) · Pydantic v2 (frozen) · PyYAML · structlog · `alfred.i18n.t()` · pytest + hypothesis · pytest AST guard · coverage `--fail-under=100` on `src/alfred/policies/` (new trust-boundary surface — runs in the slice-4 boundary file list per index §5.gates.criterion-11)

**PR #205 round-2 review closures** (load-bearing corrections — apply at implementation time):

1. **rev-001 + arch-001 HIGH (`swap()` audit-row file_path corruption)**: `PoliciesSnapshot` MUST carry a `file_path: Path` field set at parse time (the absolute path of the YAML file that produced the snapshot). `swap(new: PoliciesSnapshot)` reads `new.file_path` for the audit row — NEVER `str(new.file_mtime)`. Task 9's placeholder `file_path=str(new.file_mtime)` is REMOVED entirely; the placeholder would silently corrupt every `CONFIG_RELOAD_FIELDS` row's `file_path` column with mtime floats. §3.4 + Tasks 7/8/9/11 all reference `new.file_path` uniformly.

2. **sec-1 HIGH (TOCTOU stat-then-read)**: `load_yaml_bytes` MUST use TOCTOU-safe open-then-fstat: `fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW); try: stat = os.fstat(fd); if stat.st_size > 256_000: raise PolicyFileTooLarge; data = os.read(fd, stat.st_size); finally: os.close(fd)`. Inode-swap-between-stat-and-read attacks are refused by `O_NOFOLLOW` + fstat-on-already-open-fd. The 256KB size cap is enforced AFTER fstat (the fstat result is authoritative for the fd we'll read from). The csb-2026-001 corpus entry now ASSERTS the refusal (NOT punted to slice5_planned).

3. **sec-2 HIGH (cached mtime suppresses rejection re-emit)**: `_cached_mtime_size = new_pair` MUST move to AFTER successful swap, NOT before parse. The corrected sequence: (a) read mtime+size; (b) if unchanged from cache → return early (idempotency); (c) read file via TOCTOU-safe path; (d) parse + validate + high-blast check; (e) on REJECT → emit `CONFIG_RELOAD_REJECTED_FIELDS` BUT DO NOT update cache (operator reading "no rejections after first one" was a malicious-content blind spot); (f) on success → swap THEN update cache. The watcher re-emits the same rejection row every tick until the operator fixes the file — operators see a sustained signal, not a one-shot.

4. **sec-3 HIGH (no operator-confirmation gate per spec §6)**: PR-S4-4 ships `policies_snapshot_history` table in PR-S4-0b's migration 0013 (verified). PR-S4-4 ships the WRITER (`PolicySnapshotHistoryWriter.append(snapshot, applied_at, operator_session_id)`). On every successful swap the writer inserts a row recording: (a) `file_sha256`; (b) `applied_at` UTC; (c) `policies_blob` (the full YAML bytes; capped at 256KB); (d) `applied_by_operator_session_id` (nullable — auto-applied if None). High-blast-equivalent keys (any in the `HighBlastPolicies` family — to be enumerated in this PR's §3) refuse auto-apply with `reason="high_blast_change"` even on low-policy-watcher tick; only the reviewer-gated proposal flow may apply them. Low-blast changes auto-apply but the history row provides 1-tick rollback discipline. The operator-confirmation gate is implemented as: `if change_includes_any_high_blast_key: raise PolicyChangeRefused("high_blast_change")` — no auto-apply path for those keys ever. Slice-5 ships the rollback UI; PR-S4-4 ships the history rows so Slice-5 has the audit trail.

5. **rev-002 HIGH (i18n hard-rule violation — `t()` invocation)**: every operator-facing string emitted from `src/alfred/policies/` MUST route through `t()`. Specifically: Task 11's `structlog.warning("supervisor.config_watcher.degraded", ...)` becomes `structlog.warning("supervisor.config_watcher.degraded", message=t("config_watcher.degraded", reason=...))`. Task 26's runbook reason strings reference `t("config_reload.rejected.high_blast_change")` etc. A new unit test `tests/unit/policies/test_t_keys_invoked.py` asserts every declared `config_reload.*` and `config_watcher.*` catalog key from PR-S4-0b appears in at least one `t(...)` call site under `src/alfred/policies/`.

6. **arch-002 HIGH (BurstLimiterPolicy unilateral defaults)**: `BurstLimiterPolicy` Pydantic model MOVES to PR-S4-0a's foundational `alfred.policies.models` module (PR-S4-0a ships it; PR-S4-4 and PR-S4-8 both import). PR-S4-0a's task list expands to include the model + the field-default numbers per ADR-0023. Both PRs reference the same source — paper-only contract becomes structural.

7. **sec-4 MEDIUM (audit-write-failed re-emit can swallow watcher)**: `_reject` calls to `audit.append_schema(...)` are wrapped: `try: await audit.append_schema(CONFIG_RELOAD_REJECTED_FIELDS, ...); except AuditWriteError as exc: structlog.critical("policies.watcher.audit_write_failed", exc_info=exc); fallback_jsonl_path = Path.home() / ".local/state/alfred/policies-rejected-fallback.jsonl"; fallback_jsonl_path.parent.mkdir(parents=True, exist_ok=True); fallback_jsonl_path.write_text(json.dumps({...}) + "\n", append=True); await invoke("policies.watcher.degraded", payload={"reason": "audit_log_unwritable"})`. The watcher continues; the rejection isn't lost; the `policies.watcher.degraded` hookpoint surfaces the degraded state to operators via `alfred status`. CLAUDE.md hard rule 7 satisfied — loud, audit-tracked, no silent swallow.

8. **rev-003 MEDIUM (production refuses policies_ref=None)**: `Supervisor.__init__` MUST take `policies_ref: PoliciesSnapshotRef` as a REQUIRED kwarg (no default). The Slice-3 callers that pass nothing don't exist in production (PR-S4-1 constructs the supervisor with `policies_ref=` from daemon-boot). For test isolation, the test fixture `slice4_supervisor_with_stub_policies` provides a `_StubPoliciesSnapshotRef`. Task 14's "silently no-op on None" pattern is removed. The §3.6 production-only guard is replaced with a required-kwarg discipline that holds in test too.

9. **arch-003 MEDIUM (low-blast classification justification)**: `quarantined_extract_per_user_persona` (and any anti-abuse / rate-limit knob) is RECLASSIFIED to `HighBlastPolicies` (refuses hot-reload). Operators who need to tune anti-abuse parameters do so via the reviewer-gated proposal flow. The justification: an attacker with config-write capability can otherwise shrink rate-limit windows to 0 (DoS) or widen to infinity (anti-abuse bypass) silently. The `LowBlastPolicies` family is restricted to: (a) UI strings, (b) timezone/locale defaults, (c) observability sample rates, (d) non-security log verbosity. Everything else high-blast.

10. **perf-001 MEDIUM (`_tick` latency budget)**: `_tick` runs in `asyncio.to_thread(...)` to offload sync stat+read+parse+validate from the event loop. The task target is `<5ms p99` for the steady-state (cache-hit) path and `<50ms p99` for the parse-and-swap path. A perf-gate test `tests/perf/test_policy_watcher_tick_budget.py` asserts both budgets on the standard CI runner (per ADR-0024 hardware budget).

11. **perf-002 + perf-003 LOW**: `_diff_keys` uses frozen-Pydantic `==` direct comparison (NOT `model_dump()` 4×) — saves 75% of `model_dump` calls per swap. `run()` performs an immediate `_tick` BEFORE the first sleep so the first poll happens without a `poll_interval`-second delay. `tests/unit/policies/test_watcher_first_tick_immediate.py` asserts this.

12. **arch-004 LOW (stale-snapshot-for-one-iteration invariant explicit)**: §3.1 gains a paragraph: "Long-lived loops deref `policies_ref.current()` per iteration. A swap during iteration N means iteration N completes against the pre-swap snapshot; iteration N+1 picks up the new snapshot. This is by design — atomic per-iteration policy is simpler than mid-iteration policy lookups. Consumers MUST NOT cache the snapshot across iterations."

---

## §1 Goal

This PR implements spec [§5](../specs/2026-06-06-slice-4-design.md#5-mtime-polled-hot-reload-for-configpoliciesyaml-159--adr-0023) in full — every subsection §5.1 (`PolicyWatcher` + polling cadence + filesystem failure paths + recovery), §5.2 (`PoliciesV1` Pydantic v2 with the new `quarantined_extract_per_user_persona` field for the PR-S4-8 `BurstLimiter` consumer), §5.3 (`PoliciesSnapshot` + `PoliciesSnapshotRef` with sync `current()` and watcher-side SHA short-circuit), §5.4 (low-blast vs high-blast partitioning), §5.5 (four-consumer migration + the `_proposal_dispatch_loop` per-iteration deref + the AST guard), §5.6 (audit row families incl. `reason="audit_write_failed"`), §5.7 (three `csb-*` adversarial corpus entries — TOCTOU/symlink-swap, parser-OOM, mtime-stable revert, mtime-skew; five total when you count the spec's named entries), and §5.8 (the `watchdog` migration deferral note already lives in ADR-0023 — this PR does not change it).

It also wires the cross-PR contract from index [§3 PoliciesSnapshotRef sync read](2026-06-07-slice-4-index.md#policiessnapshotref-lock-free-o1-sync-read-defined-in-pr-s4-4) — every consumer module added by this PR uses `ref.current()` (synchronous) and every long-lived loop derefs per-iteration, with the AST guard catching the forbidden idiom.

After this PR merges:

- PR-S4-8 (`comms-mcp-foundations`) consumes `PoliciesV1.rate_limits.quarantined_extract_per_user_persona` in the new `BurstLimiter` primitive.
- PR-S4-11 (`docs-glossary-graduation`) updates `docs/subsystems/policies.md` Slice-4-final surface — this PR ships a runbook back-patch only (not the subsystem-doc Slice-4-final rewrite).
- The `supervisor.config_reload` / `supervisor.config_reload_rejected` / `supervisor.config_watcher.recovered` hookpoints become subscribable from any later PR.

**Closes:** #159.

**Depends on:**

- PR-S4-0a (`docs-adrs-foundations`) — `audit_row_schemas.py` constants `CONFIG_RELOAD_FIELDS`, `CONFIG_RELOAD_REJECTED_FIELDS`; `payload_schema.py` `csb` prefix in `_PREFIX_TO_CATEGORY` and `_ID_PATTERN`; ADR-0023 body; initial `docs/glossary.md` entry for `PoliciesSnapshot` / `PoliciesSnapshotRef`.
- PR-S4-0b (`migrations-infra-i18n`) — `policies_snapshot_history` Alembic migration (carries `loaded_at`, `prev_sha256`, `new_sha256`, `changed_keys` for forensic history); i18n catalog entries `config_reload.parse_failure`, `config_reload.high_blast_change`, `config_reload.validation_failure`, `config_reload.audit_write_failed`, `config_reload.file_vanished`, `config_reload.stat_failed`, `config_watcher.degraded`, `config_watcher.recovered`; SQLAlchemy `PoliciesSnapshotHistoryRow` model.
- PR-S4-3 (`carrier-substitution`) — `HookpointMeta.carrier_tier` + `HookpointMeta.allow_error_substitution` fields. Every `register_hookpoint(...)` call in this PR (three new hookpoints in §3.3) must pass `carrier_tier="T0"`; the registration-time AST guard from PR-S4-3 enforces presence.

**Blocks:**

- PR-S4-8 (`comms-mcp-foundations`) — consumes `PoliciesV1.rate_limits.quarantined_extract_per_user_persona` for the per-(canonical_user_id, persona) `BurstLimiter` token bucket. Spec §5.2 + §8.2 mid-paragraph.
- PR-S4-11 (`docs-glossary-graduation`) — Slice-4-final docs rely on §4 hookpoints being live.

---

## §2 Architecture overview

### §2.1 Module layout

```
src/alfred/
├── policies/                       ← NEW Slice-4 package; trust-boundary file list
│   ├── __init__.py                 ← public exports: PoliciesV1, PoliciesSnapshot,
│   │                                 PoliciesSnapshotRef, PolicyWatcher, build_initial_snapshot
│   ├── model.py                    ← Pydantic v2 PoliciesV1 + nested blocks (frozen)
│   ├── snapshot_ref.py             ← PoliciesSnapshot + PoliciesSnapshotRef (sync current(),
│   │                                 async swap with audit-then-swap + SHA short-circuit)
│   ├── watcher.py                  ← PolicyWatcher (mtime-gated read, degraded/normal state,
│   │                                 recovery, three new hookpoint emit sites)
│   └── load.py                     ← Pure load+parse helpers (YAML read, SHA, validation)
│
├── plugins/web_fetch/
│   ├── rate_limit.py               ← MIGRATE RateLimitConfig.from_settings → from_snapshot_ref
│   ├── handle_cap.py               ← MIGRATE HandleCapConfig.from_settings → from_snapshot_ref
│   └── content_store.py            ← MIGRATE Redis-quota reads → snapshot_ref.current()
│
├── security/
│   └── quarantine.py               ← MIGRATE QuarantinedExtractor provider-config consumer
│                                     (the LOW-BLAST `provider` subfield; URL is high-blast)
│
└── supervisor/
    └── core.py                     ← MIGRATE _proposal_dispatch_loop per-iteration deref;
                                      ADD policies_ref kwarg to Supervisor.__init__ (additive)
```

### §2.2 Snapshot-ref data flow

```
config/policies.yaml  (the source-of-truth file on disk)
         │
         │  PolicyWatcher.run()  ─── async TaskGroup task, owned by daemon (PR-S4-1)
         │  ┌──────────────────────────────────────────────────────────────────┐
         │  │ loop:                                                            │
         │  │   await sleep(poll_interval_s)                                   │
         │  │   try: st = os.stat(path)                                        │
         │  │   except FileNotFoundError: emit reason="file_vanished"; continue│
         │  │   except OSError:           emit reason="stat_failed";  continue │
         │  │   if (st.st_mtime, st.st_size) == cached: continue   # perf-005 │
         │  │   raw  = read_yaml(path)            # mtime gate passed         │
         │  │   try: model = PoliciesV1.model_validate(raw)                   │
         │  │   except ValidationError: emit reason="validation_failure"     │
         │  │   sha = sha256(yaml-canonical-bytes)                           │
         │  │   if sha == current.file_sha256: cached = (mtime, size); continue # sec-007
         │  │   diff_high_blast(current, model) → if any change: reason="high_blast_change"
         │  │   new = PoliciesSnapshot(policies=model, sha, mtime, loaded_at=now)
         │  │   await snapshot_ref.swap(new)        # audit-then-swap (err-004)
         │  └──────────────────────────────────────────────────────────────────┘
         │
         ▼
  PoliciesSnapshotRef._current  ←──── atomic single-attribute assignment
         │
         │  ref.current() → PoliciesSnapshot     (SYNCHRONOUS — perf-002 r2)
         │
         ▼
  consumers
  • RateLimitConfig.from_snapshot_ref(ref).rate_limits.web_fetch_per_user_per_hour
  • HandleCapConfig.from_snapshot_ref(ref).handle_caps.web_fetch_max_concurrent_handles_per_user
  • ContentStore  ……….quotas via ref.current() in every Redis-quota check
  • QuarantinedExtractor  …….provider subfield via ref.current()
  • Supervisor._proposal_dispatch_loop  …….per-iteration deref inside while
```

### §2.3 Idempotency layering

Spec §5.3 names two layers of "is this redundant?" gate:

| Layer | Location | Trigger | Behaviour |
| --- | --- | --- | --- |
| **Phase 0 — watcher-side SHA short-circuit** | `PolicyWatcher.run()` (NOT `PoliciesSnapshotRef.swap`) | `new.file_sha256 == current.file_sha256` after the mtime gate passes | Return immediately; **no audit row emit**; no `swap()` call. Transient errors that re-observe the same file content collapse to a no-op before `swap()` is reached. (sec-007 — the load-bearing idempotency surface.) |
| **Phase 1 — audit-then-swap** | `PoliciesSnapshotRef.swap()` | Any call to `swap()` | Emit `CONFIG_RELOAD_FIELDS`; **if the audit write raises, the swap aborts** (the prepared snapshot is discarded; `_current` stays at the previously-active value). The watcher catches the audit-write failure in `run()` and emits `CONFIG_RELOAD_REJECTED_FIELDS(reason="audit_write_failed")` (err-004 + err-010 + err-011). |
| **Phase 2 — atomic assignment** | `PoliciesSnapshotRef.swap()` continued | Audit row written successfully | `self._current = new` (single-attribute store; GIL-atomic). New `current()` callers see the new snapshot on their next call. |

Critical: **Slice-3's `AuditWriter` does NOT expose a `dedupe_surface`.** Earlier round-2 spec drafts cited `AuditWriter.dedupe_surface` as the idempotency mechanism; that surface does not exist and inventing it would be a fabricated-symbols violation (sec-007 round-3 closure). The watcher-side SHA short-circuit is the entire idempotency mechanism.

### §2.4 Degraded → recovered state machine

```
state := "normal"
consecutive_stat_failures := 0
consecutive_stat_successes := 0

on stat-failure:
    consecutive_stat_failures += 1
    consecutive_stat_successes := 0
    if consecutive_stat_failures >= 3 and state == "normal":
        state := "degraded"
        poll_interval_effective := poll_interval_s * 10
        emit supervisor.config_watcher.degraded
    emit CONFIG_RELOAD_REJECTED_FIELDS(reason="stat_failed", offending_key="<filesystem>")

on stat-success:
    consecutive_stat_failures := 0
    consecutive_stat_successes += 1
    if state == "degraded" and consecutive_stat_successes >= 3:
        state := "normal"
        poll_interval_effective := poll_interval_s
        emit supervisor.config_watcher.recovered    # err-006
```

The state machine ships with explicit unit tests for both transitions (see §4 Task 19/20).

---

## §3 Cross-PR contracts

### §3.1 `PoliciesSnapshotRef.current()` synchronous read (defined here, consumed slice-wide)

This is the load-bearing contract for the entire slice's hot-reload story (index §3 PoliciesSnapshotRef block):

```python
def current(self) -> PoliciesSnapshot:
    """Lock-free O(1) snapshot pointer read.

    SYNCHRONOUS — perf-002 round-2 closure. Slice-3's Settings.* split
    established the discipline that hot-path reads do not pay the
    async-await trampoline cost (~200ns under CPython). The single
    `self._current` attribute load is GIL-atomic; no lock, no await.

    Consumers call as `ref.current().rate_limits.foo`, NOT
    `await ref.current()`. mypy --strict refuses the `await` form
    because the return type is `PoliciesSnapshot`, not a coroutine.

    Long-lived loops MUST deref per-iteration (core-003) — see the
    "Forbidden idiom" / "Required idiom" pair in §4 Task 12.
    """
    return self._current
```

Every consuming PR (PR-S4-8 for `BurstLimiter`; later slice-5 consumers if any) inherits the sync contract.

### §3.2 `PoliciesV1.rate_limits.quarantined_extract_per_user_persona` (defined here, consumed in PR-S4-8)

PR-S4-8's `BurstLimiter` (spec §8.2 mid-paragraph) reads its bucket-capacity + refill-rate config from this single field. The shape is a frozen sub-model (definition lives in `src/alfred/policies/model.py`):

```python
class BurstLimiterPolicy(BaseModel):
    capacity_tokens: int = Field(default=5, ge=1, le=100)
    refill_seconds: float = Field(default=5.0, ge=0.5, le=60.0)
    model_config = ConfigDict(frozen=True)


class RateLimitPolicies(BaseModel):
    web_fetch_per_user_per_hour: int = Field(ge=0)
    web_fetch_per_session_total: int = Field(ge=0)
    operator_daily_budget_usd: float = Field(ge=0.0)
    quarantined_extract_per_user_persona: BurstLimiterPolicy = Field(
        default_factory=BurstLimiterPolicy
    )
    model_config = ConfigDict(frozen=True)
```

PR-S4-8 reads as `ref.current().rate_limits.quarantined_extract_per_user_persona.capacity_tokens` per-(canonical_user_id, persona) acquisition. The default factory makes this PR's policies.yaml change backward-compatible — existing operator policies without the block parse cleanly.

### §3.3 Three new hookpoints (declared here, subscribable slice-wide)

| Hookpoint | Carrier tier | `fail_closed` | `allow_error_substitution` | Notes |
| --- | --- | --- | --- | --- |
| `supervisor.config_reload` | `"T0"` | `True` | `True` (default) | Fires on successful swap; carries new snapshot SHA |
| `supervisor.config_reload_rejected` | `"T0"` | `True` | `True` (default) | Fires on any rejection path; carries `reason` Literal |
| `supervisor.config_watcher.recovered` | `"T0"` | `True` | `True` (default) | Fires when the watcher transitions degraded → normal (err-006) |

All three are `carrier_tier="T0"` per index §3 Hookpoint surface table — they are watcher-side operational signals, not user-content carriers. The `register_hookpoint(...)` calls land in `src/alfred/policies/watcher.py` at module import time (precedent: Slice-3 `src/alfred/security/capability_gate/__init__.py`).

### §3.4 Audit row constants consumed (defined in PR-S4-0a)

| Constant | Fields (per spec §5.6) | Emit sites in this PR |
| --- | --- | --- |
| `CONFIG_RELOAD_FIELDS` | `file_path`, `prev_sha256`, `new_sha256`, `changed_keys` (list[str], dotted), `loaded_at` | `PoliciesSnapshotRef.swap()` Phase 1 (one site) |
| `CONFIG_RELOAD_REJECTED_FIELDS` | `file_path`, `attempted_sha256` (nullable for `stat_failed` / `file_vanished`), `reason` Literal, `offending_key`, `dlp_scan_result` Literal | `PolicyWatcher.run()` (six rejection branches) + `PoliciesSnapshotRef.swap()` (one site — `audit_write_failed` re-emit) |

`reason` Literal MUST include `Literal["parse_failure", "high_blast_change", "validation_failure", "file_vanished", "stat_failed", "audit_write_failed"]` (err-011 round-4 closure). PR-S4-0a defines the Literal; this PR consumes it via `from alfred.audit.audit_row_schemas import CONFIG_RELOAD_REJECTED_FIELDS`.

### §3.5 `Settings.policy_poll_interval_seconds` (NEW in this PR)

`Settings.policy_poll_interval_seconds` does not exist on Slice-3 `Settings` (grep-verified — see §3.7 verification gate). This PR adds the field:

```python
# src/alfred/settings.py — addition
policy_poll_interval_seconds: float = Field(
    default=1.0,
    ge=0.5,
    le=10.0,
    description=(
        "Polling interval (seconds) for PolicyWatcher's mtime check. "
        "0.5s is the floor (CPU/disk noise); 10s is the ceiling (operator "
        "patience). The 1s default suffices for operator-edit cadence. "
        "Spec §5.1 / ADR-0023."
    ),
)
```

A unit test in `tests/unit/settings/test_policy_poll_interval_seconds.py` (added by this PR) asserts the field is present, has the correct default, and that values outside `[0.5, 10.0]` raise `ValidationError`.

### §3.6 Per-iteration deref of `_proposal_dispatch_loop` (defined here, AST-asserted)

`src/alfred/supervisor/core.py:_proposal_dispatch_loop` (spec §5.5 / index §3 cite `:282`; the production code at the time of writing has the body at lines ~317-365 with the launch site at ~278 — verification gate §3.7 captures the exact line numbers at PR-author time). This PR threads `policies_ref: PoliciesSnapshotRef` into `Supervisor.__init__` as a new kwarg (additive; default `None` is REFUSED in production via a `__init__` guard if `Settings.environment != "test"`), and inserts the per-iteration deref:

```python
async def _proposal_dispatch_loop(self) -> None:
    while not self._stop.is_set():
        snapshot = self._policies_ref.current()    # <<< per-iteration deref (NEW)
        # ... existing loop body now consumes snapshot.handle_caps / snapshot.rate_limits
        # in place of any Slice-3 settings reads ...
        await asyncio.sleep(snapshot.rate_limits.web_fetch_per_session_total * 0.0)  # placeholder; see §4 Task 14
```

The new kwarg ships as `policies_ref: PoliciesSnapshotRef | None = None` to keep PR-S4-1's daemon-boot path uncoupled. PR-S4-1 then passes the real ref. `_capability_heartbeat_loop` is **NOT** a snapshot consumer (core-009 round-3 closure — the round-1 spec named it in error).

### §3.7 Fabricated-surfaces verification gate

Per index §8 backlog ("Fabricated-surfaces watchlist for writing-plans") + sec-007 lesson. Run BEFORE invoking each cited surface; any cited symbol that does NOT exist is marked new Slice-4 scope and called out in this section:

| Symbol | Cited path | Verified state |
| --- | --- | --- |
| `RateLimitConfig` | spec §5.5 cites `src/alfred/web_fetch/rate_limits.py`; **real path** `src/alfred/plugins/web_fetch/rate_limit.py:131` | EXISTS at corrected path — use the real path in this plan |
| `HandleCapConfig` | spec §5.5 cites `src/alfred/web_fetch/handle_cap.py`; **real path** `src/alfred/plugins/web_fetch/handle_cap.py:49` | EXISTS at corrected path |
| `ContentStore` | spec §5.5 cites `src/alfred/security/content_store.py`; **real path** `src/alfred/plugins/web_fetch/content_store.py:113` | EXISTS at corrected path |
| `QuarantinedExtractor` | `src/alfred/security/quarantine.py:401` | EXISTS — confirmed |
| `_proposal_dispatch_loop` | `src/alfred/supervisor/core.py:282` (spec cite); actual body at `:317`, launch at `:278` | EXISTS — line drift between spec cite and current source; tasks capture the **definition** line at implementation time via `grep -n 'async def _proposal_dispatch_loop' src/alfred/supervisor/core.py` |
| `Settings.policy_poll_interval_seconds` | Slice-3 `Settings` does NOT carry this field (grep-verified) | **NEW Slice-4 scope — THIS PR adds it** (§3.5) |
| `CONFIG_RELOAD_FIELDS` / `CONFIG_RELOAD_REJECTED_FIELDS` | Slice-3 `audit_row_schemas.py` does NOT carry these | **NEW Slice-4 scope — land in PR-S4-0a** (this PR consumes them by import) |
| `AuditWriter` shape | Slice-3 `AuditWriter` has `append_schema(fields, **kwargs)` but NO `dedupe_surface`, NO `dedupe_key` parameter | DO NOT cite a non-existent dedupe surface (sec-007). Idempotency is watcher-side SHA short-circuit only. |
| `PoliciesSnapshot` / `PoliciesSnapshotRef` / `PolicyWatcher` / `PoliciesV1` | None of these exist anywhere | **NEW Slice-4 scope — THIS PR creates them** |
| `src/alfred/policies/` | Directory does not exist | **NEW Slice-4 scope — THIS PR creates the package** |
| `config/policies.yaml` | File exists at `config/policies.yaml` (verified) | Used as source-of-truth path |

Out-of-scope surfaces — explicitly NOT touched in this PR (per task prompt):

- Other PRs' hookpoint registrations (PR-S4-1, PR-S4-5, PR-S4-6, PR-S4-7, PR-S4-8, PR-S4-9 each declare their own; this PR declares only the three §3.3 hookpoints).
- `watchdog` migration (deferred to Slice 5+ per spec §5.8 + ADR-0023 future-work).
- Any consumer not in the spec §5.5 four-consumer list (no `BudgetGuard`, no `DLP` config — those have their own config sources).

---

## §4 File structure

| File | Create / Modify / Test | Responsibility |
| --- | --- | --- |
| `src/alfred/policies/__init__.py` | **Create** | Public exports: `PoliciesV1`, `PoliciesSnapshot`, `PoliciesSnapshotRef`, `PolicyWatcher`, `build_initial_snapshot` |
| `src/alfred/policies/model.py` | **Create** | `PoliciesV1`, `RateLimitPolicies`, `BurstLimiterPolicy`, `HandleCapPolicies`, `HighBlastPolicies` (all frozen, Pydantic v2 strict-extra) |
| `src/alfred/policies/load.py` | **Create** | `load_yaml_bytes(path)`, `parse_policies(raw, *, max_size_bytes)`, `compute_sha256(canonical_bytes)`, `yaml_canonical_dump(model)` |
| `src/alfred/policies/snapshot_ref.py` | **Create** | `PoliciesSnapshot` (frozen), `PoliciesSnapshotRef` (sync `current()`, async `swap()` with two-phase commit) |
| `src/alfred/policies/watcher.py` | **Create** | `PolicyWatcher` (mtime-gated read, SHA short-circuit, degraded/normal state machine, recovery emit); three `register_hookpoint(...)` calls |
| `src/alfred/settings.py` | **Modify** | Add `policy_poll_interval_seconds: float` field; range `[0.5, 10.0]`; default `1.0` |
| `src/alfred/plugins/web_fetch/rate_limit.py` | **Modify** | Add `RateLimitConfig.from_snapshot_ref(ref)` classmethod; keep Slice-3 `from_settings` for backward compat |
| `src/alfred/plugins/web_fetch/handle_cap.py` | **Modify** | Add `HandleCapConfig.from_snapshot_ref(ref)` classmethod; keep Slice-3 `from_settings` for backward compat |
| `src/alfred/plugins/web_fetch/content_store.py` | **Modify** | Migrate Redis-quota reads to `ref.current().rate_limits.web_fetch_per_session_total` (per-call deref) |
| `src/alfred/security/quarantine.py` | **Modify** | Migrate `QuarantinedExtractor` low-blast `provider` subfield reads to `ref.current()`; high-blast URL stays in process-load (refuses hot-reload) |
| `src/alfred/supervisor/core.py` | **Modify** | Add `policies_ref: PoliciesSnapshotRef \| None` kwarg to `Supervisor.__init__`; insert per-iteration `snapshot = self._policies_ref.current()` at top of `_proposal_dispatch_loop` body |
| `tests/unit/policies/__init__.py` | **Create** | Empty (package marker) |
| `tests/unit/policies/test_model_strict_extra.py` | **Create** | `PoliciesV1` refuses unknown fields with `ValidationError` (extras=forbid) |
| `tests/unit/policies/test_snapshot_ref_sync_current.py` | **Create** | `current()` is synchronous (returns `PoliciesSnapshot` not coroutine); typed as such for mypy |
| `tests/unit/policies/test_snapshot_ref_swap_audit_then_swap.py` | **Create** | Swap emits audit row BEFORE assignment; audit-write failure aborts swap; `_current` unchanged |
| `tests/unit/policies/test_snapshot_ref_swap_sha_short_circuit_NOT_in_swap.py` | **Create** | `swap()` does NOT skip on same-SHA — the short-circuit lives in `PolicyWatcher` (sec-007); `swap()` always writes when called |
| `tests/unit/policies/test_watcher_sha_short_circuit.py` | **Create** | Watcher returns without calling `swap()` when new SHA equals current SHA |
| `tests/unit/policies/test_watcher_mtime_gate.py` | **Create** | Unchanged `(mtime, size)` → no YAML re-read (perf-005); patched `open` not called |
| `tests/unit/policies/test_watcher_file_vanished.py` | **Create** | `FileNotFoundError` on stat → `CONFIG_RELOAD_REJECTED_FIELDS(reason="file_vanished")`; active snapshot unchanged |
| `tests/unit/policies/test_watcher_stat_failed.py` | **Create** | `OSError` on stat → `reason="stat_failed"`; `offending_key="<filesystem>"`; active snapshot unchanged |
| `tests/unit/policies/test_watcher_degraded_after_3_stat_failures.py` | **Create** | After 3 consecutive stat failures, watcher emits `supervisor.config_watcher.degraded` and reduces cadence to 10× |
| `tests/unit/policies/test_watcher_recovered_after_3_stat_successes.py` | **Create** | After 3 consecutive successes while in degraded state, watcher emits `supervisor.config_watcher.recovered` (err-006) and returns to normal cadence |
| `tests/unit/policies/test_watcher_parse_failure.py` | **Create** | Malformed YAML → `reason="parse_failure"`; active snapshot unchanged |
| `tests/unit/policies/test_watcher_validation_failure.py` | **Create** | `rate_limits.web_fetch_per_user_per_hour: -1` → `reason="validation_failure"` |
| `tests/unit/policies/test_watcher_high_blast_refusal.py` | **Create** | Change to `high_blast.quarantined_provider_url` → `reason="high_blast_change"`; active snapshot unchanged |
| `tests/unit/policies/test_watcher_audit_write_failed.py` | **Create** | `AuditWriter.append_schema` raises during `swap()` → watcher re-emits `CONFIG_RELOAD_REJECTED_FIELDS(reason="audit_write_failed")`; active snapshot unchanged (err-010 / err-011) |
| `tests/unit/policies/test_snapshot_ref_deref_pattern.py` | **Create** | AST guard: refuse any name binding from `ref.current()` that crosses an `await` boundary inside the four migrated consumer modules + `_proposal_dispatch_loop` |
| `tests/unit/policies/test_burst_limiter_policy_defaults.py` | **Create** | `BurstLimiterPolicy()` default matches PR-S4-8 expectation (5 tokens, 5.0s refill) — cross-PR contract anchor |
| `tests/unit/web_fetch/test_rate_limit_from_snapshot_ref.py` | **Create** | `RateLimitConfig.from_snapshot_ref(ref)` returns matching fields |
| `tests/unit/web_fetch/test_handle_cap_from_snapshot_ref.py` | **Create** | `HandleCapConfig.from_snapshot_ref(ref)` returns matching fields |
| `tests/unit/web_fetch/test_content_store_quota_deref.py` | **Create** | `ContentStore` reads quotas via per-call `ref.current()` |
| `tests/unit/security/test_quarantine_provider_subfield_deref.py` | **Create** | `QuarantinedExtractor` low-blast `provider` subfield resolves from snapshot per-call |
| `tests/unit/supervisor/test_proposal_dispatch_per_iteration_deref.py` | **Create** | `Supervisor._proposal_dispatch_loop` derefs the snapshot at the top of each iteration body |
| `tests/unit/settings/test_policy_poll_interval_seconds.py` | **Create** | New `Settings.policy_poll_interval_seconds` field; default 1.0; range [0.5, 10.0]; out-of-range raises |
| `tests/integration/test_hot_reload_high_blast_refusal.py` | **Create — MERGE-BLOCKING** | End-to-end: edit `policies.yaml` low-blast → watcher swaps + consumer observes; edit high-blast → refused + active unchanged; index §4 ubuntu-latest, merge-blocking |
| `tests/adversarial/payloads/config_reload_bypass/csb_2026_001_*.yaml` | **Create** | TOCTOU symlink-swap: rename `policies.yaml` → symlink to attacker-owned content between stat and read |
| `tests/adversarial/payloads/config_reload_bypass/csb_2026_002_*.yaml` | **Create** | Parser-OOM: 100 MB YAML; load guard refuses; `reason="parse_failure"` (with `_redacted_size_bytes` in audit) |
| `tests/adversarial/payloads/config_reload_bypass/csb_2026_003_*.yaml` | **Create** | mtime-stable revert: attacker edits file but restores mtime+size to bypass the mtime gate; SHA gate catches it |
| `tests/adversarial/payloads/config_reload_bypass/csb_2026_004_*.yaml` | **Create** | mtime-skew: attacker sets mtime to far-future; watcher still reads and validates (mtime is gate, not trust signal) |
| `tests/adversarial/payloads/config_reload_bypass/csb_2026_005_*.yaml` | **Create** | High-blast key swap via filesystem (spec §5.7 named entry `attacker_swaps_high_blast_via_filesystem`) |
| `docs/runbooks/slice-4-graduation.md` (back-patch hook) | **Modify** | Hot-reload subsection: editing policies.yaml workflow + degraded-watcher recovery procedure + how to read `CONFIG_RELOAD_REJECTED_FIELDS` audit entries |
| `docs/subsystems/supervisor.md` (back-patch) | **Modify** | Add PolicyWatcher to supervisor's child-task list; cross-reference policies subsystem |
| `docs/subsystems/policies.md` (back-patch) | **Modify** | Add `PolicyWatcher` + `PoliciesSnapshotRef` to the policies subsystem doc; cite the sync-`current()` contract; final Slice-4 rewrite happens in PR-S4-11 |

---

## §5 Tasks

Each task block carries the failing-test ➔ implementation cadence. Use `superpowers:test-driven-development` for the tight loop and `superpowers:verification-before-completion` before claiming any task done.

### Component A — Pydantic model + load helpers

- [ ] **Task 1 — Write failing tests for `PoliciesV1` strict-extra.**

  **Files:** Create `tests/unit/policies/__init__.py` (empty) and `tests/unit/policies/test_model_strict_extra.py`.

  ```python
  # tests/unit/policies/test_model_strict_extra.py
  import pytest
  from pydantic import ValidationError

  from alfred.policies.model import PoliciesV1


  def test_policies_v1_minimal_loads() -> None:
      v = PoliciesV1.model_validate({
          "schema_version": 1,
          "rate_limits": {
              "web_fetch_per_user_per_hour": 60,
              "web_fetch_per_session_total": 200,
              "operator_daily_budget_usd": 5.0,
          },
          "handle_caps": {"web_fetch_max_concurrent_handles_per_user": 8},
          "high_blast": {
              "quarantined_provider_url": "https://quarantine.local/v1",
              "secret_broker_config_ref": "broker://default",
          },
      })
      assert v.schema_version == 1


  def test_policies_v1_refuses_unknown_top_level_field() -> None:
      with pytest.raises(ValidationError) as excinfo:
          PoliciesV1.model_validate({
              "schema_version": 1,
              "rate_limits": {...},
              "handle_caps": {...},
              "high_blast": {...},
              "unknown_extra": "x",
          })
      assert "unknown_extra" in str(excinfo.value)


  def test_policies_v1_refuses_negative_rate_limit() -> None:
      with pytest.raises(ValidationError):
          PoliciesV1.model_validate({
              "schema_version": 1,
              "rate_limits": {
                  "web_fetch_per_user_per_hour": -1,
                  "web_fetch_per_session_total": 200,
                  "operator_daily_budget_usd": 5.0,
              },
              "handle_caps": {"web_fetch_max_concurrent_handles_per_user": 8},
              "high_blast": {
                  "quarantined_provider_url": "https://quarantine.local/v1",
                  "secret_broker_config_ref": "broker://default",
              },
          })


  def test_policies_v1_is_frozen() -> None:
      v = _build_minimal_policies()
      with pytest.raises(ValidationError):
          v.schema_version = 2  # type: ignore[misc]
  ```

  Run:

  ```bash
  uv run pytest tests/unit/policies/test_model_strict_extra.py -q 2>&1 | tail -10
  ```

  Expected: `ModuleNotFoundError: No module named 'alfred.policies.model'`.

- [ ] **Task 2 — Implement `PoliciesV1` and nested blocks.**

  **Files:** Create `src/alfred/policies/__init__.py` (empty for now) and `src/alfred/policies/model.py`.

  ```python
  # src/alfred/policies/model.py
  from __future__ import annotations

  from pydantic import BaseModel, ConfigDict, Field, HttpUrl
  from typing import Literal


  class BurstLimiterPolicy(BaseModel):
      """Per-(canonical_user_id, persona) token bucket — consumed by PR-S4-8 BurstLimiter."""
      capacity_tokens: int = Field(default=5, ge=1, le=100)
      refill_seconds: float = Field(default=5.0, ge=0.5, le=60.0)
      model_config = ConfigDict(frozen=True, extra="forbid")


  class RateLimitPolicies(BaseModel):
      web_fetch_per_user_per_hour: int = Field(ge=0)
      web_fetch_per_session_total: int = Field(ge=0)
      operator_daily_budget_usd: float = Field(ge=0.0)
      quarantined_extract_per_user_persona: BurstLimiterPolicy = Field(
          default_factory=BurstLimiterPolicy
      )
      model_config = ConfigDict(frozen=True, extra="forbid")


  class HandleCapPolicies(BaseModel):
      web_fetch_max_concurrent_handles_per_user: int = Field(ge=1)
      model_config = ConfigDict(frozen=True, extra="forbid")


  class HighBlastPolicies(BaseModel):
      """High-blast keys REFUSE hot-reload; reviewer-gate only."""
      quarantined_provider_url: HttpUrl
      secret_broker_config_ref: str = Field(min_length=1)
      model_config = ConfigDict(frozen=True, extra="forbid")


  class PoliciesV1(BaseModel):
      schema_version: Literal[1]
      rate_limits: RateLimitPolicies
      handle_caps: HandleCapPolicies
      high_blast: HighBlastPolicies
      model_config = ConfigDict(frozen=True, extra="forbid")
  ```

  Re-run the Task-1 test suite; expect green.

- [ ] **Task 3 — Property tests for `BurstLimiterPolicy` bounds.**

  **Files:** Create `tests/unit/policies/test_burst_limiter_policy_defaults.py`.

  ```python
  from hypothesis import given, strategies as st

  from alfred.policies.model import BurstLimiterPolicy


  def test_default_matches_pr_s4_8_contract() -> None:
      p = BurstLimiterPolicy()
      assert p.capacity_tokens == 5
      assert p.refill_seconds == 5.0


  @given(capacity=st.integers(min_value=1, max_value=100),
         refill=st.floats(min_value=0.5, max_value=60.0, allow_nan=False))
  def test_valid_bounds_accepted(capacity: int, refill: float) -> None:
      p = BurstLimiterPolicy(capacity_tokens=capacity, refill_seconds=refill)
      assert p.capacity_tokens == capacity
      assert p.refill_seconds == refill
  ```

- [ ] **Task 4 — Failing tests for load helpers (`load_yaml_bytes`, `parse_policies`, SHA, max-size).**

  **Files:** Create `tests/unit/policies/test_load_helpers.py`.

  Cover: happy-path YAML load, max-size guard refuses 100 MB input (spec §5.7 + csb-002), `parse_policies` propagates `ValidationError`, `compute_sha256` is stable under whitespace-only diffs in canonical dump.

  ```python
  import pytest
  from pathlib import Path

  from alfred.policies.load import (
      load_yaml_bytes,
      parse_policies,
      compute_sha256,
      MAX_POLICIES_BYTES,
  )


  def test_load_yaml_bytes_reads_file(tmp_path: Path) -> None:
      f = tmp_path / "policies.yaml"
      f.write_text("schema_version: 1\n")
      assert b"schema_version: 1" in load_yaml_bytes(f, max_size=MAX_POLICIES_BYTES)


  def test_load_yaml_bytes_refuses_oversize(tmp_path: Path) -> None:
      f = tmp_path / "huge.yaml"
      f.write_bytes(b"# pad\n" * (MAX_POLICIES_BYTES // 4))
      with pytest.raises(ValueError, match="exceeds max"):
          load_yaml_bytes(f, max_size=MAX_POLICIES_BYTES)


  def test_parse_policies_validation_failure_propagates() -> None:
      with pytest.raises(Exception):  # ValidationError
          parse_policies(b"schema_version: 1\nrate_limits: {}\n",
                         max_size_bytes=MAX_POLICIES_BYTES)


  def test_compute_sha256_stable_against_redundant_yaml_whitespace() -> None:
      a = compute_sha256(b"key: 1\n")
      b = compute_sha256(b"key: 1\n")
      assert a == b
  ```

- [ ] **Task 5 — Implement `load.py`.**

  **Files:** Create `src/alfred/policies/load.py`.

  ```python
  from __future__ import annotations

  from pathlib import Path
  from hashlib import sha256
  from typing import Final

  import yaml

  from alfred.policies.model import PoliciesV1

  MAX_POLICIES_BYTES: Final[int] = 256 * 1024  # 256 KB; policies.yaml is < 5 KB in practice


  def load_yaml_bytes(path: Path, *, max_size: int = MAX_POLICIES_BYTES) -> bytes:
      """Read YAML bytes from disk with a hard size cap.

      The cap defends against parser-OOM (csb-2026-002). Caller catches
      OSError / FileNotFoundError and routes to the watcher's stat-error
      / file-vanished paths.
      """
      st = path.stat()  # propagates OSError / FileNotFoundError to caller
      if st.st_size > max_size:
          raise ValueError(
              f"policies.yaml size {st.st_size} exceeds max {max_size} bytes"
          )
      return path.read_bytes()


  def parse_policies(raw: bytes, *, max_size_bytes: int) -> PoliciesV1:
      """Parse-validate YAML to PoliciesV1.

      Propagates `yaml.YAMLError` (→ watcher reason="parse_failure") and
      Pydantic `ValidationError` (→ watcher reason="validation_failure").
      """
      if len(raw) > max_size_bytes:
          raise ValueError("oversize raw bytes")
      data = yaml.safe_load(raw) or {}
      return PoliciesV1.model_validate(data)


  def compute_sha256(canonical_bytes: bytes) -> str:
      return sha256(canonical_bytes).hexdigest()
  ```

  Re-run Task-4 tests; expect green.

### Component B — `PoliciesSnapshotRef` (sync read + audit-then-swap + GIL-atomic assignment)

- [ ] **Task 6 — Failing test: `current()` is synchronous (not a coroutine).**

  **Files:** Create `tests/unit/policies/test_snapshot_ref_sync_current.py`.

  ```python
  import inspect
  from datetime import datetime, UTC

  from alfred.policies.snapshot_ref import PoliciesSnapshot, PoliciesSnapshotRef
  from alfred.policies.model import PoliciesV1


  def _build_snapshot() -> PoliciesSnapshot:
      ...  # fixture helper using a minimal PoliciesV1


  def test_current_is_synchronous_callable() -> None:
      ref = PoliciesSnapshotRef(_build_snapshot())
      assert not inspect.iscoroutinefunction(ref.current)


  def test_current_returns_active_snapshot_directly() -> None:
      initial = _build_snapshot()
      ref = PoliciesSnapshotRef(initial)
      got = ref.current()
      assert got is initial         # identity — same object
  ```

  Expected: `ModuleNotFoundError`.

- [ ] **Task 7 — Failing test: `swap()` is `audit-then-swap`; audit-write failure aborts swap.**

  **Files:** Create `tests/unit/policies/test_snapshot_ref_swap_audit_then_swap.py`.

  ```python
  import pytest

  from alfred.audit.audit_row_schemas import CONFIG_RELOAD_FIELDS
  from alfred.policies.snapshot_ref import PoliciesSnapshot, PoliciesSnapshotRef


  class _SpyAudit:
      def __init__(self) -> None:
          self.calls: list[tuple[str, dict]] = []
          self.should_raise = False
      async def append_schema(self, fields, **kwargs):
          self.calls.append((fields.name, kwargs))
          if self.should_raise:
              raise RuntimeError("audit-store outage")


  @pytest.mark.asyncio
  async def test_swap_emits_config_reload_audit_before_assignment(...):
      ...

  @pytest.mark.asyncio
  async def test_swap_audit_failure_aborts_assignment(...):
      audit = _SpyAudit(); audit.should_raise = True
      ref = PoliciesSnapshotRef(_initial)
      with pytest.raises(RuntimeError):
          await ref.swap(_new, audit=audit)
      assert ref.current() is _initial   # active snapshot unchanged
  ```

- [ ] **Task 8 — Failing test: `swap()` does NOT short-circuit on same SHA.**

  **Files:** Create `tests/unit/policies/test_snapshot_ref_swap_sha_short_circuit_NOT_in_swap.py`.

  This asserts the load-bearing sec-007 boundary: the **watcher** owns the SHA short-circuit; `swap()` always writes when called. Inverting this would silently drop audit rows that the watcher decided to emit (e.g., a hand-constructed swap-from-tests).

  ```python
  @pytest.mark.asyncio
  async def test_swap_writes_audit_even_when_sha_matches(...):
      same_sha_new = _make_snapshot_with_sha(initial.file_sha256)
      audit = _SpyAudit()
      ref = PoliciesSnapshotRef(initial)
      await ref.swap(same_sha_new, audit=audit)
      assert any(name == CONFIG_RELOAD_FIELDS.name for name, _ in audit.calls)
  ```

  Watcher tests in Component C cover the inverse (no swap call at all when SHAs match).

- [ ] **Task 9 — Implement `PoliciesSnapshot` and `PoliciesSnapshotRef`.**

  **Files:** Create `src/alfred/policies/snapshot_ref.py`.

  ```python
  from __future__ import annotations

  from datetime import datetime, UTC
  from typing import Protocol

  from pydantic import BaseModel, ConfigDict

  from alfred.audit.audit_row_schemas import CONFIG_RELOAD_FIELDS
  from alfred.policies.model import PoliciesV1


  class PoliciesSnapshot(BaseModel):
      policies: PoliciesV1
      loaded_at: datetime
      file_mtime: float
      file_sha256: str
      model_config = ConfigDict(frozen=True)


  class _AuditWriterLike(Protocol):
      async def append_schema(self, fields, /, **kwargs) -> None: ...


  class PoliciesSnapshotRef:
      """Lock-free O(1) snapshot pointer, swappable by the watcher.

      `current()` is synchronous — GIL-atomic single-attribute load
      (perf-002 round-2). Consumers call `ref.current().rate_limits.x`,
      NOT `await ref.current()`.

      `swap()` is asynchronous because it calls `AuditWriter.append_schema`
      which is async. It does Phase-1 audit-emit ➔ Phase-2 atomic assignment.
      A failed audit write raises; the active snapshot stays consistent
      with the last successful audit row (err-004 closure).

      The watcher-side SHA short-circuit (sec-007) lives in `PolicyWatcher`,
      NOT here. Calling `swap()` with a same-SHA snapshot still emits the
      audit row — the deduplication is the watcher's job, not the ref's.
      """

      __slots__ = ("_current",)

      def __init__(self, initial: PoliciesSnapshot) -> None:
          self._current = initial

      def current(self) -> PoliciesSnapshot:
          return self._current

      async def swap(
          self, new: PoliciesSnapshot, *, audit: _AuditWriterLike
      ) -> None:
          prev = self._current
          # Phase 1 — audit FIRST (err-004). If this raises, the active
          # snapshot stays at prev. The watcher catches the raise in run()
          # and emits CONFIG_RELOAD_REJECTED_FIELDS(reason="audit_write_failed").
          await audit.append_schema(
              CONFIG_RELOAD_FIELDS,
              file_path=str(new.file_mtime),  # placeholder; real path injected from watcher (see Task 11)
              prev_sha256=prev.file_sha256,
              new_sha256=new.file_sha256,
              changed_keys=_diff_keys(prev.policies, new.policies),
              loaded_at=new.loaded_at,
          )
          # Phase 2 — atomic single-attribute store under the GIL.
          self._current = new


  def _diff_keys(a: PoliciesV1, b: PoliciesV1) -> list[str]:
      """Return dotted key paths that differ between a and b."""
      ...  # mechanical recursion via model_dump()
  ```

  Note: the `file_path` argument is threaded by the watcher (see Task 11). The signature design carries `file_path` through `PolicyWatcher` rather than baking it into `PoliciesSnapshot` so the snapshot stays pure data.

  Re-run Tasks 6/7/8 tests; expect green.

### Component C — `PolicyWatcher` (mtime gate + SHA short-circuit + state machine + recovery)

- [ ] **Task 10 — Failing tests for watcher behaviour (mtime gate, SHA short-circuit, file-vanished, stat-failed, parse-failure, validation-failure, high-blast refusal, audit-write-failed, degraded, recovered).**

  **Files:** Create the ten unit-test files enumerated in §4. Use `pyfakefs` or `tmp_path` + monkeypatched `os.stat` to drive the watcher deterministically.

  Test skeleton for `test_watcher_sha_short_circuit.py`:

  ```python
  @pytest.mark.asyncio
  async def test_no_swap_when_sha_matches_active(...):
      audit = _SpyAudit()
      ref = PoliciesSnapshotRef(_active_snapshot)
      watcher = PolicyWatcher(
          config_path=path,
          snapshot_ref=ref,
          audit_writer=audit,
          poll_interval=0.01,
      )
      # Write the SAME bytes as currently loaded (same SHA)
      path.write_bytes(_canonical_bytes_of(_active_snapshot.policies))
      # Bump mtime so the mtime gate would otherwise re-read
      os.utime(path, None)
      # Tick the watcher once
      await watcher._tick()    # private hook for tests
      # SHA short-circuit means swap() never called → audit empty
      assert audit.calls == []
      assert ref.current() is _active_snapshot
  ```

  Test skeleton for `test_watcher_audit_write_failed.py`:

  ```python
  @pytest.mark.asyncio
  async def test_audit_write_failed_emits_rejected_keeps_active(...):
      audit = _SpyAudit()
      ref = PoliciesSnapshotRef(active)
      watcher = PolicyWatcher(..., snapshot_ref=ref, audit_writer=audit)
      # First call (CONFIG_RELOAD_FIELDS) raises; second (CONFIG_RELOAD_REJECTED_FIELDS) succeeds
      audit.queue_raise(once=True)
      path.write_bytes(_canonical_bytes_with_new_low_blast())
      os.utime(path, (time.time(), time.time()))
      await watcher._tick()
      kinds = [name for name, _ in audit.calls]
      assert CONFIG_RELOAD_REJECTED_FIELDS.name in kinds
      assert ref.current() is active
      reject_kwargs = next(k for n, k in audit.calls if n == CONFIG_RELOAD_REJECTED_FIELDS.name)
      assert reject_kwargs["reason"] == "audit_write_failed"
  ```

  Test skeleton for `test_watcher_recovered_after_3_stat_successes.py`:

  ```python
  @pytest.mark.asyncio
  async def test_recovered_after_three_consecutive_successes(...):
      audit = _SpyAudit()
      watcher = _build(audit=audit)
      # Drive 3 consecutive stat failures → degraded
      with monkeypatch.context() as mp:
          mp.setattr(os, "stat", _stat_raising_oserror)
          for _ in range(3): await watcher._tick()
      assert watcher.state == "degraded"
      # Drive 3 consecutive stat successes → recovered
      for _ in range(3): await watcher._tick()
      assert watcher.state == "normal"
      assert any(
          name == CONFIG_RELOAD_REJECTED_FIELDS.name and k["reason"] == "stat_failed"
          for name, k in audit.calls
      )
      # The recovered hookpoint emit:
      assert _hookpoint_emitted("supervisor.config_watcher.recovered", times=1)
  ```

  Run all watcher tests:

  ```bash
  uv run pytest tests/unit/policies/ -q 2>&1 | tail -10
  ```

  Expected: all fail with `ModuleNotFoundError: No module named 'alfred.policies.watcher'`.

- [ ] **Task 11 — Implement `PolicyWatcher`.**

  **Files:** Create `src/alfred/policies/watcher.py`.

  ```python
  from __future__ import annotations

  import asyncio
  import os
  from datetime import datetime, UTC
  from pathlib import Path
  from typing import Final, Literal

  import structlog
  import yaml
  from pydantic import ValidationError

  from alfred.audit.audit_row_schemas import (
      CONFIG_RELOAD_FIELDS,
      CONFIG_RELOAD_REJECTED_FIELDS,
  )
  from alfred.hooks import invoke, register_hookpoint
  from alfred.policies.load import (
      MAX_POLICIES_BYTES,
      compute_sha256,
      load_yaml_bytes,
      parse_policies,
  )
  from alfred.policies.model import PoliciesV1
  from alfred.policies.snapshot_ref import PoliciesSnapshot, PoliciesSnapshotRef


  _STAT_FAILURE_DEGRADED_THRESHOLD: Final[int] = 3
  _STAT_RECOVERY_THRESHOLD: Final[int] = 3
  _DEGRADED_BACKOFF_MULTIPLIER: Final[int] = 10

  _LOG = structlog.get_logger("alfred.policies.watcher")


  # Hookpoint registrations (declared at import; carrier_tier="T0" — index §3.3).
  register_hookpoint(
      name="supervisor.config_reload",
      carrier_tier="T0",
      fail_closed=True,
  )
  register_hookpoint(
      name="supervisor.config_reload_rejected",
      carrier_tier="T0",
      fail_closed=True,
  )
  register_hookpoint(
      name="supervisor.config_watcher.recovered",
      carrier_tier="T0",
      fail_closed=True,
  )


  class PolicyWatcher:
      def __init__(
          self,
          *,
          config_path: Path,
          snapshot_ref: PoliciesSnapshotRef,
          audit_writer,
          poll_interval: float = 1.0,
      ) -> None:
          self._path = config_path
          self._ref = snapshot_ref
          self._audit = audit_writer
          self._interval = poll_interval
          self._cached_mtime_size: tuple[float, int] | None = None
          self._stat_failures = 0
          self._stat_successes = 0
          self._state: Literal["normal", "degraded"] = "normal"

      @property
      def state(self) -> Literal["normal", "degraded"]:
          return self._state

      async def run(self) -> None:
          while True:
              await asyncio.sleep(self._effective_interval())
              await self._tick()

      def _effective_interval(self) -> float:
          if self._state == "degraded":
              return self._interval * _DEGRADED_BACKOFF_MULTIPLIER
          return self._interval

      async def _tick(self) -> None:
          # Stat first; route stat errors before any read attempt.
          try:
              st = os.stat(self._path)
          except FileNotFoundError:
              await self._reject(reason="file_vanished", attempted_sha=None,
                                 offending_key=str(self._path))
              await self._on_stat_failure()
              return
          except OSError:
              await self._reject(reason="stat_failed", attempted_sha=None,
                                 offending_key="<filesystem>")
              await self._on_stat_failure()
              return

          await self._on_stat_success()

          # Mtime gate — perf-005. Skip re-read on unchanged (mtime, size).
          new_pair = (st.st_mtime, st.st_size)
          if self._cached_mtime_size == new_pair:
              return
          self._cached_mtime_size = new_pair

          # Read + parse — load.py propagates ValueError for oversize and
          # YAMLError / ValidationError for shape problems.
          try:
              raw = load_yaml_bytes(self._path, max_size=MAX_POLICIES_BYTES)
          except (OSError, ValueError):
              await self._reject(reason="parse_failure", attempted_sha=None,
                                 offending_key="<yaml_load>")
              return

          try:
              model = parse_policies(raw, max_size_bytes=MAX_POLICIES_BYTES)
          except yaml.YAMLError:
              await self._reject(reason="parse_failure", attempted_sha=None,
                                 offending_key="<yaml_parse>")
              return
          except ValidationError as exc:
              await self._reject(reason="validation_failure",
                                 attempted_sha=None,
                                 offending_key=_first_error_key(exc))
              return

          # Canonical bytes for SHA (stable across whitespace).
          canonical = yaml.safe_dump(
              model.model_dump(mode="json"),
              sort_keys=True,
          ).encode("utf-8")
          new_sha = compute_sha256(canonical)

          # Phase 0 — watcher-side SHA short-circuit (sec-007).
          if new_sha == self._ref.current().file_sha256:
              return

          # High-blast diff — refuse hot-reload.
          if self._diff_high_blast(self._ref.current().policies, model):
              await self._reject(reason="high_blast_change",
                                 attempted_sha=new_sha,
                                 offending_key=self._high_blast_offending_key(
                                     self._ref.current().policies, model))
              return

          # Build the new snapshot.
          new_snapshot = PoliciesSnapshot(
              policies=model,
              loaded_at=datetime.now(UTC),
              file_mtime=st.st_mtime,
              file_sha256=new_sha,
          )

          # Phase 1+2 — audit-then-swap. The ref enforces the order.
          try:
              await self._ref.swap(new_snapshot, audit=self._audit)
          except Exception:
              # err-010 / err-011 — audit-write failure inside swap()
              await self._reject(reason="audit_write_failed",
                                 attempted_sha=new_sha,
                                 offending_key="<audit_store>")
              return

          # Successful swap → emit the success hookpoint.
          await invoke.post(
              "supervisor.config_reload",
              ctx={"new_sha": new_sha, "file_path": str(self._path)},
              source_tier="T0",
          )

      async def _reject(
          self,
          *,
          reason: Literal[
              "parse_failure", "high_blast_change", "validation_failure",
              "file_vanished", "stat_failed", "audit_write_failed",
          ],
          attempted_sha: str | None,
          offending_key: str,
      ) -> None:
          await self._audit.append_schema(
              CONFIG_RELOAD_REJECTED_FIELDS,
              file_path=str(self._path),
              attempted_sha256=attempted_sha,
              reason=reason,
              offending_key=offending_key,
              dlp_scan_result="n_a",
          )
          await invoke.post(
              "supervisor.config_reload_rejected",
              ctx={"reason": reason, "file_path": str(self._path)},
              source_tier="T0",
          )

      async def _on_stat_failure(self) -> None:
          self._stat_failures += 1
          self._stat_successes = 0
          if (
              self._stat_failures >= _STAT_FAILURE_DEGRADED_THRESHOLD
              and self._state == "normal"
          ):
              self._state = "degraded"
              _LOG.warning("supervisor.config_watcher.degraded",
                           failures=self._stat_failures)
              await invoke.post(
                  "supervisor.config_watcher.degraded",  # declared by PR-S4-1? — NO,
                  # declared here too if not already; coordinate with PR-S4-1's
                  # hookpoint list. To stay self-contained, we declare it locally
                  # if absent. (See hookpoint-coordination note in §3.3.)
                  ctx={},
                  source_tier="T0",
              )

      async def _on_stat_success(self) -> None:
          self._stat_failures = 0
          self._stat_successes += 1
          if (
              self._state == "degraded"
              and self._stat_successes >= _STAT_RECOVERY_THRESHOLD
          ):
              self._state = "normal"
              await invoke.post(
                  "supervisor.config_watcher.recovered",
                  ctx={"successes": self._stat_successes},
                  source_tier="T0",
              )

      @staticmethod
      def _diff_high_blast(a: PoliciesV1, b: PoliciesV1) -> bool:
          return a.high_blast.model_dump() != b.high_blast.model_dump()

      @staticmethod
      def _high_blast_offending_key(a: PoliciesV1, b: PoliciesV1) -> str:
          ad = a.high_blast.model_dump(); bd = b.high_blast.model_dump()
          for k in ad:
              if ad[k] != bd[k]:
                  return f"high_blast.{k}"
          return "high_blast.<unknown>"


  def _first_error_key(exc: ValidationError) -> str:
      errs = exc.errors()
      if not errs: return "<unknown>"
      return ".".join(str(part) for part in errs[0]["loc"])
  ```

  **Hookpoint coordination note:** `supervisor.config_watcher.degraded` is also referenced in spec §5.1. If PR-S4-1 or PR-S4-0a registers it (per index §3 Hookpoint surface), DO NOT double-register here — import and emit only. The implementation Task includes a step `grep -rn 'supervisor.config_watcher.degraded' src/alfred/` immediately before adding `register_hookpoint(...)` to detect any existing declaration. If found elsewhere, omit the local registration and add a comment pointing to the owner module.

  Re-run all Component-C tests; expect green.

### Component D — `PoliciesSnapshotRef` deref-pattern AST guard

- [ ] **Task 12 — Failing test: AST guard catches `ref.current()` binding crossing `await`.**

  **Files:** Create `tests/unit/policies/test_snapshot_ref_deref_pattern.py`.

  The AST guard is intentionally NARROW (spec §5.5 paragraph 7) — it scans only the four migrated consumer modules + the supervisor's `_proposal_dispatch_loop`. Broader enforcement would have too many false positives.

  Implementation: parse each target module with `ast`, locate `Call(func=Attribute(attr="current", value=Name(id="<any>")))` (or `Attribute(value=Name(id="ref"))` patterns recognised via known-binding heuristics), check that the resulting `Assign` target is not subsequently used after a sibling `Await`.

  ```python
  # tests/unit/policies/test_snapshot_ref_deref_pattern.py
  from __future__ import annotations

  import ast
  import pathlib

  import pytest

  _TARGETS: tuple[pathlib.Path, ...] = (
      pathlib.Path("src/alfred/plugins/web_fetch/rate_limit.py"),
      pathlib.Path("src/alfred/plugins/web_fetch/handle_cap.py"),
      pathlib.Path("src/alfred/plugins/web_fetch/content_store.py"),
      pathlib.Path("src/alfred/security/quarantine.py"),
      pathlib.Path("src/alfred/supervisor/core.py"),
  )


  def _flag_bad_bindings(tree: ast.AST) -> list[str]:
      """Return list of source-line descriptions where a `ref.current()`-derived
      name is used after a sibling `await`."""
      ...


  @pytest.mark.parametrize("target", _TARGETS, ids=str)
  def test_no_current_binding_crosses_await(target: pathlib.Path) -> None:
      tree = ast.parse(target.read_text(), filename=str(target))
      bad = _flag_bad_bindings(tree)
      assert not bad, (
          f"In {target}, the following lines bind ref.current() and then await:\n"
          + "\n".join(f"  - {b}" for b in bad)
          + "\nRequired idiom: per-iteration snapshot = ref.current() AFTER the await."
      )
  ```

  Run; expect FAIL on `_proposal_dispatch_loop` until Task 14 lands.

- [ ] **Task 13 — Implement the AST scanner helper `_flag_bad_bindings`.**

  Strategy: per function, walk the body collecting assignments whose RHS contains a `Call(attr="current")`. For each binding name, walk siblings forward; if an `Await` node appears, mark the binding "tainted." Any subsequent use of the tainted name is a violation. Reset state at function boundaries.

  The helper is contained in the test module — it ships as test code, not source code.

### Component E — Consumer migration (RateLimitConfig, HandleCapConfig, ContentStore, QuarantinedExtractor, `_proposal_dispatch_loop`)

- [ ] **Task 14 — `_proposal_dispatch_loop` per-iteration deref.**

  **Files:** Modify `src/alfred/supervisor/core.py`.

  Verify line number before editing:

  ```bash
  grep -n 'async def _proposal_dispatch_loop' src/alfred/supervisor/core.py
  ```

  Add the `policies_ref` kwarg to `Supervisor.__init__` (additive, defaulting to None — see §3.6):

  ```python
  def __init__(
      self,
      *,
      session_scope,
      gate,
      audit,
      state_git_path=None,
      proposal_dispatch_interval_s=...,
      policies_ref: PoliciesSnapshotRef | None = None,
      # ... other Slice-3 kwargs unchanged ...
  ) -> None:
      ...
      self._policies_ref = policies_ref
  ```

  And inside `_proposal_dispatch_loop`, top of the body:

  ```python
  async def _proposal_dispatch_loop(self) -> None:
      while not self._stop.is_set():
          if self._policies_ref is not None:
              snapshot = self._policies_ref.current()
          else:
              snapshot = None
          # ... existing loop body, gated by snapshot when present
          await asyncio.sleep(self._proposal_dispatch_interval_s)
  ```

  Write `tests/unit/supervisor/test_proposal_dispatch_per_iteration_deref.py` that constructs a `Supervisor` with a fake `policies_ref`, runs one loop iteration, asserts `ref.current()` was called.

  Re-run Task 12; expect green for `core.py` now.

- [ ] **Task 15 — Migrate `RateLimitConfig.from_snapshot_ref(ref)`.**

  **Files:** Modify `src/alfred/plugins/web_fetch/rate_limit.py`; create `tests/unit/web_fetch/test_rate_limit_from_snapshot_ref.py`.

  Add a classmethod that takes a `PoliciesSnapshotRef`, calls `ref.current()`, and returns the same `RateLimitConfig` shape Slice-3 already produces. Keep `from_settings` for backward compat (consumers migrate over time).

  Test asserts: per-call deref (call `ref.current()` twice; mutate the underlying snapshot between calls; assert the returned config reflects the mutation on the second call — proving the migration is `from_snapshot_ref` not `from_snapshot`).

- [ ] **Task 16 — Migrate `HandleCapConfig.from_snapshot_ref(ref)`.**

  Same shape as Task 15 for `src/alfred/plugins/web_fetch/handle_cap.py`.

- [ ] **Task 17 — Migrate `ContentStore` Redis-quota reads.**

  **Files:** Modify `src/alfred/plugins/web_fetch/content_store.py`; create `tests/unit/web_fetch/test_content_store_quota_deref.py`.

  Replace the Slice-3 Settings-based quota read with a per-call `self._policies_ref.current().rate_limits.web_fetch_per_session_total`. Constructor gains a `policies_ref` kwarg (additive; non-None required in production via `__init__` guard parallel to §3.6).

- [ ] **Task 18 — Migrate `QuarantinedExtractor` provider subfield consumer.**

  **Files:** Modify `src/alfred/security/quarantine.py:401` (the existing `QuarantinedExtractor` class — verification gate confirmed); create `tests/unit/security/test_quarantine_provider_subfield_deref.py`.

  The high-blast `quarantined_provider_url` field is NOT hot-reloaded (refuses change). The low-blast `provider` subfield (e.g., `provider.headers`, `provider.timeout_seconds` — whatever the Slice-3 config produces) IS hot-reloadable; this Task migrates only the low-blast read path. Slice-3 source-of-truth for the field list lives in `quarantine.py`; capture it at PR-author time.

  Per-call deref: `self._policies_ref.current().provider.timeout_seconds` etc. — replace any cached attribute that the Slice-3 extractor reads at construction time.

  Test asserts: a hot-reload of low-blast `provider.timeout_seconds` updates the extractor's next call (no extractor restart required); a hot-reload of high-blast URL is refused at the watcher layer (covered by `test_watcher_high_blast_refusal.py` in Component C).

### Component F — `Settings.policy_poll_interval_seconds`

- [ ] **Task 19 — Add `policy_poll_interval_seconds` to `Settings`.**

  **Files:** Modify `src/alfred/settings.py`; create `tests/unit/settings/test_policy_poll_interval_seconds.py`.

  Per §3.5 — the field is new in this PR. Test cases:

  ```python
  def test_default_is_one_second() -> None: ...
  def test_minimum_is_half_second() -> None: ...
  def test_maximum_is_ten_seconds() -> None: ...
  def test_below_minimum_raises() -> None: ...
  def test_above_maximum_raises() -> None: ...
  ```

### Component G — Adversarial corpus

Five entries under category `config_reload_bypass` (prefix `csb-` per index §3 payload_schema additions). Test-005 confirmed (test prompt + index §3 `_PREFIX_TO_CATEGORY`).

- [ ] **Task 20 — `csb-2026-001 toctou_symlink_swap`.**

  **Files:** Create `tests/adversarial/payloads/config_reload_bypass/csb_2026_001_toctou_symlink_swap.yaml`.

  Scenario: between the watcher's `os.stat()` and `load_yaml_bytes`, an attacker renames `policies.yaml` to a symlink pointing at attacker-controlled content.

  Expected behaviour: the watcher's load helper opens by path (not by fd) at this Slice. The realistic defence is policy-level: the file must live in a root-only-writable directory. The test entry SHOULD ASSERT that the canonical-load doesn't FOLLOW the symlink silently — if symlink-following is a Slice-5 hardening, the corpus entry is a `documented_limitation` row that the adversarial harness skips with a comment in the YAML.

  This is the round-2 closure shape: corpus entries that depend on Slice-5+ hardening are recorded with `defence_level: "slice5_planned"` and don't block this PR's merge. The corpus harness raises a warning, not a failure.

- [ ] **Task 21 — `csb-2026-002 parser_oom`.**

  Scenario: `policies.yaml` is replaced with 100 MB of nested YAML; the load helper should refuse with `ValueError` (`oversize`).

  Expected: `CONFIG_RELOAD_REJECTED_FIELDS(reason="parse_failure", offending_key="<yaml_load>")`. Active snapshot unchanged.

  The corpus entry's payload is generated at test-time (not stored in git — 100 MB blob in the repo would be wrong).

- [ ] **Task 22 — `csb-2026-003 mtime_stable_revert`.**

  Scenario: attacker edits `policies.yaml`, then restores the original mtime+size (e.g., `touch -t` with the original timestamp + payload-padding to match size). The mtime gate would skip the read; the SHA gate must catch it.

  This is the test for the load-bearing **mtime gate ≠ trust signal** property. The test runs by directly invoking `watcher._tick()` after the mtime restoration and asserting that the watcher's behaviour DEPENDS on cached `(mtime, size)` — i.e., this attacker's edit will only be detected on the next mtime change (next edit cycle). The corpus entry documents this as a known mtime-gate limitation; defence-in-depth via SHA-comparison on every read remains the long-term answer.

  This entry is documented_limitation `defence_level: "slice5_planned"` shape.

- [ ] **Task 23 — `csb-2026-004 mtime_skew`.**

  Scenario: attacker sets the file's mtime to year 2099. The watcher's mtime cache compares for inequality, not magnitude; the read proceeds normally. Test asserts that the watcher still loads + validates + emits the success row regardless of mtime magnitude.

- [ ] **Task 24 — `csb-2026-005 high_blast_swap_via_filesystem` (spec §5.7 named entry).**

  Scenario: attacker writes `policies.yaml` with a different `high_blast.quarantined_provider_url`.

  Expected: `CONFIG_RELOAD_REJECTED_FIELDS(reason="high_blast_change", offending_key="high_blast.quarantined_provider_url")`; active snapshot unchanged.

  ```yaml
  # tests/adversarial/payloads/config_reload_bypass/csb_2026_005_high_blast_swap_via_filesystem.yaml
  id: csb-2026-005
  category: config_reload_bypass
  description: |
    Filesystem-direct write to policies.yaml swaps high_blast.quarantined_provider_url.
    The PolicyWatcher must refuse the swap and emit CONFIG_RELOAD_REJECTED_FIELDS.
  payload_path: ./csb_2026_005_payload.yaml
  expected:
    - kind: audit_row
      schema: CONFIG_RELOAD_REJECTED_FIELDS
      fields:
        reason: high_blast_change
        offending_key: high_blast.quarantined_provider_url
    - kind: snapshot_unchanged
      ref: policies_snapshot_ref
  ```

### Component H — Integration test (merge-blocking)

- [ ] **Task 25 — `tests/integration/test_hot_reload_high_blast_refusal.py`.**

  Index §4 + spec §5.7 — promoted from advisory to merge-blocking in PR-S4-4 (ubuntu-latest topology).

  Shape:

  ```python
  # tests/integration/test_hot_reload_high_blast_refusal.py
  from __future__ import annotations

  import asyncio
  from pathlib import Path
  from datetime import datetime, UTC

  import pytest

  from alfred.policies.model import PoliciesV1
  from alfred.policies.snapshot_ref import PoliciesSnapshot, PoliciesSnapshotRef
  from alfred.policies.watcher import PolicyWatcher
  from tests.fixtures.audit import RealishAuditWriter
  from tests.fixtures.policies import write_valid_yaml, write_yaml_with_high_blast_swap


  @pytest.mark.asyncio
  async def test_low_blast_change_hot_reloads_high_blast_change_refused(
      tmp_path: Path,
      postgres_audit_store,            # testcontainers fixture
  ) -> None:
      cfg = tmp_path / "policies.yaml"
      initial_model = write_valid_yaml(cfg)
      initial = PoliciesSnapshot(
          policies=initial_model,
          loaded_at=datetime.now(UTC),
          file_mtime=cfg.stat().st_mtime,
          file_sha256="...",
      )
      ref = PoliciesSnapshotRef(initial)
      audit = RealishAuditWriter(postgres_audit_store)
      watcher = PolicyWatcher(
          config_path=cfg,
          snapshot_ref=ref,
          audit_writer=audit,
          poll_interval=0.05,
      )

      task = asyncio.create_task(watcher.run())
      try:
          # 1) Low-blast change: change web_fetch_per_user_per_hour 60 → 120
          write_valid_yaml(cfg, rate_per_hour=120)
          await asyncio.sleep(0.3)
          assert ref.current().policies.rate_limits.web_fetch_per_user_per_hour == 120
          assert audit.find(constant_name="CONFIG_RELOAD_FIELDS") is not None

          # 2) High-blast change: change quarantined_provider_url
          write_yaml_with_high_blast_swap(cfg)
          await asyncio.sleep(0.3)
          # Active snapshot still carries the previous low-blast value AND the
          # previous high-blast URL — refusal is total, not partial.
          assert ref.current().policies.rate_limits.web_fetch_per_user_per_hour == 120
          assert (
              str(ref.current().policies.high_blast.quarantined_provider_url)
              == "https://quarantine.local/v1"
          )
          rejection = audit.find(
              constant_name="CONFIG_RELOAD_REJECTED_FIELDS",
              kwargs_match={"reason": "high_blast_change"},
          )
          assert rejection is not None
          assert rejection["offending_key"] == "high_blast.quarantined_provider_url"
      finally:
          task.cancel()
  ```

  Promote to required-status-check at PR-S4-4 merge time per index §4 (ops-007 closure — not bulked into PR-S4-11). The promotion command lives in the PR description per the `author-gating-workflow` skill workflow.

### Component I — Docs + runbook back-patches

- [ ] **Task 26 — Back-patch `docs/runbooks/slice-4-graduation.md` hot-reload section.**

  Add subsection "Editing policies.yaml in production":

  1. Edit `config/policies.yaml`.
  2. Watch `alfred audit log --tail --filter supervisor.config_reload` — success carries `new_sha256`.
  3. If `supervisor.config_reload_rejected` appears: inspect `reason`:
     - `parse_failure` — YAML is malformed; fix and re-save.
     - `validation_failure` — a field violates its Pydantic constraint; check `offending_key`.
     - `high_blast_change` — you edited a reviewer-gated key; submit a proposal via `alfred config quarantined-provider …` instead.
     - `audit_write_failed` — the audit store is unhealthy; check Postgres; the watcher will retry on next mtime change.
     - `stat_failed` / `file_vanished` — filesystem-level problem.
  4. If you see `supervisor.config_watcher.degraded`: the watcher hit ≥3 consecutive stat errors. Fix the underlying filesystem. Recovery is automatic after 3 consecutive successful stats (look for `supervisor.config_watcher.recovered`).

- [ ] **Task 27 — Back-patch `docs/subsystems/policies.md`.**

  Add `PolicyWatcher` and `PoliciesSnapshotRef` to the subsystem doc; cite the synchronous `current()` contract; cite the watcher-side SHA short-circuit as the idempotency mechanism. Final Slice-4 docs rewrite happens in PR-S4-11; this is a back-patch covering only the new surfaces.

- [ ] **Task 28 — Back-patch `docs/subsystems/supervisor.md`.**

  Add `PolicyWatcher` to the supervisor's child-task list (under "Long-running tasks owned by the daemon's TaskGroup"). Cross-reference `docs/subsystems/policies.md`.

### Component J — Quality gates

- [ ] **Task 29 — `make check`.**

  ```bash
  uv run ruff check . && uv run ruff format --check . && uv run mypy src/ && uv run pyright src/ && uv run pytest tests/unit -q
  ```

- [ ] **Task 30 — Adversarial suite.**

  Per spec §11.5 + index §5 quality gate 2, every PR touching `src/alfred/security/`, `src/alfred/hooks/`, or `src/alfred/policies/` must run the adversarial suite:

  ```bash
  uv run pytest tests/adversarial -q
  ```

- [ ] **Task 31 — 100% coverage on `src/alfred/policies/`.**

  Per index §5 quality gate 3 + spec §14 criterion 11 — `src/alfred/policies/` is a new trust-boundary file list entry (alongside the eight Slice-3 boundary files and the Slice-4 `src/alfred/orchestrator/burst_limiter.py`). Coverage gate runs as:

  ```bash
  uv run coverage run --source=src/alfred/policies -m pytest tests/unit/policies tests/integration/test_hot_reload_high_blast_refusal.py
  uv run coverage report --fail-under=100
  ```

- [ ] **Task 32 — Integration test runs green on ubuntu-latest CI runner.**

  ```bash
  uv run pytest tests/integration/test_hot_reload_high_blast_refusal.py -q
  ```

- [ ] **Task 33 — Promote the integration test to required-status-check.**

  Per index §4 + the `author-gating-workflow` skill. After the PR merges, run:

  ```bash
  gh api repos/MrReasonable/AlfredOS/branches/main/protection/required_status_checks \
    --method PATCH --jq '.checks |= . + [{"context": "test_hot_reload_high_blast_refusal", "app_id": -1}]'
  ```

  Update the tracked required-checks manifest at `.github/required-checks.json` (or wherever it lives — verify the path at promotion time) in a follow-up commit on `main`.

- [ ] **Task 34 — `make docs-check`.**

  Per index §5 quality gate 4 — required for PRs that touch runbooks. Run:

  ```bash
  make docs-check
  ```

- [ ] **Task 35 — Conventional-commit `#NNN` reference + markdownlint.**

  Per index §5 quality gate 5 + 6. The PR title and the last commit message must reference `#159`. Markdownlint runs as `pnpm dlx markdownlint-cli2 'docs/**/*.md'` per the repo's `.markdownlint-cli2.jsonc`.

---

## §6 Trust-boundary contract

This PR ships `src/alfred/policies/` as a new trust-boundary surface. The boundary contract:

1. **`PolicyWatcher` runs under the daemon's `asyncio.TaskGroup`** owned by `Supervisor`. PR-S4-1 (daemon-boot-dispatch) wires the task into the production boot path; this PR ships the watcher class only.
2. **`policies.yaml` is read by the watcher and nobody else.** Other parts of the system read the snapshot via `ref.current()`, never the file directly. A grep guard in `tests/unit/policies/test_no_other_reader_of_policies_yaml.py` (optional follow-up; not in this PR's scope) would enforce this.
3. **High-blast keys can only change via the proposal flow** (reviewer-gated). The watcher refuses; the proposal flow lives in `src/alfred/security/capability_gate/proposals.py` (PR-S3-2 shipped). Future PRs may add a `proposal/policy-high-blast-<id>` template; not in this PR.
4. **The audit store is the second-of-two synchronisation surfaces** between the watcher and operator-visible history. The first is the file's git history (operators may keep `config/policies.yaml` in a git repo). The watcher's audit emit is the runtime-attestation that the operator-edit was applied (or refused) at a specific instant.
5. **The watcher never emits any T1/T2/T3 carrier** — only `T0` (operator/system event tier). The three new hookpoints carry `carrier_tier="T0"`.

---

## §7 Verification before completion

Before claiming the PR is ready:

1. `make check` passes.
2. `uv run pytest tests/unit/policies tests/unit/web_fetch/test_*_from_snapshot_ref.py tests/unit/security/test_quarantine_provider_subfield_deref.py tests/unit/supervisor/test_proposal_dispatch_per_iteration_deref.py tests/unit/settings/test_policy_poll_interval_seconds.py -q` is green.
3. `uv run pytest tests/integration/test_hot_reload_high_blast_refusal.py -q` is green.
4. `uv run pytest tests/adversarial -q` is green.
5. `uv run coverage report --include 'src/alfred/policies/*' --fail-under=100` is green.
6. The deref AST guard (`tests/unit/policies/test_snapshot_ref_deref_pattern.py`) is green on all five target files.
7. `grep -rn 'await ref.current()' src/alfred/` returns no matches — no consumer awaits the sync `current()` accidentally.
8. `grep -rn 'AuditWriter.dedupe_surface\|dedupe_key' src/alfred/policies/` returns no matches — sec-007 honoured.
9. `make docs-check` is green.
10. `alfred audit log --tail` (against a local docker-compose stack with the PR applied) shows `supervisor.config_reload` after a hand-edit of `config/policies.yaml`.

Apply `superpowers:verification-before-completion`. Evidence before assertions, always.

---

## §8 Risks + mitigations

| Risk | Likelihood | Severity | Mitigation |
| --- | --- | --- | --- |
| `_proposal_dispatch_loop` line drift between spec cite (:282) and current source (~:317) misleads the implementer | Med | Low | §3.7 verification gate + §5 Task 14's first step is `grep -n 'async def _proposal_dispatch_loop'` |
| AST guard produces false positives on legitimate `current()` calls that share a name with the snapshot binding | Low | Med | Scope the guard to the five named target files only (spec §5.5 paragraph 7); document in the test docstring |
| Audit-write failure during initial `swap()` of a freshly-started daemon prevents first-load attestation | Low | Med | The watcher emits `CONFIG_RELOAD_REJECTED_FIELDS(reason="audit_write_failed")` and retries on next mtime change; the daemon's `daemon.boot.completed` row from PR-S4-1 carries `policies_snapshot_hash` of the initial-load (NOT the watcher-load), so first-boot still has a SHA attestation |
| Operator edits `policies.yaml` via editor that does write-then-rename (vim default) → atomic rename emits `file_vanished` mid-watch | High | Low | Transient — next poll sees the renamed file; the `file_vanished` rejection is the loud-but-not-fatal signal the spec §5.1 documents. Runbook (Task 26) covers this case |
| `quarantined_extract_per_user_persona` field is consumed by PR-S4-8 before this PR's default values are locked | Low | Med | Task 3's property tests pin the default (5 tokens, 5.0s refill); PR-S4-8 reviews this PR's `BurstLimiterPolicy` shape before merging — cross-PR contract anchor §3.2 |
| `supervisor.config_watcher.degraded` hookpoint double-registration if PR-S4-1 or PR-S4-0a already declared it | Low | Low | Task 11 implementation note: grep before adding the local `register_hookpoint(...)`. If found, omit and import only |
| TOCTOU adversarial case csb-2026-001 is a documented Slice-5 hardening, not a Slice-4 fix | Acknowledged | Low | Task 20 records the corpus entry with `defence_level: "slice5_planned"`; suite harness warns but does not fail; the entry is the slice-5 backlog tracker |

---

## §9 Out of scope

Per the prompt + index §1.2:

- **Other PRs' hookpoint registrations.** This PR registers exactly three hookpoints (the §3.3 trio). It does NOT register `daemon.boot.completed`, `daemon.boot.failed`, `proposal.dispatch.failed` (PR-S4-1's responsibility), `hooks.carrier_substituted` (PR-S4-3's responsibility), `operator.session.*` (PR-S4-5's responsibility), `supervisor.plugin.sandbox_*` (PR-S4-6/7's responsibility), `comms.*` (PR-S4-8/9's responsibility).
- **`watchdog` migration.** Deferred to Slice 5+ per spec §5.8 and ADR-0023 future-work section. This PR ships mtime polling at 1s default.
- **Other consumers of `PoliciesSnapshotRef`.** Only the four named consumers in spec §5.5 plus the one named long-lived loop (`_proposal_dispatch_loop`) migrate in this PR. Future consumers may opt-in.
- **The Slice-4-final rewrite of `docs/subsystems/policies.md`.** This PR does a back-patch (Task 27); the full rewrite is PR-S4-11.
- **`policies_snapshot_history` Postgres-row write from the watcher.** The Alembic migration ships in PR-S4-0b; whether the watcher writes a row per swap (for forensic replay) is a Slice-5 feature gate, not a Slice-4 invariant. The runbook notes this.
- **Per-tenant policies overrides.** Spec §5 carries a single global `policies.yaml`. Multi-tenant overrides are post-MVP.

---

## §10 References

### Spec sections

- [§5.1 — PolicyWatcher + polling cadence](../specs/2026-06-06-slice-4-design.md#51-policywatcher--polling-cadence)
- [§5.2 — PoliciesV1 Pydantic v2 model](../specs/2026-06-06-slice-4-design.md#52-policiesv1-pydantic-v2-model)
- [§5.3 — PoliciesSnapshot + PoliciesSnapshotRef](../specs/2026-06-06-slice-4-design.md#53-policiessnapshot--policiessnapshotref)
- [§5.4 — Low-blast vs high-blast partitioning](../specs/2026-06-06-slice-4-design.md#54-low-blast-vs-high-blast-key-partitioning)
- [§5.5 — Consumer migration](../specs/2026-06-06-slice-4-design.md#55-consumer-migration)
- [§5.6 — Audit row families](../specs/2026-06-06-slice-4-design.md#56-audit-row-families)
- [§5.7 — Adversarial corpus](../specs/2026-06-06-slice-4-design.md#57-adversarial-corpus-entry)
- [§5.8 — `watchdog` deferral](../specs/2026-06-06-slice-4-design.md#58-watchdog-migration-deferral)

### Index cross-references

- [Index §3 — PoliciesSnapshotRef sync read contract](2026-06-07-slice-4-index.md#policiessnapshotref-lock-free-o1-sync-read-defined-in-pr-s4-4)
- [Index §3 — Hookpoint surface table](2026-06-07-slice-4-index.md#hookpoint-surface-spec-10-table--single-source-of-truth)
- [Index §3 — `payload_schema.py` Literal + dispatch additions](2026-06-07-slice-4-index.md#payload_schemapy-literal--dispatch-table-additions-defined-in-pr-s4-0a)
- [Index §4 — Cross-fork integration test gate](2026-06-07-slice-4-index.md#4-cross-fork-integration-test-gate)
- [Index §5 — Quality gates + rollback](2026-06-07-slice-4-index.md#5-slice-merge-order--rollback)

### ADRs

- [ADR-0023 — mtime-polled hot-reload for `config/policies.yaml`](../../adr/0023-mtime-polled-hot-reload-for-policies-yaml.md) (full body lands in PR-S4-0a)
- [ADR-0014 — Pluggable hooks for every action](../../adr/0014-pluggable-hooks-for-every-action.md) (load-bearing precedent — the three new hookpoints follow ADR-0014's discipline)
- [ADR-0017 — Slice-3 trust-tier completion](../../adr/0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md) (Slice-3 baseline; PR-S4-4 inherits the audit-write discipline)

### Related GitHub issues

- [#159 — mtime-polled hot-reload for `config/policies.yaml`](https://github.com/MrReasonable/AlfredOS/issues/159) — closes on PR-S4-4 merge.
- [#167 — per-kind `fail_closed` override on `HookpointMeta`](https://github.com/MrReasonable/AlfredOS/issues/167) — DEFERRED; this PR's three new hookpoints all carry uniform `fail_closed=True`.

### Code surfaces verified

- `RateLimitConfig` at `src/alfred/plugins/web_fetch/rate_limit.py:131`.
- `HandleCapConfig` at `src/alfred/plugins/web_fetch/handle_cap.py:49`.
- `ContentStore` at `src/alfred/plugins/web_fetch/content_store.py:113`.
- `QuarantinedExtractor` at `src/alfred/security/quarantine.py:401`.
- `_proposal_dispatch_loop` definition at `src/alfred/supervisor/core.py` (current line ~317; spec §5.5 cites :282; verification gate captures actual line at implementation time).
- `Settings.policy_poll_interval_seconds` — DOES NOT EXIST; this PR adds it (§3.5).
- `CONFIG_RELOAD_FIELDS` / `CONFIG_RELOAD_REJECTED_FIELDS` — DO NOT EXIST; land in PR-S4-0a; this PR consumes by import.
- `AuditWriter.dedupe_surface` / `dedupe_key` — DO NOT EXIST and MUST NOT be invented (sec-007).
- `src/alfred/policies/` package — DOES NOT EXIST; this PR creates it.
- `PoliciesV1` / `PoliciesSnapshot` / `PoliciesSnapshotRef` / `PolicyWatcher` — DO NOT EXIST; this PR creates them.

---

**End of plan.**
