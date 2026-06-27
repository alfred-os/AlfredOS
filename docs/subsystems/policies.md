# Policies subsystem (`src/alfred/policies/`)

> Back-patch (PR-S4-4, ADR-0023, #159). The Slice-4-final rewrite lands in
> PR-S4-11. This doc covers the surfaces PR-S4-4 ships.

## Purpose

Hot-reload of `config/policies.yaml` without an `alfred` process restart. An
operator edits the file; the `PolicyWatcher` notices on its next mtime poll,
validates the new content, and atomically swaps the active policy snapshot —
or refuses loudly if the edit is malformed, oversize, or touches a high-blast
key.

The subsystem is a **trust boundary**: it ingests an operator-controlled file
and is the single runtime authority for the active policy. 100% line + branch
coverage is enforced on `src/alfred/policies/`.

## Public surface

### `PoliciesV1` (`model.py`)

Frozen Pydantic v2 model (`extra="forbid"`) — the validated shape of
`config/policies.yaml` for the hot-reload path. Nested frozen blocks:
`RateLimitPolicies`, `HandleCapPolicies`, `HighBlastPolicies`, and
`BurstLimiterPolicy` (the per-(canonical_user_id, persona) token bucket
consumed by PR-S4-8's `BurstLimiter`; defaults 5 tokens / 5.0 s refill).

A typo'd operator key surfaces as a loud `validation_failure` rather than a
silently-ignored knob (CLAUDE.md hard rule 7).

### `PoliciesSnapshot` / `PoliciesSnapshotRef` (`snapshot_ref.py`)

`PoliciesSnapshot` is an immutable point-in-time view (`policies`, `loaded_at`,
`file_mtime`, `file_sha256`, and the absolute `file_path`).

`PoliciesSnapshotRef` is the lock-free O(1) snapshot pointer:

- **`current()` is synchronous** — a GIL-atomic single-attribute load
  (perf-002). Consumers read `ref.current().rate_limits.x` with **no `await`**.
  `mypy --strict` refuses the `await` form because the return type is
  `PoliciesSnapshot`, not a coroutine.
- **`swap()` is async** and is the only mutator. It does Phase-1 audit-emit
  (`CONFIG_RELOAD_FIELDS`) **then** Phase-2 atomic assignment (err-004): if the
  audit write raises, the active snapshot stays at the previous value.

**stale-snapshot-for-one-iteration invariant:** long-lived loops deref
`ref.current()` **per iteration**. A swap during iteration N means iteration N
completes against the pre-swap snapshot and iteration N+1 picks up the new one.
This is by design — atomic per-iteration policy is simpler and race-free.
Consumers MUST NOT cache the snapshot across iterations; the AST guard
`tests/unit/policies/test_snapshot_ref_deref_pattern.py` enforces this on the
migrated consumers and `_proposal_dispatch_loop`.

### `PolicyWatcher` (`watcher.py`)

Polls `(mtime, size)` at `Settings.policy_poll_interval_seconds` (default 1 s).
On a change it loads (TOCTOU-safe), parses, validates, computes the canonical
SHA, and swaps the ref — unless a gate refuses.

- **TOCTOU-safe load (sec-1):** `load_yaml_bytes` opens with
  `os.O_RDONLY | os.O_NOFOLLOW`, `fstat`s the already-open fd, enforces the
  256 KB cap against that stat, and reads from the same fd. A symlink/inode
  swap between an external stat and our read cannot redirect us.
- **Watcher-side SHA short-circuit (sec-007):** this is the **entire**
  idempotency mechanism. If the new canonical SHA equals the active snapshot's,
  the watcher returns with no audit row and no swap. There is **no**
  `AuditWriter.dedupe_surface` — do not invent one.
- **High-blast refusal (sec-3 / arch-003):** any change to a `HighBlastPolicies`
  key (`quarantined_provider_url`, `secret_broker_config_ref`) aborts the swap
  with `reason="high_blast_change"`. Only the reviewer-gated proposal flow may
  change high-blast keys. Anti-abuse / rate-limit knobs are classified
  high-blast: an attacker with config-write could otherwise shrink a window to
  0 (DoS) or widen it (anti-abuse bypass) silently.
- **Rejection durability (sec-2):** on a REJECT the `(mtime, size)` cache is
  NOT updated, so the watcher re-emits the same rejection every tick until the
  operator fixes the file — a sustained signal, not a one-shot.
- **Audit-write failure (sec-4):** if the rejected audit write itself fails
  (`SQLAlchemyError` — there is no `AuditWriteError`), the watcher logs
  critically, appends the rejection to
  `~/.local/state/alfred/policies-rejected-fallback.jsonl`, and emits
  `policies.watcher.degraded`. The watcher continues; the rejection is not lost.
- **Degraded / recovered state machine:** ≥3 consecutive stat failures →
  `degraded` (cadence backs off 10×, `supervisor.config_watcher.degraded`
  fires); ≥3 consecutive successes while degraded → `normal`
  (`supervisor.config_watcher.recovered` fires).
- **Latency (perf-001):** `_tick` offloads the synchronous stat, read, parse,
  and validate to `asyncio.to_thread`; budgets `<5 ms` p99 cache-hit, `<50 ms`
  p99 parse-swap (`tests/perf/test_policy_watcher_tick_budget.py`).
- **First tick is immediate (perf-003):** `run()` ticks once before the first
  sleep so a freshly-started daemon observes an already-edited file within one
  tick.

### Hookpoints (`carrier_tier=T0`, `fail_closed=True`)

Registered by `declare_hookpoints()` at module import:

| Hookpoint | Fires when |
| --- | --- |
| `supervisor.config_reload` | a swap succeeds (carries the new SHA) |
| `supervisor.config_reload_rejected` | any rejection branch |
| `supervisor.config_watcher.recovered` | degraded → normal transition |
| `supervisor.config_watcher.degraded` | normal → degraded (stat failures) |
| `policies.watcher.degraded` | audit store unwritable (sec-4 fallback) |

### `PolicySnapshotHistoryWriter` (`snapshot_ref.py`)

Writes one `policies_snapshot_history` row per successful swap (migration 0013,
sec-3): `file_sha256`, `loaded_at`, `policies_json` (256 KB JSONB cap),
`applied_by_operator_session_id` (NULL for an auto-applied watcher reload).
Slice-5 builds its rollback UI on these rows.

## Consumers (PR-S4-4 migration)

`RateLimitConfig.from_snapshot_ref(ref)`, `HandleCapConfig.from_snapshot_ref(ref)`,
`ContentStore.session_total_quota()`, and
`QuarantinedExtractor.burst_limiter_policy()` each deref `ref.current()`
**per call** so a watcher swap is reflected on the next use with no restart.
`Supervisor._proposal_dispatch_loop` derefs per iteration.

## Schema note (deviation)

`PoliciesV1` is the forward hot-reload schema. The currently-deployed
`config/policies.yaml` carries the Slice-3 `alfred config` low-blast knobs
(`web_fetch.*`, `quarantine.*`, `orchestrator.*`) which the `alfred config` CLI
(PR-S3-6) reads and writes. Reconciling that deployed file format and the
daemon-boot probe into `PoliciesV1` is a separate cross-cutting migration owned
by the `alfred config` / daemon-boot path, not PR-S4-4. The watcher + snapshot
quartet ship here; the file-format reconciliation is a tracked follow-up.
