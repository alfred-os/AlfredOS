# ADR-0023 — mtime-polled hot-reload for `config/policies.yaml`

**Date:** 2026-06-07
**Status:** Proposed
**Closes:** [#159](https://github.com/alfred-os/AlfredOS/issues/159)
**Implemented in:** PR-S4-4 (planned)
**Related:** [ADR-0014](./0014-pluggable-hooks-for-every-action.md) (hookpoint dispatch the watcher emits through), [ADR-0024](./0024-perf-gate-hardware-budget.md) (perf budgets for `current()`)

## Context

`config/policies.yaml` is the operator-facing knob bundle covering rate limits, handle caps, content-store quotas, and quarantined-provider settings. Slice 3 read the file once at supervisor boot. Operators changing a knob — to widen a rate-limit window during an incident, to retire an over-aggressive cap — must restart the daemon, dropping every in-flight conversation.

A persistent watcher (`watchdog`, `inotify`, file-event bridges) adds platform-specific code paths (Linux `inotify`, macOS `FSEvents`, Windows `ReadDirectoryChangesW`) and a dependency footprint disproportionate to the operational need. A poll-based watcher with mtime+size short-circuit is portable, has zero extra dependencies, and matches the once-per-second human knob-tuning cadence.

Hot-reloading EVERY config knob is unsafe — `quarantined_provider_url` and `secret_broker_config_ref` change the trust boundary mid-flight and must remain reviewer-gated. The watcher must distinguish high-blast keys (refuse hot-reload) from low-blast keys (apply atomically).

## Decision

PR-S4-4 lands the watcher per the following design:

1. **`PolicyWatcher` polls `(mtime, size)` at 1 s default.** Re-read only when the pair changes. Watcher-side short-circuit on unchanged SHA-256 of file bytes (load-bearing idempotency that does NOT rely on a non-existent `AuditWriter.dedupe_surface`).

2. **TOCTOU-safe file load via open-then-fstat.** `os.open(O_RDONLY | O_NOFOLLOW)` + `os.fstat(fd)` + `os.read(fd, stat.st_size)` — refuses inode-swap-between-stat-and-read attacks. 256 KB cap enforced after fstat.

3. **`PoliciesSnapshotRef.current()` is synchronous.** Long-lived loops deref per iteration. The sync-path is a single `__slots__` attribute load, GIL-atomic, mypy-refuses `await`. ADR-0024 carries the explicit perf budget for this path.

4. **Atomic single-attribute assignment for swap.** Phase 1: emit `CONFIG_RELOAD_FIELDS` audit row. If the primary audit write raises, the watcher MUST: (a) emit `CONFIG_RELOAD_REJECTED_FIELDS(reason="audit_write_failed")` via the fallback JSONL sink at `~/.local/state/alfred/policies-rejected-fallback.jsonl`; (b) call `invoke("policies.watcher.degraded", ...)` so `alfred status` surfaces the degradation; (c) re-raise the original `AuditWriteError` so the watcher's outer loop logs it (CLAUDE.md hard rule 7 — no silent failure on the security path). The active snapshot stays at the pre-swap value; the watcher tries again on the next mtime change. Phase 2 (atomic `self._current = new_snapshot`) ONLY runs after a successful primary audit write.

5. **Blast-radius classification refuses high-blast hot-reload.** `quarantined_provider_url`, `secret_broker_config_ref`, and the entire `HighBlastPolicies` family refuse hot-reload with `CONFIG_RELOAD_REJECTED_FIELDS(reason="high_blast_change")`. Anti-abuse / rate-limit knobs (`quarantined_extract_per_user_persona`) are HighBlast too — an attacker with config-write capability could otherwise drive rate-limits to 0 (DoS) or infinity (anti-abuse bypass) silently. Only the reviewer-gated proposal flow may change them.

6. **`policies_snapshot_history` rollback log.** Every successful swap inserts a row recording `(file_sha256, applied_at, policies_blob, applied_by_operator_session_id)` for forensic replay. The history table ships in PR-S4-0b migration 0013; the writer ships in PR-S4-4. Slice-5 adds the rollback UI.

## Consequences

**Positive.** Operators can tune low-blast knobs without restart. The high-blast refusal preserves the trust boundary. The 1 s poll is below human-perceptible latency. Zero new dependencies. Audit-write failure is loud + observable + retryable.

**Negative.** Stale-snapshot-for-one-iteration: a swap during loop iteration N completes against the pre-swap snapshot; iteration N+1 picks up the new snapshot. This is by design — atomic per-iteration policy is simpler than mid-iteration lookups. Consumers MUST NOT cache the snapshot across iterations. Sustained audit-write failure blocks all hot-reloads (a known, loudly-signalled mode) until the audit path recovers.

**Alternatives considered.** `watchdog` library or platform-specific inotify — rejected on dependency-footprint grounds; the 1 s poll matches the operational need. PostgreSQL `LISTEN`/`NOTIFY` triggered by an `alfred policies set` CLI command — rejected because operators edit the file directly; the source of truth is the file, not the DB. SIGHUP-driven reload — rejected because signal-driven reload races with in-flight `current()` reads.

## References

- [#159 — Hot-reload for policies.yaml](https://github.com/alfred-os/AlfredOS/issues/159)
- [ADR-0024](./0024-perf-gate-hardware-budget.md) (perf budgets including `current()` p99)
- Spec: [`docs/superpowers/specs/2026-06-06-slice-4-design.md`](../superpowers/specs/2026-06-06-slice-4-design.md) §4 (hot-reload)
- Plan: [`docs/superpowers/plans/2026-06-07-slice-4-pr-s4-4-policy-hot-reload.md`](../superpowers/plans/2026-06-07-slice-4-pr-s4-4-policy-hot-reload.md)
