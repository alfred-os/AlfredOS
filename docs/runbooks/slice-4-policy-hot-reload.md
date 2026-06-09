# Runbook: policy hot-reload (Slice 4)

**Status:** _machinery_ shipped in Slice 4 (PR-S4-4) — the `PolicyWatcher`,
`PoliciesSnapshotRef`, and the consumer deref pattern. **Production wiring is
pending [#225](https://github.com/MrReasonable/AlfredOS/issues/225):** the
watcher is not yet scheduled under the daemon TaskGroup, the daemon still
injects a stub ref, and `PoliciesV1` is not yet reconciled with the live
`config/policies.yaml` schema. Once wired, the watcher mtime-polls
`config/policies.yaml`, hot-reloads low-blast changes without an `alfred`
restart, and refuses high-blast changes (routed through the reviewer gate).
This runbook describes the wired behaviour.
**ADR:** [ADR-0023](../adr/0023-mtime-polled-hot-reload-for-policies-yaml.md)
**Subsystem:** [`docs/subsystems/policies.md`](../subsystems/policies.md)
**Issue:** [#159](https://github.com/MrReasonable/AlfredOS/issues/159)

This runbook covers editing `config/policies.yaml` in production, reading the
`CONFIG_RELOAD` / `CONFIG_RELOAD_REJECTED` audit rows, and recovering a
degraded watcher.

> **Schema note.** The forward hot-reload schema is `PoliciesV1`
> (`src/alfred/policies/model.py`). The currently-deployed
> `config/policies.yaml` still carries the Slice-3 `alfred config` low-blast
> knobs; reconciling the deployed file format with `PoliciesV1` (and the
> daemon-boot probe) is a tracked follow-up owned by the `alfred config` /
> daemon-boot path. The watcher refuses anything that does not validate as
> `PoliciesV1` with a loud `validation_failure` — it never applies a malformed
> file.

## Editing `config/policies.yaml` in production

1. Edit `config/policies.yaml` (or `$ALFRED_POLICIES_PATH`).
2. Watch the audit log for the outcome:

   ```bash
   alfred audit log --tail --filter supervisor.config_reload
   ```

   - A `config.reload.applied` row (carries `new_sha256` + `changed_keys`)
     means the change is live — no restart needed.
   - A `config.reload.rejected` row means the edit was refused; the active
     snapshot is unchanged. Inspect `reason`:

     | `reason` | What happened | Fix |
     |---|---|---|
     | `parse_failure` | YAML is malformed or > 256 KB | Fix the syntax / shrink the file and re-save |
     | `validation_failure` | A field violates its constraint | Check `offending_key`; correct the value |
     | `high_blast_change` | You edited a reviewer-gated key | Submit a proposal via `alfred config quarantined-provider …` instead |
     | `file_vanished` | The file disappeared between stat and read | Transient (editor write-then-rename); re-save |
     | `stat_failed` | Filesystem-level error | Check disk / permissions |
     | `audit_write_failed` | The audit store is unhealthy | Check Postgres; the watcher retries on the next change |

3. **The rejection re-emits every poll** until you fix the file (sec-2). Seeing
   the same `config.reload.rejected` row repeat is expected — it is a sustained
   signal, not a stuck loop. It stops the moment the file validates.

## High-blast keys

`high_blast.quarantined_provider_url` and `high_blast.secret_broker_config_ref`
**refuse hot-reload outright**. A direct file edit to either is refused with
`reason="high_blast_change"`; only the reviewer-gated proposal flow may change
them. This is deliberate: an attacker with config-write capability could
otherwise redirect every quarantined extraction or repoint the secret broker
silently.

## Degraded watcher recovery

If you see `supervisor.config_watcher.degraded`, the watcher hit ≥3 consecutive
stat errors and backed its poll cadence off 10×. Fix the underlying filesystem
problem (permissions, mount, disk). Recovery is **automatic** after 3
consecutive successful stats — look for `supervisor.config_watcher.recovered`.

If you see `policies.watcher.degraded` (distinct from the above), the audit
store itself is unwritable: the watcher logged the rejection to
`~/.local/state/alfred/policies-rejected-fallback.jsonl` and is continuing.
Restore the audit store (Postgres); subsequent rejections then write to the
audit log again. The fallback `.jsonl` is **not** auto-pruned — it is a
forensic record; rotate or delete it manually once the outage is resolved.

## TOCTOU + size safety

The watcher reads the file with `O_NOFOLLOW` + `fstat`-on-open-fd, so a symlink
or inode swap between stat and read cannot redirect it to attacker content
(csb-2026-001). A file over 256 KB is refused before the YAML parser ever sees
it (csb-2026-005). Keep `config/policies.yaml` in a root-only-writable
directory for defence in depth.
