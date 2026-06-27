# Config-reload bypass adversarial corpus

Attacks against the mtime-polled hot-reload path for `config/policies.yaml`
(ADR-0023). Covers TOCTOU between `stat` and `read`, blast-radius downgrade
attempts that try to slip high-blast keys through the low-blast hot-reload
channel, parse-failure cache poisoning, and silent-rollback bypasses.

**Attack vectors covered**

- TOCTOU inode-swap between `os.stat` and `os.read` (refused by
  open-then-fstat with `O_NOFOLLOW`).
- High-blast key change in a YAML diff that the watcher should refuse (e.g.,
  `quarantined_provider_url`, `secret_broker_config_ref`,
  `quarantined_extract_per_user_persona` per PR-S4-4 round-2 closure 9).
- Audit-write-failure silent rollback (closure 7 — fallback JSONL + degraded
  hookpoint, no silent watcher death).
- Cached-mtime suppression of rejection re-emit (closure 3).
- Policy-file size > 256 KB DoS attempt.
- Symlink swap targeting a non-policy-root path.

**Prefix.** `csb-`

**Owning PR.** PR-S4-4 (policy hot-reload).

**Ingestion paths.** `mtime_poll`, `sandbox_policy_load` (overlap for
nested-policy attacks).

**Expected outcomes.** `refused` (loader refuses) or `audit_row_emitted`
anchored to `CONFIG_RELOAD_REJECTED_FIELDS` with a closed-vocab `reason`.
The new `policy_swap_aborted_on_audit_failure` outcome covers the
audit-then-swap two-phase commit failure path.

**Status at graduation.** Minimum 3 entries.

## Coverage matrix

Maps each enumerated attack vector to the Slice-4 PR / task that lands its implementing
payload. Vectors labelled **TBD — Slice-4 follow-on (no current task)** have no
implementing payload in any current Slice-4 plan; they require a follow-on PR or
an explicit out-of-scope decision before Slice-4 closes. The matrix is the
contract between this category's threat model and the slice's task graph —
drift is a release-blocker.

| Attack vector | Owning PR / Task |
| --- | --- |
| TOCTOU inode-swap between `os.stat` and `os.read` | PR-S4-4 (`csb-2026-001` — `O_NOFOLLOW`+fstat refuses) |
| `high_blast.*` key change attempted via hot-reload | PR-S4-4 (`csb-2026-002` — `high_blast_change` refusal) |
| Audit-write-failure silent-rollback bypass | PR-S4-4 (`csb-2026-003` — fallback JSONL + `policies.watcher.degraded` hookpoint) |
| Cached-mtime suppression of rejection re-emit | PR-S4-4 (`csb-2026-004` — re-emit each tick until fixed) |
| Policy file >256 KB DoS attempt | PR-S4-4 (`csb-2026-005` — size cap enforced after fstat) |
| Symlink swap targeting non-policy-root path | PR-S4-4 (`csb-2026-006` — symlink refused at `O_NOFOLLOW`) |
| `rate_limits.*` / `handle_caps.*` anti-abuse-knob swap via low-blast channel | PR-S4-4 round-3 (`csb-2026-007` — `high_blast_change` refusal; ADR-0023 §5, default-refuse allowlist) |

**Executable counterparts.** `test_csb_corpus_executable.py` loads each
`csb-2026-*` payload and drives the real `PolicyWatcher` to assert the declared
`expected_outcome` actually fires — so a payload cannot be weakened or renamed
without the suite noticing (mirrors the `de-2026-*` executable-corpus pattern).

See [`.rulesync/skills/alfred-adversarial-corpus/SKILL.md`](../../../.rulesync/skills/alfred-adversarial-corpus/SKILL.md)
for naming, schema, and the "Adding a new payload" procedure.
