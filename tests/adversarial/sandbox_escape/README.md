# Sandbox-escape adversarial corpus

Attacks against the kernel-enforced trust boundary of `plugins/` plugins that declare
`sandbox.kind = "full"` per ADR-0015 (Slice-4 containerised quarantined-LLM). Covers
filesystem confinement, process-fork prevention, network-namespace isolation, and
the fd-3 provider-key delivery channel (bwrap inherits fd 3 into the sandbox by
default — no CLI flag; `--sync-fd` is bwrap's internal sync fd and must NOT be
used, it consumes fd 3; verified bubblewrap 0.8.0/0.9.0, #218).

**Attack vectors covered**

- Host filesystem read attempts (`/etc/passwd`, `/proc/<host_pid>/environ`).
- Host binary exec attempts (`/bin/sh`, `/usr/bin/env`).
- Network egress outside the policy-declared `outbound_allowlist`.
- Policy-file path traversal (`../../../etc/passwd-bind.toml`) and symlink-follow.
- TOML schema-downgrade against `sandbox_policy_registry` table writes.
- fd-3 partial-write / pipe-buffer-leak attempts on the provider-key channel.
- Sandbox-info handshake mismatch (plugin reports kind:full while actually kind:none).
- bwrap version drift (CVE-window or bwrap absent / below the version floor).

**Prefix.** `sbx-`

**Owning PRs.** PR-S4-6 (launcher), PR-S4-7 (policies). PR-S4-7 ships the bulk of
the entries; PR-S4-6 ships the launcher-side fd / handshake entries.

**Ingestion paths.** `sandbox_policy_load`, `stdio_fd3_key_delivery`.

**Expected outcomes.** Typically `refused` (bwrap or policy parser refuses)
or `audit_row_emitted` anchored to `SANDBOX_REFUSED_FIELDS` /
`SANDBOX_STUB_USED_FIELDS`.

**Status at graduation.** Minimum 3 entries (PR #205 round-1 closure
`test-eng-002`); each entry asserts a kernel-observable refusal, NOT just a
Pydantic refusal at the policy-parse step.

## Coverage matrix

Maps each enumerated attack vector to the Slice-4 PR / task that lands its implementing
payload. Vectors labelled **TBD — Slice-4 follow-on (no current task)** have no
implementing payload in any current Slice-4 plan; they require a follow-on PR or
an explicit out-of-scope decision before Slice-4 closes. The matrix is the
contract between this category's threat model and the slice's task graph —
drift is a release-blocker.

| Attack vector | Owning PR / Task |
|---|---|
| Host filesystem read attempts (`/etc/passwd`, `/proc/<host_pid>/environ`) | PR-S4-6 / PR-S4-7 (`sbx-2026-001..003`) |
| Host binary exec attempts (`/bin/sh`, `/usr/bin/env`) | PR-S4-7 (`sbx-2026-004`) |
| Network egress outside policy `outbound_allowlist` | PR-S4-7 (`sbx-2026-005`) |
| Policy-file path traversal (`../../../etc/passwd-bind.toml`) | PR-S4-6 (`sbx-2026-007`) — `policy_ref_escapes_root` refusal |
| Policy-file symlink-follow into bound read-only path | PR-S4-7 (`sbx-2026-011`) |
| TOML schema-downgrade against `sandbox_policy_registry` | PR-S4-7 (`sbx-2026-010`) |
| fd-3 partial-write / pipe-buffer-leak on provider-key channel | PR-S4-6 (`sbx-2026-008`) |
| Sandbox-info handshake mismatch (`kind:none` posing as `kind:full`) | PR-S4-6 (`sbx-2026-009`) |
| bwrap version drift (bwrap absent / below the version floor) | PR-S4-1 boot probe (#228) — TBD, no dedicated payload yet (`sbx-2026-008` is fd-3 partial-write, above) |

See [`.rulesync/skills/alfred-adversarial-corpus/SKILL.md`](../../../.rulesync/skills/alfred-adversarial-corpus/SKILL.md)
for naming, schema, and the "Adding a new payload" procedure.
