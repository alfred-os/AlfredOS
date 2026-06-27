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
- Network egress (currently UNRESTRICTED — the real Linux policy does NOT
  `--unshare-net` because the quarantined LLM makes its own provider HTTPS call;
  the provider-only allowlist is a release-blocker tracked in #230, see
  `sbx-2026-005`).
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

**Status at graduation.** 11 entries as of PR-S4-7 (density floor 10). The
PR-S4-7 kernel-observable entries (`sbx-2026-003/004/006`) drive the REAL
shipped `config/sandbox/quarantined-llm.linux.bwrap.policy` bytes under bwrap
and assert a kernel-enforced refusal, NOT just a Pydantic refusal at the
policy-parse step. `sbx-2026-005` is the honest `out_of_scope` egress gap
(#230); `sbx-2026-011` exercises the realpath policy-root confinement.

## Coverage matrix

Maps each enumerated attack vector to the Slice-4 PR / task that lands its implementing
payload. Vectors labelled **TBD — Slice-4 follow-on (no current task)** have no
implementing payload in any current Slice-4 plan; they require a follow-on PR or
an explicit out-of-scope decision before Slice-4 closes. The matrix is the
contract between this category's threat model and the slice's task graph —
drift is a release-blocker.

| Attack vector | Owning PR / Task |
| --- | --- |
| Host filesystem read of `/etc/passwd` | PR-S4-7 (`sbx-2026-003`) — kernel-observable against the REAL Linux policy (no /etc bind) |
| Host `/proc/<host_pid>/environ` read | PR-S4-7 (`sbx-2026-006`) — contained by `--unshare-pid` |
| Host binary exec attempts (`/bin/sh`, `/usr/bin/env`) | PR-S4-7 (`sbx-2026-004`) — no /bin bind + `--unshare-pid` |
| Network egress outside policy `outbound_allowlist` | PR-S4-7 (`sbx-2026-005`) — **out_of_scope: egress UNRESTRICTED, release-blocker #230** |
| Policy-file path traversal (`../../../etc/passwd-bind.toml`) | PR-S4-6 (`sbx-2026-007`) — `policy_ref_escapes_root` refusal |
| Policy-file symlink-follow outside the policy root | PR-S4-7 (`sbx-2026-011`) — `policy_ref_escapes_root` (realpath confinement) |
| FAKE_UNAME production host-OS spoof | PR-S4-6 (`sbx-2026-010`) — `fake_uname_in_production` refusal |
| Manifest omits `[sandbox]` block | PR-S4-6 (`sbx-2026-001`) — `sandbox_block_missing` refusal |
| `kind:stub` in production | PR-S4-6 (`sbx-2026-002`) — `stub_kind_in_production` refusal |
| fd-3 partial-write / pipe-buffer-leak on provider-key channel | PR-S4-6 (`sbx-2026-008`) |
| Sandbox-info handshake mismatch (`kind:none` posing as `kind:full`) | PR-S4-6 (`sbx-2026-009`) |
| bwrap version drift (bwrap absent / below the version floor) | PR-S4-1 boot probe (#228) — TBD, no dedicated payload yet |

See [`.rulesync/skills/alfred-adversarial-corpus/SKILL.md`](../../../.rulesync/skills/alfred-adversarial-corpus/SKILL.md)
for naming, schema, and the "Adding a new payload" procedure.
