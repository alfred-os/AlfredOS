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
- Over-broad bind source: host root, non-allowlisted top-level tree, soft-field
  traversal to root, or procfs magic-link (`bind_source_too_broad`, #428).
- `policy_ref` charset injection: JSON-injection characters (quote+comma,
  newline) that would forge or inject a row into the launcher's audit-JSON
  printf output (`policy_ref_charset_invalid`, #437).
- Launcher `sandbox_refused` refusal-row injection: escaped-JSON bytes in a
  field value (forged `event`, embedded newline) that must not forge a second
  audit event or smuggle an out-of-vocab `reason` past the host-side stderr
  parser (`parse_launcher_refusal_rows`, #433).
- Runtime-compromised quarantine child leaking its fd-3 provider key or the
  raw T3 body back to a host-visible surface (stdout, stderr, the audit log) —
  contained structurally by the fd-3 read-once child boundary and
  `read_frame`'s single-result-frame lift, not a child-side promise.
- Live-spawned quarantine child (real launcher + shipped bwrap policy, not a
  direct bwrap invocation) attempting the same host-escape probes as
  `sbx-2026-003/004/006` — the launcher-spawned graduation of those entries.
- Discord adapter outbound network egress to an arbitrary attacker host —
  contained by the adapter's `--unshare-net` policy; egress only via the
  gateway L7 CONNECT proxy (Spec C G7-4, ADR-0043).
- SCM_RIGHTS control-fd coax/forgery against the #340 PR2a reachability-broker
  mechanism, which ships dormant (`control_fd` default `False`) and whose
  control channel accepts only an exactly-one-fd frame (ADR-0050).
- Forged `supervisor.plugin.sandbox_stub_used` row on inherited launcher
  stderr from a live, exec'd child — must never be persisted; the host-side
  parser recognizes only `sandbox_refused` and drops every stub_used line
  unconditionally, even interleaved with a genuine refusal row (#436, D4/D7).
- `plugin_id` charset injection: an out-of-charset first positional argument
  (JSON-injection characters, path traversal, shell metacharacters) must never
  be echoed into an emitted stderr row — only the launcher-authored
  `<invalid>` sentinel may stand in for it (#435, D2).

**Prefix.** `sbx-`

**Owning PRs.** PR-S4-6 (launcher), PR-S4-7 (policies), plus later fast-follows:
PR-S4-11c-2b0 (live quarantine-child spawn), #333 G7-4 (Discord egress
containment), #340 PR2a (dormant reachability broker), #428 (bind-source
guard), #437 (`policy_ref` charset), #433 (refusal-row injection), and #436
(stub-row forgery + `plugin_id` anti-echo). PR-S4-7 ships the bulk of the
original entries; PR-S4-6 ships the launcher-side fd / handshake entries.

**Ingestion paths.** `sandbox_policy_load`, `stdio_fd3_key_delivery`,
`launcher_refusal_stderr`.

**Expected outcomes.** Typically `refused` (bwrap or policy parser refuses)
or `audit_row_emitted` anchored to `SANDBOX_REFUSED_FIELDS` /
`SANDBOX_STUB_USED_FIELDS`.

**Status at graduation.** 11 entries as of PR-S4-7 (density floor 10); 20 entries
as of #436 (2026-07-16). The PR-S4-7 kernel-observable entries
(`sbx-2026-003/004/006`) drive the REAL shipped
`config/sandbox/quarantined-llm.linux.bwrap.policy` bytes under bwrap and
assert a kernel-enforced refusal, NOT just a Pydantic refusal at the
policy-parse step. `sbx-2026-005` is the honest `out_of_scope` egress gap
(#230); `sbx-2026-011` exercises the realpath policy-root confinement.
`sbx-2026-012/013` (PR-S4-11c-2b0) graduate the live quarantine-child spawn —
013 re-runs the 003/004/006 host-escape probes through the real launcher
instead of a direct bwrap invocation. `sbx-2026-014` (#333 G7-4) covers the
Discord adapter's network-namespace containment. `sbx-2026-015` (#340 PR2a)
pins the SCM_RIGHTS reachability-broker's dormancy invariant. `sbx-2026-019`
(#436) pins that a forged `sandbox_stub_used` row is dropped unconditionally
by the host-side parser's event gate — deliberately NOT persisted (D4);
`sbx-2026-020` (#435 D2) pins the launcher's `plugin_id` anti-echo guarantee.

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
| Over-broad bind source (`/`, non-allowlisted top-level tree, `/lib64/..`, `/proc/self/root`) | #428 (`sbx-2026-016`) — `bind_source_too_broad` parse-time refusal (not kernel-observable) |
| `policy_ref` charset injection (forged `event` field / injected row via out-of-charset chars) | #437 (`sbx-2026-017`) — `policy_ref_charset_invalid` refusal; caught by the manifest parser first, not kernel-observable |
| Launcher `sandbox_refused` refusal-row injection (forged 2nd event / out-of-vocab reason via escaped-JSON field values) | #433 (`sbx-2026-018`) — host-side `parse_launcher_refusal_rows` containment, not kernel-observable |
| Runtime-compromised quarantine child leaks fd-3 key / raw T3 body to host-visible stdout, stderr, or audit log | PR-S4-11c-2b0 (`sbx-2026-012`) — structural containment via the fd-3 read-once child boundary + `read_frame`'s single-result-frame lift |
| Live-spawned quarantine child host escape (real launcher + shipped bwrap policy, not direct bwrap) | PR-S4-11c-2b0 (`sbx-2026-013`) — kernel-observable graduation of `sbx-2026-003/004/006` onto the launcher-spawned path (Docker-only) |
| Discord adapter outbound network egress to an arbitrary host | #333 G7-4 (`sbx-2026-014`) — `--unshare-net` kernel containment; egress only via the gateway L7 CONNECT proxy (ADR-0043) |
| SCM_RIGHTS control-fd coax/forgery on the dormant reachability-broker mechanism | #340 PR2a (`sbx-2026-015`) — `control_fd` default-`False` dormancy invariant + `recv_passed_fd`'s exactly-one-fd envelope (ADR-0050) |
| Forged `supervisor.plugin.sandbox_stub_used` row on inherited launcher stderr from a live, exec'd child | #436 (`sbx-2026-019`) — `parse_launcher_refusal_rows`'s event-only gate drops every stub_used line unconditionally; deliberately NOT persisted (D4), not kernel-observable |
| `plugin_id` charset injection / anti-echo into an emitted launcher row | #435 D2 (`sbx-2026-020`) — charset gate fires before any JSON-emitting branch; tainted bytes never echoed, only the `<invalid>` sentinel, not kernel-observable |

See [`.rulesync/skills/alfred-adversarial-corpus/SKILL.md`](../../../.rulesync/skills/alfred-adversarial-corpus/SKILL.md)
for naming, schema, and the "Adding a new payload" procedure.
