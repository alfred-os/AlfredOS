# ADR-0015 — Slice 4: containerise the quarantined-LLM subprocess

## Status

Proposed

**Date:** 2026-05-31

## Context

Slice 3 ships the quarantined LLM as an MCP stdio subprocess under the
`alfred-quarantine` OS user with env scrubbing and fd-3 key delivery
(ADR-0017 §5). This is a deliberate, time-bounded relaxation of PRD §5
line 117 ("containerized with declared capabilities"). The UID-separation
boundary prevents the subprocess from reading the orchestrator's secrets
file; it does NOT prevent arbitrary filesystem writes to `alfred-quarantine`-
owned paths or outbound network calls to any reachable destination.

PRD §5 line 117's full invariant requires kernel-namespace isolation: no
view of the host filesystem except declared mounts; network restricted to
the declared allowlist; no capability to spawn further subprocesses. Without
this commitment, the relaxation introduced in Slice 3 silently persists.

## Decision

Slice 4 migrates the quarantined-LLM subprocess to a container with full
kernel-namespace isolation using Linux `bwrap` (AlfredOS Docker default),
macOS `sandbox-exec`, and a Windows stub policy. The `bin/alfred-plugin-launcher`
receives the per-OS sandbox policy files in Slice 4; `ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED=1`
becomes a development-only escape hatch that refuses in production.

### bwrap fd-3 delivery: NO CLI flag — bwrap inherits fd 3 by default (#218)

> **This section supersedes both prior amendments** (the original `--keep-fd`
> claim AND the subsequent `--sync-fd` correction). Both were wrong. The
> truth below is empirically proven against the exact production image.

The Supervisor delivers the quarantined provider key over an inherited fd
(fd 3 by convention). **No bwrap CLI flag is used to do this.** bubblewrap
passes inherited, open, non-CLOEXEC fds — including fd 3 — into the sandboxed
child **by default**. The launcher therefore emits NO fd flag and relies on
that default inheritance.

**Empirically proven** in a docker `bwrap` repro against the exact production
image (Debian Bookworm, bubblewrap **0.8.0**) and **0.9.0**. The repro matrix
(identical pipe + `dup2` + bwrap setup, only the flag varying):

- `--sync-fd 3` + fd-3 inherited → **EBADF** (the plugin's `os.read(3)` fails).
- **no fd flag** + fd-3 inherited → **key delivered, exit 0** ✅.
- production-shaped policy (all unshares + `--dev` + `--die-with-parent` +
  binds), no fd flag → **key delivered, exit 0** ✅.

`--sync-fd FD` ("Keep this fd open while sandbox is running") keeps the fd open
in bwrap's **own monitor process** for its internal sync protocol; pointing it
at fd 3 **consumes** fd 3 so the sandboxed child can no longer read it. It is
**not** a key-delivery flag and must never be used for one. There is **no
`--keep-fd`** in bwrap 0.8.0/0.9.0 either.

The launcher and the `SandboxPolicy` → bwrap-flag translator
(`src/alfred/plugins/sandbox_policy.py::policy_to_bwrap_flags`) emit **no fd
flag**. The logical policy field `keep_fds` is retained as a validated
*declaration* of intent — arch-2 refuses a `kind: full` policy whose
`keep_fds` omits 3 at construction (`kind_full_requires_keep_fd_3`) — but the
inheritance itself is bwrap's default and has no CLI surface. There is no flag
to guard for version drift; the daemon-boot bwrap probe (#228) enforces the
bwrap-presence / version floor at boot.

fd-3 delivery still requires the spawning parent to place the pipe's read end
**on fd 3** (bwrap inherits whatever is on fd 3; it does not create it) — see
`fd3_key_delivery` and the resolver test's preexec `dup2`.

## Consequences

### Positive

- PRD §5 line 117 invariant satisfied from Slice 4 onwards **for the
  filesystem and namespace axes** — kernel-enforced via `bwrap` (read-only
  binds, no `/etc`/`/bin`, `--unshare-{pid,uts,cgroup,ipc}`, `die_with_parent`).
  Empirically verified against the real quarantined-LLM policy bytes (PR-S4-7).
  The **process-spawn axis is only PARTIALLY met** (amended 2026-06-09, PR-S4-7):
  pid-namespace isolation hides host processes, but the broad read-only `/usr`
  bind leaves `/usr/bin/*` (python, curl, …) **exec-reachable** inside the
  sandbox, so PRD §5's "no capability to spawn further subprocesses" condition
  does NOT yet fully hold. Tightening the bind to a minimal interpreter set is
  tracked in [#230](https://github.com/MrReasonable/AlfredOS/issues/230)
  alongside the egress allowlist; both are release-blockers before the
  quarantined LLM is wired live.

### Negative

- **Network egress is NOT yet kernel-enforced (amended 2026-06-09, PR-S4-7).**
  The quarantined LLM makes its own provider HTTPS call (provider key delivered
  over fd 3), and the Slice-4 `SandboxPolicy` schema cannot yet express a
  provider-only egress allowlist — so the Linux policy does NOT `unshare net`
  and egress is currently **unrestricted**. This is acceptable as an interim
  state because the live quarantined child is the DETERMINISTIC-ECHO loop with no
  provider client and no network-capable import reachable from its live loop, so
  the unrestricted egress contains nothing that can use it. (Superseded in part by
  the PR-S4-11c-2b note below: this bullet originally justified the open egress by
  the child not being spawned at all — `src/alfred/core/` drove no extraction and
  `PluginLifecycle` spawned no subprocess — but PR-S4-11c-2b flipped the daemon to
  spawn it end-to-end, so the justification is now the no-egress-capable-child
  property, not the absence of a spawn.)
  The provider-only egress allowlist + HTTPS-downgrade refusal are tracked in
  **[#230](https://github.com/MrReasonable/AlfredOS/issues/230) and are a
  release-blocker before the quarantined LLM is wired live.** Until #230 lands,
  the earlier claim that outbound calls are "kernel-enforced against the
  declared allowlist" does NOT hold and is superseded by this amendment.
- **The quarantined-LLM child code now ships in the wheel under a bound prefix
  (amended 2026-06-11, PR-S4-11c-2b0, ADR-0030).** The spawn target moved from
  the repo-root, wheel-excluded `plugins/alfred_quarantined_llm/quarantine_plugin.py`
  to the installed package `alfred.security.quarantine_child`
  (`python -m alfred.security.quarantine_child`), so the child is import-reachable
  under the policy's `/usr` read-only bind (site-packages) without widening the
  sandbox. This is a FACTUAL amendment; status stays **Proposed** (the
  `Proposed → Accepted` graduation flip is human-gated, deferred to PR-S4-11c-7).
  See ADR-0030 for the wheel-co-location + bound-interpreter contract.
- Per-OS sandbox policy files must be maintained and tested. The Linux policy
  is the AlfredOS primary target; macOS and Windows policies are best-effort.
- The `bwrap` cold-start overhead adds ~50-100ms to the subprocess spawn
  path (within the < 500ms cold-start budget from spec §7a.1).

### Neutral

- `StdioTransport` and `AlfredPluginSession` are unchanged; the container
  boundary is below the transport layer.

> **PR-S4-11c-2b note (2026-06-12).** The bwrap-sandboxed quarantined child is now
> LIVE in production: the daemon spawns it at boot when a comms adapter is enabled
> (ADR-0027 amendment). The shipped child is still the deterministic-echo loop — NO
> provider client, NO network egress — so the open-egress gap (release-blocker #230)
> still contains nothing that can use it; the real LLM + its egress allowlist land in
> PR-S4-11c-2c.

## References

- [PRD §5](../../PRD.md#5-architecture-overview) — hybrid-isolation invariant (line 117).
- [ADR-0017](0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md) — Slice-3 hybrid-isolation decision.
- [Spec §5.7](../superpowers/specs/2026-05-30-slice-3-trust-tier-completion-design.md#57-co-merged-slice-4-containerisation-adr-commitment--prd-5-amendment) — co-merged commitment rationale.
