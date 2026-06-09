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

### bwrap fd-inheritance flag: `--sync-fd`, not `--keep-fd` (#218)

The Supervisor delivers the quarantined provider key over an inherited fd
(fd 3 by convention). The bwrap flag that leaves an inherited fd intact in the
sandboxed process is **`--sync-fd FD`** ("Keep this fd open while sandbox is
running").

**Empirically verified** against bubblewrap **0.9.0** in PR #229 CI
(`bwrap --help`): it advertises `--sync-fd FD` and there is **no `--keep-fd`**.
The earlier belief that `--keep-fd` is "the upstream 0.9.0+ rename" of
`--sync-fd` (issue #218) is a **misconception** — `--sync-fd` is the flag in
both the Bookworm 0.8.0 image and 0.9.0; the rename never happened. No bwrap
version AlfredOS targets uses `--keep-fd`.

The launcher and the `SandboxPolicy` → bwrap-flag translator
(`src/alfred/plugins/sandbox_policy.py::policy_to_bwrap_flags`) emit
**`--sync-fd`**. The logical policy field name `keep_fds` is retained as
documented shorthand; only the emitted CLI surface uses the bwrap flag. A CI
version-drift guard greps `bwrap --help` for `--sync-fd` so a future rename
fails loudly rather than mis-running; the daemon-boot bwrap-version probe
(#228) enforces the version floor at boot.

Separately, fd-3 delivery requires the spawning parent to place the pipe's
read end **on fd 3** (`--sync-fd 3` keeps fd 3 open but does not create it) —
see `fd3_key_delivery` and the resolver test's preexec `dup2`.

## Consequences

### Positive

- PRD §5 line 117 invariant fully satisfied from Slice 4 onwards.
- Outbound network calls from the quarantined LLM are kernel-enforced against
  the declared allowlist, not just policy-checked.

### Negative

- Per-OS sandbox policy files must be maintained and tested. The Linux policy
  is the AlfredOS primary target; macOS and Windows policies are best-effort.
- The `bwrap` cold-start overhead adds ~50-100ms to the subprocess spawn
  path (within the < 500ms cold-start budget from spec §7a.1).

### Neutral

- `StdioTransport` and `AlfredPluginSession` are unchanged; the container
  boundary is below the transport layer.

## References

- [PRD §5](../../PRD.md#5-architecture-overview) — hybrid-isolation invariant (line 117).
- [ADR-0017](0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md) — Slice-3 hybrid-isolation decision.
- [Spec §5.7](../superpowers/specs/2026-05-30-slice-3-trust-tier-completion-design.md#57-co-merged-slice-4-containerisation-adr-commitment--prd-5-amendment) — co-merged commitment rationale.
