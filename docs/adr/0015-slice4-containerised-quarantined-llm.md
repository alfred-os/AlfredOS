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

### bwrap fd-inheritance flag: `--keep-fd`, NOT `--sync-fd` (corrects #218)

The Supervisor delivers the quarantined provider key over an inherited fd
(fd 3 by convention). The bwrap flag that leaves an inherited fd intact in the
sandboxed process is **`--keep-fd FD`** ("Do not close fd FD"), present since
bubblewrap **0.5.0** and still current in **0.9.0**. The launcher and the
`SandboxPolicy` → bwrap-flag translator
(`src/alfred/plugins/sandbox_policy.py::policy_to_bwrap_flags`) emit
**`--keep-fd`**. The logical policy field name `keep_fds` matches the emitted
flag.

`--sync-fd FD` is a **different, unrelated flag**: it is bwrap's *internal
sync-protocol* fd (used with `--block-fd` / `--userns-block-fd`). bwrap
consumes/closes it and does **NOT** pass it through as a data channel to the
child. Using `--sync-fd 3` for key delivery causes the sandboxed child to see
fd 3 as `OSError: [Errno 9] Bad file descriptor` on `os.read(3, ...)`.

**This amendment reverses the earlier `--sync-fd` amendment (issue #218).**
Issue #218 ("Bookworm bubblewrap 0.8.0 renamed `--keep-fd` to `--sync-fd`") is
a **misdiagnosis**: the two flags both exist and are distinct — there was no
rename. The original launcher/translator correctly emitted `--keep-fd`; #218
wrongly flipped it to `--sync-fd`, which broke fd-3 delivery. Empirical proof:
CI installed bubblewrap **0.9.0**, and `--sync-fd 3` made the sandboxed plugin's
`os.read(3, 4)` fail with `Bad file descriptor` (PR #229 / #152). Corroborating
evidence: `tests/unit/test_dockerfile_bubblewrap_present.py` always stated
"bubblewrap 0.8.x which has `--keep-fd` (introduced in 0.5.0)".

PR-S4-7 (macOS/Windows policy bytes) and any future bwrap upgrade MUST emit
`--keep-fd` for fd-3 inheritance. This invariant is owned by THIS ADR; the
daemon-boot bwrap-version probe (#228) enforces the version floor at boot.

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
