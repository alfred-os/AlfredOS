# `config/sandbox/` — plugin OS-sandbox policies

This directory holds the per-OS sandbox policy files that the plugin launcher
(`bin/alfred-plugin-launcher.sh`) resolves when it spawns a plugin whose
manifest declares `[sandbox] kind = "full"`. The policy bytes define the
kernel-enforced (Linux) or advisory (macOS) isolation the plugin subprocess
runs under (spec §7.2, ADR-0015).

> Operators: these files are part of the security trust boundary. Editing them
> by hand changes what a plugin can read, exec, and reach on the host. Treat a
> change here like a change to `policies.yaml` — it goes through the reviewer
> gate (the dedicated operator tooling for policy edits is future work; until it
> lands, edit via a reviewed proposal, never on `main` at runtime).

## What ships here

The only `kind = "full"` plugin today is the **quarantined LLM** — the single
component that handles raw T3 (untrusted) content. Its policy files:

| File | OS | Status |
|---|---|---|
| `quarantined-llm.linux.bwrap.policy` | Linux | **Kernel-enforced** via bwrap |
| `quarantined-llm.macos.sb` | macOS | File only — `sandbox-exec` execution deferred (#230); launcher refuses `kind:full` on macOS today |
| `quarantined-llm.windows.stub.policy` | Windows | Documented stub — production refuses, dev emits `supervisor.plugin.sandbox_stub_used` |

`_fixtures/` holds policy files used only by tests; they are NOT production
policies.

## Per-OS resolution

The manifest's `[sandbox.policy_refs]` maps each host OS to a policy file:

```toml
[sandbox]
kind = "full"
[sandbox.policy_refs]
linux   = "config/sandbox/quarantined-llm.linux.bwrap.policy"
macos   = "config/sandbox/quarantined-llm.macos.sb"
windows = "config/sandbox/quarantined-llm.windows.stub.policy"
```

At launch the launcher picks the entry for the host OS, confines the path to the
policy root (`resolve_policy_ref` — realpath-resolves and refuses any ref that
escapes the root, including `..` traversal and symlink-follow), and then:

- **Linux** → translates the policy into `bwrap` flags
  (`alfred.plugins.sandbox_policy.policy_to_bwrap_flags`) and `exec`s
  `bwrap <flags> -- <interpreter>`.
- **macOS** → refuses today (`macos_full_not_yet_shipped`); the `.sb` profile is
  ready for when `sandbox-exec -f` execution lands (#230).
- **Windows** → reads the stub; refuses in production
  (`windows_stub_in_production`), or in dev emits a
  `supervisor.plugin.sandbox_stub_used` audit row and runs unsandboxed.

## The Linux policy schema (bwrap)

The Linux policy is TOML validated by `alfred.plugins.sandbox_policy.SandboxPolicy`
(frozen, `extra="forbid"` — an unknown key is a load-time refusal):

| Field | Type | Meaning |
|---|---|---|
| `ro_binds` | `[[src, dst], …]` | Read-only bind mounts (interpreter + libs). |
| `rw_binds` | `[[src, dst], …]` | Writable bind mounts (avoid for the quarantined LLM). |
| `tmpfs` | `["/path", …]` | Ephemeral tmpfs scratch dirs, discarded on exit. |
| `dev` | bool (default `true`) | Synthesise a minimal `/dev` (no host device passthrough). Required for CPython startup. |
| `unshare` | subset of `pid uts cgroup ipc user net` | Linux namespaces to isolate. |
| `die_with_parent` | bool (default `true`) | Reap the sandbox subtree when the Supervisor exits. |
| `keep_fds` | `[int, …]` (must contain `3`) | Declares fd 3 (the provider-key channel) survives. Omitting `3` is refused (`kind_full_requires_keep_fd_3`). |

The shipped quarantined-LLM Linux policy binds only `/usr`, `/lib`, `/lib64`
read-only (the interpreter + its loader/libs), a tmpfs scratch dir, synthesises
`/dev`, unshares `pid/uts/cgroup/ipc`, dies with its parent, and keeps fd 3. It
binds **no** `/etc` and **no** `/bin` — so host secrets are unreadable and
`/bin/sh` / `/bin/*` are not exec targets. (Note: on x86-64 Debian `/lib64`
exists and holds `ld-linux-x86-64.so.2`; on arches without a top-level `/lib64`,
the `/usr` + `/lib` binds carry the loader via the usrmerge symlink — the
production target is x86-64 Debian Bookworm, the CI + container image arch.)

> **Known-permissive (tracked in #230): the broad `/usr` bind leaves
> `/usr/bin/*` exec-reachable.** Binding all of `/usr` read-only puts
> `/usr/bin/python`, `/usr/bin/curl`, `/usr/bin/sh`, etc. inside the sandbox's
> mount namespace, so a compromised quarantined process CAN exec an absolute
> `/usr/bin/...` path. The `/bin/sh` containment test passes only because `/bin`
> itself is not bound — `/usr/bin/sh` may still resolve. The PRIMARY exec
> containment is `--unshare-pid` + `--die-with-parent` + the empty writable
> surface (a child cannot escape the pid namespace or outlive the Supervisor),
> NOT the absence of exec targets. **#230 tightens the interpreter bind from the
> broad `/usr` down to the exact CPython prefix** so `/usr/bin/*` stops being
> exec-reachable. This is an accepted, documented limitation for the mid-flight
> slice state, not a silent gap.

Kernel enforcement of these bytes is proven by the merge-blocking integration
test `tests/integration/test_quarantined_llm_policy_kernel_enforced.py` and the
adversarial corpus `tests/adversarial/sandbox_escape/sbx-2026-003/004/006`.

## ⚠️ Known limitation — outbound egress is UNRESTRICTED (release-blocker #230)

The quarantined LLM makes its provider HTTPS call **itself** (it receives the
provider key over fd 3), so it needs outbound network. The current simple
`SandboxPolicy` schema **cannot** express "egress to the provider endpoint
only" — there is no `network.outbound_allowlist` field — so the Linux policy
deliberately does **not** `unshare net`. Consequently:

- Filesystem, process, and pid/uts/cgroup/ipc isolation **are** kernel-enforced.
- Outbound network egress is **NOT** restricted — a compromised quarantined
  process could open a connection to an arbitrary host.

This is an **accepted, documented gap** for the mid-flight slice state. Before
the quarantined LLM runs against real provider traffic, **issue #230 MUST land**
the provider-only egress allowlist (`network.outbound_allowlist` +
`--unshare-net` + a filtered forwarder / egress proxy). #230 is a release-blocker
for going live. The adversarial corpus records this honestly in
`tests/adversarial/sandbox_escape/sbx_2026_005_outbound_network_unrestricted.yaml`
(`out_of_scope: true`, rationale → #230).

## Also deferred to #230

- macOS `sandbox-exec` **execution** (the `.sb` profile ships now; the launcher
  does not yet invoke it).
- A real Windows containment primitive (AppContainer / Job Object).
- The richer policy schema (`BindSpec`, `network.outbound_allowlist`, sha256
  policy sidecars, the `SandboxPolicyLoader` + overlay-precedence resolver, and
  the `sandbox_policy_registry` table writes).

## Related

- Schema + translator: `src/alfred/plugins/sandbox_policy.py`
- Path confinement: `src/alfred/plugins/manifest_reader.py` (`resolve_policy_ref`)
- Launcher: `bin/alfred-plugin-launcher.sh`
- Audit rows: `supervisor.plugin.sandbox_refused` / `supervisor.plugin.sandbox_stub_used`
  (`src/alfred/audit/audit_row_schemas.py`)
- Adversarial corpus: `tests/adversarial/sandbox_escape/`
