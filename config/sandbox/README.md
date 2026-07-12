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

Two `kind = "full"` plugins ship today. The **quarantined LLM** — the single
component that handles raw T3 (untrusted) content — and the **Discord adapter**
— a comms relay that ingests adversary-controlled bytes from arbitrary Discord
users (PR #205 round-2 sec-1 dropped the first-party-relay `kind:none`
carve-out). Their policy files:

| File | OS | Status |
| --- | --- | --- |
| `quarantined-llm.linux.bwrap.policy` | Linux | **Kernel-enforced** via bwrap |
| `quarantined-llm.macos.sb` | macOS | File only — `sandbox-exec` execution deferred (#230); launcher refuses `kind:full` on macOS today |
| `quarantined-llm.windows.stub.policy` | Windows | Documented stub — production refuses, dev emits `supervisor.plugin.sandbox_stub_used` |
| `discord-adapter.linux.bwrap.policy` | Linux | **Kernel-enforced** via bwrap; mirrors the quarantined-LLM fs/namespace containment + ro-binds `/etc/ssl/certs` for the Discord TLS chain; now `--unshare-net` (G7-4) — egress via the gateway AF_UNIX bridge |
| `discord-adapter.macos.sb` | macOS | File only — execution deferred (#230) |
| `discord-adapter.windows.stub.policy` | Windows | Documented stub — production refuses, dev emits `supervisor.plugin.sandbox_stub_used` |

The **quarantined-LLM** policy `unshare net`s (Spec C G7-1, #333): the shipped
deterministic-echo child needs no egress, so it runs in an empty network
namespace — egress is kernel-closed for it. The **Discord adapter** policy now
also `unshare net`s (Spec C G7-4, #333, ADR-0043): the Discord child runs in an
empty network namespace and reaches the gateway L7 CONNECT proxy via a bind-mounted
AF_UNIX socket on the gateway-only `alfred_discord_egress` volume — this closes
the **Discord half** of `#230`. The **2c real-LLM quarantined child** (#230/#340)
is NOT closed here: when that child lands, it likewise reaches its provider only
through the gateway proxy, never by re-opening the child's network namespace.

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
| --- | --- | --- |
| `ro_binds` | `[[src, dst], …]` | Read-only bind mounts (interpreter + libs). A missing source is a **loud launch failure** — use this for paths that must always exist. |
| `ro_binds_try` | `[[src, dst], …]` | Read-only bind mounts applied **only when the source exists** (`--ro-bind-try`); a missing source is skipped, not a launch failure. Reserve for genuinely **arch-variable** paths — today just `/lib64` (see the arch note below). |
| `rw_binds` | `[[src, dst], …]` | Writable bind mounts (avoid for the quarantined LLM). |
| `tmpfs` | `["/path", …]` | Ephemeral tmpfs scratch dirs, discarded on exit. |
| `dev` | bool (default `true`) | Synthesise a minimal `/dev` (no host device passthrough). Required for CPython startup. |
| `unshare` | subset of `pid uts cgroup ipc user net` | Linux namespaces to isolate. |
| `die_with_parent` | bool (default `true`) | Reap the sandbox subtree when the Supervisor exits. |
| `keep_fds` | `[int, …]` (must contain `3`) | Declares fd 3 (the provider-key channel) survives. Omitting `3` is refused (`kind_full_requires_keep_fd_3`). |

The shipped quarantined-LLM Linux policy binds only `/usr` and `/lib` read-only
(hard) plus `/lib64` **softly** (the interpreter + its loader/libs), a tmpfs
scratch dir, synthesises `/dev`, unshares `pid/uts/cgroup/ipc/net` (Spec C G7-1 —
the echo child runs in an empty network namespace), dies with its parent, and
keeps fd 3. It binds **no** `/etc` and **no** `/bin` — so host secrets are
unreadable and `/bin/sh` / `/bin/*` are not exec targets.

### Why `/lib64` is a soft bind (arch portability — [#269](https://github.com/alfred-os/AlfredOS/issues/269))

`/lib64` is the one **arch-variable** path in the shipped policies:

- On **x86-64** Debian it exists and holds the dynamic linker `ld-linux-x86-64.so.2`, so it is bound (read-only) exactly as before.
- On **arm64** it does **not exist** — the aarch64 loader is `/lib/ld-linux-aarch64.so.1`, already covered by the `/lib` bind.

A hard `--ro-bind /lib64` therefore killed the sandbox launch on aarch64 with
`bwrap: Can't find source path /lib64` — the quarantined child never started,
never emitted a frame, and the host surfaced it as a truncated
`read_frame_failed`. Binding it via `ro_binds_try` (`--ro-bind-try`: bind iff
present, else skip) makes the **same policy bytes** portable across both arches,
which is what unblocks arm64 self-hosting and the `Integration (privileged
Linux, real spawn) (arm64)` CI leg.

This does **not** weaken containment: the mount stays read-only where it exists,
and a path that does not exist was never reachable from inside the sandbox. Keep
non-arch-variable trees (`/usr`, `/lib`, `/etc/ssl/certs`) in `ro_binds` so a
missing one fails **loud** at launch rather than silently degrading the sandbox.

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

## Outbound egress — CLOSED for the echo child (G7-1) and the Discord adapter (G7-4); 2c real-LLM egress is #230

The shipped quarantined-LLM child runs a **deterministic echo loop** with no
provider client and no socket of its own, so it needs **zero** outbound network.
Spec C G7-1 (#333) therefore makes the Linux policy `unshare net`, putting the
child in an **empty network namespace**. Spec C G7-4 (#333, ADR-0043) applies the
same to the **Discord adapter**: its policy now `--unshare-net`s the child; egress
routes through the gateway's L7 CONNECT proxy via a bind-mounted AF_UNIX socket on
the gateway-only `alfred_discord_egress` volume. Consequently:

- Filesystem, process, and pid/uts/cgroup/ipc isolation **are** kernel-enforced
  for both children.
- Outbound network egress is now **kernel-closed** for the echo child and the
  Discord adapter — even a compromised child has no network namespace to connect
  from; the sole hole is the sanctioned AF_UNIX socket to the gateway proxy.

The adversarial corpus records the echo-child egress as an **enforced-containment**
vector in `tests/adversarial/sandbox_escape/sbx_2026_005_outbound_network_unrestricted.yaml`
(`out_of_scope: false`; the executable corpus asserts the shipped policy unshares
`net`). A new Discord-specific corpus entry records the Discord adapter's enforced
containment.

**Still tracked by #230 — the 2c real-LLM child.** The real-LLM quarantined child
(a separate follow-on) DOES make a provider call. It will **not** re-open this
namespace: the core is connectivity-free and the gateway is the sole external I/O
plane (Spec C), so the 2c child reaches its provider **provider-only** through the
gateway L7 CONNECT proxy. The provider-only egress path + the unset-provider-key
boot guard land with 2c, behind release-blocker **#230**.

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
