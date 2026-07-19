# ADR-0037 — The production quarantine sandbox boundary (custom AppArmor + seccomp + PBS interpreter)

- **Status**: Proposed
- **Date**: 2026-06-19
- **Slice**: Slice-4 graduation hardening (PR-290a — bwrap userns containment fix)
- **Relates to**: issue [#290](https://github.com/alfred-os/AlfredOS/issues/290) ("the bwrap dual-LLM quarantine child cannot spawn in the production non-root container"), [ADR-0015](0015-slice4-containerised-quarantined-llm.md) (Slice-4 containerised quarantined-LLM subprocess), [ADR-0030](0030-first-party-kind-full-plugin-ships-in-wheel-under-bound-prefix.md) (first-party `kind=full` plugin ships in the wheel under a bound prefix; child execs a bound real interpreter)
- **Supersedes**: —

## Context

[ADR-0015](0015-slice4-containerised-quarantined-llm.md) specifies the
quarantined LLM (the only component that ever touches raw T3 content) runs as a
`bubblewrap`-sandboxed subprocess with `sandbox.kind="full"`. `bwrap` assembles
that sandbox by building an **unprivileged user namespace** (and mount / pid / uts
/ ipc / cgroup namespaces inside it).

When the real `kind=full` spawn was first driven end-to-end against the
PRODUCTION `alfred-core` posture — the non-root `alfred` user with only
`cap_add: [SETUID]`, NO `--privileged`, NO `CAP_SYS_ADMIN` — it failed:

```
bwrap: No permissions to create new namespace, likely because the kernel
       does not allow non-privileged user namespaces.
```

A posture matrix (the #288/G6-0b probe gauntlet, run with the host sysctl
`kernel.apparmor_restrict_unprivileged_userns` already relaxed to 0) showed
**every** container posture failed EXCEPT `SETUID + seccomp=unconfined +
apparmor=unconfined`. That isolates **two** independent container-level
confinement layers, both of which must be addressed:

1. **Docker's default seccomp profile** argument-masks `clone(...CLONE_NEWUSER...)`
   / `unshare(CLONE_NEWUSER)` to `EPERM` unless the caller holds `CAP_SYS_ADMIN`
   (moby/moby#42441). `seccomp=unconfined` alone was not sufficient — proving the
   second layer is also live.
2. **Docker's default AppArmor profile (`docker-default`)** independently
   restricts namespace creation; on Ubuntu 23.10+ / kernel-6.x hosts with
   `apparmor_restrict_unprivileged_userns=1` (the modern default) the kernel
   refuses unprivileged `unshare(CLONE_NEWUSER)` unless the calling process runs
   under an AppArmor profile carrying the `userns,` permission.

Two further, orthogonal #290 sub-causes blocked the spawn even once the
namespace built (both diagnosed during the same investigation):

3. The production `sys.executable` was a `uv`-venv **symlink** outside any
   bwrap-bound prefix → `bwrap: execvp <python>: No such file or directory`.
4. A stock python.org/slim CPython resolves `libpython3.14.so.1.0` via
   `/etc/ld.so.cache`, which the tight `kind=full` policy (binds `/usr` and
   `/lib` hard, plus `/lib64` softly — see the [ADR-0030](0030-first-party-kind-full-plugin-ships-in-wheel-under-bound-prefix.md)
   `ro_binds_try` amendment, #269) omits → the child died with
   `libpython3.14.so.1.0: cannot open shared object file` after the namespace was
   built.

   > **Still live, and worth knowing (#269).** This exact failure resurfaced while
   > diagnosing the arm64 spawn bug and was briefly mistaken for a *second* arm64
   > root cause. It is not: it is the expected consequence of using a **non-PBS**
   > interpreter (a Debian/`/usr/local` CPython that needs `/etc/ld.so.cache`,
   > which this policy deliberately omits). Under the bound python-build-standalone
   > interpreter this ADR mandates, it does not occur. **If you see it, you are
   > reproducing under an unsupported interpreter — fix the repro, not the sandbox.**

The quarantined LLM is the load-bearing T3 trust boundary (PRD DEC-007: the
dual-LLM split is non-negotiable). A `kind=full` child that cannot spawn at all
in the shipped image blocks the Slice-4 graduation criterion that the dual-LLM
boundary is proven against a real sandboxed child in the production posture.

The constraints on any fix are explicit: **NO** `--privileged`, **NO**
`CAP_SYS_ADMIN`, **NO** `seccomp=unconfined`, **NO** `apparmor=unconfined`, **NO**
host-wide `apparmor_restrict_unprivileged_userns=0` sysctl flip (which would lift
the restriction for every process on the host, not just our one container).

## Decision

The production quarantine sandbox boundary is the **least-privilege scalpel**, not
the sledgehammer. Four coordinated deliverables, all scoped to the one service
(`alfred-core`) that spawns the bwrap launcher:

1. **Custom AppArmor profile** (`docker/apparmor/alfred-bwrap`), applied via
   `security_opt: apparmor=alfred-bwrap`. It is `profile alfred-bwrap
   flags=(unconfined) { userns, }` — it REPLACES `docker-default` on the core to
   grant exactly the `userns,` permission the kernel requires.

   **AppArmor is NOT the load-bearing containment here.** `flags=(unconfined)`
   makes this profile a no-op AppArmor confinement; we accept that narrowly
   because (a) on current AppArmor a process can only be GRANTED userns by being
   under a profile that allows it, and a fully-enforcing profile that also
   allow-lists everything bwrap + CPython + the alfred runtime touch is large,
   brittle across glibc/base-image bumps, and needs continuous maintenance; and
   (b) the real, kernel-enforced isolation around the T3 child is the **bwrap
   policy itself** (`config/sandbox/quarantined-llm.linux.bwrap.policy`: no `/etc`
   bind, synthesised `/dev`, unshared pid/uts/cgroup/ipc, tmpfs-only writable
   surface, `--die-with-parent`) — the surface the adversarial sandbox-escape
   corpus asserts, unaffected by this AppArmor profile.

2. **Custom seccomp profile** (`docker/seccomp/alfred-bwrap.json`), applied via
   `security_opt: seccomp=docker/seccomp/alfred-bwrap.json`. It is Docker's
   default profile PLUS one unconditional `SCMP_ACT_ALLOW` for exactly the eight
   namespace syscalls bwrap needs (`clone`, `clone3`, `unshare`, `setns`,
   `mount`, `umount2`, `pivot_root`, `keyctl`). Every other docker-default deny is
   preserved verbatim — this is explicitly NOT `seccomp=unconfined`. The profile
   is a generated artifact: `scripts/gen_alfred_seccomp.py` builds it from the
   vendored moby v24.0.0 default, a `--check` drift guard + a unit test pin the
   committed bytes, and the mount-family syscalls are knowingly widened
   container-wide (acceptable: the child is the only userns user; bwrap policy is
   the containment).

3. **PBS non-editable interpreter as the production image model** (per
   [ADR-0030](0030-first-party-kind-full-plugin-ships-in-wheel-under-bound-prefix.md)).
   The `alfred-core` image's PRIMARY interpreter is a self-contained
   python-build-standalone 3.14 under `/opt/alfred-python` (RUNPATH-linked → needs
   no `ld.so.cache`) with `alfred` installed NON-editable INTO it. The launcher
   ro-binds that single prefix into the sandbox (the opt-in
   `ALFRED_SANDBOX_BIND_INTERP_PREFIX` flag), so the child resolves BOTH the
   interpreter AND `alfred.security.quarantine_child` from one bound,
   cache-independent prefix — closing sub-causes (3) and (4). This re-architects
   the shipped Dockerfile around the recipe ADR-0030 / #248 already prove in CI.
   It also adds the `jq` + PyYAML runtime dependencies the launcher and config
   loaders need, and costs roughly +110 MB of image size.

4. **Compose `security_opt`** carries (1) and (2) on `alfred-core` only, alongside
   the existing `cap_add: [SETUID]`. `alfred-discord` and `alfred-gateway` do NOT
   get them (they never spawn the launcher). The named AppArmor profile must be
   loaded into the host kernel first; `bin/alfred-setup.sh` does it idempotently
   (`apparmor_parser -r -W`), the README documents the manual `sudo
   apparmor_parser -r docker/apparmor/alfred-bwrap` for direct-compose operators,
   and the nightly e2e workflow loads it before `docker compose up`.

The whole boundary is proven end-to-end by `.github/workflows/bwrap-userns-validation.yml`:
it forces the host sysctl RESTRICTIVE (=1), loads the custom AppArmor profile,
builds the real image, and runs the spawn probe as non-root `alfred` under the
custom profiles — asserting `QUARANTINE_SPAWN_PROBE_RESULT=OK` — with a CONTROL
arm (no custom profiles, same restrictive host) that must REFUSE for the userns
reason, so the profile (not a lax host) is provably what does the work.

## Consequences

### Positive

- The dual-LLM `kind=full` quarantine child spawns in the real shipped image
  under the production non-root + `SETUID` posture, on a userns-restricted host,
  with NO `--privileged` / `CAP_SYS_ADMIN` / `*=unconfined` / host-sysctl flip.
  Slice-4 graduation's "dual-LLM boundary proven against a real sandboxed child"
  criterion is met against the actual deployment posture, not a lax stand-in.
- Confinement stays least-privilege: seccomp keeps every docker-default deny
  except the minimal namespace delta; the bwrap policy (the load-bearing
  containment) is untouched; the broad grants the matrix showed also worked
  (`seccomp=unconfined`, `apparmor=unconfined`, `SYS_ADMIN`) are all rejected.
- The boundary is regression-guarded: a CI gate proves the spawn (with a
  non-vacuous control arm), a seccomp drift unit test + `--check` mode pin the
  generated profile, and negative compose invariants forbid `privileged: true`
  and any `*=unconfined` on the core.

### Negative / trade-offs

- The AppArmor profile is `flags=(unconfined)` — it drops docker-default's
  path-based AppArmor confinement on the core. This is the deliberate trade
  documented above: AppArmor is not the load-bearing layer for the child, and a
  fully-enforcing custom profile is deferred as future hardening (tracked as a
  #290 follow-up; it needs the in-image interpreter layout pinned first, which (3)
  now provides).
- The mount-family namespace syscalls (`mount`/`umount2`/`pivot_root`/`setns`)
  are allowed CONTAINER-WIDE, not just for the child PID — seccomp filters are
  per-process and applied at container create, with no per-PID scoping.
  Acceptable: the bwrap quarantine child is the only userns user in `alfred-core`.
- The PBS interpreter adds ~110 MB to the image and a vendored/pinned PBS patch
  version that a maintainer must bump deliberately.
- Operators on userns-restricted AppArmor hosts have a new one-time host step
  (load the profile). Mitigated by `bin/alfred-setup.sh` doing it automatically +
  the README note + the nightly-workflow load.
- The seccomp `security_opt` path is CWD-relative to the compose invocation, so
  `docker compose` must run from the repo root (documented in compose + README).

## Alternatives considered

- **`seccomp=unconfined` + `apparmor=unconfined` (the matrix's only OK posture).**
  Rejected: it disables BOTH syscall and path-based confinement on the most
  adversary-adjacent service. The custom profiles achieve the same spawn with a
  minimal, reviewable delta over docker-default.
- **`--privileged` / `cap_add: SYS_ADMIN`.** Rejected: grants the core far more
  than the userns exemption the spawn needs; explicitly forbidden by the task and
  the matrix showed `SYS_ADMIN` alone did not even fix it.
- **Host-wide `apparmor_restrict_unprivileged_userns=0` sysctl.** Rejected: it
  lifts the userns restriction for EVERY process on the host, not just our
  container, and is orthogonal anyway (it was already 0 in the matrix and the
  spawn still failed on the seccomp + AppArmor layers).
- **Binding the repo root (`/repo`) into the sandbox** to reach the child code /
  interpreter. Rejected in ADR-0030: it would bind `.env` / `.git` / operator
  secrets into the most adversary-facing surface in the system — a security
  regression. The wheel-co-located child + bound PBS prefix reach the same goal
  with no host-filesystem exposure.

## References

- PRD §7.1 (Security & Prompt-Injection Defense), DEC-007 (the dual-LLM split is
  non-negotiable).
- [ADR-0015](0015-slice4-containerised-quarantined-llm.md) — Slice-4
  containerised quarantined-LLM subprocess (the bwrap `kind=full` commitment this
  ADR makes deployable in production).
- [ADR-0030](0030-first-party-kind-full-plugin-ships-in-wheel-under-bound-prefix.md)
  — wheel-co-located child code + bound real interpreter (sub-causes 3 + 4).
- `docs/subsystems/quarantine.md` — the dual-LLM subsystem deep-doc.
- `.github/workflows/bwrap-userns-validation.yml` — the decisive end-to-end gate.

## Amendment (2026-07-13, #428) — policy bind sources are governed by a closed allowlist

`SandboxPolicy` now refuses an over-broad bind **source** at parse time
(`reason="bind_source_too_broad"`), adding a structural invariant to the sandbox
boundary this ADR governs:

- A source canonicalising to `/` is refused in **every** bind field, including the
  soft `ro_binds_try`.
- A source under a root-resolving pseudo-filesystem (`/proc`, `/sys`) is refused in
  every field.
- A single-component top-level root not in the allowlist `{/usr, /lib}` is refused
  in every field, including `ro_binds_try` — checked against the CANONICAL source
  there, and exempting a genuine arch-variable root (e.g. `/lib64`), which the soft
  field legitimately carries.
- **Precedence in a HARD field:** a source that traverses an arch-variable
  directory (e.g. `/lib64/..`) is caught EARLIER, by
  `_refuse_hard_bind_of_arch_variable_path` (`reason="arch_variable_path_hard_bound"`),
  because that validator runs first. `bind_source_too_broad` is the reason seen in
  the soft field, and for non-arch-variable hard-field traversals (e.g. `/usr/..`).

**sec-001 (2026-07-13):** the soft-field check above closes a traversal bypass —
`ro_binds_try=[("/lib64/../etc", "/etc")]` was ACCEPTED (binding host `/etc` into
the sandbox) because the pre-fix soft check applied only tiers 1+2 to the RAW
source, and `/lib64/../etc` canonicalises past those two tiers while its
arch-variable match (`/lib64`, matched on the raw walk before the `..` backs out)
let it slip past `_restrict_soft_binds` too. The fix applies the full three-tier
rule to the CANONICAL source and checks arch-variance on that SAME canonical
form: `/lib64/../etc` canonicalises to `/etc` (over-broad, not arch-variable) and
is refused, while `/lib64` canonicalises to itself (arch-variable) and stays
allowed.

This is a lexical floor, not a filesystem oracle: it cannot see that a depth-2 path
is still broad, and an on-disk symlink to `/` defeats it (the module never touches
the filesystem). The `/usr` residual it permits — `/usr/bin/*` stays exec-reachable
— is tracked in #430, the live successor to the closed #230. The same change routes
the launcher's interpreter-prefix bind through the identical predicate
(`is_over_broad_bind_source`) and corrects a pre-existing audit-reason
misattribution: the five schema refusals that predate this PR
(`kind_full_requires_keep_fd_3`, `policy_path_not_absolute`,
`arch_variable_path_hard_bound`, `mount_shadows_earlier_mount`,
`soft_bind_forbidden_path`) were all logged as `policy_ref_unreadable`; the launcher
now stamps each with its own reason, and the new `bind_source_too_broad` is
attributed correctly from the start.

## Amendment (2026-07-19, #340 golive) — the "no `/etc` bind" property carves out `/etc/ssl/certs`

Decision 1 above lists "no `/etc` bind" among the load-bearing bwrap-policy
properties (alongside synthesised `/dev`, unshared namespaces, tmpfs-only writable
surface, `--die-with-parent`). The #340 quarantine-child go-live
([ADR-0052](0052-real-quarantine-child-golive.md)) makes that property **imprecise**:
the real-LLM child now terminates TLS in-child against its brokered gateway socket
(HARD #5) and therefore needs the public-CA trust store to verify the provider
certificate. The shipped Linux policy gains **exactly one** `/etc` bind —
`["/etc/ssl/certs", "/etc/ssl/certs"]`, HARD, read-only — and **nothing else** under
`/etc`.

The property is restated precisely: **no *broad* `/etc` bind; the sole `/etc` subpath
bound anywhere in the policy is `/etc/ssl/certs`.** This carries no host secret — it is
the same public root-CA bundle every TLS client on the host reads. `/etc/passwd`,
`/etc/shadow`, `resolv.conf`, and ssh configs stay **invisible**: an adversary owning
the T3 response still cannot read host usernames, credentials, or the DNS posture. The
carve-out is bound at the exact subpath (never a bare `/etc`), the same #428
over-broad-bind class this ADR's own amendment above fixed; a bare `/etc` bind would
additionally expose passwd/shadow/resolv.conf and is refused.

The containment the adversarial sandbox-escape corpus asserts is **unchanged** in
substance: `sbx-2026-003` (`open('/etc/passwd').read()` → refused) and `sbx-2026-013`
(the real-spawn escape probe reading `/etc/passwd`) still pass identically, because
`/etc/passwd` is not bound — only `/etc/ssl/certs` is. Their `references` prose strings
(which read "(no `/etc` bind)" / "(no `/etc`, no `/bin` bind; `--unshare-pid`)") are
reconciled to name the CA-store carve-out so the corpus metadata does not read as an
absolute "no `/etc` at all"; the executable `probe` and `expected_outcome` are
untouched. See the golive-updated policy comments in
`config/sandbox/quarantined-llm.linux.bwrap.policy` and the CA carve-out record in
[ADR-0052](0052-real-quarantine-child-golive.md).
