# PR-290a — bwrap userns containment fix (AppArmor + seccomp + PBS interpreter) for the dual-LLM child (#290)

> Status: DONE. Shipped on branch `fix-290-bwrap-userns-apparmor`; recorded in
> [ADR-0037](../../adr/0037-production-quarantine-sandbox-boundary.md).
>
> **What actually shipped vs this plan's original framing.** The plan below was
> drafted as an AppArmor + seccomp container-boundary fix with the interpreter
> bake-in "deferred to a separate follow-up" (see the original "Note on the
> interpreter" section). The PR instead shipped **Option B as a core deliverable
> of this same PR**: the production `alfred-core` image's PRIMARY interpreter is a
> self-contained python-build-standalone (PBS) 3.14 under `/opt/alfred-python`
> with `alfred` installed NON-editable into it (per
> [ADR-0030](../../adr/0030-first-party-kind-full-plugin-ships-in-wheel-under-bound-prefix.md)),
> plus the `jq` and PyYAML runtime dependencies the launcher and config loaders
> need. So all four orthogonal #290 sub-causes — seccomp namespace block,
> AppArmor userns block, ld.so-cache interpreter, and editable/unreachable child
> code — are fixed in THIS PR, not split across follow-ups. The deferred item is
> now only the *fully-enforcing* (non-`unconfined`) AppArmor profile.

## Problem (conclusive, from the #288/G6-0b gauntlet)

The real bwrap dual-LLM quarantine child **fails to spawn** in the production
`alfred-core` posture (non-root `alfred` user + `cap_add: [SETUID]`, NO
`--privileged`). Symptom:

```
bwrap: No permissions to create new namespace, likely because the kernel
       does not allow non-privileged user namespaces.
QUARANTINE_SPAWN_PROBE_RESULT=FAILED:round_trip_refused
```

## Root cause — TWO container-level confinement layers block userns

The throwaway probe (`experiment/g6-0b-spawn-probe`, run 27814087073) ran a
posture matrix **with the host sysctl `apparmor_restrict_unprivileged_userns`
already relaxed to 0**. Even so, every container posture failed EXCEPT one:

| Posture (host sysctl already = 0)              | Result |
| ---------------------------------------------- | ------ |
| `--cap-drop ALL --cap-add SETUID` (tight prod) | FAILED |
| `--cap-add SETUID` (compose default caps)      | FAILED |
| `SETUID + SYS_ADMIN`                            | FAILED |
| `SETUID + seccomp=unconfined`                  | FAILED |
| `SETUID + SYS_ADMIN + seccomp=unconfined`      | FAILED |
| `default caps + seccomp=unconfined`            | FAILED |
| `SETUID + seccomp=unconfined + apparmor=unconfined` | **OK** |

Decisive reading:

1. **Docker's default seccomp profile** blocks `unshare(CLONE_NEWUSER)` /
   `clone(...CLONE_NEWUSER...)` when `CAP_SYS_ADMIN` is absent — argument-masked
   block (moby/moby#42441). `seccomp=unconfined` alone was **not enough**, which
   means the second layer is also live:
2. **Docker's default AppArmor profile (`docker-default`)** independently
   restricts namespace creation; only relaxing it (`apparmor=unconfined`)
   in addition to seccomp produced OK.

So the production fix must address **both** layers at the container boundary —
NOT just AppArmor. The host sysctl is orthogonal (it was already 0 in the
matrix and still didn't help).

## Least-privilege fix (the scalpel, not the sledgehammer)

The task forbids the blunt `seccomp=unconfined` / `apparmor=unconfined` /
`--privileged` / `SYS_ADMIN` / host-sysctl-flip. The principled equivalent:

- **Custom AppArmor profile** `docker/apparmor/alfred-bwrap`: replaces
  `docker-default` for the core, carries `userns,` so the AppArmor
  userns-restriction (Ubuntu 24.04+) does not block, while keeping
  `flags=(unconfined)` documented as the trade-off (it replaces docker-default
  confinement to gain userns; the kernel-enforced bwrap policy is the real
  containment around the child).
- **Custom seccomp profile** `docker/seccomp/alfred-bwrap.json`: Docker's
  default profile semantics with `clone`, `clone3`, `unshare` ALLOWed for the
  namespace flags WITHOUT requiring CAP_SYS_ADMIN. This is explicitly NOT
  `seccomp=unconfined` — every other default deny stays. It is the minimal
  syscall delta that lets bwrap build its user namespace.

Both are applied per-container via `security_opt` on `alfred-core` (and any
other service that spawns the bwrap launcher). `cap_add: [SETUID]` stays. NO
`--privileged`, NO `SYS_ADMIN`, NO `seccomp=unconfined`, NO `apparmor=unconfined`,
NO host-sysctl flip.

## Note on the interpreter (orthogonal #290 sub-cause) — SHIPPED, not deferred

Issue #290 also notes the production `sys.executable` is a uv-venv symlink
outside any bwrap-bound prefix, and that a stock python.org/slim CPython resolves
`libpython` via `/etc/ld.so.cache` (which the tight `kind=full` policy omits).

**This PR fixed both in the image itself** rather than deferring: the shipped
`alfred-core` interpreter is now a self-contained PBS 3.14 under
`/opt/alfred-python` (RUNPATH-linked → no `ld.so.cache`) with `alfred` installed
NON-editable into it. The launcher ro-binds that one prefix into the sandbox via
`ALFRED_SANDBOX_BIND_INTERP_PREFIX`, so the child resolves both the interpreter
and `alfred.security.quarantine_child` from a single bound, cache-independent
prefix. The CI gate therefore validates the REAL shipped image+interpreter (no
`/opt` proto stand-in). The remaining follow-up is only the fully-enforcing
(non-`unconfined`) AppArmor profile.

## Deliverables (as shipped)

1. `docker/apparmor/alfred-bwrap` — the profile (`flags=(unconfined) { userns, }`).
2. `docker/seccomp/alfred-bwrap.json` — the custom seccomp profile, GENERATED by
   `scripts/gen_alfred_seccomp.py` from a vendored moby v24.0.0 default
   (offline-deterministic; `--check` drift guard +
   `tests/unit/test_seccomp_profile_drift.py`).
3. `docker-compose.yaml` — `security_opt` on `alfred-core` only (discord/gateway
   never spawn the launcher).
4. `docker/alfred-core.Dockerfile` — **Option B (core deliverable):** PBS 3.14
   primary interpreter under `/opt/alfred-python`, `alfred` non-editable into it,
   `jq` + PyYAML + `bubblewrap` runtime deps.
5. `bin/alfred-setup.sh` — idempotent host `apparmor_parser -r -W` load step;
   FATAL if the profile file is missing on an AppArmor host (build-integrity),
   graceful skip on genuinely non-AppArmor hosts.
6. `.github/workflows/bwrap-userns-validation.yml` — the decisive gate: loads the
   profile, forces the host sysctl **1** (restrictive), builds the image, runs
   the real spawn probe as **non-root alfred** under the custom apparmor + seccomp
   opts; asserts `QUARANTINE_SPAWN_PROBE_RESULT=OK` with a non-vacuous control arm.
7. `.github/workflows/nightly.yml` — loads the AppArmor profile before
   `docker compose up`.
8. `tests/unit/test_compose_invariants.py` — assert the `security_opt` entries +
   negative guards (no `privileged`, no `*=unconfined` on the core).
9. `scripts/quarantine_spawn_probe.py` — committed copy of the probe.
10. [ADR-0037](../../adr/0037-production-quarantine-sandbox-boundary.md) — records
    the production sandbox-boundary decision.
