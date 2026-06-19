# PR-290a — bwrap userns containment fix (AppArmor + seccomp) for the dual-LLM child (#290)

> Status: in-progress. Draft + validate via CI (maintainer-authorized).
> Branch: `fix-290-bwrap-userns-apparmor`.

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

## Note on the interpreter (orthogonal #290 sub-cause)

Issue #290 also notes the production `sys.executable` is a uv-venv symlink
outside any bwrap-bound prefix. The CI validation isolates the userns/AppArmor variable by
pointing `ALFRED_QUARANTINE_CHILD_PYTHON` at the image's real
`/usr/local/bin/python3.14` (a binary under the policy's `/usr` ro-bind), so the
probe's only remaining variable is the userns layer this PR fixes. The
interpreter-bake-in is a separate follow-up.

## Deliverables

1. `docker/apparmor/alfred-bwrap` — the profile.
2. `docker/seccomp/alfred-bwrap.json` — the custom seccomp profile.
3. `docker-compose.yaml` — `security_opt` on `alfred-core` (+ discord/gateway as
   they spawn the launcher).
4. `bin/alfred-setup.sh` — idempotent host `apparmor_parser -r -W` load step,
   guarded on `command -v apparmor_parser`, skips gracefully on non-AppArmor hosts.
5. `.github/workflows/ci.yml` — a validation job that loads the profile, sets the
   host sysctl back to **1** (restrictive) to prove the profile does the work,
   builds the image, and runs the real spawn probe as **non-root alfred** with
   the custom apparmor + seccomp opts; asserts `QUARANTINE_SPAWN_PROBE_RESULT=OK`.
6. `tests/unit/test_compose_invariants.py` — assert the `security_opt` entries.
7. `scripts/quarantine_spawn_probe.py` — committed copy of the probe.
