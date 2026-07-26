# ADR-0056 — e2e boot-posture assertion contract

- **Status**: Accepted
- **Date**: 2026-07-26
- **Slice**: #469 Step 3 / #500 (alfred-core boots in the shipped image)
  (`docs/superpowers/specs/2026-07-25-500-core-boots-shipped-image-design.md`,
  Part E)
- **Relates to**: issue [#494](https://github.com/alfred-os/AlfredOS/issues/494)
  (the e2e boot lane whose strict-`xfail` this ADR's oracle set flips green),
  issue [#500](https://github.com/alfred-os/AlfredOS/issues/500) sec-002/sec-003
  (the review findings this ADR resolves — a bare `assert healthy` is not a
  security oracle; `ALFRED_ENVIRONMENT=production` must be explicit in the
  e2e env-file for the sandbox axis to be live), [ADR-0040](0040-connectivity-free-core-mandatory-egress-chokepoint.md)
  (connectivity-free core — the egress-chokepoint oracle below is a live
  runtime check of that ADR's invariant, not a restatement of it), and
  [ADR-0055](0055-repo-root-resolution.md) (sibling — the repo-root
  unification that makes `alfred-core` bootable in the shipped image at all;
  this ADR governs what the e2e lane asserts once it does)
- **Supersedes**: the `xfail` + bare `assert healthy` pattern previously
  covering `test_core_is_healthy` (no ADR recorded that pattern; it is
  retired here, not formally deprecated from a prior number)

## Context

Step 1 (#494) made `alfred-core`'s e2e boot a strict `xfail`. Step 3 (#500)
makes `alfred-core` fully bootable in the shipped image, so the natural next
move is to flip that `xfail` to a passing assertion. The naive version of
that flip — `assert boot_stack.health("alfred-core") is HEALTHY` and nothing
else — is not a security oracle (sec-002): Docker's `healthy` verdict proves
only that the container's healthcheck script exited `0`, which is a
necessary but not sufficient signal. It entails nothing about whether the
core actually joined only the internal network, whether the capability gate
was actually seeded, or whether the sandbox the quarantine child depends on
can actually build a namespace on the host running the container.

The `/review-plan` security and test lanes considered the obvious next
candidate for a sandbox oracle — shelling out to `bin/alfred-plugin-launcher.sh
--self-test` and asserting its `policy-resolving` answer — and found it
tautological (sec-001/test-002). The `--self-test` case arm
(`bin/alfred-plugin-launcher.sh:46-51`) runs before any argument parsing and
before any sandbox-building code path:

```sh
case "${1:-}" in
    --self-test)
        printf 'policy-resolving\n'
        exit 0
        ;;
esac
```

It is an unconditional `printf` + `exit 0` — it proves the script was
`COPY`ed into the image, nothing more, and would print the identical answer
on a host where `bwrap` itself cannot build a user namespace. It is also
redundant with the daemon's own boot probe (a) at
`cli/daemon/_daemon_probes.py`, which already gates production boot on this
same tautological answer — asserting it a second time from the e2e lane
would add no information the daemon's own `healthy` verdict didn't already
carry.

## Decision

`test_core_is_healthy` (`tests/e2e/test_first_run_boot.py`) asserts Docker
`healthy` first (necessary, not sufficient), then calls
`_posture.assert_core_boot_posture(boot_stack)`
(`tests/e2e/_posture.py`), which composes three runtime posture oracles.
Each has its own concrete observable on the **booted** container — none is
inferred from `healthy`, and none is the `--self-test` tautology:

1. **Egress chokepoint** — `assert_egress_chokepoint` runs `docker inspect`
   on the running `alfred-core` container and passes its
   `NetworkSettings.Networks` key set to the pure predicate
   `_is_egress_chokepoint_ok`, which requires an `…alfred_internal` name
   present and an `…alfred_external` name absent. This is a live runtime
   check of the [ADR-0040](0040-connectivity-free-core-mandatory-egress-chokepoint.md)
   connectivity-free-core invariant — proof the container actually joined
   only the internal network, not a restatement of the static compose
   config.
2. **Capability gate seeded** — `assert_capability_gate_seeded` runs
   `select count(*) from plugin_grants` against `alfred-postgres` via
   `docker compose exec` and passes the captured stdout to the pure
   predicate `_is_gate_seeded`, which requires the stripped stdout to parse
   as a positive integer (a non-digit reply — e.g. a psql error — and a
   zero count both read as "not seeded"). Proves the daemon's boot-time
   `build_boot_real_gate` actually seeded the first-party grants into
   Postgres before reporting healthy, not merely that the process is
   running.
3. **Sandbox machinery live** — `assert_sandbox_machinery_live` runs
   `bwrap --ro-bind / / --unshare-user --uid 0 true` inside the running
   `alfred-core` container via `docker compose exec` and asserts exit `0`.
   This exercises the exact unprivileged-userns permission the
   `alfred-bwrap` apparmor/seccomp profile must grant and the quarantine
   child depends on (core-002: the tui-default comms graph that
   `daemon start` builds constructs a real `Orchestrator`, which spawns the
   bwrap-sandboxed quarantine child to reach healthy) — independently of
   the daemon's own internal bookkeeping, and explicitly **not** the
   `--self-test` tautology described in Context.

`_is_egress_chokepoint_ok` and `_is_gate_seeded` are pure functions over
already-parsed input (a network-name iterable; a captured stdout string) —
no I/O — so they are unit-tested in isolation in `tests/unit/e2e/test_posture.py`
without a running container, giving this contract a fast local regression
signal even on hosts (macOS, CI unit lanes) that cannot run the full e2e
lane. The I/O-performing wrapper functions (`assert_egress_chokepoint`,
`assert_capability_gate_seeded`, `assert_sandbox_machinery_live`) stay thin
shells around each predicate.

`ALFRED_ENVIRONMENT=production` is set explicitly in the e2e env-file
(`tests/e2e/_env.py::write_e2e_env_file`, sec-003) rather than relied on as
compose's implicit default. This makes the launcher's production sandbox
refusal machinery — the same machinery oracle 3 exercises — provably live
under the exact environment value the assertion claims to be testing,
instead of an unstated default that could silently drift.

This oracle set is deliberately not closed at merge time. The sign-off
block at the foot of `tests/e2e/_posture.py` invites the security engineer
to extend it — in particular with a negative production-refusal probe
(assert an unsandboxed or policy-less plugin spawn is *denied* inside the
running production container, which would make
`ALFRED_ENVIRONMENT=production` load-bearing for the sandbox axis in a
second, complementary direction) and/or a boot-audit assertion that the
quarantine child specifically spawned sandboxed. The invariant this ADR
commits to is narrower and non-negotiable: no property is asserted by
`healthy` alone, and the `--self-test` tautology is never used as the
sandbox oracle.

## Consequences

### Positive

- **Each sec-002 property has a concrete, independent runtime observable.**
  A regression in egress isolation, gate seeding, or sandbox liveness fails
  the e2e lane with a specific, attributable assertion message instead of
  silently passing behind a green `healthy`.
- **The pure predicates are unit-testable without a container.** Contributors
  on any host — including macOS, where the full e2e lane cannot run at all —
  get a fast, deterministic signal on the decision logic itself.
- **Complements, does not duplicate, the static compose-config pins.**
  `tests/unit/test_compose_invariants.py` already pins that the compose YAML
  *declares* apparmor/seccomp, non-privileged, internal-network membership,
  and SETUID. This ADR's oracles prove the *running* container actually
  achieved that posture — a declared-but-unloaded apparmor profile or a
  broken `bwrap` build on the host both pass the static check while this
  ADR's oracle 3 would catch them.

### Negative

- **macOS Docker Desktop cannot load the `alfred-bwrap` apparmor profile.**
  Oracle 3 — and the boot-time live `bwrap` quarantine-child spawn it
  mirrors — cannot be exercised there via the intended mechanism. The Linux
  nightly End-to-end lane is the sole authoritative signal for this ADR's
  contract; local verification substitutes the established
  Linux/arm64-privileged docker repro with the profile loaded.
- **The oracle set was not closed at PR time.** sec-001 sign-off on whether
  to add the negative production-refusal probe and/or the quarantine-spawn
  boot-audit assertion was still open as of this ADR's Accepted date — this
  ADR records the contract's floor, not its final shape.
- **Three additional subprocess round-trips per test run.** `docker
  inspect`, a `psql` exec, and a `bwrap` exec each add real wall-clock cost
  to `test_core_is_healthy` on top of the existing `up` + health-poll
  budget.

### Neutral

- The provisioning steps this assertion depends on — `migrate` and `user
  add` seeding an e2e operator before `up -d` — are Part D of the design
  spec, not this ADR's decision; this ADR governs only what is asserted
  once the container is healthy, not how it gets there.

## Alternatives considered

### Option A — bare `assert healthy`

The status quo the `xfail` would have flipped to without this design.
Rejected: `healthy` proves only that the Docker healthcheck script exited
`0`. None of the three sec-002 properties — egress isolation, gate seeding,
sandbox liveness — are logically entailed by that exit code, so a
regression in any one of them could ship with the e2e lane fully green.

### Option B — compose-config-only pins

Rely solely on the existing static assertions in
`tests/unit/test_compose_invariants.py`. Rejected as a replacement (kept as
a complementary, sibling layer): those pins assert what the compose YAML
*declares*, not what the running container *achieved*. A typo'd Dockerfile
build stage, an apparmor profile that fails to load on the host, or a
`bwrap` binary that cannot actually build a user namespace all pass the
static check while failing the runtime reality this ADR's oracles are
built to catch.

### Option C — launcher `--self-test` as the sandbox oracle

Shell out to `bin/alfred-plugin-launcher.sh --self-test` from the e2e lane
and assert its `policy-resolving` output. Rejected: as detailed in Context,
the `--self-test` handler is an unconditional `printf 'policy-resolving\n';
exit 0` before any sandbox-building code path runs. It would print the
identical answer on a host where the sandbox is fully broken, and it
duplicates a check the daemon's own boot probe (a) already performs —
asserting it again from the e2e lane adds no new information.

## References

- Design spec Part E:
  `docs/superpowers/specs/2026-07-25-500-core-boots-shipped-image-design.md`
  — the runtime-posture-assertion design this ADR records; Part G names
  this ADR and [ADR-0055](0055-repo-root-resolution.md).
- `tests/e2e/_posture.py` — `assert_core_boot_posture`,
  `assert_egress_chokepoint`, `assert_capability_gate_seeded`,
  `assert_sandbox_machinery_live`, and the pure predicates
  `_is_egress_chokepoint_ok` / `_is_gate_seeded`; the
  SECURITY-ENGINEER SIGN-OFF block recording the still-open sec-001
  extension decision.
- `tests/unit/e2e/test_posture.py` — the predicate unit tests (network
  membership combinations; empty/whitespace/zero/non-digit/positive psql
  stdout).
- `tests/e2e/test_first_run_boot.py::test_core_is_healthy` — the assertion
  site; calls `assert_core_boot_posture` after the Docker-`healthy` check,
  never in place of it.
- `bin/alfred-plugin-launcher.sh:46-51` — the `--self-test` case arm whose
  unconditional `printf`/`exit 0` makes it tautological as a sandbox oracle.
- `tests/unit/test_compose_invariants.py` — the sibling static compose-config
  pins this ADR's runtime oracles complement.
- [ADR-0040](0040-connectivity-free-core-mandatory-egress-chokepoint.md) —
  the connectivity-free-core invariant oracle 1 checks live at runtime.
- [ADR-0055](0055-repo-root-resolution.md) — the repo-root unification that
  makes `alfred-core` bootable in the shipped image in the first place.
- Issue [#494](https://github.com/alfred-os/AlfredOS/issues/494) — the e2e
  boot lane whose `xfail` this ADR's oracle set flips green.
- Issue [#500](https://github.com/alfred-os/AlfredOS/issues/500) — sec-002
  (no bare `healthy`), sec-003 (explicit `ALFRED_ENVIRONMENT=production` in
  the e2e env-file).
