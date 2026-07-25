# #469 First-Run — Path to Green (sequenced roadmap)

- **Epic:** [#469](https://github.com/alfred-os/AlfredOS/issues/469) — first-run experience: a documented quickstart that actually boots
- **Related:** [#494](https://github.com/alfred-os/AlfredOS/issues/494) (the e2e lane = Step 1)
- **Status:** roadmap — pending approval. Each step below becomes its own spec → plan → PR.

## Goal

The documented quickstart boots to a fully healthy stack, and a nightly e2e lane
proves it and reds on any regression:

```sh
git clone … && cd AlfredOS
cp .env.example .env       # + a provider key
bin/alfred-setup.sh
docker compose up -d
# => all 6 services (postgres, redis, prometheus, grafana, gateway, core) healthy
```

## Current reality — why it's red

Established by a two-round `/review-plan` fleet (10 specialist passes) + direct
code-trace against `main` (`eaec26a1`). The first-run is broken in a **masked
chain** — each failure hides the next:

1. **`bin/alfred-setup.sh` cannot complete.** At `:341` it runs `docker compose
   run --rm alfred-core migrate` with no `--no-deps`, which pulls core's
   `depends_on: alfred-gateway: service_healthy` (compose:95–101). The gateway is
   never healthy (blocker A), so **setup.sh hangs at migrate**. Even past that, its
   `alfred user list/add` calls (`:494–535`) construct `Settings()`, which hits the
   eager `comms_enabled_adapters` manifest validator (`settings.py:449`) — blocker B.
2. **Blocker A — gateway can't construct `Settings()`.** `_resolve_hosted_adapter_ids()`
   (`cli/gateway/_commands.py:157`) builds a full `Settings()` needing a provider
   key the gateway is denied (ADR-0036). Gateway never healthy → also the cause of
   setup.sh's hang.
3. **Blocker B — core can't boot in the shipped image.** `alfred-core.Dockerfile`
   omits `plugins/`; `Settings._REPO_ROOT` resolves to the install prefix. The eager
   validator (`settings.py:449/485`) then fails for **every** `Settings()`
   construction in the built image — core service, `migrate`, and `user add` alike.
4. **Residual documented-flow blockers** (smaller, some masked): the README/DeepSeek
   key mismatch, `audit.hash_pepper` path, `policies.yaml` provisioning — confirmed
   or dismissed by the harness's first real run.

## Strategy — instrument first, then ratchet

Build the **measuring instrument** (the e2e harness) before fixing anything. It
establishes a green baseline on the parts that already work and a strict
expected-failure (`xfail(strict=True)`) on each blocker. Then every fix flips
exactly one xfail from red to green — visible, one at a time. Two payoffs:

- **The harness's first run is the authoritative diagnosis** — it confirms the exact
  failure point of each blocker and reveals any further masked ones, de-risking
  every later step.
- **The path is adaptive.** The masking chain means a fix can uncover the next
  blocker; the harness names it the moment it surfaces. The step list below is the
  known path; the harness keeps it honest.

## The steps (tackle 1-by-1)

Each step is independently shippable, owns its own spec → plan → review → PR, and
flips a named part of the lane from red/xfail to green.

### Step 1 — Instrument: the e2e boot harness  ·  #494  ·  [test-engineer]

Build `tests/e2e/conftest.py` + per-service boot tests and wire the dormant
`nightly.yml` `e2e` job.

> **Shipped in PR #502 — the code is authoritative.** The bullets below are the design-time
> record; the implementation refined them (see the design doc's *Shipped implementation
> refinements* section): the tally reads pytest stats as **JSON** (not junit); **8** testcases
> (5 passed / 3 xfailed); the service set is **fail-closed** (a new service reds the
> classification test, not auto-asserted healthy); a **per-run-unique** `COMPOSE_PROJECT_NAME`;
> the setup.sh check runs in an **isolated git worktree** (operator `.env` never touched);
> images build once in the fixture; the GF password is env-file-owned; `e2e-stack.log` is
> secret-scrubbed.

- **Green today:** postgres, redis, prometheus, grafana brought up via `docker
  compose up -d --no-deps <those>` (pulled images, no build, no core dep) and
  asserted healthy — the regression-catching baseline.
- **`xfail(strict)` today:** (a) `bin/alfred-setup.sh` completes exit 0 (run under a
  timeout so blocker A's hang is a *bounded* fail); (b) gateway healthy; (c) core
  healthy — each tagged with its blocker issue.
- **Non-vacuity hardened** (from the review): parse junit per-`<testcase>` by `type`
  (xfail shows as `skipped` in junit); an independent literal service-count floor
  (not self-derived from `docker compose config`); compose-derived assert set;
  `cwd=<repo root>` pin (CWD-relative seccomp path); a fixed `COMPOSE_PROJECT_NAME` +
  isolated `--env-file` so a local run never clobbers an operator's `.env`/volumes.
- **Also delivers the diagnosis:** first real run confirms/files each downstream
  blocker (A, B, README/key, hash_pepper, policies.yaml).
- **Ships GREEN.** Design: the #494 spec, revised to v3 (this split posture).
- **Depends on:** nothing.

### Step 2 — Fix blocker A: gateway `Settings()` decoupling  ·  [gateway/devops]

Decouple `_resolve_hosted_adapter_ids()` from a full `Settings()` so the gateway
resolves its adapter list without a provider key (ADR-0036-compliant — **not** by
giving the gateway the key). Consider making setup.sh's `docker compose run
alfred-core migrate` use `--no-deps` so migrate never waits on the gateway.

- **Flips green:** the gateway xfail. Also removes the setup.sh migrate-hang.
- **Depends on:** Step 1 (so the flip is visible + verified).

### Step 3 — Fix blocker B: core boots in the shipped image  ·  [core/devops]

`alfred-core.Dockerfile` COPYs `plugins/`; fix `_REPO_ROOT` resolution so the eager
comms-manifest validator passes in the built image.

- **Flips green (with Step 2 done):** BOTH `core healthy` AND `setup.sh completes` —
  the corner-turn, since setup.sh's `migrate`/`user add` core-runs then succeed.
- **Security (hard requirement, sec-002):** the core-un-xfail change MUST replace the
  bare `xfail → assert healthy` with **posture assertions** — sandbox active,
  capability gate seeded, egress chokepoint enforced — carried in this issue's
  acceptance criteria, not left as prose. Boot-to-`healthy` alone is not a security
  oracle.
- **Depends on:** Step 2 (core `depends_on` gateway healthy; setup.sh's core-runs
  need the gateway un-hung).

### Step 4 — Close residual documented-flow blockers  ·  [devops/docs]

Whatever Step 1's diagnosis + Step 3's completion confirm are real:

- **README/DeepSeek key mismatch** — filed as **#501**. `README:33` tells operators to set
  only the quarantine key, but setup.sh's gate also rejects the `sk-...` DeepSeek placeholder →
  a literal README-follow fails. Fix the README or relax setup.sh (the epic owner's call).
  **This is a hard prerequisite for the #494 `test_setup_sh_completes` xfail to flip green**, not
  merely parallel to Steps 2–3: setup.sh exits at this credential gate *before* it can reach
  blocker #499's migrate hang.
- **`audit.hash_pepper`** — reconciled into **#500**'s acceptance criteria (setup.sh provisions
  it; not a separate blocker). **`policies.yaml` provisioning — STILL OPEN**: the Step-1 diagnosis
  run never reached that code path (setup.sh exits at the credential gate first), so whether it is
  a real gap is unconfirmed; confirm-by-run once #501/#500 lift, and file if real.
- Any further blocker the harness surfaces once A/B lift.
- **Flips green:** any remaining setup.sh/core sub-failures. The README fix is
  independent and may land in parallel with Steps 2–3.

### Step 5 — Promote to release-blocking  ·  [test-engineer/devops]

With every xfail green, drop them, assert the full documented flow boots healthy,
promote the nightly `e2e` job to a required/release-blocking gate, and record it in
`docs/ci/required-checks.md`.

- **The capstone:** from here, any regression that breaks the documented first-run
  reds the gate. #494 and #469 close.
- **Depends on:** all prior steps green.

## Dependency graph

```
Step 1 (harness, green baseline + xfails)
   └─> Step 2 (blocker A: gateway)  ─┐
          └─> Step 3 (blocker B: core) ─┴─> Step 4 (residuals) ─> Step 5 (promote)
   Step 4's README fix is independent and may parallelize with Steps 2–3.
```

Steps 2 → 3 are strictly ordered (A before B: core depends on gateway health, and
setup.sh's core-runs hang on the gateway until A lands).

## Ownership & scope

Step 1 is in-domain test-engineer work and proceeds now. Steps 2–4 cross into
gateway/core/devops domains — each gets its own brainstorm → spec → plan → PR.
Step 5 is test-engineer/devops. Nothing here is a mega-PR; the harness makes the
whole path measurable and each fix small and verifiable.
