# #494 — First-run e2e boot harness (self-ratcheting green baseline)

- **Issue:** [#494](https://github.com/alfred-os/AlfredOS/issues/494) — activate the dormant e2e first-run boot lane (clone → `up -d` → healthy)
- **Epic:** [#469](https://github.com/alfred-os/AlfredOS/issues/469) — first-run experience: a documented quickstart that actually boots
- **Domain:** test-engineer (integration/e2e layer, CI non-vacuity)
- **Status:** design **v2** — 5-lane `/review-plan` fleet findings folded (see *Review findings folded* at the end). Pending spec re-review.

## Problem

Nothing in CI drives the documented quickstart end to end. The README's first
run (README:30–37) is:

```sh
cp .env.example .env       # then set ALFRED_QUARANTINE_PROVIDER_API_KEY
bin/alfred-setup.sh        # macOS/Linux; on Windows, run inside WSL
docker compose up -d
```

Every individual piece is unit-tested; the *composed* path a new operator walks
— including `bin/alfred-setup.sh`, the artifact that #491/#495 actually fixed —
is never exercised. This is the systemic gap behind the whole #469 epic.

`nightly.yml` already contains an `e2e` job that does `docker compose up -d
--wait` then `pytest tests/e2e` — but it is gated on `tests/e2e/conftest.py`,
which does not exist, so the job **skip-greens**. It is a paper-gate: a lane that
reports green while gating nothing (the #245 anti-pattern this repo has fought
repeatedly).

### Why a naive smoke test can't just be added (diagnosis, corrected)

The stack does not boot from a *hand-provisioned* subset, but the true blocker
set is **narrower than a first pass suggests** — because much of what looks like a
blocker is actually provisioned by `bin/alfred-setup.sh`, which the lane must run.
Verified against `main` (HEAD `eaec26a1`):

- **Real blocker A — gateway can't construct `Settings()`.**
  `_resolve_hosted_adapter_ids()` (`src/alfred/cli/gateway/_commands.py:157`)
  builds a full `Settings()` that requires a provider key. The gateway service is
  never given `ALFRED_DEEPSEEK_API_KEY` (ADR-0036 — no secret on the gateway), so
  `Settings()` raises and the gateway never becomes healthy. **The fix is to
  decouple adapter-list resolution from full `Settings()` — NOT to give the
  gateway the key (that would violate ADR-0036).**
- **Real blocker B — core can't boot in the shipped image.**
  `docker/alfred-core.Dockerfile` copies `src`, `config`, `bin`, `locale` — **but
  never `plugins/`** — and `Settings._REPO_ROOT` resolves to the Python install
  prefix in the built image, so `Settings()` fails with "no manifest for comms
  adapter id 'alfred_tui'".
- **NOT a blocker of the documented flow (corrected):** `state.git` seeding and
  `audit.hash_pepper` bootstrap are performed by `bin/alfred-setup.sh` (`:349`
  seeds `state.git` via `alfred-state-git-seed.sh`; `:397` bootstraps
  `audit.hash_pepper`; `:142` does `cp .env.example .env`). An earlier draft
  listed these as blockers — that was an artifact of *not* running setup.sh. The
  harness must run the real flow, and the diagnosis must be re-derived from that
  run, not asserted up front.
- **Confirm-by-run:** `policies.yaml` provisioning (setup.sh only *comments* about
  it at `:375` — "shipped by downstream PR-S4-7 as default policies"), and the
  exact **quarantine-key boot semantics** below.

**The credential gate — both keys are prerequisites for the flow to run at all
(new — surfaced during review verification).** `bin/alfred-setup.sh` has a single
credential-validation gate (`:201–273`) that accumulates problems and **`exit 1`s
at `:271`** when either `ALFRED_DEEPSEEK_API_KEY` is empty/still the `sk-...`
placeholder *or* `ALFRED_QUARANTINE_PROVIDER_API_KEY` is unset. Critically, this
gate runs **before** all the real provisioning — the AppArmor load (`:275`),
`docker compose build` (`:317`), postgres start + `alfred migrate` (`:319–341`),
`state.git` seed (`:349`), and `audit.hash_pepper` bootstrap (`:397`) all come
*after* it. Stock `.env.example` ships the `sk-...` DeepSeek placeholder **and** an
empty quarantine key, so `cp .env.example .env && bin/alfred-setup.sh` on stock
values **exits 1 having provisioned nothing**. Therefore the harness must inject
**both** non-placeholder keys before running setup.sh, or setup.sh never reaches
the provisioning and the "real documented flow" degrades to the same
hand-provisioned subset this design exists to avoid. Boot-to-`healthy` makes no
real provider call at boot, so syntactically-valid non-placeholder dummy values
are *expected* to suffice; the first diagnosis run confirms presence-only vs.
live-provider validation, with a real throwaway low-balance key (repo secret, as
`real-llm-smoke` already does) as the fallback. Note: even with a DeepSeek key in
`.env`, the gateway service is denied it (ADR-0036 forwards no provider secret to
the gateway), so **blocker A holds regardless** — it is a code-coupling defect, not
a provisioning gap.

### Dependency masking

`alfred-core` `depends_on` postgres + redis + **gateway**, all `condition:
service_healthy` (compose:97–101). With the gateway broken, a plain `docker
compose up -d --wait` waits forever on the gateway and never creates core —
masking blocker B behind blocker A. The harness therefore owns lifecycle and
starts core with its *real* deps sequenced but the gateway dependency bypassed
(see Architecture), so blocker B is directly observable.

## Scope (approved)

Deliver the **harness + diagnosis**, not the blocker fixes:

- Build `tests/e2e/conftest.py` + a per-service boot smoke test that drives the
  **real documented flow** (`cp .env.example .env` → inject both non-placeholder
  keys → `bin/alfred-setup.sh` → `docker compose up -d`).
- Run it to reproduce and precisely itemize every boot blocker **from that run**.
- File each confirmed blocker as a root-caused issue, cross-linked from the harness.
- Land the lane in the self-ratcheting posture below.

The blocker **fixes** (gateway `Settings()` decoupling, core Dockerfile,
`policies.yaml` provisioning if confirmed) are follow-on work for the
devops/core/gateway domains.

## Approach: self-ratcheting green baseline

The harness owns the compose lifecycle and polls per-service health. Each known
blocker is encoded as a **strict** expected-failure. The consequence:

```
TODAY:          gateway=xfail(#gw)  core=xfail(#core)  every other service asserted healthy  -> GREEN
NEW REGRESSION: a baseline service unexpectedly unhealthy  OR a new compose service unobserved -> RED
BLOCKER FIXED:  that service now healthy but still xfail -> strict XPASS  -> RED
                (forces: drop the xfail, assert healthy)                  -> GREEN
ALL FIXED:      every service asserted healthy, zero xfails               -> GREEN gate
```

Non-vacuous by construction: green today (known blockers expected), red on any
*new* boot regression, and red the instant a known blocker is fixed. Chosen over
an *honest-red nightly* (persistent red trains reviewers to ignore it and masks
new regressions) and *runnable-now/gate-later* (no continuous signal).

## Architecture

### `tests/e2e/conftest.py` — drives the real documented flow

A **session-scoped fixture** re-enacts the README quickstart as an operator would,
then tears down:

1. **Fail loud if Docker is unavailable** — probe via the existing
   `tests/_docker_probe.py` (`docker_available()`); if absent, **raise** (never
   skip). The e2e tests use a dedicated `e2e` marker, **not** `@pytest.mark.docker`
   — the root `tests/conftest.py:50–82` auto-*skips* `docker`-marked items on a
   daemon-less/win32 host, which would re-introduce the exact skip-green paper-gate
   this effort exists to kill.
2. `cp .env.example .env` (idempotent) and inject **both** non-placeholder keys
   (`ALFRED_DEEPSEEK_API_KEY` and `ALFRED_QUARANTINE_PROVIDER_API_KEY`) — from CI
   secrets, or dummy non-placeholder values locally — so setup.sh clears its
   credential gate (`:271`) and reaches the provisioning steps.
3. Run `bin/alfred-setup.sh` — the real, verified provisioning: Grafana admin
   password (`:181`), AppArmor profile load (`:291`), `docker compose build`
   (`:317`), postgres start + `alfred migrate` (`:319–341`), `state.git` seed
   (`:349`), `audit.hash_pepper` bootstrap (`:397`). The harness runs setup.sh as
   the operator does; it hand-rolls none of this.
4. `docker compose up -d` the remaining services (setup.sh brings up only postgres,
   for migrations) **without blocking on the unsatisfiable gateway health gate**:
   sequence the real leaf deps first (`up -d --wait alfred-postgres alfred-redis
   alfred-prometheus`), then the rest, using `--no-deps` for `alfred-core` so it is
   gated on its *own* blocker rather than the never-healthy gateway. Reuse the
   proven `_compose()` wrapper + `compose_project`/`compose_stack` lifecycle
   fixtures already in `tests/smoke/test_gateway_core_link_smoke.py` and
   `tests/smoke/test_slice4_graduation.py` rather than re-implementing them (DRY).
5. **Every compose subprocess pins `cwd=<repo root>`** — the `seccomp=docker/
   seccomp/alfred-bwrap.json` path in compose is resolved by the Docker CLI
   relative to CWD (compose:131–134); a subprocess launched from elsewhere fails to
   *create* gateway/core, and that failure would otherwise hide under their xfail.
6. **Poll Docker's own health** per service (`docker inspect --format
   '{{.State.Health.Status}}'`) with a bounded, per-service **timeout budget**
   (documented per service; generous enough that a slow-but-healthy baseline does
   not false-red). The oracle is Docker's health status — independent of the app's
   own notion of health.
7. On teardown, `docker compose down -v` and capture `docker compose logs` for the
   diagnosis / CI artifact.

### State classifier

The classifier distinguishes `healthy` / `unhealthy` / `starting` / `not-created`.
Under `restart: unless-stopped`, a service whose process exits on a boot refusal
**crash-loops and presents as perpetual `starting`, not `unhealthy`** — so
"reaches `healthy` within its timeout budget, else fail" is the assertion, and the
xfail reason wording says "does not reach healthy (crash-loops as `starting`)",
not "unhealthy". The classifier ships with a **self-test** (feeding it synthetic
`docker inspect` payloads for each terminal state) — the WSL-leg CRLF-self-test
discipline: prove the detector works before trusting it.

### The asserted service set is derived, not hardcoded

The set of services to assert is derived at runtime from `docker compose config
--services`, partitioned into `{known-blocked → xfail}` (an explicit, small,
issue-tagged deny-list) and `{everything else → assert healthy}`. A **new** compose
service (e.g. Qdrant, per PRD §5/§8) therefore lands in the assert-healthy set
automatically and is observed on its first nightly — closing the "new service
boots unobserved while the lane stays green" hole. The known-blocked deny-list is
the only hardcoded part, and it shrinks to empty as blockers are fixed.

### The xfail table (re-derived from the real flow)

| Service | Expected today (real flow, key provisioned) | Disposition |
|---|---|---|
| alfred-postgres | healthy | assert healthy (baseline) |
| alfred-redis | healthy | assert healthy (baseline) |
| alfred-prometheus | healthy | assert healthy (baseline) |
| alfred-grafana | healthy (GF admin pw seeded by setup.sh) | assert healthy (baseline) |
| alfred-gateway | not healthy — `Settings()` needs a provider key it is denied (ADR-0036; `_commands.py:157`) | `xfail(strict)` → **blocker A** issue |
| alfred-core | not healthy — Dockerfile omits `plugins/`, `_REPO_ROOT` wrong (`--no-deps` unmasks it from the gateway) | `xfail(strict)` → **blocker B** issue |

The exact today-state and the residual blockers are **confirmed by the first
diagnosis run** before issues are filed and before the xfail reason strings are
finalized — the table is the expected shape, the run is the source of truth.

### Non-vacuity floor (#245 discipline)

- **No skip-green:** conftest raises on missing Docker; the `e2e` marker avoids the
  root-conftest auto-skip; the job's `has_e2e` gate is permanently true once
  `conftest.py` exists.
- **Exact assert-RAN tally.** The CI step parses `--junitxml` (not the `-q` text
  summary) and asserts the *exact* tally: `collected == N` (where `N =` the
  compose-derived service count), `passed == N − |deny-list|`, `xfailed ==
  |deny-list|`, `failed == 0`, `errors == 0`, `xpassed == 0`, `skipped == 0`.
  This is load-bearing: pytest bins fixture/setup exceptions as `errors` (not
  `failures`) and absorbs setup-phase exceptions on `xfail(strict)` tests as plain
  XFAIL, so a loose "0 failed / 0 xpassed" check would pass a run where the stack
  never came up. The exact tally closes that.
- **Host-prep is baseline-covered.** Because the lane runs the *real*
  `bin/alfred-setup.sh` (rather than hand-rolled host-prep steps that gate only the
  xfail'd services), a broken AppArmor load / provisioning step fails the setup step
  itself or a baseline-service health assertion — it can no longer stay green under
  the xfails. Any host-prep that genuinely gates only the xfail'd services (and is
  thus invisible to the baseline today) is explicitly noted in the diagnosis as a
  gap that closes when core un-xfails.
- **Strict xfail** turns a silently-fixed blocker red.

### CI wiring — restructure the existing `nightly.yml` `e2e` job

- **Remove** the `Boot stack` (`docker compose up -d --wait`) step — conftest owns
  lifecycle (and `--wait` is incompatible with observing partial boot).
- **Run the real flow:** the job (or conftest) runs `bin/alfred-setup.sh`. The
  hand-rolled `Load the bwrap userns AppArmor profile` and `Seed Grafana admin
  password` steps are **dropped** — setup.sh owns both (`:291` and `:181`,
  verified). This both de-duplicates and raises fidelity: the lane now exercises the
  operator's real host-prep instead of a CI-only reimplementation of it.
- **Inject both keys unconditionally so the lane always runs (never skips).** The
  harness writes dummy non-placeholder `ALFRED_DEEPSEEK_API_KEY` and
  `ALFRED_QUARANTINE_PROVIDER_API_KEY` values into `.env` (built at runtime, not
  committed — no push-protection trip) so setup.sh clears its credential gate every
  time. This is deliberately *not* a secret-or-skip pattern: skip-green is the
  anti-pattern this effort kills. A real throwaway low-balance quarantine key as a
  repo secret (scoped via `env:`, never interpolated into `run:` — workflow-injection
  guard, as `real-llm-smoke` does) is the **fallback**, needed only if the diagnosis
  run shows core validates the key against the live provider at boot — which matters
  only once core un-xfails.
- **Remove** the now-unused `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` env from the Run
  step — boot-to-healthy needs no provider key beyond the quarantine one.
- **Keep** the on-failure `docker compose logs` capture + artifact upload, with the
  standing constraint that the harness adds **no secret-echoing diagnostic** and the
  Grafana password stays per-run random.
- Stays on the 06:00 UTC cron + `workflow_dispatch`. No required-status-check
  promotion — nightly, not per-PR; the release-blocking promotion is deferred to
  when the lane is fully green (this is not just a choice but structurally
  consistent with `docs/ci/required-checks.md:69`, which already excludes
  `End-to-end` from required checks).

## Diagnosis deliverable

The first harness run produces the first reproducible, itemized boot-blocker report
**derived from the documented flow**. Each *confirmed* blocker is filed as a
root-caused issue and cross-linked from the xfail reason and #469/#494:

- **Blocker A** — gateway `_resolve_hosted_adapter_ids()` couples adapter-list
  resolution to a full `Settings()` needing a provider key the gateway is denied;
  decouple (must not violate ADR-0036).
- **Blocker B** — `alfred-core.Dockerfile` omits `plugins/`; `_REPO_ROOT` resolves
  to the install prefix in the built image.
- **`policies.yaml` provisioning** — filed only if the run confirms it is a real
  gap (setup.sh may or may not provision it).

`state.git` seeding and `audit.hash_pepper` bootstrap are **explicitly not filed** —
the documented flow provisions them.

## Security posture (not a security oracle)

Boot-to-`healthy` is **not** a security oracle: `alfred daemon healthcheck` →
`/metrics` responding proves nothing about the bwrap sandbox being active, the
capability gate being seeded, or the egress chokepoint being enforced. The harness
weakens no security default (it keeps the real AppArmor/seccomp profiles, runs
unprivileged, does not stub the capability gate — the gate seeds from real
`state.git`). The design records a **hard requirement on the future core-un-xfail
PR**: when blocker B is fixed and core's `xfail` is dropped, the replacement
assertion MUST include security-posture checks (sandbox active, gate seeded, egress
chokepoint on) — a bare `xfail → assert healthy` swap would bless a core with its
trust boundary silently off. No `src/alfred/security/` code changes here, so the
100%-coverage rule is N/A.

## Validation before merge

- **Local** `docker compose` run on Docker Desktop: validates the green baseline
  (postgres/redis/prometheus/grafana healthy) + the gateway `xfail` + the exact
  tally. Core stays blocker-B-red either way; the macOS/AppArmor divergence (the
  bwrap profile is not loaded on Docker Desktop) only matters once blocker B is
  fixed and core starts, so it does not affect v1.
- **`workflow_dispatch`** run of `nightly.yml` on the branch: the authoritative
  parity check on the real ubuntu runner (runs setup.sh's AppArmor load + GF-password
  seed, injects both keys, exercises the optional real quarantine-key secret path).

## Convention recording

- Record the deferred-promotion + self-ratcheting-baseline convention as a row/note
  in `docs/ci/required-checks.md` (no ADR required — the restructure touches no PRD
  §5 invariant; a lightweight ADR is optional, not mandatory).
- Note boot-only as the v1 of PRD §8's conversation-e2e: the shared conftest
  lifecycle seam is designed so a later conversation-e2e reuses it.

## Out of scope

- The blocker **fixes** (devops/core/gateway).
- Any functional / LLM message round-trip or keyed assertion beyond the dummy keys
  needed to clear setup.sh's credential gate — boot-to-healthy only, per #494.
- Qdrant — not in the default `docker-compose.yaml` yet (but the compose-derived
  service set means it is observed automatically when it lands).
- Release-blocking promotion of the lane — deferred until it is fully green.

## Risks

- **`up -d` hanging on a `service_healthy` dependency.** Mitigated by sequencing the
  real leaf deps `--wait` and using `--no-deps` for core, so no compose command
  blocks on the never-healthy gateway.
- **Dummy keys insufficient for boot** (if core validates a key against the live
  provider rather than presence). Surfaced and resolved by the first diagnosis run;
  fallback is a real throwaway low-balance quarantine key as a repo secret (as
  `real-llm-smoke` already does for its provider key).
- **A baseline service flakier than assumed.** Mitigated by generous per-service
  timeout budgets and by validating the baseline is genuinely green on the runner
  before merge.
- **macOS local run diverging from the runner.** Accepted: the `workflow_dispatch`
  runner run is authoritative; local is a fast first pass.

## Review findings folded (traceability)

5-lane `/review-plan` fleet (architect, reviewer, test-engineer, security-engineer,
devops) + direct code-verification of load-bearing findings. 0 Critical. Folded:
run the real `setup.sh` flow (test-001/ops-001); corrected diagnosis — state.git/
hash_pepper are provisioned, not blockers (ops-007); quarantine-key requirement
(verification); non-`docker` marker to avoid the root-conftest auto-skip (rev-001);
exact `--junitxml` tally (test-002); compose-derived service set (arch-001);
`cwd=repo-root` pin for the CWD-relative seccomp path (ops-002); reuse existing
compose machinery (rev-002/003); rewrite the "masked" prose — `--no-deps` unmasks
core (rev-004/test-003/4/arch-002); `starting`-not-`unhealthy` classifier (ops-004);
remove unused provider-key env (sec-001); future-core-un-xfail security-posture
assertions (sec-002); per-service timeout budgets (test-006); classifier self-test
(test-005); log-artifact hygiene (sec-003); required-checks.md convention +
PRD §8 forward-compat note (arch-003/004).
