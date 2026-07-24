# #494 — First-run e2e boot harness (self-ratcheting green baseline)

- **Issue:** [#494](https://github.com/alfred-os/AlfredOS/issues/494) — activate the dormant e2e first-run boot lane (clone → `up -d` → healthy)
- **Epic:** [#469](https://github.com/alfred-os/AlfredOS/issues/469) — first-run experience: a documented quickstart that actually boots
- **Domain:** test-engineer (integration/e2e layer, CI non-vacuity)
- **Status:** design — approved shape, pending spec review

## Problem

Nothing in CI drives the documented quickstart end to end. The README's first
run is `git clone … && cp .env.example .env && bin/alfred-setup.sh && docker
compose up -d`. Every individual piece is unit-tested; the *composed* path a new
operator walks is never exercised. This is the systemic gap behind the whole
#469 epic — each first-run blocker (env resolution #491, the gateway crash-loop
Blocker 2 #495, the four UAT blockers) was caught by hand, not by a lane.

`nightly.yml` already contains an `e2e` job that does `docker compose up -d
--wait` then `pytest tests/e2e` — but it is gated on `tests/e2e/conftest.py`,
which does not exist, so the job **skip-greens**. It is a paper-gate: a lane that
reports green while gating nothing (the #245 anti-pattern this repo has fought
repeatedly).

### Why a naive smoke test can't just be added

The stack **genuinely does not boot** today. The blockers are sequentially
masked (confirmed by code-trace against `main` and the Blocker 2 UAT):

1. **Gateway can't construct `Settings()`.** `_resolve_hosted_adapter_ids()`
   (`src/alfred/cli/gateway/_commands.py:157`) builds a full `Settings()` that
   requires a provider key. The gateway service is never given
   `ALFRED_DEEPSEEK_API_KEY` (ADR-0036 — no secret on the gateway), so `Settings()`
   raises and the gateway never becomes healthy.
2. **Core can't boot in the shipped image.** `docker/alfred-core.Dockerfile`
   copies `src`, `config`, `bin`, `locale` — **but never `plugins/`** — and
   `Settings._REPO_ROOT` resolves to the Python install prefix in the built image,
   so `Settings()` fails with "no manifest for comms adapter id 'alfred_tui'".
   *Masked:* `alfred-core` `depends_on` the gateway with `condition:
   service_healthy` (compose:97–101), so with the gateway broken **core never even
   starts** — its own blocker is unobservable via stock compose until the gateway
   is fixed.
3. **`/etc/alfred/policies.yaml` not provisioned** by the documented flow.
4. **`/var/lib/alfred/state.git` not seeded** → capability gate starts unseeded.
   (3) and (4) are runtime-state blockers inside core, doubly masked behind (1)+(2).

A real smoke test therefore goes red on day one. That is not a reason to avoid it
— a lane that fails on genuine bugs is the opposite of vacuous — but it makes the
CI **posture** a real design decision.

## Scope (approved)

This effort delivers the **harness + diagnosis**, not the blocker fixes:

- Build `tests/e2e/conftest.py` + a per-service boot smoke test now.
- Run it to reproduce and precisely itemize every boot blocker.
- File each blocker as a root-caused issue, cross-linked from the harness.
- Land the lane in the self-ratcheting posture below.

The blocker **fixes** (gateway `Settings()` decoupling, core Dockerfile,
provisioning) are explicitly follow-on work for the devops/core/gateway domains.

## Approach: self-ratcheting green baseline

The harness owns the compose lifecycle and polls per-service health. Each known
blocker is encoded as a **strict** expected-failure. The consequence:

```
TODAY:          gateway=xfail(#gw)  core=xfail(#core)  others asserted healthy  -> GREEN
NEW REGRESSION: a baseline service unexpectedly unhealthy                       -> RED
BLOCKER FIXED:  that service now healthy but still xfail -> strict XPASS         -> RED
                (forces: drop the xfail, assert healthy)                        -> GREEN
ALL FIXED:      every service asserted healthy, zero xfails                     -> GREEN gate
```

Non-vacuous by construction: it is green today (known blockers expected), red on
any *new* boot regression, and red the instant a known blocker is fixed. The gate
cannot silently drift behind reality.

### Why not the alternatives

- **Honest red nightly** (assert full boot now, red until every blocker lands):
  simplest and maximally honest, but a persistently-red nightly trains reviewers
  to ignore it and can mask a *new* regression behind the known reds.
- **Runnable-now / gate-later** (workflow_dispatch only until green): no red
  noise, but no continuous signal — the invisibility partly persists.

The self-ratcheting posture is the only one that is both continuously
signal-bearing *and* free of persistent-red noise.

## Architecture

### `tests/e2e/conftest.py` — single lifecycle owner

- A **session-scoped fixture** stands the full stack up and tears it down.
- Brings services up **without blocking on unmet health conditions**:
  `docker compose up -d --no-deps <svc> …` rather than `up -d --wait`, so a broken
  dependency (gateway) cannot hang the run waiting on a `service_healthy` gate
  that will never be satisfied. The harness — not compose — owns the wait.
- **Polls Docker health** per service (`docker inspect --format
  '{{.State.Health.Status}}'` / `docker compose ps`) with a bounded per-service
  timeout, returning the observed terminal state (`healthy` / `unhealthy` /
  `starting`-timeout / `not-started`).
- **Fails loud** (never skips) if `docker` or `docker compose` is unavailable —
  the harness's job is to drive the real stack; an absent Docker is an
  infrastructure failure, not a reason to green.
- Captures `docker compose logs` on teardown for the diagnosis and for CI
  artifact upload.

### `tests/e2e/test_first_run_boot.py` — per-service assertions

One test per service asserting it reaches `healthy` within timeout. The four
baseline services (`alfred-postgres`, `alfred-redis`, `alfred-prometheus`,
`alfred-grafana`) assert healthy with no xfail — this is what catches new
regressions. The two broken services carry `@pytest.mark.xfail(reason=…,
strict=True)`:

| Service | Expected today | Disposition |
|---|---|---|
| alfred-postgres | healthy | assert healthy |
| alfred-redis | healthy | assert healthy |
| alfred-prometheus | healthy | assert healthy |
| alfred-grafana | healthy (GF admin pw seeded) | assert healthy |
| alfred-gateway | unhealthy — `Settings()` needs a provider key it isn't given (`_commands.py:157`) | `xfail(strict)` → new gateway issue |
| alfred-core | never starts (masked behind gateway) + own Dockerfile/`_REPO_ROOT` blocker | `xfail(strict)` → new core issue |

The `xfail` reason strings name the filed issue and, for core, state explicitly
that it is masked behind the gateway blocker (so the strict-xpass will only flip
once core is *fully* bootable, not merely once the gateway is fixed).

### Non-vacuity floor

- **No skip-green:** conftest raises on missing Docker; the job's `has_e2e` gate
  is permanently true once `conftest.py` exists.
- **Assert-RAN floor:** the CI step asserts pytest collected & ran the expected
  number of service tests (≥6) and that the xfail/xpass tallies are sane — so "0
  collected" or an all-skipped run cannot false-green. Same discipline as the WSL
  leg (#496).
- **Strict xfail** does the rest: a silently-fixed blocker turns the lane red.

### CI wiring — restructure the existing `nightly.yml` `e2e` job

- **Remove** the `Boot stack` (`docker compose up -d --wait`) step — conftest now
  owns lifecycle (and `--wait` is incompatible with observing partial boot).
- **Keep** the AppArmor-profile load (`docker/apparmor/alfred-bwrap`) and the
  Grafana admin-password seed as host-prep steps (both are environment prep the
  harness relies on, not lifecycle).
- **Keep** the on-failure `docker compose logs` capture + artifact upload.
- Stays on the 06:00 UTC cron + `workflow_dispatch`. No new required-status-check
  promotion (nightly, not per-PR) — the release-blocking promotion is deferred to
  when the lane is fully green, and is out of scope here.

## Diagnosis deliverable

Running the harness produces the first reproducible, itemized boot-blocker report.
Each blocker is filed as a root-caused issue and cross-linked from the xfail
reason and #469/#494:

- gateway: `_resolve_hosted_adapter_ids()` couples adapter-list resolution to a
  full `Settings()` that needs a provider key the gateway is denied — decouple.
- core: `alfred-core.Dockerfile` omits `plugins/`; `_REPO_ROOT` resolves to the
  install prefix in the built image.
- `policies.yaml` provisioning gap in the documented flow.
- `state.git` seeding gap in the documented flow.

The provisioning blockers (3)+(4) are recorded as *masked-until-core-boots*: they
become harness assertions once core starts, but v1 asserts at service-health
granularity only.

## Validation before merge

- **Local** `docker compose` run on Docker Desktop: validates the green baseline
  (postgres/redis/prometheus/grafana healthy) + the gateway `xfail`. Core stays
  masked either way, so the macOS/AppArmor divergence (the bwrap profile isn't
  loaded on Docker Desktop) does not affect v1 — it only matters once the gateway
  blocker is fixed and core starts.
- **`workflow_dispatch`** run of `nightly.yml` on the branch: confirms
  green-with-xfails on the real ubuntu runner (which loads AppArmor and seeds the
  GF password), i.e. the authoritative parity check.

## Out of scope

- The blocker **fixes** (devops/core/gateway).
- Any functional / LLM message round-trip or API-keyed assertion — boot-to-healthy
  only, per #494.
- Qdrant — not in the default `docker-compose.yaml` yet.
- Release-blocking promotion of the lane — deferred until it is fully green.

## Risks

- **`up -d` hanging on a `service_healthy` dependency.** Mitigated by
  `--no-deps` per-service startup so the harness owns every wait; no compose
  command blocks on a gate that will never satisfy.
- **A baseline service being flakier than assumed** (e.g. Grafana without the
  seeded password) would make the lane red for a non-blocker reason. Mitigated by
  keeping the host-prep steps and by validating the baseline is genuinely green on
  the runner before merge.
- **macOS local run diverging from the runner.** Accepted: the runner
  `workflow_dispatch` is the authoritative validation; local is a fast first pass.
