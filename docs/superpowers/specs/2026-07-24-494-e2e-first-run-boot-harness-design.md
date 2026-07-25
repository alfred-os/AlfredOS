# #494 — First-run e2e boot harness (split green baseline + xfail'd blockers)

- **Issue:** [#494](https://github.com/alfred-os/AlfredOS/issues/494) — activate the dormant e2e first-run boot lane (clone → `up -d` → healthy)
- **Epic:** [#469](https://github.com/alfred-os/AlfredOS/issues/469) — first-run experience: a documented quickstart that actually boots
- **Roadmap:** this is **Step 1** of `docs/superpowers/specs/2026-07-24-469-first-run-path-to-green-roadmap.md` (instrument first, then ratchet)
- **Domain:** test-engineer (integration/e2e layer, CI non-vacuity)
- **Status:** design **v3** — two `/review-plan` rounds (10 specialist passes) + code-trace folded. **Shipped** in PR #502.

## Shipped implementation refinements (post-design; the code is authoritative)

This design doc is the design-time record. During subagent-driven implementation +
per-task/final/CodeRabbit review the harness refined below its original design text; where
this section and the sections further down disagree, **this section and the shipped code win**:

- **Tally reads pytest's own stats as JSON, not junit XML.** A `pytest_terminal_summary` hook
  writes `e2e-tally.json` from `terminalreporter.stats` (which already separates
  `xfailed`/`skipped`/`xpassed`), so there is no junit XML to parse (no XXE surface). Wherever
  the text below says "parse junit per-`<testcase>`", read "read pytest stats as JSON".
- **8 testcases, not 7:** 4 baseline passes + 1 service-classification pass + 3 xfails
  (gateway, core, setup.sh) = **5 passed, 3 xfailed**. `_assert_ran` asserts the independent
  floor `collected >= 7` plus `failed==0 / error==0 / skipped==0 / xpassed==0 / passed>=1 / xfailed>=1`.
- **The service set is fail-closed, not "auto-observed healthy":** a compose service absent from
  the baseline∪xfail partition **reds** `test_every_compose_service_is_classified` until it is
  explicitly classified — it is never silently asserted healthy.
- **Per-run-unique `COMPOSE_PROJECT_NAME`** (`_env.new_project_name()`), not a fixed name, so
  concurrent/re-entrant local runs never tear down each other's containers.
- **The setup.sh check runs in an isolated detached git worktree**, not via a repo-root `.env`
  backup/restore — the operator's `.env` is never touched (no SIGKILL residual).
- **Images are built once in the `boot_stack` fixture** (long build timeout so a cold build
  errors, not masks); there is no separate buildx-cache CI step. The **GF password is owned by
  the harness's isolated `--env-file`** (no job-level GF-seed — a shell var would shadow it via
  compose `${..}` precedence). The failure-uploaded `e2e-stack.log` is **secret-scrubbed**
  (`_env.scrub_env_secrets`).

## Problem

Nothing in CI drives the documented quickstart end to end. `nightly.yml` already
has an `e2e` job that does `docker compose up -d --wait` then `pytest tests/e2e`,
but it is gated on `tests/e2e/conftest.py`, which does not exist, so the job
**skip-greens** — a paper-gate that reports green while gating nothing (the #245
anti-pattern this repo has fought repeatedly).

### The stack is broken in a masked chain (established by review + code-trace)

Verified against `main` (`eaec26a1`):

1. **`bin/alfred-setup.sh` cannot complete.** At `:341` it runs `docker compose run
   --rm alfred-core migrate` with no `--no-deps`, pulling core's `depends_on:
   alfred-gateway: service_healthy` (compose:95–101). The gateway is never healthy
   (blocker A), so **setup.sh hangs at migrate**. Its later `alfred user list/add`
   (`:494–535`) build `Settings()`, hitting the eager `comms_enabled_adapters`
   validator (`settings.py:449`) — blocker B.
2. **Blocker A — gateway can't construct `Settings()`.** `_resolve_hosted_adapter_ids()`
   (`cli/gateway/_commands.py:157`) builds a full `Settings()` needing a provider key
   the gateway is denied (ADR-0036).
3. **Blocker B — core can't boot in the shipped image.** `alfred-core.Dockerfile`
   omits `plugins/`; `Settings._REPO_ROOT` resolves to the install prefix. The eager
   validator (`settings.py:449/485`) then fails for **every** `Settings()`
   construction in the built image.

Blocker fixes are the roadmap's Steps 2–5, out of scope here.

### Why v2's "green baseline via running the real setup.sh" was wrong

v2 proposed the harness run `bin/alfred-setup.sh` and take a *green* baseline from
it. The v2 re-review (architect + test-engineer + devops + code-trace) proved that
**self-contradictory**: setup.sh is exactly the thing that hangs/fails on blockers
A/B, so it can never produce a green baseline today. The green-baseline posture and
the run-real-setup.sh mechanism cannot both hold until the core boots.

## Scope

Deliver the **harness + diagnosis** (roadmap Step 1) — not the blocker fixes:

- `tests/e2e/conftest.py` + per-service boot tests + the `nightly.yml` `e2e` wiring.
- A first real run that produces the authoritative diagnosis and files/confirms each
  downstream blocker (A, B, README/key mismatch, `hash_pepper`, `policies.yaml`).

## Approach: split the green baseline from the xfail'd blockers

Two independent things, so the lane is green today *and* still exercises the real
broken flow as an observed failure:

- **Green baseline (today):** the infra tier — postgres, redis, prometheus, grafana
  — brought up via `docker compose up -d --no-deps <those>` (pulled images, no build,
  no core/gateway dep, no setup.sh) and asserted `healthy`. This is the
  regression-catching baseline; it does not depend on anything broken.
- **`xfail(strict=True)` (today):** three assertions, each tagged with its blocker
  issue — (a) `bin/alfred-setup.sh` completes exit 0 (run under a bounded timeout so
  blocker A's *hang* becomes a fast fail); (b) alfred-gateway `healthy`; (c)
  alfred-core `healthy`.

```
TODAY:   postgres/redis/prometheus/grafana -> assert healthy     -> GREEN
         setup.sh completes exit 0         -> xfail(strict, #A)
         gateway healthy                   -> xfail(strict, #A)
         core healthy                      -> xfail(strict, #B)
=> GREEN today; a new infra regression reds the baseline; each xfail reds via
   strict XPASS the instant its blocker lands (forcing the assertion to tighten);
   ALL green => the full documented flow boots healthy (roadmap Step 5).
```

Non-vacuous by construction and free of persistent-red noise — the two postures the
earlier options (honest-red / gate-later) each sacrificed one of.

## Architecture

### `tests/e2e/conftest.py` — isolated lifecycle owner

- **Isolation (never touch an operator's stack).** Every compose invocation uses a
  fixed dedicated `COMPOSE_PROJECT_NAME` (e.g. `alfred-e2e`) **and** an isolated
  `--env-file` the harness writes under a temp dir — so a local run never runs `cp
  .env.example .env` over an operator's real `.env` and never shares/​clobbers their
  volumes. `docker compose down -v` on that project only.
- **Fail loud if Docker is unavailable** — probe via `tests/_docker_probe.py`
  (`docker_available()`); if absent, **raise** (never skip). The e2e tests use a
  dedicated `e2e` marker, **not** `@pytest.mark.docker` — the root
  `tests/conftest.py:50–82` auto-*skips* `docker`-marked items on a daemon-less/win32
  host, re-introducing skip-green.
- **cwd = repo root** for every compose subprocess *and* the setup.sh invocation —
  the `seccomp=docker/seccomp/alfred-bwrap.json` path is CWD-relative (compose:131–134).
- **Env-file contents:** a per-run random `GF_SECURITY_ADMIN_PASSWORD` (grafana
  fail-closes on an unset/guessable one) and self-identifying dummy non-placeholder
  keys (`ALFRED_DEEPSEEK_API_KEY`, `ALFRED_QUARANTINE_PROVIDER_API_KEY`) with a
  recognizable sentinel (e.g. `sk-DUMMY-e2e-not-a-real-key`) so they can never be
  mistaken for real and are trivially scrubbed from logs. (The baseline services
  need only the GF password; the keys are for the setup.sh-completes assertion.)
- **Build the core image with a cross-run cache.** The core-health xfail needs core
  built; use a buildx/GHA cache backend so nightlies don't rebuild the multi-stage
  image from zero against the 60-minute job budget.
- **Reuse, with an explicit extract step.** `_compose()`/`compose_project`/
  `compose_stack` currently live *module-private* in `tests/smoke/
  test_gateway_core_link_smoke.py` and `test_slice4_graduation.py`; the plan extracts
  the shared lifecycle helper into an importable module (e.g. `tests/_compose.py`
  alongside `tests/_docker_probe.py`) that both smoke and e2e consume (DRY without
  over-claiming a reuse that isn't importable today).

### Two assertion groups (separate fixtures / compose projects)

1. **Service-health group** — `up -d --no-deps <service>` per service (sequencing the
   real leaf deps postgres/redis so services that need them can reach healthy), poll
   Docker health, assert per the table below.
2. **setup.sh-completes group** — in its own throwaway project, run `bin/alfred-setup.sh`
   under a bounded `timeout` with both dummy keys injected; assert exit 0 (xfail
   today; captures the "hangs at migrate" signature for the diagnosis). Kept separate
   so setup.sh's own `up -d`/migrate can't interfere with group 1.

### Health oracle + state classifier

Poll Docker's own health (`docker inspect --format '{{.State.Health.Status}}'`) — an
oracle independent of the app. Classify `healthy` / `unhealthy` / `starting` /
`not-created`. Under `restart: unless-stopped`, a boot-refusing service **crash-loops
as perpetual `starting`, not `unhealthy`** — so the assertion is "reaches `healthy`
within its (documented, per-service) timeout budget, else fail", and the classifier
ships with a **self-test** (synthetic `docker inspect` payloads per terminal state) —
prove the detector works before trusting it (the WSL-leg self-test discipline).

### The assertion table

| Service / check | Expected today | Disposition |
| --- | --- | --- |
| alfred-postgres | healthy | assert healthy (baseline) |
| alfred-redis | healthy | assert healthy (baseline) |
| alfred-prometheus | healthy | assert healthy (baseline) |
| alfred-grafana | healthy (harness seeds GF pw) | assert healthy (baseline) |
| `bin/alfred-setup.sh` completes exit 0 | hangs at `:341` migrate (blocker A) | `xfail(strict)` → **#A** |
| alfred-gateway healthy | `Settings()` denied the provider key (ADR-0036) | `xfail(strict)` → **#A** |
| alfred-core healthy | Dockerfile omits `plugins/`, `_REPO_ROOT` wrong | `xfail(strict)` → **#B** |

The exact today-states and xfail reason strings are **finalized by the first
diagnosis run**, not asserted blind.

### The asserted set is derived, guarded by an independent floor

The service list is derived at runtime from `docker compose config --services`
(no `profiles:` in compose, so it returns exactly the 6 `up -d` starts), partitioned
into `{known-blocked → xfail}` (a small, issue-tagged deny-list) and `{rest → assert
healthy}` — so a **new** service (e.g. Qdrant, PRD §5/§8) lands in assert-healthy
automatically. But the non-vacuity floor does **not** trust that derivation: it pins
an **independent literal** minimum service count (6) so a collapsed `docker compose
config` can't yield `collected == 0 == N` and false-green.

### Non-vacuity floor (#245 discipline)

- **No skip-green:** conftest raises on missing Docker; the `e2e` marker dodges the
  root-conftest auto-skip; `has_e2e` is permanently true once `conftest.py` exists.
- **Parse junit per-`<testcase>` by `type` — not the `-q` summary.** pytest reports
  `xfail` in junit XML as `<skipped type="pytest.xfail">` (there is no `xfailed`
  attribute), so a naive `skipped == 0` false-reds the happy path and the naive fix
  re-opens skip-green. The assert-RAN step classifies each `<testcase>` by its child
  element + `type`. Today's shape: **7 testcases** — 6 service-health (4 baseline
  passes: postgres/redis/prometheus/grafana; 2 xfail: gateway, core) + 1
  setup.sh-completes (xfail) — i.e. **4 genuine passes and 3 `pytest.xfail` skips**.
  The step asserts: `collected == 4 passes + all deny-list xfails`; the **6 compose
  services are all present as testcases** (independent literal floor of 6, so a
  collapsed `docker compose config` can't shrink the set unseen) plus the setup.sh
  check; every baseline testcase is a genuine pass; every deny-list testcase is a
  `pytest.xfail` skip (not a plain skip, `xpass`, failure, or error); and **0
  failures / 0 errors / 0 plain-skips / 0 xpass**. The deny-list *count* comes from
  pytest's own xfail tally, not a second hardcoded CI constant that must track the
  shrinking ratchet.
- **Strict xfail** turns a silently-fixed blocker red (xpass), and `pytest` overall
  exit status is asserted 0.

### CI wiring — restructure the `nightly.yml` `e2e` job

- **Remove** the `Boot stack` (`up -d --wait`) step — conftest owns lifecycle.
- **Remove** the now-unused `ANTHROPIC_API_KEY`/`OPENAI_API_KEY` env from the Run step.
- **Keep** the AppArmor-profile load and GF-password seed as *baseline* host-prep
  (the baseline `up -d` does not run setup.sh, so these stay in the job; setup.sh's
  own copies are exercised only inside the setup.sh-completes xfail). Add a buildx
  cache step for the core image.
- **Capture `docker compose logs` BEFORE teardown** (the current step runs after the
  fixture's `down -v`, losing the diagnosis) and upload on failure; scrub the
  sentinel dummy keys + keep the GF password per-run random.
- Stays on the 06:00 UTC cron + `workflow_dispatch`. **No** release-blocking
  promotion — that is roadmap Step 5, and is consistent with
  `docs/ci/required-checks.md:69` already excluding `End-to-end`.

## Diagnosis deliverable

The first harness run confirms each blocker's exact failure and files the roadmap's
downstream issues, cross-linked from the xfail reasons and #469/#494:

- **#A** — gateway `_resolve_hosted_adapter_ids()` couples to a full `Settings()`
  (decouple, ADR-0036-safe); also the cause of setup.sh's migrate hang.
- **#B** — `alfred-core.Dockerfile` omits `plugins/`; `_REPO_ROOT` resolves to the
  install prefix.
- **README/DeepSeek key mismatch** (`README:33` documents the quarantine key only,
  but setup.sh also rejects the `sk-...` DeepSeek placeholder) — the harness injects
  a DeepSeek key to run setup.sh at all, which is a **documented deviation** recorded
  here, not silent fidelity.
- **`audit.hash_pepper` path** and **`policies.yaml` provisioning** — confirm-by-run;
  file if real (both may have been masked behind A/B).

## Security posture (not a security oracle)

Boot-to-`healthy` proves nothing about the bwrap sandbox, capability-gate seeding, or
the egress chokepoint. This harness weakens no security default (keeps the real
AppArmor/seccomp profiles, runs unprivileged, does not stub the gate — it seeds from
real `state.git`). The **hard requirement** on roadmap Step 3 (core un-xfail): the
replacement for `assert core healthy` MUST include posture assertions (sandbox
active, gate seeded, egress chokepoint on), carried in **blocker #B's acceptance
criteria and the core xfail-reason string** — not left as spec prose. No
`src/alfred/security/` change here → the 100%-coverage rule is N/A.

## Validation before merge

- **Local** `docker compose` run on Docker Desktop: validates the green baseline
  (infra healthy) + the three xfails + the exact junit tally. The setup.sh-completes
  xfail reproduces the migrate hang (timeout-bounded). macOS/AppArmor divergence only
  matters once core un-xfails (Step 3), so it does not affect v1.
- **`workflow_dispatch`** run of `nightly.yml` on the branch: the authoritative parity
  check on the ubuntu runner.

## Convention recording

- Record the split-baseline + deferred-promotion convention in
  `docs/ci/required-checks.md` (no ADR — no PRD §5 invariant touched).
- Note boot-only as the v1 of PRD §8's conversation-e2e; the shared conftest lifecycle
  seam (`tests/_compose.py`) is designed for later reuse.

## Out of scope

- The blocker **fixes** — roadmap Steps 2–5.
- Any functional/LLM round-trip or keyed assertion beyond the dummy keys needed to
  drive the setup.sh-completes xfail — boot-to-healthy only, per #494.
- Qdrant (absent from compose; auto-observed when it lands via the derived set).
- Release-blocking promotion — roadmap Step 5.

## Risks

- **setup.sh hanging unbounded.** Mitigated by running the setup.sh-completes
  assertion under a `timeout`; the baseline never invokes setup.sh at all.
- **Core build time vs the 60-minute budget.** Mitigated by the buildx cross-run cache;
  the baseline needs no build (pulled images), so a cache miss only delays the two
  build-dependent xfails.
- **A baseline service flakier than assumed.** Mitigated by generous per-service
  timeout budgets and validating the baseline green on the runner before merge.
- **Diagnosis uncertainty** (exact setup.sh failure point, hash_pepper/policies.yaml
  reality). Resolved by the first run — which is the point of Step 1.

## Review findings folded (traceability)

Two `/review-plan` rounds (architect, reviewer, test-engineer, security-engineer,
devops ×2) + direct code-verification. Round 1 → v2 (run the real flow; corrected
diagnosis; both-keys prerequisite; non-`docker` marker; compose-derived set;
cwd/seccomp pin; DRY; masked-prose fix; sec/ops nits). Round 2 → v3: **the pivot** —
setup.sh can't complete under A/B, so split the green infra baseline from the xfail'd
setup.sh/gateway/core (arch-001/test-001/ops-101); junit-per-testcase parsing since
xfail reports as `skipped` (test-002); independent literal floor, not a self-derived
`N` (test-003); fixed `COMPOSE_PROJECT_NAME` + isolated `--env-file` so a local run
can't clobber an operator's `.env`/volumes (test-004); README/DeepSeek mismatch filed
as a deviation (rev-001); extract the private smoke `_compose` helper before reusing
it + derive the deny-list count from pytest (rev-002/003); buildx cache + budget
(ops-103); capture logs before `down -v` (ops-104); cwd pin extends to setup.sh
(ops-105); hash_pepper path confirm-by-run (ops-102); posture assertions into #B's
acceptance criteria + dummy-key sentinels/broadened log scrub (sec-001/sec-002).
