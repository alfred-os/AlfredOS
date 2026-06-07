# ADR-0024 — Perf-gate hardware budget calibration

**Date:** 2026-06-07
**Status:** Proposed
**Closes:** [#117](https://github.com/alfred-os/AlfredOS/issues/117) (closed already by [PR #180](https://github.com/alfred-os/AlfredOS/pull/180); this ADR formalises the calibration table)
**Implemented in:** PR-S4-1 (planned)
**Related:** [PR #180](https://github.com/alfred-os/AlfredOS/pull/180) (Slice-3 empty-chain budget walkback), [ADR-0023](./0023-mtime-polled-hot-reload-for-policies-yaml.md) (`current()` perf claim)

## Context

[PR #180](https://github.com/alfred-os/AlfredOS/pull/180) (Slice 3) recalibrated the empty-chain hookpoint dispatch budget from 100µs to 200µs after three consecutive flake reports on `ubuntu-latest` CI runners ([#117](https://github.com/alfred-os/AlfredOS/issues/117)). The earlier 100µs budget was M-series-Mac calibrated; `ubuntu-latest`'s steady-state observed 130–140 µs band.

Slice 4 introduces new latency-sensitive primitives:

- `PoliciesSnapshotRef.current()` (PR-S4-4) — claimed zero-cost sync path.
- `BurstLimiter.acquire()` (PR-S4-8) — token-bucket with `asyncio.Lock` per `(canonical_user_id, persona)` key.
- `_resolve_operator(ctx)` (PR-S4-5) — single-row Postgres lookup with a 5 ms p99 budget.
- `PolicyWatcher._tick` (PR-S4-4) — open-then-fstat + parse + validate; offloaded via `asyncio.to_thread`.

Each primitive needs an explicit budget that holds across the CI hardware matrix. Without an authoritative budget table, individual PRs will pick numbers that pass on the author's machine and flake on `ubuntu-latest`.

A second concern is **paper-only gates** — workflows that exist but do not block merge (see slice-2.5 [issue tracking](https://github.com/alfred-os/AlfredOS/issues/118)). A perf gate that logs a warning is no gate at all.

## Decision

PR-S4-1 lands the perf-gate hardware budget table and enforcement at `tests/perf/test_slice4_hardware_budgets.py`:

| Primitive | Budget (p99) | Surface tested | Calibration |
|---|---|---|---|
| Empty-chain hookpoint dispatch | 200 µs | Existing [#117](https://github.com/alfred-os/AlfredOS/issues/117) + [#180](https://github.com/alfred-os/AlfredOS/pull/180) budget, retained | Slice-3 measured |
| `PoliciesSnapshotRef.current()` steady-state | 50 µs | Single `__slots__` load; the GIL-atomic guarantee makes this a pure microbenchmark | **Calibrate-then-set in PR-S4-1** — measure 1000 iters on `ubuntu-latest`, pick the next 10-µs band above the observed p99 with ≥50 % headroom; pin the value into this ADR via amendment in PR-S4-1 |
| `BurstLimiter.acquire()` (lock hit) | 100 µs | Per-key lock acquire + token-bucket math | Calibrate-then-set in PR-S4-1 against `ubuntu-latest`; same rule as above |
| `_resolve_operator(ctx)` (DB hit via `uq_operator_sessions_token_hash`) | 5 ms | Single index lookup over Postgres in testcontainers | Warm-up loop primes the unique index (≥50 prime queries); `--tmpfs=/var/lib/postgresql/data` mounted on the testcontainer to remove EBS jitter; bgwriter-window excluded from the measurement window |
| `PolicyWatcher._tick` (cache-hit, no change) | 5 ms | `os.stat` + cache-comparison short-circuit | Slice-3 stat baseline + 2× headroom |
| `PolicyWatcher._tick` (parse + swap) | 50 ms | open-then-fstat + read + YAML parse + Pydantic validate + atomic assign | YAML parse cost dominates; ≤8 KB file size assumed |

**Enforcement is hard, not advisory.** The perf gate runs at every CI invocation in `.github/workflows/ci.yml`. The job is declared as a **required status check** for merge (added to `docs/ci/required-checks.md` in PR-S4-1). A breach FAILS the build — there is no warning path, no soft-fail, no merge bypass. The job sets `CI_REQUIRE_PERF_GATE=1` and the test asserts `os.environ.get("CI_REQUIRE_PERF_GATE") == "1"` before running, refusing to silently no-op if the env var is unset.

**Hardware skip discipline.** Non-amd64 runners (notably arm64) explicitly **fail with `pytest.fail("hardware unsupported — perf budgets calibrated for amd64 ubuntu-latest; see ADR-0024")`** rather than skip. A silent skip would re-create the paper-only-gate failure mode. Operators self-hosting on arm64 see a loud "this test cannot run here" rather than a green check.

Each measurement is `p99` over 1000 iterations with a 100-iteration warm-up. Median, p50, p99, and max are all reported; the gate compares p99 against budget.

## Consequences

**Positive.** Every Slice-4 primitive has a measurable budget that surfaces regression. The matrix is per-primitive; a regression in one doesn't mask a regression in another. CI hardware drift surfaces via a single calibration knob. The "calibrate-then-set" rows give PR-S4-1 explicit license to refine numbers AFTER measurement — preventing fantasy targets from landing.

**Negative.** Six new perf tests cost ~30 s of CI wall-clock. Budgets calibrated for `ubuntu-latest` don't hold on operator-self-hosted hardware; the test gate `pytest.fail`s on non-amd64 rather than skip, which is an explicit acknowledgement that production-prod parity is incomplete (operator-self-hosted hardware is Slice-5 work).

**Alternatives considered.** No perf gate (rely on production observability) — rejected because regression catch is the gate's job and observability lags by hours. Per-PR perf budgets in each PR's plan — rejected because the values drift between plans; one source of truth needed. Variance-based thresholds (e.g., 3σ) — rejected because the p99 is the actual operator-facing metric. Soft-fail with warning — rejected because slice-2.5 documented the paper-only-gate failure mode and we explicitly refuse to reproduce it.

## References

- [#117 — Perf hardware flake tracker (Slice-3)](https://github.com/alfred-os/AlfredOS/issues/117)
- [PR #180 — 100µs → 200µs recalibration](https://github.com/alfred-os/AlfredOS/pull/180)
- [#118 — Perf calibration follow-up](https://github.com/alfred-os/AlfredOS/issues/118)
- Spec: [`docs/superpowers/specs/2026-06-06-slice-4-design.md`](../superpowers/specs/2026-06-06-slice-4-design.md) §8.2 (perf budgets)
- Plan: [`docs/superpowers/plans/2026-06-07-slice-4-pr-s4-1-daemon-boot-dispatch.md`](../superpowers/plans/2026-06-07-slice-4-pr-s4-1-daemon-boot-dispatch.md)
