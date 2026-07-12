# ADR-0034 — The CI OS/arch matrix-of-record (amd64 + arm64 Linux run the full suite; coverage gates stay amd64-only)

- **Status**: Proposed
- **Date**: 2026-06-14
- **Slice**: CI-matrix epic (PR-B — the arm64 Linux leg)
- **Relates to**: issue [#265](https://github.com/alfred-os/AlfredOS/issues/265) ("run the test suite on the full OS/arch matrix"), [#245](https://github.com/alfred-os/AlfredOS/issues/245) (paper-gate / skipping-gate hazard), [#246](https://github.com/alfred-os/AlfredOS/issues/246) (macOS / Windows unit-subset follow-ups), `docs/ci/required-checks.md` (the required-status-check manifest these jobs feed)
- **Supersedes**: —

## Context

The maintainer directive is to "run on all architectures": AlfredOS ships to operators on both amd64 and arm64 Linux hosts (Graviton, Apple-Silicon-via-Docker, Ampere), and an architecture-specific regression — a `ctypes` struct layout, a byte-order assumption, a native-extension wheel that builds only on amd64, a POSIX-`struct.pack` format that differs across ABIs — is invisible to a CI matrix that runs every real test leg on amd64 only.

Today (`ci.yml` before this ADR's PR), every executable test leg runs on `ubuntu-latest` (amd64):

- `python` — lint / mypy / pyright / unit, plus the per-subsystem 100% line+branch coverage gates (`security/*`, `hooks/*`, the plugins / web-fetch trust-boundary file lists).
- `integration` — testcontainers Postgres / Redis / Qdrant + the real `bubblewrap` launcher legs; uploads the `coverage-integration` artifact.
- `integration-privileged` — the dual-LLM real-`bwrap` quarantine-child spawn under `sudo` + a hermetic proto-py3.14.
- `python-cross-os` — the PORTABLE static-analysis subset (lint + type-check only) on macOS + Windows (no unit / integration suite — the runtime is Linux-only by nature; see "Linux-only-by-nature" below).

The repo is **public**, so GitHub bills `ubuntu-24.04-arm` runner minutes at 0×. arm64 Linux coverage is therefore essentially free — there is no cost argument against running the FULL Linux suite a second time on arm64.

Two design hazards constrain how we add it:

1. **Renaming a required check breaks branch protection.** Converting an existing job (e.g. `integration`) to a `strategy.matrix` over `[amd64, arm64]` renames its emitted check context to `Integration (amd64)`. The branch-protection "require status checks" list on `main` still requires the OLD `Integration` context, which no job emits any more — so EVERY open PR is blocked from merging until the protection rules are updated, and the update is not atomic with the workflow merge. This is an availability incident waiting to happen.

2. **A skipping gate is not a gate (#245).** A leg that `pytest.skip`s in CI while appearing green gates nothing — the exact failure mode `integration-privileged` was built to close. Any new arm64 leg must EXECUTE the suite, not skip it.

## Decision

**Decision 1 — ADD new arm64 jobs; never RENAME the amd64 jobs.** TWO NEW jobs are added to `ci.yml`, each emitting a NEW, distinctly-named check context ALONGSIDE its unchanged amd64 sibling:

- `python-arm64` → `Python (lint, types, unit) (arm64)` (alongside `Python (lint, types, unit)`)
- `integration-arm64` → `Integration (arm64)` (alongside `Integration`)

Both run on `runs-on: ubuntu-24.04-arm`. The amd64 jobs and their check-context names are untouched, so branch protection on `main` keeps working for every open PR with no atomic-update requirement. The arm64 contexts are promoted to required SEPARATELY, after they have run green at least once (a post-merge `gh api POST .../contexts` step), and are tracked under "Pending required" in `docs/ci/required-checks.md` until then.

A third arm64 leg — `integration-privileged-arm64` (the dual-LLM real-`bwrap` quarantine-child spawn) — was **deferred**: when first run on arm64 it caught a REAL arm64 portability bug (the bwrap child produces a truncated frame on aarch64 → a `read_frame_failed` → a `ck_audit_log_result` CHECK violation, [#269](https://github.com/alfred-os/AlfredOS/issues/269); the latter overlaps [#252](https://github.com/alfred-os/AlfredOS/issues/252)). That is the arm64 matrix doing its job. Rather than land a red leg on `main`, the privileged-arm64 leg was added in the follow-up that FIXES #269 (after #251 un-swallowed the child stderr to diagnose it).

> **AMENDED 2026-07-12 (#269) — the deferral is DISCHARGED; the leg now exists and gates merge.** Root cause was a hard `--ro-bind /lib64` in the SHIPPED bwrap policies (`policy_to_bwrap_flags` emitted it unconditionally): `/lib64` holds the dynamic linker on x86-64 but does not exist on arm64, where the loader is `/lib/ld-linux-aarch64.so.1` under the already-bound `/lib` — so bwrap died at launch and the child never emitted a frame. Fixed by a `ro_binds_try` policy field emitting `--ro-bind-try` (bind iff present, else skip), with `/lib64` moved to it. `integration-privileged-arm64` → check context `Integration (privileged Linux, real spawn) (arm64)` is therefore ADDED (separate job, separate context — the ADD-don't-RENAME rule above still applies) and pending promotion to required in `docs/ci/required-checks.md`. The `ck_audit_log_result` half (#252) was already closed independently by migration `0022`.

**Decision 2 — coverage gates deliberately stay amd64-only (single source of truth, arch-invariant).** The per-subsystem 100% line+branch coverage gates (CLAUDE.md hard rule #7) remain ONLY on the amd64 `python` + `coverage-gates` jobs. Coverage is arch-INVARIANT: the same lines and branches execute on arm64 as on amd64 (Python is interpreted; there is no arch-conditional source under the gate's `--include` lists). Duplicating the gates on arm64 would add CI cost and a SECOND place to keep the per-file `--include` lists in sync, for ZERO additional signal — and a divergence between the two lists would be a silent gate hole. The arm64 legs therefore run their test suites with `--cov-fail-under=0` and emit NO coverage-report step. They are run-to-green ARCH-PORTABILITY signals; the amd64 jobs remain the coverage source of truth. `integration-arm64` additionally does NOT upload the `coverage-integration` artifact — only the amd64 `integration` job uploads it, and two uploaders of the same artifact name collide.

**Caveat (honest scope of the arch-invariance claim).** Coverage-invariance holds ONLY while no file under a gate's `--include` list ever branches on architecture (e.g. `if platform.machine() == ...`, an arch-conditional import, or arch-specific C-extension code paths). If such a branch is ever added, its arm64 leg would be unmeasured (arm64 runs `--cov-fail-under=0`), so an arm64-only path could go uncovered without the gate noticing. AlfredOS has no such arch-conditional source today, and one at a trust boundary would itself be a smell; if one ever lands, that file's coverage gate must move to (or be duplicated on) the arm64 leg. This is the trade-off accepted for keeping ONE coverage source of truth — not a permanent guarantee.

**Decision 3 — the bwrap `/lib64` arch-portability fix unblocks `integration-arm64`.** The `integration` suite's `test_alfred_core_image_bwrap` hand-wrote a bwrap invocation that hard-bound `--ro-bind /lib64` — amd64's `/lib64` holds `ld-linux-x86-64.so.2`, which has no arm64 analogue, so the bind fails on aarch64. The fix (this branch's commit `d9f487e1`) binds `/lib64` only when it exists. The deferred `integration-privileged-arm64` leg (Decision 1) would have mirrored `integration-privileged` byte-for-byte in its executable steps (the proto-py3.14 glob + `$(dirname "$(command -v uv)")` derivations are arch-agnostic) — it returns with the #269 fix.

> **CORRECTED 2026-07-12 (#269).** The original text claimed the `d9f487e1` test fix mirrored "the production launcher (which binds `/usr` and only existing prefixes)". **That was wrong.** The production launcher did NOT bind only existing prefixes: the shipped policies hard-bound `/lib64` and `policy_to_bwrap_flags` emitted it unconditionally — which is precisely the #269 bug that kept the privileged arm64 leg deferred. In other words the TEST helper was fixed while the PRODUCTION policy it claimed to mirror stayed broken, and the wording concealed the gap for a month. Since #269 the statement is finally true: `/lib64` is a soft `--ro-bind-try` in the shipped policies, so the test helper and production genuinely agree. **Lesson: "mirrors production" is a claim to VERIFY against production, not to assert from the test side.**

**Decision 4 — macOS / Windows full-suite coverage is a FOLLOW-UP, not in scope here.** macOS gets a Docker-free unit subset (PR-C, tracked at the `#246` marker) and Windows gets a `win32` skip-guard sweep that lets the pytest subset run there (PR-D). Both need a code change (a `requires_docker` marker / `sys.platform == "win32"` guards across dozens of tests) that is out of scope for this additive CI PR. Until they land, macOS / Windows keep the lint + type-check static-analysis subset they have today (`python-cross-os`).

## Consequences

### Positive

- An architecture-specific regression (native wheel, ctypes / struct layout, byte-order, POSIX-fd ABI assumption) on the full Linux test surface — unit, integration, AND the real-bwrap dual-LLM spawn — is now caught in CI on arm64 rather than on an operator's Graviton / Apple-Silicon host.
- Branch protection on `main` is never broken by this change: the amd64 contexts keep their exact names, and the arm64 contexts are promoted to required out-of-band only after running green.
- Coverage stays auditable and single-sourced: one set of `--include` lists, on amd64, with no risk of an arm64 copy silently drifting.
- The arm64 minutes are free (public repo), so the full second Linux run costs nothing but wall-clock.

### Negative / trade-offs

- The arm64 legs duplicate wall-clock for the Linux suite (free in minutes, but they widen the PR's slowest-leg time). Mitigated by them being independent jobs that run in parallel with amd64.
- `python-arm64`/`integration-arm64` hold near-identical step bodies to their amd64 siblings; a future change must be mirrored across the pair. This is the accepted cost of NOT using a matrix (which would rename the required context). When the deferred `integration-privileged-arm64` leg returns (#269), that duplication grows to a third pair — a future composite-action extraction (which keeps the separate check-context names) could retire it without the matrix-rename hazard.
- macOS / Windows remain on the static-analysis subset until PR-C / PR-D land — the OS axis is not yet "full" on the non-Linux runners.

### Linux-only-by-nature tests

A class of tests physically cannot run on macOS or Windows and are correctly NOT part of any non-Linux leg (this is design, not a gap):

- **`bubblewrap` sandbox legs** — `bwrap` is a Linux-kernel-namespace tool; there is no macOS / Windows equivalent. (macOS uses `sandbox-exec`, tracked separately for when `kind=full` ships its `sandbox-exec` invocation.)
- **testcontainers Integration / Smoke** — need a Docker daemon; the GitHub macOS / Windows runners ship none.
- **POSIX-fd / syscall legs** — `os.geteuid()`, `os.uname()`, `signal.SIGKILL`, `subprocess(..., pass_fds=...)`, `runuser` UID-drop. These have no Windows analogue and are guarded / skipped there.

These run on BOTH amd64 and arm64 Linux (the two ABIs the runtime actually deploys to), which is the architecture axis #265 asks for. The OS axis (macOS / Windows) is intrinsically limited to the portable layer for these tests.
