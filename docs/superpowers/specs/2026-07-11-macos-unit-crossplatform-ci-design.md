# Cross-platform unit-test CI coverage — macOS + Windows, phased (design)

**Status:** DRAFT — awaiting ratification. Branch `ci-macos-unit-crossplatform` off main `c15cc3a7`.
Scope ratified by the requester as **truly cross-platform (macOS + Windows)**; executed in two phases
(§7) because the two OSes are asymmetric in risk. Ratify §7 before `writing-plans`.

## 1. Goal

Run the unit suite on **both non-Linux CI legs** (macOS + Windows), not just Linux — so the codebase
is portability-clean on every platform a contributor might use, and Darwin/Windows-vs-Linux
divergence is caught in CI rather than on a contributor's laptop. Today `python-cross-os` (macos +
windows) runs only lint/format/type; the unit suite runs Linux-only (`python` x86 + `python-arm64`).
This closes the tracked #246 OS-matrix gap. **macOS lands blocking-green immediately** (proven, §4);
**Windows lands informational-first** and is promoted to blocking once its win32 surface is guarded
(§7, Phase B) — the highest *divergence* value is macOS (POSIX syscalls run on Darwin), while Windows'
standing value is portability hygiene (the POSIX-only tests skip there).

## 2. Why this matters (the concrete divergence)

Syscall-sensitive unit tests genuinely diverge by platform. The #340 PR2a `recvmsg`/`MSG_CTRUNC`
split (macOS/BSD sets `MSG_CTRUNC` on an over-full 1-fd buffer; Linux delivers the extra fd and trips
the count check) **passed locally on a Mac but failed the Linux lane** — precisely because the Mac had
no unit-on-macOS signal. Running the unit suite on macOS turns that class of divergence into a CI
signal on the platform where it manifests. AlfredOS's runtime is Linux-only (bwrap / namespaces /
`runuser`), so *integration* correctly stays Linux (x86 / arm64 / privileged) — this is specifically
about **unit** coverage for developer-facing (Darwin) divergence.

## 3. The blocker + why it was deferred

`ci.yml`'s `python-cross-os` job documents the macOS unit suite as deferred: ~12 unit files boot
Redis/Postgres via `testcontainers` (`with RedisContainer(...)`), and the GitHub macOS runner ships no
Docker daemon → they error at fixture setup (`docker.errors.DockerException`; #245 first run: 3731
passed / 77 errored). The maintainers' stated reason for deferral: the Docker-dependent tests are
"**not cleanly separable by a single marker or path, so a deselect allowlist would rot** the moment a
new Docker-backed test lands."

**The unlock: an anti-rot guard.** A marker-based split *plus* a static test that fails when a
Docker-using file is unmarked eliminates the rot concern — which is what makes the marker approach
safe and unblocks the deferral.

## 4. Risk is already retired

Docker is available on the dev Mac and `uv run pytest tests/unit` there is **5994 passed / 4 skipped**
— i.e. every non-Docker test (including the syscall/fd ones: `os.geteuid`, `signal.SIGKILL`,
`pass_fds`, `/bin/sh`, `recvmsg`) already passes on Darwin. So the macOS leg goes green immediately
once Docker is separated. This is a **regression guard** for the *next* divergence, not a fix-a-pile
task (the PR2a `recvmsg` bug is already fixed).

## 5. Design

### 5.1 Separation — `docker` marker + auto-skip + anti-rot (chosen)

The registered `docker` marker already exists (`pyproject.toml` markers: "docker: tests requiring a
live Docker daemon"). Three parts:

1. **Mark** each of the 12 Docker-backed unit files with a module-level `pytestmark = pytest.mark.docker`.
2. **Auto-skip-when-absent:** a `pytest_collection_modifyitems(config, items)` hook in the root
   `tests/conftest.py` that probes Docker availability **once** and, when unavailable, adds a
   `pytest.mark.skip(reason="docker daemon unavailable")` to every `docker`-marked item — a **clean
   skip, not an error**. On the Docker-less macOS runner the 12 files skip; everything else runs. (On
   Linux CI, Docker is present → they run. On a dev Mac with Docker Desktop → they run.)
3. **Anti-rot guard:** a static test (`tests/unit/meta/test_docker_tests_are_marked.py`) that scans
   `tests/unit/**/*.py` for testcontainers usage (`RedisContainer(` / `PostgresContainer(` /
   `DockerContainer(` / `import testcontainers` / `from testcontainers`) and fails — on every platform
   — listing any file that lacks the `docker` marker. This runs in the Linux `python` job too, so a
   new unmarked Docker test is caught before it can break the macOS leg.

Considered + rejected: **(B) refactor the 12 inline container fixtures to a shared self-skipping
fixture** — cleaner in theory but a larger, riskier churn across 12 files with heterogeneous fixture
shapes, and it still wants an anti-rot check to enforce use; **(C) a CI `--ignore=<paths>` deselect
allowlist** — exactly the "would rot" approach the maintainers rejected.

### 5.2 Docker availability probe (DRY)

Two copies of a Docker probe already exist (`tests/smoke/test_slice4_graduation.py::_docker_available`
and `tests/integration/test_alfred_core_image_bwrap.py::_docker_unavailable_reason`). Lift a single
shared helper (e.g. `tests/_docker_probe.py` — `docker_available() -> bool`, bounded/timeout-guarded
per the smoke precedent) and have the new `conftest.py` hook + both existing sites use it. Session-
scoped (probe once). This is a small in-scope DRY improvement the reviewer would otherwise flag.

### 5.3 CI wiring (BOTH legs — macOS blocking, Windows informational-first)

Add a unit step to **both** `python-cross-os` legs. The macOS leg is **blocking** (proven green, §4);
the Windows leg runs **informational-first** (`continue-on-error: true`) so it exercises the suite +
reveals the real win32 failure surface (§7 Phase B) without blocking merge — the repo's own
de-risking precedent (the Windows static-analysis layer ran `continue-on-error` for #312–#319, then #321
Phase 3 promoted it):

```yaml
- name: Unit tests (macOS — no coverage gate)
  if: steps.check.outputs.has_py == 'true' && matrix.os == 'macos-latest'
  run: uv run pytest tests/unit -q

- name: Unit tests (Windows — informational until green, no coverage gate)
  if: steps.check.outputs.has_py == 'true' && matrix.os == 'windows-latest'
  continue-on-error: true  # Phase B removes this once win32 skip-guards make it green (#246)
  shell: bash
  run: uv run pytest tests/unit -q
```

The `docker`-marked tests auto-skip on **both** runners (§5.1 — the Windows runner has no Docker
daemon either); `-m "not real_llm"` already applies via `addopts`. **No coverage gate on either** —
the per-subsystem 100% line+branch gates stay the Linux `python` job's job (they need the combined
Linux unit+integration corpus). These are *pass/fail runs*, not coverage gates. (`shell: bash` on the
Windows leg pins the shell to Git-Bash so the invocation is identical across runners, per the job's
existing `check`-step discipline.)

### 5.4 Required checks (phased)

No new required check is created in Phase A: the unit steps are added to the **existing** required
`Python cross-OS (macos-latest)` and `Python cross-OS (windows-latest)` checks (matrix legs of
`python-cross-os`, blocking since #321). The macOS leg's unit run is blocking immediately; the Windows
leg's unit run is `continue-on-error` (a Windows unit failure does NOT fail the required
`Python cross-OS (windows-latest)` check — the informational-first contract). **Phase B** drops
`continue-on-error` once the win32 guards make Windows green — no `gh api` gate change either time
(the check names are unchanged; the promotion is the `continue-on-error` removal). Update the
`docs/ci/required-checks.md` "OS matrix" note both times to record the current state (per the
`author-gating-workflow` tracked-manifest discipline).

## 6. The 12 Docker-backed unit files (to mark)

`tests/unit/cli/test_supervisor_status.py`, `tests/unit/conftest.py` (verify: mark applies to the
files that *use* the Docker fixture, not the shared SQLite conftest — investigate whether
`unit/conftest.py`'s testcontainers import is live or vestigial), `tests/unit/egress/test_provider_forward_proxy_e2e.py`,
`tests/unit/plugins/test_content_store_base.py`, `tests/unit/plugins/web_fetch/conftest.py`,
`tests/unit/plugins/web_fetch/test_canary_scanner_host_side.py`, `.../test_content_handle_single_use.py`,
`.../test_handle_cap.py`, `.../test_lua_atomic_rate_limit.py`,
`tests/unit/security/capability_gate/test_storage_backend.py`,
`tests/unit/security/test_default_strict_declarations_invariant.py`,
`tests/unit/test_slice_4_models_expose_columns.py`. (Plan-time: re-grep to confirm the exact set + how
each acquires a container — inline `with RedisContainer(...)` per the sample vs a shared fixture.)

## 7. Scope: truly cross-platform, phased (macOS + Windows)

**Ratified direction: both macOS and Windows** ("this should be truly cross-platform"). The two are
asymmetric in risk, so they land in two phases:

- **Phase A (this PR):** the shared separation infra (§5.1–§5.2) + **macOS unit BLOCKING** (proven
  green, §4) + **Windows unit INFORMATIONAL** (`continue-on-error`, §5.3). macOS gives the immediate
  Darwin-divergence signal; the Windows leg starts *running* the suite, auto-skipping Docker (§5.1),
  and surfaces the real win32 failure surface as a visible-but-non-blocking signal.
- **Phase B (follow-up, #246 Part 1):** iterate on the win32 failures Phase A reveals — add
  `sys.platform=="win32"` **skip-guards** for genuinely-POSIX-only behaviour (the bwrap/`runuser`
  launcher, `os.geteuid`, `signal.SIGKILL`, `pass_fds`, `/bin/sh`) and **pure-Python cross-platform
  reimplementations** where the behaviour is testable cross-platform — until the Windows leg is green,
  then drop `continue-on-error` to make it **blocking** (§5.4). Windows can't be pre-validated locally
  (dev box is Darwin), so this is deliberately discover-then-guard against real CI data, not guesswork.

**Why phase rather than block on Windows now:** the Windows failure surface is unknown (beyond the
known POSIX-syscall tests there will likely be path/encoding/subprocess-quoting failures), and forcing
it blocking up-front would either stall this PR indefinitely or invite a big guess-and-guard change
with no failure data. Informational-first is the repo's own established pattern (#312–#319 → #321
Phase 3). The divergence-prone tests will *skip* on Windows (POSIX-only), so Windows' standing value
is **portability hygiene for Windows contributors** (the platform-agnostic subset stays green on
Windows) rather than syscall-divergence coverage — a legitimate "truly cross-platform" invariant.

macOS-native `sandbox-exec` (#246 Part 2) stays **out** (blocked on PR-S4-7 shipping the real
invocation) — unrelated to unit coverage.

## 8. Testing

- **The anti-rot guard is itself a test** (runs on Linux + macOS + Windows): fails if a
  testcontainers-using unit file lacks the `docker` marker.
- **A test for the auto-skip hook:** with the Docker probe monkeypatched to "unavailable", a
  `docker`-marked dummy item is skipped; with "available", it runs. (Unit-test the hook logic without
  a real daemon.)
- **The DRY'd `docker_available()` helper:** a small unit test (probe returns bool; timeout path
  returns False).
- **CI is the integration test:** the macOS `python-cross-os` leg going **blocking-green** (12 files
  skipping) is Phase A's acceptance gate; the Windows leg running (informational) is the Phase A
  Windows signal — its failures are the Phase B work-list.

## 9. Out of scope / follow-ups

- **#246 Part 1 — Windows unit → BLOCKING (Phase B, in scope for this effort, separate follow-up PR).**
  Not "out of scope" any more — Phase A runs Windows informationally; Phase B guards the win32
  failures it surfaces and promotes the leg to required. Kept a separate PR because it's a discover-
  then-guard loop against real CI data (unknown surface, can't pre-validate locally).
- **#246 Part 2 — macOS-native `sandbox-exec` leg** — still out (blocked on PR-S4-7).
- **The deterministic-type-check trim** (run mypy/pyright once on ubuntu, drop the arm64/macos/windows
  dupes) — a *separate* CI-hygiene change, orthogonal to this coverage-adding one. Not bundled here.

## 10. Next

Ratify §7 (macOS + Windows, phased) → `writing-plans` for **Phase A** → subagent/inline TDD → the
macOS `python-cross-os` leg blocking-green + the Windows leg running informationally is the acceptance
gate → `/review-pr` (devops + test + docs lanes most relevant) + CodeRabbit → merge → update
`docs/ci/required-checks.md`. Then **Phase B** (its own PR): iterate win32 guards on the Windows
failures Phase A surfaced → drop `continue-on-error` → promote → close #246 Part 1.
