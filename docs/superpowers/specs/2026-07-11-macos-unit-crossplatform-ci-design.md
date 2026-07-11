# macOS unit-test cross-platform CI coverage (design)

**Status:** DRAFT — awaiting ratification. Branch `ci-macos-unit-crossplatform` off main `c15cc3a7`.
Scope chosen best-judgment (macOS-only) while the requester was away on the scope question; ratify
§7 before `writing-plans`.

## 1. Goal

Run the **Docker-free unit subset on the macOS CI leg** so Darwin-vs-Linux syscall/fd divergence is
caught in CI, not on a contributor's Mac. Today `python-cross-os` (macos + windows) runs only
lint/format/type; the unit suite runs Linux-only (`python` x86 + `python-arm64`). This closes the
macOS half of the tracked #246 OS-matrix gap.

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

### 5.3 CI wiring

Add a conditional unit step to `python-cross-os`, gated `if: steps.check.outputs.has_py == 'true' &&
matrix.os == 'macos-latest'` (macOS only — Windows unit stays deferred, §7):

```yaml
- name: Unit tests (macOS — no coverage gate)
  if: steps.check.outputs.has_py == 'true' && matrix.os == 'macos-latest'
  run: uv run pytest tests/unit -q
```

The `docker`-marked tests auto-skip (§5.1); `-m "not real_llm"` already applies via `addopts`. **No
coverage gate on macOS** — the per-subsystem 100% line+branch gates stay the Linux `python` job's job
(they need the combined Linux unit+integration corpus). macOS is a *pass/fail run*, not a coverage
gate.

### 5.4 Required checks

No new required check is created: the unit step is added to the **existing** required
`Python cross-OS (macos-latest)` check (a matrix leg of `python-cross-os`, blocking since #321). So no
`gh api` gate change — only a `docs/ci/required-checks.md` "OS matrix" note update to record that the
macOS leg now runs the Docker-free unit subset, and (per the `author-gating-workflow` discipline) a
tracked-manifest note.

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

## 7. Scope decision (RATIFICATION FORK)

**Chosen (best-judgment): macOS-only.** Windows unit (#246 Part 1) is **out**: the divergence-prone
tests use POSIX-only syscalls (`geteuid` / `SIGKILL` / `pass_fds` / `/bin/sh`) that don't *diverge* on
Windows — they can't *run* at all, so #246 requires `sys.platform=="win32"` **skip** guards on dozens
of tests; the net is that the platform-varying tests skip on Windows, for a non-runtime-target OS
(AlfredOS ships a *stub* sandbox there) — high cost, ~zero divergence signal. macOS-native
`sandbox-exec` (#246 Part 2) is **out** (blocked on PR-S4-7 shipping the real invocation). The user may
override to include Windows.

## 8. Testing

- **The anti-rot guard is itself a test** (runs on Linux + macOS): fails if a testcontainers-using
  unit file lacks the `docker` marker.
- **A test for the auto-skip hook:** with the Docker probe monkeypatched to "unavailable", a
  `docker`-marked dummy item is skipped; with "available", it runs. (Unit-test the hook logic without
  a real daemon.)
- **The DRY'd `docker_available()` helper:** a small unit test (probe returns bool; timeout path
  returns False).
- **CI is the integration test:** the macOS `python-cross-os` leg going green (with the 12 files
  skipping) is the end-to-end proof; the first run is the acceptance gate.

## 9. Out of scope / follow-ups

- **#246 Part 1 — Windows unit** (`sys.platform=="win32"` skip-guards on dozens of POSIX-syscall
  tests). Low value (non-target OS; divergence tests skip there) — stays tracked.
- **#246 Part 2 — macOS-native `sandbox-exec` leg** — blocked on PR-S4-7.
- **The deterministic-type-check trim** (run mypy/pyright once on ubuntu, drop the arm64/macos/windows
  dupes) — a *separate* CI-hygiene change, orthogonal to this coverage-adding one. Not bundled here.

## 10. Next

Ratify §7 → `writing-plans` → subagent/inline TDD → the macOS `python-cross-os` leg green is the
acceptance gate → `/review-pr` (devops + test + docs lanes most relevant) + CodeRabbit → merge → update
the `docs/ci/required-checks.md` OS-matrix note + close the macOS half of #246.
