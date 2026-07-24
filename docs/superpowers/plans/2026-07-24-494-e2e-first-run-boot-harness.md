# #494 e2e First-Run Boot Harness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Activate the dormant nightly e2e first-run boot lane with a green infra baseline plus strict-`xfail` assertions on the three known boot blockers, so the lane is green today, reds on any new infra regression, and reds-via-xpass the instant a blocker is fixed.

**Architecture:** A pytest harness under `tests/e2e/` owns an isolated `docker compose` lifecycle and its docker-driven tests run nightly. The pure logic (health classifier, service-set partition, env-file writer, outcome tally) lives in importable modules whose **unit tests live under `tests/unit/`** so they gate every PR. The tally is read from pytest's own outcome stats as JSON (no junit XML / no XXE surface) and enforced so the lane cannot skip-green. Blocker *fixes* are out of scope (roadmap Steps 2–5).

**Tech Stack:** Python 3.14+, pytest, `docker compose`, GitHub Actions. No new third-party dependencies (stdlib `subprocess`, `json`, `secrets`, `shutil`, `pathlib`).

**Design spec:** `docs/superpowers/specs/2026-07-24-494-e2e-first-run-boot-harness-design.md` (v3). **Roadmap:** `docs/superpowers/specs/2026-07-24-469-first-run-path-to-green-roadmap.md` (this is Step 1).

**Premises verified current (before writing):** the gateway xfail holds — `alfred-gateway`'s compose env (docker-compose.yaml) has no `ALFRED_DEEPSEEK_API_KEY` and `deepseek_api_key: SecretStr` (settings.py:160) is required-no-default, so `Settings()` fails regardless of the opt-in-`[]` adapter default. The core xfail holds — the env-file sentinel key clears `_reject_placeholder_key` (settings.py:549, exact-match on the `.env.example` placeholder only), so core reaches blocker B (the eager comms-manifest validator, settings.py:449), not the key validator.

## Global Constraints

- **Python 3.14+**, PEP 604/585/695 idioms; frozen/immutable by default; `Mapping` over `dict` for read-only inputs.
- **Strong typing:** `mypy --strict` + `pyright` clean; no unjustified `Any`; enums at boundaries.
- **No new third-party dependency** without a PR-description justification — this plan adds none.
- **Lint/format:** `uv run ruff check .` + `uv run ruff format --check .` clean; markdownlint-clean for any docs.
- **Conventional Commits** with a literal `#494` after the colon in **every** commit subject. The `git commit` examples below show the **subject line only**; append the required footer trailer `MrReasonable <4990954+MrReasonable@users.noreply.github.com>` to every commit (e.g. via a heredoc `-m` body).
- **i18n:** the harness is test code — **not** `t()` scope; add no operator-facing runtime strings. Child-subprocess/CI diagnostics are out of `t()` scope.
- **Non-vacuity (#245) is the deliverable's core quality bar:** no lane may skip-green; every gate must be able to fail; the assert-RAN tally is load-bearing.
- **Never `--no-verify`; never `git add -A`** (add named paths only).
- **No `src/alfred/security/` changes** here → the 100%-coverage-on-security rule is N/A; do not touch the capability gate.

---

### Task 1: Register the `e2e` marker, create packages, gitignore artifacts

**Files:**

- Modify: `pyproject.toml` (the `[tool.pytest.ini_options] markers` list, currently at `:179`)
- Create: `tests/e2e/__init__.py`, `tests/unit/e2e/__init__.py`
- Modify: `.gitignore`

**Interfaces:**

- Produces: the registered `e2e` marker (satisfies `--strict-markers`); the `tests/e2e/` package (harness modules + nightly docker tests) and the `tests/unit/e2e/` package (the per-PR-gated unit tests for the harness's pure logic).

- [ ] **Step 1: Register the marker.** In `pyproject.toml`, inside the `markers = [` list (alongside `docker:` and `real_llm:`), add:

```toml
  "e2e: end-to-end first-run boot lane (drives real docker compose; nightly-only). NOT the `docker` marker — the root conftest auto-skips `docker`-marked items on daemon-less/win32 hosts, which would skip-green this lane.",
```

- [ ] **Step 2: Create the packages.** Create `tests/e2e/__init__.py`:

```python
"""End-to-end first-run boot lane (#494). See docs/superpowers/specs/2026-07-24-494-e2e-first-run-boot-harness-design.md."""
```

Create `tests/unit/e2e/__init__.py`:

```python
"""Per-PR-gated unit tests for the #494 e2e harness's pure logic (the modules live in tests/e2e/)."""
```

- [ ] **Step 3: Gitignore the run artifacts.** Append to `.gitignore`:

```gitignore
# #494 e2e boot lane run artifacts (written to CWD by the harness)
/e2e-tally.json
/e2e-stack.log
```

- [ ] **Step 4: Verify.**

Run: `uv run pytest tests/e2e tests/unit/e2e --collect-only -q && uv run pytest --markers | grep -A1 '@pytest.mark.e2e'`
Expected: collection succeeds with 0 tests (no `--strict-markers` error); the `e2e` marker is listed.

- [ ] **Step 5: Commit.**

```bash
git add pyproject.toml tests/e2e/__init__.py tests/unit/e2e/__init__.py .gitignore
git commit -m "test: #494 register e2e marker + tests/e2e & tests/unit/e2e packages"
```

---

### Task 2: Extract the shared compose lifecycle helper `tests/_compose.py`

**Files:**

- Create: `tests/_compose.py`
- Test: `tests/unit/test_compose_helper.py`  ← under `tests/unit/` so it gates every PR
- Modify: `tests/smoke/test_gateway_core_link_smoke.py:84-118` (repoint its `_compose`/`compose_project`; reuse the shared constants)

**Interfaces:**

- Produces:
  - `REPO_ROOT: Path`, `COMPOSE_FILE: Path`
  - `compose(project: str, *args: str, env_file: Path | None = None, check: bool = True, timeout_s: float = 180.0) -> subprocess.CompletedProcess[str]` — runs `docker compose -f <COMPOSE_FILE> -p <project> [--env-file <env_file>] <args>` from `REPO_ROOT`, `capture_output=True, text=True`.
  - `down_project(project: str, *, timeout_s: float = 90.0) -> None` — `compose(project, "down", "-v", check=False)`.
- Consumes: nothing (stdlib only).

Rationale: rev-002/003 found `_compose` is module-private to the smoke tests, so "reuse" needs this extraction. `env_file` is the new param the e2e harness needs. The smoke module also drops its own `_REPO_ROOT`/`_COMPOSE_FILE` in favour of the shared constants (small DRY win).

- [ ] **Step 1: Write the failing test.** Create `tests/unit/test_compose_helper.py`:

```python
"""Unit tests for the shared compose lifecycle helper (tests/_compose.py)."""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest import mock

from tests import _compose


def test_compose_invokes_docker_compose_from_repo_root_with_project() -> None:
    with mock.patch.object(_compose.subprocess, "run") as run:
        run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        _compose.compose("proj-x", "up", "-d", "--no-deps", "alfred-redis")
    args, kwargs = run.call_args
    cmd = args[0]
    assert cmd[:6] == ["docker", "compose", "-f", str(_compose.COMPOSE_FILE), "-p", "proj-x"]
    assert cmd[-4:] == ["up", "-d", "--no-deps", "alfred-redis"]
    assert kwargs["cwd"] == _compose.REPO_ROOT
    assert kwargs["capture_output"] is True and kwargs["text"] is True


def test_compose_threads_env_file_before_the_subcommand() -> None:
    with mock.patch.object(_compose.subprocess, "run") as run:
        run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        _compose.compose("proj-y", "config", env_file=Path("/tmp/e2e.env"))
    cmd = run.call_args[0][0]
    assert "--env-file" in cmd and cmd[cmd.index("--env-file") + 1] == "/tmp/e2e.env"
    assert cmd.index("--env-file") < cmd.index("config")
```

- [ ] **Step 2: Run it to verify it fails.**

Run: `uv run pytest tests/unit/test_compose_helper.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'tests._compose'`.

- [ ] **Step 3: Write the helper.** Create `tests/_compose.py`:

```python
"""Shared, isolated ``docker compose`` lifecycle helper for the test suite.

Extracted from the module-private copy in
``tests/smoke/test_gateway_core_link_smoke.py`` so the e2e harness (#494) and
the smoke tests share one seam (review rev-002/003). The seccomp ``security_opt``
path in docker-compose.yaml is resolved RELATIVE TO THE INVOCATION CWD, so every
call runs from ``REPO_ROOT``.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
COMPOSE_FILE = REPO_ROOT / "docker-compose.yaml"


def compose(
    project: str,
    *args: str,
    env_file: Path | None = None,
    check: bool = True,
    timeout_s: float = 180.0,
) -> subprocess.CompletedProcess[str]:
    """Run ``docker compose -f <file> -p <project> [--env-file <f>] <args>`` from the repo root."""
    cmd = ["docker", "compose", "-f", str(COMPOSE_FILE), "-p", project]
    if env_file is not None:
        cmd += ["--env-file", str(env_file)]
    cmd += list(args)
    return subprocess.run(
        cmd, cwd=REPO_ROOT, check=check, capture_output=True, text=True, timeout=timeout_s
    )


def down_project(project: str, *, timeout_s: float = 90.0) -> None:
    """Tear down a throwaway project + its named volumes (idempotent; never raises)."""
    compose(project, "down", "-v", check=False, timeout_s=timeout_s)
```

- [ ] **Step 4: Run the helper test to verify it passes.**

Run: `uv run pytest tests/unit/test_compose_helper.py -q`
Expected: PASS (2 passed).

- [ ] **Step 5: Repoint the smoke module.** In `tests/smoke/test_gateway_core_link_smoke.py`: import the shared helper + constants, replace the local `_compose` body, and use `down_project` in `compose_project`'s finally. Replace the local `_REPO_ROOT`/`_COMPOSE_FILE` module constants with:

```python
from tests import _compose as _compose_helper

_REPO_ROOT = _compose_helper.REPO_ROOT
_COMPOSE_FILE = _compose_helper.COMPOSE_FILE


def _compose(project: str, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    """Repointed to the shared helper (tests/_compose.py); behavior unchanged."""
    return _compose_helper.compose(project, *args, check=check, timeout_s=_BOOT_TIMEOUT_S)
```

And in `compose_project`'s `finally:` block, replace the inline `subprocess.run([... "down", "-v" ...])` with:

```python
        _compose_helper.down_project(project, timeout_s=_TEARDOWN_TIMEOUT_S)
```

- [ ] **Step 6: Verify the smoke module still imports + collects (its live test stays skip-marked).**

Run: `uv run pytest tests/smoke/test_gateway_core_link_smoke.py --collect-only -q`
Expected: collection succeeds (the live test collects as skipped; no import error).

- [ ] **Step 7: Commit.**

```bash
git add tests/_compose.py tests/unit/test_compose_helper.py tests/smoke/test_gateway_core_link_smoke.py
git commit -m "test: #494 extract shared tests/_compose.py lifecycle helper (DRY)"
```

---

### Task 3: Health-state classifier `tests/e2e/_health.py`

**Files:**

- Create: `tests/e2e/_health.py`
- Test: `tests/unit/e2e/test_health_classifier.py`

**Interfaces:**

- Produces:
  - `class ServiceHealth(StrEnum)` with members `HEALTHY`, `UNHEALTHY`, `STARTING`, `NOT_CREATED`, `NO_HEALTHCHECK`.
  - `classify_health(inspect: Sequence[Mapping[str, object]]) -> ServiceHealth` — pure; maps a parsed `docker inspect` result (a list of 0-or-1 container objects) to a state.

- [ ] **Step 1: Write the failing test.** Create `tests/unit/e2e/test_health_classifier.py`:

```python
"""Self-test of the health-state classifier (prove the detector works before trusting it)."""

from __future__ import annotations

from tests.e2e._health import ServiceHealth, classify_health


def _with_health(status: str) -> list[dict[str, object]]:
    return [{"State": {"Status": "running", "Health": {"Status": status}}}]


def test_healthy_payload() -> None:
    assert classify_health(_with_health("healthy")) is ServiceHealth.HEALTHY


def test_unhealthy_payload() -> None:
    assert classify_health(_with_health("unhealthy")) is ServiceHealth.UNHEALTHY


def test_starting_payload_is_starting_not_unhealthy() -> None:
    # Under restart: unless-stopped a boot-refusing service crash-loops as perpetual
    # `starting`, NOT `unhealthy` (review ops-004). The classifier must not conflate them.
    assert classify_health(_with_health("starting")) is ServiceHealth.STARTING


def test_unknown_status_is_starting_never_a_silent_pass() -> None:
    # An unrecognised Docker health string must degrade to STARTING (still coming up),
    # never to HEALTHY (review test-engineer: the fallback branch must be covered).
    assert classify_health(_with_health("reloading")) is ServiceHealth.STARTING


def test_empty_inspect_is_not_created() -> None:
    assert classify_health([]) is ServiceHealth.NOT_CREATED


def test_no_health_block_is_no_healthcheck() -> None:
    assert classify_health([{"State": {"Status": "running"}}]) is ServiceHealth.NO_HEALTHCHECK
```

- [ ] **Step 2: Run it to verify it fails.**

Run: `uv run pytest tests/unit/e2e/test_health_classifier.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'tests.e2e._health'`.

- [ ] **Step 3: Write the classifier.** Create `tests/e2e/_health.py`:

```python
"""Pure health-state classifier for the e2e boot lane.

Oracle = Docker's own health status (independent of the app's notion of health).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from enum import StrEnum


class ServiceHealth(StrEnum):
    HEALTHY = "healthy"
    UNHEALTHY = "unhealthy"
    STARTING = "starting"
    NOT_CREATED = "not_created"
    NO_HEALTHCHECK = "no_healthcheck"


_DOCKER_STATUS: Mapping[str, ServiceHealth] = {
    "healthy": ServiceHealth.HEALTHY,
    "unhealthy": ServiceHealth.UNHEALTHY,
    "starting": ServiceHealth.STARTING,
}


def classify_health(inspect: Sequence[Mapping[str, object]]) -> ServiceHealth:
    """Map a parsed ``docker inspect`` result (0-or-1 container objects) to a state.

    Empty list => container does not exist (NOT_CREATED). No ``State.Health`` block =>
    no healthcheck declared (NO_HEALTHCHECK). Any unrecognised health string => STARTING
    (still coming up), never a silent pass.
    """
    if not inspect:
        return ServiceHealth.NOT_CREATED
    state = inspect[0].get("State")
    if not isinstance(state, Mapping):
        return ServiceHealth.NOT_CREATED
    health = state.get("Health")
    if not isinstance(health, Mapping):
        return ServiceHealth.NO_HEALTHCHECK
    status = health.get("Status")
    if isinstance(status, str):
        return _DOCKER_STATUS.get(status, ServiceHealth.STARTING)
    return ServiceHealth.STARTING
```

- [ ] **Step 4: Run the test to verify it passes.**

Run: `uv run pytest tests/unit/e2e/test_health_classifier.py -q`
Expected: PASS (6 passed).

- [ ] **Step 5: Commit.**

```bash
git add tests/e2e/_health.py tests/unit/e2e/test_health_classifier.py
git commit -m "test: #494 pure health-state classifier + self-test (starting != unhealthy)"
```

---

### Task 4: Service-set derivation + independent floor `tests/e2e/_services.py`

**Files:**

- Create: `tests/e2e/_services.py`
- Test: `tests/unit/e2e/test_services.py`

**Interfaces:**

- Produces:
  - `MIN_SERVICE_FLOOR: int = 6` — an **independent literal** floor (never re-derive it from the `docker compose config` output being validated).
  - `BASELINE_SERVICES: frozenset[str]` = `{"alfred-postgres", "alfred-redis", "alfred-prometheus", "alfred-grafana"}`.
  - `XFAIL_SERVICES: Mapping[str, str]` = `{"alfred-gateway": "#A", "alfred-core": "#B"}` (issue refs finalized in Task 10).
  - `parse_services(config_services_stdout: str) -> tuple[str, ...]` — pure.
  - `assert_service_floor(services: Sequence[str]) -> None` — raises if `< MIN_SERVICE_FLOOR`.

- [ ] **Step 1: Write the failing test.** Create `tests/unit/e2e/test_services.py`:

```python
"""Unit tests for the service-set derivation + independent floor guard."""

from __future__ import annotations

import pytest

from tests.e2e import _services


def test_parse_services_splits_and_strips() -> None:
    out = "alfred-postgres\nalfred-redis\nalfred-core\n\n"
    assert _services.parse_services(out) == ("alfred-postgres", "alfred-redis", "alfred-core")


def test_floor_passes_on_full_stack() -> None:
    _services.assert_service_floor(["a", "b", "c", "d", "e", "f"])  # no raise


def test_floor_fails_on_collapsed_config() -> None:
    with pytest.raises(AssertionError, match="below the independent floor"):
        _services.assert_service_floor([])


def test_baseline_and_xfail_partition_covers_the_six() -> None:
    known = _services.BASELINE_SERVICES | set(_services.XFAIL_SERVICES)
    assert known == {
        "alfred-postgres", "alfred-redis", "alfred-prometheus",
        "alfred-grafana", "alfred-gateway", "alfred-core",
    }
```

- [ ] **Step 2: Run it to verify it fails.**

Run: `uv run pytest tests/unit/e2e/test_services.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'tests.e2e._services'`.

- [ ] **Step 3: Write the module.** Create `tests/e2e/_services.py`:

```python
"""Service-set derivation for the e2e boot lane, with an independent floor guard.

The asserted set is derived at runtime from ``docker compose config --services`` so a
future service (e.g. Qdrant) is observed automatically. The non-vacuity floor is an
INDEPENDENT literal — never re-derived from the same command being validated — so a
collapsed ``docker compose config`` cannot yield ``0 == 0`` and false-green (test-003).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

# Independent literal floor: docker-compose.yaml ships exactly these 6 services (no
# `profiles:` keys). If it collapses to fewer, the lane must RED, not pass vacuously.
MIN_SERVICE_FLOOR = 6

BASELINE_SERVICES: frozenset[str] = frozenset(
    {"alfred-postgres", "alfred-redis", "alfred-prometheus", "alfred-grafana"}
)

# Known-blocked services -> the roadmap issue that un-blocks them (refs finalized in Task 10).
# Shrinks toward empty as blockers land (the ratchet).
XFAIL_SERVICES: Mapping[str, str] = {
    "alfred-gateway": "#A",
    "alfred-core": "#B",
}


def parse_services(config_services_stdout: str) -> tuple[str, ...]:
    """Split the newline-delimited ``docker compose config --services`` output."""
    return tuple(line.strip() for line in config_services_stdout.splitlines() if line.strip())


def assert_service_floor(services: Sequence[str]) -> None:
    """Fail loud if fewer than ``MIN_SERVICE_FLOOR`` services were discovered."""
    assert len(services) >= MIN_SERVICE_FLOOR, (
        f"discovered {len(services)} compose service(s) {tuple(services)!r} — below the "
        f"independent floor of {MIN_SERVICE_FLOOR}; `docker compose config` may have collapsed."
    )
```

- [ ] **Step 4: Run the test to verify it passes.**

Run: `uv run pytest tests/unit/e2e/test_services.py -q`
Expected: PASS (4 passed).

- [ ] **Step 5: Commit.**

```bash
git add tests/e2e/_services.py tests/unit/e2e/test_services.py
git commit -m "test: #494 service-set derivation + independent literal floor guard"
```

---

### Task 5: Isolated env-file writer `tests/e2e/_env.py`

**Files:**

- Create: `tests/e2e/_env.py`
- Test: `tests/unit/e2e/test_env.py`

**Interfaces:**

- Produces:
  - `E2E_PROJECT_NAME: str = "alfred-e2e"` — the fixed isolated compose project name.
  - `DUMMY_KEY_SENTINEL: str = "sk-DUMMY-e2e-not-a-real-key"` — self-identifying dummy key (sec-002). Verified to clear `deepseek_api_key`'s `_reject_placeholder_key` validator (settings.py:549 exact-matches only the `.env.example` placeholder).
  - `write_e2e_env_file(dest_dir: Path) -> Path` — writes `<dest_dir>/e2e.env` with a per-run random `GF_SECURITY_ADMIN_PASSWORD` and both dummy keys; returns the path.

- [ ] **Step 1: Write the failing test.** Create `tests/unit/e2e/test_env.py`:

```python
"""Unit tests for the isolated e2e env-file writer."""

from __future__ import annotations

from pathlib import Path

from tests.e2e import _env


def _read(env_path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in env_path.read_text().splitlines():
        if "=" in line and not line.startswith("#"):
            k, _, v = line.partition("=")
            out[k] = v
    return out


def test_writes_gf_password_and_sentinel_keys(tmp_path: Path) -> None:
    values = _read(_env.write_e2e_env_file(tmp_path))
    assert values["ALFRED_DEEPSEEK_API_KEY"] == _env.DUMMY_KEY_SENTINEL
    assert values["ALFRED_QUARANTINE_PROVIDER_API_KEY"] == _env.DUMMY_KEY_SENTINEL
    assert len(values["GF_SECURITY_ADMIN_PASSWORD"]) >= 32


def test_gf_password_is_per_run_random(tmp_path: Path) -> None:
    a = _read(_env.write_e2e_env_file(tmp_path / "a"))["GF_SECURITY_ADMIN_PASSWORD"]
    b = _read(_env.write_e2e_env_file(tmp_path / "b"))["GF_SECURITY_ADMIN_PASSWORD"]
    assert a != b


def test_dummy_key_is_not_the_env_example_placeholder(tmp_path: Path) -> None:
    assert _env.DUMMY_KEY_SENTINEL != "sk-..."
```

- [ ] **Step 2: Run it to verify it fails.**

Run: `uv run pytest tests/unit/e2e/test_env.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'tests.e2e._env'`.

- [ ] **Step 3: Write the module.** Create `tests/e2e/_env.py`:

```python
"""Isolated env-file for the e2e boot lane.

Written under a temp dir and passed to compose via ``--env-file`` so a local run NEVER
runs ``cp .env.example .env`` over an operator's real ``.env`` or shares their volumes
(test-004). Keys are self-identifying sentinels (sec-002).
"""

from __future__ import annotations

import secrets
from pathlib import Path

E2E_PROJECT_NAME = "alfred-e2e"
DUMMY_KEY_SENTINEL = "sk-DUMMY-e2e-not-a-real-key"


def write_e2e_env_file(dest_dir: Path) -> Path:
    """Write ``<dest_dir>/e2e.env`` (per-run random GF password + dummy keys); return it."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    env_path = dest_dir / "e2e.env"
    lines = (
        f"GF_SECURITY_ADMIN_PASSWORD={secrets.token_hex(24)}",
        f"ALFRED_DEEPSEEK_API_KEY={DUMMY_KEY_SENTINEL}",
        f"ALFRED_QUARANTINE_PROVIDER_API_KEY={DUMMY_KEY_SENTINEL}",
    )
    env_path.write_text("\n".join(lines) + "\n")
    env_path.chmod(0o600)
    return env_path
```

- [ ] **Step 4: Run the test to verify it passes.**

Run: `uv run pytest tests/unit/e2e/test_env.py -q`
Expected: PASS (3 passed).

- [ ] **Step 5: Commit.**

```bash
git add tests/e2e/_env.py tests/unit/e2e/test_env.py
git commit -m "test: #494 isolated e2e env-file (per-run GF pw + sentinel dummy keys)"
```

---

### Task 6: Tally guard `tests/e2e/_assert_ran.py` (pytest-stats JSON, no XML)

**Files:**

- Create: `tests/e2e/_assert_ran.py`
- Test: `tests/unit/e2e/test_assert_ran.py`

**Interfaces:**

- Produces:
  - `write_tally(counts: Mapping[str, int], dest: Path) -> None` — serialize outcome counts as JSON (called from the Task 7 `pytest_terminal_summary` hook).
  - `assert_boot_lane_tally(tally_path: Path) -> None` — read the JSON, raise unless the tally is the expected non-vacuous shape: `collected >= MIN_SERVICE_FLOOR + 1`, ≥1 pass, ≥1 xfail, and **0 failed / 0 error / 0 skipped / 0 xpassed**.
  - `main(argv: Sequence[str]) -> int` — CLI (`python -m tests.e2e._assert_ran <tally.json>`).
- Consumes: `MIN_SERVICE_FLOOR` from `tests.e2e._services`.

Rationale: pytest's junit folds `xfail` into `<skipped type="pytest.xfail">` (test-002 hazard) and stdlib `xml.etree` is XXE-exposed. Instead the Task 7 conftest reads pytest's **own** `terminalreporter.stats` — empirically confirmed (pytest 9.1.1) to key errors as `error` (singular) and to record a strict XPASS under `failed` — and writes a stdlib-`json` tally. No XML, no new dep, pytest's classification is the independent oracle.

- [ ] **Step 1: Write the failing test.** Create `tests/unit/e2e/test_assert_ran.py`:

```python
"""Unit tests for the tally guard — the load-bearing non-vacuity gate."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path

import pytest

from tests.e2e._assert_ran import assert_boot_lane_tally, write_tally

# Healthy today-shape: 5 passes (4 baseline + service-classification) + 3 xfails = 8 collected.
_HEALTHY = {"collected": 8, "passed": 5, "failed": 0, "error": 0, "skipped": 0, "xfailed": 3, "xpassed": 0}
_XPASS = {**_HEALTHY, "xfailed": 2, "failed": 1}       # a blocker fixed -> strict xpass -> pytest 'failed'
_REGRESSION = {**_HEALTHY, "passed": 4, "failed": 1}   # a baseline service went red
_COLLAPSED = {"collected": 0, "passed": 0, "failed": 0, "error": 0, "skipped": 0, "xfailed": 0, "xpassed": 0}
_PLAIN_SKIP = {**_HEALTHY, "passed": 4, "skipped": 1}  # a real skip sneaking in -> skip-green guard
_ERRORED = {**_HEALTHY, "error": 2}                    # fixture/setup blew up -> stack never came up


def _write(tmp_path: Path, counts: Mapping[str, int]) -> Path:
    p = tmp_path / "tally.json"
    write_tally(counts, p)
    return p


def test_write_tally_roundtrips(tmp_path: Path) -> None:
    assert json.loads(_write(tmp_path, _HEALTHY).read_text()) == _HEALTHY


def test_healthy_tally_passes(tmp_path: Path) -> None:
    assert_boot_lane_tally(_write(tmp_path, _HEALTHY))  # no raise


@pytest.mark.parametrize("counts", [_XPASS, _REGRESSION, _COLLAPSED, _PLAIN_SKIP, _ERRORED])
def test_bad_tally_reds(tmp_path: Path, counts: Mapping[str, int]) -> None:
    with pytest.raises(AssertionError):
        assert_boot_lane_tally(_write(tmp_path, counts))
```

- [ ] **Step 2: Run it to verify it fails.**

Run: `uv run pytest tests/unit/e2e/test_assert_ran.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'tests.e2e._assert_ran'`.

- [ ] **Step 3: Write the guard.** Create `tests/e2e/_assert_ran.py`:

```python
"""Tally guard for the e2e boot lane — the load-bearing non-vacuity gate.

Reads a JSON tally written from pytest's OWN ``terminalreporter.stats`` (Task 7 conftest
hook), which already separates ``xfailed``/``skipped``/``xpassed`` — so there is no XML to
parse (no XXE surface, no new ``defusedxml`` dep) and no re-derivation of pytest's own
classification. A collapsed run reds via the independent floor.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

from tests.e2e._services import MIN_SERVICE_FLOOR

# 6 compose services + the setup.sh-completes check.
_MIN_COLLECTED = MIN_SERVICE_FLOOR + 1
_KEYS = ("collected", "passed", "failed", "error", "skipped", "xfailed", "xpassed")


def write_tally(counts: Mapping[str, int], dest: Path) -> None:
    """Serialize the outcome counts as JSON (stdlib only)."""
    dest.write_text(json.dumps({k: int(counts.get(k, 0)) for k in _KEYS}))


def assert_boot_lane_tally(tally_path: Path) -> None:
    """Raise ``AssertionError`` unless the tally is the expected non-vacuous shape."""
    raw = json.loads(tally_path.read_text())
    t = {k: int(raw.get(k, 0)) for k in _KEYS}

    assert t["collected"] >= _MIN_COLLECTED, (
        f"collected {t['collected']} — below the independent floor {_MIN_COLLECTED} "
        f"(6 services + setup.sh); a collapsed run or collection error is masked otherwise."
    )
    assert t["failed"] == 0, (
        f"{t['failed']} failure(s) — a baseline regression OR a strict XPASS "
        f"(a known blocker was fixed: drop its xfail and assert healthy)."
    )
    assert t["error"] == 0, f"{t['error']} test error(s) — the stack likely never came up."
    assert t["skipped"] == 0, (
        f"{t['skipped']} plain skip(s) — the lane must never skip-green; every non-pass "
        f"must be a strict xfail on a known blocker, not a skip."
    )
    assert t["xpassed"] == 0, f"{t['xpassed']} xpass(es) — a non-strict xfail leaked; use strict."
    assert t["passed"] >= 1, "no genuine passes — the green baseline did not run."
    assert t["xfailed"] >= 1, "no xfails — the known-blocker assertions did not run."


def main(argv: Sequence[str]) -> int:
    if len(argv) != 1:
        print("usage: python -m tests.e2e._assert_ran <tally.json>", file=sys.stderr)
        return 2
    tally = Path(argv[0])
    if not tally.is_file():
        print(f"tally file {tally} missing — pytest never wrote it (session errored?)", file=sys.stderr)
        return 1
    try:
        assert_boot_lane_tally(tally)
    except AssertionError as exc:
        print(f"e2e boot-lane tally FAILED: {exc}", file=sys.stderr)
        return 1
    print("e2e boot-lane tally OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
```

- [ ] **Step 4: Run the test to verify it passes.**

Run: `uv run pytest tests/unit/e2e/test_assert_ran.py -q`
Expected: PASS (7 passed — roundtrip + healthy + 5 bad-tally params).

- [ ] **Step 5: Commit.**

```bash
git add tests/e2e/_assert_ran.py tests/unit/e2e/test_assert_ran.py
git commit -m "test: #494 tally guard from pytest stats (JSON, no XML/XXE; xpass reds)"
```

---

### Task 7: e2e conftest lifecycle `tests/e2e/conftest.py`

**Files:**

- Create: `tests/e2e/conftest.py`

**Interfaces:**

- Consumes: `tests._docker_probe`, `tests._compose`, `tests.e2e._env`, `tests.e2e._assert_ran`, `tests.e2e._health`.
- Produces (for Task 8):
  - `boot_stack` (session-scoped) → yields a `BootStack` dataclass (`project`, `env_file`, and `health(service, *, timeout_s=…) -> ServiceHealth`). It **builds the core + gateway images once with a long timeout** (so a slow cold build errors instead of masking an xfail — ops-001), then brings the infra baseline up via `up -d --no-deps`; captures logs before `down -v`.
  - a `pytest_terminal_summary` hook that writes `e2e-tally.json` from pytest's own stats.

Verified by a **real run** (Task 8 Step 3), not a unit test.

- [ ] **Step 1: Write the conftest.** Create `tests/e2e/conftest.py`:

```python
"""Session lifecycle for the e2e first-run boot lane (#494).

Owns an ISOLATED docker compose project (fixed name + temp --env-file) so a local run
never touches an operator's stack. Fails LOUD (raises) if Docker is absent — never skips.
"""

from __future__ import annotations

import json
import subprocess
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest

from tests import _compose
from tests._docker_probe import docker_available, docker_unavailable_reason
from tests.e2e import _env
from tests.e2e._assert_ran import write_tally
from tests.e2e._health import ServiceHealth, classify_health

pytestmark = pytest.mark.e2e

_HEALTH_TIMEOUT_S = 180.0   # per-service budget: generous so a slow-but-healthy baseline never false-reds.
_POLL_INTERVAL_S = 3.0
_BUILD_TIMEOUT_S = 1800.0   # a cold multi-stage py3.14 build must ERROR on failure, not silently time out.
_BASELINE = ("alfred-postgres", "alfred-redis", "alfred-prometheus", "alfred-grafana")
_TALLY_PATH = Path("e2e-tally.json")


@dataclass(frozen=True)
class BootStack:
    project: str
    env_file: Path

    def health(self, service: str, *, timeout_s: float = _HEALTH_TIMEOUT_S) -> ServiceHealth:
        """Poll Docker health for a service until HEALTHY or the budget expires."""
        deadline = time.monotonic() + timeout_s
        last = ServiceHealth.NOT_CREATED
        while time.monotonic() < deadline:
            cid = _compose.compose(
                self.project, "ps", "-q", service, env_file=self.env_file, check=False
            ).stdout.strip()
            if cid:
                proc = subprocess.run(
                    ["docker", "inspect", cid],
                    cwd=_compose.REPO_ROOT, capture_output=True, text=True, timeout=30.0, check=False,
                )
                payload = json.loads(proc.stdout) if proc.returncode == 0 and proc.stdout else []
                last = classify_health(payload)
                if last is ServiceHealth.HEALTHY:
                    return last
            time.sleep(_POLL_INTERVAL_S)
        return last


@pytest.fixture(scope="session")
def boot_stack(tmp_path_factory: pytest.TempPathFactory) -> Iterator[BootStack]:
    if not docker_available():
        raise RuntimeError(  # FAIL LOUD — never skip (rev-001).
            f"e2e boot lane requires a Docker daemon: {docker_unavailable_reason()}"
        )
    env_file = _env.write_e2e_env_file(tmp_path_factory.mktemp("e2e-env"))
    project = _env.E2E_PROJECT_NAME
    try:
        # Build the app images ONCE with a long timeout so a cold build fails LOUD (fixture
        # error -> tally error>0 -> RED) rather than tripping the per-`up` 180s timeout and
        # being swallowed by the gateway/core xfail (ops-001).
        _compose.compose(
            project, "build", "alfred-core", "alfred-gateway",
            env_file=env_file, timeout_s=_BUILD_TIMEOUT_S,
        )
        # Baseline: bring the infra tier up bypassing deps (a broken gateway/core must not
        # block or hang the baseline). --no-deps + explicit service list = start-then-poll.
        _compose.compose(project, "up", "-d", "--no-deps", *_BASELINE, env_file=env_file)
        yield BootStack(project=project, env_file=env_file)
    finally:
        # Capture logs BEFORE teardown (ops-104) so a failure's diagnosis survives.
        logs = _compose.compose(project, "logs", "--no-color", env_file=env_file, check=False)
        Path("e2e-stack.log").write_text(logs.stdout + logs.stderr)
        _compose.down_project(project)


def pytest_terminal_summary(
    terminalreporter: pytest.TerminalReporter, exitstatus: int, config: pytest.Config
) -> None:
    """Write the outcome tally from pytest's OWN stats for the Task 6 non-vacuity guard.

    pytest's ``stats`` dict already separates xfailed/skipped/xpassed authoritatively, so the
    guard needs no junit XML (no XXE surface) and re-derives nothing.
    """
    stats = terminalreporter.stats
    outcomes = ("passed", "failed", "error", "skipped", "xfailed", "xpassed")
    counts = {k: len(stats.get(k, [])) for k in outcomes}
    counts["collected"] = sum(counts.values())
    write_tally(counts, _TALLY_PATH)
```

- [ ] **Step 2: Verify import + collection (no docker needed for collection).**

Run: `uv run pytest tests/e2e --collect-only -q`
Expected: collection succeeds; still 0 tests until Task 8.

- [ ] **Step 3: Type-check.**

Run: `uv run mypy tests/e2e/ tests/unit/e2e/ && uv run pyright tests/e2e/`
Expected: no errors.

- [ ] **Step 4: Commit.**

```bash
git add tests/e2e/conftest.py
git commit -m "test: #494 e2e conftest — build-once, isolated lifecycle, fail-loud, logs-before-teardown"
```

---

### Task 8: The boot tests `tests/e2e/test_first_run_boot.py`

**Files:**

- Create: `tests/e2e/test_first_run_boot.py`

**Interfaces:**

- Consumes: `boot_stack` (Task 7), `ServiceHealth` (Task 3), `_services` (Task 4), `_env`/`_compose` (Tasks 2/5).
- Produces the 8 nightly testcases the Task 6 tally expects (4 baseline pass + service-classification pass + gateway/core/setup.sh xfail).

Verified by the **real run** (Step 3). The baseline uses `parametrize` so each service is its own testcase.

- [ ] **Step 1: Write the tests.** Create `tests/e2e/test_first_run_boot.py`:

```python
"""The e2e first-run boot assertions (#494): green infra baseline + xfail'd blockers.

Baseline services are asserted healthy (regression net). The gateway/core/setup.sh
assertions are strict-xfail on their roadmap blockers — each reds via XPASS the instant
its blocker lands, forcing the assertion to tighten (Steps 2/3/5).
"""

from __future__ import annotations

import os
import shutil
import subprocess
from collections.abc import Iterator

import pytest

from tests import _compose
from tests.e2e import _services
from tests.e2e._env import E2E_PROJECT_NAME
from tests.e2e._health import ServiceHealth
from tests.e2e.conftest import BootStack

pytestmark = pytest.mark.e2e

# Cold image builds happen in the boot_stack fixture; per-service `up` here is fast, but keep a
# comfortable margin for local runs where the fixture just built.
_UP_TIMEOUT_S = 300.0
_SETUP_SH_TIMEOUT_S = 900.0


@pytest.mark.parametrize(
    "service",
    ["alfred-postgres", "alfred-redis", "alfred-prometheus", "alfred-grafana"],
)
def test_baseline_service_is_healthy(boot_stack: BootStack, service: str) -> None:
    assert boot_stack.health(service) is ServiceHealth.HEALTHY, (
        f"{service} did not reach healthy — a NEW infra regression (this is the green baseline)."
    )


def test_every_compose_service_is_classified(boot_stack: BootStack) -> None:
    # Derived-set guard (arch-001): a NEW compose service must not boot unobserved. Reds if
    # `docker compose config --services` returns anything not in BASELINE ∪ XFAIL.
    out = _compose.compose(
        boot_stack.project, "config", "--services", env_file=boot_stack.env_file
    ).stdout
    discovered = _services.parse_services(out)
    _services.assert_service_floor(discovered)
    known = _services.BASELINE_SERVICES | set(_services.XFAIL_SERVICES)
    assert set(discovered) == known, (
        f"compose services {sorted(discovered)} != classified {sorted(known)} — add a new/removed "
        f"service to BASELINE_SERVICES or XFAIL_SERVICES in tests/e2e/_services.py."
    )


@pytest.mark.xfail(strict=True, reason="blocker #A: gateway _resolve_hosted_adapter_ids builds a "
                   "full Settings() needing a provider key it is denied (ADR-0036). Roadmap Step 2.")
def test_gateway_is_healthy(boot_stack: BootStack) -> None:
    _compose.compose(boot_stack.project, "up", "-d", "--no-deps", "alfred-gateway",
                     env_file=boot_stack.env_file, timeout_s=_UP_TIMEOUT_S)
    assert boot_stack.health("alfred-gateway") is ServiceHealth.HEALTHY


@pytest.mark.xfail(strict=True, reason="blocker #B: alfred-core.Dockerfile omits plugins/ and "
                   "_REPO_ROOT resolves to the install prefix. Ratchets green only when core is "
                   "FULLY bootable (image + provisioning) at Roadmap Step 3, whose un-xfail must "
                   "add posture assertions (sandbox/gate/egress), not a bare assert-healthy.")
def test_core_is_healthy(boot_stack: BootStack) -> None:
    _compose.compose(boot_stack.project, "up", "-d", "--no-deps", "alfred-core",
                     env_file=boot_stack.env_file, timeout_s=_UP_TIMEOUT_S)
    assert boot_stack.health("alfred-core") is ServiceHealth.HEALTHY


@pytest.fixture
def _stock_dotenv() -> Iterator[None]:
    """Deterministic, host-independent, operator-safe setup.sh precondition (sec-001).

    setup.sh reads repo-root ``.env``. If a dev box has a real .env with real keys, setup.sh
    would clear its credential gate and run the INVASIVE path (sudo apparmor / build / migrate)
    and hang. So we WRITE the stock ``.env.example`` (placeholder keys) to ``.env`` before the
    run — guaranteeing the fast credential-gate exit everywhere — and restore the original after.
    """
    dotenv = _compose.REPO_ROOT / ".env"
    example = _compose.REPO_ROOT / ".env.example"
    backup = dotenv.read_bytes() if dotenv.exists() else None
    try:
        shutil.copyfile(example, dotenv)
        yield
    finally:
        if backup is None:
            dotenv.unlink(missing_ok=True)
        else:
            dotenv.write_bytes(backup)


@pytest.mark.xfail(strict=True, reason="blocker: bin/alfred-setup.sh does not complete under the "
                   "stock documented flow — it exits at the credential gate on the .env.example "
                   "placeholder DeepSeek key (README:33 omits ALFRED_DEEPSEEK_API_KEY). Roadmap "
                   "Step 4 (README/setup.sh reconciliation); after that, blocker #A's migrate hang.")
def test_setup_sh_completes(_stock_dotenv: None) -> None:
    setup_project = f"{E2E_PROJECT_NAME}-setup"
    try:
        proc = subprocess.run(
            ["bash", str(_compose.REPO_ROOT / "bin" / "alfred-setup.sh")],
            cwd=_compose.REPO_ROOT, capture_output=True, text=True,
            timeout=_SETUP_SH_TIMEOUT_S, check=False,
            env={**os.environ, "COMPOSE_PROJECT_NAME": setup_project},
        )
        assert proc.returncode == 0, f"setup.sh exit {proc.returncode}: {proc.stderr[-800:]}"
    finally:
        # Belt-and-braces: on the stock fast-exit path setup.sh creates no containers, but tear
        # down the -setup project anyway in case a future change lets it reach `up`.
        _compose.down_project(setup_project)
```

- [ ] **Step 2: Verify collection shape (8 testcases, no docker needed to collect).**

Run: `uv run pytest tests/e2e/test_first_run_boot.py --collect-only -q`
Expected: 8 items (4 parametrized baseline + service-classification + gateway + core + setup.sh).

- [ ] **Step 3: Real run — the load-bearing validation** (requires Docker; Linux/CI or Docker Desktop).

Run: `uv run pytest tests/e2e -o addopts='' ; uv run python -m tests.e2e._assert_ran e2e-tally.json`
Expected: `5 passed, 3 xfailed` (4 baseline healthy + service-classification; gateway/core/setup.sh xfail); the conftest hook writes `e2e-tally.json`; the guard prints `e2e boot-lane tally OK`. If a baseline is red, fix the environment — never weaken the assertion.

- [ ] **Step 4: Commit.**

```bash
git add tests/e2e/test_first_run_boot.py
git commit -m "test: #494 e2e boot tests — green baseline + xfail(strict) gateway/core/setup.sh"
```

---

### Task 9: Restructure the nightly `e2e` job + record the convention

**Files:**

- Modify: `.github/workflows/nightly.yml:22-94` (the `e2e` job)
- Modify: `docs/ci/required-checks.md`

**Interfaces:**

- Consumes: `tests/e2e/**` (Tasks 1–8), the `python -m tests.e2e._assert_ran` CLI (Task 6).

The restructured job (the conftest now owns build + lifecycle + logs + tally, so the job is minimal). Replace the steps AFTER `uv sync` with:

```yaml
      - name: Load the bwrap userns AppArmor profile (#290)
        if: steps.check.outputs.has_e2e == 'true'
        # docker-compose.yaml pins alfred-core at security_opt: apparmor=alfred-bwrap; Docker
        # REFUSES to create the container without the loaded profile — so without this, core's
        # xfail would fire for an apparmor reason, MASKING blocker B. Guarded on apparmor_parser.
        run: |
          set -euo pipefail
          if command -v apparmor_parser >/dev/null 2>&1; then
            sudo apparmor_parser -r -W docker/apparmor/alfred-bwrap
            echo "Loaded alfred-bwrap AppArmor profile."
          else
            echo "::notice::apparmor_parser absent — skipping profile load (security_opt is a no-op)."
          fi
      - name: Run E2E boot lane
        if: steps.check.outputs.has_e2e == 'true'
        # No GF-password seed and no provider-key env here: the harness's isolated --env-file
        # owns GF_SECURITY_ADMIN_PASSWORD and the dummy sentinel keys. A shell env var would
        # SHADOW the --env-file via compose ${..} precedence (ops-004). The real throwaway
        # quarantine key is a Roadmap Step-3 concern (added when core un-xfails).
        run: uv run pytest tests/e2e -o addopts=''
      - name: Assert the boot-lane tally is non-vacuous
        if: always() && steps.check.outputs.has_e2e == 'true'
        # always(): the conftest hook writes e2e-tally.json even when pytest exits non-zero;
        # a missing file (session errored before the hook) is itself a red (_assert_ran).
        run: uv run python -m tests.e2e._assert_ran e2e-tally.json
      - name: Upload diagnostics on failure
        if: failure() && steps.check.outputs.has_e2e == 'true'
        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
        with:
          name: e2e-diagnostics
          path: |
            e2e-stack.log
            e2e-tally.json
```

Delete the old `Seed Grafana admin password`, `Boot stack`, `Run E2E` (with the ANTHROPIC/OPENAI env), `Stack logs on failure`, and `Upload logs` steps. Keep the `Check for e2e suite` gate, `setup-uv`, and `uv sync`. Cross-run image-build caching (gha) is a follow-up optimization, NOT wired here — a cold build fits the 60-min timeout; the build is guarded by the fixture's long timeout so a failure errors rather than masks.

- [ ] **Step 1: Apply the YAML edits above** to `.github/workflows/nightly.yml`.

- [ ] **Step 2: Record the convention.** In `docs/ci/required-checks.md`, under the `End-to-end` row (already excluded from required checks), add: the nightly `End-to-end` runs the #494 split-baseline lane (green infra baseline + `xfail(strict)` on the roadmap blockers); it is **promoted to release-blocking only at roadmap Step 5**, once every xfail is green. English-only; markdownlint-clean (MD004/MD032/MD031/MD060).

- [ ] **Step 3: Validate YAML + markdown.**

Run: `uv run python -c "import yaml; yaml.safe_load(open('.github/workflows/nightly.yml')); print('yaml ok')" && npx --yes markdownlint-cli2@0.22.1 "docs/ci/required-checks.md"`
Expected: `yaml ok`; 0 markdownlint errors.

- [ ] **Step 4: Commit.**

```bash
git add .github/workflows/nightly.yml docs/ci/required-checks.md
git commit -m "ci: #494 wire the e2e boot lane (env-file-owned config, tally, logs-before-teardown)"
```

---

### Task 10: Diagnosis run — confirm blockers, file issues, finalize refs

**Files:**

- Modify: `tests/e2e/_services.py` (`XFAIL_SERVICES` real issue numbers)
- Modify: `tests/e2e/test_first_run_boot.py` (the **three** xfail `reason` issue refs)

This is the diagnosis deliverable: the first authoritative run confirms each blocker's exact failure and files the roadmap's downstream issues.

- [ ] **Step 1: Run the lane and capture the real failure signatures.** CI `workflow_dispatch` on the branch is authoritative; local Docker Desktop is the fast first pass.

Run: `gh workflow run nightly.yml --ref 494-e2e-first-run-boot-harness` (then `gh run watch`), or local `uv run pytest tests/e2e -o addopts=''`
Expected: `5 passed, 3 xfailed`; `e2e-stack.log` shows the gateway `Settings()` refusal (missing DeepSeek key), the core `no manifest for comms adapter id` error, and setup.sh exiting at the credential gate.

- [ ] **Step 2: File the confirmed blocker issues** (only those the run confirms; do NOT file `state.git`/`hash_pepper` — setup.sh seeds them):

```bash
gh issue create --title "gateway can't construct Settings(): decouple adapter-list resolution from full Settings() (ADR-0036)" --body "Blocker A (roadmap #469 Step 2). Observed by the #494 e2e lane: <paste the gateway log signature>."
gh issue create --title "alfred-core cannot boot in the shipped image: Dockerfile omits plugins/, _REPO_ROOT resolves to install prefix" --body "Blocker B (roadmap #469 Step 3). Acceptance criteria MUST include boot-posture assertions (sandbox active, gate seeded, egress chokepoint on) AND provisioning so the core xfail can ratchet green — a bare assert-healthy is insufficient (sec-002). The e2e env-file must set ALFRED_ENVIRONMENT=production so the posture assertion tests the real gate, not DevGate (sec-003). Observed by #494: <paste the core log signature>."
gh issue create --title "README first-run omits ALFRED_DEEPSEEK_API_KEY, but setup.sh's credential gate requires it" --body "Documented-flow blocker (roadmap #469 Step 4). README:33 vs setup.sh:227-236. The #494 harness's test_setup_sh_completes xfails here; it flips green when the README/setup.sh key requirements are reconciled."
```

- [ ] **Step 2b: Confirm-by-run residuals.** If the run shows `hash_pepper`/`policies.yaml` genuinely unprovisioned under the documented flow, file them (Step 4 of the roadmap); otherwise record in the PR description that the run confirmed they are provisioned.

- [ ] **Step 3: Replace the placeholder refs** with the real issue numbers — in `tests/e2e/_services.py` (`XFAIL_SERVICES` for gateway=Blocker-A, core=Blocker-B) and the `reason=` strings in `tests/e2e/test_first_run_boot.py` (the **three** xfail markers: gateway → #A, core → #B, setup.sh → the README/key issue).

- [ ] **Step 4: Verify + commit.**

Run: `uv run pytest tests/e2e --collect-only -q && uv run ruff check tests/e2e/`
Expected: 8 collected, ruff clean.

```bash
git add tests/e2e/_services.py tests/e2e/test_first_run_boot.py
git commit -m "test: #494 finalize xfail issue refs from the diagnosis run"
```

---

## Definition of Done

- `tests/e2e/` harness ships: infra baseline asserted healthy; gateway/core/setup.sh `xfail(strict)` on their filed blockers; the boot_stack fixture builds the app images once (long timeout).
- The pure-helper unit tests live under `tests/unit/` and therefore run in the **per-PR-gated** `make check` / CI unit lane (verified: Makefile:87-101, ci.yml:149 run `pytest tests/unit`).
- The nightly `e2e` job runs `pytest tests/e2e` + the exact JSON tally guard; it cannot skip-green; a cold build failure errors (not a masked xfail).
- A `workflow_dispatch` run on the branch is green (`5 passed, 3 xfailed`, tally OK).
- The diagnosis run's blockers are filed (A, B, README/key; hash_pepper/policies.yaml confirmed-or-filed), each cross-linked from its xfail; blocker B's acceptance criteria carry the posture-assertion + `ALFRED_ENVIRONMENT` requirements.
- `make check` clean (ruff + format + mypy + pyright + the pure-helper unit tests); no new dependency; every commit subject carries `#494` + the required trailer footer.
- Blocker *fixes* are NOT done here — roadmap Steps 2–5.

## Self-Review notes (spec coverage)

Split posture (spec §Approach) → Tasks 7/8. Non-vacuity floor (§Non-vacuity) → Tasks 4/6 + Task 9 tally step + the pure-helper tests now gated under `tests/unit/` (rev-001/ops-003/test-001). Isolation/`.env` safety (§Architecture) → Tasks 2/5/7; the setup.sh determinism/host-safety (sec-001/arch-003) → Task 8 `_stock_dotenv`. junit-xfail-as-skipped (test-002) sidestepped via pytest-stats JSON → Tasks 6/7. Independent floor (test-003) → Task 4. Compose-project/env isolation (test-004) → Tasks 5/7. DRY extract (rev-002/003) → Task 2. `starting`≠`unhealthy` + unknown-status branch (ops-004/test-engineer) → Task 3. Build-timeout-masks-xfail (ops-001) → Task 7 build-once. Logs-before-teardown (ops-104) → Task 7. env-file owns GF + no premature real key (sec-002/arch-004/ops-004) → Tasks 5/9. Dummy-key sentinels + validator-clearance (sec-002) → Task 5. Posture-assertion + `ALFRED_ENVIRONMENT` into blocker-B (sec-001/002/003) → Tasks 8/10. README/key mismatch (rev-001/arch-003) → Tasks 8/10. Gateway/core premises verified current → header + Tasks 8/10. Diagnosis deliverable (§Diagnosis) → Task 10. Convention recording (§Convention) → Task 9.
