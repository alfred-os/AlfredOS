# #500 — alfred-core boots in the shipped image — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
>
> **Revised after a 6-reviewer /review-plan fleet** (architect, reviewer, test-engineer, security, devops, core-engineer). Findings folded: core-001 (Crit — operator seed), test-001/sec-002 (Crit — per-module coverage gate), sec-001/test-002 (sandbox oracle tautology), core-002 (boot spawns the bwrap quarantine child), arch-002 (tally), rev-001/test-003 (test-migration completeness), devops-001 (.dockerignore), + mediums/lows. See `${findings}` under `~/.cache/alfred-os/review-plan/2026-07-25-500-core-boots-shipped-image/`.

**Goal:** Make `alfred-core` boot to Docker `healthy` in the shipped (non-editable) image, in production mode, and ratchet the #494 e2e lane's `alfred-core` strict-xfail to green with runtime boot-posture assertions.

**Architecture:** Unify every hand-rolled `Path(__file__).parents[N]` "repo root" behind one `alfred._repo_root.repo_root()` that honours an `ALFRED_REPO_ROOT` deploy seam (set to `/app` by the Dockerfile) with a source-tree + `/app` fallback; COPY a `.dockerignore`-cleaned `plugins/` into the image; point the daemon at the shipped `policies.yaml`; provision `migrate` + operator-seed in the e2e core-healthy test; replace the xfail + bare `assert healthy` with runtime posture oracles (network isolation, capability-gate seeded, sandbox machinery live).

**Tech Stack:** Python 3.14, pydantic-settings v2, Docker + Docker Compose, pytest (unit + nightly e2e), alembic.

## Global Constraints

- **Design spec (verbatim authority):** `docs/superpowers/specs/2026-07-25-500-core-boots-shipped-image-design.md`.
- **Python conventions:** modern 3.14 idioms, PEP 604/585/695, frozen/immutable by default, no `Any` without justification, `mypy --strict` + `pyright`, structlog. Use the `alfred-python-developer` conventions.
- **Whole-tree type gate:** run `uv run mypy src/` (NOT per-module) — the #499 pydantic-mypy-plugin lesson: a widely-constructed type breaks only under whole-tree mypy.
- **Security HARD rules + explicit coverage gate (test-001/sec-002):** touching `src/alfred/security/**` → the full adversarial suite runs (`uv run pytest tests/adversarial`) AND an **explicit per-module 100% line+branch coverage** check is run for each touched security module — do NOT lean on `make check` (per memory #474 it runs 0 of the 47 per-module coverage gates). The per-module command is: `uv run pytest <the module's unit tests> --cov=<dotted.module> --cov-report=term-missing --cov-fail-under=100`. Modules in scope: `alfred.security.capability_gate._comms_adapter_grants` (Task 3), `alfred.security.quarantine_child_io` (Task 4). Never weaken the `validate_comms_adapter_ids` traversal guard (`is_relative_to(plugins/)`, `.`/`..` reject, charset) — `cap-2026-012` must stay green.
- **i18n:** operator-facing strings via `t()`. This change adds no new operator strings (repo-root resolution + Dockerfile/compose/test-only). Child-subprocess stderr + structlog event keys are NOT `t()` scope.
- **Conventional commits:** every commit subject carries a literal `#500` after the colon. End every commit message with `MrReasonable <4990954+MrReasonable@users.noreply.github.com>` (shown as `<trailer>` in commit steps below).
- **Branch:** `500-core-boots-shipped-image` (already created; the design-spec + plan commits are HEAD). Rebase-only repo — never `--admin` merge.
- **`make check` before every push** (mechanical breakage net — NOT a substitute for the per-module coverage gate above). The macOS integration lane is flaky under load — verify suspects in isolation; trust Linux CI.
- **Verification authority:** the Linux nightly End-to-end lane is authoritative for the shipped-image boot. macOS Docker-Desktop cannot load the `alfred-bwrap` AppArmor profile → the boot's **live bwrap quarantine-child spawn** (see core-002 below) and the sandbox posture fail there via a different mechanism. Local shipped-image verification uses the Linux/arm64-privileged docker repro.
- **core-002 boot fact (load-bearing for Task 8):** the shipped `ALFRED_COMMS_ENABLED_ADAPTERS=["alfred_tui"]` default makes `daemon start` build the FULL comms graph — which constructs the real `Orchestrator` (→ requires a seeded operator, core-001) AND spawns the **bwrap-sandboxed quarantine child** (the first live userns bwrap spawn in the e2e lane). The tui *carrier* binds a socket and spawns nothing; the comms *graph* around it does. `/app/src` is still NOT needed (the child resolves `alfred` from the PBS prefix, not `/app/src`).

## File structure

| File                                                           | Responsibility                                                                                |
| -------------------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| `src/alfred/_repo_root.py` (**new**)                           | The single repo-root resolver: `repo_root()` + pure `_resolve` helper                         |
| `src/alfred/config/settings.py`                                | validator uses `repo_root()`; drop the `_REPO_ROOT` const                                     |
| `src/alfred/cli/_launcher_spawn.py`                            | `repo_root()` delegates to the shared resolver; expose `launcher_path()`                      |
| `src/alfred/security/capability_gate/_comms_adapter_grants.py` | grant-seed manifest read uses `repo_root()`                                                   |
| `src/alfred/cli/daemon/_daemon_probes.py`                      | launcher self-test resolves path via `launcher_path()` (fixes const-ignores-env + wrong path) |
| `src/alfred/security/quarantine_child_io.py`                   | launcher default via shared resolver                                                          |
| `src/alfred/plugins/comms_stdio_transport.py`                  | launcher default via shared resolver                                                          |
| `src/alfred/gateway/adapter_child_factory.py`                  | launcher default via `repo_root()`                                                            |
| `.dockerignore` (**new**)                                      | exclude `.venv/`, `__pycache__/`, plugin `tests/`, VCS from the build context                 |
| `docker/alfred-core.Dockerfile`                                | `COPY plugins/`; `ENV ALFRED_REPO_ROOT=/app`                                                  |
| `docker-compose.yaml`                                          | `ALFRED_POLICIES_PATH` on `alfred-core` (+ fix stale hash_pepper comment)                     |
| `tests/e2e/_env.py`                                            | e2e env-file adds `ALFRED_ENVIRONMENT=production`; scrub skips non-secret keys                |
| `tests/e2e/test_first_run_boot.py`                             | provision `migrate` + operator-seed; un-xfail core with posture assertions                    |
| `tests/e2e/_posture.py` (**new**)                              | posture probe helpers (network / grants / sandbox-machinery)                                  |
| `tests/e2e/_services.py`                                       | `alfred-core`: XFAIL → HEALTHY_APP                                                            |
| `tests/unit/e2e/test_services.py`                              | partition test: xfail bucket empty (kept non-vacuous)                                         |
| `tests/unit/test_repo_root.py` (**new**)                       | resolver unit tests                                                                           |
| `tests/unit/test_dockerfile_invariants.py` (**new**)           | pin runtime-stage `plugins/` COPY + `ALFRED_REPO_ROOT`                                        |
| `docs/adr/0055-repo-root-resolution.md` (**new**)              | ADR — repo-root resolution convention                                                         |
| `docs/adr/0056-e2e-boot-posture-assertions.md` (**new**)       | ADR — boot-posture assertion contract                                                         |

---

### Task 1: The shared repo-root resolver

**Files:**

- Create: `src/alfred/_repo_root.py`
- Test: `tests/unit/test_repo_root.py`

**Interfaces:**

- Produces: `alfred._repo_root.repo_root() -> Path` and pure `alfred._repo_root._resolve(env_value: str | None, module_path: Path) -> Path`. Env var name constant `_REPO_ROOT_ENV = "ALFRED_REPO_ROOT"`; `_CONTAINER_ROOT = Path("/app")`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/test_repo_root.py
"""Unit tests for the single repo-root resolver (#500)."""

from __future__ import annotations

from pathlib import Path

from alfred._repo_root import _CONTAINER_ROOT, _resolve, repo_root


def test_env_override_wins(monkeypatch) -> None:
    monkeypatch.setenv("ALFRED_REPO_ROOT", "/opt/somewhere")
    assert repo_root() == Path("/opt/somewhere")


def test_resolve_env_value_wins_over_source() -> None:
    assert _resolve("/deploy/root", Path("/x/y/z/_repo_root.py")) == Path("/deploy/root")


def test_resolve_blank_env_is_ignored(tmp_path: Path) -> None:
    (tmp_path / "src" / "alfred").mkdir(parents=True)
    (tmp_path / "plugins").mkdir()
    module_path = tmp_path / "src" / "alfred" / "_repo_root.py"
    assert _resolve("   ", module_path) == tmp_path


def test_resolve_source_tree_when_marker_present(tmp_path: Path) -> None:
    (tmp_path / "src" / "alfred").mkdir(parents=True)
    (tmp_path / "plugins").mkdir()  # the marker
    module_path = tmp_path / "src" / "alfred" / "_repo_root.py"
    assert _resolve(None, module_path) == tmp_path


def test_resolve_container_fallback_when_no_marker(tmp_path: Path) -> None:
    (tmp_path / "lib" / "site-packages").mkdir(parents=True)
    module_path = tmp_path / "lib" / "site-packages" / "_repo_root.py"
    assert _resolve(None, module_path) == _CONTAINER_ROOT


def test_repo_root_finds_worktree_plugins_dir(monkeypatch) -> None:
    monkeypatch.delenv("ALFRED_REPO_ROOT", raising=False)
    root = repo_root()
    assert (root / "plugins").is_dir()
```

- [ ] **Step 2: Run tests to verify they fail** — `uv run pytest tests/unit/test_repo_root.py -v` → FAIL `ModuleNotFoundError: No module named 'alfred._repo_root'`.

- [ ] **Step 3: Write the resolver**

```python
# src/alfred/_repo_root.py
"""Single source of truth for the in-tree repo root (#500).

Resolves the directory that ships ``plugins/``, ``bin/``, ``config/``, and
``alembic.ini`` — the runtime artifacts the running container / a source
checkout reads by PATH (as opposed to the installed ``alfred`` package, which
carries only Python code + the wheel-embedded ``_locale``).

WHY this is ONE module: in the shipped image ``alfred`` is installed
NON-editable into a PBS python prefix, so ``Path(__file__).parents[N]`` in any
``alfred.*`` module resolves under the interpreter's ``site-packages``, NOT the
repo root — and modules at different nesting depths overshoot by different
amounts. Routing every call site through this resolver removes that drift and
makes the installed image depend on an explicit deploy seam
(``ALFRED_REPO_ROOT``, set to ``/app`` by ``docker/alfred-core.Dockerfile``)
instead of ``__file__`` arithmetic. Dependency-free (``os`` + ``pathlib`` only)
so ``config/settings.py`` may import it during very-early boot without a cycle.

Trust model (ADR-0055): ``ALFRED_REPO_ROOT`` is a PROCESS-environment seam set
by whoever controls process launch (the Dockerfile / an operator). It is NOT a
T3-reachable or lower-trust source — no untrusted content can set it — so it
needs none of the ``/etc``-vs-env precedence machinery ADR-0053 gives
``environment``. It only relocates where in-tree artifacts are read from; the
manifest path-traversal containment guard re-anchors to the resolved root and is
unchanged.
"""

from __future__ import annotations

import os
from pathlib import Path

#: Deploy-time seam. The Dockerfile sets it to ``/app`` (WORKDIR).
_REPO_ROOT_ENV = "ALFRED_REPO_ROOT"

#: Terminal container fallback (mirrors the ``/app`` fallback in
#: ``i18n/translator.py``): reached when neither the env seam nor a
#: marker-bearing source tree resolves.
_CONTAINER_ROOT = Path("/app")

#: The artifact whose presence distinguishes a source checkout / editable
#: install from an installed ``site-packages`` layout.
_ROOT_MARKER = "plugins"


def _resolve(env_value: str | None, module_path: Path) -> Path:
    """Pure resolution: explicit seam > marker-bearing source tree > ``/app``."""
    if env_value is not None and env_value.strip():
        return Path(env_value.strip())
    source_root = module_path.resolve().parents[2]
    if (source_root / _ROOT_MARKER).is_dir():
        return source_root
    return _CONTAINER_ROOT


def repo_root() -> Path:
    """Return the directory that ships ``plugins/``, ``bin/``, ``config/``."""
    return _resolve(os.environ.get(_REPO_ROOT_ENV), Path(__file__))
```

- [ ] **Step 4: Verify pass + 100% cov** — `uv run pytest tests/unit/test_repo_root.py --cov=alfred._repo_root --cov-report=term-missing` → 6 PASS, 100% line+branch.

- [ ] **Step 5: Commit**

```bash
git add src/alfred/_repo_root.py tests/unit/test_repo_root.py
git commit -m "feat: #500 single repo-root resolver honouring ALFRED_REPO_ROOT

<trailer>"
```

---

### Task 2: Route `settings.py` through the resolver

**Files:**

- Modify: `src/alfred/config/settings.py:49-55` (drop `_REPO_ROOT`), `:135`, `:141` (validator body)
- Test: `tests/unit/config/test_settings_comms_enabled_adapters.py`, `tests/unit/config/test_gateway_hosted_adapters_settings.py`

**Interfaces:**

- Consumes: `alfred._repo_root.repo_root` (Task 1).
- Produces: `validate_comms_adapter_ids` plugins-root is now `repo_root() / "plugins"`, re-read per validation call.

- [ ] **Step 1: Migrate the tests first — BOTH the monkeypatch AND the direct import (rev-002/sec-004)**

`grep -n "_REPO_ROOT" tests/unit/config/test_settings_comms_enabled_adapters.py tests/unit/config/test_gateway_hosted_adapters_settings.py`. Two shapes exist and BOTH must change:

- **Direct import** at `test_settings_comms_enabled_adapters.py:96` — `from alfred.config.settings import _REPO_ROOT` (used at :99/:101). Deleting the const makes this an **ImportError at collection**. Replace the import + its uses with `monkeypatch.setenv("ALFRED_REPO_ROOT", str(tmp_path))` and point the fake `plugins/<id>/manifest.toml` under `tmp_path`.
- **`monkeypatch.setattr(..., "_REPO_ROOT", ...)`** sites → `monkeypatch.setenv("ALFRED_REPO_ROOT", str(tmp_path))`.

Run: `uv run pytest tests/unit/config/test_settings_comms_enabled_adapters.py -v` → FAIL (ImportError / still references the const).

- [ ] **Step 2: Edit `settings.py`** — delete the `_REPO_ROOT = Path(__file__).resolve().parents[3]` const (`:55`) and its "do NOT import `_launcher_spawn`" block comment; add `from alfred._repo_root import repo_root`; in `validate_comms_adapter_ids`:

```python
def validate_comms_adapter_ids(value: tuple[str, ...]) -> tuple[str, ...]:
    """... (unchanged docstring) ..."""
    root = repo_root()  # #500: re-read per call so ALFRED_REPO_ROOT / tests are honoured.
    plugins_root = (root / "plugins").resolve()
    for adapter_id in value:
        if not _COMMS_ADAPTER_ID_RE.match(adapter_id):
            raise ValueError(f"invalid comms adapter id {adapter_id!r}")
        if adapter_id in {".", ".."}:
            raise ValueError(f"invalid comms adapter id {adapter_id!r}")
        manifest_path = root / "plugins" / adapter_id / "manifest.toml"
        if not manifest_path.resolve().is_relative_to(plugins_root):
            raise ValueError(f"invalid comms adapter id {adapter_id!r}")
        if not manifest_path.is_file():
            raise ValueError(f"no manifest for comms adapter id {adapter_id!r}")
    return value
```

- [ ] **Step 3: Run the migrated tests** — `uv run pytest tests/unit/config/test_settings_comms_enabled_adapters.py tests/unit/config/test_gateway_hosted_adapters_settings.py -v` → PASS.

- [ ] **Step 4: Whole-tree type + adversarial traversal gate** — `uv run mypy src/ && uv run pytest tests/adversarial -k cap_2026_012 -v` → mypy clean; `cap-2026-012` PASS.

- [ ] **Step 5: Commit**

```bash
git add src/alfred/config/settings.py tests/unit/config/
git commit -m "refactor: #500 settings validator resolves plugins/ via repo_root()

<trailer>"
```

---

### Task 3: Route the boot-critical resolvers (+ migrate ALL patch sites)

**Files:**

- Modify: `src/alfred/cli/_launcher_spawn.py:54-66,289` (delegate `repo_root`; expose `launcher_path`)
- Modify: `src/alfred/security/capability_gate/_comms_adapter_grants.py:95-155` (use `repo_root()`)
- Modify: `src/alfred/cli/daemon/_daemon_probes.py:89-91,111` (launcher via `launcher_path()`)
- Test: migrate `_REPO_ROOT`/`_LAUNCHER_PATH` patch sites (see Step 4 — includes an ADVERSARIAL file), add a default-branch test + a probe-USE test.

**Interfaces:**

- Consumes: `alfred._repo_root.repo_root` (Task 1).
- Produces: `alfred.cli._launcher_spawn.repo_root() -> Path` (delegates), `alfred.cli._launcher_spawn.launcher_path() -> str` (public; `ALFRED_PLUGIN_LAUNCHER` override else `repo_root()/bin/alfred-plugin-launcher.sh`).

- [ ] **Step 1: `_launcher_spawn.py` — delegate + expose `launcher_path`**

```python
from alfred._repo_root import repo_root as _resolve_repo_root


def repo_root() -> Path:
    """Repo root that ships ``bin/`` and ``plugins/`` (delegates to the single
    resolver — #500). Thin wrapper so existing importers + test patches of
    ``_launcher_spawn.repo_root`` keep working."""
    return _resolve_repo_root()


def launcher_path() -> str:
    """The plugin-launcher path: ``ALFRED_PLUGIN_LAUNCHER`` override else the
    in-tree default. Public so daemon-boot probe (a) shares ONE resolution."""
    return os.environ.get(_LAUNCHER_ENV_VAR, str(repo_root() / "bin" / "alfred-plugin-launcher.sh"))
```

Repoint the existing private `_launcher_path()` to call `launcher_path()`. Add `"launcher_path"` to `__all__` (`:289`).

- [ ] **Step 2: `_comms_adapter_grants.py` — use `repo_root()`** — delete `_REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[4]` (`:100`); add `from alfred._repo_root import repo_root`; in the manifest-reading function (`:151-155`):

```python
    root = repo_root()  # #500: fresh per call (honours ALFRED_REPO_ROOT / test patches).
    plugins_root = (root / "plugins").resolve()
    ...
        manifest_path = root / "plugins" / adapter_id / "manifest.toml"
```

Keep the containment/charset guards byte-for-byte.

- [ ] **Step 3: `_daemon_probes.py` — resolve the launcher via the shared path** — delete the `_LAUNCHER_PATH = Path(__file__).resolve().parents[4] / ...` const (`:89-91`); in `_launcher_self_test_impl` (`:111`):

```python
from alfred.cli._launcher_spawn import launcher_path
...
    launcher = launcher_path()  # #500: image-correct + env-overridable (was a wrong-path const).
    # ... exec `launcher --self-test` exactly as before, using `launcher` ...
```

Do NOT touch the `_STUB_SIGNATURE` / production-refusal logic.

- [ ] **Step 4: Migrate ALL patch sites (rev-001, test-003) + add the two missing tests**

`grep -rn "_REPO_ROOT\|_LAUNCHER_PATH" tests/` and migrate EVERY site — the migration MUST include (these were missed in v1):

- **`tests/adversarial/comms_confusion/test_cap_2026_004_system_tier_comms_adapter_refused.py:127`** — patches `_comms_adapter_grants._REPO_ROOT` (release-blocking; will ERROR the adversarial suite if not migrated) → `monkeypatch.setenv("ALFRED_REPO_ROOT", str(tmp_path))`.
- **`tests/unit/cli/daemon/test_probe_launcher_not_policy_resolving.py`** — the `_LAUNCHER_PATH` patch sites → `monkeypatch.setenv("ALFRED_PLUGIN_LAUNCHER", str(fake_launcher))`.
- **`tests/adversarial/sandbox_escape/test_quarantined_llm_spawn_site_and_import_time_egress_backstop.py`** — any `_LAUNCHER_PATH` reference → same env form.

Add to `test_probe_launcher_not_policy_resolving.py` (test-003/sec-005 — assert the probe's USE + the DEFAULT branch, not just `launcher_path()`):

```python
def test_probe_launcher_uses_repo_root_default_when_no_env(monkeypatch) -> None:
    # #500: the ACTUAL fix — with no ALFRED_PLUGIN_LAUNCHER, the probe resolves the
    # launcher under repo_root()/bin (not a parents[N] const). Pin ALFRED_REPO_ROOT so
    # the default is deterministic, and assert the probe execs THAT path.
    monkeypatch.delenv("ALFRED_PLUGIN_LAUNCHER", raising=False)
    monkeypatch.setenv("ALFRED_REPO_ROOT", "/app")
    from alfred.cli._launcher_spawn import launcher_path
    assert launcher_path() == "/app/bin/alfred-plugin-launcher.sh"
    # And the probe uses launcher_path() — patch it and assert the probe execs the patched value.
    # (Follow the file's existing subprocess-capture pattern to assert the exec'd argv[0].)


def test_launcher_self_test_honours_env_override(monkeypatch, tmp_path) -> None:
    fake = tmp_path / "my-launcher.sh"
    fake.write_text("#!/bin/sh\n")
    monkeypatch.setenv("ALFRED_PLUGIN_LAUNCHER", str(fake))
    from alfred.cli._launcher_spawn import launcher_path
    assert launcher_path() == str(fake)
```

Run: `uv run pytest tests/unit/cli/ -k "launcher or daemon_prob" -v` → PASS.

- [ ] **Step 5: Whole-tree + adversarial + per-module coverage gate (test-001)**

```bash
uv run mypy src/
uv run pytest tests/adversarial -q
# Explicit per-module 100% coverage on the touched security module (NOT make check — #474):
uv run pytest tests/unit/security/capability_gate/ tests/adversarial/comms_confusion/test_cap_2026_004_system_tier_comms_adapter_refused.py \
  --cov=alfred.security.capability_gate._comms_adapter_grants --cov-report=term-missing --cov-fail-under=100
```

Expected: clean; 100% line+branch on `_comms_adapter_grants` (esp. the `is_relative_to` fail-closed branch under the new per-call `repo_root()`).

- [ ] **Step 6: Commit**

```bash
git add src/alfred/cli/_launcher_spawn.py src/alfred/security/capability_gate/_comms_adapter_grants.py src/alfred/cli/daemon/_daemon_probes.py tests/
git commit -m "refactor: #500 boot-critical resolvers share repo_root()/launcher_path()

<trailer>"
```

---

### Task 4: Route the remaining security/gateway resolvers (finish unify-all)

**Files:**

- Modify: `src/alfred/security/quarantine_child_io.py:238-252` (the `parents[3]` `_repo_root()`, NOT the package-relative `:306` — that one is correctly out of scope)
- Modify: `src/alfred/plugins/comms_stdio_transport.py:69-83`
- Modify: `src/alfred/gateway/adapter_child_factory.py:269`
- Test: migrate patches; **add a default-branch resolution test per module (arch-004)** — the adversarial suite exercises the OVERRIDE path, not the changed DEFAULT.

**Interfaces:** Consumes `alfred._repo_root.repo_root` / `alfred.cli._launcher_spawn.launcher_path`.

- [ ] **Step 1: `quarantine_child_io.py`** — replace the `parents[3]` `_repo_root()` body (`:238-247`) with a delegation to `repo_root()`; keep the `ALFRED_PLUGIN_LAUNCHER` override at `:251-252`. Do NOT touch the package-relative resolver at `:306`.

- [ ] **Step 2: `comms_stdio_transport.py`** — same (`:69-83`): local `_repo_root()` delegates to `repo_root()`; keep the `_LAUNCHER_ENV_VAR` override.

- [ ] **Step 3: `adapter_child_factory.py:269`** — replace the inline `Path(__file__).resolve().parents[3] / "bin" / "alfred-plugin-launcher.sh"` with `repo_root() / "bin" / "alfred-plugin-launcher.sh"`.

- [ ] **Step 4: Migrate patches + add default-branch tests (arch-004)**

For EACH of the three modules add/keep a test that asserts the DEFAULT launcher path (NO `ALFRED_PLUGIN_LAUNCHER`) resolves under `repo_root()/bin` — e.g.:

```python
def test_quarantine_launcher_default_resolves_under_repo_root(monkeypatch) -> None:
    monkeypatch.delenv("ALFRED_PLUGIN_LAUNCHER", raising=False)
    monkeypatch.setenv("ALFRED_REPO_ROOT", "/app")
    # call the module's launcher-default resolver and assert it == "/app/bin/alfred-plugin-launcher.sh"
```

Migrate any `_repo_root`/`_LAUNCHER_PATH` monkeypatch in these modules' tests to the env form.

- [ ] **Step 5: Whole-tree + adversarial + per-module coverage on the touched security module (test-001)**

```bash
uv run mypy src/
uv run pytest tests/unit/security/ tests/unit/plugins/ tests/unit/gateway/ -q
uv run pytest tests/adversarial -q
uv run pytest tests/unit/security/ -k quarantine_child_io \
  --cov=alfred.security.quarantine_child_io --cov-report=term-missing --cov-fail-under=100
```

Expected: PASS / clean; 100% line+branch on `quarantine_child_io` (the changed default-launcher branch covered).

- [ ] **Step 6: Commit**

```bash
git add src/alfred/security/quarantine_child_io.py src/alfred/plugins/comms_stdio_transport.py src/alfred/gateway/adapter_child_factory.py tests/
git commit -m "refactor: #500 finish unify-all — every repo-root resolver shares one source

<trailer>"
```

---

### Task 5: `.dockerignore` + Dockerfile COPY `plugins/` + `ALFRED_REPO_ROOT`

**Files:**

- Create: `.dockerignore`
- Modify: `docker/alfred-core.Dockerfile` (runtime stage: `ENV` block + runtime-artefact COPY block)
- Test: `tests/unit/test_dockerfile_invariants.py` (new; parse the Dockerfile — verify the RUNTIME stage, test-007)

**Interfaces:** none exported.

- [ ] **Step 1: Write the failing invariant test (runtime-stage-scoped, test-007)**

```python
# tests/unit/test_dockerfile_invariants.py
"""Static pins on docker/alfred-core.Dockerfile (#500)."""

from __future__ import annotations

from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]
_DOCKERFILE = _ROOT / "docker" / "alfred-core.Dockerfile"


def _runtime_stage(text: str) -> str:
    # Everything from the LAST `FROM ... AS runtime` to EOF — so a builder-stage COPY
    # can't satisfy a runtime-stage pin (test-007).
    marker = "AS runtime"
    idx = text.rfind(marker)
    assert idx != -1, "no `AS runtime` stage found in the Dockerfile."
    return text[idx:]


@pytest.fixture
def runtime_stage() -> str:
    return _runtime_stage(_DOCKERFILE.read_text())


def test_runtime_stage_copies_plugins(runtime_stage: str) -> None:
    assert "COPY plugins ./plugins" in runtime_stage


def test_runtime_stage_sets_repo_root_env(runtime_stage: str) -> None:
    assert "ALFRED_REPO_ROOT=/app" in runtime_stage


def test_dockerignore_excludes_venv_and_pycache() -> None:
    di = (_ROOT / ".dockerignore").read_text()
    for pat in ("**/.venv", "**/__pycache__"):
        assert pat in di, f".dockerignore must exclude {pat} (reproducible-image hygiene)."
```

Run: `uv run pytest tests/unit/test_dockerfile_invariants.py -v` → FAIL.

- [ ] **Step 2: Create `.dockerignore` (devops-001)**

```gitignore
# #500: keep the build context hermetic so the shipped image is reproducible across
# machines (a dev tree's plugins/*/.venv holds a dangling host-absolute python symlink;
# __pycache__ / plugin tests are non-runtime). This governs EVERY COPY in the Dockerfile.
.git
**/.venv
**/__pycache__
**/*.pyc
**/.pytest_cache
**/.mypy_cache
**/.ruff_cache
plugins/*/tests
plugins/*/.venv
```

(Keep it minimal + correct: the builder COPYs `src`, `pyproject.toml`, `uv.lock`, `README.md`, `locale`; none of these excludes touch those. Verify no needed file is excluded.)

- [ ] **Step 3: Edit the Dockerfile** — in the runtime `ENV` block (after `ALFRED_QUARANTINE_CHILD_PYTHON=...`):

```dockerfile
    # #500: the repo-root deploy seam (alfred._repo_root.repo_root). WORKDIR is /app
    # and plugins/bin/config/alembic.ini are COPYed there; the non-editable install
    # means parents[N] arithmetic overshoots into site-packages, so pin the root here.
    ALFRED_REPO_ROOT=/app
```

In the runtime-artefact COPY block (near `COPY config ./config`):

```dockerfile
# #500: plugins/ is a RUNTIME artifact — the daemon resolves plugins/<id>/manifest.toml
# by path (comms-adapter validator + first-party grant seed). The wheel does NOT carry it.
# .dockerignore keeps .venv/__pycache__/tests out so the image is reproducible.
COPY plugins ./plugins
```

- [ ] **Step 4: Verify + assert the shipped tree is clean**

Run: `uv run pytest tests/unit/test_dockerfile_invariants.py -v` → PASS.
Then a build-context smoke (Linux/local, Docker required) — confirm the noise is gone:
`docker build -f docker/alfred-core.Dockerfile --target runtime -t alfred-core-500 . && docker run --rm --entrypoint /bin/sh alfred-core-500 -c 'test ! -e /app/plugins/alfred_tui/.venv && test ! -e /app/plugins/alfred_tui/tests && ls /app/plugins/alfred_tui/manifest.toml'`
Expected: exit 0 (venv/tests absent, manifest present).

- [ ] **Step 5: Commit**

```bash
git add .dockerignore docker/alfred-core.Dockerfile tests/unit/test_dockerfile_invariants.py
git commit -m "build: #500 COPY plugins/ into image + ALFRED_REPO_ROOT + hermetic .dockerignore

<trailer>"
```

---

### Task 6: Compose — point the daemon at the shipped `policies.yaml`

**Files:**

- Modify: `docker-compose.yaml` (`alfred-core` `environment:` block; fix the stale hash_pepper header comment — test-008)
- Test: `tests/unit/test_compose_invariants.py` (add one pin)

- [ ] **Step 1: Write the failing invariant test (use the file's EXISTING helper, rev-003/test-006)**

Match the file's convention — it accesses services as `compose.get("services", {}).get("<name>", {})` (there is NO `_service()` helper). Add:

```python
def test_alfred_core_points_policies_path_at_shipped_config(compose: dict[str, Any]) -> None:
    # #500 probe (b): settings.policies_path defaults to /etc/alfred/policies.yaml (not in
    # the image); the image ships it at /app/config/policies.yaml, so compose must override
    # the path or the daemon refuses boot in production with snapshot_ref_init_failed.
    core = compose.get("services", {}).get("alfred-core", {})
    val = core.get("environment", {}).get("ALFRED_POLICIES_PATH", "")
    assert "/app/config/policies.yaml" in val, (
        "alfred-core must set ALFRED_POLICIES_PATH to the in-image /app/config/policies.yaml."
    )
```

Run: `uv run pytest tests/unit/test_compose_invariants.py::test_alfred_core_points_policies_path_at_shipped_config -v` → FAIL.

- [ ] **Step 2: Edit `docker-compose.yaml`** — add to the `alfred-core` `environment:` block:

```yaml
      # #500 probe (b): the daemon loads policies.yaml at boot. settings.policies_path
      # defaults to the bare-host /etc/alfred/policies.yaml, which the image does not
      # provision; the Dockerfile COPYs it to /app/config/policies.yaml, so point the
      # documented ALFRED_POLICIES_PATH override there. In production a missing policies
      # file refuses boot (snapshot_ref_init_failed) — this is what lets core reach healthy.
      ALFRED_POLICIES_PATH: ${ALFRED_POLICIES_PATH:-/app/config/policies.yaml}
```

Also fix the stale service-header comment (test-008): the `alfred-core` header comment says a seeded `audit.hash_pepper` is required "before `up -d`, or the daemon refuse-boots" — the verified boot trace shows hash_pepper is LAZY (first-inbound) and does NOT gate boot-to-healthy. Reword to: the daemon needs a MIGRATED DB + a seeded operator before it reaches healthy; `audit.hash_pepper` is required for inbound message handling (lazy), not for boot.

- [ ] **Step 3: Verify** — `uv run pytest tests/unit/test_compose_invariants.py -v` → PASS.

- [ ] **Step 4: Commit**

```bash
git add docker-compose.yaml tests/unit/test_compose_invariants.py
git commit -m "build: #500 point alfred-core at the in-image /app/config/policies.yaml

<trailer>"
```

---

### Task 7: e2e env-file — explicit `ALFRED_ENVIRONMENT=production` (+ scrub fix)

**Files:**

- Modify: `tests/e2e/_env.py:write_e2e_env_file`, `scrub_env_secrets`
- Test: `tests/unit/e2e/test_env.py`

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/e2e/test_env.py
from pathlib import Path

from tests.e2e import _env


def test_e2e_env_file_sets_production(tmp_path: Path) -> None:
    env_file = _env.write_e2e_env_file(tmp_path)
    assert "ALFRED_ENVIRONMENT=production" in env_file.read_text()


def test_scrub_does_not_redact_nonsecret_environment_value(tmp_path: Path) -> None:
    # sec-007: ALFRED_ENVIRONMENT=production is not a secret; scrubbing "production" from
    # captured logs would over-redact legitimate log text. Non-secret keys are skipped.
    env_file = _env.write_e2e_env_file(tmp_path)
    text = "core booting in production mode"
    assert "production" in _env.scrub_env_secrets(text, env_file)
```

Run → FAIL.

- [ ] **Step 2: Edit `_env.py`** — add `ALFRED_ENVIRONMENT=production` to the `lines` tuple in `write_e2e_env_file`. In `scrub_env_secrets`, skip a small NON-SECRET key allow-set so it doesn't redact `production`:

```python
_NON_SECRET_KEYS = frozenset({"ALFRED_ENVIRONMENT"})  # sec-007: values here are not secrets.
...
def scrub_env_secrets(text: str, env_file: Path) -> str:
    for line in env_file.read_text().splitlines():
        key, sep, value = line.partition("=")
        value = value.strip()
        if sep and value and key.strip() not in _NON_SECRET_KEYS:
            text = text.replace(value, "***REDACTED***")
    return text
```

- [ ] **Step 3: Verify** — `uv run pytest tests/unit/e2e/test_env.py -v` → PASS.

- [ ] **Step 4: Commit**

```bash
git add tests/e2e/_env.py tests/unit/e2e/test_env.py
git commit -m "test: #500 e2e env-file sets ALFRED_ENVIRONMENT=production; scrub skips it

<trailer>"
```

---

### Task 8: Flip `alfred-core` green — provision (migrate + operator seed) + posture + ratchet

**Files:**

- Create: `tests/e2e/_posture.py`
- Modify: `tests/e2e/test_first_run_boot.py:test_core_is_healthy` (+ drop `_XFAIL_HEALTH_TIMEOUT_S` for core)
- Modify: `tests/e2e/_services.py` (`alfred-core`: XFAIL → HEALTHY_APP)
- Modify: `tests/unit/e2e/test_services.py` (partition test — keep non-vacuous, test-005)
- Modify: `.github/workflows/nightly.yml` (fix the stale "real quarantine key" comment — devops-low)

**Interfaces:**

- Consumes: `tests._compose.compose`, `tests.e2e.conftest.BootStack`, `tests.e2e._health.ServiceHealth`.
- Produces: `tests.e2e._posture.assert_core_boot_posture(boot_stack) -> None`.

- [ ] **Step 1: Move `alfred-core` XFAIL → HEALTHY_APP in `_services.py`**

```python
HEALTHY_APP_SERVICES: frozenset[str] = frozenset({"alfred-gateway", "alfred-core"})
# Empty now: every boot-gating blocker has landed. Kept typed so a regression can re-add.
XFAIL_SERVICES: Mapping[str, str] = {}
```

- [ ] **Step 2: Update the partition unit test — keep it non-vacuous (test-005)**

```python
    assert app == {"alfred-gateway", "alfred-core"}
    assert xfail == set()
    # test-005: an empty xfail bucket makes the isdisjoint asserts trivially true, so ALSO
    # assert the concrete membership + that baseline/app carry the six and are non-empty —
    # the guard that actually catches a mis-move.
    assert baseline == {"alfred-postgres", "alfred-redis", "alfred-prometheus", "alfred-grafana"}
    assert (baseline | app | xfail) == {
        "alfred-postgres", "alfred-redis", "alfred-prometheus",
        "alfred-grafana", "alfred-gateway", "alfred-core",
    }
```

Run: `uv run pytest tests/unit/e2e/test_services.py -v` → PASS.

- [ ] **Step 3: Write the posture helper (sec-001/test-002 — NO tautological self-test)**

```python
# tests/e2e/_posture.py
"""Runtime boot-posture oracles for the un-xfail'd alfred-core (#500 sec-002).

Each property has its OWN concrete runtime observable on the BOOTED container — NOT
inferred from `healthy`. Distinct from tests/unit/test_compose_invariants.py, which pins
the static compose CONFIG (apparmor/seccomp present, internal network, SETUID).

NB (sec-001/test-002): the `bin/alfred-plugin-launcher.sh --self-test` answer is an
UNCONDITIONAL `printf 'policy-resolving'; exit 0` — it proves only the script was COPYed
in and would pass on a broken sandbox, so it is NOT used as the sandbox oracle. Instead we
functionally exercise the bwrap userns machinery the quarantine child actually depends on
(core-002: the daemon spawns that child under bwrap to reach healthy).
"""

from __future__ import annotations

import json
import subprocess

from tests import _compose
from tests.e2e.conftest import BootStack


def _core_container_id(boot_stack: BootStack) -> str:
    cid = _compose.compose(
        boot_stack.project, "ps", "-q", "alfred-core", env_file=boot_stack.env_file
    ).stdout.strip()
    assert cid, "alfred-core container not found — cannot assert boot posture."
    return cid


def assert_egress_chokepoint(boot_stack: BootStack) -> None:
    """Core is attached ONLY to the internal (internal:true) network — no external route."""
    cid = _core_container_id(boot_stack)
    inspect = subprocess.run(
        ["docker", "inspect", cid], cwd=_compose.REPO_ROOT,
        capture_output=True, text=True, timeout=30.0, check=True,
    )
    names = set(json.loads(inspect.stdout)[0]["NetworkSettings"]["Networks"])
    assert any(n.endswith("alfred_internal") for n in names), (
        f"alfred-core must join the internal network; got {sorted(names)}."
    )
    assert not any(n.endswith("alfred_external") for n in names), (
        f"alfred-core must NOT join alfred_external (connectivity-free core); got {sorted(names)}."
    )


def assert_capability_gate_seeded(boot_stack: BootStack) -> None:
    """The daemon boot seeded the first-party RealGate grants into Postgres (>0 rows)."""
    out = _compose.compose(
        boot_stack.project, "exec", "-T", "alfred-postgres",
        "psql", "-U", "alfred", "-d", "alfred", "-tAc",
        "select count(*) from plugin_grants",
        env_file=boot_stack.env_file,
    ).stdout.strip()
    assert out.isdigit() and int(out) > 0, (
        f"plugin_grants must be seeded by daemon boot; psql returned {out!r}."
    )


def assert_sandbox_machinery_live(boot_stack: BootStack) -> None:
    """bwrap can build an unprivileged userns INSIDE the running production container.

    Non-tautological with `healthy`: this exercises the SAME userns machinery the
    apparmor/seccomp profiles must permit and the quarantine child requires (core-002),
    independently of the daemon. A broken sandbox host fails HERE with a userns denial.
    """
    proc = _compose.compose(
        boot_stack.project, "exec", "-T", "alfred-core",
        "bwrap", "--ro-bind", "/", "/", "--unshare-user", "--uid", "0", "true",
        env_file=boot_stack.env_file, check=False,
    )
    assert proc.returncode == 0, (
        f"bwrap userns build failed inside alfred-core (sandbox machinery not live): "
        f"rc={proc.returncode} {proc.stderr[-400:]!r}"
    )


def assert_core_boot_posture(boot_stack: BootStack) -> None:
    assert_egress_chokepoint(boot_stack)
    assert_capability_gate_seeded(boot_stack)
    assert_sandbox_machinery_live(boot_stack)
```

> **SECURITY-ENGINEER SIGN-OFF (PR-time, owns the oracle — sec-001):** confirm this set
> satisfies sec-002. In particular decide whether to ADD a negative production-refusal probe
> (assert an unsandboxed / policy-less launcher spawn is DENIED in the running production
> container — which makes sec-003's `ALFRED_ENVIRONMENT=production` load-bearing for the
> sandbox axis) and/or a boot-audit assertion that the quarantine child spawned sandboxed.
> The hard constraint the design commits to: NO property asserted by `healthy` alone, and
> the `--self-test` tautology is NOT used.

- [ ] **Step 4: Rewrite `test_core_is_healthy` (provision migrate + OPERATOR SEED — core-001)**

```python
def test_core_is_healthy(boot_stack: BootStack) -> None:
    # #500: core boots in the shipped image (plugins/ COPYed hermetically, repo_root()
    # unified, policies.yaml pointed at /app/config). The tui-default comms graph builds the
    # real Orchestrator, which REFUSES boot on an unseeded operator (core-001) — so provision
    # BOTH a migrated DB AND an operator, mirroring bin/alfred-setup.sh. --no-deps: baseline
    # postgres/redis are already up; core reaches healthy without the gateway (verified).
    from tests.e2e import _posture

    _compose.compose(
        boot_stack.project, "run", "--rm", "--no-deps", "alfred-core", "migrate",
        env_file=boot_stack.env_file, timeout_s=_UP_TIMEOUT_S,
    )
    _compose.compose(
        boot_stack.project, "run", "--rm", "--no-deps", "alfred-core",
        "user", "add", "--name", "e2e-operator", "--authorization", "operator",
        "--daily-budget-usd", "1.0",
        env_file=boot_stack.env_file, timeout_s=_UP_TIMEOUT_S,
    )
    _compose.compose(
        boot_stack.project, "up", "-d", "--no-deps", "alfred-core",
        env_file=boot_stack.env_file, timeout_s=_UP_TIMEOUT_S,
    )
    assert boot_stack.health("alfred-core") is ServiceHealth.HEALTHY
    _posture.assert_core_boot_posture(boot_stack)  # sec-002: posture oracles, not bare-healthy.
```

Note (test-004): `_compose.compose` raises `CalledProcessError` on a non-zero `migrate`/`user add`, and the fixture's `except` re-raises a scrubbed tail — a provisioning failure surfaces loudly, not silently. Verify the `migrate`/`user add`/`up` calls use `check=True` (the `compose()` default) so a failure is not swallowed. Confirm the exact `user add` flags against `alfred user add --help` before running.

Remove the `@pytest.mark.xfail(...)` decorator and the now-unused `_XFAIL_HEALTH_TIMEOUT_S` constant so `health()` uses the full baseline budget.

- [ ] **Step 5: Fix the stale nightly.yml comment (devops-low)** — `.github/workflows/nightly.yml:67-70` says the real quarantine key is added "when core un-xfails"; this IS that transition and the dummy sentinel suffices for boot-to-healthy. Reword/remove the stale note.

- [ ] **Step 6: Local Linux verify (AUTHORITATIVE for this task)**

macOS cannot fully verify (apparmor / the live bwrap child spawn). On a Linux host (or the arm64-privileged docker repro with the `alfred-bwrap` AppArmor profile loaded):

Run: `uv run pytest tests/e2e/test_first_run_boot.py::test_core_is_healthy -v`
Expected: PASS — core healthy + all three posture assertions. Full lane: `make test-e2e` → **7 passed / 1 xfailed** (`test_setup_sh_completes` stays xfail on #501; gateway + core now assert healthy), tally OK.

- [ ] **Step 7: Commit**

```bash
git add tests/e2e/_posture.py tests/e2e/test_first_run_boot.py tests/e2e/_services.py tests/unit/e2e/test_services.py .github/workflows/nightly.yml
git commit -m "test: #500 flip alfred-core green — provision operator + runtime boot-posture oracles

<trailer>"
```

---

### Task 9: ADR-0055 — repo-root resolution convention

**Files:** Create `docs/adr/0055-repo-root-resolution.md`

- [ ] **Step 1: Write the ADR** — Status Accepted, Date 2026-07-25, Slice #469 Step 3 / #500. Relates to #494, #499, ADR-0036, the `i18n/translator.py` precedent, ADR-0053 (contrast: env-precedence NOT needed here — see trust model). Context: the non-editable-image `parents[N]` overshoot + the multi-depth drift #499 flagged. Decision: one `alfred._repo_root.repo_root()` honouring `ALFRED_REPO_ROOT` (deploy seam) with a marker-gated source-tree + `/app` fallback; all repo-root call sites route through it; the installed image never depends on `parents[N]`. **Trust model (sec-002/003):** `ALFRED_REPO_ROOT` is a process-env seam set by process-launch control (Dockerfile/operator), NOT a T3-reachable source, so it needs no `/etc`-vs-env precedence (contrast ADR-0053); the manifest-traversal containment guard re-anchors to the resolved root and is unchanged. **Scope boundaries (arch-003):** deliberately excludes `src/` COPY (the opt-in Discord/stdio adapter's `/app/src` need → follow-up); `hash_pepper`/`state.git` provisioning stays with setup.sh (non-boot-gating). Alternatives: per-module `parents[N]` fix (rejected — reproduces the drift); candidate-list-only à la translator.py (kept as fallback; explicit env seam is primary).

- [ ] **Step 2: Markdown-lint** — `npx markdownlint-cli2@0.22.1 "docs/adr/0055-*.md"` → clean.

- [ ] **Step 3: Commit**

```bash
git add docs/adr/0055-repo-root-resolution.md
git commit -m "docs: #500 ADR-0055 single repo-root resolution convention

<trailer>"
```

---

### Task 10: ADR-0056 — e2e boot-posture assertion contract

**Files:** Create `docs/adr/0056-e2e-boot-posture-assertions.md`

- [ ] **Step 1: Write the ADR (arch-001 — one decision per ADR)** — Status Accepted, Date 2026-07-25, Slice #469 Step 3 / #500. Relates to #494, #500 sec-002/003, ADR-0040 (connectivity-free core — the egress-isolation oracle encodes it). Context: un-xfailing the #494 core assertion must not regress to a bare `assert healthy` (not a security oracle). Decision: the e2e core-healthy assertion carries **runtime posture oracles**, each with its own observable on the booted container, none inferred from `healthy`: (1) egress chokepoint — core joins ONLY the internal (internal:true) network; (2) capability gate seeded — `plugin_grants` rows present in Postgres; (3) sandbox machinery live — bwrap can build a userns inside the running container (NOT the tautological launcher `--self-test`). `ALFRED_ENVIRONMENT=production` in the e2e env-file makes the sandbox refusals live (sec-003). Consequences: macOS cannot fully assert (3) (apparmor) → the Linux nightly is authoritative. Note the security-engineer may extend with a negative production-refusal probe. Alternatives: bare `assert healthy` (rejected — sec-002); compose-config-only pins (rejected — those are static, already unit-pinned, not runtime proof).

- [ ] **Step 2: Markdown-lint** — `npx markdownlint-cli2@0.22.1 "docs/adr/0056-*.md"` → clean.

- [ ] **Step 3: Commit**

```bash
git add docs/adr/0056-e2e-boot-posture-assertions.md
git commit -m "docs: #500 ADR-0056 e2e boot-posture assertion contract

<trailer>"
```

---

## Final verification (before PR)

- [ ] `uv run ruff check . && uv run ruff format --check .`
- [ ] `uv run mypy src/ && uv run pyright src/` (whole-tree)
- [ ] `uv run pytest tests/unit -q` (resolver, migrated `_REPO_ROOT`/`_LAUNCHER_PATH` tests, partition, Dockerfile/compose invariants, env)
- [ ] `uv run pytest tests/adversarial -q` (security modules touched — `cap-2026-012` + `cap-2026-004` green)
- [ ] **Explicit per-module coverage (NOT make check — #474):** 100% line+branch on `alfred.security.capability_gate._comms_adapter_grants` and `alfred.security.quarantine_child_io`
- [ ] `make check`
- [ ] Linux/arm64-privileged docker repro: hermetic build (clean `/app/plugins`) → full core boot to `healthy` → `tests/e2e/test_first_run_boot.py` core assertions green (`7 passed / 1 xfailed`)
- [ ] i18n drift gate (`pybabel extract` + `compile --check`) — no new `t()` keys, confirm no drift
- [ ] Security-engineer sign-off on the Task 8 posture-oracle set (sec-001)

## Self-review notes (spec coverage + fleet findings folded)

- Spec Part A → Tasks 1–4. Part B → Task 5 (+ `.dockerignore`). Part C → Task 6. Part D → Tasks 7, 8. Part E → Task 8. Part F → Task 8. Part G → Tasks 9, 10.
- **Fleet findings folded:** core-001 (Task 8 operator seed), test-001/sec-002 (per-module coverage gate — Global Constraints + Tasks 3/4), sec-001/test-002 (Task 8 sandbox oracle replaced + security sign-off), core-002 (Global Constraints boot-fact + Task 8 provisioning), arch-002 (Task 8 tally 7/1), rev-001/test-003 (Task 3 adversarial + `_LAUNCHER_PATH` migrations + default-branch test), rev-002/sec-004 (Task 2 direct-import migration), rev-003/test-006 (Task 6 `_service` fix), devops-001 (Task 5 `.dockerignore`), arch-001 (ADR split 0055/0056), arch-003/sec-002 (ADR trust model + scope), arch-004 (Task 4 default-branch tests), test-005 (Task 8 partition non-vacuity), test-007 (Task 5 runtime-stage test), test-008 (Task 6 stale comment), sec-007 (Task 7 scrub), devops-low (Task 8 nightly comment).
- Scope boundaries honoured: no `src/` COPY (Discord/stdio deferred → follow-up filed at PR time); `hash_pepper`/`state.git` untouched.
- Type consistency: `repo_root()` / `launcher_path()` / `_resolve()` / `assert_core_boot_posture()` used identically across tasks.
