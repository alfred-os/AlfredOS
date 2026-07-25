# #500 — alfred-core boots in the shipped image — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `alfred-core` boot to Docker `healthy` in the shipped (non-editable) image, in production mode, and ratchet the #494 e2e lane's `alfred-core` strict-xfail to green with runtime boot-posture assertions.

**Architecture:** Unify every hand-rolled `Path(__file__).parents[N]` "repo root" behind one `alfred._repo_root.repo_root()` that honours an `ALFRED_REPO_ROOT` deploy seam (set to `/app` by the Dockerfile) with a source-tree + `/app` fallback; COPY `plugins/` into the image; point the daemon at the shipped `policies.yaml`; provision `migrate` in the e2e core-healthy test; replace the xfail + bare `assert healthy` with runtime posture oracles (network isolation, capability-gate seeded, sandbox active).

**Tech Stack:** Python 3.14, pydantic-settings v2, Docker + Docker Compose, pytest (unit + nightly e2e), alembic.

## Global Constraints

- **Design spec (verbatim authority):** `docs/superpowers/specs/2026-07-25-500-core-boots-shipped-image-design.md`.
- **Python conventions:** modern 3.14 idioms, PEP 604/585/695, frozen/immutable by default, no `Any` without justification, `mypy --strict` + `pyright`, structlog. Use the `alfred-python-developer` conventions.
- **Whole-tree type gate:** run `uv run mypy src/` (NOT per-module) — the #499 pydantic-mypy-plugin lesson: a widely-constructed type breaks only under whole-tree mypy.
- **Security HARD rules:** touching `src/alfred/security/**` → the full adversarial suite runs (`uv run pytest tests/adversarial`). Never weaken the `validate_comms_adapter_ids` traversal guard (`is_relative_to(plugins/)`, `.`/`..` reject, charset) — `cap-2026-012` must stay green.
- **i18n:** operator-facing strings via `t()`. This change adds no new operator strings (repo-root resolution + Dockerfile/compose/test-only). Child-subprocess stderr + structlog event keys are NOT `t()` scope.
- **Conventional commits:** every commit subject carries a literal `#500` after the colon. End every commit message with `MrReasonable <4990954+MrReasonable@users.noreply.github.com>`.
- **Branch:** `500-core-boots-shipped-image` (already created; the design-spec commit is HEAD). Rebase-only repo — never `--admin` merge.
- **`make check` before every push.** The macOS integration lane is flaky under load — verify suspects in isolation; trust Linux CI.
- **Verification authority:** the Linux nightly End-to-end lane is authoritative for the shipped-image boot. macOS Docker-Desktop cannot load the `alfred-bwrap` AppArmor profile → the sandbox posture (and possibly boot) fails there via a different mechanism. Local shipped-image verification uses the Linux/arm64-privileged docker repro.

## File structure

| File | Responsibility |
|------|----------------|
| `src/alfred/_repo_root.py` (**new**) | The single repo-root resolver: `repo_root()` + pure `_resolve` helper |
| `src/alfred/config/settings.py` | validator uses `repo_root()`; drop the `_REPO_ROOT` const |
| `src/alfred/cli/_launcher_spawn.py` | `repo_root()` delegates to the shared resolver; expose `launcher_path()` |
| `src/alfred/security/capability_gate/_comms_adapter_grants.py` | grant-seed manifest read uses `repo_root()` |
| `src/alfred/cli/daemon/_daemon_probes.py` | launcher self-test resolves path via the shared `launcher_path()` (fixes const-ignores-env + wrong path) |
| `src/alfred/security/quarantine_child_io.py` | launcher default via shared resolver |
| `src/alfred/plugins/comms_stdio_transport.py` | launcher default via shared resolver |
| `src/alfred/gateway/adapter_child_factory.py` | launcher default via `repo_root()` |
| `docker/alfred-core.Dockerfile` | `COPY plugins/`; `ENV ALFRED_REPO_ROOT=/app` |
| `docker-compose.yaml` | `ALFRED_POLICIES_PATH` on `alfred-core` |
| `tests/e2e/_env.py` | e2e env-file adds `ALFRED_ENVIRONMENT=production` |
| `tests/e2e/test_first_run_boot.py` | provision `migrate`; un-xfail core with posture assertions |
| `tests/e2e/_posture.py` (**new**) | posture probe helpers (network / grants / sandbox) |
| `tests/e2e/_services.py` | `alfred-core`: XFAIL → HEALTHY_APP |
| `tests/unit/e2e/test_services.py` | partition test: xfail bucket empty |
| `tests/unit/test_repo_root.py` (**new**) | resolver unit tests |
| `tests/unit/test_dockerfile_invariants.py` (**new or extend**) | pin `plugins/` COPY + `ALFRED_REPO_ROOT` |
| `docs/adr/0055-repo-root-resolution-and-boot-posture.md` (**new**) | ADR |

---

### Task 1: The shared repo-root resolver

**Files:**
- Create: `src/alfred/_repo_root.py`
- Test: `tests/unit/test_repo_root.py`

**Interfaces:**
- Produces: `alfred._repo_root.repo_root() -> Path` and `alfred._repo_root._resolve(env_value: str | None, module_path: Path) -> Path`. Env var name constant `_REPO_ROOT_ENV = "ALFRED_REPO_ROOT"`.

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
    # Even a module_path whose parents[2] has no marker: the env value wins.
    assert _resolve("/deploy/root", Path("/x/y/z/_repo_root.py")) == Path("/deploy/root")


def test_resolve_blank_env_is_ignored(tmp_path: Path) -> None:
    # Whitespace-only env is treated as unset (falls through to source/fallback).
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
    # Installed layout: parents[2] has no plugins/ marker -> /app terminal fallback.
    (tmp_path / "lib" / "site-packages").mkdir(parents=True)
    module_path = tmp_path / "lib" / "site-packages" / "_repo_root.py"
    assert _resolve(None, module_path) == _CONTAINER_ROOT


def test_repo_root_finds_worktree_plugins_dir(monkeypatch) -> None:
    # Running under pytest from the worktree with no override: the real repo root
    # is returned and it contains plugins/.
    monkeypatch.delenv("ALFRED_REPO_ROOT", raising=False)
    root = repo_root()
    assert (root / "plugins").is_dir()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/unit/test_repo_root.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'alfred._repo_root'`.

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

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/unit/test_repo_root.py -v`
Expected: PASS (6 tests). Then `uv run pytest tests/unit/test_repo_root.py --cov=alfred._repo_root --cov-report=term-missing` → 100% line + branch.

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
- Test: `tests/unit/config/test_settings_comms_enabled_adapters.py`, `tests/unit/config/test_gateway_hosted_adapters_settings.py` (migrate `_REPO_ROOT` monkeypatch → `ALFRED_REPO_ROOT` env)

**Interfaces:**
- Consumes: `alfred._repo_root.repo_root` (Task 1).
- Produces: `validate_comms_adapter_ids` behaviour unchanged except the plugins-root is now `repo_root() / "plugins"`, re-read per validation call (honours `ALFRED_REPO_ROOT`).

- [ ] **Step 1: Update the failing test first (migrate the monkeypatch)**

In `tests/unit/config/test_settings_comms_enabled_adapters.py` and `test_gateway_hosted_adapters_settings.py`, find every `monkeypatch.setattr(settings_module, "_REPO_ROOT", tmp_path)` (or `monkeypatch.setattr("alfred.config.settings._REPO_ROOT", ...)`) and replace with `monkeypatch.setenv("ALFRED_REPO_ROOT", str(tmp_path))`. The test that builds a fake `plugins/<id>/manifest.toml` under `tmp_path` keeps doing so; only the pointing mechanism changes.

Run: `uv run pytest tests/unit/config/test_settings_comms_enabled_adapters.py -v`
Expected: FAIL (still references `_REPO_ROOT` or the validator still reads the old const).

- [ ] **Step 2: Edit `settings.py`**

Replace the module-level const block:

```python
# DELETE (lines ~49-55):
# _REPO_ROOT = Path(__file__).resolve().parents[3]
```

Add the import near the top imports:

```python
from alfred._repo_root import repo_root
```

In `validate_comms_adapter_ids` (`:124`), replace the two `_REPO_ROOT` uses:

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

Update the `_REPO_ROOT` block comment (`:49-54`) — it explained why NOT to import `_launcher_spawn`; replace with a one-line pointer to `alfred._repo_root`.

- [ ] **Step 3: Run the migrated tests**

Run: `uv run pytest tests/unit/config/test_settings_comms_enabled_adapters.py tests/unit/config/test_gateway_hosted_adapters_settings.py -v`
Expected: PASS.

- [ ] **Step 4: Whole-tree type + adversarial traversal gate**

Run: `uv run mypy src/ && uv run pytest tests/adversarial -k cap_2026_012 -v`
Expected: mypy clean; `cap-2026-012` traversal-refusal PASS.

- [ ] **Step 5: Commit**

```bash
git add src/alfred/config/settings.py tests/unit/config/
git commit -m "refactor: #500 settings validator resolves plugins/ via repo_root()

<trailer>"
```

---

### Task 3: Route the remaining boot-critical resolvers

**Files:**
- Modify: `src/alfred/cli/_launcher_spawn.py:54-66` (delegate `repo_root`; expose `launcher_path()`)
- Modify: `src/alfred/security/capability_gate/_comms_adapter_grants.py:95-155` (use `repo_root()`)
- Modify: `src/alfred/cli/daemon/_daemon_probes.py:89-91,111` (resolve launcher via shared `launcher_path()`)
- Test: the modules' existing tests (migrate `_REPO_ROOT` monkeypatches → env), plus a new probe-honours-env test.

**Interfaces:**
- Consumes: `alfred._repo_root.repo_root` (Task 1).
- Produces: `alfred.cli._launcher_spawn.repo_root() -> Path` (delegates), `alfred.cli._launcher_spawn.launcher_path() -> str` (public; honours `ALFRED_PLUGIN_LAUNCHER` else `repo_root()/bin/alfred-plugin-launcher.sh`).

- [ ] **Step 1: `_launcher_spawn.py` — delegate + expose `launcher_path`**

Replace the body of `repo_root()` (keep the name/signature — `main.py`, `_comms_boot.py`, `gateway/_commands.py` import it):

```python
from alfred._repo_root import repo_root as _resolve_repo_root


def repo_root() -> Path:
    """Repo root that ships ``bin/`` and ``plugins/`` (delegates to the single
    resolver — #500). Kept as a thin wrapper so existing importers and test
    patches of ``_launcher_spawn.repo_root`` keep working."""
    return _resolve_repo_root()


def launcher_path() -> str:
    """The plugin-launcher path: ``ALFRED_PLUGIN_LAUNCHER`` override else the
    in-tree default. Public so daemon-boot probe (a) shares ONE resolution."""
    return os.environ.get(_LAUNCHER_ENV_VAR, str(repo_root() / "bin" / "alfred-plugin-launcher.sh"))
```

Repoint the existing private `_launcher_path()` to call `launcher_path()` (or replace its callers). Add `"launcher_path"` to `__all__` (`:289`).

- [ ] **Step 2: `_comms_adapter_grants.py` — use `repo_root()`**

Replace the `_REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[4]` const (`:100`) — delete it — and in the manifest-reading function (`:151-155`) use:

```python
from alfred._repo_root import repo_root
...
    root = repo_root()  # #500: fresh per call (honours ALFRED_REPO_ROOT / test patches).
    plugins_root = (root / "plugins").resolve()
    ...
        manifest_path = root / "plugins" / adapter_id / "manifest.toml"
```

Keep the existing containment/charset guards byte-for-byte.

- [ ] **Step 3: `_daemon_probes.py` — resolve the launcher via the shared path**

Replace the module const (`:89-91`):

```python
# DELETE: _LAUNCHER_PATH = Path(__file__).resolve().parents[4] / "bin" / "alfred-plugin-launcher.sh"
```

In `_launcher_self_test_impl` (`:111`), resolve per call so the path is image-correct AND `ALFRED_PLUGIN_LAUNCHER` is honoured (the const-ignores-env bug):

```python
from alfred.cli._launcher_spawn import launcher_path
...
    launcher = launcher_path()  # #500: image-correct + env-overridable (was a wrong-path const).
    # ... exec `launcher --self-test` exactly as before, using `launcher` ...
```

- [ ] **Step 4: Migrate tests + add the env-honour test**

Migrate any `_REPO_ROOT` / `_LAUNCHER_PATH` monkeypatch in the affected modules' tests to `monkeypatch.setenv("ALFRED_REPO_ROOT", ...)` / `monkeypatch.setenv("ALFRED_PLUGIN_LAUNCHER", ...)`. Add to the daemon-probes test file:

```python
def test_launcher_self_test_honours_env_override(monkeypatch, tmp_path) -> None:
    # #500: probe (a) must exec ALFRED_PLUGIN_LAUNCHER, not a parents[N] const.
    fake = tmp_path / "my-launcher.sh"
    fake.write_text("#!/bin/sh\n")
    monkeypatch.setenv("ALFRED_PLUGIN_LAUNCHER", str(fake))
    from alfred.cli._launcher_spawn import launcher_path
    assert launcher_path() == str(fake)
```

Run: `uv run pytest tests/unit/cli/ tests/unit/security/ -k "launcher or comms_adapter_grant or daemon_prob" -v`
Expected: PASS.

- [ ] **Step 5: Whole-tree gates + commit**

Run: `uv run mypy src/ && uv run pytest tests/adversarial -q`
Expected: clean (security modules touched → full adversarial suite).

```bash
git add src/alfred/cli/_launcher_spawn.py src/alfred/security/capability_gate/_comms_adapter_grants.py src/alfred/cli/daemon/_daemon_probes.py tests/
git commit -m "refactor: #500 boot-critical resolvers share repo_root()/launcher_path()

<trailer>"
```

---

### Task 4: Route the remaining security/gateway resolvers (finish unify-all)

**Files:**
- Modify: `src/alfred/security/quarantine_child_io.py:238-252`
- Modify: `src/alfred/plugins/comms_stdio_transport.py:69-83`
- Modify: `src/alfred/gateway/adapter_child_factory.py:269`
- Test: migrate any `_repo_root` patches in their tests to `ALFRED_REPO_ROOT` / `ALFRED_PLUGIN_LAUNCHER`.

**Interfaces:**
- Consumes: `alfred._repo_root.repo_root` / `alfred.cli._launcher_spawn.launcher_path` (Tasks 1, 3).

- [ ] **Step 1: `quarantine_child_io.py`** — replace the local `_repo_root()` (`:238-247`) body with `from alfred._repo_root import repo_root` and use `repo_root()` where the launcher default is built (`:251-252`). Preserve the `ALFRED_PLUGIN_LAUNCHER` override.

- [ ] **Step 2: `comms_stdio_transport.py`** — same treatment (`:69-83`): local `_repo_root()` delegates to `repo_root()`; keep the `_LAUNCHER_ENV_VAR` override.

- [ ] **Step 3: `adapter_child_factory.py:269`** — replace the inline `Path(__file__).resolve().parents[3] / "bin" / "alfred-plugin-launcher.sh"` with `repo_root() / "bin" / "alfred-plugin-launcher.sh"` (`from alfred._repo_root import repo_root`).

- [ ] **Step 4: Migrate tests + run gates**

Run: `uv run pytest tests/unit/security/ tests/unit/plugins/ tests/unit/gateway/ -q && uv run mypy src/ && uv run pytest tests/adversarial -q`
Expected: PASS / clean.

- [ ] **Step 5: Commit**

```bash
git add src/alfred/security/quarantine_child_io.py src/alfred/plugins/comms_stdio_transport.py src/alfred/gateway/adapter_child_factory.py tests/
git commit -m "refactor: #500 finish unify-all — every repo-root resolver shares one source

<trailer>"
```

---

### Task 5: Dockerfile — COPY `plugins/` + `ALFRED_REPO_ROOT`

**Files:**
- Modify: `docker/alfred-core.Dockerfile` (runtime stage, ~`:183-196` region + the runtime `ENV` block ~`:102-113`)
- Test: `tests/unit/test_dockerfile_invariants.py` (new; parse the Dockerfile text)

**Interfaces:** none exported.

- [ ] **Step 1: Write the failing invariant test**

```python
# tests/unit/test_dockerfile_invariants.py
"""Static pins on docker/alfred-core.Dockerfile (#500)."""

from __future__ import annotations

from pathlib import Path

import pytest

_DOCKERFILE = Path(__file__).resolve().parents[2] / "docker" / "alfred-core.Dockerfile"


@pytest.fixture
def dockerfile_text() -> str:
    return _DOCKERFILE.read_text()


def test_runtime_stage_copies_plugins(dockerfile_text: str) -> None:
    # #500: plugins/ is a runtime artifact (the daemon reads plugins/<id>/manifest.toml
    # by path); without this COPY the comms-adapter validator refuses every Settings().
    assert "COPY plugins ./plugins" in dockerfile_text


def test_runtime_stage_sets_repo_root_env(dockerfile_text: str) -> None:
    # #500: the deploy seam so the installed image never depends on parents[N].
    assert "ALFRED_REPO_ROOT=/app" in dockerfile_text
```

Run: `uv run pytest tests/unit/test_dockerfile_invariants.py -v`
Expected: FAIL (neither string present).

- [ ] **Step 2: Edit the Dockerfile**

In the runtime stage `ENV` block (after `ALFRED_QUARANTINE_CHILD_PYTHON=...`), add:

```dockerfile
    # #500: the repo-root deploy seam (alfred._repo_root.repo_root). WORKDIR is /app
    # and plugins/bin/config/alembic.ini are COPYed there; the non-editable install
    # means parents[N] arithmetic overshoots into site-packages, so pin the root here.
    ALFRED_REPO_ROOT=/app
```

In the runtime stage's runtime-artefacts COPY block (near `COPY config ./config`), add:

```dockerfile
# #500: plugins/ is a RUNTIME artifact — the daemon resolves plugins/<id>/manifest.toml
# by path (comms-adapter validator + first-party grant seed). The wheel does NOT carry
# it, so COPY it into /app alongside config/bin/locale.
COPY plugins ./plugins
```

(The existing `RUN chown -R alfred:alfred /app` covers it.)

- [ ] **Step 3: Run the invariant test**

Run: `uv run pytest tests/unit/test_dockerfile_invariants.py -v`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add docker/alfred-core.Dockerfile tests/unit/test_dockerfile_invariants.py
git commit -m "build: #500 COPY plugins/ into image + ALFRED_REPO_ROOT=/app seam

<trailer>"
```

---

### Task 6: Compose — point the daemon at the shipped `policies.yaml`

**Files:**
- Modify: `docker-compose.yaml` (`alfred-core` `environment:` block, ~`:140-210`)
- Test: `tests/unit/test_compose_invariants.py` (add one pin)

**Interfaces:** none.

- [ ] **Step 1: Write the failing invariant test**

```python
# add to tests/unit/test_compose_invariants.py
def test_alfred_core_points_policies_path_at_shipped_config(compose: dict[str, Any]) -> None:
    # #500 probe (b): the daemon loads policies.yaml at boot. settings.policies_path
    # defaults to /etc/alfred/policies.yaml (not provisioned in the image); the image
    # ships it at /app/config/policies.yaml, so compose must override the path there or
    # the daemon refuses boot in production with snapshot_ref_init_failed.
    env = _service(compose, "alfred-core").get("environment", {})
    val = env.get("ALFRED_POLICIES_PATH", "")
    assert "/app/config/policies.yaml" in val, (
        "alfred-core must set ALFRED_POLICIES_PATH to the in-image /app/config/policies.yaml."
    )
```

(Reuse the file's existing `_service`/`compose` fixtures; match their helper names.)

Run: `uv run pytest tests/unit/test_compose_invariants.py::test_alfred_core_points_policies_path_at_shipped_config -v`
Expected: FAIL (key absent).

- [ ] **Step 2: Edit `docker-compose.yaml`**

Add to the `alfred-core` `environment:` block (near the other `ALFRED_*` boot vars):

```yaml
      # #500 probe (b): the daemon loads policies.yaml at boot. settings.policies_path
      # defaults to the bare-host /etc/alfred/policies.yaml, which the image does not
      # provision; the Dockerfile COPYs it to /app/config/policies.yaml, so point the
      # documented ALFRED_POLICIES_PATH override there. In production a missing policies
      # file refuses boot (snapshot_ref_init_failed) — this is what lets core reach healthy.
      ALFRED_POLICIES_PATH: ${ALFRED_POLICIES_PATH:-/app/config/policies.yaml}
```

- [ ] **Step 3: Run the invariant test**

Run: `uv run pytest tests/unit/test_compose_invariants.py -v`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add docker-compose.yaml tests/unit/test_compose_invariants.py
git commit -m "build: #500 point alfred-core at the in-image /app/config/policies.yaml

<trailer>"
```

---

### Task 7: e2e env-file — explicit `ALFRED_ENVIRONMENT=production`

**Files:**
- Modify: `tests/e2e/_env.py:write_e2e_env_file`
- Test: `tests/unit/e2e/test_env.py` (new or extend) — assert the env-file line is written

**Interfaces:**
- Produces: the e2e env-file now carries `ALFRED_ENVIRONMENT=production` (sec-003).

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/e2e/test_env.py
from pathlib import Path

from tests.e2e import _env


def test_e2e_env_file_sets_production(tmp_path: Path) -> None:
    # sec-003: the posture assertions must test the REAL production gate, not an
    # implicit compose default — pin the env-file makes it explicit.
    env_file = _env.write_e2e_env_file(tmp_path)
    text = env_file.read_text()
    assert "ALFRED_ENVIRONMENT=production" in text
```

Run: `uv run pytest tests/unit/e2e/test_env.py -v`
Expected: FAIL.

- [ ] **Step 2: Edit `_env.py`**

Add to the `lines` tuple in `write_e2e_env_file`:

```python
        "ALFRED_ENVIRONMENT=production",  # sec-003 (#500): posture tests the real gate.
```

- [ ] **Step 3: Run tests**

Run: `uv run pytest tests/unit/e2e/test_env.py -v`
Expected: PASS. (`scrub_env_secrets` still redacts the random GF password + dummy keys — `production` is not a secret, so its appearance in logs is fine.)

- [ ] **Step 4: Commit**

```bash
git add tests/e2e/_env.py tests/unit/e2e/test_env.py
git commit -m "test: #500 e2e env-file sets ALFRED_ENVIRONMENT=production (sec-003)

<trailer>"
```

---

### Task 8: Flip `alfred-core` green — provision + posture assertions + ratchet

**Files:**
- Create: `tests/e2e/_posture.py`
- Modify: `tests/e2e/test_first_run_boot.py:test_core_is_healthy` (+ remove the shrunken `_XFAIL_HEALTH_TIMEOUT_S` usage for core)
- Modify: `tests/e2e/_services.py` (`alfred-core`: XFAIL → HEALTHY_APP)
- Modify: `tests/unit/e2e/test_services.py` (partition test)

**Interfaces:**
- Consumes: `tests._compose.compose`, `tests.e2e.conftest.BootStack`, `tests.e2e._health.ServiceHealth`.
- Produces: `tests.e2e._posture.assert_core_boot_posture(boot_stack) -> None`.

- [ ] **Step 1: Move `alfred-core` XFAIL → HEALTHY_APP in `_services.py`**

```python
HEALTHY_APP_SERVICES: frozenset[str] = frozenset({"alfred-gateway", "alfred-core"})

# Empty now: every roadmap blocker with a boot-gating xfail has landed. The map stays
# (typed Mapping) so a future regression can re-add an entry without a shape change.
XFAIL_SERVICES: Mapping[str, str] = {}
```

- [ ] **Step 2: Update the partition unit test**

In `tests/unit/e2e/test_services.py::test_baseline_app_and_xfail_partition_covers_the_six`:

```python
    assert app == {"alfred-gateway", "alfred-core"}
    assert xfail == set()
    # An empty xfail bucket is still a valid partition: disjoint from all, union covers six.
```

Keep the three `isdisjoint` assertions (empty set is disjoint from everything) and the `known == {the six}` assertion.

Run: `uv run pytest tests/unit/e2e/test_services.py -v`
Expected: PASS.

- [ ] **Step 3: Write the posture helper**

```python
# tests/e2e/_posture.py
"""Runtime boot-posture oracles for the un-xfail'd alfred-core (#500 sec-002).

Each property has its OWN concrete runtime observable on the BOOTED container —
NOT inferred from `healthy`. Distinct from tests/unit/test_compose_invariants.py,
which pins the static compose CONFIG (apparmor/seccomp present, internal network,
SETUID) rather than the running-container runtime facts asserted here.
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
    networks = json.loads(inspect.stdout)[0]["NetworkSettings"]["Networks"]
    names = set(networks)
    assert any(n.endswith("alfred_internal") for n in names), (
        f"alfred-core must join the internal network; got {sorted(names)}."
    )
    assert not any(n.endswith("alfred_external") for n in names), (
        f"alfred-core must NOT join alfred_external (connectivity-free core); got {sorted(names)}."
    )


def assert_capability_gate_seeded(boot_stack: BootStack) -> None:
    """The daemon boot seeded the first-party RealGate grants into Postgres."""
    out = _compose.compose(
        boot_stack.project, "exec", "-T", "alfred-postgres",
        "psql", "-U", "alfred", "-d", "alfred", "-tAc",
        "select count(*) from plugin_grants",
        env_file=boot_stack.env_file,
    ).stdout.strip()
    assert out.isdigit() and int(out) > 0, (
        f"plugin_grants must be seeded by daemon boot; psql returned {out!r}."
    )


def assert_sandbox_active(boot_stack: BootStack) -> None:
    """The plugin launcher resolves policy inside the running image (probe-a check)."""
    proc = _compose.compose(
        boot_stack.project, "exec", "-T", "alfred-core",
        "/app/bin/alfred-plugin-launcher.sh", "--self-test",
        env_file=boot_stack.env_file, check=False,
    )
    assert proc.returncode == 0, (
        f"launcher --self-test failed inside alfred-core (sandbox not policy-resolving): "
        f"rc={proc.returncode} {proc.stderr[-400:]!r}"
    )


def assert_core_boot_posture(boot_stack: BootStack) -> None:
    assert_egress_chokepoint(boot_stack)
    assert_capability_gate_seeded(boot_stack)
    assert_sandbox_active(boot_stack)
```

> **NOTE for the security reviewer (plan-review + PR-review):** confirm this
> oracle set is sufficient for sec-002 — in particular whether `assert_sandbox_active`
> should additionally assert an audited boot event, whether `--self-test` is the
> right launcher contract, and whether the egress assertion wants a complementary
> negative probe. Adjust the helper accordingly; the design commits only to "no
> property asserted by `healthy` alone."

- [ ] **Step 4: Rewrite `test_core_is_healthy`**

```python
def test_core_is_healthy(boot_stack: BootStack) -> None:
    # #500 landed: core boots in the shipped image (plugins/ COPYed, repo_root() unified,
    # policies.yaml pointed at /app/config). Provision the DB first (mirrors setup.sh's
    # migrate step) — daemon start does NOT auto-migrate and the first-party grant seed
    # writes plugin_grants. --no-deps: postgres/redis are already up (baseline).
    from tests.e2e import _posture

    _compose.compose(
        boot_stack.project, "run", "--rm", "--no-deps", "alfred-core", "migrate",
        env_file=boot_stack.env_file, timeout_s=_UP_TIMEOUT_S,
    )
    _compose.compose(
        boot_stack.project, "up", "-d", "--no-deps", "alfred-core",
        env_file=boot_stack.env_file, timeout_s=_UP_TIMEOUT_S,
    )
    assert boot_stack.health("alfred-core") is ServiceHealth.HEALTHY
    # sec-002: posture oracles — NOT a bare assert-healthy.
    _posture.assert_core_boot_posture(boot_stack)
```

Remove the `@pytest.mark.xfail(...)` decorator and the now-unused `_XFAIL_HEALTH_TIMEOUT_S` constant (or leave the constant only if `test_setup_sh_completes` still needs it — it does not; delete it and let `health()` use the default full budget).

- [ ] **Step 5: Local Linux verify (authoritative for this task)**

macOS cannot fully verify (apparmor). On a Linux host (or the arm64-privileged docker repro), run:

Run: `uv run pytest tests/e2e/test_first_run_boot.py::test_core_is_healthy -v` (Docker required)
Expected: PASS — core healthy + all three posture assertions. Also run the full lane: `make test-e2e` → 6 passed / 2 xfailed (`test_setup_sh_completes` stays xfail on #501; the gateway + core now assert healthy), tally OK.

- [ ] **Step 6: Commit**

```bash
git add tests/e2e/_posture.py tests/e2e/test_first_run_boot.py tests/e2e/_services.py tests/unit/e2e/test_services.py
git commit -m "test: #500 flip alfred-core green with runtime boot-posture oracles

<trailer>"
```

---

### Task 9: ADR-0055

**Files:**
- Create: `docs/adr/0055-repo-root-resolution-and-boot-posture.md`

- [ ] **Step 1: Write the ADR**

Sections: Status (Accepted), Date (2026-07-25), Slice (#469 Step 3 / #500), Relates to (#494, #499, ADR-0036, `i18n/translator.py` precedent). Context: the non-editable-image `parents[N]` overshoot + the multi-depth drift #499 flagged. Decision 1: one `alfred._repo_root.repo_root()` honouring `ALFRED_REPO_ROOT` (deploy seam) with source-tree + `/app` fallback; all repo-root call sites route through it; the installed image never depends on `parents[N]`. Decision 2: the e2e core-healthy assertion carries runtime posture oracles (network isolation, gate seeded, sandbox active), never a bare `assert healthy`. Consequences: drift removed; a new repo-root consumer imports the resolver; the Dockerfile owns the seam value. Alternatives considered: per-module `parents[N]` fix (rejected — reproduces the drift), candidate-list-only à la translator.py (kept as fallback, but the explicit env seam is primary).

- [ ] **Step 2: Markdown-lint**

Run: `npx markdownlint-cli2@0.22.1 "docs/adr/0055-*.md"`
Expected: clean (MD004/MD032/MD031).

- [ ] **Step 3: Commit**

```bash
git add docs/adr/0055-repo-root-resolution-and-boot-posture.md
git commit -m "docs: #500 ADR-0055 repo-root resolution + boot-posture assertion contract

<trailer>"
```

---

## Final verification (before PR)

- [ ] `uv run ruff check . && uv run ruff format --check .`
- [ ] `uv run mypy src/ && uv run pyright src/` (whole-tree)
- [ ] `uv run pytest tests/unit -q` (incl. the migrated `_REPO_ROOT` tests, partition test, Dockerfile/compose invariants, resolver tests)
- [ ] `uv run pytest tests/adversarial -q` (security modules touched — `cap-2026-012` green)
- [ ] `make check`
- [ ] Linux/arm64-privileged docker repro: full core boot to `healthy` + `tests/e2e/test_first_run_boot.py` core assertions green
- [ ] i18n drift gate (no new `t()` keys expected, but run `pybabel extract` + `compile --check` to confirm no drift)

## Self-review notes (spec coverage)

- Spec Part A → Tasks 1–4. Part B → Task 5. Part C → Task 6. Part D → Tasks 7, 8. Part E → Task 8. Part F → Task 8. Part G → Task 9. All covered.
- Scope boundaries honoured: no `src/` COPY (Discord/stdio deferred → follow-up filed at PR time); `hash_pepper`/`state.git` untouched.
- Type consistency: `repo_root()` / `launcher_path()` names used identically across Tasks 1/3/4/8.
