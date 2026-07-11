# Cross-platform unit-test CI — Phase A Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Run the unit suite on the macOS CI leg (blocking) and the Windows CI leg (informational), by cleanly separating the Docker-daemon-dependent unit tests so they auto-skip on daemon-less runners instead of erroring — closing the macOS half of the #246 OS-matrix gap.

**Architecture:** The only unit files that need a live Docker daemon are the 4 `tests/unit/plugins/web_fetch/` Testcontainers files (verified empirically — see the note below). Mark them `pytest.mark.docker`; add a root-conftest collection hook that turns those marks into clean *skips* when no daemon is reachable; add a static anti-rot guard so a future unmarked Docker test can't silently re-break the macOS leg; DRY the two existing inline Docker probes into one shared helper the hook reuses. Then wire a unit step into each `python-cross-os` matrix leg — macOS blocking (proven green), Windows `continue-on-error` (informational-first, promoted to blocking in Phase B / #246 Part 1).

**Tech Stack:** pytest (collection hooks, markers), Testcontainers, GitHub Actions matrix jobs, uv, ruff, mypy/pyright.

> **PLAN-TIME CORRECTION (authoritative — overrides spec §6).** The ratified spec (`docs/superpowers/specs/2026-07-11-macos-unit-crossplatform-ci-design.md`) §6 lists "~12" Docker-backed unit files. A precise re-grep + an **empirical daemon-less run** proved that number is a grep-for-the-word artifact: most of those files only *mention* "testcontainers" in prose to explain they **deliberately avoid** it (`"NOT an integration test — pulls no testcontainers"`, `"a double rather than testcontainers"`, `":class:`testcontainers...`"` docstring cross-refs). The **only** files that instantiate a container (and therefore ERROR without a daemon) are these **4**:
>
> - `tests/unit/plugins/web_fetch/test_canary_scanner_host_side.py`
> - `tests/unit/plugins/web_fetch/test_content_handle_single_use.py`
> - `tests/unit/plugins/web_fetch/test_handle_cap.py`
> - `tests/unit/plugins/web_fetch/test_lua_atomic_rate_limit.py`
>
> Empirical proof (this Darwin box, `DOCKER_HOST=tcp://127.0.0.1:1`): `test_handle_cap.py` → **32 errors**; the four "docker"-named text-parsers (`test_dockerfile_bubblewrap_present.py`, `config/test_settings.py`, `test_compose_invariants.py`, `test_seccomp_profile_drift.py`) → **61 passed** (they `read_text()` / `yaml.safe_load()` files — no daemon). `tests/unit/conftest.py`'s "testcontainers" line is a **vestigial docstring** — its `session_factory` uses `create_engine("sqlite:///:memory:")`. **Do NOT mark it.** Re-run the sweep in Task B Step 1 to confirm the set is still exactly these 4 before marking.

## Global Constraints

- **Python 3.14+ idioms.** `from __future__ import annotations` at the top of every new module; PEP 604 unions (`str | None`), never `Optional`; PEP 585 built-in generics (`list[...]`).
- **Type hygiene.** Keep every new/edited file mypy-strict + pyright clean (the CI type gate is `src/` only, but keep tests typed).
- **Ruff.** `uv run ruff check .` and `uv run ruff format --check .` must pass; remove any import that ruff flags F401 after a deletion.
- **Conventional commits — HARD.** Every commit subject MUST contain the literal `#246` **after the colon** (a `(246)` scope does NOT satisfy the required `Conventional commit format` check). E.g. `test(ci): #246 add shared docker-availability probe helper`.
- **i18n — not in scope here.** All strings in this plan are test/CI-side skip reasons and diagnostics, NOT `src/alfred/` operator-facing strings, so `t()` does NOT apply and there are no catalog changes. (i18n rules govern `src/alfred/` only.)
- **Markdown lint.** The `docs/ci/required-checks.md` edit (Task D) must pass `markdownlint-cli2` (MD032 list-blank-lines, MD031 fence-blank-lines, MD004 dash bullets, MD060 table separators).
- **Git hygiene.** Never `git add -A`; stage named paths only. Run `make check` before any eventual push (push/PR is a later, user-gated step outside this plan).
- **Marking granularity is module-level** (`pytestmark = pytest.mark.docker`), matching the spec. Trade-off (accepted): the pure-logic tests co-located in those 4 files also skip on the daemon-less legs — this is **not** a handful (≈15 in `test_canary_scanner_host_side.py`, ≈10 in `test_handle_cap.py`: frozen-dataclass, blank-token, config-validation, `_sanitize_url_for_log` cases). Linux (the release gate) still runs them, so no release coverage is lost; if a specific pure test is wanted on the macOS divergence leg, the lever is to relocate it to an unmarked sibling module. Module-level marking keeps the anti-rot guard's file-level detection simple and rot-proof.
- **Container fixtures live in test modules, NEVER in a `conftest.py`.** A `pytestmark` in a `conftest.py` does not apply to sibling modules' items, so a Testcontainers fixture hoisted into a conftest cannot be skip-marked and would ERROR on the daemon-less legs — silently defeating the whole separation. The anti-rot guard (Task B) enforces this. (The 4 target files each define their own byte-identical module-scoped `redis_url` fixture; the repo's DRY discipline makes hoisting it tempting — this constraint is why the guard must forbid it, not just enforce marking.)

---

### Task A: Shared Docker-availability probe (DRY)

Two inline Docker probes exist today: `tests/smoke/test_slice4_graduation.py::_docker_available` (`-> bool`, `docker info`) and `tests/integration/test_alfred_core_image_bwrap.py::_docker_unavailable_reason` (`-> str | None`, `docker version --format`, richer diagnostics). Lift ONE shared helper (the richer reason-returning form + a bool wrapper), refactor both call sites onto it, and unit-test it. The root-conftest hook (Task C) also consumes it.

**Files:**

- Create: `tests/_docker_probe.py`
- Create: `tests/unit/meta/__init__.py` (empty — keeps the meta dir a package, matching the 35 existing `__init__.py` under `tests/unit`)
- Create: `tests/unit/meta/test_docker_probe.py`
- Modify: `tests/smoke/test_slice4_graduation.py` (delete local `_docker_available`, delegate)
- Modify: `tests/integration/test_alfred_core_image_bwrap.py` (delete local `_docker_unavailable_reason`, delegate)

**Interfaces:**

- Produces: `tests._docker_probe.docker_unavailable_reason() -> str | None` (lru_cache'd; `None` == daemon reachable) and `tests._docker_probe.docker_available() -> bool` (`== docker_unavailable_reason() is None`). Task C imports `docker_available`.

- [ ] **Step 1: Write the failing probe test**

Create `tests/unit/meta/__init__.py` (empty file), then create `tests/unit/meta/test_docker_probe.py`:

```python
"""Unit tests for the shared Docker-availability probe."""

from __future__ import annotations

import subprocess
from collections.abc import Iterator

import pytest

from tests import _docker_probe
from tests._docker_probe import docker_available, docker_unavailable_reason


@pytest.fixture(autouse=True)
def _clear_probe_cache() -> Iterator[None]:
    """The probe is lru_cache'd; clear on BOTH sides so a monkeypatched value from
    one test can't bleed into the smoke/integration probes later in the session."""
    docker_unavailable_reason.cache_clear()
    yield
    docker_unavailable_reason.cache_clear()


def test_reason_when_binary_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_docker_probe.shutil, "which", lambda _name: None)
    assert docker_unavailable_reason() == "docker binary not on PATH"
    docker_unavailable_reason.cache_clear()
    assert docker_available() is False


def test_reason_none_when_daemon_reachable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_docker_probe.shutil, "which", lambda _name: "/usr/bin/docker")
    monkeypatch.setattr(
        _docker_probe.subprocess,
        "run",
        lambda *a, **k: subprocess.CompletedProcess(a[0], 0, b"27.0.0", b""),
    )
    assert docker_unavailable_reason() is None
    docker_unavailable_reason.cache_clear()
    assert docker_available() is True


def test_reason_on_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_docker_probe.shutil, "which", lambda _name: "/usr/bin/docker")

    def _raise_timeout(*_a: object, **_k: object) -> object:
        raise subprocess.TimeoutExpired(cmd=["docker"], timeout=10.0)

    monkeypatch.setattr(_docker_probe.subprocess, "run", _raise_timeout)
    reason = docker_unavailable_reason()
    assert reason is not None
    assert "timed out" in reason


def test_reason_on_nonzero_exit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_docker_probe.shutil, "which", lambda _name: "/usr/bin/docker")
    monkeypatch.setattr(
        _docker_probe.subprocess,
        "run",
        lambda *a, **k: subprocess.CompletedProcess(a[0], 1, b"", b"Cannot connect"),
    )
    reason = docker_unavailable_reason()
    assert reason is not None
    assert "exit 1" in reason


def test_reason_on_oserror(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_docker_probe.shutil, "which", lambda _name: "/usr/bin/docker")

    def _raise_oserror(*_a: object, **_k: object) -> object:
        raise OSError("boom")

    monkeypatch.setattr(_docker_probe.subprocess, "run", _raise_oserror)
    reason = docker_unavailable_reason()
    assert reason is not None
    assert "OSError" in reason
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/unit/meta/test_docker_probe.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'tests._docker_probe'`.

- [ ] **Step 3: Create the shared probe module**

Create `tests/_docker_probe.py`:

```python
"""Shared Docker-daemon availability probe for the test suite.

DRY home for the two probes that previously lived inline in
``tests/smoke/test_slice4_graduation.py`` and
``tests/integration/test_alfred_core_image_bwrap.py``. The root
``tests/conftest.py`` collection hook also consumes it to auto-skip
``docker``-marked tests on a daemon-less runner (the macOS / Windows CI
legs), which is what lets ``tests/unit`` run on those platforms instead of
erroring at Testcontainers fixture setup.

The probe is bounded (a misconfigured Docker context can make the CLI hang)
and cached so a session pays the subprocess cost once. Tests that exercise
the probe itself must call ``docker_unavailable_reason.cache_clear()`` first.
"""

from __future__ import annotations

import shutil
import subprocess
from functools import lru_cache

_PROBE_TIMEOUT_S = 10.0


@lru_cache(maxsize=1)
def docker_unavailable_reason() -> str | None:
    """Return ``None`` when a Docker daemon is reachable, else a short reason.

    The reason string keeps flaky-daemon vs absent-daemon distinguishable in
    CI logs (PR #217 error-reviewer closure). Probes the SERVER (not just the
    client) via ``docker version --format {{.Server.Version}}`` so a present
    CLI with no daemon still reports unavailable.
    """
    if shutil.which("docker") is None:
        return "docker binary not on PATH"
    try:
        proc = subprocess.run(
            ["docker", "version", "--format", "{{.Server.Version}}"],
            capture_output=True,
            check=False,
            timeout=_PROBE_TIMEOUT_S,
        )
    except subprocess.TimeoutExpired:
        return f"docker version probe timed out after {_PROBE_TIMEOUT_S:.0f}s (daemon hung?)"
    except OSError as exc:
        return f"docker version probe raised OSError: {exc}"
    if proc.returncode != 0:
        return (
            f"docker version probe exit {proc.returncode}: "
            f"{proc.stderr.decode(errors='replace')!r}"
        )
    return None


def docker_available() -> bool:
    """``True`` iff a Docker daemon is reachable (thin wrapper over the reason)."""
    return docker_unavailable_reason() is None
```

- [ ] **Step 4: Run the probe test to verify it passes**

Run: `uv run pytest tests/unit/meta/test_docker_probe.py -q`
Expected: PASS (5 passed).

- [ ] **Step 5: Refactor the smoke probe onto the shared helper**

In `tests/smoke/test_slice4_graduation.py`: **delete** the whole `_docker_available` function (the `def _docker_available() -> bool:` block, ~lines 66–84), add the import near the other top-level imports:

```python
from tests._docker_probe import docker_available
```

and change its single call site in the `compose_stack` fixture:

```python
    if not _docker_available():
```

to:

```python
    if not docker_available():
```

- [ ] **Step 6: Refactor the integration probe onto the shared helper**

In `tests/integration/test_alfred_core_image_bwrap.py`: **delete** the whole `_docker_unavailable_reason` function (the `def _docker_unavailable_reason() -> str | None:` block, ~lines 47–70), add near the top-level imports:

```python
from tests._docker_probe import docker_unavailable_reason
```

and change its single call site in the `alfred_core_image` fixture:

```python
    reason = _docker_unavailable_reason()
```

to:

```python
    reason = docker_unavailable_reason()
```

- [ ] **Step 7: Clean up now-unused imports**

Run: `uv run ruff check tests/smoke/test_slice4_graduation.py tests/integration/test_alfred_core_image_bwrap.py`
Expected: it will flag `F401 [*] shutil imported but unused` in both files (the deleted probes were the only `shutil.which` users). Remove the `import shutil` line from each file. (`subprocess` stays — both files use it elsewhere.)
Re-run the same `ruff check` → Expected: clean.

- [ ] **Step 8: Verify probes + collection still work**

Run: `uv run pytest tests/unit/meta/test_docker_probe.py tests/smoke/test_slice4_graduation.py tests/integration/test_alfred_core_image_bwrap.py --collect-only -q`
Expected: collects with no import errors (the smoke/integration tests will skip at runtime if no daemon, but collection must be clean).
Run: `uv run ruff format tests/_docker_probe.py tests/unit/meta/test_docker_probe.py && uv run ruff check tests/_docker_probe.py tests/unit/meta/test_docker_probe.py`
Expected: clean.

- [ ] **Step 9: Commit**

```bash
git add tests/_docker_probe.py tests/unit/meta/__init__.py tests/unit/meta/test_docker_probe.py tests/smoke/test_slice4_graduation.py tests/integration/test_alfred_core_image_bwrap.py
git commit -m "test(ci): #246 add shared docker-availability probe helper

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

### Task B: Mark the Docker unit files + anti-rot guard

Mark the 4 Testcontainers files `pytest.mark.docker`, and add a static guard that fails — on every platform — if any Testcontainers-using unit file is unmarked. The guard is what resolves the maintainers' documented "would rot" deferral reason.

**Files:**

- Modify: `tests/unit/plugins/web_fetch/test_canary_scanner_host_side.py`
- Modify: `tests/unit/plugins/web_fetch/test_content_handle_single_use.py`
- Modify: `tests/unit/plugins/web_fetch/test_handle_cap.py`
- Modify: `tests/unit/plugins/web_fetch/test_lua_atomic_rate_limit.py`
- Create: `tests/unit/meta/test_docker_tests_are_marked.py`

**Interfaces:**

- Consumes: nothing from earlier tasks.
- Produces: `find_unmarked_docker_files(unit_root: Path, *, exclude: Path) -> list[Path]` (used only within its own module's tests).

- [ ] **Step 1: Re-confirm the Docker file set (guard against spec drift)**

Run:

```bash
grep -rlnE '^(from|import) testcontainers|(Redis|Postgres|Mongo|Kafka|Docker|Generic)Container\(' tests/unit
```

Expected: EXACTLY these 4 lines (the web_fetch files). If the set differs, mark whatever this grep returns instead — the grep is the source of truth, not this plan's list.

- [ ] **Step 2: Write the failing anti-rot guard**

Create `tests/unit/meta/test_docker_tests_are_marked.py`:

```python
"""Anti-rot guard: Testcontainers usage in unit tests must be ``docker``-marked.

This is what unblocks running ``tests/unit`` on the daemon-less macOS / Windows
CI legs. The root-conftest auto-skip hook only skips ``docker``-MARKED items; an
unmarked Testcontainers file would ERROR at fixture setup and turn the macOS leg
red. Two static invariants keep the separation from silently rotting (the
maintainers' stated deferral reason), both enforced on every platform including
the Linux ``python`` job:

1. Every TEST MODULE that uses Testcontainers carries ``pytest.mark.docker``.
2. NO ``conftest.py`` under ``tests/unit`` uses Testcontainers — a conftest's
   container fixture cannot be effectively skip-marked (a ``pytestmark`` in a
   conftest does not apply to sibling modules' items), so container fixtures
   MUST live in a markable test module. This closes the "hoist the shared
   ``redis_url`` fixture into conftest" loophole that would blind invariant (1).
"""

from __future__ import annotations

import re
from pathlib import Path

_UNIT_ROOT = Path(__file__).resolve().parents[1]  # tests/unit
_META_DIR = Path(__file__).resolve().parent  # tests/unit/meta (holds pattern literals — excluded)
_REPO_ROOT = _UNIT_ROOT.parents[1]  # repo root, for readable failure paths

# Real Testcontainers usage: an import of the package, or instantiation of a
# *Container class. Prose mentions ("doesn't want testcontainers", a ``:class:``
# cross-ref) do NOT match — they are not import lines and carry no ``Container(``.
_IMPORT_RE = re.compile(r"^\s*(from|import)\s+testcontainers\b", re.MULTILINE)
_CONTAINER_RE = re.compile(r"\b(?:Redis|Postgres|Mongo|Kafka|Docker|Generic)Container\s*\(")
_MARK_RE = re.compile(r"mark\.docker\b")


def _uses_testcontainers(src: str) -> bool:
    return bool(_IMPORT_RE.search(src)) or bool(_CONTAINER_RE.search(src))


def _is_docker_marked(src: str) -> bool:
    return bool(_MARK_RE.search(src))


def find_unmarked_docker_files(unit_root: Path, *, exclude: Path) -> list[Path]:
    """Return TEST MODULES that use Testcontainers but lack the ``docker`` marker."""
    offenders: list[Path] = []
    for path in sorted(unit_root.rglob("*.py")):
        if path.name == "conftest.py":
            continue  # conftests are handled by find_testcontainers_conftests
        if path.parent == exclude or exclude in path.parents:
            continue
        src = path.read_text(encoding="utf-8")
        if _uses_testcontainers(src) and not _is_docker_marked(src):
            offenders.append(path)
    return offenders


def find_testcontainers_conftests(unit_root: Path) -> list[Path]:
    """Return ``conftest.py`` files under ``unit_root`` that use Testcontainers."""
    return [
        path
        for path in sorted(unit_root.rglob("conftest.py"))
        if _uses_testcontainers(path.read_text(encoding="utf-8"))
    ]


def test_all_testcontainers_unit_files_are_docker_marked() -> None:
    offenders = find_unmarked_docker_files(_UNIT_ROOT, exclude=_META_DIR)
    assert offenders == [], (
        "These unit files use Testcontainers but are not `docker`-marked, so they "
        "would ERROR (not skip) on the daemon-less macOS/Windows CI legs. Add a "
        "module-level `pytestmark = pytest.mark.docker` to each:\n"
        + "\n".join(f"  - {p.relative_to(_REPO_ROOT)}" for p in offenders)
    )


def test_no_testcontainers_in_unit_conftests() -> None:
    offenders = find_testcontainers_conftests(_UNIT_ROOT)
    assert offenders == [], (
        "These conftest.py files use Testcontainers. A conftest's container "
        "fixture cannot be skip-marked (a `pytestmark` in a conftest does not "
        "apply to sibling modules' items), so it would ERROR on the daemon-less "
        "macOS/Windows legs with no way to skip it. Move the container fixture "
        "into a `docker`-marked test module instead:\n"
        + "\n".join(f"  - {p.relative_to(_REPO_ROOT)}" for p in offenders)
    )


def test_guard_flags_unmarked_synthetic_file(tmp_path: Path) -> None:
    (tmp_path / "test_bad.py").write_text(
        "from testcontainers.redis import RedisContainer\n\n"
        "def test_x() -> None:\n    RedisContainer('redis:8')\n",
        encoding="utf-8",
    )
    offenders = find_unmarked_docker_files(tmp_path, exclude=tmp_path / "nonexistent")
    assert [p.name for p in offenders] == ["test_bad.py"]


def test_guard_passes_marked_synthetic_file(tmp_path: Path) -> None:
    (tmp_path / "test_good.py").write_text(
        "import pytest\nfrom testcontainers.redis import RedisContainer\n\n"
        "pytestmark = pytest.mark.docker\n\n"
        "def test_x() -> None:\n    RedisContainer('redis:8')\n",
        encoding="utf-8",
    )
    offenders = find_unmarked_docker_files(tmp_path, exclude=tmp_path / "nonexistent")
    assert offenders == []


def test_guard_ignores_prose_mention(tmp_path: Path) -> None:
    (tmp_path / "test_prose.py").write_text(
        '"""This test uses a double rather than testcontainers Postgres."""\n\n'
        "def test_x() -> None:\n    assert True\n",
        encoding="utf-8",
    )
    offenders = find_unmarked_docker_files(tmp_path, exclude=tmp_path / "nonexistent")
    assert offenders == []


def test_guard_flags_testcontainers_conftest(tmp_path: Path) -> None:
    (tmp_path / "conftest.py").write_text(
        "import pytest\nfrom testcontainers.redis import RedisContainer\n\n"
        "@pytest.fixture\ndef redis_url():\n"
        "    with RedisContainer('redis:8') as r:\n        yield r\n",
        encoding="utf-8",
    )
    offenders = find_testcontainers_conftests(tmp_path)
    assert [p.name for p in offenders] == ["conftest.py"]
```

- [ ] **Step 3: Run the guard to verify it fails**

Run: `uv run pytest tests/unit/meta/test_docker_tests_are_marked.py -q`
Expected: `test_all_testcontainers_unit_files_are_docker_marked` FAILS, listing the 4 unmarked web_fetch files. `test_no_testcontainers_in_unit_conftests` PASSES (no conftest uses Testcontainers today) and the 4 synthetic tests PASS.

- [ ] **Step 4: Mark the 4 files**

In EACH of the 4 files, add a module-level marker on its own line, immediately after the import block (after the last `from alfred...` import, before the first `def`/`@pytest.fixture`), separated by a blank line. (`import pytest` is already present in all 4 — they use `@pytest.fixture`.) The line to add is identical in each:

```python
pytestmark = pytest.mark.docker
```

Files:

- `tests/unit/plugins/web_fetch/test_canary_scanner_host_side.py`
- `tests/unit/plugins/web_fetch/test_content_handle_single_use.py`
- `tests/unit/plugins/web_fetch/test_handle_cap.py`
- `tests/unit/plugins/web_fetch/test_lua_atomic_rate_limit.py`

(None of the 4 has an existing `pytestmark` — verified — so this is a clean add, not a list merge.)

- [ ] **Step 5: Run the guard to verify it passes**

Run: `uv run pytest tests/unit/meta/test_docker_tests_are_marked.py -q`
Expected: PASS (6 passed — 2 real guards + 4 synthetic tests).

- [ ] **Step 6: Confirm the marks are inert with Docker present**

Run: `uv run pytest tests/unit/plugins/web_fetch/test_handle_cap.py -q`
Expected: PASS (with a live Docker daemon the marked tests still run — the mark only matters to the Task C skip hook when the daemon is absent).

- [ ] **Step 7: Format + lint**

Run: `uv run ruff format tests/unit/meta/test_docker_tests_are_marked.py && uv run ruff check tests/unit/meta/test_docker_tests_are_marked.py tests/unit/plugins/web_fetch/`
Expected: clean.

- [ ] **Step 8: Commit**

```bash
git add tests/unit/meta/test_docker_tests_are_marked.py tests/unit/plugins/web_fetch/test_canary_scanner_host_side.py tests/unit/plugins/web_fetch/test_content_handle_single_use.py tests/unit/plugins/web_fetch/test_handle_cap.py tests/unit/plugins/web_fetch/test_lua_atomic_rate_limit.py
git commit -m "test(ci): #246 mark testcontainers unit files + add anti-rot guard

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

### Task C: Root-conftest auto-skip-when-Docker-absent hook

Add a `pytest_collection_modifyitems` hook to the root `tests/conftest.py` that skips `docker`-marked items when the daemon is unreachable — the mechanism that lets the macOS/Windows legs run `tests/unit` without erroring.

**Files:**

- Modify: `tests/conftest.py` (add the import + the hook)
- Create: `tests/unit/meta/test_docker_autoskip_hook.py`

**Interfaces:**

- Consumes: `tests._docker_probe.docker_available` (Task A). Marks applied in Task B.
- Produces: `tests.conftest.pytest_collection_modifyitems(items: list[pytest.Item]) -> None`.

- [ ] **Step 1: Write the failing hook test**

Create `tests/unit/meta/test_docker_autoskip_hook.py`:

```python
"""Unit tests for the root-conftest docker auto-skip collection hook."""

from __future__ import annotations

import pytest

from tests import conftest as root_conftest


class _FakeItem:
    """Minimal ``pytest.Item`` stand-in exposing only what the hook touches."""

    def __init__(self, *, marked: bool) -> None:
        self._marked = marked
        self.added: list[pytest.MarkDecorator] = []

    def get_closest_marker(self, name: str) -> object | None:
        return object() if (name == "docker" and self._marked) else None

    def add_marker(self, marker: pytest.MarkDecorator) -> None:
        self.added.append(marker)


def test_docker_items_skipped_when_daemon_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(root_conftest, "docker_available", lambda: False)
    monkeypatch.setattr(root_conftest, "docker_unavailable_reason", lambda: "no daemon")
    docker_item = _FakeItem(marked=True)
    plain_item = _FakeItem(marked=False)
    root_conftest.pytest_collection_modifyitems(items=[docker_item, plain_item])
    assert len(docker_item.added) == 1
    assert docker_item.added[0].name == "skip"
    assert plain_item.added == []


def test_nothing_skipped_when_daemon_present(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(root_conftest, "docker_available", lambda: True)
    docker_item = _FakeItem(marked=True)
    root_conftest.pytest_collection_modifyitems(items=[docker_item])
    assert docker_item.added == []


def test_docker_marked_test_skips_not_errors_when_daemon_absent(
    pytester: pytest.Pytester, monkeypatch: pytest.MonkeyPatch
) -> None:
    """END-TO-END: a real ``docker``-marked test SKIPS (its module-scoped fixture
    never runs) when the daemon is absent.

    Proves the load-bearing chain the ``_FakeItem`` tests cannot: real marker
    propagation + skip-at-collection pre-empting module-scoped fixture setup.
    Runs on every platform (incl. the Linux ``python`` job) — no daemon needed,
    because we force ``docker_available`` False.
    """
    monkeypatch.setattr(root_conftest, "docker_available", lambda: False)
    monkeypatch.setattr(root_conftest, "docker_unavailable_reason", lambda: "forced-absent")
    # The sandbox re-uses the REAL hook from tests.conftest (same process, same
    # module object → the monkeypatch above is honoured).
    pytester.makeconftest("from tests.conftest import pytest_collection_modifyitems\n")
    pytester.makepyfile(
        """
        import pytest

        pytestmark = pytest.mark.docker

        @pytest.fixture(scope="module")
        def exploding_container():
            raise RuntimeError("fixture setup must not run for a skipped test")

        def test_needs_docker(exploding_container):
            assert True
        """
    )
    result = pytester.runpytest("-p", "no:cacheprovider")
    # skipped (not errored) proves the fixture never entered setup.
    result.assert_outcomes(skipped=1, passed=0, failed=0, errors=0)
```

- [ ] **Step 2: Run the hook test to verify it fails**

Run: `uv run pytest tests/unit/meta/test_docker_autoskip_hook.py -q`
Expected: FAIL — the fake-item tests fail (`AttributeError: module 'tests.conftest' has no attribute 'pytest_collection_modifyitems'`) and the pytester test errors (`fixture 'pytester' not found`, until Step 3 enables it).

- [ ] **Step 3: Add the import + hook to `tests/conftest.py`**

Add to the imports at the top of `tests/conftest.py` (below the existing `from tests.support.discord_mocks import DiscordMockFactory`):

```python
from tests._docker_probe import docker_available, docker_unavailable_reason
```

Enable the built-in `pytester` plugin (needed by the end-to-end hook test) by adding this module-level line near the top of `tests/conftest.py` (it MUST live in the top-most conftest — verified there is no repo-root `conftest.py`, so `tests/conftest.py` is top-most; `pytester` is inert unless the `pytester` fixture is requested):

```python
pytest_plugins = ["pytester"]
```

Add the hook (place it after the imports / module constants, before the fixtures — a natural spot is right after the `_LAUNCHER_TIMEOUT_S` constant):

```python
def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Skip ``docker``-marked tests when no Docker daemon is reachable.

    The Docker-backed unit modules (the Testcontainers web_fetch files, each
    module-marked ``pytest.mark.docker``) would ERROR at fixture setup on a
    daemon-less runner. On the macOS / Windows CI legs — which have no Docker
    daemon — this hook turns that error into a clean SKIP, which is what lets
    ``tests/unit`` run there. On Linux CI and dev boxes with Docker the probe
    returns ``True`` and this is a no-op.

    The skip reason carries the specific probe reason (PATH-absent / hung /
    OSError / nonzero-exit) so the integration fixture's flaky-vs-absent
    diagnostic (PR #217) is preserved uniformly across all docker skips.
    """
    if docker_available():
        return
    skip_docker = pytest.mark.skip(reason=f"docker daemon unavailable: {docker_unavailable_reason()}")
    for item in items:
        if item.get_closest_marker("docker") is not None:
            item.add_marker(skip_docker)
```

- [ ] **Step 4: Run the hook test to verify it passes**

Run: `uv run pytest tests/unit/meta/test_docker_autoskip_hook.py -q`
Expected: PASS (3 passed — 2 fake-item + 1 pytester end-to-end).

- [ ] **Step 5: ACCEPTANCE — simulate the daemon-less macOS runner locally**

This reproduces the macOS CI leg on this Darwin box by making the daemon unreachable. Run:

```bash
DOCKER_HOST=tcp://127.0.0.1:1 TESTCONTAINERS_RYUK_DISABLED=true \
  uv run pytest tests/unit/plugins/web_fetch/test_handle_cap.py -q
```

Expected: the Docker tests now report **skipped** (`docker daemon unavailable`), **zero errors** — contrast the pre-hook baseline (32 errors). Some pure-logic tests in the file may still run/skip; the key assertion is **0 errors**.

- [ ] **Step 6: ACCEPTANCE — the whole unit suite goes green daemon-less**

Run:

```bash
DOCKER_HOST=tcp://127.0.0.1:1 TESTCONTAINERS_RYUK_DISABLED=true \
  uv run pytest tests/unit -q
```

Expected: all pass with the 4 Docker files' tests skipped, **0 errors** — i.e. the macOS `python-cross-os` leg will be blocking-green. (This is Phase A's acceptance gate, reproduced locally.) Note the passed/skipped counts for the PR body.

- [ ] **Step 7: Confirm normal (daemon-present) runs are unaffected**

Run: `uv run pytest tests/unit/meta -q`
Expected: PASS. Then a spot check that Docker files still RUN with the daemon up:
Run: `uv run pytest tests/unit/plugins/web_fetch/test_lua_atomic_rate_limit.py -q`
Expected: PASS (not skipped) — the hook is a no-op when Docker is present.

- [ ] **Step 8: Format + lint + commit**

Run: `uv run ruff format tests/conftest.py tests/unit/meta/test_docker_autoskip_hook.py && uv run ruff check tests/conftest.py tests/unit/meta/test_docker_autoskip_hook.py`
Expected: clean.

```bash
git add tests/conftest.py tests/unit/meta/test_docker_autoskip_hook.py
git commit -m "test(ci): #246 auto-skip docker-marked tests when daemon absent

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

### Task D: CI wiring — macOS blocking + Windows informational + docs

Add a unit step to each `python-cross-os` matrix leg, refresh the now-stale job comments, and update the required-checks manifest. macOS blocks; Windows is `continue-on-error` (informational-first).

**Files:**

- Modify: `.github/workflows/ci.yml` (the `python-cross-os` job: replace the "no unit-test step" NOTE with the two steps; refresh the stale "unit suite is NOT run" comment blocks)
- Modify: `docs/ci/required-checks.md` (macOS + Windows entries + the "OS matrix" reality note)

**Interfaces:**

- Consumes: the marks (Task B) + the auto-skip hook (Task C) — without them the macOS step would error.

- [ ] **Step 1: Replace the "no unit-test step" NOTE with the two unit steps**

In `.github/workflows/ci.yml`, in the `python-cross-os` job, replace this block (currently right after the `Pyright (Linux target)` step, `run: uv run pyright --pythonplatform Linux src/`):

```yaml
      # NOTE: no unit-test step. ~77 tests under tests/unit/ boot Redis/Postgres
      # via Testcontainers and the GitHub macOS runner has no Docker daemon, so
      # they error at fixture setup. The Docker-free unit subset on macOS is
      # deferred to the follow-up tracked in docs/ci/required-checks.md (needs a
      # `requires_docker` marker on the entangled tests). See the job-level
      # comment for the full rationale.
```

with:

```yaml
      # Unit suite on the non-Linux legs (#246). The Testcontainers-backed unit
      # files are module-marked `pytest.mark.docker` and the root-conftest
      # collection hook SKIPS them cleanly when no Docker daemon is reachable
      # (neither runner has one) — so the suite runs without erroring at fixture
      # setup. No coverage gate here: the per-subsystem 100% line+branch gates
      # stay on the Linux `python` job (they need the combined unit+integration
      # corpus). These are pass/fail portability runs.
      - name: Unit tests (macOS — no coverage gate)
        # BLOCKING: proven green — tests/unit is all-pass on Darwin with the
        # Docker files skipping. macOS is the highest-value divergence signal:
        # the POSIX syscalls (recvmsg/MSG_CTRUNC, os.geteuid, SIGKILL, pass_fds)
        # run on Darwin, catching the class of bug the #340 PR2a split hit.
        if: steps.check.outputs.has_py == 'true' && matrix.os == 'macos-latest' && hashFiles('tests/unit/**/*.py') != ''
        shell: bash  # parity with this job's check-step discipline (identical invocation on every runner)
        run: uv run pytest tests/unit -q
      - name: Unit tests (Windows — informational until green, no coverage gate)
        # INFORMATIONAL — #246 Phase B promotes to blocking. The win32 failure
        # surface is unknown and not locally validatable (POSIX-only tests need
        # `sys.platform == "win32"` skip-guards). `continue-on-error` lets the
        # leg RUN and surface that failure surface without blocking merge — the
        # same de-risking the windows static layer used (#312–#319 → #321).
        if: steps.check.outputs.has_py == 'true' && matrix.os == 'windows-latest' && hashFiles('tests/unit/**/*.py') != ''
        continue-on-error: true
        shell: bash
        run: uv run pytest tests/unit -q
```

- [ ] **Step 2: Refresh the stale macOS job comment**

In the same job's header comment, replace the macOS paragraph (the block that begins `#     The UNIT suite is NOT run on macOS. ~77 unit tests under` and ends `#     zero-code-change, Docker-free layer today — lint + format + type-check.`) with:

```yaml
    #     The UNIT suite NOW runs on macOS (#246). The Testcontainers-backed
    #     unit files (tests/unit/plugins/web_fetch/) are module-marked
    #     `pytest.mark.docker`; the root-conftest collection hook skips them
    #     cleanly when no daemon is reachable (the macOS runner ships none), so
    #     the rest of tests/unit runs and gives the Darwin-vs-Linux divergence
    #     signal that caught nothing before (e.g. the #340 PR2a recvmsg split).
    #     No coverage gate — the per-subsystem 100% gates stay on the Linux job.
```

- [ ] **Step 3: Refresh the stale Windows job comment**

Replace the windows paragraph (the block beginning `#   * windows-latest — runs lint + format + mypy + pyright ONLY (same layer` through `#     scope on Windows (win32 skip-guards, #246).`) with:

```yaml
    #   * windows-latest — runs lint + format + mypy + pyright, and the unit
    #     suite INFORMATIONALLY (`continue-on-error`, #246 Phase A). The Docker
    #     files auto-skip (no daemon), but many tests still invoke POSIX-only
    #     surface (`/bin/sh`, `os.uname()`, `os.geteuid()`, `signal.SIGKILL`,
    #     `subprocess(..., pass_fds=...)`) with no `sys.platform == "win32"`
    #     guard, so they ERROR rather than skip. Guarding them is a discover-
    #     then-guard change against real CI data (#246 Phase B) — until then the
    #     unit step is non-blocking so its failures are visible but do not fail
    #     the required `Python cross-OS (windows-latest)` check. The static
    #     layer (lint/format/type) stays REQUIRED (#321 Phase 3).
```

- [ ] **Step 4: Refresh the "Both matrix legs are now BLOCKING" comment**

Replace the block beginning `# Both matrix legs are now BLOCKING.` through `# skip-guards tracked in #246 remain out of scope here.` (a `#`-comment block in the job body, indented 4 spaces) with:

```yaml
    # Both matrix legs' STATIC layer (lint/format/type) is BLOCKING — the
    # `continue-on-error` that kept windows informational-until-green was
    # removed 2026-06-24 (#321 Phase 3) after 6+ green cycles (#312–#319). The
    # UNIT step is BLOCKING on macos-latest (proven green) and INFORMATIONAL on
    # windows-latest (its own step-level `continue-on-error`, #246 Phase A) —
    # Phase B removes that once win32 skip-guards make Windows green (#246).
```

- [ ] **Step 5: Lint the workflow**

Run: `actionlint .github/workflows/ci.yml`
Expected: no errors. (If `actionlint` reports pre-existing warnings unrelated to this diff, confirm they also appear on `git stash` of the change; do not introduce new ones.)

- [ ] **Step 6: Update the required-checks manifest**

`docs/ci/required-checks.md` has SIX spots that go stale — verbatim find/replace each (do NOT paraphrase away surrounding true content; each replacement below preserves it):

**(a) macOS required-check row** — find:

```
Does NOT run the unit suite (Docker-needing tests error on the daemon-less macOS runner — #245/#246).
```

replace with:

```
Runs the unit suite BLOCKING (the 4 Testcontainers files auto-skip via the root-conftest hook; #246 Phase A) — the macOS-vs-Linux divergence signal.
```

**(b) Windows required-check row** — find:

```
Does NOT run the unit suite (POSIX-only tests would ERROR; win32 skip-guards tracked in #246).
```

replace with:

```
Runs the unit suite INFORMATIONALLY (`continue-on-error`; #246 Phase A) — Docker files auto-skip, POSIX-only tests still error; win32 skip-guards promote it to blocking in #246 Phase B.
```

**(c) "Required:" prose parenthetical** — find:

```
(Only the **static-analysis** layer is required on the non-Linux legs — the unit suite remains out of scope; see below / #246.)
```

replace with:

```
(The static-analysis layer is required on both non-Linux legs; the unit suite is now BLOCKING on macOS and INFORMATIONAL on Windows — #246 Phase A. See below.)
```

**(d) macOS "Why each OS runs what it runs" bullet** — find the sentence:

```
The unit suite is **not** run here: ~77 tests under `tests/unit/` boot a real Redis/Postgres via Testcontainers (no `@pytest.mark.integration` — they `import testcontainers` directly) and the GitHub macOS runner has no Docker daemon, so they ERROR at fixture setup (`docker.errors.DockerException`; #245 first real run = 3731 passed / 77 errored). They are not cleanly separable by a single marker or path, so a deselect allowlist would rot the moment a new Docker-backed unit test lands — the Docker-free macOS unit subset is deferred (see below).
```

replace with:

```
The unit suite **now runs here** (#246 Phase A): the 4 Testcontainers unit files (`tests/unit/plugins/web_fetch/`) are module-marked `pytest.mark.docker` and the root-conftest collection hook skips them cleanly when no Docker daemon is reachable (the macOS runner has none), so the rest of `tests/unit` runs and gives the Darwin-vs-Linux divergence signal (e.g. the class of bug the #340 PR2a `recvmsg`/`MSG_CTRUNC` split hit). An anti-rot guard (`tests/unit/meta/test_docker_tests_are_marked.py`) fails if a new Testcontainers file is unmarked, so the separation can't rot. No coverage gate here — the per-subsystem 100% gates stay on the Linux `python` job.
```

**(e) Windows "Why each OS runs what it runs" bullet** — find the sentence:

```
The unit suite is **not** Windows-clean: many tests invoke the POSIX bash launcher (`/bin/sh`), `os.uname()`, `os.geteuid()`, `signal.SIGKILL`, and `subprocess(..., pass_fds=...)` with no `sys.platform == "win32"` skip-guard, so they would ERROR rather than skip. Adding those guards is a cross-cutting code change across dozens of files — tracked as a follow-up to #245 (#246).
```

replace with:

```
The unit suite **now runs here INFORMATIONALLY** (`continue-on-error`; #246 Phase A): the Docker files auto-skip (no daemon), but many tests still invoke the POSIX bash launcher (`/bin/sh`), `os.uname()`, `os.geteuid()`, `signal.SIGKILL`, and `subprocess(..., pass_fds=...)` with no `sys.platform == "win32"` skip-guard, so they ERROR rather than skip. The step's own `continue-on-error` keeps those failures visible but non-blocking (they do NOT fail the required `Python cross-OS (windows-latest)` check). Adding the win32 skip-guards — a discover-then-guard change against the real CI failure surface — promotes the leg to blocking in #246 Phase B.
```

(Leave the following sentence in that bullet, `The Windows static-analysis layer (lint/format/type) is now **required** …`, untouched.)

**(f) The per-OS reality table Unit-suite row** — find:

```
| Unit suite | ✓ (+ 100% coverage gates) | ✗ deferred (Docker-needing tests; see below) | ✗ deferred (see below) |
```

replace with:

```
| Unit suite | ✓ (+ 100% coverage gates) | ✓ blocking (Docker tests auto-skip; #246) | informational (`continue-on-error`; #246) |
```

**(g) The "Deferred to a follow-up issue" list items 1–2** — find:

```
1. **Docker-free unit subset on macOS** — the ~77 Testcontainers-backed tests under `tests/unit/` need a `requires_docker` marker so the macOS leg can run `pytest tests/unit -m "not requires_docker"` and add real unit coverage on Darwin (bash 3.2 / BSD coreutils / `os.uname()`/`geteuid()` paths) without erroring on the absent Docker daemon.
2. **Unit suite on Windows** — the Windows static-analysis layer is already required (#321 Phase 3); what remains deferred is adding the **unit suite** to the Windows leg, which needs `sys.platform == "win32"` skip-guards (or pure-Python reimplementations) on the bash-launcher / POSIX-syscall unit tests so they skip cleanly instead of erroring.
```

replace with:

```
1. **Docker-free unit subset on macOS — DONE (#246 Phase A).** Shipped via the `docker` marker + root-conftest auto-skip hook (not the originally-sketched `requires_docker` / `-m "not requires_docker"` deselect); the macOS leg now runs `pytest tests/unit -q` blocking-green with the Testcontainers files skipping.
2. **Unit suite on Windows → BLOCKING (#246 Phase B).** Phase A runs the Windows unit leg INFORMATIONALLY (`continue-on-error`); Phase B adds `sys.platform == "win32"` skip-guards (or pure-Python reimplementations) on the bash-launcher / POSIX-syscall unit tests against the real CI failure surface, then drops `continue-on-error` to make the leg blocking.
```

(Item 3 — macOS-native `sandbox-exec` — stays unchanged.)

- [ ] **Step 7: Markdown-lint the doc**

Run: `npx markdownlint-cli2 docs/ci/required-checks.md` (or the repo's configured markdownlint invocation).
Expected: 0 errors. If it flags MD032/MD031/MD004/MD060 on the edited lines, fix by hand (do NOT blanket `--fix` — it can corrupt prose); re-read the file after any fix.

- [ ] **Step 8: Commit**

```bash
git add .github/workflows/ci.yml docs/ci/required-checks.md
git commit -m "ci(cross-os): #246 run unit suite on macOS (blocking) + Windows (informational)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

### Task E: Whole-branch verification (Phase A acceptance)

**Files:** none (verification only).

- [ ] **Step 1: Full local quality gate**

Run: `make check`
Expected: lint + format + type + unit all green. (If `make check` masks the exit code via a piped `tail`, check `$?` explicitly per the repo's `make check` discipline.)

- [ ] **Step 2: Re-run the daemon-less acceptance sim**

Run:

```bash
DOCKER_HOST=tcp://127.0.0.1:1 TESTCONTAINERS_RYUK_DISABLED=true \
  uv run pytest tests/unit -q
```

Expected: all-pass-with-skips, **0 errors** — the macOS leg's behaviour, reproduced. Record the `N passed / M skipped` line for the eventual PR body.

- [ ] **Step 3: Confirm the anti-rot guard + hook + probe all run in the normal suite**

Run: `uv run pytest tests/unit/meta -q`
Expected: PASS (probe 5 + guard 6 + hook 3 = 14 tests, adjust if counts differ).

- [ ] **Step 4: Sanity the git history**

Run: `git log --oneline origin/main..HEAD`
Expected: 4 commits (Tasks A–D), each subject carrying `#246` after the colon.

**Phase A is complete when:** `make check` is green, the daemon-less sim is 0-errors, and the branch is ready for the standing outward-facing cadence (full `/review-pr` fleet — devops/test/docs lanes most relevant, security always — + BOTH CodeRabbit, then non-admin `gh pr merge --rebase`). Push/PR is user-gated and out of this plan's scope.

**Before merge (macOS blocking-first-run caveat):** the green evidence is from this Darwin dev box with a *simulated* daemon-less env, not the GitHub `macos-latest` runner (arm64 M1, fresh environment) — and catching that exact host divergence is the point. So on the PR's OWN CI run, confirm the `Python cross-OS (macos-latest)` leg is green before merging; if it's red for an environment reason (not a real code divergence), consider a brief informational-first window on the macOS unit step mirroring the Windows treatment rather than blocking `main`.

**Phase B (#246 Part 1)** — win32 skip-guards against the Windows failure surface this PR reveals, then drop `continue-on-error` — is a separate follow-up plan.

---

## Self-Review

**Spec coverage (against `2026-07-11-macos-unit-crossplatform-ci-design.md` rev.2):**

- §5.1 marker + auto-skip + anti-rot → Task B (marker + guard) + Task C (auto-skip hook). ✔
- §5.2 DRY the two `_docker_available` probes → Task A. ✔ (Note: unified on the richer reason-returning `docker version` probe; smoke's old `docker info` → `docker version` is an intentional, behaviour-equivalent consolidation, both being daemon-reachability checks.)
- §5.3 CI wiring, macOS blocking + Windows `continue-on-error` + `shell: bash` + no coverage gate → Task D Step 1. ✔
- §5.4 required checks (no new check; steps added to existing legs; manifest note) → Task D Steps 6–7. ✔
- §6 the file set → **corrected to the empirically-verified 4** (Task B Step 1 re-confirms). `tests/unit/conftest.py` correctly NOT marked (vestigial docstring; SQLite fixture). ✔
- §8 testing (anti-rot guard is a test; auto-skip hook test; DRY helper test; CI is the integration test) → Tasks A/B/C tests + Task C Step 6 local acceptance. ✔
- §7 scope: macOS + Windows phased → Task D (macOS blocking, Windows informational); Phase B explicitly deferred. ✔

**Placeholder scan:** no TBD/TODO/"handle appropriately"; every code step shows complete code; every command has an expected result. ✔

**Type consistency:** `docker_unavailable_reason` / `docker_available` names identical across Tasks A and C; `find_unmarked_docker_files(unit_root, *, exclude)` signature consistent within Task B; the hook signature `pytest_collection_modifyitems(items)` matches its test call in Task C. ✔

## Focused plan-review folds (devops + test lanes, 2026-07-11)

Both lanes returned 0 Critical and CONFIRMED the load-bearing mechanism (skip-at-collection pre-empts the module-scoped `RedisContainer` fixture; the "4 files not 12" correction; the DRY refactor is behavior-preserving). Folded findings:

- **[test H1]** Anti-rot guard was blind to a shared-fixture-into-conftest hoist (the `redis_url` fixture is byte-identical across all 4 files → a likely DRY refactor). Guard now ALSO forbids Testcontainers in any `tests/unit/**/conftest.py` (`find_testcontainers_conftests` + `test_no_testcontainers_in_unit_conftests`), and a Global Constraint documents the "container fixtures in test modules, never conftest" rule.
- **[test M1]** Added a committed `pytester` end-to-end test (`test_docker_marked_test_skips_not_errors_when_daemon_absent`) proving a real `docker`-marked test SKIPS (fixture never runs) daemon-less — runs on Linux too, converting the manual Step 5/6 acceptance into a permanent guard. Enables `pytest_plugins = ["pytester"]` in the top-most `tests/conftest.py`.
- **[test L2]** `_clear_probe_cache` is now a `yield` fixture (clears on both sides — no cross-test lru_cache bleed into smoke/integration).
- **[test L3]** The hook's skip reason now carries `docker_unavailable_reason()` (preserves the PR #217 flaky-vs-absent diagnostic uniformly).
- **[test L4]** The module-level-marking constraint now honestly states the dropped-test count (≈15 + ≈10, not "a handful") and names the relocate-to-unmarked-sibling lever.
- **[devops M1+M2]** Task D Step 6 rewritten as SIX verbatim find/replace anchors covering every stale spot in `required-checks.md` (the two required-check rows, the "Required:" parenthetical, both per-OS bullets, the reality-table row, and the "Deferred" list items 1–2) — no paraphrase-away of true content.
- **[devops L1]** macOS unit step gains `shell: bash` for parity with the job's check-step discipline.
- **[devops L3]** Task E adds the "macOS blocking-first-run" caveat: confirm the `macos-latest` leg green on the PR's own CI before merge (evidence so far is a *simulated* daemon-less env on Darwin).
