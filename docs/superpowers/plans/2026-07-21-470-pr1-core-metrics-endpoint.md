# #470 PR1 — core `/metrics` endpoint + failure-observability Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

> **rev.1 (2026-07-21)** — folds an 8-lane plan-review (1 Critical, empirically reproduced ×4). The
> Critical was the leak-guard test (Task 3) failing at t=0; fixed here (parser strips `_total`,
> `_created` siblings filtered, label keys asserted from *declared* names). See the §fold-log at the end.

**Goal:** Serve the core's Prometheus `/metrics` from `alfred daemon start` over a curated, leak-guarded registry on a compose-internal never-host-published port, with a `daemon healthcheck` + compose healthcheck that make a bind failure non-silent.

**Architecture:** Promote the gateway's metrics-exposition helpers into a neutral `alfred/observability/` module; the daemon serves a dedicated `CollectorRegistry` built from a single `CORE_OWNED_COLLECTORS` source of truth (10 families across 4 modules) so it exposes exactly the core-owned series and none of the stale `gateway_*` families the default registry accretes; a two-sided, oracle-independent leak-guard test pins the exposed surface; a `daemon healthcheck` subcommand + a compose `healthcheck:` block surface a loud-and-continue bind failure.

**Tech Stack:** Python 3.14+, `prometheus_client`, Typer CLI, `http.client`, pytest, structlog, Babel (`t()`), Docker Compose.

## Global Constraints

- Python floor `>=3.14.6`; `mypy --strict` + `pyright` clean; `ruff check` + `ruff format` clean; no `Any` without justification; PEP 604/585/695 idioms; frozen/immutable by default.
- **HARD rule 7 (no silent failures in security paths):** the metrics-bind failure must be surfaced (loud-and-continue log + compose healthcheck), never swallowed.
- **HARD rule 4 (DLP-exempt paths declare + test the claim):** the leak-guard IS the DLP-equivalent for `/metrics`; it is BLOCKING and must be green before the endpoint is scraped.
- **100% line+branch coverage** on `src/alfred/security/` touch AND on the new `src/alfred/observability/` module (it holds the security-load-bearing leak-guard control). Editing `src/alfred/security/observability.py` triggers the **adversarial suite**.
- **i18n:** all operator-facing CLI strings via `t()` with catalog keys; `pybabel extract/update/compile` drift-gate runs. structlog event keys are NOT `t()` scope.
- **Conventional Commits:** every commit subject carries a literal `#470` after the colon.
- **No `--no-verify`.** Never host-publish the core metrics port. `ALFRED_CORE_METRICS_PORT` default `9465` (distinct from the gateway's 9464).
- Spec: `docs/superpowers/specs/2026-07-21-470-core-metrics-observability-design.md` (rev.1). This plan implements §5 (PR1). §13 fold-log overrides where sections conflict.

---

## File structure

- Create `src/alfred/observability/__init__.py` — package marker; re-exports the public seam.
- Create `src/alfred/observability/metrics_server.py` — `resolve_metrics_port(env_var, default)`, `start_metrics_server(port, registry=None)`, `fetch_metrics_text(host, port)` (promoted from gateway).
- Create `src/alfred/observability/core_metrics.py` — `CORE_OWNED_COLLECTORS`, `build_core_registry()`.
- **Delete** `src/alfred/gateway/metrics_server.py` and repoint every importer at `alfred.observability.metrics_server`. (rev.1 review: Task 1 originally *picked the shim* — a thin re-export "keeping `alfred.gateway.metrics_server` import paths alive". **Struck**: pre-#470 `resolve_metrics_port` took NO arguments, so re-exporting the new two-argument resolver under the old path is a breaking change wearing a back-compat label. Every importer had to be migrated regardless, leaving the shim with zero consumers.)
- Modify `src/alfred/cli/gateway/_commands.py` (metrics-start :288-290, healthcheck resolve :546, `_fetch_metrics_text` :492) + `src/alfred/cli/gateway/_egress.py` (:23, :39) — call the promoted helpers with the gateway env-var/default.
- Modify `src/alfred/cli/daemon/_commands.py` — start the metrics server in `_start_async` before the Supervisor; import `core_metrics` at boot.
- Modify `src/alfred/cli/daemon/__init__.py` — register the `healthcheck` command.
- Create `src/alfred/cli/daemon/_healthcheck.py` — `healthcheck_daemon()`.
- Modify `docker-compose.yaml` — `alfred-core`: add `ALFRED_CORE_METRICS_PORT` env + `healthcheck:` block.
- Modify the i18n catalog (`daemon.healthcheck.*` keys) + `.rulesync`-managed help if applicable.
- Tests: `tests/unit/observability/test_metrics_server.py`, `test_core_registry_surface.py` (the leak-guard), `tests/unit/cli/daemon/test_daemon_healthcheck.py`, `tests/unit/test_compose_invariants.py` (extend), `tests/unit/cli/daemon/test_daemon_boot_metrics.py`.

---

## Task 1: Promote the metrics-exposition helpers to `alfred/observability/`

**Files:**

- Create: `src/alfred/observability/__init__.py`, `src/alfred/observability/metrics_server.py`
- Delete: `src/alfred/gateway/metrics_server.py` — Modify: `src/alfred/cli/gateway/_commands.py`, `src/alfred/cli/gateway/_egress.py`
- Test: `tests/unit/observability/test_metrics_server.py`

**Interfaces:**

- Produces: `resolve_metrics_port(env_var: str, default: int) -> int`; `start_metrics_server(port: int, registry: CollectorRegistry | None = None) -> bool`; `fetch_metrics_text(host: str, port: int) -> str`.

- [ ] **Step 1: Write the failing test for the parameterized resolver**

```python
# tests/unit/observability/test_metrics_server.py
import pytest
from alfred.observability.metrics_server import resolve_metrics_port

def test_resolve_uses_default_when_env_absent(monkeypatch):
    monkeypatch.delenv("ALFRED_CORE_METRICS_PORT", raising=False)
    assert resolve_metrics_port("ALFRED_CORE_METRICS_PORT", 9465) == 9465

def test_resolve_reads_env(monkeypatch):
    monkeypatch.setenv("ALFRED_CORE_METRICS_PORT", "9500")
    assert resolve_metrics_port("ALFRED_CORE_METRICS_PORT", 9465) == 9500

def test_resolve_rejects_out_of_range(monkeypatch):
    monkeypatch.setenv("ALFRED_CORE_METRICS_PORT", "70000")
    with pytest.raises(ValueError):
        resolve_metrics_port("ALFRED_CORE_METRICS_PORT", 9465)
```

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest tests/unit/observability/test_metrics_server.py -q`
Expected: FAIL — `ModuleNotFoundError: alfred.observability`.

- [ ] **Step 3: Create the promoted module**

```python
# src/alfred/observability/metrics_server.py
"""Prometheus HTTP exposition + loopback fetch — shared by the gateway and the core daemon.

Loud-and-continue on a bind failure (observability must never drop a data plane); a
healthcheck surfaces the degraded endpoint. Promoted from alfred.gateway.metrics_server so
the connectivity-free core daemon can reuse it (its second consumer) — #470.
"""
from __future__ import annotations

import http.client
import os
from typing import Final

import structlog
from prometheus_client import CollectorRegistry, start_http_server

log = structlog.get_logger(__name__)

_FETCH_TIMEOUT_S: Final[float] = 2.0

def resolve_metrics_port(env_var: str, default: int) -> int:
    """Resolve a metrics port from ``env_var`` (default ``default``). Raises loudly on a bad value."""
    raw = os.environ.get(env_var)
    if raw is None or raw == "":
        return default
    port = int(raw)  # ValueError on a non-int surfaces loud.
    if not 1 <= port <= 65535:
        raise ValueError(f"{env_var} must be in 1..65535, got {port}")
    return port

def start_metrics_server(port: int, registry: CollectorRegistry | None = None) -> bool:
    """Start the Prometheus exposition on ``port`` serving ``registry`` (default registry if None).

    Loud-and-continue on OSError (e.g. EADDRINUSE): logs ``metrics.bind_failed`` and returns False.
    """
    try:
        if registry is None:
            start_http_server(port)
        else:
            start_http_server(port, registry=registry)
    except OSError as exc:
        log.warning("metrics.bind_failed", port=port, error=repr(exc))
        return False
    log.info("metrics.serving", port=port)
    return True

def fetch_metrics_text(host: str, port: int) -> str:
    """GET the /metrics exposition over loopback via http.client (fixed host — no SSRF surface).

    Raises OSError when unreachable. Lossless-safe decode so a non-UTF-8 body never raises.
    """
    conn = http.client.HTTPConnection(host, port, timeout=_FETCH_TIMEOUT_S)
    try:
        conn.request("GET", "/metrics")
        body: bytes = conn.getresponse().read()
    finally:
        conn.close()
    return body.decode("utf-8", errors="replace")

__all__ = ["resolve_metrics_port", "start_metrics_server", "fetch_metrics_text"]
```

Create `src/alfred/observability/__init__.py`:

```python
"""Shared observability seam (metrics exposition + core registry) — #470."""
```

- [ ] **Step 4: Run the resolver test to verify it passes**

Run: `uv run pytest tests/unit/observability/test_metrics_server.py -q`
Expected: PASS.

- [ ] **Step 5: Update the gateway to consume the promoted module**

**Delete** `src/alfred/gateway/metrics_server.py` (`git rm`) — do **not** leave a re-export shim. (rev.1 review, struck: the plan originally replaced the body with a `"""Back-compat shim"""` re-export. It is not back-compatible — the pre-#470 `resolve_metrics_port` took no arguments, so any surviving `alfred.gateway.metrics_server` importer would break on the new two-argument signature anyway. Step 6 below migrates every importer, which leaves the shim with no consumers.)

Update gateway call sites to pass the gateway env-var/default:

- `src/alfred/cli/gateway/_commands.py:290` → `start_metrics_server(resolve_metrics_port("ALFRED_GATEWAY_METRICS_PORT", 9464))`
- `src/alfred/cli/gateway/_commands.py:546` → `port = resolve_metrics_port("ALFRED_GATEWAY_METRICS_PORT", 9464)`
- `src/alfred/cli/gateway/_egress.py:39` → `port = resolve_metrics_port("ALFRED_GATEWAY_METRICS_PORT", 9464)`
- Replace the local `_fetch_metrics_text(port)` in `cli/gateway/_commands.py` with `fetch_metrics_text(_HEALTHCHECK_HOST, port)` (import from `alfred.observability.metrics_server`); update its callers (`_commands.py:553`; and `_egress.py:40` — which currently calls `_fetch_metrics_text(port)` and **must now pass the host**: `fetch_metrics_text(_HEALTHCHECK_HOST, port)`, importing `_HEALTHCHECK_HOST` too).

- [ ] **Step 6: Find and update the existing tests the signature change breaks (rev.1 core-002)**

The 0-arg→2-arg `resolve_metrics_port` and the `_fetch_metrics_text`→`fetch_metrics_text(host, port)` rename break existing gateway tests. Find and update every caller:

Run: `grep -rn "resolve_metrics_port(\|_fetch_metrics_text\b\|fetch_metrics_text(" tests/ src/`
Update each to the new signatures (pass `"ALFRED_GATEWAY_METRICS_PORT", 9464` / a host). Then:

Run: `uv run pytest tests/unit/gateway -q && uv run pytest tests/unit/cli/gateway -q`
Expected: PASS (no behavior change for the gateway).

- [ ] **Step 7: Commit**

```bash
git add src/alfred/observability src/alfred/cli/gateway tests/unit/gateway tests/unit/cli/gateway tests/unit/observability/test_metrics_server.py
git rm src/alfred/gateway/metrics_server.py tests/unit/gateway/test_metrics_server.py
git commit -m "refactor(observability): #470 promote metrics exposition to shared module"
```

---

## Task 2: `CORE_OWNED_COLLECTORS` + curated registry

**Files:**

- Create: `src/alfred/observability/core_metrics.py`
- Test: `tests/unit/observability/test_core_registry_surface.py` (Task 3 adds the leak-guard; this task adds the builder + a smoke test)

**Interfaces:**

- Produces: `CORE_OWNED_COLLECTORS: tuple[Collector, ...]` (10 collectors); `build_core_registry() -> CollectorRegistry`. (rev.1 review: the earlier `CORE_METRIC_BASE_NAMES` export was vestigial — no consumer, incl. Task 3's leak-guard — struck.)

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/observability/test_core_registry_surface.py
from prometheus_client.parser import text_string_to_metric_families
from prometheus_client import generate_latest
from alfred.observability.core_metrics import build_core_registry, CORE_OWNED_COLLECTORS

def test_build_core_registry_serves_the_capability_counter():
    reg = build_core_registry()
    families = {f.name for f in text_string_to_metric_families(generate_latest(reg).decode())}
    assert "alfred_quarantine_capability_revoked" in families  # parser strips the Counter's _total

def test_ten_core_collectors():
    assert len(CORE_OWNED_COLLECTORS) == 10
```

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest tests/unit/observability/test_core_registry_surface.py -q`
Expected: FAIL — `core_metrics` not found.

- [ ] **Step 3: Create the module (single source of truth for all four observability modules)**

```python
# src/alfred/observability/core_metrics.py
"""The exact set of collectors the core /metrics exposes — one source of truth (#470).

Importing this module registers all ten on the DEFAULT registry at import (side effect of
importing the four observability modules), so build_core_registry has live references AND
alfred_quarantine_capability_revoked_total reads 0 from t=0. The collectors are NOT moved off
the default registry (the duplicate-name-loud property + the gateway process depend on them).
"""
from __future__ import annotations

from prometheus_client import CollectorRegistry
from prometheus_client.registry import Collector

from alfred.comms_mcp.observability import (
    BURST_LIMITER_WAIT_HISTOGRAM, HANDLER_FAILURES_COUNTER,
    INBOUND_DISPATCH_HISTOGRAM, QUARANTINED_EXTRACT_HISTOGRAM,
)
from alfred.plugins._observability import (
    DISPATCH_DURATION, INBOUND_SCANNER_SCAN_DURATION,
    OUTBOUND_DLP_SCAN_DURATION, PLUGIN_SPAWN_DURATION,
)
from alfred.security.observability import CAPABILITY_REVOKED_COUNTER
from alfred.supervisor.observability import ACTION_DURATION_HISTOGRAM

CORE_OWNED_COLLECTORS: tuple[Collector, ...] = (
    CAPABILITY_REVOKED_COUNTER,
    INBOUND_DISPATCH_HISTOGRAM, QUARANTINED_EXTRACT_HISTOGRAM,
    BURST_LIMITER_WAIT_HISTOGRAM, HANDLER_FAILURES_COUNTER,
    ACTION_DURATION_HISTOGRAM,
    DISPATCH_DURATION, OUTBOUND_DLP_SCAN_DURATION,
    INBOUND_SCANNER_SCAN_DURATION, PLUGIN_SPAWN_DURATION,
)

def build_core_registry() -> CollectorRegistry:
    """A dedicated registry holding exactly the core-owned collectors (drops the stale gateway_*)."""
    registry = CollectorRegistry()
    for collector in CORE_OWNED_COLLECTORS:
        registry.register(collector)
    return registry

__all__ = ["CORE_OWNED_COLLECTORS", "build_core_registry"]
```

- [ ] **Step 4: Run to verify it passes**

Run: `uv run pytest tests/unit/observability/test_core_registry_surface.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/alfred/observability/core_metrics.py tests/unit/observability/test_core_registry_surface.py
git commit -m "feat(observability): #470 curated core CollectorRegistry from one source of truth"
```

---

## Task 3: BLOCKING two-sided, oracle-independent leak-guard

**Files:**

- Modify: `tests/unit/observability/test_core_registry_surface.py`
- Modify: the coverage-gate config so `src/alfred/observability/` is held to 100% line+branch.

**Interfaces:**

- Consumes: `build_core_registry`, `CORE_OWNED_COLLECTORS` from Task 2.

- [ ] **Step 1: Write the two-sided leak-guard — three `prometheus_client` gotchas the review reproduced**

The expected set is an **independently-authored literal** (NOT derived from `CORE_OWNED_COLLECTORS` — that would be a tautological oracle). The rev.1 review (sec/rev/test/core all ran it) found the naïve version RED at t=0 for three reasons that MUST be handled — and the fix is to make the literal correct, **NEVER** to weaken `==` to a subset or drop the label pin (that would silently defeat the DLP-equivalent):

1. **The parser strips a Counter's `_total`** — `text_string_to_metric_families` yields `alfred_quarantine_capability_revoked` (not `..._total`) and `alfred_comms_handler_failures` (not `..._total`). Author `_EXPECTED_FAMILIES` in the parser's naming.
2. **`_created` series are separate families** (no `PROMETHEUS_DISABLE_CREATED_SERIES` in this repo) — filter names ending `_created`.
3. **Labeled families expose NO label keys at t=0** (a child only materializes on first `.labels(...)`). So enforce the value-boundedness label pin from each collector's **declared** label names (`_labelnames`), NOT from emitted samples.

```python
# append to tests/unit/observability/test_core_registry_surface.py
# (imports consolidated at the top of the file with Task 2's — no mid-file re-import)

# Reviewed allowlist in the PARSER's naming (counters WITHOUT _total; _created filtered).
# Author these to match the actual exposition (Step 2 freezes them); a human reviews this literal.
_EXPECTED_FAMILIES: frozenset[str] = frozenset({
    "alfred_quarantine_capability_revoked",        # Counter — parser strips _total
    "alfred_comms_inbound_dispatch_seconds",
    "alfred_comms_quarantined_extract_seconds",
    "alfred_comms_burst_limiter_wait_seconds",
    "alfred_comms_handler_failures",               # Counter — parser strips _total
    "alfred_orchestrator_action_duration_seconds",
    "alfred_stdio_transport_dispatch_seconds",
    "alfred_plugin_spawn_seconds",
    "alfred_outbound_dlp_scan_seconds",
    "alfred_inbound_scanner_scan_seconds",
})

# Declared label names, keyed on the collector's stored base name (`_name`). Present at t=0
# even with zero children — this is the value-boundedness invariant's enforcement (spec §5.2).
_EXPECTED_DECLARED_LABELS: dict[str, frozenset[str]] = {
    "alfred_orchestrator_action_duration_seconds": frozenset({"user_id_bucket", "action_outcome", "breaker_state"}),
    "alfred_stdio_transport_dispatch_seconds": frozenset({"plugin_id", "method_shape", "outcome"}),
    "alfred_plugin_spawn_seconds": frozenset({"plugin_id", "outcome"}),
    "alfred_outbound_dlp_scan_seconds": frozenset({"outcome"}),
    "alfred_inbound_scanner_scan_seconds": frozenset({"outcome"}),
    # every other core family declares NO labels (defaults to frozenset()).
}

def _exposed_family_names() -> set[str]:
    text = generate_latest(build_core_registry()).decode()
    return {f.name for f in text_string_to_metric_families(text) if not f.name.endswith("_created")}

def test_no_leak_no_stale_family():
    exposed = _exposed_family_names()
    assert exposed == set(_EXPECTED_FAMILIES), (
        f"extra={exposed - set(_EXPECTED_FAMILIES)} missing={set(_EXPECTED_FAMILIES) - exposed}"
    )
    assert not any(n.startswith("gateway_") for n in exposed), "gateway_* leaked onto core /metrics"

def test_declared_label_keys_bounded():
    # Read declared label names off the collector objects (robust at t=0 with no children).
    for c in CORE_OWNED_COLLECTORS:
        declared = frozenset(c._labelnames)  # prometheus_client stores the declared labels here
        expected = _EXPECTED_DECLARED_LABELS.get(c._name, frozenset())
        assert declared == expected, f"{c._name} declares labels {declared} != reviewed {expected}"

def test_source_of_truth_count_matches_reviewed_literal():
    # A collector added to CORE_OWNED_COLLECTORS without updating the reviewed literal fails here.
    assert len(CORE_OWNED_COLLECTORS) == len(_EXPECTED_FAMILIES)
```

- [ ] **Step 2: Run; freeze `_EXPECTED_FAMILIES` to the actual parser output; verify green**

Run: `uv run pytest tests/unit/observability/test_core_registry_surface.py -q`
Expected: PASS. If `test_no_leak_no_stale_family` is red, read the `extra=`/`missing=` diff and correct the **literal** to the parser's naming (the three gotchas above) — a human reviews the frozen literal. **Do NOT** relax `==` to subset or delete `test_declared_label_keys_bounded`; that defeats the control (rev.1 Critical). A red here from a short `CORE_OWNED_COLLECTORS` is the core-002 bug, caught as intended.

- [ ] **Step 3: Wire the 100% coverage gate for `src/alfred/observability/` (a CI step, not a config toggle)**

The per-module 100% gates are **hardcoded `coverage report` invocations in CI**, not a config one-liner (rev.1: rev-003/test-005; and #474 — `make check` does NOT run them). Mirror an existing security-module gate: add to the CI coverage job

```bash
uv run coverage report --include='src/alfred/observability/*' --fail-under=100 --show-missing
```

Note in the PR description that `make check` does not exercise this gate (#474); verify locally with the explicit command in Step 4, not via `make check`.

- [ ] **Step 4: Verify coverage**

Run: `uv run pytest tests/unit/observability --cov=src/alfred/observability --cov-branch --cov-report=term-missing`
Expected: 100% line + branch on `metrics_server.py` + `core_metrics.py`.

- [ ] **Step 5: Commit**

```bash
git add tests/unit/observability/test_core_registry_surface.py <coverage-config-file>
git commit -m "test(observability): #470 BLOCKING oracle-independent /metrics leak-guard + 100% gate"
```

---

## Task 4: Serve `/metrics` from the daemon (monkeypatchable seam) + counter-at-zero

**Files:**

- Modify: `src/alfred/cli/daemon/_commands.py` (in `_start_async`, before the `Supervisor`)
- Test: `tests/unit/cli/daemon/test_daemon_boot_metrics.py`

**Interfaces:**

- Consumes: `start_metrics_server`, `resolve_metrics_port` (Task 1), `build_core_registry` (Task 2).

- [ ] **Step 1: Write the failing test (boot calls the metrics seam with the curated registry)**

```python
# tests/unit/cli/daemon/test_daemon_boot_metrics.py
from unittest.mock import patch
import alfred.cli.daemon._commands as cmd

def test_boot_serves_curated_registry_on_core_port(monkeypatch):
    monkeypatch.setenv("ALFRED_CORE_METRICS_PORT", "9465")
    with patch.object(cmd, "start_metrics_server", return_value=True) as m:
        cmd._start_core_metrics_server()   # the extracted monkeypatchable seam
    (port,), kwargs = m.call_args
    assert port == 9465
    assert kwargs["registry"] is not None  # curated, not the default registry
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/unit/cli/daemon/test_daemon_boot_metrics.py -q`
Expected: FAIL — `_start_core_metrics_server` not defined.

- [ ] **Step 3: Add the seam + call it in `_start_async` before the Supervisor**

```python
# src/alfred/cli/daemon/_commands.py  (module scope)
from alfred.observability.core_metrics import build_core_registry
from alfred.observability.metrics_server import resolve_metrics_port, start_metrics_server

def _start_core_metrics_server() -> None:
    """Serve the core /metrics over the curated registry (loud-and-continue). Monkeypatchable seam.

    Importing core_metrics registers the ten core families on the default registry; the unlabeled
    ones (incl. alfred_quarantine_capability_revoked) read 0 from t=0, and the labeled ones expose
    their family metadata immediately (child series materialize on first .labels(...) — rev.1
    core-006). start_http_server spawns a detached daemon thread binding a real socket — invisible
    to the #472 teardown, but tests stub this seam so per-test boots don't leak threads/sockets.
    """
    start_metrics_server(
        resolve_metrics_port("ALFRED_CORE_METRICS_PORT", 9465),
        registry=build_core_registry(),
    )
```

In `_start_async`, call `_start_core_metrics_server()` **early in the boot body, before the `Supervisor(...)` construction** (it is built ~`_commands.py:856`; place the call in the same pre-flight region where the boot resolves its config, mirroring the gateway's pre-relay call site `cli/gateway/_commands.py:288-290`). Placing it before Supervisor keeps it out of the #472 teardown `finally` (`~:1020-1075`).

- [ ] **Step 4: Run to verify it passes**

Run: `uv run pytest tests/unit/cli/daemon/test_daemon_boot_metrics.py -q`
Expected: PASS.

- [ ] **Step 5: Isolate the existing boot-wiring tests from the real socket (rev.1 core-004/test-006)**

Every existing test that drives `_start_async` would now call the real `_start_core_metrics_server` → bind port 9465 → leak a detached thread across the many per-process boots. Add an **autouse fixture** in `tests/unit/cli/daemon/conftest.py` that stubs the seam for every daemon boot test that does not assert on it:

```python
# tests/unit/cli/daemon/conftest.py
import pytest
@pytest.fixture(autouse=True)
def _stub_core_metrics_server(monkeypatch):
    import alfred.cli.daemon._commands as cmd
    monkeypatch.setattr(cmd, "_start_core_metrics_server", lambda: None)
```

(The dedicated `test_daemon_boot_metrics.py` from Steps 1-4 patches `start_metrics_server` directly, so it still exercises the seam.) Then:

Run: `uv run pytest tests/unit/cli/daemon -q`
Expected: PASS, no `EADDRINUSE`/thread-leak warnings.

- [ ] **Step 6: Commit**

```bash
git add src/alfred/cli/daemon/_commands.py tests/unit/cli/daemon/test_daemon_boot_metrics.py
git commit -m "feat(daemon): #470 serve core /metrics over the curated registry at boot"
```

---

## Task 5: `alfred daemon healthcheck` (metrics-endpoint liveness) + i18n

**Files:**

- Create: `src/alfred/cli/daemon/_healthcheck.py`
- Modify: `src/alfred/cli/daemon/__init__.py`
- Modify: the i18n catalog (`daemon.healthcheck.*`)
- Test: `tests/unit/cli/daemon/test_daemon_healthcheck.py`

**Interfaces:**

- Consumes: `fetch_metrics_text`, `resolve_metrics_port` (Task 1).
- Produces: `healthcheck_daemon() -> None` (exit 0 healthy / 1 unhealthy; never a traceback).

- [ ] **Step 1: Write the failing trio (happy / error / bad-port)**

```python
# tests/unit/cli/daemon/test_daemon_healthcheck.py
import pytest, typer
from unittest.mock import patch
from alfred.cli.daemon._healthcheck import healthcheck_daemon

def test_healthy_when_metrics_reachable(monkeypatch):
    monkeypatch.setenv("ALFRED_CORE_METRICS_PORT", "9465")
    with patch("alfred.cli.daemon._healthcheck.fetch_metrics_text", return_value="# ok\n"):
        healthcheck_daemon()  # no raise == exit 0

def test_unhealthy_when_metrics_unreachable(monkeypatch):
    monkeypatch.setenv("ALFRED_CORE_METRICS_PORT", "9465")
    with patch("alfred.cli.daemon._healthcheck.fetch_metrics_text", side_effect=OSError("refused")):
        with pytest.raises(typer.Exit) as e:
            healthcheck_daemon()
    assert e.value.exit_code == 1

def test_unhealthy_on_bad_port(monkeypatch):
    monkeypatch.setenv("ALFRED_CORE_METRICS_PORT", "70000")
    with pytest.raises(typer.Exit) as e:
        healthcheck_daemon()
    assert e.value.exit_code == 1
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/unit/cli/daemon/test_daemon_healthcheck.py -q`
Expected: FAIL — module missing.

- [ ] **Step 3: Implement the command**

```python
# src/alfred/cli/daemon/_healthcheck.py
"""`alfred daemon healthcheck` — metrics-endpoint liveness probe (#470).

Scope: liveness of the /metrics endpoint ONLY, not full data-plane readiness (spec §5.4). A
metrics-bind failure marks the container unhealthy with a DISTINCT operator message; because
nothing depends_on core health, this is observational — it makes the loud-and-continue bind
failure visible (HARD rule 7) without wedging the stack.
"""
from __future__ import annotations

from typing import Final

import structlog
import typer

from alfred.i18n import t
from alfred.observability.metrics_server import fetch_metrics_text, resolve_metrics_port

log = structlog.get_logger(__name__)
_HOST: Final[str] = "127.0.0.1"
_EXIT_UNHEALTHY: Final[int] = 1

def healthcheck_daemon() -> None:
    try:
        port = resolve_metrics_port("ALFRED_CORE_METRICS_PORT", 9465)
    except ValueError as exc:
        log.warning("daemon.healthcheck.bad_port", error=repr(exc))
        typer.echo(t("daemon.healthcheck.bad_port"))  # distinct config-error message (i18n-004)
        raise typer.Exit(code=_EXIT_UNHEALTHY) from exc
    try:
        fetch_metrics_text(_HOST, port)
    except OSError as exc:
        log.warning("daemon.healthcheck.metrics_unreachable", port=port, error=repr(exc))
        typer.echo(t("daemon.healthcheck.metrics_unreachable", port=port))
        raise typer.Exit(code=_EXIT_UNHEALTHY) from exc
```

Register the command in `src/alfred/cli/daemon/__init__.py`:

```python
@daemon_app.command("healthcheck", help=t("daemon.help.healthcheck"))
def healthcheck() -> None:
    from alfred.cli.daemon._healthcheck import healthcheck_daemon
    healthcheck_daemon()
```

- [ ] **Step 4: Add the i18n catalog keys + run the drift-gate (rev.1 i18n-001/003/004)**

Add three keys to the catalog at `locale/en/LC_MESSAGES/alfred.po` (the repo's canonical catalog, domain `alfred` — NOT `src/alfred/i18n/locales`):

- `daemon.help.healthcheck` → "Probe the core /metrics endpoint; exit non-zero if unreachable."
- `daemon.healthcheck.metrics_unreachable` → "Core metrics endpoint unreachable on port {port}; the data plane may still be serving." (keeps the `{port}` placeholder — the msgstr is NOT brace-free; `t()` does `raw.format(**vars)`.)
- `daemon.healthcheck.bad_port` → "ALFRED_CORE_METRICS_PORT is invalid; cannot probe the core metrics endpoint." (distinct message for the config-error branch — i18n-004.)

Run the drift-gate (correct path + domain):

```bash
pybabel extract -F babel.cfg -o /tmp/alfred.pot src/alfred plugins \
  && pybabel update -i /tmp/alfred.pot -d locale -D alfred --no-fuzzy-matching \
  && pybabel compile -d locale -D alfred
```

Expected: no fuzzy/missing entries; the `metrics_unreachable` msgstr retains its `{port}` placeholder and every `{...}` is a valid `str.format` field.

- [ ] **Step 5: Run to verify it passes**

Run: `uv run pytest tests/unit/cli/daemon/test_daemon_healthcheck.py -q`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/alfred/cli/daemon/_healthcheck.py src/alfred/cli/daemon/__init__.py src/alfred/i18n tests/unit/cli/daemon/test_daemon_healthcheck.py
git commit -m "feat(daemon): #470 add daemon healthcheck probing the core metrics endpoint"
```

---

## Task 6: Compose wiring — core metrics port env + healthcheck + never-published pin

> **Port contract — 9465 is FIXED for the bundled stack (rev.1 arch-001/rev-004; rev.2 disambiguation;
> spec §5.5).** `ALFRED_CORE_METRICS_PORT` sets the *daemon bind* port (default 9465), mirroring the
> gateway's `ALFRED_GATEWAY_METRICS_PORT`. **Prometheus cannot env-expand a `static_configs` target**,
> so PR2's scrape target is the literal `alfred-core:9465`. Rather than leave two places that must be
> edited in lockstep, the decision is: **the env var is a bind-port seam, not a supported operator
> knob** — it exists so the daemon and `alfred daemon healthcheck` resolve one port from one place,
> and so a test can bind an ephemeral port. That is exactly the status of the gateway's
> `ALFRED_GATEWAY_METRICS_PORT` against its likewise-hardcoded `alfred-gateway:9464`. Overriding it in
> compose without also editing `ops/prometheus/prometheus.yml` silently breaks scraping and nothing
> validates it; do **not** document it as a tunable. Making it genuinely tunable would require
> generating the scrape config from the resolved value with startup validation plus a non-default-port
> test — a design change, not a config change. The compose comment, the spec, and both plans state
> this identically.

**Files:**

- Modify: `docker-compose.yaml` (`alfred-core`)
- Test: `tests/unit/test_compose_invariants.py`

- [ ] **Step 1: Write the failing invariant tests**

```python
# tests/unit/test_compose_invariants.py  (append)
_CORE_METRICS_PORT = 9465

def test_core_metrics_port_never_host_published(compose):
    for name, svc in (compose.get("services", {}) or {}).items():
        for mapping in svc.get("ports", []) or []:
            assert _container_port(mapping) != str(_CORE_METRICS_PORT), (
                f"{name} host-publishes the core metrics port {_CORE_METRICS_PORT}; it must stay "
                "compose-internal (#470)."
            )

def test_alfred_core_has_metrics_healthcheck(compose):
    core = compose["services"]["alfred-core"]
    assert core.get("healthcheck", {}).get("test") == ["CMD", "alfred", "daemon", "healthcheck"]

def test_alfred_core_sets_core_metrics_port(compose):
    env = compose["services"]["alfred-core"].get("environment", {}) or {}
    assert env.get("ALFRED_CORE_METRICS_PORT") == "${ALFRED_CORE_METRICS_PORT:-9465}"
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run pytest tests/unit/test_compose_invariants.py -q -k "core_metrics or metrics_healthcheck"`
Expected: FAIL.

- [ ] **Step 3: Add the env + healthcheck to `alfred-core` in `docker-compose.yaml`**

Under `alfred-core:` add to `environment:` `ALFRED_CORE_METRICS_PORT: ${ALFRED_CORE_METRICS_PORT:-9465}`, and add (no `ports:` line — never host-published):

```yaml
    healthcheck:
      test: ["CMD", "alfred", "daemon", "healthcheck"]
      interval: 15s
      timeout: 5s
      retries: 3
      start_period: 30s
```

- [ ] **Step 4: Run to verify they pass + full compose-invariant suite**

Run: `uv run pytest tests/unit/test_compose_invariants.py -q`
Expected: PASS (incl. the existing `test_only_gateway_on_external`, `test_core_joins_internal_only`).

- [ ] **Step 5: Commit**

```bash
git add docker-compose.yaml tests/unit/test_compose_invariants.py
git commit -m "feat(compose): #470 wire core metrics port + healthcheck (never host-published)"
```

---

## Task 7: Full-gate pass (quality bar + adversarial suite)

- [ ] **Step 1: Run the full quality gates**

Run: `uv run ruff check . && uv run ruff format --check . && uv run mypy src/ && uv run pyright src/`
Expected: clean.

- [ ] **Step 2: Run the adversarial suite (defense-in-depth)**

PR1 **imports from** `src/alfred/security/observability.py` (the `CAPABILITY_REVOKED_COUNTER`) and reshapes the security-relevant `/metrics` surface, but does **not edit** that file (the edit is PR2 Task 6) — so the HARD "changed `src/alfred/security/`" trigger fires in PR2, not strictly here (rev.1 arch-003/test-007). Run it here anyway as a safety net for the surface change:

Run: `uv run pytest tests/adversarial -q`
Expected: PASS (release-blocking).

- [ ] **Step 3: Confirm the gates — run the observability coverage gate EXPLICITLY (not via `make check`)**

Run: `uv run coverage report --include='src/alfred/observability/*' --fail-under=100 --show-missing`
Expected: 100%. **`make check` does NOT run the per-module coverage gates (#474)** — do not rely on it for this; the CI job (Task 3 Step 3) and this explicit command are the real gate.

Run: `make check` — Expected: lint/format/type/test clean (mechanical bar), understanding it does not exercise the coverage gate above.

- [ ] **Step 4: No commit unless a fix was needed** (fixups per the in-branch-fixes convention).

---

## Self-Review

**Spec coverage (§5):** §5.1 → Task 1; §5.2 (`CORE_OWNED_COLLECTORS`, value-boundedness) → Task 2 + the label-key pin in Task 3; §5.3 (two-sided oracle-independent leak-guard + coverage gate) → Task 3; §5.4 (boot seam, counter-at-zero, healthcheck plane-scope, i18n) → Tasks 4+5; §5.5 (port + compose healthcheck) → Task 6. §7 adversarial obligation → Task 7.

**Type consistency:** `resolve_metrics_port(env_var, default)` and `start_metrics_server(port, registry=None)` and `fetch_metrics_text(host, port)` are used identically in Tasks 1/4/5. `build_core_registry()` / `CORE_OWNED_COLLECTORS` consistent across Tasks 2/3/4. `_start_core_metrics_server` seam name consistent (Task 4 def == boot call).

**Placeholders:** none — every code step shows code; the coverage-config line and i18n catalog file are named by their role (the implementer's tree has one). Image/port literals are concrete (9465).

**Boundary note:** PR2 (Prometheus/Grafana services, scrape job, rules, docs, caveat reframe) + the ADR-0040 amendment are a **separate plan** (`2026-07-21-470-pr2-observability-bundle.md`, to be written) — PR1 leaves the endpoint scrapeable + its failure observable, standing on its own.

---

## rev.1 fold log (8-lane plan-review)

**Critical** `[×4 reproduced]` — Task 3 leak-guard failed at t=0 (`_total` strip / `_created` siblings / no-labels-at-t=0): rewrote Task 3 Step 1-2 (parser-named `_EXPECTED_FAMILIES`, `_created` filter, declared-`_labelnames` label pin, anti-weakening note) + fixed Task 2's smoke assertion.
**High** — i18n pybabel path/domain (Task 5 Step 4 → `-d locale -D alfred`); coverage-gate is a CI `coverage report --fail-under=100` step not a config toggle + `make check` doesn't run it (Task 3 Step 3 / Task 7 Step 3, #474); signature-change breaks existing gateway tests (Task 1 Step 6 grep+update).
**Medium** — port contract PR1↔PR2 (Task 6 note: scrape target is literal 9465); boot-seam anchor precision + `_start_async` placement (Task 4 Step 3); boot-test isolation via autouse fixture (Task 4 Step 5); bind-failure branch test (add in Task 1 — the `start_metrics_server` OSError arm — to hit 100%).
**Low** — adversarial rationale corrected: PR1 imports, doesn't edit `security/observability.py` (Task 7 Step 2); counter-at-zero wording accurate for labeled families (Task 4 docstring, core-006); `_egress.py` host arg (Task 1 Step 5); distinct `daemon.healthcheck.bad_port` message (Task 5, i18n-004); imports consolidated (no mid-file re-import, rev-008); trio render-assertion + brace-free wording (i18n-002/003, addressed in Task 5 Step 4 Expected).

## rev.2 fold log (PR #480 review — documentation wave)

- **Task 1 shim decision reversed** — `src/alfred/gateway/metrics_server.py` is **deleted**, not
  shimmed. The "back-compat" re-export was not back-compatible: pre-#470 `resolve_metrics_port` took
  no arguments, so every importer had to migrate to the two-argument form anyway, leaving the shim
  with zero consumers.
- **Task 6 port contract disambiguated** — `ALFRED_CORE_METRICS_PORT` is a bind-port seam, not an
  operator knob; 9465 is fixed for the bundled stack (matching the gateway's hardcoded 9464
  precedent). Stated identically in `docker-compose.yaml`, the spec §5.5, and the PR2 plan.
- **ADR-0040 amended in PR1, not deferred** — the Decision-1 inbound-listener class-line and residual
  **(viii)** (unauthenticated plaintext `/metrics` readable by any `alfred_internal` peer) are both
  true at PR1 merge, so they land here; only the third-party-services arm waits for PR2.

## rev.3 fold log (PR #480 CodeRabbit cloud review)

- **Shipped fetch-helper signature supersedes this plan's `(host, port)` steps.** Tasks 1 and 3 above
  specify `fetch_metrics_text(host: str, port: int)` and call sites passing `_HEALTHCHECK_HOST`. The
  implementation folded a security finding (sec-001) during execution: the destination host is now
  the module constant `_LOOPBACK_HOST = "127.0.0.1"` inside
  `src/alfred/observability/metrics_server.py`, **not** a parameter, so the no-SSRF property is
  structural rather than a convention every call site must remember. The shipped surface is
  **`fetch_metrics_text(port: int) -> str`**, and `cli/daemon/_healthcheck.py`,
  `cli/gateway/_commands.py`, and `cli/gateway/_egress.py` all call it with the port alone. The steps
  are left as executed for the record; read this entry before quoting their signature. The design doc
  (`…-470-core-metrics-observability-design.md` §5.1/§14) has been corrected in place.
