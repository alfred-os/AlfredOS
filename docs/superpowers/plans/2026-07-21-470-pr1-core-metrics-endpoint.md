# #470 PR1 — core `/metrics` endpoint + failure-observability Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

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
- Create `src/alfred/observability/core_metrics.py` — `CORE_OWNED_COLLECTORS`, `CORE_METRIC_BASE_NAMES`, `build_core_registry()`.
- Modify `src/alfred/gateway/metrics_server.py` → thin shim re-exporting from `alfred.observability.metrics_server` (keeps `alfred.gateway.metrics_server` import paths alive) OR delete + update imports (Task 1 picks the shim).
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
- Modify: `src/alfred/gateway/metrics_server.py`, `src/alfred/cli/gateway/_commands.py`, `src/alfred/cli/gateway/_egress.py`
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

Replace `src/alfred/gateway/metrics_server.py` body with a re-export shim (keeps existing `alfred.gateway.metrics_server` imports working):

```python
"""Back-compat shim — the exposition moved to alfred.observability.metrics_server (#470)."""
from alfred.observability.metrics_server import (
    fetch_metrics_text, resolve_metrics_port, start_metrics_server,
)
__all__ = ["fetch_metrics_text", "resolve_metrics_port", "start_metrics_server"]
```

Update gateway call sites to pass the gateway env-var/default:

- `src/alfred/cli/gateway/_commands.py:290` → `start_metrics_server(resolve_metrics_port("ALFRED_GATEWAY_METRICS_PORT", 9464))`
- `src/alfred/cli/gateway/_commands.py:546` → `port = resolve_metrics_port("ALFRED_GATEWAY_METRICS_PORT", 9464)`
- `src/alfred/cli/gateway/_egress.py:39` → `port = resolve_metrics_port("ALFRED_GATEWAY_METRICS_PORT", 9464)`
- Replace the local `_fetch_metrics_text(port)` in `cli/gateway/_commands.py` with `fetch_metrics_text(_HEALTHCHECK_HOST, port)` (import from `alfred.observability.metrics_server`); update its callers (`_commands.py:553`, `_egress.py` import).

- [ ] **Step 6: Run the gateway test suite to verify the refactor holds**

Run: `uv run pytest tests/unit/gateway -q && uv run pytest tests/unit/cli/gateway -q`
Expected: PASS (no behavior change for the gateway).

- [ ] **Step 7: Commit**

```bash
git add src/alfred/observability src/alfred/gateway/metrics_server.py src/alfred/cli/gateway tests/unit/observability/test_metrics_server.py
git commit -m "refactor(observability): #470 promote metrics exposition to shared module"
```

---

## Task 2: `CORE_OWNED_COLLECTORS` + curated registry

**Files:**

- Create: `src/alfred/observability/core_metrics.py`
- Test: `tests/unit/observability/test_core_registry_surface.py` (Task 3 adds the leak-guard; this task adds the builder + a smoke test)

**Interfaces:**

- Produces: `CORE_OWNED_COLLECTORS: tuple[Collector, ...]` (10 collectors); `CORE_METRIC_BASE_NAMES: frozenset[str]`; `build_core_registry() -> CollectorRegistry`.

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/observability/test_core_registry_surface.py
from prometheus_client.parser import text_string_to_metric_families
from prometheus_client import generate_latest
from alfred.observability.core_metrics import build_core_registry, CORE_OWNED_COLLECTORS

def test_build_core_registry_serves_the_capability_counter():
    reg = build_core_registry()
    families = {f.name for f in text_string_to_metric_families(generate_latest(reg).decode())}
    assert "alfred_quarantine_capability_revoked_total" in families

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

- [ ] **Step 1: Write the failing two-sided leak-guard**

The expected set is an **independently-authored literal** (NOT derived from `CORE_OWNED_COLLECTORS` — that would be a tautological oracle). Assert on parsed family BASE names (the parser strips `_bucket`/`_sum`/`_count`/`_created`) + label keys.

```python
# append to tests/unit/observability/test_core_registry_surface.py
from prometheus_client import generate_latest
from prometheus_client.parser import text_string_to_metric_families
from alfred.observability.core_metrics import build_core_registry, CORE_OWNED_COLLECTORS

# Reviewed allowlist — hand-authored (spec §5.2). Adding a metric is a deliberate edit here.
_EXPECTED: dict[str, frozenset[str]] = {
    "alfred_quarantine_capability_revoked_total": frozenset(),
    "alfred_comms_inbound_dispatch_seconds": frozenset(),
    "alfred_comms_quarantined_extract_seconds": frozenset(),
    "alfred_comms_burst_limiter_wait_seconds": frozenset(),
    "alfred_comms_handler_failures_total": frozenset(),
    "alfred_orchestrator_action_duration_seconds": frozenset({"user_id_bucket", "action_outcome", "breaker_state"}),
    "alfred_stdio_transport_dispatch_seconds": frozenset({"plugin_id", "method_shape", "outcome"}),
    "alfred_plugin_spawn_seconds": frozenset({"plugin_id", "outcome"}),
    "alfred_outbound_dlp_scan_seconds": frozenset({"outcome"}),
    "alfred_inbound_scanner_scan_seconds": frozenset({"outcome"}),
}

def _exposed() -> dict[str, frozenset[str]]:
    text = generate_latest(build_core_registry()).decode()
    out: dict[str, frozenset[str]] = {}
    for fam in text_string_to_metric_families(text):
        keys: set[str] = set()
        for s in fam.samples:
            keys.update(k for k in s.labels if k != "le")
        out[fam.name] = frozenset(keys)
    return out

def test_no_leak_no_stale_family():
    exposed = _exposed()
    assert set(exposed) == set(_EXPECTED), (
        f"extra={set(exposed) - set(_EXPECTED)} missing={set(_EXPECTED) - set(exposed)}"
    )
    assert not any(n.startswith("gateway_") for n in exposed), "gateway_* leaked onto core /metrics"

def test_label_keys_match_reviewed_allowlist():
    exposed = _exposed()
    for name, keys in _EXPECTED.items():
        assert exposed[name] == keys, f"{name} labels {exposed[name]} != reviewed {keys}"

def test_source_of_truth_matches_reviewed_literal():
    # Independent cross-check: CORE_OWNED_COLLECTORS must not drift from the reviewed literal.
    names = set()
    for c in CORE_OWNED_COLLECTORS:
        text = generate_latest(_single_registry(c)).decode()
        names.update(f.name for f in text_string_to_metric_families(text))
    assert names == set(_EXPECTED)

def _single_registry(collector):
    from prometheus_client import CollectorRegistry
    r = CollectorRegistry(); r.register(collector); return r
```

- [ ] **Step 2: Run to verify it passes (Task 2's builder already satisfies it)**

Run: `uv run pytest tests/unit/observability/test_core_registry_surface.py -q`
Expected: PASS. (If a family is missing, `CORE_OWNED_COLLECTORS` is short — the core-002 bug is caught here.)

- [ ] **Step 3: Add the 100% coverage gate for `src/alfred/observability/`**

Add `src/alfred/observability/` to the per-module `--fail-under=100` coverage set (mirror an existing security-module entry in the coverage config / `Makefile` / CI). Show the exact added line in the diff.

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

    Importing core_metrics registers all ten core families at 0 from t=0. start_http_server spawns a
    detached daemon thread binding a real socket — invisible to the #472 teardown, but tests stub
    this seam so per-test boots don't leak threads/sockets.
    """
    start_metrics_server(
        resolve_metrics_port("ALFRED_CORE_METRICS_PORT", 9465),
        registry=build_core_registry(),
    )
```

In `_start_async`, add `_start_core_metrics_server()` near the top of the boot body — **before** the `Supervisor(...)` construction — mirroring the gateway's pre-relay call site (`cli/gateway/_commands.py:288-290`).

- [ ] **Step 4: Run to verify it passes**

Run: `uv run pytest tests/unit/cli/daemon/test_daemon_boot_metrics.py -q`
Expected: PASS.

- [ ] **Step 5: Guard the existing boot-wiring tests against the real socket**

Confirm the daemon boot-body tests monkeypatch `_start_core_metrics_server` (or `start_metrics_server`) so they never bind a real port. Run the daemon boot test module:

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
        typer.echo(t("daemon.healthcheck.metrics_unreachable", port="unset"))
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

- [ ] **Step 4: Add the i18n catalog keys**

Add to the English catalog source: `daemon.help.healthcheck` ("Probe the core /metrics endpoint; exit non-zero if unreachable.") and `daemon.healthcheck.metrics_unreachable` ("Core metrics endpoint unreachable on port {port}; the data plane may still be serving."). Then run the drift-gate:

Run: `pybabel extract -F babel.cfg -o /tmp/alfred.pot src/alfred plugins && pybabel update --no-fuzzy-matching -i /tmp/alfred.pot -d src/alfred/i18n/locales && pybabel compile -d src/alfred/i18n/locales`
Expected: no fuzzy/missing entries; msgstrs brace-free.

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

- [ ] **Step 2: Run the adversarial suite (PR1 edits `src/alfred/security/observability.py` in Task 3's coverage config + imports it)**

Run: `uv run pytest tests/adversarial -q`
Expected: PASS (release-blocking).

- [ ] **Step 3: Confirm `make check` and the per-module coverage gates**

Run: `make check`
Expected: clean, incl. the new `src/alfred/observability/` 100% gate.

- [ ] **Step 4: No commit unless a fix was needed** (fixups per the in-branch-fixes convention).

---

## Self-Review

**Spec coverage (§5):** §5.1 → Task 1; §5.2 (`CORE_OWNED_COLLECTORS`, value-boundedness) → Task 2 + the label-key pin in Task 3; §5.3 (two-sided oracle-independent leak-guard + coverage gate) → Task 3; §5.4 (boot seam, counter-at-zero, healthcheck plane-scope, i18n) → Tasks 4+5; §5.5 (port + compose healthcheck) → Task 6. §7 adversarial obligation → Task 7.

**Type consistency:** `resolve_metrics_port(env_var, default)` and `start_metrics_server(port, registry=None)` and `fetch_metrics_text(host, port)` are used identically in Tasks 1/4/5. `build_core_registry()` / `CORE_OWNED_COLLECTORS` consistent across Tasks 2/3/4. `_start_core_metrics_server` seam name consistent (Task 4 def == boot call).

**Placeholders:** none — every code step shows code; the coverage-config line and i18n catalog file are named by their role (the implementer's tree has one). Image/port literals are concrete (9465).

**Boundary note:** PR2 (Prometheus/Grafana services, scrape job, rules, docs, caveat reframe) + the ADR-0040 amendment are a **separate plan** (`2026-07-21-470-pr2-observability-bundle.md`, to be written) — PR1 leaves the endpoint scrapeable + its failure observable, standing on its own.
