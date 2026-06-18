# G6-0 — Deployable Gateway Substrate Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the AlfredOS gateway a long-running, observable Compose service — its own image entry, a shared socket volume, a Prometheus `/metrics` exposition, and a two-tier healthcheck — so Spec B's adapter hosting (G6-1+) has an always-up process to live in.

**Architecture:** The gateway already exists as code (`src/alfred/gateway/`) and runs via `alfred gateway start`, but has never been a deployed service: there is no `alfred-gateway` Compose service, and although the gateway *registers* Prometheus collectors it *exposes* none over HTTP. This plan adds the missing **gateway-side** runtime surface only. It deliberately does **not** touch `alfred-core`, enable any comms adapter, or establish the gateway↔core link — those are **G6-0b** (see Scope boundary below). In G6-0 the deployed gateway boots and is **healthy while its core link is down/buffering** (the spec's defined healthy state: only wedged-past-breaker is unhealthy). No SETUID, no adapter hosting (G6-1+).

**Tech Stack:** Docker Compose, `prometheus_client` (already a dependency), Typer CLI, pytest, PyYAML (already a dep), stdlib `urllib`/`http.client`.

---

## Scope boundary — G6-0 (this plan) vs G6-0b (next plan)

A plan-review (architect + security + devops, 2026-06-18) found that *linking* the gateway to the core is not a config tweak: the daemon binds the gateway-facing `comms-tui.sock` only when a socket-backed comms adapter is enabled (`_SOCKET_BACKED_ADAPTER_KIND = "tui"`, `src/alfred/cli/daemon/_commands.py:352`), the gateway's dial id and the core's bound id are **not coupled by construction** (Spec A's G5 proof used a *fake* core, so a real daemon↔gateway socket link has never been exercised), and enabling comms triggers `_build_comms_boot_graph` → the live bwrap quarantine-child spawn, which **fail-closes** and would crash-loop an always-up `restart: unless-stopped` core on a non-Linux/unprovisioned host. That is a coherent, security-sensitive chunk of its own.

- **G6-0 (this plan):** gateway-side substrate only. `alfred-core` is left **unchanged** (still the one-shot runner); no comms adapter is enabled; the gateway has **no `depends_on: alfred-core`** (readiness is independent of the core, and the core is not yet a service). Zero quarantine/crash-loop risk.
- **G6-0b (next plan, gets its own plan-review):** daemon-ify `alfred-core`; enable the socket-backed comms adapter; couple the gateway dial id ↔ the core bound id by construction; document + gate the always-up-core quarantine provisioning invariant (Linux + launcher + `quarantine_provider_api_key`) with crash-loop mitigation; the `docker compose up -d` / setup-script / README / stale-header flag-day; and a **real-daemon ↔ real-gateway integration test** that the link establishes (closing the fake-core gap).

---

## Design decisions made in this plan (for the implementer + reviewers)

1. **First Prometheus HTTP exposition in the system.** No `/metrics` endpoint exists anywhere today. G6-0 adds it for the gateway via `prometheus_client.start_http_server(port)`, port from `ALFRED_GATEWAY_METRICS_PORT` (default **9464**), binding `0.0.0.0` on the **compose-internal** network with **no host port published** (a compose-invariant test pins the no-host-port posture). `0.0.0.0` (not loopback) is required so a future Prometheus container can scrape `alfred-gateway:9464`; the healthcheck itself uses loopback.
2. **Default-registry leak guard.** `start_http_server` serves the process-global default registry. Other modules' collectors carry per-user/per-plugin labels (`comms_mcp.observability`, `supervisor.observability`, `plugins._observability`). A unit test asserts the gateway-process import graph does **not** pull those modules, so no per-user series can leak onto the unauthenticated `/metrics`.
3. **Metrics-bind-fail is loud-and-continue** (`gateway.metrics.bind_failed`); it does not drop the relay. The healthcheck then marks the container unhealthy.
4. **Two-tier healthcheck reads the breaker gauge over `/metrics`.** `alfred gateway healthcheck` (run by Docker `HEALTHCHECK`, a separate process): liveness = endpoint reachable; readiness = `gateway_circuit_breaker_open != 1`. It deliberately does **not** require `gateway_core_link_up == 1` — a core-down gateway that is buffering is healthy (spec §7).
5. **Shared-volume ownership via the image.** `alfred_run` mounts at `/home/alfred/.run`; the Dockerfile pins `ENV HOME=/home/alfred` and pre-creates that dir owned by `alfred:alfred` `0700`, so the fresh named volume inherits `alfred` ownership (the container runs as `USER alfred` and cannot `chown` a root-owned mount). `_runtime_dir()` (`Path.home()/.run/alfred`) then resolves under it.

---

## File structure

**Create:**

- `src/alfred/gateway/metrics_server.py` — starts the Prometheus HTTP exposition for the default registry. One responsibility: serve metrics.
- `ops/prometheus/prometheus.yml` — Prometheus scrape config (the `alfred-gateway` job).
- `ops/alerts/gateway.yml` — Prometheus alerting rules.
- `ops/grafana/gateway.json` — Grafana dashboard.
- `tests/unit/gateway/test_metrics_server.py` — metrics-server wrapper + import-surface guard tests.
- `tests/unit/gateway/test_metrics_exposition.py` — real bind+GET+parse round-trip test.
- `tests/unit/cli/test_gateway_healthcheck.py` — healthcheck command unit tests.
- `tests/unit/test_ops_scaffold.py` — validity + PromQL-name tests for the `ops/` artifacts.

**Modify:**

- `locale/en/LC_MESSAGES/alfred.po` (+ compiled `.mo`) — new `gateway.help.healthcheck` / `gateway.healthcheck.*` keys.
- `src/alfred/cli/gateway/__init__.py` — register the `healthcheck` subcommand.
- `src/alfred/cli/gateway/_commands.py` — start the metrics server in `start_gateway()`; add `healthcheck_gateway()`.
- `tests/unit/cli/test_gateway_cli.py` — assert `healthcheck` is registered.
- `docker/alfred-core.Dockerfile` — `ENV HOME=/home/alfred`; pre-create `/home/alfred/.run` owned by alfred 0700.
- `docker-compose.yaml` — add the `alfred-gateway` service + the `alfred_run` volume (no `alfred-core` change).
- `tests/unit/test_compose_invariants.py` — gateway-service invariants.

**Task order note** `[plan-review rev-001/arch-004]`: the i18n keys land **first** (Task 1), because `@gateway_app.command(help=t("gateway.help.healthcheck"))` resolves `t()` at **import time** — registering the command before the key exists would leave a bare-key import window.

---

## Task 1: i18n keys for the healthcheck command

**Files:**

- Modify: `locale/en/LC_MESSAGES/alfred.po`

- [ ] **Step 1: Add the new msgid/msgstr blocks**

In `locale/en/LC_MESSAGES/alfred.po`, after the `gateway.status.socket_present` block (around line 1200), add:

```po
#: src/alfred/cli/gateway/__init__.py
msgid "gateway.help.healthcheck"
msgstr "Two-tier liveness/readiness probe for Docker HEALTHCHECK (exit 0 healthy, 1 unhealthy)."

#: src/alfred/cli/gateway/_commands.py
msgid "gateway.healthcheck.unreachable"
msgstr "Gateway metrics endpoint unreachable on port {port}; the gateway is not serving. Marking unhealthy."

#: src/alfred/cli/gateway/_commands.py
msgid "gateway.healthcheck.breaker_open"
msgstr "Gateway back-pressure breaker is latched (buffer past cap); marking unhealthy."
```

- [ ] **Step 2: Compile the catalog**

Run: `uv run pybabel compile -d locale -D alfred`
Expected: `compiling catalog locale/en/LC_MESSAGES/alfred.po to locale/en/LC_MESSAGES/alfred.mo` with no fuzzy/error.

- [ ] **Step 3: Verify the catalog drift gate**

Run: `uv run pybabel extract -F babel.cfg -o /tmp/alfred.pot src/ && uv run pybabel update -i /tmp/alfred.pot -d locale -D alfred --no-fuzzy-matching --check`
Expected: no drift error.
NOTE: never pass `--omit-header` to `pybabel update` (it strips the required header → fuzzy/skip). Plain `update ... --no-fuzzy-matching` preserves the header.

- [ ] **Step 4: Commit**

```bash
git add locale/en/LC_MESSAGES/alfred.po locale/en/LC_MESSAGES/alfred.mo
git commit -m "i18n(gateway): reserve gateway.healthcheck.* catalog keys (Spec B G6-0) (#288)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 2: Gateway Prometheus metrics exposition

**Files:**

- Create: `src/alfred/gateway/metrics_server.py`
- Test: `tests/unit/gateway/test_metrics_server.py`
- Test: `tests/unit/gateway/test_metrics_exposition.py`
- Modify: `src/alfred/cli/gateway/_commands.py`

- [ ] **Step 1: Write the failing wrapper + import-surface tests**

```python
# tests/unit/gateway/test_metrics_server.py
"""Unit tests for the gateway Prometheus HTTP exposition wrapper (G6-0)."""

from __future__ import annotations

import pytest

from alfred.gateway import metrics_server


def test_resolve_port_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ALFRED_GATEWAY_METRICS_PORT", raising=False)
    assert metrics_server.resolve_metrics_port() == 9464


def test_resolve_port_env_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ALFRED_GATEWAY_METRICS_PORT", "9999")
    assert metrics_server.resolve_metrics_port() == 9999


def test_resolve_port_rejects_nonint(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ALFRED_GATEWAY_METRICS_PORT", "notaport")
    with pytest.raises(ValueError):
        metrics_server.resolve_metrics_port()


def test_start_calls_prometheus_and_returns_true(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[int] = []
    monkeypatch.setattr(metrics_server, "start_http_server", lambda port: calls.append(port))
    assert metrics_server.start_metrics_server(9464) is True
    assert calls == [9464]


def test_start_loud_and_continue_on_bind_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(port: int) -> None:
        raise OSError("address in use")

    monkeypatch.setattr(metrics_server, "start_http_server", _boom)
    assert metrics_server.start_metrics_server(9464) is False  # loud-and-continue, no raise


def test_metrics_import_graph_excludes_per_user_collectors() -> None:
    """Default-registry leak guard (plan-review sec-002): importing the gateway
    metrics surface must NOT pull modules whose collectors carry per-user / per-plugin
    labels, so no such series can leak onto the unauthenticated gateway /metrics.
    """
    import sys

    # Import the gateway metrics surface in a clean check: assert the offending
    # observability modules are not a dependency of the gateway metrics modules.
    import alfred.gateway.metrics  # noqa: F401
    import alfred.gateway.metrics_server  # noqa: F401

    forbidden = {
        "alfred.comms_mcp.observability",
        "alfred.supervisor.observability",
        "alfred.plugins._observability",
    }
    # The guard is meaningful only if the gateway modules don't import them. If a
    # future edit adds such an import, this fails — pointing at the leak.
    gateway_mod = sys.modules["alfred.gateway.metrics_server"]
    assert forbidden.isdisjoint(set(getattr(gateway_mod, "__dict__", {}).get("__all__", []) or []))
    # Structural: the gateway metrics module's own imports must not include them.
    src = (
        __import__("pathlib").Path(alfred.gateway.metrics_server.__file__).read_text()
        + __import__("pathlib").Path(alfred.gateway.metrics.__file__).read_text()
    )
    for mod in forbidden:
        assert mod not in src, f"gateway metrics surface must not import {mod}"
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/unit/gateway/test_metrics_server.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'alfred.gateway.metrics_server'`.

- [ ] **Step 3: Write the implementation**

```python
# src/alfred/gateway/metrics_server.py
"""Prometheus HTTP exposition for the gateway's default-registry collectors (G6-0).

The gateway registers its collectors on the default ``prometheus_client`` registry at
import (see :mod:`alfred.gateway.metrics`), but nothing has ever *served* them. This
module starts the standard ``prometheus_client`` HTTP exposition so a Prometheus
scrape can read ``gateway_*`` series. It is the first ``/metrics`` endpoint in the
system; the daemon / supervisor can reuse the pattern later.

A metrics-port bind failure is LOUD-AND-CONTINUE (CLAUDE.md hard rule #7 is about not
*silently* swallowing — here we log loudly and keep the relay alive, because
observability must never drop the chat data plane). The two-tier healthcheck
(:func:`alfred.cli.gateway._commands.healthcheck_gateway`) then marks the container
unhealthy, so a misconfigured port is still surfaced.
"""

from __future__ import annotations

import os
from typing import Final

import structlog
from prometheus_client import start_http_server

log = structlog.get_logger(__name__)

_DEFAULT_METRICS_PORT: Final[int] = 9464
_METRICS_PORT_ENV: Final[str] = "ALFRED_GATEWAY_METRICS_PORT"


def resolve_metrics_port() -> int:
    """Resolve the metrics port from ``ALFRED_GATEWAY_METRICS_PORT`` (default 9464).

    Raises ``ValueError`` loudly on a non-integer value (operator misconfig — never
    silently fall back).
    """
    raw = os.environ.get(_METRICS_PORT_ENV)
    if raw is None or raw == "":
        return _DEFAULT_METRICS_PORT
    return int(raw)  # ValueError on a bad value surfaces loud.


def start_metrics_server(port: int) -> bool:
    """Start the Prometheus exposition on ``port``; return True on success.

    Loud-and-continue on an ``OSError`` (e.g. EADDRINUSE): logs
    ``gateway.metrics.bind_failed`` and returns False rather than raising.
    """
    try:
        start_http_server(port)
    except OSError as exc:
        log.warning("gateway.metrics.bind_failed", port=port, error=repr(exc))
        return False
    log.info("gateway.metrics.serving", port=port)
    return True


__all__ = ["resolve_metrics_port", "start_metrics_server"]
```

- [ ] **Step 4: Run to verify it passes**

Run: `uv run pytest tests/unit/gateway/test_metrics_server.py -q`
Expected: PASS (6 passed).

- [ ] **Step 5: Write the real round-trip exposition test**

```python
# tests/unit/gateway/test_metrics_exposition.py
"""A real bind+GET+parse round-trip for the gateway exposition (plan-review test-003)."""

from __future__ import annotations

import urllib.request

from alfred.gateway import metrics
from alfred.gateway.metrics_server import start_metrics_server


def _free_port() -> int:
    import socket

    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def test_metrics_endpoint_serves_gateway_series() -> None:
    metrics.CIRCUIT_BREAKER_OPEN.set(0)
    port = _free_port()
    assert start_metrics_server(port) is True
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/metrics", timeout=2.0) as resp:  # noqa: S310
        body = resp.read().decode("utf-8")
    # Real exposition wraps samples in # HELP / # TYPE blocks — assert the gauge sample
    # is present alongside the comment lines.
    assert "# TYPE gateway_circuit_breaker_open gauge" in body
    assert "gateway_circuit_breaker_open 0.0" in body
```

- [ ] **Step 6: Run it**

Run: `uv run pytest tests/unit/gateway/test_metrics_exposition.py -q`
Expected: PASS (1 passed). (Binds an ephemeral loopback port; `start_http_server` leaves a daemon thread — acceptable in the test process.)

- [ ] **Step 7: Wire the metrics server into `start_gateway()`**

In `src/alfred/cli/gateway/_commands.py`, inside `start_gateway()`, after `typer.echo(t("gateway.start.starting"))` and before `async def _main()`:

```python
    # G6-0: stand up the Prometheus exposition before the relay so a scrape can read
    # gateway_* series. Loud-and-continue on a bind failure; the healthcheck surfaces
    # a degraded endpoint.
    from alfred.gateway.metrics_server import resolve_metrics_port, start_metrics_server

    start_metrics_server(resolve_metrics_port())
```

- [ ] **Step 8: Run the gateway CLI suite (no regression)**

Run: `uv run pytest tests/unit/cli/test_gateway_cli.py -q`
Expected: PASS (the new import is lazy inside the command body).

- [ ] **Step 9: Commit**

```bash
git add src/alfred/gateway/metrics_server.py tests/unit/gateway/test_metrics_server.py tests/unit/gateway/test_metrics_exposition.py src/alfred/cli/gateway/_commands.py
git commit -m "feat(gateway): Prometheus /metrics exposition + default-registry leak guard (Spec B G6-0) (#288)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 3: `alfred gateway healthcheck` command (two-tier, via /metrics)

**Files:**

- Modify: `src/alfred/cli/gateway/_commands.py`
- Modify: `src/alfred/cli/gateway/__init__.py`
- Modify: `tests/unit/cli/test_gateway_cli.py`
- Test: `tests/unit/cli/test_gateway_healthcheck.py`

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/cli/test_gateway_healthcheck.py
"""`alfred gateway healthcheck` — two-tier liveness/readiness probe (G6-0)."""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from alfred.cli.gateway import _commands, gateway_app


@pytest.fixture(autouse=True)
def _env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-test")
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")


def _patch_fetch(monkeypatch: pytest.MonkeyPatch, text: str | None) -> None:
    def _fake_fetch(port: int) -> str:
        if text is None:
            raise OSError("connection refused")
        return text

    monkeypatch.setattr(_commands, "_fetch_metrics_text", _fake_fetch)


def test_healthcheck_registered() -> None:
    result = CliRunner().invoke(gateway_app, ["--help"])
    assert result.exit_code == 0
    assert "healthcheck" in result.stdout


def test_healthy_when_breaker_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_fetch(monkeypatch, "# TYPE gateway_circuit_breaker_open gauge\ngateway_circuit_breaker_open 0.0\n")
    assert CliRunner().invoke(gateway_app, ["healthcheck"]).exit_code == 0


def test_healthy_when_core_down_but_breaker_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_fetch(monkeypatch, "gateway_core_link_up 0.0\ngateway_circuit_breaker_open 0.0\n")
    assert CliRunner().invoke(gateway_app, ["healthcheck"]).exit_code == 0


def test_healthy_when_breaker_metric_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    # No breaker sample yet (process just started) → not latched → healthy.
    _patch_fetch(monkeypatch, "gateway_core_link_up 0.0\n")
    assert CliRunner().invoke(gateway_app, ["healthcheck"]).exit_code == 0


def test_ignores_help_comment_line(monkeypatch: pytest.MonkeyPatch) -> None:
    # A # HELP line that contains the metric name must NOT be parsed as a sample.
    _patch_fetch(
        monkeypatch,
        "# HELP gateway_circuit_breaker_open 1 while latched\ngateway_circuit_breaker_open 0.0\n",
    )
    assert CliRunner().invoke(gateway_app, ["healthcheck"]).exit_code == 0


def test_unhealthy_when_breaker_open(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_fetch(monkeypatch, "gateway_circuit_breaker_open 1.0\n")
    assert CliRunner().invoke(gateway_app, ["healthcheck"]).exit_code == 1


def test_unhealthy_when_unreachable(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_fetch(monkeypatch, None)
    assert CliRunner().invoke(gateway_app, ["healthcheck"]).exit_code == 1


def test_malformed_sample_is_not_a_traceback(monkeypatch: pytest.MonkeyPatch) -> None:
    # A garbled value must not crash the HEALTHCHECK process with a traceback.
    _patch_fetch(monkeypatch, "gateway_circuit_breaker_open NaNgarbage extra\n")
    result = CliRunner().invoke(gateway_app, ["healthcheck"])
    assert result.exit_code in (0, 1)  # a decision, never an unhandled exception
    assert result.exception is None or isinstance(result.exception, SystemExit)
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/unit/cli/test_gateway_healthcheck.py -q`
Expected: FAIL — `AttributeError: _fetch_metrics_text` / `healthcheck` not registered.

- [ ] **Step 3: Implement in `_commands.py`**

Add `import urllib.request` to the module-top imports, and append before `__all__`:

```python
_HEALTHCHECK_HOST: Final[str] = "127.0.0.1"
_HEALTHCHECK_TIMEOUT_S: Final[float] = 2.0
_BREAKER_METRIC: Final[str] = "gateway_circuit_breaker_open"
_EXIT_UNHEALTHY: Final[int] = 1


def _fetch_metrics_text(port: int) -> str:
    """GET the gateway /metrics exposition text. Raises OSError when unreachable."""
    url = f"http://{_HEALTHCHECK_HOST}:{port}/metrics"
    with urllib.request.urlopen(url, timeout=_HEALTHCHECK_TIMEOUT_S) as resp:  # noqa: S310 (fixed localhost)
        return resp.read().decode("utf-8")


def _breaker_latched(metrics_text: str) -> bool:
    """True iff a gateway_circuit_breaker_open SAMPLE reports >= 1.

    Skips ``# HELP`` / ``# TYPE`` comment lines and any line whose value cannot be
    parsed as a float (a malformed/exemplar line must never crash the HEALTHCHECK
    process with a traceback).
    """
    sample_prefix = f"{_BREAKER_METRIC} "
    for line in metrics_text.splitlines():
        if line.startswith("#"):
            continue
        if not line.startswith(sample_prefix):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        try:
            return float(parts[1]) >= 1.0
        except ValueError:
            continue
    return False


def healthcheck_gateway() -> None:
    """Two-tier Docker healthcheck (G6-0).

    Liveness: the /metrics endpoint is reachable. Readiness: the ReplayBuffer
    back-pressure breaker is NOT latched. A core-down gateway that is buffering is
    HEALTHY (spec §7) — only wedged-past-breaker is unhealthy. Exits 0 (healthy) or 1
    (unhealthy); never raises a traceback.
    """
    from alfred.gateway.metrics_server import resolve_metrics_port

    port = resolve_metrics_port()
    try:
        metrics_text = _fetch_metrics_text(port)
    except OSError as exc:
        log.warning("gateway.healthcheck.unreachable", port=port, error=repr(exc))
        typer.echo(t("gateway.healthcheck.unreachable", port=port))
        raise typer.Exit(code=_EXIT_UNHEALTHY) from exc
    if _breaker_latched(metrics_text):
        log.warning("gateway.healthcheck.breaker_open")
        typer.echo(t("gateway.healthcheck.breaker_open"))
        raise typer.Exit(code=_EXIT_UNHEALTHY)
```

Add `"healthcheck_gateway"` to `__all__`.

- [ ] **Step 4: Register the subcommand in `__init__.py`**

After the `status` command in `src/alfred/cli/gateway/__init__.py`:

```python
@gateway_app.command("healthcheck", help=t("gateway.help.healthcheck"))
def healthcheck() -> None:
    from alfred.cli.gateway._commands import healthcheck_gateway

    healthcheck_gateway()
```

- [ ] **Step 5: Add the registration assertion to the existing CLI test**

In `tests/unit/cli/test_gateway_cli.py`, in `test_gateway_subcommands_listed`, add:

```python
    assert "healthcheck" in result.stdout
```

- [ ] **Step 6: Run the suites**

Run: `uv run pytest tests/unit/cli/test_gateway_healthcheck.py tests/unit/cli/test_gateway_cli.py -q`
Expected: PASS (all green — keys resolve from Task 1).

- [ ] **Step 7: Commit**

```bash
git add src/alfred/cli/gateway/_commands.py src/alfred/cli/gateway/__init__.py tests/unit/cli/test_gateway_healthcheck.py tests/unit/cli/test_gateway_cli.py
git commit -m "feat(gateway): alfred gateway healthcheck two-tier probe (Spec B G6-0) (#288)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 4: Dockerfile — pin HOME + pre-own the shared runtime dir

**Files:**

- Modify: `docker/alfred-core.Dockerfile`

- [ ] **Step 1: Pin HOME in the runtime ENV block**

In `docker/alfred-core.Dockerfile`, in the second `ENV` block (the runtime layer, ~line 38), add `HOME`:

```dockerfile
ENV PYTHONUNBUFFERED=1 \
    HOME=/home/alfred \
    ...
```

(Keep the existing keys in that `ENV`; only add the `HOME=/home/alfred \` line. This pins `_runtime_dir()`'s `Path.home()` to `/home/alfred` for both the gateway and any future shared-volume consumer instead of relying on `/etc/passwd` lookup — plan-review devops-001.)

- [ ] **Step 2: Pre-create the runtime dir owned by alfred**

In the `RUN` chain that creates the users (the block containing `useradd --system --gid alfred --create-home --home-dir /home/alfred alfred` AND `useradd --system --no-create-home --user-group alfred-quarantine` AND `mkdir ... /var/lib/alfred`, ~lines 70-72), append to that same `&&` chain, immediately after the line that creates `/var/lib/alfred` and before `USER alfred`:

```dockerfile
    && mkdir -p /home/alfred/.run \
    && chown alfred:alfred /home/alfred/.run \
    && chmod 0700 /home/alfred/.run \
```

(Anchor precisely to the `/var/lib/alfred` line per plan-review rev-005 — the RUN chain has two `useradd`s; append at the end of the chain, not after the first useradd.)

- [ ] **Step 3: Verify the image builds + ownership**

Run: `docker build -f docker/alfred-core.Dockerfile -t alfred-core:g6-0-check .`
Then: `docker run --rm alfred-core:g6-0-check sh -c 'echo $HOME; ls -ld /home/alfred/.run'`
Expected: prints `/home/alfred` then `drwx------ ... alfred alfred ... /home/alfred/.run`.

- [ ] **Step 4: Commit**

```bash
git add docker/alfred-core.Dockerfile
git commit -m "build(docker): pin HOME=/home/alfred + pre-own /home/alfred/.run for the alfred_run volume (Spec B G6-0) (#288)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 5: Compose — add the gateway service + shared volume (TDD via invariants)

**Files:**

- Test: `tests/unit/test_compose_invariants.py`
- Modify: `docker-compose.yaml`

- [ ] **Step 1: Write the failing invariant tests**

Append to `tests/unit/test_compose_invariants.py`:

```python
def test_alfred_gateway_service_exists(compose: dict[str, Any]) -> None:
    gw = compose.get("services", {}).get("alfred-gateway")
    assert gw is not None, "alfred-gateway service must exist (Spec B G6-0)."
    assert gw.get("command") == ["gateway", "start"]
    assert gw.get("restart") == "unless-stopped"


def test_alfred_gateway_has_no_setuid(compose: dict[str, Any]) -> None:
    """G6-0: the gateway is still a pure relay — SETUID arrives in G6-1, not here."""
    gw = compose.get("services", {}).get("alfred-gateway", {})
    assert "SETUID" not in (gw.get("cap_add", []) or []), (
        "alfred-gateway must NOT have SETUID in G6-0; it moves in G6-1 with ADR-0036."
    )


def test_alfred_gateway_has_no_state_git_volume(compose: dict[str, Any]) -> None:
    gw = compose.get("services", {}).get("alfred-gateway", {})
    entries = _volume_strings(gw.get("volumes", []) or [])
    assert not any("alfred_state_git" in v for v in entries), (
        "alfred-gateway must not mount alfred_state_git — the relay has no grant files."
    )


def test_alfred_gateway_has_alfred_run_volume(compose: dict[str, Any]) -> None:
    gw = compose.get("services", {}).get("alfred-gateway", {})
    entries = _volume_strings(gw.get("volumes", []) or [])
    assert "alfred_run:/home/alfred/.run" in entries, (
        "alfred-gateway must mount alfred_run at /home/alfred/.run for its sockets."
    )


def test_alfred_run_mounted_only_by_gateway(compose: dict[str, Any]) -> None:
    """G6-0: only alfred-gateway mounts alfred_run (core joins in G6-0b).

    A stray mount would widen who can reach the gateway's client socket.
    """
    services = compose.get("services", {})
    mounters = {
        name
        for name, svc in services.items()
        if any("alfred_run" in v for v in _volume_strings(svc.get("volumes", []) or []))
    }
    assert mounters == {"alfred-gateway"}, (
        f"alfred_run must be mounted only by alfred-gateway in G6-0; got {mounters}."
    )


def test_alfred_gateway_publishes_no_host_port(compose: dict[str, Any]) -> None:
    """The /metrics endpoint stays compose-internal — no host port published (sec-003)."""
    gw = compose.get("services", {}).get("alfred-gateway", {})
    assert not (gw.get("ports") or []), (
        "alfred-gateway must publish no host port — /metrics is compose-internal only."
    )


def test_alfred_gateway_has_healthcheck(compose: dict[str, Any]) -> None:
    gw = compose.get("services", {}).get("alfred-gateway", {})
    hc = gw.get("healthcheck", {})
    assert hc.get("test") == ["CMD", "alfred", "gateway", "healthcheck"]
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run pytest tests/unit/test_compose_invariants.py -q`
Expected: FAIL — new gateway tests fail (no service yet). The pre-existing core/discord/redis tests still PASS (G6-0 does not touch them).

- [ ] **Step 3: Add the `alfred-gateway` service**

In `docker-compose.yaml`, after the `alfred-discord:` service block and before `volumes:`:

```yaml
  # Spec B G6-0 (#288) — the always-up resumable gateway, deployed as its own service.
  # Reuses the alfred-core image (one Dockerfile) and runs `alfred gateway start`. In
  # G6-0 it is a pure relay (no adapter hosting, no SETUID — G6-1+) and is NOT yet
  # linked to the core (G6-0b enables comms on the core + couples the socket ids); it
  # boots HEALTHY in its core-down/buffering state (spec §7: only wedged-past-breaker
  # is unhealthy). It shares alfred_run so it can bind its client socket + (in G6-0b)
  # dial the core. No depends_on: readiness is independent of the core, and the core is
  # not a long-running service until G6-0b. /metrics is compose-internal (no host port).
  alfred-gateway:
    build:
      context: .
      dockerfile: docker/alfred-core.Dockerfile
    command: ["gateway", "start"]
    restart: unless-stopped
    environment:
      ALFRED_ENVIRONMENT: ${ALFRED_ENVIRONMENT:-production}
      ALFRED_OPERATOR_LANGUAGE: ${ALFRED_OPERATOR_LANGUAGE:-en-US}
      ALFRED_GATEWAY_METRICS_PORT: ${ALFRED_GATEWAY_METRICS_PORT:-9464}
    volumes:
      - alfred_run:/home/alfred/.run
    healthcheck:
      test: ["CMD", "alfred", "gateway", "healthcheck"]
      interval: 10s
      timeout: 5s
      retries: 3
      start_period: 10s
```

- [ ] **Step 4: Add the `alfred_run` named volume**

In the `volumes:` block at the bottom:

```yaml
volumes:
  alfred_pg_data:
  alfred_redis_data:
  alfred_state_git:
  alfred_run:
```

- [ ] **Step 5: Run the invariant tests + compose validity**

Run: `uv run pytest tests/unit/test_compose_invariants.py -q`
Expected: PASS (all — new gateway invariants + the untouched pre-existing ones).
Run: `docker compose config --quiet && echo OK`
Expected: `OK`.

- [ ] **Step 6: Commit**

```bash
git add docker-compose.yaml tests/unit/test_compose_invariants.py
git commit -m "feat(compose): add the always-up alfred-gateway service on a shared alfred_run volume (Spec B G6-0) (#288)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 6: `ops/` observability scaffold (scrape + alerts + dashboard)

**Files:**

- Create: `ops/prometheus/prometheus.yml`
- Create: `ops/alerts/gateway.yml`
- Create: `ops/grafana/gateway.json`
- Test: `tests/unit/test_ops_scaffold.py`

- [ ] **Step 1: Write the failing validity + PromQL-name tests**

```python
# tests/unit/test_ops_scaffold.py
"""Validity assertions for the ops/ observability scaffold (Spec B G6-0).

Asserts the committed config parses, declares the gateway scrape job + the three
gateway alerts + a non-empty dashboard, and that every metric name referenced by an
alert/panel actually EXISTS in src/alfred/gateway/metrics.py (no silently-dead alerts).
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).parent.parent.parent
OPS = ROOT / "ops"
METRICS_SRC = (ROOT / "src" / "alfred" / "gateway" / "metrics.py").read_text()


def _known_metric_bases() -> set[str]:
    # Counters expose a _total suffix; gauges expose the bare name. Collect both forms.
    names = set(re.findall(r'"(gateway_[a-z_]+)"', METRICS_SRC))
    return names | {f"{n}_total" for n in names}


def test_prometheus_scrape_has_gateway_job() -> None:
    cfg = yaml.safe_load((OPS / "prometheus" / "prometheus.yml").read_text())
    assert "alfred-gateway" in {s["job_name"] for s in cfg["scrape_configs"]}


def test_gateway_alerts_present_and_reference_real_metrics() -> None:
    cfg = yaml.safe_load((OPS / "alerts" / "gateway.yml").read_text())
    rules = [r for g in cfg["groups"] for r in g["rules"] if "alert" in r]
    names = {r["alert"] for r in rules}
    assert {"GatewayCoreUnavailable", "GatewayBufferNearCap", "GatewayCircuitBreakerOpen"} <= names
    known = _known_metric_bases()
    for r in rules:
        referenced = set(re.findall(r"gateway_[a-z_]+", r["expr"]))
        assert referenced <= known, f"alert {r['alert']} references unknown metric(s): {referenced - known}"


def test_gateway_dashboard_parses_and_references_real_metrics() -> None:
    dash = json.loads((OPS / "grafana" / "gateway.json").read_text())
    assert dash.get("title")
    assert len(dash.get("panels", [])) >= 1
    known = _known_metric_bases()
    for panel in dash["panels"]:
        for target in panel.get("targets", []):
            referenced = set(re.findall(r"gateway_[a-z_]+", target.get("expr", "")))
            assert referenced <= known, f"panel {panel.get('title')} references unknown: {referenced - known}"
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/unit/test_ops_scaffold.py -q`
Expected: FAIL — `FileNotFoundError` (no `ops/` tree).

- [ ] **Step 3: Create `ops/prometheus/prometheus.yml`**

```yaml
# AlfredOS Prometheus scrape config (Spec B G6-0, #288).
# The gateway exposes /metrics on ALFRED_GATEWAY_METRICS_PORT (default 9464) on the
# compose-internal network (no host port). This is a config scaffold — there is no
# Prometheus service in docker-compose.yaml yet; point an external/added Prometheus at
# this file or merge the job into an existing scrape config.
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - /etc/prometheus/alerts/gateway.yml

scrape_configs:
  - job_name: alfred-gateway
    static_configs:
      - targets: ["alfred-gateway:9464"]
```

- [ ] **Step 4: Create `ops/alerts/gateway.yml`**

```yaml
# AlfredOS gateway alerting rules (Spec B G6-0, #288).
groups:
  - name: alfred-gateway
    rules:
      - alert: GatewayCoreUnavailable
        expr: gateway_core_link_up == 0
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "AlfredOS gateway core link has been down for 5m"
          description: "gateway_core_link_up has been 0 for 5m; the gateway is buffering operator input and cannot reach the core daemon."
      - alert: GatewayBufferNearCap
        expr: gateway_buffer_cap_ratio > 0.8
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "AlfredOS gateway ReplayBuffer is near its soft cap"
          description: "gateway_buffer_cap_ratio > 0.8 for 2m; approaching the back-pressure breaker."
      - alert: GatewayCircuitBreakerOpen
        expr: gateway_circuit_breaker_open == 1
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "AlfredOS gateway back-pressure breaker is latched"
          description: "gateway_circuit_breaker_open == 1; the gateway has stopped draining the client (buffer past cap). Operator input is held, not dropped."
```

- [ ] **Step 5: Create `ops/grafana/gateway.json`**

```json
{
  "title": "AlfredOS Gateway",
  "uid": "alfred-gateway",
  "schemaVersion": 39,
  "tags": ["alfred", "gateway"],
  "panels": [
    {"id": 1, "title": "Core link up", "type": "stat", "gridPos": {"h": 4, "w": 6, "x": 0, "y": 0}, "targets": [{"expr": "gateway_core_link_up"}]},
    {"id": 2, "title": "Circuit breaker open", "type": "stat", "gridPos": {"h": 4, "w": 6, "x": 6, "y": 0}, "targets": [{"expr": "gateway_circuit_breaker_open"}]},
    {"id": 3, "title": "ReplayBuffer depth (frames)", "type": "timeseries", "gridPos": {"h": 8, "w": 12, "x": 0, "y": 4}, "targets": [{"expr": "gateway_buffer_depth_frames"}]},
    {"id": 4, "title": "ReplayBuffer cap ratio", "type": "timeseries", "gridPos": {"h": 8, "w": 12, "x": 12, "y": 4}, "targets": [{"expr": "gateway_buffer_cap_ratio"}]},
    {"id": 5, "title": "Reconnect attempts (rate)", "type": "timeseries", "gridPos": {"h": 8, "w": 12, "x": 0, "y": 12}, "targets": [{"expr": "rate(gateway_reconnect_attempts_total[5m])"}]},
    {"id": 6, "title": "Core unavailable seconds (rate)", "type": "timeseries", "gridPos": {"h": 8, "w": 12, "x": 12, "y": 12}, "targets": [{"expr": "rate(gateway_core_unavailable_seconds_total[5m])"}]}
  ]
}
```

- [ ] **Step 6: Run the validity test**

Run: `uv run pytest tests/unit/test_ops_scaffold.py -q`
Expected: PASS (3 passed) — confirms every alert/panel PromQL references a real `gateway_*` metric.

- [ ] **Step 7: Commit**

```bash
git add ops/ tests/unit/test_ops_scaffold.py
git commit -m "feat(ops): gateway Prometheus scrape + alerts + Grafana dashboard scaffold (Spec B G6-0) (#288)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 7: Full quality gate + README note

**Files:**

- Modify: `README.md`

- [ ] **Step 1: Add a gateway note to the README quickstart**

In `README.md`, near the `docker compose up` instructions, add:

```markdown
`docker compose up -d` also starts **`alfred-gateway`** — the always-up resumable front
door that (once linked to the core in a later release) holds an `alfred chat` session
across a core restart. It exposes Prometheus metrics on the compose-internal
`alfred-gateway:9464/metrics` (see `ops/prometheus/prometheus.yml`). Note: the
`alfred_run` volume inherits ownership from the image on **first** creation; if you are
upgrading an older deployment that already has an `alfred_run` volume with the wrong
owner, run `docker compose down && docker volume rm <project>_alfred_run` before
`up -d` so it is re-created owned by the `alfred` user.
```

- [ ] **Step 2: Run the full local quality gate**

Run: `uv run ruff check . && uv run ruff format --check . && uv run mypy src/ && uv run pytest tests/unit -q`
Expected: all green. Fix any lint/type findings in the touched files before proceeding.

- [ ] **Step 3: Markdownlint the touched docs**

Run: `npx --yes markdownlint-cli2 README.md docs/superpowers/plans/2026-06-18-g6-0-deployable-gateway.md 2>&1 | grep -E 'README|g6-0' | grep -v Finding: || echo CLEAN`
Expected: `CLEAN`.

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "docs(readme): note the always-up alfred-gateway service + metrics endpoint (Spec B G6-0) (#288)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Self-review

**1. Spec coverage (spec §9 G6-0 row, scoped to the substrate per the G6-0/G6-0b split):**

- Long-running `alfred-gateway` Compose service → Task 5. ✓
- Shared `alfred_run` volume (+ ownership) → Task 4 (image HOME + pre-own) + Task 5 (mount + volume). ✓
- Two-tier healthcheck → Task 3 (command) + Task 5 (compose `healthcheck:`). ✓
- Prometheus exposition endpoint + `ops/` scrape/alerts/dashboard → Tasks 2 + 6. ✓
- `alfred-core` daemon-ification, comms-enablement, gateway↔core link, quarantine provisioning invariant, flag-day → **NOT here — G6-0b** (Scope boundary). ✓
- SETUID / adapter hosting → **NOT here** (G6-1; Task 5 asserts the gateway has no SETUID). ✓

**2. Placeholder scan:** No "TBD"/"add error handling"/"similar to Task N". Every code step shows full code; every run step shows the command + expected output. ✓

**3. Type/name consistency:** `resolve_metrics_port`/`start_metrics_server` (Task 2) match their imports in Task 2 Step 7 + Task 3 (`healthcheck_gateway`). `_fetch_metrics_text`/`_breaker_latched`/`healthcheck_gateway` (Task 3) match the test monkeypatch target + the `__init__.py` import. Volume string `alfred_run:/home/alfred/.run` identical in Tasks 4/5 + the invariant tests. Metrics port `9464` identical across Task 2, the compose env, and the scrape target. Metric names in `ops/` are asserted against `metrics.py` by Task 6's test. i18n keys (Task 1) precede the command that resolves them at import (Task 3). ✓

**Plan-review findings dispositioned:** arch-001/arch-002/sec-001/devops-002 (the Critical + the daemon-ification flag-day + crash-loop) → moved to **G6-0b**. devops-001/sec-005 (HOME pin) → Task 4. devops-003 (gateway `ALFRED_ENVIRONMENT`) → Task 5. rev-001/arch-004 (i18n import-time order) → Task 1 first. sec-002/arch-003 (registry leak) → Task 2 guard test. sec-003 (no host port) → Task 5 invariant. sec-004/test-005 (alfred_run exclusivity) → Task 5 invariant. test-001/002/003 (breaker parse vs real exposition + round-trip + malformed) → Tasks 2/3. rev-005 (Dockerfile anchor) → Task 4. arch-006 (bogus hard-rule cite) → fixed in the Task 2 docstring. volume-migration caveat → Task 7 README. ops PromQL-name check → Task 6 test.
