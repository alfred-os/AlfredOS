# G6-0 — Deployable Always-Up Gateway Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the AlfredOS gateway a long-running Compose service alongside a daemon-ified `alfred-core`, sharing a socket volume, with a Prometheus `/metrics` exposition + a two-tier healthcheck + an `ops/` observability scaffold — the deployment precursor that Spec B's adapter hosting (G6-1+) builds on. (Completes Spec A's deferred G3-4.)

**Architecture:** The gateway already exists as code (`src/alfred/gateway/`) and runs via `alfred gateway start`, but it has never been a deployed service: there is no `alfred-gateway` Compose service, `alfred-core` is a one-shot command runner, and although the gateway *registers* Prometheus collectors it *exposes* none over HTTP. This plan adds the missing runtime surface only — no adapter hosting, no SETUID move (that is G6-1). The gateway dials the core on `comms-tui.sock` and binds `comms-gateway.sock`, both under `/home/alfred/.run/alfred`; core + gateway share that directory via a new `alfred_run` named volume.

**Tech Stack:** Docker Compose, `prometheus_client` (already a dependency), Typer CLI, pytest, PyYAML (already a dep), stdlib `urllib`/`http.server`.

---

## Design decisions made in this plan (for architect + security plan-review scrutiny)

These were not pinned by the spec; they are made here with defensible defaults and flagged for the plan-review gate:

1. **First Prometheus HTTP exposition in the system.** No `/metrics` endpoint exists anywhere today (the gateway, `comms_mcp`, and `supervisor` all register collectors with no exposition). G6-0 adds it for the gateway via `prometheus_client.start_http_server(port)`, port from `ALFRED_GATEWAY_METRICS_PORT` (default **9464**). It binds on the compose-internal network only — **no host port is published** — so it is not externally reachable. This establishes the exposition pattern the daemon/supervisor can reuse later.
2. **Metrics-server start is loud-and-continue, not fatal.** A metrics-port bind failure logs `gateway.metrics.bind_failed` (loud) but does **not** drop the relay/chat data plane (observability must not kill delivery). The healthcheck (decision 3) then surfaces the degraded state, so the container is still marked unhealthy.
3. **Two-tier healthcheck reads the breaker gauge over `/metrics`.** A new `alfred gateway healthcheck` command (run by Docker `HEALTHCHECK`, a separate process) does an HTTP GET to `127.0.0.1:{port}/metrics`: **liveness** = endpoint reachable; **readiness** = `gateway_circuit_breaker_open != 1`. It deliberately does **not** require `gateway_core_link_up == 1` — a core-down gateway that is buffering is *healthy* (that is the whole resume point); only wedged-past-breaker is unhealthy (spec §7). This is why metrics + healthcheck land together rather than as a deploy/observe split.
4. **Shared-volume ownership via the image.** The `alfred_run` volume mounts at `/home/alfred/.run`; the Dockerfile pre-creates that dir owned by `alfred:alfred` mode `0700` so the named volume inherits `alfred` ownership on first mount (the container runs as `USER alfred` and cannot `chown` a root-owned mount). `_runtime_dir()` then creates `/home/alfred/.run/alfred` as an alfred-owned subdir.
5. **Gateway has NO `cap_add: SETUID` in G6-0.** SETUID moves into the gateway in **G6-1** (with ADR-0036 + the devops-010 positive-allowed-set reframe). G6-0's compose-invariant test asserts the gateway does **not** have SETUID yet, so the privilege escalation is a reviewable single-PR event.

---

## File structure

**Create:**

- `src/alfred/gateway/metrics_server.py` — thin wrapper that starts the Prometheus HTTP exposition for the default registry. One responsibility: serve metrics.
- `ops/prometheus/prometheus.yml` — Prometheus scrape config (the `alfred-gateway` job).
- `ops/alerts/gateway.yml` — Prometheus alerting rules (core-unavailable, buffer-near-cap, breaker-open).
- `ops/grafana/gateway.json` — Grafana dashboard for the gateway metrics.
- `tests/unit/gateway/test_metrics_server.py` — metrics-server wrapper unit tests.
- `tests/unit/cli/test_gateway_healthcheck.py` — healthcheck command unit tests.
- `tests/unit/test_ops_scaffold.py` — validity tests for the `ops/` artifacts.

**Modify:**

- `src/alfred/cli/gateway/_commands.py` — start the metrics server in `start_gateway()`; add `healthcheck_gateway()`.
- `src/alfred/cli/gateway/__init__.py` — register the `healthcheck` subcommand.
- `locale/en/LC_MESSAGES/alfred.po` (+ compiled `.mo`) — new `gateway.help.healthcheck` / `gateway.healthcheck.*` keys.
- `tests/unit/cli/test_gateway_cli.py` — assert `healthcheck` is registered.
- `docker/alfred-core.Dockerfile` — pre-create `/home/alfred/.run` owned by alfred 0700.
- `docker-compose.yaml` — daemon-ify `alfred-core`; add `alfred-gateway` service; add `alfred_run` volume.
- `tests/unit/test_compose_invariants.py` — gateway-service invariants; core-daemon invariants.

---

## Task 1: Gateway Prometheus metrics exposition

**Files:**

- Create: `src/alfred/gateway/metrics_server.py`
- Test: `tests/unit/gateway/test_metrics_server.py`

- [ ] **Step 1: Write the failing test**

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
    monkeypatch.setattr(
        metrics_server, "start_http_server", lambda port: calls.append(port)
    )
    ok = metrics_server.start_metrics_server(9464)
    assert ok is True
    assert calls == [9464]


def test_start_loud_and_continue_on_bind_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(port: int) -> None:
        raise OSError("address in use")

    monkeypatch.setattr(metrics_server, "start_http_server", _boom)
    # Loud-and-continue (decision 2): returns False, does NOT raise.
    assert metrics_server.start_metrics_server(9464) is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/gateway/test_metrics_server.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'alfred.gateway.metrics_server'`.

- [ ] **Step 3: Write minimal implementation**

```python
# src/alfred/gateway/metrics_server.py
"""Prometheus HTTP exposition for the gateway's default-registry collectors (G6-0).

The gateway registers its collectors on the default ``prometheus_client`` registry at
import (see :mod:`alfred.gateway.metrics`), but nothing has ever *served* them. This
module starts the standard ``prometheus_client`` HTTP exposition so a Prometheus
scrape can read ``gateway_*`` series. It is the first ``/metrics`` endpoint in the
system; the daemon / supervisor can reuse the pattern later.

Decision (G6-0): a metrics-port bind failure is LOUD-AND-CONTINUE — observability must
never drop the relay/chat data plane. The two-tier healthcheck
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
    silently fall back, CLAUDE.md hard rule #7 / #13).
    """
    raw = os.environ.get(_METRICS_PORT_ENV)
    if raw is None or raw == "":
        return _DEFAULT_METRICS_PORT
    return int(raw)  # ValueError on a bad value surfaces loud.


def start_metrics_server(port: int) -> bool:
    """Start the Prometheus exposition on ``port``; return True on success.

    Loud-and-continue on an ``OSError`` (e.g. EADDRINUSE): logs
    ``gateway.metrics.bind_failed`` and returns False rather than raising, so the
    relay still runs (decision 2).
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

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/gateway/test_metrics_server.py -q`
Expected: PASS (5 passed).

- [ ] **Step 5: Wire the metrics server into `start_gateway()`**

In `src/alfred/cli/gateway/_commands.py`, inside `start_gateway()`, after `typer.echo(t("gateway.start.starting"))` and before the `async def _main()` block, add the metrics-server bootstrap:

```python
    # G6-0: stand up the Prometheus exposition before the relay so a scrape can read
    # gateway_* series. Loud-and-continue on a bind failure (observability must not
    # drop the data plane); the healthcheck surfaces a degraded endpoint.
    from alfred.gateway.metrics_server import resolve_metrics_port, start_metrics_server

    start_metrics_server(resolve_metrics_port())
```

- [ ] **Step 6: Run the gateway CLI suite to confirm no regression**

Run: `uv run pytest tests/unit/cli/test_gateway_cli.py -q`
Expected: PASS (existing tests still green — the new import is lazy inside the command body).

- [ ] **Step 7: Commit**

```bash
git add src/alfred/gateway/metrics_server.py tests/unit/gateway/test_metrics_server.py src/alfred/cli/gateway/_commands.py
git commit -m "feat(gateway): Prometheus /metrics exposition for the gateway process (Spec B G6-0) (#288)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 2: `alfred gateway healthcheck` command (two-tier, via /metrics)

**Files:**

- Modify: `src/alfred/cli/gateway/_commands.py`
- Modify: `src/alfred/cli/gateway/__init__.py`
- Test: `tests/unit/cli/test_gateway_healthcheck.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/cli/test_gateway_healthcheck.py
"""`alfred gateway healthcheck` — two-tier liveness/readiness probe (G6-0)."""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from alfred.cli.gateway import gateway_app


@pytest.fixture(autouse=True)
def _env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-test")
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")


def _patch_fetch(monkeypatch: pytest.MonkeyPatch, text: str | None) -> None:
    # text=None simulates an unreachable endpoint (liveness fail).
    from alfred.cli.gateway import _commands

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
    _patch_fetch(monkeypatch, "gateway_circuit_breaker_open 0.0\n")
    result = CliRunner().invoke(gateway_app, ["healthcheck"])
    assert result.exit_code == 0


def test_healthy_when_core_link_down_but_breaker_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    # Core-down + buffering is HEALTHY (the resume point); only the breaker matters.
    _patch_fetch(
        monkeypatch,
        "gateway_core_link_up 0.0\ngateway_circuit_breaker_open 0.0\n",
    )
    result = CliRunner().invoke(gateway_app, ["healthcheck"])
    assert result.exit_code == 0


def test_unhealthy_when_breaker_open(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_fetch(monkeypatch, "gateway_circuit_breaker_open 1.0\n")
    result = CliRunner().invoke(gateway_app, ["healthcheck"])
    assert result.exit_code == 1


def test_unhealthy_when_unreachable(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_fetch(monkeypatch, None)
    result = CliRunner().invoke(gateway_app, ["healthcheck"])
    assert result.exit_code == 1
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/cli/test_gateway_healthcheck.py -q`
Expected: FAIL — `healthcheck` not in help / `AttributeError: _fetch_metrics_text`.

- [ ] **Step 3: Implement `_fetch_metrics_text` + `healthcheck_gateway` in `_commands.py`**

Append to `src/alfred/cli/gateway/_commands.py` (before `__all__`), and add `urllib.request` to the imports at module top:

```python
# (add near the existing stdlib imports at module top)
import urllib.request

# Health-probe network constants. The metrics endpoint is compose-internal; the probe
# runs INSIDE the container (Docker HEALTHCHECK), so localhost is correct.
_HEALTHCHECK_HOST: Final[str] = "127.0.0.1"
_HEALTHCHECK_TIMEOUT_S: Final[float] = 2.0
_BREAKER_METRIC: Final[str] = "gateway_circuit_breaker_open"
_EXIT_UNHEALTHY: Final[int] = 1


def _fetch_metrics_text(port: int) -> str:
    """GET the gateway /metrics exposition text. Raises OSError when unreachable."""
    url = f"http://{_HEALTHCHECK_HOST}:{port}/metrics"
    with urllib.request.urlopen(url, timeout=_HEALTHCHECK_TIMEOUT_S) as resp:  # noqa: S310 (fixed localhost scheme)
        return resp.read().decode("utf-8")


def _breaker_latched(metrics_text: str) -> bool:
    """True iff the exposition reports gateway_circuit_breaker_open == 1."""
    for line in metrics_text.splitlines():
        if line.startswith(_BREAKER_METRIC) and not line.startswith("#"):
            # Format: "gateway_circuit_breaker_open 1.0"
            value = line.split()[-1]
            return float(value) >= 1.0
    return False


def healthcheck_gateway() -> None:
    """Two-tier Docker healthcheck (G6-0).

    Liveness: the /metrics endpoint is reachable. Readiness: the ReplayBuffer
    back-pressure breaker is NOT latched. A core-down gateway that is buffering is
    HEALTHY (spec §7) — only wedged-past-breaker is unhealthy. Exits 0 (healthy) or
    1 (unhealthy); never raises a traceback.
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

Add `"healthcheck_gateway"` to the `__all__` list in the same file.

- [ ] **Step 4: Register the subcommand in `__init__.py`**

In `src/alfred/cli/gateway/__init__.py`, after the `status` command, add:

```python
@gateway_app.command("healthcheck", help=t("gateway.help.healthcheck"))
def healthcheck() -> None:
    from alfred.cli.gateway._commands import healthcheck_gateway

    healthcheck_gateway()
```

- [ ] **Step 5: Run test to verify it passes**

Run: `uv run pytest tests/unit/cli/test_gateway_healthcheck.py -q`
Expected: FAIL — missing i18n keys (`gateway.help.healthcheck`, `gateway.healthcheck.*`). That is fixed in Task 3; run again after Task 3.

- [ ] **Step 6: Commit (with Task 3, after keys exist)**

Defer the commit to the end of Task 3 so the command + its strings land together.

---

## Task 3: i18n keys for the healthcheck command

**Files:**

- Modify: `locale/en/LC_MESSAGES/alfred.po`
- Modify: `tests/unit/cli/test_gateway_cli.py`

- [ ] **Step 1: Add the new msgid/msgstr blocks to the catalog**

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

- [ ] **Step 3: Verify the catalog drift gate passes**

Run: `uv run pybabel extract -F babel.cfg -o /tmp/alfred.pot src/ && uv run pybabel update -i /tmp/alfred.pot -d locale -D alfred --no-fuzzy-matching --check`
Expected: no drift error (the new `t()` call sites are present in the catalog).
NOTE: never pass `--omit-header` to `pybabel update` (it strips the required header → fuzzy/skip). Plain `update ... --no-fuzzy-matching` preserves the header and fixes `#:` location refs.

- [ ] **Step 4: Add the registration assertion to the existing CLI test**

In `tests/unit/cli/test_gateway_cli.py`, in `test_gateway_subcommands_listed`, add:

```python
    assert "healthcheck" in result.stdout
```

- [ ] **Step 5: Run the gateway CLI + healthcheck suites**

Run: `uv run pytest tests/unit/cli/test_gateway_cli.py tests/unit/cli/test_gateway_healthcheck.py -q`
Expected: PASS (all green now that the keys resolve).

- [ ] **Step 6: Commit**

```bash
git add src/alfred/cli/gateway/_commands.py src/alfred/cli/gateway/__init__.py locale/en/LC_MESSAGES/alfred.po locale/en/LC_MESSAGES/alfred.mo tests/unit/cli/test_gateway_healthcheck.py tests/unit/cli/test_gateway_cli.py
git commit -m "feat(gateway): alfred gateway healthcheck two-tier probe + i18n (Spec B G6-0) (#288)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 4: Dockerfile — pre-own the shared runtime dir

**Files:**

- Modify: `docker/alfred-core.Dockerfile`

- [ ] **Step 1: Add the runtime-dir creation after the `useradd` for `alfred`**

In `docker/alfred-core.Dockerfile`, in the `RUN` block that creates the `alfred` user (the `useradd --system --gid alfred --create-home --home-dir /home/alfred alfred` line, ~line 70), append to that same `&&` chain (before the `USER alfred` line):

```dockerfile
    && mkdir -p /home/alfred/.run \
    && chown alfred:alfred /home/alfred/.run \
    && chmod 0700 /home/alfred/.run \
```

This makes `/home/alfred/.run` exist, owned by `alfred` mode `0700`, BEFORE the `alfred_run` named volume mounts there — so Docker initializes the fresh volume with `alfred` ownership (the container runs as `USER alfred` and cannot `chown` a root-owned mount). `_runtime_dir()` then creates `/home/alfred/.run/alfred` as an alfred-owned subdir.

- [ ] **Step 2: Verify the image builds**

Run: `docker build -f docker/alfred-core.Dockerfile -t alfred-core:g6-0-check .`
Expected: build succeeds; `docker run --rm --user alfred alfred-core:g6-0-check sh -c 'ls -ld /home/alfred/.run'` prints a `drwx------ ... alfred alfred` line.

- [ ] **Step 3: Commit**

```bash
git add docker/alfred-core.Dockerfile
git commit -m "build(docker): pre-own /home/alfred/.run so the alfred_run volume inherits alfred ownership (Spec B G6-0) (#288)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 5: Compose — daemon-ify core, add the gateway service + shared volume (TDD via invariants)

**Files:**

- Test: `tests/unit/test_compose_invariants.py`
- Modify: `docker-compose.yaml`

- [ ] **Step 1: Write the failing invariant tests**

Append to `tests/unit/test_compose_invariants.py`:

```python
def test_alfred_core_is_long_running_daemon(compose: dict[str, Any]) -> None:
    """alfred-core must run `daemon start` with a restart policy (Spec B G6-0).

    The one-shot command-runner model dies after each subcommand; the gateway needs
    a long-running core to dial, so core becomes the daemon service.
    """
    core = compose.get("services", {}).get("alfred-core", {})
    assert core.get("command") == ["daemon", "start"], (
        "alfred-core must run `daemon start` as a long-running daemon for the gateway "
        "to have a core socket to dial."
    )
    assert core.get("restart") == "unless-stopped", (
        "alfred-core must restart unless-stopped now that it is the daemon."
    )


def test_alfred_core_has_alfred_run_volume(compose: dict[str, Any]) -> None:
    """alfred-core must mount alfred_run at /home/alfred/.run (shared socket dir)."""
    core = compose.get("services", {}).get("alfred-core", {})
    entries = _volume_strings(core.get("volumes", []) or [])
    assert "alfred_run:/home/alfred/.run" in entries, (
        "alfred-core must share alfred_run at /home/alfred/.run so the gateway can "
        "dial comms-tui.sock under the shared runtime dir."
    )


def test_alfred_gateway_service_exists(compose: dict[str, Any]) -> None:
    gw = compose.get("services", {}).get("alfred-gateway")
    assert gw is not None, "alfred-gateway service must exist (Spec B G6-0)."
    assert gw.get("command") == ["gateway", "start"]
    assert gw.get("restart") == "unless-stopped"


def test_alfred_gateway_has_no_setuid(compose: dict[str, Any]) -> None:
    """G6-0: the gateway is still a pure relay — SETUID arrives in G6-1, not here."""
    gw = compose.get("services", {}).get("alfred-gateway", {})
    cap_add = gw.get("cap_add", []) or []
    assert "SETUID" not in cap_add, (
        "alfred-gateway must NOT have SETUID in G6-0 (it hosts no adapters yet). "
        "SETUID moves into the gateway in G6-1 with ADR-0036."
    )


def test_alfred_gateway_has_no_state_git_volume(compose: dict[str, Any]) -> None:
    gw = compose.get("services", {}).get("alfred-gateway", {})
    entries = _volume_strings(gw.get("volumes", []) or [])
    assert not any("alfred_state_git" in v for v in entries), (
        "alfred-gateway must not mount alfred_state_git — the relay has no business "
        "with grant files."
    )


def test_alfred_gateway_has_alfred_run_volume(compose: dict[str, Any]) -> None:
    gw = compose.get("services", {}).get("alfred-gateway", {})
    entries = _volume_strings(gw.get("volumes", []) or [])
    assert "alfred_run:/home/alfred/.run" in entries, (
        "alfred-gateway must share alfred_run at /home/alfred/.run to reach the core "
        "socket and bind its own client socket."
    )


def test_alfred_gateway_readiness_independent_of_core(compose: dict[str, Any]) -> None:
    """depends_on must NOT gate the gateway on core health (spec §7 invariant).

    The gateway must boot even when the core is down (resume). A `service_healthy`
    condition would block the always-up gateway behind core liveness.
    """
    gw = compose.get("services", {}).get("alfred-gateway", {})
    depends = gw.get("depends_on", {})
    if isinstance(depends, dict):
        core_dep = depends.get("alfred-core", {})
        assert core_dep.get("condition") != "service_healthy", (
            "alfred-gateway must not depend on alfred-core service_healthy — gateway "
            "readiness is independent of core liveness."
        )
    else:
        # list form (start-order only, no condition) is acceptable
        assert "alfred-core" in depends
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run pytest tests/unit/test_compose_invariants.py -q`
Expected: FAIL — new tests fail (no gateway service; core has no command/restart/alfred_run).

- [ ] **Step 3: Edit `docker-compose.yaml` — daemon-ify `alfred-core`**

In the `alfred-core:` service, add `command` + `restart` (after the `build:` block) and add the `alfred_run` volume mount to its `volumes:` list:

```yaml
  alfred-core:
    build:
      context: .
      dockerfile: docker/alfred-core.Dockerfile
    # Spec B G6-0: alfred-core is now the long-running daemon (was a one-shot command
    # runner). The gateway dials its comms-tui.sock, so the core must stay up.
    command: ["daemon", "start"]
    restart: unless-stopped
    depends_on:
      alfred-postgres:
        condition: service_healthy
      alfred-redis:
        condition: service_healthy
    cap_add:
      - SETUID
    environment:
      # ... (unchanged) ...
    volumes:
      - alfred_state_git:/var/lib/alfred
      # Spec B G6-0: shared socket dir for the gateway leg (comms-tui.sock lives here).
      - alfred_run:/home/alfred/.run
```

(Keep the existing `environment:` block and the `alfred_state_git` mount exactly as they are; only `command`, `restart`, and the `alfred_run` volume line are added.)

- [ ] **Step 4: Edit `docker-compose.yaml` — add the `alfred-gateway` service**

Add after the `alfred-discord:` service block and before `volumes:`:

```yaml
  # Spec B G6-0 (#288) — the always-up resumable gateway. Reuses the alfred-core
  # image (one Dockerfile) and runs the long-running `alfred gateway start`. It is a
  # pure relay in G6-0 (no adapter hosting, no SETUID — those arrive in G6-1+). It
  # shares the alfred_run volume so it can dial the core's comms-tui.sock and bind its
  # own comms-gateway.sock under /home/alfred/.run/alfred. `depends_on` is start-order
  # only (NOT service_healthy): the gateway must boot even when the core is down so it
  # can hold a client across a core restart (spec §7 — readiness independent of core).
  alfred-gateway:
    build:
      context: .
      dockerfile: docker/alfred-core.Dockerfile
    command: ["gateway", "start"]
    restart: unless-stopped
    depends_on:
      - alfred-core
    environment:
      ALFRED_OPERATOR_LANGUAGE: ${ALFRED_OPERATOR_LANGUAGE:-en-US}
      # Prometheus exposition port (compose-internal only; no host port published).
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

- [ ] **Step 5: Add the `alfred_run` named volume**

In the `volumes:` block at the bottom of `docker-compose.yaml`, add:

```yaml
volumes:
  alfred_pg_data:
  alfred_redis_data:
  alfred_state_git:
  alfred_run:
```

- [ ] **Step 6: Run the invariant tests + compose config validity**

Run: `uv run pytest tests/unit/test_compose_invariants.py -q`
Expected: PASS (all, including the pre-existing core/discord/redis invariants).
Run: `docker compose config --quiet && echo OK`
Expected: `OK` (YAML + interpolation valid).

- [ ] **Step 7: Commit**

```bash
git add docker-compose.yaml tests/unit/test_compose_invariants.py
git commit -m "feat(compose): daemon-ify alfred-core + add always-up alfred-gateway service on shared alfred_run volume (Spec B G6-0) (#288)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 6: `ops/` observability scaffold (scrape + alerts + dashboard)

**Files:**

- Create: `ops/prometheus/prometheus.yml`
- Create: `ops/alerts/gateway.yml`
- Create: `ops/grafana/gateway.json`
- Test: `tests/unit/test_ops_scaffold.py`

- [ ] **Step 1: Write the failing validity test**

```python
# tests/unit/test_ops_scaffold.py
"""Validity assertions for the ops/ observability scaffold (Spec B G6-0).

These do not run Prometheus/Grafana; they assert the committed config parses and
declares the gateway scrape job + the three gateway alerts + a non-empty dashboard,
so a typo doesn't ship a silently-broken ops tree.
"""

from __future__ import annotations

import json
from pathlib import Path

import yaml

OPS = Path(__file__).parent.parent.parent / "ops"


def test_prometheus_scrape_has_gateway_job() -> None:
    cfg = yaml.safe_load((OPS / "prometheus" / "prometheus.yml").read_text())
    jobs = {s["job_name"] for s in cfg["scrape_configs"]}
    assert "alfred-gateway" in jobs


def test_gateway_alerts_present() -> None:
    cfg = yaml.safe_load((OPS / "alerts" / "gateway.yml").read_text())
    names = {
        rule["alert"]
        for group in cfg["groups"]
        for rule in group["rules"]
        if "alert" in rule
    }
    assert {"GatewayCoreUnavailable", "GatewayBufferNearCap", "GatewayCircuitBreakerOpen"} <= names


def test_gateway_dashboard_parses_and_has_panels() -> None:
    dash = json.loads((OPS / "grafana" / "gateway.json").read_text())
    assert dash.get("title")
    assert len(dash.get("panels", [])) >= 1
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/unit/test_ops_scaffold.py -q`
Expected: FAIL — `FileNotFoundError` (no `ops/` tree).

- [ ] **Step 3: Create `ops/prometheus/prometheus.yml`**

```yaml
# AlfredOS Prometheus scrape config (Spec B G6-0, #288).
# The gateway exposes /metrics on ALFRED_GATEWAY_METRICS_PORT (default 9464) on the
# compose-internal network. Point a Prometheus at this file (or merge the job into an
# existing scrape config). The gateway service name resolves on the compose network.
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
    {
      "id": 1,
      "title": "Core link up",
      "type": "stat",
      "gridPos": {"h": 4, "w": 6, "x": 0, "y": 0},
      "targets": [{"expr": "gateway_core_link_up"}]
    },
    {
      "id": 2,
      "title": "Circuit breaker open",
      "type": "stat",
      "gridPos": {"h": 4, "w": 6, "x": 6, "y": 0},
      "targets": [{"expr": "gateway_circuit_breaker_open"}]
    },
    {
      "id": 3,
      "title": "ReplayBuffer depth (frames)",
      "type": "timeseries",
      "gridPos": {"h": 8, "w": 12, "x": 0, "y": 4},
      "targets": [{"expr": "gateway_buffer_depth_frames"}]
    },
    {
      "id": 4,
      "title": "ReplayBuffer cap ratio",
      "type": "timeseries",
      "gridPos": {"h": 8, "w": 12, "x": 12, "y": 4},
      "targets": [{"expr": "gateway_buffer_cap_ratio"}]
    },
    {
      "id": 5,
      "title": "Reconnect attempts (rate)",
      "type": "timeseries",
      "gridPos": {"h": 8, "w": 12, "x": 0, "y": 12},
      "targets": [{"expr": "rate(gateway_reconnect_attempts_total[5m])"}]
    },
    {
      "id": 6,
      "title": "Core unavailable seconds (rate)",
      "type": "timeseries",
      "gridPos": {"h": 8, "w": 12, "x": 12, "y": 12},
      "targets": [{"expr": "rate(gateway_core_unavailable_seconds_total[5m])"}]
    }
  ]
}
```

- [ ] **Step 6: Run to verify the validity test passes**

Run: `uv run pytest tests/unit/test_ops_scaffold.py -q`
Expected: PASS (3 passed).

- [ ] **Step 7: Commit**

```bash
git add ops/ tests/unit/test_ops_scaffold.py
git commit -m "feat(ops): gateway Prometheus scrape + alerts + Grafana dashboard scaffold (Spec B G6-0) (#288)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 7: Full quality gate + README/runbook note

**Files:**

- Modify: `README.md` (quickstart — gateway service note)

- [ ] **Step 1: Add a gateway note to the README quickstart**

In `README.md`, in the deployment/quickstart section that lists the compose services, add a sentence:

```markdown
`docker compose up -d` now also starts **`alfred-gateway`** — the always-up resumable
front door that holds an `alfred chat` session across a core restart. It exposes
Prometheus metrics on the compose-internal `alfred-gateway:9464/metrics`
(see `ops/prometheus/prometheus.yml`).
```

(If the README has no service list yet, add the sentence under the `docker compose up` instruction.)

- [ ] **Step 2: Run the full local quality gate**

Run: `uv run ruff check . && uv run ruff format --check . && uv run mypy src/ && uv run pytest tests/unit -q`
Expected: all green. Fix any lint/type findings in the files this plan touched before proceeding.

- [ ] **Step 3: Run markdownlint on the touched docs**

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

**1. Spec coverage (spec §9 G6-0 row + §7 deployment correction):**

- Long-running `alfred-gateway` Compose service → Task 5. ✓
- `alfred-core` daemon-ification → Task 5. ✓
- Shared `alfred_run` volume (+ ownership) → Task 4 (image) + Task 5 (mounts + volume). ✓
- Two-tier healthcheck → Task 2 (command) + Task 5 (compose `healthcheck:`). ✓
- Create `ops/grafana/gateway.json` + `ops/alerts/gateway.yml` + Prometheus scrape → Task 6. ✓
- Prometheus exposition endpoint (implied by "scrape"; was missing system-wide) → Task 1. ✓
- devops-010 reframe to `{core, gateway}` SETUID positive-allowed-set → **NOT here** — that is G6-1 (gateway has no SETUID in G6-0; Task 5 asserts its absence). Intentional per epic order. ✓
- Operator migration runbook / Discord flag-day → **NOT here** — G6-5. ✓

**2. Placeholder scan:** No "TBD"/"add error handling"/"similar to Task N". Every code step shows full code; every run step shows the command + expected output. ✓

**3. Type/name consistency:** `resolve_metrics_port()` / `start_metrics_server()` (Task 1) are the names imported in Task 2 (`_commands.py`) and Task 1 Step 5 (`start_gateway`). `_fetch_metrics_text(port)` / `_breaker_latched()` / `healthcheck_gateway()` (Task 2) match the test's monkeypatch target and the `__init__.py` import (Task 2 Step 4). Volume string `alfred_run:/home/alfred/.run` is identical in Tasks 4/5 and both invariant tests. Metrics port default `9464` is identical across Task 1, the compose env, and the scrape target. ✓

**Open item for plan-review (not a gap):** the metrics-server uses `prometheus_client.start_http_server`, which serves the **default registry** — confirm no other module's collectors leak onto the gateway's exposition in a way that matters (they are all `gateway_*` / distinct names today). Flag for the security reviewer: the endpoint binds `0.0.0.0` inside the container with no host port published; confirm that posture is acceptable (decision 1).
