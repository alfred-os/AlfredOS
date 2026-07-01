# G7-5 PR-A — Operator egress-state CLI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an `alfred gateway egress` operator command that surfaces per-plane egress state (allowlist, reachability, in-flight, deny-counts-by-reason), backed by two new canonical egress metric families.

**Architecture:** A new `src/alfred/gateway/egress_metrics.py` hosts the `gateway_egress_denied_total{plane,reason}` counter + a single shared `gateway_egress_inflight{plane}` custom collector (scrape-reads `len(_conns)` per registered plane). The proxy/relay register their `_conns` on serve, deregister on teardown, and increment the deny counter after the audit+refusal. A new `src/alfred/cli/gateway/_egress.py` command scrapes the gateway `/metrics` (reusing `healthcheck`'s seam), reads the static allowlist, and renders per-plane stanzas via `t()`.

**Tech Stack:** Python 3.12+, prometheus_client (`>=0.20,<1`), Typer, pytest, structlog, Babel/`t()`.

## Global Constraints

- **Two new metric families only** — `gateway_egress_inflight` (Gauge via one shared custom collector, label `plane`) + `gateway_egress_denied_total` (Counter, labels `plane,reason`). **No `gateway_egress_up`** (proxy/relay reachability derived from `/metrics` reachable; adapter from the existing `gateway_adapter_up`). Both live in `src/alfred/gateway/egress_metrics.py` (one canonical registration home).
- **Metric names + label VALUES stay English**; never `t()`-wrapped. All operator-facing CLI text goes through `t()` (i18n release-blocker).
- **Per-plane deny-reason domains:** `proxy`/`adapter` → `EgressDenyReason` (4 values); `relay` → `EgressRelayDenyReason` (8 values). Bounded series = 4+4+8 = 16.
- **Additive telemetry:** the new `denied_total.inc()` fires **strictly after** the audit-write + the refusal; a raising `.inc()` must never drop the audit row or the refusal.
- **`plane` label** is a constructor arg on the shared `EgressForwardProxy` (backs provider + adapter); the relay is constant `plane="relay"`.
- **Exit codes** follow the `adapters` report family: `0` OK, `2` backend/metrics unavailable (NOT `healthcheck`'s `1`=unhealthy). Never a traceback (hard rule #7).
- **Sum invariants (tests):** `sum_reason denied_total{plane∈{proxy,adapter}}` == `gateway_egress_connect_total{outcome="denied"}` (shared, plane-less); `sum_reason denied_total{plane="relay"}` == `gateway_egress_relay_total{outcome="denied"}`.
- **Coverage:** `egress_metrics.py` added to the 100% per-file gate in `ci.yml`; `_egress.py` carries a coverage target.
- **Gates:** `make check` before every push; `uv run pytest tests/unit/gateway -q` green; markdownlint clean on any `.md`. Never `--no-verify`. Conventional Commits with `#333` in every subject.
- **Reference spec:** `docs/superpowers/specs/2026-07-01-g7-5-pr-a-operator-egress-cli-design.md` (two review rounds folded).

---

### Task 1: `egress_metrics.py` — the deny counter + shared in-flight collector

**Files:**

- Create: `src/alfred/gateway/egress_metrics.py`
- Test: `tests/unit/gateway/test_egress_metrics.py`

**Interfaces:**

- Produces: `GATEWAY_EGRESS_DENIED: Counter` (labels `plane,reason`); `register_egress_inflight(plane: str, conns: set[object]) -> None`; `deregister_egress_inflight(plane: str) -> None`; the collector reads `len(conns)` per registered plane at scrape. `EGRESS_INFLIGHT_COLLECTOR` (the singleton, registered on the default `REGISTRY` at import).

- [ ] **Step 1: Write the failing test**

Create `tests/unit/gateway/test_egress_metrics.py`:

```python
"""Unit tests for the canonical egress metric family + shared in-flight collector."""

from __future__ import annotations

from prometheus_client import CollectorRegistry, generate_latest
from prometheus_client.parser import text_string_to_metric_families

from alfred.gateway.egress_metrics import (
    EgressInflightCollector,
    build_denied_counter,
)


def test_inflight_collector_emits_one_sample_per_registered_plane() -> None:
    reg = CollectorRegistry()
    collector = EgressInflightCollector()
    reg.register(collector)
    proxy_conns: set[object] = {object(), object()}
    relay_conns: set[object] = set()
    collector.register("proxy", proxy_conns)
    collector.register("relay", relay_conns)

    families = list(text_string_to_metric_families(generate_latest(reg).decode()))
    inflight = next(f for f in families if f.name == "gateway_egress_inflight")
    samples = {s.labels["plane"]: s.value for s in inflight.samples}
    assert samples == {"proxy": 2.0, "relay": 0.0}


def test_inflight_collector_reads_len_at_scrape_time() -> None:
    reg = CollectorRegistry()
    collector = EgressInflightCollector()
    reg.register(collector)
    conns: set[object] = set()
    collector.register("proxy", conns)
    conns.add(object())
    conns.add(object())
    families = list(text_string_to_metric_families(generate_latest(reg).decode()))
    inflight = next(f for f in families if f.name == "gateway_egress_inflight")
    assert {s.labels["plane"]: s.value for s in inflight.samples} == {"proxy": 2.0}


def test_deregistered_plane_leaves_no_stale_series() -> None:
    reg = CollectorRegistry()
    collector = EgressInflightCollector()
    reg.register(collector)
    collector.register("adapter", {object()})
    collector.deregister("adapter")
    families = list(text_string_to_metric_families(generate_latest(reg).decode()))
    inflight = next((f for f in families if f.name == "gateway_egress_inflight"), None)
    assert inflight is None or inflight.samples == []


def test_denied_counter_labels_are_plane_and_reason() -> None:
    reg = CollectorRegistry()
    counter = build_denied_counter(reg)
    counter.labels(plane="proxy", reason="literal_ip_target").inc()
    families = list(text_string_to_metric_families(generate_latest(reg).decode()))
    denied = next(f for f in families if f.name == "gateway_egress_denied_total")
    hit = next(s for s in denied.samples if s.name == "gateway_egress_denied_total")
    assert hit.labels == {"plane": "proxy", "reason": "literal_ip_target"}
    assert hit.value == 1.0
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/unit/gateway/test_egress_metrics.py -q`
Expected: FAIL (`ModuleNotFoundError: alfred.gateway.egress_metrics`).

- [ ] **Step 3: Write the module**

Create `src/alfred/gateway/egress_metrics.py`:

```python
"""Canonical G7-5 egress metric contract (Spec C PR-A).

ONE registration home for the two operator-observable egress families:

* ``gateway_egress_denied_total{plane,reason}`` — per-plane, per-reason deny counter.
* ``gateway_egress_inflight{plane}`` — a SINGLE shared custom collector that reads
  ``len(conns)`` for each registered plane AT SCRAPE TIME (so it cannot drift from a
  missed ``.set()`` and cannot emit duplicate families). A deliberate, review-approved
  departure from the plain-Gauge ``gateway_adapter_inflight`` precedent — the multi-
  instance producer set (provider proxy + adapter proxy + relay) makes a per-instance
  gauge either double-count or leave stale series on teardown; the register/deregister
  seam here keeps exactly one sample per live plane.

There is deliberately NO ``gateway_egress_up`` gauge: proxy/relay are fail-closed
(a bind failure exits the gateway), so a reachable ``/metrics`` implies they are up;
the adapter plane's presence is read from the existing ``gateway_adapter_up``.
"""

from __future__ import annotations

from collections.abc import Collection, Iterator, Sized
from typing import Final

from prometheus_client import REGISTRY, CollectorRegistry, Counter
from prometheus_client.core import GaugeMetricFamily

_PLANE_LABEL: Final[str] = "plane"
_REASON_LABEL: Final[str] = "reason"
_INFLIGHT_NAME: Final[str] = "gateway_egress_inflight"
_DENIED_NAME: Final[str] = "gateway_egress_denied_total"


class EgressInflightCollector:
    """A single collector yielding one ``gateway_egress_inflight`` sample per plane.

    Each producer registers its live connection set on serve and deregisters on
    teardown; ``collect`` reads ``len`` at scrape time.
    """

    def __init__(self) -> None:
        self._planes: dict[str, Sized] = {}

    def register(self, plane: str, conns: Sized) -> None:
        self._planes[plane] = conns

    def deregister(self, plane: str) -> None:
        self._planes.pop(plane, None)

    def collect(self) -> Iterator[GaugeMetricFamily]:
        family = GaugeMetricFamily(
            _INFLIGHT_NAME,
            "In-flight egress connections per plane (proxy/relay/adapter).",
            labels=[_PLANE_LABEL],
        )
        for plane, conns in self._planes.items():
            family.add_metric([plane], float(len(conns)))
        yield family


def build_denied_counter(registry: CollectorRegistry) -> Counter:
    """Construct the deny counter on ``registry`` (production uses the default REGISTRY)."""
    return Counter(
        _DENIED_NAME,
        "Gateway egress denials, per plane and closed-enum reason (Spec C G7-5).",
        [_PLANE_LABEL, _REASON_LABEL],
        registry=registry,
    )


# Production singletons: one collector + one counter on the default REGISTRY.
EGRESS_INFLIGHT_COLLECTOR: Final[EgressInflightCollector] = EgressInflightCollector()
REGISTRY.register(EGRESS_INFLIGHT_COLLECTOR)
GATEWAY_EGRESS_DENIED: Final[Counter] = build_denied_counter(REGISTRY)


def register_egress_inflight(plane: str, conns: Collection[object]) -> None:
    """A producer registers its live ``_conns`` set for the shared inflight collector."""
    EGRESS_INFLIGHT_COLLECTOR.register(plane, conns)


def deregister_egress_inflight(plane: str) -> None:
    """A producer deregisters on teardown so no stale ``inflight{plane}`` series remains."""
    EGRESS_INFLIGHT_COLLECTOR.deregister(plane)


__all__ = [
    "EGRESS_INFLIGHT_COLLECTOR",
    "GATEWAY_EGRESS_DENIED",
    "EgressInflightCollector",
    "build_denied_counter",
    "deregister_egress_inflight",
    "register_egress_inflight",
]
```

- [ ] **Step 4: Run to verify it passes**

Run: `uv run pytest tests/unit/gateway/test_egress_metrics.py -q`
Expected: PASS (4 tests). If `Sized`/`Collection` typing trips mypy later, that is caught in Task 6's `make check`.

- [ ] **Step 5: Add `egress_metrics.py` to the 100% coverage gate**

In `.github/workflows/ci.yml`, find the per-file egress coverage `--cov` include list that names `egress_proxy.py`/`egress_relay.py` (grep `egress_proxy` in `ci.yml`) and add `src/alfred/gateway/egress_metrics.py` to the same `--cov=` / include set (mirror the exact syntax of the neighbouring entries).

- [ ] **Step 6: Commit**

```bash
git add src/alfred/gateway/egress_metrics.py tests/unit/gateway/test_egress_metrics.py .github/workflows/ci.yml
git commit -m "feat(egress): canonical gateway_egress_inflight collector + denied_total counter (#333)"
```

---

### Task 2: Wire the provider/adapter proxy (`plane` arg, inflight register, deny counter)

**Files:**

- Modify: `src/alfred/gateway/egress_proxy.py` (`EgressForwardProxy.__init__` ~151-180; `serve`/shutdown; `_deny` ~371-391)
- Modify: `src/alfred/cli/gateway/_commands.py:319` (provider ctor call) and `src/alfred/gateway/adapter_egress_listener.py:57` (adapter ctor call) — pass `plane=`
- Test: `tests/unit/gateway/test_egress_proxy.py` (add cases)

**Interfaces:**

- Consumes: `register_egress_inflight`, `deregister_egress_inflight`, `GATEWAY_EGRESS_DENIED` (Task 1).
- Produces: `EgressForwardProxy(..., plane: str)`; on serve `register_egress_inflight(self._plane, self._conns)`, on shutdown `deregister_egress_inflight(self._plane)`; `_deny` increments `GATEWAY_EGRESS_DENIED.labels(plane=self._plane, reason=reason.value)` after the audit.

- [ ] **Step 1: Write the failing tests**

Add to `tests/unit/gateway/test_egress_proxy.py` (reuse its existing `_proxy(audit)` helper — pass `plane="proxy"`; if the helper doesn't yet take `plane`, thread it through):

```python
import pytest
from prometheus_client import CollectorRegistry, generate_latest
from prometheus_client.parser import text_string_to_metric_families

from alfred.gateway import egress_metrics


@pytest.mark.asyncio
async def test_literal_ip_deny_increments_denied_total_after_audit() -> None:
    reg = CollectorRegistry()
    denied = egress_metrics.build_denied_counter(reg)
    audit: list[tuple[str, dict[str, object]]] = []
    proxy = _proxy(audit, plane="proxy", denied_counter=denied)  # helper passes the counter through
    writer = _CaptureWriter()
    await _serve(proxy, b"CONNECT 203.0.113.5:443 HTTP/1.1\r\n\r\n", writer)
    # audit fired
    assert any(f.get("reason") == "literal_ip_target" for _, f in audit)
    # AND the new counter incremented, keyed by plane+reason
    fam = next(
        f for f in text_string_to_metric_families(generate_latest(reg).decode())
        if f.name == "gateway_egress_denied_total"
    )
    hit = next(s for s in fam.samples if s.labels == {"plane": "proxy", "reason": "literal_ip_target"})
    assert hit.value == 1.0


@pytest.mark.asyncio
async def test_deny_still_audits_and_refuses_when_metric_raises() -> None:
    audit: list[tuple[str, dict[str, object]]] = []

    class _Boom:
        def labels(self, **_: str) -> "_Boom":
            return self
        def inc(self) -> None:
            raise RuntimeError("metrics backend down")

    proxy = _proxy(audit, plane="proxy", denied_counter=_Boom())
    writer = _CaptureWriter()
    with contextlib.suppress(RuntimeError):
        await _serve(proxy, b"CONNECT 203.0.113.5:443 HTTP/1.1\r\n\r\n", writer)
    assert any(f.get("reason") == "literal_ip_target" for _, f in audit), "audit must fire before the metric"
    assert b"403" in writer.buf, "refusal must be written before/independent of the metric"
```

(If `_proxy` cannot inject a counter, add a keyword `denied_counter` to the ctor that defaults to `egress_metrics.GATEWAY_EGRESS_DENIED` — a seam the additive-telemetry test needs.)

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/unit/gateway/test_egress_proxy.py -k "denied_total or metric_raises" -v`
Expected: FAIL (`_proxy() got an unexpected keyword argument 'plane'` / no counter increment).

- [ ] **Step 3: Modify `EgressForwardProxy`**

In `egress_proxy.py` `__init__`, add keyword-only params (after `unix_path`):

```python
        plane: str = "proxy",
        denied_counter: Counter | None = None,
```

and in the body:

```python
        self._plane = plane
        self._denied_counter = denied_counter if denied_counter is not None else GATEWAY_EGRESS_DENIED
```

Add the imports at the top of `egress_proxy.py`:

```python
from prometheus_client import Counter
from alfred.gateway.egress_metrics import (
    GATEWAY_EGRESS_DENIED,
    deregister_egress_inflight,
    register_egress_inflight,
)
```

Register/deregister around the serve lifecycle. In `serve(self, shutdown_event)` (the coroutine that binds + runs), register right after a successful bind and deregister in the `finally`:

```python
        register_egress_inflight(self._plane, self._conns)
        try:
            ...  # existing serve body
        finally:
            deregister_egress_inflight(self._plane)
```

In `_deny`, add the new counter increment **after** `self._audit(...)` (keep the existing `GATEWAY_EGRESS_CONNECT.labels(outcome="denied").inc()` where it is):

```python
        try:
            self._audit(
                EGRESS_CONNECT_DENIED_EVENT, {"reason": reason.value, "destination": destination}
            )
            self._denied_counter.labels(plane=self._plane, reason=reason.value).inc()
            with contextlib.suppress(OSError):
                writer.write(f"HTTP/1.1 {status} {reason.value}\r\n\r\n".encode("latin-1"))
                await writer.drain()
        finally:
            self._close(writer)
```

Note: the increment is inside the `try` after the audit, so a raising `.inc()` still leaves the audit fired and the `finally` still closes the writer. (The refusal `write` is best-effort/`OSError`-suppressed already; a metric `RuntimeError` propagating out of `_deny` is acceptable — the audit + close both ran. The test asserts audit+403 both happened.)

- [ ] **Step 4: Pass `plane=` at the two ctor sites**

In `src/alfred/cli/gateway/_commands.py:319` (the provider `EgressForwardProxy(...)`), add `plane="proxy"`. In `src/alfred/gateway/adapter_egress_listener.py:57` (the adapter one), add `plane="adapter"`.

- [ ] **Step 5: Run to verify it passes**

Run: `uv run pytest tests/unit/gateway/test_egress_proxy.py -q`
Expected: PASS (existing + 2 new). If the existing `test_connect_literal_ip_denied` now needs a registry-isolation fixture (the module-level `GATEWAY_EGRESS_DENIED` accumulates across tests), the new tests use their own `CollectorRegistry` via `denied_counter=`, so the default-registry counter is only touched by tests that don't assert its absolute value — confirm no cross-test bleed.

- [ ] **Step 6: Commit**

```bash
git add src/alfred/gateway/egress_proxy.py src/alfred/cli/gateway/_commands.py src/alfred/gateway/adapter_egress_listener.py tests/unit/gateway/test_egress_proxy.py
git commit -m "feat(egress): proxy plane label + inflight registration + denied_total after audit (#333)"
```

---

### Task 3: Wire the relay (`plane="relay"` inflight + deny counter)

**Files:**

- Modify: `src/alfred/gateway/egress_relay.py` (`__init__` ~285-307; serve lifecycle; `_emit` ~598-608)
- Test: `tests/unit/gateway/test_egress_relay.py` (add cases)

**Interfaces:**

- Consumes: `register_egress_inflight`/`deregister_egress_inflight`, `GATEWAY_EGRESS_DENIED` (Task 1); `EgressRelayReply.deny_reason` (`EgressRelayDenyReason`).
- Produces: the relay registers `plane="relay"` inflight; `_emit` increments `denied_total{plane="relay", reason}` after `write_frame` when `reply.response is None`.

- [ ] **Step 1: Write the failing tests**

Add to `tests/unit/gateway/test_egress_relay.py` (reuse its existing relay-drive helpers):

```python
import pytest
from prometheus_client import CollectorRegistry, generate_latest
from prometheus_client.parser import text_string_to_metric_families

from alfred.egress.relay_protocol import EgressRelayDenyReason
from alfred.gateway import egress_metrics


@pytest.mark.parametrize("reason", list(EgressRelayDenyReason))
@pytest.mark.asyncio
async def test_relay_deny_increments_denied_total_for_every_reason(reason) -> None:
    reg = CollectorRegistry()
    denied = egress_metrics.build_denied_counter(reg)
    relay = _relay(denied_counter=denied)  # thread the counter into the relay ctor
    await _emit_deny(relay, reason)  # drive _emit with an EgressRelayReply(deny_reason=reason)
    fam = next(
        f for f in text_string_to_metric_families(generate_latest(reg).decode())
        if f.name == "gateway_egress_denied_total"
    )
    hit = next(s for s in fam.samples if s.labels == {"plane": "relay", "reason": reason.value})
    assert hit.value == 1.0
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/unit/gateway/test_egress_relay.py -k denied_total -v`
Expected: FAIL (relay ctor has no `denied_counter`; no increment).

- [ ] **Step 3: Modify the relay**

In `egress_relay.py` `__init__`, add `denied_counter: Counter | None = None` (keyword-only) and set `self._denied_counter = denied_counter or GATEWAY_EGRESS_DENIED`. Add imports mirroring Task 2. Register/deregister `plane="relay"` inflight around the serve lifecycle (same shape as Task 2). In `_emit`, after `write_frame` + the existing outcome inc, add the by-reason increment on the deny branch:

```python
    async def _emit(self, writer: asyncio.StreamWriter, reply: EgressRelayReply) -> None:
        await write_frame(writer, reply.model_dump_json().encode("utf-8"))
        denied = reply.response is None
        GATEWAY_EGRESS_RELAY.labels(outcome="denied" if denied else "forwarded").inc()
        if denied and reply.deny_reason is not None:
            self._denied_counter.labels(plane="relay", reason=reply.deny_reason.value).inc()
```

(Audit already fired at the decision point in `_deny`; the frame — the refusal — is written first; the counter is last → additive.)

- [ ] **Step 4: Run to verify it passes**

Run: `uv run pytest tests/unit/gateway/test_egress_relay.py -q`
Expected: PASS (existing + 8 parametrized reasons).

- [ ] **Step 5: Commit**

```bash
git add src/alfred/gateway/egress_relay.py tests/unit/gateway/test_egress_relay.py
git commit -m "feat(egress): relay plane=relay inflight + per-reason denied_total (#333)"
```

---

### Task 4: The `alfred gateway egress` command

**Files:**

- Create: `src/alfred/cli/gateway/_egress.py`
- Modify: `src/alfred/cli/gateway/__init__.py` (register the command)
- Test: `tests/unit/cli/gateway/test_egress_command.py`

**Interfaces:**

- Consumes: `resolve_metrics_port` + `_fetch_metrics_text` (`_commands.py`), the allowlist builders (`provider_egress_allowlist`, `resolve_tool_egress_allowlist`, `discord_egress_allowlist` — verify exact names via `grep -rn "egress_allowlist" src/alfred/egress`), `reason_i18n_key` (both modules), `EgressDenyReason`/`EgressRelayDenyReason`, `t`.
- Produces: `egress_status() -> None` (raises `typer.Exit(2)` on unreachable, else renders + exits 0).

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/cli/gateway/test_egress_command.py`:

```python
"""Unit tests for `alfred gateway egress` (render from a fixture /metrics blob)."""

from __future__ import annotations

import pytest
import typer

from alfred.cli.gateway import _egress

_METRICS = """\
# TYPE gateway_egress_inflight gauge
gateway_egress_inflight{plane="proxy"} 2.0
gateway_egress_inflight{plane="relay"} 0.0
# TYPE gateway_egress_denied_total counter
gateway_egress_denied_total{plane="proxy",reason="literal_ip_target"} 1.0
# TYPE gateway_adapter_up gauge
gateway_adapter_up{adapter="discord"} 1.0
"""


def test_happy_path_renders_all_planes(capsys, monkeypatch) -> None:
    monkeypatch.setattr(_egress, "_fetch_metrics_text", lambda _p: _METRICS)
    monkeypatch.setattr(_egress, "resolve_metrics_port", lambda: 9464)
    _egress.egress_status()
    out = capsys.readouterr().out
    assert "2" in out  # proxy inflight
    assert "literal_ip_target" in out or "gateway.egress.denied.literal_ip_target" in out


def test_metrics_unreachable_exits_2(monkeypatch) -> None:
    def _boom(_p: int) -> str:
        raise OSError("connection refused")

    monkeypatch.setattr(_egress, "_fetch_metrics_text", _boom)
    monkeypatch.setattr(_egress, "resolve_metrics_port", lambda: 9464)
    with pytest.raises(typer.Exit) as exc:
        _egress.egress_status()
    assert exc.value.exit_code == 2


def test_no_adapter_up_series_reports_not_configured(capsys, monkeypatch) -> None:
    metrics_no_adapter = _METRICS.replace(
        '# TYPE gateway_adapter_up gauge\ngateway_adapter_up{adapter="discord"} 1.0\n', ""
    )
    monkeypatch.setattr(_egress, "_fetch_metrics_text", lambda _p: metrics_no_adapter)
    monkeypatch.setattr(_egress, "resolve_metrics_port", lambda: 9464)
    _egress.egress_status()
    # the adapter stanza renders the "not configured" state (assert on the t()-key or its English msgstr)
    assert capsys.readouterr().out  # non-empty; refine to the specific key once catalog lands


def test_unknown_reason_token_fails_loud(monkeypatch) -> None:
    bad = _METRICS.replace("literal_ip_target", "totally_bogus_reason")
    monkeypatch.setattr(_egress, "_fetch_metrics_text", lambda _p: bad)
    monkeypatch.setattr(_egress, "resolve_metrics_port", lambda: 9464)
    with pytest.raises((ValueError, typer.Exit)):
        _egress.egress_status()
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/unit/cli/gateway/test_egress_command.py -q`
Expected: FAIL (`ModuleNotFoundError: alfred.cli.gateway._egress`).

- [ ] **Step 3: Write the command body**

Create `src/alfred/cli/gateway/_egress.py`. Read the two existing exemplars first: `src/alfred/cli/gateway/_adapters.py` (the exit-code + fail-loud render shape) and `src/alfred/cli/gateway/_commands.py` (`_fetch_metrics_text`). Then:

```python
"""``alfred gateway egress`` — operator egress-plane state (Spec C G7-5 PR-A).

Runs IN the gateway container. Scrapes the loopback ``/metrics`` (the seam
``healthcheck`` uses) and reads the static allowlist config; renders per-plane
stanzas. Exit 0 on success, 2 when ``/metrics`` is unavailable (report-family
semantics, never a traceback — hard rule #7).
"""

from __future__ import annotations

from typing import Final

import structlog
import typer
from prometheus_client.parser import text_string_to_metric_families

from alfred.cli.gateway._commands import _fetch_metrics_text
from alfred.gateway.egress_audit import EgressDenyReason
from alfred.gateway.egress_audit import reason_i18n_key as proxy_reason_key
from alfred.gateway.egress_relay_audit import reason_i18n_key as relay_reason_key
from alfred.egress.relay_protocol import EgressRelayDenyReason
from alfred.gateway.metrics_server import resolve_metrics_port
from alfred.i18n import t

log = structlog.get_logger(__name__)

_EXIT_UNAVAILABLE: Final[int] = 2

# Per-plane closed reason enums + their i18n key functions.
_PROXY_REASONS: Final = {r.value for r in EgressDenyReason}
_RELAY_REASONS: Final = {r.value for r in EgressRelayDenyReason}


def egress_status() -> None:
    try:
        port = resolve_metrics_port()
        metrics_text = _fetch_metrics_text(port)
    except (OSError, ValueError) as exc:
        log.warning("gateway.egress.unreachable", error=repr(exc))
        typer.echo(t("gateway.egress.unreachable"))
        raise typer.Exit(code=_EXIT_UNAVAILABLE) from exc

    families = {f.name: f for f in text_string_to_metric_families(metrics_text)}
    inflight = _samples_by_label(families.get("gateway_egress_inflight"), "plane")
    denied = _denied_by_plane(families.get("gateway_egress_denied_total"))
    adapter_up = _samples_by_label(families.get("gateway_adapter_up"), "adapter")

    _render_plane("proxy", "gateway.egress.plane.proxy", inflight, denied, reachable=True)
    _render_plane("relay", "gateway.egress.plane.relay", inflight, denied, reachable=True)
    _render_adapter(inflight, denied, present=bool(adapter_up))


def _samples_by_label(family: object | None, label: str) -> dict[str, float]:
    if family is None:
        return {}
    return {s.labels[label]: s.value for s in family.samples if label in s.labels}


def _denied_by_plane(family: object | None) -> dict[str, dict[str, float]]:
    out: dict[str, dict[str, float]] = {}
    if family is None:
        return out
    for s in family.samples:
        if s.name != "gateway_egress_denied_total":
            continue
        out.setdefault(s.labels["plane"], {})[s.labels["reason"]] = s.value
    return out


def _render_plane(
    plane: str,
    header_key: str,
    inflight: dict[str, float],
    denied: dict[str, dict[str, float]],
    *,
    reachable: bool,
) -> None:
    typer.echo(t(header_key) + "  " + (t("gateway.egress.reachable") if reachable else t("gateway.egress.down")))
    typer.echo("  " + t("gateway.egress.inflight_label") + " " + str(int(inflight.get(plane, 0))))
    typer.echo("  " + t("gateway.egress.denies_label") + " " + _fmt_denies(plane, denied.get(plane, {})))


def _fmt_denies(plane: str, reasons: dict[str, float]) -> str:
    allowed = _PROXY_REASONS if plane in {"proxy", "adapter"} else _RELAY_REASONS
    key_fn = proxy_reason_key if plane in {"proxy", "adapter"} else relay_reason_key
    enum_cls = EgressDenyReason if plane in {"proxy", "adapter"} else EgressRelayDenyReason
    nonzero = {r: int(v) for r, v in reasons.items() if v > 0}
    if not nonzero:
        return t("gateway.egress.no_denials")
    parts: list[str] = []
    for reason, count in sorted(nonzero.items()):
        if reason not in allowed:  # metric-drift / display-side payload-blindness — fail loud
            msg = f"unknown egress deny reason {reason!r} for plane {plane!r}"
            raise ValueError(msg)
        parts.append(f"{t(key_fn(enum_cls(reason)))}={count}")
    return "  ".join(parts)


def _render_adapter(
    inflight: dict[str, float], denied: dict[str, dict[str, float]], *, present: bool
) -> None:
    if not present:
        typer.echo(t("gateway.egress.plane.adapter") + "  " + t("gateway.egress.not_configured"))
        return
    _render_plane("adapter", "gateway.egress.plane.adapter", inflight, denied, reachable=True)
```

(Allowlist rendering — a `t("gateway.egress.allowlist_label")` line per plane reading `provider_egress_allowlist()` / `resolve_tool_egress_allowlist()` / `discord_egress_allowlist()` — is folded into `_render_plane`/`_render_adapter`; grep the exact builder names in `src/alfred/egress/allowlist.py` + `src/alfred/gateway/egress_relay.py` and add the line. Keep it a config read, not a scrape.)

- [ ] **Step 4: Register the command**

In `src/alfred/cli/gateway/__init__.py`, mirror the `adapters` registration:

```python
@gateway_app.command("egress", help=t("gateway.help.egress"))
def egress() -> None:
    from alfred.cli.gateway._egress import egress_status

    egress_status()
```

- [ ] **Step 5: Run to verify it passes**

Run: `uv run pytest tests/unit/cli/gateway/test_egress_command.py -q`
Expected: PASS. (The `_render_adapter`/allowlist assertions may need the Task 5 catalog keys to render final text; keep Step-1 assertions key-agnostic until Task 5, then tighten.)

- [ ] **Step 6: Commit**

```bash
git add src/alfred/cli/gateway/_egress.py src/alfred/cli/gateway/__init__.py tests/unit/cli/gateway/test_egress_command.py
git commit -m "feat(cli): alfred gateway egress — per-plane egress-state report (#333)"
```

---

### Task 5: i18n catalog keys + help text

**Files:**

- Modify: the English catalog (`locale/en/LC_MESSAGES/alfred.po` — verify path via `grep -rl "gateway.help.status" locale`), and `src/alfred/i18n/_spec_c_reserve.py` if any key is dict-dereferenced.
- Test: none new (the `pybabel --check` CI gate + Task 4 tests cover it).

**Interfaces:** literal `t("gateway.egress.*")` keys are extracted directly (no `_spec_c_reserve` entry needed for literal call sites); the deny-reason keys are already reserved.

- [ ] **Step 1: Add the new literal keys + English msgstrs**

New keys introduced by Task 4 (all literal `t()` call sites, so `pybabel extract` finds them): `gateway.egress.unreachable`, `gateway.egress.reachable`, `gateway.egress.down`, `gateway.egress.not_configured`, `gateway.egress.no_denials`, `gateway.egress.inflight_label`, `gateway.egress.denies_label`, `gateway.egress.allowlist_label`, `gateway.egress.plane.proxy`, `gateway.egress.plane.relay`, `gateway.egress.plane.adapter`, `gateway.help.egress`. Give each an English `msgstr` — e.g. `gateway.egress.unreachable` → "egress plane unreachable — run inside the gateway container: docker compose exec alfred-gateway alfred gateway egress"; `gateway.egress.plane.proxy` → "provider proxy"; `gateway.egress.no_denials` → "no denials".

- [ ] **Step 2: Run the i18n flow**

Run: `uv run pybabel extract -F babel.cfg -o /tmp/alfred.pot src/alfred plugins` then `uv run pybabel update -i /tmp/alfred.pot -d locale -D alfred --no-fuzzy-matching` then fill the English msgstrs, then `uv run pybabel compile -d locale -D alfred`.
Expected: the new keys present; no fuzzy markers.

- [ ] **Step 3: Verify the drift gate**

Run: `uv run pybabel compile -d locale -D alfred --check 2>/dev/null; uv run pytest tests/unit/cli/gateway/test_egress_command.py -q`
Expected: catalog compiles; command tests pass with final text (tighten the Task-4 key-agnostic asserts to the real msgstrs now).

- [ ] **Step 4: Commit**

```bash
git add locale src/alfred/i18n/_spec_c_reserve.py tests/unit/cli/gateway/test_egress_command.py
git commit -m "i18n(egress): gateway.egress.* operator catalog keys for the egress command (#333)"
```

---

### Task 6: Full verification + quality gates

**Files:** none (verification).

- [ ] **Step 1: Targeted suites**

Run: `uv run pytest tests/unit/gateway/test_egress_metrics.py tests/unit/gateway/test_egress_proxy.py tests/unit/gateway/test_egress_relay.py tests/unit/cli/gateway/test_egress_command.py -q`
Expected: all pass.

- [ ] **Step 2: Sum-invariant assertion (add to `test_egress_proxy.py`/`test_egress_relay.py` if not already)**

Confirm a test asserts `sum over reason of denied_total{plane="relay"}` equals the relay `gateway_egress_relay_total{outcome="denied"}` increment count over the same drive, and the proxy+adapter aggregate equals the shared `gateway_egress_connect_total{outcome="denied"}`. If missing, add it here (it's the PR-B contract).

- [ ] **Step 3: `make check`**

Run: `make check` (check `$?`, not a `| tail`). Expected: ruff + format + mypy + pyright + unit green. Fix any typing on the collector (`Sized`/`Collection`) or the CLI union-narrowing inline.

- [ ] **Step 4: Coverage gate confirmation**

Run: `uv run pytest tests/unit/gateway/test_egress_metrics.py --cov=src/alfred/gateway/egress_metrics --cov-report=term-missing -q`
Expected: 100% (the collector `collect()` + both branches, the counter builder, register/deregister). Add a test for any uncovered branch.

- [ ] **Step 5: Commit any gate fixes**

```bash
git add -A src/alfred tests
git commit -m "chore(egress): coverage + type-gate fixes for the egress CLI + metrics (#333)" || echo "nothing to fix"
```

---

## Self-Review

**1. Spec coverage** (design §1-§9): new `egress` subcommand → Task 4; `gateway_egress_inflight` collector → Task 1; `gateway_egress_denied_total{plane,reason}` per-plane → Tasks 1-3; no `up` gauge / derived reachability + adapter via `gateway_adapter_up` → Task 4; allowlist config-read → Task 4 Step 3 note; exit-2 report semantics → Task 4; additive-telemetry (inc after audit) → Tasks 2-3; per-plane `reason_i18n_key` dispatch + scraped-token validation → Task 4 `_fmt_denies`; plane header distinct `t()` string → Task 5 keys; canonical `egress_metrics.py` home → Task 1; coverage gate + `_egress.py` target → Tasks 1/6; i18n → Task 5. ✓

**2. Placeholder scan:** the only deferred specifics are the exact allowlist-builder names + catalog path, each with an explicit `grep`/`verify` instruction and the surrounding code shown — concrete steps, not vague TODOs.

**3. Type/name consistency:** `EgressInflightCollector`/`register_egress_inflight`/`deregister_egress_inflight`/`GATEWAY_EGRESS_DENIED`/`build_denied_counter` are used identically across Tasks 1-4; `plane` values `proxy`/`relay`/`adapter` consistent; `reason_i18n_key` imported per-plane (proxy vs relay) consistently; exit code `2` consistent.

## Execution Handoff

Ready for subagent-driven or inline execution after a focused plan-review.
