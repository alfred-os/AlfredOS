"""Validity assertions for the ops/ observability scaffold (Spec B G6-0).

Asserts the committed config parses, declares the gateway scrape job + the three
gateway alerts + a non-empty dashboard, and that every metric name referenced by an
alert/panel actually EXISTS in one of the gateway metric-defining modules under
src/alfred/gateway/ (no silently-dead alerts). The known-name set is DERIVED from
source — never hardcoded — so a new series (or a renamed one) is checked honestly.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).parent.parent.parent
OPS = ROOT / "ops"
GATEWAY_SRC = ROOT / "src" / "alfred" / "gateway"
# Every gateway module that DEFINES a Prometheus series. G6-4 (#288) split the
# per-adapter ingress/leg series out of metrics.py into adapter_metrics.py and the
# ingress-audit sink, so scanning metrics.py alone would miss them and the
# dashboard/alert cross-check would falsely fail. The known-name set is derived from
# EVERY ``Counter(``/``Gauge(``/``Histogram(``-bearing module so the scaffold validates
# the panels/alerts against the REAL registered metric names.
_METRIC_DEFINING_FILES = sorted(
    path
    for path in GATEWAY_SRC.glob("*.py")
    if re.search(r"\b(?:Counter|Gauge|Histogram)\(", path.read_text())
)


def _known_metric_bases() -> set[str]:
    names: set[str] = set()
    for path in _METRIC_DEFINING_FILES:
        names |= set(re.findall(r'"(gateway_[a-z_]+)"', path.read_text()))
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
        unknown = referenced - known
        assert referenced <= known, f"alert {r['alert']} references unknown metric(s): {unknown}"


def test_gateway_dashboard_parses_and_references_real_metrics() -> None:
    dash = json.loads((OPS / "grafana" / "gateway.json").read_text())
    assert dash.get("title")
    assert len(dash.get("panels", [])) >= 1
    known = _known_metric_bases()
    for panel in dash["panels"]:
        for target in panel.get("targets", []):
            referenced = set(re.findall(r"gateway_[a-z_]+", target.get("expr", "")))
            unknown = referenced - known
            assert referenced <= known, f"panel {panel.get('title')} references unknown: {unknown}"
