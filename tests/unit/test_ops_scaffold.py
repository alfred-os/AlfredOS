"""Validity assertions for the ops/ observability scaffold (Spec B G6-0).

Asserts the committed config parses, declares the gateway scrape job + the three
gateway alerts + a non-empty dashboard, and that every metric name referenced by an
alert/panel actually EXISTS in one of the gateway metric-defining modules under
src/alfred/gateway/ (no silently-dead alerts). The known-name set is DERIVED from
source — never hardcoded — so a new series (or a renamed one) is checked honestly.
"""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).parent.parent.parent
OPS = ROOT / "ops"
GATEWAY_SRC = ROOT / "src" / "alfred" / "gateway"
# Prometheus series are registered exactly at their constructor calls. Deriving the
# known-name set from the FIRST-ARG name literal of every ``Counter(``/``Gauge(``/
# ``Histogram(`` call (via ``ast``) — not a blind ``gateway_*`` string regex — keeps the
# "no silently-dead alerts" cross-check honest: a quoted metric name that isn't actually
# a registered series can no longer whitelist an alert/panel that references it.
_PROMETHEUS_CTORS = frozenset({"Counter", "Gauge", "Histogram"})
_METRIC_REF_RE = re.compile(r"\bgateway_[a-z0-9_]*\b")


def _call_name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _metric_names_in(path: Path) -> set[str]:
    names: set[str] = set()
    tree = ast.parse(path.read_text())
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or _call_name(node.func) not in _PROMETHEUS_CTORS:
            continue
        if not node.args or not isinstance(node.args[0], ast.Constant):
            continue
        metric_name = node.args[0].value
        if isinstance(metric_name, str) and _METRIC_REF_RE.fullmatch(metric_name):
            names.add(metric_name)
    return names


# Every gateway module under src/alfred/gateway/ is scanned for constructor-registered
# series. G6-4 (#288) split the per-adapter ingress/leg series out of metrics.py into
# adapter_metrics.py and the ingress-audit sink, so the known-name set is the union across
# ALL modules — not metrics.py alone — to validate the panels/alerts against the REAL
# registered metric names.
_METRIC_DEFINING_FILES = sorted(GATEWAY_SRC.glob("*.py"))


def _known_metric_bases() -> set[str]:
    names: set[str] = set()
    for path in _METRIC_DEFINING_FILES:
        names |= _metric_names_in(path)
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
