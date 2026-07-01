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
# GaugeMetricFamily is how a custom collector emits a Gauge (gateway_egress_inflight);
# CounterMetricFamily is intentionally NOT listed — it is unused in source.
_PROMETHEUS_CTORS = frozenset({"Counter", "Gauge", "Histogram", "GaugeMetricFamily"})
_METRIC_REF_RE = re.compile(r"\bgateway_[a-z0-9_]*\b")


def _call_name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _module_str_consts(tree: ast.Module) -> dict[str, str]:
    # Resolve module-level string constants bound via ``X = "..."`` (ast.Assign) OR
    # ``X: Final[str] = "..."`` (ast.AnnAssign) so a ctor called with a Name first-arg
    # (e.g. ``Counter(_DENIED_NAME, ...)``) is derivable, not silently skipped.
    consts: dict[str, str] = {}
    for node in tree.body:
        if (
            isinstance(node, ast.Assign)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        ):
            for tgt in node.targets:
                if isinstance(tgt, ast.Name):
                    consts[tgt.id] = node.value.value
        elif (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        ):
            consts[node.target.id] = node.value.value
    return consts


def _metric_names_in(path: Path) -> set[str]:
    names: set[str] = set()
    tree = ast.parse(path.read_text())
    consts = _module_str_consts(tree)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or _call_name(node.func) not in _PROMETHEUS_CTORS:
            continue
        if not node.args:
            continue
        arg = node.args[0]
        metric_name: str | None = None
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            metric_name = arg.value
        elif isinstance(arg, ast.Name):
            metric_name = consts.get(arg.id)
        if metric_name is not None and _METRIC_REF_RE.fullmatch(metric_name):
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


def _known_reason_values() -> set[str]:
    # The deny-reason label values the alerts' ``reason=~``/``reason=`` matchers select on.
    from alfred.egress.relay_protocol import EgressRelayDenyReason
    from alfred.gateway.egress_audit import EgressDenyReason

    return {r.value for r in EgressDenyReason} | {r.value for r in EgressRelayDenyReason}


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


def test_egress_custom_collector_metrics_are_derivable() -> None:
    # gateway_egress_inflight (GaugeMetricFamily via _INFLIGHT_NAME const) and
    # gateway_egress_denied_total (Counter via _DENIED_NAME const) must be visible to
    # the derivation, else PR-B's egress alerts/panels fail the referenced<=known check.
    known = _known_metric_bases()
    assert "gateway_egress_inflight" in known
    assert "gateway_egress_denied_total" in known


def test_known_reason_values_cover_both_enums() -> None:
    vals = _known_reason_values()
    assert "canary_tripped" in vals  # EgressRelayDenyReason
    assert "malformed_connect" in vals  # EgressDenyReason
    assert "destination_not_allowlisted" in vals  # both


_EGRESS_ALERTS = frozenset(
    {
        "GatewayEgressDenyRate",
        "GatewayEgressInflightSaturation",
        "GatewayEgressSecurityDenySpike",
        "GatewayEgressExfilSpike",
        "GatewayEgressOutage",
    }
)


def test_egress_alerts_present() -> None:
    cfg = yaml.safe_load((OPS / "alerts" / "gateway.yml").read_text())
    names = {r["alert"] for g in cfg["groups"] for r in g["rules"] if "alert" in r}
    assert names >= _EGRESS_ALERTS


def test_alert_reason_labels_are_real_enum_values() -> None:
    # The critical pager selects on reason label VALUES via reason=~/reason= matchers;
    # a typo or enum rename would silently fail it open. Assert every alternative is real.
    cfg = yaml.safe_load((OPS / "alerts" / "gateway.yml").read_text())
    known = _known_reason_values()
    reason_re = re.compile(r'reason(?:=~|=)"([^"]+)"')
    # Sentinel: accumulate checked reasons per alert so we can assert the two security-critical
    # alerts are NOT vacuous (a future refactor that removes the reason= matcher would silently
    # zero the guard — this catches it before the gap ships).
    checked_reasons: dict[str, list[str]] = {}
    for r in (r for g in cfg["groups"] for r in g["rules"] if "alert" in r):
        alert_name: str = r["alert"]
        for match in reason_re.findall(r["expr"]):
            for alt in match.split("|"):  # bare-| alternation; a lone value has no |
                assert alt in known, f"alert {alert_name} references unknown reason: {alt!r}"
                checked_reasons.setdefault(alert_name, []).append(alt)
    # Both reason-bearing critical alerts must have contributed ≥1 checked reason.
    assert "GatewayEgressSecurityDenySpike" in checked_reasons, (
        "GatewayEgressSecurityDenySpike has no reason= matcher — the enum guard is vacuous"
    )
    assert "GatewayEgressExfilSpike" in checked_reasons, (
        "GatewayEgressExfilSpike has no reason= matcher — the enum guard is vacuous"
    )


def test_egress_panels_present() -> None:
    dash = json.loads((OPS / "grafana" / "gateway.json").read_text())
    exprs = {t.get("expr") for p in dash["panels"] for t in p.get("targets", [])}
    assert "gateway_egress_inflight" in exprs
    assert "rate(gateway_egress_denied_total[5m])" in exprs
