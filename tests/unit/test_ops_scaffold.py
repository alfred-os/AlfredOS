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
    dash = json.loads((OPS / "grafana" / "dashboards" / "gateway.json").read_text())
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
    dash = json.loads((OPS / "grafana" / "dashboards" / "gateway.json").read_text())
    exprs = {t.get("expr") for p in dash["panels"] for t in p.get("targets", [])}
    assert "gateway_egress_inflight" in exprs
    assert "rate(gateway_egress_denied_total[5m])" in exprs


# ---------------------------------------------------------------------------
# #470 PR2 Task 2 (rev.4 test-005/rev-004/sec-003/devops-007): the sibling
# no-silently-dead-alerts cross-check for ops/alerts/core.yml. This does NOT reuse
# the gateway_* regex / AST-scan-of-src/alfred/gateway/ machinery above: core.yml
# references exposition names resolved against alfred.observability.core_metrics'
# CORE_OWNED_COLLECTORS tuple, not source-scanned Counter()/Gauge()/Histogram() call
# sites, and prometheus_client's Counter strips the "_total" suffix from `._name` —
# so the known-name set must re-append "_total" rather than mutually strip both
# sides (a tautological oracle that would pass a wrong name).
# ---------------------------------------------------------------------------


def _known_core_metric_names() -> set[str]:
    """The Task 2 Step 5 resolver, factored out so Task 4's dashboard test-002
    reuses it verbatim instead of re-deriving a second (possibly divergent) copy."""
    from alfred.observability.core_metrics import CORE_OWNED_COLLECTORS

    # Public prometheus_client API rather than the private `._name` attribute:
    # `.describe()` yields each collector's Metric descriptor(s), whose `.name` is the
    # same _total-STRIPPED base `._name` exposes (verified against every CORE_OWNED_COLLECTORS
    # entry — Counter/Histogram both yield exactly one descriptor matching `._name`).
    # Re-append _total so both exposition forms are known.
    base = {name for c in CORE_OWNED_COLLECTORS for name in (m.name for m in c.describe())}
    return base | {n + "_total" for n in base} | {"up"}  # explicit builtin allowlist


def _alfred_metric_refs(text: str) -> set[str]:
    """Every ``alfred_*`` identifier (plus builtin ``up``) referenced in ``text``."""
    return set(re.findall(r"\balfred_[a-z0-9_]*\b", text)) | (
        {"up"} if re.search(r"\bup\b", text) else set()
    )


def test_core_alerts_reference_real_core_metrics() -> None:
    known = _known_core_metric_names()
    exprs = " ".join(
        r["expr"]
        for g in yaml.safe_load((OPS / "alerts" / "core.yml").read_text())["groups"]
        for r in g["rules"]
    )
    refs = _alfred_metric_refs(exprs)
    unknown = refs - known
    assert not unknown, f"core.yml references metrics no core collector exposes: {sorted(unknown)}"
    # Oracle-independence: also assert the EXPECTED set as an independent literal, so a
    # mis-derived `known` cannot pass a mutated rule. MUTATION-CHECK: a rule referencing
    # `alfred_quarantine_capability_revoked_typo` MUST fail this test.
    assert refs >= {"alfred_quarantine_capability_revoked_total", "up"}


# ---------------------------------------------------------------------------
# #470 PR2 Task 4 (rev.4 test-002/test-006): Grafana dashboard + provisioning
# validity. Task 4 otherwise ships quarantine.json and both provisioning YAMLs
# with zero assertion — a panel querying a renamed/nonexistent alfred_* metric,
# or a datasource/provider typo, would ship silently green (Task 5's e2e is
# Prometheus-only and never loads Grafana).
# ---------------------------------------------------------------------------


def test_core_dashboard_references_real_core_metrics() -> None:
    # test-002: mirrors the gateway sibling (test_gateway_dashboard_parses_and_
    # references_real_metrics above) but resolves against CORE_OWNED_COLLECTORS
    # via the shared _known_core_metric_names() helper, not the gateway_* AST scan.
    dash = json.loads((OPS / "grafana" / "dashboards" / "quarantine.json").read_text())
    assert dash.get("title")
    assert len(dash.get("panels", [])) >= 1
    known = _known_core_metric_names()
    for panel in dash["panels"]:
        for target in panel.get("targets", []):
            refs = _alfred_metric_refs(target.get("expr", ""))
            unknown = refs - known
            assert refs <= known, f"panel {panel.get('title')} references unknown: {unknown}"
    # Oracle-independence, same rationale as test_core_alerts_reference_real_core_metrics.
    all_refs: set[str] = set()
    for panel in dash["panels"]:
        for target in panel.get("targets", []):
            all_refs |= _alfred_metric_refs(target.get("expr", ""))
    assert all_refs >= {"alfred_quarantine_capability_revoked_total", "up"}


def test_grafana_provisioning_targets_are_correct() -> None:
    # test-006: a typo in either provisioning YAML yields a silently dead
    # datasource / unloaded dashboards — nothing else in the ops/ scaffold
    # cross-checks these against the compose service bind / mount target.
    datasource_cfg = yaml.safe_load(
        (OPS / "grafana" / "provisioning" / "datasources" / "prometheus.yml").read_text()
    )
    datasources = datasource_cfg["datasources"]
    assert len(datasources) == 1
    assert datasources[0]["url"] == "http://alfred-prometheus:9090"

    dashboard_cfg = yaml.safe_load(
        (OPS / "grafana" / "provisioning" / "dashboards" / "dashboards.yml").read_text()
    )
    providers = dashboard_cfg["providers"]
    assert len(providers) == 1
    assert providers[0]["options"]["path"] == "/var/lib/grafana/dashboards"
