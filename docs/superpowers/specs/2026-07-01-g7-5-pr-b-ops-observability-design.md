# G7-5 PR-B — Egress-plane ops observability (design)

- **Date**: 2026-07-01
- **Epic**: [#333](https://github.com/alfred-os/AlfredOS/issues/333) — Spec C egress control plane
- **Predecessor**: G7-5 PR-A (operator egress-state CLI + the two canonical metric families) MERGED (#354, main `7c304d6a`). This is **PR-B** of the G7-5 decomposition (C→A→B→D).
- **Program spec**: [2026-07-01-g7-5-invariant-corpus-docs-design.md](2026-07-01-g7-5-invariant-corpus-docs-design.md) §5 (PR-B sketch)
- **Status**: design — under review before the implementation plan

## 1. Purpose

PR-A shipped two canonical egress metric families but nothing in `ops/` observes them. PR-B makes the egress plane **operator-observable**: a Grafana dashboard view + Prometheus alerting for the egress control plane, mirroring the existing `gateway_adapter_*` / `gateway_buffer_*` dashboard and alert idioms. It ships **no new `src/` runtime behaviour** — it wires dashboards, alerts, and the tooling that validates them.

The consumed metric contract (from PR-A, `src/alfred/gateway/egress_metrics.py`):

- `gateway_egress_inflight{plane}` — Gauge via a shared custom collector (`GaugeMetricFamily`); one sample per registered plane (`proxy` / `relay` / `adapter`).
- `gateway_egress_denied_total{plane,reason}` — Counter. `reason` is **per-plane**: proxy/adapter → `EgressDenyReason` (4: `destination_not_allowlisted`, `literal_ip_target`, `resolved_ip_not_global`, `malformed_connect`); relay → `EgressRelayDenyReason` (8: adds `dlp_redacted`, `canary_tripped`, `response_too_large`, `malformed_envelope`, `upstream_redirect_refused`, …).

No `gateway_egress_up` exists (PR-A derived reachability); PR-B does not add one.

## 2. Decisions (locked with maintainer 2026-07-01)

1. **Dashboard: 2 timeseries panels** in `ops/grafana/gateway.json`, mirroring the adapter panels — egress in-flight per plane, egress deny-rate per plane/reason.
2. **Alerts: all three** (maintainer selected the full set) in `ops/alerts/gateway.yml`'s `alfred-gateway` group — a deny-rate warning, an inflight-saturation warning, and a **critical** security-reason deny-spike.
3. **promtool: `check rules` + `test rules`** (maintainer selected the full depth) — validate PromQL syntax AND unit-test the firing logic; new CI toolchain step.
4. **Extend the ops-scaffold AST test** so its metric-name derivation recognises the custom-collector families (`GaugeMetricFamily`/`CounterMetricFamily`) and module-const names — otherwise the new egress alerts/panels fail the existing "no silently-dead alerts" cross-check (both new metrics are currently invisible to it: `gateway_egress_inflight` is a `GaugeMetricFamily`, `gateway_egress_denied` is built with a module-const name, not a string literal).

## 3. Architecture / files touched

| File | Change |
| --- | --- |
| `ops/grafana/gateway.json` | +2 timeseries panels (new `id`s + `gridPos` below the adapter row) |
| `ops/alerts/gateway.yml` | +3 alert rules in the `alfred-gateway` group |
| `ops/alerts/gateway_test.yml` (new) | `promtool test rules` firing-logic unit tests |
| `.github/workflows/*.yml` | new CI step: install promtool + `promtool check rules` + `promtool test rules` |
| `tests/unit/test_ops_scaffold.py` | extend `_metric_names_in` to recognise `GaugeMetricFamily`/`CounterMetricFamily` ctors + resolve module-const name args; add assertions for the 3 egress alerts + 2 panels |

No `src/alfred/` change.

## 4. Dashboard panels

Mirror the adapter timeseries panels (`{type: timeseries, gridPos {h:8,w:12}, targets:[{expr, legendFormat}]}`):

| Title | expr | legendFormat |
| --- | --- | --- |
| Egress in-flight (per plane) | `gateway_egress_inflight` | `{{plane}}` |
| Egress denials (rate, per plane/reason) | `rate(gateway_egress_denied_total[5m])` | `{{plane}} / {{reason}}` |

New panel `id`s continue the existing sequence; `gridPos.y` places them below the current bottom row.

## 5. Alert rules

Added to the `alfred-gateway` group in `ops/alerts/gateway.yml`, following the existing `expr`/`for`/`severity`/`summary`+`description` shape:

| Alert | Severity | expr | for |
| --- | --- | --- | --- |
| `GatewayEgressDenyRate` | warning | `rate(gateway_egress_denied_total[5m]) > 0` | 5m |
| `GatewayEgressInflightSaturation` | warning | `gateway_egress_inflight > 100` | 5m |
| `GatewayEgressSecurityDenySpike` | critical | `rate(gateway_egress_denied_total{reason=~"literal_ip_target\|resolved_ip_not_global\|canary_tripped\|dlp_redacted\|upstream_redirect_refused"}[5m]) > 0` | 2m |

**Threshold honesty.** `GatewayEgressInflightSaturation`'s `> 100` is a **conservative starting threshold**, not a derived cap — egress in-flight (concurrent CONNECT tunnels) has no hard cap (unlike the adapter buffer's 8 MiB). The alert `description` states this and tells operators to tune it to their deployment's baseline.

**Two-tier deny design.** `GatewayEgressDenyRate` (warning) surfaces ANY sustained denial (e.g. a misconfigured client repeatedly hitting the default-deny allowlist). `GatewayEgressSecurityDenySpike` (critical) escalates the **security subset** — an SSRF attempt (`literal_ip_target`/`resolved_ip_not_global`), a canary trip (active exfil probe), a DLP catch (`dlp_redacted`), or a redirect attack (`upstream_redirect_refused`). The overlap is intentional: a routine allowlist-miss warns; a security-relevant denial pages. `destination_not_allowlisted`, `malformed_connect`, `response_too_large`, `malformed_envelope` are routine/protocol — warning-tier via the deny-rate alert only.

## 6. promtool gate (check + test rules)

`promtool check rules ops/alerts/gateway.yml` validates every rule's PromQL/structure — catching a malformed `reason=~"..."` matcher or a bad `rate()` the pure-Python regex-grep would miss.

`promtool test rules ops/alerts/gateway_test.yml` unit-tests firing logic against synthetic series. Minimum cases:

- `GatewayEgressSecurityDenySpike` **fires** when `gateway_egress_denied_total{plane="relay",reason="canary_tripped"}` increases; and when `reason="literal_ip_target"`.
- `GatewayEgressSecurityDenySpike` **stays quiet** on `gateway_egress_denied_total{plane="proxy",reason="destination_not_allowlisted"}` alone (proves the regex discriminates the security subset).
- `GatewayEgressDenyRate` **fires** on any sustained `gateway_egress_denied_total` increase.
- `GatewayEgressInflightSaturation` **fires** when `gateway_egress_inflight{plane="proxy"}` exceeds the threshold for the `for` window; quiet below it.

CI: a step installs promtool (from the Prometheus release/toolchain) and runs both commands; a non-zero exit fails the build. promtool does NOT verify metric existence in `src/` — that stays the AST test's job (§7). The two are complementary.

## 7. Ops-scaffold AST-test extension (required)

`tests/unit/test_ops_scaffold.py::_metric_names_in` currently derives known series only from `Counter(`/`Gauge(`/`Histogram(` calls whose first arg is a **string literal**. Both new egress metrics evade this:

- `gateway_egress_inflight` is yielded by a custom collector via `GaugeMetricFamily(_INFLIGHT_NAME, …)` — not a `Gauge(` constructor.
- `gateway_egress_denied` is built via `Counter(<module-const>, …)` — the name arg is an `ast.Name`, not an `ast.Constant`.

Extension: (a) add `GaugeMetricFamily` / `CounterMetricFamily` to the recognised constructor set; (b) resolve a module-level `Final[str]` / assigned string constant when the first arg is an `ast.Name` (build a name→value map from the module's top-level assignments, then look it up). This keeps the "no silently-dead alerts" cross-check honest for custom-collector metrics rather than hardcoding an exception. Then extend the alert/panel assertions to require the 3 new alerts + confirm the 2 new panels reference the (now-known) egress series.

## 8. Testing

- `tests/unit/test_ops_scaffold.py` — parses the JSON/YAML, asserts the 3 egress alerts present + all referenced `gateway_*` series known (now including the egress families via the §7 extension), asserts the 2 egress panels present + their exprs reference known series.
- `promtool check rules` + `promtool test rules` in CI (§6).
- No `src/` change → no unit/integration/adversarial impact beyond the ops-scaffold test.

## 9. Out of scope

- No new metric families or `src/` runtime change (PR-A owns the contract).
- No dashboard for the CLI itself; no per-destination panels (payload-blindness — labels are closed enums only).
- ADR-0040 / PRD / CLAUDE.md documentation of the egress metric set + the corrected adapter-reachability-by-value derivation is **PR-D** (human-gated). PR-B is self-mergeable.
