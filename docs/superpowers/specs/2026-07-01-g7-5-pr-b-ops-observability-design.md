# G7-5 PR-B — Egress-plane ops observability (design)

- **Date**: 2026-07-01
- **Epic**: [#333](https://github.com/alfred-os/AlfredOS/issues/333) — Spec C egress control plane
- **Predecessor**: G7-5 PR-A (operator egress-state CLI + the two canonical metric families) MERGED (#354, main `7c304d6a`). This is **PR-B** of the G7-5 decomposition (C→A→B→D).
- **Program spec**: [2026-07-01-g7-5-invariant-corpus-docs-design.md](2026-07-01-g7-5-invariant-corpus-docs-design.md) §5 (PR-B sketch)
- **Status**: design — 4-lens design-review folded (architect / devops / test-engineer / security)

## 1. Purpose

PR-A shipped two canonical egress metric families but nothing in `ops/` alerts on them *by reason or plane*. PR-B makes the egress plane **operator-observable**: a Grafana dashboard view + Prometheus alerting for the egress control plane, mirroring the existing `gateway_adapter_*` / `gateway_buffer_*` idioms. It adds **no new egress runtime behaviour**; its only `src/` touch is a small metric-hygiene fix the critical alert's correctness requires (§5.1).

The consumed metric contract (from PR-A, `src/alfred/gateway/egress_metrics.py`):

- `gateway_egress_inflight{plane}` — Gauge via a shared custom collector (`GaugeMetricFamily`); one sample per registered plane (`proxy` / `relay` / `adapter`).
- `gateway_egress_denied_total{plane,reason}` — Counter (built with a module-const name arg). `reason` is **per-plane**: proxy/adapter → `EgressDenyReason` (4: `destination_not_allowlisted`, `literal_ip_target`, `resolved_ip_not_global`, `malformed_connect`); relay → `EgressRelayDenyReason` (8: adds `dlp_redacted`, `canary_tripped`, `response_too_large`, `malformed_envelope`, `upstream_redirect_refused`, …).

**Pre-existing related counters (acknowledged, not replaced):** `gateway_egress_connect_total{outcome}` (proxy/adapter, plane-less) and `gateway_egress_relay_total{outcome}` already count denials *without a reason breakdown*. PR-B's `denied_total{plane,reason}` view is the by-reason refinement; the outcome counters remain the plane-level totals + the source for the egress-outage alert (§5). No `gateway_egress_up` exists; PR-B adds none.

## 2. Decisions (locked with maintainer 2026-07-01, post design-review)

1. **Dashboard: 2 timeseries panels** in `ops/grafana/gateway.json`, mirroring the adapter panels (new `id`s 11/12, `gridPos.y=36`, **no `datasource`** key — the existing panels inherit the default, new ones must match).
2. **Alerts: five** in `ops/alerts/gateway.yml`'s `alfred-gateway` group — see §5. The security review reshaped the tiers: `destination_not_allowlisted` (the primary *domain*-exfil signal, which the SSRF reasons do NOT catch) gets its own **critical spike** alert; `upstream_redirect_refused` is demoted to warning (benign-noisy — `web.fetch` refuses every http→https/CDN redirect, so paging on it would mask real canary trips); an **egress-outage** alert closes the "a sustained outage silently suppresses deny-counting" blind spot.
3. **promtool: `check rules` + `test rules`** — validate PromQL syntax AND unit-test firing logic, with a firing case for **every** critical-alert reason (a typo in one label-value alternative otherwise fails the pager open, silently). Window math sized so no assertion passes vacuously (§6).
4. **Extend the ops-scaffold AST test** — (a) recognise `GaugeMetricFamily` (for `gateway_egress_inflight`); (b) resolve a first-arg `ast.Name` against a module const map built from **both `ast.Assign` and `ast.AnnAssign`** (both new names are `Final[str]` = AnnAssign; `gateway_egress_denied` is a plain `Counter(_DENIED_NAME,…)`, so const resolution must apply to the whole recognised-ctor set, not just the family ctors). (c) Add a **label-value guard**: derive the `EgressDenyReason`+`EgressRelayDenyReason` member values and assert every `reason=~`/`reason=` alternative in the alerts is a real enum value — the "no silently-dead alerts" cross-check, one level down at the label-value the critical pager selects on. `CounterMetricFamily` is unused in source — do not add it.

## 3. Architecture / files touched

| File | Change |
| --- | --- |
| `ops/grafana/gateway.json` | +2 timeseries panels (ids 11/12, `gridPos.y=36`, no `datasource`) |
| `ops/alerts/gateway.yml` | +5 alert rules in the `alfred-gateway` group |
| `ops/alerts/gateway_test.yml` (new) | `promtool test rules` firing-logic unit tests |
| `.github/workflows/*.yml` | new CI step: install promtool + `promtool check rules` + `promtool test rules` |
| `tests/unit/test_ops_scaffold.py` | extend `_metric_names_in` (ctor set + const resolution over Assign/AnnAssign); add the reason-label-value ⊆ enum guard; assert the 5 egress alerts + 2 panels |
| `src/alfred/gateway/egress_metrics.py` (+ test) | **one metric-hygiene src change** (sec-355-1, §5.1): pre-initialise the deny counter's 16 closed `(plane,reason)` children to 0 so the critical alert fires on the FIRST occurrence |

**Src scope:** PR-B is ops observability plus a **single** small metric-hygiene fix in `egress_metrics.py` (the sec-355-1 pre-init, §5.1). A PR-B-review finding surfaced that the critical alert would otherwise miss the first zero-baseline deny; the fix and the alert must reach `main` together (architect coherence constraint), so the pre-init ships here rather than in a separate PR. No other `src/` change.

## 4. Dashboard panels

Mirror the adapter timeseries panels (`{type: timeseries, gridPos {h:8,w:12}, targets:[{expr, legendFormat}]}`, no `datasource`):

| id | Title | expr | legendFormat |
| --- | --- | --- | --- |
| 11 | Egress in-flight (per plane) | `gateway_egress_inflight` | `{{plane}}` |
| 12 | Egress denials (rate, per plane/reason) | `rate(gateway_egress_denied_total[5m])` | `{{plane}} / {{reason}}` |

## 5. Alert rules

Added to the `alfred-gateway` group, following the existing `expr`/`for`/`severity`/`summary`+`description` shape. **The `reason=~` regex uses a BARE `|`** (alternation) in the YAML — NOT `\|` (a literal-pipe match that would make the alert match nothing and fail-open); single-quote the `expr` so it can embed the `"`.

| Alert | Severity | expr | for |
| --- | --- | --- | --- |
| `GatewayEgressDenyRate` | warning | `rate(gateway_egress_denied_total[5m]) > 0` | 5m |
| `GatewayEgressInflightSaturation` | warning | `gateway_egress_inflight > 100` | 5m |
| `GatewayEgressSecurityDenySpike` | critical | `rate(gateway_egress_denied_total{reason=~"literal_ip_target\|resolved_ip_not_global\|canary_tripped\|dlp_redacted"}[5m]) > 0` | 2m |
| `GatewayEgressExfilSpike` | critical | `rate(gateway_egress_denied_total{reason="destination_not_allowlisted"}[5m]) > 0.1` | 2m |
| `GatewayEgressOutage` | warning | `rate(gateway_egress_connect_total{outcome="error"}[5m]) > 0 or rate(gateway_egress_relay_total{outcome="error"}[5m]) > 0` | 5m |

**Reason tiers (security-reviewed).**

- **Critical zero-baseline set** (`GatewayEgressSecurityDenySpike`): `literal_ip_target`, `resolved_ip_not_global` (SSRF), `canary_tripped` (active exfil probe), `dlp_redacted` (a genuine detector-deny — confirmed at `egress_relay.py` L446-467, increments the counter). Any occurrence pages.
- **Critical domain-exfil spike** (`GatewayEgressExfilSpike`): `destination_not_allowlisted` is the realistic data-exfil signal (POST to an attacker's *globally-routable* domain — the SSRF reasons never fire on it). It's also the noisiest routine reason (a misconfigured client), so it pages on a **rate SPIKE** (`> 0.1`/s ≈ 6/min, a **conservative tunable starting threshold**), not on the trickle. The warning-tier `GatewayEgressDenyRate` still catches the trickle.
- **Warning-tier only**: `malformed_connect`, `response_too_large`, `malformed_envelope`, and `upstream_redirect_refused` (benign-noisy — every `web.fetch` http→https/CDN redirect trips it; paging would desensitize on-call and mask a real canary trip).

**Thresholds are honest starting points, not derived caps.** `GatewayEgressInflightSaturation`'s `>100` (concurrent CONNECT tunnels — no hard cap exists) and `GatewayEgressExfilSpike`'s `>0.1`/s each carry a `description` saying "conservative starting threshold; tune to your deployment's baseline."

**Outage alert.** `GatewayEgressOutage` (warning) fires on a sustained egress error rate — a broken egress plane that could itself suppress deny-counting (making the security alerts blind). The `outcome="error"` value is confirmed real on both `gateway_egress_connect_total` and `gateway_egress_relay_total`; the `or` disjunct in the alert expr covers both counters. Note the scope boundary: this alert covers the **erroring-but-alive** case (the gateway process is up, `/metrics` reachable, tunnels/fetches failing). A **hard-down** gateway (process dead or `/metrics` unreachable) is covered by Prometheus scrape-health (`up{job="alfred-gateway"}==0`), not this alert.

### 5.1 Counter pre-initialisation (sec-355-1 — the one `src/` change)

A PR-B-review finding: `gateway_egress_denied_total`'s `(plane,reason)` children are **lazily created** (only on the first `.inc()`). A rate-based alert on a lazily-created counter cannot fire on the FIRST occurrence — a single first deny makes the series appear flat-at-`1`, so `rate([5m])==0` and the critical `GatewayEgressSecurityDenySpike` silently misses the very event it exists to catch (a first canary trip / SSRF / DLP catch). The idiomatic Prometheus fix is to **pre-initialise** the closed label space to 0. `build_denied_counter` (`src/alfred/gateway/egress_metrics.py`) therefore instantiates all 16 children (`proxy`×`EgressDenyReason`=4, `adapter`×`EgressDenyReason`=4, `relay`×`EgressRelayDenyReason`=8) at 0 at construction, giving `rate()` the `0→1` transition it needs. A src test asserts all 16 render at 0 on a fresh registry (`egress_metrics.py` stays 100%); a promtool case (`0 0 0 1 1 1 …`) proves the first single deny fires. This is the alert's enabling metric-hygiene, so it ships with the alert (the alert and the pre-init reach `main` together).

## 6. promtool gate (check + test rules)

`promtool check rules ops/alerts/gateway.yml` validates every rule's PromQL/structure — but note it PASSES a `\|`-broken regex (valid regex, wrong semantics), so `test rules` is the real guard for the critical alerts' matchers.

`promtool test rules ops/alerts/gateway_test.yml` unit-tests firing logic. **Window math:** each `input_series` must be long enough that `eval_time` sits *past* the alert's `for` window with ≥2 samples inside the `rate([5m])` window — otherwise the alert never leaves `pending` and an `exp_alerts: []` assertion passes **vacuously** (false-green). Required cases:

- `GatewayEgressSecurityDenySpike` **fires** — one case per reason in its set (`literal_ip_target`, `resolved_ip_not_global`, `canary_tripped`, `dlp_redacted`) so a typo in any alternative is caught.
- `GatewayEgressSecurityDenySpike` **stays quiet** on a shared series that DOES fire `GatewayEgressDenyRate` (a `destination_not_allowlisted` increase) — anchoring the negative on a genuinely-firing positive control so "quiet" isn't vacuous.
- `GatewayEgressExfilSpike` **fires** above the spike threshold, **quiet** below it (a low `destination_not_allowlisted` trickle).
- `GatewayEgressDenyRate` **fires** on any sustained denial; `GatewayEgressInflightSaturation` fires above / quiet below `>100`; `GatewayEgressOutage` fires on a sustained error rate.

CI installs promtool (Prometheus release/toolchain) and runs both; non-zero fails the build. promtool does NOT verify metric existence or label-value validity against `src/` — that stays the AST test's job (§7).

## 7. Ops-scaffold AST-test extension (required)

`tests/unit/test_ops_scaffold.py::_metric_names_in` currently derives known series only from `Counter(`/`Gauge(`/`Histogram(` calls whose first arg is a **string literal**. Both new egress metrics evade this — `gateway_egress_inflight` via `GaugeMetricFamily(_INFLIGHT_NAME,…)`, `gateway_egress_denied` via `Counter(_DENIED_NAME,…)` — because (a) `GaugeMetricFamily` isn't recognised and (b) the name args are `ast.Name`s bound to `Final[str]` consts.

Extension:

1. Add `GaugeMetricFamily` to the recognised constructor set.
2. Build a module-level name→value map from top-level `ast.Assign` **and `ast.AnnAssign`** string constants; when a recognised ctor's first arg is an `ast.Name`, resolve it through the map. Applies to the WHOLE ctor set (Counter included).
3. **Label-value guard (new test):** derive the member `.value`s of `EgressDenyReason` + `EgressRelayDenyReason` (AST or import) and assert every `reason` alternative referenced by an alert `expr` is a real enum value. Keeps the highest-severity pager from silently fail-opening on a typo or enum rename.

Then extend the alert/panel assertions to require the 5 egress alerts + confirm the 2 panels reference the (now-known) egress series.

## 8. Testing

- `tests/unit/test_ops_scaffold.py` — parses JSON/YAML, asserts the 5 egress alerts present, all referenced `gateway_*` series known (via the §7 ctor+const extension), all alert `reason` label-values are real enum members (§7.3), and the 2 egress panels present + reference known series.
- `promtool check rules` + `promtool test rules` in CI (§6).
- The only `src/` change is the §5.1 pre-init (a src coverage test keeps `egress_metrics.py` at 100%); no other unit/integration/adversarial impact beyond the ops-scaffold test.

## 9. Out of scope

- No new metric families (PR-A owns the contract). The only `src/` change is the §5.1 deny-counter pre-init — metric hygiene the alert requires, not new runtime behaviour.
- No per-destination panels (payload-blindness — labels are closed enums only).
- ADR-0040 / PRD / CLAUDE.md documentation of the egress metric set + the corrected adapter-reachability-by-value derivation is **PR-D** (human-gated). PR-B is self-mergeable.
