# G7-5 PR-A — Operator egress-state CLI (design)

- **Date**: 2026-07-01
- **Epic**: [#333](https://github.com/alfred-os/AlfredOS/issues/333) — Spec C egress control plane
- **Predecessor**: G7-5 PR-C (adversarial corpus §9) MERGED (#353). This is **PR-A** of the G7-5 decomposition (C→A→B→D).
- **Program spec**: [2026-07-01-g7-5-invariant-corpus-docs-design.md](2026-07-01-g7-5-invariant-corpus-docs-design.md) §5 (PR-A sketch)
- **Status**: design — under review before the implementation plan

## 1. Purpose

Give an operator a read-only view of the **egress plane's** live state so they can answer "is egress healthy and what is it doing?" without reading raw container logs. Surfaces four things per egress plane: the **destination allowlist**, **reachability**, **in-flight count**, and **recent deny counts by reason**. Ships no new egress *behaviour*; it makes the existing plane observable.

## 2. Decisions (locked with maintainer 2026-07-01)

1. **New `alfred gateway egress` subcommand** — not an overload of `status`. `status` stays the minimal Settings-only health line; `healthcheck` stays the Docker probe; `egress` is the detailed egress-plane view.
2. **PR-A wires the `gateway_egress_inflight` gauge** — the mechanism (`_conns` sets) exists but is unexposed; PR-A exposes it (and PR-B's saturation alert then has its metric).
3. **Deny counts by reason, from metrics** — not individual audit-log deny events (the audit-log backend is not wired to the CLI yet — `alfred audit log` → `AuditBackendUnavailable`; individual-event detail is a later follow-on).

## 3. Architecture

`alfred gateway egress` is a Typer command registered under `gateway_app` (alongside `status`/`healthcheck`/`adapters`), body in `src/alfred/cli/gateway/_egress.py` (new file — keeps `_commands.py` from growing further). It runs **in the gateway container** (`docker compose exec alfred-gateway alfred gateway egress`) because it reads the loopback metrics endpoint and the in-process egress config.

**Two data sources, each matched to the data's nature:**

- **Allowlist** — an **in-process config read**. Call the existing resolver/builders (`alfred.egress.allowlist` provider + Discord builders; `alfred.gateway.egress_relay` tool-allowlist parse) which read env/config. Static at startup; no scrape needed.
- **Reachability + in-flight + deny counts** — a **metrics scrape** of `http://127.0.0.1:<metrics-port>/metrics`, reusing the established `alfred.gateway.metrics_server.resolve_metrics_port()` + `_fetch_metrics_text(port)` seam that `healthcheck_gateway` already uses. **Parse with `prometheus_client.parser.text_string_to_metric_families`** (real label-aware parsing) — NOT `healthcheck`'s naive `_breaker_latched` line-scan, since a `{plane,reason}` table needs the label values. No new wire protocol; the metrics endpoint is the existing gateway observability seam.
- **Allowlist caveat:** the allowlist shown is the operator-configured set (a config re-read), not live per-connection proxy state — a one-line caveat in the output makes that honest.

## 4. Metric wiring (the `src/` additions)

PR-A owns the **canonical egress metric contract** (`egress_relay_audit.py:88` already reserves this for G7-5). Metric names follow the established `gateway_adapter_*` precedent (`adapter_metrics.py`); the `plane` label is a **constructor arg** on the shared `EgressForwardProxy` class (the *same* class backs both the provider proxy and the adapter proxy — it is not three separate wiring sites) plus the relay + adapter listener. Registered near the existing `gateway_egress_connect_total{outcome}` / `gateway_egress_relay_total{outcome}` counters.

| Metric | Type | Labels | Wiring |
| --- | --- | --- | --- |
| `gateway_egress_inflight` | Gauge (**custom collector**) | `plane` (`proxy`/`relay`/`adapter`) | a **scrape-time collector** reads `len(self._conns)` at collection — NOT `.set()` in `_on_connection_done` (that callback is reap-only, so set-on-reap never rises; a collector is single-source-of-truth and cannot go negative on task-cancel). Mirrors `gateway_adapter_inflight{adapter}`. |
| `gateway_egress_up` | Gauge | `plane` | set `1` on successful bind; mirrors `gateway_adapter_up{adapter}`. Meaningful signal is the **conditional adapter plane** (present iff a Discord adapter is hosted). For proxy/relay it is structurally-always-1 (bind failure is fail-closed → the gateway exits 7/8; a reachable `/metrics` tautologically implies proxy+relay up) — emitted for uniform PR-B panels, but the CLI derives proxy/relay reachability from "`/metrics` reachable". |
| `gateway_egress_denied_total` | Counter | `plane`, `reason` | incremented on each deny. **`reason` domain is PER-PLANE (two distinct closed enums):** `proxy`/`adapter` → `EgressDenyReason` (4: `destination_not_allowlisted`, `literal_ip_target`, `resolved_ip_not_global`, `malformed_connect`); `relay` → `EgressRelayDenyReason` (8: incl. `canary_tripped`, `dlp_redacted`, `response_too_large`, `malformed_envelope`, `upstream_redirect_refused`, …). Bounded: per-plane union ≈ 4 + 8 ≈ 16 series. |

Metric **names + label values stay English** (Prometheus convention; not `t()`-wrapped). The existing `{outcome}` counters are unchanged. **Sum invariant (state in TDD, for PR-B):** `sum(gateway_egress_denied_total{plane=p})` over `reason` == `gateway_egress_connect_total{plane=p,outcome=denied}` (proxy) / the relay equivalent — so PR-B uses `denied_total` as the single authoritative by-reason source. **Additive-telemetry invariant:** the deny path stays *audit-then-refuse*; the metric increment is additive and a metric exception must never swallow the audit row or the refusal.

## 5. Output & i18n

`egress` renders **per-plane stanzas** (not a single columnar table — the allowlist wraps and breaks columns), all operator text via `t()`, e.g.:

```
provider proxy      reachable
  allowlist         api.anthropic.com:443, api.deepseek.com:443
  in-flight         2
  denies            destination_not_allowlisted=4  literal_ip_target=1

tool relay          reachable
  allowlist         <none> (default-deny)
  in-flight         0
  denies            no denials

discord adapter     not configured
```

Contract: one stanza per plane; reachability, allowlist, in-flight, deny-counts-by-reason, all `t()`-localised. **Deny display:** omit zero-count reasons, but print an explicit `no denials` line so "0 denies" is distinguishable from "metric absent". **Reason labels reuse the already-reserved i18n keys** in `src/alfred/i18n/_spec_c_reserve.py` (via the existing `reason_i18n_key()` pattern) — do not mint new catalog keys. Deny counts are cumulative-since-gateway-start (Prometheus counters are monotonic; windowed "last 5m" rates are a dashboard concern → PR-B, not the CLI).

## 6. Error handling & exit codes (fail-loud, no traceback)

**Exit codes follow the report family (`adapters`), NOT `healthcheck`.** `adapters` established **exit-2 = backend unavailable** ("I can't read the data") distinct from a real negative state — `healthcheck`'s exit-1 means *unhealthy*. Reusing exit-1 would conflate "can't tell" with "egress is down" and misbranch a script.

- Metrics endpoint unreachable / malformed `ALFRED_GATEWAY_METRICS_PORT` → a friendly `t("gateway.egress.unreachable", …)` line + **exit-2** (unavailable), never a raw traceback. The message includes a next-step hint that `egress` must run **in the gateway container** (`docker compose exec alfred-gateway alfred gateway egress`) — a host invocation legitimately hits this path.
- **Plane-aware absence:** a plane whose `gateway_egress_up` gauge is absent is `not configured` **only for the conditional adapter plane** (hosted iff a Discord adapter is enabled). For the always-on proxy/relay an absent gauge is a **wiring anomaly** surfaced as such (not masked as "not configured").

## 7. Security considerations

- **Payload-blind metrics.** The new metric labels are **closed enums** (`plane`, `reason`) — never a destination host or any T3-derived value. This preserves the payload-blindness the egress audit already enforces (no destination in a metric label; destinations live only in the structlog audit line, not the scraped series).
- **Allowlist shown is config, not runtime T3.** The allowlist is operator-configured (env/config), tier T0 — safe to display.
- **Metrics endpoint binds `0.0.0.0`** (`metrics_server.py:51`) — the **container network boundary** is the actual control, not loopback (the gateway holds no secret and cannot authenticate a client; ADR-0036). Pre-existing posture; PR-A adds no new exposure surface — it reads the same endpoint `healthcheck` already reads.
- No secret, no capability-gate, no DLP path touched.

## 8. Testing

- **Happy path** — metrics text with the three families present → the full table renders with correct per-plane values (parse a fixture metrics blob).
- **Error path** — metrics endpoint unreachable / malformed port → graceful i18n message + non-zero exit, no traceback.
- **Out-of-scope refusal** — running `egress` where the gateway/metrics is absent behaves as the error path (not a crash).
- **Gauge/counter unit tests** — the `gateway_egress_inflight` collector reports `len(_conns)` at scrape time across connection add/reap (and cannot go negative on cancel); `gateway_egress_denied_total{plane,reason}` increments on each **per-plane** deny reason (both `EgressDenyReason` and `EgressRelayDenyReason` domains); `gateway_egress_up{plane}` set at bind. **Additive-telemetry test:** the deny path still emits its audit row + refuses even if the metric increment raises (the metric never swallows the audit/refusal). These live with the proxy/relay unit tests (`tests/unit/gateway/`) under the existing per-file coverage gates for `egress_proxy.py`/`egress_relay.py`.
- **i18n** — new `gateway.egress.*` catalog keys extracted + English msgstrs; `pybabel` drift gate green.

## 9. Resolved by the design-review panel (2026-07-01)

The architect/security/devops/devex design review (no Critical/High blockers) resolved the open questions and hardened the metric contract:

1. **Reachability (Q1) — keep `gateway_egress_up{plane}`** (renamed from `plane_up` per the `gateway_adapter_up` precedent). Meaningful for the conditional adapter plane; structurally-always-1 for the fail-closed proxy/relay (emitted for uniform PR-B panels; the CLI derives their reachability from "`/metrics` reachable").
2. **Deny-counter (Q2) — new `gateway_egress_denied_total` counter** (all four reviewers endorsed; widening `{outcome}` is wrong — `allowed`/`error` rows carry no reason and it breaks the existing series shape). Reason domain is **per-plane** (§4).
3. **`status` (Q3) — untouched** (hard reason). `status` is the contractual non-dialing security-L3 probe; a live egress summary would need a metrics wire-read that violates that. `egress` (which openly scrapes, like `healthcheck`) is the only correct home; discoverability is bridged by a static help-text pointer, not a live summary.
4. **Canonical names locked.** `ops/grafana/gateway.json` + `ops/alerts/gateway.yml` have zero egress refs today, so PR-A locks the canonical metric set for PR-B to consume — hence getting the `gateway_adapter_*`-idiomatic names right here is load-bearing.

## 10. Non-goals

- Individual recent-deny event detail (needs audit-log CLI wiring — later follow-on).
- Windowed/"last 5m" deny rates (a dashboard concern → PR-B).
- Any new egress behaviour, allowlist mutation, or authenticated wire protocol (ADR-0040 future extension).
- Running `egress` from the connectivity-free core (would need a relayed metrics channel — out of scope).
