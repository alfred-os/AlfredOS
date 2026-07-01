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
- **Reachability + in-flight + deny counts** — a **metrics scrape** of `http://127.0.0.1:<metrics-port>/metrics`, reusing the established `alfred.gateway.metrics_server.resolve_metrics_port()` + `_fetch_metrics_text(port)` seam that `healthcheck_gateway` already uses. **Parse with `prometheus_client.parser.text_string_to_metric_families`** (real label-aware parsing) — NOT `healthcheck`'s naive `_breaker_latched` line-scan, since a `{plane,reason}` table needs the label values. **Reachability is derived** (no `up` gauge): proxy + relay are up iff `/metrics` is reachable (fail-closed bind); the adapter plane's presence is read from the *existing* `gateway_adapter_up{adapter}` series in the same scrape. In-flight + deny-counts come from the two new families. No new wire protocol.
- **Allowlist caveat:** the allowlist shown is the operator-configured set (a config re-read), not live per-connection proxy state — a one-line caveat in the output makes that honest.

## 4. Metric wiring (the `src/` additions)

PR-A owns the **canonical egress metric contract** (`egress_relay_audit.py:88` reserves this for G7-5). **Two** new families + their collector live in ONE new module `src/alfred/gateway/egress_metrics.py` (mirroring `adapter_metrics.py`) — a single canonical registration home. (The existing `connect_total`/`relay_total` live in two different modules; the new families are cross-plane singletons and Prometheus forbids duplicate registration, so they need one home.) Names follow the `gateway_adapter_*` precedent. The `plane` label is a **constructor arg** on the shared `EgressForwardProxy` class (the *same* class backs both the provider proxy and the adapter proxy) plus the relay.

| Metric | Type | Labels | Wiring |
| --- | --- | --- | --- |
| `gateway_egress_inflight` | Gauge (**one shared custom collector**) | `plane` (`proxy`/`relay`/`adapter`) | a SINGLE scrape-time collector (registered once in `egress_metrics.py`) reads `len(_conns)` for each **registered** plane instance and emits **one sample per plane** — NOT a per-instance collector (which emits duplicate `gateway_egress_inflight` TYPE lines and breaks PR-A's own `text_string_to_metric_families` parse), and NOT `.set()` on reap (that callback is reap-only, so it never rises). A **register/deregister seam** (a plane registers its `_conns` on bind, deregisters on teardown) keeps a torn-down adapter plane from leaving a stale `inflight{plane=adapter}` series. Mirrors `gateway_adapter_inflight{adapter}`. |
| `gateway_egress_denied_total` | Counter | `plane`, `reason` | incremented on each deny **strictly after the audit-write + the refusal** (relay: in `_emit` after `write_frame`; proxy/adapter: in `_deny` after the audit) so a raising `.inc()` can never drop the audit row or the refusal (additive-telemetry). **`reason` domain is PER-PLANE (two distinct closed enums):** `proxy`/`adapter` → `EgressDenyReason` (4: `destination_not_allowlisted`, `literal_ip_target`, `resolved_ip_not_global`, `malformed_connect`); `relay` → `EgressRelayDenyReason` (8: incl. `canary_tripped`, `dlp_redacted`, `response_too_large`, `malformed_envelope`, `upstream_redirect_refused`, …). Bounded series: 4 (proxy) + 4 (adapter) + 8 (relay) = 16. |

**No `gateway_egress_up` gauge** (design-review convergence). Reachability is *derived*, not gauged: proxy/relay are fail-closed (a bind failure exits the gateway 7/8), so a reachable `/metrics` tautologically implies both are up; the **adapter** plane's presence is read from the *existing* `gateway_adapter_up{adapter}` (a dedicated egress up-gauge would duplicate it). Drops a redundant/decorative series and keeps PR-A to two new families.

Metric **names + label values stay English** (Prometheus; not `t()`-wrapped). The existing `{outcome}` counters are **unchanged** — critically, `gateway_egress_connect_total` carries only `{outcome}` (no `plane`) and is **shared by the provider + adapter proxies** (one `EgressForwardProxy` module-level counter). **Sum invariants (state in TDD, for PR-B):** `sum over reason of gateway_egress_denied_total{plane∈{proxy,adapter}}` == `gateway_egress_connect_total{outcome="denied"}` (the shared, plane-less proxy/adapter counter); `sum over reason of gateway_egress_denied_total{plane="relay"}` == `gateway_egress_relay_total{outcome="denied"}`. PR-B uses `denied_total` as the authoritative by-reason source and `absent(...)` / `/metrics`-reachability for proxy/relay liveness.

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

Contract: one stanza per plane; reachability, allowlist, in-flight, deny-counts-by-reason, all `t()`-localised. **The plane header** ("provider proxy"/"tool relay"/"discord adapter") is a **distinct `t()` string**, NOT the English metric label value (`proxy`/`relay`/`adapter`) — so it never ships as hardcoded English. **Deny display:** omit zero-count reasons, but print an explicit `no denials` line so "0 denies" is distinguishable from "metric absent". **Reason labels render via the PER-PLANE `reason_i18n_key()` — there are TWO functions** (`egress_audit.reason_i18n_key` → `gateway.egress.denied.*` for proxy/adapter; `egress_relay_audit.reason_i18n_key` → `gateway.egress.relay_denied.*` for relay); the renderer dispatches by plane. All 12 keys are already reserved in `src/alfred/i18n/_spec_c_reserve.py` — do not mint new ones. **The renderer validates each scraped `reason` token against the plane's closed enum and fails loud on an unknown token** (metric-drift detection + display-side payload-blindness). Deny counts are cumulative-since-gateway-start (windowed rates are a dashboard concern → PR-B).

## 6. Error handling & exit codes (fail-loud, no traceback)

**Exit codes follow the report family (`adapters`), NOT `healthcheck`.** `adapters` established **exit-2 = backend unavailable** ("I can't read the data") distinct from a real negative state — `healthcheck`'s exit-1 means *unhealthy*. Reusing exit-1 would conflate "can't tell" with "egress is down" and misbranch a script.

- Metrics endpoint unreachable / malformed `ALFRED_GATEWAY_METRICS_PORT` → a friendly `t("gateway.egress.unreachable", …)` line + **exit-2** (unavailable), never a raw traceback. The message includes a next-step hint that `egress` must run **in the gateway container** (`docker compose exec alfred-gateway alfred gateway egress`) — a host invocation legitimately hits this path.
- **Plane-aware reachability (derived, no `up` gauge):** with `/metrics` reachable, proxy + relay are **up** (fail-closed bind — a down proxy/relay means the gateway already exited). The **adapter** plane is `up` iff a `gateway_adapter_up{adapter}` series is present in the scrape, else `not configured` (no Discord adapter hosted). If `/metrics` itself is unreachable, the whole command takes the exit-2 unavailable path above — no per-plane state is knowable.

## 7. Security considerations

- **Payload-blind metrics.** The new metric labels are **closed enums** (`plane`, `reason`) — never a destination host or any T3-derived value. This preserves the payload-blindness the egress audit already enforces (no destination in a metric label; destinations live only in the structlog audit line, not the scraped series).
- **Allowlist shown is config, not runtime T3.** The allowlist is operator-configured (env/config), tier T0 — safe to display.
- **Metrics endpoint binds `0.0.0.0`** (`metrics_server.py:51`) — the **container network boundary** is the actual control, not loopback (the gateway holds no secret and cannot authenticate a client; ADR-0036). Pre-existing posture. PR-A adds **two new payload-blind series** (`inflight`, `denied_total`) to that endpoint — same sensitivity class as the existing `{outcome}` counters (closed enums, no secret/T3/destination) — and reads the same endpoint `healthcheck` already reads.
- No secret, no capability-gate, no DLP path touched.

## 8. Testing

- **Happy path** — a fixture `/metrics` blob with the two new families (+ `gateway_adapter_up`) → the per-plane stanzas render with correct values (parse via `text_string_to_metric_families`).
- **Output-branch tests** — (a) **`no denials` vs metric-absent**: a present-but-zero `denied_total` prints `no denials`; the family absent prints the unavailable state — distinct outputs. (b) **Plane-aware reachability**: `/metrics` reachable but `gateway_adapter_up{adapter}` absent → adapter `not configured`; present → `up`.
- **Error path** — `/metrics` unreachable / malformed port → graceful i18n message + **exit-2** (report-family, not `healthcheck`'s exit-1), no traceback; the message carries the `docker compose exec` hint.
- **Reason-validation refusal** — a scraped `reason` token outside the plane's closed enum → the renderer fails loud (never silently rendered).
- **Metric unit tests** (per-test `CollectorRegistry`) — the shared `gateway_egress_inflight` collector emits **one sample per registered plane** = `len(_conns)`, and a **deregistered** (torn-down) plane leaves no stale series (reap-consistency — not the trivial `len≥0`); `gateway_egress_denied_total{plane,reason}` increments, **parametrised over the full `EgressDenyReason` (4) and `EgressRelayDenyReason` (8)** so a future unwired reason is caught. **Additive-telemetry test:** the deny path still emits its audit row + refuses even if the `.inc()` raises (increment pinned *after* the audit + refusal). These live in `tests/unit/gateway/`; the metric wiring in `egress_proxy.py`/`egress_relay.py` is under their existing 100% per-file gates (`ci.yml`), and **`egress_metrics.py` (the collector home) must be added to that 100% include list**.
- **CLI coverage** — `_egress.py` (parse/render/exit-2/i18n — the bulk of the new code) carries an explicit coverage target so its branches don't escape the gate.
- **i18n** — new literal `gateway.egress.*` keys (headers, reachability words, `no denials`, unreachable+hint) extracted + English msgstrs; the reserved deny-reason keys need no new entry; `pybabel` drift gate green.

## 9. Resolved by review (design-review + `/review-plan` panel, 2026-07-01)

Two rounds (a 4-lens design review, then a 6-reviewer `/review-plan`; 0 Critical, 1 High — all caught pre-code) settled the open questions and hardened the metric contract:

1. **Reachability — no `up` gauge (dropped as redundant).** Proxy/relay reachability is derived from "`/metrics` reachable" (fail-closed bind); the adapter plane reuses the *existing* `gateway_adapter_up{adapter}`. PR-A wires **two** families, not three.
2. **Deny-counter — new `gateway_egress_denied_total{plane,reason}`** (endorsed; widening the existing `{outcome}` counter is wrong — it carries no `reason` and is *shared, plane-less* across the proxy+adapter). Reason domain is **per-plane** (`EgressDenyReason` 4 for proxy/adapter, `EgressRelayDenyReason` 8 for relay); sum invariants in §4.
3. **`status` — untouched** (hard reason): it is the non-dialing security-L3 probe; a live egress summary needs a metrics wire-read that would violate that. `egress` (which openly scrapes, like `healthcheck`) is the only correct home; discoverability via a static help-text pointer.
4. **Canonical set locked.** `ops/grafana/gateway.json` + `ops/alerts/gateway.yml` have zero egress refs today, so PR-A locks the `gateway_adapter_*`-idiomatic names + the sum invariants that PR-B builds its saturation alert + per-reason panel on.
5. **One canonical home** — the two families + the shared inflight collector live in a new `src/alfred/gateway/egress_metrics.py` (Prometheus forbids duplicate registration).

## 10. Non-goals

- Individual recent-deny event detail (needs audit-log CLI wiring — later follow-on).
- Windowed/"last 5m" deny rates (a dashboard concern → PR-B).
- Any new egress behaviour, allowlist mutation, or authenticated wire protocol (ADR-0040 future extension).
- Running `egress` from the connectivity-free core (would need a relayed metrics channel — out of scope).
