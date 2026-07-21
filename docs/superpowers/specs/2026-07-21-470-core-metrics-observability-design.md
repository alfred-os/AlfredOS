# #470 — core `/metrics` scrapeable + bundled observability stack (design)

**Status:** DRAFT (2026-07-21) — pending requester review before `writing-plans`. On branch
`470-core-metrics-observability-design` off main `1f94bfef`. Cross-vetted pre-execution by four
lanes (security ×2, architect, devops — all AGREE, 0 design-killers; verdicts folded into §§4–9).
Doc-only artifact; no code yet. Editing PRD/CLAUDE.md is human-gated and out of scope here; the
ADR named in §8 (ADR-0053) belongs to the **separate** notification-egress issue, not this design.

Parent context: #340 PR2b-golive (`docs/superpowers/specs/2026-07-11-issue-340-pr2b-golive-cutover-design.md`)
added the `alfred_quarantine_capability_revoked_total` counter + alert rule + runbook as the
security-lane precondition for shipping the real quarantine child **without** a respawn scheduler
(#455). This design makes that counter — and every other core-registered series — actually
collected.

---

## 1. Goal

`alfred-core` (the connectivity-free core, Spec C / ADR-0040) exposes **no `/metrics` endpoint**,
and `docker-compose.yaml` bundles **no Prometheus service at all** (`ops/prometheus/prometheus.yml`
is a scaffold that scrapes only `alfred-gateway:9464` and wires only `gateway.yml` into
`rule_files`). Every core-registered Prometheus series is therefore constructed, incremented on the
real paths, and discarded — including the security-critical `alfred_quarantine_capability_revoked_total`,
whose promtool-verified alert rule *cannot fire* because nothing scrapes the process that increments
it. This is the repo's own documented "paper-only gate" failure mode.

Make the core metrics **scrapeable** and bundle an **internal-only** monitoring stack so the
`QuarantineCapabilityRevoked` rule evaluates against a live, firing, queryable series — satisfying
the security lane's "alertable" precondition — without opening any new external egress from the
connectivity-free core.

## 2. Scope & decomposition

This design covers **#470 = two PRs**:

- **PR1 — core `/metrics` endpoint** (§5). Security-weighted core change.
- **PR2 — bundle Prometheus + profile-gated Grafana** (§6). Ops/compose change.

The **real external paging** (Alertmanager + notification egress to Slack/webhook) is carved into a
**separate new issue** (§8), because it opens the *first non-provider external egress in the
connectivity-free core's history* and needs its own ADR (**0053**) + security sign-off. That issue
overlaps #469 (first-run experience). The split is deliberate: #470 delivers rule-evaluation + a
queryable firing alert (which *is* the precondition floor and unblocks the "armed, not live"
caveats); the follow-up delivers the human-gets-paged delivery (genuinely wanted, sequenced
immediately after, not gold-plating).

**Why the precondition is met by rule-evaluation alone:** the `ops/alerts/quarantine.yml` header
made "shipping the real child without #455-respawn conditional on *this alert existing*." Today the
rule exists but evaluates against a series nothing scrapes (armed, not live). The precondition is
honestly met the moment Prometheus scrapes the core and the rule can transition to firing
(queryable in Prometheus's `/alerts` UI + API). Notification *delivery* is the follow-up.

## 3. Verified current-state anchors (confirmed vs tree `1f94bfef`, 2026-07-21)

- **No core `/metrics`.** `start_metrics_server` (`src/alfred/gateway/metrics_server.py:44`) is
  called only from `alfred gateway start` (`src/alfred/cli/gateway/_commands.py:290`). The daemon
  (`alfred daemon start`) serves nothing.
- **No Prometheus in compose.** `docker-compose.yaml` services are postgres, redis, core, gateway.
  `ops/prometheus/prometheus.yml` is a scaffold: single `alfred-gateway:9464` job; `rule_files`
  lists only `gateway.yml` (not `quarantine.yml`).
- **The counter is real on every revoke path.** `CAPABILITY_REVOKED_COUNTER.inc()`
  (`src/alfred/security/observability.py:47`) fires before teardown on every revoke path —
  **including the cancel-path revoke (#472) that writes no `egress.broker.refused` audit row.** So
  the metric is the *only* durable signal for that revoke class: landing #470 is security-additive,
  not merely ops hygiene.
- **The core has no container healthcheck.** Only postgres/redis/gateway define one.
- **The connectivity-free network topology** (`docker-compose.yaml`; `tests/unit/test_compose_invariants.py`):
  `alfred_internal` is `internal: true` (kernel-isolated, no internet route); `alfred-core` joins it
  **only** (`test_core_joins_internal_only`); `alfred_external` carries **only** `alfred-gateway`
  (`test_only_gateway_on_external`, a generic fail-closed guard for any non-gateway service).
- **macOS/OrbStack host-port loss** (ADR-0042:43-44, verified 2026-06-29): an `internal:true`-only
  container's host-published port is not forwarded on OrbStack/Docker-Desktop. `alfred-postgres`
  publishes `5432` anyway as a Linux-only-convenience precedent.

## 4. Invariant analysis — an inbound `/metrics` listener does not breach connectivity-free

ADR-0040 Decision 1 governs the core opening **external** sockets ("No process inside the core can
open an external socket" — the whole two-layer model is about *outbound* reachability). An inbound
TCP listener that accepts connections from peers already on the kernel-isolated `alfred_internal`
network is a **different class**: it creates no route out. The core already binds inbound listeners
on `alfred_internal` (the `comms-tui.sock` the gateway dials; postgres/redis bind 5432/6379).
`prometheus_client.start_http_server` is **listen-only** — it opens no outbound connection and
cannot break `internal:true` (a network-level property). No `test_compose_invariants.py` ratchet is
tripped: the core stays internal-only, joins no new network, and the metrics port is never
host-published (§5.6). *Security-lane verdict: CONFIRMED.*

## 5. PR1 — core `/metrics` endpoint

### 5.1 Shared metrics-server module

Promote the gateway's exposition (`resolve_metrics_port` + `start_metrics_server`) out of
`alfred/gateway/metrics_server.py` into a neutral shared module (e.g.
`alfred/observability/metrics_server.py`) — the core is its second consumer (the
refactor-on-second-use trigger). Parameterize `resolve_metrics_port(env_var, default)` so the
gateway keeps `ALFRED_GATEWAY_METRICS_PORT` and the core reads a new `ALFRED_CORE_METRICS_PORT`.
Gateway call sites (`_egress.py`, `_commands.py` ×2) update to pass their env-var/default.

### 5.2 Curated registry — the load-bearing correctness fix (not hygiene)

The core process pulls **~20 stale `gateway_*` families** onto the `prometheus_client` **default**
registry via an import side-effect: `alfred.cli.daemon._comms_boot:62` imports
`alfred.gateway._seq_tracker`, which executes `alfred/gateway/__init__.py` →
`core_link`/`process`/`relay`, each registering its `gateway_*` collectors at import. The core never
runs those components, so every one sits at its default value.

Serving the default registry from the core `/metrics` would expose those stale families on the
`alfred-core` scrape target. `ops/alerts/gateway.yml`'s **`GatewayCoreUnavailable: gateway_core_link_up == 0`
carries no `{job}` selector**, so it would match the core's **permanently-zero** `gateway_core_link_up`
copy → **fire and stay firing → page continuously and falsely**, even when the real gateway link is
up. This is a deterministic mis-fire, the decisive argument.

**Design:** the core builds a dedicated `CollectorRegistry` and registers exactly the core-owned
collector *objects* onto it (`prometheus_client` allows a collector to live in multiple registries —
`curated.register(CAPABILITY_REVOKED_COUNTER)` etc.), then serves it via `start_http_server(port,
registry=curated)`. The collectors **stay constructed on the default registry** (do not move them —
the "duplicate-name regression surfaces loud at import" property in `security/observability.py` /
`gateway/metrics.py` depends on default-registry construction, and the gateway process still serves
them). The core simply never *serves* the default registry. **Note for reviewers:** promoting the
metrics-server module (§5.1) does **not** fix the leak — the leak is the `_comms_boot` import, not
where the server lives. Only the curated registry does.

The reviewed core-owned family set (from the security-lane label audit — all closed-domain or
bucketed, **no leak**):

| Family | Labels | Domain |
| --- | --- | --- |
| `alfred_quarantine_capability_revoked_total` | (none) | — |
| `alfred_comms_inbound_dispatch_seconds` | (none) | — |
| `alfred_comms_quarantined_extract_seconds` | (none) | — |
| `alfred_comms_burst_limiter_wait_seconds` | (none) | — |
| `alfred_comms_handler_failures_total` | (none) | — |
| `alfred_orchestrator_action_duration_seconds` | `user_id_bucket`, `action_outcome`, `breaker_state` | SHA-256 mod-256 bucket (non-reversible) + closed enums; out-of-domain → `unknown` |
| `alfred_stdio_transport_dispatch_seconds` | `plugin_id`, `method_shape`, `outcome` | plugin_id allowlist-bucketed to 100 + `"other"`; closed enums |
| `alfred_plugin_spawn_seconds` | `plugin_id`, `outcome` | same bucketing |
| `alfred_outbound_dlp_scan_seconds` | `outcome` | closed `{allowed,refused}` |
| `alfred_inbound_scanner_scan_seconds` | `outcome` | closed `{clean,canary_trip}` |

`plugin_id` is a manifest-declared, author-chosen, human-gated-at-install operational identifier
(not user identity / T3 / secret), allowlist-bounded — scrape-safe.

### 5.3 Leak-guard ratchet test — BLOCKING (the DLP-equivalent for this surface)

`/metrics` is a new outbound-shaped surface that bypasses `OutboundDlp`; per HARD rule 4 a
DLP-exempt path must declare it once and have the suite verify the claim. A **two-sided** test pins
the curated exposition:

1. **No leak / no stale:** the exposed family set contains **no** `gateway_*` family (and no label
   outside the reviewed allowlist above) — so a future `Counter("...", labels=["user_id"])` on the
   default registry, or a re-introduced `gateway_*` bleed, fails loud.
2. **No silent under-include:** enumerate the core observability modules' collectors and assert each
   is present in the curated exposition — so a *future* core metric can't silently miss the endpoint.

Pin exact family + label-key sets (not `contains`/subset), so adding a family is a deliberate,
reviewed act — same discipline as the DLP allowlist. This test **must land in PR1 and be green
before anything scrapes the endpoint** (the endpoint is a disclosure surface the instant it serves).

### 5.4 Bind-failure policy + core healthcheck

Keep `start_metrics_server`'s **loud-and-continue** posture (log `metrics.bind_failed`, return
`False`, never raise) — never take down the comms/quarantine data plane to protect its telemetry.
**But** the gateway's loud-and-continue only satisfies HARD rule 7 ("no silent failures in security
paths") because the gateway has a two-tier healthcheck that flips the container unhealthy; the core
has **no healthcheck today**, so a naive reuse would be *effectively silent* — the `bind_failed`
warning rides the very observability plane that just failed, and a never-bound `/metrics` silently
disables the security alert.

Add a **core container healthcheck that probes `/metrics`** (an `alfred daemon healthcheck`
subcommand mirroring the gateway's, using the **in-image `alfred` CLI, not curl** — not guaranteed
in the image — against `127.0.0.1:$ALFRED_CORE_METRICS_PORT`, a compose-internal never-published
port). Safe today: nothing has `depends_on: alfred-core: service_healthy`, so core-unhealthy is
observable without wedging the stack.

### 5.5 Expose the security counter at 0 from t=0

Import `alfred.security.observability` explicitly at daemon boot (ordered before/at metrics-server
start) so `alfred_quarantine_capability_revoked_total` is registered and exposed **at 0 from t=0**,
not only after the first revoke — the alert (`increase(...[5m]) > 0`) needs the series present. Add
an `absent(alfred_quarantine_capability_revoked_total)` belt-and-suspenders alert (mirrors the
`egress_metrics` pre-init-to-zero pattern). Also add a Prometheus `up{job="alfred-core"} == 0`
target-down alert (PR2, §6.1) as the primary out-of-band detection independent of the core's own
logs.

### 5.6 Port pin

New `ALFRED_CORE_METRICS_PORT` (compose-internal, **never host-published**). Add a compose-invariant
test mirroring `test_egress_proxy_port_never_host_published` / `test_alfred_gateway_publishes_no_host_port`:
no service host-publishes the core metrics container port.

## 6. PR2 — bundle Prometheus + profile-gated Grafana (internal-only)

Both services join `alfred_internal` **only** — `test_only_gateway_on_external` already forbids
`alfred_external`, and this design *strengthens* that into a positive "observability components are
egress-incapable" pin (§6.3). Neither needs external network: Prometheus scrapes internal targets
and evaluates rules locally; Grafana queries Prometheus internally.

### 6.1 Prometheus

- `image: prom/prometheus:<pinned>`; `restart: unless-stopped`; `networks: [alfred_internal]`; no
  `ports:`.
- Command: `--config.file`, `--storage.tsdb.path=/prometheus`, `--storage.tsdb.retention.time=15d`,
  `--web.listen-address=0.0.0.0:9090`. **No** `--web.enable-admin-api`, **no** `--web.enable-lifecycle`,
  **no** `remote_write`.
- Volumes: `alfred_prom_data:/prometheus`; `./ops/prometheus/prometheus.yml:...:ro`;
  `./ops/alerts:/etc/prometheus/alerts:ro` (config + rules mounted **read-only**).
- `ops/prometheus/prometheus.yml` gains: the `alfred-core → ["alfred-core:${ALFRED_CORE_METRICS_PORT}"]`
  scrape job; `quarantine.yml` added to `rule_files`; the `up{job="alfred-core"} == 0` and
  `absent(...)` rules (§5.5). Keep the existing `ops/alerts/*_test.yml` promtool unit tests green.

### 6.2 Grafana — profile-gated, internal-only, zero egress

**Access decision (all three lanes: reject the second-bridge option; A demoted to last resort):** a
non-`internal:true` bridge would grant Grafana a standing internet NAT route — a second, non-gateway
egress plane on the stack's highest-CVE-surface component (Grafana's data-source proxy is a built-in
SSRF primitive) — a direct ADR-0040 regression that the app-level hardening flags cannot remove
(defense-in-depth inverted). Grafana stays `alfred_internal`-only, **zero egress, no notifier
secret** (paging lives with the follow-up's Alertmanager). Browsable across platforms without egress:

- **Linux** — `ports: ["127.0.0.1:3000:3000"]` (works on an internal-only container, per the
  postgres precedent; inert where OrbStack doesn't forward it).
- **OrbStack** — `alfred-grafana.<project>.orb.local` / direct container IP. This is an **inbound**
  unified-bridge path (the OrbStack host is a peer on the bridge), mechanistically distinct from the
  broken outbound port-forward, so it reaches an `internal:true`-only container with no published
  port and no egress. **One empirical check is a PR2 smoke-test task** (undocumented for the
  `internal:true` case; high-confidence but must be confirmed before documenting as primary).
- **Docker Desktop** — no `*.orb.local`; documented opt-in ambassador-tunnel container as the
  guaranteed fallback.

**Profile-gated (`--profile observability`):** the *default* `docker compose up` ships **zero
Grafana surface** (default-deny; dashboards are operator convenience, not a security function; the
orb.local uncertainty never touches the default stack). PRD §7.5's "default Grafana bundle in
`ops/grafana/`" is satisfied by shipping the dashboard *artifacts* + provisioning by default; only
the running *container* is opt-in. (If a reviewer reads §7.5 as mandating a *running* Grafana by
default, fall back to plain internal-only default-on — **never** the second bridge — and treat the
reinterpretation as a human-gated PRD clarification.)

- `image: grafana/grafana:<pinned>`; `profiles: [observability]`; `networks: [alfred_internal]`.
- Hardening (defense-in-depth *on top of* zero egress): `GF_ANALYTICS_REPORTING_ENABLED=false`,
  `GF_ANALYTICS_CHECK_FOR_UPDATES=false`, `GF_ANALYTICS_CHECK_FOR_PLUGIN_UPDATES=false`,
  `GF_AUTH_ANONYMOUS_ENABLED=false`, `GF_USERS_ALLOW_SIGN_UP=false`, `GF_INSTALL_PLUGINS=""`,
  `GF_SNAPSHOTS_EXTERNAL_ENABLED=false`, `GF_SECURITY_DISABLE_GRAVATAR=true`,
  `GF_SECURITY_ADMIN_PASSWORD=${GF_SECURITY_ADMIN_PASSWORD:?set in .env}` (never hardcoded; `.env` +
  placeholder in `.env.example`).
- Volumes: `alfred_grafana_data:/var/lib/grafana`; `./ops/grafana/provisioning:...:ro`;
  `./ops/grafana:/var/lib/grafana/dashboards:ro`. Ship a datasource provision → `http://alfred-prometheus:9090`
  and a dashboards provider over `ops/grafana/*.json` (`gateway.json` exists).

### 6.3 Compose-invariant tests

- Core metrics port never host-published (§5.6).
- The observability components (`alfred-prometheus`, `alfred-grafana`) join `alfred_internal`
  **only** — a positive egress-incapable pin, keeping `test_only_gateway_on_external == {alfred-gateway}`
  intact rather than growing a named exception.
- Grafana's only published port (if present) binds `127.0.0.1`, never `0.0.0.0`.
- `alfred-core` now defines a `healthcheck`.
- Prometheus command contains neither `--web.enable-admin-api` nor `--web.enable-lifecycle`;
  `GF_SECURITY_ADMIN_PASSWORD` is env-sourced, not literal.
- **Healthcheck realism:** Prometheus/Grafana minimal images may lack a shell/curl — use each image's
  own probe path (`/-/healthy`, `/api/health`) or omit rather than ship a broken healthcheck. The
  load-bearing core healthcheck (§5.4) uses the in-image `alfred` CLI and is unaffected.

### 6.4 Caveat reframe (drop "armed, not live" — but keep the audit path)

Remove the "armed, not yet live" blocks in `src/alfred/security/observability.py`,
`ops/alerts/quarantine.yml`, and the `⚠ Read first: the alert cannot fire yet` block in
`docs/runbooks/quarantine-capability-revoked.md`. **Reframe, don't delete**, the runbook's
audit-log detection path: because of the cancel-path revoke that writes no audit row (#472), the
audit path and the metric are **complementary**, not redundant — retain it as the durable
cross-check.

## 7. Security conditions summary (folded from the security lanes)

1. Curated registry (§5.2) — resolves the `GatewayCoreUnavailable` false-page and bounds the surface.
2. Two-sided leak-guard test (§5.3) — BLOCKING; lands in PR1, green before any scrape.
3. Core healthcheck probing `/metrics` (§5.4) — so loud-and-continue isn't silent on the core.
4. Counter exposed at 0 from t=0 + `up==0` + `absent()` alerts (§5.5).
5. Core metrics port + observability components pinned (§5.6, §6.3) — internal-only, never
   host-published; `test_only_gateway_on_external` untouched.
6. The core `/metrics` is unauthenticated plaintext HTTP readable by any `alfred_internal` peer
   (inherent to `start_http_server`; matches the internal-net posture). Per the label audit it
   carries only operational aggregates — no T3/PII/secret. **Record as an accepted residual**; the
   leak-guard keeps it true.

## 8. Handoff — the separate notification-egress issue (NOT this design)

Real external paging is tracked in **#479** (filed 2026-07-21). Its shape (pre-vetted here so the
boundary is clean):

- **Alertmanager** (not Grafana-managed alerting — the rules already live as promtool-tested
  `rule_files`; re-homing them in Grafana would fork the definitions). Alertmanager holds the paging
  secret and the egress capability, keeping the host-published Grafana egress-free and secret-free.
- **Notification egress through the gateway**, via a **dedicated `plane="notifier"` L7-proxy
  instance with a notifier-scoped, exact-match allowlist** (e.g. `hooks.slack.com:443`) — **not** by
  widening the shared provider `:8889` allowlist (which the core's own EgressClient uses; widening it
  would silently expand the connectivity-free core's reachable destinations). Mirrors ADR-0040 §4's
  "one implementation, multiple instances by `_plane`". The gateway L7 CONNECT proxy supports this
  (an HTTPS_PROXY Go client issues `CONNECT hooks.slack.com:443`; `_authorize` gates it). **SMTP does
  not route through an HTTPS proxy — webhook/Slack HTTPS POST is the clean fit.**
- **ADR-0053** required (first non-provider external egress destination class through the chokepoint;
  one-peer widening of ADR-0040 residual (iv), tracked #358; receiver-secret placement on the
  notifier, not the gateway) + security sign-off. New config surface: `ALFRED_ALERT_EGRESS_ALLOWLIST`
  (gateway, notifier-scoped), `HTTPS_PROXY` on the notifier, `ALFRED_ALERT_RECEIVER_URL`.
- The `QuarantineCapabilityRevoked` payload is safe to egress (label-less series, static English
  annotation, no templating); the leak-guard discipline is declared to cover alert-notification
  bodies.

## 9. Testing strategy

- **PR1 (unit):** leak-guard two-sided test (§5.3); the endpoint serves the curated registry and
  omits `gateway_*` (hit `/metrics`, assert family set); `resolve_metrics_port` env parsing; the
  core-metrics-port never-published compose-invariant test.
- **PR2 (unit + smoke):** the new compose-invariant tests (§6.3); promtool unit tests
  (`ops/alerts/*_test.yml`) stay green with `quarantine.yml` loaded + the new `up`/`absent` rules; a
  macOS/OrbStack smoke task empirically confirms `alfred-grafana.<project>.orb.local` reaches the
  internal-only Grafana before it's documented as primary (§6.2).
- Adversarial suite: PR1 touches `src/alfred/security/` (the observability module + the boot import),
  so the full adversarial suite runs.

## 10. Risks / open items

- **orb.local × internal:true** is mechanistically expected but undocumented for that case — one
  empirical check gates documenting it as primary (tunnel is the guaranteed fallback). Non-blocking:
  neither B's nor C's *security posture* depends on the answer, only click-count.
- **PRD §7.5 "default Grafana bundle"** interpretation (§6.2) — if read as "running by default,"
  fall back to internal-only default-on, never the second bridge; that reinterpretation is
  human-gated.
- `test_only_gateway_on_external` is a live tripwire in PR2 — all three new/opt-in services must be
  placed on `alfred_internal` explicitly; do not "fix" a Grafana-reachability problem by joining
  `alfred_external`.

## 11. Out of scope

- Alertmanager + real external paging (§8 — separate issue + ADR-0053).
- The core→proxy per-caller authentication (#358 — residual (iv), independent).
- Any new core metric or label (the leak-guard pins the current reviewed set; adding one is a
  deliberate, reviewed act).
- Editing PRD.md / CLAUDE.md (human-gated).

## 12. References

- Issue #470; #479 (notification-egress follow-up, §8); related #455 (respawn), #469 (first-run),
  #358 (core→proxy auth), #340 PR2b-golive.
- `docs/adr/0040-connectivity-free-core-mandatory-egress-chokepoint.md` (Decision 1; residual (iv)).
- `docs/adr/0042-connectivity-free-core-cutover.md` (macOS/OrbStack host-port loss).
- `src/alfred/gateway/metrics_server.py`, `src/alfred/security/observability.py`,
  `src/alfred/comms_mcp/observability.py`, `src/alfred/supervisor/observability.py`,
  `src/alfred/plugins/_observability.py`, `src/alfred/cli/daemon/_comms_boot.py:62`.
- `ops/prometheus/prometheus.yml`, `ops/alerts/quarantine.yml`, `ops/alerts/gateway.yml`,
  `ops/grafana/gateway.json`, `docs/runbooks/quarantine-capability-revoked.md`.
- `tests/unit/test_compose_invariants.py` (`test_only_gateway_on_external`,
  `test_egress_proxy_port_never_host_published`, `test_alfred_gateway_publishes_no_host_port`).
