# Runbook: the bundled observability stack (Prometheus + Grafana)

Since [#470](https://github.com/alfred-os/AlfredOS/issues/470) PR2, `docker compose up -d`
brings up an internal-only Prometheus (`alfred-prometheus`) and Grafana (`alfred-grafana`)
alongside `alfred-core`, `alfred-gateway`, and the datastores. Both join `alfred_internal`
only — the same kernel-isolated, `internal: true` network the connectivity-free core lives
on (ADR-0040) — so the stack opens **no** new external egress
(`test_observability_services_internal_only`, `tests/unit/test_compose_invariants.py`).
Prometheus scrapes `alfred-core:9465` and `alfred-gateway:9464`; Grafana is provisioned with
that Prometheus as its only datasource and two starter dashboards.

## Accessing Grafana

Grafana's `3000` is bound to the host loopback only (`127.0.0.1:3000:3000` in
`docker-compose.yaml`), never `0.0.0.0` — no LAN exposure by default.

- **Linux:** <http://127.0.0.1:3000>. Published ports on an `internal: true` network still
  NAT correctly on Linux (the same fact the
  [Postgres host-access note](../../README.md#macos-host-access-to-postgres-g7-3-connectivity-free-core)
  in the README documents).
- **OrbStack (macOS):** `http://alfred-grafana.<project>.orb.local`, where `<project>` is
  your Compose project name (the repo directory name unless overridden by
  `COMPOSE_PROJECT_NAME` or `docker compose -p`). OrbStack's unified network bridge gives
  the host direct DNS + routing into container networks, including `internal: true` ones,
  which is a different mechanism from the host-published-port path that fails for
  `internal: true` containers on plain Docker Desktop and (separately) on OrbStack itself
  for `alfred-postgres`'s `5432`. If `*.orb.local` does not resolve for you, fall back to
  the loopback URL or the tunnel below — either always works.
- **Docker Desktop (macOS/Windows, non-OrbStack):** the host-published-port loss that
  affects `alfred-postgres:5432` (see the README note above) affects `alfred-grafana:3000`
  the same way — `internal: true` is the reason, not anything Grafana-specific. There is no
  bundled ambassador container; bridge one yourself with any relay image attached to both
  a normal (non-internal) network and `alfred_internal`, for example:

  ```sh
  docker network ls | grep alfred_internal   # confirm the actual network name for your project
  docker run -d --name alfred-grafana-tunnel -p 127.0.0.1:3000:3000 \
    alpine/socat TCP-LISTEN:3000,fork,reuseaddr TCP:alfred-grafana:3000
  docker network connect <the-alfred_internal-network-name> alfred-grafana-tunnel
  ```

  Remove it with `docker rm -f alfred-grafana-tunnel` when done. Switching to OrbStack
  avoids the workaround entirely.

### First login

Username `admin`; password is `GF_SECURITY_ADMIN_PASSWORD` from your `.env` (see below).
`GF_USERS_ALLOW_SIGN_UP` and anonymous auth are both off — there is no self-service
account creation.

## `GF_SECURITY_ADMIN_PASSWORD` — first-run note

`.env.example` ships `GF_SECURITY_ADMIN_PASSWORD=` (present, empty).
[`bin/alfred-setup.sh`](../../bin/alfred-setup.sh) seeds a random 48-hex-character value
into `.env` on first run (`openssl rand -hex 24`) and leaves an existing non-empty value
untouched — safe to re-run. If you set `.env` by hand instead of running the setup script,
choose a strong, non-default value yourself; never leave it empty and never use the
well-known default `admin`.

**The guard does not support `GF_SECURITY_ADMIN_PASSWORD__FILE`.** Grafana's own
file-secret convention (reading the password from a path instead of an env var) is not
read by the compose-level preflight guard below — a deployment that sets only the `_FILE`
variant leaves the plain `GF_SECURITY_ADMIN_PASSWORD` unset and trips the guard, whose
message will point you at `alfred-setup.sh` even though that is not your actual gap. This
errs *closed* (it never silently admits a weak credential), and the bundled compose file
uses `.env` interpolation, not Compose secrets, so the shipped path is unaffected — this
is only a trap for an operator who adapts the compose file to a secrets-file deployment
without also adapting the guard.

### Troubleshooting: `alfred-grafana` exits 78

```
FATAL: GF_SECURITY_ADMIN_PASSWORD is unset, empty, or the well-known default 'admin'.
Grafana refuses to start rather than serve dashboards on a guessable credential.
Fix: run bin/alfred-setup.sh (seeds a random value into .env), then 'docker compose up -d alfred-grafana'.
```

This is the entrypoint preflight guard in `docker-compose.yaml` (`alfred-grafana`
service), not a crash. It fires when the resolved `GF_SECURITY_ADMIN_PASSWORD` is unset,
empty, or the literal string `admin` — the stack was started without
`bin/alfred-setup.sh`, or `.env` was edited by hand and left the value weak. Fix:

```sh
bin/alfred-setup.sh                    # seeds a strong random value into .env
docker compose up -d alfred-grafana    # or set a strong value in .env yourself, then this
```

**The rest of the stack is unaffected** — nothing `depends_on: alfred-grafana`, so
`alfred-core`, `alfred-gateway`, and `alfred-prometheus` come up and stay healthy while
Grafana sits refused. Grafana deliberately will **not** start on `admin:admin`; there is
no bypass short of setting a real password.

## Accessing Prometheus

Prometheus has no host-published port by design — it is reached two ways:

- **Through Grafana (primary).** The bundled datasource
  (`ops/grafana/provisioning/datasources/prometheus.yml`) points Grafana at
  `http://alfred-prometheus:9090` over `alfred_internal`, already selected as the default
  datasource. Use Grafana's **Explore** view for ad hoc PromQL, or the two starter
  dashboards below.
- **Directly, for debugging.** Exec into the container (it ships `wget`, used by its own
  healthcheck):

  ```sh
  docker compose exec alfred-prometheus wget -qO- \
    'http://127.0.0.1:9090/api/v1/query?query=alfred_quarantine_capability_revoked_total'
  ```

  Prometheus's own alert-rule and target-health UI is reachable the same way at
  `http://127.0.0.1:9090/alerts` and `/targets` inside the container.

## What the bundled dashboards show

Two dashboards are provisioned (`ops/grafana/dashboards/*.json`, loaded via
`ops/grafana/provisioning/dashboards/dashboards.yml`):

- **AlfredOS Gateway** (`gateway.json`) — the mature one, dating to Spec B (#288). Twelve
  panels covering the gateway's own metrics: core-link liveness, circuit-breaker state,
  replay-buffer depth and cap ratio, reconnect rate, per-adapter up/in-flight/buffer-depth,
  ingress throttling, and egress in-flight/denial-rate by plane and reason.
- **AlfredOS Core / Quarantine** (`quarantine.json`) — **be honest about its scope: this
  is a minimal 2-panel starter**, new in #470 PR2 Task 4. It shows `up{job="alfred-core"}`
  (is the core's `/metrics` endpoint being scraped) and
  `alfred_quarantine_capability_revoked_total` (the counter this whole design exists to
  make alertable). Of the ten collectors in `CORE_OWNED_COLLECTORS`
  (`src/alfred/observability/core_metrics.py`), only that one counter has a panel. The
  other nine — eight latency histograms spanning comms dispatch, quarantined extraction,
  the burst limiter, orchestrator actions, plugin dispatch, and DLP/content scanning, plus
  the `alfred_comms_handler_failures_total` counter — are registered, scraped, and
  queryable in Prometheus/Grafana Explore today, but have no dashboard panel yet. A
  follow-up will build those out; until then, query them directly.

## Fixed-port contract

`ALFRED_CORE_METRICS_PORT` (default `9465`) is a **bind-seam, not an operator-tunable
port.** It exists so the daemon and `alfred daemon healthcheck` resolve one port from one
place. `ops/prometheus/prometheus.yml` hardcodes its scrape target as the literal
`alfred-core:9465`, exactly as it already hardcodes `alfred-gateway:9464` — Prometheus
cannot env-expand a `static_configs` target. Overriding `ALFRED_CORE_METRICS_PORT` without
also editing `ops/prometheus/prometheus.yml` silently stops the scrape, with nothing to
catch the mismatch. Leave it at its default.

## Related

- [Quarantine capability-revoked runbook](quarantine-capability-revoked.md) — the primary
  consumer of this stack today; the counter is the sole durable signal for a cancel-path
  revoke.
- [docs/subsystems/security.md](../subsystems/security.md) — the quarantine transport and
  its signals.
- [#479](https://github.com/alfred-os/AlfredOS/issues/479) — real external paging
  (Alertmanager + notification egress). Until it ships, an alert firing in Prometheus is
  pull-only: nothing pages you, so an operator needs an open Grafana or Prometheus tab (or
  a periodic check) to see it.
