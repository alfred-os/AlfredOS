# #470 — core `/metrics` scrapeable + bundled observability stack (design)

**Status:** rev.3 (2026-07-21) — rev.1 reviewed and planned; **rev.2** folds the PR #480 (PR1) review
wave: the value-boundedness claim corrected to what the leak-guard actually proves (§5.2), the
`ALFRED_CORE_METRICS_PORT` contract declared fixed (§5.5/§6.1), the Grafana password default
corrected from a literal placeholder to an empty `:-` arm (§6.2), the shim-vs-delete outcome recorded
(§5.1), and the ADR-0040 amendment split PR1/PR2 by when each fact goes live (§7 — the PR1 half is
**landed**). **rev.3** folds the PR #480 CodeRabbit cloud review — see §14: the Grafana
"empty fails closed" claim is empirically false and is replaced by an entrypoint preflight guard
(§6.2a), the promoted fetch-helper name/signature is aligned to the shipped
`fetch_metrics_text(port)` (§5.1), and the dashboards mount is aligned to the dedicated
`ops/grafana/dashboards` subdir (§6.2). On branch
`470-core-metrics-observability-design` off main `1f94bfef`. rev.1 folds a **9-lane coordinated
plan-review** (architect / reviewer / test / security / devops / core / docs / i18n / devex +
coordinator): 0 Critical, no design-killers; the load-bearing security + core decisions were
independently verified sound. The review's High/Medium findings are folded below — see §13 (fold
log), which **overrides section bodies where they conflict**. Doc-only artifact; no code yet.
Editing PRD/CLAUDE.md is human-gated (§11); the ADR named in §8 (ADR-0053) belongs to the
**separate** #479, and the ADR named in §7 (an ADR-0040 amendment) belongs to **this** work and is
reviewer-gated, not human-gated.

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

Make the core metrics **scrapeable** and bundle an **internal-only** monitoring stack (Prometheus +
Grafana) so the `QuarantineCapabilityRevoked` rule evaluates against a live, firing, queryable series
— satisfying the security lane's "alertable" precondition — without opening any new external egress
from the connectivity-free core.

## 2. Scope & decomposition

This design covers **#470 = two PRs + an ADR**:

- **PR1 — core `/metrics` endpoint + its failure-observability wiring** (§5). The security-weighted
  core change. **Not "code-only":** it includes the minimal `docker-compose.yaml` touch that keeps
  its own loud-and-continue bind failure from being *silent* — the core `healthcheck:` block + the
  `ALFRED_CORE_METRICS_PORT` env (rev.1 fold of review finding **rev-001**: the HARD-rule-7
  silent-bind-failure window must not straddle the PR1→PR2 interval). The bulk of compose (the
  Prometheus/Grafana services) stays in PR2.
- **PR2 — bundle Prometheus + Grafana + rules + operator docs** (§6). Ops/compose change.
- **ADR (this work, §7)** — an **ADR-0040 amendment** recording #470's own invariant-touching
  decisions (rev.1 fold of **arch-002**, confirmed by security + devops). Reviewer-gated. Lands
  with PR2 (or ahead of it).

The **real external paging** (Alertmanager + notification egress to Slack/webhook) is carved into a
**separate new issue #479** (§8) — it opens the *first non-provider external egress in the
connectivity-free core's history* and needs its own ADR (**0053**) + security sign-off. That issue
overlaps #469 (first-run experience).

**"Alertable" precondition — met by #470, with a recorded interim residual.** The
`ops/alerts/quarantine.yml` header made "shipping the real child without #455-respawn conditional on
*this alert existing*." #470 makes the rule evaluate against a live, firing, queryable series
(Prometheus `/alerts` UI + API). **Interim residual (rev.1 fold of the confirmed coverage gap
arch-005):** until #479 ships *push/notification* — and until an operator actually has a path to
reach Prometheus (§6.5) — a *firing-but-unrouted* alert on the **sole durable signal** for the #472
cancel-path revoke of an already-live child is weaker than "alertable" fully implies. Record this
explicitly (§10); it is the reason #479 is a scheduled fast-follow, not optional.

## 3. Verified current-state anchors (confirmed vs tree `1f94bfef`, 2026-07-21)

- **No core `/metrics`.** `start_metrics_server` (then `src/alfred/gateway/metrics_server.py:44` —
  PR1 promoted it to `src/alfred/observability/metrics_server.py` and deleted the gateway module) is
  called only from `alfred gateway start` (`src/alfred/cli/gateway/_commands.py:290`). The daemon
  (`alfred daemon start`) serves nothing.
- **No Prometheus in compose.** `docker-compose.yaml` services are postgres, redis, core, gateway.
  `ops/prometheus/prometheus.yml` is a scaffold: single `alfred-gateway:9464` job; `rule_files`
  lists only `gateway.yml` (not `quarantine.yml`).
- **The counter is real on every revoke path.** `CAPABILITY_REVOKED_COUNTER` is *defined* at
  `src/alfred/security/observability.py:47` and `.inc()`-ed at
  `src/alfred/security/quarantine_transport.py:623` (rev.1 fold of **sec-001** line-cite fix) before
  teardown on every revoke path — **including the cancel-path revoke (#472) that writes no
  `egress.broker.refused` audit row.** So the metric is the *only* durable signal for that revoke
  class: landing #470 is security-additive, not merely ops hygiene.
- **The core has no container healthcheck.** Only postgres/redis/gateway define one. **Nothing has
  `depends_on: alfred-core: condition: service_healthy`** — so a core-unhealthy state is observable
  but does not wedge the stack (load-bearing for §5.4's plane-scope decision).
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
cannot break `internal:true`. No `test_compose_invariants.py` ratchet is tripped. *Security- and
core-lane verdicts: CONFIRMED.* Because future work will cite this Decision-1 class-line, it is
recorded durably in the ADR-0040 amendment (§7), not only here (rev.1 fold of **arch-002**).

## 5. PR1 — core `/metrics` endpoint + failure-observability wiring

### 5.1 Shared observability module

Promote out of `alfred/gateway/` into a neutral shared module `alfred/observability/`:

- `metrics_server.py` — `resolve_metrics_port(env_var: str, default: int) -> int` (parameterized;
  gateway keeps `ALFRED_GATEWAY_METRICS_PORT`, core reads `ALFRED_CORE_METRICS_PORT`) and
  `start_metrics_server(port: int, registry: CollectorRegistry | None = None) -> bool` (**rev.1 fold
  of core-003**: `start_metrics_server` gains the `registry` param, not just `resolve_metrics_port`;
  `None` → default registry, preserving gateway behaviour). Also promote the gateway's private
  `_fetch_metrics_text` here as the public helper **`fetch_metrics_text(port: int) -> str`**
  (**rev.1 fold of core-004**: the core healthcheck is its *third* consumer — DRY-reuse the
  `http.client` loopback GET, do not re-mirror it).
  **rev.3 (PR #480 CR):** the promoted helper takes **`port` only** — the destination host is the
  module constant `_LOOPBACK_HOST = "127.0.0.1"`, deliberately *not* a parameter, so the no-SSRF
  property is structural rather than a per-call-site convention (the sec-001 fold applied during PR1
  implementation). Earlier drafts of this section and of the PR1 plan wrote `_fetch_metrics_text(host,
  port)`; the shipped signature in `src/alfred/observability/metrics_server.py` is
  `fetch_metrics_text(port)`, and every consumer (`cli/daemon/_healthcheck.py`,
  `cli/gateway/_commands.py`, `cli/gateway/_egress.py`) calls it that way.
The old `src/alfred/gateway/metrics_server.py` is **deleted, not left as a re-export shim** (rev.2):
`resolve_metrics_port` took **no** arguments pre-#470, so re-exporting the new two-argument resolver
under the old path would have been a *breaking* change wearing a back-compat label — every importer
had to be migrated anyway.

- Gateway call sites update to pass their env-var/default: `cli/gateway/_egress.py` (×1),
  `cli/gateway/_commands.py` (×2 — the `start_metrics_server(resolve_metrics_port())` at :290 and
  the healthcheck resolve at :546).

### 5.2 One `CORE_OWNED_COLLECTORS` source of truth + curated registry

**rev.1 fold of core-002 (CONFIRMED, the pool's most actionable defect) + arch-003/test-003/rev-003
(oracle independence).** The core-owned metrics span **four** modules; a single tuple is the source
of truth for *both* registration and the leak-guard test, so they cannot drift and no family is
silently dropped:

`alfred/observability/core_metrics.py`:

```python
from alfred.comms_mcp.observability import (
    BURST_LIMITER_WAIT_HISTOGRAM, HANDLER_FAILURES_COUNTER,
    INBOUND_DISPATCH_HISTOGRAM, QUARANTINED_EXTRACT_HISTOGRAM,
)
from alfred.plugins._observability import (
    DISPATCH_DURATION, INBOUND_SCANNER_SCAN_DURATION,
    OUTBOUND_DLP_SCAN_DURATION, PLUGIN_SPAWN_DURATION,
)
from alfred.security.observability import CAPABILITY_REVOKED_COUNTER
from alfred.supervisor.observability import ACTION_DURATION_HISTOGRAM

# The exact set the core /metrics exposes. Importing this module registers all
# ten on the default registry at import (so build_core_registry has live refs AND
# the counter reads 0 from t=0 — resolves the §5.5 "only 1 of 4 modules imported" bug).
CORE_OWNED_COLLECTORS: tuple[Collector, ...] = (
    CAPABILITY_REVOKED_COUNTER, INBOUND_DISPATCH_HISTOGRAM,
    QUARANTINED_EXTRACT_HISTOGRAM, BURST_LIMITER_WAIT_HISTOGRAM,
    HANDLER_FAILURES_COUNTER, ACTION_DURATION_HISTOGRAM,
    DISPATCH_DURATION, OUTBOUND_DLP_SCAN_DURATION,
    INBOUND_SCANNER_SCAN_DURATION, PLUGIN_SPAWN_DURATION,
)

def build_core_registry() -> CollectorRegistry:
    reg = CollectorRegistry()
    for c in CORE_OWNED_COLLECTORS:
        reg.register(c)   # a collector may live in multiple registries
    return reg
```

The collectors **stay constructed on the default registry** (do not move them — the
"duplicate-name regression surfaces loud at import" property in `security/observability.py` /
`gateway/metrics.py` depends on it, and the gateway process still serves them). The core simply
serves the curated registry via `start_metrics_server(port, registry=build_core_registry())`.

**Why curated is load-bearing (not hygiene):** the default registry also carries ~20 stale
`gateway_*` families pulled in by an import side-effect (`cli/daemon/_comms_boot.py:62` →
`alfred.gateway.__init__`). `ops/alerts/gateway.yml`'s `GatewayCoreUnavailable: gateway_core_link_up
== 0` has **no `{job}` selector**, so serving the default registry would match the core's
permanently-zero copy → **page continuously and falsely**. Verified real against the tree by the
security lane.

The reviewed core-owned family set (security-lane label audit — all closed-domain or bucketed, **no
leak**):

| Family (base name) | Labels | Domain |
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

**Value-boundedness invariant (rev.1 fold of sec-002; rev.2 correction).** The leak-guard (§5.3) is
a CI-time *schema* ratchet, not a runtime *value* redactor. Its safety therefore rests on an
explicit invariant that must be stated in-doc and upheld by the label audit: **no core-owned metric
attaches a free-text or otherwise-unbounded label value** — every label is `none`, a closed enum, or
a fixed-cardinality bucket. `plugin_id` (manifest-declared, human-gated-at-install, allowlist-bounded)
is the widest and is scrape-safe.

**What the guard proves, precisely.** The leak-guard pins two things and nothing more: the exact set
of exposed family **base names**, and the exact set of **declared label keys** per family. From that
it follows that a re-introduced `gateway_*` bleed fails CI, a *new* label key (`labels=["user_id"]`)
fails CI, and a family added to or dropped from `CORE_OWNED_COLLECTORS` without review fails CI. A
label-key pin **cannot** decide value-boundedness: it says nothing about what strings a call site
passes into an already-approved key.

**Residual (rev.2, un-closed by this design).** Two of the four label-emitting call sites feed labels
from **un-normalized locals**: `src/alfred/plugins/stdio_transport.py:474` (`outcome` on
`alfred_plugin_spawn_seconds`) and `:708` (`outcome` / `method_shape` on
`alfred_stdio_transport_dispatch_seconds`). Every value they pass today is a source literal (verified
against the tree) — so the invariant *holds* at the exposed surface — but there is no mechanism
keeping it true: a future `outcome = f"error:{exc}"` would ship an unbounded, potentially
content-bearing label value under an already-approved key with the leak-guard green. Contrast
`alfred.supervisor.observability.record_action_duration`, which normalises `action_outcome` /
`breaker_state` into their closed domains (with an `unknown` fallback) *inside the recorder*, so no
caller can widen them. **Normalization belongs at the recorder, not the call site** — closing this
residual means giving the two `stdio_transport` families the same closed-domain fallback (and
`bucket_plugin_id` already demonstrates the pattern for the `plugin_id` key). Out of scope for #470
(no metric or label changes, §11); until it lands, value-boundedness is a **reviewed property of the
call sites**, not a CI-enforced one.

### 5.3 Leak-guard ratchet test — BLOCKING (the DLP-equivalent for this surface)

`/metrics` is a new outbound-shaped surface that bypasses `OutboundDlp`; per HARD rule 4 a
DLP-exempt path must declare it once and have the suite verify the claim. **Two-sided, oracle-
independent** (rev.1 fold of core-002 / arch-003 / test-003 / rev-003):

1. **No leak / no stale:** scrape the curated exposition; the exposed family **base names** (the
   prometheus parser strips `_bucket`/`_sum`/`_count`/`_created`/`le` — **rev.1 fold of test-004**:
   assert on parsed family names + label keys, which reconciles "pin exact set" with the histogram
   suffix expansion) contain **no** `gateway_*` and no label key outside the reviewed allowlist
   (§5.2). Catches a re-introduced `gateway_*` bleed or a new `labels=["user_id"]`.
2. **No silent under-include:** the *expected* family set is a **hardcoded literal** in the test
   (independently authored — the tautological-oracle anti-pattern is that the test derives its
   oracle from `CORE_OWNED_COLLECTORS` itself). A third assertion cross-checks that
   `CORE_OWNED_COLLECTORS` *names* equal that literal, so adding a collector without updating the
   reviewed literal fails loud, and a `CORE_OWNED_COLLECTORS` that under-lists a live core metric
   also fails. The test **exercises the production `build_core_registry()`**, not a re-built copy.

Pin exact family + label-key sets (not `contains`/subset). **Must land in PR1 and be green before
anything scrapes the endpoint.** The builder + guard are security-critical: place them so the
per-module 100%-line+branch coverage gate binds them (rev.1 fold of **test-006** — add
`src/alfred/observability/` to the per-module 100%-coverage set even though it is not under
`src/alfred/security/`).

### 5.4 Daemon boot wiring, healthcheck, and counter-at-zero

**Boot wiring (rev.1 fold of core-001):** call `start_metrics_server(resolve_metrics_port("ALFRED_CORE_METRICS_PORT",
9465), registry=build_core_registry())` in the daemon boot body **before** the `Supervisor`
TaskGroup starts, mirroring the gateway's pre-relay call site (`cli/gateway/_commands.py:288-290`).
`start_http_server` spawns a **detached daemon thread** binding a real socket — it is invisible to
(and so harmless for) the #472 cancellation-safe teardown, but the call **must be a monkeypatchable
seam** so the many boot-wiring unit tests (which invoke the boot body per-test in one process) can
stub it and not leak threads/sockets. Importing `alfred.observability.core_metrics` at boot (for
`build_core_registry`) registers all ten families on the default registry, so
`alfred_quarantine_capability_revoked_total` — and the other nine — read **0 from t=0**, not only
after first use (this is why §5.2 imports all four modules; the earlier "import only
`security.observability`" was the core-002 bug).

**Healthcheck (rev.1 fold of core-004 + devex-004 + i18n-001):** add `alfred daemon healthcheck`,
DRY-reusing the promoted `fetch_metrics_text(port)` to probe `127.0.0.1:$ALFRED_CORE_METRICS_PORT/metrics`
over loopback; exit 0/1, never a traceback (mirrors `healthcheck_gateway`). **Scope it explicitly as
*metrics-endpoint liveness*, not full data-plane readiness** (devex-004): a metrics-bind failure →
`unhealthy` with a **distinct operator message** (`daemon.healthcheck.metrics_unreachable`) that
says the metrics endpoint is unreachable and the data plane may still be serving; a richer OODA-loop
readiness probe is out of scope (future). Because nothing `depends_on` core health (§3), `unhealthy`
is observational — it makes the loud-and-continue bind failure *visible* (HARD rule 7) without
wedging the stack. All operator-facing strings go through `t()` with new `daemon.healthcheck.*`
catalog keys (mirroring `gateway.healthcheck.*`: key-as-msgid + kwargs, no f-string interpolation);
`metrics.bind_failed` stays a structlog event key (NOT `t()` scope).

### 5.5 Port pin + minimal compose wiring (in PR1)

New `ALFRED_CORE_METRICS_PORT` (default **9465** — distinct from the gateway's 9464 for scrape-config
clarity; compose-internal, **never host-published**).

**Port contract — 9465 is FIXED for the bundled stack (rev.2, resolving the two-place-edit trap).**
Prometheus cannot env-expand a `static_configs` target, so the bundled scrape config carries the
literal `alfred-core:9465`. Rather than leave two places that must be edited in lockstep, the
decision is: **`ALFRED_CORE_METRICS_PORT` is a bind-port seam, not a supported operator knob.** It
exists so the daemon and `alfred daemon healthcheck` resolve the same port from one place, and so a
test can bind an ephemeral port — exactly the status of the gateway's `ALFRED_GATEWAY_METRICS_PORT`
against its likewise-hardcoded `alfred-gateway:9464`. Overriding it in `docker-compose.yaml` without
also editing `ops/prometheus/prometheus.yml` silently breaks scraping, and no validation catches
that; do not document it as a tunable. If a future need makes the port genuinely operator-tunable,
the rendered scrape config must be generated from the resolved value with a startup validation and a
non-default-port test — a design change, not a config change. `docker-compose.yaml`, this spec, and
both plans state this identically.

PR1's compose touch (rev.1 fold of rev-001):
add the `ALFRED_CORE_METRICS_PORT` env + the `healthcheck:` block (`["CMD","alfred","daemon","healthcheck"]`)
to the `alfred-core` service, and a compose-invariant test that no service host-publishes the core
metrics container port (mirror `test_egress_proxy_port_never_host_published`). This closes the
HARD-7 window *within PR1*; the Prometheus/Grafana services + alert rules remain PR2.

## 6. PR2 — bundle Prometheus + Grafana (internal-only) + rules + docs

Both services join `alfred_internal` **only** — `test_only_gateway_on_external` already forbids
`alfred_external`, and this design *strengthens* that into a positive "observability components are
egress-incapable" pin (§6.3).

### 6.1 Prometheus + the alert-rule wiring

- `image: prom/prometheus:<pin exact tag in PR2>`; `restart: unless-stopped`; `networks:
  [alfred_internal]`; no `ports:`.
- Command: `--config.file`, `--storage.tsdb.path=/prometheus`, `--storage.tsdb.retention.time=15d`,
  `--web.listen-address=0.0.0.0:9090`. **No** `--web.enable-admin-api`, **no** `--web.enable-lifecycle`,
  **no** `remote_write`.
- Volumes: `alfred_prom_data:/prometheus`; config + rules mounted **read-only**.
- Healthcheck realism (rev.1 fold of devops-006 + §6.3): the Prometheus/Grafana images may lack a
  shell/curl — use each image's own probe path (Prometheus `/-/healthy`, Grafana `/api/health`) via
  its own binary, or omit the healthcheck; **do not ship a broken curl-based healthcheck.** Pin the
  exact probe command in PR2.
- `ops/prometheus/prometheus.yml` gains the `alfred-core → ["alfred-core:9465"]` scrape job — a
  **literal**, per the port contract below — and `quarantine.yml` in `rule_files`.
- **New alert rules live in a named `rule_file`, not inline** (rev.1 fold of arch-004/devops-003/test-002):
  add `up{job="alfred-core"} == 0` (target-down) and `absent(alfred_quarantine_capability_revoked_total)`
  to a rule file (e.g. extend `quarantine.yml` or a new `core.yml`), with **promtool unit tests**
  (positive + negative controls, mirroring `quarantine_test.yml`) and `ci.yml` wiring. **Extend the
  existing "no silently-dead alerts" cross-check** (currently gateway-only) to validate the core
  `alfred_*` alerts too.

### 6.2 Grafana — default-on, internal-only, zero egress

**Access decision (all three lanes: reject the second-bridge option).** A non-`internal:true` bridge
would grant Grafana a standing internet NAT route — a second, non-gateway egress plane on the
stack's highest-CVE-surface component (its data-source proxy is a built-in SSRF primitive) — a
direct ADR-0040 regression the app-level hardening flags cannot remove. Grafana stays
`alfred_internal`-only, **zero egress, no notifier secret** (paging is #479's Alertmanager).

**Default-on, NOT profile-gated (rev.1 fold of arch-001).** PRD §4 MVP release-gate criterion 9
requires the *default* deployment's Grafana dashboard to **show** the running system; profile-gating
Grafana off-by-default would be an MVP-scope reduction. So Grafana runs in the default stack
(internal-only, zero egress, hardened, auth-on). Profile-gating for a smaller default surface was
the security lane's stated preference; it is **deferred as a human-gated PRD-interpretation
open-item** (§10) — *never* resolved by giving Grafana an egress bridge. (This also dissolves the
devops-001/devex-002/003 cluster: a default dashboard the operator can actually see.)

- `image: grafana/grafana:<pin exact tag in PR2>`; `networks: [alfred_internal]`.
- **Password (rev.1 fold of devops-001 — the High that empirically aborts default `up`; rev.2
  security correction):** `GF_SECURITY_ADMIN_PASSWORD: ${GF_SECURITY_ADMIN_PASSWORD:-}` using `:-`
  (**never** `:?` — Compose evaluates `${VAR:?}` before profile/onerror filtering and aborts every
  `docker compose` invocation). The default arm is **empty**, never a literal placeholder: Compose
  substitutes the placeholder *verbatim*, so a `:-<generated>`-style default would start Grafana with
  a predictable, repo-published admin credential on any `docker compose up` that skipped the setup
  script.
  **rev.3 (PR #480 CR, Major/security — the rev.2 claim was empirically FALSE):** "empty fails
  closed" is not how Grafana behaves. Verified against `grafana/grafana:11.6.0` on 2026-07-21:
  Grafana's env-override applies a value only when it is non-empty, so an **empty**
  `GF_SECURITY_ADMIN_PASSWORD` is *ignored* and `conf/defaults.ini`'s `admin_password = admin` wins.
  (The observed behaviour is what was measured; the override rule is the inference that explains it.)
  The container starts, `/api/health` answers 200, and `curl -u admin:admin /api/org` returns **200**.
  So the `:-` empty arm alone leaves an operator who runs `docker compose up` *without* running
  `bin/alfred-setup.sh` with a Grafana on the best-known default credential in existence. The `:-`
  form still **must** stay (see the constraint above — `:?` aborts every `docker compose` invocation,
  including `down`/`ps`/`config`, because Compose interpolates before profile filtering), and the
  setup-script seed still stays; what was missing is a **third, fail-closed layer inside the service
  itself** — see §6.2a.
  `bin/alfred-setup.sh` generates a random admin password into `.env` on first run (mirroring the
  `audit.hash_pepper` seed) and `.env.example` ships the key **present but empty**. Because first-run
  does `cp .env.example .env`, the seed guard must key on **present-and-non-empty** and *replace* the
  empty line in place — an "append if absent" guard never fires and leaves the password empty.
  **Required regression test** (the guard is easy to get subtly wrong and its failure mode is a
  silent weak credential): cover all three cases against a temp `.env` — an existing *empty* value is
  replaced with a generated one, an existing *non-empty* value is preserved unchanged, and no
  duplicate `GF_SECURITY_ADMIN_PASSWORD=` key is ever produced.
- Hardening (defense-in-depth on top of zero egress): `GF_ANALYTICS_REPORTING_ENABLED=false`,
  `GF_ANALYTICS_CHECK_FOR_UPDATES=false`, `GF_ANALYTICS_CHECK_FOR_PLUGIN_UPDATES=false`,
  `GF_AUTH_ANONYMOUS_ENABLED=false`, `GF_USERS_ALLOW_SIGN_UP=false`, `GF_INSTALL_PLUGINS=""`,
  `GF_SNAPSHOTS_EXTERNAL_ENABLED=false`, `GF_SECURITY_DISABLE_GRAVATAR=true`.
- Volumes (**rev.3 (PR #480 CR)** — aligned to the plan's devops-006 layout; this bullet still
  described mounting all of `ops/grafana`, which would nest `provisioning/` *inside* the dashboards
  provider path and make Grafana try to load its own provisioning YAML as dashboard JSON):
  `alfred_grafana_data:/var/lib/grafana`; `./ops/grafana/provisioning:/etc/grafana/provisioning:ro`
  (datasource → `http://alfred-prometheus:9090`); and a **dedicated dashboards subdir**
  `./ops/grafana/dashboards:/var/lib/grafana/dashboards:ro` — `ops/grafana/dashboards/*.json`, never
  `ops/grafana/*.json`. The pre-existing `ops/grafana/gateway.json` is `git mv`-ed into that subdir
  so the narrower mount still serves it.
- **Host access (documented in §6.5, zero egress on every platform):** Linux → `ports:
  ["127.0.0.1:3000:3000"]` (works on internal-only per the postgres precedent); OrbStack →
  `alfred-grafana.<project>.orb.local` (inbound unified-bridge path, distinct from the broken
  outbound port-forward — **PR2 smoke-task verifies it empirically**, §9); Docker Desktop →
  documented ambassador-tunnel container.

### 6.2a Grafana credential fail-closed layer (rev.3 — PR #480 CR Major/security)

The credential story is **three layers**, and only the third holds when the operator skips setup:

1. `.env.example` ships the key present-but-empty; `bin/alfred-setup.sh` seeds a random value with a
   present-and-non-empty grep-guard that *replaces* the empty line (§6.2).
2. Compose reads it with `:-` (never `:?`), so no `docker compose` verb aborts.
3. **A service-level preflight guard that refuses to start Grafana on a guessable credential.**

Layer 3 is a shell preflight in front of the image's `/run.sh` entrypoint: if
`GF_SECURITY_ADMIN_PASSWORD` is unset, empty, or the literal `admin`, print an actionable refusal to
stderr and `exit 78` (`EX_CONFIG`) instead of `exec`-ing Grafana. It is expressed inline in
`docker-compose.yaml`'s `entrypoint:` so there is no extra file to keep in sync and no image rebuild.

**Why this and not `:?`.** `${VAR:?}` makes *Compose* fail, and Compose interpolates the whole file
before any profile/service filtering — so `docker compose down`, `ps`, `config`, `logs`, and
`up alfred-core` all abort on an unrelated missing Grafana password. That is a stack-wide denial of
service to punish one optional service's misconfiguration. The entrypoint guard fails **exactly one
container**, at container start, with a message the operator actually reads in
`docker compose logs alfred-grafana`; every other service comes up normally. A future reader tempted
to "simplify" this back to `:?` should read this paragraph and the constraint in §6.2 first.

**Empirically verified 2026-07-21** against `grafana/grafana:11.6.0` (all three arms, real containers):

- empty password, no guard → container **starts**, `/api/health` 200, `admin:admin` → **200** (the
  hazard);
- empty password, guard → `docker compose config` clean; container exits **78** with the refusal on
  stderr; sibling services unaffected;
- real password, guard → Grafana boots normally, `/api/health` 200, `admin:admin` → **401**, real
  credential → 200.

The refusal is terminal in practice: changing `.env` requires `docker compose up -d` to recreate the
container anyway, so `restart: unless-stopped` re-running the guard is a loud repeat of the same
message, not a self-heal path.

### 6.3 Compose-invariant tests

- Core metrics port never host-published (§5.5, in PR1); the observability components
  (`alfred-prometheus`, `alfred-grafana`) join `alfred_internal` **only** (positive egress-incapable
  pin; keeps `test_only_gateway_on_external == {alfred-gateway}` intact); Grafana's published port
  binds `127.0.0.1`, never `0.0.0.0`; `alfred-core` defines a `healthcheck`; Prometheus command
  contains neither `--web.enable-admin-api` nor `--web.enable-lifecycle`; `GF_SECURITY_ADMIN_PASSWORD`
  uses `:-` (not `:?`) and is env-sourced.
- **rev.3:** the §6.2a guard needs *both* a compose-shape assertion **and** a real-execution test. A
  lexical assertion over the `entrypoint:` string cannot decide whether Grafana actually refuses —
  that is a runtime fact about a third-party binary. The runtime test's non-vacuity control is the
  `admin:admin` → 401 arm on the *pass* path: it proves the assertion is about Grafana's real auth
  state, not about our own predicate. The runtime test must read the entrypoint **out of
  `docker-compose.yaml`**, never re-declare it, or the two drift and the shipped guard goes untested.

### 6.4 Caveat reframe (rev.1 rewrite — folds docs-003/docs-004/sec-003)

Landing #470 falsifies **every** "armed, not live / nothing scrapes the core" reference — enumerate
and update them all, not just one block:

- `src/alfred/security/observability.py` — the `.. warning:: Armed, not yet live` block.
- `ops/alerts/quarantine.yml` — the `ARMED, NOT YET LIVE` header.
- `docs/runbooks/quarantine-capability-revoked.md` — the `⚠ Read first: the alert cannot fire yet`
  block **and** the `Related`-`#470` entry, the `un-scrapeable, #470` parenthetical embedded in the
  audit section, and the "Detecting it today / Both work without Prometheus" framing.

**Corrected rationale (sec-003/docs-004 — same defect, two lenses):** do **not** say "keep the audit
path because it is complementary." Say: **the metric is now the *sole durable signal* for the
cancel-path revoke class (#472 writes no `egress.broker.refused` row on that path); the audit-log
detection path remains as an *additive* cross-check for the other revoke classes.** Retain the
audit-path guidance under that corrected framing; do not propagate the inverted rationale into the
security runbook.

### 6.5 Operator observability doc + doc-drift (rev.1 fold of docs-001/docs-002/devex-001)

- New operator doc (`docs/runbooks/observability-stack.md` or similar): how to reach Grafana per
  platform (Linux loopback / OrbStack `*.orb.local` / Docker-Desktop tunnel), how to reach Prometheus
  (via Grafana datasource; direct access for debugging), what the bundled dashboards show, and the
  `GF_SECURITY_ADMIN_PASSWORD` first-run note.
- Update `README.md` quickstart (Prometheus/Grafana are now default services).
- **Human-gated (flag, do not self-apply, §11):** the CLAUDE.md command-table entry for `alfred
  daemon healthcheck` (a net-new CLI surface) — schedule it as a flagged follow-up, not buried under
  "out of scope."

## 7. ADR-0040 amendment (this work — rev.1 fold of arch-002)

Add an **ADR-0040 amendment** (reviewer-gated; ADRs are *not* human-gated like PRD/CLAUDE.md)
recording #470's own invariant-touching decisions, which future work will cite. **Split across the
two PRs by when each fact goes live (rev.2 fold of arch-001)** — an amendment that lands entirely in
PR2 would leave `main` carrying a new listener class whose only rationale is a draft spec, for the
whole PR1→PR2 interval:

**Lands in PR1 (both facts are true the moment PR1 merges) — DONE:**

- The **inbound-listener-vs-external-socket** interpretation of Decision 1 (§4) — that an inbound
  `/metrics` listener on `alfred_internal` is not the "external socket" the invariant forbids.
  Landed as a class-line paragraph under ADR-0040 Decision 1.
- The new **accepted residual**: the core `/metrics` is unauthenticated plaintext HTTP readable by
  any `alfred_internal` peer; per the §5.2 label audit it carries only bounded operational aggregates
  (no T3/PII/secret). Landed as ADR-0040 residual **(viii)**, carrying the §5.2 value-boundedness
  residual as an explicit edge.

**Deferred to PR2 (only true once PR2 introduces the services):**

- The **two new third-party services + a Prometheus TSDB** attached to the connectivity-free stack
  (the CLAUDE.md "no new datastore/third-party service without an ADR" line; PRD §7.5/§9 pre-name the
  tools but not their post-Spec-C stack-attachment). PR1 attaches no third-party service.

(A dedicated ADR-0054 is the alternative if the amendment grows too large; the amendment is preferred
— the residual panel already accretes here.)

### Security conditions summary (folded from the security lanes)

1. Curated registry (§5.2) — closes the `GatewayCoreUnavailable` false-page; bounds the surface.
2. Two-sided, oracle-independent leak-guard (§5.3) — BLOCKING; lands + green in PR1 before any scrape;
   100%-coverage-gated (test-006).
3. Value-boundedness invariant (§5.2) — no free-text/unbounded labels. **The label-key pin does not
   enforce this** (it pins keys, not values); it is a reviewed property of the call sites, with the
   two un-normalized `stdio_transport` sites recorded as an open residual in §5.2.
4. Core healthcheck probing `/metrics` (§5.4) — makes loud-and-continue non-silent (HARD rule 7),
   scoped to metrics-endpoint liveness.
5. Counter (and all ten families) exposed at 0 from t=0 (§5.4) + `up==0` + `absent()` alerts (§6.1).
6. Core metrics port + observability components internal-only, never host-published (§5.5/§6.3).
7. #470 opens **no** egress (verified); the ADR-0040 amendment records the residual (§7).

## 8. Handoff — the separate notification-egress issue #479 (NOT this design)

Issue #479 (filed 2026-07-21) delivers real external paging. Pre-vetted shape (boundary is clean):
**Alertmanager** (not Grafana-managed alerting — rules stay as promtool-tested `rule_files`);
notification egress through a **dedicated `plane="notifier"` gateway L7-proxy instance with a
notifier-scoped, exact-match allowlist** (e.g. `hooks.slack.com:443`) — **not** the shared provider
`:8889` allowlist; **ADR-0053** + security sign-off; receiver secret on the notifier, off the
gateway. Webhook/Slack HTTPS POST (SMTP can't route through an HTTPS proxy).

## 9. Testing strategy

- **PR1 (unit):** the two-sided oracle-independent leak-guard (§5.3), exercising production
  `build_core_registry()`; `CORE_OWNED_COLLECTORS`-names == reviewed literal; the endpoint serves
  the curated registry and omits `gateway_*`; `resolve_metrics_port(env_var, default)` env parsing;
  the `start_metrics_server(registry=...)` param; the **`alfred daemon healthcheck` happy/error/
  refusal trio** (rev.1 fold of test-001 — mirror `test_gateway_healthcheck.py`); the boot wiring is
  a monkeypatchable seam (no thread/socket leak across tests, core-001); the core-metrics-port
  never-published compose-invariant test. 100%-coverage on `src/alfred/observability/` + the
  `src/alfred/security/` touch; adversarial suite runs (PR1 edits `security/observability.py` +
  the boot import).
- **PR2 (unit + integration/smoke):** the new compose-invariant tests (§6.3); **promtool unit tests**
  for the `up==0`/`absent()` rules (positive + negative controls) + `ci.yml` wiring (rev.1 fold of
  test-002/devops-003); the "no silently-dead alerts" cross-check extended to core `alfred_*` alerts;
  an **end-to-end scrape-precondition test** (rev.1 fold of devops-002/test-002 — Prometheus loads
  the config, `up{job="alfred-core"} == 1`, and the quarantine rule is live in `/api/v1/rules`) so a
  typo'd scrape target fails loud instead of shipping green; the i18n pybabel `extract/update/compile`
  drift-gate (rev.1 fold of i18n-001); the OrbStack `*.orb.local` empirical smoke-task with a
  concrete hostname/command/pass-criteria (rev.1 fold of devops-008/test-005 — documented as a
  manual macOS check, NOT a Linux-CI `tests/smoke/` gate, to avoid a paper-gate).
- **Any PR touching `src/alfred/security/`** (§6.4 edits `security/observability.py`) inherits the
  adversarial-suite + 100%-coverage obligation regardless of PR number (rev.1 fold of sec-004/rev-002).

## 10. Risks / open items

- **PRD §4 MVP criterion 9 vs profile-gating (arch-001, human-gated).** rev.1 defaults Grafana to
  running-in-the-default-stack (internal-only, zero egress) to satisfy "the default dashboard
  *shows*…". If a human confirms profile-gating is acceptable under §4, it may be re-gated (never via
  an egress bridge). This is a PRD-interpretation decision, human-gated.
- **Interim "alertable" residual (arch-005, security-endorsed).** Until #479 ships push/notification
  and an operator has a Prometheus access path (§6.5), the firing alert on the #472 cancel-path
  sole-signal is pull-only and unrouted — record it as an explicit interim residual; it is why #479
  is a scheduled fast-follow.
- **Core healthcheck plane-scope (devex-004, resolved).** Scoped to metrics-endpoint liveness, not
  data-plane readiness; a wedged-but-serving core can read healthy — a richer readiness probe is
  future work, noted so it is not mistaken for a data-plane guarantee.
- **orb.local × internal:true** mechanistically expected but undocumented for that case — the PR2
  smoke-task gates documenting it as primary (tunnel is the guaranteed fallback).
- `test_only_gateway_on_external` is a live tripwire in PR2 — place all new services on
  `alfred_internal` explicitly; never "fix" a Grafana-reachability problem by joining `alfred_external`.

## 11. Out of scope

- Alertmanager + real external paging (§8 — #479 + ADR-0053).
- The core→proxy per-caller authentication (#358 — residual (iv), independent).
- A data-plane / OODA-loop readiness probe (§5.4 healthcheck is metrics-endpoint liveness only).
- Any new core metric or label (the leak-guard pins the reviewed set; adding one is a deliberate,
  reviewed act subject to the value-boundedness invariant).
- **Editing PRD.md / CLAUDE.md (human-gated)** — incl. the CLAUDE.md command-table entry for `alfred
  daemon healthcheck` (§6.5) and any PRD §4/§7.5 clarification (§10). Flag; do not self-apply.

## 12. References

- Issue #470; #479 (notification-egress follow-up, §8); related #455 (respawn), #469 (first-run),
  #358 (core→proxy auth), #340 PR2b-golive.
- 9-lane review findings: `~/.cache/alfred-os/review-plan/2026-07-21-470-core-metrics-observability-design/`.
- `docs/adr/0040-connectivity-free-core-mandatory-egress-chokepoint.md` (Decision 1; residual panel —
  the §7 amendment target); `docs/adr/0042-connectivity-free-core-cutover.md` (macOS/OrbStack host-port loss).
- `src/alfred/observability/metrics_server.py` (PR1's promotion target; the former
  `src/alfred/gateway/metrics_server.py` was deleted, not shimmed — see §5.1),
  `src/alfred/security/observability.py` (`:47` def) +
  `src/alfred/security/quarantine_transport.py:623` (`.inc()`), `src/alfred/comms_mcp/observability.py`,
  `src/alfred/supervisor/observability.py`, `src/alfred/plugins/_observability.py`,
  `src/alfred/cli/daemon/_comms_boot.py:62`, `src/alfred/cli/gateway/_commands.py` (whose private
  `_fetch_metrics_text` PR1 replaced with the promoted `fetch_metrics_text(port)`).
- `ops/prometheus/prometheus.yml`, `ops/alerts/quarantine.yml`, `ops/alerts/gateway.yml`
  (`GatewayCoreUnavailable`, no `{job}` selector), `ops/grafana/gateway.json`,
  `docs/runbooks/quarantine-capability-revoked.md`.
- `tests/unit/test_compose_invariants.py` (`test_only_gateway_on_external`,
  `test_egress_proxy_port_never_host_published`, `test_alfred_gateway_publishes_no_host_port`).

## 13. rev.1 fold log (overrides section bodies where they conflict)

High: **core-002** (§5.2 CORE_OWNED_COLLECTORS single source of truth) · **arch-003/test-003/rev-003**
(§5.3 oracle independence) · **rev-001** (§2/§5.5 PR1 owns its compose healthcheck) · **arch-002**
(§7 ADR-0040 amendment) · **devops-001/devex-002** (§6.2 `:-` password + setup-script gen) ·
**devops-002/test-002** (§9 e2e scrape-precondition test) · **test-001** (§9 healthcheck trio) ·
**devex-001/003/docs-002** (§6.5 operator doc) · **docs-001** (§6.5/§11 CLAUDE.md entry flagged
human-gated) · **arch-001** (§6.2 Grafana default-on per PRD §4 crit 9) · **devex-004** (§5.4
healthcheck plane-scope).
Medium: **docs-003/docs-004/sec-003** (§6.4 reframe rewrite) · **arch-004/devops-003** (§6.1 named
rule_file + promtool + ci) · **sec-004/rev-002** (§9 adversarial obligation on any security edit) ·
**sec-002** (§5.2 value-boundedness invariant) · **test-006** (§5.3 coverage gate on observability/)
· **core-001/003/004** (§5.1/§5.3/§5.4 seam + registry param + DRY fetch) · **i18n-001** (§5.4/§9
t() + pybabel) · **test-004** (§5.3 parsed-family-name assertion).
Low: image-tag pins (§6.1/§6.2) · `ALFRED_CORE_METRICS_PORT` default 9465 (§5.5) · orb.local concrete
command (§9) · **sec-001** §3 `.inc()` line-cite fix.
Confirmed gap: **arch-005** (§2/§10 interim pull-only residual). No standing disputes.

## 14. rev.3 fold log (PR #480 CodeRabbit cloud review)

- **Major/security — §6.2/§6.2a Grafana credential.** The rev.2 claim "empty fails closed — Grafana
  refuses to start without an admin password" was **falsified empirically** against
  `grafana/grafana:11.6.0`: an empty `GF_SECURITY_ADMIN_PASSWORD` is ignored by Grafana's
  env-override loop, `defaults.ini`'s `admin_password = admin` applies, and `admin:admin` authenticates
  (200). Added the §6.2a three-layer model whose third layer is an entrypoint preflight guard
  (`exit 78`, actionable stderr) plus a §6.3 test obligation (compose-shape assertion **and** a
  real-execution test with the `admin:admin`→401 non-vacuity control). `:-` stays; `:?` is
  re-documented as *not* the answer, with the reason, so it is not "fixed" back.
- **Minor/correctness — §5.1/§5.4/§12 fetch-helper name.** The design named the promoted helper
  `_fetch_metrics_text(host, port)`; the shipped surface is `fetch_metrics_text(port)` with the host
  pinned to the module constant `_LOOPBACK_HOST` (sec-001, structural no-SSRF). Aligned all three
  mentions and recorded why the host is not a parameter.
- **Major/correctness — §6.2 dashboards mount.** The Volumes bullet still said "dashboards over
  `ops/grafana/*.json`", contradicting the plan's devops-006 decision; mounting all of `ops/grafana`
  nests `provisioning/` under the dashboards provider path. Aligned to the dedicated
  `./ops/grafana/dashboards:/var/lib/grafana/dashboards:ro` subdir + the `gateway.json` `git mv`.
- **Plan-side (same review wave), recorded here for traceability:** the PR2 plan's Task 5 fixed
  `time.sleep(3)` was replaced with bounded readiness polling, and its two `httpx.get` probes gained
  explicit timeouts. See that plan's rev.3 fold log.
