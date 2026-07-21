# #470 PR2 — bundle Prometheus + Grafana + rules + docs Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

> **rev.1 (2026-07-21)** — folds the 8-lane plan-review (no PR2 Critical). Fixed: the e2e testcontainers
> fixture (network alias + `ops/alerts` mount), the no-silently-dead-alerts cross-check location
> (`tests/unit/test_ops_scaffold.py`, not ci.yml), the Grafana password seed guard (present-and-non-empty),
> the caveat-reframe completeness (`docs/subsystems/security.md` + the 4th runbook target), and the
> `absent()` promtool control. See the §fold-log at the end.

**Goal:** Bundle an internal-only Prometheus (scraping the core `/metrics` PR1 exposes) + a default-on internal-only Grafana into the compose stack, wire the `quarantine.yml` rules + new `up==0`/`absent()` rules with promtool tests, reframe the "armed, not live" caveats, ship an operator observability doc, and record #470's own ADR-0040 amendment.

**Architecture:** Two new `alfred_internal`-only services (zero external egress — `test_only_gateway_on_external` stays intact); Prometheus evaluates the promtool-tested rule files against the live core scrape target (satisfying the "alertable" precondition); Grafana is dashboards-only, zero-egress, hardened, reached per-platform without egress (Linux loopback / OrbStack `*.orb.local` / Docker-Desktop tunnel).

**Tech Stack:** Docker Compose, Prometheus, Grafana, promtool, pytest (+ testcontainers for the end-to-end scrape test), YAML.

## Global Constraints

- **Depends on PR1** (`2026-07-21-470-pr1-core-metrics-endpoint.md`): the core `/metrics` endpoint, `ALFRED_CORE_METRICS_PORT` (default 9465), and the core compose healthcheck must already exist.
- **Connectivity-free core:** every new service joins `alfred_internal` ONLY — never `alfred_external`. No new external egress (that is #479).
- **No `--web.enable-admin-api` / `--web.enable-lifecycle` / `remote_write`** on Prometheus. Config + rules mounted read-only.
- **`GF_SECURITY_ADMIN_PASSWORD` uses `:-`, never `:?`** (Compose evaluates `${VAR:?}` before profile/onerror filtering → aborts every `docker compose` invocation). Setup-script-generated into `.env`.
- **Grafana default-on** (PRD §4 MVP criterion 9 "the default dashboard shows…"); profile-gating is deferred as a human-gated PRD-interpretation item — never resolved via an egress bridge.
- **Editing PRD.md / CLAUDE.md is human-gated** — the CLAUDE.md `alfred daemon healthcheck` command-table entry is flagged as a follow-up, not applied here.
- **Conventional Commits:** literal `#470` after the colon in every subject.
- Spec: `docs/superpowers/specs/2026-07-21-470-core-metrics-observability-design.md` (rev.1). Implements §6 + §7 (the ADR amendment). §13 fold-log overrides where sections conflict.

---

## File structure

- Modify `docker-compose.yaml` — add `alfred-prometheus`, `alfred-grafana`; new named volumes `alfred_prom_data`, `alfred_grafana_data`.
- Modify `ops/prometheus/prometheus.yml` — `alfred-core` scrape job; `rule_files` += `quarantine.yml`, `core.yml`.
- Create `ops/alerts/core.yml` — `up{job="alfred-core"} == 0`, `absent(alfred_quarantine_capability_revoked_total)`.
- Create `ops/alerts/core_test.yml` — promtool unit tests (positive + negative controls).
- Create `ops/grafana/provisioning/datasources/prometheus.yml`, `ops/grafana/provisioning/dashboards/dashboards.yml`, `ops/grafana/dashboards/quarantine.json`; `git mv ops/grafana/gateway.json ops/grafana/dashboards/`.
- Modify `bin/alfred-setup.sh` — generate `GF_SECURITY_ADMIN_PASSWORD` into `.env`; `.env.example` placeholder.
- Modify `.github/workflows/ci.yml` — promtool-test `core.yml`; extend the "no silently-dead alerts" cross-check to core `alfred_*` rules.
- Reframe caveats: `src/alfred/security/observability.py`, `ops/alerts/quarantine.yml`, `docs/runbooks/quarantine-capability-revoked.md`, `docs/subsystems/security.md`.
- Create `docs/runbooks/observability-stack.md`; modify `README.md`.
- Create `docs/adr/0040-...` amendment (edit ADR-0040 residual panel + a new decision note).
- Tests: `tests/unit/test_compose_invariants.py` (extend), `tests/integration/test_prometheus_scrapes_core.py` (testcontainers).

---

## Task 1: Add the Prometheus service (internal-only, hardened)

**Files:**

- Modify: `docker-compose.yaml`
- Test: `tests/unit/test_compose_invariants.py`

- [ ] **Step 1: Write the failing invariant tests**

```python
# tests/unit/test_compose_invariants.py (append)
def test_observability_services_internal_only(compose):
    for name in ("alfred-prometheus", "alfred-grafana"):
        nets = _service_networks(compose, name)
        assert nets == {"alfred_internal"}, f"{name} must join alfred_internal ONLY; got {sorted(nets)}"

def test_prometheus_has_no_admin_or_lifecycle_api(compose):
    cmd = compose["services"]["alfred-prometheus"].get("command", []) or []
    joined = " ".join(cmd) if isinstance(cmd, list) else str(cmd)
    assert "--web.enable-admin-api" not in joined
    assert "--web.enable-lifecycle" not in joined
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run pytest tests/unit/test_compose_invariants.py -q -k "observability_services or admin_or_lifecycle"`
Expected: FAIL (service absent).

- [ ] **Step 3: Add the service to `docker-compose.yaml`**

```yaml
  alfred-prometheus:
    image: prom/prometheus:v3.5.0   # pin the exact current tag at implementation
    restart: unless-stopped
    command:
      - "--config.file=/etc/prometheus/prometheus.yml"
      - "--storage.tsdb.path=/prometheus"
      - "--storage.tsdb.retention.time=15d"
      - "--web.listen-address=0.0.0.0:9090"
    volumes:
      - alfred_prom_data:/prometheus
      - ./ops/prometheus/prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - ./ops/alerts:/etc/prometheus/alerts:ro
    networks:
      - alfred_internal
    healthcheck:
      test: ["CMD", "wget", "-q", "-O", "-", "http://127.0.0.1:9090/-/healthy"]
      interval: 15s
      timeout: 5s
      retries: 3
```

Add `alfred_prom_data:` to the top-level `volumes:`. (Verify the image ships `wget`/`/bin/sh`; if not, drop the healthcheck rather than ship a broken one — spec §6.1.)

- [ ] **Step 4: Run to verify they pass**

Run: `uv run pytest tests/unit/test_compose_invariants.py -q` — Expected: PASS (incl. `test_only_gateway_on_external`).

- [ ] **Step 5: `docker compose config --quiet`** to confirm YAML validity. Then commit:

```bash
git add docker-compose.yaml tests/unit/test_compose_invariants.py
git commit -m "feat(compose): #470 bundle internal-only Prometheus"
```

---

## Task 2: Prometheus scrape job + rule files + promtool tests + CI

**Files:**

- Modify: `ops/prometheus/prometheus.yml`
- Create: `ops/alerts/core.yml`, `ops/alerts/core_test.yml`
- Modify: `.github/workflows/ci.yml`

- [ ] **Step 1: Add the core scrape job + rule files to `prometheus.yml`**

```yaml
rule_files:
  - /etc/prometheus/alerts/gateway.yml
  - /etc/prometheus/alerts/quarantine.yml
  - /etc/prometheus/alerts/core.yml

scrape_configs:
  - job_name: alfred-gateway
    static_configs:
      - targets: ["alfred-gateway:9464"]
  - job_name: alfred-core
    static_configs:
      - targets: ["alfred-core:9465"]   # literal — Prometheus can't env-expand static targets (rev.1 arch-001/rev-004)
```

> **Port contract (rev.1):** the `9465` here is a **literal** and must equal PR1's `ALFRED_CORE_METRICS_PORT` default. Prometheus `static_configs` cannot read `${...}`, so an operator overriding the daemon's port MUST also edit this line — the same constraint the gateway's hardcoded `9464` already carries. Document this in `observability-stack.md` (Task 6 Step 3).

- [ ] **Step 2: Create `ops/alerts/core.yml`** (target-down + counter-absent — spec §5.5/§6.1)

```yaml
groups:
  - name: alfred-core
    rules:
      - alert: AlfredCoreMetricsDown
        expr: up{job="alfred-core"} == 0
        for: 2m
        labels: {severity: critical}
        annotations:
          summary: "alfred-core /metrics is unscraped"
          description: "Prometheus cannot scrape alfred-core:9465 — the quarantine capability-revoke alert is blind. Check `alfred daemon healthcheck` in the alfred-core container."
      - alert: AlfredQuarantineCounterAbsent
        expr: absent(alfred_quarantine_capability_revoked_total)
        for: 10m
        labels: {severity: warning}
        annotations:
          summary: "quarantine capability-revoke counter series is absent"
          description: "The counter is not registered/exposed — the QuarantineCapabilityRevoked alert cannot fire. Expected present at 0 from daemon boot (#470)."
```

- [ ] **Step 3: Create `ops/alerts/core_test.yml`** (positive + negative controls — mirror `quarantine_test.yml`)

```yaml
rule_files:
  - core.yml
evaluation_interval: 1m
tests:
  - interval: 1m
    input_series:
      - series: 'up{job="alfred-core"}'
        values: "0x5"
    alert_rule_test:
      - eval_time: 3m
        alertname: AlfredCoreMetricsDown
        exp_alerts:
          - exp_labels: {severity: critical, job: alfred-core}
            exp_annotations: {summary: "alfred-core /metrics is unscraped", description: "Prometheus cannot scrape alfred-core:9465 — the quarantine capability-revoke alert is blind. Check `alfred daemon healthcheck` in the alfred-core container."}
  - interval: 1m       # negative control: target up ⇒ no alert
    input_series:
      - series: 'up{job="alfred-core"}'
        values: "1x5"
    alert_rule_test:
      - eval_time: 3m
        alertname: AlfredCoreMetricsDown
        exp_alerts: []
  # rev.1 (devops-002/rev-005/sec-003/test-004): the security-relevant absent() rule also needs controls.
  - interval: 1m       # positive: the counter series is ABSENT ⇒ AlfredQuarantineCounterAbsent fires
    input_series:
      - series: 'up{job="alfred-core"}'   # some series exists, but NOT the counter
        values: "1x15"
    alert_rule_test:
      - eval_time: 11m
        alertname: AlfredQuarantineCounterAbsent
        exp_alerts:
          - exp_labels: {severity: warning}
            exp_annotations: {summary: "quarantine capability-revoke counter series is absent", description: "The counter is not registered/exposed — the QuarantineCapabilityRevoked alert cannot fire. Expected present at 0 from daemon boot (#470)."}
  - interval: 1m       # negative: counter present at 0 ⇒ no AlfredQuarantineCounterAbsent
    input_series:
      - series: 'alfred_quarantine_capability_revoked_total'
        values: "0x15"
    alert_rule_test:
      - eval_time: 11m
        alertname: AlfredQuarantineCounterAbsent
        exp_alerts: []
```

- [ ] **Step 4: Run promtool locally**

Run: `promtool check rules ops/alerts/core.yml && promtool test rules ops/alerts/core_test.yml`
Expected: `SUCCESS`.

- [ ] **Step 5: Wire CI + extend the no-silently-dead-alerts cross-check (rev.1 devops-001/test-003/rev-007)**

Add `core.yml` to the promtool step in `ci.yml`. Then extend the **no-silently-dead-alerts cross-check — which is a pytest test, `tests/unit/test_ops_scaffold.py` (currently hardcoded to `gateway_*`), NOT a ci.yml step.** It asserts every alert rule references a metric the code actually exposes. The extension must add the core `alfred_*` alerts and cross-reference them against `CORE_OWNED_COLLECTORS` (PR1) so a renamed/removed core metric fails loud. Write the test change concretely (parametrize over both rule files; resolve `alfred_quarantine_capability_revoked_total`/`up` against the core surface):

```python
# tests/unit/test_ops_scaffold.py (extend the existing gateway-only assertion)
def test_core_alerts_reference_real_core_metrics():
    from alfred.observability.core_metrics import CORE_OWNED_COLLECTORS
    core_names = {c._name for c in CORE_OWNED_COLLECTORS}  # base names; _total-stripped forms
    # parse ops/alerts/core.yml exprs, extract metric refs, assert each is a known core metric
    # (or the built-in `up`), else the rule is silently dead. See the gateway sibling for the parser.
    ...
```

Run: `uv run pytest tests/unit/test_ops_scaffold.py -q` — Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add ops/prometheus/prometheus.yml ops/alerts/core.yml ops/alerts/core_test.yml .github/workflows/ci.yml
git commit -m "feat(ops): #470 scrape alfred-core + core up/absent alerts with promtool tests"
```

---

## Task 3: Add the Grafana service (default-on, internal-only, `:-` password)

**Files:**

- Modify: `docker-compose.yaml`, `bin/alfred-setup.sh`, `.env.example`
- Test: `tests/unit/test_compose_invariants.py`

- [ ] **Step 1: Write the failing invariant tests**

```python
# tests/unit/test_compose_invariants.py (append)
def test_grafana_password_uses_soft_default_not_required(compose):
    env = compose["services"]["alfred-grafana"].get("environment", {}) or {}
    val = str(env.get("GF_SECURITY_ADMIN_PASSWORD", ""))
    assert val.startswith("${GF_SECURITY_ADMIN_PASSWORD:-"), "must use :- (never :?) or it aborts default `up`"

def test_grafana_publishes_only_loopback(compose):
    for m in compose["services"]["alfred-grafana"].get("ports", []) or []:
        s = m if isinstance(m, str) else f"{m.get('published','')}"
        assert "127.0.0.1" in s and not s.startswith("0.0.0.0"), "Grafana must bind loopback only"
```

- [ ] **Step 2: Run to verify they fail** — `uv run pytest tests/unit/test_compose_invariants.py -q -k grafana` → FAIL.

- [ ] **Step 3: Add the service**

```yaml
  alfred-grafana:
    image: grafana/grafana:11.6.0   # pin the exact current tag at implementation
    restart: unless-stopped
    environment:
      GF_ANALYTICS_REPORTING_ENABLED: "false"
      GF_ANALYTICS_CHECK_FOR_UPDATES: "false"
      GF_ANALYTICS_CHECK_FOR_PLUGIN_UPDATES: "false"
      GF_AUTH_ANONYMOUS_ENABLED: "false"
      GF_USERS_ALLOW_SIGN_UP: "false"
      GF_INSTALL_PLUGINS: ""
      GF_SNAPSHOTS_EXTERNAL_ENABLED: "false"
      GF_SECURITY_DISABLE_GRAVATAR: "true"
      GF_SECURITY_ADMIN_USER: ${GF_SECURITY_ADMIN_USER:-admin}
      GF_SECURITY_ADMIN_PASSWORD: ${GF_SECURITY_ADMIN_PASSWORD:-}   # :- NEVER :? ; setup-script fills .env
    volumes:
      - alfred_grafana_data:/var/lib/grafana
      - ./ops/grafana/provisioning:/etc/grafana/provisioning:ro
      - ./ops/grafana/dashboards:/var/lib/grafana/dashboards:ro   # rev.1 devops-006: dedicated subdir, NOT all of ops/grafana (which contains provisioning/)
    ports:
      - "127.0.0.1:3000:3000"   # loopback (Linux); OrbStack via *.orb.local; DD via tunnel
    networks:
      - alfred_internal
    depends_on:
      - alfred-prometheus
```

Add `alfred_grafana_data:` to top-level `volumes:`.

- [ ] **Step 4: Seed the password in `bin/alfred-setup.sh` — guard on PRESENT-AND-NON-EMPTY, not absent (rev.1 devops-004/sec-004)**

`.env.example` carries `GF_SECURITY_ADMIN_PASSWORD=` (empty), and first-run does `cp .env.example .env`, so the key is **present but empty** — an "if absent, append" guard would never fire and Grafana would boot with an empty admin password (sec-004). Mirror the `audit.hash_pepper` seed's **present-and-non-empty** grep-guard and **replace** the empty line in place rather than append:

```bash
# in bin/alfred-setup.sh — seed a Grafana admin password if unset OR empty
if ! grep -qE '^GF_SECURITY_ADMIN_PASSWORD=.+' .env; then
  pw="$(openssl rand -hex 24)"
  # replace an existing empty line, else append
  if grep -qE '^GF_SECURITY_ADMIN_PASSWORD=' .env; then
    sed -i.bak "s|^GF_SECURITY_ADMIN_PASSWORD=.*|GF_SECURITY_ADMIN_PASSWORD=${pw}|" .env && rm -f .env.bak
  else
    printf 'GF_SECURITY_ADMIN_PASSWORD=%s\n' "$pw" >> .env
  fi
fi
```

`.env.example` placeholder line:

```bash
# Grafana admin password — auto-generated by bin/alfred-setup.sh on first run (never commit a real value).
GF_SECURITY_ADMIN_PASSWORD=
```

- [ ] **Step 5: Run to verify they pass** — `uv run pytest tests/unit/test_compose_invariants.py -q` → PASS.

- [ ] **Step 6: Commit**

```bash
git add docker-compose.yaml bin/alfred-setup.sh .env.example tests/unit/test_compose_invariants.py
git commit -m "feat(compose): #470 bundle default-on internal-only Grafana (:- password)"
```

---

## Task 4: Grafana provisioning + dashboard

**Files:**

- Create: `ops/grafana/provisioning/datasources/prometheus.yml`, `ops/grafana/provisioning/dashboards/dashboards.yml`, `ops/grafana/dashboards/quarantine.json`

- [ ] **Step 1: Datasource provision**

```yaml
# ops/grafana/provisioning/datasources/prometheus.yml
apiVersion: 1
datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://alfred-prometheus:9090
    isDefault: true
```

- [ ] **Step 2: Dashboard provider**

```yaml
# ops/grafana/provisioning/dashboards/dashboards.yml
apiVersion: 1
providers:
  - name: alfred
    type: file
    options: {path: /var/lib/grafana/dashboards}
```

- [ ] **Step 3: Add a core/quarantine dashboard** `ops/grafana/dashboards/quarantine.json` with panels for `alfred_quarantine_capability_revoked_total`, `up{job="alfred-core"}`, and the comms/supervisor histograms (a minimal starter). **Also move the existing `ops/grafana/gateway.json` into `ops/grafana/dashboards/`** (`git mv ops/grafana/gateway.json ops/grafana/dashboards/`) so the dashboards-only mount (`./ops/grafana/dashboards`, Task 3 rev.1 devops-006) actually serves it.

- [ ] **Step 4: Validate JSON** — `python -c "import json;json.load(open('ops/grafana/dashboards/quarantine.json'))"`. Commit:

```bash
git add ops/grafana
git commit -m "feat(ops): #470 Grafana datasource + dashboard provisioning for core series"
```

---

## Task 5: End-to-end scrape-precondition test (the anti-paper-gate)

**Files:**

- Create: `tests/integration/test_prometheus_scrapes_core.py`

- [ ] **Step 1: Write the fixture + test (rev.1 test-002/devops-003/rev-006 — the two load-bearing details spelled out)**

The fixture is the anti-paper-gate's whole point; two details are non-negotiable or it proves nothing: **(1)** the stub `/metrics` container MUST be network-aliased **exactly `alfred-core`** on port **9465** (the literal scrape target), and **(2)** the Prometheus container MUST mount **both** the repo `prometheus.yml` **and** `ops/alerts/` (else Prometheus loads zero rules and the `/api/v1/rules` assertion is vacuous). Use a shared testcontainers network.

```python
# tests/integration/test_prometheus_scrapes_core.py
import time
import pytest, httpx
from pathlib import Path
from testcontainers.core.container import DockerContainer
from testcontainers.core.network import Network

pytestmark = pytest.mark.integration
_REPO = Path(__file__).resolve().parents[2]

@pytest.fixture
def prometheus_with_stub_core():
    with Network() as net:
        # (1) stub core /metrics, aliased EXACTLY as the scrape target expects
        stub_body = "# TYPE alfred_quarantine_capability_revoked_total counter\nalfred_quarantine_capability_revoked_total 0\n"
        stub = (DockerContainer("python:3.14-slim")
                .with_network(net).with_kwargs(network_aliases=["alfred-core"])
                .with_command(f"python -c \"import http.server,functools;h=functools.partial(http.server.SimpleHTTPRequestHandler);"
                              f"import http.server as s;\\n"))  # simplest: serve a static /metrics on :9465 (see note)
        # NOTE: implement the stub as a tiny script that answers GET /metrics with stub_body on :9465.
        prom = (DockerContainer("prom/prometheus:v3.5.0")
                .with_network(net)
                .with_exposed_ports(9090)
                .with_volume_mapping(str(_REPO / "ops/prometheus/prometheus.yml"), "/etc/prometheus/prometheus.yml", "ro")
                .with_volume_mapping(str(_REPO / "ops/alerts"), "/etc/prometheus/alerts", "ro"))
        with stub, prom:
            base = f"http://{prom.get_container_host_ip()}:{prom.get_exposed_port(9090)}"
            time.sleep(3)  # allow one scrape interval
            yield base

def test_prometheus_loads_config_and_rule_is_live(prometheus_with_stub_core):
    base = prometheus_with_stub_core
    rules = httpx.get(f"{base}/api/v1/rules").json()
    names = {r["name"] for g in rules["data"]["groups"] for r in g["rules"]}
    assert "QuarantineCapabilityRevoked" in names       # rules actually loaded (ops/alerts mounted)
    up = httpx.get(f"{base}/api/v1/query", params={"query": 'up{job="alfred-core"}'}).json()
    assert up["data"]["result"][0]["value"][1] == "1"   # the alfred-core alias was scraped
```

(Implement the stub container's `/metrics` responder however is cleanest in-repo — the load-bearing invariants are the `alfred-core` alias + the two ro mounts, not the stub's language.)

- [ ] **Step 2: Run it** — `uv run pytest tests/integration/test_prometheus_scrapes_core.py -q` → PASS (a typo'd scrape target would fail here instead of shipping green).

- [ ] **Step 3: Commit**

```bash
git add tests/integration/test_prometheus_scrapes_core.py
git commit -m "test(ops): #470 end-to-end proof Prometheus scrapes core and the rule is live"
```

---

## Task 6: Caveat reframe + operator doc + README

**Files:**

- Modify: `src/alfred/security/observability.py`, `ops/alerts/quarantine.yml`, `docs/runbooks/quarantine-capability-revoked.md`, `docs/subsystems/security.md`, `README.md`
- Create: `docs/runbooks/observability-stack.md`

- [ ] **Step 0: Enumerate ALL "#470 not scraped" references first (rev.1 docs-001)** — a naïve list misses some. Run `grep -rn "#470\|not scraped\|nothing scrapes\|armed" docs/ ops/ src/alfred/security/observability.py` and reframe every hit. Known targets include the three below **plus `docs/subsystems/security.md:452-453`** ("The metric is not scraped yet ([#470]) — use the audit-log path"), which the first draft missed.

- [ ] **Step 1: Drop the "armed, not live" blocks** in `observability.py` (the `.. warning::`), `quarantine.yml` (the `ARMED, NOT YET LIVE` header), and the `docs/subsystems/security.md:452-453` "not scraped yet" claim. Editing `security/observability.py` triggers the adversarial suite (Task 8).

- [ ] **Step 2: Reframe the runbook** (spec §6.4 — corrected rationale): remove **all four** falsified fragments — the `⚠ Read first: the alert cannot fire yet` block, the `Related`-`#470` entry, the `un-scrapeable, #470` parenthetical inside the audit section, **and the "Detecting it today / Both work without Prometheus" framing** (rev.1 docs-002); rewrite the audit-path framing as **"the metric is the sole durable signal for the cancel-path revoke class (#472 writes no `egress.broker.refused` row); the audit-log path is the additive cross-check for the other revoke classes."** Do NOT say "keep the audit path because complementary" (inverted).

- [ ] **Step 3: Write `docs/runbooks/observability-stack.md`** — per-platform Grafana access (Linux `http://127.0.0.1:3000`; OrbStack `http://alfred-grafana.<project>.orb.local`; Docker-Desktop tunnel), Prometheus access, what the bundled dashboards show, and the `GF_SECURITY_ADMIN_PASSWORD` first-run note.

- [ ] **Step 4: Update `README.md`** quickstart — Prometheus/Grafana are now default services; link the observability runbook.

- [ ] **Step 5: Markdown lint** — `npx markdownlint-cli2@0.22.1 "docs/**/*.md" "README.md"` → 0 errors. Commit:

```bash
git add src/alfred/security/observability.py ops/alerts/quarantine.yml docs/runbooks README.md
git commit -m "docs(observability): #470 reframe armed-not-live caveats + operator stack doc"
```

---

## Task 7: ADR-0040 amendment (this work — spec §7)

**Files:**

- Modify: `docs/adr/0040-connectivity-free-core-mandatory-egress-chokepoint.md`

- [ ] **Step 1: Add an `Amended: 2026-07-21 (#470)` line** and a **new residual `(viii)`** in ADR-0040's residual panel (the panel currently runs (i)–(vii); confirm the next free numeral at implementation) recording: (a) the inbound-`/metrics`-listener-vs-external-socket interpretation of Decision 1; (b) the two new internal-only third-party services + a Prometheus TSDB attached to the connectivity-free stack; (c) the accepted residual — core `/metrics` is unauthenticated plaintext HTTP readable by any `alfred_internal` peer, carrying only bounded operational aggregates (no T3/PII/secret), kept true by the PR1 leak-guard + value-boundedness invariant.

- [ ] **Step 2: Markdown lint** the ADR; confirm ADR cross-links resolve. Commit:

```bash
git add docs/adr/0040-connectivity-free-core-mandatory-egress-chokepoint.md
git commit -m "docs(adr): #470 amend ADR-0040 with the inbound-metrics decision + unauth-disclosure residual"
```

---

## Task 8: OrbStack access verification + full-gate pass

- [ ] **Step 1: OrbStack `*.orb.local` smoke-task** (spec §6.2/§9 — manual macOS check, NOT a Linux-CI gate): with the internal-only Grafana up (no second bridge), from a Mac host on OrbStack, confirm `http://alfred-grafana.<project>.orb.local` returns the Grafana login (and `curl http://<container-ip>:3000/api/health` → 200). Record the result in `docs/runbooks/observability-stack.md`; keep the tunnel as the documented fallback if it fails.

- [ ] **Step 2: Full quality gates** — `uv run ruff check . && uv run ruff format --check . && uv run mypy src/ && uv run pyright src/` → clean.

- [ ] **Step 3: Adversarial suite** (Task 6 edits `src/alfred/security/observability.py`) — `uv run pytest tests/adversarial -q` → PASS.

- [ ] **Step 4: `make check`** → clean.

- [ ] **Step 5: `docker compose up -d` smoke** — the stack boots (default `up`, no `:?` abort); `alfred-core` healthy; Prometheus scrapes `up{job="alfred-core"}==1`; Grafana reachable per platform.

---

## Self-Review

**Spec coverage (§6 + §7):** §6.1 Prometheus + rules → Tasks 1+2; §6.2 Grafana default-on + `:-` password + access → Tasks 3+4+8; §6.3 compose-invariant tests → Tasks 1+3; §6.4 caveat reframe → Task 6; §6.5 operator doc + README + (human-gated) CLAUDE.md flag → Task 6 (+ the CLAUDE.md entry stays a flagged human-gated follow-up, NOT applied); §7 ADR amendment → Task 7; §9 e2e scrape test + promtool + OrbStack smoke → Tasks 2+5+8.

**Type/name consistency:** the scrape target `alfred-core:9465` matches PR1's `ALFRED_CORE_METRICS_PORT` default; `core.yml`/`core_test.yml` names align; `alfred_prom_data`/`alfred_grafana_data` volumes declared once and mounted once.

**Placeholders:** image tags say "pin the exact current tag at implementation" (a deliberate instruction, not a TBD); the dashboard JSON + `ci.yml` diff + testcontainers fixture are described by role for the implementer's tree.

**Human-gated guard:** the CLAUDE.md `alfred daemon healthcheck` command-table entry and any PRD §4/§7.5 clarification are flagged (§6.5, spec §10/§11) and NOT edited by this plan.

---

## rev.1 fold log (8-lane plan-review)

**High** — e2e testcontainers fixture spelled out: the stub MUST be aliased `alfred-core:9465` and Prometheus MUST mount BOTH `prometheus.yml` and `ops/alerts/` (Task 5, else zero rules / vacuous assertion); the no-silently-dead-alerts cross-check is `tests/unit/test_ops_scaffold.py` (a pytest test, gateway-hardcoded), NOT a ci.yml diff — concrete core extension added (Task 2 Step 5); `docs/subsystems/security.md:452-453` added to the caveat reframe (Task 6 Step 0/1).
**Medium** — `absent()` alert now has promtool positive+negative controls (Task 2 Step 3); Grafana password seed guards on present-AND-non-empty and replaces in place, since `cp .env.example .env` makes the key present-but-empty (Task 3 Step 4, sec-004/devops-004); port contract reconciled — the scrape target is a literal 9465, an override must be mirrored (Task 2 note + PR1 Task 6 note); the 4th runbook target ("Detecting it today / Both work without Prometheus") added to the reframe (Task 6 Step 2, docs-002).
**Low** — Grafana dashboards mount is a dedicated `ops/grafana/dashboards/` subdir (not all of ops/grafana, which holds provisioning/) + `git mv gateway.json` into it (Task 3/4, devops-006); ADR amendment carries a concrete date `2026-07-21` + residual `(viii)` (Task 7, docs-004).
**Verified sound (no change):** compose blocks valid + internal-only, `:-` empty password boots on Grafana 11, `prom/prometheus` ships wget for `/-/healthy`, promtool `up==0` schema valid, `#470` opens no egress.
