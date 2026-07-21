# #470 PR2 — bundle Prometheus + Grafana + rules + docs Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

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
- Create `ops/grafana/provisioning/datasources/prometheus.yml`, `ops/grafana/provisioning/dashboards/dashboards.yml`; a core/quarantine dashboard JSON under `ops/grafana/`.
- Modify `bin/alfred-setup.sh` — generate `GF_SECURITY_ADMIN_PASSWORD` into `.env`; `.env.example` placeholder.
- Modify `.github/workflows/ci.yml` — promtool-test `core.yml`; extend the "no silently-dead alerts" cross-check to core `alfred_*` rules.
- Reframe caveats: `src/alfred/security/observability.py`, `ops/alerts/quarantine.yml`, `docs/runbooks/quarantine-capability-revoked.md`.
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
      - targets: ["alfred-core:9465"]
```

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
```

- [ ] **Step 4: Run promtool locally**

Run: `promtool check rules ops/alerts/core.yml && promtool test rules ops/alerts/core_test.yml`
Expected: `SUCCESS`.

- [ ] **Step 5: Wire CI** — add `core.yml` to the promtool step in `ci.yml` and **extend the "no silently-dead alerts" cross-check** so it validates the core `alfred_*` alert series exist in the core scrape surface (currently gateway-only). Show the exact `ci.yml` diff.

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
      - ./ops/grafana:/var/lib/grafana/dashboards:ro
    ports:
      - "127.0.0.1:3000:3000"   # loopback (Linux); OrbStack via *.orb.local; DD via tunnel
    networks:
      - alfred_internal
    depends_on:
      - alfred-prometheus
```

Add `alfred_grafana_data:` to top-level `volumes:`.

- [ ] **Step 4: Generate the password in `bin/alfred-setup.sh`** (mirror the `audit.hash_pepper` seed): if `GF_SECURITY_ADMIN_PASSWORD` is absent from `.env`, append a random one (e.g. `openssl rand -hex 24`). Add a placeholder line to `.env.example`:

```bash
# Grafana admin password — auto-generated by bin/alfred-setup.sh on first run.
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

- Create: `ops/grafana/provisioning/datasources/prometheus.yml`, `ops/grafana/provisioning/dashboards/dashboards.yml`, `ops/grafana/quarantine.json`

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

- [ ] **Step 3: Add a core/quarantine dashboard** `ops/grafana/quarantine.json` with panels for `alfred_quarantine_capability_revoked_total`, `up{job="alfred-core"}`, and the comms/supervisor histograms (a minimal starter; the existing `gateway.json` covers gateway series).

- [ ] **Step 4: Validate JSON** — `python -c "import json;json.load(open('ops/grafana/quarantine.json'))"`. Commit:

```bash
git add ops/grafana
git commit -m "feat(ops): #470 Grafana datasource + dashboard provisioning for core series"
```

---

## Task 5: End-to-end scrape-precondition test (the anti-paper-gate)

**Files:**

- Create: `tests/integration/test_prometheus_scrapes_core.py`

- [ ] **Step 1: Write the test** (testcontainers — spec §9/devops-002): boot a Prometheus container with the repo `prometheus.yml` + a stub target exposing `alfred_quarantine_capability_revoked_total`, then assert `up{job="alfred-core"} == 1` and that the `QuarantineCapabilityRevoked` rule is present in `/api/v1/rules`. Skip on no-docker.

```python
# tests/integration/test_prometheus_scrapes_core.py (shape)
import pytest, httpx
pytestmark = pytest.mark.integration

def test_prometheus_loads_config_and_rule_is_live(prometheus_with_stub_core):
    base = prometheus_with_stub_core  # fixture: Prometheus + a stub /metrics on the alfred-core alias
    rules = httpx.get(f"{base}/api/v1/rules").json()
    names = {r["name"] for g in rules["data"]["groups"] for r in g["rules"]}
    assert "QuarantineCapabilityRevoked" in names
    up = httpx.get(f"{base}/api/v1/query", params={"query": 'up{job="alfred-core"}'}).json()
    assert up["data"]["result"][0]["value"][1] == "1"
```

- [ ] **Step 2: Run it** — `uv run pytest tests/integration/test_prometheus_scrapes_core.py -q` → PASS (a typo'd scrape target would fail here instead of shipping green).

- [ ] **Step 3: Commit**

```bash
git add tests/integration/test_prometheus_scrapes_core.py
git commit -m "test(ops): #470 end-to-end proof Prometheus scrapes core and the rule is live"
```

---

## Task 6: Caveat reframe + operator doc + README

**Files:**

- Modify: `src/alfred/security/observability.py`, `ops/alerts/quarantine.yml`, `docs/runbooks/quarantine-capability-revoked.md`, `README.md`
- Create: `docs/runbooks/observability-stack.md`

- [ ] **Step 1: Drop the "armed, not live" blocks** in `observability.py` (the `.. warning::`), `quarantine.yml` (the `ARMED, NOT YET LIVE` header). Editing `security/observability.py` triggers the adversarial suite (Task 8).

- [ ] **Step 2: Reframe the runbook** (spec §6.4 — corrected rationale): remove the `⚠ Read first: the alert cannot fire yet` block, the `Related`-`#470` entry, and the `un-scrapeable, #470` parenthetical inside the audit section; rewrite the audit-path framing as **"the metric is the sole durable signal for the cancel-path revoke class (#472 writes no `egress.broker.refused` row); the audit-log path is the additive cross-check for the other revoke classes."** Do NOT say "keep the audit path because complementary" (inverted).

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

- [ ] **Step 1: Add an `Amended: 2026-07-XX (#470)` line** and a residual-panel entry recording: (a) the inbound-`/metrics`-listener-vs-external-socket interpretation of Decision 1; (b) the two new internal-only third-party services + a Prometheus TSDB attached to the connectivity-free stack; (c) the accepted residual — core `/metrics` is unauthenticated plaintext HTTP readable by any `alfred_internal` peer, carrying only bounded operational aggregates (no T3/PII/secret), kept true by the PR1 leak-guard + value-boundedness invariant.

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
