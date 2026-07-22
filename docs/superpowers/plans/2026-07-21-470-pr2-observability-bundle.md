# #470 PR2 — bundle Prometheus + Grafana + rules + docs Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

> **rev.1 (2026-07-21)** — folds the 8-lane plan-review (no PR2 Critical). Fixed: the e2e testcontainers
> fixture (network alias + `ops/alerts` mount), the no-silently-dead-alerts cross-check location
> (`tests/unit/test_ops_scaffold.py`, not ci.yml), the Grafana password seed guard (present-and-non-empty),
> the caveat-reframe completeness (`docs/subsystems/security.md` + the 4th runbook target), and the
> `absent()` promtool control. See the §fold-log at the end.

> **rev.3 (2026-07-21)** — folds the PR #480 CodeRabbit cloud review. Load-bearing correction: the
> rev.2 "an empty `GF_SECURITY_ADMIN_PASSWORD` fails closed" claim is **empirically false** (Grafana
> ignores the empty value and falls back to `admin:admin`), so Task 3 gains an `entrypoint:` preflight
> guard + a real-execution test; Task 5's fixed `sleep(3)` becomes bounded readiness polling and its
> probes gain explicit timeouts. See the rev.3 fold log at the end.

> **rev.4 (2026-07-22)** — folds the 6-lane `/review-plan` fleet (0 Critical). The *design* was verified
> sound; every High/Medium is **test fidelity** — tests that prove the security guards are themselves
> wrong, vacuous, or uncommitted. Load-bearing corrections: (1) the rev.3 Grafana fail-closed test read
> the entrypoint via `yaml.safe_load`, which keeps compose's `$$` escape intact → run outside compose
> the guard expands `$$`→PID and proves nothing (Task 3 Step 4c now extracts via `docker compose config`);
> (2) Task 4's `git mv gateway.json` orphans two live `test_ops_scaffold.py` tests → `make check` reddens
> at Task 8 (now rewritten in-step); (3) Task 2 Step 5's `...` cross-check resolver is under-specified AND
> wrong (`_name` is `_total`-stripped) → now spelled out; (4) the Grafana seed regression test was never
> committed + risked a grep-only oracle; (5) Task 4 shipped dashboards/provisioning with no validity test.
> See the rev.4 fold log at the end for the full 22-finding disposition.

**Goal:** Bundle an internal-only Prometheus (scraping the core `/metrics` PR1 exposes) + a default-on internal-only Grafana into the compose stack, wire the `quarantine.yml` rules + new `up==0`/`absent()` rules with promtool tests, reframe the "armed, not live" caveats, ship an operator observability doc, and record #470's own ADR-0040 amendment.

**Architecture:** Two new `alfred_internal`-only services (zero external egress — `test_only_gateway_on_external` stays intact); Prometheus evaluates the promtool-tested rule files against the live core scrape target (satisfying the "alertable" precondition); Grafana is dashboards-only, zero-egress, hardened, reached per-platform without egress (Linux loopback / OrbStack `*.orb.local` / Docker-Desktop tunnel).

**Tech Stack:** Docker Compose, Prometheus, Grafana, promtool, pytest (+ testcontainers for the end-to-end scrape test), YAML.

## Global Constraints

- **Depends on PR1** (`2026-07-21-470-pr1-core-metrics-endpoint.md`): the core `/metrics` endpoint, `ALFRED_CORE_METRICS_PORT` (default 9465), and the core compose healthcheck must already exist.
- **Connectivity-free core:** every new service joins `alfred_internal` ONLY — never `alfred_external`. No new external egress (that is #479).
- **No `--web.enable-admin-api` / `--web.enable-lifecycle` / `remote_write`** on Prometheus. Config + rules mounted read-only.
- **`GF_SECURITY_ADMIN_PASSWORD` uses `:-`, never `:?`** (Compose evaluates `${VAR:?}` before profile/onerror filtering → aborts every `docker compose` invocation). Setup-script-generated into `.env`. **rev.3:** `:-` alone is not fail-closed — Grafana ignores an empty env value and falls back to `admin:admin`, so the service also carries an `entrypoint:` preflight guard that refuses to start on an unset/empty/`admin` password (Task 3, spec §6.2a).
- **Grafana default-on** (PRD §4 MVP criterion 9 "the default dashboard shows…"); profile-gating is deferred as a human-gated PRD-interpretation item — never resolved via an egress bridge.
- **Editing PRD.md / CLAUDE.md is human-gated** — PR2 must not edit CLAUDE.md. **rev.4 (docs-001/arch-003):** the `alfred daemon healthcheck` command-table row *already landed in PR1* (`.rulesync/rules/CLAUDE.md:106`, generated `CLAUDE.md:99`, via #481, human-approved 2026-07-22). It is DONE, not an outstanding follow-up — do not re-add it or re-flag it. The human-gated posture now applies only to any genuinely-pending PRD §4/§7.5 clarification.
- **Conventional Commits:** literal `#470` after the colon in every subject.
- Spec: `docs/superpowers/specs/2026-07-21-470-core-metrics-observability-design.md` (rev.3). Implements §6 + §6.2a + §7 (the ADR amendment). The §13/§14 fold-logs override where sections conflict.

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
- Modify `docs/adr/0040-connectivity-free-core-mandatory-egress-chokepoint.md` — the **third-party-services** arm of #470's amendment only; PR1 already landed the Decision-1 class-line + residual (viii) (Task 7).
- Tests: `tests/unit/test_compose_invariants.py` (extend), `tests/integration/test_prometheus_scrapes_core.py` (testcontainers), `tests/integration/test_grafana_password_fail_closed.py` (rev.3 — the entrypoint guard's real-execution proof).

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

# rev.4 (sec-001): the "no remote_write" hardening invariant (plan line 27, spec §6.1) is enumerated
# but the command-flag test above only checks the compose `command:` array — remote_write/remote_read
# are BLOCKS in ops/prometheus/prometheus.yml, unchecked, which is this repo's paper-only-gate pattern
# (enumerated invariant, no guard). internal:true is the kernel-level backstop (egress can't reach a
# public host), so this is defense-in-depth, but the guard must exist. Assert over the PARSED config file.
def test_prometheus_config_has_no_remote_write():
    import yaml
    from pathlib import Path
    cfg = yaml.safe_load((Path(__file__).resolve().parents[2] / "ops/prometheus/prometheus.yml").read_text())
    assert "remote_write" not in cfg, "Prometheus must not remote_write (would be external egress)"
    assert "remote_read" not in cfg, "Prometheus must not remote_read"
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

> **Port contract — 9465 is FIXED for the bundled stack (rev.1; rev.2 disambiguation; spec §5.5):** the `9465` here is a **literal** and must equal PR1's `ALFRED_CORE_METRICS_PORT` default. Prometheus `static_configs` cannot read `${...}`. Rather than leave two places that must be edited in lockstep, the decision is: **`ALFRED_CORE_METRICS_PORT` is a bind-port seam, not a supported operator knob** — the same status the gateway's `ALFRED_GATEWAY_METRICS_PORT` has against its likewise-hardcoded `alfred-gateway:9464`. Overriding it in compose without editing this line silently breaks scraping and nothing validates it. `observability-stack.md` (Task 6 Step 3) must document it as **fixed**, NOT as a tunable. Making it genuinely tunable is a design change (render the scrape config from the resolved value + startup validation + a non-default-port test), not a config change.

> **rev.4 (devops-004) — refresh the `prometheus.yml` header comment while you're in the file.** The
> existing file carries a stale scaffold header ("there is no Prometheus service in docker-compose.yaml
> yet; point an external/added Prometheus at this file") that PR2 falsifies. Task 6 Step 0's reframe grep
> (`#470|not scraped|nothing scrapes|armed`) does NOT match it, so it is missed unless fixed here: state
> the file is now consumed by the bundled `alfred-prometheus` service and drop the "point an external
> Prometheus at this file" line.

> **rev.4 (arch-002) — add a drift guard for the 9465 lockstep.** The plan admits "nothing validates"
> that the literal `alfred-core:9465` scrape target equals compose's `${ALFRED_CORE_METRICS_PORT:-9465}`
> default (`docker-compose.yaml`). Task 5's e2e catches `prometheus.yml` drifting *from* 9465 but NOT the
> compose default drifting *from* `prometheus.yml`. Close it with a ~6-line unit test (drift-detection —
> orthogonal to the "genuine tunability = design change" this plan rightly rejects); for free it also pins
> the gateway `9464` pair:
>
> ```python
> # tests/unit/test_compose_invariants.py (append) — rev.4 arch-002
> def test_scrape_target_ports_match_compose_defaults(compose):
>     import re, yaml
>     from pathlib import Path
>     prom = yaml.safe_load((Path(__file__).resolve().parents[2] / "ops/prometheus/prometheus.yml").read_text())
>     targets = {sc["job_name"]: sc["static_configs"][0]["targets"][0] for sc in prom["scrape_configs"]}
>     def _compose_default(svc, var):  # ${VAR:-9465} -> "9465"
>         env = compose["services"][svc].get("environment", {}) or {}
>         m = re.search(r":-(\d+)}", str(env.get(var, "")))
>         return m.group(1) if m else None
>     assert targets["alfred-core"].endswith(":" + _compose_default("alfred-core", "ALFRED_CORE_METRICS_PORT"))
>     # gateway pair is likewise hardcoded — pin it too so a future bump is caught
>     assert targets["alfred-gateway"].endswith(":9464")
> ```
>
> (Adjust the compose var/key to the actual `alfred-core` service env shape; the point is the assertion,
> not the exact accessor.)

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

**CI (rev.4 arch-004):** the existing gateway/quarantine precedent (`ci.yml` lines ~68-74) runs BOTH `promtool check rules X.yml` AND `promtool test rules X_test.yml`. Add BOTH `promtool check rules ops/alerts/core.yml` **and** `promtool test rules ops/alerts/core_test.yml` to the ops-promtool job, mirroring the `quarantine.yml`/`quarantine_test.yml` pair. Adding only `check` ships green while the positive/negative controls (the anti-paper-gate for the `absent()`/`up==0` rules) never run.

Then extend the **no-silently-dead-alerts cross-check — a pytest test, `tests/unit/test_ops_scaffold.py` (currently hardcoded to `gateway_*`), NOT a ci.yml step.** It asserts every alert rule references a metric the code actually exposes.

> **rev.4 (test-005/rev-004/sec-003/devops-007) — the `...` stub is under-specified AND the naive impl
> is WRONG; spell out the resolver explicitly.** Four lanes flagged this. Empirically confirmed against
> the tree: `CAPABILITY_REVOKED_COUNTER._name == "alfred_quarantine_capability_revoked"` — the `prometheus_client`
> Counter STRIPS the `_total` suffix from `_name`, while `core.yml` references the exposition name
> `alfred_quarantine_capability_revoked_total` and the builtin `up`. So `{c._name for c in CORE_OWNED_COLLECTORS}`
> matches **neither** referenced metric. The gateway sibling's `gateway_[a-z0-9_]*` ref-regex, its `_total`
> re-append (`test_ops_scaffold.py:97`), and its `src/alfred/gateway/` AST scan do **not** transfer to
> `alfred_*` names resolved against a tuple of collector objects. A literal copy yields a vacuous guard on
> the **sole durable signal for the #472 cancel-path revoke** — the exact class of security-critical
> silent-dead-alert this test exists to prevent. Required shape:
>
> ```python
> # tests/unit/test_ops_scaffold.py (extend the existing gateway-only assertion) — rev.4
> def test_core_alerts_reference_real_core_metrics():
>     import re, yaml
>     from pathlib import Path
>     from alfred.observability.core_metrics import CORE_OWNED_COLLECTORS
>     # _name is _total-STRIPPED; re-append _total so both exposition forms are known.
>     base = {c._name for c in CORE_OWNED_COLLECTORS}
>     known = base | {n + "_total" for n in base} | {"up"}  # explicit builtin allowlist
>     exprs = " ".join(
>         r["expr"]
>         for g in yaml.safe_load(Path("ops/alerts/core.yml").read_text())["groups"]
>         for r in g["rules"]
>     )
>     refs = set(re.findall(r"\balfred_[a-z0-9_]*\b", exprs)) | (
>         {"up"} if re.search(r"\bup\b", exprs) else set()
>     )
>     unknown = refs - known
>     assert not unknown, f"core.yml references metrics no core collector exposes: {sorted(unknown)}"
>     # Oracle-independence: also assert the EXPECTED set as an independent literal, so a mis-derived
>     # `known` cannot pass a mutated rule. MUTATION-CHECK: a rule referencing
>     # `alfred_quarantine_capability_revoked_typo` MUST fail this test.
>     assert refs >= {"alfred_quarantine_capability_revoked_total", "up"}
> ```
>
> Do NOT reconcile by mutual-stripping both sides (a tautological oracle that passes on a wrong name);
> map exposition names deterministically as above.

Run: `uv run pytest tests/unit/test_ops_scaffold.py -q` — Expected: PASS (a renamed/typo'd core metric fails loud; the mutation-check above is the non-vacuity control).

- [ ] **Step 6: Commit**

```bash
# rev.4: test_compose_invariants.py carries the arch-002 drift guard, which needs the alfred-core
# scrape target THIS task adds — so it lands here (not Task 1). Verify it passes only after Step 1.
git add ops/prometheus/prometheus.yml ops/alerts/core.yml ops/alerts/core_test.yml .github/workflows/ci.yml \
        tests/unit/test_ops_scaffold.py tests/unit/test_compose_invariants.py
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

# rev.3 (PR #480 CR): the `:-` arm alone does NOT fail closed — Grafana ignores an empty env value
# and falls back to defaults.ini `admin_password = admin`. Pin the preflight guard's SHAPE here;
# its RUNTIME behaviour is proven by tests/integration/test_grafana_password_fail_closed.py
# (a lexical assertion cannot decide what a third-party binary does).
def test_grafana_entrypoint_guards_the_admin_password(compose):
    ep = compose["services"]["alfred-grafana"].get("entrypoint")
    joined = " ".join(ep) if isinstance(ep, list) else str(ep or "")
    assert "GF_SECURITY_ADMIN_PASSWORD" in joined, "entrypoint must preflight the admin password"
    assert "exit 78" in joined, "the guard must refuse (EX_CONFIG), not warn"
    assert "exec /run.sh" in joined, "the pass path must hand off to Grafana's real entrypoint"
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
    # rev.3 (PR #480 CR, Major/security): layer 3 — refuse to START on a guessable credential.
    # `$$` so Compose does not interpolate; the guard runs INSIDE the container, at start.
    entrypoint:
      - /bin/sh
      - -ec
      - |
        if [ -z "$${GF_SECURITY_ADMIN_PASSWORD}" ] || [ "$${GF_SECURITY_ADMIN_PASSWORD}" = "admin" ]; then
          echo "FATAL: GF_SECURITY_ADMIN_PASSWORD is unset, empty, or the well-known default 'admin'." >&2
          echo "Grafana refuses to start rather than serve dashboards on a guessable credential." >&2
          echo "Fix: run bin/alfred-setup.sh (seeds a random value into .env), then 'docker compose up -d alfred-grafana'." >&2
          exit 78
        fi
        exec /run.sh
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

`.env.example` carries `GF_SECURITY_ADMIN_PASSWORD=` (empty), and first-run does `cp .env.example .env`, so the key is **present but empty** — an "if absent, append" guard would never fire and Grafana would boot with an empty admin password (sec-004). Guard on **present-and-non-empty** and **replace** the empty line in place rather than append.

> **rev.4 (devops-003) — "mirror the `audit.hash_pepper` seed" is INACCURATE; do not follow it literally.**
> That seed writes to `secrets.toml` (not `.env`), guards present-**only** (not present-and-non-empty),
> **appends** (never `sed` — `sed -i` appears 0× in the script today), and wraps `openssl rand` in a
> graceful `command -v openssl` check + a `mkdir` concurrency lock. This Grafana seed is genuinely
> different (`.env`, present-and-non-empty, in-place `sed`). Two corrections carried into the code below:
> **(1) placement is load-bearing** — the seed MUST run **after** `cp .env.example .env` creates the file
> and **before** the credential-validation gate (`bin/alfred-setup.sh` ~lines 77-149) that `exit 1`s on a
> placeholder `.env`, so a stock first run seeds in one pass; **(2) add the same `command -v openssl`
> graceful preflight** the pepper seed uses (under `set -euo pipefail` a bare `openssl rand` on a host
> without openssl aborts opaquely). A concurrency lock is optional (the entrypoint guard is the
> fail-closed backstop for any weak/empty result); note it but do not block on it. `sed -i.bak` itself is
> BSD/GNU-portable — verified, no change needed there.

```bash
# in bin/alfred-setup.sh — PLACEMENT (rev.4 devops-003): AFTER `cp .env.example .env`, BEFORE the
# credential-validation gate that exit 1s on a placeholder .env. Seed a Grafana admin password if
# the key is unset OR empty.
if ! grep -qE '^GF_SECURITY_ADMIN_PASSWORD=.+' .env; then
  # rev.4 (devops-003/sec-005): graceful openssl preflight — a bare `openssl rand` under
  # `set -euo pipefail` aborts opaquely on a host without openssl. Mirror the pepper seed's message.
  if ! command -v openssl >/dev/null 2>&1; then
    echo "ERROR: openssl is required to generate GF_SECURITY_ADMIN_PASSWORD. Install openssl and re-run." >&2
    exit 1
  fi
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

**Never a literal default in compose** (rev.2 security fold): the compose value's `:-` arm stays
**empty**. Compose substitutes a placeholder like `${GF_SECURITY_ADMIN_PASSWORD:-<generated>}`
*verbatim*, so any non-empty literal default would start Grafana with a predictable, repo-published
admin credential on a plain `docker compose up` that skipped the setup script.

> **rev.3 (PR #480 CR, Major/security) — "empty fails closed" was FALSE; do not rely on it.**
> The rev.2 text claimed an empty value made Grafana refuse to start. Verified against
> `grafana/grafana:11.6.0` on 2026-07-21: Grafana's env-override loop applies an env value only when
> it is non-empty, so an **empty** `GF_SECURITY_ADMIN_PASSWORD` is *ignored* and
> `conf/defaults.ini`'s `admin_password = admin` wins — the container starts, `/api/health` answers
> 200, and `curl -u admin:admin /api/org` returns **200**. An operator who runs `docker compose up`
> without ever running `bin/alfred-setup.sh` therefore gets a Grafana on `admin:admin`.
> The fix is the **`entrypoint:` preflight guard in Step 3** (layer 3), not a change to the `:-`.

**Why not `${GF_SECURITY_ADMIN_PASSWORD:?}` — read before "fixing" this back.** `:?` makes *Compose*
fail, and Compose interpolates the entire file before any profile/service filtering, so a missing
Grafana password aborts `docker compose down`, `ps`, `config`, `logs`, and even
`up alfred-core` — a stack-wide denial of service to punish one optional service's misconfiguration
(this is the Global Constraint at the top of this plan). The entrypoint guard fails **exactly one
container**, at container start, with an actionable message in `docker compose logs alfred-grafana`,
while every sibling service comes up normally. Keep `:-`; keep the setup-script seed; keep the guard.

**Credential design = three layers** (spec §6.2a): (1) `.env.example` present-but-empty +
`bin/alfred-setup.sh` present-and-non-empty seed; (2) compose reads it with `:-`, so no
`docker compose` verb aborts; (3) the entrypoint preflight refuses to start Grafana when the value is
unset, empty, or the literal `admin`. Only layer 3 holds for the operator who skipped setup.

- [ ] **Step 4b: Regression-test the seed guard (rev.2 — REQUIRED)**

The guard's failure mode is a *silent weak credential*, so it needs its own test.

> **rev.4 (test-003) — REAL EXECUTION is mandatory; a grep-only oracle is FORBIDDEN here.** The three
> cases below are **runtime facts** (what the script *does* to a file), which a static-text assertion
> cannot decide — and the existing `test_setup_script_audit_pepper.py` is grep-only (it asserts on the
> script's TEXT, never runs it). "Extend it rather than duplicating" must NOT be read as "add another
> grep assertion." Two hard requirements: **(1)** drive the seed by real execution — either extract the
> seed into a **sourceable shell function** the test invokes directly, or add a documented
> `ALFRED_SETUP_ENV_FILE` env-file seam so the test can point the script at a temp `.env`; **(2)** the
> test must **bypass the credential-validation gate** (`bin/alfred-setup.sh` ~77-149) that `exit 1`s on a
> placeholder `.env` before the seed runs — shelling the *whole* script cannot reach the seed, which is
> exactly why the sourceable-function / env-file seam is required, not optional. Assert all three cases
> against the real post-run file contents:

- an existing **empty** `GF_SECURITY_ADMIN_PASSWORD=` line is **replaced** with a generated value
  (the `cp .env.example .env` first-run shape — the case an "append if absent" guard misses);
- an existing **non-empty** value is **preserved byte-for-byte** (re-running setup must never
  rotate an operator's password out from under a running Grafana);
- the resulting `.env` contains **exactly one** `GF_SECURITY_ADMIN_PASSWORD=` key in every case
  (no duplicate-key append, whose last-wins semantics are shell-dependent).

Run: `uv run pytest tests/unit/test_setup_script_env_seed.py -q` (or the existing setup-script test
module, if one already covers the `audit.hash_pepper` seed — extend it rather than duplicating).

- [ ] **Step 4c: Prove the entrypoint guard actually fails closed (rev.3 — REQUIRED)**

`test_grafana_entrypoint_guards_the_admin_password` (Step 1) is **lexical**: it asserts the compose
string mentions the env var and an exit code. It cannot decide what Grafana does — that is a runtime
fact about a third-party binary, and the false rev.2 claim is exactly what happens when a runtime
fact is asserted from a doc. Add a real-execution test:

```python
# tests/integration/test_grafana_password_fail_closed.py
#
# rev.4 (test-004/devops-001 — CORROBORATED, the review's top finding): extract the entrypoint via
# COMPOSE INTERPOLATION, never raw yaml.safe_load. The shipped guard uses compose's `$$` escape
# (`$${GF_SECURITY_ADMIN_PASSWORD}`). Compose transforms `$$`->`$` before running; `yaml.safe_load`
# (the raw `compose` fixture at test_compose_invariants.py:33) keeps `$$` INTACT. Run that raw string
# through `sh -ec` outside compose and `$$` expands to the shell PID — the guard becomes "never empty",
# the empty-password refusal arm CANNOT fire, and the non-vacuity control validates NOTHING while
# reporting green. Do NOT hand-de-escape the guard string either (that drifts the tested guard from the
# shipped one). Instead resolve the real entrypoint from `docker compose config` (which performs the
# `$$`->`$` interpolation), e.g. `yaml.safe_load(subprocess.check_output(["docker","compose","config"]))`
# -> services["alfred-grafana"]["entrypoint"], and assert it byte-equals what you execute.
pytestmark = pytest.mark.integration

def test_empty_admin_password_refuses_to_start(grafana_entrypoint_from_compose):
    """No password (the skipped-setup operator) => the container exits non-zero, loudly."""
    # run grafana/grafana:<pinned> with the compose entrypoint and GF_SECURITY_ADMIN_PASSWORD=""
    # assert: exit code == 78, and the refusal text is on stderr (actionable: names alfred-setup.sh)

def test_literal_admin_password_refuses_to_start(grafana_entrypoint_from_compose):
    """The well-known default is refused explicitly, not just the empty string."""

def test_real_password_boots_and_rejects_admin_admin(grafana_entrypoint_from_compose):
    """NON-VACUITY CONTROL — the arm that proves this suite is about Grafana's real auth state.

    With a seeded password the container boots (/api/health 200), `admin:admin` is REJECTED (401),
    and the seeded credential is accepted (200). Without this arm the two refusal tests would still
    pass against a guard that refuses everything, and against a Grafana that authenticates nothing.
    """
```

> **rev.4 fixture mechanics for the three arms:**
>
> - **Refusal arms (empty / literal `admin`) — devops-005:** the container `exit 78`s immediately, but
>   testcontainers `DockerContainer.start()` is service-oriented (its host-ip/port/wait helpers assume a
>   long-lived container and raise on an immediately-exiting one). Use the docker SDK directly for these:
>   `client.containers.run(image, entrypoint=..., environment=..., detach=True)`, then `wait()` for
>   `StatusCode == 78` and `logs(stderr=True)` for the refusal text. Reserve `DockerContainer` for the
>   long-lived real-password `/api/health`-polling arm.
> - **Share the image pull — test-008:** the mac integration lane already runs >20 min and is flaky under
>   load; pull `grafana/grafana:<pinned>` once and reuse across all three arms, with deterministic teardown.
> - **Anti-paper-gate discipline — sec-002/devops-006 (disputed → resolved):** keep the file plain
>   `pytest.mark.integration` (no `skipif`, no `docker` marker). As written it **errors** (not silently
>   skips) when Docker is absent on the required lane — genuinely NOT a paper gate. IF a future contributor
>   ever adds a docker-skip for dev ergonomics, it MUST be paired with a #245-style "assert RAN" `ci.yml`
>   guard. Also record in-plan: the guard's `exec /run.sh` couples to `grafana/grafana:11.6.0`'s canonical
>   entrypoint — re-measure it on every Grafana image bump (a base-image entrypoint change would
>   fail-closed-to-broken undetected).

Run: `uv run pytest tests/integration/test_grafana_password_fail_closed.py -q` → PASS.

> **Expected values, measured 2026-07-21 on `grafana/grafana:11.6.0` (real containers, all three
> arms).** Guard absent + empty password: container starts, `/api/health` 200, `admin:admin` → **200**
> (the hazard this task closes). Guard present + empty or `admin`: `docker compose config` clean,
> container exits **78**, refusal on stderr, sibling services unaffected. Guard present + real
> password: boots, `/api/health` 200, `admin:admin` → **401**, real credential → **200**. If the
> pinned Grafana tag changes, re-measure before trusting these numbers.

- [ ] **Step 5: Run to verify they pass** — `uv run pytest tests/unit/test_compose_invariants.py -q` → PASS.

- [ ] **Step 6: Commit**

```bash
# rev.4 (rev-002): the Step 4b seed regression test MUST be staged — its failure mode is a silent weak
# credential, so an uncommitted test means CI never runs it. Use the actual filename you created
# (tests/unit/test_setup_script_env_seed.py, or test_setup_script_audit_pepper.py if you extended it).
git add docker-compose.yaml bin/alfred-setup.sh .env.example \
        tests/unit/test_compose_invariants.py tests/integration/test_grafana_password_fail_closed.py \
        tests/unit/test_setup_script_env_seed.py
git commit -m "feat(compose): #470 bundle default-on internal-only Grafana (:- password + fail-closed guard)"
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

> **rev.4 (rev-001/test-001 — CORROBORATED) — the `git mv` orphans two LIVE tests; fix them IN THIS STEP.**
> `tests/unit/test_ops_scaffold.py` reads the old hardcoded path `ops/grafana/gateway.json` at **line ~126**
> (`test_gateway_dashboard_parses_and_references_real_metrics`) and **line ~196** (`test_egress_panels_present`).
> Task 4 runs only `json.load`, so the resulting `FileNotFoundError` would not surface until Task 8
> `make check`, three commits later, with no fix step. In the SAME step as the `git mv`, rewrite both reads
> to `OPS / "grafana" / "dashboards" / "gateway.json"` and run `uv run pytest tests/unit/test_ops_scaffold.py -q`
> before committing. (This is why Step 4's `git add` below is widened to include `test_ops_scaffold.py`.)

- [ ] **Step 3b: Dashboard + provisioning validity tests (rev.4 test-002/test-006 — REQUIRED)**

Task 4 otherwise ships the new dashboard and both provisioning YAMLs with **zero** assertion — a panel
querying a renamed/nonexistent `alfred_*` metric, or a datasource/provider typo, would ship silently
green (Task 5's e2e is Prometheus-only and never loads Grafana). Add two unit tests, both derivable
from `docker-compose.yaml`:

- **test-002** — mirror the gateway sibling (`test_ops_scaffold.py:125-134`): parse `quarantine.json`
  panel exprs and assert every `alfred_*` ref (plus builtin `up`) resolves against `CORE_OWNED_COLLECTORS`,
  **reusing the exact Task 2 Step 5 resolver** (`_name` + `_total` expansion + `{"up"}` allowlist).
- **test-006** — parse both provisioning YAMLs and assert the datasource `url` host+port equals the
  `alfred-prometheus` service bind (`alfred-prometheus:9090`) and the dashboards-provider `path` equals
  the compose mount target (`/var/lib/grafana/dashboards`). A typo in either yields a silently dead
  datasource / unloaded dashboards.

Run: `uv run pytest tests/unit/test_ops_scaffold.py -q` → PASS.

- [ ] **Step 4: Validate JSON** — `python -c "import json;json.load(open('ops/grafana/dashboards/quarantine.json'))"`. Commit:

```bash
# rev.4: test_ops_scaffold.py carries the git-mv path rewrites (Step 3) + the two new validity tests
# (Step 3b). Staging ops/grafana alone would leave make check red at Task 8.
git add ops/grafana tests/unit/test_ops_scaffold.py
git commit -m "feat(ops): #470 Grafana datasource + dashboard provisioning for core series"
```

---

## Task 5: End-to-end scrape-precondition test (the anti-paper-gate)

**Files:**

- Create: `tests/integration/test_prometheus_scrapes_core.py`

- [ ] **Step 1: Write the fixture + test (rev.1 test-002/devops-003/rev-006 — the two load-bearing details spelled out)**

The fixture is the anti-paper-gate's whole point; two details are non-negotiable or it proves nothing: **(1)** the stub `/metrics` container MUST be network-aliased **exactly `alfred-core`** on port **9465** (the literal scrape target), and **(2)** the Prometheus container MUST mount **both** the repo `prometheus.yml` **and** `ops/alerts/` (else Prometheus loads zero rules and the `/api/v1/rules` assertion is vacuous). Use a shared testcontainers network.

> **rev.4 (arch-005/rev-003/devops-002 — CORROBORATED) — resolve the Prometheus image from compose, do
> not hardcode it a second time.** The fixture below re-hardcodes `prom/prometheus:v3.5.0` while Task 1
> Step 3 also hardcodes it under "pin the exact current tag at implementation" — two literals that must
> match, so a CVE bump to the compose tag would silently test a *different* Prometheus than ships. The
> fixture already reads the real `prometheus.yml` + `ops/alerts/`; have it read the image too:
> `yaml.safe_load(Path(_REPO/"docker-compose.yaml").read_text())["services"]["alfred-prometheus"]["image"]`.
> (Same DRY discipline the rev.3 Grafana fail-closed test applies to the entrypoint.)

```python
# tests/integration/test_prometheus_scrapes_core.py
import time
import pytest, httpx, yaml   # rev.4 (devops-002): yaml to resolve the Prometheus image from compose
from pathlib import Path
from testcontainers.core.container import DockerContainer
from testcontainers.core.network import Network

pytestmark = pytest.mark.integration
_REPO = Path(__file__).resolve().parents[2]

# rev.3 (PR #480 CR): every probe carries an explicit timeout. Precision on the CR wording — httpx
# 0.28.1 already defaults to Timeout(5.0), so these calls could NOT "hang indefinitely" (that is the
# `requests` failure mode, not httpx's). Explicit is still right: the value is now visible next to
# the readiness deadline it interacts with, and a library-default change or a Client(timeout=None)
# can no longer alter this test's behaviour silently.
_PROBE_TIMEOUT_S = 5.0
_READY_DEADLINE_S = 60.0
_POLL_INTERVAL_S = 0.25


def _wait_for_first_scrape(base: str) -> None:
    """Block until Prometheus has COMPLETED one scrape attempt of the alfred-core target.

    rev.3 (PR #480 CR): replaces a fixed `time.sleep(3)`, which is flaky under CI load (image pull,
    cold container start) and wasteful when the stack is fast.

    The gate is `health != "unknown"` — i.e. a scrape ATTEMPT finished — deliberately NOT `up == 1`.
    Waiting on `up == 1` would move the test's own oracle into the fixture: a genuinely dead stub
    would time out here with a fixture error instead of failing the assertion that exists to catch
    it. With this gate, a dead stub yields health="down"/up=0 and the TEST fails, loudly and
    specifically.
    """
    deadline = time.monotonic() + _READY_DEADLINE_S
    last = "no probe completed"
    while time.monotonic() < deadline:
        try:
            data = httpx.get(f"{base}/api/v1/targets", timeout=_PROBE_TIMEOUT_S).json()
            active = data["data"]["activeTargets"]
            core = [t for t in active if t["labels"].get("job") == "alfred-core"]
            if core and core[0]["health"] != "unknown":
                return
            last = repr([(t["labels"].get("job"), t["health"]) for t in active])
        except (httpx.HTTPError, KeyError, IndexError, ValueError) as exc:
            last = repr(exc)
        time.sleep(_POLL_INTERVAL_S)
    raise AssertionError(
        f"Prometheus did not complete a scrape of job=alfred-core within {_READY_DEADLINE_S}s; "
        f"last observation: {last}"
    )


@pytest.fixture
def prometheus_with_stub_core():
    with Network() as net:
        # (1) stub core /metrics, aliased EXACTLY as the scrape target expects
        stub_body = "# TYPE alfred_quarantine_capability_revoked_total counter\nalfred_quarantine_capability_revoked_total 0\n"
        # rev.2: the stub MUST RUN A PERSISTENT SERVER. The earlier draft's command only
        # *imported* http.server and exited, so the alias resolved to a dead container and
        # `up{job="alfred-core"}` was 0 — the test would have proven nothing. Bind 0.0.0.0
        # (not 127.0.0.1) or Prometheus cannot reach it across the container network, and
        # keep serve_forever() alive for the whole fixture.
        stub_script = (
            "import http.server\n"
            f"BODY = {stub_body!r}.encode()\n"
            "class H(http.server.BaseHTTPRequestHandler):\n"
            "    def do_GET(self):\n"
            "        if self.path != '/metrics':\n"
            "            self.send_error(404); return\n"
            "        self.send_response(200)\n"
            "        self.send_header('Content-Type', 'text/plain; version=0.0.4')\n"
            "        self.send_header('Content-Length', str(len(BODY)))\n"
            "        self.end_headers()\n"
            "        self.wfile.write(BODY)\n"
            "    def log_message(self, *a): pass\n"
            "http.server.HTTPServer(('0.0.0.0', 9465), H).serve_forever()\n"
        )
        stub = (DockerContainer("python:3.14-slim")
                .with_network(net).with_kwargs(network_aliases=["alfred-core"])
                .with_command(["python", "-c", stub_script]))
        _prom_image = yaml.safe_load((_REPO / "docker-compose.yaml").read_text())["services"]["alfred-prometheus"]["image"]  # rev.4 devops-002
        prom = (DockerContainer(_prom_image)
                .with_network(net)
                .with_exposed_ports(9090)
                .with_volume_mapping(str(_REPO / "ops/prometheus/prometheus.yml"), "/etc/prometheus/prometheus.yml", "ro")
                .with_volume_mapping(str(_REPO / "ops/alerts"), "/etc/prometheus/alerts", "ro"))
        with stub, prom:
            base = f"http://{prom.get_container_host_ip()}:{prom.get_exposed_port(9090)}"
            _wait_for_first_scrape(base)   # rev.3: bounded readiness poll, not a fixed sleep
            yield base

def test_prometheus_loads_config_and_rule_is_live(prometheus_with_stub_core):
    base = prometheus_with_stub_core
    rules = httpx.get(f"{base}/api/v1/rules", timeout=_PROBE_TIMEOUT_S).json()
    names = {r["name"] for g in rules["data"]["groups"] for r in g["rules"]}
    # rev.2: assert THIS PR's new core rules, not only the pre-existing quarantine rule —
    # `core.yml` is the file this task adds to `rule_files`, so a typo'd rule_files entry
    # must fail here. QuarantineCapabilityRevoked is kept as the #470 raison d'etre (and as
    # proof `quarantine.yml` reached the mount too).
    assert {"AlfredCoreMetricsDown", "AlfredQuarantineCounterAbsent"} <= names
    assert "QuarantineCapabilityRevoked" in names
    up = httpx.get(
        f"{base}/api/v1/query",
        params={"query": 'up{job="alfred-core"}'},
        timeout=_PROBE_TIMEOUT_S,
    ).json()
    assert up["data"]["result"][0]["value"][1] == "1"   # the alfred-core alias was scraped
```

(Implement the stub container's `/metrics` responder however is cleanest in-repo — the load-bearing invariants are the `alfred-core` alias, a **long-lived** listener on `0.0.0.0:9465` answering `GET /metrics` with the exposition body, and the two ro mounts. Not the stub's language: a one-shot command that exits is the failure this test exists to catch, so it must not be the test's own bug.)

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

- [ ] **Step 0: Enumerate ALL "#470 not scraped" references first (rev.1 docs-001)** — a naïve list misses some. **rev.4 (docs-003): the grep scope must include `tests/`** (the prior scope `docs/ ops/ src/…observability.py` structurally excluded it). Run `grep -rn "#470\|not scraped\|nothing scrapes\|armed" docs/ ops/ tests/ src/alfred/security/observability.py` and reframe every hit. Known targets include the three below **plus `docs/subsystems/security.md:452-453`** ("The metric is not scraped yet ([#470]) — use the audit-log path"), **plus `tests/unit/security/test_quarantine_revocation_metric.py:73-74`** (a "the counter exists as an object but nothing scrapes it, so the alert rule is dead" assertion *message* that PR2 falsifies — the assertion logic stays, only the failure-message rationale is refreshed for the post-scrape world).

- [ ] **Step 1: Drop the "armed, not live" blocks** in `observability.py` (the `.. warning::`), `quarantine.yml` (the `ARMED, NOT YET LIVE` header), and the `docs/subsystems/security.md:452-453` claim.
  - **rev.4 (docs-004):** in `security.md`, drop the **ENTIRE** sentence "**The metric is not scraped yet ([#470]) — use the audit-log path**", not just the "not scraped yet" fragment. If only the fragment goes, the residual "use the audit-log path" IS the inverted guidance spec §6.4 warns against for the #472 cancel-path class (whose revoke writes no audit row). Replace it with the corrected sole-durable-signal framing (see Step 2).
  - **rev.4 (docs-003):** refresh the failure-message rationale in `tests/unit/security/test_quarantine_revocation_metric.py:73-74` for the post-scrape world (the assertion itself is unchanged).
  - **rev.4 (test-007):** the `security/observability.py` edit is **docstring-only** (the dropped `.. warning::` lives in the module docstring, lines ~19-27 — non-executable, zero line/branch delta), so the 100%-line+branch obligation on `src/alfred/security/` is satisfied by inspection; the material obligation, the adversarial-suite run, is Task 8 Step 3. Editing `security/observability.py` triggers that suite. (Noted because #474 means `make check` may not run per-module coverage gates.)

- [ ] **Step 2: Reframe the runbook** (spec §6.4 — corrected rationale): remove **all four** falsified fragments — the `⚠ Read first: the alert cannot fire yet` block, the `Related`-`#470` entry, the `un-scrapeable, #470` parenthetical inside the audit section, **and the "Detecting it today / Both work without Prometheus" framing** (rev.1 docs-002); rewrite the audit-path framing as **"the metric is the sole durable signal for the cancel-path revoke class (#472 writes no `egress.broker.refused` row); the audit-log path is the additive cross-check for the other revoke classes."** Do NOT say "keep the audit path because complementary" (inverted).

- [ ] **Step 3: Write `docs/runbooks/observability-stack.md`** — per-platform Grafana access (Linux `http://127.0.0.1:3000`; OrbStack `http://alfred-grafana.<project>.orb.local`; Docker-Desktop tunnel), Prometheus access, what the bundled dashboards show, and the `GF_SECURITY_ADMIN_PASSWORD` first-run note. **rev.3:** include a named troubleshooting entry for the fail-closed guard — *"`alfred-grafana` exits 78 / restarts with `FATAL: GF_SECURITY_ADMIN_PASSWORD is unset, empty, or the well-known default`"* → the stack was started without `bin/alfred-setup.sh`; run it (it generates a strong random secret), or, when setting `.env` by hand, choose a strong, non-default `GF_SECURITY_ADMIN_PASSWORD` — never a guessable value; the guard rejects an empty value and the well-known `admin` default — then `docker compose up -d alfred-grafana`. State plainly that the rest of the stack is unaffected by this refusal, and that Grafana deliberately will **not** start on `admin:admin`. **rev.4 (sec-004):** also document that the guard reads only the plain `GF_SECURITY_ADMIN_PASSWORD` env var and does **not** support Grafana's `GF_SECURITY_ADMIN_PASSWORD__FILE` secret convention — a file-secret deployment leaves the plain var unset and would trip the guard (exit 78) with a message that mis-directs to `alfred-setup.sh`. This errs *closed* (never admits a weak credential); the bundled compose uses `.env` interpolation, not compose secrets, so the shipped path is unaffected. Note the fixed-port contract here too: `ALFRED_CORE_METRICS_PORT` is a bind-seam, **not** a tunable — the `alfred-core:9465` scrape target is hardcoded to match its default (spec §5.5).

- [ ] **Step 4: Update `README.md`** quickstart — Prometheus/Grafana are now default services; link the observability runbook.

- [ ] **Step 5: Markdown lint** — `npx markdownlint-cli2@0.22.1 "docs/**/*.md" "README.md"` → 0 errors. Commit:

```bash
# rev.4 (docs-003): the reframe now also touches the test-message rationale — stage it too.
git add src/alfred/security/observability.py ops/alerts/quarantine.yml docs/runbooks docs/subsystems/security.md README.md \
        tests/unit/security/test_quarantine_revocation_metric.py
git commit -m "docs(observability): #470 reframe armed-not-live caveats + operator stack doc"
```

---

## Task 7: ADR-0040 amendment (this work — spec §7)

**Files:**

- Modify: `docs/adr/0040-connectivity-free-core-mandatory-egress-chokepoint.md`

> **Already landed in PR1 — do NOT re-land (rev.2 fold of arch-001).** Two of the three facts go live
> the moment PR1 merges, so PR1 amended ADR-0040 with them directly: the **Decision-1 class-line**
> (an inbound listener on `alfred_internal` is not the "external socket" the invariant forbids) and
> **residual (viii)** (the core `/metrics` is unauthenticated plaintext HTTP readable by any
> `alfred_internal` peer, bounded by the curated registry + leak-guard, with the §5.2
> value-boundedness residual recorded as an explicit edge). PR2 owns only the third fact. Read
> ADR-0040 before editing; extend, do not duplicate.

- [ ] **Step 1: Add an `Amended: 2026-07-21 (#470 PR2)` line** recording the remaining fact: the **two new internal-only third-party services (Prometheus + Grafana) + the Prometheus TSDB** attached to the connectivity-free stack (CLAUDE.md's "no new datastore or third-party service without an ADR"; PRD §7.5/§9 pre-name the tools but not their post-Spec-C stack-attachment). Cover: both join `alfred_internal` only (zero egress — `test_only_gateway_on_external` stays intact), the TSDB holds operational aggregates only (the same bounded set residual (viii) describes) and is not a system-of-record datastore, and Grafana's data-source proxy is the reason it is never given an external bridge. Then **update BOTH of PR1's "deferred to PR2" promissory sentences (rev.4 docs-002 — there are TWO, not one):** (1) the PR1 `Amended: 2026-07-21` entry's "deferred to PR2" sentence (ADR-0040 lines ~28-30), and (2) the `*Scope of this amendment:*` note at the end of residual (viii) (ADR-0040 lines ~347-351: "… lands with PR2, which is what introduces them. Nothing in PR1 attaches a third-party service."). Past-tense both / point them at the new `Amended (#470 PR2)` entry — otherwise a durable ADR ships stale promissory text *after* the PR2 that lands the third arm, plus an ambiguous second "where the amendment lives" pointer.

- [ ] **Step 2: Markdown lint** the ADR; confirm ADR cross-links resolve. Commit:

```bash
git add docs/adr/0040-connectivity-free-core-mandatory-egress-chokepoint.md
git commit -m "docs(adr): #470 amend ADR-0040 with the bundled observability stack attachment"
```

---

## Task 8: OrbStack access verification + full-gate pass

- [ ] **Step 1: OrbStack `*.orb.local` smoke-task** (spec §6.2/§9 — manual macOS check, NOT a Linux-CI gate): with the internal-only Grafana up (no second bridge), from a Mac host on OrbStack, confirm `http://alfred-grafana.<project>.orb.local` returns the Grafana login (and `curl http://<container-ip>:3000/api/health` → 200). Record the result in `docs/runbooks/observability-stack.md`; keep the tunnel as the documented fallback if it fails. **rev.4 (rev-005):** that doc was already committed in Task 6 Step 5, and Task 8 has no `git add`/commit — so either give this step its own commit (`git add docs/runbooks/observability-stack.md && git commit -m "docs(observability): #470 record OrbStack access smoke result"`), OR write the OrbStack section speculatively in Task 6 Step 3 and make this step a pure confirm-or-file-follow-up. Do not leave an uncommitted change at plan end.

- [ ] **Step 2: Full quality gates** — `uv run ruff check . && uv run ruff format --check . && uv run mypy src/ && uv run pyright src/` → clean.

- [ ] **Step 3: Adversarial suite** (Task 6 edits `src/alfred/security/observability.py`) — `uv run pytest tests/adversarial -q` → PASS.

- [ ] **Step 4: `make check`** → clean.

- [ ] **Step 5: `docker compose up -d` smoke** — the stack boots (default `up`, no `:?` abort); `alfred-core` healthy; Prometheus scrapes `up{job="alfred-core"}==1`; Grafana reachable per platform.

- [ ] **Step 6: Fail-closed credential smoke (rev.3)** — with `GF_SECURITY_ADMIN_PASSWORD` blanked in `.env`, `docker compose up -d` must still bring up **every other service** (no `:?`-style abort on `up`, `ps`, `logs`, or `down`) while `alfred-grafana` exits 78 with the refusal in `docker compose logs alfred-grafana`. Restore the seeded value, `docker compose up -d alfred-grafana`, and confirm Grafana serves and rejects `admin:admin` (401).

---

## Self-Review

**Spec coverage (§6 + §7):** §6.1 Prometheus + rules → Tasks 1+2; §6.2 Grafana default-on + `:-` password + access → Tasks 3+4+8; §6.2a credential fail-closed layer → Task 3 Steps 1/3/4c + Task 6 Step 3 + Task 8 Step 6; §6.3 compose-invariant tests → Tasks 1+3; §6.4 caveat reframe → Task 6; §6.5 operator doc + README + (human-gated) CLAUDE.md flag → Task 6 (+ the CLAUDE.md entry stays a flagged human-gated follow-up, NOT applied); §7 ADR amendment → Task 7 (PR2's third-party-services arm only; the Decision-1 class-line + residual (viii) landed in PR1); §9 e2e scrape test + promtool + OrbStack smoke → Tasks 2+5+8.

**Type/name consistency:** the scrape target `alfred-core:9465` matches PR1's `ALFRED_CORE_METRICS_PORT` default; `core.yml`/`core_test.yml` names align; `alfred_prom_data`/`alfred_grafana_data` volumes declared once and mounted once.

**Placeholders:** image tags say "pin the exact current tag at implementation" (a deliberate instruction, not a TBD); the dashboard JSON + `ci.yml` diff + testcontainers fixture are described by role for the implementer's tree.

**Human-gated guard:** any genuinely-pending PRD §4/§7.5 clarification stays human-gated and is NOT edited by this plan. **rev.4 (docs-001/arch-003):** the CLAUDE.md `alfred daemon healthcheck` command-table row is NOT a pending item — it already landed in PR1/#481 (`.rulesync/rules/CLAUDE.md:106`); PR2 leaves CLAUDE.md untouched.

**Known residual — PRD §4 criterion 9 partially met (rev.4, arch-001):** Grafana ships default-on citing criterion 9 ("the default dashboard shows tokens-by-tier-and-persona, cache hit rates, plugin error rates, security events"), but PR2's starter dashboard delivers only **security-events + partial plugin-health**. The token/cost/tier/persona and cache-hit panels require provider/caching/persona metrics that are **not** in `CORE_OWNED_COLLECTORS` and land with a later slice. This is recorded (here + spec §10) so criterion 9 is NOT mis-tracked as fully closed by #470; the default-on justification must not imply the criterion is met.

---

## rev.1 fold log (8-lane plan-review)

**High** — e2e testcontainers fixture spelled out: the stub MUST be aliased `alfred-core:9465` and Prometheus MUST mount BOTH `prometheus.yml` and `ops/alerts/` (Task 5, else zero rules / vacuous assertion); the no-silently-dead-alerts cross-check is `tests/unit/test_ops_scaffold.py` (a pytest test, gateway-hardcoded), NOT a ci.yml diff — concrete core extension added (Task 2 Step 5); `docs/subsystems/security.md:452-453` added to the caveat reframe (Task 6 Step 0/1).
**Medium** — `absent()` alert now has promtool positive+negative controls (Task 2 Step 3); Grafana password seed guards on present-AND-non-empty and replaces in place, since `cp .env.example .env` makes the key present-but-empty (Task 3 Step 4, sec-004/devops-004); port contract reconciled — the scrape target is a literal 9465, an override must be mirrored (Task 2 note + PR1 Task 6 note); the 4th runbook target ("Detecting it today / Both work without Prometheus") added to the reframe (Task 6 Step 2, docs-002).
**Low** — Grafana dashboards mount is a dedicated `ops/grafana/dashboards/` subdir (not all of ops/grafana, which holds provisioning/) + `git mv gateway.json` into it (Task 3/4, devops-006); ADR amendment carries a concrete date `2026-07-21` + residual `(viii)` (Task 7, docs-004).
**Verified sound (no change):** compose blocks valid + internal-only, `:-` empty password boots on Grafana 11, `prom/prometheus` ships wget for `/-/healthy`, promtool `up==0` schema valid, `#470` opens no egress.

## rev.2 fold log (PR #480 review — documentation wave)

Applied to this plan while PR1 was in review, so PR2 does not inherit known-bad steps:

- **Port contract disambiguated** — `ALFRED_CORE_METRICS_PORT` is declared a bind-port seam, NOT an
  operator knob; 9465 is fixed for the bundled stack. Compose comment, spec §5.5, and both plans now
  state it identically (Task 2 Step 1 note).
- **Task 5 stub container made persistent** — the drafted `python -c` command only *imported*
  `http.server` and exited, so the `alfred-core` alias resolved to a dead container and
  `up{job="alfred-core"}` would have been 0. Replaced with a long-lived `HTTPServer` on
  `0.0.0.0:9465` answering `GET /metrics`.
- **Task 5 rule assertion refreshed** — asserts this PR's new `AlfredCoreMetricsDown` /
  `AlfredQuarantineCounterAbsent` rules (keeping `QuarantineCapabilityRevoked` and the `up` query).
- **Two `git add` omissions fixed** — Task 2 Step 6 += `tests/unit/test_ops_scaffold.py`; Task 6
  Step 5 += `docs/subsystems/security.md`.
- **Grafana credential hardened** — the `:-` arm stays empty (a literal default would be substituted
  verbatim into a predictable admin password) + a REQUIRED seed-guard regression test (Task 3 Step 4b:
  empty replaced, non-empty preserved, no duplicate key).
- **Task 7 de-double-claimed** — PR1 landed the ADR-0040 Decision-1 class-line + residual (viii);
  Task 7 now owns only the third-party-services arm.

## rev.3 fold log (PR #480 CodeRabbit cloud review — documentation wave 3)

- **Major/security — Grafana admin credential (Task 3).** The rev.2 rationale ended with a claim that
  an empty `GF_SECURITY_ADMIN_PASSWORD` "fails closed". Measured against `grafana/grafana:11.6.0` on
  2026-07-21, that is **false**: the empty env value is ignored, `defaults.ini`'s
  `admin_password = admin` applies, the container starts, and `admin:admin` authenticates (200). The
  residual CR pointed at is real — an operator who skips `bin/alfred-setup.sh` gets a Grafana on the
  best-known credential in existence. Added a **third layer**: an `entrypoint:` preflight guard that
  refuses (exit 78, actionable stderr) when the password is unset, empty, or the literal `admin`,
  plus a compose-shape invariant (Step 1) and a REQUIRED real-execution test with an
  `admin:admin`→401 non-vacuity control (Step 4c), an operator troubleshooting entry (Task 6 Step 3),
  and a fail-closed smoke (Task 8 Step 6). `:-` and the setup-script seed are unchanged, and the
  reason `:?` is **not** the fix (Compose interpolates before profile filtering → every
  `docker compose` verb aborts) is now recorded next to the guard so it is not "fixed" back.
- **Major/stability — Task 5 fixed sleep.** `time.sleep(3)` before probing replaced with
  `_wait_for_first_scrape()`: bounded polling (0.25s interval, 60s deadline) on
  `/api/v1/targets` until the alfred-core target's `health != "unknown"`. Gating on a *completed
  scrape attempt* rather than on `up == 1` keeps the test's oracle in the test — a dead stub fails
  the assertion, not the fixture.
- **Minor/stability — Task 5 HTTP timeouts (applied, with one correction to the finding).** All
  probes (`/api/v1/targets`, `/api/v1/rules`, `/api/v1/query`) now pass an explicit
  `timeout=_PROBE_TIMEOUT_S`. The finding's premise — "can hang indefinitely" — is **not accurate for
  httpx**: 0.28.1 (the pinned version) defaults to `Timeout(5.0)` on every operation, verified in the
  repo venv. The change is kept anyway because the value belongs next to the readiness deadline it
  interacts with, and an explicit timeout cannot be changed out from under the test by a library
  default or a differently-configured client.
- **Spec-side (same wave):** fetch-helper name/signature aligned to the shipped
  `fetch_metrics_text(port)`, and the Grafana dashboards mount aligned to the dedicated
  `ops/grafana/dashboards` subdir this plan already used (devops-006). See the spec's §14.

## rev.4 fold log (6-lane `/review-plan` fleet — 0 Critical)

Fleet: architect, reviewer, test-engineer, security-engineer, devops-engineer, docs-reviewer.
The **design was verified sound** — connectivity-free `internal:true` pinning (exact `== {"alfred_internal"}`),
entrypoint guard shell (`$$`/`-ec`/`exit 78`/`exec /run.sh`), `sed -i.bak` BSD-safety, `/run.sh` as
grafana:11.6.0's canonical entrypoint, busybox `wget`, mount-over-mount ordering, `/metrics` as untagged
internal telemetry, and the ADR PR1/PR2 de-double-claim all hold. Every fix below is **test fidelity**.

**High (fix before executing):**

- **`$$` extraction bug in the fail-closed test [test-004 + devops-001, CORROBORATED]** — Task 3 Step 4c.
  `yaml.safe_load` keeps compose's `$$` escape; run outside compose, `$$`→PID and the guard proves nothing.
  Fixed: extract the interpolated entrypoint via `docker compose config`, assert byte-equality; never run
  the raw YAML string through a bare shell, never hand-de-escape the guard.
- **`git mv gateway.json` orphans two live tests [rev-001 + test-001, CORROBORATED]** — Task 4 Step 3.
  `test_ops_scaffold.py:126,196` read the old path → `make check` reddens at Task 8. Fixed: rewrite both
  refs in the same step, run pytest before commit, widen Step 4's `git add`.
- **Task 2 Step 5 `...` cross-check under-specified AND wrong [test-005 + rev-004 + sec-003 + devops-007,
  CORROBORATED ×4]** — `_name` is `_total`-stripped, so `{c._name}` matches neither core metric; gateway
  regex doesn't transfer. Fixed: concrete `alfred_[a-z0-9_]*` resolver + `{name, name+"_total"}` expansion +
  `{"up"}` allowlist + independent-literal oracle + mutation-check note.
- **Grafana seed test uncommitted + vacuity-prone [rev-002 + test-003, CORROBORATED; devops-003, sec-005]** —
  Task 3 Step 4b/4/6. Fixed: staged the test in Step 6; mandated real execution (sourceable fn /
  `ALFRED_SETUP_ENV_FILE` seam), forbade a grep-only oracle, specified the credential-gate bypass; corrected
  the inaccurate "mirror audit.hash_pepper" framing, pinned placement (after `.env` create, before the gate),
  added the `command -v openssl` graceful check.
- **No dashboard/provisioning validity test [test-002 + test-006]** — Task 4 Step 3b (new): a core-dashboard
  metric-reference test (reusing the Step 5 resolver) + a provisioning-YAML test (datasource url ==
  `alfred-prometheus:9090`, provider path == the mount).

**Medium:**

- **Prometheus image two-place drift [arch-005 + rev-003 + devops-002, CORROBORATED]** — Task 5 fixture now
  resolves the image from `docker-compose.yaml` (+ `import yaml`).
- **9465 compose↔prometheus.yml drift guard [arch-002]** — Task 2 Step 1: ~6-line invariant test asserting
  the scrape-target port equals the compose `ALFRED_CORE_METRICS_PORT` default (+ gateway 9464 pair); staged
  in Task 2 Step 6 (needs the scrape job this task adds).
- **No `remote_write`/`remote_read` guard [sec-001]** — Task 1 Step 1: config-file assertion over parsed
  `prometheus.yml` (the command-flag test only checks the compose `command:` array).
- **Stale CLAUDE.md follow-up claim [docs-001 + arch-003, CORROBORATED]** — the `alfred daemon healthcheck`
  row already landed in PR1/#481; corrected the Global Constraints + Self-Review framing (still: don't edit
  CLAUDE.md). **Second ADR promissory note [docs-002]** — Task 7 now updates BOTH "deferred to PR2" sentences
  (incl. ADR-0040:347-351).
- **PRD §4 criterion-9 over-claim [arch-001, requires_human_judgment]** — recorded a residual in Self-Review
  (+ spec §10): criterion 9 is only partially met (security-events + plugin-health); token/tier/persona +
  cache-hit panels need metrics not yet in `CORE_OWNED_COLLECTORS`.

**Low / punch-list:**

- **CI: `promtool test` not just `check` [arch-004]** — Task 2 Step 5 (else the `core_test.yml` controls never run).
- **security.md: drop the WHOLE inverted sentence [docs-004]** — Task 6 Step 1 (not just the "not scraped yet" fragment).
- **Reframe grep excluded `tests/` [docs-003]** — Task 6 Step 0 widened; `test_quarantine_revocation_metric.py:73-74` message refreshed + staged.
- **Stale `prometheus.yml` scaffold header [devops-004]** — Task 2 Step 1 refresh.
- **exit-78 arms need the docker SDK, not `DockerContainer.start()` [devops-005]** — Task 3 Step 4c fixture note.
- **`__FILE` secret-convention non-support [sec-004]** — documented in `observability-stack.md` (Task 6 Step 3).
- **`openssl` preflight + optional lock [sec-005]** — folded into the Task 3 Step 4 seed.
- **Task 8 uncommitted doc change [rev-005]** — Task 8 Step 1 gets its own commit.
- **observability.py edit is docstring-only [test-007]** — noted in Task 6 Step 1 (coverage satisfied by inspection).
- **Integration-lane flake [test-008]** — Task 3 Step 4c shares the Grafana image pull across the three arms.

**Disputed → resolved [sec-002 vs devops-006]:** the integration tests **error** (not silently skip) when
Docker is absent on the required lane, so they are NOT paper gates as written (devops verified against
`ci.yml` + conftest). Remedy folded into Task 3 Step 4c / Task 5: keep them plain `integration`; add an
assert-RAN guard (#245-style) only IF a docker-skip is ever introduced; and re-measure the `exec /run.sh`
base-image coupling on every Grafana tag bump (sec-002).
