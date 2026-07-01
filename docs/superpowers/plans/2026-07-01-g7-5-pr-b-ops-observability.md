# G7-5 PR-B — Egress-plane ops observability Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the PR-A egress metric families operator-observable — a Grafana dashboard view + 5 Prometheus alerts, gated by an extended ops-scaffold AST test and a promtool check+test suite.

**Architecture:** Ops-only, plus one small metric-hygiene `src/` fix (the sec-355-1 deny-counter pre-init, folded in per a PR-B review finding so the alert's correctness ships with it). Extend `tests/unit/test_ops_scaffold.py` so its metric-name derivation sees the custom-collector / module-const egress metrics and add a reason-label-value ⊆ enum guard; add 5 rules to `ops/alerts/gateway.yml` + 2 panels to `ops/grafana/gateway.json`; add a promtool `test rules` file + a CI job that installs promtool and runs `check rules` + `test rules`.

**Tech Stack:** Prometheus alerting rules (YAML), Grafana dashboard (JSON), `promtool` (Prometheus toolchain), pytest + `ast`/`yaml`/`json`, GitHub Actions.

## Global Constraints

- **One `src/alfred/` change only** — the sec-355-1 deny-counter pre-init in `egress_metrics.py` (metric hygiene the critical alert requires). PR-A still owns the metric contract; PR-B adds no new families.
- **Consumed metrics:** `gateway_egress_inflight{plane}` (via `GaugeMetricFamily(_INFLIGHT_NAME,…)`, `_INFLIGHT_NAME: Final[str] = "gateway_egress_inflight"`); `gateway_egress_denied_total{plane,reason}` (via `Counter(_DENIED_NAME,…)`, `_DENIED_NAME: Final[str] = "gateway_egress_denied_total"`). Both in `src/alfred/gateway/egress_metrics.py`.
- **Pre-existing (already string-literal Counters, already in the known set):** `gateway_egress_connect_total{outcome}` (`egress_proxy.py:86`), `gateway_egress_relay_total{outcome}` (`egress_relay_audit.py:89`). Outcome values used in source: `error`, `allowed`/`forwarded`, `denied`.
- **Reason enums:** `EgressDenyReason` (`src/alfred/gateway/egress_audit.py`, `enum.Enum`, 4 values); `EgressRelayDenyReason` (`src/alfred/egress/relay_protocol.py`, `enum.StrEnum`, 8 values). Member `.value`s are the label strings.
- **Regex matchers use a BARE `|`** in the YAML (alternation), never `\|` (a literal-pipe match → alert fails-open). Single-quote the `expr` so it embeds the `"`.
- **Alert set (5), `alfred-gateway` group:** `GatewayEgressDenyRate` (warning), `GatewayEgressInflightSaturation` (warning), `GatewayEgressSecurityDenySpike` (critical), `GatewayEgressExfilSpike` (critical), `GatewayEgressOutage` (warning).
- **Conventional Commits** with `#333` in EVERY commit subject (the CI regex rejects a digit-in-type, so no `i18n(...)`-style type). `make check`-relevant: `uv run ruff check`/`format` on touched Python; `uv run pytest tests/unit/test_ops_scaffold.py -q` green; markdownlint clean on any `.md`. Never `--no-verify`.
- **Spec:** `docs/superpowers/specs/2026-07-01-g7-5-pr-b-ops-observability-design.md`.

---

### Task 1: Extend the ops-scaffold AST derivation + reason-value helper

**Files:**

- Modify: `tests/unit/test_ops_scaffold.py`

**Interfaces:**

- Produces: `_metric_names_in(path)` now also recognises `GaugeMetricFamily(` and resolves a first-arg `ast.Name` via a module const map (from `ast.Assign` + `ast.AnnAssign` string constants). New helper `_known_reason_values() -> set[str]` returning `{r.value for r in EgressDenyReason} | {r.value for r in EgressRelayDenyReason}`.

- [ ] **Step 1: Write the failing test**

Add to `tests/unit/test_ops_scaffold.py`:

```python
def test_egress_custom_collector_metrics_are_derivable() -> None:
    # gateway_egress_inflight (GaugeMetricFamily via _INFLIGHT_NAME const) and
    # gateway_egress_denied_total (Counter via _DENIED_NAME const) must be visible to
    # the derivation, else PR-B's egress alerts/panels fail the referenced<=known check.
    known = _known_metric_bases()
    assert "gateway_egress_inflight" in known
    assert "gateway_egress_denied_total" in known


def test_known_reason_values_cover_both_enums() -> None:
    vals = _known_reason_values()
    assert "canary_tripped" in vals  # EgressRelayDenyReason
    assert "malformed_connect" in vals  # EgressDenyReason
    assert "destination_not_allowlisted" in vals  # both
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/unit/test_ops_scaffold.py::test_egress_custom_collector_metrics_are_derivable -q`
Expected: FAIL (`gateway_egress_inflight` not in the derived set — `GaugeMetricFamily` unrecognised + const-named args unresolved); `_known_reason_values` NameError.

- [ ] **Step 3: Extend `_metric_names_in` + add the reason helper**

Replace the constructor set and `_metric_names_in`, and add the reason helper. In `test_ops_scaffold.py`:

```python
# GaugeMetricFamily is how a custom collector emits a Gauge (gateway_egress_inflight);
# CounterMetricFamily is intentionally NOT listed — it is unused in source.
_PROMETHEUS_CTORS = frozenset({"Counter", "Gauge", "Histogram", "GaugeMetricFamily"})


def _module_str_consts(tree: ast.Module) -> dict[str, str]:
    # Resolve module-level string constants bound via `X = "..."` (ast.Assign) OR
    # `X: Final[str] = "..."` (ast.AnnAssign) so a ctor called with a Name first-arg
    # (e.g. Counter(_DENIED_NAME, ...)) is derivable, not silently skipped.
    consts: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant):
            if isinstance(node.value.value, str):
                for tgt in node.targets:
                    if isinstance(tgt, ast.Name):
                        consts[tgt.id] = node.value.value
        elif isinstance(node, ast.AnnAssign) and isinstance(node.value, ast.Constant):
            if isinstance(node.target, ast.Name) and isinstance(node.value.value, str):
                consts[node.target.id] = node.value.value
    return consts


def _metric_names_in(path: Path) -> set[str]:
    names: set[str] = set()
    tree = ast.parse(path.read_text())
    consts = _module_str_consts(tree)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or _call_name(node.func) not in _PROMETHEUS_CTORS:
            continue
        if not node.args:
            continue
        arg = node.args[0]
        metric_name: str | None = None
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            metric_name = arg.value
        elif isinstance(arg, ast.Name):
            metric_name = consts.get(arg.id)
        if metric_name is not None and _METRIC_REF_RE.fullmatch(metric_name):
            names.add(metric_name)
    return names
```

Add the reason helper (near `_known_metric_bases`):

```python
def _known_reason_values() -> set[str]:
    # Import at call time to keep module import cheap + avoid a hard dep at collection.
    from alfred.egress.relay_protocol import EgressRelayDenyReason
    from alfred.gateway.egress_audit import EgressDenyReason

    return {r.value for r in EgressDenyReason} | {r.value for r in EgressRelayDenyReason}
```

- [ ] **Step 4: Run to verify it passes**

Run: `uv run pytest tests/unit/test_ops_scaffold.py -q`
Expected: PASS (all existing tests + the 2 new ones). `uv run ruff check tests/unit/test_ops_scaffold.py && uv run ruff format --check tests/unit/test_ops_scaffold.py` clean.

- [ ] **Step 5: Commit**

```bash
git add tests/unit/test_ops_scaffold.py
git commit -m "test(ops): derive custom-collector + const-named egress metrics in ops-scaffold (#333)"
```

---

### Task 2: Add the 5 egress alerts + presence + reason-label-value guard

**Files:**

- Modify: `ops/alerts/gateway.yml`
- Modify: `tests/unit/test_ops_scaffold.py`

**Interfaces:**

- Consumes: `_known_reason_values()`, `_known_metric_bases()` (Task 1).

- [ ] **Step 1: Write the failing tests**

Add to `tests/unit/test_ops_scaffold.py`:

```python
_EGRESS_ALERTS = frozenset({
    "GatewayEgressDenyRate",
    "GatewayEgressInflightSaturation",
    "GatewayEgressSecurityDenySpike",
    "GatewayEgressExfilSpike",
    "GatewayEgressOutage",
})


def test_egress_alerts_present() -> None:
    cfg = yaml.safe_load((OPS / "alerts" / "gateway.yml").read_text())
    names = {r["alert"] for g in cfg["groups"] for r in g["rules"] if "alert" in r}
    assert _EGRESS_ALERTS <= names


def test_alert_reason_labels_are_real_enum_values() -> None:
    # The critical pager selects on reason label VALUES via reason=~/reason= matchers;
    # a typo or enum rename would silently fail it open. Assert every alternative is real.
    cfg = yaml.safe_load((OPS / "alerts" / "gateway.yml").read_text())
    known = _known_reason_values()
    reason_re = re.compile(r'reason(?:=~|=)"([^"]+)"')
    for r in (r for g in cfg["groups"] for r in g["rules"] if "alert" in r):
        for match in reason_re.findall(r["expr"]):
            for alt in match.split("|"):  # bare-| alternation; a lone value has no |
                assert alt in known, f"alert {r['alert']} references unknown reason: {alt!r}"
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/unit/test_ops_scaffold.py::test_egress_alerts_present -q`
Expected: FAIL (the 5 alerts are not yet in `gateway.yml`).

- [ ] **Step 3: Add the 5 alert rules**

Append to the `rules:` list under the `alfred-gateway` group in `ops/alerts/gateway.yml` (note the single-quoted `expr` with a BARE `|`):

```yaml
      # Spec C G7-5 PR-B (#333): egress-plane alerting over the PR-A metric families.
      - alert: GatewayEgressDenyRate
        expr: rate(gateway_egress_denied_total[5m]) > 0
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "AlfredOS gateway is denying egress"
          description: "gateway_egress_denied_total{plane,reason} is increasing for 5m; a client/tool/adapter is repeatedly hitting the default-deny egress allowlist. Inspect the plane + reason breakdown."
      - alert: GatewayEgressInflightSaturation
        expr: gateway_egress_inflight > 100
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "AlfredOS gateway egress in-flight is high"
          description: "gateway_egress_inflight{plane} > 100 concurrent CONNECT tunnels for 5m. NOTE: egress in-flight has no hard cap; 100 is a conservative STARTING threshold — tune it to your deployment's baseline."
      - alert: GatewayEgressSecurityDenySpike
        expr: 'rate(gateway_egress_denied_total{reason=~"literal_ip_target|resolved_ip_not_global|canary_tripped|dlp_redacted"}[5m]) > 0'
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "AlfredOS gateway refused a security-relevant egress"
          description: "A zero-baseline security deny is occurring: SSRF (literal_ip_target / resolved_ip_not_global), a canary trip (active exfil probe), or a DLP catch (dlp_redacted). Treat as a possible active attack."
      - alert: GatewayEgressExfilSpike
        expr: 'rate(gateway_egress_denied_total{reason="destination_not_allowlisted"}[5m]) > 0.1'
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "AlfredOS gateway is refusing a burst of non-allowlisted egress"
          description: "gateway_egress_denied_total{reason=destination_not_allowlisted} rate > 0.1/s for 2m. A burst of denials to non-allowlisted (globally-routable) destinations is the realistic data-exfil signal (POST to an attacker domain). NOTE: 0.1/s is a conservative STARTING threshold — tune to baseline; the warning-tier GatewayEgressDenyRate still catches the trickle."
      - alert: GatewayEgressOutage
        expr: rate(gateway_egress_connect_total{outcome="error"}[5m]) > 0 or rate(gateway_egress_relay_total{outcome="error"}[5m]) > 0
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "AlfredOS gateway egress is erroring"
          description: "gateway_egress_{connect,relay}_total{outcome=error} is increasing for 5m; the egress plane is failing to complete tunnels/fetches. A sustained outage can itself suppress deny-counting, blinding the security alerts — investigate promptly."
```

- [ ] **Step 4: Run to verify it passes**

Run: `uv run pytest tests/unit/test_ops_scaffold.py -q`
Expected: PASS (presence + the reason-label-value guard + the existing `referenced <= known` alert check all green — `gateway_egress_denied_total`/`connect_total`/`relay_total`/`inflight` are all known via Task 1 + the pre-existing literals).

- [ ] **Step 5: Commit**

```bash
git add ops/alerts/gateway.yml tests/unit/test_ops_scaffold.py
git commit -m "feat(ops): egress-plane Prometheus alerts (deny-rate, saturation, security/exfil spike, outage) (#333)"
```

---

### Task 3: Add the 2 egress dashboard panels

**Files:**

- Modify: `ops/grafana/gateway.json`
- Modify: `tests/unit/test_ops_scaffold.py`

- [ ] **Step 1: Write the failing test**

Add to `tests/unit/test_ops_scaffold.py`:

```python
def test_egress_panels_present() -> None:
    dash = json.loads((OPS / "grafana" / "gateway.json").read_text())
    exprs = {t.get("expr") for p in dash["panels"] for t in p.get("targets", [])}
    assert "gateway_egress_inflight" in exprs
    assert "rate(gateway_egress_denied_total[5m])" in exprs
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/unit/test_ops_scaffold.py::test_egress_panels_present -q`
Expected: FAIL (panels not present).

- [ ] **Step 3: Add the 2 panels**

Append to the `panels` array in `ops/grafana/gateway.json` (no `datasource` key — match the existing panels; ids 11/12 continue the sequence; `gridPos.y=36` is the next row below the current bottom row at y=28):

```json
    {
      "id": 11,
      "title": "Egress in-flight (per plane)",
      "type": "timeseries",
      "gridPos": { "h": 8, "w": 12, "x": 0, "y": 36 },
      "targets": [
        { "expr": "gateway_egress_inflight", "legendFormat": "{{plane}}" }
      ]
    },
    {
      "id": 12,
      "title": "Egress denials (rate, per plane/reason)",
      "type": "timeseries",
      "gridPos": { "h": 8, "w": 12, "x": 12, "y": 36 },
      "targets": [
        { "expr": "rate(gateway_egress_denied_total[5m])", "legendFormat": "{{plane}} / {{reason}}" }
      ]
    }
```

- [ ] **Step 4: Run to verify it passes**

Run: `uv run pytest tests/unit/test_ops_scaffold.py -q`
Expected: PASS (panels present + `test_gateway_dashboard_parses_and_references_real_metrics` still green — both exprs reference known series). Confirm the JSON still parses: `python3 -c "import json; json.load(open('ops/grafana/gateway.json'))"`.

- [ ] **Step 5: Commit**

```bash
git add ops/grafana/gateway.json tests/unit/test_ops_scaffold.py
git commit -m "feat(ops): egress in-flight + deny-rate Grafana panels (#333)"
```

---

### Task 4: promtool check + test rules + CI job

**Files:**

- Create: `ops/alerts/gateway_test.yml`
- Modify: `.github/workflows/ci.yml`

**Interfaces:**

- Consumes: `ops/alerts/gateway.yml` (Task 2).

- [x] **Step 1: Write the promtool test file (the "failing test" — it fails until the rules exist, which they now do)**

Create `ops/alerts/gateway_test.yml`. Window math: `interval: 1m` with 10 samples spans 9m; `eval_time` past each alert's `for` window with ≥2 samples inside `rate([5m])`. Each "quiet" negative is anchored by a genuinely-firing positive control. `exp_annotations` must match the alert's summary+description verbatim — YAML-anchored (`&name` / `*name`) to avoid drift.

The shipped file also includes two additional cases (sec-355-1 / FIX-3):

- **First-occurrence (sec-355-1):** series `0 0 0 1 1 1 1 1 1 1` (pre-init 0 baseline, single 0→1 deny). Window math: rate([5m]) at eval_time=7m covers [2m,7m] (samples t=2m(0), t=3m(1)…t=7m(1)), non-zero; for:2m satisfied since t=5m. eval_time=8m would have rate=0 (window [3m,8m] is flat at 1 — the 0 baseline is outside the 5m window).
- **Relay outage disjunct (FIX-3):** exercises the `or rate(gateway_egress_relay_total{outcome="error"}...)` branch of `GatewayEgressOutage`.

```yaml
# promtool test rules for ops/alerts/gateway.yml (Spec C G7-5 PR-B, #333).
# NOTE: promtool matches exp_annotations too (not just exp_labels) — each firing entry's
# exp_annotations MUST equal the alert's summary+description in gateway.yml verbatim. The
# repeated blocks below are YAML-anchored (&name / *name) so they are written once.
rule_files:
  - gateway.yml

evaluation_interval: 1m

tests:
  # --- security-spike fires on EACH reason in its set (a typo in any is caught) ---
  - interval: 1m
    input_series:
      - series: 'gateway_egress_denied_total{plane="relay",reason="canary_tripped"}'
        values: '0 1 2 3 4 5 6 7 8 9'
      - series: 'gateway_egress_denied_total{plane="proxy",reason="literal_ip_target"}'
        values: '0 1 2 3 4 5 6 7 8 9'
      - series: 'gateway_egress_denied_total{plane="proxy",reason="resolved_ip_not_global"}'
        values: '0 1 2 3 4 5 6 7 8 9'
      - series: 'gateway_egress_denied_total{plane="relay",reason="dlp_redacted"}'
        values: '0 1 2 3 4 5 6 7 8 9'
    alert_rule_test:
      - eval_time: 8m
        alertname: GatewayEgressSecurityDenySpike
        exp_alerts:
          - exp_labels: { severity: critical, plane: relay, reason: canary_tripped }
            exp_annotations: &sec_ann
              summary: "AlfredOS gateway refused a security-relevant egress"
              description: "A zero-baseline security deny is occurring: SSRF (literal_ip_target / resolved_ip_not_global), a canary trip (active exfil probe), or a DLP catch (dlp_redacted). Treat as a possible active attack."
          - exp_labels: { severity: critical, plane: proxy, reason: literal_ip_target }
            exp_annotations: *sec_ann
          - exp_labels: { severity: critical, plane: proxy, reason: resolved_ip_not_global }
            exp_annotations: *sec_ann
          - exp_labels: { severity: critical, plane: relay, reason: dlp_redacted }
            exp_annotations: *sec_ann

  # --- security-spike STAYS QUIET on a routine allowlist-miss; DenyRate fires (positive control) ---
  - interval: 1m
    input_series:
      - series: 'gateway_egress_denied_total{plane="proxy",reason="destination_not_allowlisted"}'
        values: '0 1 2 3 4 5 6 7 8 9'
    alert_rule_test:
      - eval_time: 8m
        alertname: GatewayEgressSecurityDenySpike
        exp_alerts: []
      - eval_time: 8m
        alertname: GatewayEgressDenyRate
        exp_alerts:
          - exp_labels: { severity: warning, plane: proxy, reason: destination_not_allowlisted }
            exp_annotations: &deny_ann
              summary: "AlfredOS gateway is denying egress"
              description: "gateway_egress_denied_total{plane,reason} is increasing for 5m; a client/tool/adapter is repeatedly hitting the default-deny egress allowlist. Inspect the plane + reason breakdown."

  # --- exfil-spike fires above the 0.1/s threshold (10/min ≈ 0.167/s) ---
  - interval: 1m
    input_series:
      - series: 'gateway_egress_denied_total{plane="proxy",reason="destination_not_allowlisted"}'
        values: '0 10 20 30 40 50 60 70 80 90'
    alert_rule_test:
      - eval_time: 8m
        alertname: GatewayEgressExfilSpike
        exp_alerts:
          - exp_labels: { severity: critical, plane: proxy, reason: destination_not_allowlisted }
            exp_annotations:
              summary: "AlfredOS gateway is refusing a burst of non-allowlisted egress"
              description: "gateway_egress_denied_total{reason=destination_not_allowlisted} rate > 0.1/s for 2m. A burst of denials to non-allowlisted (globally-routable) destinations is the realistic data-exfil signal (POST to an attacker domain). NOTE: 0.1/s is a conservative STARTING threshold — tune to baseline; the warning-tier GatewayEgressDenyRate still catches the trickle."

  # --- exfil-spike QUIET below threshold (3/min ≈ 0.05/s); DenyRate fires (positive control) ---
  - interval: 1m
    input_series:
      - series: 'gateway_egress_denied_total{plane="proxy",reason="destination_not_allowlisted"}'
        values: '0 3 6 9 12 15 18 21 24 27'
    alert_rule_test:
      - eval_time: 8m
        alertname: GatewayEgressExfilSpike
        exp_alerts: []
      - eval_time: 8m
        alertname: GatewayEgressDenyRate
        exp_alerts:
          - exp_labels: { severity: warning, plane: proxy, reason: destination_not_allowlisted }
            exp_annotations: *deny_ann

  # --- inflight saturation fires above 100, quiet below ---
  - interval: 1m
    input_series:
      - series: 'gateway_egress_inflight{plane="proxy"}'
        values: '0 50 101 101 101 101 101 101 101 101'
      - series: 'gateway_egress_inflight{plane="relay"}'
        values: '0 10 90 90 90 90 90 90 90 90'
    alert_rule_test:
      - eval_time: 8m
        alertname: GatewayEgressInflightSaturation
        exp_alerts:
          - exp_labels: { severity: warning, plane: proxy }
            exp_annotations:
              summary: "AlfredOS gateway egress in-flight is high"
              description: "gateway_egress_inflight{plane} > 100 concurrent CONNECT tunnels for 5m. NOTE: egress in-flight has no hard cap; 100 is a conservative STARTING threshold — tune it to your deployment's baseline."

  # --- security-spike fires on a first-occurrence deny (pre-init 0 baseline, then 0→1 flat) ---
  # sec-355-1 (#333): without pre-init the series appears at t=3m with value=1 and
  # rate([5m]) is 0 (flat-at-1, no baseline). With pre-init the 0→1 rise is visible.
  # eval_time=7m: window [2m,7m] contains the 0→1 transition; for:2m satisfied since t=5m.
  - interval: 1m
    input_series:
      - series: 'gateway_egress_denied_total{plane="relay",reason="canary_tripped"}'
        values: '0 0 0 1 1 1 1 1 1 1'
    alert_rule_test:
      - eval_time: 7m
        alertname: GatewayEgressSecurityDenySpike
        exp_alerts:
          - exp_labels: { severity: critical, plane: relay, reason: canary_tripped }
            exp_annotations: *sec_ann

  # --- outage fires on a sustained connect_total error rate ---
  - interval: 1m
    input_series:
      - series: 'gateway_egress_connect_total{outcome="error"}'
        values: '0 1 2 3 4 5 6 7 8 9'
    alert_rule_test:
      - eval_time: 8m
        alertname: GatewayEgressOutage
        exp_alerts:
          - exp_labels: { severity: warning, outcome: error }
            exp_annotations: &outage_ann
              summary: "AlfredOS gateway egress is erroring"
              description: "gateway_egress_{connect,relay}_total{outcome=error} is increasing for 5m; the egress plane is failing to complete tunnels/fetches. A sustained outage can itself suppress deny-counting, blinding the security alerts — investigate promptly."

  # --- outage fires on the relay_total{outcome=error} disjunct (tests the 'or' branch) ---
  - interval: 1m
    input_series:
      - series: 'gateway_egress_relay_total{outcome="error"}'
        values: '0 1 2 3 4 5 6 7 8 9'
    alert_rule_test:
      - eval_time: 8m
        alertname: GatewayEgressOutage
        exp_alerts:
          - exp_labels: { severity: warning, outcome: error }
            exp_annotations: *outage_ann
```

- [x] **Step 2: Install promtool + run it locally to verify**

Install promtool (choose per platform): `brew install prometheus` (macOS) OR download from `https://github.com/prometheus/prometheus/releases` and put `promtool` on PATH.

Run (from `ops/alerts/`):

```bash
cd ops/alerts && promtool check rules gateway.yml && promtool test rules gateway_test.yml
```

Expected: `SUCCESS` for check-rules and `PASSED` for all unit tests. If any `exp_alerts` mismatch, fix the window math / labels (NOT by loosening an assertion to `[]`).

- [x] **Step 3: Verify the negative control (bare-| guard)**

Temporarily change the `GatewayEgressSecurityDenySpike` expr's `|` to `\|` and re-run `promtool test rules gateway_test.yml`. Expected: the security-spike fire cases FAIL (matcher now matches a literal-pipe reason → no series → no alert). This proves the test catches the fail-open regex. Revert the `\|` back to `|` before committing.

- [x] **Step 4: Add the CI job**

Add a job to `.github/workflows/ci.yml` (mirror the sibling jobs: `actions/checkout@v4`, a job-level `permissions: contents: read` — the `python` job pins this and it's what the required `Zizmor` check enforces). The Install step downloads to a temp file, verifies the sha256 before extracting (FIX-2 integrity check), and keeps `set -euo pipefail`:

```yaml
  ops-promtool:
    name: promtool (alert rules)
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v4
      - name: Install promtool
        run: |
          set -euo pipefail
          PROM_VERSION=2.53.0
          curl --fail -sSL -o prometheus.tar.gz \
            "https://github.com/prometheus/prometheus/releases/download/v${PROM_VERSION}/prometheus-${PROM_VERSION}.linux-amd64.tar.gz"
          echo "d9900a11e3c89261e6416e3c9989858bad7b206af8b6838dfe9a5392d8ddc60d  prometheus.tar.gz" | sha256sum -c -
          tar xzf prometheus.tar.gz
          sudo mv "prometheus-${PROM_VERSION}.linux-amd64/promtool" /usr/local/bin/promtool
      - name: Validate + unit-test the gateway alert rules
        working-directory: ops/alerts
        run: |
          set -euo pipefail
          promtool check rules gateway.yml
          promtool test rules gateway_test.yml
```

- [x] **Step 5: Register the check as required (a job that runs but isn't required does NOT gate merge)**

Add a row to the **"Pending required"** table in `docs/ci/required-checks.md` (not "Currently required" — the branch-protection POST has not yet run; the doc's own flow routes a not-yet-promoted check through Pending first):

```markdown
| `promtool (alert rules)` | `.github/workflows/ci.yml` | `ops-promtool` | Spec C G7-5 PR-B (#333): `promtool check rules` validates the gateway alert PromQL/syntax + `promtool test rules` unit-tests firing logic — critically that the critical security/exfil alerts fire on the right deny reasons and stay quiet otherwise. | First green run on `main`; controller runs `gh api -X POST` at merge time. |
```

The branch-protection promotion itself is a repo-admin action taken after the job first runs green — the manifest row documents the intent regardless.

- [ ] **Step 6: Commit**

```bash
git add ops/alerts/gateway_test.yml .github/workflows/ci.yml docs/ci/required-checks.md
git commit -m "ci(ops): promtool check + firing-logic test rules for the egress alerts (#333)"
```

---

## Self-Review

**Spec coverage:** §4 panels → Task 3. §5 alerts (5) → Task 2. §6 promtool check+test → Task 4. §7 AST extension (ctor+const+Assign/AnnAssign) → Task 1; §7.3 reason-label-value guard → Task 1 (`_known_reason_values`) + Task 2 (`test_alert_reason_labels_are_real_enum_values`). §1 outcome-counters → Task 2 (outage alert) + Global Constraints. §2 panel `datasource`-omission/ids/gridPos → Task 3. All covered.

**Placeholder scan:** No TBD/TODO. Every step has real code/YAML/JSON + concrete window-math numbers + expected output.

**Type/name consistency:** `_known_reason_values` / `_metric_names_in` / `_module_str_consts` / `_PROMETHEUS_CTORS` / `_EGRESS_ALERTS` consistent across Tasks 1-2. Alert names identical between the YAML (Task 2), the `_EGRESS_ALERTS` set (Task 2), and the promtool tests (Task 4). Metric names match the source consts (Global Constraints).

**Ordering:** Task 1 (make metrics + reason-values derivable) precedes Task 2 (alerts, which the existing `referenced <= known` check would otherwise redden) — correct per the design's TDD-coupling note.
