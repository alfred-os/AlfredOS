# G7-5 — Spec C closeout: invariant + corpus + docs + observability

- **Date**: 2026-07-01
- **Epic**: [#333](https://github.com/alfred-os/AlfredOS/issues/333) — Spec C egress control plane / connectivity-free core
- **Predecessor spec**: [2026-06-25-spec-c-egress-control-plane-design.md](2026-06-25-spec-c-egress-control-plane-design.md) §11 (G7-5 bullet), §9 (adversarial corpus), §10 (PRD & ADR changes)
- **Status**: brainstorm → decomposition; PR-C detailed, PR-A/B/D sketched

## 1. Purpose & the numbering reconciliation

G7-5 is the **final, documentation-and-observability tail** of Spec C. The egress
*mechanism* is complete (G7-0..G7-4 merged; `main` at `5b3a3414`); it is a
fail-closed seam with **no live caller** yet (`build_orchestrator` is wired into
daemon `start` by #338/#339, out of G7-5 scope). G7-5 makes the invariant
**documented, adversarially-covered, and operator-observable** — it ships no new
runtime egress behaviour.

**Numbering:** this tail is **G7-5**, per predecessor-spec §11, ADR-0042 (line 6:
"ADR-0040 … G7-5"), ADR-0043, and project memory. Epic #333's *body sketch*
mislabels it "G7-6" (and mislabels the already-merged Discord hardening "G7-5") —
that sketch predates the G7-3/G7-4 merges and was never renumbered. **G7-5 is
authoritative**; the epic-body labels are stale.

## 2. Decomposition — four PRs

Locked with the maintainer (2026-07-01). Ordering: **C → A → B → D**.

| PR | Scope | Merge disposition |
| --- | --- | --- |
| **PR-C** | Adversarial corpus §9 closure (`de-2026-013..016` + README refresh) | self-merge (release-blocking corpus; full cadence) |
| **PR-A** | Operator egress-state CLI (`alfred gateway status`/`healthcheck` extension) | self-merge |
| **PR-B** | Ops dashboards/alerts (`ops/grafana`, `ops/alerts` egress-plane extension) | self-merge |
| **PR-D** | ADR-0040 + PRD §5/§7.1 + CLAUDE.md | **human-gated** — open as a **draft**, full review, hand to maintainer; **never self-merge** |

PR-D is one PR (maintainer preference) covering all three human-gated documents,
drafted **last** so it cites the merged A/B/C surfaces accurately. CLAUDE.md is
edited via `.rulesync/rules/CLAUDE.md` + `rulesync generate` (the root CLAUDE.md is
a gitignored rulesync output). Editing CLAUDE.md/PRD.md is human-gated per repo
rules; ADR-0040 carries three honest-scope residuals needing maintainer co-sign.

Each PR runs the full per-PR cadence: brainstorming → writing-plans → focused
plan-review → subagent-driven TDD → `make check` → full `/review-pr` fleet +
CodeRabbit → resolve every thread → `gh pr merge --rebase` (self-merge PRs) /
hand-off (PR-D). Never `--admin`, never `--no-verify`.

## 3. The §9 audit — most of the corpus already landed

A read-only audit (2026-07-01) of `tests/adversarial/` against predecessor-spec §9
found that the egress corpus is **~85% already shipped incrementally across
G7-1..G7-4**. §9 was the epic-start *plan*; the entries landed with the mechanism
PRs, not deferred to this tail.

| §9 class | Status | Corpus entry |
| --- | --- | --- |
| 1. Non-canary body exfil (gateway DLP catch) | **DONE** (G7-2) | `de-2026-007` |
| 2. Canary trip on egress | **DONE** (G7-2) | `de-2026-008` |
| 3. DNS exfil — core cannot resolve external name | **GAP** | integration/kernel proof only; no corpus entry |
| 4. Mode-(a) provider-prompt exfil residual | **GAP** | none (accepted residual, undocumented in corpus) |
| 5a. L7-proxy raw-IP / literal-IP CONNECT refusal | **GAP** | unit-tested only; no corpus entry |
| 5b. SNI-spoof-to-cotenant / CDN-cotenant residual | **GAP** | none (accepted residual, undocumented) |
| 6. Egress-id replay / forgery | **DONE** (G7-2) | `de-2026-009` |
| 7. Cross-mode tier-downgrade | **DONE** (G7-2) | `tl-2026-010` |
| 8. IO-plane-down audit completeness | **DONE** (G7-2) | `de-2026-010` |
| 9. Flip `sbx-2026-005` out_of_scope→enforced + invert tripwire | **DONE** (G7-1) | `sbx-2026-005` |
| 10. Migrate (not drop) Discord adapter policy tests | **DONE** (G7-4) | `sbx-2026-014` + `test_discord_policy_kernel_enforced.py` |

So **PR-C is exactly the four remaining §9 entries** — two passing-defense, two
recorded residuals — plus a stale-README fix. Nothing else in §9 is outstanding.

## 4. PR-C — the four new `dlp_egress` entries

Category `dlp_egress` (T3-origin exfiltration paths — predecessor-spec §12.1).
Max existing `de-` id is `de-2026-012`; new ids are monotonic **013–016** (schema
`tests/adversarial/payload_schema.py` enforces `<prefix>-YYYY-NNN`, monotonic per
year per category, never reused).

### 4.1 Encoding decision — residuals use `out_of_scope`, not a `refused` fudge

Two encoding patterns exist in the tree for "accepted residual":

- **`tl-2026-003`** — the schema's first-class mechanism: `out_of_scope: true` +
  a required non-empty `out_of_scope_rationale` (validator-enforced), with a test
  asserting the acknowledgement is present. The rationale states *why* no defence
  exists, so the absence is a recorded invariant, not a silent gap.
- **`de-2026-002`** — an older, muddier pattern: `expected_outcome: refused`
  *without* the flag, claiming a "refusal" for a payload that actually leaves.

**The two new residuals (`de-2026-014`, `de-2026-016`) use the schema's
`out_of_scope: true` + `out_of_scope_rationale` encoding** — the intended honest
form that does not misrepresent an un-caught attack as refused. `de-2026-002` is
**not** touched (Slice-3 entry, out of G7-5 scope).

### 4.2 The entries

| id | §9 | Type | `expected_outcome` / flag | Executable proof |
| --- | --- | --- | --- | --- |
| `de-2026-013` | 3 | passing-defense | `refused` | two assertions: (a) the shipped compose connectivity-free precondition — core on the internal-only network, not on external, with a positive control; and (b) **anti-rot on the runtime proof** — the docker-gated `test_core_network_isolation_kernel.py` still exists and still asserts `EXTERNAL_DNS_BLOCKED`. (a) intentionally overlaps the required compose-invariant lint (defense-in-depth, framed as the DNS-exfil class); (b) adds a signal no lint gives. The `sbx-2026-005/014` static-bytes / anti-rot pattern applied to the core. |
| `de-2026-014` | 4 | **recorded residual** | `out_of_scope: true` + rationale | meta-assertion: the YAML carries `out_of_scope=true` + non-empty rationale. Rationale: mode-(a) provider egress is TLS-passthrough (destination-allowlisted only); the L7 proxy never inspects the wrapped request body, so a provider-prompt-exfil in the plaintext prompt is **destination-gated only** by design. |
| `de-2026-015` | 5a | passing-defense | `refused` | drives the gateway L7 CONNECT parser/allowlist (`src/alfred/gateway/egress_proxy.py`) with a **literal-IP** CONNECT target → asserts the `literal_ip_target` deny. Elevates the existing `tests/unit/gateway/test_egress_proxy.py` logic into the release-blocking adversarial corpus (§9 wants the class documented adversarially). |
| `de-2026-016` | 5b | **recorded residual** | `out_of_scope: true` + rationale | meta-assertion of the acknowledgement. Rationale: within an allowlisted CDN-fronted destination (e.g. Cloudflare-fronted `discord.com`), TLS-passthrough is SNI-blind and cannot distinguish a co-tenant behind the same fronting; SNI-spoof-to-cotenant + CDN-cotenant survive the destination gate. Recorded as ADR-0040 honest-scope residual (i). |

`ingestion_path` values are drawn from the schema `IngestionPath` literal
(`web.fetch` / `mcp.tool.output` as appropriate); exact values are a TDD-phase
detail, not a design fork.

### 4.3 README coverage-matrix refresh

`tests/adversarial/dlp_egress/README.md`'s coverage matrix stops at `de-2026-010`
and omits the shipped `de-2026-011`/`012` (audit finding). The README's own text
declares matrix↔corpus drift a **release-blocker**. PR-C refreshes the matrix
through `de-2026-016` (fix-don't-dismiss). No behavioural change.

### 4.4 What PR-C is NOT

- Not the `sbx-2026-005` flip (done G7-1) or the Discord policy-test migration
  (done G7-4).
- Not a refactor of `de-2026-002`'s legacy encoding.
- Not new runtime egress behaviour — corpus + docs only.

## 5. PR-A / PR-B / PR-D — sketches (own brainstorm at their turn)

Detailed design for A/B/D is deferred to each PR's own brainstorming pass; recorded
here so the program shape is legible.

- **PR-A — operator egress-state CLI.** Extend `alfred gateway status` /
  `healthcheck` to surface egress-plane state (destination allowlist, proxy/relay
  reachability, in-flight count, recent denies). Open design question to resolve at
  PR-A brainstorm: `status` is deliberately *Settings-only* today (no authenticated
  wire read) — the runtime state (inflight, recent denies) needs a chosen
  observability source (Prometheus scrape vs a status wire message vs audit-log
  read). All CLI text through `t()` (i18n release-blocker).
- **PR-B — ops dashboards/alerts.** Extend the **existing** `ops/grafana/gateway.json`
  - `ops/alerts/gateway.yml` (they already exist) with egress-plane panels/alerts.
  Emitted today: `gateway_egress_connect_total`, `gateway_egress_dlp`,
  `gateway_egress_relay_total`. The design's named `gateway_egress_inflight`
  saturation alert requires that gauge — **verify at PR-B brainstorm whether it is
  emitted**; if not, wiring it is a small in-core/gateway change that PR-B carries.
  Metric names + Help strings stay English (not `t()`-wrapped).
- **PR-D — ADR-0040 + PRD §5/§7.1 + CLAUDE.md (human-gated draft).** ADR-0040:
  two-layer enforcement (kernel `internal:true` = enforcement-of-record + userspace
  proxy/DLP defense-in-depth), the two egress modes, egress-idempotency, the
  credential-concentration payoff + serial-transit residue, and the **three
  honest-scope residuals** for maintainer co-sign: (i) Discord SNI-spoof-to-cotenant
  / CDN-cotenant; (ii) mode-(a) provider-prompt exfil is destination-gated only;
  (iii) gateway-compromise degrades the "two independent layers" framing. PRD §5/§7.1
  per predecessor-spec §10. Drafted last to cite merged A/B/C surfaces.

## 6. Testing & gates (PR-C)

- Every new YAML validates against `payload_schema.py` at collection
  (`extra=forbid`; `provenance` non-empty; `references` non-empty tuple;
  `out_of_scope` ⟹ non-empty rationale).
- `de-2026-013` + `de-2026-015` ship executable `test_*.py` assertions (real gates,
  not paper entries — per the paper-only-gates lesson).
- `de-2026-014` + `de-2026-016` ship the `out_of_scope`-acknowledgement
  meta-assertions.
- Corpus-density guard (`test_corpus_density.py`) floor for `dlp_egress` stays
  satisfied (count only rises).
- `uv run pytest tests/adversarial -q` green; `make check` before every push.

## 7. References

- Predecessor spec §9 (corpus), §10 (PRD/ADR), §11 (decomposition):
  [2026-06-25-spec-c-egress-control-plane-design.md](2026-06-25-spec-c-egress-control-plane-design.md)
- Schema: `tests/adversarial/payload_schema.py`; skill:
  `.rulesync/skills/alfred-adversarial-corpus/SKILL.md`
- Residual-encoding exemplar: `tests/adversarial/tier_laundering/tl_gc_traversal_out_of_scope.yaml`
- Kernel proofs cross-referenced by `de-2026-013`:
  `tests/integration/egress/test_core_network_isolation_kernel.py`,
  `tests/integration/egress/test_discord_policy_kernel_enforced.py`
- ADR-0042 (G7-3 cutover, reserves ADR-0040), ADR-0043 (G7-4 Discord egress)
