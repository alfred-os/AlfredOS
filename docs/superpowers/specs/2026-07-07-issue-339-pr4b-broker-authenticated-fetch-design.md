# #339 PR4b-broker — authenticated web.fetch via broker secret substitution

**Issue:** #339 (epic) / #347 blocker 4 (the last remaining merge-blocker) ·
**Date:** 2026-07-07 · **Branch (proposed):** `339-pr4b-broker-secret-substitution` off `main` @ `6a14c173`
**Predecessor:** PR4b-audit (#402, blocker 2) merged. **Successor:** PR4c (corpus breadth + nightly real-LLM smoke) → **#339 epic CLOSES**.

Security-critical (CLAUDE.md HARD rule #6). Requires: a new ADR (ADR-0048), an adversarial
corpus entry, and PR-time `alfred-security-engineer` sign-off before merge.

---

## 0. SCOPE DECISION — best-judgment, RATIFY at review

The author asked the user the scope/threat-model crux (below) via `AskUserQuestion`; the user
was away. Per the established project cadence, the author proceeded on best judgment and is
**holding at this review gate**. **This decision needs the user's ratification before
`writing-plans`.**

**The crux:** the planner (LLM) is untrusted (T3-influenced), and #339 has **no live
authenticated-fetch consumer** — `web.fetch` is driven by the act-phase loop, and no domain is
bound to a secret. Yet blocker 4 asks for a `broker.substitute()` contract where "the caller
supplies a broker SecretId per auth header." How much *positive* injection machinery do we build,
and does the live auth surface ship open or closed?

**DECISION (Option A):** build `SecretBroker.substitute()` (the shared primitive) + wire it into
`dispatch_web_fetch` **after DLP, before `_RawToolRequest`**, gated by a **closed web.fetch
auth-secret allowlist that ships EMPTY**. The planner may write `{{secret:<name>}}` placeholders,
but the empty allowlist means every reference refuses → **live authenticated fetch is OFF in
#339**; the mechanism + contract are fully built and proven against a fixture binding in tests.
Includes the negative defence (a raw secret in a URL/header is refused at the core DLP boundary).

**Why A over the alternatives:**
- **Faithful to the blocker's literal wording** — "broker secret-ID references, with the broker
  substituting the real secret value at the tool-call boundary."
- **Builds the reusable primitive** the `_SecretBrokerSubstitute` Protocol in
  `stdio_transport.py` is explicitly waiting on ("the orchestrator-level `substitute(params)`
  lands alongside the plugin host (separate PR)").
- **Closed-by-default live surface** — an empty allowlist means zero confused-deputy
  exfiltration surface in #339, while the path is exercised by a fixture-binding test.
- **Mirrors the strongest precedent** — `adapter_credential_resolver`'s closed
  `_ADAPTER_SECRET_ALLOWLIST` (an unknown key is a typed refusal, never a broker passthrough).

**Rejected:**
- **Option B (operator domain→secret binding, planner never names secrets):** tighter (zero
  planner secret surface) but diverges from the blocker's "caller supplies a SecretId per header"
  and does not build the reusable `substitute()` primitive.
- **Option C (defence + ADR + primitive only, no positive wiring):** smallest, but leaves the
  blocker's "dispatcher performs broker substitution before building `_RawToolRequest`" only
  partially satisfied.

---

## 1. What blocker 4 requires (verbatim obligations)

From #347 §4:

1. **Define the authenticated-fetch contract:** the caller supplies a broker `SecretId` for each
   auth header; the dispatcher performs broker substitution before building `_RawToolRequest`;
   raw secret values never appear in the tool request, ledger, or audit row.
2. **Correct the defence-in-depth positioning:** core-side DLP over URL and headers (added in
   G7-2.5 PR1) is the **sole** broker-secret defence at the core boundary. The gateway DLP runs
   with `broker=None`; it is **not** an independent defence-in-depth layer for broker secrets.
3. **Add an adversarial corpus entry:** a broker-secret-in-URL / broker-secret-in-header call is
   refused at the core DLP boundary before reaching the relay.

---

## 2. Verified current-state anchors (re-grepped 2026-07-07, main `6a14c173`)

The PR4b-audit merge shifted line numbers; these are re-confirmed against the merged tree.

- **`SecretBroker`** (`src/alfred/security/secrets.py:439`) has `get` (`:626`) / `has` / `known` /
  `redact` (`:696`) / `reload` (`:757`) but **no `substitute()`** — confirmed absent.
  `get(name)` raises `UnknownSecretError` for any `name` not in the closed
  `SUPPORTED_SECRETS = {deepseek_api_key, anthropic_api_key, discord_bot_token, audit.hash_pepper,
  quarantine_provider_api_key}` (`secrets.py:66`). **All five are infra secrets — none is a
  third-party web-auth token.**
- **`dispatch_web_fetch`** (`src/alfred/plugins/web_fetch/fetch_dispatcher.py:250`):
  - Step 1 DLP: `clean_url = outbound_dlp.scan(url)`; `clean_headers = {name: outbound_dlp.scan(v)
    for name, v in headers.items()}` (`:312`, `:317`).
  - URL raw-secret defence: `if clean_url != url:` → loud audit `dlp_scan_result="url_secret_refused"`
    → `raise WebFetchError(t("web.fetch.error.url_secret_refused"))` (`:360-386`). **Headers today
    are redacted-and-SENT (no refusal) — the gap this PR closes.**
  - `_RawToolRequest(method="GET", url=url, headers=clean_headers, body="", idempotent=True)`
    (`:558-560`). **The substitution point is immediately before this build.**
- **`OutboundDlp.scan`** (`src/alfred/security/dlp.py`): three stages — (1) broker redaction,
  (2) regex, (3) canary. Core wires all three (`broker` present). A known broker secret is
  redacted at stage 1 → drives the raw-secret refusal.
- **Relay client** (`src/alfred/egress/relay_client.py:234,247,288-297`): `scan_for_outbound`
  scans `raw_request.body` **only** (body is `""` for web.fetch); `raw_request.headers` are
  forwarded **verbatim** (only `Idempotency-Key` is added on replay). A secret substituted into
  headers survives to the gateway.
- **Egress ledger** (`src/alfred/memory/egress_idempotency.py:63`): `commit_intent(...,
  body_hash, ...)` stores a **body** hash, not headers. Body is `""` → the ledger never sees the
  secret.
- **Gateway relay** (`src/alfred/gateway/egress_relay.py:225,447-468`): built with
  `OutboundDlp(broker=None, …)` (stages 2+3 only). It re-scans `body + URL + forwarded header
  values` and **denies (`DLP_REDACTED`) on ANY change** — it is a *detector*, not a re-redacter
  (`:462`). See §7 (residual).
- **`stdio_transport.py`** (`:157-164`): declares an aspirational `runtime_checkable`
  `_SecretBrokerSubstitute` Protocol (`async def substitute(params: dict[str, Any], /) ->
  dict[str, Any]`) and comments that the concrete broker method "lands alongside the plugin host
  (separate PR)". Its outbound order — serialize placeholder frame → DLP on placeholders →
  broker-substitute AFTER DLP → build real frame (`:532-592`) — is the **ADR-0017 ordering this
  PR mirrors**.
- **`adapter_credential_resolver.py`** (`src/alfred/comms_mcp/`): closed
  `_ADAPTER_SECRET_ALLOWLIST = {"discord": "discord_bot_token"}`; an unknown key is a typed,
  audited refusal — **never** `broker.get(attacker_influenced_name)`. The confused-deputy
  precedent this PR mirrors for the web.fetch allowlist.
- **`web.fetch` tool arg schema** (`src/alfred/orchestrator/builtin_tools.py:56-68`): accepts
  `url` (required) + `headers` (optional object). The planner can already supply headers; the
  `_dispatch` coerces them to `{str: str}` and passes to `dispatch_web_fetch`.

---

## 3. The `SecretBroker.substitute()` primitive

Add to `SecretBroker` (`secrets.py`):

```python
def substitute(self, text: str, *, allowed_secrets: frozenset[str]) -> str:
    """Replace every ``{{secret:<name>}}`` placeholder in ``text`` with the real
    secret value. ``<name>`` MUST be in BOTH ``allowed_secrets`` (the caller's
    closed, context-specific allowlist) AND ``SUPPORTED_SECRETS`` (the broker's
    registry). A value with no placeholder is returned byte-for-byte unchanged.

    Refuses (never a silent passthrough — HARD rules #6/#7):
    * ``SecretSubstitutionNotAllowed(name)`` — ``<name>`` is not in
      ``allowed_secrets`` (confused-deputy defence, mirrors adapter_credential_resolver).
    * ``UnknownSecretError`` — ``<name>`` is allowlisted but not in SUPPORTED_SECRETS
      or unprovisioned (delegates to ``get``).

    This method assumes ``text`` is already DLP-clean of RAW secrets (ADR-0017:
    DLP scans the placeholder frame BEFORE substitution). It resolves placeholders
    ONLY; raw secret detection is the upstream DLP's job.
    """
```

**Design choices (locked, best-judgment — open to review):**

- **Single-string atom, not `dict -> dict`.** The most reusable unit; each consumer maps over
  its own structure (`web.fetch` over header values). Sidesteps the `dict[str, Any]` shape
  mismatch with `stdio`'s JSON-RPC params. Easy to unit-test in isolation.
- **Sync, not async.** Matches the broker's synchronous env/file backend and its existing
  `get/has/redact/reload` surface — no false "async without await." `stdio_transport`'s Protocol
  is async (aspirational, for a future remote store); converging the two is a **documented
  follow-up**, out of scope here. This PR mirrors `stdio`'s *pattern* (placeholder + DLP
  ordering); it does not retrofit `stdio`'s working path.
- **`allowed_secrets` is a per-call keyword.** The confused-deputy narrowing is context-specific
  (web.fetch's allowlist ≠ a future stdio allowlist), so it is a call parameter, not a
  construction-time property. The check lives inside `substitute` so there is one placeholder
  parse and one enforcement point.
- **Placeholder syntax:** `{{secret:<name>}}`, `<name>` matching `[a-z0-9_.]+` (secret names
  include `.`, e.g. `audit.hash_pepper`). Placeholders may be embedded in surrounding text
  (`Bearer {{secret:x}}`); the surrounding text is preserved. Multiple placeholders per value are
  supported. `{{secret:}}` (empty name) → refuse.
- **New refusal exception:** `SecretSubstitutionNotAllowed(AlfredError)` in `secrets.py`, carrying
  the offending `name` ONLY (a secret *name*, not a *value* — safe to audit, per the
  adapter_credential_resolver `adapter_id`-only precedent). Never chains a `from` that could carry
  the raw value.

---

## 4. The closed web.fetch auth-secret allowlist

New module constant (in `src/alfred/plugins/web_fetch/`, e.g. `constants.py` or a new
`auth_allowlist.py`):

```python
# The CLOSED set of broker secret names a web.fetch header may reference via a
# {{secret:<name>}} placeholder (confused-deputy defence; mirrors
# adapter_credential_resolver._ADAPTER_SECRET_ALLOWLIST). Ships EMPTY: no
# SUPPORTED_SECRET is a third-party web-auth token, so there is no live binding
# in #339. A future authenticated integration adds both a new SUPPORTED_SECRET
# and an entry here (behind operator config + its own security review).
WEB_FETCH_AUTH_SECRET_ALLOWLIST: Final[frozenset[str]] = frozenset()
```

Rationale for empty: with `WEB_FETCH_AUTH_SECRET_ALLOWLIST == frozenset()`, **every**
`{{secret:<name>}}` a planner writes is refused (`SecretSubstitutionNotAllowed`). Live
authenticated fetch is off; the positive path is proven only by tests that pass their own
fixture allowlist. This is the `adapter_credential_resolver` posture: the mechanism exists and is
tested; the live surface is closed until an operator opens it.

---

## 5. Data flow in `dispatch_web_fetch` (the wiring)

Ordering preserves ADR-0017 (DLP on the placeholder frame FIRST, substitute AFTER):

```
Step 1  DLP scan (unchanged):
          clean_url     = outbound_dlp.scan(url)
          clean_headers = {k: outbound_dlp.scan(v) for k, v in headers.items()}
          # {{secret:x}} placeholders are benign text -> pass through unredacted.
          # a RAW secret -> redacted -> clean != original.

Step 1a URL raw-secret defence (unchanged): clean_url != url -> url_secret_refused (audit + raise)

Step 1b HEADER raw-secret defence (NEW):    any clean_headers[k] != headers[k]
          -> loud audit dlp_scan_result="header_secret_refused"
          -> raise WebFetchError(t("web.fetch.error.header_secret_refused"))

Step 1c SUBSTITUTE (NEW, after DLP):
          auth_headers = {
              k: broker.substitute(v, allowed_secrets=WEB_FETCH_AUTH_SECRET_ALLOWLIST)
              for k, v in clean_headers.items()
          }
          # off-allowlist ref -> SecretSubstitutionNotAllowed -> loud audit
          #   dlp_scan_result="secret_substitution_refused" -> raise WebFetchError
          # empty allowlist (#339) -> ANY placeholder refuses here.

Steps 2..3b  allowlist / rate-limit / handle_cap (unchanged; operate on clean_url).

Step 4  _RawToolRequest(method="GET", url=url, headers=auth_headers, body="", idempotent=True)
          # auth_headers carries substituted real values (or is identical to
          # clean_headers when no placeholder was present).
```

Placement: Step 1c goes **after** the existing header DLP (Step 1) and the new header
raw-secret defence (Step 1b), and **before** the `_RawToolRequest` build at `:558`. The
substitution result flows only into the relay request — never into an audit `subject` (no
headers field), never into the ledger (body-hash only), never logged.

**URLs are never substituted.** Auth belongs in headers; a raw secret in a URL is already
refused (`url_secret_refused`). A literal `{{secret:...}}` in a URL is left as-is (benign text to
an allowlisted domain) — not special-cased. The ADR records this.

**`SecretBroker` reaches `dispatch_web_fetch`.** New required kwarg `broker: SecretBroker`
(structural `_SecretBrokerLike`-style Protocol for test doubles), threaded through
`build_web_fetch_tool` → `build_tool_registry` → all callers, mirroring how `rate_limiter` /
`handle_cap` were threaded in PR4a (kept REQUIRED — no fail-open default). Exact plumbing verified
during `writing-plans`.

---

## 6. What never sees the secret (the invariants this PR establishes)

| Surface | Why the secret is absent |
| --- | --- |
| Audit rows | `WEB_FETCH_FIELDS` has no headers field; only `url`/`domain` are recorded, and those are the DLP-clean values. |
| Egress ledger | `commit_intent` hashes the **body**; web.fetch body is `""`. Headers are never hashed/stored. |
| `egress_id` | `compute_egress_id(ctx, call_index)` is positional — independent of header content. |
| Logs | The secret value is never passed to a logger; refusals log the secret *name* (safe) via the closed vocabulary. |
| Core→gateway relay frame | Carries the substituted value (it must, to authenticate) — this is the trusted `alfred_internal` leg. The secret is *in transit* here, never *persisted* here. |

The substituted secret **does** travel the trusted relay leg to the gateway and out to the
destination (that is what authenticated fetch means). "Never on the wire" in prior notes is
imprecise: the invariant is **never persisted/audited/logged/ledgered**, and **never in the
DLP-scanned or planner-facing representation**.

---

## 7. The gateway re-scan residual (real; accepted; documented in the ADR)

The gateway re-scans `body + URL + forwarded header values` with `broker=None` (stages 2+3) and
**denies on any redaction** (`egress_relay.py:462`, `DLP_REDACTED`). Consequences:

- **Negative-defence corollary (why core DLP is the *sole* broker-secret defence):** the gateway
  has `broker=None`, so it cannot redact *broker* secrets it does not know. It catches only
  pattern-shaped (stage-2) or canary (stage-3) secrets. A broker secret that matches no stage-2
  regex is invisible to the gateway → the **core-side DLP is the sole broker-secret defence**
  (blocker 4 obligation 2, satisfied and documented).
- **Positive-path residual:** a substituted secret whose value matches a gateway stage-2 regex
  would be denied fail-closed at the gateway (`DLP_REDACTED`), breaking that authenticated fetch.
  **Moot in #339** (empty allowlist → nothing substituted in production). The fixture-binding test
  uses a non-pattern token so the loopback-relay leg passes. Resolving this generally (a gateway
  auth-header allowance) is **future work**, tracked when a real authenticated integration lands.

The ADR names both explicitly so the constraint is not rediscovered later.

---

## 8. Error handling & refusal vocabulary

- **`header_secret_refused`** (NEW `DlpScanResult` Literal token) — a RAW secret detected in a
  header by DLP. `result="refused"` (in-domain; no migration). New i18n key
  `web.fetch.error.header_secret_refused`.
- **`secret_substitution_refused`** (NEW `DlpScanResult` Literal token) — a `{{secret:<name>}}`
  ref that is off the web.fetch allowlist or unprovisioned. `result="refused"`. New i18n key
  `web.fetch.error.secret_substitution_refused`.
- Both are added to the `DlpScanResult` Literal **and** its lockstep test
  (`test_audit_row_schemas.py`), and registered in the line-pinned audit domain-closed AST guard
  if they introduce a new dynamic `result=` site (they reuse `refused`, so likely no guard
  change — verified at implementation).
- `SecretSubstitutionNotAllowed` and `UnknownSecretError` from `substitute` are caught in
  `dispatch_web_fetch`, audited loud (HARD rule #7), and re-raised as a benign `WebFetchError`
  (the raw exception, which carries only a secret *name*, is not propagated to the planner).
- No new dispatch arm in `dispatch_tool` is required if the refusals surface as `WebFetchError`
  (already handled). Verified during `writing-plans`.

---

## 9. ADR-0048 (outline)

**Title:** *Authenticated web.fetch — broker secret substitution invariant.*

- **Context:** G7-2.5 shipped unauthenticated GET-only web.fetch; HARD rule #6 requires
  authenticated calls to inject secrets via the broker, never raw. #339 wires the first live
  `dispatch_web_fetch` caller.
- **Decision:** `{{secret:<name>}}` placeholders in header values, resolved by
  `SecretBroker.substitute()` **after** core DLP and **before** `_RawToolRequest`, gated by a
  closed web.fetch auth-secret allowlist (empty by default). Raw secrets in URL/headers are
  refused at the core DLP boundary. Substitution applies to header values only.
- **Invariants:** (1) DLP-before-substitute (ADR-0017 extension); (2) closed allowlist ∩
  SUPPORTED_SECRETS (confused-deputy defence); (3) raw secret in URL/header → refuse
  (never redact-and-send); (4) the secret is never persisted/audited/logged/ledgered nor in the
  DLP/planner representation.
- **Positioning:** core-side DLP is the *sole* broker-secret defence; gateway `broker=None` is not
  an independent DiD layer for broker secrets.
- **Accepted residuals:** the gateway re-scan positive-path residual (§7); the empty live
  allowlist (no live binding in #339); `stdio_transport` async-Protocol convergence deferred.
- **Cross-refs:** ADR-0017, ADR-0036, ADR-0040, ADR-0041, #347.

---

## 10. Adversarial corpus entry

- **Category:** `dlp_egress` (prefix `de`), "T3-origin credential exfiltration paths" — the
  precise fit for "a broker secret must not egress via URL/header." New id
  `de-2026-0NN` (next free) under `tests/adversarial/dlp_egress/`.
- **Scenarios (all refused pre-relay; a `fire_spy`/fake relay proves no egress call):**
  1. A **raw** known broker secret in the URL → `url_secret_refused`.
  2. A **raw** known broker secret in a header value → `header_secret_refused` (NEW behaviour).
  3. A `{{secret:<name>}}` placeholder naming an **off-allowlist** secret → `secret_substitution_refused`
     (empty allowlist ⇒ any placeholder refuses).
- YAML payload + a test harness following the PR2 `cap-2026-006` pattern (fixture-filter +
  real `dispatch_web_fetch` + fire-spy). Runs under the nightly adversarial job.
- **`alfred-security-engineer` sign-off on the corpus entry is a hard merge gate.**

---

## 11. Testing strategy

- **Unit — `substitute()`:** no-placeholder passthrough (byte-identical); single/multi placeholder
  in surrounding text; off-allowlist ref → `SecretSubstitutionNotAllowed(name)`; allowlisted +
  unprovisioned → `UnknownSecretError`; empty-name placeholder → refuse; a value containing a raw
  secret is out of scope (DLP handles it) — assert the method does NOT try to detect raw secrets.
- **Unit — `dispatch_web_fetch`:** header raw-secret → `header_secret_refused` audit + raise
  (mirror the url_secret_refused test); off-allowlist placeholder → `secret_substitution_refused`
  audit + raise; **positive path** with a fixture allowlist + benign fixture secret → substituted
  value reaches `_RawToolRequest.headers` (assert via a relay/extractor spy), while the audit rows
  and (asserted) ledger row carry no secret. 100% line + branch on the new arms (CI gate).
- **Integration (loopback relay + Postgres):** extend `test_web_fetch_assembly.py` /
  `test_act_loop_real_chain.py` — a fixture-bound placeholder fetch reaches a loopback echo
  server with the substituted `Authorization` header (benign token that passes the gateway
  stage-2 scan), proving end-to-end substitution + gateway pass-through; and assert the stored T2
  + audit row carry no secret.
- **Adversarial:** the `de-2026-0NN` entry (§10).
- **Non-vacuous secret-absence assertion:** a test that scans the whole audit-row set + the
  serialized ledger row for the fixture secret value and asserts it is absent (mirrors PR3's
  non-vacuous HARD#5 marker guard).

---

## 12. Scope / PR shape

**ONE PR.** Blocker 4 is a single cohesive contract — the primitive, the allowlist, the wiring,
the negative defence, the ADR, and the adversarial entry are tightly coupled. Splitting would
ship a `substitute()` primitive with no consumer (worse than PR4b-audit's clean split, which had
two independent concerns).

**Task decomposition (for `writing-plans`, sketch):**
1. `SecretBroker.substitute()` + `SecretSubstitutionNotAllowed` + placeholder regex + unit tests.
2. `WEB_FETCH_AUTH_SECRET_ALLOWLIST` (empty) + the two new `DlpScanResult` tokens + lockstep +
   i18n keys.
3. `dispatch_web_fetch` wiring: header raw-secret defence (Step 1b) + substitute (Step 1c) +
   thread `broker` through `build_web_fetch_tool`/`build_tool_registry`/callers.
4. ADR-0048.
5. Adversarial `de-2026-0NN` + harness (+ security sign-off).
6. security.md DLP-positioning correction + docstrings + `make check` + full verification
   (adversarial suite release-blocking — this PR touches `src/alfred/security/`).

---

## 13. Out of scope / follow-ups

- **#358** (core→proxy `Proxy-Authorization` / mTLS on the CONNECT proxy) — a different egress
  leg; explicitly NOT this PR.
- **`stdio_transport` convergence** onto `SecretBroker.substitute()` (adapting its aspirational
  async Protocol + wiring) — documented follow-up.
- **Gateway auth-header allowance** (resolving the §7 positive-path residual) — future work when a
  real authenticated integration lands.
- **Operator config surface** for populating `WEB_FETCH_AUTH_SECRET_ALLOWLIST` (domain-bound auth)
  — future work; the allowlist ships empty and code-defined for now.
- Prior #339 carried follow-ups (export hookpoint literals as constants; `RealGate.grants`
  accessor; prompt-cache prefix) remain open, unaffected.

---

## 14. Merge gates

- FULL `/review-pr` fleet (architect + security ALWAYS) + CodeRabbit CLI **and** cloud.
- `alfred-security-engineer` M4 sign-off (new secret-substitution contract + adversarial entry).
- Adversarial suite green (touches `src/alfred/security/`).
- Non-admin `gh pr merge --rebase` on green (NEVER `--admin`).
