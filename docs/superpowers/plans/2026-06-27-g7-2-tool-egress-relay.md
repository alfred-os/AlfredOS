# G7-2 — Mode-(b) Inspecting Tool-Egress Relay + Gateway DLP + Egress Idempotency — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the AlfredOS egress *spine* for inspectable tool egress — the gateway becomes the second DLP chokepoint and the sole maker of tool HTTP requests — proven end-to-end by a deterministic synthetic driver, so a later epic can drive it from a real LLM tool-calling loop without re-opening any security gap.

**Architecture:** The connectivity-free core (Spec C) cannot open external sockets. For tool egress (web POST, email — `web.fetch` is the G7-2 live-path consumer), the core DLP-redacts the request body and sends an `egress.request` envelope over a new HTTP relay endpoint on `alfred_internal` to the gateway. The gateway independently re-runs `OutboundDlp` (stages 2+3 — shape regex + a real canary scan) on the body, enforces a per-tool destination allowlist (reusing the G7-1 SSRF chain), originates the real outbound TLS itself (resolve-once, connect-to-validated-IP, validate-cert-against-hostname), and returns an `egress.response`. Every side-effecting egress is stamped with a deterministic, injective `egress-id` and recorded in a tri-state durable Postgres ledger, so a Spec-A replay / core restart never double-fires; the tool RESPONSE is T3 and routes through the one production dual-LLM quarantine extractor, with the ledger storing only the post-extraction T2 so a replay can never re-hand raw T3 to the orchestrator.

**Tech Stack:** Python 3.12+, asyncio, Pydantic v2, SQLAlchemy 2.0 (typed) + Alembic, Postgres 16, httpx 0.28.1 / httpcore 1.0.9 (pinned — verified), structlog, prometheus_client, pytest + hypothesis + testcontainers + the adversarial harness.

## Global Constraints

- **Pinned stack — verify, don't assume.** httpx **0.28.1**, httpcore **1.0.9** (the TLS engine). `proxies=` does not exist; there is **no resolver-injection hook** on httpx/httpcore. The only "connect-to-IP-but-validate-cert-against-hostname" mechanism is **IP-in-URL host + the `sni_hostname` request extension** (httpcore connects to `_origin.host`; SNI + cert identity come from `request.extensions["sni_hostname"]`).
- **The gateway holds NO DB session, NO signing key, NO vault** (ADR-0036). Gateway-side audit is the **structlog tier + a Counter** only (mirror `gateway/egress_audit.py`). The gateway derives all config from **public env** threaded by compose (mirror `resolve_deepseek_base_url`), never `Settings()` (which requires `deepseek_api_key` and raises without it).
- **`internal:true` is NOT yet flipped** (that is G7-3). G7-2 is behaviour-neutral for real tools until the dispatcher re-point in Part C; the core keeps its direct fallback until G7-3.
- **The privileged orchestrator never sees raw T3** (HARD rule #5). The ledger stores **post-extraction T2**, never raw T3. A replay returns stored T2 flagged `deduplicated`, never re-fetches, never re-tags T3.
- **No silent failures in security paths** (HARD rule #7): every deny / canary-trip / integrity-mismatch / IO-down / idempotency-replay writes a non-skippable audit row; the canary scanner fails **loud, not open**, on an internal error.
- **i18n:** typed-error reasons + operator-rendered audit-reason *presentations* + any new CLI text route through `t()`; audit-reason **tokens** stay stable English identifiers; metric names / Help strings stay English. Run the i18n drift flow after any code edit that shifts `#:` line refs (`pybabel extract -F babel.cfg -o /tmp/alfred.pot src/alfred plugins` → `pybabel update -i /tmp/alfred.pot -d locale -D alfred --no-fuzzy-matching` → `pybabel compile -d locale -D alfred --statistics`; **never** `--omit-header`; the CI `--check` uses `--ignore-pot-creation-date`).
- **Commit trailers on EVERY commit** (commit-hygiene CI): `(#333)` scope + the `MrReasonable` + `Claude-Session` trailers.
- **Two-gates coverage:** every NEW security-boundary file outside `src/alfred/security/` needs an explicitly-named 100% line+branch step in BOTH the `python` job (ci.yml ~489/491) AND the `coverage-gates` job (ci.yml ~1627/1629), and must be added to BOTH `hashFiles()` guards. Files under `src/alfred/security/` ride the existing `security/*` glob automatically.
- **`make check` before every push** (`uv run ruff check . && uv run ruff format --check . && uv run mypy src/ && uv run pyright src/` + the unit lane). Check `$?` directly — a `| tail` masks the exit code.
- **No `--no-verify`, no `--admin` merge** (HARD rules). Per-PR cadence: plan → focused plan-review → subagent TDD → full `/review-pr` fleet + CodeRabbit (BOTH) → resolve every thread → plain `gh pr merge --rebase`.

---

## Charter & scope (read before touching code)

**G7-2 ships the egress SPINE, not a live LLM consumer.** Verified against the tree: the orchestrator has **no tool-calling loop** (`orchestrator/core.py:749` is a single `router.complete()`; `CompletionRequest`/`CompletionResponse` are frozen with no `tools`/`tool_use` — `providers/base.py:93`), and `dispatch_web_fetch` has **zero production callers**. Building the LLM tool-calling subsystem is a separate L/XL epic — **#339** — sequenced after G7-3. The comms path also still runs a deterministic-ack adapter (**#338**), and the real-LLM quarantine child is **#340**. All three are sequenced **after Spec C G7-3** (a live agent must not egress while the core's direct fallback still exists).

**Two charter conditions (both AI-expert and architect insisted):**

1. The synthetic driver drives the **real** `dispatch_web_fetch` and the **real** `QuarantinedExtractor` — it substitutes ONLY the LLM's tool-selection decision, never the dispatcher / relay / proxy / DLP / extractor. The production `web.fetch` dispatcher **is genuinely re-pointed** at the relay (Part C). If a relay only the synthetic driver can reach ships while the dispatcher stays unwired, that is the dead-code trap — do not do that.
2. The deferred risk — **injection-driven URL/argument selection** (a model coerced into fetching an attacker URL) — is **out of G7-2's charter** (it lives in the tool-loop, #339) and is recorded on #339 as its release-blocker. G7-2's synthetic driver cannot and need not exercise it; G7-2's security surface is *what happens to bytes once a destination is chosen*, which is fully determinable without an LLM.

**What stays DEFERRED to G7-5 (human-gated):** ADR-0040 (incl. the new Stage-1 residual below) and the PRD §5/§7.1 rewrite. Do NOT edit `PRD.md` / `CLAUDE.md` / ADRs in G7-2 except factual amendments already permitted.

---

## Resolved design decisions (this brainstorm — 6-lens panel, unanimous)

- **D1 — Transport = dedicated relay (A).** New `src/alfred/gateway/egress_relay.py` (do **not** extend the payload-blind `egress_proxy.py` — fusing inspect-and-forward into the CONNECT splicer degrades the HARD-rule-#5 payload-blindness guarantee from structural to conventional). New in-core relay client kept **separate** from `EgressClient` (which is a stateless httpx-*proxy*-factory; the relay client is a stateful protocol caller). The wire is **HTTP POST over `alfred_internal`** — NOT a unix socket (the existing socket primitives are AF_UNIX/same-host and cannot cross the core↔gateway container boundary). The relay client's in-core httpx construction is import-guard-allowlisted.
- **D2 — Gateway TLS origination = IP-in-URL + `sni_hostname`.** The gateway resolves the destination once, validates it through the full G7-1 SSRF chain (`is_literal_ip` refuse, allowlist membership on the request-URL authority only, `is_globally_routable` on the resolved IP, `follow_redirects=False`), then builds the request with the **validated IP as the URL host** and `request.extensions["sni_hostname"] = original_hostname` so TLS SNI + cert-identity validate against the hostname while the TCP connect targets the pinned IP (no re-resolution → no DNS-rebinding window). `trust_env=False` on the gateway client too.
- **D3 — Gateway DLP = stages 2+3 (A).** The gateway re-runs the **secret-independent** stages: the generic API-key-shape regex (stage 2 — `redact_secret_shapes` is already broker-free) + a **net-new real canary scan** (stage 3, replacing the no-op stub). Stage 1 (broker redaction of known secret *values*) stays **core-only** — the gateway holds no vault, and replicating it would make the gateway a secret-holder (ADR-0036). **This is an honest ADR-0040 residual:** a broker-known secret the compromised core failed to redact that is neither API-key-shaped nor a registered canary survives the gateway pass. Do not overclaim "full second pass." `OutboundDlp` gets an **optional** `broker` (one code path, no fork). The pure token-matcher is extracted to `src/alfred/security/canary_matcher.py` (DRY across the inbound scanner + the new outbound stage). Gateway canary tokens arrive via **public startup config**, never a DB.
- **D4 — Egress-id = positional + content-hash integrity check (A).** `egress-id = f(adapter_id, inbound_id, session_id, call_index)` — a deterministic, injective function over an **unambiguous length-prefixed encoding** (so `turn=1,call=23` ≠ `turn=12,call=3`), never completion-order. The **redacted-body** content-hash is stored alongside; a duplicate egress-id whose body-hash differs **fails loud** (`EgressIdIntegrityError`, generic audit reason — no body oracle, constant-time digest compare). The ledger is **tri-state** durable Postgres (`committed_no_response` vs `committed_with_response`; the absent row is the implicit third state), mirroring `InboundIdempotency`, with its own autocommit session factory. Forged/unknown egress-ids are rejected **core-side** (the gateway holds no dedup state).

---

## Plan-review findings (2026-06-27 — security + architect; RESOLVE before implementing Parts B/C)

A 2-lens plan-review (security-engineer + architect, verifying against the tree) found Part A sound to start but **two CRITICAL blockers** + an architectural ruling that must be folded before Parts B/C. Recorded here so implementation does not proceed on the stale model.

### Round 2 — full 8-lens `/review-plan` (2026-06-27)

An 8-specialist `/review-plan` (architect, reviewer, test, security, memory, core, provider, devops) on the round-1-folded plan. Part A largely sound; Parts B/C need the items below folded. Corroboration tags note where multiple lenses converged.

- **R2-Critical (ARCH-1) — C1 not folded into the executable tasks.** The C1 reconciliation is recorded but C3 still describes the impossible "re-point"; G7-2c-2's end-to-end exit is unachievable until the C1 rework lands in the tasks themselves.
- **R2 design clarification (CORE-1, `[core+architect]`) — C1 shape is gateway-returns-bytes / core-mints-T3.** "Re-home the ContentHandle mint into the gateway" is **structurally impossible** — minting T3 needs the boot `CapabilityGateNonce`, which the gateway (ADR-0036) does not hold. End-state: the **gateway fetches + returns the response body over the framed wire; the CORE mints the `ContentHandle` + tags T3 + runs the one extractor** (as C2 already does). This also resolves the parallel-extractor concern. Update the C1 prose accordingly.
- **R2-High ① — the in-doubt / GET-refire / idempotency knot `[corroborated ×5]` — redesign as ONE unit:** (TE-1) the barrier test self-contradicts — kill-before-`record_response` leaves `committed_no_response`, so the replay hits `IntentInDoubt`, and a GET auto-refire makes `fire_count==2` ≠ the asserted `==1`; (MEM-1) `session_scope` rolls back the intent on the barrier-kill exception → replay re-fires → defeats the ledger (use commit-then-fire in a dedicated session; there is no `_autocommit_audit` symbol — the real pattern is a separate `session_scope` session); (MEM-3) `record_response`'s `WHERE state='committed_no_response'` raises on a second (already-recorded) call — make it idempotent; (SEC-2/PROV-4) the egress-id is never forwarded as the remote idempotency key, so GET auto-refire has zero at-most-once protection. Resolve H3 here: in-doubt ⇒ `EgressInDoubtError` by default; auto-refire only on a manifest-declared idempotent tool, and forward the egress-id as the remote `Idempotency-Key` when forwarding.
- **R2-High ② — C2 gate-seam not folded `[corroborated ×3]`:** C2's task body still calls the gateless `extract()` (`quarantine.py:404`) instead of `quarantined_to_structured(…, gate: CapabilityGate)` (`:1385`); and `extract(handle, schema)` has **no `canonical_user_id`** param (CORE-2) — so H1's per-user-rate-limiter premise is dead plumbing on the live path. Thread the gate; drop or re-source `canonical_user_id`.
- **R2-High ③ — gateway TLS origination bugs (PROV-1/PROV-2):** httpx auto-sends `Host: <IP>` upstream (CDNs/vhosts reject) → `_safe_headers` must inject `Host: <hostname>`; and **connection pooling defeats the per-request cert-vs-hostname check** (shared-IP allowlisted hostnames reuse one TLS connection → cert-identity bypass) → disable keepalive (`max_keepalive_connections=0`) or use a per-hostname client + a no-reuse test. (PROV-3: IPv6 host must be bracketed in the URL but unbracketed in `sni_hostname`.)
- **R2-High ④ — replay return shape + raw-T3 barrier:** `ExtractionResult` has **no `deduplicated` field** (reviewer-1) — define the stored-T2 ↔ replay-return serialization; C1 misuses `scan_for_outbound` (returns a `ScannedOutboundBody` wrapper, not `str`) (reviewer-2); `RelayEgressClient.fire` should return an already-staged `ContentHandle`, not a readable raw-T3 `.body` (SEC-1, dovetails with CORE-1's core-mints model).
- **R2-High ⑤ — CI gates (TE-2/devops-1):** the two integration-branch files (`egress_idempotency.py`, `egress_response_extract.py`) go in the **combined** coverage gate ONLY (unit-only data → RED); and the framed-transport ruling means **remove** `egress/relay_client.py` from the import-guard `_CONSTRUCT_ALLOWLIST` (no in-core httpx) while keeping its coverage gate. Fix the file-map + C1/A4 instructions accordingly.
- **R2-Medium:** `language` → `String(16)` (MEM-2, convention); `EgressRequest.body` modelled as empty/optional + named DiD-infra if (A) (ARCH-3); `TurnEgressContext` cannot reach `dispatch_web_fetch` today (only `user_id`+`correlation_id`) — thread it explicitly, never synthesize from `correlation_id` (CORE-3); the real HoL is the **shared single quarantine child** at the §4.3 extract, not the relay semaphore — C5 must assert a bounded-timeout *refusal*, and name the action-deadline as the bound (CORE-4); split the `extract.assert_not_called` T3 negative into its own `IntentReplayComplete` setup (TE-3); add a fired-but-unextracted audit owner (SEC-3); `alfred gateway healthcheck` now covers 1 of 3 I/O planes — probe the relay or record a residual (devops-2); add a *positive* compose-wiring invariant (core URL == gateway port; canary/allowlist env present) (devops-3).
- **R2-Low:** `egress_id` PK `String(64)` + consider a nullable user-scoped column while the table is empty (MEM-4); canary env-delivery residual for §9/ADR-0040 (SEC-4).

- **[CRITICAL C1 — the web.fetch consumer reality breaks the mode-b body model].** Verified against the tree: the live `web.fetch` egress runs in the **`alfred_web_fetch` plugin subprocess** (`plugins/alfred_web_fetch/web_fetch_plugin.py` — `aiohttp.ClientSession.get(url, allow_redirects=False)`), is **GET-only with NO request body**, and the **T3 tag + content-store write already happen transport-side** (`StdioTransport._read_response`); `dispatch_web_fetch` returns a `ContentHandle`, it never opens a socket. Consequences: (a) mode-b's headline "gateway re-runs DLP on the redacted **body**" (decision 12) has **no live exerciser** — web.fetch sends no body, so the body-DLP layer is synthetic-driver-only (the dead-code trap the charter forbids); (b) routing web.fetch through the gateway is **not a "re-point"** — it means **re-homing the fetch out of the subprocess** (its TLS/size/MIME/redirect enforcement + the content-store/`ContentHandle` mint) into the gateway relay, an **L-sized** change; (c) C2's in-core `ContentHandle` mint would be a **parallel extractor**, which spec §4.3 explicitly forbids ("the **one** production seam, not a parallel extractor"). **DECISION NEEDED (see C1 reconciliation below).**
- **[CRITICAL C2 — §4.3 must go through the gate-checked seam].** Task C2 calls `QuarantinedExtractor.extract(handle, schema)` directly. The sole sanctioned path is `quarantined_to_structured(...)` (`security/quarantine.py:~1385`), which runs `gate.check_content_clearance(plugin_id="alfred.quarantined-llm", hookpoint="quarantine.dereference", content_tier="T3")` **before** extract. **Fix:** C2 routes through `quarantined_to_structured` (or replicates the gate-first check) with a **required** `CapabilityGate`; add a gate-denial test (deny ⇒ no extract, no T2 stored).
- **[RULING — transport = framed JSON protocol, NOT HTTP POST].** Adopt the architect's decisive ruling: the core↔gateway relay uses a **length-prefixed JSON-frame protocol over `asyncio.start_server`** (reusing `egress_proxy.py`'s `_handle_client`/`_serve_connection`/`_on_connection_done`/bounded-read/`_drain_connections` discipline). Rationale: no second in-core httpx construction site → the import-guard `_CONSTRUCT_ALLOWLIST` stays at one entry (the connectivity-free-core budget is not spent on an internal hop); smaller, `extra="forbid"`-validated parse surface than a hand-rolled HTTP/1.1 server (no CL/TE smuggling). The envelope types (`EgressRequest`/`EgressResponse`, `model_dump_json()`) are unchanged — only the transport bytes differ. **Effect:** Task B4 drops the "minimal HTTP/1.1 handler"; Task C1 drops the `egress/relay_client.py` import-guard allowlist entry; the gateway upstream-origination client (`gateway/egress_relay.py`, D2 IP-in-URL+`sni_hostname`) is the ONLY new httpx site and stays gateway-side-allowlisted.
- **[HIGH H1 — `canonical_user_id` source].** The egress-extract `(canonical_user_id, tool-call id)` key has no production source (no inbound user on a tool-originated call). Add the canonical user id to `TurnEgressContext` (threaded from the turn) or record it as a residual until #339; do not let it silently become a constant (it keys the per-user quarantine rate-limiter).
- **[HIGH H2 — gateway trip must be durably audited core-side].** The gateway holds no DB (ADR-0036), so its DLP/canary-trip deny is structlog-only — but HARD rule #7 requires a non-skippable durable row for a canary trip. **Fix:** the relay-deny path returns a distinct `deny_reason` that the in-core relay client turns into `EgressDeniedError`, which the core records via its DB-backed `AuditWriter`. Name the core-side audit owner; gateway structlog + the durable signed reconcile residual go to ADR-0040/G7-5.
- **[HIGH H3 — `IntentInDoubt` re-fire].** Do NOT infer "safe to re-fire" from `method == GET` (HTTP idempotency is a remote convention, not a guarantee; the live consumer is a GET → it'd take the re-fire branch every time, making the ledger at-most-once for zero live calls). **Fix:** in-doubt ⇒ `EgressInDoubtError` by default; auto-refire only when the **tool manifest** declares idempotency. Reconcile with §5's "egress-id as the remote idempotency key" (Task B4 currently never forwards it).
- **[HIGH H4 — `_RawToolRequest` undefined].** It is consumed by C1/C2 but never produced. Define it (frozen Pydantic, fields enumerated; the C1 reconciliation decides whether it even has a `body`) in `relay_protocol.py` (B1) and add it to the type-consistency list.
- **[HIGH H5 — integrity-mismatch / in-doubt / deny audit owners].** `commit_intent` raising `EgressIdIntegrityError` (and `EgressInDoubtError`, and gateway-DLP `EgressDeniedError`) needs a named core-side `AuditWriter` owner emitting exactly one non-skippable, value-free (no body/hash oracle) row. The DAO "logs nothing" by design (mirrors `inbound_idempotency`); the relay-client/extractor wrapper is the owner.
- **[HIGH H6 — request-line/header smuggling].** Validate `req.method` against a closed set (GET-only for the live path); strip caller-supplied `Host`/`Content-Length`/`Transfer-Encoding` before forwarding; test a `Host: evil` drop + CRLF-method refusal. (The destination SSRF chain is verified correct; the request-line/headers are the unguarded surface.)
- **[MEDIUM].** Fix stale line refs (`extract` at :624, `del canonical_user_id` at :155, canary compile loop ~:322). Record the env-delivered gateway canary tokens as a (host-root-readable) residual. State B4 scans the **request** body only (response canary/T3 = the §4.3 path). Reconcile the now-permanently-`False` `OutboundDlpScanResult.canary_tripped` field (a trip raises). Make `record_response` idempotent on already-recorded rows. Move the "mode-(a) residual" out of the executable corpus into ADR-0040 prose. Make the "compromised core → gateway catches" corpus entry inject a **no-op core DLP** so the gateway is provably the catcher.

**C1 reconciliation — the decision for the next session.** Mode-b for web.fetch is really "**the gateway performs the fetch on behalf of the core**" (the subprocess's job moves to the gateway), not "core redacts a body." Two shapes: **(A) Relay-as-fetcher** — re-home `web_fetch_plugin.py`'s fetch + TLS/size/MIME/redirect + content-store/handle-mint into `gateway/egress_relay.py`; `dispatch_web_fetch` calls the relay client; the §4.3 response uses the **existing** transport-side T3 seam, not a new mint. L-sized but it is the real connectivity-free end-state (required by G7-3). The body-DLP second pass (decision 12) ships as **honestly-named DiD infrastructure awaiting a body-sending tool** (proven by the synthetic driver + the corpus), like the gateway proxy shipped before all its consumers. **(B) Split** — G7-2 ships Part A (ledger) + the gateway relay infra + the framed transport, proven by the synthetic driver, and the web.fetch **re-home** becomes its own sub-slice (G7-2.5) landing with/just before G7-3's connectivity flip. Recommend confirming (A)-as-end-state with the re-home tracked as its own task, since the body-DLP-without-a-body-tool reality means "live web.fetch cutover" is the fetch re-home, not a body redaction.

---

## PR decomposition (3 PRs; each leaves `main` coherent; no PR opens a side-effecting-egress-without-ledger window)

- **G7-2a — egress-id + `TurnEgressContext` + the tri-state ledger.** Pure + DB infra, no egress consumer. The ledger must exist before any relay-send path.
- **G7-2b — `gateway/egress_relay.py` (gateway side only) + gateway DLP (stages 2+3) + real canary.** The gateway inspecting-relay endpoint: parse the envelope, re-run DLP, enforce the tool allowlist + SSRF chain, originate the real TLS, return the response. Tested entirely **gateway-side** (loopback fake upstream + a test HTTP client) — **no in-core consumer, no in-core T3 handling**, so no production caller exists.
- **G7-2c — in-core relay client (ledger-wrapped) + §4.3 T3 response-extract, then the dispatcher re-point + synthetic driver + adversarial corpus.** Ships as **two PRs**: **G7-2c-1** (the core relay mechanism: `relay_client.py` + the §4.3 tag-at-ingestion/extract/record-T2 — fires only via tests, no dispatcher re-point) and **G7-2c-2** (re-point the real `dispatch_web_fetch` at the relay — the side-effecting flip, guarded by the G7-2a ledger — + the synthetic driver + the release-blocking barrier test + the §9 corpus).

Sequencing rule: **the relay-send path and the ledger that wraps it must never exist in separate merges** — G7-2a (ledger) precedes any fire; the in-core fire (G7-2c-1) is ledger-wrapped from its first line and has no production caller until the dispatcher re-point (G7-2c-2) merges last. The gateway relay (G7-2b) enforces the allowlist + DLP independently, so even the first core call is doubly guarded.

---

## File structure map

**Created:**

- `src/alfred/egress/egress_id.py` — `TurnEgressContext`, `compute_egress_id`, `compute_body_hash`, `EgressIdIntegrityError` (pure; rides nothing — see coverage note). *(G7-2a)*
- `src/alfred/memory/egress_idempotency.py` — `EgressIdempotencyStore` Protocol + `PostgresEgressIdempotencyStore` DAO (tri-state). *(G7-2a)*
- `src/alfred/memory/migrations/versions/0023_egress_idempotency.py` — the ledger table migration. *(G7-2a)*
- `src/alfred/egress/relay_client.py` — in-core mode-b relay client (HTTP POST → gateway; ledger-wrapped). *(G7-2c-1)*
- `src/alfred/gateway/egress_relay.py` — gateway mode-b inspecting relay endpoint (DLP + SSRF + TLS origination). *(G7-2b)*
- `src/alfred/security/canary_matcher.py` — shared pure canary token-matcher. *(G7-2b)*
- `src/alfred/gateway/egress_relay_audit.py` — mode-b relay audit vocab (structlog tier; separate from the CONNECT field-allowlist). *(G7-2b)*
- `tests/integration/egress/conftest.py` — the epic-wide `fake_external_world` fixture. *(G7-2c)*
- `tests/integration/egress/test_egress_barrier_dedup_postgres.py` — the release-blocking §5 barrier test. *(G7-2c)*
- `tests/integration/test_egress_idempotency_postgres.py`, `tests/integration/test_migration_0023_egress_idempotency.py` — ledger contract + migration round-trip. *(G7-2a)*
- `tests/adversarial/dlp_egress/*.yaml` + executable drivers; `tests/adversarial/tier_laundering/*` additions. *(G7-2c)*

**Modified:**

- `src/alfred/security/dlp.py` — `OutboundDlp.broker` becomes optional; `_canary_stub` → real canary stage via `canary_matcher`. *(G7-2b)*
- `src/alfred/config/settings.py` — add the relay-endpoint URL field (core side). *(G7-2c-1)*
- `docker-compose.yaml` + `.env.example` — relay endpoint env wiring (never host-published). *(G7-2c)*
- `src/alfred/cli/gateway/_commands.py` — mount the relay endpoint as a third sibling `TaskGroup` task. *(G7-2b)*
- `src/alfred/plugins/web_fetch/fetch_dispatcher.py` — re-point outbound through the relay client. *(G7-2c)*
- `tests/unit/egress/test_in_core_http_egress_guard.py` — add `egress/relay_client.py` to `_CONSTRUCT_ALLOWLIST`. *(G7-2c-1)*
- `tests/unit/security/test_dlp.py` — retire `test_canary_stub_is_identity_in_slice_2`; add the real-canary suite. *(G7-2b)*
- `.github/workflows/ci.yml` — extend BOTH egress coverage steps + BOTH `hashFiles()` guards. *(G7-2a adds the ledger DAO; G7-2b adds the relay + audit files)*

---

## Part A — G7-2a: egress-id + `TurnEgressContext` + the tri-state ledger

**PR scope:** pure egress-id machinery + the durable tri-state Postgres ledger. No egress consumer. Self-contained and fully testable.

### Task A1: The egress-id function + `TurnEgressContext` (pure)

**Files:**

- Create: `src/alfred/egress/egress_id.py`
- Test: `tests/unit/egress/test_egress_id.py`

**Interfaces:**

- Produces:
  - `TurnEgressContext` — frozen Pydantic model: `adapter_id: str`, `inbound_id: str`, `session_id: str`. (The per-turn anchor; `(adapter_id, inbound_id)` is the committed G0 identity. Constructed by whoever drives the turn — the synthetic driver in G7-2, the tool-loop in #339.)
  - `compute_egress_id(ctx: TurnEgressContext, *, call_index: int) -> str` — deterministic, injective; sha256 hex over an **unambiguous length-prefixed encoding** of `(adapter_id, inbound_id, session_id, call_index)`. Never uses wall-clock / completion order.
  - `compute_body_hash(redacted_body: str) -> str` — sha256 hex of the UTF-8 redacted body.
  - `EgressIdIntegrityError(AlfredError)` — `reason = "egress_id_integrity_mismatch"`; raised when a duplicate egress-id carries a different body-hash. Message via `t()`; carries no hash values (no oracle).

- [ ] **Step 1: Write the failing tests** (`tests/unit/egress/test_egress_id.py`)

```python
import hypothesis.strategies as st
from hypothesis import assume, given

from alfred.egress.egress_id import (
    TurnEgressContext,
    compute_body_hash,
    compute_egress_id,
)

_CTX = TurnEgressContext(adapter_id="discord", inbound_id="msg-1", session_id="sess-1")

def test_determinism_same_inputs_same_id() -> None:
    assert compute_egress_id(_CTX, call_index=0) == compute_egress_id(_CTX, call_index=0)

def test_distinct_call_index_distinct_id() -> None:
    assert compute_egress_id(_CTX, call_index=0) != compute_egress_id(_CTX, call_index=1)

def test_no_separator_collision() -> None:
    # The classic concatenation bug: (turn=1, call=23) must NOT collide with (turn=12, call=3).
    a = TurnEgressContext(adapter_id="discord", inbound_id="1", session_id="23")
    b = TurnEgressContext(adapter_id="discord", inbound_id="12", session_id="3")
    assert compute_egress_id(a, call_index=0) != compute_egress_id(b, call_index=0)

def test_golden_vector_is_stable() -> None:
    # A frozen golden so a hash-algo / field-order change fails loud, not silently re-namespaces.
    assert compute_egress_id(_CTX, call_index=0) == (
        "GOLDEN_TO_FILL_FROM_FIRST_RUN"  # replace with the literal the implementation emits
    )

@given(
    a=st.text(min_size=1), b=st.text(min_size=1), c=st.text(min_size=1), i=st.integers(min_value=0),
    a2=st.text(min_size=1), b2=st.text(min_size=1), c2=st.text(min_size=1), i2=st.integers(min_value=0),
)
def test_injective(a, b, c, i, a2, b2, c2, i2) -> None:
    assume((a, b, c, i) != (a2, b2, c2, i2))
    id1 = compute_egress_id(TurnEgressContext(adapter_id=a, inbound_id=b, session_id=c), call_index=i)
    id2 = compute_egress_id(TurnEgressContext(adapter_id=a2, inbound_id=b2, session_id=c2), call_index=i2)
    assert id1 != id2

def test_body_hash_of_redacted_is_deterministic() -> None:
    assert compute_body_hash("redacted") == compute_body_hash("redacted")
    assert compute_body_hash("a") != compute_body_hash("b")
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/unit/egress/test_egress_id.py -v`
Expected: FAIL (module not found / golden placeholder).

- [ ] **Step 3: Implement** (`src/alfred/egress/egress_id.py`)

```python
"""Deterministic, injective egress-id + body-hash for the egress idempotency ledger (Spec C §5)."""

from __future__ import annotations

import hashlib

from pydantic import BaseModel, ConfigDict

from alfred.errors import AlfredError
from alfred.i18n import t


class TurnEgressContext(BaseModel):
    """The committed per-turn anchor for egress-id stamping. Constructed turn-side."""

    adapter_id: str
    inbound_id: str
    session_id: str
    model_config = ConfigDict(frozen=True, extra="forbid")


def _length_prefixed(*fields: str) -> bytes:
    # Unambiguous encoding: each field is its UTF-8 byte length (8-byte big-endian) + bytes.
    # No separator can be forged across field boundaries -> injective over the field tuple.
    out = bytearray()
    for f in fields:
        raw = f.encode("utf-8")
        out += len(raw).to_bytes(8, "big") + raw
    return bytes(out)


def compute_egress_id(ctx: TurnEgressContext, *, call_index: int) -> str:
    encoded = _length_prefixed(ctx.adapter_id, ctx.inbound_id, ctx.session_id, str(call_index))
    return hashlib.sha256(encoded).hexdigest()


def compute_body_hash(redacted_body: str) -> str:
    return hashlib.sha256(redacted_body.encode("utf-8")).hexdigest()


class EgressIdIntegrityError(AlfredError):
    """A duplicate egress-id arrived with a different redacted-body hash (non-deterministic re-run)."""

    reason = "egress_id_integrity_mismatch"

    def __init__(self, *, egress_id: str) -> None:
        self.egress_id = egress_id
        # No hash values in the message — a mismatch surface must not be a body-content oracle.
        super().__init__(t("egress.id_integrity_mismatch", egress_id=egress_id))


__all__ = [
    "EgressIdIntegrityError",
    "TurnEgressContext",
    "compute_body_hash",
    "compute_egress_id",
]
```

- [ ] **Step 4: Fill the golden vector** — run the test once, copy the actual `compute_egress_id(_CTX, call_index=0)` hex into `test_golden_vector_is_stable`, re-run green.

- [ ] **Step 5: Add the i18n keys** — add `egress.id_integrity_mismatch` to `src/alfred/i18n/_spec_c_reserve.py` (the Spec C reserve anchor) and extend `tests/unit/test_catalog_g7_egress_keys.py`'s `G7_EGRESS_KEYS`. Run the i18n drift flow (Global Constraints).

- [ ] **Step 6: `make check` + commit**

```bash
uv run pytest tests/unit/egress/test_egress_id.py -v
git add src/alfred/egress/egress_id.py tests/unit/egress/test_egress_id.py src/alfred/i18n/_spec_c_reserve.py tests/unit/test_catalog_g7_egress_keys.py locale/
git commit -m "feat(egress): deterministic injective egress-id + body-hash (#333)"
```

### Task A2: The tri-state ledger ORM model + migration

**Files:**

- Modify: `src/alfred/memory/models.py` (append `EgressIdempotency` near `InboundIdempotency` ~line 726)
- Create: `src/alfred/memory/migrations/versions/0023_egress_idempotency.py` (down_revision `0022`)
- Test: `tests/integration/test_migration_0023_egress_idempotency.py` (mirror `test_migration_0018_inbound_idempotency.py`)

**Interfaces:**

- Produces: table `egress_idempotency` with columns `egress_id` (PK, String(255)), `adapter_id` String(128), `inbound_id` String(255), `session_id` String(255), `call_index` Integer, `body_hash` String(64), `state` String(32) CHECK in `('committed_no_response','committed_with_response')`, `response` Text NULL, `language` String(35) NULL, `committed_at` timestamptz server-default `now()`; index `ix_egress_idempotency_committed_at`.

- [ ] **Step 1: Add the ORM model** (`src/alfred/memory/models.py`)

```python
class EgressIdempotency(Base):
    """Durable tri-state egress dedup ledger (Spec C / G7-2, §5).

    Mirrors InboundIdempotency. ``response`` stores the POST-extraction T2 (never raw T3),
    so a duplicate-egress replay returns stored T2 — never re-hands T3 to the orchestrator.
    ``language`` carries the BCP-47 tag because this row holds user-derived content (i18n #3).
    """

    __tablename__ = "egress_idempotency"

    egress_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    adapter_id: Mapped[str] = mapped_column(String(128), nullable=False)
    inbound_id: Mapped[str] = mapped_column(String(255), nullable=False)
    session_id: Mapped[str] = mapped_column(String(255), nullable=False)
    call_index: Mapped[int] = mapped_column(Integer, nullable=False)
    body_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False)
    response: Mapped[str | None] = mapped_column(Text, nullable=True)
    language: Mapped[str | None] = mapped_column(String(35), nullable=True)
    committed_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        sa.CheckConstraint(
            "state IN ('committed_no_response', 'committed_with_response')",
            name="ck_egress_idempotency_state",
        ),
        sa.CheckConstraint(
            "(state = 'committed_no_response') = (response IS NULL)",
            name="ck_egress_idempotency_response_matches_state",
        ),
        Index("ix_egress_idempotency_committed_at", "committed_at"),
    )
```

- [ ] **Step 2: Write the migration** (`0023_egress_idempotency.py`) — mirror `0018`'s structure (`op.create_table` + the two CHECK constraints + the retention index; `downgrade` drops index `if_exists=True` + `DROP TABLE IF EXISTS`). `revision = "0023"`, `down_revision = "0022"`.

- [ ] **Step 3: Migration round-trip integration test** — mirror `tests/integration/test_migration_0018_inbound_idempotency.py`: upgrade to `0023`, assert the table + CHECK + index exist; downgrade, assert gone.

- [ ] **Step 4: Run + commit**

```bash
uv run pytest tests/integration/test_migration_0023_egress_idempotency.py -v
git add src/alfred/memory/models.py src/alfred/memory/migrations/versions/0023_egress_idempotency.py tests/integration/test_migration_0023_egress_idempotency.py
git commit -m "feat(egress): tri-state egress idempotency ledger table + migration 0023 (#333)"
```

### Task A3: The tri-state DAO

**Files:**

- Create: `src/alfred/memory/egress_idempotency.py`
- Test: `tests/integration/test_egress_idempotency_postgres.py` (mirror `test_inbound_idempotency_postgres.py`)

**Interfaces:**

- Consumes: `compute_body_hash` (A1); `session_scope` callable (`memory/db.py` `build_session_scope`).
- Produces:
  - `EgressIdempotencyStore` (`@runtime_checkable` Protocol).
  - DAO results — a discriminated union: `IntentFresh` (no row — caller fires), `IntentReplayComplete(response: str, language: str | None)` (existing `committed_with_response` — caller returns stored T2 deduplicated), `IntentInDoubt` (existing `committed_no_response` — prior fire outcome unknown).
  - `PostgresEgressIdempotencyStore.commit_intent(*, egress_id, adapter_id, inbound_id, session_id, call_index, body_hash) -> IntentFresh | IntentReplayComplete | IntentInDoubt` — atomic `INSERT … ON CONFLICT (egress_id) DO NOTHING RETURNING egress_id`; on conflict, `SELECT` the row, **compare `body_hash` (constant-time)** → raise `EgressIdIntegrityError` on mismatch, else map state → `IntentReplayComplete`/`IntentInDoubt`.
  - `.record_response(*, egress_id, response, language) -> None` — `UPDATE … SET state='committed_with_response', response=:r, language=:l WHERE egress_id=:id AND state='committed_no_response'` (idempotent; raises if no row).
  - `.prune_expired(*, older_than: dt.datetime) -> int` — `DELETE … WHERE committed_at < :older_than` (TTL sweep; injected clock for tests).

- [ ] **Step 1: Write the failing integration tests** — cover, against real Postgres (testcontainers): fresh→intent row is `committed_no_response`; `record_response`→`committed_with_response`; duplicate same-hash + `committed_with_response`→`IntentReplayComplete(stored T2)`; duplicate same-hash + `committed_no_response`→`IntentInDoubt`; duplicate **different**-hash→`EgressIdIntegrityError`; 8-way concurrent `commit_intent`→exactly one `IntentFresh` (lift `test_concurrent_commits_exactly_one_winner`); `prune_expired` with a back-dated row deletes it.

- [ ] **Step 2–4:** Implement the DAO (raw `sa.text` SQL, `async with self._session_scope()`, mirror `PostgresInboundIdempotencyStore`); use `hmac.compare_digest` for the body-hash compare. Run green. Commit.

```bash
git commit -m "feat(egress): tri-state egress idempotency DAO with integrity + TTL sweep (#333)"
```

### Task A4: CI coverage gate for the ledger DAO

**Files:** Modify `.github/workflows/ci.yml` (both egress steps + both guards).

- [ ] **Step 1:** Append `src/alfred/memory/egress_idempotency.py` to the `--include` list AND the `hashFiles()` guard in BOTH the `python` job (~489/491) and the `coverage-gates` job (~1627/1629). The DAO's `committed_no_response` branch is exercised by integration data, so the **combined** gate is the one that reaches 100% — confirm the barrier/contract integration tests emit to the `coverage-integration` artifact.
- [ ] **Step 2:** `egress_id.py` is pure and rides nothing — add it to the SAME egress `--include` lists (both jobs) so it gets a named 100% gate too (it is security-boundary logic).
- [ ] **Step 3:** Verify locally with the CI pattern: `uv run coverage run -m pytest tests/unit/egress/test_egress_id.py tests/integration/test_egress_idempotency_postgres.py && uv run coverage report --include='src/alfred/egress/egress_id.py,src/alfred/memory/egress_idempotency.py' --fail-under=100`. Commit.

```bash
git commit -m "ci(egress): name 100% line+branch gates for egress-id + ledger DAO (#333)"
```

**G7-2a exit:** ledger + egress-id machinery on `main`, fully tested, **no egress consumer** — no side-effecting path exists, so no double-fire window. Run the full `/review-pr` fleet (security ALWAYS) + CodeRabbit, resolve threads, `gh pr merge --rebase`.

---

## Part B — G7-2b: the gateway inspecting relay endpoint + gateway DLP (stages 2+3) + real canary

**PR scope:** the **gateway side only** — the inspecting relay endpoint, the shared canary matcher, the broker-optional `OutboundDlp`, and the relay audit vocab. Tested entirely gateway-side with a loopback fake upstream + a test HTTP client. **No in-core consumer, no in-core T3 handling** in this PR.

> **Open sub-decision for plan-review:** the core↔gateway relay wire. This plan specifies **HTTP POST (httpx core-side → a minimal framework-free asyncio HTTP/1.1 handler gateway-side)** per the provider-engineer panel position (verified against pinned httpx 0.28.1). The alternative is a **length-prefixed JSON frame protocol** over `asyncio.start_server` (core uses raw asyncio → no in-core httpx → the import-guard needs no new allowlist entry). Trade-off: HTTP is the panel default and gives natural request/response semantics; the framed protocol is ~20 lines simpler and keeps the in-core import-guard story trivial. Both are payload-explicit and `alfred_internal`-only. **Let the plan-review fleet rule before implementing B4/C-1.** The tasks below assume HTTP POST; if the framed protocol wins, B4's parser + C-1's client swap accordingly (the envelope types and all enforcement are identical either way).

### Task B1: shared relay protocol envelopes + the canary matcher

**Files:**

- Create: `src/alfred/egress/relay_protocol.py`
- Create: `src/alfred/security/canary_matcher.py`
- Test: `tests/unit/egress/test_relay_protocol.py`, `tests/unit/security/test_canary_matcher.py`

**Interfaces:**

- Produces:
  - `EgressRequest` — frozen Pydantic: `method: str`, `url: str`, `headers: Mapping[str, str]`, `body: str` (the **redacted** body), `egress_id: str`. `model_config = ConfigDict(frozen=True, extra="forbid")`.
  - `EgressResponse` — frozen Pydantic: `status: int`, `headers: Mapping[str, str]`, `body: str`.
  - `CanaryMatcher` — pure token-matcher extracted from `InboundCanaryScanner`'s logic:
    - `__init__(self, *, tokens: Sequence[CanaryToken])` — compiles `re.compile(re.escape(t.value), re.IGNORECASE)` per token; reuse the existing `CanaryToken` value object (with its blank-token `__post_init__` guard) from `plugins/web_fetch/canary_scanner.py`.
    - `first_match(self, text: str) -> str | None` — returns the matched token value (for the audit row) or `None`. Pure, no I/O, no store coupling.

- [ ] **Step 1:** Write `test_canary_matcher.py` — happy (a planted token returns its value), clean (no token → `None`), case-insensitive, non-UTF8-safe input, blank-token rejection (constructing with a blank token raises via `CanaryToken.__post_init__`). Write `test_relay_protocol.py` — round-trip `model_dump_json()`/`model_validate_json()`; `extra="forbid"` rejects unknown fields.
- [ ] **Step 2:** Run → FAIL.
- [ ] **Step 3:** Implement both. `CanaryMatcher` lifts the compile + `pattern.search` loop from `canary_scanner.py:323` (DRY — the inbound scanner is refactored to depend on `CanaryMatcher` in Step 5).
- [ ] **Step 4:** Run → PASS.
- [ ] **Step 5: DRY the inbound scanner** — refactor `InboundCanaryScanner` to construct a `CanaryMatcher` internally and call `first_match` instead of its own inline pattern loop. Run `uv run pytest tests/unit/plugins/web_fetch/test_canary_scanner_host_side.py -v` → still PASS (behaviour-neutral refactor).
- [ ] **Step 6:** `make check` + commit.

```bash
git commit -m "feat(egress): shared CanaryMatcher + relay protocol envelopes; DRY the inbound scanner (#333)"
```

### Task B2: broker-optional `OutboundDlp` + the real canary stage

**Files:**

- Modify: `src/alfred/security/dlp.py`
- Modify: `tests/unit/security/test_dlp.py` (retire `test_canary_stub_is_identity_in_slice_2`; add the real-canary suite)

**Interfaces:**

- Consumes: `CanaryMatcher` (B1).
- Produces:
  - `OutboundDlp.__init__(self, *, broker: _BrokerLike | None, audit: _AuditSink, canary: CanaryMatcher | None = None)` — `broker` and `canary` both **optional**. Core-side: all three (broker + regex + canary). Gateway-side: `broker=None` (stages 2+3 only). One code path, no fork.
  - Stage 3 (`_canary_stub` → `_scan_canary`): if `self._canary` is set and `first_match` hits, **fail loud** — raise a typed `OutboundCanaryTripped(AlfredError)` (`reason = "outbound_canary_tripped"`) AFTER writing the trip audit row; on an internal matcher error, also fail loud (never fail-open). When `canary is None`, the stage is a no-op (preserves today's core behaviour until the core wires a matcher — out of G7-2 scope).
  - `OutboundCanaryTripped` exported from `dlp.py`.

- [ ] **Step 1: Update the failing tests** — DELETE `test_canary_stub_is_identity_in_slice_2`. Add: with a `CanaryMatcher`, a body containing a token raises `OutboundCanaryTripped` + emits a `dlp.outbound_canary_tripped` audit row; a clean body returns redacted text; `broker=None` skips stage 1 (a broker-only-detectable value passes through, an API-key-shaped value is still redacted by stage 2, a canary still trips at stage 3); an internal matcher error fails loud (inject a matcher whose `first_match` raises → assert it propagates, not swallowed).
- [ ] **Step 2:** Run → FAIL.
- [ ] **Step 3: Implement** — make `broker` optional (`if self._broker is not None:` around the stage-1 block; omit `"broker"` from `stages_triggered` when absent), replace `_canary_stub` with the real `_scan_canary`, add `OutboundCanaryTripped`. Keep the audit-on-modification contract (raises propagate — HARD rule #7).
- [ ] **Step 4:** Run → PASS. `dlp.py` rides the `security/*` glob coverage gate — confirm `uv run coverage run -m pytest tests/unit/security/test_dlp.py && uv run coverage report --include='src/alfred/security/dlp.py' --fail-under=100` is 100%.
- [ ] **Step 5:** i18n keys for the canary-trip reason; i18n drift flow. `make check` + commit.

```bash
git commit -m "feat(dlp): broker-optional OutboundDlp + real outbound canary stage; retire the no-op stub (#333)"
```

### Task B3: the mode-b relay audit vocab

**Files:**

- Create: `src/alfred/gateway/egress_relay_audit.py`
- Test: `tests/unit/gateway/test_egress_relay_audit.py`

**Interfaces:**

- Produces (modelled on `gateway/egress_audit.py` — **structlog tier only**, gateway holds no DB/signing key):
  - `EgressRelayEvent` constants: `EGRESS_RELAY_FORWARDED_EVENT = "gateway.egress.relay_forwarded"`, `EGRESS_RELAY_DENIED_EVENT = "gateway.egress.relay_denied"`, `EGRESS_RELAY_CANARY_EVENT = "gateway.egress.relay_canary_tripped"`.
  - `EgressRelayDenyReason` enum (closed vocab): `DESTINATION_NOT_ALLOWLISTED`, `LITERAL_IP_TARGET`, `RESOLVED_IP_NOT_GLOBAL`, `DLP_REDACTED`, `CANARY_TRIPPED`, `RESPONSE_TOO_LARGE`, `MALFORMED_ENVELOPE`, `UPSTREAM_REDIRECT_REFUSED`.
  - `record_egress_relay(event: str, fields: Mapping[str, object]) -> None` — enforces a **per-event field-allowlist** distinct from the CONNECT one (do NOT widen `egress_audit`'s `{destination[, reason]}`): forwarded ⇒ `{destination, method, status, egress_id, dlp_redactions}`; denied ⇒ `{destination, reason}`; canary ⇒ `{destination, reason}`. A missing or extra field fails loud (payload-blindness floor for the relay's own audit). `reason_i18n_key(reason)` → `gateway.egress.relay_denied.<reason>`.
  - `GATEWAY_EGRESS_RELAY` Counter `{outcome}` (forwarded/denied/error).

- [ ] **Steps 1–4:** TDD the field-allowlist enforcement (exact-set per event; missing field raises; extra field raises) + the reason→i18n-key mapping. Mirror `tests/unit/gateway/test_egress_audit.py`. i18n keys + drift flow. Commit.

```bash
git commit -m "feat(gateway): mode-b relay audit vocab (structlog tier, separate field-set) (#333)"
```

### Task B4: the gateway inspecting relay endpoint *(the crux)*

**Files:**

- Create: `src/alfred/gateway/egress_relay.py`
- Test: `tests/unit/gateway/test_egress_relay.py` (in-memory streams + a loopback fake upstream, mirroring `egress_proxy.py`'s test discipline)

**Interfaces:**

- Consumes: `EgressRequest`/`EgressResponse` (B1), `OutboundDlp` (broker=None) + `CanaryMatcher` (B1/B2), `record_egress_relay` (B3), `is_literal_ip`/`is_globally_routable`/`host_port_from_url` (`egress/allowlist.py`).
- Produces:
  - `EgressRelay.__init__(self, *, tool_allowlist: frozenset[EgressDestination], dlp: OutboundDlp, audit, bind_host, port, resolve=_default_resolve, open_client=_default_httpx_client, response_byte_cap: int = _DEFAULT_RESPONSE_CAP)`.
  - `async serve(self, shutdown_event) -> None` — bind + serve the minimal HTTP/1.1 endpoint until shutdown; **fail-closed** bind (OSError propagates → B5 maps to `IOPlaneUnavailableError`).
  - `resolve_egress_relay_port()` / `resolve_egress_relay_bind()` — env `ALFRED_EGRESS_RELAY_PORT` (default e.g. 8890) / `ALFRED_EGRESS_RELAY_BIND` (default `0.0.0.0`, never host-published). Mirror `resolve_egress_proxy_port`.

**The enforcement pipeline (per request — order is load-bearing):**

```python
# 1. Read the request envelope (bounded Content-Length; reject oversized/malformed -> MALFORMED_ENVELOPE).
req = EgressRequest.model_validate_json(body_bytes)          # extra="forbid" rejects junk
host, port = host_port_from_url(req.url)                     # authority from the URL ONLY
# 2. SSRF chain — IDENTICAL to the CONNECT proxy (these do NOT come for free; per-path):
if is_literal_ip(host):            deny(LITERAL_IP_TARGET)   # an IP target dodges gateway DNS
if (host, port) not in self._allowlist:  deny(DESTINATION_NOT_ALLOWLISTED)   # default-deny, TOOL allowlist
resolved_ip = await loop.run_in_executor(None, self._resolve, host)          # gateway-side DNS, off-loop
if not is_globally_routable(resolved_ip): deny(RESOLVED_IP_NOT_GLOBAL)       # DNS-rebinding TOCTOU
# 3. Gateway DLP second pass (decision 12) — stages 2+3 on the REDACTED body the core sent:
scanned = self._dlp.scan(req.body)   # broker=None -> regex + canary; canary trip raises -> CANARY/DLP_REDACTED deny
# (a redaction that CHANGES the body = the core failed to redact -> DLP_REDACTED deny + audit; do not forward.)
# 4. Originate the REAL upstream TLS — connect to the validated IP, validate cert against the hostname:
ip_url = req.url with host replaced by resolved_ip (bracket IPv6); keep scheme/port/path/query
request = client.build_request(req.method, ip_url, headers=_safe_headers(req.headers), content=req.body)
request.extensions["sni_hostname"] = host                   # SNI + cert identity = original hostname
resp = await client.send(request, follow_redirects=False, stream=True)       # NO redirect chasing
if resp.is_redirect: deny(UPSTREAM_REDIRECT_REFUSED)        # a 3xx to an unchecked host must not be followed
# 5. Buffer-with-cap (streaming fights the response scan; the cap makes buffering safe):
body = bounded_read(resp.aiter_bytes(), self._response_byte_cap)  # exceed -> RESPONSE_TOO_LARGE deny
# 6. Audit forwarded + return EgressResponse(status, _safe_headers(resp.headers), body)
record_egress_relay(EGRESS_RELAY_FORWARDED_EVENT, {...})
```

- `_default_httpx_client()` builds `httpx.AsyncClient(trust_env=False)` (gateway-side; ambient proxy env must not redirect mode-b). This file is the **gateway-side sanctioned httpx construction** — it lives under `src/alfred/gateway/`, so the in-core import-guard **will** flag it → add `gateway/egress_relay.py` to the guard's `_CONSTRUCT_ALLOWLIST` with a justification ("the sanctioned gateway-side egress origination site — Spec C G7-2; the gateway IS the egress plane").
- `_safe_headers` strips hop-by-hop headers (`Connection`, `Proxy-*`, `Keep-Alive`, `TE`, `Trailer`, `Transfer-Encoding`, `Upgrade`) and builds a fresh dict; lets httpx set `Host`/`Content-Length`. The `egress_id` is NOT forwarded upstream by default (internal correlation only — §5 honest contract).

- [ ] **Step 1: Write the failing tests** — happy forward (loopback fake upstream returns a body; assert `EgressResponse` + a forwarded audit row); literal-IP deny; non-allowlisted deny; non-globally-routable resolved IP deny (inject a resolver returning `10.0.0.1`); **DLP second-pass catch** (a body with an API-key shape the "core forgot" → `DLP_REDACTED` deny + audit, NOT forwarded); **canary trip** (a planted token → `CANARY_TRIPPED` deny + audit); redirect refusal (fake upstream returns 302 → `UPSTREAM_REDIRECT_REFUSED`); response-too-large (fake upstream returns body > cap → `RESPONSE_TOO_LARGE` deny); malformed envelope (junk JSON → `MALFORMED_ENVELOPE`); **IP-pinning** (assert the client connects to the resolved IP with `sni_hostname` = the original host — inject a fake `open_client` capturing the request and assert `request.extensions["sni_hostname"]` + the IP-host URL). Use in-memory streams for parsing logic + a loopback `asyncio.start_server` fake upstream for origination (mirror `test_provider_forward_proxy_e2e.py`; reuse the `_shutdown_default_executor` autouse drain — the off-loop resolver leaks the default executor otherwise).
- [ ] **Step 2:** Run → FAIL.
- [ ] **Step 3: Implement** `egress_relay.py` per the pipeline above. The minimal HTTP/1.1 handler: bounded request-line + headers read (cap + timeout, mirror `egress_proxy._read_connect_target`), parse `Content-Length`, bounded body read, dispatch, write a JSON HTTP/1.1 response. Each connection is its own task with `_on_connection_done` loud-logging (mirror `egress_proxy`).
- [ ] **Step 4:** Run → PASS. Add `gateway/egress_relay.py` + `gateway/egress_relay_audit.py` to BOTH egress coverage `--include` lists + BOTH `hashFiles()` guards in `ci.yml`. Verify 100% via the CI pattern.
- [ ] **Step 5:** Add `gateway/egress_relay.py` to the import-guard `_CONSTRUCT_ALLOWLIST` (`tests/unit/egress/test_in_core_http_egress_guard.py`); add an assertion in the guard's "allowlist entries still exist" test. `make check` + commit.

```bash
git commit -m "feat(gateway): mode-b inspecting tool-egress relay (DLP 2nd pass + SSRF + TLS origination) (#333)"
```

### Task B5: mount the relay endpoint + CI gates

**Files:** Modify `src/alfred/cli/gateway/_commands.py` (third sibling `TaskGroup` task), Modify `.github/workflows/ci.yml`.

- [ ] **Step 1:** Mount `EgressRelay.serve(shutdown_event)` as a **third** `tg.create_task(...)` alongside the CONNECT proxy + the gateway process (the existing sibling-task pattern). Build it from **public env** — `resolve_egress_relay_port/bind`, `resolve_deepseek_base_url` is NOT enough here (the tool allowlist is the web-fetch allowlist, not the provider one). The gateway derives the **tool allowlist** + the **canary tokens** from public compose-threaded config (e.g. `ALFRED_TOOL_EGRESS_ALLOWLIST`, `ALFRED_CANARY_TOKENS` — public, non-secret; never `Settings()`). Bind OSError → `IOPlaneUnavailableError` → friendly `gateway.start.egress_relay_bind_failed` exit (mirror the proxy's fail-closed mount, distinct from the metrics server's loud-and-continue).
- [ ] **Step 2:** Tests: the relay task is mounted; a bind failure is fail-closed (gateway crash-loops under `restart: unless-stopped`). i18n key for the bind-failed message.
- [ ] **Step 3:** `make check` + commit.

```bash
git commit -m "feat(gateway): mount the mode-b relay as a fail-closed sibling task (#333)"
```

**G7-2b exit:** the gateway inspecting relay is on `main`, fully tested gateway-side, **with no in-core consumer** — nothing POSTs to it in production. Full `/review-pr` fleet + CodeRabbit (this is a security boundary — the gateway DLP second pass + SSRF chain), resolve threads, merge.

---

## Part C — G7-2c: in-core relay client + §4.3 response-extract, then the dispatcher re-point + synthetic driver + corpus

**PR split:** **G7-2c-1** = the core relay mechanism (relay client + §4.3) with no production caller; **G7-2c-2** = the dispatcher re-point (the side-effecting flip) + the synthetic driver + the release-blocking barrier test + the §9 corpus.

**G7-2c-1 — in-core relay client (ledger-wrapped) + §4.3 T3 response-extract**

### Task C1: the in-core relay client

**Files:**

- Create: `src/alfred/egress/relay_client.py`
- Modify: `src/alfred/config/settings.py` (add `egress_relay_url: str | None = None` with the blank→None validator, mirror `egress_proxy_url`)
- Modify: `tests/unit/egress/test_in_core_http_egress_guard.py` (allowlist `egress/relay_client.py` if HTTP-POST wire wins)
- Test: `tests/unit/egress/test_relay_client.py`

**Interfaces:**

- Consumes: `EgressRequest`/`EgressResponse` (B1), `OutboundDlp` (core-side, broker set) for the core stage-1 redaction, `compute_egress_id`/`compute_body_hash`/`TurnEgressContext` (A1), `EgressIdempotencyStore` + `IntentFresh`/`IntentReplayComplete`/`IntentInDoubt` (A3), `IOPlaneUnavailableError`/`EgressDeniedError` (`egress/errors.py`).
- Produces:
  - `RelayEgressClient.__init__(self, *, relay_url, core_dlp: OutboundDlp, ledger: EgressIdempotencyStore, http_client_factory, concurrency: int)` — an `asyncio.Semaphore(concurrency)` + a per-call `asyncio.timeout`. Holds NO `core_link`/seq-ack reference (must not HoL the comms relay).
  - `async fire(self, *, raw_request: _RawToolRequest, ctx: TurnEgressContext, call_index: int) -> RelayOutcome` where `RelayOutcome = Fired(EgressResponse) | Deduplicated(stored_t2: str, language)`. Flow:
    1. `redacted = self._core_dlp.scan_for_outbound(raw_request.body)` (core stage 1+2+3).
    2. `egress_id = compute_egress_id(ctx, call_index=call_index)`; `body_hash = compute_body_hash(redacted_text)`.
    3. `intent = await ledger.commit_intent(egress_id=..., body_hash=body_hash, ...)`.
    4. `match intent`: `IntentReplayComplete(resp, lang)` → return `Deduplicated(resp, lang)` (**no fire, no re-extract**); `IntentInDoubt()` → if `raw_request.method in {"GET","HEAD"}` fall through (idempotent, safe re-fire) else `raise EgressInDoubtError` (at-most-once: never blind double-fire); `IntentFresh()` → fall through.
    5. POST the `EgressRequest` envelope to `relay_url` (httpx, `trust_env=False`); a connect failure → `IOPlaneUnavailableError`; a relay deny (non-2xx relay status with a deny reason) → `EgressDeniedError(destination, deny_reason)`.
    6. return `Fired(EgressResponse(...))`. (The §4.3 extract + `ledger.record_response` happen in the C2 wrapper, NOT here — the relay client never stores raw T3.)
  - `EgressInDoubtError(AlfredError)` (`reason = "egress_in_doubt"`) added to `egress/errors.py`.

- [ ] **Step 1: Write failing tests** — fresh fire POSTs the envelope + returns `Fired`; a `ReplayComplete` intent returns `Deduplicated` WITHOUT POSTing (assert the http_client_factory is never called — `assert_not_called`); `IntentInDoubt` + GET re-fires; `IntentInDoubt` + POST raises `EgressInDoubtError`; a different-hash duplicate surfaces `EgressIdIntegrityError` (from the ledger); relay-unreachable → `IOPlaneUnavailableError`; relay-deny → `EgressDeniedError`; HoL: a slow fire under the semaphore does not block a second concurrent fire on a free slot (deterministic Event-gated).
- [ ] **Step 2–4:** Implement (fake gateway via the injected `http_client_factory`; real `PostgresEgressIdempotencyStore` against testcontainers for the intent states). Run green.
- [ ] **Step 5:** CI gate — add `src/alfred/egress/relay_client.py` to BOTH egress coverage `--include` + guards. i18n keys (`egress.in_doubt`). `make check` + commit.

```bash
git commit -m "feat(egress): in-core ledger-wrapped mode-b relay client (#333)"
```

### Task C2: §4.3 egress-response quarantine-extract + ledger response recording

**Files:**

- Create: `src/alfred/egress/egress_response_extract.py` (the §4.3 wrapper)
- Test: `tests/unit/egress/test_egress_response_extract.py` + `tests/integration/egress/test_egress_response_extract_postgres.py`

**Interfaces:**

- Consumes: `RelayEgressClient` (C1), `QuarantinedExtractor.extract` (`security/quarantine.py:404`), the `T3BodyRecorder`/`ContentHandle`/`tag_t3_with_nonce` ingestion seam (`security/quarantine_transport.py`), `EgressIdempotencyStore.record_response` (A3).
- Produces:
  - `EgressResponseExtractor.handle(self, *, raw_request, ctx, call_index, canonical_user_id, schema) -> ExtractionResult` — wraps `RelayEgressClient.fire`:
    - `Deduplicated(stored_t2, lang)` → return the stored T2 **directly**, flagged `deduplicated` — **do NOT call `QuarantinedExtractor.extract`** (the replay must not re-enter raw-T3 ingestion; HARD rule #5).
    - `Fired(response)` → the response body is **T3**: mint a `ContentHandle`, stage it via `T3BodyRecorder` (under `tag_t3_with_nonce`), call the **one** `QuarantinedExtractor.extract(handle, schema)`, then `await ledger.record_response(egress_id=..., response=<serialized post-extraction T2>, language=...)`, and return the `ExtractionResult`. `canonical_user_id` is **host-side only**, never threaded into the extractor call (mirror `comms_mcp/bootstrap.py:138` — `del canonical_user_id`).
    - The privileged orchestrator only ever receives the `ExtractionResult` (T2 `Extracted | TypedRefusal`), never the raw response.

- [ ] **Step 1: Write failing tests** —
  - **Fresh:** a fired T3 response → `QuarantinedExtractor.extract` is called **once** (spy `assert_awaited_once`), the ledger row transitions to `committed_with_response` with the **post-extraction T2** (assert the stored value is the extracted data, never the raw T3 body), the returned tier is T2.
  - **Replay (the load-bearing negative):** a `Deduplicated` outcome → `QuarantinedExtractor.extract` is **`assert_not_called`** (replay must not re-enter T3 ingestion), the returned value is the stored T2 flagged `deduplicated`.
  - **Tier-downgrade guard:** the returned object is structurally T2; a mode-b (T3) response cannot acquire a mode-a T2 tag except via the extractor (assert the type/tag).
- [ ] **Step 2–4:** Implement. Run green (real extractor spy + real Postgres for the ledger transition).
- [ ] **Step 5:** CI gate for `egress_response_extract.py` (combined-job — the record_response transition needs integration data). `make check` + commit.

```bash
git commit -m "feat(egress): §4.3 T3 response quarantine-extract + ledger T2 recording; replay never re-tags T3 (#333)"
```

**G7-2c-1 exit:** the core egress mechanism is on `main`, **fires only via tests** (no dispatcher re-point) — no production live egress yet. Full fleet + CodeRabbit (security ALWAYS — this is the T3 boundary + the dedup ledger), merge.

**G7-2c-2 — the dispatcher re-point + synthetic driver + barrier test + corpus**

### Task C3: re-point `dispatch_web_fetch` through the relay + compose wiring

**Files:**

- Modify: `src/alfred/plugins/web_fetch/fetch_dispatcher.py`
- Modify: `docker-compose.yaml`, `.env.example`
- Test: `tests/unit/plugins/web_fetch/...`, `tests/unit/test_compose_invariants.py`

- [ ] **Step 1:** Re-point the web-fetch outbound: instead of the plugin subprocess opening its own httpx, the dispatcher builds an `EgressRequest` and calls the `EgressResponseExtractor` (C2). **This is the anti-dead-code wiring** — the REAL production dispatcher now reaches the relay. Keep the existing DLP-scan of url+headers (`clean_url`/`clean_headers`) as the core stage-1; the relay client re-redacts the body; the gateway re-runs stages 2+3.
- [ ] **Step 2:** Compose: `alfred-core` gets `ALFRED_EGRESS_RELAY_URL=http://alfred-gateway:8890`; `alfred-gateway` gets `ALFRED_EGRESS_RELAY_PORT` + `ALFRED_TOOL_EGRESS_ALLOWLIST` + `ALFRED_CANARY_TOKENS` (public, non-secret). Relay port NEVER under `ports:` (compose-invariant test asserts it). No `depends_on` (G7-3 adds boot ordering). `.env.example` placeholders.
- [ ] **Step 3:** Tests: the dispatcher reaches the relay client (not a direct socket); compose-invariant pins (relay port not host-published; core+gateway share the tool-allowlist/canary env). `make check` + commit.

```bash
git commit -m "feat(web-fetch): route tool egress through the mode-b relay (the live cutover) (#333)"
```

### Task C4: the synthetic driver + `fake_external_world` fixture + the release-blocking barrier test

**Files:**

- Create: `tests/integration/egress/conftest.py` (`fake_external_world` fixture), `tests/integration/egress/test_egress_barrier_dedup_postgres.py`, the synthetic driver helper.

**Interfaces:**

- `fake_external_world` — a loopback `asyncio.start_server` upstream with a `fire_count` ref + a settable canned response (mirror `test_provider_forward_proxy_e2e.py::_serving_proxy`), epic-wide so the barrier test + the corpus share one counter. Reuse `_await_proxy_ready` + `_shutdown_default_executor`.
- The **synthetic driver** = a deterministic helper that constructs a `TurnEgressContext` + `call_index` and invokes the **real** `dispatch_web_fetch` → `EgressResponseExtractor` → `RelayEgressClient` → the **real** `EgressRelay` (loopback) → `fake_external_world`. It substitutes ONLY the LLM tool-selection.
- The **barrier seam** = an injectable `post_commit_hook: Callable[[], Awaitable[None]] = _noop` on `RelayEgressClient.fire`, invoked **after** the ledger `committed_no_response` intent and the fire, **before** `record_response`. The test injects a hook that raises `_EgressBarrierKill`.

- [ ] **Step 1: Write the release-blocking barrier test** (real Postgres):
  - **Act 1 (fire):** drive web-fetch via the synthetic driver; barrier hook fires after the external call commits, before ack → assert `fire_count == 1` and the ledger row is `committed_no_response`.
  - **Act 2 (replay):** re-run the identical logical call (same `ctx` + `call_index` → same egress-id) → assert `fire_count` still `1` (no re-fire), the result is the stored T2 flagged `deduplicated`, the row is now `committed_with_response`, and `QuarantinedExtractor.extract` was **not** re-called on the replay (spy `assert_not_called`).
  - **Act 3 (TTL):** `prune_expired(older_than=<injected now past the window>)` removes the row → a subsequent run re-fires (`fire_count == 2`) — proving expiry is not a silent permanent drop.
  - Plus: 8-way concurrent `commit_intent` → exactly one winner (lift `test_concurrent_commits_exactly_one_winner`).
- [ ] **Step 2–4:** Implement the fixture + driver + hook seam. Run green against testcontainers Postgres. **This test must live in `tests/integration/` (a required check), NOT `tests/e2e/`** — the loopback fixture removes any real-network/budget dependency, so there is no excuse to push it behind a skip-on-PR gate (paper-gate hazard).
- [ ] **Step 5:** `make check` + commit.

```bash
git commit -m "test(egress): release-blocking egress-barrier dedup + TTL proof (real Postgres) (#333)"
```

### Task C5: the §9 adversarial corpus + tier-downgrade + contention tests

**Files:**

- Create: `tests/adversarial/dlp_egress/*.yaml` + executable drivers; `tests/adversarial/tier_laundering/*` addition; `tests/integration/egress/test_quarantine_contention.py`.

- [ ] **Step 1:** Add corpus entries (YAML per `payload_schema.py`, `de-`/`tl-` id prefixes, threat + provenance + `ingestion_path` + `expected_outcome`), each driven against `fake_external_world` + real Postgres:
  - `de-` **non-canary body exfil to an allowlisted destination** → caught by the **gateway DLP pass** (`caught_by_dlp`) + audited + refused. (Makes the two-layer content claim real.)
  - `de-` **canary trip on egress** → `quarantined`/refused; scanner fails loud not open.
  - `de-` **egress-id replay / false-replay / forgery** → replay returns memoized T2, no re-fire; a forged/incremented id is rejected core-side; a same-position-different-hash replay → `EgressIdIntegrityError` (`refused`/`audit_row_emitted`).
  - `de-` **IO-plane-down audit completeness** → `IOPlaneUnavailableError`/`EgressDeniedError` each emit their non-skippable audit row.
  - `de-` **mode-(a) provider-prompt exfil residual** → recorded as an accepted residual (destination-only by design), not claimed caught.
  - `tl-` **cross-mode tier-downgrade** → a mode-b T3 response cannot acquire the mode-a T2 tag via the response path (`boundary_refused`) — model on `test_tier_laundering_t3_derived_provenance.py`.
- [ ] **Step 2: §4.3 contention HoL test** — deterministic Event-gated interleave: submit an inbound-extract + an egress-extract against the ONE quarantine child; release in reverse order; assert both complete within a bounded `asyncio.wait_for` (no deadlock); a hung first extract must not starve the second past the action-deadline (a bounded timeout refusal is a pass, a hang is a fail).
- [ ] **Step 3:** Confirm `adversarial.yml` (release-blocking, runs every PR) picks up the new `dlp_egress`/`tier_laundering` entries. `make check` + commit.

```bash
git commit -m "test(adversarial): G7-2 egress corpus (gateway-DLP catch, canary, replay/forgery, tier-downgrade) (#333)"
```

**G7-2c-2 exit:** web-fetch tool egress flows through the gateway relay end-to-end (synthetic-driver-proven), the dedup ledger blocks double-fire, the §4.3 extract is replay-safe, the corpus is green. Full fleet + CodeRabbit, resolve threads, merge. **Spec C G7-2 complete.**

---

## CI gate changes (cumulative — both jobs, both `hashFiles()` guards)

Append to the egress coverage `--include` in BOTH the `python` job (ci.yml ~489/491) and the `coverage-gates` job (~1627/1629), and to BOTH `hashFiles()` `if:` guards:

```
src/alfred/egress/egress_id.py,              # G7-2a
src/alfred/memory/egress_idempotency.py,     # G7-2a (combined-job reaches the committed_no_response branch)
src/alfred/gateway/egress_relay.py,          # G7-2b
src/alfred/gateway/egress_relay_audit.py,    # G7-2b
src/alfred/egress/relay_client.py,           # G7-2c-1
src/alfred/egress/egress_response_extract.py # G7-2c-1 (combined-job — record_response transition)
```

`OutboundDlp` (`security/dlp.py`) + `CanaryMatcher` (`security/canary_matcher.py`) ride the existing `security/*` glob — no named step. **Every** new file MUST be in BOTH `hashFiles()` guards or the gate silently no-ops on the introducing branch.

## Release-blocking test inventory

- **Integration (real Postgres, required):** the §5 barrier (fire-count==1 + deduplicated replay + TTL re-fire + 8-way exactly-one-winner); the ledger tri-state contract; the 0023 migration round-trip; the §4.3 contention/no-deadlock.
- **Unit (pure + property):** egress-id determinism + injectivity (hypothesis + hand-written collision vectors + golden literal + completion-order independence); content-hash integrity fails loud; replay does NOT re-enter T3 (`extract.assert_not_called`); the real canary scanner suite (replacing the retired stub test).
- **Adversarial (release-blocking via `adversarial.yml`):** gateway-DLP non-canary catch; canary trip; egress-id replay/forgery; cross-mode tier-downgrade; IO-plane-down audit completeness; mode-(a) residual recorded.

## Deferred / human-gated (G7-5, do NOT do in G7-2)

- **ADR-0040** gains a residual: the gateway's DLP second pass is stages 2+3 only (no broker stage — ADR-0036); a broker-known, non-shaped, non-canary value the compromised core failed to redact survives the gateway pass. Also record: two sanctioned httpx-construction sites with opposite justifications (core = proxied; gateway = direct-originating); mode-b is deliberately NOT payload-blind (contrast `core_link.py`/`egress_proxy.py`).
- **PRD §5/§7.1** rewrite — the gateway as the I/O plane; per-session allowlist narrows within the structural tool-egress ceiling.
- **Live LLM consumer** — the model-initiated tool turn is **#339** (the convergence PR), sequenced after G7-3; its release-blocker is the injection-driven-URL/argument corpus.

## Self-review

- **Spec coverage:** §4.2 mode-b relay → B4/C3; decision-12 gateway DLP → B2/B4 (with the honest stage-1 residual); §4.2 real canary → B1/B2; §4.3 quarantine-extract → C2 (replay-safe); §5 idempotency (deterministic+injective id, tri-state, memoize+replay, TTL, barrier test) → A1/A3/C1/C4; §6 fail-loud/HoL → B4/C1 (typed errors, semaphore, off-comms-relay); §9 corpus → C5; §7 enforcement (SSRF chain) → B4. Gaps: none — the connectivity-free flip + kernel tests are G7-3 (correctly out of scope).
- **Placeholder scan:** the only intentional placeholder is the egress-id **golden vector** (A1 Step 4 fills it from the first run) — flagged, not a gap.
- **Type consistency:** `TurnEgressContext`, `compute_egress_id(ctx, *, call_index)`, `compute_body_hash`, `EgressRequest`/`EgressResponse`, `commit_intent`/`record_response`/`prune_expired`, `IntentFresh`/`IntentReplayComplete`/`IntentInDoubt`, `RelayOutcome = Fired | Deduplicated`, `EgressIdIntegrityError`/`EgressInDoubtError`/`OutboundCanaryTripped` are used consistently across A→B→C.
