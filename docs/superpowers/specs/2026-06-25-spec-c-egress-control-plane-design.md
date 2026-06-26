# Egress Control Plane / Connectivity-Free Core (Spec C / G7)

- **Date:** 2026-06-25
- **Status:** Draft (design approved in brainstorming 2026-06-25; 8-specialist `/review-plan` fleet + coordinator reviewed 2026-06-25, all findings folded in; `[fleet]` marks a change that landed from that review). Not yet plan-reviewed at the per-PR level. Epic [#333](https://github.com/alfred-os/AlfredOS/issues/333). ADR-0040 pending (human-gated). PRD §5/§7.1 rewrite pending (human-gated).
- **Scope:** This is **Spec C**, the final epic of the three-epic gateway control-plane program (see [gateway-control-plane-roadmap](2026-06-13-gateway-control-plane-roadmap.md)). Spec C makes the **core connectivity-free** — it loses its external network — and turns the **gateway into the sole external I/O plane** for all outbound network I/O (providers, tools, hosted adapters).
- **Gated on:** Spec A (comms-resume gateway, #237 crit #7) and Spec B (gateway adapter-hosting inversion, [#288](https://github.com/alfred-os/AlfredOS/issues/288) / [spec-b-adapter-inversion-design](2026-06-18-spec-b-adapter-inversion-design.md)) complete and merged. The literal sole-egress prerequisite is met: the standalone `alfred-discord` egress service is gone (#309, PR #332).
- **Resolves:** #230 (sandbox network-egress schema / unrestricted child egress).
- **Out of scope (follow-on epic):** the **2c real-LLM quarantine child** — its provider call over the audited proxy is a thin follow-on behind this work, not part of Spec C. Spec C gives the quarantine child `--unshare-net` immediately (it is deterministic-echo and needs no network), closing its #230 hole; the real-LLM go-live keeps its own human sign-off.
- **Related:** ADR-0036 (adapter inversion), ADR-0038 (daemon control socket), ADR-0039 (gateway-adapter inbound bridge), ADR-0015/0030 (launcher/sandbox: bwrap kind model, fd-3 key delivery), ADR-0032/0033 (Spec A wire + lifecycle), ADR-0005/0012 (secret broker), #330 (encrypted/pluggable secret vault), #331 (gateway supervisor park-not-abort), #287 (nightly gateway restart live smoke).

## 1. Problem & scope

Today every external network connection in AlfredOS is opened **directly by the process that needs it**, with no chokepoint and no kernel-level egress cap:

- The **core** opens provider sockets itself — `AnthropicProvider` builds an `AsyncAnthropic` client (`src/alfred/providers/anthropic_native.py`), `DeepSeekProvider` an `AsyncOpenAI` client (`src/alfred/providers/deepseek.py`). No proxy, no destination allowlist at the call boundary.
- **Tool egress** (web-fetch) has a three-way allowlist data model (`src/alfred/plugins/web_fetch/allowlist.py`) but it is not enforced at call time yet. There is **no outbound-body content scanner**: `OutboundDlp.scan_for_outbound` does redaction, and `OutboundDlp._canary_stub` is a literal `return text` no-op (`src/alfred/security/dlp.py`); the only real canary scanner — `InboundCanaryScanner` — runs on **inbound** content.
- **Sandboxed children** have **full unrestricted egress**. Both `config/sandbox/quarantined-llm.linux.bwrap.policy` and `config/sandbox/discord-adapter.linux.bwrap.policy` deliberately omit `--unshare-net`, each with an in-file comment naming #230 as the release-blocker and the *same* intended fix: a `network.outbound_allowlist` field + `--unshare-net` + a slirp/pasta-style filtered forwarder, or fd-passing.
- The **Docker Compose** topology puts every service on the **default bridge** (no `networks:` block today); `alfred-core` has unrestricted outbound NAT.

The PRD documents the *goal* (§7.1, line 447: "Default-deny for outbound network calls") as a **per-tool allowlist**, not a structural property of the core. There is no statement that the core is connectivity-free, and today it is not.

**Spec C makes the connectivity-free-core invariant structurally true.** The gateway becomes the mandatory chokepoint for all outbound I/O; the core loses its external network at the kernel level (a container on an `internal:true` network); and the two egress-needing children (the deterministic-echo quarantine child and the live Discord adapter) are brought under egress control. The gateway and its hosted adapters *are* the external I/O plane by design — the invariant is about the **core**, not the gateway.

**In scope:** the network split; the provider forward-proxy; the inspecting tool-egress relay with a gateway-side DLP pass; egress idempotency; fail-loud I/O-plane errors; head-of-line isolation; the connectivity-free enforcement tests; the Discord-adapter egress hardening (now via the unified L7 proxy); the adversarial corpus additions; and the PRD §5/§7.1 + ADR-0040 writes.

**Out of scope:** the 2c real-LLM quarantine child (separate follow-on); building a new adapter; the encrypted secret vault (#330, designed-but-unscheduled; the env-on-core interim migrates into it cleanly later); the gateway supervisor park-not-abort structural fix (#331).

## 2. Locked decisions

Resolved during brainstorming (2026-06-25). Decisions 1, 3–8, 11 were pre-locked across the prior sessions; decisions 2, 9, 10, 12 were settled in this session with maintainer co-sign. Do not re-litigate.

1. **Full structural switch — subsumes #230.** There is no per-plugin kernel egress cap today; Spec C is the first real network isolation. The roadmap's "kernel-cap regression" framing was false (there was no cap to regress from).
2. **Enforcement model = two independent layers** (maintainer co-sign). **Kernel network isolation** — empty-netns for children + an `internal:true` network for the core container — is the **structural enforcement-of-record** that the PRD "connectivity-free" invariant cites. The gateway forward-proxy destination-allowlist + the **gateway-side DLP+canary content pass on mode-(b) bodies** (decision 12) + audit is **independent userspace defense-in-depth** on top: it does not depend on the kernel layer being flawless, and a gap in either still leaves one boundary. ADR-0040 states precisely what each layer does and does not guarantee.
3. **Provider egress = forward-proxy with TLS passthrough.** The core's provider SDK targets the gateway as an HTTPS forward-proxy; TLS terminates at the provider, so the gateway enforces the **destination** allowlist + audit but **never sees the decrypted prompt**, and native SDK streaming is preserved. Provider responses are **T2** (assistant output), **not T3**.
4. **Two egress modes.** (a) destination-allowlisted forward-proxy / TLS-passthrough for providers and the hosted Discord adapter (where the gateway must not see plaintext); (b) **inspecting** frame-relay with a core-DLP-redacted body **plus an independent gateway-side DLP+canary pass** for tool egress (web posts, email).
5. **Egress idempotency** = deterministic `egress-id = f(committed inbound-id, session, logical-call identity)` where the per-turn component is the **deterministic logical-call position/content**, never completion-order; **core-stamped + core-committed durable** in Postgres (gateway stays stateless); the ledger is **tri-state** (committed-no-response-yet vs committed-with-response); on a duplicate **memoize + replay the stored response flagged `deduplicated`**, never a silent drop; **TTL-swept** to the replay window; framed honestly as "**at-most-once at the gateway + egress-id forwarded as the remote idempotency key where the API supports one**."
6. **Network split:** two custom networks — `alfred_internal` (`internal: true`; core ↔ datastores ↔ gateway) and `alfred_external` (gateway only). The gateway joins **both**; the core joins **internal only**. The core performs **no client-side DNS** for egress — the gateway resolves (closes the embedded-resolver DNS-exfil side-channel, §7).
7. **Fail-loud:** typed `IOPlaneUnavailableError` (gateway unreachable → total external-I/O outage) distinct from `EgressDeniedError` (allowlist/DLP denial); bounded timeouts, no quiet-dark; a non-skippable audit row on every deny / IO-down / canary-trip / idempotency-replay path; `gateway_core_link_up` metric (note: reuse the existing name, not a new `core_gateway_link_up`).
8. **Head-of-line isolation:** every egress call is an isolated `asyncio.TaskGroup` task with a per-call timeout + a per-destination/global concurrency cap, on a channel separate from the comms-relay serial await chain; the CONNECT byte-splice must yield (no event-loop starvation); `gateway_egress_inflight` gauge + saturation alert.
9. **2c real-LLM quarantine child is OUT of scope** (maintainer co-sign) — a separate follow-on epic. Spec C gives the quarantine child `--unshare-net` immediately.
10. **Discord-adapter egress hardening is IN scope, as a tail PR** (maintainer co-sign). `[fleet]` The mechanism is **not** a pasta/slirp filtered forwarder — review proved that L3/L4 forwarders cannot enforce a hostname/SNI allowlist and Discord is Cloudflare-fronted on rotating IPs. Instead the Discord child runs `--unshare-net` and points `discord.py` at the **same L7 CONNECT forward-proxy as the providers** via its native `Client(proxy=...)` config (a supported knob, not transport surgery). This **unifies** child egress with mode (a), retires the pasta/slirp tooling entirely, and avoids any gateway seccomp/apparmor profile widening. The strict **empty-netns + SCM_RIGHTS fd-broker** model remains a future option for the in-house quarantine child (2c) only.
11. **ADR-0040 + PRD §5/§7.1 rewrite are human-gated.** Egress-policy citation = PRD **§7.1** (line 447, "Default-deny for outbound network calls").
12. **Gateway is a second DLP chokepoint for mode (b)** (maintainer co-sign). `[fleet]` In mode (b) the gateway already receives the redacted body to scan it, so it re-runs the full `OutboundDlp` (redaction + the real outbound canary scanner) as an **independent** second pass. This makes the two-layer enforcement real for *content*, not just destination: a compromised core that skips its own redaction is caught at the gateway. The gateway DLP module is a security boundary (100% coverage + corpus). Mode (a) and adapter egress stay TLS-passthrough/destination-only by design (the gateway cannot read those bodies).

## 3. Topology — the connectivity-free core

The headline invariant: **the core has no external sockets** (kernel-enforced, the enforcement-of-record), and **the gateway is the sole external I/O plane**.

```
            ┌─────────────────── alfred_external (internet) ───────────────────┐
            │                                                                  │
   ┌────────┴──────────┐  ── L7 CONNECT forward-proxy (TLS-passthrough) ──▶ api.anthropic.com
   │   alfred-gateway  │     (one listener; gateway resolves DNS)         ──▶ api.deepseek.com
   │  (joins BOTH nets)│     • providers (mode a)                         ──▶ gateway.discord.gg
   │  • L7 egress proxy│     • hosted Discord child  (Client(proxy=...))   ──▶ *.discord.com / cdn
   │  • mode-b relay   │  ── inspecting relay: gateway re-runs OutboundDlp ──▶ web-fetch hosts
   │    (gateway DLP)  │     + canary on the redacted body, then forwards
   └────────┬──────────┘
            │  alfred_internal  (internal: true — NO route to the internet, NO external DNS)
   ┌────────┴───────────────────────────────────────────────────────────────────┐
   │  alfred-core          alfred-postgres   alfred-redis   alfred-qdrant   ...    │
   │  (connectivity-free)                                                         │
   │   • provider SDK  ──▶ gateway L7 CONNECT proxy (over the egress channel)      │
   │   • tool egress   ──▶ gateway mode-b relay (DLP-redacted body)                │
   │   • quarantine child: --unshare-net NOW (echo; needs no network)             │
   └──────────────────────────────────────────────────────────────────────────────┘
```

- The **gateway** joins both networks — it is the bridge/chokepoint. The **core and datastores** (Postgres, Redis, Qdrant — enumerate all in compose; Qdrant is currently absent and must be added) join `alfred_internal` only, so the core *cannot route* to the internet. That container-level isolation is the core's kernel enforcement-of-record; it is independent of, and stronger than, the userspace proxy allowlist.
- **The core does no client-side DNS for egress.** It sends `CONNECT host:port` and the gateway resolves the name. `internal:true` alone does **not** block DNS — Docker's embedded resolver (127.0.0.11) can still recurse upstream, so a `connect()`-only block would leave a DNS-exfil (QNAME) channel open (§7). Forbidding core-side external resolution closes it.
- **The egress channel is a dedicated core↔gateway socket**, separate from the Spec A/B comms control wire (perf-F2 — a streaming provider call must not head-of-line-block the comms relay). `[fleet]` Its lifecycle must be specified, not assumed: a 0600 unix socket under the shared `alfred_run` dir, `SO_PEERCRED`-checked, epoch-tagged handshake, supervised accept/pump, bounded reconnect/backoff, and defined delivery semantics — reusing the Spec A/B socket discipline (ADR-0031/0032), not a new ad-hoc transport.
- **One L7 CONNECT forward-proxy listener** on the gateway serves providers, the hosted Discord child, and (later) the 2c quarantine child. It enforces a **per-caller** destination allowlist, refuses literal-IP CONNECT targets, resolves the host itself, and audits the destination. `[fleet]` This unifies the provider and adapter egress paths and retires the pasta/slirp design.
- Postgres currently publishes `5432:5432` to the host. **Platform note (verified live during G7-0):** an `internal: true` membership breaks that published host port on **Docker Desktop/macOS** (an internal-only container is not port-forwarded there) but works on **Linux** (published ports NAT independently of the network's external gateway). This is why G7-0 lays the network *membership* without `internal: true`, and the isolation flip (`internal: true` + core-off-external) is deferred to G7-3, which re-probes on its target Linux host. Intra-compose DNS is unaffected (all internal services co-inhabit `alfred_internal`). The gateway already carries `cap_add: SETUID` + the bwrap launcher (Spec B); Spec C adds **no** new capability and (with decision 10) **no** new forwarder tooling. Note: core and gateway build from one Dockerfile today — with pasta/slirp retired, no image split is needed.

> **G7-1 plan reconciliation (#333).** G7-1b implements the egress channel as a **TCP CONNECT proxy on `alfred_internal`**, NOT a 0600 unix socket. An httpx / discord.py CONNECT proxy needs a TCP endpoint, and a unix-socket proxy is not natively supported by either client, so this **supersedes the §3 egress-channel unix-socket lifecycle described above**. The 0600-unix-socket + `SO_PEERCRED` discipline that paragraph borrows (ADR-0031/0032) remains the **Spec A/B comms control wire's**; only the egress channel adopts the TCP form. **Honest framing of the control:** the proxy is **reachability-scoped** to `alfred_internal` (network membership) and allowlist-enforced — it does **not** authenticate the individual caller (a `Proxy-Authorization` token / mTLS is the named ADR-0040 future path, not built in G7-1). A 5-lens fleet panel recommended and the maintainer co-signed this transport (2026-06-26). The compensating riders: never host-published, destination-allowlist-is-the-control, refuse-literal-IP, gateway-resolves-DNS, reject a non-globally-routable resolved IP (DNS-rebinding TOCTOU), request-line-authority-only (never trust the `Host:` header), bounded reads, and a gateway-local audit on every CONNECT. The authoritative PRD / ADR-0040 reconciliation is human-gated and lands at G7-5.

## 4. The egress classes and the two modes

Four egress classes. Three are handled in Spec C; the fourth (2c) reuses the same L7 proxy.

| Class | Today | Spec C |
|---|---|---|
| Core to provider (Anthropic / DeepSeek) | direct HTTPS from the core | core SDK targets the gateway **L7 CONNECT proxy** (mode a); destination allowlist + audit; TLS passthrough (gateway never sees the prompt); streaming preserved; responses tagged **T2** |
| Core / plugin tool egress (web-fetch, email) | allowlist data model exists, unenforced | **inspecting relay** (mode b): core DLP-redacts the body, then the **gateway re-runs `OutboundDlp` (redaction + canary) as an independent pass**, destination-allowlists, audits, forwards; the response is handled by the §4.3 quarantine-extract entry |
| Quarantine child | full unrestricted net (no 2c yet) | gets `--unshare-net` immediately — deterministic-echo needs zero net; the L7-proxy provider path is built in the 2c follow-on |
| Hosted Discord adapter child | full unrestricted net, live in prod | `--unshare-net` + `discord.py` pointed at the **same L7 CONNECT proxy** via `Client(proxy=...)` (mode-a-shaped, TLS-passthrough); per-adapter destination allowlist; tail PR |

### 4.1 Mode (a) — provider forward-proxy

The core's `EgressClient` builds each provider SDK with an explicit proxied HTTP client. `[fleet]` On the pinned stack (httpx 0.28.1, openai 2.38.0, anthropic 0.104.1) the SDK `proxies=` kwarg was removed and never existed on `AsyncOpenAI`; both proxy **only** via `http_client=httpx.AsyncClient(proxy=...)` (the anthropic ctor takes `http_client`; openai takes `http_client=DefaultHttpxClient(proxy=...)`). The provider `from_settings` constructors (`AnthropicProvider`, `DeepSeekProvider`) gain an injected `http_client` seam — these two construction sites are exactly what the §7 import-guard lint gates. Injection is **per-client**, not a process-wide `HTTP(S)_PROXY` env (explicit, lint-checkable, no ambient leak).

The gateway terminates the `CONNECT`, checks the destination host against the provider allowlist, audits, then opens the upstream and splices. TLS is end-to-end core↔provider, so the gateway is **payload-blind to the prompt and response**; SDK streaming, retries, and timeouts are preserved (the connect-timeout budget adds the gateway hop). The destination allowlist is **derived from live provider config** (the DeepSeek `base_url` override + the Anthropic SDK default), reconciled at startup — not a second hard-coded list that can drift. Provider responses re-enter the core as **T2** assistant output, not T3 (the "egress-response is T3" rule explicitly carves out providers). Provider reads are **not** money side-effects and do **not** route through the §5 egress-id ledger.

### 4.2 Mode (b) — inspecting tool-egress relay with a gateway DLP pass

Tool egress (web POST, email) is content the gateway *must* inspect. The core runs `OutboundDlp.scan_for_outbound` to produce a redacted body, then sends an `egress.request` frame carrying the **already-redacted** body + destination + egress-id (§5) to the gateway. `[fleet]` The gateway then re-runs the **full `OutboundDlp`** (redaction + the canary scan) as an **independent second pass** over the (bounded, streamed) body, re-checks the destination against the tool allowlist, audits, and forwards. This is the second of the two enforcement layers (decision 12): a compromised core that skips its own redaction is caught here. Mode (b) is therefore **deliberately not payload-blind** (unlike the comms relay and mode (a)) — the wording in docs must not conflate them.

`[fleet]` The outbound canary scanner is **net-new**, not the mythical "Slice-2 stub": `InboundCanaryScanner` already exists (a reusable token-matcher to DRY-reuse), `OutboundDlp._canary_stub` is the real no-op to replace. The scanner ships with a happy/error/refusal trio, a 100% line+branch gate, and **fails loud (not fail-open) on an internal scan error**; the `test_canary_stub_is_identity_in_slice_2` test is retired.

### 4.3 Egress-response quarantine path

A tool-egress **response** is a T3 tool result and **cannot** reuse `process_inbound_message` (no `platform_user_id` / persona / per-user rate-limit fit). `[fleet]` The response is **tagged at the ingestion boundary** before anything else: mint a `ContentHandle`, record/stage it via `T3BodyRecorder` under the `tag_t3_with_nonce` gate (the single-use-handle invariant), then route through the **one production dual-LLM structured-extraction seam** (not a parallel extractor) keyed on `(canonical_user_id, tool-call id)` — where `canonical_user_id` is supplied **host-side**, never from the T3 payload. The privileged orchestrator never sees the raw T3 response (HARD rule 5). Inbound-extract vs egress-extract contend for the one quarantine child — the HoL design (§6) covers it.

Crucially, the §5 dedup ledger stores the **post-extraction T2 result** (or a redaction-safe form), **never the raw T3 body**, and a duplicate-egress replay returns that stored T2 — so a replay can never hand raw T3 back to the orchestrator on the second occurrence.

## 5. Egress idempotency

External calls cross a money/side-effect boundary. A re-run of a turn — a core restart mid-turn, a Spec A replay — must not double-fire them.

- **Deterministic, injective id.** `egress-id = f(committed inbound-id, session, logical-call identity)`. The per-turn component is the **deterministic logical-call position/content**, never completion-order — concurrent fan-out otherwise mis-keys the ledger, and a non-deterministic re-run otherwise mis-attributes a stored response to a different logical call (worse than silent loss). `f` is a property-tested deterministic injective function.
- **Core-stamped, core-committed, durable, tri-state.** The core stamps the egress-id and commits a **tri-state** row — `committed-no-response-yet` *before* the side-effect, then `committed-with-response` after — to a durable Postgres ledger, mirroring the G0 inbound commit-once pattern (G0 stores no response; this ledger adds a response column + its schema/owner). A bare existence probe is insufficient: a crash in the committed-no-response window must be recoverable, not replayed-as-success. The **gateway stays stateless** — a gateway restart must not re-enable double-send. A forged or unknown egress-id is rejected **core-side** (the gateway holds no dedup state to check against).
- **Memoize + replay on duplicate.** On a duplicate egress-id the stored T2 response is **replayed flagged `deduplicated`** — never silently dropped.
- **TTL-swept.** The dedup set is swept to the replay window.
- **Honest contract.** "At-most-once at the gateway + egress-id forwarded as the remote idempotency key where the API supports one." True exactly-once needs the remote endpoint's cooperation; we do not claim it.
- **Release-blocking test.** An epic-wide fake-external-world fixture (not barrier-only) + a deterministic **egress barrier** that kills the core *after the external call commits, before the response is acked*; the test asserts fire-count == 1 on the fake external, the re-run returns the `deduplicated`-flagged stored response (not a re-fire, not a silent drop), against a real Postgres, and exercises the TTL-expiry path.

## 6. Fail-loud, head-of-line isolation, and the egress channel

- **Two distinct typed errors.** `IOPlaneUnavailableError` — the gateway is unreachable, so *all* external I/O is down; loud, audited, bounded timeout (no hang), `gateway_core_link_up` metric. `EgressDeniedError` — an allowlist or gateway-DLP denial; surfaced distinctly to the agent and the operator (not a generic tool failure), reason via `t()`. The two are never conflated. Every egress-deny / IO-down / canary-trip / idempotency-replay path writes a **non-skippable audit row** (hard rule 7 — metrics are not the audit trail).
- **i18n.** `[fleet]` The two typed-error reasons, the operator-rendered audit-reason *presentations*, and the egress CLI text route through `t()` (a per-PR clause, mirroring Spec B). Audit-reason **tokens** stay stable identifiers (not localized). Metric **names**, Prometheus Help strings, and `ops/alerts` annotations stay English literals by existing convention.
- **Head-of-line isolation.** All external I/O shares one event loop, so isolation is cooperative: every egress call is an isolated `asyncio.TaskGroup` task with a per-call timeout + a per-destination and global concurrency cap; the CONNECT byte-splice must **yield** so a tight high-throughput stream cannot starve the loop; the egress path does not share a serial await chain with the comms relay; `gateway_egress_inflight` gauge + a saturation alert. Tests prove a blocked/slow streaming egress does not HoL a concurrent egress or the comms relay.

## 7. Connectivity-free enforcement (the structural claim is tested)

A structural invariant with no *runnable-on-every-PR* test rots. `[fleet]` The kernel-block integration test (a direct core→external `connect()` fails in the split topology) is **best-effort, not the gate** — it is split-network/root-only and skips on PR runners (the #243/#245 paper-gate hazard). The real merge gate is **non-root and in-process**:

- **A non-root AST import-guard lint, promoted to a required PR-level check** — forbids any *new* in-core external-HTTP-egress client: a provider-SDK / alt-HTTP import (`anthropic`/`openai`/`requests`/`aiohttp`) or an `httpx.AsyncClient`/`Client` construction in any binding form, outside the sanctioned `EgressClient`. Raw `socket` is deliberately **not** linted — unix-domain sockets are pervasive in-core; a raw *external* socket is stopped by the kernel block (the enforcement-of-record), not this lint. This is the always-on structural ratchet; the repo already has the pattern (`test_quarantined_llm_not_yet_spawned_while_egress_open.py`).
- **A `getaddrinfo`-external-name-must-fail probe** alongside the `connect()` block — proves the core cannot resolve an external name (closes the DNS-exfil side-channel), promoted into the §9 corpus.
- **A required compose-lint** in `test_compose_invariants.py` pinning: core attached to `alfred_internal` only, gateway to both, `alfred_internal.internal == true`, datastores internal-only.

The in-core `EgressClient` exposes no socket-opening capability; it speaks only the wire/proxy protocol to the gateway.

## 8. Credential-concentration: Spec B's invariant becomes true

Spec B placed credential-handling so that Spec C "flips the switch with zero cred movement." After the split, the **core** still holds the vault and **decrypts** every platform credential — but it **no longer has external network**. The **gateway** has network but never holds a vault key (Spec B); at adapter spawn it transiently transits the already-resolved plaintext over fd-3 and zeroes its copy. The **Discord child** holds exactly one credential (its own bot token) and now reaches only Discord via the L7 proxy. Therefore: **no process that holds external network *decrypts* more than one platform credential's plaintext** — Spec B's testable cred-concentration invariant becomes true here.

`[fleet]` ADR-0040 is honest about the residue: the invariant holds on the word *decrypts*; the gateway still **transits** the plaintext of each credential serially at spawn time (the Spec B serial-harvest residual), and payload-blindness is about T3 message bodies, not spawn-time cred control frames. This is an accepted, recorded residual, not a silent gap.

## 9. Adversarial corpus (release-blocking)

New categories, layered on the existing dual-LLM / DLP corpus. `[fleet]` The earlier single "allowlisted-destination exfil = canary" entry was vacuous (a seeded canary certifies only the seeded case); the corpus must cover the attack classes the design actually opens:

- **Non-canary body exfil to an allowlisted destination** — a planted secret/PII (not a canary token) in an outbound mode-(b) body is caught by the **gateway DLP pass** (decision 12) + audited + the egress refused. (This is the entry that makes the two-layer content claim real.)
- **Canary trip on egress** — a seeded canary in a mode-(b) body trips + audits + refuses; the scanner fails loud, not open, on an internal error.
- **DNS exfil** — the core cannot resolve an external name in the split topology (§7 probe).
- **Mode-(a) provider-prompt exfil residual** — recorded as an accepted residual (TLS-passthrough is destination-only by design); the corpus documents the scope rather than claiming a catch.
- **Discord raw-IP / SNI-spoof / DNS-label bypass** — the L7 proxy refuses literal-IP CONNECT and resolves the host itself; the surviving SNI-spoof-to-cotenant + CDN-cotenant residuals are recorded (ADR-0040 honest scope), not claimed caught.
- **Egress-id replay / false-replay / forgery** — a re-run replays the memoized T2 and does not re-fire; a forged/incremented egress-id is rejected core-side.
- **Cross-mode tier-downgrade** — a tool-egress (T3) response can never acquire the mode-(a) T2 tag via the response path (tier-laundering guard).
- **IO-plane-down audit completeness** — `IOPlaneUnavailableError` / `EgressDeniedError` each emit their non-skippable audit row.

`[fleet]` Also: flip `sbx-2026-005` from `out_of_scope` to **enforced containment** (and invert its "net not in `policy.unshare`" tripwire) when the quarantine child gets `--unshare-net`; and **migrate (don't drop)** the Discord adapter policy tests (`test_discord_adapter_sandbox_policy.py`) to the new proxy model.

## 10. PRD & ADR changes (human-gated)

- **ADR-0040** — Connectivity-free core / mandatory egress chokepoint: the network split as enforcement-of-record; the two-layer disposition (kernel enforcement-of-record + the userspace proxy/DLP defense-in-depth, decisions 2 + 12); the two egress modes; the unified L7 CONNECT forward-proxy; the egress-idempotency contract; the credential-concentration payoff + the serial-transit residue (§8). **Three honest-scope residuals for sign-off:** (i) Discord SNI-spoof-to-cotenant + CDN-cotenant (Cloudflare-fronted, TLS-passthrough is SNI-blind, ECH defeats SNI-peek); (ii) mode-(a) provider-prompt exfil is destination-gated only (TLS-passthrough by design); (iii) under full **gateway compromise** the "two independent layers" framing degrades (the gateway is both the egress point and the serial cred-transit point). No additional per-plugin kernel cap is built — empty-netns is already socketless for the quarantine child, and the Discord child reaches only the L7 proxy.
- **PRD §5 rewrite** — the gateway above the core as the I/O plane; the connectivity-free invariant **promoted to an invariant only at G7**; centralize §7.1 egress enforcement at the gateway; fix the §5 comms-bus drift (the stale Redis-streams depiction → the notification model).
- **PRD §7.1** — the per-session empty-by-default allowlist is reconciled with the structural gate: the gateway enforces the **structural ceiling** (the destination allowlist + the DLP pass); the per-session grant **narrows within** that ceiling — both compose, the gateway is the enforcement point. Citation: §7.1, line 447 ("Default-deny for outbound network calls").

## 11. Epic decomposition (sketch; `writing-plans` details and sequences each PR)

Core-invariant-first, with the structural gates landing early so no merged PR ships an unguarded window. Each PR runs the full per-PR cadence (plan → architect+security plan-review → subagent TDD → full `/review-pr` fleet + CodeRabbit → resolve every thread → plain `gh pr merge --rebase`). The new security-boundary modules (EgressClient, the L7 proxy, the gateway DLP pass, the idempotency ledger) live **outside** `src/alfred/security/` so they are **not** swept by the existing 100% gate — each needs an explicitly-named per-file line+branch coverage gate in `ci.yml`.

- **G7-0 — topology & the structural gates.** The two custom networks (compose) + the required compose-lint + **the non-root AST import-guard lint promoted to a required check now** (so every later PR is structurally guarded). Network *membership* only — behaviour-neutral; the `internal: true` + core-off-external isolation flips atomically at G7-3. The in-core `EgressClient` seam + the fail-loud typed errors move to **G7-1** (no consumer in G7-0 would be dead code; the structural gates §11 wants still land here).
- **G7-1 — provider forward-proxy + the in-core egress seam.** The in-core `EgressClient` / egress-channel seam (with its defined socket lifecycle) + the fail-loud typed errors (`IOPlaneUnavailableError`, `EgressDeniedError`); the gateway L7 CONNECT proxy (mode a); the per-client `http_client=AsyncClient(proxy=...)` seam on both providers (and add the sanctioned EgressClient module to the import-guard's construct-allowlist); live-config-derived allowlist; T2 carve-out; quarantine-child `--unshare-net`.
- **G7-2 — inspecting tool-egress relay + gateway DLP + idempotency together.** `[fleet]` Mode (b), the real outbound canary scanner, the gateway DLP second pass, **and** the egress-idempotency ledger (deterministic id + tri-state commit + barrier test) ship in one PR — the side-effecting flip must not land before the dedup ledger exists (no double-fire window); the §4.3 egress-response quarantine-extract entry; the fake-external fixture.
- **G7-3 — flip the core connectivity-free.** Move the core to `alfred_internal` only + no client-side DNS; the kernel-block + `getaddrinfo`-must-fail enforcement tests; the boot-ordering `depends_on`/`--wait` so the core waits for the gateway proxy; **atomically delete the G7-0 direct-egress fallback** (no fail-open-to-dead seam); HoL isolation + `gateway_egress_inflight` saturation alert.
- **G7-4 (tail) — Discord-adapter L7-proxy hardening.** `--unshare-net` + `discord.py` `Client(proxy=...)` at the gateway L7 proxy (REST + the `gateway.discord.gg` WSS both over CONNECT); per-adapter destination allowlist; migrate (don't drop) the Discord policy tests; flip `sbx-2026-005`; closes the rest of #230.
- **G7-5 — invariant + corpus + docs.** PRD §5/§7.1 + ADR-0040 (incl. the three honest-scope residuals); the adversarial corpus additions (§9); ops dashboards/alerts (`ops/grafana`, `ops/alerts`) for the egress plane with thresholds/exprs; the operator egress-state CLI surface (`alfred gateway` status/healthcheck extension); CLAUDE.md command/surface updates.

Sequencing note: the gateway/forward-proxy exists from G7-1, the idempotency ledger from G7-2, and the import-guard + compose-lint from G7-0 — so the core is never cut off from providers, and no merged PR has an unguarded direct-socket or double-fire window.

## 12. Out of scope / deferred

- **2c real-LLM quarantine child** — the child's real provider call over the L7 proxy is a separate follow-on epic with its own human sign-off; #230's go-live note flips unset-provider-key → refuse-boot there, not here.
- **Encrypted secret vault (#330)** — the env-on-core interim (`ALFRED_DISCORD_BOT_TOKEN`, the quarantine provider key) is unchanged by Spec C and migrates into the vault cleanly when #330 is scheduled. It is **broker-mediated and file-preferred** (`secrets.py` `_PREFER_FILE`), not a direct env read in agent paths (hard rule 6) — Spec C does not condone direct env reads.
- **Gateway supervisor park-not-abort (#331)** — independent of the egress plane.
- **Telegram / additional adapters** — ride the inverted host (#40); each new adapter points its SDK at the L7 proxy and declares its own destination allowlist.
- **Internal-CLI providers** (Claude Code / Codex) — absent from the repo today; when added they join the egress taxonomy via the same L7 proxy.

## 13. References

- [gateway-control-plane-roadmap](2026-06-13-gateway-control-plane-roadmap.md) — the captured B/C findings this spec resolves.
- [spec-b-adapter-inversion-design](2026-06-18-spec-b-adapter-inversion-design.md) — the inverted host Spec C builds on; the credential placement Spec C activates (§8).
- [comms-gateway-resume-design](2026-06-13-comms-gateway-resume-design.md) — Spec A; the G0 inbound-idempotency commit pattern the egress-idempotency ledger mirrors (§5).
- PRD §5 (architecture), §7.1 (egress allowlists, line 447) — the sections this epic rewrites.
- Issues: #333 (this epic), #230 (resolved here), #330 / #331 / #287 (adjacent, deferred).
