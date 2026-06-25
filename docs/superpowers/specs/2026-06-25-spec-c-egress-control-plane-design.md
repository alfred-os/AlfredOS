# Egress Control Plane / Connectivity-Free Core (Spec C / G7)

- **Date:** 2026-06-25
- **Status:** Draft (design approved in brainstorming 2026-06-25; not yet plan-reviewed). Epic [#333](https://github.com/alfred-os/AlfredOS/issues/333). ADR-0040 pending (human-gated). PRD §5/§7.1 rewrite pending (human-gated).
- **Scope:** This is **Spec C**, the final epic of the three-epic gateway control-plane program (see [gateway-control-plane-roadmap](2026-06-13-gateway-control-plane-roadmap.md)). Spec C makes the **core connectivity-free** — it loses its external network — and turns the **gateway into the sole external I/O plane** for all outbound network I/O (providers, tools, hosted adapters).
- **Gated on:** Spec A (comms-resume gateway, #237 crit #7) and Spec B (gateway adapter-hosting inversion, [#288](https://github.com/alfred-os/AlfredOS/issues/288) / [spec-b-adapter-inversion-design](2026-06-18-spec-b-adapter-inversion-design.md)) complete and merged. The literal sole-egress prerequisite is met: the standalone `alfred-discord` egress service is gone (#309, PR #332).
- **Resolves:** #230 (sandbox network-egress schema / unrestricted child egress).
- **Out of scope (follow-on epic):** the **2c real-LLM quarantine child** — its provider call over the audited proxy is a thin follow-on behind this work, not part of Spec C. Spec C gives the quarantine child `--unshare-net` immediately (it is deterministic-echo and needs no network), closing its #230 hole; the real-LLM go-live keeps its own human sign-off.
- **Related:** ADR-0036 (adapter inversion), ADR-0038 (daemon control socket), ADR-0039 (gateway-adapter inbound bridge), ADR-0015/0030 (launcher/sandbox: bwrap kind model, fd-3 key delivery), ADR-0032/0033 (Spec A wire + lifecycle), ADR-0005/0012 (secret broker), #330 (encrypted/pluggable secret vault), #331 (gateway supervisor park-not-abort), #287 (nightly gateway restart live smoke).

## 1. Problem & scope

Today every external network connection in AlfredOS is opened **directly by the process that needs it**, with no chokepoint and no kernel-level egress cap:

- The **core** opens provider sockets itself — `AnthropicProvider` builds an `AsyncAnthropic` client (`src/alfred/providers/anthropic_native.py`), `DeepSeekProvider` an `AsyncOpenAI` client (`src/alfred/providers/deepseek.py`). No proxy, no destination allowlist at the call boundary.
- **Tool egress** (web-fetch) has a three-way allowlist data model (`src/alfred/plugins/web_fetch/allowlist.py`) but it is not enforced at call time yet, and the canary scanner is a Slice-2 stub.
- **Sandboxed children** have **full unrestricted egress**. Both `config/sandbox/quarantined-llm.linux.bwrap.policy` and `config/sandbox/discord-adapter.linux.bwrap.policy` deliberately omit `--unshare-net`, each with an in-file comment naming #230 as the release-blocker and the *same* intended fix: a `network.outbound_allowlist` field + `--unshare-net` + a slirp/pasta-style filtered forwarder, or fd-passing.
- The **Docker Compose** topology puts every service on the **default bridge**; `alfred-core` has unrestricted outbound NAT.

The PRD documents the *goal* (§7.1: "Default-deny for outbound network calls") as a **per-tool allowlist**, not a structural property of the core. There is no statement that the core is connectivity-free, and today it is not.

**Spec C makes the connectivity-free-core invariant structurally true.** The gateway becomes the mandatory chokepoint for all outbound I/O; the core loses its external network at the kernel level (a container on an `internal:true` network); and the two egress-needing children (the deterministic-echo quarantine child and the live Discord adapter) are brought under egress control. The gateway and its hosted adapters *are* the external I/O plane by design — the invariant is about the **core**, not the gateway.

**In scope:** the network split; the provider forward-proxy; the inspecting tool-egress relay; egress idempotency; fail-loud I/O-plane errors; head-of-line isolation; the connectivity-free enforcement tests; the Discord-adapter filtered-forwarder hardening; the adversarial corpus additions; and the PRD §5/§7.1 + ADR-0040 writes.

**Out of scope:** the 2c real-LLM quarantine child (separate follow-on); building a new adapter; the encrypted secret vault (#330, designed-but-unscheduled; the env-on-core interim migrates into it cleanly later); the gateway supervisor park-not-abort structural fix (#331).

## 2. Locked decisions

Resolved during brainstorming (2026-06-25). Decisions 1, 3–8, 11 were pre-locked across the prior sessions; decisions 2, 9, 10 were settled in this session with maintainer co-sign. Do not re-litigate.

1. **Full structural switch — subsumes #230.** There is no per-plugin kernel egress cap today; Spec C is the first real network isolation. The roadmap's "kernel-cap regression" framing was false (there was no cap to regress from).
2. **Enforcement model = two independent layers** (maintainer co-sign, this session). **Kernel network isolation** — empty-netns for children + an `internal:true` network for the core container — is the **structural enforcement-of-record** that the PRD "connectivity-free" invariant cites. The gateway forward-proxy destination-allowlist + mandatory canary-scan-on-egress + audit is **independent userspace defense-in-depth** on top: it does not depend on the kernel layer being flawless, and a gap in either still leaves one boundary. ADR-0040 states precisely what each layer does and does not guarantee.
3. **Provider egress = forward-proxy with TLS passthrough.** The core's provider SDK targets the gateway as an HTTPS forward-proxy; TLS terminates at the provider, so the gateway enforces the **destination** allowlist + audit + canary-on-destination but **never sees the decrypted prompt**, and native SDK streaming is preserved. Provider responses are **T2** (assistant output), **not T3**.
4. **Two egress modes.** (a) destination-allowlisted forward-proxy / TLS-passthrough for providers and any egress where the gateway must not see plaintext; (b) **inspecting** frame-relay with a core-DLP-redacted body for tool egress (web posts, email) where canary/destination control on the body matters.
5. **Egress idempotency** = deterministic `egress-id = f(committed inbound-id, session, per-turn egress ordinal)`; **core-stamped + core-committed durable** (gateway stays stateless); on a duplicate **memoize + replay the stored response flagged `deduplicated`**, never a silent drop; **TTL-bounded** dedup set; framed honestly as "**at-most-once at the gateway + egress-id forwarded as the remote idempotency key where the API supports one**."
6. **Network split:** two custom networks — `alfred_internal` (`internal: true`; core ↔ datastores ↔ gateway) and `alfred_external` (gateway only). The gateway joins **both**; the core joins **internal only**.
7. **Fail-loud:** typed `IOPlaneUnavailableError` (gateway unreachable → total external-I/O outage) distinct from `EgressDeniedError` (allowlist denial); bounded timeouts, no quiet-dark; `core_gateway_link_up` metric.
8. **Head-of-line isolation:** every egress call is an isolated `asyncio.TaskGroup` task with a per-call timeout + per-destination/global concurrency cap, on a channel separate from the comms-relay serial await chain; `gateway_egress_inflight` gauge + saturation alert.
9. **2c real-LLM quarantine child is OUT of scope** (maintainer co-sign, this session) — a separate follow-on epic. Spec C gives the quarantine child `--unshare-net` immediately.
10. **Discord-adapter egress hardening is IN scope, as a tail PR** (maintainer co-sign, this session). The live gateway-hosted Discord child gets a **pasta/slirp-style filtered forwarder** pinned to a per-adapter destination allowlist — transparent to the third-party `discord.py`, no SDK-transport surgery. The strict **empty-netns + SCM_RIGHTS fd-broker** model is reserved for the future in-house quarantine child (2c), where we own the transport and it makes a single bounded call.
11. **ADR-0040 + PRD §5/§7.1 rewrite are human-gated.** Egress-policy citation = PRD **§7.1** (line 445), not "§49".

## 3. Topology — the connectivity-free core

The headline invariant: **the core has no external sockets** (kernel-enforced, the enforcement-of-record), and **the gateway is the sole external I/O plane**.

```
            ┌─────────────────── alfred_external (internet) ───────────────────┐
            │                                                                  │
   ┌────────┴──────────┐                                          api.anthropic.com
   │   alfred-gateway  │ ── forward-proxy (CONNECT, TLS-passthrough) ─▶ api.deepseek.com
   │  (joins BOTH nets)│ ── inspecting relay (DLP-redacted body)      ─▶ web-fetch hosts
   │                   │ ── hosted Discord child ──(filtered forwarder)─▶ discord.com (WSS)
   └────────┬──────────┘
            │  alfred_internal  (internal: true — NO route to the internet)
   ┌────────┴───────────────────────────────────────────────────────────┐
   │  alfred-core              alfred-postgres   alfred-redis   ...        │
   │  (connectivity-free)                                                 │
   │   • provider SDK  ──▶ gateway forward-proxy endpoint (on internal)   │
   │   • tool egress   ──▶ gateway inspecting relay (on internal)         │
   │   • quarantine child: --unshare-net NOW (echo; needs no network)     │
   └──────────────────────────────────────────────────────────────────────┘
```

- The **gateway** joins both networks — it is the bridge/chokepoint. The **core and datastores** join `alfred_internal` only, so the core *cannot route* to the internet. That container-level isolation is the core's kernel enforcement-of-record; it is independent of, and stronger than, the userspace proxy allowlist.
- Egress runs on a **channel separate from the comms control wire** (perf-F2). A dedicated gateway egress endpoint on `alfred_internal` carries provider and tool egress; it is not multiplexed onto the Spec A/B single-writer comms leg, so a streaming provider call cannot head-of-line-block the comms relay.
- Postgres currently publishes `5432:5432` to the host. Under the split, Postgres stays on `alfred_internal`; the host port-publish is preserved for operator/dev access (a published port maps the host to the container, it does not give the container outbound internet), reconciled in the compose-invariants test.
- The gateway already carries `cap_add: SETUID` + the bwrap launcher (Spec B). Spec C adds the forwarder tooling (`pasta`/`passt` or `slirp4netns`) to the gateway image for the adapter filtered-forwarder; the core image gains no new capability.

## 4. The egress classes and the two modes

There are four egress classes. Three are handled in Spec C; the fourth (2c) reuses what Spec C builds.

| Class | Today | Spec C |
|---|---|---|
| Core → provider (Anthropic / DeepSeek) | direct HTTPS from the core | core SDK targets the gateway **CONNECT forward-proxy** (mode a); destination allowlist + audit + canary-on-destination; TLS passthrough (gateway never sees the prompt); streaming preserved; responses tagged **T2** |
| Core / plugin → tool egress (web-fetch, email) | allowlist data model exists, unenforced | **inspecting frame-relay** (mode b): core DLP-redacts the body, gateway canary-scans + destination-allowlists + audits + forwards; the response is handled by a dedicated quarantine-extract entry (§4.3) |
| Quarantine child | full unrestricted net (no 2c yet) | gets `--unshare-net` immediately — deterministic-echo needs zero net; the SCM_RIGHTS provider path is built in the 2c follow-on |
| Hosted Discord adapter child | full unrestricted net, live in prod | **pasta/slirp filtered forwarder** pinned to the Discord destination allowlist (mode-a-shaped: TLS-passthrough to Discord, the gateway sees destination only); tail PR |

### 4.1 Mode (a) — provider forward-proxy

The core's `EgressClient` configures the provider SDKs to use the gateway as an HTTPS proxy (httpx and both SDKs accept a standard proxy via `proxies=` / `HTTP(S)_PROXY`). The gateway terminates the proxy `CONNECT`, checks the **destination host** against the provider allowlist, audits the destination, runs the canary-on-destination check, then opens the upstream TCP and splices bytes. TLS is end-to-end core↔provider, so the gateway is **payload-blind to the prompt and response**; SDK streaming, retries, and timeouts are preserved. Provider responses re-enter the core as **T2** assistant output, not T3 — the "egress-response is T3" rule explicitly carves out providers (otherwise every model token is mis-tagged T3).

### 4.2 Mode (b) — inspecting tool-egress relay

Tool egress (web POST, email) is content the gateway *must* be able to inspect (destination control + canary on the body matter). The core runs `OutboundDlp.scan_for_outbound` to produce a redacted body, then sends an `egress.request` frame carrying the **already-redacted** body + the destination + the egress-id (§5) to the gateway over the dedicated egress channel. The gateway re-checks the destination against the tool allowlist, runs the **mandatory canary-scan-on-egress** over the (bounded, streamed) body, audits, then performs the outbound call. The canary scanner — a Slice-2 stub today — must be implemented for real here; it is the **one content check the payload-blind gateway performs**, and the honest second line against allowlisted-destination exfil (§9).

### 4.3 Egress-response quarantine path

A tool-egress **response** is a T3 tool result and **cannot** reuse `process_inbound_message` (no `platform_user_id` / persona / per-user rate-limit fit). Spec C defines a **separate quarantine-extract entry keyed on `(canonical_user_id, tool-call id)`**, routing the T3 response through the existing dual-LLM structured-extraction path. (The privileged orchestrator never sees the raw T3 response — HARD rule 5 holds.)

## 5. Egress idempotency

External calls cross a money/side-effect boundary (sending an email, posting to an API). A re-run of a turn — a core restart mid-turn, a Spec A replay — must not double-fire them.

- **Deterministic id.** `egress-id = f(committed inbound-id, session, per-turn egress ordinal)`. A `uuid4` per call silently double-fires on a re-run because the re-run mints a fresh id; the deterministic function yields the *same* id for the *same* logical call, so the dedup record matches.
- **Core-stamped, core-committed, durable.** The core stamps and commits the egress-id (and, on completion, the stored response) to a durable, **TTL-bounded** dedup ledger *before* the side-effect, mirroring the G0 inbound-idempotency commit-once-before-side-effects pattern. The **gateway stays stateless** — a gateway restart must not re-enable double-send.
- **Memoize + replay on duplicate.** On a duplicate egress-id the stored response is **replayed flagged `deduplicated`** — never silently dropped (silent loss at a money boundary is the failure mode we are preventing).
- **Honest contract.** "At-most-once at the gateway + egress-id forwarded as the remote idempotency key where the API supports one." True exactly-once needs the remote endpoint's cooperation; we do not claim it.
- **Release-blocking test.** A fake-external-world seam + a deterministic **egress barrier** that kills the core *after the external call commits, before the response is acked*, then asserts the re-run replays (does not re-fire).

## 6. Fail-loud and head-of-line isolation

- **Two distinct typed errors.** `IOPlaneUnavailableError` — the gateway is unreachable, so *all* external I/O is down; loud, audited, bounded timeout (no hang), `core_gateway_link_up` metric. `EgressDeniedError` — an allowlist denial for a specific destination; surfaced distinctly to the agent and the operator (not a generic tool failure), reason via `t()`. The two are never conflated: "the plane is down" and "this destination is denied" are different operator actions.
- **Head-of-line isolation.** All external I/O shares one event loop. Every egress call is an isolated `asyncio.TaskGroup` task with a per-call timeout + a per-destination and global concurrency cap; the egress path does not share a serial await chain with the comms relay; `gateway_egress_inflight` gauge + a saturation alert.

## 7. Connectivity-free enforcement (the structural claim is tested)

A structural invariant with no test rots on the first plugin that re-opens a socket. Spec C makes "connectivity-free core" enforceable:

- **No socket capability in-core.** The in-core `EgressClient` exposes no socket-opening capability; it speaks only the wire/proxy protocol to the gateway.
- **Integration test in the split topology.** A direct core→external `connect()` **fails loud** when the core is on `alfred_internal` only — the test asserts the kernel-level block, the enforcement-of-record.
- **Import-guard lint.** A repo lint forbids any in-core HTTP/socket client (`httpx.Client`, raw `socket`, provider SDKs constructed without the proxy seam) outside the sanctioned wire/egress client — so a future change that re-opens a direct socket fails CI, not production.

## 8. Credential-concentration: Spec B's invariant becomes true

Spec B placed credential-handling so that Spec C "flips the switch with zero cred movement." Spec C is that switch. After the split, the **core** still holds the vault and decrypts every platform credential — but it **no longer has external network**. The **gateway** has network but never holds a vault key (Spec B); at adapter spawn it transiently transits the already-resolved plaintext over fd-3 and zeroes its copy. The **Discord child** holds exactly one credential (its own bot token) and now reaches only Discord via the filtered forwarder. Therefore: **no process that holds external network decrypts more than one platform credential's plaintext** — Spec B's testable cred-concentration invariant becomes true here. ADR-0040 records this as the payoff, and is honest about the one residue (the gateway transits — does not decrypt — a single cred at spawn time; payload-blindness is about T3 message bodies, not spawn-time cred control frames).

## 9. Adversarial corpus (release-blocking)

New categories, layered on the existing dual-LLM / DLP corpus:

- **Allowlisted-destination exfil** — "DLP-in-core, allowlist-in-gateway" gates *destination*, not content over an allowlisted channel; a compromised core could exfil in the body the gateway forwards. The honest second line is the **mandatory canary-scan-on-egress** (mode b); the corpus asserts a planted canary in an outbound body to an allowlisted destination is caught + audited + the egress refused. ADR-0040 carries the honest scope: TLS-passthrough provider egress (mode a) is destination-gated only by design.
- **Egress-id replay / double-fire** — a re-run with the same logical call replays the memoized response and does not re-fire; a forged/incremented egress-id is rejected.
- **Forged destination / spoofed egress frame** — an egress frame with a destination not matching the committed call, or a forged gateway response, is refused + audited.
- **Child attempts an off-allowlist connection** — the Discord child connecting to a non-Discord host is refused by the filtered forwarder + audited.
- **Core attempts a direct external connect** — kernel-blocked in the split topology + loud (the §7 enforcement test, promoted to a release-blocking corpus entry).

## 10. PRD & ADR changes (human-gated)

- **ADR-0040** — Connectivity-free core / mandatory egress chokepoint: the network split as enforcement-of-record; the two-layer disposition (kernel enforcement-of-record + proxy defense-in-depth, decision 2); the two egress modes; the provider forward-proxy; the egress-idempotency contract; the credential-concentration payoff (§8); the honest exfil scope (§9); the kernel-cap disposition (no additional per-plugin kernel cap is built — empty-netns is already socketless for the quarantine child, and the Discord child's filtered forwarder is the enforcement for that case).
- **PRD §5 rewrite** — the gateway above the core as the I/O plane; the connectivity-free invariant **promoted to an invariant only at G7** (it is false through A/B — land the diagram earlier as "target architecture," promote here); centralize §7.1 egress enforcement at the gateway; fix the §5 comms-bus drift (the stale Redis-streams depiction → the notification model).
- **PRD §7.1** — the egress allowlist becomes structurally-gated at the gateway, not merely policy-gated per tool; honest about the two layers and the TLS-passthrough scope. Citation fix (§7.1, line 445) applied wherever the draft cited "§49".

## 11. Epic decomposition (sketch; `writing-plans` details and sequences each PR)

Core-invariant-first, so the headline ships before the adapter hardening. Each PR runs the full per-PR cadence (plan → architect+security plan-review → subagent TDD → full `/review-pr` fleet + CodeRabbit → resolve every thread → plain `gh pr merge --rebase`).

- **G7-0 — topology & seam.** The two custom networks (compose), the in-core `EgressClient` / wire seam, the fail-loud typed errors (`IOPlaneUnavailableError`, `EgressDeniedError`). No behaviour change yet (the seam forwards to direct egress until G7-1/G7-2 land), so the core keeps working while the plane is built.
- **G7-1 — provider forward-proxy.** The gateway CONNECT forward-proxy endpoint (mode a); re-point the core provider SDKs at it; T2 response tagging carve-out; quarantine-child `--unshare-net`.
- **G7-2 — inspecting tool-egress relay.** Mode b; the real canary scanner; the egress-response quarantine-extract entry keyed on `(canonical_user_id, tool-call id)`.
- **G7-3 — egress idempotency.** The deterministic egress-id, the core-committed TTL-bounded dedup ledger, memoize-and-replay, and the release-blocking deterministic-barrier test.
- **G7-4 — flip the core connectivity-free.** Move the core to `alfred_internal` only; the §7 enforcement tests + the in-core socket-client import-guard lint; HoL isolation + `gateway_egress_inflight` saturation alert.
- **G7-5 (tail) — Discord-adapter filtered forwarder.** The `network.outbound_allowlist` schema field + `--unshare-net` + the pasta/slirp filtered forwarder pinned to the Discord allowlist; migrate (don't drop) the Discord adapter's egress-related tests; closes the rest of #230.
- **G7-6 — invariant + corpus + docs.** PRD §5/§7.1 + ADR-0040; the adversarial corpus additions (§9); ops dashboards/alerts (`ops/grafana`, `ops/alerts`) for the egress plane; CLAUDE.md command/surface updates.

Sequencing note: the gateway/forward-proxy must exist **before** the core loses its net (G7-1/G7-2 before G7-4), or the core is cut off from providers mid-epic.

## 12. Out of scope / deferred

- **2c real-LLM quarantine child** — the child's real provider call over the audited proxy is a separate follow-on epic with its own human sign-off; #230's go-live note flips unset-provider-key → refuse-boot there, not here.
- **Encrypted secret vault (#330)** — the env-on-core interim (ALFRED_DISCORD_BOT_TOKEN, quarantine provider key) is unchanged by Spec C and migrates into the vault cleanly when #330 is scheduled.
- **Gateway supervisor park-not-abort (#331)** — the blast-radius structural fix is independent of the egress plane.
- **Telegram / additional adapters** — ride the inverted host (#40); each new adapter declares its own `network.outbound_allowlist`.

## 13. References

- [gateway-control-plane-roadmap](2026-06-13-gateway-control-plane-roadmap.md) — the captured B/C findings this spec resolves.
- [spec-b-adapter-inversion-design](2026-06-18-spec-b-adapter-inversion-design.md) — the inverted host Spec C builds on; the credential placement Spec C activates (§8).
- [comms-gateway-resume-design](2026-06-13-comms-gateway-resume-design.md) — Spec A; the G0 inbound-idempotency commit pattern the egress-idempotency ledger mirrors (§5).
- PRD §5 (architecture), §7.1 (egress allowlists, line 445) — the sections this epic rewrites.
- Issues: #333 (this epic), #230 (resolved here), #330 / #331 / #287 (adjacent, deferred).
