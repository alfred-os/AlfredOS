# Comms-Resume Gateway (Spec A) — resumable dial-in transport

- **Date:** 2026-06-13
- **Status:** Draft (design approved + twice fleet-reviewed; convergence green). ADR-0032/0033 pending.
- **Scope:** This is **Spec A** of a three-epic program (see [gateway-control-plane-roadmap](2026-06-13-gateway-control-plane-roadmap.md) for B + C). Spec A ships an always-up gateway that fronts **dial-in clients (the TUI)** with a resumable, payload-blind wire so a core restart never drops the operator or loses their input. It closes #237 graduation criterion #7. It deliberately does **NOT** host platform adapters (Spec B), proxy tool/provider egress, or make the core connectivity-free (Spec C). The PRD "all external I/O via the gateway / connectivity-free core" invariant lands with **Spec C**, not here.
- **Related:** ADR-0025 (line-delimited transport), ADR-0031 (TUI socket / Shape B), PR #258 (daemon socket listener), PR #259 (foreground TUI dials the daemon).
- **Reviewed by:** architect, security, devops, comms, error, performance, reviewer, test (two 8-agent `/review-pr` passes, 2026-06-13; all prior findings CLOSED). `[fleet]` marks a fix that landed from review.

## 1. Problem & scope

The core self-modifies and **restarts** (a change that can't hot-reload, a crash, `alfred daemon stop`, container recycle). Today `alfred chat` dials the core socket directly (ADR-0031 / PR #259); when the core closes that socket the client can only exit, dropping the operator mid-conversation and losing in-flight input.

Spec A introduces a **standalone, always-up gateway** between dial-in clients and the core. Clients dial the **gateway**; the gateway is the stable part (rarely changes) and holds the client connection across a core restart, buffering + replaying the operator's un-acked input to the freshly-restarted core. The core is the smart part that restarts.

**Out of scope (Spec B/C):** gateway-hosting of platform adapters (Discord/Telegram), the egress chokepoint for tool/provider I/O, and the connectivity-free-core network split. Spec A leaves the core's existing network and adapter-spawning untouched.

## 2. Locked decisions

1. **Gateway fronts dial-in clients (TUI first).** Clients dial the gateway, never the core. The gateway terminates the client connection — on a core restart the client never sees EOF; it gets a control frame (`reconnecting`/`restored`/`unavailable`) + a banner instead of dying.
2. **Resume guarantee = no operator-INPUT loss + no double-effect** `[fleet]`: the gateway buffers + replays un-acked **inbound** (client→core) frames; nothing typed is dropped, and replay never double-executes (idempotency commit, decision 4). A core reply in flight at restart is **not** replayed — the turn re-runs from the replayed input. Transparent mid-turn continuity is out of scope (§10).
3. **Envelope-aware, payload-blind** `[fleet]`: seq/ack/dedup ride an out-of-band header wrapping the opaque ADR-0025 payload (forwarded byte-for-byte). The gateway never decodes payload; T3 tagging stays in the core. The gateway is a **T1 carrier**.
4. **Idempotent inbound via a core-side durable commit** `[fleet]`: each inbound frame carries a durable wire **inbound-id**; the core commits "accepted" keyed on it **before any side effect** (audit, extract, dispatch), so a replayed frame short-circuits.
5. **AF_UNIX over a shared volume** `[fleet]`: the gateway dials the core over a `0600` socket on a shared `alfred_run` volume, under a `0700` dir, with `SO_PEERCRED` + a per-core-boot epoch nonce. The gateway is a **separate** Compose service that boots even when the core is down.

## 3. Topology

```
 alfred chat ──▶ alfred-gateway ──▶ alfred-core (daemon)
   (TUI+wire)    (relay + buffer,     (orchestrator; self-modifies, restarts;
                  always up, sep.      network + adapter-spawning UNCHANGED in Spec A)
                  Compose service)
```

- **Inbound:** client→gateway→core; the gateway buffers un-acked inbound across a core restart and replays it.
- The gateway↔core leg reuses PR #259's `dial_comms_socket` over the shared-volume socket; the core side is PR #258's `CommsSocketListener`, hosted by a **new long-running `alfred-core` daemon service** (today's compose `alfred-core` is a one-shot runner) on a daemon-boot-independent `comms-core.sock`.
- **Stable-kernel split:** the connection-holder (`GatewayClientListener`) is the stable kernel; resume/buffer logic sits above it (enables the future fd-handoff self-upgrade, §10).
- **One gateway process** multiplexes client listeners `[fleet perf]`.
- **Note on the §5 PRD diagram drift** `[fleet architect]`: comms ingress is the MCP *notification* model (`process_inbound_message` / `InboundMessageNotification`), **not** a Redis-streams comms bus — the PRD §5 diagram is already stale on this. Spec A does not touch the PRD; the Spec C PRD rewrite must fix the drift rather than redraw over it. The Redis event bus remains an *intra-core* mechanism, unrelated to comms ingress.

## 4. Wire protocol (ADR-0025 → ADR-0032; lifecycle → ADR-0033)

Out-of-band header (decision 3) adds:

- **Per-direction monotonic seq**, distinct from + additive to the JSON-RPC `id` (gateway preserves `id` end-to-end so the runner's request/response correlation survives the relay) `[fleet comms]`.
- **Cumulative ack** of the highest contiguous seq the receiver **durably intaken** — the ack point is the core's durable intake commit (decision 4), decoupled from the core's existing out-of-order dispatch fan-out `[fleet comms]`. Acks coalesced (piggyback + bounded timer); no standalone ack per data frame `[fleet perf]`.
- **Idempotent dedup**, key = `(leg, seq)` only — never payload-derived `[fleet security]`.
- **Core lifecycle** (ADR-0033, core-owned): `core.lifecycle.going_down{reason}` on the drain; `core.lifecycle.ready` only after the **full security boot graph is healthy** (`ready` = health, not socket-bind) `[fleet error]`. Gateway holds buffers until `ready`.
- **Per-core-boot epoch nonce** at the handshake (reuse the boot-nonce pattern); gateway rejects a `ready`/handshake whose epoch mismatches; binds the last-acked exchange to the epoch (seq resets on a fresh core; epoch reconciles "new-core seq=0" vs the gateway's retained high-water) `[fleet security/reviewer]`. Conversely, the **core authenticates the gateway** via `SO_PEERCRED` on accept (a stale-socket race must not let an impostor bind first) `[fleet security]`.
- **Client control frames:** `link.reconnecting` / `restored` / `unavailable` (the last is the back-pressure/breaker signal).

`_MAX_COMMS_LINE_BYTES` unchanged; header version-gated at handshake.

## 5. Resume flow (inbound input only)

1. Core `going_down` (or unsignalled EOF → crash) → gateway marks the core link down, keeps the client connection open, buffers inbound frames, signals `reconnecting`.
2. Retry-dial with bounded backoff (initial ≥100–250 ms, exp to a 2–5 s ceiling, full jitter, never a 0-delay first retry) until the new core re-binds, handshakes, passes the epoch check, and emits `ready` `[fleet perf]`.
3. Replay un-acked inbound in FIFO order; the core dedups by inbound-id (decision 4) — replayed-already-committed short-circuit before side effects.
4. Signal `restored`; resume.

**Guarantee:** no operator-typed frame dropped; no double-effect. A core reply in flight at restart is not replayed — the turn re-runs from the deduplicated input.

**Failed restart** (G4 contract, not deferred `[fleet]`): the `ReplayBuffer` enforces a hard cap (bytes **and** frames **and** max-retry window); on breach the gateway **back-pressures the client read** (stops draining the client socket — never silent drop), emits `link.unavailable` + a loud audit row, holds the buffer. The **core/supervisor** owns self-mod rollback — the gateway never triggers it (a fail-safe buffer, not a supervisor) `[fleet architect/devops]`.

**Gateway-unreachable from the client** `[fleet error]`: if the gateway is down, a dialing client fails loud (reuse `comms.tui.daemon_required_to_chat`-style messaging + exit 3) rather than hanging. (In Spec A the core retains its own network, so a gateway outage only affects comms delivery, not all core I/O — that broader concern is Spec C's.)

## 6. Trust-boundary posture

- **Payload-blind wire** (decision 3): the gateway parses only the out-of-band header; **T3 tagging stays in the core** at `process_inbound_message` (hard rule #5 intact — the privileged orchestrator never sees raw T3). The gateway is a **T1 carrier**, no trust-tier authority.
- **Buffered pre-DLP input bounded as a security property** `[fleet]`: cap + TTL + zero-on-trim/breaker + `MADV_DONTDUMP` (operator input pinned in the always-up process across a crash-loop is an exposure).
- **Gateway↔core auth beyond same-uid** `[fleet]`: AF_UNIX 0600 under a 0700 shared-volume dir + `SO_PEERCRED` (both directions) + per-boot epoch nonce — a spoofed `ready` must not exfiltrate the buffer.
- **Audit non-skippable** `[fleet]`: every link-state transition (`going_down`, crash-EOF, each retry-dial, `ready`/restored, breaker-trip, malformed-frame-rejected) writes an audit row. A malformed frame is never ack-and-dropped (seq not advanced; audited; link teardown + reconnect). **Audit-during-core-down** `[fleet devops]`: the gateway buffers its own audit rows durably and reconciles them into the signed core audit log on reconnect (it must NOT hold the core's signing key) — Spec A specifies the gateway-local append + reconcile mechanism; ADR-0032 records it.
- **Adversarial corpus** (before the gateway ships): (a) a canary T3 transits the relay → trips only in the core; (b) crash-pre-ack → replay delivers exactly once; (c) spoofed `ready`/stale epoch → buffer not flushed; (d) wedged-core flood → bounded + loud.

## 7. Components & deployment

Injectable seams `[fleet test]`: fake clock; explicit link-state machine (`UP / DOWN_SIGNALLED / DOWN_CRASH / REDIALING`).

- **`CommsSeqCodec`** — out-of-band header encode/decode; payload verbatim. Pure, hypothesis-property-testable (replay idempotent; ack-trim; FIFO).
- **`ReplayBuffer`** — per-direction un-acked retention; trim+zero on ack; cap+TTL+breaker+back-pressure; FIFO replay. Pure state machine, no deps.
- **`GatewayCoreLink`** — gateway→core connection over the shared-volume socket; fake-clock reconnect/backoff; epoch handshake; consumes `core.lifecycle.*`.
- **`GatewayClientListener`** — stable kernel: binds client-facing sockets (PR #258 posture), terminates connections, emits control frames.
- **Core `InboundIdempotencyCommit`** (decision 4) — durable accept-once keyed on the wire inbound-id, consulted **before** identity-resolve/rate-limit/extract/audit (NOT the existing late `uuid4` in `process_inbound_message`); the unbound-first-contact binding-request branch is itself idempotent on the same id. With `alfred-memory-engineer` (schema) + `alfred-security-engineer` `[fleet comms]`.
- **Core `LifecycleSignaller`** (ADR-0033).
- **`alfred-gateway`** — composes the above; a Compose service; exposes Prometheus metrics.

**Deployment** `[fleet devops]`:

- **Shared `alfred_run` volume** in both the gateway and a **new long-running `alfred-core` daemon service** (today's core compose entry is a one-shot runner); `$HOME`/uid pinned (reuse setup `UID/GID` discipline); gateway↔core socket lives here. *(Spec A keeps the core's external network — the network split is Spec C.)*
- **Gateway service:** `restart: unless-stopped`; two-tier healthcheck (liveness = client listener bindable; readiness = core-link up OR buffering; only wedged-past-breaker = unhealthy); `depends_on` core **without** `service_healthy`. Invariant: *gateway readiness is independent of core liveness.*
- **Observability:** `gateway_core_link_up`, `gateway_buffer_depth_{frames,bytes}`, `gateway_buffer_cap_ratio`, `gateway_replay_frames_total`, `gateway_reconnect_attempts_total`, `gateway_core_unavailable_seconds`, `gateway_circuit_breaker_open`. Add `ops/grafana/gateway.json` + `ops/alerts/gateway.yml` (`GatewayCoreUnavailable`, `GatewayBufferNearCap`, `GatewayCircuitBreakerOpen`) — these + a Prometheus scrape config do **not** yet exist (PRD §7.5 promise, unbuilt) — create here.
- **Footprint/docs:** a second always-up process; README quickstart + setup script change (`alfred chat` dials the gateway; setup provisions `alfred_run`).

## 8. Epic decomposition (Spec A)

| PR | Scope |
|----|-------|
| **#259** | Land now — foreground TUI dials the core directly + co-hosts (substrate; `dial_comms_socket` reused by the gateway). |
| **G0** | Core `InboundIdempotencyCommit` (wire inbound-id + durable dedup-before-side-effect + schema migration). Independently valuable; commit point at the **top** of the inbound pipeline. |
| **G1** | ADR-0033 lifecycle signal (`going_down` on drain; `ready` after healthy boot graph) + epoch nonce. |
| **G2** | `CommsSeqCodec` (out-of-band seq/ack/dedup, `id` preserved, version-gated handshake). |
| **G3** | `alfred-gateway` process (listener + core-link, pure relay) + Compose (separate service, shared `alfred_run` volume, SO_PEERCRED, epoch, healthchecks, metrics). No buffering yet. |
| **G4** | `ReplayBuffer` (cap+TTL+breaker+back-pressure+zeroing) + reconnect/replay + control frames + audit (+ gateway-local audit reconcile) + Grafana/alerts. Failed-restart loudness ships here. *(Split candidate: G4a buffer / G4b reconnect+replay+frames.)* |
| **G5** | Re-point `alfred chat` to dial the gateway; banners; **delete the #259 direct-dial path** (no dual-mode); note the interim no-resume window between #259 and G5. |

**G5-era smoke** closes the deferred #237 PR-4 PTY smoke (TUI survives a core restart; banner renders). **ADR-0032** (gateway comms-resume transport — payload-blind wire, buffer security, epoch auth, shared-volume AF_UNIX, gateway-local audit reconcile). **ADR-0033** (core lifecycle signalling). Spec A ships **no** PRD invariant change (that lands with Spec C).

## 9. Testing

- **Unit:** `CommsSeqCodec` props (replay idempotent, ack-trim, **FIFO**); `ReplayBuffer` vs fake-core-dies+revives (cap/TTL/breaker/**back-pressure** asserted); `GatewayCoreLink` fake-clock (reconnect-race, **non-spin** backoff ≤N dials over a dead-core interval, crash-vs-`going_down` as pure transitions, truncated-frame-then-EOF); banner state machine (no `restored` without `reconnecting`; exactly one per gap); `InboundIdempotencyCommit` dedup-before-side-effect.
- **Integration:** gateway↔core over real shared-volume sockets; restart at a **deterministic barrier** → each inbound frame delivered **exactly once** (release-blocking; catches double-delivery, not just loss); replay-into-half-booted-core refused (`ready`=health).
- **Smoke (G5):** live core+gateway+chat survives a restart, banner renders; demotable to nightly if flaky (the deterministic integration test carries the release-blocking proof, not the smoke).
- **Adversarial (§6):** the four corpus entries; (b) exactly-once and (d) bounded-flood are release-blocking.
- **Coverage bar** `[fleet]`: `GatewayClientListener` bind + core-frame ingest/containment held to **100% branch** (trust-boundary; confirm with security in ADR-0032); ≥80% relay/codec core; happy/error/refusal triad per component.

## 10. Deferred / future concerns

- **Specs B & C** — adapter-hosting inversion (Discord/Telegram → gateway-hosted) and the egress control plane + connectivity-free core (forward-proxy TLS-passthrough for providers). Captured with all review decisions in [gateway-control-plane-roadmap](2026-06-13-gateway-control-plane-roadmap.md). Spec A is gated to ship first; B and C open only after A proves out in prod.
- **Transparent mid-turn continuity** — resume a half-generated reply token-for-token; needs durable mid-turn core state. Out of scope (decision 2).
- **Gateway self-upgrade** — in-place `SCM_RIGHTS` fd-handoff drain-and-takeover (NOT `SO_REUSEPORT` — wrong for AF_UNIX). Pinned forward-compat (ADR-0032): client-facing socket is a stable externally-owned path on the shared volume, bound unlink-if-stale; any handoff MUST authenticate the takeover. Out of scope until that auth is designed.
- **Multi-user / non-local clients** — peer auth for non-same-uid clients. Separate decision.

## 11. Resolved open questions

- **Per-adapter vs multiplexed socket:** one TUI socket to start; codec/relay are socket-count-agnostic; multiplex rides with Spec B.
- **Core-side gateway socket location:** a daemon-boot-independent `comms-core.sock` on the shared `alfred_run` volume, owned by the long-running core daemon service. G3 precondition.
