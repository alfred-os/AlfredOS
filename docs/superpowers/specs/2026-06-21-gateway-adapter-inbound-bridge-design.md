# Gateway-hosted-adapter inbound → core bridge (epic #309) — Design Spec

- **Date**: 2026-06-21
- **Epic**: #309 — the gateway-hosted-adapter inbound→core bridge (the Spec B / #288
  flag-day prerequisite)
- **Spec B parent**: `docs/superpowers/specs/2026-06-18-spec-b-adapter-inversion-design.md`
- **Status**: DRAFT for maintainer review (design-only; no implementation in this change)
- **Companion ADR**: `docs/adr/0039-gateway-adapter-inbound-bridge.md`
- **Relates to**: ADR-0031 (comms socket / leg), ADR-0032 (gateway resume transport +
  seq/ack codec), ADR-0033 (core-owned lifecycle epoch), ADR-0036 (gateway
  adapter-hosting inversion), ADR-0025 (comms stdio wire). Issue #288 (Spec B), #309
  (this epic), #235 (deferred persona-outbound), #230 (egress / Spec C).

> **The fork is DECIDED.** This spec designs **option 1** in depth: the gateway forwards a
> hosted adapter's inbound to the CORE over the ADR-0031 leg, and the CORE dispatches
> (identity-resolve → burst-limit → quarantined-extract → orchestrator). Options 2 and 3
> are recorded in §7 only to document *why* option 1, not to re-open the decision.

> **#309 is INBOUND-ONLY (DECIDED).** The spec-review confirmed (core + comms engineers,
> grounded in `plugins/alfred_discord/notifications.py` + `inbound_emitter.py`) that the
> child's `inbound.message` is a **fire-and-forget JSON-RPC notification with no id** — the
> child awaits nothing. The earlier hypothesis that a reverse "inbound ack" was needed to
> stop the child hanging is **factually wrong**: there is no inbound ack to deliver. The
> `core.adapter.outbound` reverse path is therefore **CUT from #309**; **all** outbound
> (including the daemon's fixed protocol ack, which is a *separate* host-initiated
> `outbound.message` request that lands a real platform send) is **deferred to #235**.
> #309 ships the inbound forward + the durable leg + the dispatched-edge delivery guarantee
> only.
>
> **Honest delivery guarantee (read this before "exactly-once").** The forwarded path is
> **exactly-once *once committed*; at-least-once on the dispatched edge**. There is no atomic
> commit↔dispatch: a crash between `dispatch` returning and the G0 commit becoming durable
> re-dispatches the frame (and, under the contiguous-ack model, its tail) on replay. The
> on-success steady state is exactly-once; the crash-window posture is
> at-least-once-with-idempotent-effect-where-possible (§3.5.2). Wherever this spec writes
> "exactly-once" unqualified, read it as this guarantee.

---

## 1. Goal

Make a **gateway-hosted comms adapter child** (the G6-5 substrate: a bwrap-spawned Discord
child supervised by `GatewayAdapterSupervisor`) deliver its inbound platform messages
through the **core's** trust-boundary dispatch pipeline — `process_inbound_message`
(identity-resolve → pre-resolution DoS gate → burst-limit → sub-payload-promote →
quarantined-extract → ingest → dispatch) — **without the gateway ever parsing, decrypting,
or dispatching the T3 body itself**.

This is the *missing inbound data path* of Spec B. The gateway already:

- spawns + supervises the sandbox adapter child (G6-2b / G6-5),
- delivers the platform credential fd-3 out-of-band over a core round-trip (G6-3),
- emits `gateway.adapter.*` lifecycle status to the core observer (G6-2b-2a),
- buffers + replays the **TUI dial-in** leg across a core restart (G5 / G6-4).

What it does **not** do: route the adapter child's *actual inbound messages* anywhere. The
G6-5 spawn substrate brings the child `up` and then has no wired inbound consumer — that is
the seam `_unwired_runner_factory` fails loud on (`src/alfred/gateway/process.py:209-228`).
This epic wires that seam under option 1.

Closing this epic makes the flag-day (delete the daemon-spawned Discord path + the
standalone Compose service) a *follow-on slice* rather than a same-PR change, and the
deferred G6-5 Tasks 11–15 (Compose-service delete, secret cutover, privileged real-spawn
proof) move under that follow-on slice (§9).

---

## 2. The gap (cited against `main`)

### 2.1 The gateway relay is OPAQUE transport-level — no session, no dispatch

- `GatewayRelay` (`src/alfred/gateway/relay.py`) joins two legs and forwards opaque
  payloads byte-for-byte in both directions. Its client→core pump
  (`_client_to_core_pump`, relay.py:205-279) does **ZERO body parse** (H3) and hands the
  opaque payload to `GatewayCoreLink.submit_tui_unit` (relay.py:279).
- `GatewayCoreLink` (`src/alfred/gateway/core_link.py`) drains legs onto the SINGLE
  physical writer `write_leg_unit` (core_link.py:1253-1304) carrying the per-leg seq + the
  core cumulative ack. The only method-peek in the whole gateway is the lifecycle router
  (`_route_unit`), which consumes the two `daemon.lifecycle.*` control frames; everything
  else is forwarded opaque (relay.py:30-35).
- The leg router (`src/alfred/gateway/leg_router.py:45-58`) routes an inbound envelope to
  the right per-leg scheduler queue on an **out-of-band** `adapter_id` — *route-only, no
  new core wire field* (leg_router.py:16-20, the **arch-M3** principle). The core re-derives
  `adapter_id` from the notification body itself; the gateway envelope `adapter_id` is
  purely local routing.

**So:** the relay/leg/scheduler machinery already carries opaque payloads with out-of-band
`adapter_id` routing, seq/ack, and resume. It has no notion of "an adapter's inbound."

### 2.2 The core's dispatch lives entirely core-side

- `process_inbound_message` (`src/alfred/comms_mcp/inbound.py:403-609`) is the single
  trust-boundary chokepoint: cheap-validate → promoter-required guard → **G0
  commit-once on `(adapter_id, inbound_id)`** (inbound.py:479-505) → pre-resolution DoS
  limiter → identity resolve → burst-limit → sub-payload promote → `quarantined_extract`
  (T3 hard-coded, inbound.py:584-588) → ingest → dispatch.
- It is driven by `InboundMessageHandler` (`src/alfred/comms_mcp/handlers.py:145-225`),
  fanned in by the session from `CommsPluginRunner._route_notification`
  (`src/alfred/plugins/comms_runner.py:790-864`) on the `inbound.message` method.
- The daemon's dispatch ORIGINATES a **separate host→plugin `outbound.message` request**
  via the late-bound `OutboundSenderLike` seam (`daemon_runtime.py:183-217`) — this is NOT
  a reply to the inbound notification; it is a new persona-direction that, on Discord,
  produces a real platform send (`server.py:97-128`). Rich persona-outbound (and this
  fixed-ack request itself) is the **#235** deferral — see §3.4.

### 2.3 The child's notifications are all fire-and-forget (the F4a fact-check)

The hosted Discord child emits **four** plugin→host JSON-RPC **notifications** (no id, no
reply awaited — `plugins/alfred_discord/notifications.py:1-8,31-34`):

- `inbound.message` — the platform message (`inbound_emitter.py:185-204`); emitted via
  `StdoutNotificationSink` and the child moves on. **It awaits nothing.**
- `adapter.crashed` — process-exit signal (covered by the supervisor + status leg, §3.1).
- `adapter.rate_limit_signal` — platform rate-limit notice (`rate_limit_emitter.py`).
- `adapter.binding_request` — first-contact binding mint (`binding_emitter.py`).

The only request/response on the child wire is the **opposite** direction: the daemon
ORIGINATES an `outbound.message` **request** the child answers with an
`OutboundMessageResult` (`server.py:97-128`). That request/result round-trip is rich
outbound — **#235**, not #309.

### 2.4 The G6-5 spawn substrate + the fail-loud seam this epic wires

- `GatewayAdapterChildFactory` (`src/alfred/gateway/adapter_child_factory.py:216-365`):
  the real bwrap spawn + fd-3 credential delivery + handshake. It takes a `runner_factory`
  closure (adapter_child_factory.py:225-232) that builds *some runner* over the child's
  stdio transport, and `await`s `runner.start_and_handshake()` (adapter_child_factory.py:276).
- `GatewayAdapterStdioTransport` (`adapter_stdio_transport.py`) wraps the child's
  `Popen` stdio.
- `GatewayAdapterSupervisor` (`adapter_supervisor.py:250-887`) drives spawn / crash /
  backoff / breaker, racing `child.wait_until_exit()` against a planned stop.
- `GatewayProcess._unwired_runner_factory` (`process.py:209-228`) is the **fail-loud seam**:
  it raises `GatewayAdapterSpawnError` because the standalone gateway "does NOT build the
  daemon boot graph (a full `AlfredPluginSession` + handlers + credential resolver)."

### 2.5 The architecture tension #309 resolves

The merged **G6-5 plan** (`docs/superpowers/plans/2026-06-21-g6-5-discord-flag-day.md`,
"real runner/transport build to REUSE" + FOUNDATION GAP #2) assumes the gateway-hosted
child runs a **session-bearing `CommsPluginRunner`** built from the daemon's
`_build_comms_runner` — i.e. the gateway runs the session and dispatches locally. **That is
option 2.** Under option 2 the gateway would need the orchestrator, the quarantined
extractor, the capability gate, the secret broker, and the audit DB — collapsing the
connectivity-free-core posture and concentrating trust in the always-up front door. Epic
\#309 **overrides** that assumption with option 1: the gateway forwards; the core dispatches.
This is precisely why #309 is the flag-day prerequisite — it re-shapes the runner-factory
seam *before* the flag-day deletes the daemon-spawn path.

---

## 3. Chosen design (option 1) — architecture

```
        platform                  gateway (privileged, payload-blind)                 core (daemon)
        ────────                  ──────────────────────────────────                 ────────────
                       fd-3 cred                                       ADR-0031 leg
   Discord  ──stdio──▶ adapter child ──▶ GatewayInboundForwardRunner ──┐  (seq/ack,
   inbound            (bwrap, kind=full)   (reads child stdio,         │   replay,
                                            forwards inbound opaque,   │   G0 dedup)
                                            pauses reader on leg-full) │
                                                                       ▼
                                          GatewayLeg(adapter_id) ──▶ GatewayCoreLink.write_leg_unit ──▶ daemon CommsPluginRunner (HOST)
                                                ▲   (per-leg buffer,                                      │  _route_notification
                                                │    seq, contig. ack)                                    ▼
                                          contiguous high-water     ◀──────────────────────────────── process_inbound_message
                                          advances ONLY past                                            (resolve→burst→quarantine
                                          DISPATCHED seqs (§3.5)                                         →ingest→dispatch)
```

The gateway stays a **T1 payload-blind carrier**. The opaque T3 body crosses to the core;
the credential never returns to the gateway; quarantine + capability-gate stay core-side.
**No reverse path** crosses core→gateway in #309 (the inbound is fire-and-forget; the leg
ack is the only feedback, and it rides the existing leg ack channel — §3.5).

### 3.1 The gateway-side runner-factory (sub-decision 1)

`_unwired_runner_factory` is replaced by a **`GatewayInboundForwardRunner`** (new module
`src/alfred/gateway/inbound_forward_runner.py`). It is a *session-LESS* runner: it satisfies
the factory's `_RunnerLike` Protocol (`start_and_handshake`) and the steady-state pump, but
its inbound handler does **NOT** dispatch — it **forwards**.

Interface (mirrors `CommsPluginRunner`'s public lifecycle so the supervisor + factory are
unchanged):

```python
class GatewayInboundForwardRunner:
    def __init__(
        self, *, transport: GatewayAdapterStdioTransport, adapter_id: str,
        forward: InboundForwardSink,            # core_link.forward_adapter_inbound (§3.3)
        boot_epoch_source: Callable[[], str | None],
        shutdown_event: asyncio.Event | None = None,
    ) -> None: ...
    async def start_and_handshake(self) -> None: ...   # host-side lifecycle.start to the CHILD
    async def pump(self) -> None: ...                  # single-reader read loop
    async def run(self) -> None: ...                   # start_and_handshake + pump
```

**Reuse the `CommsPluginRunner` read loop.** The child→host wire is unchanged ADR-0025: the
child is the **same Discord adapter** speaking the same `inbound.message` notification. So
the forward runner reuses the existing `CommsPluginRunner` single-reader pump *mechanics*
(`read_frame`, the in-flight task tracking, the malformed/crash/EOF arms, the
`_read_frame_or_shutdown` race) — but its `_route_notification` body is replaced. The
recommended realisation: **`CommsPluginRunner` grows an injectable inbound disposition**
(an `InboundDisposition` seam) with two implementations — the daemon's existing
session-dispatch (default), and the gateway's forward-only disposition — so the
single-reader/crash/teardown machinery is shared (DRY, one audited reader) and only the
inbound leaf differs. The forward runner is then a thin construction of `CommsPluginRunner`
with the forward disposition + no session collaborators.

> **F1 (factoring) — DECIDED: accept the injectable-disposition seam.** The core engineer
> confirmed `CommsPluginRunner`'s session entanglement is narrow (only three sites:
> `_route_notification` — the inbound leaf being factored — plus `_route_transport_crash`
> and `_request_restart`, both of which the gateway disposition does NOT use, since the
> supervisor owns crash detection). The read/correlation/teardown machinery is
> session-independent, so the extraction is clean and behaviour-preserving with the existing
> daemon dispatch as the default disposition. The exact mechanism (Protocol seam vs subclass)
> is an implementation detail for `alfred-comms-engineer` / `alfred-core-engineer`; the seam
> *shape* is the design commitment. **Constraint:** the gateway disposition MUST NOT drag the
> session-bound crash-synth / restart path into the gateway (it has no session).

**What it forwards (and what it does NOT).** On an `inbound.message` notification from the
child it forwards the **opaque body blob** + the out-of-band routing metadata (§3.2). It
does NOT: run identity resolution, burst limit, quarantine, sub-payload promotion, audit, or
the capability gate — all of those stay core-side.

**Disposition for ALL FOUR child notification types under gateway hosting.** An unhandled
method on the forward runner is undefined behaviour (silent drop = hard-rule-#7 violation,
or a pump crash), so each is given an EXPLICIT disposition:

| Child notification | #309 disposition | Rationale |
| --- | --- | --- |
| `inbound.message` | **Forward to core** (§3.2–§3.5). | The platform message; the whole point of the bridge. |
| `adapter.crashed` | **Gateway-local — supervisor + status leg.** The forward runner treats a transport crash / EOF exactly as `CommsPluginRunner` does (ends the pump; the supervisor's `wait_until_exit` crash arm fires); it does NOT synthesize a core-bound `adapter.crashed` (the `gateway.adapter.*` status leg already reports it, §6). | Crash is supervision, already wired. |
| `adapter.rate_limit_signal` | **Gateway-local LOUD drop + audited — a TEMPORARY capability gap.** Its core consumer (the `RateLimitSignal` handler) is a daemon-session collaborator the gateway does not run; forwarding it would need a #235-class consumer route that does not exist yet. The signal is **currently dropped** (with a named audit row `gateway.adapter.rate_limit_signal.dropped`); this is a known, tracked capability gap, not the end state — a future slice (the §10 follow-on) adds the core route. | No core route exists yet; never silent; tracked for restoration. |
| `adapter.binding_request` | **DEFER — gateway-local LOUD drop + audited.** Its receiver (`BindingRequestHandler`) is audit-only in Slice-4, the plugin emit path is **un-rate-limited** (a known #235 finding), and the host already mints+audits a binding request per unbound first-contact behind the pre-resolution limiter. Blind-forwarding it un-gated would be an **audit-write DoS amplifier**. Dropped with a named audit row (`gateway.adapter.binding_request.dropped`), tracked. | DoS-amplifier risk; correlation consumer is Slice-5. |

Any method the forward runner does not explicitly route is a **LOUD audited drop**, never a
silent skip and never a pump crash.

### 3.2 Payload-blindness on the forward (sub-decision 2)

The forward must keep the gateway from parsing the T3 body while still carrying enough
out-of-band metadata for the core to dispatch. The framing reuses the **existing two-channel
split** the gateway already has:

1. **The opaque T3 body** rides the **same payload-unit channel** the relay/leg/scheduler
   already drain (`write_leg_unit` → `send_payload_unit`, seq/ack-framed, ADR-0032). The
   body bytes are the child's `inbound.message` `params.body` blob, forwarded
   **byte-for-byte**. The gateway never `json.loads` it. **This is the key invariant:** the
   forwarded inbound is *just another opaque leg payload* — it gets seq/ack, the per-leg
   `ReplayBuffer`, and resume for free (§3.5).

2. **The out-of-band routing metadata** — `adapter_id` — must reach the core *without* the
   gateway reading the body. Two design constraints collide here:

   - The leg router already carries `adapter_id` out-of-band for **local routing** only
     (leg_router.py:16-20, arch-M3: "no new core wire field"); the core re-derives
     `adapter_id` from the body.
   - But the core's `process_inbound_message` needs `adapter_id` **and** `inbound_id` from
     the body for the G0 commit-once (inbound.py:480-483) — and under option 1 the body is
     opaque to the gateway, so the gateway cannot supply them, and the **core CAN** (the
     core re-parses the body it receives).

   **Resolution:** the forwarded inbound is wrapped in a thin **method-bearing envelope
   frame** — `gateway.adapter.inbound` — carrying ONLY the out-of-band routing `adapter_id`
   plus the **opaque body as an embedded bytes member the core (not the gateway) parses**.

   > **SEC-309-1 — HARD REQUIREMENT (not implementation discretion).** The gateway MUST mint
   > the envelope `adapter_id` from its **per-child SPAWN BINDING** — the supervisor's per-leg
   > `adapter_id` value the child was spawned under — and **NEVER** from any field read out of
   > the opaque body. The envelope==body equality check (§3.3) is **necessary but
   > insufficient alone**: if an implementation copies the body's `adapter_id` into the
   > envelope to make equality trivially pass, the check is vacuous and a compromised T3 child
   > can self-assert any registered kind. The real defense is the spawn-binding origin of the
   > envelope id. This mirrors `send_status_frame` (core_link.py:1306-1332) and
   > `request_spawn_grant` (core_link.py:1334+), which build method-bearing frames from
   > *supervision metadata*, not from a parsed T3 body. An adversarial **gateway-originate spy
   > test** (§6) MUST prove the envelope id provably comes from the spawn binding and the
   > gateway never reads `adapter_id` from the body.

   The `inbound_id` is **inside** the opaque body (it is adapter-minted opaque metadata,
   protocol.py:103-106) — the core extracts it on receipt. The gateway never needs it. This
   keeps the G0 dedup key `(adapter_id, inbound_id)` exactly as-is (§3.5).

   > **SEC-309-2 — replay byte-stability invariant.** The gateway's leg `ReplayBuffer` MUST
   > re-send the forwarded inbound's opaque body **byte-for-byte** on replay (never a
   > re-framed or re-encoded copy), so the embedded `inbound_id` is stable across replay and
   > G0 dedup on `(adapter_id, inbound_id)` is never a silent no-op. (The Discord child's
   > `inbound_id` is derived from the platform `message.id`, stable across the child's own
   > retries — protocol.py:111-116.) A perturbed body would defeat exactly-once and
   > double-dispatch the same T3 message past the trust boundary (a T3-replay-amplification:
   > double quarantine-extract + double ingest). Proven by an adversarial test (§6).

So the framing is: **method `gateway.adapter.inbound`** + **out-of-band `adapter_id`**
(gateway-supplied, **spawn-binding** metadata) + **opaque body** (gateway-blind,
core-parsed, **byte-stable across replay**). No T3 byte is ever interpreted by the gateway.

**Channel choice (F2 — DECIDED: the opaque payload-unit / leg channel).** Two carriers were
viable: (a) the method-bearing `send` channel (like `send_status_frame`), which is simplest
but does NOT get the per-leg `ReplayBuffer` / seq/ack resume (the status leg is explicitly
"observability, not durable-intake", core_link.py:1322); and (b) the opaque payload-unit
channel via a registered adapter `GatewayLeg`, which gets resume + G0 dedup. The design
**chooses (b)**: the forwarded inbound MUST be durable-intake (resume + exactly-once). The
envelope (method + adapter_id + opaque body) is the **payload** the leg buffers and the
scheduler drains. The adapter leg already exists (`build_adapter_leg`, registered via
`_register_adapter_legs`, process.py:313-332); this epic gives it *content*.

### 3.3 The core-side receive + dispatch path (sub-decision 3)

The daemon already runs a `CommsPluginRunner` as **HOST** over the gateway socket leg
(`_build_comms_runner` with `credential_resolver=True` + the `AdapterStatusObserver`
wired, `_commands.py:975-1015`, `1267-1322`). That runner's `_route_notification`
(comms_runner.py:790-864) already discriminates methods:

- `gateway.adapter.spawn_request` → credential resolver (comms_runner.py:820-822),
- `gateway.adapter.*` status → session → `AdapterStatusObserver` (via the prefix route),
- everything else → session dispatch.

**The discriminator for a forwarded-adapter-inbound is a NEW method:
`gateway.adapter.inbound`** (F3 — DECIDED below), routed in the same `_route_notification`
switch to a new **`forward → process_inbound_message`** arm:

- A **TUI dial-in frame** rides the leg as the opaque relayed payload carrying the
  operator's own `inbound.message` for the daemon's TUI session — method `inbound.message`.
- A **forwarded-adapter-inbound** carries the explicit method `gateway.adapter.inbound`.

So the discriminator is the **method name**, exactly as the status + credential frames are
discriminated today — NOT a fragile `adapter_id` heuristic.

> **F3 — DECIDED: new method `gateway.adapter.inbound` + core-validated envelope==body
> equality + core-side registered-leg admission.** The new method keeps the trust-boundary
> route explicit and audited and cannot be confused with a directly-connected adapter's
> `inbound.message`. The envelope `adapter_id` selects the dispatch route + the (now-cut)
> reverse target only; the body stays the sole authority for G0. To preserve
> body-authoritativeness AND close a forged-body/valid-leg mismatch the pre-309 arch-M3 left
> implicit, the core MUST, on the receive side:
>
> 1. **Validate the envelope `adapter_id` equals the body-derived `adapter_id`** — mismatch →
>    loud K4-style refusal (§ERR-309-3 disposition below).
> 2. **Mirror K4 registered-leg admission on the RECEIVE side** — refuse an envelope
>    `adapter_id` that is not a known/registered adapter the gateway is authorised to host
>    (not only the gateway *send* side). Note `adapter_id` is a **closed-vocab KIND**
>    (`"discord"`, `"tui"` — `protocol.py:_check_adapter_kind`), so a spoof = self-attributing
>    a *registered kind*; the registered-leg admission is what makes the closed vocabulary
>    load-bearing rather than decorative.
>
> This is a *strengthening* of arch-M3, not an erosion: the validated equality makes the
> envelope id non-authoritative while the body stays the sole G0 source. **Human-gated**
> (ADR-0039 is human-approved), but recorded as the decision, not an open question.

The new arm re-parses the opaque body it received into an `InboundMessageNotification`
(protocol.py:322+) — the same model the directly-connected adapter produces — and feeds the
*unchanged* `process_inbound_message`. The G0 commit-once, identity resolve, burst-limit,
quarantine, ingest, dispatch all run **exactly as today** — except for the dispatch-outcome
ack ordering the forwarded path requires (§3.5). No change to the dispatch pipeline logic;
only a new entry route and the leg-ack timing.

**CORE-309-2 / COMMS-309-2 — per-`adapter_id` core-side collaborator registry (NOT "feed the
unchanged pipeline").** The receive arm is NOT a bare `process_inbound_message` call. The
HOST runner that owns `_route_notification` is the **TUI/socket session** (built for the TUI
dial-in leg), but `process_inbound_message` is collaborator-parameterised and **fail-closes**
(`PromoterRequiredError`, inbound.py:452-465) when a forwarded body carries
`adapter_id="discord"` with no Discord `SubPayloadPromoter` wired. PR-S4-235-1 builds
per-adapter promoters keyed on `wire.adapter_kind`, but those are bound to the per-adapter
`InboundMessageHandler`, NOT to the TUI socket runner. So the receive slice MUST add a
**per-`adapter_id` core-side inbound-collaborator registry** — keyed on the **VALIDATED
envelope `adapter_id`** (after the §3.3 equality + registered-leg check) — that resolves
`adapter_id → {sub_payload_promoter, required-classifier expectations, identity_resolver,
rate-limiter, handler}` (the same collaborator set the daemon-spawned path used). Without it
a forwarded Discord inbound either fail-closes at the promoter guard or (worse) dispatches
with the wrong/no promoter, skipping sub-payload promotion before `quarantined_extract`
(hard rule #5). This is buildable but is **not "unchanged"** — it is an explicit obligation
of G6-7-4.

**ARCH-309-3 — malformed core-side re-parse disposition.** The core re-parses an opaque body
the gateway never validated (`InboundMessageNotification.model_validate`). A parse failure at
the core MUST be a **LOUD bounded-field audit drop** with a named closed-vocab row
(`gateway.adapter.inbound.malformed`), that **ACKs the leg frame to drain it** (so a
persistently-malformed forged frame is NOT replayed forever into an infinite loop), and is
caught by the HOST runner's err-007 catch-and-continue (comms_runner.py:856) so it **never
crashes the shared single-reader pump**. Never a silent drop, never a replay loop, never a
reader crash. An adversarial companion (§6, G6-7-7) proves it.

**Why this is safe:** the core was always the parser of the T3 body (the gateway is T1).
The forward simply *delivers the bytes the core would have read anyway* — over the leg
instead of over a daemon-spawned child's stdio.

### 3.4 Inbound-only: no reverse path in #309 (sub-decision 4)

**#309 ships NO reverse core→gateway→child path.** The spec-review fact-check (core + comms
engineers) is decisive:

- The child's `inbound.message` is a **fire-and-forget JSON-RPC notification with no id**
  (notifications.py:1-8,31-34; `inbound_emitter.py:185-204`). The child awaits nothing, so
  it **cannot hang / retry forever** on a missing reply. The earlier "child hangs without an
  inbound ack" justification (and the `_SEND_REQUEST_TIMEOUT_SECONDS` citation, which governs
  the *runner's own* `send_request`, not the child's notification emit) is **factually
  wrong**. There is **no inbound ack to deliver**.
- The daemon's fixed-shape `_FIXED_ACK` is **not** a reply to the inbound notification. It is
  a **separate host-initiated `outbound.message` request** (daemon_runtime.py:183-217) that
  the child answers with an `OutboundMessageResult` (server.py:97-128) and that, on Discord,
  produces a **real platform send**. Routing it core→gateway→child is therefore *itself*
  rich-outbound territory (it lands a platform message; the child's result half must route
  back) — **#235**, not a #309 inbound prerequisite.

**Decision (resolves F4 + F4a): #309 is inbound-only.** The `core.adapter.outbound` reverse
path, the gateway `_route_unit` outbound consume arm, and any reverse envelope model are
**CUT** from #309. **ALL** outbound — persona replies AND the daemon's fixed protocol ack —
is **deferred to #235**, where the outbound leg (`OutboundQueue`, DLP-scanned
`ScannedOutboundBody`, addressing-drift, the child-`OutboundMessageResult` return route) is
built coherently. The only feedback that crosses core→gateway in #309 is the **existing leg
ack** (the contiguous-seq high-water on the leg, §3.5) — not a new method-bearing frame.

This is the single largest scope reduction in the epic and removes its former "sharpest
call." The boundary is clean: **#309 = inbound forward + durable leg + the dispatched-edge
delivery guarantee; everything outbound = #235.**

> **Delivery guarantee, stated plainly (no unqualified "exactly-once").** The forwarded
> inbound path is **exactly-once *once committed*; at-least-once on the dispatched edge**.
> There is no atomic commit↔dispatch step, so a crash in the window between `dispatch`
> returning and the G0 commit becoming durable re-dispatches the frame **and its tail** on
> replay (§3.5 head-of-line amplification). On the steady (no-crash) path this collapses to
> exactly-once. The crash-window downstream posture is
> **at-least-once-with-idempotent-effect-where-possible** (§3.5.2). The mitigations that keep
> the window bounded and safe are (a) the poison ceiling + dead-letter (§3.5.1) and (b) G0
> dedup on the common (already-committed) path.

### 3.5 Resume + idempotency + the dispatch-outcome ack (sub-decision 5)

Because the forwarded inbound rides a **registered per-adapter `GatewayLeg`** (§3.2 choice
b), it inherits the Spec A/B resume machinery — **but the leg-ack semantics for the
forwarded path are REDESIGNED** to close a silent-loss window (ERR-309-1).

**The ERR-309-1 problem (CRITICAL).** On the *direct* (daemon-spawned) path,
`process_inbound_message` runs G0 `commit_once` AND records the seq into the contiguous-ack
tracker (`ack_tracker.observe(wire_seq)`, which advances `BoundedSeqAckTracker`'s
`_contiguous_high` once the run is unbroken) on the **commit==True** branch
(inbound.py:494-505) — **BEFORE** `quarantined_extract` (inbound.py:584), `ingest`
(inbound.py:601), and `dispatch` (inbound.py:609), all of which can raise. On that path the
recorded seq means "bytes received". That is fine for the daemon-spawned model (the child owns
re-delivery). But **#309 makes the LEG the durable-intake authority** and markets
resume + exactly-once as the Spec B win. If, on the forwarded path, a forwarded frame's seq is
`observe`d (entering the contiguous high-water) on *receipt* and a post-commit dispatch
failure (e.g. `quarantined_extract` raises) occurs:

- the contiguous high-water advances past the frame → the leg sees it as durably accepted →
  the `ReplayBuffer` trims it,
- the G0 row exists → any later replay is `commit==False` → short-circuits to
  `replay_observed` → **never dispatched**.

The inbound is **permanently lost while every signal says "accepted"** — the exact
silent-inbound-loss this epic must forbid. The "buffered in the leg for replay" fail-loud
story only covers *forward-side transport failure*, not *core-side dispatch failure*: the leg
buffer cannot save a frame whose seq has already entered the contiguous high-water.

**The decision (ack-means-DISPATCHED on the forwarded path).** For a **forwarded inbound**,
the durable-intake signal is the leg's **contiguous high-water** — the
`BoundedSeqAckTracker.cumulative_ack()` value (`_seq_tracker.py:43-97`), a single
CONTIGUOUS high-water emitted **periodically** as the core writes units back, **not** a
per-frame ack. The redesign moves the moment a forwarded frame's `wire_seq` becomes
**eligible to enter that contiguous high-water** — i.e. the moment the core calls
`ack_tracker.observe(wire_seq)` for the forwarded frame — to **AFTER the core has
successfully DISPATCHED**, never on receipt/commit. Precisely:

1. **Ordering.** On a `gateway.adapter.inbound` frame the core runs, in order:
   (i) structural refusals (cheap-validate, promoter-required, the §3.3 envelope==body
   equality + registered-leg admission) — these sit **ahead** of any G0/ack mutation and
   never consume an idempotency row (mirroring inbound.py:474-476);
   (ii) G0 `commit_once(adapter_id, inbound_id)`;
   (iii) identity resolve → burst-limit → sub-payload promote → `quarantined_extract` →
   ingest → **dispatch**;
   (iv) **only on dispatch success**, call `ack_tracker.observe(wire_seq)` so the frame's
   seq becomes eligible to advance the contiguous high-water. The G0 `commit` and the
   `ack_tracker.observe` MUST move **together** to this dispatch-success edge — on the
   forwarded path they are a single "dispatched" transition; splitting them (commit on
   receipt, observe on dispatch, or vice-versa) re-opens the ERR-309-1 silent-loss window and
   regresses the TUI path's receipt-time semantics into the forwarded path.
2. **Dispatch failure.** A failure at (iii) → the core **does NOT `observe(wire_seq)`**, so
   that seq never enters the contiguous high-water → the frame stays un-acked in the
   `ReplayBuffer` → the leg replays it on the next core reconnect → the core re-dispatches. A
   new closed-vocab LOUD audit row (`gateway.adapter.inbound.dispatch_failed`, distinct from
   `replay_observed`) is written.

   > **Head-of-line replay amplification (the honest consequence).** Because the high-water is
   > a single CONTIGUOUS value, an un-`observe`d (failed) seq **stalls the high-water at that
   > hole**: every later forwarded seq that DID dispatch successfully sits *above* the hole and
   > therefore **cannot** trim the gateway's `ReplayBuffer` either. On the next reconnect the
   > leg replays the failed seq **and its entire successfully-dispatched tail**. The tail is
   > re-delivered, re-parsed, and **G0-deduped** to `replay_observed` (so it is not
   > re-dispatched — exactly-once on the already-dispatched tail holds), but it IS
   > re-transmitted and re-parsed. This is the price of a contiguous-ack model with a
   > dispatched-edge gate; it is bounded by the poison ceiling (§3.5.1) so a deterministically
   > failing head cannot stall the high-water forever.
3. **G0 must NOT block the retry.** The committed-but-undispatched G0 row would otherwise
   dedup the replay to `replay_observed` and re-create the silent loss. Resolution
   (**DECIDED: option (a) — commit-reflects-dispatched for the forwarded path**): on the
   forwarded path the `(adapter_id, inbound_id)` commit is **only durable once dispatch has
   succeeded** — i.e. the commit moves to the *dispatched edge* for forwarded inbounds. A
   dispatch failure leaves **no committed row**, so the replayed frame is `commit==True`
   again and re-dispatches exactly once on success. (Mechanism — commit-after-dispatch vs a
   transactional commit+side-effects vs a compensating delete — is an implementation call for
   `alfred-core-engineer`; the **semantic** commitment is: *no committed-but-undispatched row
   may exist for a forwarded inbound that would dedup its own retry*.)
4. **The delivery guarantee, honestly.** A genuine double *physical* delivery of the same
   `(adapter_id, inbound_id)` (the resume case: un-acked frame replayed after a core bounce
   where the **first delivery DID dispatch AND the commit became durable**) still finds a
   committed row → short-circuits to exactly one `replay_observed` and re-runs nothing. So:
   dispatch-success-and-committed → future replays dedup; dispatch-failure → uncommitted →
   future replays re-dispatch. The honest statement is therefore **exactly-once *once
   committed*; at-least-once on the dispatched edge**: because commit↔dispatch is not atomic, a
   crash in the window between `dispatch` returning and the commit becoming durable leaves the
   frame un-acked AND uncommitted, so the replay re-dispatches it (and, under the contiguous-ack
   model, re-delivers its tail — §3.5 head-of-line). Never silent loss; never an unbounded
   replay (§3.5.1).

> **The existing TUI/daemon-local inbound semantics are UNCHANGED.** The receipt-time
> commit+ack ordering on `process_inbound_message`'s direct path (inbound.py:494-505) stays
> exactly as-is for the TUI dial-in leg and any daemon-spawned adapter. The
> dispatch-outcome ack + commit-after-dispatch is **specific to the forwarded
> (`gateway.adapter.inbound`) path** — the new entry route carries the new ordering; the
> shared pipeline body is untouched.

> **ARCH-RR-2 — the one-path-per-`adapter_id` invariant (load-bearing, pin it).** Two G0
> ack/commit semantics now coexist: **receipt-time** (the direct TUI / daemon-spawned path,
> unchanged) and **dispatched-edge** (the forwarded path). This dual-semantics design is safe
> **only because each `adapter_id` maps to exactly one leg / one entry route** — the closed-vocab
> kind `"tui"` is always the direct receipt-time path and a hosted kind like `"discord"` is
> always the forwarded dispatched-edge path; an `adapter_id` is **never** delivered over both at
> once. If a single `adapter_id`'s frames could arrive on both routes, the same
> `(adapter_id, inbound_id)` could be committed receipt-time on one and dispatched-edge on the
> other, and the two semantics would race the G0 row. The §3.3 registered-leg admission + the
> spawn-binding-minted envelope id enforce this one-route mapping; it is an explicit invariant,
> not an accident of current wiring.

#### 3.5.1 Bounding the failure-replay — the poison ceiling + dead-letter

The at-least-once-until-success loop above is, on its own, **unbounded in time**: a
deterministically-failing **poison** inbound (a T3 body whose `quarantined_extract` — a
provider call — or `ingest` raises every time, e.g. a malformed-but-parseable body the
extractor chokes on) re-runs the whole dispatch pipeline on **every reconnect**, with **no G0
row to dedup it** (it never committed), **no ceiling**, and it **stalls the contiguous
high-water** so its entire successfully-dispatched tail is re-delivered + re-parsed each round
too (§3.5 head-of-line). That is a self-inflicted replay-amplification DoS + an unbounded
provider-cost drain (SEC-309-4 / PERF-309-4 / ERR-309-5 / core tail-amplification).

**Decision — a dispatch-retry ceiling → terminal poison-sink, SYMMETRIC with the
malformed→ack-to-drain disposition (§3.3 / ARCH-309-3).** The core maintains a per-`(adapter_id,
inbound_id)` **dispatch-attempt counter** (durable enough to survive a core bounce, since the
poison frame survives via the leg). On each forwarded-path dispatch FAILURE:

1. **Charge the cost budget per attempt.** Each re-`quarantined_extract` attempt charges the
   inbound cost budget (the provider call is real work whether or not it succeeds), so a poison
   frame's replays cannot drain provider budget invisibly. The `dispatch_failed` audit row
   carries the attempt count.
2. **On exceeding the ceiling N** (a small bounded constant; the exact value is a tuning call
   for `alfred-core-engineer`), the frame is routed to a **terminal poison-sink / dead-letter**:
   a named, signed, closed-vocab LOUD audit row **`gateway.adapter.inbound.poisoned`**
   (distinct from `dispatch_failed` and `replay_observed`), AND the frame is
   **ack-to-drain**ed — the core calls `ack_tracker.observe(wire_seq)` for the poisoned frame
   **purely to release the contiguous high-water** (exactly as the malformed-body disposition
   acks to drain, §3.3). This stops the frame replaying forever AND un-stalls the high-water so
   its tail can finally trim. The poisoned body is NOT dispatched and NOT committed — it is
   terminally parked with a loud audit trail an operator can inspect.

This is fail-loud, not silent-drop: a poisoned inbound ends in a named dead-letter row, never
a quiet disappearance, and the replay loop + tail-amplification are hard-bounded by N. An
adversarial test (§6) proves the full cycle: a poison frame → bounded N attempts (each charged,
each writing a `dispatch_failed` row) → one `poisoned` dead-letter row → drained → the stalled
tail resumes.

#### 3.5.2 Crash-window idempotency posture (the disclosed double-dispatch window)

The dispatched-edge gate closes *core-side dispatch failure* loss, but it cannot make
commit↔dispatch atomic. The residual exposure is the **crash window**: `dispatch` returns
successfully, then the core crashes **before** the G0 commit (and the `ack_tracker.observe`)
become durable. On replay the frame is un-acked AND uncommitted → it **re-dispatches**, which
**re-runs `quarantined_extract` + `ingest`** for an inbound whose effects partly landed.

**Posture: at-least-once-with-idempotent-effect-where-possible.** #309 does not claim atomic
exactly-once across a crash; it claims the window is **real, bounded, and loudly mitigated**:

- **Bounded** — the same poison ceiling (§3.5.1) caps re-dispatch attempts, so even a frame
  that crashes the core mid-commit on every attempt terminates at the dead-letter, never loops
  forever.
- **Idempotent-effect-where-possible** — G0 on the **common path** (the crash is the rare case;
  most replays find a durable committed row and dedup to `replay_observed`) is the primary
  mitigation; downstream effects (ingest, persona dispatch) are expected to be idempotent or
  tolerant of a bounded replay where the platform/adapter semantics allow. Where an effect
  cannot be made idempotent, the bounded double-dispatch is the accepted, documented cost of
  the no-atomic-commit design — it is at-least-once, not exactly-once, on that edge.

The honest one-line summary: **a crash between dispatch-success and commit-durability
re-dispatches the frame (and its tail) once on replay; the poison ceiling + common-path G0 are
the mitigations; there is no silent loss.** Proven by a §6 test distinct from the
dispatch-failure test (a dispatch-SUCCESS-then-crash-before-commit replay).

The remaining resume machinery is inherited free:

- **Per-leg `ReplayBuffer`** (append-before-send, seq mint, TTL eviction, hard-ceiling
  drop) — the adapter leg already has one (process.py:325-332). An un-acked forwarded inbound
  is **replayed** on reconnect via `_flush_pending_replay` (core_link.py:573-662).
- **G0 exactly-once on `(adapter_id, inbound_id)`** dedups a *dispatched* replay by the
  composite of the **byte-stable in-body `inbound_id`** (SEC-309-2) and the **out-of-band
  `adapter_id`**.
- **Independent buffers + binding caps.** The adapter leg's `ReplayBuffer` is independent of
  the TUI leg's (global cap K2 bounds the sum, process.py:457-459); a forwarded-inbound flood
  is bounded by the adapter leg's BINDING ingress caps (the G6-4 ingress gate,
  process.py:389-420), so the adapter leg is *more* constrained than the non-binding TUI leg —
  correct for an adversary-facing platform.

One ordering note (minor): the forward runner reads child stdio **concurrently** (the pump
dispatches notifications as in-flight tasks, comms_runner.py:586-604), but the leg enforces a
single drain + seq order, and the core's G0 + per-message independence (inbound.py:494-505,
"strict in-order is NOT required") tolerate out-of-order delivery. No new ordering guarantee
is needed.

### 3.6 Back-pressure on leg-full (sub-decision 6)

**PERF-309-1 — the load-bearing back-pressure seam.** The forward runner's reaction to a
`LegQueueFullError` (per-leg send-queue full, `leg_scheduler.py`) or a `ReplayBufferError`
global-cap-full is **specified**, because "buffered for replay" does NOT apply when the frame
is **not accepted** (queue-full = rejected). The three bad defaults — silent drop
(hard-rule-#7 violation), swallow-and-retry-spin (busy loop), or let-the-exception-kill-the-pump
(adapter outage on transient core slowness) — are all forbidden.

**Decision.** On leg-full / cap-full, the forward runner **PAUSES its child-stdio read loop**
(does not drop, does not spin, does not die) until the scheduler drains, mirroring the
relay's stop-draining-upstream / read-halt discipline (relay.py / leg_scheduler.py:56-62).
The bwrap child's stdout OS buffer fills, and the platform adapter naturally slows — so
back-pressure propagates child→gateway→core as **bounded buffering**, the Spec B promise. The
child-stdio reader already exists (`adapter_stdio_transport.py`, bounded readline); the
missing piece is wiring forward-sink-full → pause-the-reader. (Exact pause mechanism is an
implementation call for `alfred-comms-engineer` / `alfred-core-engineer` on the F1 seam; the
back-pressure **contract** belongs here.)

### 3.7 Trust-boundary invariants preserved (sub-decision 7)

| Invariant | How #309 preserves it |
| --- | --- |
| Gateway payload-blind (hard rule #5) | The gateway forwards the T3 body opaque; the only method-peek stays the lifecycle router; `adapter_id` is gateway-supplied **spawn-binding** metadata, never read from the body (SEC-309-1). |
| Quarantine stays core-side (hard rule #5) | `quarantined_extract` runs in `process_inbound_message` on the core, on the body the core re-parses. The gateway has no extractor. |
| Capability gate stays core-side | Unchanged — it gates the core's plugin loads, not the forward. The gateway runs no session/gate for the forwarded inbound. |
| Credential never returns to the gateway (hard rule #6) | The credential flows core→gateway→child fd-3 (G6-3) on spawn only; the inbound forward carries no credential, and there is no reverse path in #309. |
| Fail-loud, no silent drop / no silent loss (hard rule #7) | A forward-transport failure is a LOUD drop leaving the frame buffered for replay (leg append-before-send, core_link.py:42-44); a **core dispatch failure leaves the frame UN-acked → replayed → re-dispatched** with a `dispatch_failed` audit row (§3.5, ERR-309-1); a **deterministically-failing (poison) frame is bounded by the dispatch-retry ceiling → terminal `poisoned` dead-letter row + ack-to-drain** (§3.5.1, never an unbounded replay or provider-cost drain); a leg-full halts the reader (§3.6); a forge mismatch / malformed body is a loud bounded-field audit drop (§3.3). No path silently loses an inbound and no path replays forever. |
| Dual-LLM split (PRD §7.1) | Untouched — the privileged orchestrator still never sees raw T3; only the core's quarantined extractor does. |

---

## 4. Component inventory (what changes)

| Component | Change |
| --- | --- |
| `src/alfred/gateway/inbound_forward_runner.py` (NEW) | `GatewayInboundForwardRunner` — session-less runner; forwards `inbound.message` opaque to the leg; explicit disposition for all four child notifications (§3.1); pauses the reader on leg-full (§3.6). **Trust-boundary module → both ci.yml per-file 100% gates.** |
| `src/alfred/plugins/comms_runner.py` | Add an injectable inbound disposition seam so the single-reader pump is shared (F1); the existing session-dispatch becomes the default disposition (behaviour-preserving). |
| `src/alfred/gateway/process.py` | Replace `_unwired_runner_factory` with a forward-runner factory bound to `core_link.forward_adapter_inbound` + the per-adapter leg. |
| `src/alfred/gateway/core_link.py` | `forward_adapter_inbound(adapter_id, body)` — builds the `gateway.adapter.inbound` envelope (adapter_id from spawn binding) onto the adapter leg. **No reverse `core.adapter.outbound` arm in #309.** |
| `src/alfred/gateway/leg_router.py` / scheduler | No change — the adapter leg + router already route on out-of-band `adapter_id`. |
| `src/alfred/comms_mcp/protocol.py` | The `gateway.adapter.inbound` envelope model (method + out-of-band `adapter_id` + opaque body member). **No reverse-outbound model in #309.** |
| daemon HOST runner disposition + **per-`adapter_id` core-side collaborator registry** (NEW, core-side) | New `gateway.adapter.inbound` route → envelope==body + registered-leg validation → per-adapter collaborator selection → `process_inbound_message` with the **dispatch-outcome ack** ordering (§3.5). **Trust-boundary module → both ci.yml per-file 100% gates.** |
| Audit | New closed-vocab rows: `gateway.adapter.inbound.forward_accepted`, `…forward_dropped` (gateway-side, honest structlog mirroring `_audit_awaiting_core`); `gateway.adapter.inbound.forge_refused`, `…malformed`, `…dispatch_failed` (carries the attempt count), `…poisoned` (the terminal dead-letter on exceeding the dispatch-retry ceiling, §3.5.1) (core-side, signed); `gateway.adapter.rate_limit_signal.dropped`, `gateway.adapter.binding_request.dropped` (gateway-side, §3.1). The dispatch-success / `replay_observed` rows are the existing `process_inbound_message` set. |
| i18n | New operator strings via `t()` + reserve in `_spec_b_reserve.py`. |

---

## 5. Decomposition into sub-slices (G-numbers + dependency order)

> **Banner: G6-7 (NEW Spec-B sub-epic, the inbound bridge).** The merged G6-5 plan already
> assigns **G6-6** to a *different* sibling scope — the full adversarial-restart corpus +
> the `adversarial.yml`-to-required promotion (`g6-5-discord-flag-day.md:36`). To avoid the
> collision this epic's sub-slices are numbered **G6-7-1…N**; the pre-existing G6-6
> (adversarial corpus) remains a separate sibling under its own owner.

Critical path top-to-bottom:

- **G6-7-1 — inbound-forward envelope model + core re-parse seam.**
  The `gateway.adapter.inbound` Pydantic envelope model (protocol.py) + a pure
  `body → InboundMessageNotification` re-parse helper. **No reverse-outbound model** (cut per
  §3.4). No wiring. Pure + unit-testable. *(no deps)*
- **G6-7-2 — `CommsPluginRunner` inbound-disposition seam (F1).**
  Refactor the single-reader pump to take an injectable inbound disposition; the existing
  session-dispatch becomes the default disposition (behaviour-preserving; gated by a test
  asserting the daemon stdio path is byte-for-byte unchanged). *(dep: none; enables 3)*
- **G6-7-3 — `GatewayInboundForwardRunner` + the gateway forward path.**
  The session-less forward runner (over the G6-7-2 seam) + `core_link.forward_adapter_inbound`
  building the envelope (adapter_id from the **spawn binding**, SEC-309-1) onto the per-adapter
  leg; the four-notification disposition table (§3.1); the leg-full reader-pause (§3.6).
  Replaces `_unwired_runner_factory`. Unit + in-process (non-root) leg-forward test +
  gateway-originate spy (envelope id from spawn binding, not body). *(deps: 1, 2)*
- **G6-7-4 — core-side receive route → `process_inbound_message`.**
  The daemon HOST runner's `gateway.adapter.inbound` arm: envelope==body equality +
  registered-leg admission (§3.3 F3) → the **per-`adapter_id` core-side collaborator
  registry** (CORE-309-2 / COMMS-309-2) → the unchanged dispatch with the **dispatch-outcome
  ack** ordering (§3.5). In-process test: a forwarded envelope drives
  identity-resolve→promote→quarantine→ingest→dispatch on a fake orchestrator with the Discord
  promoter; the forge-mismatch + malformed-body refusals fire loud. *(deps: 1; pairs with 3)*
- **G6-7-5 — resume + dispatched-edge guarantee + the poison bound over the adapter leg.**
  In-process restart-survival proof using the dispatched-edge ack: (a) a forwarded inbound
  whose dispatch SUCCEEDS **and commits**, then a genuine double physical delivery across a core
  bounce, dedups to one dispatch + one `replay_observed`; (b) a forwarded inbound whose
  `quarantined_extract` RAISES leaves the frame un-acked + uncommitted, the core bounces, the
  replay **re-dispatches** (no silent loss), with a `dispatch_failed` row on the first attempt;
  (c) the **poison bound** (§3.5.1) — a deterministically-failing frame stops at N attempts →
  `poisoned` dead-letter + ack-to-drain → tail resumes; (d) the **crash-window** (§3.5.2) — a
  dispatch-SUCCESS-then-crash-before-commit replay re-dispatches once (bounded, not a loop).
  Reuses the K7 / `_gateway_restart_harness` pattern with the forward leg. *(deps: 3, 4)*
- **G6-7-6 — end-to-end non-root happy path + adversarial in-process companions.**
  Forward-runner ⇄ core dispatch with a fake child; the SEC-309-1 binding spy + the F3
  forge-MISMATCH refusal + the unregistered-adapter refusal + the SEC-309-2 byte-stability +
  the malformed-envelope drain + payload-blindness spy (no `json.loads` of the body in the
  gateway). *(deps: all above)*

**Closing sub-slices — the flag-day + real-spawn proof (moved from G6-5 Tasks 11–15):**

- **G6-7-7 — privileged real-spawn inbound e2e.**
  The bwrap Discord child spawned by the gateway, a real inbound forwarded over the leg,
  `process_inbound_message` dispatched on the core. On the `integration-privileged` lane
  (mirrors `test_daemon_comms_flip_real_spawn.py`), with a non-root companion for the wire
  contract (#245 paper-gate rule). **Lane honesty (TE-309-1):** `integration-privileged` is
  currently **PENDING-required** (`docs/ci/required-checks.md` §Pending), so the **gating
  property lives on the non-root in-process companions until the lane is promoted**.
  **G6-7-7's done-definition INCLUDES** promoting `integration-privileged` to a
  currently-required check (`gh api POST …/contexts`) and moving the `required-checks.md` row,
  OR the flag-day gate (G6-7-8) must name a check that is actually required. The real-spawn
  test MUST assert its preconditions (`euid==0`, bwrap present, `ALFRED_QUARANTINE_CHILD_PYTHON`
  provisioned) so it **fails loud rather than skips**.
- **G6-7-8 — flag-day: delete the daemon-spawned Discord path + Compose service + secret
  cutover.** The deferred G6-5 Tasks 11–15: core-vault `discord_bot_token` mount precedes the
  service delete (GAP-4); delete the standalone `alfred-discord` service + bind-mount; source
  `adapter_ids` from `settings.comms_enabled_adapters`; the `alfred gateway adapters
  --wait-ready` CLI; runbook + compose-invariant + ADR-0036 annotation. *(dep: G6-7-7 green +
  the privileged lane actually required)*

> The flag-day (G6-7-8) is a **follow-on slice gated on G6-7-7 green** (with the lane
> promoted to currently-required) — exactly the sequencing the epic brief requires: the
> bridge lands first, the delete follows.

---

## 6. Testing strategy

- **Unit:** the envelope model (round-trip, reject malformed); the `body → notification`
  re-parse; the forward runner's forward-not-dispatch behaviour (it calls the forward sink,
  never an orchestrator); the four-notification disposition (each unhandled-but-known method
  is a loud audited drop, never silent); the leg-full reader-pause.
- **In-process / non-root (the GATING layer until the privileged lane is promoted):**
  forward-runner reads a fake child's `inbound.message` → envelope on the leg → daemon route →
  per-adapter collaborator selection → `process_inbound_message` on a fake orchestrator
  (assert resolve→promote→quarantine→ingest→dispatch order, with the Discord promoter so the
  promoter-required guard does NOT trip); the **dispatched-edge ack** (the seq is `observe`d —
  becoming eligible for the contiguous high-water — only on dispatch success); resume replay +
  G0 dedup. **Every wire contract the privileged lane proves has a non-root companion (the #245
  lesson).**
- **Back-pressure pause → drain → RESUME (non-root):** drive the forward runner against a
  leg-full / cap-full sink, assert it **pauses** the child-stdio read loop (no drop, no spin,
  no death, §3.6); then drain the scheduler and assert the reader **RESUMES** and the held
  inbound is forwarded. A pause with no resume is a silent stall (a #7-shape hazard), so the
  resume leg is asserted explicitly, not just the pause entry.
- **Privileged real-spawn e2e (`integration-privileged`, PENDING-required → promoted in
  G6-7-7):** the real bwrap Discord child, real inbound forwarded, real core dispatch.
  Non-vacuity: a real sentinel inbound arrives at `process_inbound_message`; the credential is
  ABSENT from `/proc/<pid>/environ` (G6-3 invariant unbroken by the forward). The test asserts
  `euid==0` + bwrap-present + `ALFRED_QUARANTINE_CHILD_PYTHON` provisioned so it **fails loud,
  not skips**.
- **Adversarial** (extend `tests/adversarial/comms/`):
  - **SEC-309-1 binding spy:** the envelope `adapter_id` provably comes from the spawn binding;
    the gateway never reads `adapter_id` from the body (extend the H3 `json.loads` spy).
  - **F3 forge-MISMATCH:** a `gateway.adapter.inbound` envelope whose out-of-band `adapter_id`
    != the body-derived `adapter_id` is a LOUD K4-style refusal with a closed-vocab signed
    audit row, NO dispatch, and (proven separately) **does not advance the leg ack and does
    not consume a G0 row** (the forge refusal sits ahead of commit, §3.3/§3.5). Pattern from
    `test_gateway_ready_epoch_forgery.py`.
  - **Unregistered-adapter:** a forged envelope naming an adapter the gateway is not
    registered to host is K4-refused loud (separate negative from the mismatch).
  - **SEC-309-2 byte-stability + genuine double-delivery (exactly-once):** force a SECOND
    physical delivery of one `(adapter_id, inbound_id)` across a core bounce (un-acked frame →
    `ReplayBuffer` → reconnect → re-deliver the SAME opaque body) and assert dispatch count
    == 1, exactly one `replay_observed` row, and the SAME re-parsed `inbound_id` — NOT a
    send-once/see-once tautology.
  - **ERR-309-1 dispatch-failure restart-survival:** forward an inbound, make
    `quarantined_extract` RAISE, restart the core, assert the inbound IS re-dispatched (or
    loudly quarantined) and is **never silently swallowed**; a `dispatch_failed` row exists on
    the first attempt and is distinct from `replay_observed`.
  - **SEC-309-4 / PERF-309-4 / ERR-309-5 poison-bound:** a deterministically-failing (poison)
    forwarded inbound is re-dispatched at most **N** times (each attempt charges the cost budget
    and writes a `dispatch_failed` row carrying the attempt count), then on exceeding the
    ceiling is routed to the **terminal `poisoned` dead-letter row + ack-to-drain**ed; assert
    the replay loop STOPS (attempt count ceases growing), the stalled contiguous high-water is
    released, and the poison frame's previously-blocked successfully-dispatched **tail resumes**
    (one `replay_observed` per tail frame, not re-dispatched). This is the symmetric companion
    to the malformed→ack-to-drain test.
  - **ERR-309-5 crash-window double-dispatch (distinct from the dispatch-FAILURE test):**
    forward an inbound whose dispatch **SUCCEEDS**, then crash the core **before the G0 commit /
    `observe` becomes durable**; restart and assert the replay **re-dispatches** the frame
    (proving the at-least-once-on-the-dispatched-edge window is real **and bounded** — it
    terminates, it does not loop), with the re-dispatch re-running quarantine-extract + ingest.
    This is the crash-window posture (§3.5.2), separate from the dispatch-failure-then-replay
    case above.
  - **Malformed-envelope:** a malformed forwarded body is a loud bounded-field audit drop that
    drains the leg frame (no infinite replay) and does not crash the reader.
- **Coverage gates (TE strength + ask):** the new trust-boundary modules
  (`inbound_forward_runner.py` and the core-side disposition + collaborator registry) MUST be
  added to **all four** ci.yml per-file 100% edit points — the python-job `hashFiles` guard
  AND the `coverage-gates --include=` list — mirroring every `gateway/*.py` (cf.
  `_bootstrap_grants.py`).

---

## 7. Alternatives considered (why option 1)

### Option 2 — gateway runs the session (the G6-5 plan's latent assumption)

The gateway builds a full session-bearing `CommsPluginRunner` (the daemon's
`_build_comms_runner`) and dispatches the inbound locally: identity-resolve, burst-limit,
quarantine, capability-gate, audit — all in the gateway.
**Rejected:** it would require the always-up, network-facing, *privileged* (SETUID, bwrap-
host) gateway to hold the orchestrator, the quarantined extractor, the secret broker, the
capability gate, and the audit DB. That **collapses the connectivity-free-core posture**
(ADR-0036: "the core observes; the gateway hosts"), concentrates the highest-value trust
surface in the most-exposed process, and would put raw T3 dispatch behind the front door. It
is the exact inversion ADR-0036's "core never commands; core observes" intends to *prevent*
for data, not just lifecycle.

### Option 3 — RPC (gateway calls a core dispatch RPC per inbound)

A request/response RPC: the gateway sends each inbound and awaits a structured core
dispatch result.
**Rejected:** (a) it does not naturally inherit the leg's `ReplayBuffer` / seq-ack / G0
exactly-once — resume would need re-building on the RPC layer (the Spec B goal is *free*
resume via the leg); (b) a synchronous per-inbound RPC couples the gateway's inbound liveness
to a live core (a core gap would block/queue inbounds in the gateway with no durable buffer),
which is precisely the fragility Spec B's buffered leg removes; (c) it adds a second
core-facing control surface alongside the existing leg, contradicting "the gateway is the
single chokepoint with one core leg." Option 1's "forward as an opaque leg payload" gets
resume + exactly-once + payload-blindness from machinery that already exists and is already
adversarially tested.

**Why option 1:** it keeps the trust boundary where ADR-0036 / the PRD put it (quarantine +
gate + dispatch core-side; gateway T1 payload-blind), and it reuses the leg's resume + G0 +
seq/ack so a hosted adapter's inbound gets the **dispatched-edge delivery guarantee**
(exactly-once once committed; at-least-once on the dispatched edge — §3.5) across a core
restart with the least new trust-bearing code.

---

## 8. Trust-boundary analysis — what crosses where

- **Crosses gateway → core (over the ADR-0031 leg):** the opaque T3 body (gateway-blind,
  byte-stable across replay — SEC-309-2) + the out-of-band `adapter_id` (gateway
  **spawn-binding** metadata, never read from the body — SEC-309-1). Seq/ack-framed,
  buffered, replayable.
- **Crosses core → gateway:** ONLY the existing leg ack (contiguous-seq high-water), which
  on the forwarded path advances **only after dispatch success** (§3.5). **No new
  method-bearing reverse frame** in #309; all outbound is #235.
- **Stays core-side (never crosses to the gateway):** identity resolution, the canonical
  `user_id`, the per-`adapter_id` collaborator registry, burst-limit state, sub-payload
  promotion, the quarantined extractor + T3 content interpretation, the capability gate, the
  secret broker, the signed audit DB, the orchestrator/persona dispatch.
- **Stays gateway-side:** the child process supervision (spawn/crash/backoff/breaker), the
  fd-3 credential delivery (transient), the per-leg buffer + resume, the payload-blind
  forward, the four-notification disposition + the leg-full reader-pause.

**The arch-M3 widening (resolved, no longer an open question).** The leg router's
"route-only, no new core wire field" principle (leg_router.py:16-20) says the gateway
`adapter_id` is *local routing only* and the core re-derives `adapter_id` from the body.
Option 1's `gateway.adapter.inbound` envelope carries `adapter_id` **to the core** as the
dispatch route discriminator. This is a *strengthening*, not an erosion (ARCH-309-1): the
core still re-parses the body for the authoritative `adapter_id` + `inbound_id` (G0 source);
the envelope `adapter_id` is used only to **select the dispatch route + the collaborator
set**; and the core validates **envelope == body-derived** AND **registered-leg admission**
(§3.3 F3), so the body stays sole authority while a forged-body/valid-leg mismatch — which
pre-309 arch-M3 left implicit — is now closed loud. The minted envelope id originates from
the **spawn binding** (SEC-309-1), so a compromised child cannot self-route.

**The one-path-per-`adapter_id` invariant (ARCH-RR-2).** The two coexisting G0 ack/commit
semantics — receipt-time (direct TUI/daemon-spawned) and dispatched-edge (forwarded, §3.5) —
are safe **only because each `adapter_id` maps to exactly one leg / one entry route** (the
closed-vocab kind `"tui"` always the direct path, a hosted kind like `"discord"` always the
forwarded path; never both for one id). This is what stops the same `(adapter_id, inbound_id)`
being committed under both semantics and racing the G0 row; it is enforced by the
registered-leg admission (§3.3 F3) + the spawn-binding-minted envelope id, and pinned here as
an explicit invariant rather than an accident of current wiring.

---

## 9. Flag-day enablement (closing the epic)

Once the bridge (G6-7-1..6) + the privileged real-spawn proof (G6-7-7, with the
`integration-privileged` lane promoted to currently-required) are green, the gateway hosts +
forwards a real Discord inbound end-to-end. The **flag-day** (G6-7-8) then becomes a clean
follow-on slice: delete the daemon-spawned Discord path + the standalone `alfred-discord`
Compose service + the `secrets.toml` bind-mount, cut the `discord_bot_token` over to the core
vault (GAP-4: the core mount ADD precedes the service delete), source `adapter_ids` from
`settings.comms_enabled_adapters`, and ship the `alfred gateway adapters --wait-ready` verify
command + runbook. **The deferred G6-5 Tasks 11–15 (Compose delete, secret cutover,
privileged real-spawn proof, restart-survival, the adversarial real-child realization) move
under G6-7-7 / G6-7-8.**

---

## 10. Resolved decisions (formerly open flags) + tracked follow-ups

All four prior maintainer-steer flags are now **resolved as stated decisions** (ADR-0039 is
human-gated; these record the recommended resolution, not open questions):

- **F1 (runner factoring) — DECIDED:** the injectable inbound-disposition seam, with the
  daemon dispatch as the behaviour-preserving default; the gateway disposition carries no
  session and no crash-synth/restart path (§3.1). Clean per the core engineer.
- **F2 (carrier) — DECIDED:** the opaque payload-unit / leg channel (for resume + G0), not
  the status `send` channel (§3.2).
- **F3 (route discriminator) — DECIDED:** new method `gateway.adapter.inbound` + core-side
  envelope==body equality + registered-leg admission, with the envelope id minted from the
  spawn binding (§3.3, SEC-309-1). A strengthening of arch-M3 (§8, ARCH-309-1).
- **F4 / F4a (ack scope) — DECIDED:** #309 is **inbound-only**; the child's `inbound.message`
  is fire-and-forget; the reverse path is **cut**; all outbound (incl. the fixed protocol
  ack) is **#235** (§3.4).

**Tracked follow-ups (not #309 scope):**

- **PERF-309-3 (interactive-leg fairness at adapter scale).** Once adapter legs carry real
  inbound, the single physical core writer's round-robin (one frame per non-empty leg per
  round, TUI first) makes interactive-leg latency **O(N_busy_adapter_legs)** — the TUI's
  reserved credit is first-frame-per-round, not bandwidth-proportional. No redesign for the
  bridge; the lever is **weighted TUI scheduler credit** (more than one frame/round) — a
  scheduler-local change, no wire impact. Tracked for `alfred-core-engineer` (leg-scheduler
  owner) when multi-adapter scale is real.
- **`adapter.rate_limit_signal` / `adapter.binding_request` core routes.** Dropped-loud
  gateway-local in #309 (§3.1) — `rate_limit_signal` is a **temporary capability gap** (the
  signal is currently dropped); a core consumer route (and, for binding_request, the
  host-side rate gate + Slice-5 correlation consumer the #235 finding requires) is a separate
  follow-on.
- **Edit-coalescing × dispatched-edge G0 (small open item).** Where a platform produces an
  edit/update of an already-delivered message (Discord message edits), an adapter that coalesces
  edits onto the same `inbound_id` would, under the dispatched-edge G0, dedup the edit to
  `replay_observed` (the original already committed) — so the edited content would not
  re-dispatch. This is consistent with the daemon-spawned path's existing G0 behaviour (no
  regression), but the desired end-state semantics for edits over the forwarded path
  (re-dispatch the edit vs treat-as-replay) are an open question to settle alongside the #235
  outbound/threading work. Noted, not designed in #309.

---

## 11. Self-review

- **Placeholder scan:** no TODO/TBD/`<...>`/lorem; all citations are concrete `file:line`.
- **Inbound-only consistency:** the reverse path is cut everywhere — §3 diagram (no
  core→child arrow), §3.4 (decision), §3.7 (no reverse credential row), §4 (no reverse model
  / no `core.adapter.outbound` arm), §5 (no reverse sub-slice; G6-7-5 is resume + poison-bound,
  not a reverse-ack), §8 (core→gateway is contiguous-high-water only), §10 (F4/F4a decided). No
  residual mention of a #309 reverse frame.
- **G-number uniformity:** the banner is **G6-7**; every sub-slice is G6-7-1…8 in §5, §6, §9;
  the §5 reconciliation note records that the pre-existing G6-6 (adversarial corpus) is a
  separate sibling. No stray G6-6 references to this epic.
- **Ack model uniformity:** the durable-intake signal reads as the **contiguous high-water**
  (`BoundedSeqAckTracker.cumulative_ack()` / `observe(wire_seq)`) **everywhere** — §3 diagram,
  §3.5 ordering + head-of-line disclosure, §6 in-process test, §8 trust-boundary table. No
  residual "advance the ack for this frame's `wire_seq`" per-frame phrasing.
- **No unqualified "exactly-once":** the banner (§ banner) + §3.4 + §3.5 state the **honest
  guarantee** (exactly-once once committed; at-least-once on the dispatched edge); every other
  "exactly-once" is a qualified property name (the G0 dedup primitive, the already-dispatched
  tail, the Spec-B goal label) read against that banner. No unqualified delivery claim remains
  at the banner/§1/§3.4/§7-closing.
- **Internal consistency:** §3.2 chooses carrier (b) = the leg; §3.5 + §5 + §6 + §8 all
  assume the per-adapter leg; the discriminator (§3.3) = the new method, consistent with §8 +
  §10; the dispatched-edge ack + commit-move-together (§3.5) is consistent with the ERR-309-1
  fix, the poison bound (§3.5.1), the crash-window posture (§3.5.2), the ARCH-RR-2 one-route
  invariant (§3.5), §3.7 fail-loud row, §4 audit rows, and the G6-7-5 tests; the collaborator
  registry (§3.3) is consistent with §4 + G6-7-4.
- **Scope:** designs option 1 only; options 2/3 are §7 rationale; no fork redesign; no
  implementation code; flag-day + real-spawn are the closing sub-slices, not the bridge; the
  poison ceiling + crash-window + back-pressure-resume are bounding refinements of the chosen
  design, not new architecture.
- **Ambiguity:** no open maintainer-steer flags remain (all four resolved, §10); the
  remaining engineer-discretion points (F1 mechanism, the §3.5 commit-after-dispatch
  mechanism, the poison ceiling **N** value) are explicitly scoped to writing-plans with the
  semantic commitment pinned.
- **PRD vocabulary:** trust tier (T1/T3), quarantined extractor, capability gate, secret
  broker, payload-blind, connectivity-free core, dual-LLM split (PRD §7.1), reviewer-gate-
  adjacent audit rows — all used per the PRD/ADR-0036 vocabulary.
