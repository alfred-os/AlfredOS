# ADR-0032 — The comms-resume gateway transport carries an out-of-band seq/ack header

- **Status**: Proposed (first cut — codec / wire-format only; G3/G4 amend)
- **Date**: 2026-06-13
- **Slice**: Spec A (Comms-Resume Gateway) — `docs/superpowers/specs/2026-06-13-comms-gateway-resume-design.md`
- **Relates to**: ADR-0025 (the line-delimited comms transport this extends), ADR-0031 (the TUI socket carrier), ADR-0033 (core lifecycle signalling / epoch, G1), issue #237 (graduation criterion #7).
- **Supersedes**: —

## Context

The comms-resume gateway (Spec A) fronts dial-in clients with a resumable, payload-blind wire so a core restart never drops the operator or loses in-flight input. The ADR-0025 wire is a thin line-delimited JSON-RPC frame (`json.dumps(frame) + "\n"`) with a per-frame DoS bound (`_MAX_COMMS_LINE_BYTES`) and no notion of sequence, acknowledgement, or replay-dedup. Buffer-and-replay across a restart (G4) needs all three. They cannot live in the JSON-RPC payload: the relay (G3) must forward the body byte-for-byte to stay payload-blind (a T1 carrier, not a trust-tier authority) and to preserve the runner's request/response `id` correlation end-to-end. So the sequence metadata must ride OUT OF BAND, wrapping the opaque payload. The codec needs the existing frame bound + the loud-failure type, which moved into a shared leaf module (`src/alfred/plugins/comms_wire.py`) so the codec and both transports import them from one place rather than closing a codec↔transport import cycle.

## Decision

The following decisions are recorded by G2 (the codec); the gateway, buffer, epoch-auth, shared-volume AF_UNIX, and audit-reconcile decisions the spec §8 also assigns to ADR-0032 are amended in by G3/G4 when those components land. This first cut is scoped to the wire format.

- **Decision 1 — An out-of-band, magic-gated ASCII header wraps the verbatim payload.** A negotiated wire unit is `A1 s=<seq> a=<ack> n=<payload_len> |<opaque-payload>\n` — a single newline-terminated line, so the existing `readline()` reader on both transports is unchanged. `A1` is the magic + wire version. The codec (`src/alfred/plugins/comms_seq_codec.py`) never decodes the payload; it splits the header off and returns the payload bytes untouched.

- **Decision 2 — `seq` is a per-direction monotonic counter, additive to and distinct from the JSON-RPC `id`.** The relay preserves `id` end-to-end (the runner's `_pending`/`_resolve_pending` correlation survives the relay) because the codec touches no payload byte. `seq` is a second, header-level counter.

- **Decision 3 — Cumulative ack = the highest CONTIGUOUS seq durably intaken; the G2 wire ack is an `a=0` placeholder.** A gap does not advance the ack. Acks are coalesced (piggyback + bounded timer) by the sender/relay — there is NO standalone ack per data frame. The G2 transport emits `a=0` as a PLACEHOLDER and deliberately does NOT piggyback a `max(seq seen)` high-water: a high-water would falsely ack PAST gaps, contradicting this contiguous-ack definition. G2 ships the ack VALUE semantics on the PURE, property-tested `SeqDedupWindow.cumulative_ack()`; the G3 relay wires that as the ack source AND owns the coalescing timer. The transport carries `a=0` and consumes no ack.

- **Decision 4 — Idempotent dedup keyed on `(leg, seq)` ONLY, never payload-derived.** `SeqDedupWindow` is constructed per-leg; a re-seen `(leg, seq)` is dropped idempotently. No header value is derived from payload content — the structural guarantee that the carrier stays payload-blind.

- **Decision 5 — Version-gated at the handshake, default-OFF, mixed-safe; decode is direction-agnostic.** The header is emitted only when both peers advertise `AlfredSeqAck/1` in the `lifecycle.start` capability exchange (`SeqAckCapability` on `LifecycleStartRequest`/`LifecycleStartResult`). The gate flag is per-transport and controls only what `send` EMITS; `decode` is magic-gated and direction-agnostic, so a seq-enabled reader still reads a plain `{`-line from an un-upgraded peer (and vice versa). The runner flips the transport via a TYPED `enable_seq_ack` on the `_CommsTransportLike` Protocol — never `getattr` duck-typing.

  - **A daemon-spawned plugin is NOT the seq/ack peer (G2 scope).** seq/ack exists to make the **core↔gateway** leg (G3) resumable across a core restart. A daemon-SPAWNED comms plugin (e.g. the reference adapter, or Discord) dies *with* the core, so it gets no resume benefit and must NOT advertise the capability — it stays plain ADR-0025. The host (runner) MAY keep advertising `AlfredSeqAck/1` on `lifecycle.start`: that is HARMLESS, because the version-gate only flips `send` to the `A1` header when a peer ECHOES the capability, and a spawned plugin never does. The gateway (G3) is the peer that both echoes the capability **and** deframes the header. (A plugin that echoed without deframing would flip the gate ON and then be unable to parse the `A1`-wrapped frames the host sent it — so the reference adapter deliberately does not echo.)

- **Decision 6 — The header costs payload budget (Option A).** `_MAX_COMMS_LINE_BYTES` is unchanged and bounds the WHOLE unit (header + payload + `\n`). Because the `A1 s=… a=… n=… |` header plus the trailing newline add a bounded overhead, on a NEGOTIATED wire the effective payload ceiling is `max_unit_bytes - _MAX_HEADER_BYTES`, where `_MAX_HEADER_BYTES` is the worst-case NON-payload width — the literal skeleton (incl. the `|` delimiter), three base-10 counters each at most the decimal width of `_MAX_COMMS_LINE_BYTES`, and the trailing `\n`. A payload at or under the ceiling is GUARANTEED to encode for any counter widths. The runtime check is on the OUTER unit; `_MAX_HEADER_BYTES` is the documented reservation the G3 relay sizes payloads against.

## Consequences

### Positive

- The relay can forward the JSON-RPC body verbatim, staying payload-blind, while seq/ack/dedup ride alongside.
- `id` correlation survives the relay untouched; the existing runner is undisturbed.
- The codec is a pure, hypothesis-property-testable unit, decoupled from the gateway/buffer that consume it.

### Negative / accepted

- A second framing concept (the seq header) now layers over ADR-0025. The cost is one small codec; the alternative — an in-band JSON field — would force the relay to parse + re-serialize every frame, breaking payload-blindness and adding a hot-path cost.
- G2 wires the codec into both transports behind the gate but ships NO consumer of ack/dedup. The seq value is computed and carried; the ack is an `a=0` placeholder and the dedup window is unwired — they are not acted on until G3/G4. Recorded so a later reader does not mistake the unconsumed ack/window for a bug.

### Scope boundary (this ADR / G2)

G2 ships the codec (`CommsSeqCodec` + `SeqDedupWindow`), the `comms_wire` leaf module, the handshake version-gate (`SeqAckCapability`), and the gate-conditional transport insertion. It builds NO gateway (G3), NO `ReplayBuffer` (G4), NO ack-coalescing timer, NO send-window/back-pressure, and changes NO resume behaviour. The buffer-security, epoch-auth, shared-volume AF_UNIX, and gateway-local audit-reconcile sections the spec assigns to ADR-0032 are amended by G3/G4.

## Amendment — Peer authentication (G3-1)

The gateway↔core leg rendezvous over the ADR-0031 named AF_UNIX socket (`CommsSocketListener` binds + accepts; the gateway/foreground `alfred chat` dials in). Spec A §4/§6 require the core to authenticate the peer via `SO_PEERCRED` on accept, in BOTH directions. G3-1 lands the **accept side**; the dial side (the gateway authenticating the core after `connect`) is G3-3.

- **FS perms are the enforcement-of-record.** The socket is `0600` under a `0700` runtime dir, so only the owner uid can `connect()` it. This already bars a cross-uid peer on every platform; the `SO_PEERCRED` check is defense-in-depth ON TOP, not the only line.

- **`SO_PEERCRED` is cross-platform best-effort.** On Linux, `_resolve_peer_uid` reads the kernel-attested `(pid, uid, gid)` of the connector off the **accepted child socket** (`writer.get_extra_info("socket")`) — never the listening socket, which would return our own uid and always pass. The creds are unpacked as three UNSIGNED ints (`"3I"` — the kernel `struct ucred`). A platform without `SO_PEERCRED` (macOS dev hosts) resolves to `None`.

- **It NEVER fail-closes on an unanswerable platform.** `_peer_uid_authorized` accepts a `None` uid (degrade to the FS-perms guarantee) and a uid equal to `os.getuid()`; it refuses only a uid that genuinely mismatches ours (a same-uid-race re-bind or a wider-perm misconfig). `getsockopt` may also return fewer bytes than requested — a length-guard plus an `(OSError, struct.error)` catch degrade a short read / closed socket to `None` rather than crashing the accept callback and wedging the listener (CLAUDE.md hard rule #7).

- **A rejected peer is refused without wedging a legitimate dial-in.** On reject the listener closes the writer, logs `comms.socket.peer_uid_rejected` (structlog), and does NOT resolve the accept future — so a subsequent same-uid peer still connects. The core-side daemon AUDIT row for the rejection lands in G3-2 (the daemon caller owns the injected audit writer; the G3-1 listener is a dependency-light library whose loud surface is the structlog warning + the refusal).

This amendment introduces NO env override: the configurable runtime/socket dir (`ALFRED_COMMS_RUNTIME_DIR`, behind fail-closed validation) is deferred to G3-4 with the shared-volume mount it serves.

## Amendment — Link-state machine + control frames (G3-3a)

G3-3a lands the gateway's **stable kernel**: the part that decides what the client is told when the core link gaps and recovers. The kernel is two pieces — a pure state machine and three control-frame wire models — plus a thin client-facing listener that emits them. NO core dial, NO seq/ack relay, NO buffer (those are G3-3b/G4).

### The `LinkStateMachine` (pure, typed-event-driven)

`LinkStateMachine.feed(event) -> LinkControl | None` is a total function of `(state, event)` over four states (`UP` / `DOWN_SIGNALLED` / `DOWN_CRASH` / `REDIALING`) and four events (`core_going_down` / `core_crash_eof` / `redial_started` / `core_ready`). It is **pure — no I/O, no clock**: the wire send, the socket, and the reconnect/backoff loop all sit above it (the G3-3b core-link). That split is what makes the §9 invariant hypothesis-testable in isolation.

- **Typed events only — the kernel makes NO wire-trust decision.** `feed` accepts a `GatewayLinkEvent`, never a raw wire frame. Deriving `core_ready` from a lifecycle frame is a G3-3b obligation: the frame must be `ReadyNotification`-parsed and epoch-checked BEFORE `feed(core_ready)` is called. The pure machine is structurally incapable of being driven by raw bytes, so a forged `ready` cannot reach it (the forged-`ready` defense itself is G3-3b).

- **The §9 invariant.** No `restored` without a preceding `reconnecting`; exactly one control frame per gap; never a spurious second `restored`. A hypothesis property over random event sequences proves it.

- **Fail-loud on an undefined pair.** An unmodelled `(state, event)` raises `GatewayLinkStateError` (CLAUDE.md hard rule #7) — never a silent no-op. The transition table is deliberately permissive on the legitimate races: the idempotent self-loops (a second down-signal within one gap, repeated redial attempts, a late/duplicate `core_ready` while already `UP`) emit nothing, and `DOWN_SIGNALLED`/`DOWN_CRASH + core_ready -> UP` emits `restored` directly (a `core_ready` can legitimately race AHEAD of `redial_started`; the gap closes regardless, so this must NOT crash a real sequence). The only genuinely-undefined pair is `UP + redial_started` (a redial cannot begin while the link is up — no gap is open).

### The control frames — pure state signals, NO banner, NO T3

The gateway→client vocabulary is exactly three id-less notifications: `link.reconnecting` / `link.restored` / `link.unavailable` (the wire-method constant and the model are the SAME string by construction). They are **pure STATE signals** — fieldless `_WireModel` subclasses (`extra="forbid"` rejects any smuggled field loudly) carrying NO operator-text and NO `adapter_id`.

- **No `banner`/`reason` text on the wire.** An open `str` field here would be a standing invitation to later smuggle a core-supplied / T3-derived reason into a client-visible frame, and operator text on the wire breaks i18n rule #1. The gateway sends only the STATE; the **client (the TUI, G5) renders its own localized banner from the method**, against `{user.language}` where the user's language lives. The gateway is a T1 carrier — T3 stays in the core.

- **`link.unavailable` is defined but never emitted in G3-3a.** Its trigger — the ReplayBuffer cap breach (spec §5) — lands with the G4 breaker. Defining the model now keeps the wire vocabulary whole without a half-specified G4 edge; G3-3a ships no transition that emits it.

### The client listener

`GatewayClientListener` reuses the merged `CommsSocketListener` (`adapter_id="gateway"`, socket `comms-gateway.sock` — the gateway's own stable externally-owned path per spec §10) so it inherits the `0600`/`0700` posture + the `SO_PEERCRED` peer-auth. **Single-accept-for-life:** the client connection is held across core restarts; all reconnect churn is on the core-link (G3-3b), never a client re-accept. `send_control` routes the id-less frame through the accepted transport's `send()` (NOT a bespoke serialize — inherits its single-writer lock + the future client-leg seq/ack wrapping). A write to a dead client is LOUD (`comms.gateway.control_send_failed`) and re-raised.

### Audit deferral

Every link-state transition is **loud via structlog** in G3-3a: a SUCCESSFUL emit logs `comms.gateway.control_sent` at INFO (so a reconnect/restore is observable, not just failures), and a write to a dead client logs `comms.gateway.control_send_failed` + re-raises. The durable, signed, reconcilable gateway-local audit row is **G4** (spec §6) — the 3a kernel has no audit sink. Likewise the peer-auth reject seam is a structlog-only stub here (the gateway stub warns `comms.gateway.peer_uid_rejected`, and the reused listener independently warns `comms.socket.peer_uid_rejected` at the reject point); the durable reject audit row + the `gateway_peer_auth_rejected_total` metric are G3-3b/G4. This is a deliberate deferral, NOT a gap.

## Amendment — Core-link manager (G3-3b-1)

G3-3b-1 lands the gateway's **core-facing half**: the connection to the core that drives the G3-3a kernel and the reconnect banner. NO payload relay (non-lifecycle frames are dropped + counted; the opaque relay is G3-3b-2), NO buffer (G4).

### Role direction — the gateway is PEER on the core leg

The core (daemon) **binds + accepts** its socket and runs `CommsPluginRunner` as **HOST** (`src/alfred/cli/daemon/_commands.py` `_listen_socket_comms_adapter` / `_build_comms_runner`); the HOST sends `lifecycle.start` first (`comms_runner.py` `_handshake`). The gateway **dials** the core's socket (`dial_comms_socket`, default `adapter_id="tui"` — G3-4 relocates it to a shared volume), so on the core leg the gateway is the **PEER**: it RECEIVES `lifecycle.start`, validates it, captures the core's per-boot `epoch`, and RESPONDS with `{"ok": true, "plugin_version": ..., "seq_ack": {...}}` (echoing `AlfredSeqAck/1` iff the core advertised it, then enabling core-leg seq/ack). On the client leg the gateway is HOST (it binds `comms-gateway.sock`, the TUI dials in) — that client-leg host handshake is G3-3b-2 (only the relay needs client-leg seq/ack).

### The handshake epoch IS the liveness signal

In the normal boot the core emits its `daemon.lifecycle.ready` broadcast **before the gateway has dialed in** (zero senders — `comms_runner.py` reconciliation note), so the gateway never receives a `ready` frame on first connect. Therefore a **successful core-leg handshake (with a valid 32-hex epoch captured) is itself the `core_ready` signal** — `GatewayCoreLink` feeds `CORE_READY` on handshake success, not on a separate `ready` frame. This is provably safe against a premature banner-clear: the core's socket only becomes dialable **after `supervisor.start()` succeeds** (`_commands.py` boot order: `mint_boot_epoch` → `supervisor.start()` → `listener.bind()`), so a completed handshake genuinely implies a healthy core.

### The epoch-reconcile forgery defense

A `daemon.lifecycle.ready` frame that DOES arrive mid-connection is corroboration only: it is `ReadyNotification`-parsed (epoch pinned 32-hex) and its epoch is **reconciled against the captured handshake epoch**. A match → `feed(CORE_READY)` (idempotent). A **mismatch** → a stale/forged `ready` (a same-uid peer past `SO_PEERCRED` injecting a false liveness signal) → rejected: NO `feed`, NO control frame, a loud `gateway.core_link.ready_epoch_mismatch` warning. **A false `restored` is an attack surface**, so this is a forgery defense, not noise — it is exercised by an adversarial-corpus test now (the forgery attempt is test-observable before the durable sink exists). G4 owes a **dedicated** durable `ready_epoch_mismatch` audit row (NOT bundled with generic link transitions). The typed-event boundary the G3-3a kernel established holds: a raw/forged frame is Pydantic-validated + epoch-checked BEFORE the typed `feed(core_ready)` — it can never reach the pure machine as bytes. A malformed lifecycle frame (`reason`/`epoch` shape) is likewise loud (`gateway.core_link.malformed_lifecycle_frame`) + dropped, never fed.

### Reconnect / backoff

On a gap (a planned `going_down` then EOF, or a crash EOF / transport-crash exception) the core-link reconnects with exponential backoff + **full jitter with a non-zero floor**: an injectable-clock loop whose backoff CEILING starts at `0.25 s`, ×2 to a `5.0 s` ceiling. The realised per-attempt delay is the full-jitter draw `uniform(0, ceiling)` **CLAMPED in CODE** to `[_MIN_RECONNECT_DELAY_SECONDS (0.05 s), ceiling]` — so the FIRST (and every) retry delay is in `[0.05 s, 0.25 s]` on attempt 1, **NEVER `0`** (honours spec §4: never a 0-delay first retry, enforced in code, not just documented). The clamp also defends a pathological injected jitter: a `0` / negative draw is floored to `0.05 s` and a draw `> ceiling` is pinned back to `ceiling`. This 50 ms floor is anti-stampede (a thundering-herd / tight-spin guard) and negligible to an operator. Each attempt feeds `redial_started` + increments `gateway_reconnect_attempts_total`. A successful dial + handshake feeds `core_ready` → from `REDIALING` emits `restored`. A half-open transport (dial succeeds, handshake then fails) is closed before retrying (no FD leak). The reconnect loop also **honours shutdown** (CLAUDE.md hard rule #7): a shutdown signalled between attempts ends it at the top-of-iteration check, and a shutdown during the backoff sleep races the sleep and returns promptly rather than waiting out the backoff — so an operator stop never hangs behind a dial-forever loop during a prolonged core outage. The §9 invariant holds end-to-end across a real gap+reconnect: exactly `[reconnecting, restored]`, one per gap.

### Dial-side peer-auth (recorded under ADR-0031)

The both-direction `SO_PEERCRED` G3-1 deferred ships here as a `dial_comms_socket` extension (**ADR-0031**'s socket-transport concern — it owns the accept-side peer-auth): a `CommsPeerAuthError` (a `CommsProtocolError` subclass) on a mismatched-uid listener. It is **Linux-enforcing** (where `SO_PEERCRED` answers); on a degrade-open host (no `SO_PEERCRED`) the dial side does NOT own the dialed inode, so a **pre-dial `lstat` owner+socket guard** is the backstop (the dialed path must be a socket owned by the current uid). The reconnect loop treats a dial peer-auth reject as a transient and retries.

### Audit deferral (unchanged from G3-3a)

Link transitions + epoch rejects are loud via structlog; the durable, signed, reconcilable gateway-local audit row is **G4** (spec §6) — the gateway still has no audit sink. `gateway_core_unavailable_seconds_total` accrues the not-UP wall time as the operational signal in the interim. This is a deliberate deferral, NOT a gap.

## Amendment — Opaque relay engine (G3-3b-2a)

G3-3b-2a makes the gateway a **payload-blind, byte-for-byte relay** between the dial-in client (the TUI) and the core — the first real `AlfredSeqAck/1` peer that DEFRAMES one leg and REFRAMES onto the other. NO process/CLI yet (G3-3b-2b); NO buffer/resume (G4).

### The wire reality: the client leg is PLAIN in production

The merged TUI never negotiates seq/ack, so **in production only the gateway↔core leg is seq/ack-enabled; the gateway↔client leg is plain ADR-0025.** The relay is seq-gated per leg (each `CommsSocketTransport` carries its own `_seq_ack_enabled`): the plain-client path is the production path; a seq-enabled-client path is forward-looking (G4/G5 may upgrade the TUI for resume). The across-restart client-leg-seq invariant (the client `seq` climbs monotonically across a core reconnect because the single-accept-for-life client transport is never replaced) therefore applies only on the forward-looking seq-enabled-client wire; on the plain production leg the relay simply forwards plain lines.

### The opaque seam + routing

`CommsSocketTransport.read_payload_unit() -> SeqFrame | None` returns the opaque ADR-0025 payload bytes (the `SeqFrame.payload`, `seq=None` on a plain line) WITHOUT `json.loads`-ing them; `send_payload_unit(payload, *, ack)` reframes with this leg's `_send_seq` + the supplied REAL ack (not the merged `a=0` placeholder), seq-gated, under `_send_lock`. `read_frame`/`read_payload_unit` share one private read+bound+seq-deframe helper so the three-point DoS bound never diverges. To ROUTE, the relay peeks the JSON-RPC `method` on a COPY of the payload — wrapped `try/except (JSONDecodeError, ValueError, RecursionError)`, and on ANY parse failure it **fails TOWARD relay** (forwards the original bytes, never drops/consumes — hard rule #7): a `daemon.lifecycle.*` method is CONSUMED (the merged forgery-defended `_consume_frame` — a forged `ready` is still epoch-rejected), everything else (incl. a no-`method` response) is RELAYED byte-for-byte. The client→core leg does ZERO body parse (pure opaque forward). T3 stays in the core; the canary trips only in the core (the gateway never reads a body, and a relayed canary never reaches a gateway log row or metric label).

### The ack tracker — bounded (the first long-lived process)

The gateway is the first real `cumulative_ack()` source. It does NOT reuse the merged `SeqDedupWindow` (its `_seen` grows unbounded; pruning it would break its idempotent-`accept()` contract). Instead a shared `src/alfred/gateway/_seq_tracker.py` leaf module owns the `BoundedSeqAckTracker` (imported by both the relay and the core-link, avoiding a relay↔core_link cycle): the contiguous high-water + a bounded out-of-order gap set — a seq more than `_MAX_OOO_GAP` (1024) beyond the high-water is REJECTED loud, closing the every-other-seq adversary (`0,2,4,…` would otherwise grow the gap set unbounded since the holes are all ABOVE the high-water). The ack a leg writes is that SAME leg's receive-tracker `cumulative_ack()` (the ack rides the reverse-flowing frames of the leg it acknowledges). The gateway computes its own ack from its own tracker — it NEVER trusts the peer's `ack` field. The send-seq is capped by `encode_seq_frame`'s width guard (~10^8 frames); exhaustion is a loud fatal leg error (G4 resume resets epoch+seq on reconnect).

### No buffering + reconnect-race

`relay_to_core` snapshots the link's CURRENT core transport into a local before writing (swap-atomic from the reverse pump's view; the link binds the transport reference only post-handshake), so a write racing a reconnect hits the captured (old, closing) transport → a clean broken-pipe/closed-state → **loud DROP** (`gateway.relay.core_send_dropped`), never buffered/retried/crashed. Symmetrically, the core→client sink (`_send_to_client`) loud-drops a dead/encode-failed client under `gateway.relay.client_send_dropped`. Both drop families are widened beyond the transport-died errors to also cover an encode-failed unit (`ValueError` from `encode_seq_frame` send-seq exhaustion, or `CommsProtocolError` from an over-bound reframe) and a write to a transport `close()`d mid-reconnect-swap (`RuntimeError`) — each a loud drop, never a relay-TaskGroup crash. A frame in flight across a core gap is dropped; the core tracker's `cumulative_ack()` stalls at the gap. G4's `ReplayBuffer` adds resume.

### The non-root wire-contract gate (#245 paper-gate fix)

The relay's contract is proven by an in-process, NON-root test over REAL loopback `CommsSocketTransport`s + a REAL `GatewayClientListener` (the G2 lesson: a launcher/root-only test is not a real gate). It asserts byte-for-byte payloads, the §9 control sequence, RESEQ (the client-leg sent seq ≠ the core-leg received seq — proving reframe, not pass-through), the client-leg seq climbing across a reconnect, the payload-blindness canary (byte-identical + no body parse + no log leak), and the forgery/dial-reject paths. (This real gate caught a `-1`-initial-ack crash the in-process fakes could not — the exact value of testing the real wire.)

## Amendment — ReplayBuffer security-bounded retention (G4a)

G4a lands the gateway's pure `ReplayBuffer` (`src/alfred/gateway/replay_buffer.py`): the un-acked **inbound** (client→core) frames live here between the moment the relay forwards them and the moment the (possibly freshly-restarted) core durably acks them, so a core restart never loses typed input (spec §5). It is a pure state machine in the same family as `LinkStateMachine` and `BoundedSeqAckTracker` — no I/O, no clock, no logging; time is injected as an explicit monotonic `now`. The reconnect/relay wiring that consumes it (drives `breaker_tripped` into the link state, writes the audit rows, halts the client read on back-pressure) is **G4b**.

### What the buffer retains — pre-DLP, payload-blind, T1-carrier input

The `ReplayBuffer` stores opaque inbound bytes verbatim and replays them verbatim — it never inspects, decodes, or trust-tags them (T3 tagging stays in the core, per hard rule #5). Because it pins **pre-DLP operator input** in the always-up process across a crash-loop, its bounded retention is a **security** property, not just a resource cap.

### Bounded retention as a security property

- **Soft cap (`max_frames` + `max_bytes`)** — a breach KEEPS the frame (the spec §5 no-silent-drop guarantee) and trips a monotone `breaker_tripped` latch. The latch is the back-pressure SIGNAL; G4b enforces the bound by ceasing to drain the client socket. Post-breach growth is bounded only by G4b's read-halt latency — the residual window this pure layer does not close (the adversarial wedged-core-flood corpus entry, spec §6(d), is a G4b release-blocker proving G4b actually halts).
- **Hard ceiling (`2×` each soft cap)** — a defence-in-depth backstop against a buggy G4b that ignores back-pressure: an append that would breach it raises loud (`ReplayBufferError`, fail-closed — never a silent drop) so the always-up security process cannot be driven to OOM.
- **TTL (`ttl_seconds`)** — pre-DLP input cannot be pinned across an unbounded crash-loop, so a frame older than the TTL is evicted. TTL eviction IS input-loss, so it is **observable**: `evict_expired` returns the evicted seqs and G4b writes a loud audit row per dropped frame (hard rule #7). The monotonic-`now` invariant on `append` is what makes "expired frames are a leading FIFO prefix" a guarantee rather than a hope.

### Zero-on-removal (best-effort)

Every byte that leaves on a removal path (`trim_to_ack` ack-trim, `evict_expired` TTL-eviction, `discard`) is overwritten in place (`bytearray` overwrite) before its reference is dropped, with white-box tests asserting the captured body reads all-zero. **Residual-risk caveat:** Python gives no crypto-erase guarantee (the GC may have copied, interned, or paged the bytes). The buffer zeros only its own mutable copy; the immutable `bytes` a caller passes to `append`, and the immutable copies `unacked_frames` hands back (a flapping reconnect can mint many live at once), are caller/wire-owned and not the buffer's to zero. `MADV_DONTDUMP` / core-dump suppression are the G4b process-level mitigations and G4b must not retain replay results beyond the single send.

### Seq is gateway-owned and monotonic across a core restart

The inbound (client→core) seq the gateway mints does NOT reset on a core bounce (only the core→client direction resets — Decision 1/§4); a normal reconnect does NOT discard, so the gateway keeps minting the next seq and the monotonic guard is never tripped on a successful resume. Replay carries each frame's ORIGINAL seq (`ReplayFrame(seq, payload)`) so the core dedups on `(leg, seq)` (Decision 4) — re-minting would defeat the no-double-effect guarantee. `discard` (clean shutdown / retry-window exhaustion) zeroes everything and clears the breaker but **deliberately does NOT reset the monotonic floor**: a late stale-stream frame after a discard is rejected loud rather than silently re-admitted. A genuine seq-space restart is a G4b epoch-handshake concern, sequenced after the old leg is torn down.

### Loudness is the G4b wiring's obligation

The pure buffer exposes signals — `evict_expired`'s returned seqs, the `breaker_tripped` latch, and the hard-ceiling raise — but writes no audit row and no log. G4b turns every signal loud (audits each eviction / breaker-trip / hard-ceiling raise, drives `breaker_tripped` → `GatewayLinkEvent.BREAKER_TRIPPED` → `LinkControl.UNAVAILABLE`, and gates `trim_to_ack` on epoch-validated durable acks — a spoofed/stale-epoch ack would zero un-committed input, and the pure buffer cannot tell a real ack from a forged one).

## Amendment — `daemon.comms.ack` consumed control frame (G4b-2a-pre)

G4b-2a-pre makes Decision 3's coalesced ack REAL on the **inbound (client→core) direction** so the G4b-2a `ReplayBuffer.trim_to_ack` drains on a healthy link instead of stalling at `trim_to_ack(0)`. Two corrections to Decision 3, both inbound-direction only:

- **The inbound ack SOURCE is the core/daemon's durable-intake tracker, NOT a gateway tracker.** The gateway is the SENDER of inbound, so it cannot ack its own client→core frames; the core is the receiver and the only party that knows what it durably intook. The daemon reads the gateway's per-connection client→core wire seq off its OWN seq-enabled socket leg (carrier header metadata — never payload-derived, never used to derive `inbound_id`), advances a host-side `BoundedSeqAckTracker` (the same bounded out-of-order tracker the gateway uses for the reverse direction) ONLY on the G0 `commit_once == True` branch — never on a replay (`commit_once == False`), a structural refusal ahead of the gate, or a `None` store. The ack therefore means "highest CONTIGUOUS client→core seq the core has DURABLY intaken". The G3 relay still owns the ack for the REVERSE (core→client) direction (its `_client_tracker`); this adds the inbound-direction ack source the core owns.

- **The ack is carried on a NEW standalone, timer-coalesced `daemon.comms.ack` control frame** the daemon emits (an id-less notification, `params={"cumulative_ack": <int>}`) on a per-connection bounded timer (Decision 3's coalescing — emit only on a high-water advance; sentinel `-1` so the first commit emits; emitted value floored to `max(ack, 0)`; fail-loud send) and the gateway CONSUMES (never relays). `daemon.comms.ack` joins the host→outward **consumed-control-frame vocabulary** alongside `daemon.lifecycle.{ready, going_down}`: `core_link._route_unit` consumes it in its OWN arm BEFORE `_consume_frame` (it has no epoch and is not a `LinkStateMachine` event, so it must not trip epoch validation), payload-blind — `trim_to_ack` itself is G4b-2a. The host tracker + timer are PER-CONNECTION (the daemon's comms listener is one-shot per boot; G4b-2b's reconnect-replay must reset the tracker per accepted connection). The seq/idempotency framing above (the gateway-owned monotonic seq, `(leg, seq)` dedup) is UNCHANGED — the host ack is the ack-VALUE source only; it reports no dedup verdict. Trust impact: a forged in-window seq could corrupt only the gateway's buffer-trim liveness, never the durable `commit_once` exactly-once (the in-payload `inbound_id`); `_MAX_OOO_GAP` bounds the memory surface and out-of-window is loud.
