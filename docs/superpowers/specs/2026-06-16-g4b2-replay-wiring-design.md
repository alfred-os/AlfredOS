# G4b-2 — Inbound ReplayBuffer wiring into the live gateway relay (Spec A, #237)

**Status:** design, to plan from. **Date:** 2026-06-16. **Anchors:** ADR-0032
(`docs/adr/0032-gateway-comms-resume-transport.md`), Spec A
(`docs/superpowers/specs/2026-06-13-comms-gateway-resume-design.md` §4/§5/§6/§9),
PRD §5 invariants (T1 carrier / payload-blind), CLAUDE.md hard rules #5 + #7.

## 1. Scope

G4a merged the pure `ReplayBuffer` (`src/alfred/gateway/replay_buffer.py`). G4b-2
wires it into the live relay so un-acked **inbound** (client→core) frames survive a
core restart and replay on reconnect (spec §5). The relay today is fail-loud,
**no-buffer** (`relay.py:36-41`, `core_link.py:722-733` loud-drop a gapped core).
This wedge replaces the loud-drop with buffer-and-replay.

The core→client direction, the lifecycle/breaker plumbing, and the `ReplayBuffer`
unit itself are NOT re-opened. Only the **client→core leg** buffers.

## 2. The fork — RESOLVED: Option B (per-connection seq + re-sequence on reconnect)

### 2.1 Decision

**Adopt Option B.** The gateway owns a per-connection client→core send-seq that
resets to `0` on every core (re)connect; on reconnect it drains the buffer's
un-acked remainder and re-sends those payloads with **fresh** contiguous seqs
`0,1,2,…` against the new core's fresh `BoundedSeqAckTracker`. No core-side change.
Gateway-local blast radius.

Option A (monotonic-across-restart seq) is **rejected**: it requires a core-side
epoch-seq-reconciliation in `BoundedSeqAckTracker` (`_seq_tracker.py:62-80`,
`_MAX_OOO_GAP=1024`) that does not exist — a fresh core has `_contiguous_high=-1`,
so a replayed seq > 1023 is rejected out-of-window (`_seq_tracker.py:72-80`), the
core never advances or acks, and the gateway can never `trim_to_ack`. Building that
reconciliation touches gateway + core/daemon + wire/ADR for **zero** correctness
gain over B, because — per §2.2 — cross-restart exactly-once does not depend on the
seq at all.

### 2.2 Why B is correct — the security argument (exactly-once survives re-sequencing)

The load-bearing fact, verified in the code:

**Cross-restart idempotency is the durable `inbound_id`, NOT the seq.**

- The core's accept-once commit is `commit_once(inbound_id, adapter_id)` against a
  durable Postgres composite-PK ledger, run **before any side effect**
  (`inbound.py:162`, store impl `memory/inbound_idempotency.py:47,78`, gate at
  `inbound.py:462-464`).

- `inbound_id` is **adapter-supplied, opaque, and lives INSIDE the JSON-RPC payload
  body** (`protocol.py:97-113`). Real emitters: Discord `str(message.id)`
  (`plugins/alfred_discord/inbound_emitter.py:190-195`, stable across redelivery),
  TUI stable-across-reflush (`plugins/alfred_tui/.../test_inbound_notification.py:126-163`).

- The gateway relays that payload **byte-for-byte** and is forbidden to parse it
  (T1 carrier, hard rule #5): `relay.py:157-210` (`_client_to_core_pump`, zero body
  parse), `core_link.py:707-744` (`relay_to_core`), the codec never `json.loads` the
  payload (`comms_seq_codec.py:9-12`). The `ReplayBuffer` stores opaque bytes
  verbatim and `unacked_frames()` returns them verbatim (`replay_buffer.py:248-261`,
  ADR-0032:150).

Therefore a re-sequenced replay carries a **different wire seq** but the **same
inbound_id** (it is in the untouched payload). The core's `commit_once` short-circuits
the already-committed frame before any side effect → **exactly-once holds regardless
of the seq.** Re-sequencing changes only the per-connection wire-dedup key
`(leg, seq)`, which is a *within-connection* duplicate-suppressor, not the durable
guarantee.

Note the future-tense in `protocol.py:108-113`: "The gateway (G1+) makes this id
host-trusted by deriving it from a `(leg, seq, epoch)` envelope." That derivation
**does not exist** (no `inbound_id` reference anywhere in `src/alfred/gateway/`). It
is a Spec B/C concern. **Until it ships, the gateway must NOT derive `inbound_id`
from the seq** — doing so would make re-sequencing change the idempotency key and
break exactly-once. G4b-2 explicitly preserves the inbound_id-in-payload model. When
that envelope eventually lands, the derivation must use the **buffer key (original
seq), not the wire seq** — recorded here as a constraint on the future work.

**Buffer security posture is preserved.** Option B uses the merged buffer's bound,
TTL, zero-on-removal, and breaker exactly as designed (`replay_buffer.py:25-53`);
re-sequencing happens at the *send* boundary and does not touch retained bodies. The
pre-DLP bound and zeroing are untouched.

### 2.3 Why B is correct — the comms/wire argument

- **Within a connection**, the gateway's send-seq is still strictly monotonic
  `0,1,2,…`, so G2's `(leg, seq)` wire-dedup is satisfied per connection (a
  retransmit within one live leg would carry the same seq). Cross-connection there is
  no wire-dedup to satisfy — the core tracker is fresh per leg
  (`core_link.py:610-619` resets the *receive* tracker per handshake; the symmetric
  *send* reset is what §3 adds).

- **Replayed frames arrive as contiguous `0,1,2`** on the fresh leg, so the core's
  `BoundedSeqAckTracker.observe` advances `_contiguous_high` over the unbroken run
  (`_seq_tracker.py:82-93`) and its `cumulative_ack()` climbs normally — no
  out-of-window rejection, because nothing exceeds `0 + _MAX_OOO_GAP`.

- `send_payload_unit(payload, *, seq, ack)` with a **caller-owned seq** is the right
  contract (§3.1). The transport's internal `_send_seq` stays the source for `send()`
  (lifecycle/handshake, `ack=0`, `comms_socket_transport.py:331-343`) and coexists
  cleanly: on the gateway core-leg the handshake `send` happens **before**
  `enable_seq_ack` (`core_link.py:607-609`), so post-enable the core-leg consumes
  seqs ONLY via `send_payload_unit` — no interleaving with `send`'s internal counter.

## 3. Seq-ownership mechanism

### 3.1 Contract change to `send_payload_unit`

`send_payload_unit` is **gateway-only** (callers: `relay.py:147` client leg,
`core_link.py:744` core leg; only `CommsSocketTransport` implements it). Change the
signature to a **caller-owned seq**:

```
async def send_payload_unit(self, payload: bytes, *, seq: int, ack: int) -> None
```

`_write_payload_unit` (`comms_socket_transport.py:345-374`) is split so the
caller-supplied `seq` is used for the relay path while `send()` keeps using the
internal `self._send_seq` for its `a=0` lifecycle frames. Concretely: add a
`seq: int | None = None` param to `_write_payload_unit`; `None` → use+increment
`self._send_seq` (the `send()` path, unchanged); an explicit `seq` → encode with it
and do **not** touch `self._send_seq` (the relay path). The `_send_lock` critical
section, the over-bound `CommsProtocolError`, and the seq-OFF plain-line fallback are
unchanged.

**Why caller-owned, not transport-owned, on the relay path:** a frame that is
buffered (`append`) must carry a wire seq **equal to its buffer key**, even when the
*previous* frame's send was loud-dropped on a dying leg. A transport-internal
auto-increment would advance independently of buffer appends, so a dropped-but-buffered
frame would desync wire-seq from buffer-key and the core's `(leg,seq)` dedup +
`trim_to_ack` math would drift. The gateway therefore mints the seq, appends under
it, and sends it explicitly — one counter, one source of truth.

### 3.2 The gateway send-seq counter location

A new per-leg counter on `GatewayCoreLink` (the client→core leg owner):
`self._client_to_core_seq: int`, reset to `0` in `_peer_handshake`
(`core_link.py:576-619`, alongside the existing per-handshake receive-tracker reset at
:619) so it tracks the fresh core's fresh seq space. `relay_to_core` mints the next
seq from it. The buffer's `append(seq, …)` uses that same minted seq, so wire-seq ==
buffer-key by construction.

The `ReplayBuffer` lives on `GatewayCoreLink` too (it is the client→core leg's
state), constructed once per gateway process and injected (a ctor param, default-None
for the 3b tests that don't buffer — mirroring `_payload_relay`).

### 3.3 Drop handling

`relay_to_core` already loud-drops a dead/swapping leg (`core_link.py:735-752`). With
buffering, the order is: **append first, then attempt send**. The buffer is the
durable record; the send is best-effort. A loud-dropped send leaves the frame
buffered (un-acked) → it replays on reconnect. The send still loud-drops (no raise),
because the buffer — not a raise — is now what guarantees no-loss.

## 4. Reconnect-replay sequence (epoch-gated on validated `CORE_READY`)

The replay is triggered on the **not-UP → UP edge for a successful handshake**, which
is exactly where `_initial_connect`/`_reconnect` feed `CORE_READY`
(`core_link.py:386,573`) and `_feed` observes the UP edge (`core_link.py:826-849`).
Replay must run **after** the fresh `_peer_handshake` (new epoch captured,
`enable_seq_ack` flipped, receive tracker reset) and **after** the link is UP, but
**before** any new client→core frame is pumped, so replayed frames precede fresh
input in FIFO order.

Step-by-step (on the reconnect `CORE_READY`, i.e. NOT the very first connect):

1. **Trim to the new core's durable high-water.** A fresh core has acked nothing on
   the new leg yet, so the first replay-time `trim_to_ack` is effectively a no-op —
   but the call is kept for symmetry and to absorb any ack already observed during the
   handshake. (Trim is also driven continuously in §5; this is the reconnect-time
   guard.)
2. **Drain `unacked_frames()`** (`replay_buffer.py:248-261`) — the FIFO un-acked
   remainder, each a `ReplayFrame(original_seq, payload)`.
3. **Floor-reset the buffer for the new epoch** via the new additive method
   `reset_for_new_epoch()` (§6.2): zero+empty the retained bodies AND reset
   `_last_seq=-1` / `_last_now=-inf` so fresh seqs `0,1,…` re-append cleanly. Reset the
   `GatewayCoreLink._client_to_core_seq` to `0`.
4. **Re-send + re-append** each drained payload with a FRESH seq `0,1,2,…`: for each
   payload, mint `seq = next`, `buffer.append(seq, payload, now=…)`, then
   `transport.send_payload_unit(payload, seq=seq, ack=current_core_ack)`. (Append
   before send — §3.3.) The core G0-dedups on the in-payload `inbound_id`, so a
   re-sequenced replay of an already-committed frame short-circuits before side
   effects (§2.2).
5. The relay then resumes normal pumping; subsequent fresh client→core frames mint
   seqs continuing from where replay left off.

**Epoch gating is implicit and correct:** replay runs only on a `CORE_READY` that
passed `_peer_handshake`'s epoch validation (`core_link.py:588-619`) or the forgery
-defended `_consume_ready` epoch reconcile (`core_link.py:801-824`). A spoofed/stale
`ready` is rejected with NO `CORE_READY` feed (`core_link.py:818-823`), so it never
triggers a flush — satisfying spec §6 adversarial (c) "spoofed `ready`/stale epoch →
buffer not flushed". **The very first connect (`_initial_connect`, `core_link.py:386`)
must NOT replay** (the buffer is empty; guard replay on "have we been UP before").

## 5. Where the buffer hooks into the relay

All client→core leg, all on `GatewayCoreLink` (the leg owner):

- **`append`** — in `relay_to_core` (`core_link.py:707-744`), BEFORE the
  `send_payload_unit` at :744, using the minted `_client_to_core_seq` and an injected
  monotonic `now`. This is the one new append site on the steady-state path.

- **`trim_to_ack`** — driven by the **core leg's receive tracker** advancing. The core
  acks inbound by riding its `ack` field on core→client frames; the gateway reads
  those acks in `_pump_once`/`_route_unit` where it already calls
  `self._core_tracker.observe(unit.seq)` (`core_link.py:360-362`). The core's
  cumulative ack of *our* inbound seqs arrives as the `ack` field on the core's
  frames — read it in `_route_unit` (`core_link.py:671-705`) from `frame.ack` and call
  `buffer.trim_to_ack(frame.ack)` when present. **Security precondition** (buffer
  docstring `replay_buffer.py:204-208`): the ack must be epoch-validated — it is, by
  construction, because the leg is post-epoch-handshake and `trim` runs only on the
  current UP leg's frames.

- **back-pressure read-halt** — `breaker_tripped` (`replay_buffer.py:153-156`) is
  polled after each `append`. On trip, the relay ceases draining the **client** socket:
  `_client_to_core_pump` (`relay.py:157-210`) must check the breaker and stop reading
  (await a "breaker cleared / leg restored" condition) rather than calling
  `read_payload_unit`. This is the residual-window closer the pure buffer leaves to
  G4b (`replay_buffer.py:32-38`). The hard-ceiling raise (`replay_buffer.py:181-188`)
  is the fail-closed backstop if the halt is buggy.

- **`BREAKER_TRIPPED` feed** — on `breaker_tripped`, feed the link-state machine the
  `BREAKER_TRIPPED` event (G4b-1, `link_state.py`) so the client receives
  `link.unavailable` and the breaker→UNAVAILABLE escalation (merged G4b-1:
  `8f59fbf3`/`3a52c65e`) fires + a loud audit row is written (spec §6 audit
  non-skippable).

- **`evict_expired` + `discard`** — `evict_expired(now=…)` is polled on a timer (or each
  pump tick) and each returned seq is audited as input-loss (spec §6, hard rule #7);
  `discard()` on clean shutdown and on retry-window exhaustion (the max-retry cap the
  pure buffer cannot see — `replay_buffer.py:263-278`).

## 6. ADR-0032 amendment owed

### 6.1 The contradiction to fix

ADR-0032 §"Seq is gateway-owned and monotonic across a core restart" (lines 162-164)
states "Replay carries each frame's ORIGINAL seq … so the core dedups on `(leg, seq)`
… re-minting would defeat the no-double-effect guarantee." Spec §5 step 3 says the
opposite: "the core dedups by **inbound-id**". The **code agrees with the spec**:
`commit_once` is on `(adapter_id, inbound_id)` (`inbound.py:162`), the `SeqDedupWindow`
is per-connection and **unwired** (ADR-0032:42), and `BoundedSeqAckTracker` resets per
leg. The ADR's "monotonic across restart + dedup on `(leg,seq)` + re-minting defeats
exactly-once" framing is the part that is wrong for the cross-restart case.

### 6.2 The amendment

Add a Decision/clarification (and correct the lines-162-164 section + ReplayBuffer
docstring `replay_buffer.py:9-15,85-95,263-278`):

- **Cross-restart exactly-once is the durable `inbound_id` (in the opaque payload),
  not the `(leg, seq)` wire key.** `(leg, seq)` is *within-connection* wire-dedup only.

- **The client→core send-seq is per-connection (resets to 0 each core leg).** On
  reconnect the gateway re-sequences the un-acked remainder `0,1,2,…` against the
  fresh core's fresh tracker; the in-payload `inbound_id` keeps it exactly-once. This
  supersedes the "monotonic across restart / replay carries the ORIGINAL seq"
  framing for the **client→core** direction.

- Record the **additive** `ReplayBuffer.reset_for_new_epoch()` method (zero+empty AND
  reset `_last_seq`/`_last_now`) — the "epoch-gated seq-floor reset G4a deferred". The
  merged buffer's `append`/`trim_to_ack`/`evict_expired`/`unacked_frames`/`discard`
  are **unchanged**; only this one method is added. (`discard` keeps its no-reset
  semantics for the shutdown/retry-exhaustion path; `reset_for_new_epoch` is the
  distinct reconnect-flush path.)

- Note the future constraint: when the `(leg, seq, epoch)` `inbound_id`-derivation of
  protocol.py:108-113 lands (Spec B/C), it must derive from the **buffer key (original
  retained seq)**, never the re-sequenced wire seq.

A docs-author + reviewer pass owns the ADR prose; this design specifies the content.

## 7. PR decomposition

Four PRs, each green and reviewer-gated (the §9 prerequisite splits 2a in two —
see §9.6). Adversarial entries (spec §6 b/d, §9 release-blocking) land with the
behaviour they test.

### G4b-2-pre — seq-ownership contract (`send_payload_unit(payload, *, seq, ack)`)

- **Ships:** the `_write_payload_unit` split (caller-owned `seq` on the relay path,
  internal `_send_seq` for `send()`); `send_payload_unit` signature change; both call
  sites (`relay.py:147`, `core_link.py:744`) pass an explicit seq; the
  `_client_to_core_seq` counter on `GatewayCoreLink` reset in `_peer_handshake`.

- **No buffering yet** — seq is minted + carried, behaviour otherwise identical.
- **Tests:** unit — `send()` still uses internal seq + `a=0`; relay path uses caller
  seq; `_send_seq` untouched by the relay path; wire round-trip
  (`test_relay_wire_contract`-style, real encode) asserting the explicit seq lands on
  the wire and decodes back. Property test: minted seqs are contiguous within a leg
  and reset on a fresh handshake.

### G4b-2a-pre — daemon durable-intake ack emission (the §9 prerequisite)

- **Ships (all daemon/host-side, NO gateway change):** a host-side
  `BoundedSeqAckTracker` observing the gateway's INBOUND (client→core) seqs; the seq
  carried from `CommsSocketTransport.read_frame` into `process_inbound_message` via a
  new `wire_seq` notification field; the tracker `observe(wire_seq)` advanced ONLY on a
  successful G0 `commit_once` (durable-intake, decision 4); the daemon's core→client
  frames carrying `cumulative_ack()` as a REAL ack instead of the `a=0` placeholder
  (the periodic standalone-ack-frame mechanism of §9.3). See §9 for the full mechanism.

- **No gateway buffer yet** — the daemon now EMITS a true cumulative ack of durably-
  committed inbound seqs; the gateway still discards it (its `trim_to_ack` lands in
  G4b-2a). This PR is independently valuable + provable on the daemon alone (§9.5).

- **Tests:** see §9.5 — the daemon emits a real cumulative ack of durably-committed
  inbound seqs; a replayed/duplicate `inbound_id` does NOT re-advance the ack; a gap in
  the inbound seq stream stalls the ack at the gap until filled.

### G4b-2a — buffer append + ack-trim + back-pressure

- **Ships:** `ReplayBuffer` injected into `GatewayCoreLink`; `append` in `relay_to_core`
  (append-before-send); `trim_to_ack` driven from `frame.ack` in `_route_unit` — now a
  REAL durable-intake ack (G4b-2a-pre wired the daemon to emit it; before the prerequisite
  it was always `0` and the buffer never drained — see §9.1); `breaker_tripped` →
  `BREAKER_TRIPPED` feed → `link.unavailable` + audit; client read-halt in
  `_client_to_core_pump`; `evict_expired` timer + per-seq input-loss audit;
  `reset_for_new_epoch()` added to the buffer.

- **No reconnect-replay yet** — buffered frames are held + trimmed + bounded, but a
  reconnect does not yet re-send them (the leg comes back, fresh frames flow; the held
  remainder waits for G4b-2b).

- **Tests:** unit — append-before-send ordering; ack on a core→client frame trims the
  prefix; breaker trip halts the client read + writes the audit row + feeds the link
  state; TTL eviction audits each seq. **Adversarial §6(d) wedged-core flood** (release
  -blocking): a core that never acks → buffer fills to the soft cap → breaker trips →
  client read halts → `link.unavailable` + loud audit → growth bounded (hard-ceiling
  raise as backstop, never OOM, never silent drop).

### G4b-2b — reconnect-replay (the resume)

- **Ships:** the §4 flush on the reconnect `CORE_READY` edge — drain `unacked_frames`,
  `reset_for_new_epoch`, re-send+re-append with fresh seqs `0,1,2,…`, then resume the
  pump; the first-connect "never replayed" guard; `discard` on retry-window exhaustion.

- **Tests:** unit — reconnect re-sends the un-acked remainder as contiguous `0,1,2`;
  the fresh core's `BoundedSeqAckTracker` advances + acks; first-connect does not
  replay; a spoofed `ready` (no `CORE_READY` feed) does not flush (spec §6(c) — extend
  the merged forgery test). **Adversarial §6(b) crash-pre-ack → exactly-once**
  (release-blocking): client→core frame buffered, core crashes before its durable ack,
  fresh core handshakes, replay re-sends the SAME payload (with the SAME in-payload
  `inbound_id` but a FRESH seq) → assert the core's `commit_once` is invoked twice with
  the same `inbound_id` and the side effect fires exactly once (the second is a dedup
  short-circuit). This is the test that proves re-sequencing is safe.

## 8. Recommendation

Adopt **Option B**: a per-connection gateway-owned client→core send-seq that resets to
0 each core leg, with un-acked inbound re-sequenced `0,1,2,…` on reconnect. It is
correct because the cross-restart exactly-once guarantee is the durable, in-payload
`inbound_id` that the byte-for-byte relay never touches — not the wire seq — so
re-sequencing is provably safe (`commit_once` short-circuits the replayed frame before
any side effect), and it is the only gateway-local option (Option A needs a non-existent
core-side epoch-seq reconciliation in `BoundedSeqAckTracker` for zero correctness gain).
The merged `ReplayBuffer` needs only one ADDITIVE method (`reset_for_new_epoch`); the
work owes an ADR-0032 amendment correcting the "monotonic-across-restart / dedup-on-
`(leg,seq)`" framing to "per-connection seq + idempotency-is-the-inbound-id", and ships
as four reviewer-gated PRs (pre-seq-ownership → **2a-pre daemon durable-intake ack**
(§9) → 2a buffer+backpressure → 2b reconnect-replay) with the §6 wedged-flood and
crash-pre-ack adversarial entries as the release-blocking proof.

## 9. Daemon durable-intake ack emission (G4b-2a prerequisite)

### 9.1 The confirmed gap — the daemon emits `a=0` on every core→client frame

§5's `trim_to_ack` is driven from `frame.ack` on the core→client frames the gateway
receives (this design §5, second bullet). I traced the daemon's outbound and confirmed
that ack is **always the `a=0` placeholder** — the daemon keeps NO host-side receive
tracker of the gateway's inbound seqs and computes no real cumulative ack:

- The daemon's outbound to the gateway runs through `CommsPluginRunner.send_request`
  (`comms_runner.py:264`, the `outbound.message` dispatch ack from
  `_RunnerOutboundSender.send_outbound`, `_commands.py:258-261`) and
  `send_notification` (`comms_runner.py:300`, the lifecycle frames). BOTH call
  `self._transport.send(...)`.

- `CommsSocketTransport.send` is hard-wired to the placeholder:
  `await self._write_payload_unit(body, ack=0)` (`comms_socket_transport.py:343`).
  Its docstring is explicit — "`send` carries the `a=0` PLACEHOLDER ack (ADR-0032
  Decision 3) — NOT a high-water" (`:340-342`). The real-ack path
  `send_payload_unit(payload, *, seq, ack)` (`:388`) exists but has NO daemon-side
  caller — only the GATEWAY's relay (`relay.py:156`, `core_link.py:759`) uses it.

Consequence, exactly as the blocker states: the gateway's `buffer.trim_to_ack(frame.ack)`
would always be `trim_to_ack(0)`. On a HEALTHY link the buffer never drains, grows to
the soft cap, and the §5 `breaker_tripped` latch trips in steady state — a functional
break, not merely a missed resume. **Trim-on-ack is therefore essential to G4b-2a and
the daemon must first be taught to emit a real cumulative ack.** This is the §5
"`trim_to_ack` … gates on epoch-validated DURABLE acks" promise (ADR-0032:168) made
real on the emitting side; spec §4 (line 45) pins the ack point as "the core's durable
intake commit (decision 4), decoupled from the core's existing out-of-order dispatch
fan-out".

### 9.2 Where the daemon reads the gateway's inbound seq — and where it dies today

The seq IS on the wire when it reaches the daemon. The gateway frames each
client→core unit with its owned `_client_to_core_seq` (`core_link.py:756-759`,
`send_payload_unit(payload, seq=seq, ack=…)`), so on the seq-enabled core leg the
daemon receives `A1 s=<seq> a=… |<payload>\n`. But the daemon-as-HOST read path
**discards the seq**:

- `_accept_and_pump` (`_commands.py:1132`) runs the UNCHANGED `runner.pump()`.
- `CommsPluginRunner._pump` reads via `transport.read_frame()`
  (`comms_runner.py:479` → `_read_frame_or_shutdown` → `:556`).

- `CommsSocketTransport.read_frame` (`comms_socket_transport.py:465`) calls
  `_read_seq_frame` (`:405`), which on the seq-enabled wire `decode_seq_frame`s the
  unit and then **returns only the decoded JSON body** — the `SeqFrame.seq` is read for
  the bound check and dropped (`:440-447`; the docstring even says "CONSUMES NO seq/ack
  here … the G3 relay is the consumer"). The seq never reaches `_pump`, the session,
  the `InboundMessageHandler`, or `process_inbound_message`.

So the two halves of the dedup identity diverge in transit:

- the **out-of-band header seq** dies at `_read_seq_frame` (`comms_socket_transport.py:447`);
- the **in-payload `inbound_id`** (`protocol.py:117`, inside the opaque body the codec
  never parses) survives intact to `commit_once(inbound_id, adapter_id)`
  (`inbound.py:464-467`).

The durable G0 commit therefore already works on the `inbound_id` (cross-restart
exactly-once, §2.2) — what is missing is a path that lets the daemon ALSO observe the
per-connection wire seq and advance a cumulative ack on each durable commit.

### 9.3 The resolved mechanism — three parts, all daemon-side

**(a) Carry the seq inward.** `read_frame` is `Mapping`-typed and shared with the stdio
carrier, so do NOT widen it. Instead add a thin seq-bearing read path on the socket
carrier only: have the runner's pump, on a seq-enabled transport, read via
`read_payload_unit()` (`comms_socket_transport.py:453` — it ALREADY returns the full
`SeqFrame` with `seq` + opaque payload) and `json.loads` the body itself. The seq MUST
travel WITH its own frame: a shared per-transport `last_received_seq` slot is **RACY and
REJECTED** — the pump detaches dispatch as a background task then immediately reads the
next frame, clobbering the slot before the dispatched task builds the notification
(`session.py:738`). **Implemented form:** the socket carrier's `read_frame` folds the
decoded `frame.seq` onto the returned frame under a reserved TOP-LEVEL key
(`WIRE_SEQ_FRAME_KEY`), set UNCONDITIONALLY (`None` on a plain unit, which clears any
peer-smuggled body `_wire_seq`); the pump lifts it synchronously and threads it as an
explicit per-task `wire_seq` arg into the per-frame `model_validate` merge. The
notification model gains an OPTIONAL
`wire_seq: int | None` field (`protocol.py`), defaulted `None` so the stdio adapters
(Discord, reference plugin — plain ADR-0025, no seq) and every existing test are
byte-for-byte unchanged. `wire_seq` is carrier metadata, never payload-derived — it
does not weaken the T1/payload-blind invariant (the daemon is the trust boundary, not a
carrier; it is allowed to read its own wire header).

**(b) Advance the tracker on the DURABLE commit, not on receipt.** A new host-side
`BoundedSeqAckTracker` (reuse `gateway/_seq_tracker.py` — same bounded out-of-order
window, same memory-DoS defence; it is leg-agnostic and the daemon's inbound is exactly
the "always-up receive leg" it was built for) lives on the per-adapter inbound wiring
(alongside the `InboundMessageHandler`, one per socket adapter). The tracker
`observe(wire_seq)` is called **immediately after a successful `commit_once`** in
`process_inbound_message`, i.e. the `True` branch of the G0 gate (`inbound.py:464`),
BEFORE the rest of the pipeline runs (resolve → burst → extract → ingest → dispatch).
On the `False` (replay/duplicate) branch — and on the structural refusals AHEAD of the
gate (cheap-validate, promoter-required) — the tracker is NOT advanced. This makes the
ack mean "highest contiguous seq the core has DURABLY ACCEPTED", which is precisely
spec §4's durable-intake ack and decision 4's commit point.

**(c) Ride the real ack out.** The daemon's outbound `send` is one-directional JSON-RPC
and `a=0`-hardcoded, so do NOT try to retrofit a real ack onto every `send_request`
(that would couple the dispatch-reply path to the inbound-seq tracker and muddle the
two directions). Instead emit a **periodic standalone cumulative-ack frame** from the
socket adapter: a small supervised timer task (mirroring ADR-0032 Decision 3's
"coalesced — piggyback + bounded timer; no standalone ack per data frame") that, on a
bounded interval, sends one lifecycle-style notification
(`daemon.comms.ack`, `params={"cumulative_ack": tracker.cumulative_ack()}`) via
`runner.send_notification` whenever the high-water has advanced since the last emit.
The gateway's core-link router already has the seam to consume it: `_route_unit`
(`core_link.py:680`) peeks the method; add `daemon.comms.ack` to the CONSUMED set
(alongside the two `daemon.lifecycle.*` frames) and **(in G4b-2a)** route its
`cumulative_ack` to the buffer's `trim_to_ack` (this design §5). **In G4b-2a-pre the
gateway consume is drop-only** (a `log.debug` no-op) — the `trim_to_ack` wiring lands
with the buffer in G4b-2a, per the §9.5/§9.7 split. This keeps the gateway payload-blind
— the ack frame is a control frame the gateway consumes, never a relayed body.

  *Why a standalone ack frame over piggybacking on the dispatch reply:* the dispatch
  `outbound.message` reply is a per-message JSON-RPC RESPONSE; it (i) is not emitted for
  inbound messages that don't produce an outbound (binding requests, dropped/capped
  frames, T3-promotion-only turns), so it cannot carry a regular ack heartbeat, and
  (ii) putting an `ack=` on it means re-plumbing `send_request` to carry a caller-owned
  ack like the gateway's `send_payload_unit` — a wider change for a worse cadence
  (ack only when a reply happens). The standalone timer gives a steady, message-rate-
  independent ack that drains the buffer on a quiet-but-healthy link too. The bounded
  timer is the coalescing ADR-0032 Decision 3 already prescribes.

### 9.4 Async/ordering — where exactly `observe` slots in, and why it stays correct

`commit_once` runs at the TOP of the inbound pipeline, before any side effect
(`inbound.py:452-476`), and the spec requires the ack be "decoupled from the core's
existing out-of-order dispatch fan-out" (spec §4 line 45). The inbound notifications are
dispatched as independent background tasks (`comms_runner._spawn_notification_dispatch`,
`comms_runner.py:586-598`) — the runner does NOT process them in strict order, so two
inbound frames `seq=k` and `seq=k+1` can reach their `commit_once` in EITHER order.

`BoundedSeqAckTracker.observe` is exactly built for this: it is order-INSENSITIVE within
its window. `observe(k+1)` before `observe(k)` records the hole and `cumulative_ack`
stalls at `k-1`; `observe(k)` later fills it and the high-water jumps to `k+1` (the
`while (high+1) in seen` advance loop, `_seq_tracker.py:83-84`). So the **contiguous**
ack is correct regardless of dispatch-fan-out order — it advances only over the unbroken
durably-committed run, never past a not-yet-committed gap. This is the same contiguous-
ack semantic the gateway's core tracker already relies on for the reverse direction.

The one concurrency precondition: `observe` mutates a shared set, and the dispatch tasks
run concurrently on one event loop. `observe` is pure-CPU (no `await`), so it is atomic
w.r.t. the single-threaded loop — no lock needed, as long as the `commit_once`→`observe`
pair is not split by an `await`. It is not: place `tracker.observe(wire_seq)` on the
line immediately after the `commit_once` returns `True`, before the next `await`. (If a
future refactor inserts an `await` between them, a per-adapter `asyncio.Lock` around the
commit+observe pair restores atomicity — noted as a constraint, not needed today.)

One further subtlety the blocker flags: keep the per-connection G2 `SeqDedupWindow`
(decision 4, `(leg, seq)` wire-dedup) DISTINCT from this cross-restart durable ack. The
G2 window — were it ever wired on the daemon's receive leg — would dedup re-seen wire
seqs WITHIN one connection; the durable G0 commit dedups the `inbound_id` ACROSS
restarts. They answer different questions (wire-replay-within-a-leg vs accepted-once-
ever) and must not be conflated. The host-side `BoundedSeqAckTracker` here is neither —
it is purely the ack-VALUE source (it reports no dedup verdict; it only advances a
high-water on a commit the G0 store already adjudicated).

### 9.5 Blast radius + test surface — a clean standalone daemon PR

This is a self-contained daemon/host PR with **no gateway change** and **no
client→core wire change** (the gateway already sends seq-framed inbound; the daemon
simply starts observing the seq and emitting a real ack). It is independently valuable
and provable on the daemon alone, so it lands as **G4b-2a-pre** BEFORE the gateway
buffer wiring (G4b-2a), which then consumes the real ack it produces.

Touch list (all under `src/alfred/comms_mcp/` + `src/alfred/cli/daemon/` +
`src/alfred/plugins/`):

- `protocol.py` — optional `wire_seq: int | None = None` on `InboundMessageNotification`.
- `comms_socket_transport.py` — expose the decoded `frame.seq` to the inbound wiring
  (a `last_received_seq` slot or the `read_payload_unit`-based pump path of §9.3a).

- `inbound.py` / `handlers.py` — inject the host-side `BoundedSeqAckTracker`; call
  `observe(notification.wire_seq)` on the `commit_once == True` branch only.

- `_commands.py` (`_listen_socket_comms_adapter` / `_build_comms_adapter_wiring`) —
  construct the per-adapter tracker; schedule the bounded standalone-ack timer task
  (supervised; reaped on `_CommsBootGraph.aclose`).

- `core_link.py` — add `daemon.comms.ack` to `_route_unit`'s consumed set (the gateway
  half of the loop; arguably belongs in G4b-2a where `trim_to_ack` is wired, but the
  CONSUME-don't-relay routing is cheap to land here so the daemon's frame is not
  mis-relayed to the client as an opaque body in the interim).

Tests (unit, all daemon-side, no gateway):

- a sequence of inbound `wire_seq=0,1,2` each committing → the emitted standalone-ack
  frame carries `cumulative_ack=2`.

- a REPLAYED `inbound_id` (commit_once → False) carrying a fresh wire seq does NOT
  advance the ack (it never reaches `observe`); a duplicate wire seq with an
  already-committed id likewise does not double-advance.

- a GAP in the inbound seq stream (`0,1,3`) stalls the ack at `1` until `2` arrives +
  commits, then jumps to `3` — the contiguous-ack property under out-of-order dispatch.

- the ack timer emits only when the high-water advanced (no redundant frames on a quiet
  link); it is reaped on shutdown (no leaked task).

- `daemon.comms.ack` is CONSUMED by the gateway's `_route_unit`, never relayed to the
  client (extend the merged route-unit test).

### 9.6 ADR-0032 implication

Fold into the §6 amendment this design already owes. ADR-0032 Decision 3 currently
reads "The transport carries `a=0` and consumes no ack … the G3 relay wires
[`cumulative_ack`] as the ack source AND owns the coalescing timer". Two corrections:

- The ack SOURCE for the **client→core (inbound) direction** is the **daemon/core's**
  durable-intake `BoundedSeqAckTracker` advanced on the G0 `commit_once`, NOT a gateway
  tracker — the gateway is the SENDER of inbound, so it cannot ack its own frames; the
  core is the receiver and the only party that knows what it durably intook. The G3
  relay owns the ack for the REVERSE (core→client) direction (its `_client_tracker`);
  this G4b-2a-pre adds the inbound-direction ack source the core owns.

- The ack is carried on a **standalone, timer-coalesced `daemon.comms.ack` control
  frame** the daemon emits and the gateway CONSUMES (not a payload ride on the dispatch
  reply) — record the new method name in the consumed-control-frame vocabulary
  alongside `daemon.lifecycle.{ready,going_down}`. This is the concrete shape of
  Decision 3's "coalesced (piggyback + bounded timer)" for the inbound leg.

### 9.7 Decomposition — the revised chain

```
G4b-2-pre  (seq-ownership contract; MERGED/ready — gateway mints + carries the seq)
   → G4b-2a-pre  (DAEMON: durable-intake BoundedSeqAckTracker + observe-on-commit_once
                  + standalone daemon.comms.ack timer; gateway _route_unit consumes it)
   → G4b-2a   (GATEWAY: ReplayBuffer append + trim_to_ack(real ack) + back-pressure)
   → G4b-2b   (GATEWAY: reconnect-replay — the resume)
```

Each link is green, reviewer-gated, and holdable-in-head: 2a-pre is daemon-only and
proven on the daemon; 2a consumes the ack 2a-pre emits and proves the buffer drains on
a healthy link + bounds on a wedged one; 2b adds resume. The §6(d) wedged-flood and
§6(b) crash-pre-ack adversarial proofs stay on 2a and 2b respectively.

### 9.8 Recommendation (decisive)

**Yes — the daemon ack-emission is a separable PR (G4b-2a-pre) that MUST land before
the gateway buffer wiring (G4b-2a).** Without it the gateway's `trim_to_ack(frame.ack)`
is `trim_to_ack(0)` forever and the buffer breaker trips on a healthy steady-state link,
so the gateway-side trim is untestable-as-correct and the buffer is functionally broken;
sequencing the daemon ack first makes 2a's "drains on a healthy link" assertion real.

**There is NO simpler existing ack signal I missed.** I searched the daemon outbound and
confirmed every core→client frame is `a=0` (`comms_socket_transport.py:343`, the
hardcoded placeholder), there is no daemon-side receive tracker (the only
`BoundedSeqAckTracker` instances are the gateway's `_core_tracker`/`_client_tracker`),
and the JSON-RPC dispatch reply carries no ack field. The durable G0 `commit_once`
(`inbound.py:464`) is the right and only ack POINT (it is already the cross-restart
exactly-once authority), but it currently advances nothing observable. The minimal
correct move is the three-part mechanism of §9.3: carry the wire seq inward, advance a
host-side bounded tracker on the durable commit, and emit a timer-coalesced standalone
`daemon.comms.ack` the gateway consumes. It is small, daemon-local, security-neutral
(carrier-metadata seq, no payload parse, reuses the existing bounded tracker), and it
turns the §5 `trim_to_ack` from a no-op into the real durable-intake drain the resume
guarantee needs.
