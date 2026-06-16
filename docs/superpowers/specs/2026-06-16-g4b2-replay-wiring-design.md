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

Three PRs, each green and reviewer-gated. Adversarial entries (spec §6 b/d, §9
release-blocking) land with the behaviour they test.

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

### G4b-2a — buffer append + ack-trim + back-pressure

- **Ships:** `ReplayBuffer` injected into `GatewayCoreLink`; `append` in `relay_to_core`
  (append-before-send); `trim_to_ack` driven from `frame.ack` in `_route_unit`;
  `breaker_tripped` → `BREAKER_TRIPPED` feed → `link.unavailable` + audit; client
  read-halt in `_client_to_core_pump`; `evict_expired` timer + per-seq input-loss
  audit; `reset_for_new_epoch()` added to the buffer.
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
as three reviewer-gated PRs (pre-seq-ownership → 2a buffer+backpressure → 2b
reconnect-replay) with the §6 wedged-flood and crash-pre-ack adversarial entries as the
release-blocking proof.
