# G3-3b-2 — Gateway Opaque Relay + `alfred gateway` Process Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Steps use `- [ ]`. This is the second half of G3-3b (parent: `2026-06-15-g3-3b-gateway-core-link-relay.md`; **G3-3b-1 / #272 is MERGED** — `GatewayCoreLink` (peer-handshake, epoch-reconcile forgery defense, reconnect/backoff, `run()` pump), `dial_comms_socket` dial-side peer-auth, the gateway metrics + `_control_frames` helper are on `main`). Because the relay engine + the runnable process is large, **G3-3b-2 is split into two PRs**: **G3-3b-2a** (the opaque relay engine — detailed below, full TDD) and **G3-3b-2b** (the `alfred gateway` process + CLI — scope-fixed, detailed against 2a's merged reality). Both are trust-boundary PRs (always-up T1 carrier).

**Goal:** Make the gateway a payload-blind, byte-for-byte relay between the dial-in client (the TUI) and the core, closing #237 graduation criterion #7 (a real `alfred chat` turn round-trips through the resumable front door).

**Architecture:** The relay terminates seq/ack independently on each leg (the gateway is the **first real `AlfredSeqAck/1` peer** — it deframes a core-leg unit and reframes it onto the client leg with the client leg's own monotonic `seq`, so the client-leg counter survives a core restart). It forwards the **opaque ADR-0025 payload bytes byte-for-byte** (never `json.loads`-ing the body — T3 stays in the core, hard rule #5), parsing only the JSON-RPC `method` to ROUTE: a `daemon.lifecycle.*` frame is CONSUMED (fed to the merged `GatewayCoreLink` link-state machine → a `link.*` control frame to the client); everything else is RELAYED. There is **no buffering** — a frame in flight across a core gap is dropped (G4's `ReplayBuffer` adds resume). The core leg reconnects (the merged `GatewayCoreLink` reconnect machinery); the client connection is held single-accept-for-life across the gap.

**Tech Stack:** Python 3.12+, asyncio, AF_UNIX, Pydantic v2, structlog, prometheus_client, pytest + hypothesis, mypy --strict + pyright.

---

## G3-3b-2 sub-epic decomposition

| PR | Scope | Trust-boundary? |
|----|-------|-----------------|
| **G3-3b-2a** | The **opaque relay engine**: the codec-level opaque-payload transport seam (`read_payload_unit`/`send_payload_unit` on `CommsSocketTransport`); a `GatewayCoreLink` extension so its pump reads RAW units + routes (lifecycle→consume, payload→a relay sink) instead of dropping; the `GatewayRelay` (`src/alfred/gateway/relay.py`) — two pumped directions sharing a core-leg holder, per-leg bounded `SeqDedupWindow` supplying the real `cumulative_ack()`, no buffering; the **non-root in-process wire-contract test** (#245 paper-gate hazard) + the **payload-blindness canary test** (spec §6 corpus (a)). Tested in-process with fake core + client transports. NO process/CLI yet. | Yes — T1 carrier wire-trust. |
| **G3-3b-2b** | The **runnable process**: the client-leg HOST handshake (gateway → TUI `lifecycle.start`, `adapter_id="tui"`); `GatewayProcess` (`src/alfred/gateway/process.py`) — bind the client listener, accept the TUI, run the client handshake, wire `GatewayCoreLink` + `GatewayRelay`, supervise in an `asyncio.TaskGroup` with a shared `shutdown_event`, reap every transport + the listener on every exit; the `gateway_peer_auth_rejected_total` metric (wire the client listener's `on_peer_rejected`); the `alfred gateway` CLI (`src/alfred/cli/gateway/`) + `src/alfred/gateway/__main__.py`. | Yes — always-up T1 carrier. |

**Deferred (NOT G3-3b-2):** `ReplayBuffer`/resume/cap/TTL/breaker/back-pressure/zeroing + the durable signed gateway-local audit reconcile (G4); the Compose service + long-running core daemon + shared-volume socket relocation (G3-4); re-pointing `alfred chat` from `comms-tui.sock` → `comms-gateway.sock` + the PTY smoke (G5); egress proxy (Spec C).

---

## Design notes (read before any task)

### The real TUI is PLAIN — the client leg does NOT negotiate seq/ack (plan-review CRITICAL C1/C2)

The merged TUI **never speaks `AlfredSeqAck/1`**: `plugins/alfred_tui/src/alfred_tui/server.py` returns `LifecycleStartResult(ok=True, plugin_version=...)` with NO `seq_ack`, and nothing in `plugins/alfred_tui/` calls `enable_seq_ack`. So **in production the gateway↔TUI leg is plain ADR-0025; only the gateway↔core leg negotiates seq/ack.** The relay therefore supports BOTH per-leg (each transport is seq-gated by its own `_seq_ack_enabled` flag): the **plain-client path is the PRIMARY tested path** (it is the only one that runs against the real TUI today); the **seq-enabled-client path is forward-looking** (G4/G5 may upgrade the TUI for resume). Consequences that reshape the design:

- **`read_payload_unit` must surface the seq, not just bytes** — change the seam return to `read_payload_unit() -> SeqFrame | None` (the merged `SeqFrame` carries `seq` (`None` on a plain line) + `ack` + `payload`). The relay needs the received `seq` to feed the per-leg ack window; a bare-`bytes` return discards it.
- **A `BoundedSeqAckTracker` exists per SEQ-ENABLED leg only** (the core leg in production). A plain leg has no tracker (no seqs to track). The `ack` the gateway writes ON a leg is **that SAME leg's receive-tracker `cumulative_ack()`** — the ack rides the reverse-flowing frames of the leg it acknowledges (architect H1 — NOT "the other leg's"). On a plain leg `send_payload_unit` emits a plain line with NO header/ack (the `ack` arg is ignored when `_seq_ack_enabled` is False).
- **The across-restart client-leg-seq invariant applies ONLY when the client negotiated seq/ack** (the forward-looking path). With a plain client (production) there is no client-leg seq; the relay just forwards plain lines. Test the monotonic-across-restart invariant in the seq-enabled-client case; test the plain-client forward in the production case.
- **`send_control` + `send_payload_unit` share the client transport's single `_send_seq`+`_send_lock`** (architect H2) — one monotonic stream when the client leg IS seq-enabled; on the plain production leg both emit plain lines (no seq), so no collision. The seam reuses the merged counter+lock, never a parallel one.

### The relay/core-link integration (the crux — confirmed against merged code)

The merged `GatewayCoreLink.run()` (`src/alfred/gateway/core_link.py`) is a self-contained pump: it `_read_frame_or_shutdown` (PARSED `read_frame`) → `_consume_frame` (lifecycle→feed; everything else `_dropped_payload_frames += 1`) → reconnect on a gap (`_reconnect_closing` / `_initial_connect` / `_reconnect`, all reused unchanged). For byte-for-byte relay the pump must instead read RAW payload units and ROUTE them. The integration (minimal, reuses ALL the reconnect machinery):

- **Add a raw-unit seam to the transport.** `CommsSocketTransport.read_payload_unit() -> SeqFrame | None` returns the merged `SeqFrame` (carrying `seq`/`ack`/`payload`; `seq=None` on a plain line via `decode_seq_frame`'s magic-gated fallback) WITHOUT `json.loads`-ing the payload bytes; `None` on clean EOF; the SAME over-bound/malformed loud-failure (`CommsProtocolError`) discipline as `read_frame` — **including the THREE-point bound** the merged `read_frame` enforces (the `readline` `LimitOverrunError` arm, the explicit `len(line) > _max_line_bytes` belt-and-braces, AND `decode_seq_frame`'s `max_unit_bytes` re-check). `read_payload_unit` and `read_frame` MUST SHARE one private read+bound+seq-deframe helper (one returning `.payload` via `json.loads`, the other the raw `SeqFrame`) so a future bound-fix patches both (architect M1). `send_payload_unit(payload: bytes, *, ack: int)` reseq-frames the bytes with this leg's `_send_seq` + the supplied real `ack` (the merged `send()` hard-codes the `a=0` placeholder — the seam MUST take `ack`), under the existing `_send_lock`; on a seq-DISABLED transport it emits a plain `payload + b"\n"` and ignores `ack`. **Reframe ceiling (comms H3):** the reframed unit is `header + payload + \n`, so the effective payload ceiling is `max_unit_bytes - _MAX_HEADER_BYTES` (the codec's documented reservation). A payload at the core-leg ceiling that arrived plain (no header) can OVERFLOW when reframed with a client-leg header — `encode_seq_frame` raises `CommsProtocolError`; the relay must treat that as a loud drop (test the boundary payload), NOT crash the relay task.
- **`GatewayCoreLink` grows a relay sink.** A new ctor param `payload_relay: Callable[[bytes], Awaitable[None]] | None = None`. When set, the pump reads RAW (`read_payload_unit`) and routes: peek `method` (see below); a `daemon.lifecycle.*` method → `_consume_frame(parsed)` (the merged lifecycle/feed path); anything else → `await self._payload_relay(raw_bytes)` (forward the ORIGINAL bytes). When `payload_relay is None` (the 3b-1 behaviour) the pump stays exactly as merged (parsed `read_frame` + drop) — so the merged 3b-1 tests are unaffected. The reconnect machinery (`_reconnect_closing` etc.) is REUSED verbatim — only the per-frame read+route changes.
- **The `GatewayCoreLink` exposes its current transport for the reverse direction.** The client→core direction (the other relay leg) must write to the CURRENT core transport, which the reconnect swaps. Add `async def relay_to_core(self, payload: bytes) -> None` that sends to the link's current core transport via `send_payload_unit` with the core-leg window's `cumulative_ack()`; on a `(BrokenPipeError, ConnectionResetError)` (the core gapped mid-write) it DROPS the frame loud (no buffering — the core→client pump owns the reconnect; G4 buffers). The link holds the current transport reference (it already does in `run()`); expose it through this method so the relay never touches a stale FD.

### Routing peek — fail TOWARD relay (security SEC-3, hard rule #7)

To distinguish a consumed `daemon.lifecycle.*` frame from a relayed payload frame, the relay parses a COPY of the raw bytes for the `method` ONLY — it never reads/acts on the body. The parse runs on attacker-controlled T3 bytes (size-bounded by `_MAX_COMMS_LINE_BYTES`, not depth-bounded), so it is wrapped `try/except (json.JSONDecodeError, ValueError, RecursionError)`; on ANY parse failure, the frame is **relayed as opaque** (forward the original bytes), NEVER dropped and NEVER consumed — a frame the gateway cannot route is the core's parser's problem, not the gateway's. A frame with **no `method`** (a JSON-RPC RESPONSE, `id`-only — core→client) is ALSO relayed. Only an explicit `DAEMON_LIFECYCLE_READY`/`DAEMON_LIFECYCLE_GOING_DOWN` method is consumed.

### Two directions + the core-transport swap + no buffering

`GatewayRelay` runs two pumped directions concurrently (an `asyncio.TaskGroup`, supervised by `GatewayProcess` in 2b):

- **core→client**: this IS the `GatewayCoreLink` pump (with `payload_relay` = the client-send sink). It owns the core-leg read + the reconnect; it feeds the **core-leg** receive tracker `accept(frame.seq)` (when the core leg is seq-enabled, which it is in production) and on a payload frame calls the sink which does `client_transport.send_payload_unit(raw, ack=<client-leg tracker>.cumulative_ack())` — the ack is the SAME (client) leg's receive high-water (architect H1; on the plain production client leg there is no client tracker, so `send_payload_unit` emits a plain line and the `ack` arg is moot). The client-leg `seq` (when negotiated) keeps climbing across a core reconnect because the CLIENT transport is never replaced (single-accept-for-life) — only the core transport is.
- **client→core**: a loop reading `client_transport.read_payload_unit()` → `core_link.relay_to_core(raw)`, which writes to the link's CURRENT core transport with `ack=<core-leg tracker>.cumulative_ack()`. **This leg does ZERO body parse** (the client never sends a `daemon.lifecycle.*` frame the gateway consumes) — pure opaque forward (security H3; assert no `json.loads` on this path). On client EOF the relay ends (the client hung up). **Swap-atomic + post-handshake-only (architect M3 / security M2):** `relay_to_core` snapshots `self._current_transport` into a LOCAL once and writes through that local, so a reconnect swapping the reference mid-method writes to the captured (old, closing) transport → a clean `BrokenPipeError`/`ConnectionResetError`/closed-state → **loud DROP** (no buffering — the core→client pump owns the reconnect; G4 buffers). The merged `_reconnect` only `return`s a transport AFTER `_peer_handshake` + `enable_seq_ack`, so the link exposes the core transport reference only post-handshake — a reverse write never reaches a pre-handshake leg. The drop-arm catches `(BrokenPipeError, ConnectionResetError)` AND a closed/`None` transport; widen it if the reconnect-race write test surfaces another post-close raise (e.g. `RuntimeError`).
- **`BoundedSeqAckTracker` (NEW, in `relay.py` — do NOT mutate the merged `SeqDedupWindow`; architect M2 + security H2):** the relay needs only the contiguous-high-water `cumulative_ack()`, NOT the merged window's replay-dedup `_seen` (pruning `_seen` would break the merged class's documented "idempotent `accept()`" contract that other call sites rely on). So `relay.py` owns a small `BoundedSeqAckTracker` that tracks `_contiguous_high` + a **bounded** out-of-order gap set: a `seq` more than `_MAX_OOO_GAP` (e.g. 1024) beyond the contiguous high-water is REJECTED loud (`gateway.relay.seq_out_of_window`) rather than admitted — closing the every-other-seq adversary (a stream `0,2,4,…` that never fills the gap would otherwise grow the gap set unbounded; pruning-below-high-water does NOT bound this because the holes are all ABOVE the high-water). The core is the same-uid daemon (trusted, behind dial-side peer-auth), so this is defense-in-depth + protection against a buggy core. Test the every-other-seq stream stays bounded.
- **Send-seq exhaustion (security M1):** the gateway's own monotonic `_send_seq` is capped by `encode_seq_frame`'s `_MAX_DECIMAL_WIDTH` guard (~10^8 frames ≈ 27 h at 1/ms), past which `encode_seq_frame` raises `ValueError`. A `ValueError` escaping a relay task is a hard-rule-#7 silent-failure shape — so `send_payload_unit`/the relay must catch it loud (`gateway.relay.seq_exhausted`) and treat it as a fatal leg error (refuse, not wrap — a wrap would replay seqs). Document the ceiling as acceptable-for-G3 with a G4 follow-up (resume resets the epoch+seq on reconnect anyway). **Forged-ack defense:** the gateway computes its OWN ack from its OWN receive tracker; it NEVER trusts the peer's `ack` field for any advancement — state this as the defense.

### Client-leg handshake — `adapter_id="tui"` (architect HIGH, G3-3b-2b)

The gateway is HOST on the client leg: it sends `lifecycle.start` to the dialed-in TUI. **It MUST send `adapter_id="tui"`, NOT `"gateway"`** — the merged TUI server does `LifecycleStartRequest.model_validate(params)` and `AdapterId` validates against the `adapter_kind` frozenset `{"alfred_comms_test","discord","tui"}`; `"gateway"` is not a member, so a `{adapter_id:"gateway"}` handshake fails `ValidationError` and the relay never comes up. The gateway transparently stands in for the daemon toward an unmodified TUI that only knows the kind `"tui"`. Enable client-leg seq/ack ONLY iff the TUI echoes `seq_ack` (half-negotiated is a corruption surface — SEC-6b negative test: TUI omits `seq_ack` → gateway stays plain on that leg, relay still works).

---

## PR G3-3b-2a — The opaque relay engine (TDD)

**Goal:** A complete, in-process-tested relay engine: opaque byte-for-byte forwarding both directions, lifecycle interception, per-leg reseq with the real ack, no buffering, reconnect-coordinated. Tested with fake core + client transports — NO process/CLI.

### Files

- Modify: `src/alfred/plugins/comms_socket_transport.py` — `read_payload_unit` / `send_payload_unit` + their `__all__`.
- Modify: `src/alfred/gateway/core_link.py` — the `payload_relay` sink + raw-unit routing pump + `relay_to_core`.
- Create: `src/alfred/gateway/relay.py` — `GatewayRelay` (the two-direction engine + the bounded per-leg windows).
- Modify: `src/alfred/gateway/__init__.py` — export `GatewayRelay`.
- Modify: `docs/adr/0032-gateway-comms-resume-transport.md` — the relay/payload-blind/reseq/no-buffering contract.
- Test: `tests/unit/plugins/test_comms_socket_transport.py` (extend: the raw-unit seam).
- Test: `tests/unit/gateway/test_core_link.py` (extend: the `payload_relay` routing + `relay_to_core`).
- Test: `tests/unit/gateway/test_relay.py` (the engine: byte-for-byte, both directions, reseq, no-buffering-drop, reconnect).
- Test: `tests/unit/gateway/test_relay_wire_contract.py` (the non-root in-process wire-contract + the payload-blindness canary).

### Tasks

- [ ] **Task 1: opaque-payload transport seam (TDD)**

**Files:** `src/alfred/plugins/comms_socket_transport.py`; Test: `tests/unit/plugins/test_comms_socket_transport.py`.

- [ ] Step 1 — failing tests over a loopback `CommsSocketListener`/`dial_comms_socket` pair (the existing test idiom). The seam returns `SeqFrame | None` (carrying `seq`/`ack`/`payload`):
  - seq DISABLED (the PRODUCTION client leg): `send_payload_unit(b'{"x":1}', ack=0)` writes a PLAIN line (no header); `read_payload_unit()` on the peer returns a `SeqFrame(seq=None, ack=None, payload=b'{"x":1}')`;
  - seq ENABLED (the core leg): `send_payload_unit(b'{"x":1}', ack=5)` writes a unit whose decoded `SeqFrame` has the sender's `seq` (monotonic per send) + `ack=5` + `payload == b'{"x":1}'` byte-for-byte; `read_payload_unit()` returns `SeqFrame(seq=<n>, ack=5, payload=b'{"x":1}')` WITHOUT `json.loads` (assert it round-trips a payload that is NOT valid JSON, e.g. `b'\\x00not-json'` — proving no parse);
  - **MIXED-WIRE (comms H2):** a seq-ENABLED `read_payload_unit` reading a PLAIN line (an un-upgraded peer) returns `SeqFrame(seq=None, ...)` via the magic-gated fallback — does NOT raise (mirrors merged `read_frame`);
  - **the three-point bound (security H1):** an over-bound unit raises `CommsProtocolError` from EACH arm — the over-limit `readline`, the exactly-at-limit `len(line)` belt-and-braces, and a `decode_seq_frame` mismatch;
  - **reframe ceiling (comms H3):** `send_payload_unit` of a payload at `max_unit_bytes` (no room for the header) raises `CommsProtocolError` (the `cap - _MAX_HEADER_BYTES` reservation);
  - clean EOF → `read_payload_unit()` returns `None`.
- [ ] Step 2 — run, expect FAIL.
- [ ] Step 3 — implement on `CommsSocketTransport`: extract the merged `read_frame`'s read+bound+seq-deframe into ONE private helper returning a `SeqFrame` (architect M1); `read_frame` = that helper + `json.loads(frame.payload)`, `read_payload_unit` = that helper verbatim (returns the `SeqFrame`). `send_payload_unit(payload, *, ack)` mirrors `send` but takes pre-serialized bytes + the supplied `ack` (not the `a=0` placeholder) under `_send_lock`, incrementing `_send_seq` (seq on) or emitting `payload + b"\n"` (seq off, `ack` ignored). Add both to `__all__`.
- [ ] Step 4 — run, expect PASS. Step 5 — commit (`feat(comms): opaque read_payload_unit/send_payload_unit seam for the gateway relay (Spec A G3-3b-2 / ADR-0032) (#237)` + trailer).

- [ ] **Task 2: `GatewayCoreLink` raw-unit relay sink + `relay_to_core` (TDD)**

**Files:** `src/alfred/gateway/core_link.py`; Test: `tests/unit/gateway/test_core_link.py`.

- [ ] Step 1 — failing tests (the fake `_CommsTransportLike` grows `read_payload_unit`/`send_payload_unit`):
  - with `payload_relay` set: the pump on a payload frame (`{"method":"inbound.message",...}` as raw bytes) calls the sink with the ORIGINAL bytes byte-for-byte (NOT a re-serialization); a `daemon.lifecycle.going_down` raw frame is still CONSUMED (feeds the machine → `reconnecting`), NOT relayed; a parse-failure raw frame (`b'\\x00garbage'`) is RELAYED (sink called), never consumed/dropped (SEC-3 fail-toward-relay); a no-`method` response frame (`{"id":7,"result":{}}`) is relayed;
  - with `payload_relay=None` (merged behaviour): the pump still uses parsed `read_frame` + drops (the existing 3b-1 tests still pass — run them);
  - `relay_to_core(b'...')` sends via the current transport's `send_payload_unit` with the core-leg window's `cumulative_ack()`; a `BrokenPipeError` mid-write DROPS loud (`gateway.relay.core_send_dropped`) without raising (no buffering).
- [ ] Step 2 — run, expect FAIL.
- [ ] Step 3 — implement: `__init__` gains `payload_relay`; add `read_payload_unit` to the local `_CommsTransportLike` Protocol; the pump branches on `payload_relay` (raw-route when set, parsed-drop when None); `_route_unit(raw)` peeks method (fail-toward-relay) → `_consume_frame(parsed)` or `await self._payload_relay(raw)`; `relay_to_core` + a core-leg `SeqDedupWindow` (the receive side feeding `cumulative_ack`). Keep the reconnect machinery untouched.
- [ ] Step 4 — run, expect PASS. Step 5 — commit (`feat(gateway): GatewayCoreLink raw-unit relay sink + relay_to_core (Spec A G3-3b-2 / ADR-0032) (#237)` + trailer).

- [ ] **Task 3: `GatewayRelay` — two directions + bounded windows (TDD)**

**Files:** `src/alfred/gateway/relay.py`, `src/alfred/gateway/__init__.py`; Test: `tests/unit/gateway/test_relay.py`.

- [ ] Step 0 — `BoundedSeqAckTracker` (TDD, its own test): tracks `_contiguous_high` + a bounded out-of-order gap set; `observe(seq) -> None` rejects loud (`gateway.relay.seq_out_of_window`) a seq more than `_MAX_OOO_GAP` (1024) beyond the high-water; `cumulative_ack() -> int` is the contiguous high-water. Test: the every-other-seq stream `0,2,4,…` stays bounded (the gap set never exceeds the cap, far-out seqs rejected); contiguous fills advance the high-water.
- [ ] Step 1 — failing tests with fake core + client transports. The PRIMARY path is **core seq-ENABLED, client seq-DISABLED** (production); a SECONDARY suite runs seq-enabled-both (forward-looking):
  - **byte-for-byte both directions:** a client→core payload is delivered to the core's `send_payload_unit` with the ORIGINAL bytes; a core→client payload likewise; the inner JSON-RPC `id` survives (assert the bytes contain the same `"id":` run);
  - **the core-leg ack is real (production):** the gateway's writes TO the core (`relay_to_core`) carry `ack = <core-leg tracker>.cumulative_ack()` (what the gateway received from the core); the plain client leg carries no ack;
  - **reseq proves reframe, not pass-through (comms M3, seq-enabled-both suite):** the client-leg sent header's `seq` DIFFERS from the core-leg received header's `seq` for the same payload (the gateway re-sequenced; it did not forward the core's header verbatim);
  - **client→core does ZERO body parse (security H3):** spy that no `json.loads` runs on the client→core path;
  - **bounded tracker:** the core-leg tracker stays bounded under a long contiguous stream (Step 0's `BoundedSeqAckTracker`, not the merged `SeqDedupWindow`);
  - **no buffering across a gap + reconnect-race write (architect M3):** a client→core frame written while the core leg is gapped (the fake core `send_payload_unit` raises `BrokenPipeError`, or the transport is mid-swap/closed) is DROPPED loud (`gateway.relay.core_send_dropped`), not buffered/retried/crashed; and the core-leg tracker's `cumulative_ack()` STALLS at the gap (not advanced past the dropped seq) — the observable proof the drop is accounted;
  - **across-restart seq climb (seq-enabled-client suite only):** drive a core gap+reconnect (the fake core EOFs then a fresh transport, whose `_send_seq` resets to 0 — the core is a fresh peer each dial, M1 asymmetry); assert the CLIENT-leg `seq` keeps climbing monotonically across the reconnect (the client transport is never replaced) while the core-leg seq resets;
  - **`_dropped_payload_frames` meaning (security L2):** with `payload_relay` set, a lifecycle frame is consumed (not relayed, NOT counted as dropped) — the counter's meaning doesn't drift.
- [ ] Step 2 — run, expect FAIL.
- [ ] Step 3 — implement `GatewayRelay(core_link, client_transport, ...)`: a `BoundedSeqAckTracker` per seq-enabled leg; wires `core_link.payload_relay` = a sink that `client_transport.send_payload_unit(raw, ack=self._client_tracker.cumulative_ack() if client_seq else 0)`; the core-receive side feeds `self._core_tracker.observe(seq)`; runs `core_link.run()` (core→client incl. reconnect) + a `_client_to_core_pump()` (`client_transport.read_payload_unit()` → `core_link.relay_to_core`) as two tasks. Export `GatewayRelay` + `BoundedSeqAckTracker`.
- [ ] Step 4 — run, expect PASS. Step 5 — commit (`feat(gateway): GatewayRelay — two-direction opaque relay with per-leg reseq + bounded windows (Spec A G3-3b-2 / ADR-0032) (#237)` + trailer).

- [ ] **Task 4: non-root wire-contract test + payload-blindness canary (TDD)**

**Files:** Test: `tests/unit/gateway/test_relay_wire_contract.py`.

- [ ] Step 1 — failing tests (the #245 paper-gate fix — an in-process, NON-root proof of the wire contract, no launcher gate). Use a **REAL `GatewayClientListener`** over a real loopback client transport (architect L3 — a fake listener would not prove the control-frame-interleaved-with-payload property):
  - **wire-contract (PRODUCTION: core seq-on, client seq-off):** an in-process gateway (real `GatewayCoreLink` + `GatewayRelay` + real `GatewayClientListener`) between a fake-core and a fake-client over real loopback `CommsSocketTransport`s exercises the FULL deframe (core) → forward (client) relay both directions + a core reconnect + a `going_down`→`reconnecting`→`restored` gap, asserting: byte-for-byte payloads, the §9 control-frame sequence ON the client leg, and an interleaved `going_down` consumed mid-payload-stream does NOT corrupt the relay (SEC-3b);
  - **reseq proof (comms M3, seq-on-both suite):** in the forward-looking seq-enabled-client variant, assert the client-leg sent `seq` ≠ the core-leg received `seq` for the same payload (proves reframe), and the client-leg seq stays monotonic across the core reconnect;
  - **payload-blindness canary (spec §6 corpus (a)):** a payload bearing a canary-T3 token is relayed client→core; assert the bytes the fake-core receives are byte-identical to what the fake-client sent (no re-serialization), the gateway never `json.loads`'d the body, AND the canary token NEVER appears in any gateway structlog row or metric label (security L3 — the T1 carrier leaks no T3 even on its observability surface);
  - **forgery + dial-reject on the non-root leg (SEC-6a):** the epoch-mismatch `ready` + a dial peer-auth reject also fire here, not just the happy relay.
- [ ] Step 2 — run, expect FAIL. Step 3 — wire the in-process harness. Step 4 — PASS. (Folds into the Task 3 commit, or its own.)

- [ ] **Task 5: ADR-0032 amendment + CI coverage gate + full gate + open PR**

- [ ] ADR-0032: add a "Opaque relay engine (G3-3b-2a)" subsection — the raw-unit seam, the route-by-method-peek (fail-toward-relay), the per-leg reseq + the bounded-window decision, the no-buffering-drop-on-gap (G4 buffers), the across-restart client-leg-seq invariant, and the payload-blind T1-carrier posture (the canary trips only in the core). MD032-clean.
- [ ] Add `src/alfred/gateway/relay.py` to BOTH gateway per-file 100%-coverage gates in `ci.yml` (python-job + combined), keeping them symmetric (the `_control_frames.py` + `core_link.py` + `metrics.py` precedent). `read_payload_unit`/`send_payload_unit` are on the already-gated `comms_socket_transport.py`.
- [ ] `uv run ruff check . && uv run ruff format --check . && uv run mypy src/ && uv run pyright src/ && uv run pytest tests/unit/gateway tests/unit/plugins/test_comms_socket_transport.py -q && npx markdownlint-cli2@0.14.0 docs/adr/0032-gateway-comms-resume-transport.md docs/superpowers/plans/2026-06-15-g3-3b2-gateway-relay-process.md`
- [ ] `make check` (NOT piped through `tail`). Commit the plan + ADR; open the PR; run the FULL `/review-pr` fleet (security ALWAYS — wire-trust + payload-blindness; + error, test, performance, comms, docs, i18n, devex, architect) + CodeRabbit; **resolve every addressed CR thread** (`resolveReviewThread`); auto-merge `gh pr merge <n> --auto --rebase --delete-branch` (NO `--admin`).

### G3-3b-2a acceptance

- The relay forwards payloads byte-for-byte both directions with per-leg reseq + the real ack; the inner `id` survives end-to-end; the gateway never parses a body (canary trips only in the core).
- Lifecycle frames are consumed (not relayed); a parse-failure frame is relayed (fail-toward-relay), never dropped.
- No buffering: a frame in flight across a core gap is dropped; the client-leg seq stays monotonic across the reconnect.
- The non-root in-process wire-contract test proves the seq/ack peer contract (the #245 paper-gate fix).
- New `relay.py` at 100% branch; the transport seam on its gate; `make check` green.

---

## PR G3-3b-2b — The `alfred gateway` process + CLI (scope-fixed; detailed against 2a's merged reality)

**Goal:** Wrap the 2a relay engine in a runnable, supervised process + the operator CLI — the surface that closes #237 criterion #7.

**Key tasks (detailed when 2b is written against 2a's merged kernel):**

- **Client-leg HOST handshake** (`src/alfred/gateway/client_link.py` or a `GatewayProcess` method): send `lifecycle.start` to the dialed-in TUI with `adapter_id="tui"` (NOT `"gateway"` — the merged TUI `AdapterId` validator), `seq_ack:{version:SEQ_VERSION}`, and **NO `epoch`** (comms L2 — the TUI has no epoch concept; the gateway is not the core boot). Read the TUI's `ok` + `seq_ack` echo, `enable_seq_ack()` on the client transport IFF echoed (the half-negotiated negative test, SEC-6b — the REAL merged TUI omits `seq_ack`, so the production path is the plain-client leg). Mirror the merged `comms_runner._handshake` SEND side WITHOUT the session/gate. **`adapter_id` naming table (comms L1 — three distinct uses, do NOT align them):** the client *listener socket* is keyed `adapter_id="gateway"` (the socket FILENAME `comms-gateway.sock`); the client-leg *handshake wire field* is `adapter_id="tui"` (what the TUI's `AdapterId` validator accepts); the core *dial target* is `dial_adapter_id="tui"` (`comms-tui.sock`).
- **Injectable `on_peer_rejected` on `GatewayClientListener` (architect §6 gap):** the merged `GatewayClientListener.__init__` HARDCODES `_structlog_only_peer_rejected` — 2b MUST add a ctor param so `GatewayProcess` injects the metric-incrementing callback. Keep the CALLBACK shape (not a counter — preserves `peer_uid` for the structlog row + the G4 audit row, arch-263-001); the new callback increments `gateway_peer_auth_rejected_total` AND logs `peer_uid`.
- **`GatewayProcess`** (`src/alfred/gateway/process.py`): bind the merged `GatewayClientListener`, accept the TUI (single-accept-for-life), run the client handshake, construct `GatewayCoreLink(client_listener=..., payload_relay=...)` + `GatewayRelay`, supervise the two relay directions in an `asyncio.TaskGroup` with a shared `shutdown_event`; reap every transport + the listener on EVERY exit path (mirror the merged `_CommsBootGraph.aclose` / `CommsSocketListener.aclose` leak discipline). Fail-closed on a client-handshake failure.
- **`gateway_peer_auth_rejected_total`** metric (the 4th, completing the set) + wire the client listener's `on_peer_rejected` to increment it + a loud structlog row (the durable signed reject audit row stays G4 — still no audit sink).
- **`alfred gateway` CLI** (`src/alfred/cli/gateway/__init__.py`, a `gateway_app` typer group registered in `src/alfred/cli/main.py` via `app.add_typer(gateway_app, name="gateway")`) + **`src/alfred/gateway/__main__.py`** (`python -m alfred.gateway`, mirroring the daemon launch). Lazy heavy imports inside the callback (perf-001). `gateway start` (long-running: build + run `GatewayProcess`) + `gateway status` minimum. `t()`-routed operator strings.
- **i18n:** any new operator-facing CLI/process strings through `t()` + the catalog update (`pybabel update -i ... --no-fuzzy-matching` then compile; NEVER `--omit-header`).

**Coverage:** `process.py`/client-handshake 100% branch where trust-bearing; the CLI ≥ the surrounding `cli/` bar.

---

## Self-review (G3-3b-2)

- **Spec coverage:** §6 payload-blind T1 carrier + the canary → Task 4; §7 seq/ack first-real-peer (deframe/reframe both legs) → Tasks 1–3; §4 no-buffer-drop-on-gap → Task 3; §1 single-accept-for-life client across the core gap → the reused merged listener + the across-restart seq test; criterion #7 (a real `alfred chat` turn) → G3-3b-2b's process + CLI. ✓
- **Grounded in merged constants (architect M2):** `GatewayCoreLink` (`run`, `_consume_frame`, `_reconnect_closing`, the `_CommsTransportLike` seam, `payload_relay` extension point), `CommsSocketTransport.send`/`read_frame`/`enable_seq_ack`/`_send_lock`/`_send_seq`, `comms_seq_codec` (`encode_seq_frame`/`decode_seq_frame`/`SeqFrame`/`SeqDedupWindow`), `DAEMON_LIFECYCLE_*`, the merged `GatewayClientListener` + `on_peer_rejected` seam, the TUI `AdapterId` frozenset — all cited. ✓
- **Placeholders:** none in 2a — every task has real signatures/tests/commands. 2b scope-fixed, each item grounded in a merged seam. ✓
- **Type consistency:** `read_payload_unit() -> bytes | None`; `send_payload_unit(payload: bytes, *, ack: int)`; `GatewayCoreLink(..., payload_relay: Callable[[bytes], Awaitable[None]] | None)`; `relay_to_core(payload: bytes)`; `GatewayRelay(core_link, client_transport)` — consistent across tasks 1–4 and forward into 2b. ✓
- **Security posture:** payload-blind (method-only peek, fail-toward-relay, byte-for-byte forward); no buffering (drop-on-gap, no T3 retained); bounded per-leg windows (no OOM on the always-up process); the canary trips only in the core; no audit sink → loud structlog, durable row G4 (stated, not a gap). ✓
- **CR discipline:** Task 5 resolves addressed CR threads (the merge-unblock discipline), not waiting for a re-review. ✓
