# G4b-2a — Gateway ReplayBuffer wiring (append + trim + back-pressure) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire the merged pure `ReplayBuffer` into the live gateway core-leg so un-acked inbound (client→core) frames are buffered, trimmed on the daemon's durable-intake ack, and bounded by a back-pressure breaker that halts the client read and signals `link.unavailable` — the steady-state half of the resume gateway (reconnect-replay is G4b-2b).

**Architecture:** `GatewayCoreLink` gains an injected `ReplayBuffer`. `relay_to_core` appends each inbound frame under its minted seq BEFORE sending (the buffer is the durable record; the send is best-effort). The `daemon.comms.ack` control frame the gateway already consumes (`core_link._route_unit`) now drives `buffer.trim_to_ack`. On a soft-cap breach the breaker latches → the relay's `_client_to_core_pump` ceases draining the client socket (back-pressure) and feeds `GatewayLinkEvent.BREAKER_TRIPPED` → the merged `UNAVAILABLE` escalation → `link.unavailable` + a loud audit row. A bounded timer evicts TTL-expired pre-DLP input (audited per-seq). No reconnect-replay (2b).

**Tech Stack:** Python 3.12+, asyncio, `mypy --strict` + `pyright`, `ruff`, `pytest` + `hypothesis`. Design: `docs/superpowers/specs/2026-06-16-g4b2-replay-wiring-design.md` §5/§7. Prereqs (all merged): `ReplayBuffer` (#277), `BREAKER_TRIPPED`/`UNAVAILABLE` link-state (#278), caller-owned send-seq (#279), `daemon.comms.ack` consume (#280).

---

## Context the engineer needs

**Read first:** the design doc §5 ("Where the buffer hooks into the relay") + §7 (the G4b-2a row), `src/alfred/gateway/replay_buffer.py` (the buffer API), `src/alfred/gateway/core_link.py` (`__init__` ~250-270, `relay_to_core` ~735-790, `_route_unit` daemon-ack consume ~707-717, `_peer_handshake` ~620 where `_client_to_core_seq` resets, `_feed` + metrics ~826-849), `src/alfred/gateway/relay.py` (`_client_to_core_pump` ~157-210), `src/alfred/gateway/link_state.py` (`GatewayLinkEvent.BREAKER_TRIPPED`), `src/alfred/audit/log.py` (the `AuditWriter.append` pattern).

**The merged `ReplayBuffer` API (do not change beyond Task 1):** `append(seq, payload, *, now) -> None` (strictly-increasing seq, monotonic now), `trim_to_ack(cumulative_ack) -> None`, `evict_expired(*, now) -> tuple[int,...]` (returns evicted seqs), `unacked_frames() -> tuple[ReplayFrame,...]`, `discard() -> None` (zeros+empties, clears breaker, does NOT reset the seq/now floor), props `depth_frames`/`depth_bytes`/`breaker_tripped`. Internals: `_last_seq=-1`, `_last_now=-inf`, `_breaker_tripped=False`.

**Load-bearing security rules (CLAUDE.md + spec §6):**

- The buffer holds **pre-DLP, payload-blind T1-carrier** operator input. Append/replay verbatim; never decode (hard rule #5).
- **append-before-send** (design §3.3): in `relay_to_core`, append THEN attempt send. A loud-dropped send leaves the frame buffered (no loss); the send still loud-drops (no raise) because the buffer — not a raise — now guarantees no-loss.
- **No silent failure (hard rule #7):** TTL eviction returns evicted seqs → audit each as input-loss; the breaker trip → loud audit row; `trim_to_ack`'s ack must be the daemon's durable-intake ack (it is — the gateway consumes `daemon.comms.ack`, which the daemon emits only on the G0 durable commit).
- **Back-pressure, not drop:** on breaker trip the relay STOPS reading the client socket (never drops). The pure buffer's hard-ceiling raise is the fail-closed backstop if the halt is buggy.

### PLAN-REVIEW REVISIONS (security + architect, 2026-06-17) — these supersede the original task prose where they conflict

**R1 — reconnect = reset-with-loud-loss, NOT hold (resolves the security HIGH + a 3rd bug both reviews missed).** The original "hold the buffer across a 2a reconnect" is BROKEN: `_peer_handshake` resets `_client_to_core_seq=0` on the fresh leg, so the next `relay_to_core` mints `seq=0` and calls `buffer.append(0, …)` while `buffer._last_seq` is still `N` from the old epoch → `ReplayBufferError("seq must strictly increase")` escapes the relay pump (it's NOT in the pump's caught family) → crash. AND (security HIGH) a fresh-leg `daemon.comms.ack` would `trim_to_ack` old-epoch frames the new core never committed → silent loss. **The correct 2a behaviour:** on the reconnect edge (a fresh `_peer_handshake` after the link has been UP before), if the buffer is non-empty, enumerate `buffer.unacked_frames()`, emit ONE loud `gateway.comms.buffer_reset_input_loss` structlog row per dropped seq (hard rule #7 — loud, not silent), then call `buffer.reset_for_new_epoch()` (zeros+empties+floor-reset so epoch B's seqs `0..` append cleanly). This is LOUD interim loss; G4b-2b replaces it with reconnect-replay (drain `unacked_frames` → re-send → `reset_for_new_epoch`) so the loss closes. The very first connect (no prior UP) does NOT reset (buffer empty).

**R2 — audit = LOUD structlog rows for 2a, NOT an AuditWriter (resolves architect F3, avoids a deployment fork).** The gateway process has ZERO DB wiring today; injecting an `AuditWriter` (which needs a Postgres `session_factory`) would make the always-up front door depend on DB reachability at boot — a cross-subsystem deployment decision the gateway's connectivity-light design rejects. Design §6 already scopes the gateway's audit as a SEPARATE "buffer-local audit rows + reconcile into the signed core log on reconnect" mechanism (it must NOT hold the core signing key). So **2a uses loud structlog `log.warning(...)` rows** for the breaker-trip + the per-seq input-loss/eviction events (the gateway's honest current logging — loud satisfies hard rule #7). The signed-audit-reconcile is a TRACKED FOLLOW-UP (design §6), NOT this PR. No `AuditWriter` is injected anywhere in 2a → no None-audit branch, no DB dependency. (Flag this for the PR-time security review; the plan-review security engineer endorsed the structlog fallback.)

**R3 — breaker idempotency is OWNED BY THE MACHINE; drop `_breaker_signalled` (architect F1).** G4b-1 made `(UNAVAILABLE, BREAKER_TRIPPED) → (UNAVAILABLE, None)` (`link_state.py:213`). So feed `BREAKER_TRIPPED` UNCONDITIONALLY whenever `buffer.breaker_tripped` is observed after an append — the machine absorbs repeats (no second control frame). Write the ONE breaker structlog row keyed on `control is LinkControl.UNAVAILABLE` (the machine emits that exactly once). No gateway-local flag.

**R4 — back-pressure read-halt = park on the EXISTING `shutdown_event`, NO new Event (architect F2).** In 2a the breaker latch never clears (only 2b's `reset_for_new_epoch` clears it), so a new clearable `asyncio.Event` would have an unreachable clear-branch → fails the 100% gate. The halt is TERMINAL in 2a (UNAVAILABLE is absorbing). So: at the TOP of `_client_to_core_pump`, if `core_link.replay_buffer_tripped`, `await self._shutdown_event.wait()` (park until shutdown-cancel — the OS socket buffer back-pressures the TUI; loss-free). `Event.wait()` is cancellation-safe; place it OUTSIDE the malformed-frame `try` so `CancelledError` propagates. A clearable Event is a 2b concern.

**R5 — `trim_to_ack` must NOT clear the breaker (architect F4).** On a wedged-then-recovered core, `trim_to_ack` drains durably-acked frames but the breaker stays latched + the link stays terminal-UNAVAILABLE (intended — recovery is a fresh session). Do NOT add a "clear breaker on trim" convenience (a security regression that silently un-wedges a terminal state).

**Scope (2a only — NOT in this PR):** reconnect-REPLAY (`unacked_frames` re-send to the fresh core). 2a adds `reset_for_new_epoch()` (Task 1) and CALLS it on reconnect with loud per-seq loss (R1); 2b adds the replay that drains-before-reset so the loss closes.

**i18n:** 2a's breaker/loss events are LOUD STRUCTLOG (R2), not `t()`-rendered operator strings — no catalog entry. Wire identifiers (`daemon.comms.ack`) are not `t()`. (The signed-audit-reconcile follow-up will own any operator-facing reasons.)

**STOP-and-surface:** if R4's `shutdown_event`-park can't be wired without restructuring the relay TaskGroup, or R1's reconnect-reset edge isn't cleanly reachable in `_peer_handshake`/`_feed`, STOP and report.

---

## File structure

- **Modify:** `src/alfred/gateway/replay_buffer.py` — add `reset_for_new_epoch()`.
- **Modify:** `src/alfred/gateway/core_link.py` — inject `ReplayBuffer | None`; `append` in `relay_to_core`; `trim_to_ack` in the `_route_unit` daemon-ack consume; the breaker→`BREAKER_TRIPPED` feed; the `evict_expired` timer + audit; the audit-writer injection.
- **Modify:** `src/alfred/gateway/relay.py` — back-pressure read-halt in `_client_to_core_pump`.
- **Modify:** `src/alfred/gateway/metrics.py` — add `gateway_buffer_depth_{frames,bytes}`, `gateway_buffer_cap_ratio`, `gateway_circuit_breaker_open` gauges.
- **Create:** `tests/adversarial/comms/test_gateway_wedged_core_flood.py` — §6(d) wedged-core-flood adversarial (release-blocking).
- **Modify:** `tests/unit/gateway/test_core_link.py`, `test_relay.py`, `test_replay_buffer.py` — unit coverage.
- **Modify:** `.github/workflows/ci.yml` — the new metrics/code stays within the existing gateway per-file 100% gates (no new gate file unless a new module is added).

---

### Task 1: `ReplayBuffer.reset_for_new_epoch()` (additive)

**Files:** Modify `src/alfred/gateway/replay_buffer.py`; Test `tests/unit/gateway/test_replay_buffer.py`.

- [ ] **Step 1 (failing test):**

```python
def test_reset_for_new_epoch_zeros_empties_clears_breaker_and_floor() -> None:
    buf = _buffer(max_frames=1, max_bytes=10_000)
    buf.append(0, b"a", now=1.0)
    buf.append(1, b"b", now=2.0)  # trips breaker
    bodies = [e.body for e in buf._retained]  # white-box zeroing assertion
    assert buf.breaker_tripped is True
    buf.reset_for_new_epoch()
    assert buf.depth_frames == 0 and buf.depth_bytes == 0
    assert buf.breaker_tripped is False
    assert all(bytes(b) == b"\x00" * len(b) for b in bodies)
    # Unlike discard(), the seq/now floor IS reset — a fresh epoch's seq restarts at 0.
    buf.append(0, b"fresh", now=0.0)  # would raise after discard(); accepted after reset
    assert buf.unacked_frames() == (ReplayFrame(seq=0, payload=b"fresh"),)
```

- [ ] **Step 2 (fail) → Step 3 (impl):** add after `discard`:

```python
    def reset_for_new_epoch(self) -> None:
        """Zero + empty + clear the breaker AND reset the monotonic seq/now floor.

        The G4b-2b reconnect path calls this when a fresh core epoch is bound: the
        new core leg is a fresh seq space (restarts at 0), so unlike :meth:`discard`
        (which preserves the floor — a stale post-discard frame is rejected loud) this
        rebinds the floor for the new epoch. Zeroes every retained body first (the
        spec §6 pre-DLP bound).
        """
        for entry in self._retained:
            _zero(entry.body)
        self._retained.clear()
        self._depth_bytes = 0
        self._breaker_tripped = False
        self._last_seq = -1
        self._last_now = float("-inf")
```

- [ ] **Step 4 (pass) → Step 5 (commit):** `feat(gateway): ReplayBuffer.reset_for_new_epoch — zero+empty+clear+floor-reset (Spec A G4b-2a / ADR-0032) (#237)` + trailer.

### Task 2: Inject `ReplayBuffer` into `GatewayCoreLink` (+ a monotonic clock seam)

**Files:** Modify `src/alfred/gateway/core_link.py`; Test `tests/unit/gateway/test_core_link.py`.

- [ ] **Step 1 (read):** find the `GatewayCoreLink.__init__` signature + the `_client_to_core_seq` init (~265). The buffer + an injected monotonic `now` callable (default `time.monotonic`) are new ctor params, both optional (default `None`/`time.monotonic`) so the merged G3 tests that don't buffer construct unchanged.
- [ ] **Step 2 (failing test):** constructing `GatewayCoreLink(..., replay_buffer=buf)` stores it; default `replay_buffer=None` leaves buffering off (the 3b carrier tests still pass byte-for-byte).
- [ ] **Step 3 (impl):** add `replay_buffer: ReplayBuffer | None = None` and `monotonic: Callable[[], float] = time.monotonic` ctor params; store `self._replay_buffer = replay_buffer`, `self._monotonic = monotonic`. Import `ReplayBuffer` from `alfred.gateway.replay_buffer` and `time`.
- [ ] **Step 4 (pass) → Step 5 (commit):** `feat(gateway): inject ReplayBuffer + monotonic clock into GatewayCoreLink (Spec A G4b-2a / ADR-0032) (#237)` + trailer.

### Task 3: `append`-before-send in `relay_to_core`

**Files:** Modify `src/alfred/gateway/core_link.py` (`relay_to_core` ~760); Test `tests/unit/gateway/test_core_link.py`.

- [ ] **Step 1 (failing tests):**
  - with a buffer injected, `relay_to_core(b"x")` appends `(seq=0, b"x")` to the buffer BEFORE the send (assert `buffer.depth_frames == 1` and the appended seq == the wire seq sent).
  - a loud-dropped send (broken-pipe) STILL leaves the frame buffered (append happened before the send attempt) — `depth_frames == 1` after the drop.
  - with NO buffer (default None), `relay_to_core` behaves exactly as today (no append, no crash).
- [ ] **Step 2 (fail) → Step 3 (impl):** in `relay_to_core`, after minting `seq` (the existing `seq = self._client_to_core_seq; self._client_to_core_seq += 1`) and BEFORE the `try: send`:

```python
        if self._replay_buffer is not None:
            # append-before-send (design §3.3): the buffer is the durable no-loss
            # record; the send below is best-effort and may loud-drop. Keyed on the
            # exact wire seq (G4b-2-pre). The hard-ceiling raise is the fail-closed
            # backstop if G4b's read-halt is buggy.
            self._replay_buffer.append(payload=payload, seq=seq, now=self._monotonic())
```

(Placement: AFTER the `local is None` early-return and AFTER the seq-mint, BEFORE the send `try`. A None-transport drop neither mints a seq nor appends; a live-transport send that loud-drops still mints the seq and appends — so the frame is buffered for replay (correct for 2a; the held frame replays in 2b).)

- [ ] **Step 4 (pass) → Step 5 (commit):** `feat(gateway): append inbound frames to the ReplayBuffer before send (Spec A G4b-2a / ADR-0032) (#237)` + trailer.

### Task 4: `trim_to_ack` from the `daemon.comms.ack` consume

**Files:** Modify `src/alfred/gateway/core_link.py` (`_route_unit` ~707); Test `tests/unit/gateway/test_core_link.py`.

- [ ] **Step 1 (failing tests):**
  - a `daemon.comms.ack` frame with `params={"cumulative_ack": 2}` calls `buffer.trim_to_ack(2)` (assert the buffer's prefix `seq<=2` is trimmed).
  - a malformed / missing `cumulative_ack` is still CONSUMED (not relayed, no crash) and does NOT trim (payload-blind robustness — the existing test asserts consume; extend it to assert no trim + no raise).
  - with no buffer, the consume is the existing no-op log.
- [ ] **Step 2 (fail) → Step 3 (impl):** replace the `log.debug("gateway.core_link.daemon_comms_ack_consumed")` no-op body with:

```python
            if self._replay_buffer is not None:
                params = parsed.get("params") if isinstance(parsed, Mapping) else None
                ack = params.get("cumulative_ack") if isinstance(params, Mapping) else None
                # `not isinstance(ack, bool)`: bool is an int subclass, so a JSON `true`
                # must NOT be read as ack=1 (a malformed-input buffer-trim).
                if isinstance(ack, int) and not isinstance(ack, bool) and ack >= 0:
                    # The daemon emits this ONLY on its durable-intake commit (G0), so
                    # the ack is epoch-validated by construction (current UP leg) — the
                    # security precondition the ReplayBuffer.trim_to_ack docstring names.
                    self._replay_buffer.trim_to_ack(ack)
                else:
                    log.warning("gateway.core_link.daemon_comms_ack_malformed")
            log.debug("gateway.core_link.daemon_comms_ack_consumed")
            return
```

- [ ] **Step 4 (pass) → Step 5 (commit):** `feat(gateway): trim the ReplayBuffer on the daemon durable-intake ack (Spec A G4b-2a / ADR-0032) (#237)` + trailer.

### Task 4.5: reconnect = enumerate-loud-loss + `reset_for_new_epoch` (per R1)

**Files:** Modify `src/alfred/gateway/core_link.py` (the reconnect edge — a fresh `_peer_handshake` after a prior UP); Test `tests/unit/gateway/test_core_link.py`.

- [ ] **Step 1 (failing tests):**
  - frames buffered under epoch A; a reconnect (fresh `_peer_handshake`, link was UP before) → each held seq emits a loud `gateway.comms.buffer_reset_input_loss` structlog row, then the buffer is empty + floor-reset (a fresh `relay_to_core` on epoch B appends `seq=0` WITHOUT raising).
  - a fresh-leg `daemon.comms.ack` after the reset does NOT trim old-epoch frames (they're gone) — no cross-epoch trim.
  - the FIRST connect (no prior UP) does NOT reset (buffer empty, no-op).
- [ ] **Step 2 (fail) → Step 3 (impl):** in the reconnect path (guard on "have we been UP before" — reuse the existing edge state, e.g. the link-state machine having left UP, or a `self._has_connected` flag set after the first handshake), if `self._replay_buffer is not None and self._replay_buffer.depth_frames > 0`:

```python
            for frame in self._replay_buffer.unacked_frames():
                log.warning(
                    "gateway.comms.buffer_reset_input_loss",
                    seq=frame.seq,
                    reason="reconnect_no_replay_2a",  # 2b replaces this with replay
                )
            self._replay_buffer.reset_for_new_epoch()
```

- [ ] **Step 4 (pass) → Step 5 (commit):** `feat(gateway): reconnect resets the ReplayBuffer with loud per-seq input-loss (Spec A G4b-2a / ADR-0032) (#237)` + trailer.

### Task 5: breaker → `BREAKER_TRIPPED` feed → `link.unavailable` + loud structlog (per R2 + R3)

> **OVERRIDE (R2/R3):** NO `AuditWriter`, NO `_breaker_signalled` flag. Feed `BREAKER_TRIPPED` UNCONDITIONALLY on an observed `buffer.breaker_tripped` after append (the machine absorbs repeats — `link_state.py:213`); write ONE loud `gateway.comms.breaker_tripped` structlog row keyed on `control is LinkControl.UNAVAILABLE` (the once-only escalation edge). Test: a second tripped append re-feeds but the machine returns `None` (no second control frame, no second structlog row).

**Files:** Modify `src/alfred/gateway/core_link.py`; Test `tests/unit/gateway/test_core_link.py`.

- [ ] **Step 1 (read):** confirm how the link-state machine is fed (`self._machine.feed(...)` via `_feed`, ~826) and that `_feed` already returns the `LinkControl` the machine emits (the once-only `UNAVAILABLE` edge). NO `AuditWriter` is injected (R2 — the gateway has zero DB wiring); the breaker-trip audit is a LOUD structlog row.
- [ ] **Step 2 (failing tests):**
  - when `relay_to_core`'s append trips `buffer.breaker_tripped`, the link-state machine is fed `GatewayLinkEvent.BREAKER_TRIPPED` and the resulting `control is LinkControl.UNAVAILABLE` edge writes exactly ONE `gateway.comms.breaker_tripped` loud structlog row; a SECOND tripped append re-feeds `BREAKER_TRIPPED` but the machine returns `None` (link_state.py:213 absorbs the repeat) → no second control frame, no second structlog row.
  - the `BREAKER_TRIPPED` feed produces `LinkControl.UNAVAILABLE` (the merged escalation) → the client receives `link.unavailable`.
- [ ] **Step 3 (impl, per R2/R3):** after the append in `relay_to_core`, if `self._replay_buffer is not None and self._replay_buffer.breaker_tripped`, feed `GatewayLinkEvent.BREAKER_TRIPPED` UNCONDITIONALLY via the existing `_feed`/control path (the machine — not a gateway-local flag — absorbs repeats). When the returned `control is LinkControl.UNAVAILABLE` (the once-only escalation edge), write the single `log.warning("gateway.comms.breaker_tripped", ...)` structlog row and send the control frame. No `self._breaker_signalled`.
- [ ] **Step 4 (pass) → Step 5 (commit):** `feat(gateway): breaker trip feeds BREAKER_TRIPPED -> link.unavailable + loud audit (Spec A G4b-2a / ADR-0032) (#237)` + trailer.

### Task 6: client read-halt (back-pressure) in `_client_to_core_pump` (per R4)

> **OVERRIDE (R4):** NO new `asyncio.Event` (its clear-branch is unreachable in 2a → fails the 100% gate). At the TOP of `_client_to_core_pump`, if `core_link.replay_buffer_tripped` (a read-only property on `GatewayCoreLink`: `self._replay_buffer.breaker_tripped if self._replay_buffer else False`), `await self._shutdown_event.wait()` — park until shutdown-cancel (the OS socket buffer back-pressures the TUI; loss-free, terminal in 2a). Place the await OUTSIDE the malformed-frame `try` so `CancelledError` propagates cleanly. Test: with a tripped breaker the pump reads NO further client frame and the frame that tripped it IS in the buffer (append-before-send); the park is cancellation-safe on shutdown.

**Files:** Modify `src/alfred/gateway/relay.py` (`_client_to_core_pump` ~188); Test `tests/unit/gateway/test_relay.py`.

- [ ] **Step 1 (read):** the pump loops `frame = await read_payload_unit()` then `relay_to_core(frame.payload)`. Back-pressure = stop calling `read_payload_unit` while the breaker is tripped (await a "breaker cleared / leg restored" condition rather than reading). The relay needs access to the buffer's `breaker_tripped` (via the core_link).
- [ ] **Step 2 (failing test):** with a tripped breaker, the pump does NOT read another client frame — it parks on `self._shutdown_event.wait()` (terminal in 2a: the latch only clears on `reset_for_new_epoch`/`discard`, which 2b owns). Assert the read-halt holds while tripped and that a `shutdown_event.set()` (shutdown-cancel) releases the park cleanly (cancellation-safe).
- [ ] **Step 3 (impl, per R4):** at the TOP of the pump loop, before `read_payload_unit`, check `core_link.replay_buffer_tripped` (a small read-only property on `GatewayCoreLink` exposing `self._replay_buffer.breaker_tripped if self._replay_buffer else False`); if tripped, `await self._shutdown_event.wait()` (park until shutdown-cancel — NO new `asyncio.Event`, whose clear-branch would be unreachable in 2a and fail the 100% gate). Place the await OUTSIDE the malformed-frame `try` so `CancelledError` propagates. The OS socket buffer back-pressures the TUI (loss-free); the hard-ceiling raise is the fail-closed backstop.
- [ ] **Step 4 (pass) → Step 5 (commit):** `feat(gateway): client read-halt back-pressure while the buffer breaker is tripped (Spec A G4b-2a / ADR-0032) (#237)` + trailer.

### Task 7: `evict_expired` timer + per-seq input-loss audit + metrics

**Files:** Modify `src/alfred/gateway/core_link.py` + `metrics.py`; Test `tests/unit/gateway/test_core_link.py`, `test_metrics.py`.

- [ ] **Step 1 (failing tests):**
  - a bounded supervised timer calls `buffer.evict_expired(now=...)` on an interval; each returned (evicted) seq is audited as input-loss (`gateway.comms.buffer_evicted`); reaped on shutdown (no leaked task).
  - the depth/cap-ratio/breaker gauges reflect the buffer state after each mutating call.
- [ ] **Step 2 (fail) → Step 3 (impl):** add `gateway_buffer_depth_frames`, `gateway_buffer_depth_bytes`, `gateway_buffer_cap_ratio`, `gateway_circuit_breaker_open` to `metrics.py` (module-level, mirror the existing gauges). Add a per-connection eviction timer in the core-link's run/supervisor (mirror the daemon's `_emit_durable_intake_ack_loop` reap pattern); set the gauges after append/trim/evict.
- [ ] **Step 4 (pass) → Step 5 (commit):** `feat(gateway): TTL-eviction timer + buffer metrics + per-seq input-loss audit (Spec A G4b-2a / ADR-0032) (#237)` + trailer.

### Task 8: §6(d) wedged-core-flood adversarial test (release-blocking)

**Files:** Create `tests/adversarial/comms/test_gateway_wedged_core_flood.py` (follow the existing gateway adversarial dir pattern); register any new audit reason.

- [ ] **Step 1 (the adversarial scenario):** a core that ACCEPTS the socket but never acks (never emits `daemon.comms.ack`) → the gateway buffers inbound to the soft cap → the breaker trips → the client read halts → `link.unavailable` + a loud audit row → growth is BOUNDED (the hard-ceiling raise is the backstop; never OOM, never a silent drop). Assert: depth never exceeds the hard ceiling; the breaker latched; the audit row written; `link.unavailable` emitted to the client; no frame silently dropped.
- [ ] **Step 1b (strengthen — plan-review):** also assert (a) **payload-blindness** — spy that `json.loads` is never called on a relayed payload during the flood (the relay imports `json` specifically so a test can spy it, `relay.py:47`) → makes hard rule #5 release-blocking, not a comment; (b) the **frame that tripped the breaker is in the buffer** (append-before-send, not dropped); (c) a **cross-epoch no-trim** case — wedge+trip, reconnect to a fresh epoch, the held old-epoch frames are reset-with-loud-loss (R1), NOT trimmed by a fresh-leg ack (this catches the security HIGH).
- [ ] **Step 2-4:** write it red→green against the wired behaviour; it is release-blocking (the spec §6 corpus entry). In-process / non-root (fake `_CommsTransportLike` transports — like `test_gateway_ready_epoch_forgery.py`) so it runs on the REQUIRED standard adversarial gate (the #245 paper-gate lesson — NOT a root-skipped launcher test). Commit: `test(adversarial): wedged-core flood -> bounded + loud + payload-blind (Spec A G4b-2a / §6(d)) (#237)` + trailer.

### Task 9: coverage + full gates + ADR note

**Files:** verify; ADR-0032 (the buffer-wiring note, NOT the deferred §6 idempotency amendment which stays in 2b).

- [ ] **Step 1:** `core_link.py`/`relay.py`/`metrics.py` stay at 100% in their gateway per-file gates; add targeted tests for any uncovered branch (the malformed-ack path, the no-buffer default path, the breaker-idempotency edge).
- [ ] **Step 2:** `make check` (NOT piped through `tail`; run `ruff format --check` too — a recurring miss). Known flakes (re-run isolated): `tests/unit/memory/.../test_per_key_asyncio_lock`, `test_daemon_comms_inbound_turn_lands_t3_promotion_row` (#275).
- [ ] **Step 3:** ADR-0032 gains a short note that G4b-2a wires append/trim/back-pressure (the resume-replay + the §6 idempotency amendment remain 2b). Markdownlint the ADR.
- [ ] **Step 4 (commit):** `docs(adr): ADR-0032 records the G4b-2a buffer append/trim/back-pressure wiring (Spec A) (#237)` + trailer.

---

## Self-Review

**Spec coverage (design §5/§7):** ReplayBuffer injected (T2) · append-before-send (T3) · trim_to_ack from the ack (T4) · breaker→BREAKER_TRIPPED→link.unavailable+audit (T5) · client read-halt (T6) · evict timer + audit + metrics (T7) · reset_for_new_epoch added (T1) · §6(d) wedged-flood adversarial (T8). NO reconnect-replay (correctly deferred to 2b).

**Plan-review flags (for the security + architect plan-review before implementation):** (a) the audit-writer injection into the gateway (none today — confirm the right seam, `GatewayProcess` vs `GatewayCoreLink`); (b) the back-pressure read-halt mechanism (an `asyncio.Event` halt vs restructuring the TaskGroup — confirm it can't deadlock the relay); (c) the breaker-idempotency (`_breaker_signalled` edge vs the buffer's monotone latch); (d) `trim_to_ack`'s ack is the daemon durable-intake ack (epoch-validated by construction — confirm no spoofed-ack path); (e) whether the per-connection buffer should `discard()` on a 2a reconnect (no replay yet) or hold (the design says hold for 2b — confirm the 2a interim behaviour is loss-free).

**Placeholder scan:** Task 3's append-placement note + Task 5/6's audit-writer + halt-Event seams are the implementer-resolves points, constrained + STOP-and-surface-gated. Every production code block is concrete.

**Type consistency:** `replay_buffer: ReplayBuffer | None`, `monotonic: Callable[[], float]`, `reset_for_new_epoch() -> None`, `trim_to_ack(int)`, `append(payload, seq, *, now)`, `evict_expired(*, now) -> tuple[int,...]` — consistent across tasks.
