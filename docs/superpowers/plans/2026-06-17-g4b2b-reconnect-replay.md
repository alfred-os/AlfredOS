# G4b-2b — Gateway reconnect-replay (the resume drain) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace G4b-2a's reconnect "reset-with-loud-loss" with **drain → replay → reset** so un-acked inbound (client→core) frames buffered before a core restart are re-sent on the fresh leg — closing the resume guarantee (spec §5: nothing typed is lost across a core bounce). Completes G4 of the Comms-Resume Gateway (Spec A).

**Architecture:** On a *reconnect* `CORE_READY` (not the first connect), `_peer_handshake` captures `unacked_frames()` into a `_pending_replay` stash BEFORE `reset_for_new_epoch()` (the bodies are independent copies that survive the buffer zeroing). After `run()` binds the new `_current_core_transport` and the link is UP, a `_flush_pending_replay()` re-sends each stashed payload through `relay_to_core` with FRESH per-connection seqs `0,1,…` (append-before-send; the core G0-dedups on the in-payload `inbound_id`, NOT `(leg,seq)` — see ADR-0032 §6.2). Replayed frames take the lowest seqs so they precede fresh input; the relay's client→core pump is held off until the flush completes so a fresh frame cannot steal a low seq.

**Tech Stack:** Python 3.12+, asyncio, `mypy --strict` + `pyright`, `ruff`, `pytest` + `hypothesis`. Design: `docs/superpowers/specs/2026-06-16-g4b2-replay-wiring-design.md` §4/§6. Prereqs (all merged): the full G4b-2a wiring (PR #284) — `ReplayBuffer` injected, `relay_to_core` appends, `daemon.comms.ack` trims, `_peer_handshake` resets, breaker→read-halt.

---

## Context the engineer needs

**Read first:** design doc §4 (the reconnect-replay sequence) + §6 (the ADR amendment owed); `src/alfred/gateway/core_link.py` — `run()` (the reconnect arm: line ~415-417, `transport = await self._reconnect_closing(transport); self._current_core_transport = transport; continue`; the initial arm: ~392-393), `_peer_handshake` (the reset block ~738-761), `relay_to_core` (~707-744, the append-before-send + breaker feed), `__init__` (~266-280, where `_client_to_core_seq`/seams init); `src/alfred/gateway/relay.py` `_client_to_core_pump` (the read-halt park ~197); `src/alfred/gateway/replay_buffer.py` (`unacked_frames()` returns `tuple[ReplayFrame,…]` with fresh `bytes` copies; `reset_for_new_epoch()`).

**The current 2a reconnect block (in `_peer_handshake`, ~line 753-761) — this is what 2b changes:**

```python
        self._client_to_core_seq = 0
        if self._replay_buffer is not None:
            # ... unconditional floor-reset; loud per-seq loss (2a interim) ...
            for seq in self._replay_buffer.retained_seqs():
                log.warning("gateway.comms.buffer_reset_input_loss", seq=seq, reason="reconnect_no_replay_2a")
            self._replay_buffer.reset_for_new_epoch()
```

2b replaces the *loss-logging* with a *capture* — the un-acked remainder is stashed into `_pending_replay` (FIFO-merged ahead of any deferred remainder; see Task 2 / R1) BEFORE the reset; the reset + seq-reset stay. The loud row moves to the flush as `gateway.comms.buffer_replayed` (the resume happened, per-seq, hard rule #7 observability — replay is a state change worth auditing, not a loss).

---

### DESIGN DECISION FOR PLAN-REVIEW (architect + security) — the replay/fresh-input FIFO barrier

The relay's `_client_to_core_pump` (a separate task) calls `relay_to_core` for fresh client input concurrently with `run()`'s flush. Both mint from `_client_to_core_seq`. If a fresh frame's `relay_to_core` interleaves between flush frames, it could grab a low seq, putting fresh input *ahead of* replayed input in the core's seq-ordered intake — violating spec §4 ("replayed frames precede fresh input in FIFO order").

**Recommended (Option A — replay-pending barrier, mirrors the read-halt):** add a `_replay_pending` gate on `GatewayCoreLink` (an `asyncio.Event`, *set* = pump may run, *clear* = pump parks). The flush clears it before re-sending and sets it after; `_client_to_core_pump` `await`s it at the top of its loop (next to the existing `replay_buffer_tripped` check). Both branches are reachable (clear→set on every reconnect-with-frames; the always-set path on first connect / no-buffer), so it passes the 100% gate — unlike R4's unreachable-clear concern. **Rejected (Option B — atomic seq-reservation):** the flush appends ALL replay frames synchronously (reserving seqs `0..N-1` with no `await`) then sends them; fresh frames then necessarily get `>= N`. Simpler concurrency but duplicates `relay_to_core`'s mint+append, and a mid-flush send failure leaves a half-reserved buffer. Option A keeps `relay_to_core` the single append/send site.

> **The plan below assumes Option A.** If plan-review prefers B, Task 4/5 change to the atomic-reservation shape; STOP-and-surface before implementing if the review is split.

**Scope (G4b-2b only):** the replay drain + flush + the FIFO barrier + the ADR §6.2 amendment. NOT in scope: `discard()` on retry-window exhaustion (already merged), the signed-audit reconcile (design §6 follow-up), re-pointing `alfred chat` at the gateway (that is G5).

**i18n:** replay/barrier events are LOUD STRUCTLOG (`gateway.comms.buffer_replayed`), not `t()` operator strings — consistent with the G4b-2a R2 decision. No catalog entry.

---

### PLAN-REVIEW REVISIONS (architect + security, 2026-06-17) — these supersede conflicting task prose

**Decision confirmed:** Option A (the `_replay_pending` gate) is APPROVED by both reviewers (mirrors the read-halt; no deadlock — the parked client pump is a *separate task* from `run()`'s flush task; the buffer-side seq-reservation third option is rejected for splitting seq-mint authority). Replay re-append is sound (no double-count: reset empties+zeros, the new core must re-ack because exactly-once is the in-payload `inbound_id`).

**R1 — None-transport-at-flush = RE-STASH, never accept-drop (both reviewers; BLOCKER otherwise).** Accept-drop is a hard-rule-#7 silent cross-restart loss AND a lying audit (`buffer_replayed` would claim a resume that did not send). `_flush_pending_replay` must, per frame, check `self._current_core_transport is None` BEFORE calling `relay_to_core`: on None, re-stash the un-sent remainder into `self._pending_replay`, emit ONE loud `gateway.comms.buffer_replay_deferred` row (`deferred=<n>`, `reason="transport_lost_mid_replay"`), and RETURN leaving the gate CLEARED (the next bind's flush retries; the client pump stays parked — correct, the leg is unusable). Emit `buffer_replayed` only for a frame that was actually handed to `relay_to_core`. The gate `set()` happens ONLY on a COMPLETE flush — implement as `finally: if not self._pending_replay: self._replay_pending.set()` (a defer leaves `_pending_replay` non-empty → gate stays clear; a complete/empty flush → gate set; a stray `relay_to_core` raise still hits the `finally` → gate set = the S5 DoS fail-safe). NOTE: a *broken-pipe* mid-replay (transport non-None, send raises inside `relay_to_core`) is SELF-HEALING — `relay_to_core` already appended the frame before the send, so it stays buffered (un-acked) and replays next reconnect; only the None-transport case needs the explicit re-stash (`relay_to_core` returns early on None WITHOUT appending).

**R2 — Task 6 also corrects `ReplayFrame` (`replay_buffer.py:91-93`)** — its docstring "Replay MUST carry the ORIGINAL seq — the core dedups on `(leg, seq)`" is the most direct contradiction of the per-connection-reseq + inbound-id model. Add it to Task 6's touch list alongside the module / `unacked_frames` / `discard` docstrings.

**R3 — Task 5 adversarial assertions are tightened to POSITIVE call-count gates (security; these are the owed corpus entries):**

- (a) **forged-ready → flush-not-called:** feed a forged/stale-epoch `ready` to `_consume_ready` and assert `_flush_pending_replay` was NOT called (spy/call-count == 0) AND `_pending_replay` is untouched — not merely "no CORE_READY feed".
- (b) **payload-blind replay:** a `json.loads`-never-called spy over the replay path (both `relay.json.loads` and `core_link.json.loads`, as the §6(d) flood test does) asserts `loads_calls == []` across the whole replay.
- (c) **stash-residency:** after a COMPLETE flush, assert `_pending_replay == ()` (no lingering pre-DLP refs pinned in the always-up process).
- (d) **None-transport defer:** force `_current_core_transport = None` mid-flush → assert re-stash (`_pending_replay` holds the remainder), the loud `buffer_replay_deferred` row, and the gate stays CLEARED.
- (e) **gate fail-safe:** a flush whose loop raises mid-way still SETS the gate (no client→core wedge / DoS).
- (f) **trim-mid-flush benign:** the new core's early ack arriving during the flush (`trim_to_ack` on a partially-appended buffer) removes only `seq <= ack` and does not corrupt the ascending replay — assert no loss/corruption.

**R4 — gate-clear-before-CORE_READY ordering invariant (architect A5).** The gate is cleared in `_peer_handshake` (Task 2), which COMPLETES before its caller (`_reconnect`/`_initial_connect`) feeds `CORE_READY` and before `run()` rebinds the transport + flushes. So the client pump can never observe an unparked gate between CORE_READY and the flush. Make this explicit in the Task 2 comment; Task 5 asserts replay-precedes-fresh-input by SEQ ORDER (a fresh client frame queued during the gap gets `seq >= N`).

---

## File structure

- **Modify:** `src/alfred/gateway/core_link.py` — `__init__` (`_pending_replay` stash + `_replay_pending` Event); `_peer_handshake` (capture-before-reset, replacing the loss-log); `run()` (call `_flush_pending_replay` after each transport bind); new `_flush_pending_replay()`.
- **Modify:** `src/alfred/gateway/relay.py` — `_client_to_core_pump` awaits the `_replay_pending` gate (via a `GatewayCoreLink` read-only accessor, mirroring `replay_buffer_tripped`).
- **Modify:** `src/alfred/gateway/replay_buffer.py` — docstring corrections only (the "monotonic-across-restart / dedup-on-(leg,seq)" framing → per-connection seq + inbound-id dedup; design §6.2).
- **Modify:** `docs/adr/0032-gateway-comms-resume-transport.md` — the §6.2 amendment (correct the lines ~162-164 contradiction; record the reconnect-replay sequence + the FIFO barrier).
- **Create:** `tests/adversarial/comms/test_gateway_reconnect_replay.py` — the end-to-end reconnect-replay round-trip + the §6 adversarial (spoofed-ready → no flush; replay precedes fresh input).
- **Modify:** `tests/unit/gateway/test_core_link.py`, `test_relay.py` — unit coverage for capture/flush/barrier.

---

### Task 1: `_pending_replay` stash + `_replay_pending` gate on `GatewayCoreLink`

**Files:** Modify `src/alfred/gateway/core_link.py` (`__init__`); Test `tests/unit/gateway/test_core_link.py`.

- [ ] **Step 1 (failing test):** a fresh `GatewayCoreLink` has `_pending_replay == ()` and a read-only `replay_pending_gate` accessor (an `asyncio.Event`) that starts SET (pump may run); with no buffer the gate is permanently set.
- [ ] **Step 2 (impl):** in `__init__` add `self._pending_replay: tuple[ReplayFrame, ...] = ()` and `self._replay_pending: asyncio.Event` (constructed set — `evt = asyncio.Event(); evt.set()`). Import `ReplayFrame` from `alfred.gateway.replay_buffer`. Add a read-only property `replay_pending_gate -> asyncio.Event` (or a coroutine `wait_replay_clear`) the relay awaits. NOTE: an `asyncio.Event` constructed at ctor time (no running loop) is fine — `Event()` does not require a loop until `.wait()`.
- [ ] **Step 3-5:** green; commit `feat(gateway): _pending_replay stash + replay-pending gate on GatewayCoreLink (Spec A G4b-2b / ADR-0032) (#237)` + trailer.

### Task 2: capture-before-reset in `_peer_handshake`

**Files:** Modify `src/alfred/gateway/core_link.py` (`_peer_handshake` ~753-761); Test `test_core_link.py`.

- [ ] **Step 1 (failing test):** drive a `_peer_handshake` with a non-empty buffer → afterwards `_pending_replay` holds the (FIFO) `ReplayFrame`s that WERE retained, the buffer is reset (empty, floor rebound), and the `_replay_pending` gate is CLEARED (pump must hold). An empty buffer → `_pending_replay == ()`, gate stays SET.
- [ ] **Step 2 (impl):** replace the `buffer_reset_input_loss` loop with:

```python
        if self._replay_buffer is not None:
            # G4b-2b: capture the un-acked remainder BEFORE the floor-reset so it can be
            # replayed on the new leg (the bodies are independent copies that survive the
            # reset's zeroing). FIFO-MERGE (review fix): PREPEND any deferred remainder from
            # a prior None-transport flush ahead of this epoch's capture — do NOT overwrite
            # _pending_replay, else those deferred frames (which are NOT in the buffer) are
            # silently lost, breaking R1's no-silent-loss guarantee. Deferred frames are
            # older in the stream, so they replay first; the core dedups any already-committed
            # re-send on the in-payload inbound_id. Clear the replay-pending gate so the
            # relay's client->core pump HOLDS until the flush re-sends these — replayed frames
            # must take the lowest seqs (precede fresh input, spec §4). An empty buffer with
            # no deferred remainder is a no-op (first connect / fully-acked reconnect): nothing
            # to replay, gate stays set.
            self._pending_replay = self._pending_replay + self._replay_buffer.unacked_frames()
            if self._pending_replay:
                self._replay_pending.clear()
            self._replay_buffer.reset_for_new_epoch()
```

  (Keep `self._client_to_core_seq = 0` above it. The unconditional `reset_for_new_epoch()` — the comms-1 fix — stays.)

- [ ] **Step 3-5:** green; commit `feat(gateway): capture un-acked frames before the reconnect reset (Spec A G4b-2b / ADR-0032) (#237)` + trailer.

### Task 3: `relay.py` client pump awaits the replay-pending gate

**Files:** Modify `src/alfred/gateway/relay.py` (`_client_to_core_pump`); Test `test_relay.py`.

- [ ] **Step 1 (failing test):** with the core link's `_replay_pending` cleared, the client pump does NOT read a fresh client frame (parks on the gate); once the gate is set (flush done) it resumes. The park is cancellation-safe (outside the read `try`).
- [ ] **Step 2 (impl):** at the TOP of the pump loop, AFTER the existing `replay_buffer_tripped` read-halt, add `await self._core_link.replay_pending_gate.wait()` (via a read-only accessor on `GatewayCoreLink`). On first connect / no-buffer the gate is set so `wait()` returns immediately (no overhead). Place OUTSIDE the malformed-frame `try`.
- [ ] **Step 3-5:** green; commit `feat(gateway): hold the client->core pump until reconnect-replay completes (Spec A G4b-2b / ADR-0032) (#237)` + trailer.

### Task 4: `_flush_pending_replay()` + wire it into `run()`

**Files:** Modify `src/alfred/gateway/core_link.py` (new method + `run()` ~393, ~416); Test `test_core_link.py`.

- [ ] **Step 1 (failing tests):**
  - after a reconnect (handshake stashed 3 frames, new transport bound), `_flush_pending_replay()` re-sends all 3 via `relay_to_core` with seqs `0,1,2` (assert the fake transport received them in FIFO order with fresh seqs), re-appends them to the buffer (depth 3, un-acked on the new leg), emits one `gateway.comms.buffer_replayed` row per seq, clears `_pending_replay`, and SETS the `_replay_pending` gate.
  - first connect / empty stash → `_flush_pending_replay()` is a no-op (no sends, gate already set).
  - if `_current_core_transport` is None at flush time (a reconnect race), the flush RE-STASHES the un-sent remainder into `_pending_replay`, emits one loud `gateway.comms.buffer_replay_deferred` row, and RETURNS leaving the gate CLEARED so the next bind's flush retries — never accept-drop (R1; accept-drop is a hard-rule-#7 silent loss + a lying `buffer_replayed` audit). The next `_peer_handshake` FIFO-merges the deferred remainder ahead of its fresh capture so it is not clobbered (review fix).
- [ ] **Step 2 (impl):**

```python
    async def _flush_pending_replay(self) -> None:
        """Re-send the captured un-acked remainder on the freshly-bound leg (G4b-2b).

        Called from ``run`` after a (re)connect binds ``_current_core_transport`` and the
        link is UP, BEFORE the pump resumes. Each stashed payload is re-sent via
        ``relay_to_core`` (append-before-send, fresh per-connection seq 0,1,…) so the core
        G0-dedups on the in-payload ``inbound_id`` (ADR-0032 §6.2). Sets the replay-pending
        gate when done so the held client->core pump resumes — replayed frames have taken
        the lowest seqs, so fresh input follows in FIFO order. Idempotent: clears the stash
        first so a re-entrant call cannot double-replay.
        """
        frames = self._pending_replay
        self._pending_replay = ()
        try:
            for index, frame in enumerate(frames):
                if self._current_core_transport is None:
                    # R1: the leg vanished mid-flush (a reconnect race). Re-stash the
                    # un-sent remainder so the next bind retries; do NOT claim resume for
                    # frames that never went out (hard rule #7). Gate stays CLEARED (the
                    # client pump stays parked until the retry flush completes).
                    self._pending_replay = frames[index:]
                    log.warning(
                        "gateway.comms.buffer_replay_deferred",
                        deferred=len(self._pending_replay),
                        reason="transport_lost_mid_replay",
                    )
                    return
                log.warning("gateway.comms.buffer_replayed", seq=frame.seq, reason="reconnect_resume")
                await self.relay_to_core(frame.payload)  # append-before-send, fresh seq
        finally:
            # Release the held client->core pump ONLY on a COMPLETE flush. A defer (R1)
            # leaves _pending_replay non-empty -> gate stays clear; a complete/empty flush
            # -> gate set; a stray relay_to_core raise still hits this -> gate set (the S5
            # DoS fail-safe, no client->core wedge).
            if not self._pending_replay:
                self._replay_pending.set()
```

  Wire into `run()`: after BOTH `self._current_core_transport = transport` bindings (the initial ~393 and the reconnect ~416), add `await self._flush_pending_replay()`. (Initial connect: empty stash → no-op. Place BEFORE the reconnect arm's `continue`.)

- [ ] **Step 3-5:** green; commit `feat(gateway): flush captured frames on reconnect — the resume replay (Spec A G4b-2b / ADR-0032) (#237)` + trailer.

> **RESOLVED by plan-review (Task 4, R1):** the `_current_core_transport is None at flush` edge RE-STASHES the un-sent frames (never accept-drop — both reviewers ruled accept-drop a hard-rule-#7 silent loss + a lying audit). The flush re-stashes the remainder, emits a loud `buffer_replay_deferred`, and leaves the gate CLEARED; the next `_peer_handshake` FIFO-merges the deferred remainder ahead of its fresh capture so it survives to the retry. (None is a near-impossible race — effectively the shutdown-during-flush case — but the loss must still never be silent.)

### Task 5: end-to-end reconnect-replay adversarial + the §6 spoofed-ready guard

**Files:** Create `tests/adversarial/comms/test_gateway_reconnect_replay.py` (follow `test_gateway_ready_epoch_forgery.py` / `test_gateway_wedged_core_flood.py` in-process, NON-root style — the #245 paper-gate lesson).

- [ ] **Step 1 (the round-trip):** drive the relay + core link in-process: client sends N frames (buffered, un-acked) → core leg gaps (CRASH_EOF) → reconnect handshakes a fresh epoch → assert the N frames are re-sent on the NEW transport with fresh seqs `0..N-1` in FIFO order, BEFORE any fresh client frame (a fresh client frame queued during the gap gets seq `>= N`), and re-appended to the buffer (un-acked on the new leg). Then the new core acks → `trim_to_ack` drains them. Mutation-test: disabling the flush leaves the frames lost (test fails).
- [ ] **Step 1b (§6 adversarial):** (a) a spoofed/stale-epoch `ready` does NOT trigger a flush (no `CORE_READY` feed → no replay; mirror the forgery test); (b) replay-precedes-fresh-input is asserted by seq order, not wall-clock; (c) the replay re-appends, so a STILL-wedged new core trips the breaker again (bounded).
- [ ] **Step 2-4:** green + mutation-verified; commit `test(adversarial): reconnect-replay round-trip + spoofed-ready-no-flush (Spec A G4b-2b / §6) (#237)` + trailer.

### Task 6: ADR-0032 §6.2 amendment + ReplayBuffer docstring corrections

**Files:** Modify `docs/adr/0032-gateway-comms-resume-transport.md`, `src/alfred/gateway/replay_buffer.py` (docstrings only).

- [ ] **Step 1:** add an ADR-0032 "Reconnect-replay (G4b-2b)" amendment: the drain→reset→replay sequence, the FIFO barrier (the chosen option), and the §6.2 correction — replace the "Seq is gateway-owned and monotonic across a core restart / dedup on `(leg,seq)` / re-minting defeats exactly-once" framing (lines ~162-164) with: the client→core seq is PER-CONNECTION (resets each handshake); replay re-mints fresh seqs; cross-restart exactly-once is the durable in-payload `inbound_id` (G0 `commit_once` on `(adapter_id, inbound_id)`), NOT `(leg,seq)`. (The G4b-2a amendment already noted the supersession; this completes it for the replay case.)
- [ ] **Step 2:** correct the `replay_buffer.py` module + `unacked_frames`/`discard` docstrings that still say "monotonic across a core restart" / "a normal reconnect does NOT discard" to reflect the per-connection-reset + replay model. Markdownlint the ADR.
- [ ] **Step 3-4:** commit `docs(adr): ADR-0032 records reconnect-replay + corrects the cross-restart dedup framing (Spec A G4b-2b) (#237)` + trailer.

### Task 7: coverage + full gates

- [ ] **Step 1:** `core_link.py`/`relay.py`/`replay_buffer.py` stay 100% line+branch in the unit-scope gates (the comms-1 lesson: verify with `pytest tests/unit/gateway --cov=<module> --cov-branch`, NOT just full `make check`). Cover: the flush no-op (empty stash), the flush-with-frames, the gate clear/set branches, the None-transport flush edge, the pump-park-on-gate branch.
- [ ] **Step 2:** `make check` (full bar; NOT piped through `tail`; includes `ruff format --check`). Known flakes (re-run isolated): `test_per_key_asyncio_lock`, `test_daemon_comms_inbound_turn_lands_t3_promotion_row`, `test_dispatch_cycle_records_handler_returned_failed_outcome` (Postgres testcontainer).

---

## Self-Review

**Spec coverage (design §4/§6):** capture-before-reset (T2) · flush re-sends fresh-seq FIFO (T4) · the replay-pending barrier so replay precedes fresh input (T1/T3/T4) · epoch-gated (replay only on validated `CORE_READY`, T5) · first-connect no-op (T2/T4) · ADR §6.2 dedup correction (T6). NOT in scope: discard-on-retry-exhaustion (merged), signed-audit reconcile (follow-up), `alfred chat` re-point (G5).

**Plan-review flags (all RESOLVED — see the R1–R4 revisions block above):** (a) the FIFO barrier — Option A (gate) chosen; (b) the None-transport-at-flush edge — RE-STASH chosen (R1, never accept-drop); (c) replay re-appending into the buffer confirmed as the intended resume semantics (the new core must re-ack; no double-count — exactly-once is the in-payload `inbound_id`).

**Type consistency:** `_pending_replay: tuple[ReplayFrame, …]`, `_replay_pending: asyncio.Event`, `_flush_pending_replay() -> None`, `relay_to_core(bytes)`, `replay_pending_gate -> asyncio.Event` — consistent across tasks.
