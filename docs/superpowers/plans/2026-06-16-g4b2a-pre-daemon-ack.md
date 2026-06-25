# G4b-2a-pre — daemon durable-intake ack emission Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Teach the daemon (host) to observe the gateway's inbound (client→core) wire seq, advance a host-side cumulative ack **only on the G0 durable `commit_once`**, and ride that ack out on a new timer-coalesced `daemon.comms.ack` control frame the gateway consumes — so the upcoming G4b-2a `ReplayBuffer.trim_to_ack(real_ack)` actually drains on a healthy link instead of stalling at `trim_to_ack(0)`.

**Architecture:** Daemon-only (the only gateway edit is making `_route_unit` CONSUME the new control frame). Three parts (design §9.3): (a) carry the decoded wire seq inward to `process_inbound_message` via an optional `wire_seq` on `InboundMessageNotification` — the seq **travels with its own frame** through the runner→session dispatch path (a shared per-transport slot is RACY — see below); (b) a host-side `BoundedSeqAckTracker` (reuse `gateway/_seq_tracker.py`) `observe()`d on the `commit_once == True` branch only — durable intake, never replay/refusal; (c) a **per-connection** bounded supervised timer that emits `daemon.comms.ack{cumulative_ack}` via `runner.send_notification` when the high-water advanced, consumed (payload-blind) by the gateway's `_route_unit`.

**Tech Stack:** Python 3.12+, asyncio, Pydantic v2, `mypy --strict` + `pyright`, `ruff`, `pytest`. Design: `docs/superpowers/specs/2026-06-16-g4b2-replay-wiring-design.md` §9 (committed). No new deps.

---

## Context the engineer needs

**Where this sits.** Spec A **G4b-2a-pre** of the Comms-Resume Gateway (#237) — the daemon prerequisite for the gateway buffer wiring. Chain: G4b-2-pre (merged) → **2a-pre (this PR)** → 2a (gateway buffer) → 2b (reconnect-replay). **READ design doc §9 in full before coding** — it grounds every decision with `file:line`. This plan was hardened by a security + comms plan-review (findings F1-F6 folded in below).

**The confirmed gap (§9.1-9.2).** The daemon emits the `a=0` placeholder on every core→client frame (`comms_socket_transport.py:343`); the gateway's inbound wire seq is decoded then **discarded** at `_read_seq_frame` (`comms_socket_transport.py:440-447`); only the in-payload `inbound_id` survives to `commit_once` (`inbound.py:464`). So `trim_to_ack(frame.ack)` would be `trim_to_ack(0)` forever → the buffer never drains on a healthy link → steady-state breaker trip. This PR gives the daemon a real cumulative ack.

**The durable-intake invariant (the crux — §9.3b/§9.4).** `observe(wire_seq)` runs **only when `commit_once` returns `True`** (a fresh durable accept), placed right after that branch in `process_inbound_message`, before the rest of the pipeline. On the replay branch (`commit_once == False`, `inbound.py:464` returns early) and on the structural refusals AHEAD of the gate (cheap-validate `:422`, promoter-required `:437`) the tracker is NOT advanced. The ack then means "highest contiguous seq the core has DURABLY accepted" (spec §4 decision 4). `observe` is order-insensitive (the runner dispatches notifications as CONCURRENT background tasks — `comms_runner.py:586`), so the contiguous ack is correct under out-of-order dispatch.

### F1 (CRITICAL, both reviewers) — the seq MUST travel with its frame; a shared slot is racy

A per-transport `last_received_seq` slot is **unconditionally racy** and is REJECTED. The pump (`comms_runner.py:467-538`) is a single reader: it `read_frame()`s (where a slot would be set, `comms_socket_transport.py:440-447`), then `_spawn_notification_dispatch` runs the route as a **detached background task** and **immediately loops to read the next frame**. The notification is built much later, inside that task, at `session.py:738` (`InboundMessageNotification.model_validate(raw)`). So `read N (slot←seqN) → spawn task N → read N+1 (slot←seqN+1) → task N validates reading slot==seqN+1` — the wrong seq is stamped on frame N. If N+1 later refuses/replays while N commits, the gateway trims a frame the core never durably took → **input loss**.

**Mandated threading:** capture the decoded `frame.seq` at read time and carry it WITH its `(method, params)` through the dispatch path so it arrives at `model_validate` bound to its own frame. The cleanest small form: have the **socket carrier's** read fold the decoded seq into the returned mapping under a reserved key the host merges into `params` (socket-only; stdio never sets it), OR thread an explicit `wire_seq` param through `comms_runner._pump → session._on_post_handshake_method → _dispatch_comms_notification → _route_comms_notification` into the `model_validate(raw | {"wire_seq": seq})` merge. Pick whichever the real code makes smaller/race-free — BOTH are "bind seq to its frame." Do NOT add the slot.

### F3 (trust posture — record in the implementation + Self-Review)

`wire_seq` is **carrier header metadata** the daemon legitimately reads off its own wire — NOT payload-derived, and NOT used to derive `inbound_id` (the `(leg,seq,epoch)` derivation is forbidden until Spec B/C — `protocol.py:108-113`, design §2.2). Reachability: `None` is the unconditional default (stdio/Discord/reference plugins never carry a seq — back-compat + payload-blindness preserved); a non-`None` `wire_seq` can ONLY arrive on the seq-enabled **socket** leg, whose only peer is the gateway (T1-trusted carrier infra, not an untrusted plugin). Worst-case blast radius if a forged in-window seq advanced the tracker wrongly: it corrupts only the **gateway's buffer trim** (a liveness / possible-input-loss concern on the resume path), NOT the durable `commit_once` exactly-once guarantee (that's the in-payload `inbound_id`, untouched). `BoundedSeqAckTracker._MAX_OOO_GAP` bounds the memory-DoS and is loud on out-of-window (`_seq_tracker.py:72-80`). State this "trust impact: ack-trim liveness, not durable idempotency" in the Self-Review.

### F2/F4 (lifetime — both reviewers) — tracker AND timer are PER-CONNECTION

The host tracker needs no per-connection reset *today* ONLY because `CommsSocketListener` is one-shot per boot (`accept()` raises on a second call, `comms_socket_transport.py:629-636`; `_accept_and_pump` accepts once, `cli/daemon/_commands.py:1132`), so connection-lifetime == tracker-lifetime == boot-lifetime. This is a **load-bearing, non-obvious invariant** — pin it in a comment + test, and note that **G4b-2b's reconnect-replay MUST reset/reconstruct the tracker per accepted connection** (mirroring `core_link._peer_handshake`'s `self._core_tracker = BoundedSeqAckTracker()` reset, `core_link.py:617-623`), else the long-lived tracker carries the old connection's high-water and the new connection's seqs (restarting at 0) look already-settled → the daemon acks frames the new connection never sent.

**Therefore: construct the tracker AND schedule the timer at the per-connection accept point** (`_accept_and_pump`, `cli/daemon/_commands.py:1061-1109`), NOT in the per-boot carrier-agnostic `_build_comms_adapter_wiring`. Reap the timer in `_accept_and_pump`'s teardown `finally` using the per-connection cancel→`await gather(..., return_exceptions=True)` reap pattern already at `cli/daemon/_commands.py:1084-1090` — **NOT** `_CommsBootGraph.aclose` (that reaps process-singletons; wrong lifetime). The stdio path then never gets a needless tracker, and 2b's reset falls out for free when the accept loop arrives.

**i18n:** `daemon.comms.ack` + params are wire identifiers, not operator strings — no `t()`. No new audit reason (the ack is not a refusal; the existing replay-observed row suffices — state this in Task 5).

**STOP-and-surface rule.** If the real runner/session code makes the mandated seq-threading (F1) genuinely unworkable, STOP and report (BLOCKED/DONE_WITH_CONCERNS) rather than reverting to the racy slot or inventing a parallel pump — exactly as the G4b-1 implementer surfaced the table-totality issue.

---

## File structure (corrected paths — F6)

- **Modify:** `src/alfred/comms_mcp/protocol.py` — optional `wire_seq: int | None = None` on `InboundMessageNotification` (non-negative when present).
- **Modify:** `src/alfred/plugins/comms_socket_transport.py` — expose the decoded `frame.seq` from the read path so the host can bind it to the frame's `params` (F1 threading; NOT a shared slot).
- **Modify:** `src/alfred/plugins/comms_runner.py` + `src/alfred/plugins/session.py` — thread the per-frame seq from the pump to `_route_comms_notification` where `InboundMessageNotification.model_validate(raw)` runs (`session.py:717-738`).
- **Modify:** `src/alfred/comms_mcp/inbound.py` — inject `ack_tracker: BoundedSeqAckTracker | None = None`; `observe(notification.wire_seq)` on `commit_once == True` only; preserve the replay branch + None-store fallthrough byte-for-byte.
- **Modify:** `src/alfred/cli/daemon/_commands.py` (`_accept_and_pump` / `_build_comms_adapter_wiring`) — construct the per-connection tracker; wire it into `process_inbound_message`; schedule + reap the per-connection ack timer.
- **Modify:** `src/alfred/gateway/core_link.py` — `_route_unit` CONSUMES `daemon.comms.ack` in its OWN arm (before `_consume_frame`); no-op/log body (`trim_to_ack` is G4b-2a).
- **Tests:** `tests/unit/comms_mcp/`, `tests/unit/plugins/`, `tests/unit/gateway/` (extend the merged `_route_unit` consume test) + `tests/adversarial/` (F6).

---

### Task 1: `InboundMessageNotification.wire_seq` (optional, default None, non-negative)

**Files:** `src/alfred/comms_mcp/protocol.py`; test the model.

- [ ] **Step 1 (failing test):** the model accepts `wire_seq: int | None`, defaults `None`, round-trips `model_dump(mode="json")`→parse, a notification WITHOUT it still parses (back-compat), and a NEGATIVE `wire_seq` is REJECTED at validation (so a forged negative never reaches `observe`, which would `ValueError` — F2.2).
- [ ] **Step 2 (fail) → Step 3 (impl):** add `wire_seq: int | None = None` (after `addressing_signal`) with a `Field`/validator enforcing `>= 0` when present; docstring: carrier out-of-band wire seq (the gateway's per-connection client→core send-seq), `None` for plain/stdio adapters, used by the host durable-intake ack tracker, NEVER payload-derived. Keep `_WireModel`'s `extra="forbid"` (the default keeps it optional for producers that omit it).
- [ ] **Step 4 (pass) → Step 5 (commit):** `feat(comms): InboundMessageNotification.wire_seq for host durable-intake ack (Spec A G4b-2a-pre / ADR-0032) (#237)` + trailer.

### Task 2: Thread the per-frame wire seq to `model_validate` (F1 — travels with its frame)

**Files:** `src/alfred/plugins/comms_socket_transport.py`, `comms_runner.py`, `session.py`; tests.

- [ ] **Step 1 (read + confirm the path):** trace `_read_seq_frame` (`comms_socket_transport.py:405-447`, seq decoded then dropped) → `read_frame` → `comms_runner._pump` (`:467-538`, detaches dispatch) → `session._on_post_handshake_method` → `_dispatch_comms_notification` → `_route_comms_notification` → `model_validate(raw)` (`session.py:734-738`). The seq must arrive bound to ITS frame's `params` — implement EITHER (a) the socket carrier folds the decoded seq into the returned frame mapping under a reserved key the host lifts into the `model_validate` merge (socket-only; stdio frames never carry it), OR (b) an explicit `wire_seq: int | None` param threaded pump→route. Do NOT use a shared `last_received_seq` slot (F1, racy).
- [ ] **Step 2 (failing test):** a seq-enabled inbound frame `A1 s=5 a=0 |<body>` yields `InboundMessageNotification.wire_seq == 5`; a plain (seq-OFF) frame yields `wire_seq is None`; **two back-to-back inbound frames (`seq=5` then `seq=6`) under concurrent dispatch each yield their OWN seq** (the anti-race assertion — drive two dispatches and assert each notification's `wire_seq` matches its own payload, not the other's).
- [ ] **Step 3 (fail) → Step 4 (impl the chosen binding) → Step 5 (pass).**
- [ ] **Step 6 (commit):** `feat(comms): bind the inbound wire seq to its own dispatched frame (Spec A G4b-2a-pre / ADR-0032) (#237)` + trailer.

### Task 3: Host `BoundedSeqAckTracker` advanced on the durable commit (preserve the gate byte-for-byte)

**Files:** `src/alfred/comms_mcp/inbound.py`; tests.

- [ ] **Step 1 (failing tests, §9.5 surface):**
  - `wire_seq=0,1,2` each `commit_once → True` → `tracker.cumulative_ack() == 2`.
  - a REPLAYED `inbound_id` (`commit_once → False`) with a fresh wire seq does NOT advance (returns at the replay branch, never reaches `observe`).
  - a GAP `0,1,3` stalls the ack at `1` until `2` commits, then jumps to `3` (feed `observe` out-of-order to model concurrent dispatch).
  - a structural refusal ahead of the gate (promoter-required / cheap-validate) does NOT advance.
  - `wire_seq is None` (stdio) is a safe no-op.
  - `ack_tracker is None` (pre-G0 unit caller) path unchanged.
- [ ] **Step 2 (fail) → Step 3 (impl):** inject `ack_tracker: BoundedSeqAckTracker | None = None` (mirror the `idempotency_store`/`audit_writer` optional-injection). Restructure the `commit_once` gate, **preserving the existing behaviour byte-for-byte (F2.1)**:

  ```python
  if idempotency_store is not None:
      if not await idempotency_store.commit_once(inbound_id=notification.inbound_id, adapter_id=notification.adapter_id):
          # REPLAY branch — UNCHANGED: set_broker -> _emit_idempotency_replay_observed -> log -> return
          audit_hash.set_broker(secret_broker)
          await _emit_idempotency_replay_observed(notification, audit_writer=audit_writer)
          _log.info("comms.inbound.idempotency.replay_short_circuit", adapter_id=notification.adapter_id)
          return
      # durable accept (commit_once == True): advance the host intake ack (no await between).
      if ack_tracker is not None and notification.wire_seq is not None:
          ack_tracker.observe(notification.wire_seq)
  # None-store path (pre-G0 unit callers) falls through UNCHANGED to the rest of the pipeline.
  ```

  Confirm the `None`-store fallthrough still reaches resolution (must NOT skip the pipeline); confirm `commit_once`'s DB-error still PROPAGATES (not caught). `observe` reads off the VALIDATED model (Task 1's `>=0` validator already ran).
- [ ] **Step 4 (pass) → Step 5 (commit):** `feat(comms): host durable-intake ack tracker advanced on commit_once (Spec A G4b-2a-pre / ADR-0032) (#237)` + trailer.

### Task 4: Per-connection ack timer + gateway consume arm (F2/F4/F5)

**Files:** `src/alfred/cli/daemon/_commands.py`, `src/alfred/gateway/core_link.py`; tests both sides.

- [ ] **Step 1 (failing tests):**
  - first committed seq emits: `cumulative_ack()` goes `-1 → 0` → the timer DOES emit `daemon.comms.ack{cumulative_ack: 0}` (the last-emitted sentinel is `-1`, NOT `0` — F5; else the first trim never fires).
  - emit-only-on-advance: no advance since last emit → no frame (quiet-link suppression).
  - the emitted frame floors to `max(cumulative_ack, 0)` (the tracker returns `-1` before any commit — F5; mirror `core_link.py:751`).
  - the timer is reaped on the per-connection teardown (cancel→await), no leaked task (assert via the `_accept_and_pump` finally, NOT `_CommsBootGraph.aclose`).
  - the timer is fail-loud on a broken-pipe send (does not swallow into a quiet retry — F5).
  - the gateway's `_route_unit` lands `daemon.comms.ack` in its OWN consumed arm: NOT forwarded to `_payload_relay`, NOT routed into `_consume_frame` (no epoch / not a LinkStateMachine event), NOT counted as a dropped payload frame (F4).
- [ ] **Step 2 (fail) → Step 3 (impl):**
  - In `_accept_and_pump` (per-connection, after handshake — alongside the existing per-connection setup near `cli/daemon/_commands.py:1131`): construct the `BoundedSeqAckTracker`, inject it into the inbound wiring (`process_inbound_message`'s `ack_tracker`), and schedule a supervised timer task. Reap it in the SAME `finally` that tears down the connection (the cancel→`await gather(return_exceptions=True)` pattern at `:1084-1090`). The timer body, on a bounded interval (`Final` const, e.g. ~0.5-2s — ADR-0032 Decision 3 coalescing; document the choice), reads `tracker.cumulative_ack()`; iff `> last_emitted` (sentinel init `-1`) it emits `runner.send_notification("daemon.comms.ack", {"cumulative_ack": max(ack, 0)})` and updates `last_emitted`. Narrow + logged except only; never bare; a broken-pipe send re-raises loud (the pump's crash arm handles connection death). Note: `send_notification` rides IN the seq stream (consumes a send-seq, `comms_socket_transport.py:368` — that's WHY the gateway needs the consume arm; F5/comms-F5).
  - In `core_link._route_unit` (`:680-714`): define a `DAEMON_COMMS_ACK` method constant (where `DAEMON_LIFECYCLE_*` live) and add an arm that CONSUMES it **BEFORE** the `_consume_frame` lifecycle path (it has no epoch and is not a forgery-defended lifecycle frame) — consume = log/no-op for this PR (`trim_to_ack` is G4b-2a). Must NOT fall into the relay `else` (would leak the host control frame to the client) NOR into `_consume_frame` (would trip epoch validation every ack).
- [ ] **Step 4 (pass) → Step 5 (commit):** `feat(comms): per-connection timer-coalesced daemon.comms.ack + gateway consume arm (Spec A G4b-2a-pre / ADR-0032) (#237)` + trailer.

### Task 5: Adversarial entries + ADR-0032 vocabulary note + full gates

**Files:** `tests/adversarial/...`, `docs/adr/0032-*.md`; verify gates.

- [ ] **Step 1 (adversarial — F6):** add to `tests/adversarial/` (follow the existing comms adversarial dir pattern):
  - **forged/out-of-window `wire_seq` does not advance the durable-intake ack** — a `wire_seq` beyond `_MAX_OOO_GAP` is rejected loud (`gateway.relay.seq_out_of_window`) and `cumulative_ack` is unchanged (proves the F3 bound end-to-end through `process_inbound_message`).
  - **replay-after-commit does not double-advance the ack** (the exactly-once-vs-ack-monotonicity property; the existing replay-observed audit row is the evidence — no new audit reason).
- [ ] **Step 2 (ADR):** add `daemon.comms.ack` to ADR-0032's consumed-control-frame vocabulary (alongside `daemon.lifecycle.{ready,going_down}`), recording it as the **inbound-direction** durable-intake ack carrier (the §9.6 shape of Decision 3's coalesced ack; the ack SOURCE is the core's durable tracker, not a gateway one). Do NOT touch the lines-162-164 idempotency framing (that amendment is 2b). Markdownlint: `npx markdownlint-cli2@0.14.0 docs/adr/0032-*.md`.
- [ ] **Step 3 (gates):** coverage — touched daemon files keep their per-file gate bars (check `ci.yml`); `core_link.py` stays 100%. `uv run coverage run -m pytest tests/unit tests/adversarial -q && uv run coverage report --include='src/alfred/comms_mcp/inbound.py,src/alfred/gateway/core_link.py' --show-missing`. Then `make check` (NOT piped through `tail`). Known pre-existing flakes (re-run isolated if tripped, orthogonal): `tests/unit/memory/test_working_pool.py::TestPerKeyLock::test_per_key_asyncio_lock`; `tests/integration/cli/daemon/test_daemon_comms_inbound_turn.py::test_daemon_comms_inbound_turn_lands_t3_promotion_row` (#275).
- [ ] **Step 4 (commit):** `docs(adr): ADR-0032 records daemon.comms.ack consumed control frame (Spec A G4b-2a-pre) (#237)` + trailer.

---

## Self-Review

**Spec coverage (design §9):**

| Requirement | Task |
|---|---|
| carry the inbound wire seq inward, bound to its frame (NOT a slot) | Tasks 1-2 |
| host `BoundedSeqAckTracker` advanced ONLY on `commit_once == True` | Task 3 |
| replay / refusal / `wire_seq is None` / `None`-store do NOT advance | Task 3 |
| contiguous ack under out-of-order dispatch | Tasks 3-4 |
| PER-CONNECTION tracker + timer (one-shot-listener invariant pinned) | Task 4 |
| timer: emit-on-advance (sentinel `-1`), `max(ack,0)` floor, fail-loud, reaped per-connection | Task 4 |
| gateway `_route_unit` consumes in its OWN arm (before `_consume_frame`) | Task 4 |
| adversarial: forged-seq-no-advance + replay-no-double-advance | Task 5 |
| ADR-0032 vocabulary note (idempotency amendment deferred to 2b) | Task 5 |

**Plan-review findings folded in:** F1 (mandate seq-travels-with-frame, strike the slot — Task 2), F2 (per-connection tracker+timer at the accept point, one-shot invariant pinned, 2b reset obligation noted — Task 4), F3 (trust posture: ack-trim liveness not durable idempotency — Context + here), F4 (timer reaped in `_accept_and_pump` finally not `_CommsBootGraph.aclose`; consume arm before `_consume_frame` — Task 4), F5 (sentinel `-1`, `max(ack,0)` floor, fail-loud send — Task 4), F6 (corrected paths `cli/daemon/_commands.py`+`session.py`; adversarial entries — Tasks 2/4/5).

**Trust impact (F3):** a forged in-window `wire_seq` could only corrupt the **gateway buffer trim (liveness / resume-path input-loss)**, never the durable `commit_once` exactly-once (the in-payload `inbound_id`). `_MAX_OOO_GAP` bounds the memory surface; out-of-window is loud.

**Scope discipline:** daemon-only + the one gateway consume arm (no-op body). NO `ReplayBuffer`, NO `trim_to_ack` wiring, NO reconnect-replay — 2a/2b. ADR §6 idempotency amendment stays deferred to 2b.

**Placeholder scan:** Task 2's exact binding mechanism (carrier-folds-into-params vs threaded-param) is the one implementer decision, constrained to the two race-free forms (the racy slot is struck); STOP-and-surface if the real code makes both unworkable. Every other step is concrete.
