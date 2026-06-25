# G6-4a — GatewayLeg / TUI Leg-Ownership Migration (Task 7 of the single G6-4 PR)

> **DECISION (2026-06-20, after grounding): the "precursor PR" framing is SUPERSEDED — this is NOT a standalone PR.** `gateway_leg.py` imports `ingress_gate` + `ingress_audit` + `global_replay_cap` + `adapter_metrics`, so a standalone "leg-abstraction precursor" would necessarily ship the full G6-4 admission stack — the separation-of-review-concerns benefit evaporates. And migrating the TUI onto `GatewayLeg` is NOT a behavior-preserving refactor in isolation: the TUI becomes an admission-gated, fair-scheduled leg BY DESIGN (K3 reserves it priority credit) — it is intrinsic to G6-4's behavior change. So G6-4 ships as ONE coherent PR ("gateway leg-routing substrate + TUI-as-first-leg") on branch `spec-b-g6-4` (which already carries the machinery commits). **This document is now the detailed, fleet-reviewed sub-spec for the TUI-migration portion of G6-4 Task 7.** Its "Tasks 1-6" are the migration steps; its quality bar folds into G6-4 Task 9. The scheduler/process-wiring (K5 sweeper/teardown) + multi-leg restart-survival (K7) come from the parent G6-4 plan's Tasks 7-8. The RESUME-REGRESSION RISK is managed by the UNCHANGED G5 resume + restart-survival oracle + the PR1-PR13 corrections below — NOT by packaging.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the TUI dial-in the FIRST `GatewayLeg` instance and route it through the single `write_leg_unit` physical writer, so there is exactly ONE serialization point — proven behavior-preserving by the UNCHANGED G5 resume + restart-survival suites.

**Architecture:** `relay_to_core` today owns the single TUI leg inline (seq mint + `ReplayBuffer.append` + breaker-feed + reconnect capture/flush + single-buffer gauges). This precursor moves leg-owned state (`adapter_id`, buffer, per-leg seq, breaker latch, reconnect-replay seams) into a `GatewayLeg`-shaped owner and makes `write_leg_unit` the SOLE physical writer. It introduces NO scheduler fairness (one leg only), NO ingress gate, and NO global cap — those are G6-4 proper. The final SHAPE (`write_leg_unit` as sole writer; leg owns seq/buffer/breaker) is locked so G6-4 only ADDS legs.

**Tech Stack:** Python 3.12+, asyncio, structlog, prometheus_client, pytest + pytest-asyncio + hypothesis. `mypy --strict` + `pyright`. The correctness oracle is the EXISTING `tests/unit/gateway/test_core_link.py`, `tests/unit/gateway/test_relay.py`, and `tests/integration/test_gateway_restart_survival.py`.

---

## CRITICAL: judgment calls the human MUST resolve before execution

This precursor CANNOT be 1:1 behavior-preserving while reusing the EXISTING `GatewayLeg` verbatim, because the shipped `GatewayLeg` (commit `e1a64202`) is the G6-4-PROPER shape — it hard-couples a `GlobalReplayCap` + `PerAdapterIngressGate` and emits the per-adapter (labelled) `ADAPTER_BUFFER_DEPTH_*` gauges, NOT the unlabelled single-buffer `BUFFER_DEPTH_*` gauges the G5 TUI path emits. The four divergences below are flagged loudly; **`### Task N` bodies assume Decision A on each — change the task if you choose otherwise.**

- **JC-1 (metrics series).** G5 `relay_to_core` refreshes the UNLABELLED `BUFFER_DEPTH_FRAMES/BYTES/CAP_RATIO` + `CIRCUIT_BREAKER_OPEN` (`alfred.gateway.metrics`). The shipped `GatewayLeg` refreshes the LABELLED `ADAPTER_BUFFER_DEPTH_FRAMES/BYTES` (`alfred.gateway.adapter_metrics`) and does NOT touch cap-ratio/breaker gauges. Tests `test_refresh_buffer_metrics_*` assert the UNLABELLED gauges. **Decision A (assumed):** the migrated TUI leg keeps refreshing the UNLABELLED gauges (the leg owner refreshes BOTH the G5 unlabelled set AND, harmlessly, the per-adapter `tui`-labelled set), so the existing gauge tests pass unchanged. **Decision B:** rewrite the gauge tests to assert the per-adapter series — REJECTED here (not behavior-preserving; the G5 dashboards key on the unlabelled gauges).

- **JC-2 (breaker-feed / link-state escalation lives in the LEG vs the LINK).** G5 `relay_to_core` feeds `GatewayLinkEvent.BREAKER_TRIPPED` to the `LinkStateMachine` and writes the `gateway.comms.breaker_tripped` row at append time. The shipped `GatewayLeg.record_for_send` does NEITHER (the leg is pure-ish; it never reaches the machine). The fairness rationale only needs seq+buffer+breaker-LATCH in the leg — the link-state ESCALATION is a link concern. **Decision A (assumed):** the per-leg seq mint + `buffer.append` move into the leg owner; the breaker-FEED + `gateway.comms.breaker_tripped` row + `BREAKER_TRIPPED` machine event STAY in the link (in the new `write_leg_unit`-adjacent drain path), reading `leg.breaker_tripped` after the append. This preserves the once-only escalation edge the G5 + adversarial flood tests assert. **Decision B:** move the machine feed into the leg (needs the leg to hold a `_feed` callback) — heavier, larger blast radius, REJECTED.

- **JC-3 (global cap presence).** The shipped `GatewayLeg.record_for_send` calls `global_cap.reserve` and raises `ReplayBufferError` on refusal. The G5 path has no global cap. **Decision A (assumed):** the precursor introduces a `GlobalReplayCap` with an effectively-unbounded ceiling (`max_total_bytes = ReplayBuffer hard ceiling` = `2 * 8 MiB` for the one TUI leg) so the reserve NEVER refuses on the single-leg path — byte-for-byte behavior preservation (the existing hard-ceiling raise still fires first at the same point). **Decision B:** make the leg's global cap OPTIONAL (`global_cap: GlobalReplayCap | None`) so the TUI leg can run with NO cap — cleaner conceptually but EDITS the shipped `GatewayLeg` ctor + `record_for_send`/`_reclaim` (touches G6-4-proper code the adapter rebase depends on). **RECOMMEND Decision A** (zero edit to shipped `GatewayLeg`; the unbounded cap is a no-op).

- **JC-4 (reconnect capture/flush + `_replay_pending` gate ownership).** The capture (`unacked_frames` → `_pending_replay`, clear gate) + `reset_for_new_epoch` + `_flush_pending_replay` (re-send via the writer) + the `replay_pending_gate` are TUI-leg-shaped resume internals. The shipped `GatewayLeg` exposes `unacked_frames()` and `reset_for_new_epoch()` but NOT the `_pending_replay`/gate. **Decision A (assumed):** the `_pending_replay` tuple + `replay_pending_gate` + `_flush_pending_replay` STAY on `GatewayCoreLink` (they are link-lifecycle, driven from `run`/`_peer_handshake`), but they read the captured frames from `self._tui_leg.unacked_frames()` and reset via `self._tui_leg.reset_for_new_epoch()` instead of `self._replay_buffer.*`. The flush re-sends via `self._tui_leg.record_for_send()` + `write_leg_unit` (NOT `relay_to_core`). **Decision B:** move the gate into the leg — REJECTED (G6-4 proper schedules per-leg replay; do not pre-build it).

Everything below assumes **A on all four**.

---

## File Structure

| File | Create / Modify | Responsibility after this PR |
|---|---|---|
| `src/alfred/gateway/core_link.py` | Modify | Replace `_replay_buffer` + `_client_to_core_seq` with a single `_tui_leg: GatewayLeg`. `relay_to_core` RETIRED as a write path; the TUI client→core send goes through `_drain_tui_unit` → `write_leg_unit` (sole writer). Capture/flush read the leg. `__init__` swaps `replay_buffer: ReplayBuffer \| None` for `tui_leg: GatewayLeg \| None`. |
| `src/alfred/gateway/gateway_leg.py` | UNCHANGED | The shipped owning object is reused verbatim (JC-1..4 Decision A keep it edit-free). |
| `src/alfred/gateway/replay_buffer.py` | UNCHANGED | The `ReplayBuffer` class is reused verbatim, one instance per leg. |
| `src/alfred/gateway/relay.py` | Modify | `_client_to_core_pump` calls the new `core_link.submit_tui_unit(payload)` (the leg-routed replacement) instead of `relay_to_core`. `replay_buffer_tripped`/`replay_pending_gate` reads unchanged. |
| `src/alfred/gateway/process.py` | Modify | Build the `GatewayLeg` (`adapter_id="tui"`, the per-client `ReplayBuffer`, an unbounded `GlobalReplayCap`, a permissive `PerAdapterIngressGate`) and pass `tui_leg=` instead of `replay_buffer=`. |
| `tests/unit/gateway/test_core_link.py` | Modify (mechanical) | `_link_with_relay_and_buffer` + `_run_link` + `_capture_replay` construct a `GatewayLeg` wrapping the buffer and pass `tui_leg=`. Direct `link.relay_to_core(...)` calls become `link.submit_tui_unit(...)`. Construction-shape-only; assertions unchanged. |
| `tests/unit/gateway/test_relay.py` | Modify (mechanical) | The `_HaltStubCoreLink` gains `submit_tui_unit` (renamed from `relay_to_core`); `_build_relay` construction-shape update. |
| `tests/integration/_gateway_restart_harness.py` | Modify (mechanical) | `send_operator_input` is unchanged (it drives the REAL socket); only the harness's leg construction (if any direct `replay_buffer=` is passed) updates — VERIFY: it passes `replay_buffer_factory` to `GatewayProcess`, so only `process.py` changes, harness UNCHANGED. |
| `tests/adversarial/comms/test_gateway_reconnect_replay.py` | Modify (mechanical) | Direct `link.relay_to_core(...)` → `link.submit_tui_unit(...)`; leg construction-shape. |
| `tests/adversarial/comms/test_gateway_wedged_core_flood.py` | Modify (mechanical) | Same: `relay_to_core` → `submit_tui_unit`; the breaker-flood assertions unchanged (JC-2 keeps the feed in the link). |
| `docs/adr/0032-gateway-comms-resume-transport.md` | Modify | Dated G6-4a annotation: `relay_to_core` retired; the single writer is now `write_leg_unit`; the TUI is leg `tui`. |
| `docs/subsystems/comms.md` | Modify (if it names `relay_to_core`) | VERIFY + annotate. |
| `.github/workflows/ci.yml` | UNCHANGED | `core_link.py` + `relay.py` + `process.py` + `gateway_leg.py`-adjacent are ALREADY in both per-file 100% gates (lines 277/319 + the G6-4 commits added `gateway_leg.py`). VERIFY `gateway_leg.py` is in the include list; if not, ADD it (it is touched-adjacent). |

---

## Complete enumeration of every `relay_to_core` caller (134 references; from the graph + grep)

PRODUCTION call sites (only TWO — these are what the migration rewires):

1. `src/alfred/gateway/relay.py:239` — `GatewayRelay._client_to_core_pump`: `await self._core_link.relay_to_core(frame.payload)`. **Rewire → `await self._core_link.submit_tui_unit(frame.payload)`.**
2. `src/alfred/gateway/core_link.py:563` — `GatewayCoreLink._flush_pending_replay`: `await self.relay_to_core(frame.payload)`. **Rewire → the flush re-sends through the leg: `seq = self._tui_leg.record_for_send(frame.payload); await self.write_leg_unit(self._tui_leg.adapter_id, frame.payload, seq=seq, ack=self.core_cumulative_ack())`.**

The remaining 132 references are NON-call: docstrings in `core_link.py` (lines 304, 522, 533, 544, 545, 567, 639, 863, 1011, 1049, 1096, 1098, 1108, 1111, 1159), `gateway_leg.py` (4, 134), `relay.py` (15, 39, 144, 173), `status_leg.py` test refs, and TEST bodies/comments. Every TEST that CALLS `link.relay_to_core(...)` directly (the `submit_tui_unit` rename in tasks 3–6) is enumerated in those tasks; every COMMENT/docstring mention is updated in Task 8 (docs sweep) for accuracy but is not load-bearing.

Test call sites to rewire (`link.relay_to_core(` → `link.submit_tui_unit(`): `tests/unit/gateway/test_core_link.py` lines 1661,1681,1682,1704,1708,1721,1725,1736,1737,1743,1762,1778,1820,1843,1861,1862,1876,1926,1948,1966,1985,2003,2269,2270,2291,2316,2343,2367,2368,2375,2428,2429,2448,2499,2502,2532,2533,2534,2535,2554,2572,2616,2618,2932,2943,2966,3003,3133(method-assign),3187,3236; `tests/adversarial/comms/test_gateway_reconnect_replay.py` lines 164,212,285,343,370,398,441; `tests/adversarial/comms/test_gateway_wedged_core_flood.py` (its direct relay calls). `tests/unit/gateway/test_relay.py:708` is the STUB method (rename to `submit_tui_unit`).

---

## Behavior-preservation argument (why the existing suites are a sufficient oracle)

The migration preserves the four externally-observable behaviors the resume contract depends on, each pinned by an existing test:

1. **Per-leg FIFO seq mint, contiguous, advancing on a loud-dropped send, resetting on a fresh epoch.** `record_for_send` mints `seq = self._send_seq; self._send_seq += 1` BEFORE the buffer append — IDENTICAL ordering to `relay_to_core`'s `seq = self._client_to_core_seq; self._client_to_core_seq += 1`. Pinned by `test_relay_to_core_mints_contiguous_seq_and_passes_it_explicitly`, `..._loud_drop_still_advances_the_send_seq`, `..._none_transport_drop_does_not_consume_a_seq`, `test_peer_handshake_resets_the_client_to_core_seq`, `test_minted_core_seqs_are_contiguous_within_a_leg` (hypothesis). NOTE the `none_transport` case: in G5 the None-transport drop happens BEFORE the mint; in the migrated path `submit_tui_unit` MUST keep the None-check ahead of `record_for_send` (the leg never mints on a dead leg) — Task 3 encodes this.
2. **Append-before-send: a loud-dropped send still leaves the frame buffered.** `record_for_send` appends, then `write_leg_unit` best-effort-sends + loud-drops. Pinned by `..._appends_inbound_frame_keyed_on_wire_seq`, `..._loud_drop_still_leaves_frame_buffered`.
3. **Breaker trip → once-only `LinkControl.UNAVAILABLE` + one `gateway.comms.breaker_tripped` row + client read-halt.** JC-2 Decision A keeps the feed in the link, reading `leg.breaker_tripped` after `record_for_send`. Pinned by `..._breaker_trip_escalates_link_unavailable_once`, `..._breaker_idempotent_refeed_no_second_escalation`, and the merge-blocking `tests/adversarial/comms/test_gateway_wedged_core_flood.py` + integration `test_wedged_core_trips_breaker_and_chat_shows_unavailable_banner`.
4. **Reconnect capture + FIFO fresh-seq flush + `replay_pending` gate discipline + terminal zeroing.** Capture reads `leg.unacked_frames()`, resets via `leg.reset_for_new_epoch()`, flush re-sends via the leg+writer; the gate stays on the link. Pinned by `test_flush_pending_replay_*` (5 tests), `test_run_reconnect_flushes_replay_before_pump_resumes`, `test_run_discards_replay_buffer_on_terminal_exit_zeroing_pre_dlp_bytes`, and the crit-#7 integration `test_unacked_operator_input_replays_across_a_core_restart`.

The single physical writer + `_current_core_transport` snapshot atomicity (architect M3) are preserved because `write_leg_unit` ALREADY snapshots `local = self._current_core_transport` first and is the only `send_payload_unit` caller after this PR. Payload-blindness (#5): `record_for_send`/`write_leg_unit`/`ReplayBuffer` never parse the body (`adapter_id` is the only key). Fail-loud (#7): loud-drop on a dead transport preserved verbatim. **The integration restart-survival canary running GREEN UNCHANGED is the strongest single proof** — it drives REAL chat → REAL socket → gateway → fake-core across a restart and asserts the exact replayed FIFO/fresh-seq order.

---

## Tasks

### Task 0: Pin the oracle — capture the current GREEN baseline

**Files:** none (read-only baseline).

- [ ] **Step 1:** Run the full oracle suite to confirm it is GREEN before any change.

Run:

```bash
uv run pytest tests/unit/gateway/test_core_link.py tests/unit/gateway/test_relay.py -q
uv run pytest tests/integration/test_gateway_restart_survival.py -q
uv run pytest tests/adversarial/comms/test_gateway_reconnect_replay.py tests/adversarial/comms/test_gateway_wedged_core_flood.py -q
```

Expected: all PASS. Record the counts — every later task must keep these counts (minus renamed-method mechanical diffs).

- [ ] **Step 2:** No commit (baseline only).

### Task 1: `GatewayCoreLink` accepts a `tui_leg` alongside the legacy `replay_buffer` (additive, no behavior change)

**Files:**

- Modify: `src/alfred/gateway/core_link.py` (`__init__`)
- Test: `tests/unit/gateway/test_core_link.py`

- [ ] **Step 1: Write the failing test** (append to `test_core_link.py`):

```python
@pytest.mark.asyncio
async def test_tui_leg_injection_is_accepted_and_exposed() -> None:
    """A ``GatewayLeg`` injected as ``tui_leg`` is held and exposed read-only."""
    from alfred.gateway.gateway_leg import GatewayLeg
    from alfred.gateway.global_replay_cap import GlobalReplayCap
    from alfred.gateway.ingress_gate import PerAdapterIngressGate
    from alfred.gateway.replay_buffer import ReplayBuffer

    buf = ReplayBuffer()
    cap = GlobalReplayCap(max_total_bytes=16 * 1024 * 1024)
    gate = PerAdapterIngressGate(
        "tui", sustained_rate_per_s=1e9, burst=1_000_000, max_inflight=1_000_000,
        ttl_seconds=1e9, max_frame_bytes=1 << 30, now=lambda: 0.0,
    )
    leg = GatewayLeg(adapter_id="tui", buffer=buf, ingress_gate=gate, global_cap=cap, now=lambda: 0.0)
    link = GatewayCoreLink(client_listener=_RecordingClientListener(), tui_leg=leg)  # type: ignore[arg-type]
    assert link._tui_leg is leg
```

- [ ] **Step 2: Run — verify it fails.** Run: `uv run pytest tests/unit/gateway/test_core_link.py::test_tui_leg_injection_is_accepted_and_exposed -q`. Expected: FAIL — `GatewayCoreLink.__init__() got an unexpected keyword argument 'tui_leg'`.

- [ ] **Step 3: Implement** — in `core_link.py` `__init__`, add the param and store it, KEEPING `replay_buffer` for now (Task 7 removes it):

```python
        replay_buffer: ReplayBuffer | None = None,
        tui_leg: "GatewayLeg | None" = None,
    ) -> None:
        ...
        self._replay_buffer = replay_buffer
        # G6-4a (#288): the TUI is the FIRST GatewayLeg. When injected it OWNS the
        # buffer + per-leg seq + breaker latch; the legacy ``replay_buffer`` slot is
        # retired in Task 7 once every path reads the leg.
        self._tui_leg = tui_leg
```

Add `from alfred.gateway.gateway_leg import GatewayLeg` under `TYPE_CHECKING` (or top-level — no import cycle: `gateway_leg` does not import `core_link`).

- [ ] **Step 4: Run — verify it passes.** Run: `uv run pytest tests/unit/gateway/test_core_link.py::test_tui_leg_injection_is_accepted_and_exposed -q`. Expected: PASS. Also rerun the full `test_core_link.py` — still GREEN (additive).

- [ ] **Step 5: Commit.**

```bash
git add src/alfred/gateway/core_link.py tests/unit/gateway/test_core_link.py
git commit -m "feat(gateway): GatewayCoreLink accepts a tui_leg owner (additive) (Spec B G6-4a, #288)"
```

Body trailer: `MrReasonable <4990954+MrReasonable@users.noreply.github.com>`

### Task 2: Add `submit_tui_unit` (the leg-routed client→core send) routed through `write_leg_unit`

**Files:**

- Modify: `src/alfred/gateway/core_link.py` (new `submit_tui_unit`)
- Test: `tests/unit/gateway/test_core_link.py`

- [ ] **Step 1: Write the failing test** — mirror `test_relay_to_core_sends_payload_with_cumulative_ack` against the leg path. Add a helper `_link_with_tui_leg(buffer)` (constructs the leg as in Task 1 and passes `tui_leg=`), then:

```python
@pytest.mark.asyncio
async def test_submit_tui_unit_sends_via_write_leg_unit_with_cumulative_ack() -> None:
    buf = ReplayBuffer()
    link = _link_with_tui_leg(buf)
    transport = _FakeCoreTransport([])
    link._current_core_transport = transport
    for seq in (0, 1, 2):
        link._core_tracker.observe(seq)
    await link.submit_tui_unit(b'{"id":1,"result":{}}')
    assert transport.sent_units == [(b'{"id":1,"result":{}}', 0, 2)]
    assert buf.depth_frames == 1  # append-before-send via the leg
```

- [ ] **Step 2: Run — verify it fails.** `uv run pytest tests/unit/gateway/test_core_link.py::test_submit_tui_unit_sends_via_write_leg_unit_with_cumulative_ack -q`. Expected: FAIL — `'GatewayCoreLink' object has no attribute 'submit_tui_unit'`.

- [ ] **Step 3: Implement `submit_tui_unit`** in `core_link.py` (mirrors the G5 `relay_to_core` ordering EXACTLY, but routes the mint+append into the leg and the physical send into `write_leg_unit`; JC-2 keeps the breaker feed here):

```python
    async def submit_tui_unit(self, payload: bytes) -> None:
        """Forward an opaque TUI client payload through the TUI leg + single writer (G6-4a).

        The leg-routed replacement for the retired ``relay_to_core``. Snapshots the core
        transport FIRST (None -> loud drop, NO seq minted — preserving the G5
        none-transport-no-mint semantics), then the LEG mints the seq + appends to its
        buffer (append-before-send), feeds the breaker escalation here (JC-2: link owns
        the LinkStateMachine), and hands the pre-sequenced unit to ``write_leg_unit`` (the
        SOLE physical writer). Loud-drop, never raise, never buffer beyond the leg.
        """
        if self._current_core_transport is None:
            log.warning("gateway.relay.core_send_dropped", reason="no_core_transport")
            return
        assert self._tui_leg is not None  # submit path is only reached on a leg-wired link
        ack = self.core_cumulative_ack()
        seq = self._tui_leg.record_for_send(payload)
        if self._tui_leg.breaker_tripped:
            control = await self._feed(GatewayLinkEvent.BREAKER_TRIPPED)
            if control is LinkControl.UNAVAILABLE:
                log.warning(
                    "gateway.comms.breaker_tripped",
                    depth_frames=self._tui_leg.depth_frames,
                    depth_bytes=self._tui_leg.depth_bytes,
                )
        self._refresh_buffer_metrics()
        await self.write_leg_unit(self._tui_leg.adapter_id, payload, seq=seq, ack=ack)
```

NOTE: `_refresh_buffer_metrics` (JC-1 Decision A) is updated in Task 4 to read the leg's depth onto the UNLABELLED gauges. For now it reads `self._replay_buffer`; since the leg wraps the SAME `ReplayBuffer` instance, point it at the leg in Task 4.

- [ ] **Step 4: Run — verify it passes.** `uv run pytest tests/unit/gateway/test_core_link.py::test_submit_tui_unit_sends_via_write_leg_unit_with_cumulative_ack -q`. Expected: PASS.

- [ ] **Step 5: Commit.**

```bash
git add src/alfred/gateway/core_link.py tests/unit/gateway/test_core_link.py
git commit -m "feat(gateway): submit_tui_unit routes the TUI leg through write_leg_unit (Spec B G6-4a, #288)"
```

### Task 3: Reconnect capture + flush read the leg (not `_replay_buffer`)

**Files:**

- Modify: `src/alfred/gateway/core_link.py` (`_peer_handshake` capture block; `_flush_pending_replay`)
- Test: `tests/unit/gateway/test_core_link.py` (the `_capture_replay` helper + the 5 `test_flush_pending_replay_*` + `test_run_reconnect_flushes_replay_before_pump_resumes`)

- [ ] **Step 1: Update the `_capture_replay` helper** (construction-shape; BEFORE/AFTER):

BEFORE:

```python
async def _capture_replay(link: GatewayCoreLink, payloads: list[bytes]) -> None:
    leg1 = _FakeCoreTransport([])
    link._current_core_transport = leg1
    for payload in payloads:
        await link.relay_to_core(payload)
    ...
```

AFTER (the only changes: `relay_to_core` → `submit_tui_unit`; the link is already leg-wired by `_link_with_tui_leg`):

```python
async def _capture_replay(link: GatewayCoreLink, payloads: list[bytes]) -> None:
    leg1 = _FakeCoreTransport([])
    link._current_core_transport = leg1
    for payload in payloads:
        await link.submit_tui_unit(payload)
    ...
```

This is **mechanical-not-behavioral**: the leg wraps the same buffer; capture still reads exactly the un-acked remainder.

- [ ] **Step 2: Run — verify the flush tests FAIL** against the un-migrated impl. `uv run pytest tests/unit/gateway/test_core_link.py -k flush_pending_replay -q`. Expected: FAIL (capture still keys off `_replay_buffer`, but the leg-wired link has `_replay_buffer is None` → nothing captured).

- [ ] **Step 3: Implement** — in `_peer_handshake`, change the capture block to read the leg; in `_flush_pending_replay`, change the re-send to the leg+writer. Replace the `if self._replay_buffer is not None:` capture block with:

```python
        leg = self._tui_leg
        if leg is not None:
            self._pending_replay = self._pending_replay + tuple(
                ReplayFrame(seq=s, payload=p) for (s, p) in leg.unacked_frames()
            )
            if self._pending_replay:
                self._replay_pending.clear()
            leg.reset_for_new_epoch()
            self._refresh_buffer_metrics()
```

And in `_flush_pending_replay`, replace `await self.relay_to_core(frame.payload)` with:

```python
                seq = leg.record_for_send(frame.payload)
                await self.write_leg_unit(leg.adapter_id, frame.payload, seq=seq, ack=self.core_cumulative_ack())
```

(bind `leg = self._tui_leg` at the top of the method; the per-connection seq reset in `record_for_send`'s `reset_for_new_epoch` already restarts the flush seqs at 0). Keep the R1 None-transport defer + the `finally` gate-set verbatim.

- [ ] **Step 4: Run — verify it passes.** `uv run pytest tests/unit/gateway/test_core_link.py -k "flush_pending_replay or reconnect_flushes" -q`. Expected: PASS. NOTE: `test_flush_pending_replay_relay_raise_still_sets_gate` monkeypatches `link.relay_to_core = _boom` — UPDATE it to `link.submit_tui_unit = _boom` and call `submit_tui_unit` in `_flush_pending_replay`? NO — the flush no longer calls `submit_tui_unit`, it calls `record_for_send`+`write_leg_unit`. **Construction-shape change:** rewrite that test to monkeypatch `link.write_leg_unit = _boom` (the raise-point moved); the gate-set fail-safe is unchanged. Show this BEFORE/AFTER in the test diff.

- [ ] **Step 5: Commit.**

```bash
git add src/alfred/gateway/core_link.py tests/unit/gateway/test_core_link.py
git commit -m "feat(gateway): reconnect capture + flush read the TUI leg (Spec B G6-4a, #288)"
```

### Task 4: Terminal-exit zeroing + gauges read the leg; evict loop reads the leg

**Files:**

- Modify: `src/alfred/gateway/core_link.py` (`_refresh_buffer_metrics`, `_buffer_evict_loop`, `run`'s `finally` discard, the `run` evict-task spawn guard)
- Test: `tests/unit/gateway/test_core_link.py` (`test_refresh_buffer_metrics_*`, `test_run_discards_replay_buffer_on_terminal_exit_*`, evict-loop tests)

- [ ] **Step 1: Write/adjust the failing tests** — the gauge tests already assert the UNLABELLED gauges (JC-1 Decision A keeps them). They construct via `_link_with_relay_and_buffer`; change that helper to `_link_with_tui_leg`-shaped (BELOW). They drive `link.submit_tui_unit(...)` (rename). The terminal-zeroing test holds `buf._retained[0].body` — unchanged (the leg wraps the same buffer).

- [ ] **Step 2: Run — verify FAIL.** With the helper renamed but impl still reading `_replay_buffer`, the gauges stay 0 → FAIL.

- [ ] **Step 3: Implement** — point the four buffer-reading methods at the leg:
  - `_refresh_buffer_metrics`: read `self._tui_leg` (None-guard) → set the UNLABELLED `BUFFER_DEPTH_FRAMES/BYTES/CAP_RATIO/CIRCUIT_BREAKER_OPEN` from `leg.depth_frames/depth_bytes/cap_ratio/breaker_tripped`. The leg ALSO refreshes its own per-adapter gauges inside `record_for_send` — harmless (JC-1).
  - `_buffer_evict_loop`: `evicted = leg.evict_expired()` (the leg's `evict_expired` takes no `now` — it uses the injected `now`; VERIFY the leg `now` is wired to the same monotonic seam in Task 6 process wiring).
  - `run` spawn guard + `finally` discard: `if self._tui_leg is not None:` → `evict_task` spawn; `finally` calls `self._tui_leg.discard()`.
  - `_on_evict_task_done` unchanged.

- [ ] **Step 4: Run — verify PASS.** `uv run pytest tests/unit/gateway/test_core_link.py -k "refresh_buffer_metrics or discards_replay_buffer or evict" -q`. Expected: PASS.

- [ ] **Step 5: Commit.**

```bash
git add src/alfred/gateway/core_link.py tests/unit/gateway/test_core_link.py
git commit -m "feat(gateway): metrics + evict + terminal zeroing read the TUI leg (Spec B G6-4a, #288)"
```

### Task 5: Sweep the remaining unit-test construction shapes + rename direct relay calls

**Files:** Modify: `tests/unit/gateway/test_core_link.py`, `tests/unit/gateway/test_relay.py`

- [ ] **Step 1:** Replace `_link_with_relay_and_buffer(buffer=buf)` body to build a `GatewayLeg` and pass `tui_leg=`; keep its signature so callers are unchanged. Provide the helper:

```python
def _link_with_tui_leg(buf: ReplayBuffer) -> GatewayCoreLink:
    cap = GlobalReplayCap(max_total_bytes=buf._max_bytes * 2)  # unbounded for one leg (JC-3 A)
    gate = PerAdapterIngressGate("tui", sustained_rate_per_s=1e9, burst=10**9,
        max_inflight=10**9, ttl_seconds=1e9, max_frame_bytes=1 << 30, now=lambda: 0.0)
    leg = GatewayLeg(adapter_id="tui", buffer=buf, ingress_gate=gate, global_cap=cap, now=lambda: 0.0)
    return GatewayCoreLink(client_listener=_RecordingClientListener(), payload_relay=_RelaySink(), tui_leg=leg)  # type: ignore[arg-type]
```

- [ ] **Step 2:** Bulk-rename every direct `link.relay_to_core(` → `link.submit_tui_unit(` in `test_core_link.py` (the enumerated line list). For the `_run_link` helper (used by `run`-driving tests) add a `tui_leg`-building path mirroring `_link_with_tui_leg` when a buffer is requested.
- [ ] **Step 3:** In `test_relay.py`, rename `_HaltStubCoreLink.relay_to_core` → `submit_tui_unit` and update `_build_relay` to construct a leg-wired `GatewayCoreLink`.
- [ ] **Step 4: Run** `uv run pytest tests/unit/gateway/test_core_link.py tests/unit/gateway/test_relay.py -q`. Expected: ALL PASS (counts match Task 0 minus any removed legacy-only `_replay_buffer`-named tests — there should be NONE removed; only renamed-method bodies).
- [ ] **Step 5: Commit.**

```bash
git add tests/unit/gateway/test_core_link.py tests/unit/gateway/test_relay.py
git commit -m "test(gateway): migrate unit tests to the tui_leg construction shape (Spec B G6-4a, #288)"
```

### Task 6: Wire `GatewayRelay` + `GatewayProcess` to the leg; retire `relay_to_core`

**Files:** Modify: `src/alfred/gateway/relay.py`, `src/alfred/gateway/process.py`, `src/alfred/gateway/core_link.py` (DELETE `relay_to_core` + the now-dead `_replay_buffer`/`_client_to_core_seq`)

- [ ] **Step 1: Write the failing test** — a `process.py` test asserting it builds a `tui` leg and passes `tui_leg=` (or assert via the integration smoke). Minimal unit:

```python
def test_process_builds_tui_leg_not_raw_buffer(...): ...  # assert the constructed core_link._tui_leg.adapter_id == "tui"
```

- [ ] **Step 2: Run — FAIL** (process still passes `replay_buffer=`).
- [ ] **Step 3: Implement.**
  - `relay.py:239`: `await self._core_link.submit_tui_unit(frame.payload)`. Update docstrings (lines 15,39,144,173) to name `submit_tui_unit` / the single writer.
  - `process.py`: in `run`, build the leg from `self._replay_buffer_factory()` + an unbounded `GlobalReplayCap` + a permissive `PerAdapterIngressGate(now=self._monotonic)` and pass `tui_leg=leg` instead of `replay_buffer=`. Wire the leg `now=self._monotonic` (matches the evict-loop clock).
  - `core_link.py`: DELETE `relay_to_core`, the `_replay_buffer` slot, the `_client_to_core_seq` slot, and the `replay_buffer` ctor param. Update `replay_buffer_tripped`/`replay_buffer` properties to read the leg (`return self._tui_leg.breaker_tripped if self._tui_leg is not None else False`). Update the `__all__`/docstrings.
- [ ] **Step 4: Run** the full unit + integration + adversarial oracle:

```bash
uv run pytest tests/unit/gateway -q
uv run pytest tests/integration/test_gateway_restart_survival.py -q
uv run pytest tests/adversarial/comms/test_gateway_reconnect_replay.py tests/adversarial/comms/test_gateway_wedged_core_flood.py -q
```

Expected: ALL PASS (the adversarial direct-`relay_to_core` calls were renamed in this task's adversarial sweep — fold those edits in here). The restart-survival canary GREEN UNCHANGED is the behavior-preservation proof.

- [ ] **Step 5: Commit.**

```bash
git add src/alfred/gateway/relay.py src/alfred/gateway/process.py src/alfred/gateway/core_link.py tests/
git commit -m "feat(gateway): retire relay_to_core; TUI is the first leg through write_leg_unit (Spec B G6-4a, #288)"
```

### Task 7: Adversarial-suite sweep (the security-blocking proof)

**Files:** Modify: `tests/adversarial/comms/test_gateway_reconnect_replay.py`, `tests/adversarial/comms/test_gateway_wedged_core_flood.py`

- [ ] **Step 1:** Rename direct `link.relay_to_core(` → `link.submit_tui_unit(` (enumerated lines) and build the leg-wired link via the shared helper. The wedged-core flood test's breaker assertions are UNCHANGED (JC-2 kept the feed in the link). The reconnect-replay test's FIFO/fresh-seq assertions are UNCHANGED.
- [ ] **Step 2: Run the FULL adversarial suite** (release-blocking — `src/alfred/gateway` is trust-boundary-adjacent):

```bash
uv run pytest tests/adversarial -q
```

Expected: PASS.

- [ ] **Step 3: Commit.**

```bash
git add tests/adversarial/comms/
git commit -m "test(gateway): migrate adversarial gateway suite to submit_tui_unit (Spec B G6-4a, #288)"
```

### Task 8: Docs + ADR annotation + comment accuracy sweep

**Files:** Modify: `docs/adr/0032-gateway-comms-resume-transport.md`, `docs/subsystems/comms.md` (if it names `relay_to_core`), `src/alfred/gateway/core_link.py`+`gateway_leg.py`+`relay.py` (docstring accuracy)

- [ ] **Step 1:** Add to ADR-0032 (the doc that records the single-writer / `relay_to_core` shape — VERIFIED at lines 139/183/187/201/205):

```
> **G6-4a annotation (#288):** `relay_to_core` is retired. The TUI dial-in is now the
> first `GatewayLeg` (`adapter_id="tui"`); its client→core send goes through
> `GatewayCoreLink.submit_tui_unit` → the leg-agnostic `write_leg_unit`, which is the
> SOLE physical writer (G6-4 proper adds N more legs behind the same writer + a fair
> scheduler). The seq mint + `ReplayBuffer.append` now live in `GatewayLeg`; the
> breaker-feed / `LinkStateMachine` escalation + the `_replay_pending` gate stay on the
> link. Snapshot atomicity + append-before-send + loud-drop semantics are unchanged.
```

- [ ] **Step 2:** Sweep `core_link.py`/`gateway_leg.py`/`relay.py` docstrings that still describe `relay_to_core` as the live write path; correct to `submit_tui_unit`/`write_leg_unit`. (Comment-accuracy, not behavior.)
- [ ] **Step 3:** Run markdownlint on the COMMITTED docs only (the plan doc is NOT committed):

```bash
npx markdownlint-cli2 docs/adr/0032-gateway-comms-resume-transport.md docs/subsystems/comms.md
```

Expected: clean.

- [ ] **Step 4: Commit.**

```bash
git add docs/adr/0032-gateway-comms-resume-transport.md docs/subsystems/comms.md src/alfred/gateway/
git commit -m "docs(gateway): annotate ADR-0032 + correct docstrings for relay_to_core retirement (Spec B G6-4a, #288)"
```

### Task 9: Full quality bar (the release gate)

**Files:** none (gate run).

- [ ] **Step 1: Lint + format.**

```bash
uv run ruff check . && uv run ruff format --check .
```

Expected: clean.

- [ ] **Step 2: Type check (strict, both checkers).**

```bash
uv run mypy src/ && uv run pyright src/
```

Expected: clean. Watch the `tui_leg: GatewayLeg | None` import (no cycle) and the deleted-`_replay_buffer` references.

- [ ] **Step 3: Per-file 100% line+branch coverage gates** for every changed gateway module that has a CI per-file gate (VERIFIED in `.github/workflows/ci.yml` lines 277 + 319: `core_link.py`, `relay.py`, `process.py`, `replay_buffer.py` are all listed; CONFIRM `gateway_leg.py` is listed — if not, add it to BOTH include lists in a `ci.yml` edit folded into Task 8):

```bash
uv run coverage run --branch -m pytest tests/unit/gateway
uv run coverage report --include='src/alfred/gateway/core_link.py,src/alfred/gateway/relay.py,src/alfred/gateway/process.py,src/alfred/gateway/gateway_leg.py' --show-missing --fail-under=100
```

Expected: 100% line+branch on each. If `submit_tui_unit`'s `assert self._tui_leg is not None` or a None-guard is uncovered, add a targeted test.

- [ ] **Step 4: Full touched-module unit run.**

```bash
uv run coverage run --branch -m pytest tests/unit
uv run pytest tests/integration/test_gateway_restart_survival.py -q
uv run pytest tests/adversarial -q
```

Expected: ALL PASS.

- [ ] **Step 5: i18n drift.** NO `t()` strings change in this PR (the gateway emits only structlog keys, no operator-facing catalog strings — VERIFIED: `process.py` docstring says "No t() here"). So no `pybabel` step is required; CALL THIS OUT in the PR description rather than running a needless extract. If a reviewer disputes, run `uv run pybabel extract` + `uv run pybabel update --check` and confirm zero drift.

- [ ] **Step 6: Commit any coverage-driven test additions** (only if Step 3 surfaced a gap):

```bash
git add tests/unit/gateway/
git commit -m "test(gateway): close coverage gaps on submit_tui_unit guards (Spec B G6-4a, #288)"
```

---

## Self-review (run before handing off)

- **Spec coverage:** K1 (TUI = one `GatewayLeg`, one code path) → Tasks 1–6; behavior-preserving oracle → Task 0 + the unchanged-assertion sweeps; single writer preserved → `write_leg_unit` sole caller (Task 6 deletes `relay_to_core`); ReplayBuffer class untouched → File Structure + JC-3 A; ADR annotation → Task 8; quality bar → Task 9. No G6-4-proper scheduler/ingress/global-cap wiring is added (only the unbounded-cap no-op per JC-3 A).
- **Placeholder scan:** every code step shows real code; every command has expected output. The four JC decisions are explicit human gates, not placeholders.
- **Type consistency:** `submit_tui_unit(payload: bytes) -> None`, `record_for_send(payload) -> int`, `write_leg_unit(adapter_id, payload, *, seq, ack) -> None`, `unacked_frames() -> tuple[tuple[int, bytes], ...]` (note: leg returns `(seq, payload)` pairs — Task 3 wraps them in `ReplayFrame` for `_pending_replay`, which is `tuple[ReplayFrame, ...]`; the flush reads `frame.seq`/`frame.payload`). `core_cumulative_ack() -> int`. All consistent across tasks.

---

## Plan-review corrections (MUST apply — architect + core-engineer + security + test + performance, 2026-06-20)

All 5 reviewers returned approve-with-changes; the split (precursor + rebase) is endorsed as the 11b pattern done right (a behavior-preserving refactor of shipped G5 resume internals, proven by an unchanged oracle, must NOT be entangled with G6-4's new fairness behavior). The findings CONVERGE on the corrections below. **These OVERRIDE conflicting earlier task text.** Do NOT start Task 2/3 until PR2/PR3/PR4/PR5 are reflected.

### PR1 (HIGH — test F1 + security #5) — `gateway_leg.py` is NOT in the CI per-file gates; "100% on both" is FALSE

`ci.yml` per-file gate include-lists (~lines 277/319) list `replay_buffer.py` but NOT `gateway_leg.py`. Code moving OUT of 100%-gated `core_link.py` INTO un-gated `gateway_leg.py` can silently drop coverage while merge stays green. **Fix (Task 9, hard step — not "confirm if"):** ADD `src/alfred/gateway/gateway_leg.py` (and `global_replay_cap.py` if newly reachable from the TUI path) to BOTH ci.yml include-lists AND both `hashFiles(...)` guards; run the EXACT ci.yml coverage command, NOT a partial `--include` of four files.

### PR2 (HIGH — architect JC-3 + core-engineer JC-3 + security #2) — relabel JC-3 as a NON-BINDING aggregate cap; ceiling STRICTLY ABOVE the buffer hard ceiling

Drop the "effectively-unbounded no-op" framing — it is dishonest and bakes a value G6-4 must re-edit. The honest statement: with a SINGLE leg there is no aggregate-across-legs constraint, so the buffer's OWN hard ceiling is the binding constraint; the `GlobalReplayCap` becomes binding only when G6-4 adds a 2nd leg. **The cap ceiling MUST be set STRICTLY ABOVE the buffer hard ceiling** (e.g. `sys.maxsize`, or `_max_bytes * 4`) so `ReplayBuffer.append`'s hard-ceiling raise ALWAYS fires first — a cap sized == the hard ceiling could refuse at the exact boundary, flipping the loud-fail from the buffer's hard-ceiling `ReplayBufferError` (G5 behavior) to a cap-refusal `ReplayBufferError` with a different message/path and breaking a test asserting the hard-ceiling message. Reconcile the Task-1-test value (`16MiB`) and the Task-5 helper (`_max_bytes * 2`) to ONE strictly-above-hard-ceiling value. Add a test asserting `submit_tui_unit` NEVER raises a CAP-refusal on the single leg (only ever the buffer's own hard-ceiling raise) + an accounting invariant `cap.total_bytes == leg.depth_bytes` after any append/trim/discard/reset.

### PR3 (CRITICAL — core-engineer C1 + architect #5 + security #2) — preserve `relay_to_core`'s NEVER-RAISE contract in `_flush_pending_replay` + broken-pipe self-healing

`record_for_send` can raise `ReplayBufferError`; the old `relay_to_core` never raised in the flush (loud-drop only). An uncaught raise escapes into `run`'s reconnect path → fail-loud→crash regression. With PR2's non-binding cap the cap won't raise, and a flush of the JUST-CAPTURED remainder cannot exceed the buffer ceiling it just fit in, so the hard-ceiling won't fire either — **state this invariant explicitly in Task 3 AND pin it with a test**; if the invariant cannot be proven, guard the flush re-send to preserve the never-raise contract. ALSO add the broken-pipe-mid-flush test: capture N frames → fresh leg with `send_unit_error=BrokenPipeError` → run flush → assert the N frames are re-buffered (`leg.depth_frames == N`, append-before-send self-healing) AND replay again on the next epoch EXACTLY ONCE (the existing suite covers only None-transport-mid-flush, not broken-pipe — a coverage gap).

### PR4 (HIGH — core-engineer H2) — FIFO-merge: PREPEND deferred remainder ahead of this epoch's capture

G5 prepends deferred-from-prior-None frames AHEAD of the new capture (`self._pending_replay + tuple(...)` — `_pending_replay` is the LEFT operand). Task 3 preserves R1 FIFO ONLY because of that operand order. **Cite the FIFO-merge invariant explicitly in Task 3 and pin it with the existing deferred-remainder test** so an implementer "cleaning up" the concatenation cannot silently break replay ordering.

### PR5 (HIGH — core-engineer H1) — None-check stays STRICTLY AHEAD of `record_for_send`

A None transport mid-send/flush must NOT consume a leg seq (G5 mints AFTER the None-check). Keep `record_for_send` strictly inside the post-None-check arm in BOTH `submit_tui_unit` and the flush loop; add an assertion-comment so an implementer cannot hoist the mint above the None-check for "efficiency" (would burn seqs and corrupt the seq-space). Retarget+keep the existing `none_transport_drop_does_not_consume_a_seq` test.

### PR6 (MEDIUM — architect M1 + core-engineer M1 + test F3) — monkeypatch BOTH raise-points; fix the circular prose

`test_flush_pending_replay_relay_raise_still_sets_gate`: the raise-point moved. Retarget to `write_leg_unit = _boom` AND add a SECOND variant boobytrapping `record_for_send` to raise — both must still hit the `finally` gate-set (the `finally` covers both, but only one is exercised otherwise → 100%-branch-gate gap + avoids the test passing vacuously). Clean up the circular "UPDATE it to… NO —" prose in Task 3 Step 4 so the implementer encodes the right targets.

### PR7 (MEDIUM — security #2) — Task 4 MUST keep the per-seq TTL-evict LOUD audit emit

The `gateway.comms.buffer_evicted` row per dropped seq lives in `_buffer_evict_loop` (core_link.py:412-413), NOT in `leg.evict_expired()`. Task 4 Step 3 must EXPLICITLY retain `for seq in evicted: log.warning("gateway.comms.buffer_evicted", ...)` (hard rule #7) — the plan bullet currently mentions only the call, not the emit.

### PR8 (HIGH — test F2 + F4) — add the `submit_tui_unit` branch tests masked by the non-binding cap

`submit_tui_unit` is NEW code in 100%-gated `core_link.py`; its branches need direct tests: (a) the breaker-feed-reorder / JC-2 once-only edge — N `submit_tui_unit` appends breaching the soft cap → `BREAKER_TRIPPED` fed EXACTLY once + EXACTLY one `gateway.comms.breaker_tripped` row (drive `submit_tui_unit` directly, not via the flood harness); (b) the `assert self._tui_leg is not None` branch; (c) the None-drop branch (PR5). The leg-internal cap-refusal/reserve-release branches live in `gateway_leg.py` and are covered by `test_gateway_leg.py` — CONFIRM they are (re PR1's gate), do not assume.

### PR9 (MEDIUM — test F5) — assert terminal `discard()` preserves the seq floor

Add an explicit assertion in the terminal-zeroing test that `leg.discard()` on terminal exit zeros bodies but does NOT reset the seq floor (only `reset_for_new_epoch` does) — catches a future leg refactor folding discard into reset (the terminal-vs-reconnect distinction the G5 comment relies on).

### PR10 (MEDIUM — test F6) — re-run the integration test AFTER Task 5's shared-fake edits

The restart-survival harness imports `_DialRecorder`/`_ScriptedCoreTransport` from `test_core_link.py`; Task 5 edits those helpers. Add a Task 8 step re-running `tests/integration/test_gateway_restart_survival.py` AFTER Task 5 (the plan only runs it in Task 6/9) to catch an import-shape break in the shared fakes early.

### PR11 (MEDIUM — architect #4) — ADR treatment

Annotate ADR-0032 (resume transport — it records the single-writer / `relay_to_core` shape; annotation, NOT a new ADR, since the DECISION is unchanged and only the implementation locus moves). ALSO add a one-line ADR-0036 cross-reference noting the TUI is now the canonical FIRST `GatewayLeg` instance the adapter-inversion builds on, so the two ADRs don't drift.

### Smaller (MUST unless noted)

- **PR12 (LOW — security #4):** add a self-review line asserting `_pending_grants` / `request_spawn_grant` / `_route_spawn_grant` (the G6-3 credential correlation) are NOT perturbed by the refactor.
- **PR13 (LOW — perf M-1):** note in JC-1 that the UNLABELLED `_refresh_buffer_metrics` is a single-TUI-leg compatibility shim; G6-4 must NOT call it per-non-TUI-leg drain — only the leg's OWN labelled refresh scales (keep it O(1)-per-frame, never O(N)-over-legs / the perf-H3 trap).
- **perf/clock:** verify the leg's injected `now` is the SAME `self._monotonic` callable the old `evict_expired(now=...)` used (Task 6) — the buffer raises on non-monotonic `now`.

### Disposition of the four judgment calls

JC-1 (keep unlabelled gauges) — SOUND (no resume property reads gauges; see PR13). JC-2 (breaker-feed + audit row stay on the link, read `leg.breaker_tripped` after append) — SOUND and architecturally REQUIRED (the `LinkStateMachine` is link-lifecycle; moving it would lose the once-only edge — see PR8a test). JC-3 — AMENDED by PR2 (non-binding cap, ceiling strictly above the hard ceiling; not a "no-op"). JC-4 (`_pending_replay`/gate/`_flush_pending_replay` stay on the link) — SOUND (link-lifecycle; reads `leg.unacked_frames()`/`reset_for_new_epoch()` — see PR4 FIFO + PR3 never-raise).
