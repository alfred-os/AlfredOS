# G5 — Restart-survival proof (close #237 graduation criterion #7) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the release-blocking **deterministic integration test** that proves the full **chat → gateway → core** stack survives a core restart end-to-end — chat does not exit, the `link.reconnecting → link.restored` banners render, and in-flight un-acked operator input is **replayed** (the G4b-2b resume) — closing #237 graduation criterion #7. Plus a live-stack **smoke** (demotable to nightly).

**Architecture:** The `alfred chat` re-point to the gateway, the no-dual-mode dial, and banner rendering are ALREADY shipped (PR-S4-237-2). What is missing is the proof that the assembled stack actually resumes across a restart. The deterministic test wires a real `GatewayProcess` (injectable `core_dial` → a CONTROLLABLE fake core leg that can be "restarted" — close → next dial returns a fresh epoch) to a real cohosted chat wire pump (`run_cohosted` with an injected `dial` onto the gateway's in-memory client socket + a recording `on_link_state`). It drives input, restarts the core, and asserts survival + banner transitions + replay. No docker/Postgres — the core is the injectable fake.

**Tech Stack:** Python 3.12+, asyncio, `pytest` + `pytest-asyncio`, `mypy --strict` + `pyright`, `ruff`. The pieces (all merged): `GatewayProcess` (injectable `core_dial`), `GatewayCoreLink` (dial→handshake→pump→reconnect + G4b-2b replay), `GatewayClientListener`, `run_cohosted` (chat wire pump + banner callback), the `link.*` control vocabulary.

---

## Context the engineer needs

**Read first:** `src/alfred/gateway/process.py` (`GatewayProcess.__init__` — the injectable `core_dial: Callable[[], Awaitable[_CommsTransportLike]] | None`; `run()`), `src/alfred/gateway/core_link.py` (the reconnect loop + the G4b-2b `_flush_pending_replay`), `src/alfred/gateway/client_listener.py` (`send_control` + `control_notification`), `plugins/alfred_tui/src/alfred_tui/cohost.py` (`run_cohosted(*, adapter_id, dial, build_app_fn, on_link_state)` — the injectable seams; the pump routes `link.*` → `on_link_state`), `tests/integration/test_tui_round_trip.py` + `tests/integration/_comms_mcp_harness.py` (the existing in-process TUI/comms harness to model on), `src/alfred/comms_mcp/protocol.py` (`DAEMON_LIFECYCLE_{READY,GOING_DOWN}`, the `link.*` notifications, `LinkReconnectingNotification`/`LinkRestoredNotification`).

**The link-state vocabulary (what the gateway sends the client on a gap):** on `going_down`/EOF the gateway emits `link.reconnecting`; on the new core's validated `ready` it emits `link.restored`. The TUI's `on_link_state` callback receives the method string; `AlfredTuiApp.set_link_state` paints `tui.banner.{reconnecting,restored,unavailable}`.

**The controllable fake core:** a fake `_CommsTransportLike` that (a) completes the `lifecycle.start` handshake with a per-epoch 32-hex epoch, (b) echoes/acks the client→core payload units it receives, (c) can be told to "go down" (emit `daemon.lifecycle.going_down` then EOF, or a bare EOF) so the gateway reconnects, and (d) on the NEXT `core_dial` returns a FRESH instance with a NEW epoch. The `core_dial` thunk hands out successive fake cores from a list/queue.

---

### KEY DESIGN POINT FOR PLAN-REVIEW — deterministic restart vs live smoke

The design doc (§G5, lines 105/111) splits the proof: a **deterministic integration test carries the release-blocking proof** (it must be reliable on the required CI gate); a **live-stack smoke** (real `alfred gateway start` + `alfred chat` subprocesses + a real `alfred daemon` restart) is **demotable to nightly if flaky**. So:

- **Task 1–4 (the release-blocking core):** the deterministic in-process integration test — real `GatewayProcess` + controllable fake core + real `run_cohosted` chat pump over an in-memory client socket. NO subprocesses, NO docker, NO Postgres. This is what gates merge.
- **Task 5 (the smoke, lower bar):** a `tests/smoke/` test that drives the REAL CLI (`alfred gateway start` + `alfred chat` over a PTY) across a real `alfred daemon` restart, asserting the banner renders. Marked demotable-to-nightly (a `@pytest.mark` the smoke runner can skip) since a live PTY+subprocess+restart is inherently timing-sensitive. **STOP-and-surface if the smoke can't be made non-flaky in-budget** — the deterministic test is the actual gate, so a flaky smoke must be marked nightly, never block.

**Scope (G5 only):** the restart-survival PROOF (deterministic test + smoke) + any banner-wiring gap the test exposes. NOT in scope: Spec B (platform adapters), Spec C (egress / connectivity-free core), the signed-audit reconcile.

---

## File structure

- **Create:** `tests/integration/test_gateway_restart_survival.py` — the deterministic release-blocking proof (Tasks 1–4).
- **Create:** `tests/smoke/test_gateway_chat_restart_smoke.py` — the live-stack smoke (Task 5, demotable).
- **Modify (only if a gap is found):** `plugins/alfred_tui/src/alfred_tui/cohost.py` / `textual/app.py` — wire a missing banner transition (e.g. `link.restored` clearing) IF Task 2 exposes it; otherwise no production change.
- **Modify:** `.github/workflows/ci.yml` — ensure the new integration test runs on the required integration gate (it lives under `tests/integration/`, already collected — verify no new gate entry needed).
- **Modify (docs):** `docs/superpowers/specs/2026-06-13-comms-gateway-resume-design.md` / a short note that crit #7 is proven; the #237 issue gets the closing reference.

---

### Task 1: the harness — real gateway + controllable fake core + chat pump

**Files:** Create `tests/integration/test_gateway_restart_survival.py`.

- [ ] **Step 1 (build the controllable fake core):** a `_FakeCore` `_CommsTransportLike` that handshakes `lifecycle.start` with an injected epoch, ack-echoes client→core units, and exposes a `go_down()` (queue a `going_down` + EOF) — and a `_core_dial` thunk that pops successive `_FakeCore`s (each a fresh epoch) from a list. Model the handshake/ack framing on `tests/integration/_comms_mcp_harness.py` + the gateway unit-test fakes (`tests/unit/gateway/test_core_link.py`).
- [ ] **Step 2 (wire the stack):** construct a real `GatewayProcess(core_dial=_core_dial, ...)`; start its `run()` as a task; connect a real `run_cohosted` chat pump by injecting a `dial` that returns the in-memory client end of the gateway's client listener socket (model on `test_tui_round_trip.py`'s in-memory transport pair), and an `on_link_state` that RECORDS the method strings into a list. Assert the stack reaches steady state (handshake complete, no banner yet).
- [ ] **Step 3-5:** a smoke-of-the-harness test (stack builds + tears down cleanly, no leaked task); commit `test(integration): gateway+chat restart-survival harness — real gateway, controllable fake core (Spec A G5 / #237)` + trailer.

### Task 2: banner transition on a core restart

**Files:** `tests/integration/test_gateway_restart_survival.py`.

- [ ] **Step 1 (failing test):** drive the stack to steady state; call `fake_core.go_down()`; the gateway detects the gap → emits `link.reconnecting` to the chat client → the next `_core_dial` returns a fresh-epoch `_FakeCore` → the gateway handshakes it → emits `link.restored`. Assert the recorded `on_link_state` sequence is `["link.reconnecting", "link.restored"]` (the banner transitions), and the chat pump did NOT exit (the wire task is still alive). **If `link.restored` is never emitted/recorded** (a banner-wiring gap — the `restored` key is noted "reserved for future" in `app.py`), STOP and surface: the production gap is then in `GatewayCoreLink`'s not-UP→UP edge control emit or the TUI's restored handling — fix THAT (the smallest production change) in this task.
- [ ] **Step 2-5:** green; commit `test(integration): core restart paints reconnecting->restored banner, chat survives (Spec A G5 / #237)` + trailer (fold any banner-wiring production fix into this commit).

### Task 3: in-flight input is REPLAYED across the restart (the G4b-2b resume)

**Files:** `tests/integration/test_gateway_restart_survival.py`.

- [ ] **Step 1 (failing test, THE crit-#7 assertion):** send operator input frames from chat → gateway → fake core; before the fake core ACKS them (un-acked), call `go_down()`; after the reconnect, assert the SAME payloads are re-delivered to the NEW fake core (replayed with fresh seqs — the G4b-2b resume), in FIFO order, and that a subsequent post-restart input lands AFTER the replayed ones. This is the "nothing typed is lost across a core restart" proof. Assert the un-acked input is not duplicated at the application layer (the new core would dedup on `inbound_id`, but here assert the wire re-delivery + ordering).
- [ ] **Step 2-5:** green; commit `test(integration): un-acked operator input replays across a core restart (Spec A G5 / G4b-2b / #237)` + trailer.

### Task 4: the unavailable terminal + clean-teardown edges

**Files:** `tests/integration/test_gateway_restart_survival.py`.

- [ ] **Step 1 (failing tests):** (a) if the gateway's ReplayBuffer breaker trips (flood a wedged-never-acking core), the chat receives `link.unavailable` and the banner shows the unavailable state (terminal). (b) clean teardown: a gateway shutdown closes the chat wire gracefully (the pump returns, no leaked task, transports closed) — the hard-rule-#7 symmetric-teardown property end-to-end.
- [ ] **Step 2-5:** green; commit `test(integration): link.unavailable terminal + symmetric teardown end-to-end (Spec A G5 / #237)` + trailer.

### Task 5: the live-stack smoke (demotable to nightly)

**Files:** Create `tests/smoke/test_gateway_chat_restart_smoke.py`.

- [ ] **Step 1 (the smoke):** drive the REAL CLI — `alfred gateway start` (subprocess) + `alfred chat` over a PTY (model on the existing `tests/smoke/test_tui_e2e.py` PTY harness) against a real `alfred daemon`; send a line; `alfred daemon stop`+restart (or kill+respawn the daemon); assert `alfred chat` survives and the reconnecting/restored banner renders in the PTY. Mark it demotable: a `@pytest.mark.nightly`-style marker the smoke runner can exclude (the deterministic Tasks 1–4 carry the release-blocking proof). **STOP-and-surface if it cannot be made non-flaky in a reasonable budget** — mark nightly + document, never let it block merge.
- [ ] **Step 2-5:** green (or marked-nightly with a documented flake reason); commit `test(smoke): live core+gateway+chat survives a daemon restart, banner renders (Spec A G5 / #237)` + trailer.

### Task 6: close-out — crit #7 proven

**Files:** docs + the #237 reference.

- [ ] **Step 1:** a short note in `docs/superpowers/specs/2026-06-13-comms-gateway-resume-design.md` (or the runbook) that graduation criterion #7 is proven by `test_gateway_restart_survival.py`; the PR body references-closes the relevant #237 sub-issue (PR-4 PTY smoke). Markdownlint clean.
- [ ] **Step 2:** `make check` (full bar; NOT piped through `tail`; includes `ruff format --check`). Known flakes (re-run isolated): `test_per_key_asyncio_lock`, `test_daemon_comms_inbound_turn_lands_t3_promotion_row`, `test_dispatch_cycle_records_handler_returned_failed_outcome`.
- [ ] **Step 3 (commit):** `docs: record #237 graduation criterion #7 proven by the restart-survival test (Spec A G5) (#237)` + trailer.

---

## Self-Review

**Spec coverage (design §G5):** deterministic restart-survival proof (T1–T4: harness, banner transitions, input replay, unavailable/teardown) · live smoke demotable-to-nightly (T5) · crit #7 close-out (T6). The re-point + banner rendering are pre-shipped (verified); this plan proves them end-to-end.

**Plan-review flags:** (a) the deterministic-vs-smoke split — confirm the in-process harness (real gateway + fake core) is a faithful crit-#7 proof, not a mock that proves nothing; (b) whether `link.restored` is actually wired to fire+render (Task 2 may expose a production gap); (c) the input-replay assertion (T3) genuinely exercises the G4b-2b path (un-acked-before-restart → replayed-after), not a trivially-passing re-send.

**Type consistency:** `core_dial: Callable[[], Awaitable[_CommsTransportLike]]`, `run_cohosted(*, adapter_id, dial, build_app_fn, on_link_state)`, `on_link_state: Callable[[str], Awaitable[None]]`, the `link.*` method strings — consistent with the shipped seams.
