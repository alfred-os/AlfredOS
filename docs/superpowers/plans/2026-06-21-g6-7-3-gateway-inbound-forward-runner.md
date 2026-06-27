# G6-7-3 — GatewayInboundForwardRunner + the gateway forward path Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Steps use `- [ ]`. **This plan has open design forks flagged `PLAN-REVIEW` — resolve them via an architect+security plan-review BEFORE locking the bite-sized TDD steps.**

**Goal:** Replace the fail-loud `GatewayProcess._unwired_runner_factory` with a session-LESS `GatewayInboundForwardRunner` that reuses the G6-7-2 inbound-disposition seam to FORWARD a hosted Discord child's `inbound.message` (opaque, byte-for-byte) to the core over a per-adapter ADR-0031 leg — adapter_id minted from the spawn binding (SEC-309-1), the four child-notification types given explicit dispositions (§3.1), and leg-full handled as reader back-pressure (§3.6). The core-side receive/dispatch is G6-7-4.

**Architecture:** A new `GatewayForwardDisposition` (implements the G6-7-2 `InboundDisposition`) routes `inbound.message` → `core_link.forward_adapter_inbound(adapter_id, body)`; `rate_limit_signal`/`binding_request`/any-unknown → loud audited gateway-local drop. `core_link.forward_adapter_inbound` wraps the opaque body in a `GatewayAdapterInboundEnvelope` (`gateway.adapter.inbound`) and **enqueues it on the per-adapter GatewayLeg** (seq/ack + ReplayBuffer → resume for free), NOT the bare status `send` channel. `GatewayInboundForwardRunner` is a thin construction of `CommsPluginRunner` with the forward disposition and **no session collaborators** (the F1 design commitment). The process wires a real `adapter_runner_factory` + registers a per-adapter (discord) leg.

**Tech Stack:** Python 3.14, asyncio, Pydantic v2, structlog, pytest. AlfredOS gateway (`src/alfred/gateway/`) + the G6-7-2 seam (`src/alfred/plugins/`).

---

## Grounding (verified facts — engineer must not re-derive)

- **The factory contract:** `GatewayAdapterChildFactory` calls `runner = self._runner_factory(transport=transport, adapter_id=adapter_id)` (`adapter_child_factory.py:275`) then `await runner.start_and_handshake()`. The `_RunnerLike` Protocol (`process.py:101-110`) requires only `async start_and_handshake()`. The supervisor owns the steady-state pump lifetime + crash detection (`wait_until_exit`), NOT the factory. **So the runner must expose `start_and_handshake()`; the supervised TaskGroup runs `pump()`.** (Confirm how the supervisor drives `pump()` for a hosted adapter — `adapter_supervisor.py:347+`.)
- **`_unwired_runner_factory`** (`process.py:209-228`) raises `GatewayAdapterSpawnError`. G6-7-3 replaces the production wiring: `GatewayProcess(adapter_runner_factory=<forward factory>)`.
- **The 3 session-touch sites in `CommsPluginRunner`** (the rest of the pump is session-independent): (1) `_handshake()` → `self._session._on_handshake_complete()` (`comms_runner.py:502` — the daemon's gate+audit arm); (2) `_route_transport_crash()` → `self._session._on_post_handshake_method("adapter.crashed", …)` (`:841`); (3) `_request_restart()` → `self._session._supervisor` (`:858`, already logs loud when the supervisor is None). The G6-7-2 disposition seam already removed the 4th (`_route_notification`).
- **Envelope** (`protocol.py:540-567`): `GatewayAdapterInboundEnvelope(adapter_id: AdapterId, body: bytes | str)`; method const `GATEWAY_ADAPTER_INBOUND = "gateway.adapter.inbound"` (`protocol.py:440`). `body` is opaque, carried byte-for-byte; the gateway NEVER `json.loads` it.
- **Leg write path:** the per-adapter `GatewayLeg` is drained by `GatewayLegScheduler` → `core_link.write_leg_unit(adapter_id, payload, seq=, ack=)` (`core_link.py:1253+`, K1 single writer). Enqueue is `GatewayLeg.record_for_send(...)` which raises `LegQueueFullError` (per-leg) / `ReplayBufferError` (global cap). G6-4 registered only the **TUI** leg (`scheduler.register_leg(tui_leg)`, `core_link.set_leg_router(LegRouter(scheduler))`, `process.py:203-206`). **G6-7-3 must register a discord leg.**
- **Spawn binding:** the supervisor passes `adapter_id` → factory → `runner_factory(transport=, adapter_id=)`. The forward runner mints the envelope `adapter_id` from THIS param (SEC-309-1), never the body.
- **Mirror pattern:** `core_link.send_status_frame` / `request_spawn_grant` (`core_link.py:1306-1372`) build method-bearing frames from supervision metadata — but they use the non-replayable `send()` channel. **`forward_adapter_inbound` must NOT copy that channel choice (see FORK-B).**
- **CI gates:** gateway-kernel per-file 100% gate is duplicated (python-job ~`ci.yml:306-309` + coverage-gates ~`1369-1372`): a hashFiles guard + an `--include` list each = up to 4 edit points. Add `src/alfred/gateway/inbound_forward_runner.py` to all.

---

## Design forks to resolve in plan-review (architect + security)

### FORK-A — session-less runner realisation `[PLAN-REVIEW]`

**Recommendation: make `session` Optional on `CommsPluginRunner`** (spec §3.1 "thin construction … with no session collaborators"). When `session is None`:

- `_handshake()` SKIPS `_on_handshake_complete()` — the gateway has NO capability gate (core-side by design / connectivity-free-core); the gate legitimately does not run here. It still performs the transport-level lifecycle.start + ack read + shape validation.
- `_route_transport_crash()` becomes a LOUD log only (no session route) — per §3.1 the supervisor's `wait_until_exit` owns crash detection; the gateway must NOT synthesize a session-bound `adapter.crashed`.
- `_request_restart()` already logs loud when supervisor is None (no change).

**Alternative (separate class):** a `GatewayInboundForwardRunner` that does not subclass/construct `CommsPluginRunner` but reuses extracted pump helpers. Heavier; risks DRY divergence of the audited reader.

**Question for review:** session-Optional (adds None-branches to the most-tested module, each needing 100% coverage + a behaviour-preserving daemon-path gate) vs a thin gateway runner that owns its own handshake but delegates the pump? Which keeps the capability-gate boundary clearest + the reader single-audited? Either way the gateway path must NOT bypass any gate that SHOULD apply (there is none gateway-side — confirm).

### FORK-B — the forward carrier channel `[PLAN-REVIEW]`

**Recommendation: the `gateway.adapter.inbound` envelope rides the per-adapter LEG payload-unit path** (`record_for_send` → scheduler → `write_leg_unit` → seq/ack → ReplayBuffer), NOT the bare `send()` channel — so the forwarded inbound gets resume + replay byte-stability (§3.2 item 1, ADR-0039 item 2/6; SEC-309-2). The envelope (method + adapter_id + opaque body) is serialized as the leg payload bytes. This is what makes §3.6's `LegQueueFullError` handling meaningful (the bare `send` channel has no queue). **Confirm:** the exact `GatewayLeg.record_for_send` signature + whether the method-bearing envelope is serialized whole as the leg payload, and how the core HOST runner then sees it as a `gateway.adapter.inbound` notification (G6-7-4 dependency — the receive side decodes the leg payload back to the envelope).

### FORK-C — back-pressure mechanism (§3.6) `[PLAN-REVIEW]`

On `LegQueueFullError`/`ReplayBufferError` from `record_for_send`, the forward runner must PAUSE the child-stdio read loop (no drop, no spin, no pump-death). **Recommendation:** the forward disposition signals back-pressure to the pump via a shared `asyncio.Event`/condition the pump checks at the top of `_pump()` before the next `read_frame`, released when the scheduler drains. **Question:** is coupling the disposition→pump via a back-pressure primitive acceptable on the G6-7-2 seam (the disposition currently cannot signal the pump), or should the forward runner own a bespoke pump that bakes in the pause? This interacts with FORK-A.

### FORK-D — per-adapter (discord) leg registration `[PLAN-REVIEW]`

G6-4 registered only the TUI leg. G6-7-3 must create + register a discord `GatewayLeg` with the scheduler + LegRouter so `forward_adapter_inbound("discord", …)` routes. **Confirm:** the `GatewayLeg` construction API (per-leg replay cap under the global aggregate), where in `process.py` boot to register it (alongside the supervisor wiring for the configured `adapter_ids`), and the LegRouter's forged-adapter refusal still holds.

---

## File structure (subject to FORK resolutions)

| File | Responsibility |
| --- | --- |
| `src/alfred/gateway/inbound_forward_runner.py` (**NEW**) | `GatewayForwardDisposition` (implements `InboundDisposition`: the §3.1 four-notification table) + `GatewayInboundForwardRunner` (thin `CommsPluginRunner` construction, session-less) + the gateway-local audit/structlog rows. Trust-boundary → both ci.yml per-file 100% gates. |
| `src/alfred/gateway/core_link.py` (modify) | `forward_adapter_inbound(adapter_id, body)` — build `GatewayAdapterInboundEnvelope` (adapter_id from spawn binding) + enqueue on the per-adapter leg (FORK-B). |
| `src/alfred/plugins/comms_runner.py` (modify, IF FORK-A=session-optional) | `session: AlfredPluginSession \| None`; None-branches for handshake-complete + transport-crash; behaviour-preserving for the daemon path. |
| `src/alfred/gateway/process.py` (modify) | Replace `_unwired_runner_factory` wiring with the real forward-runner factory; register the per-adapter discord leg (FORK-D). |
| `tests/unit/gateway/test_inbound_forward_runner.py` (**NEW**) | Disposition table, SEC-309-1 spawn-binding-origin spy, payload-blindness (no `json.loads`), byte-stable forward, leg-full back-pressure pause, loud-drop arms. |
| `.github/workflows/ci.yml` (modify) | Register the new module in both gateway-kernel per-file 100% gates. |

## Task skeleton (finalise to bite-sized TDD AFTER plan-review)

1. **`core_link.forward_adapter_inbound`** (FORK-B carrier) — build envelope from the spawn-binding adapter_id, enqueue on the per-adapter leg, raise/propagate `LegQueueFullError` to the caller (the disposition handles back-pressure), loud-drop only on a genuine transport fault. Test: envelope adapter_id == the passed arg (NOT body-derived); body forwarded byte-for-byte; leg-full surfaces to the caller (not swallowed).
2. **`GatewayForwardDisposition`** — the §3.1 table: `inbound.message`→`forward(adapter_id, body)` with `forward_accepted`/`forward_dropped` structlog; `adapter.rate_limit_signal`→`gateway.adapter.rate_limit_signal.dropped` loud audited; `adapter.binding_request`→`gateway.adapter.binding_request.dropped` loud audited; any other method→loud audited drop. Never raises (fire-and-forget contract). SEC-309-1: the disposition gets `adapter_id` from construction (spawn binding), passes it to `forward`, NEVER reads it from `params.body`. Tests: each arm; the gateway-originate spy proving adapter_id provenance; payload-blindness (the disposition never `json.loads` the body).
3. **`GatewayInboundForwardRunner`** (FORK-A) — thin construction of `CommsPluginRunner` (session-less) with the forward disposition; expose `start_and_handshake`/`pump`/`run`. Tests: handshake works with no session/gate; a transport crash ends the pump without a session route; the disposition receives notifications.
4. **Back-pressure** (FORK-C) — leg-full pauses the reader; released on drain. Test: a full-leg sink → the child-stdio reader pauses (no drop, no spin, no death), resumes when the scheduler drains.
5. **`process.py` wiring** (FORK-D) — real `adapter_runner_factory` building `GatewayInboundForwardRunner`; register the discord leg with scheduler+LegRouter for the configured `adapter_ids`; delete the `_unwired_runner_factory` production path (keep its fail-loud for an unconfigured factory). Test: an in-process (non-root) forward — a fake child's `inbound.message` reaches `core_link.forward_adapter_inbound` and lands as a `gateway.adapter.inbound` leg unit; `_unwired_runner_factory` still refuses when no factory is wired.
6. **CI gates + i18n + full bar** — register the new module in both gateway-kernel gates; any new `t()` operator string reserved; full quality bar; per-file 100%.

## §6 adversarial/in-process companions (this slice ships the NON-root ones; privileged real-spawn is G6-7-7)

- SEC-309-1 gateway-originate spy (envelope id from spawn binding, never body) — release-blocking property, in-process.
- Payload-blindness spy (no `json.loads` of the body in the gateway).
- SEC-309-2 byte-stability (the forwarded body is byte-identical to the child's `params.body`).
- The four-notification disposition coverage incl. the two loud-audited drops + the unknown-method loud drop.
- Leg-full reader-pause (no drop / no spin / no death).

## Plan-review corrections (MUST apply) — architect + security + core + comms, 2026-06-21

**FORK-A — RESOLVED: session-Optional on `CommsPluginRunner` (unanimous).** `session: AlfredPluginSession | None`. None-branches: `_handshake` skips `_on_handshake_complete` (gateway has no capability gate — it's core-side by design, §3.7; NOT a dropped control); `_route_transport_crash` → loud-log only (supervisor owns crash via `wait_until_exit`); `_request_restart` → **add a None guard** (CORE-FIX: `self._session._supervisor` NPEs when session is None — the plan's "no change" was wrong). MUST ship a test asserting the **daemon path (session present) is byte-for-byte unchanged** (`_on_handshake_complete` + crash-synth still fire) — a future daemon must not get a gate-skipping `session=None` runner; None is only the gateway construction site. Each None-branch at per-file 100%.

**FORK-B — RESOLVED + MECHANIC CORRECTED (comms, decisive).** The envelope rides the **leg payload-unit path** (resume/byte-stability; the bare `send()` channel is non-durable, no queue). **`forward_adapter_inbound` does NOT call `GatewayLeg.record_for_send`** — that is DRAIN-time, scheduler-only (`leg_scheduler.py:289`). The PRODUCER enqueues via `core_link`'s **`LegRouter.route(adapter_id, payload)` → `scheduler.enqueue(adapter_id, payload)`** (raises `LegQueueFullError` per-leg / `ReplayBufferError` global-cap / `KeyError` unregistered). So `forward_adapter_inbound(adapter_id, body)`: (1) build `GatewayAdapterInboundEnvelope(adapter_id=<spawn-binding id>, body=body)`; (2) serialize the WHOLE envelope (method + adapter_id + opaque body) to `payload: bytes`, body **byte-for-byte, no re-encode** (a `str` body via `model_dump_json` stays verbatim; a `bytes` body must avoid a lossy round-trip — **pin the exact serializer** + a SEC-309-2 byte-stability test asserting the serialized payload's body member equals the child's `params.body` byte-identical, AND survives a ReplayBuffer round-trip identical); (3) hand to the `LegRouter` the link already holds (`set_leg_router`); `LegQueueFullError`/`ReplayBufferError` SURFACE to the caller for FORK-C. The core HOST runner sees `method == "gateway.adapter.inbound"` after the leg unit drains+decodes (G6-7-4's `reparse_forwarded_inbound`).

**FORK-C — RESOLVED: shared back-pressure `asyncio.Event`, pump-checked, mirroring `relay.py:257` `replay_pending_gate.wait()`.** The producer RAISES on full (no blocking-enqueue exists), and the G6-7-2 `dispatch` Protocol is one-way (no return channel) — so the Event is the mechanism. Inject an optional `back_pressure_gate: asyncio.Event | None = None` into `CommsPluginRunner`; `_pump` awaits it at the TOP before the next `read_frame` ONLY when present (daemon passes None → pump byte-for-byte unchanged). On `LegQueueFullError`/`ReplayBufferError` the forward path CLEARS the gate (pause); the **scheduler-drain SETS it** (resume) — keep the set/clear ownership clear and the Event a forward-runner collaborator, NOT part of `InboundDisposition`. **Shutdown MUST win** (the pump's `_read_frame_or_shutdown` race / a `shutdown_event` check so a permanently-full leg during drain never wedges). **Cancellation-safe** (a force-cancel during a pause unwinds cleanly). Reap/clear the gate on teardown so a left-cleared gate can't wedge a restart. Test contract: full leg (BOTH `LegQueueFullError` AND `ReplayBufferError`) → reader PAUSES (no drop, no spin, no death) → scheduler drains → reader RESUMES; force-cancel-during-pause unwinds; emit a `gateway.adapter.inbound.backpressure_engaged`/`released` structlog pair (§3.6 "never silent"). (Core's synchronous-in-reader simplification — no `_spawn_notification_dispatch`, simpler `_inflight` teardown — is an ACCEPTABLE realization IF it keeps the daemon path untouched; the Event + the test contract above are the requirement either way.)

**FORK-D — RESOLVED + SCOPE REDUCED (comms): ~half-built.** `build_adapter_leg` + `_register_adapter_legs` ALREADY exist (`process.py:313-332`) and construct a BINDING `GatewayLeg` per `self._adapter_ids` + `scheduler.register_leg` them. The work: (1) confirm `run()` calls `_register_adapter_legs` after `wire_leg_scheduler` (the architect flagged `wire_leg_scheduler` currently hard-codes a single `tui_leg` — confirm the discord leg is registered in lockstep, and update any gateway-chain integration proofs that call it); (2) inject the real `adapter_runner_factory`. Use `build_adapter_leg(adapter_id, replay_buffer_factory=, monotonic=)`, NEVER the raw `GatewayLeg` ctor (it wires the per-leg cap under the shared `GlobalReplayCap` + the finite binding ingress gate). LegRouter forged-adapter refusal (`router.py:55`) + the `register_leg` duplicate-guard (one-path-per-`adapter_id`, `scheduler.py:160`) hold for discord.

**SECURITY MUST-FIX (4):** (1) the SEC-309-1 gateway-originate spy MUST use a **body whose `adapter_id` MISMATCHES the spawn binding** (or a garbage/no-id body) and assert the envelope still carries the BINDING value — NOT envelope==body equality (the spec calls that vacuous); (2) byte-stability asserted at the **leg-payload layer** (post-serialize + post-replay), not just at the `forward()` boundary; (3) the FORK-A daemon-path-unchanged test (above); (4) enumerate **ALL FOUR** ci.yml gateway-kernel edit points (python-job hashFiles guard + `--include`, coverage-gates hashFiles guard + `--include`), not two.

**ADDITIONAL (architect):** the in-process test asserts the leg unit LANDS as a `gateway.adapter.inbound` payload and STOPS there (does NOT reach G6-7-4 dispatch collaborators that don't exist yet); both leg-full and global-cap-full trigger the pause; unknown-method drop is an explicit loud-audited test row.

## After plan-review (corrections folded above)

1. Convert the corrected design into bite-sized TDD steps (the corrections section is the source of truth where it differs from the task skeleton).
2. subagent-driven-development → FULL 12-reviewer /review-pr fleet → alfred-uat → push → CodeRabbit → merge (`--rebase`, NEVER `--admin`/`--no-verify`).
3. Record the merge to memory.
