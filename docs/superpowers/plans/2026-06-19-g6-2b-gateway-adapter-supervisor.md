# G6-2b — GatewayAdapterSupervisor + lifecycle machine (Spec B §9 G6-2 / #288)

- **Date:** 2026-06-19
- **Branch:** `spec-b-g6-2b` (off `main`; G6-2a wire contract + core observer already merged)
- **Spec:** [`2026-06-18-spec-b-adapter-inversion-design.md`](../specs/2026-06-18-spec-b-adapter-inversion-design.md) §2 (decision 2), §3 (topology / two crash signals / de-dup join), §4 (Components), §6 (audit non-skippable), §9 (G6-2 row).
- **ADR:** ADR-0036 (gateway adapter-hosting inversion — already merged; this PR adds the carrier-auth follow-up annotation G6-2a deferred).
- **Issue trailer for every commit:** `(#288)` + the `MrReasonable <4990954+MrReasonable@users.noreply.github.com>` trailer.

---

## 0. Split assessment (REQUIRED reading before any task)

**Recommendation: SPLIT G6-2b into two sub-PRs. This plan covers 2b-1 ONLY.**

G6-2b as scoped in the prompt mixes a **pure-logic + fake-seam core** (lifecycle
state machine, supervisor spawn/crash/backoff/breaker, runner/transport
relocation) with a **live trust-boundary wiring** (registering the G6-2a
`AdapterStatusObserver` into the live daemon boot graph consuming a real
gateway→core status leg, the crash de-dup join, the `alfred status` render, the
emitters that put frames on the wire). Reasons to split:

1. **Reviewability.** The pure-logic half is ~5 bite-sized TDD tasks against
   injectable fakes — a clean, self-contained, security-low review. The live
   half drags in the daemon boot graph (`_start_async`,
   `_build_comms_boot_graph`), the gateway↔core status leg, and a real
   producer→consumer path. Bundling them makes one ~12-task PR the reviewer
   cannot hold in their head (CLAUDE.md "small PRs").

2. **The live-wiring depends on a precursor gap (see §8).** On `main` the daemon
   does NOT dial/host a gateway, and the gateway process does NOT relay
   `gateway.adapter.*` frames to the core — there is no transport leg for the
   observer to consume yet. The honest "live observer wiring" needs a
   gateway→core status-frame relay that does not exist. 2b-1 ships the producer
   (emitter) + the supervisor in the gateway role against a **fake status sink**;
   2b-2 lands the real leg + the live observer registration + the de-dup join +
   the render, once 2b-1 has proven the producer shape. Forcing the live leg into
   2b-1 would either (a) invent the leg here (scope creep into what is really a
   transport PR) or (b) register the observer against a producer that cannot
   reach it (a paper-gate — the exact G2/#245 hazard this plan must avoid).

3. **Test isolation.** The state machine + supervisor get hypothesis property
   tests and fake-seam unit tests that run on the **required non-root** gate with
   zero bwrap. The live half needs a real-launcher integration counterpart
   (root) PLUS its non-root in-process analog — a different test surface that
   should not gate the pure-logic merge.

4. **Trust boundary.** "Register the observer into the live boot graph" is a
   trust-boundary change (a forged status frame reaching the core's audit log).
   It deserves its own security plan-review, not a ride-along on the
   supervisor-mechanics PR.

**2b-1 scope (this plan):**

- Relocate/share `CommsPluginRunner` + `CommsStdioTransport` into a gateway host
  role (verify import graph; no daemon-coupling).
- The per-adapter pure lifecycle state machine (`AdapterLifecycleMachine`),
  mirroring `link_state.py`'s shape.
- `GatewayAdapterSupervisor`: per-adapter spawn → handshake → crash detection →
  bounded-backoff restart (per-adapter decorrelated jitter) → per-adapter circuit
  breaker → status **emission to an injected sink** (the fake-status-sink seam).
- Multi-adapter concurrent boot under a bounded `TaskGroup`.
- The gateway-side **emitter** that produces the four `gateway.adapter.*` G6-2a
  frames (validated against the merged Pydantic models) — emitted to the
  injectable sink, NOT yet onto a live wire.
- Per-adapter metrics: `gateway_adapter_up`, `gateway_adapter_restarts_total`,
  `gateway_adapter_breaker_open`, `gateway_adapter_inflight`,
  `gateway_adapter_awaiting_core` (`{adapter}`-labelled).
- The #295 follow-up rename `SLICE_4_FIELDSET_NAMES` → `AUDIT_FIELDSET_ROSTER`.
- The ADR-0036 carrier-auth follow-up annotation (G6-2a flagged it).

**2b-2 scope (outlined in §7, NOT planned here):** the live gateway→core
status-frame relay leg; registering `AdapterStatusObserver` into
`_build_comms_boot_graph`; the crash de-dup core-side join (in-child
`CrashedNotification` vs gateway `AdapterCrashedNotification` on
`adapter_id` + host-restart sequence); the `alfred status` /
`alfred gateway adapters` render calling `t()` on the reserved
`gateway.adapter.status.*` keys.

**OUT of all of G6-2b (deferred, per spec §9):** real credential
`spawn_request`/`spawn_grant`/fd-3 delivery (G6-3 — 2b uses a FAKE cred seam);
`PerAdapterIngressGate` + `GatewayLegScheduler` + per-leg `ReplayBuffer` +
global aggregate cap (G6-4); Discord flag-day / Compose-service deletion / real
token path (G6-5); adversarial corpus (G6-6).

---

## 1. Goal

Give the always-up gateway the ability to **supervise** a sandbox-spawned comms
adapter child: spawn it through the launcher, run the handshake, detect a crash,
restart with bounded decorrelated-jitter backoff, open a per-adapter circuit
breaker on a crash-loop, and **emit** the four `gateway.adapter.{up,down,crashed,
breaker_open}` status frames (the exact G6-2a wire models) so the core can later
observe the adapter lifecycle. All of it provable on the required non-root gate
against injectable fakes (fake clock, fake cred, fake child, fake fd-3, fake
status sink) — real-credential spawn is G6-3, the live status leg is 2b-2.

## 2. Architecture

```
                         [fake cred seam]      [fake child / fake fd-3]
                               │                       │
  AdapterLifecycleMachine ◀────┴── GatewayAdapterSupervisor ──▶ CommsPluginRunner
   (pure (state,event)            (imperative shell:               + CommsStdioTransport
    → AdapterControl|None)         spawn/handshake/crash/           (relocated host role,
                                   backoff/breaker, per-            per-adapter session)
                                   adapter decorrelated jitter)
                                          │
                                          ▼ emit(AdapterUp/Down/Crashed/BreakerOpen)
                                   _AdapterStatusSink (Protocol)
                                          │
                              ┌───────────┴────────────┐
                       [fake sink, 2b-1 tests]   [live gateway→core leg, 2b-2]
```

- **Functional core, imperative shell.** `AdapterLifecycleMachine` is a pure
  `feed(event) -> AdapterControl | None` table exactly like
  `LinkStateMachine.feed` — no I/O, no clock. The supervisor is the shell that
  reads the wire, drives the clock/backoff, and turns each emitted
  `AdapterControl` into a `gateway.adapter.*` frame on the sink.
- **The supervisor reuses `CommsPluginRunner` + `CommsStdioTransport` unchanged**
  (verified host-agnostic — both already bind to `PluginLaunchSpec` / a structural
  transport seam, and neither imports the daemon). The gateway constructs a
  **per-adapter** `AlfredPluginSession` (NOT the daemon's shared boot graph).
- **The emitter** validates against the merged G6-2a models
  (`AdapterUpNotification` etc.) so a wrong field is a loud `ValidationError` at
  the producer, symmetric with the observer's consumer-side validation.
- **Loudness contract mirrors `Supervisor`** (`src/alfred/supervisor/core.py`):
  every lifecycle transition is loud + emits a frame; a crash-loop trips the
  breaker (no silent dark); fail-closed spawn raises a typed error.

## 3. Tech stack

Python 3.12+, asyncio (`TaskGroup`, decorrelated-jitter via injected `jitter`
seam mirroring `core_link.py`), Pydantic v2 (the merged G6-2a models),
`prometheus_client` Gauge/Counter (mirror `gateway/metrics.py`), hypothesis
(state-machine property tests, mirror `test_link_state.py`), structlog,
`mypy --strict` + `pyright`. No new datastore. **Does NOT touch
`src/alfred/security/`** (see §6).

## 4. File structure

**New:**

- `src/alfred/gateway/adapter_lifecycle.py` — `AdapterLifecycleMachine`,
  `AdapterLifecycleState`, `AdapterLifecycleEvent`, `AdapterControl`,
  `AdapterLifecycleStateError` (pure; mirrors `link_state.py`).
- `src/alfred/gateway/adapter_supervisor.py` — `GatewayAdapterSupervisor`,
  the `_AdapterStatusSink` Protocol, the `_AdapterChildFactoryLike` /
  `_FakeCredSeamLike` seams, the decorrelated-backoff helper.
- `src/alfred/gateway/adapter_status_emitter.py` — `AdapterStatusEmitter`
  (builds + validates the four G6-2a frames, writes to the sink).
- `src/alfred/gateway/adapter_metrics.py` — the five `{adapter}`-labelled series.
- `tests/unit/gateway/test_adapter_lifecycle.py` — pure-machine unit + hypothesis.
- `tests/unit/gateway/test_adapter_supervisor.py` — spawn/handshake/crash/backoff/
  breaker against fakes; concurrent multi-adapter boot.
- `tests/unit/gateway/test_adapter_status_emitter.py` — frame build/validate/emit
  - forgery-shape refusal.
- `tests/unit/gateway/test_adapter_metrics.py` — label/series presence.
- `tests/unit/gateway/test_runner_transport_host_agnostic.py` — import-graph
  guard (the relocation invariant).

**Modified:**

- `src/alfred/audit/audit_row_schemas.py` — rename `SLICE_4_FIELDSET_NAMES` →
  `AUDIT_FIELDSET_ROSTER` (+ keep a re-export alias if any non-test consumer
  exists — verify in Task 1).
- `tests/unit/audit/test_slice_4_audit_row_fields.py` — rename roster references
  (the #295 follow-up).
- `docs/adr/0036-gateway-adapter-hosting-inversion.md` — carrier-auth follow-up
  annotation.

**NOT modified in 2b-1** (these are 2b-2): `src/alfred/cli/daemon/_commands.py`,
`src/alfred/cli/gateway/_commands.py`, `src/alfred/comms_mcp/adapter_status_observer.py`,
`src/alfred/i18n/_spec_b_reserve.py` (the `t()` render keys are consumed in 2b-2).

## 5. Tasks (bite-sized TDD)

Each task: write the failing test → run it to confirm it fails for the stated
reason → minimal impl → run to green → `uv run ruff check . && uv run ruff format
--check . && uv run mypy src/ && uv run pyright src/` → commit. Commit message
ends with `(#288)` + the trailer.

### Task 1 — #295 roster rename (no behaviour change)

- **Pre-step (verify):** `rg -rn 'SLICE_4_FIELDSET_NAMES' src/ tests/` to enumerate
  every consumer. The prompt names only the test file; confirm `src/` has exactly
  the one definition in `audit_row_schemas.py` (no other `src/` consumer) before
  renaming.
- **Failing test:** in `test_slice_4_audit_row_fields.py`, rename the references to
  `audit_row_schemas.AUDIT_FIELDSET_ROSTER`. The suite fails (`AttributeError`,
  the module still exports the old name).
- **Impl:** rename the constant in `audit_row_schemas.py` to `AUDIT_FIELDSET_ROSTER`,
  update its `__all__` entry + the roster's doc-comment (it now owns Spec-B vocab,
  so the name drops the slice-specific label). Update the AST-walk helper's section
  marker comment ONLY if it referenced the old name (it keys off the
  `Slice-4 audit-row constants` source marker string, not the roster name — keep
  that marker so the existing 32-entry walk is unaffected).
- **Green:** count assertion stays `== 32`; bidirectional walk passes.
- **Commit:** `refactor(audit): rename SLICE_4_FIELDSET_NAMES → AUDIT_FIELDSET_ROSTER (slice-agnostic, owns Spec-B vocab) (#288)`

### Task 2 — runner/transport host-agnostic import guard (relocation invariant)

- **Failing test:** `test_runner_transport_host_agnostic.py` — an AST/import
  assertion that `alfred.plugins.comms_runner` and
  `alfred.plugins.comms_stdio_transport` import NOTHING from `alfred.cli.daemon`
  and nothing from `alfred.cli` at module top (so the gateway can construct them
  without pulling the daemon). Mirror the existing import-discipline guards (e.g.
  `tests/unit/cli/test_main_lazy_imports.py` shape). Run it: it passes IF the
  modules are already clean, fails if a daemon coupling exists.
- **Impl:** if the guard fails, the relocation is to **share, not move** — the two
  modules already live in `src/alfred/plugins/` and are host-agnostic (verified:
  the runner binds `_SupervisorLike` structurally and the transport binds
  `PluginLaunchSpec`). The "relocation into the gateway host role" is therefore a
  **consumer-side** construction in the supervisor (Task 4), not a file move. This
  task's deliverable is the GUARD that pins the no-daemon-coupling invariant so a
  future edit cannot re-couple them. If the guard passes immediately, the impl is
  the guard test itself (a green pin) — note that explicitly in the commit body.
- **Commit:** `test(gateway): pin comms runner/transport host-agnostic import invariant for gateway reuse (#288)`

### Task 3 — `AdapterLifecycleMachine` (pure transitions)

Mirror `link_state.py` exactly in shape: `StrEnum` states + events, an explicit
`_TRANSITIONS` table, `feed(event) -> AdapterControl | None`, fail-loud on an
undefined pair via `AdapterLifecycleStateError(AlfredError)`.

- States: `SPAWNING`, `HANDSHAKING`, `UP`, `CRASHED`, `RESTARTING`,
  `BREAKER_OPEN`, `AWAITING_CORE`.
- Events: `SPAWN_STARTED`, `HANDSHAKE_OK`, `HANDSHAKE_FAILED`, `CHILD_EXITED`
  (the process-level crash), `BACKOFF_ELAPSED`, `BREAKER_TRIPPED`,
  `CRED_UNAVAILABLE` (the fake-cred-down → AWAITING_CORE edge), `CRED_AVAILABLE`,
  `STOP_REQUESTED`.
- Controls emitted (map 1:1 to the four frames): `EMIT_UP`, `EMIT_DOWN`,
  `EMIT_CRASHED`, `EMIT_BREAKER_OPEN`, or `None`.
- **Failing tests (TDD, then a hypothesis property suite):**
  1. `SPAWNING --SPAWN_STARTED--> HANDSHAKING` (no emit).
  2. `HANDSHAKING --HANDSHAKE_OK--> UP` emits `EMIT_UP`.
  3. `UP --CHILD_EXITED--> CRASHED` emits `EMIT_CRASHED`.
  4. `CRASHED --BACKOFF_ELAPSED--> RESTARTING --SPAWN_STARTED--> HANDSHAKING`.
  5. `CRASHED --BREAKER_TRIPPED--> BREAKER_OPEN` emits `EMIT_BREAKER_OPEN`.
  6. `RESTARTING --CRED_UNAVAILABLE--> AWAITING_CORE` (no emit; the await-core
     state is observable but does not assert a new wire transition).
  7. `AWAITING_CORE --CRED_AVAILABLE--> RESTARTING`.
  8. `* --STOP_REQUESTED--> DOWN-terminal` emits `EMIT_DOWN` exactly once
     (planned/operator stop; mirror `link_state`'s absorbing terminal).
  9. Fail-loud: an undefined pair (e.g. `UP --BACKOFF_ELAPSED-->`) raises
     `AdapterLifecycleStateError`.
  - **Hypothesis property** (mirror `test_link_state.py`): over a random event
    sequence, `EMIT_UP` is emitted at most once per spawn-incarnation and only
    out of `HANDSHAKING`; `EMIT_BREAKER_OPEN` is terminal-absorbing like
    `UNAVAILABLE`.
- **Impl:** the table + `feed`, `AlfredError` subclass.
- **Commit:** `feat(gateway): pure per-adapter lifecycle state machine (spawn→up→crashed→breaker, fail-loud) (#288)`

### Task 4 — `GatewayAdapterSupervisor`: single-adapter spawn + handshake (fake child/cred)

Define the injectable seams as Protocols on the supervisor module: `_AdapterChildFactoryLike` (returns a `CommsPluginRunner`-driving transport), `_FakeCredSeamLike` (the 2b cred stand-in — returns a sentinel "granted"/"unavailable"), `_AdapterStatusSink` (`async def emit(self, control, frame)`), and the determinism seams `sleep` / `jitter` / `monotonic` (mirror `GatewayProcess.__init__`).

- **Failing tests:**
  1. `supervise_one(adapter_id)` drives `SPAWN_STARTED` then, on a fake child that
     handshakes OK, reaches `UP` and emits a single `AdapterUpNotification` to the
     sink carrying the supervisor's epoch (injected, 32-hex).
  2. A fake cred seam returning "unavailable" routes the machine to
     `AWAITING_CORE` and emits NO `up` (loud audit/log breadcrumb asserted via the
     metric `gateway_adapter_awaiting_core{adapter}` == 1).
  3. Fail-closed: a fake child whose spawn raises surfaces a typed
     `GatewayAdapterSpawnError` (analog of `QuarantineChildSpawnError`) — never
     log-and-continue. **(trust-boundary test, first-class.)**
- **Impl:** the supervisor shell wiring the machine to the runner + emitter + sink;
  the fake-cred gate before spawn; the typed spawn error.
- **Commit:** `feat(gateway): GatewayAdapterSupervisor single-adapter spawn+handshake→up against fake child/cred seams (#288)`

### Task 5 — crash detection → bounded decorrelated-jitter restart

- **Failing tests:**
  1. A fake child that exits after `UP` drives `CHILD_EXITED` → `CRASHED`, emits
     `AdapterCrashedNotification` (with a redacted, bounded `detail` —
     reuse `_MAX_CRASH_DETAIL_LEN` from `comms_mcp.handlers`, do NOT introduce a
     new bound), then schedules a restart after a backoff drawn from the injected
     `jitter` seam.
  2. The backoff schedule is **decorrelated per-adapter**: with a seeded
     `random.Random` injected, two adapters' restart delays are independently
     drawn (assert the two delay sequences differ given distinct seeds) — proves
     no stampede (spec §4 `[fleet perf-004]`). Clamp to a
     `[_MIN, _MAX]` window mirroring `core_link.py`'s clamp rationale.
  3. `gateway_adapter_restarts_total{adapter}` increments once per restart attempt.
- **Impl:** the crash arm + the decorrelated-jitter backoff helper +
  metric increments. The redaction reuses `redact_secret_shapes` already imported
  by the observer — but NOTE: redaction lives in `src/alfred/security/dlp`; the
  supervisor only *calls* it, it does not modify it (see §6).
- **Commit:** `feat(gateway): crash→bounded decorrelated-jitter restart + crashed-frame emit (per-adapter, no stampede) (#288)`

### Task 6 — per-adapter circuit breaker → BREAKER_OPEN

- **Failing tests:**
  1. N crash→restart cycles within the breaker window (fake clock) trip the
     per-adapter breaker → `BREAKER_OPEN`, emit a single
     `AdapterBreakerOpenNotification` with `retry_after_seconds` >= 0, and the
     machine absorbs further `CHILD_EXITED` without a second emit (terminal-
     absorbing, mirror `link_state` UNAVAILABLE). **(crash-loop-never-silently-
     dark — a release-blocking property in spec §6(c); proven here at the
     producer.)**
  2. `gateway_adapter_breaker_open{adapter}` == 1 after the trip;
     `gateway_adapter_up{adapter}` == 0.
- **Impl:** the per-adapter breaker counter + the BREAKER_OPEN arm. Reuse the
  `Supervisor` loudness contract pattern (closed-vocab reason, single audited
  transition) WITHOUT importing the daemon `Supervisor` — the gateway breaker is
  its own small primitive (the daemon `CircuitBreaker` is Postgres-backed; the
  gateway is stateless-beyond-connection per the comms-adapter contract, so it
  uses an in-memory window — note this divergence in the module docstring).
- **Commit:** `feat(gateway): per-adapter circuit breaker → breaker_open emit, terminal-absorbing, never silently dark (#288)`

### Task 7 — multi-adapter concurrent boot under a bounded TaskGroup

- **Failing tests:**
  1. `supervise_all([a, b, c])` spawns all three CONCURRENTLY under a bounded
     `asyncio.TaskGroup` (assert via fake-child spawn-timestamps that they overlap,
     not serialize — spec §4 `[fleet perf-004]`).
  2. One adapter's fail-closed spawn error does NOT prevent the others reaching
     `UP` (the TaskGroup aggregates the one failure loudly; siblings still boot) —
     assert the surviving two emit `up` and the failing one's typed error is
     surfaced in the aggregated `ExceptionGroup`.
- **Impl:** the bounded-`TaskGroup` boot orchestration.
- **Commit:** `feat(gateway): concurrent multi-adapter boot under bounded TaskGroup, one failure does not block siblings (#288)`

### Task 8 — `AdapterStatusEmitter` validate-on-produce + metrics module

- **Failing tests:**
  1. The emitter builds each of the four frames via the merged G6-2a models and
     writes `(method_constant, params_dict)` to the sink; a malformed build (e.g. a
     non-32-hex epoch) raises `ValidationError` at the PRODUCER before it reaches
     the sink. **(symmetric-to-observer producer-side validation; trust-boundary.)**
  2. `test_adapter_metrics.py`: the five Gauges/Counters exist with the
     `{adapter}` label and the exact metric names from spec §7.
- **Impl:** `adapter_status_emitter.py` + `adapter_metrics.py` (mirror
  `gateway/metrics.py` module-level construction; ADD the `["adapter"]` labelnames
  — unlike Spec A's unlabelled gauges, these ARE per-adapter-labelled per spec §7,
  and that is safe: `adapter_id` is gateway-known (it spawned the child), NOT
  payload-derived, so no per-user cardinality leak).
- **Commit:** `feat(gateway): adapter-status emitter (validate-on-produce) + per-adapter {adapter}-labelled metrics (#288)`

### Task 9 — ADR-0036 carrier-auth follow-up annotation

- **Failing test:** a docs-presence assertion is overkill; instead this task is a
  doc edit gated by `markdownlint` (the docs gate). Add the annotation to
  `docs/adr/0036-gateway-adapter-hosting-inversion.md`: record that the live
  gateway→core status leg's carrier-auth (Spec A `0600` + `SO_PEERCRED` +
  per-boot-epoch envelope) is what authenticates the non-`up` status frames'
  origin + anti-replays them, and that the producer (this PR) emits the `up`
  payload-epoch as the additional application-level false-liveness defense — the
  exact posture the observer docstring already states, now recorded ADR-side as
  G6-2a flagged.
- **Verify:** `uv run pytest tests/unit -q -k spec_b` stays green; markdownlint
  passes.
- **Commit:** `docs(adr): ADR-0036 carrier-auth posture annotation for the gateway→core status leg (G6-2a follow-up) (#288)`

## 6. Security note — does NOT touch `src/alfred/security/`

2b-1 adds NO file under `src/alfred/security/` and modifies none. It *calls*
`redact_secret_shapes` (Task 5) and validates against the merged G6-2a Pydantic
models, but both already exist and are unchanged. Therefore the
100%-branch-coverage + adversarial-suite obligation for `src/alfred/security/`
is NOT triggered by 2b-1. **If implementation reveals a security-module edit is
needed (e.g. a new redaction bound), STOP and flag it loudly** — that would
move the PR into release-blocking-adversarial territory and likely belongs in its
own PR. The trust-boundary tests in this PR (fail-closed spawn, validate-on-
produce, crash-loop-never-dark) are first-class TDD tasks (Tasks 4/6/8) but they
exercise gateway code, not `security/`.

## 7. Scope-boundary note — what 2b-2 owns (NOT planned here)

2b-2 is the live-wiring half and needs its own plan + security plan-review:

1. The **live gateway→core status-frame relay leg** (the transport that carries
   `gateway.adapter.*` frames from the gateway process to the core) — this leg
   does not exist on `main` (see §8).
2. Registering the merged `AdapterStatusObserver` into `_build_comms_boot_graph`
   (`src/alfred/cli/daemon/_commands.py`) consuming that leg — now there is a real
   producer (this PR's emitter), so the paper-gate concern G6-2a deferred is
   resolved AT THAT POINT, not in 2b-1.
3. The **crash de-dup core-side join** (in-child `CrashedNotification` via the
   relay/session vs the gateway `AdapterCrashedNotification` via the status leg)
   on `adapter_id` + a host-restart sequence. NOTE the host-restart sequence is
   this PR's supervisor's per-adapter restart counter — 2b-2 must thread it onto
   the crashed frame; per the G6-2a `AdapterCrashedNotification` docstring the
   frozen model can be **additively** extended with a `host_restart_seq` field.
4. The `alfred status` / `alfred gateway adapters` render calling `t()` on the
   reserved `gateway.adapter.status.*` keys (already reserved in
   `_spec_b_reserve.py`).

## 7b. Plan-review corrections (MUST apply — architect + security + test-engineer, 2026-06-19)

The plan-review fleet cleared the design (split sound, precursor gap real, share-in-place + per-adapter session + fake-seam altitude all correct, paper-gate guard holds). Apply these corrections — they OVERRIDE conflicting earlier text:

1. **Emitter crash-detail redaction: REDACT-then-bound (SEC-1, medium).** The status emitter is the PRODUCER of `gateway.adapter.crashed`; it must redact `detail` before the wire. Use `redact_secret_shapes(detail)[:_MAX_CRASH_DETAIL_LEN]` (REDACT first, THEN truncate — reuse the existing bound from `comms_mcp.handlers`, no new value). NOT bound-then-redact (truncating first can sever a secret straddling the cap, leaking an unredacted prefix the shape-regex no longer matches). Add a producer TDD test with a boundary-straddling secret (a delimiter before the secret so the shape-regex matches; assert no `sk-` fragment survives) and mutation-verify it fails under bound-then-redact. Mirrors the G6-2a observer-side fix (consumer side already does redact-then-bound at `adapter_status_observer.py`). Stays a `redact_secret_shapes` caller — NO `src/alfred/security/` edit.

2. **Per-transition emission is non-skippable BY CONSTRUCTION (ARCH-8, medium).** Spec §6 makes audit/status non-skippable for EVERY lifecycle transition (spawn, handshake_ok, crashed, each restart attempt, breaker_open, awaiting_core). Wire the emitter INTO the supervisor's transition handler so each transition emits its `gateway.adapter.*` frame as an inseparable part of the transition — not an optional call a future edit could silently drop. Add a test that drives the supervisor through every transition and asserts the emitter produced exactly the matching frame for each (against the injected fake sink). **Decision (state in the plan):** 2b-1's per-transition observability obligation is met by this status-frame emission (tested against the fake sink); the **gateway-LOCAL audit append + reconcile to the signed core log (Spec A's mechanism) is explicitly deferred to 2b-2** — it requires the live gateway→core reconcile leg that does not exist on main until 2b-2. This closes the "audit obligation falls through the 2b-1/2b-2 crack" gap.

3. **Fix the deferral pointers (TE-1, low).** Per spec §9: the real-credential **bwrap spawn** proof is **G6-3** (line 149), and the **restart-survival** integration proof is **G6-6** (line 152). **2b-2 is the LIVE gateway→core status leg + observer registration**, NOT the spawn. Correct every "deferred to 2b-2/G6-6" pointer for the spawn accordingly (the substance — fake child in 2b-1, real spawn later — is right; only the labels were off).

4. **Metrics (SEC-2 / TE lows).** Assert the per-adapter metrics carry EXACTLY the sole `adapter` label (cardinality-safe — `adapter_id` is gateway-known, never payload-derived; restate that rationale in a comment). For the counter, test the EXPOSED `_total` sample name, and remember a labelled collector yields NO sample until `.labels(adapter=...)` is first called — the test must call `.labels()` before asserting the sample exists.

5. **Host-agnostic import guard (TE low).** The Task-2 relocation-invariant test must distinguish AST-level imports from runtime — exclude `TYPE_CHECKING`-guarded imports (not runtime daemon coupling). Assert `CommsPluginRunner`/`CommsStdioTransport` have no runtime `alfred.cli`/daemon import.

6. **Emitter must resolve transition payloads (TE low).** The emitter maps each transition's data into its frame: `crashed` → `error_class` + redacted `detail`; `down` → the closed-vocab `reason`; `up` → the captured `epoch`; `breaker_open` → `retry_after_seconds`. Pin these mappings in the emitter tests (a frame missing a required field is a producer bug caught here, not at the core).

## 8. Precursor gaps & spec/code anchors (verified)

Anchors verified against the working tree on `spec-b-g6-2b`:

- **VERIFIED — G6-2a contract on `main`:**
  `src/alfred/comms_mcp/protocol.py` exports `GATEWAY_ADAPTER_UP/DOWN/CRASHED/
  BREAKER_OPEN` (lines 420–423) + `AdapterUp/Down/Crashed/BreakerOpenNotification`
  (lines 434–502). `AdapterUpNotification.epoch` is `Field(min_length=32,
  max_length=32, pattern=r"^[0-9a-f]{32}$")`. The emitter (Task 8) MUST build to
  these exact shapes. Down's `reason` is the closed `AdapterDownReason`
  (`operator|supervisor|config_reload|shutdown`).
- **VERIFIED — observer on `main`:**
  `src/alfred/comms_mcp/adapter_status_observer.py` `AdapterStatusObserver.observe`
  - the `_TRANSITIONS` table. 2b-2 (not this PR) registers it.
- **VERIFIED — `link_state.py` shape to mirror** (Task 3): explicit
  `_TRANSITIONS` dict keyed `(state, event)`, `feed` raises
  `GatewayLinkStateError` on a `KeyError`, hypothesis suite in
  `tests/unit/gateway/test_link_state.py`.
- **VERIFIED — runner/transport are host-agnostic:**
  `CommsPluginRunner` (`src/alfred/plugins/comms_runner.py`) binds
  `_SupervisorLike` + `_CommsTransportLike` structurally; `CommsStdioTransport`
  (`src/alfred/plugins/comms_stdio_transport.py`) binds `PluginLaunchSpec` and
  computes `_repo_root()` itself to avoid importing `cli`. Neither imports the
  daemon. So "relocate into the gateway host role" is a **consumer-side reuse**
  (the supervisor constructs them per-adapter), NOT a file move — Task 2 pins this
  as an invariant. **Spec wording mismatch:** spec §4 says "relocated/shared into
  the gateway host role" which could read as a move; the code shows share-in-place
  is correct. Flagged for plan-review.
- **VERIFIED — decorrelated jitter precedent:** `core_link.py` already implements
  full-jitter with a `[_MIN_RECONNECT_DELAY_SECONDS, backoff]` clamp + an
  injectable `jitter` seam (lines 85–95, 222–234) and `GatewayProcess` threads
  `sleep`/`jitter`/`monotonic` (lines 66–87). Task 5 mirrors this; there is NO
  pre-existing shared "decorrelated backoff" helper (`rg` found none), so Task 5
  writes a small gateway-local one.
- **VERIFIED — metrics precedent:** `gateway/metrics.py` constructs unlabelled
  module-level collectors. Task 8's five collectors ADD `labelnames=["adapter"]`
  (spec §7 requires `{adapter}`). Safe: `adapter_id` is gateway-known, not
  payload-derived.
- **VERIFIED — #295 rename target:**
  `tests/unit/audit/test_slice_4_audit_row_fields.py` references
  `audit_row_schemas.SLICE_4_FIELDSET_NAMES` (count `== 32`, bidirectional AST
  walk). `audit_row_schemas.py` defines it once + lists it in `__all__`. Task 1
  renames to `AUDIT_FIELDSET_ROSTER`. **Verify in Task 1's pre-step** there is no
  other `src/` consumer before renaming (grep showed only the definition + the
  test).
- **VERIFIED — `_MAX_CRASH_DETAIL_LEN`** is owned by `comms_mcp.handlers` and
  re-exported by the observer; Task 5 reuses it (correction #1 — no new bound).
- **PRECURSOR GAP (the split driver) — no live gateway→core status leg on `main`:**
  `GatewayProcess` (`src/alfred/gateway/process.py`) wires client-leg + core-link
  relay only — it has NO adapter supervisor and NO `gateway.adapter.*` producer.
  The daemon's `_start_async` (`src/alfred/cli/daemon/_commands.py` ~line 1994)
  builds `_build_comms_boot_graph` but never constructs/dials a gateway and never
  consumes a status leg. So there is **no transport path** from a gateway-side
  producer to the core observer today. 2b-1's emitter writes to an injected sink;
  2b-2 builds the real leg + registration. This is the concrete reason the live
  observer wiring CANNOT be honestly done in 2b-1 — flagged for plan-review.
- **PAPER-GATE / root note:** 2b-1 has NO bwrap/launcher spawn — the fake-child
  seam means every test runs in-process on the required NON-ROOT gate. The real
  launcher-spawn path is G6-3 (real cred) / 2b-2 (live leg) territory; when those
  add a root-only integration test, they MUST also add the in-process non-root
  analog (the G2/#245 + G6-0b lesson). 2b-1 deliberately keeps the whole surface
  non-root so the pure-logic + producer contract is gated for real, not
  green-because-skipped.

## 9. Self-review

- **Spec coverage (2b-1 portion of the G6-2 row):** ✓ supervisor spawn/handshake/
  crash/backoff/breaker (Tasks 4–6); ✓ pure lifecycle machine (Task 3); ✓ runner/
  transport reuse invariant (Task 2); ✓ `gateway.adapter.*` emitters (Task 8); ✓
  per-adapter decorrelated jitter + concurrent bounded-TaskGroup boot (Tasks 5,7);
  ✓ per-adapter metrics (Task 8); ✓ #295 rename (Task 1); ✓ ADR-0036 carrier-auth
  annotation (Task 9). Deferred-and-stated: live observer wiring, crash de-dup
  join, `alfred status` render → 2b-2 (§7); fake cred seam now, real cred G6-3;
  ingress/scheduler/replay-buffer G6-4; flag-day G6-5; corpus G6-6.
- **Placeholder scan:** no `TODO`/`...`/`pass`-stub in any task; every task has a
  real failing test → minimal impl → green.
- **Type/name consistency:** `AdapterLifecycleMachine`/`State`/`Event`/`Control`/
  `StateError` mirror the `Link*` family; `GatewayAdapterSupervisor`,
  `AdapterStatusEmitter`, `_AdapterStatusSink`, `GatewayAdapterSpawnError`,
  `AUDIT_FIELDSET_ROSTER` used consistently throughout. Frame model + method-
  constant names match `protocol.py` exactly (`AdapterUpNotification`,
  `GATEWAY_ADAPTER_UP`, …). Metric names match spec §7 exactly.
- **i18n:** 2b-1 emits structlog keys + wire metadata only; NO new operator-facing
  `t()` string (the render keys are reserved already and consumed in 2b-2). No
  i18n catalog change → the drift gate is untouched.
- **Security:** no `src/alfred/security/` edit (§6); trust-boundary tests are
  first-class (Tasks 4/6/8).
