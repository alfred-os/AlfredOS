# Supervisor — plugin lifecycle, circuit breakers, and deadline enforcement

**Status:** shipped in Slice 3 (PR-S3-3b)
**Owner:** `alfred-supervisor-engineer`
**Code:** `src/alfred/supervisor/`
**PRD:** [§5 Architecture Overview](../../PRD.md#5-architecture-overview) — plugin supervisor circuit-breaker invariant; [§7.1 Security & Prompt Injection Defense](../../PRD.md#71-security--prompt-injection-defense)
**ADRs:** [ADR-0017](../adr/0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md)
**Spec:** §4.8, §10 (supervisor), §10.2 (circuit breaker), §10.4 (capability monitor), §10.5 (deadline), §10.6 (persistence), §10.8 (operator reset), §14 (hookpoints)

## Purpose

The supervisor owns three concerns that sit above the plugin transport but
below the orchestrator proper:

1. **Plugin process lifecycle** — gate-checking manifests at load time,
   coordinating subprocess spawn, and recording crashes in the audit log.
2. **Circuit-breaker fault isolation** — per-component three-state state
   machines (CLOSED/OPEN/HALF_OPEN) that quarantine a crashed plugin
   subprocess after three failures in a five-minute window.
3. **Deadline and capability-gate health** — bounding every orchestrator
   action turn with `asyncio.timeout`, and surfacing gate-outage
   transitions to the operator's audit graph.

These three concerns are in one subsystem because they share the same
`asyncio.TaskGroup`: every supervised plugin stdio-reader task runs inside
the group, the deadline wrapper runs inside the orchestrator's action path
which is also supervised, and the capability-gate monitor's heartbeat task
is registered in the same group. Keeping them co-located makes cascade
cancellation on `stop()` a single operation with a single drain timeout,
rather than three independent shutdown sequences.

## Public surface

### Supervisor (`src/alfred/supervisor/core.py`)

- `Supervisor(session_scope, gate, audit, *, policies_ref, ...)` — constructor.
  Immediately creates a `PluginLifecycle` and a `CapabilityGateMonitor` bound to
  the same gate + audit references. Registers the supervisor's hookpoints via
  `_register_hookpoints()`, which delegates to
  `alfred.supervisor.hookpoints.declare_hookpoints()` (spec §14; #443 PR1 — see
  [Hookpoint registration discipline](#hookpoint-registration-discipline)
  below). `policies_ref` (PR-S4-4, ADR-0023) is a
  **required** `PoliciesSnapshotRef` — production refuses to run the privileged
  orchestrator with no policy snapshot (rev-003 closure). `_proposal_dispatch_loop`
  derefs `policies_ref.current()` once per iteration (the stale-snapshot-for-one-
  iteration invariant — see [`policies.md`](./policies.md)).
- `await Supervisor.start()` — opens the supervised `asyncio.TaskGroup` via an
  internal `_run()` coroutine that holds it open until `_shutdown_event` is set.
  Returns only after `_task_group` is populated; callers can immediately call
  `register_plugin_task()`.
- `Supervisor.register_plugin_task(coro)` — schedules a supervised coroutine
  inside the active `TaskGroup`. Raises `RuntimeError` if called before
  `start()` or after `stop()`.
- `await Supervisor.stop()` — sets the shutdown event; waits up to
  `_STOP_DRAIN_TIMEOUT_SECONDS` (10 s) for the group to drain; persists every
  breaker's state to Postgres; emits `supervisor.lifecycle.stopped`.
- `Supervisor.get_or_create_breaker(component_id)` — singleton-per-component
  breaker factory. Two paths calling `record_failure()` against the same
  component converge on the same state machine.
- `await Supervisor.reset_breaker(component_id, *, operator_user_id)` —
  operator API (spec §10.8). Any state → CLOSED; emits
  `supervisor.breaker.reset` with `trust_tier_of_trigger="T1"` (this is an
  operator command, distinct from the supervisor's own T0 rows); persists.
  Raises `SupervisorError` if `component_id` is not registered.
- `await Supervisor.load_all_breakers()` — bulk-load from Postgres at bootstrap
  (after all component breakers are registered, before any plugin spawn).

CLI surface (`alfred supervisor status`, `alfred supervisor reset <component>
--confirm`) lives in `src/alfred/cli/supervisor.py`. The two commands reach
the running supervisor via materially different mechanisms — see [CLI access
model](#cli-access-model) below and the [Slice-3 runbook](../runbooks/slice-3-supervisor.md).

### CircuitBreaker (`src/alfred/supervisor/breaker.py`)

- `CircuitBreaker(component_id, session_scope, *, failure_threshold=3,
  failure_window_seconds=300.0, re_arm_seconds=3600.0)` — one instance per
  supervised component. Three public state-machine methods:
  - `record_failure(exception_type, *, now)` — slides the failure window;
    trips CLOSED→OPEN at threshold. `exception_type` is the Python type name
    only — never `str(exc)` or `exc.args` (spec §5.6 T3 leak guard).
  - `assert_available()` — raises `QuarantinedUnavailable` if OPEN. HALF_OPEN
    is permissive (the probe must run).
  - `reset()` — any state → CLOSED. Clears the failure window and backoff
    counter; does NOT clear `trip_count` (cumulative audit counter).
  - `maybe_rearm(*, now)` — OPEN→HALF_OPEN when the re-arm window has elapsed.
    No-op for CLOSED/HALF_OPEN. Driven by the supervisor's restart scheduler
    (Slice 4 — see Slice graduation map).
  - `record_probe_success()` — HALF_OPEN→CLOSED; resets backoff.
  - `record_probe_failure(exception_type)` — HALF_OPEN→OPEN; doubles backoff
    (capped at `_BACKOFF_MAX_SECONDS` = 300 s).
- `await CircuitBreaker.save_to_db(session)` — upserts via `session.merge`.
  Per-instance `_save_lock` serialises concurrent callers (PR-S3-3a CR-R3
  lost-update fix pattern).
- `await CircuitBreaker.load_from_db(session, *, now)` — restores state at
  bootstrap; applies `maybe_rearm()` inline if the persisted state is OPEN and
  the re-arm window has elapsed (spec §10.6 flap protection).

Module-level hookpoint helpers (awaited by the supervisor; not called from the
state machine itself):

- `invoke_breaker_tripped_hookpoint(component_id, trip_count, last_failure_type)`
- `invoke_breaker_reset_hookpoint(component_id, old_state, new_state,
  trip_count, operator_user_id)`

### PluginLifecycle (`src/alfred/supervisor/plugin_lifecycle.py`)

- `PluginLifecycle(gate, audit)` — thin coordinator; no subprocess spawn, no
  SIGKILL, no hookpoint invocation.
- `await start_plugin(plugin_id, manifest_tier, breaker, trace_id,
  correlation_id)` → `Literal["loaded", "load_refused"]` — gate-checks at
  load; emits the appropriate `plugin.lifecycle.*` audit row.
- `await on_crash(plugin_id, exception_type, exit_code, signal, restart_count,
  breaker, trace_id, *, kill_succeeded, correlation_id, now)` — records
  failure in the breaker; emits `plugin.lifecycle.crashed` (breaker still
  CLOSED) or `plugin.lifecycle.quarantined` (breaker tripped OPEN).

### CapabilityGateMonitor (`src/alfred/supervisor/capability_monitor.py`)

- `CapabilityGateMonitor(gate, audit, *, heartbeat_interval=5.0)` — polls
  `gate.is_backing_store_available()` once per heartbeat cycle.
- `await run_one_heartbeat()` — emits at most one
  `supervisor.capability_gate_unavailable` row per call (entering OR exiting
  transition only). No-op on steady state.
- `record_denied_dispatch()` — called from dispatch code paths during
  fail-closed to accumulate the per-outage `denied_dispatch_count` rollup.
  No-op outside fail-closed (err-015 guard).

### PolicyWatcher (`src/alfred/policies/watcher.py`)

A long-running child task **intended** to run in the supervisor's
`asyncio.TaskGroup`. PR-S4-4 ships the class only; **scheduling is not yet wired
— pending [#225](https://github.com/MrReasonable/AlfredOS/issues/225)** (the
daemon still injects a stub ref and `PoliciesV1` is unreconciled with the live
file). Once wired it owns `config/policies.yaml` as the **only** runtime reader
of that file; every other subsystem reads the active policy through
`PoliciesSnapshotRef.current()`.
Full surface — mtime gate, watcher-side SHA short-circuit, high-blast refusal,
degraded/recovered state machine, the five `supervisor.config_*` /
`policies.watcher.degraded` hookpoints — is documented in
[`policies.md`](./policies.md).

### DeadlineWrapper (`src/alfred/supervisor/deadline.py`)

- `DeadlineWrapper(*, deadline_seconds=30.0)` — one instance shared across
  orchestrator turns; stateless beyond the deadline value.
- `await run(fn, *args, *, _user_id, _correlation_id, **kwargs)` → `R` — wraps
  `fn` in `asyncio.timeout(deadline_seconds)`. Raises `asyncio.TimeoutError`
  on deadline; propagates `CancelledError` unchanged (core-002). The wrapper
  itself emits no audit rows — that is the orchestrator's responsibility.

## Internal model

### TaskGroup lifecycle

`asyncio.TaskGroup` must be entered with `async with` before any
`create_task()` calls; the group's lifetime cannot span a constructor. The
supervisor solves this with a long-lived `_run()` coroutine:

```python
async def _run(self) -> None:
    async with asyncio.TaskGroup() as tg:
        self._task_group = tg
        self._started_event.set()
        await self._shutdown_event.wait()
```

`start()` spawns this coroutine, then awaits `_started_event` so the
`TaskGroup` is populated before `start()` returns. `stop()` sets
`_shutdown_event`, waits for the runner with a 10-second drain timeout, then
persists breaker state and emits the stopped row. This pattern (core-001) is
the correct solution to the Slice-3 plan-review landmine about `TaskGroup`
construction order.

### Circuit breaker state machine

```
CLOSED ──(3 failures in 5 min)──► OPEN
OPEN   ──(1 h elapsed)──────────► HALF_OPEN  (maybe_rearm)
HALF_OPEN ──(probe success)─────► CLOSED
HALF_OPEN ──(probe failure)─────► OPEN       (backoff doubled, 5s→300s cap)
any state ──(operator reset)────► CLOSED      (trip_count preserved)
```

State constants (`src/alfred/supervisor/breaker.py`):

| Constant | Value | Meaning |
| --- | --- | --- |
| `_FAILURE_THRESHOLD` | 3 | Trips in one window |
| `_FAILURE_WINDOW_SECONDS` | 300.0 | 5-minute sliding window |
| `_RE_ARM_SECONDS` | 3600.0 | 1 h before OPEN→HALF_OPEN |
| `_BACKOFF_INITIAL_SECONDS` | 5.0 | First probe delay |
| `_BACKOFF_MULTIPLIER` | 2.0 | Doubling per failed probe |
| `_BACKOFF_MAX_SECONDS` | 300.0 | 5-minute cap |

`trip_count` is a cumulative counter and is NOT reset by `reset()` or
`record_probe_success()` — it is a lifetime audit signal. State is persisted
to the `circuit_breakers` Postgres table (migration 0010) after every
significant transition and on `Supervisor.stop()`.

The state machine itself (`CircuitBreaker`) is a pure domain object with no
awaits and no I/O. Hookpoint invocation and audit row emission live in
`PluginLifecycle` and the module-level `invoke_*` helpers, keeping test
surfaces for the state machine separate from I/O paths.

### DeadlineWrapper — autocommit audit attribution

`DeadlineWrapper.run()` is called inside the orchestrator's `session_scope`
(the same transactional session that wraps the full turn). When
`asyncio.timeout` fires, that session is rolled back. A session-bound audit
row would be lost with the rollback.

The `supervisor.action_timeout` audit row is therefore written by the
orchestrator via an **autocommit writer** (an independent session not subject
to rollback), before re-raising `CancelledError` to trigger the existing
rollback arm. This is the CR-S3-2 R3 lesson: the distinction between
session-bound and autocommit audit writes must be deliberate and
documented — not discovered at incident time when a timeout row goes missing.

### CapabilityGateMonitor — per-outage correlation

`CapabilityGateMonitor` tracks a single `_outage_correlation_id` (a UUID set
on `entering_fail_closed` and cleared after the matching `exiting_fail_closed`
row is emitted). The exiting transition receives the correlation ID as
`correlation_id_override` rather than reading the now-cleared instance field,
so a crash between "clear the field" and "await the emit" never attaches a
stale ID to a future outage (err-014).

The `denied_dispatch_count` on the `exiting_fail_closed` row is accumulated by
`record_denied_dispatch()` calls from dispatch code paths. The increment is a
plain `+= 1` on a Python `int`, which is atomic under the GIL; no lock is
needed because the counter is only read from the single heartbeat task.

### Hookpoint registration discipline

The supervisor's hookpoints are declared by
`alfred.supervisor.hookpoints.declare_hookpoints()` (#443 PR1), extracted from
`Supervisor._register_hookpoints()` so the supervisor can satisfy the boot
seam's obligation that every in-tree publisher be declarable at boot. The boot
seam (`alfred.hooks.boot._declare_all_subsystem_hookpoints`) calls
`declare_hookpoints()` directly; `Supervisor.__init__()` also calls it, via a
delegating `_register_hookpoints()` kept for callers (tests, non-boot code)
that construct a `Supervisor` directly without going through boot.
`register_hookpoint()` is idempotent on equal metadata, so the two call sites
firing for the same process is a no-op, not a conflict.

core-010 still holds: `declare_hookpoints()` is a plain function with **no**
module-bottom, import-time call. Import-time registration in `hookpoints.py`
(or `deadline.py` / `breaker.py`) was explicitly rejected at plan review:
pytest collects every test module's imports before any fixture runs, so a
module-level `register_hookpoint()` call would persist metadata across tests
that expect a clean registry. Explicit-call registration — from boot, from
`Supervisor.__init__()`, or from a direct call to `declare_hookpoints()`
itself — keeps cleanup straightforward: a test's registry holds exactly the
hookpoints its own `declare_*` calls put there. The third pattern is how this
repo's own tests reach the supervisor's hookpoints without booting or
constructing a `Supervisor`:
[`test_known_hookpoints_sync.py`](../../tests/unit/hooks/test_known_hookpoints_sync.py),
[`test_sandbox_hookpoints_registered.py`](../../tests/unit/hooks/test_sandbox_hookpoints_registered.py),
and
[`test_sandbox_refusal_audit.py`](../../tests/unit/security/test_sandbox_refusal_audit.py)
all call `declare_hookpoints()` (imported as `declare_supervisor`) directly.

The original core-010 hookpoints (`supervisor.breaker.tripped`, `.reset`,
`supervisor.action_timeout`, and the three `plugin.lifecycle.*` events) use
two tier constants (`SYSTEM_ONLY_TIERS`, `SYSTEM_OPERATOR_TIERS`) and
`fail_closed=False` throughout. The rationale: these are observability
surfaces. A crashing subscriber on `supervisor.breaker.tripped` is noise, not
a security regression — the breaker transition is persisted to Postgres
irrespective of the hook chain. The PR-S4-6/PR-S4-7 sandbox-launcher additions
are the exception to `fail_closed=False` — see the [Hookpoints](#hookpoints)
table below for the full per-hookpoint disposition.

### No T3 in failure metadata

`record_failure()` and `on_crash()` accept `exception_type: str` — the Python
type name only. Callers must funnel through `type(exc).__name__`; passing
`str(exc)` or `exc.args` is forbidden by spec §5.6 because a misbehaving
subprocess's crash message can carry T3 fragments. The audit row schema
constants in `src/alfred/audit/audit_row_schemas.py` mirror this contract so
the symmetric missing/extra-field guard catches drift.

### Operator attribution resolves at the CLI boundary, not in the Supervisor

`Supervisor.__init__` accepts an `operator_session_resolver` kwarg (a
PR-S4-1 stub), but the field is **stored and never read**. Operator
attribution for the reviewer-gated commands is resolved at the CLI boundary —
`alfred config set` / `alfred plugin grant|revoke` call
`resolve_operator_user_id_or_refuse`, and `alfred supervisor reset` calls
`_resolve_operator_session_or_refuse`, each constructing a
`DefaultOperatorSessionResolver` directly from the CLI bootstrap (#153). The
stored `Supervisor._operator_session_resolver` is therefore **not live
wiring**; it is retained so a future in-supervisor consumer can dereference it
without re-touching `__init__`, and a cleanup PR may remove the kwarg. Do not
read it as an active resolution path.

## Audit row families

Three families of audit rows, all carrying `trust_tier_of_trigger="T0"` and
`actor_persona="supervisor"` (except `supervisor.breaker.reset` which carries
`trust_tier_of_trigger="T1"` — it is an operator-tier command):

### Breaker rows

| Event | Schema constant | Key subject fields |
| --- | --- | --- |
| `supervisor.breaker.tripped` | `SUPERVISOR_BREAKER_TRIPPED_FIELDS` | `component_id`, `trip_count`, `last_failure_type`, `breaker_state="OPEN"`, `correlation_id` |
| `supervisor.breaker.reset.requested` | `SUPERVISOR_BREAKER_RESET_REQUESTED_FIELDS` | `component_id`, `operator_user_id`, `proposal_branch`, `trust_tier_of_trigger="T1"`, `correlation_id` |
| `supervisor.breaker.reset` | `SUPERVISOR_BREAKER_RESET_FIELDS` | `component_id`, `old_state`, `new_state="CLOSED"`, `trip_count`, `operator_user_id`, `correlation_id` |

### Lifecycle rows

| Event | Schema constant | Key subject fields |
| --- | --- | --- |
| `plugin.lifecycle.loaded` | `PLUGIN_LIFECYCLE_FIELDS` | `plugin_id`, `manifest_subscriber_tier`, `manifest_version`, `sandbox_profile`, `breaker_state` |
| `plugin.lifecycle.load_refused` | `PLUGIN_LIFECYCLE_FIELDS` | same, `result="load_refused"` |
| `plugin.lifecycle.crashed` | `PLUGIN_LIFECYCLE_CRASHED_FIELDS` | base fields + `exception_type` |
| `plugin.lifecycle.quarantined` | `PLUGIN_LIFECYCLE_QUARANTINED_FIELDS` | base fields + `kill_succeeded`, `quarantine_reason="circuit_breaker_open"`, `trip_count` |

### Capability-gate rows

| Event | Schema constant | Key subject fields |
| --- | --- | --- |
| `supervisor.capability_gate_unavailable` | `SUPERVISOR_CAPABILITY_GATE_UNAVAILABLE_FIELDS` | `state_transition` (`"entering_fail_closed"` \| `"exiting_fail_closed"`), `denied_dispatch_count`, `backing_store_error_type`, `correlation_id` |

## Hookpoints

Hookpoints registered via `Supervisor._register_hookpoints()`, which delegates
to `alfred.supervisor.hookpoints.declare_hookpoints()` (see [Hookpoint
registration discipline](#hookpoint-registration-discipline) above). All carry
`carrier_tier=T0` (system-internal observability). All `fail_closed=False`
except the two PR-S4-6/PR-S4-7 sandbox-launcher rows,
`supervisor.plugin.sandbox_refused` (a subscriber timeout there must not let a
refused spawn slip through) and `supervisor.plugin.sandbox_stub_used`
(mirrors `sandbox_refused`'s `fail_closed=True` verbatim — #167 per-kind
override deferred).

| Hookpoint | `subscribable_tiers` | `fail_closed` | Fires when |
| --- | --- | --- | --- |
| `supervisor.breaker.tripped` | `{"system"}` | `False` | Breaker trips to OPEN |
| `supervisor.breaker.reset` | `{"system", "operator"}` | `False` | Operator reset completes |
| `supervisor.action_timeout` | `{"system"}` | `False` | Orchestrator action deadline exceeded |
| `plugin.lifecycle.loaded` | `{"system"}` | `False` | Plugin loaded successfully |
| `plugin.lifecycle.crashed` | `{"system"}` | `False` | Plugin crashed (breaker still CLOSED) |
| `plugin.lifecycle.quarantined` | `{"system"}` | `False` | Plugin crash trips breaker to OPEN |
| `supervisor.plugin.sandbox_refused` | `{"system"}` | `True` | Every `SANDBOX_REFUSED_FIELDS` emit (PR-S4-6) |
| `supervisor.plugin.sandbox_stub_used` | `{"system"}` | `True` | Launcher execs unsandboxed in dev/test with no real sandbox available (PR-S4-7) — declared only, no `invoke()` call site yet (#447) |
| `supervisor.boot.mlock_unavailable` | `{"system"}` | `False` | `mlockall` unavailable at boot (PR-S4-6) |
| `supervisor.boot.core_dumps_disabled` | `{"system"}` | `False` | `RLIMIT_CORE` set to 0 at boot (PR-S4-6) |

## Sandbox launcher policy resolution (PR-S4-6)

The Supervisor spawns each plugin through `bin/alfred-plugin-launcher.sh`
(bash). PR-S4-6 extends the Slice-3 UID-separated baseline into a manifest-
driven, policy-resolving flow while preserving every Slice-3 invariant
(charset-validated `plugin_id`, fail-closed refusals, bare i18n keys on
stderr, `_do_exec` defined before its call site).

**Pre-launcher Python helper.** The launcher stays bash; a one-shot
`python3 -m alfred.plugins.manifest_reader` subprocess reads the manifest's
`[sandbox]` block, resolves `Settings.environment`, and translates a policy
file into bwrap flags. This keeps the trust-tier-tagging surface in Python
(unit-testable) rather than in bash. Each invocation is independent.

**Manifest `[sandbox]` block.** Every plugin manifest now declares
`kind` (`full` | `none` | `stub`) and, for `kind: full`, a per-OS
`policy_refs` map (`linux` / `macos` / `windows`). A missing block refuses
the load (`reason="sandbox_block_missing"`). See the
[glossary](../glossary.md#sandbox-kind).

**`Settings.environment` dual-source resolver.** Mandatory at boot, sourced
`ALFRED_ENVIRONMENT` env var (primary) > `/etc/alfred/environment` file
(fallback). Neither set → refuse. Disagreement audits
`daemon.boot.environment_source_conflict` and the env var wins. (Shipped by
PR-S4-1; consumed here.)

**Dev escape hatch production-refusal (devex-001).**
`ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED` truthy (`1`/`true`/`yes`/`on`, case-
insensitive — the same vocabulary the Python `_truthy_env` accepts) in
`production` is refused with an operator-visible stderr key
(`supervisor.sandbox.unsandboxed_refused_in_production`) + a
`SANDBOX_REFUSED` audit row.

**`policy_ref` path-confinement (sec-2).** `resolve_policy_ref` refuses any
`policy_ref` with a `..` component, an absolute path, or one resolving (via
symlink) outside the sandbox-policy root — `reason="policy_ref_escapes_root"`
— BEFORE the file is ever read.

**fd-3 inheritance.** The Supervisor delivers the quarantined provider key
out-of-band over fd 3: a single atomic `os.writev` of a 4-byte big-endian
length prefix + the key bytes (`deliver_provider_key_via_fd3`). The launcher
passes fd 3 through to the plugin via bwrap's DEFAULT fd inheritance — NO CLI
flag is used; bwrap inherits open, non-CLOEXEC fds into the sandboxed child.
(`--sync-fd` is bwrap's internal sync fd and would CONSUME fd 3 — verified
bubblewrap 0.8.0/0.9.0, #218; there is no `--keep-fd` either.) The launcher
never reads fd 3 itself. On a partial write / EAGAIN the Supervisor REFUSES to spawn
(`reason="provider_key_delivery_failed"`). This reason stays **reserved** — a
launcher sandbox refusal (a *different* failure mode, keyed on
`sandbox_refused`-in-stderr) is now persisted at first-extraction via the
`read_frame` drain (ADR-0051, #433); `provider_key_delivery_failed` has no
writer yet because the genuine fd-3 delivery-failure path it covers is a
separate, rarer condition (the read end actually closed) than a launcher
refusal, and remains a tracked follow-up.

**Honest residency-window limitation.** The provider key arrives at
`deliver_provider_key_via_fd3` as a Python `str` (interned, non-zeroizable).
The mutable copy is zeroed immediately after the writev and `gc.collect()`
runs, but the brief residency window between `SecretBroker.get` and the write
is a real (microsecond-scale) limitation. Slice-5
`SecretBroker.get_bytes(name) -> bytearray` closes it.

**`sandbox_info` handshake (arch-3).** After the handshake a plugin may
attest its `effective_sandbox_kind`; the Supervisor compares it against the
manifest's declared `sandbox.kind` and tears the session down
(`SandboxInfoHandshakeMismatch` + quarantine) on a mismatch — a plugin lying
about its own containment.

**Process posture.** At boot the Supervisor calls `disable_core_dumps()`
(`RLIMIT_CORE` → 0, so a core dump cannot leak the in-memory key) and
`try_mlockall()` (best-effort; failure is loud but non-fatal).

## Failure modes

| Trigger | Behaviour | Observable signal |
| --- | --- | --- |
| 3 plugin crashes in 5 min | Breaker trips OPEN; `plugin.lifecycle.quarantined` emitted; `QuarantinedUnavailable` raised on next dispatch | audit log + structlog `supervisor.plugin.quarantined` |
| Plugin crashes in HALF_OPEN probe | `record_probe_failure()` → OPEN; backoff doubled | structlog `supervisor.breaker.tripped` |
| Gate backing store unreachable for 60 s | `RealGate` trips fail-closed; `CapabilityGateMonitor` emits `entering_fail_closed` row | audit log + Prometheus `alfred_capability_gate_fail_closed` |
| Gate backing store recovers | `CapabilityGateMonitor` emits `exiting_fail_closed` with `denied_dispatch_count` | audit log |
| Orchestrator action exceeds deadline | `DeadlineWrapper.run()` raises `asyncio.TimeoutError`; orchestrator emits `supervisor.action_timeout` via autocommit writer; turn session rolled back | audit log + `asyncio.TimeoutError` re-raise |
| `register_plugin_task()` before `start()` | `RuntimeError` | exception |
| `reset_breaker()` on unknown `component_id` | `SupervisorError` | exception; CLI surfaces "no such component" |
| `Supervisor.stop()` drain timeout (10 s) | `_run_task` force-cancelled; `supervisor.lifecycle.stopped` row still emitted with partial component count | structlog `supervisor.stop_timeout_force_cancel` |
| `save_to_db()` concurrent callers | Serialised by per-instance `_save_lock`; no lost update | no signal (correctness guarantee) |
| `load_from_db()` with OPEN state within re-arm window | Breaker stays OPEN (flap protection) | no signal; breaker refuses dispatch |
| `load_from_db()` with OPEN state past re-arm window | `maybe_rearm()` transitions to HALF_OPEN at load | structlog `supervisor.breaker.half_open` |

## Trust-boundary contract

The supervisor operates entirely on T0 content — it manages internal system
state (process lifecycle, fault isolation, deadlines). Its audit rows carry
`trust_tier_of_trigger="T0"` with one exception: `supervisor.breaker.reset`
carries `T1` because it is an operator-tier CLI command (spec §3.6).

The supervisor does not itself tag or consume T3 content. The
`assert_available()` check on `CircuitBreaker` is the gate that prevents the
orchestrator from dispatching to a quarantined plugin subprocess; the actual
T3 isolation boundary is the `StdioTransport` / `tag_t3_with_nonce` pipeline
in [docs/subsystems/plugins.md](plugins.md).

See [docs/subsystems/security.md](security.md) for the capability gate
internals that the `CapabilityGateMonitor` wraps.

## Performance characteristics

- `CircuitBreaker.record_failure()` and `assert_available()` are synchronous
  and allocation-free on the hot path (no Postgres access; the sliding-window
  list has at most `_FAILURE_THRESHOLD - 1` entries before a trip).
- `CapabilityGateMonitor.run_one_heartbeat()` performs one synchronous read on
  `gate.is_backing_store_available()` per call; the Postgres round-trip is
  inside `RealGate`'s own heartbeat loop (not repeated here).
- `DeadlineWrapper.run()` adds one `asyncio.timeout` context manager per
  orchestrator turn; no allocation beyond the context-manager object.
- `CircuitBreaker.save_to_db()` serialises under `_save_lock`; the lock is
  per-instance so unrelated breakers do not block each other.

Self-healing restart scheduling (the loop that calls `maybe_rearm()` and
drives HALF_OPEN probes) is a Slice-4 concern. The breaker primitives
(`maybe_rearm`, `record_probe_success`, `record_probe_failure`) ship here;
the scheduling loop that drives them does not.

## Slice graduation map

| Subsystem | Slice 3 / PR-S3-3b | Deferred to | Anchor |
| --- | --- | --- | --- |
| Supervisor | `Supervisor`, `CircuitBreaker`, `BreakerState`, `PluginLifecycle`, `CapabilityGateMonitor`, `DeadlineWrapper`; all 6 hookpoints registered; Postgres persistence (migration 0010); `load_all_breakers` + `save_to_db` round-trip; `alfred supervisor status` (Postgres read) + `alfred supervisor reset --confirm` (reviewer-gated `BreakerResetProposal` via the merged-proposal-branch dispatcher) + `alfred supervisor proposals --since 1h` (ledger readout). ADR-0021 dispatch loop wired (test-construction + dev-local). | [#174](https://github.com/alfred-os/AlfredOS/issues/174): daemon boot path that supplies `state_git_path` so the loop runs in production deployments. Slice 4: self-healing restart scheduling loop (`maybe_rearm` cadence + exponential backoff probe timing); multi-process `SELECT … FOR UPDATE` escalation for `save_to_db`. [#173](https://github.com/alfred-os/AlfredOS/issues/173): DLP wiring on the dispatcher's `failure_detail` boundary. | [ADR-0017](../adr/0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md), [ADR-0020](../adr/0020-supervisor-cli-access-via-postgres-and-state-git.md), [ADR-0021](../adr/0021-merged-proposal-branch-dispatch-for-side-effecting-proposals.md), spec §10 |

## CLI access model

The supervisor lives in the long-running daemon process; the `alfred` CLI is
a short-lived synchronous Typer invocation in a different OS process. The CLI
cannot acquire a live `Supervisor` handle — the `Supervisor.get_instance`
singleton accessor was the original wiring story (PR-S3-3b) and never
shipped, because the singleton would live in the daemon process anyway.

ADR-0020 (revised) accepts the asymmetry: the two CLI commands reach the
supervisor's state via materially different mechanisms.

### `alfred supervisor status` — synchronous Postgres read

The CLI opens a sync SQLAlchemy session against the same `DATABASE_URL` the
supervisor uses, reads `circuit_breakers`, renders the table, and exits. No
supervisor handle. No async runtime in the CLI. No new infrastructure. The
freshness contract is "rows reflect the supervisor's last `save_to_db`
write; typically lags by ≤1 supervisor cycle" — the same staleness model
`alfred audit log` uses against the audit Postgres projection.

Failure modes funnel through narrow `except` arms:

| Condition | Disposition |
| --- | --- |
| `DATABASE_URL` unset OR Postgres unreachable | `cli.supervisor.status.postgres_unavailable` + exit 1 |
| `circuit_breakers` table empty | `cli.supervisor.status.no_components_yet` + exit 0 |
| Row decode fails (schema drift) | Raw traceback (programmer bug) |

### `alfred supervisor reset` — reviewer-gated state.git proposal

`alfred supervisor reset <component> --confirm` queues a `BreakerResetProposal`
through the canonical state.git writer per
[ADR-0021](../adr/0021-merged-proposal-branch-dispatch-for-side-effecting-proposals.md).
The supervisor's `_proposal_dispatch_loop` (sibling to
`_capability_heartbeat_loop`, same `TaskGroup` membership) walks the
HEAD-diff on each cycle (≤`proposal_dispatch_interval_s` seconds; default
30s), finds new blobs in `policies/<type>/<id>.json`, parses them into
typed Pydantic payloads, dispatches through `PROPOSAL_HANDLERS`, and records
the outcome in the `processed_proposals` ledger.

The CLI flow:

1. Honours the `--confirm` gate (BLOCKER #6 from #154 preserved).
2. Emits the forensic-attempt audit row (`supervisor.breaker.reset.attempted`)
   BEFORE the proposal write so operator intent always lands in the audit
   graph.
3. Calls `queue_proposal_or_exit` with a typed `BreakerResetProposal`,
   which writes the proposal branch and emits the
   `supervisor.breaker.reset.requested` audit row stand-in.
4. Prints the localised `cli.supervisor.reset.proposal_submitted` body with
   the proposal id, branch, dispatch-cycle interval, and the
   `alfred supervisor proposals --since 1h` follow-up command.
5. Exits 0 — the request landed.

**Slice-3 limitation — daemon boot wiring (#174).** The dispatch loop only
runs when a `Supervisor` is constructed with a `state_git_path`. The daemon
boot path that wires the production state.git location is tracked at
[#174](https://github.com/alfred-os/AlfredOS/issues/174). Until #174 ships,
the dispatch flow runs in tests and dev-local supervisor constructions but
not in production.

### `alfred supervisor proposals` — ledger readout

Renders the `processed_proposals` table. Flags: `--since DURATION`
(default `1h`), `--limit N` (default 20), `--all` (forensic export
escape hatch). Closed-vocab `result` values (`applied`,
`failed_handler`, `failed_parse`, `failed_unknown_type`) decoded inline
via the printed legend.

## Operator interfaces

`Supervisor.reset_breaker(component_id, *, operator_user_id)` is the single
operator programmatic API surface. It transitions any state → CLOSED, emits
the `supervisor.breaker.reset` audit row with T1 attribution, and persists the
new state. The CLI wrapping (`alfred supervisor reset <component> --confirm`)
ships the `--confirm` gate + forensic-attempt audit row, and — since
[#171](https://github.com/alfred-os/AlfredOS/issues/171) — writes a typed
`BreakerResetProposal` through the merged-proposal-branch dispatch
infrastructure documented above (ADR-0021). On reviewer-gate approval the
supervisor's `_proposal_dispatch_loop` picks up the merged blob and routes
through `Supervisor.reset_breaker` via the
`ProposalEffectsProtocol.reset_breaker` adapter — the same underlying
mutation tests call directly.

**Audit-graph query for breaker diagnostics:**

```sql
-- All trips for a component, with outage duration where available
SELECT event, subject->>'trip_count', subject->>'last_failure_type',
       created_at
FROM audit_log
WHERE subject->>'component_id' = '<component_id>'
  AND event IN ('supervisor.breaker.tripped', 'supervisor.breaker.reset')
ORDER BY created_at;
```

**Audit-graph query for capability-gate outage window:**

```sql
-- Duration and denial count for an outage by correlation_id
SELECT state_transition, denied_dispatch_count, created_at
FROM audit_log
CROSS JOIN LATERAL jsonb_to_record(subject) AS s(
    state_transition text, denied_dispatch_count int, correlation_id text
)
WHERE event = 'supervisor.capability_gate_unavailable'
  AND s.correlation_id = '<outage-correlation-id>'
ORDER BY created_at;
```

## Cross-references

- PRD §6.7 — plugin supervision; §7.1 — dual-LLM split (the supervisor guards
  the quarantined-LLM dispatch boundary via `assert_available()`).
- [ADR-0017](../adr/0017-slice3-trust-tier-completion-mcp-transport-dual-llm.md) —
  Decision 2 (stdio transport as the plugin that demands a supervisor),
  Decision 5 (PR-S3-3b split from PR-S3-3a).
- Spec §4.8, §10, §14 — supervisor design, circuit breaker, hookpoints.
- Sibling subsystems: [plugins.md](plugins.md) (the transport the supervisor
  protects), [security.md](security.md) (the `RealGate` the monitor wraps),
  [hooks.md](hooks.md) (the hookpoints the supervisor registers).
- Glossary: [Supervisor](../glossary.md#supervisor),
  [DeadlineWrapper](../glossary.md#deadlinewrapper),
  [CapabilityGateMonitor](../glossary.md#capabilitygatemonitor),
  [PluginLifecycle](../glossary.md#pluginlifecycle),
  [CircuitBreaker / BreakerState / CircuitBreakerState](../glossary.md#circuitbreaker--breakerstate--circuitbreakerstate),
  [supervisor.action_timeout hookpoint](../glossary.md#supervisoraction_timeout-hookpoint),
  [supervisor.breaker.tripped / supervisor.breaker.reset hookpoints](../glossary.md#supervisorbreakertripped--supervisorbreakerreset-hookpoints),
  [supervisor.capability_gate_unavailable audit event](../glossary.md#supervisorcapability_gate_unavailable-audit-event).
