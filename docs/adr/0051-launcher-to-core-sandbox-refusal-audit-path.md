# ADR-0051 — Launcher-to-core sandbox-refusal audit path

- **Status**: Accepted
- **Date**: 2026-07-16
- **Slice**: #433 (launcher-refusal audit-persistence)
- **Relates to**: [ADR-0015](0015-slice4-containerised-quarantined-llm.md) (quarantine-child
  containerisation; the `sandbox_refused` row family this ADR persists), issue
  [#432](https://github.com/alfred-os/AlfredOS/issues/432) (the closed
  `SANDBOX_REFUSED_REASONS` vocab-sync guard this path's parser validates against),
  issue [#437](https://github.com/alfred-os/AlfredOS/issues/437) (the `policy_ref`
  charset guard this parser's inputs are already constrained by), epic
  [#433](https://github.com/alfred-os/AlfredOS/issues/433) (launcher-refusal
  audit-persistence)
- **Supersedes**: —

## Context

`bin/alfred-plugin-launcher.sh` is the sole producer of the
`supervisor.plugin.sandbox_refused` row: on every sandbox refusal it `printf`s
the row as one JSON line to stderr and `exit 1`s *before* `exec`ing the plugin.
Four spawn sites drain that stderr today (the quarantine-child spawn, the
comms-adapter spawn, the gateway-adapter spawn, and the foreground TUI spawn),
and prior to this ADR none of them turned the drained bytes into a persisted
audit row — the row was logged into a `child_stderr` field and nothing else.
That is a CLAUDE.md hard-rule-#7 gap: a security-boundary refusal producing no
durable, hookpoint-dispatched audit trail.

This ADR records the design for the **first** producer this epic wires up —
the quarantine-child spawn — and the reusable pieces the other three
producers adopt as #433 follow-ups.

## Decision

### 1. The v1 → v2 interception-point correction

The original (v1) plan proposed intercepting the refusal at fd-3 provider-key
delivery: on a launcher refusal the plugin process never starts, so the
`os.writev` of the provider key onto fd 3 would presumably fail, and the
existing `ProviderKeyDeliveryError` arm (`alfred.supervisor.fd3_key_delivery`)
could be the interception point.

**This premise is wrong, and the plan-review fleet (test/reviewer/security/core,
four independently, plus an author code-check) caught it before any code
shipped.** The fd-3 payload is small (a ~100-byte key plus a 4-byte length
prefix), and a pipe's kernel buffer is 64KB. When the launcher refuses, the
read end of the pipe (fd 3, inherited by the not-yet-`exec`'d launcher process)
is still open — bwrap has not yet replaced the process image. The `writev`
therefore **buffers into the pipe and returns success**; there is no partial
write, no `EAGAIN`, no `OSError`. `ProviderKeyDeliveryError` never fires on a
refusal. The refusal instead surfaces downstream, when the quarantine
supervisor calls `read_frame()` expecting a completion response from the
child: the refused launcher exited pre-`exec`, so the child process produced
no frame at all, `read_frame` observes EOF, and *that* is where the failure
first becomes observable.

v2 re-anchors the entire design to this corrected interception point.

### 2. Decision B: record at the `read_frame` drain, not a spawn-time probe barrier

Two shapes were considered for *where* to hook this:

- **(A) A spawn-time probe barrier.** Before handing control to the real
  spawn path, run a preflight that spawns the launcher, waits for either a
  successful handshake or a refusal signal, and only then proceeds. This
  would let a refusal be caught (and boot refused, if desired) before any
  extraction is attempted.
- **(B) Record at the existing `read_frame` / `_log_child_stderr` drain.**
  `_SubprocessChildIO.read_frame()` already has a well-defined EOF-on-refusal
  failure arm (`security.quarantine_child.read_frame_failed`) that calls
  `_log_child_stderr(failure=True)` to drain and log the child's stderr. Add
  a narrow `SandboxRefusalRecorder` Protocol seam there: parse the drained
  stderr for `sandbox_refused` rows and persist them through the same seam,
  guarded so a persistence failure can never mask the underlying refusal.

**Decision: (B).** Minimal blast radius — no new spawn-time control flow, no
new barrier that could itself introduce a startup race or a new failure mode
to reason about. It also correctly matches today's *first-extraction*
semantics: the quarantine child is spawned once and reused across
extractions, so the refusal is discovered (and now persisted) at the moment
the first extraction actually needs the child, not preemptively at boot. The
tradeoff, recorded honestly: (B) means core-001 (whether
`supervisor.plugin.sandbox_refused` is *declared* in the hook registry by the
time this dispatch fires) is moot for this specific call site — the
dispatch happens well after `Supervisor.__init__` has already called
`_register_hookpoints()`, so the hookpoint is always declared by then. A
future **boot-time** fail-closed health-check (option A, deferred — see
Follow-ups) would need to re-examine core-001 for itself, since a probe that
runs *before* `Supervisor` is constructed cannot assume the hookpoint is
declared yet.

### 3. Parser placement in `audit/`, not `plugins/`

`alfred.audit.launcher_refusal.parse_launcher_refusal_rows` is a pure
function — no I/O, no audit-writer import, no hooks import, no plugins
import — that turns raw launcher stderr bytes into validated
`SandboxRefusalRow` values. It lives in `audit/`, next to
`audit_row_schemas.py` (the `SANDBOX_REFUSED_FIELDS` / `SANDBOX_REFUSED_REASONS`
schema it validates against), not in `plugins/`. Placing it in `plugins/`
would invert the dependency direction: `audit/` already sits below
`plugins/` and `security/` in the import graph, and a parser that the
security-side `SandboxRefusalAuditor` needs to import must not force
`security/` to import from `plugins/`. Being pure also means the parser is
100% line- and branch-testable with no fixtures beyond raw bytes.

### 4. The guarded-`record()` posture

`alfred.security.sandbox_refusal_audit.SandboxRefusalAuditor.record(...)` is
the reusable half: given validated rows, it writes each as a
`supervisor.plugin.sandbox_refused` audit row (the full symmetric
`SANDBOX_REFUSED_FIELDS` key-set) and dispatches the registered
`fail_closed=True` T0 hookpoint. The call site inside
`_SubprocessChildIO._record_launcher_refusals` wraps this in a bare
`try`/`except Exception` that logs
`security.quarantine_child.refusal_record_failed` with an explicit
`error_class` and swallows — deliberately, and only here. The reason: this
recorder runs from inside the `read_frame_failed` failure arm, whose job is
to raise the contracted `QuarantineChildSpawnError` so the caller sees a
loud, typed refusal. A persistence-layer failure in the recorder (a DB
outage, a hook-chain timeout) must never **replace** that contracted
exception with an unrelated one, and must never silently swallow the
original refusal either — logging the persistence failure loudly while
still letting `QuarantineChildSpawnError` propagate satisfies both.

### 5. Task 0 empirically confirmed the corrected premise

Before any implementation code was written, Task 0 ran the real launcher
against a real refusal condition and captured the real failure shape on
**two** platforms: macOS and native arm64 privileged Linux (the same
target the #269 arm64 `/lib64` soft-bind fix required real hardware for).
Both confirmed: the fd-3 `writev` succeeds (no `ProviderKeyDeliveryError`),
and the refusal surfaces as a `read_frame` EOF. This closes the gap between
"the ADR says X" and "X is what actually happens on the real sandbox" that
past incidents (#269's stale `/lib64` claim) show can otherwise persist
undetected for a month.

## Consequences

- **The T3-adjacent refusal is persisted at first-use, fail-closed at
  point-of-use.** Every quarantine-child spawn refusal now produces a
  durable, hookpoint-dispatched audit row instead of a stderr log line with
  no downstream trace.
- **core-001 is moot for the quarantine-child call site, by construction.**
  The dispatch happens strictly after `Supervisor.__init__`, so
  `supervisor.plugin.sandbox_refused` is always declared. This is proven,
  not merely assumed, by the core-001 registry test
  (`tests/unit/security/test_sandbox_refusal_audit.py`), which registers the
  real supervisor hookpoints into the real registry and then runs the
  auditor's real (unpatched) `invoke(...)` dispatch end-to-end.
- **Three producers remain unwired.** The comms-adapter, gateway-adapter, and
  foreground-TUI launcher spawns still only log to `child_stderr` — they do
  not yet call `SandboxRefusalAuditor`. Tracked as #433 follow-ups (the TUI
  producer additionally needs an stderr-capture change, since it inherits
  stderr today rather than piping it).
- **The `provider_key_delivery_failed` reason stays reserved, not emitted.**
  The v1 premise's interception point is now known not to fire in practice; a
  genuine fd-3 delivery failure (the read end actually closed — a much rarer
  condition than a launcher refusal) would still need a writer for this
  reason, and that writer is deferred (see Follow-ups) because its dispatch
  point is *pre*-`Supervisor`, which reopens the core-001 question this ADR
  otherwise closes for the quarantine-child path.

## Alternatives considered

### (A) Spawn-time probe barrier

Rejected for #433's scope — see Decision 2. Larger blast radius (new
spawn-time control flow), reopens core-001 (a pre-`Supervisor` dispatch would
need `_register_hookpoints()` to run earlier, or a different declaration
mechanism), and adds boot latency for every plugin spawn to catch a condition
that, in the quarantine-child case, is already caught correctly at
first-extraction. Recorded as a genuine future option — a **boot-time
fail-closed quarantine health-check** — for operators who want a refusal to
block boot rather than surface at first use; see Follow-ups.

### Intercept at `ProviderKeyDeliveryError` (v1's premise)

Rejected — see Decision 1. Does not fire on a refusal; the pipe write
succeeds because the read end is still open when the write happens.

### All four producers wired in one PR

Rejected for scope control. The quarantine-child spawn is the highest-value
producer (it is the one path exercised by the docker-gated C1/C2 real-spawn
CI lane, and the one this repo's #269/#428/#432 investigation history shows
gets exercised in practice); wiring the other three in the same change would
have made this PR's review surface span four independent spawn call sites
plus the shared mechanism, which the plan-review fleet judged as raising
risk without raising confidence.

### Parser in `plugins/`

Rejected — see Decision 3. Inverts the dependency direction between `audit/`
and `plugins/`.

## Follow-ups

- Persist `sandbox_refused` for the **comms-adapter** (#440),
  **gateway-adapter** (#441), and **foreground-TUI** (#442) producers via the
  same `SandboxRefusalAuditor`.
- **Boot-time fail-closed quarantine health-check** (#443 — option A above):
  detect a refusal at spawn/boot and refuse boot, rather than at first
  extraction. A separate operability concern from what this ADR ships.
- **Synthesized `provider_key_delivery_failed` row** (#444): on a genuine
  fd-3 delivery failure (the rare case where the read end is actually
  closed), write the reserved reason. Deferred because its dispatch would be
  pre-`Supervisor` (needs a `declare_hookpoints()`-shaped fix first) and the
  underlying condition is rare.
- #434 (the `2>/dev/null` five-key collapse + `policy_translate_failed`
  alarm/real conflation), #435 (four launcher refusal paths that emit no
  audit row at all), #436 (the undeclared `sandbox_stub_used` reason field)
  — sibling refinements on the same row family, out of scope here.

## Post-review hardening

The plan/PR review fleet raised two findings that shaped the shipped
mechanism beyond the original v2 design:

- **sec-001/arch-001 — gate recording to the launcher-authored signal only.**
  `_record_launcher_refusals` is called from `_log_child_stderr` strictly
  under `refusal_candidate and not self._child_wrote_stdout`. `refusal_candidate`
  is true only for a **zero-byte** `_TruncatedFrameError` — a `read_frame` EOF at
  offset zero, which is exactly how a refused launcher presents (it exits
  pre-`exec`, closing stdout immediately). A `TimeoutError` is **never** a
  refusal candidate: a launcher refusal closes stdout at once rather than
  stalling to the wall-clock deadline, and a timed-out read leaves the executor
  read in flight with no byte-count evidence — so attributing it to the launcher
  would let a child stall a partial header to the deadline, then exit, and forge
  a row. `_child_wrote_stdout` is the second, lifetime discriminator: it is set
  the instant **any** byte is read off the child's stdout — the moment the header
  read returns, and (via `_TruncatedFrameError.bytes_read`) even when the header
  read itself tears after a partial read. So once the child writes even one byte
  it is live and exec'd — the most adversary-facing surface — and a subsequent
  `read_frame` failure (a crash or wedge of that *running* child) is
  child-authored and never turned into an attributed audit row; the same applies
  to the `aclose` teardown path, which never calls the recorder at all. Keying on
  a zero-byte EOF (not a full frame, and not a timeout) closes both forgery
  bypasses CodeRabbit flagged: a malicious child that writes a valid 4-byte header
  then fails the body read on frame one (excluded by `_child_wrote_stdout`), and
  one that stalls a partial header to the read deadline then exits (excluded by
  `refusal_candidate`). Without this gate, an exec'd T3 child could
  crash itself on cue and have its own (attacker-influenced) stderr persisted
  as a signed `supervisor.plugin.sandbox_refused` row.
- **sec-001 (parser) — validate field values, not just field names.**
  `parse_launcher_refusal_rows` validates that every `SANDBOX_REFUSED_FIELDS`
  value is string-typed and free of `Cc` (control) / `Cf` (format) code
  points before a row is accepted — the same category set the #251
  `child_stderr` sanitizer strips. Without this, a child that could
  influence the drained stderr bytes (see the residual below) could inject
  a forged newline, ANSI escape, or bidi-spoofing character into the signed
  audit log via a field value.

The residual this ADR still carries (now far narrower): a child that execs,
writes **zero** stdout bytes, and then dies while emitting a forged
`sandbox_refused` row on stderr is indistinguishable from a genuine launcher
refusal at this call site — both present as `read_frame` EOF with
`self._child_wrote_stdout is False`. A child that writes *any* stdout (a full
or even partial header) is already excluded. This last sliver is not a gap the
launcher-authored gate can close by itself (the discriminator IS "no stdout
byte ever seen"); it defers to the boot-time fail-closed health-check
(option A, #443), which would observe the launcher's refusal (or lack thereof)
directly at spawn time rather than inferring it from a later `read_frame`
failure shape.

## References

- [ADR-0015](0015-slice4-containerised-quarantined-llm.md) — quarantine-child
  containerisation; the `sandbox_refused` row family.
- [ADR-0037](0037-production-quarantine-sandbox-boundary.md) — the production
  quarantine sandbox boundary; the launcher's bind-source hardening (amended
  by #428) is one of several passes on the same launcher this ADR's parser
  now audits.
- Issue [#432](https://github.com/alfred-os/AlfredOS/issues/432) — the closed
  `SANDBOX_REFUSED_REASONS` vocab-sync guard.
- Issue [#437](https://github.com/alfred-os/AlfredOS/issues/437) — the
  `policy_ref` charset guard constraining this parser's inputs.
- Epic [#433](https://github.com/alfred-os/AlfredOS/issues/433) —
  launcher-refusal audit-persistence.
- Spec: `docs/superpowers/specs/2026-07-15-433-launcher-refusal-audit-design.md`
  — the design this ADR records.
