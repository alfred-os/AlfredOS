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

> **SUPERSEDED by the "Amendment (#443 PR2 — boot-time handshake)" §8.2
> below.** The claim "Four spawn sites drain that stderr today" is **false**:
> verified on this branch, ONLY the quarantine-child spawn drains its stderr
> (`_log_child_stderr`). The comms-adapter (`comms_stdio_transport.py:173`)
> and gateway-adapter (`adapter_child_factory.py:497`) **pipe** stderr but
> never read it, and the foreground-TUI producer
> (`cli/_launcher_spawn.spawn_plugin_via_launcher`) has zero production call
> sites. So #440/#441 must first BUILD a drain before adopting the auditor,
> and #442 is a rescope-to-delete the dead seam — not the symmetric
> "adopt the same auditor" this paragraph implies. This historical text is
> kept, not deleted; §8.2 is the current picture.

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
the first extraction actually needs the child, not preemptively at boot.

> **SUPERSEDED for the quarantine-child call site by the "Amendment (#443
> PR2 — boot-time handshake)" section below.** #443 PR2 moves this call
> site's dispatch into the boot-time spawn handshake — before
> `Supervisor.__init__` runs — which the paragraph below did not anticipate.
> See the amendment for what makes the moved dispatch safe.

The tradeoff, recorded honestly at the time: (B) means core-001 (whether
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
  no downstream trace. **This holds on BOTH refusal arms** (see the §8.4
  amendment below): the handshake-observable (slow) arm records via the
  `read_frame` zero-stdout EOF, and the fast-refusal EPIPE arm records via the
  SAME zero-stdout-gated drain (`_record_fast_launcher_refusal`). The only
  residual is spec §11.5's pre-hello window, common to both arms.
- **core-001 is moot for the quarantine-child call site, by construction —
  SUPERSEDED for the quarantine path by the "Amendment (#443 PR2 —
  boot-time handshake)" section below.** As shipped at the time of this
  ADR: the dispatch happens strictly after `Supervisor.__init__`, so
  `supervisor.plugin.sandbox_refused` is always declared. This was proven,
  not merely assumed, by the core-001 registry test
  (`tests/unit/security/test_sandbox_refusal_audit.py`), which registers the
  real supervisor hookpoints into the real registry and then runs the
  auditor's real (unpatched) `invoke(...)` dispatch end-to-end. #443 PR2
  moves the dispatch to fire *inside* the boot-time spawn handshake —
  before `Supervisor.__init__` — so this bullet's premise no longer holds
  for that call site; see the amendment for what makes the moved dispatch
  safe.
- **Three producers remain unwired.** The comms-adapter, gateway-adapter, and
  foreground-TUI launcher spawns still only log to `child_stderr` — they do
  not yet call `SandboxRefusalAuditor`. Tracked as #433 follow-ups (the TUI
  producer additionally needs an stderr-capture change, since it inherits
  stderr today rather than piping it).
- **The `provider_key_delivery_failed` reason is now WRITTEN, for a narrower
  case than originally scoped — see the "Amendment (#443 PR2 — boot-time
  handshake)" section below, §8.1/§8.4, for the corrected picture, and #444
  for the writer.** As shipped at the time of this ADR: a genuine fd-3
  delivery failure was believed to be a much rarer condition than a launcher
  refusal, largely disjoint from it — Task 0 (Decision 5) sampled only the
  slow refusal paths. §8.1 below shows this premise was incomplete: the fd-3
  `writev` and the launcher's exit race nondeterministically, and on the arm
  where the launcher wins fast (e.g. the charset-gate refusal, which exits
  before the first `python3` subprocess spins up), the `writev` fails with
  EPIPE — the very `ProviderKeyDeliveryError` this bullet originally said "is
  now known not to fire in practice." §8.4 goes further: on that EPIPE arm the
  launcher genuinely did refuse, so `provider_key_delivery_failed` and a
  launcher refusal are frequently the SAME underlying event observed through a
  different arm, not a rarer, disjoint condition. For that common case — a
  genuine launcher refusal that surfaces as EPIPE — the §8.4 amendment
  RECOVERS the launcher's true reason via the same zero-stdout-gated drain
  (`_record_fast_launcher_refusal`), WITHOUT reopening the forgery the
  two-frame handshake closes (the earlier claim that it would has been
  reversed). `provider_key_delivery_failed` (#444) is therefore WRITTEN only
  for the narrower case that remains: a genuine NON-refusal delivery failure,
  where the launcher's stderr carries no `sandbox_refused` row and the §8.4
  gated drain records nothing — a host-authored row via
  `SandboxRefusalAuditor.record_provider_key_delivery_failure`, called from
  `_record_fast_launcher_refusal`'s `poll() is None` arm.

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
  > **SUPERSEDED by §8.2 below.** "Via the same `SandboxRefusalAuditor`"
  > overstates the work: #440/#441 must first BUILD an stderr drain (both
  > **pipe** stderr but never read it today), and #442's producer
  > (`spawn_plugin_via_launcher`) has zero production call sites, so #442 is a
  > rescope-to-delete the dead seam, not an adoption. §8.2 is the current
  > picture; this bullet is kept as the historical record.
- **Boot-time fail-closed quarantine health-check** (#443 — option A above):
  detect a refusal at spawn/boot and refuse boot, rather than at first
  extraction. A separate operability concern from what this ADR ships.
- **Synthesized `provider_key_delivery_failed` row** (#444): on a genuine
  fd-3 delivery failure, write the reserved reason. The
  `declare_hookpoints()`-shaped fix this bullet named as a prerequisite has
  landed: PR1 (#443, PR #456) is merged to main (`65d86886`) and makes the
  supervisor hookpoints boot-declarable, so a pre-`Supervisor` dispatch no
  longer reopens core-001. **#444 was UNBLOCKED, not folded into PR1** — per
  the spec's own §0 decision 3, it needed its own writer at the
  `ProviderKeyDeliveryError` arm — but for a narrower case: §8.4's
  amendment CLOSED the fast-refusal hole itself (`_record_fast_launcher_refusal`
  recovers a genuine fast refusal's true reason via the zero-stdout-gated
  drain), so #444's scope was the genuine NON-refusal delivery
  failure, where the launcher's stderr carries no `sandbox_refused` row. The
  "underlying condition is rare" framing above is also stale: §8.1 shows the
  fd-3 `writev` and a launcher's exit race nondeterministically, not that
  one side is structurally rare.
  > **DONE (#444), 2026-07-19.** The genuine (child-still-up, `poll() is
  > None`) delivery-failure arm now persists the reserved
  > `provider_key_delivery_failed` row via
  > `SandboxRefusalAuditor.record_provider_key_delivery_failure`, called
  > from `_record_fast_launcher_refusal`'s `poll() is None` branch in
  > `quarantine_child_io.py` — host-authored (no launcher stderr involved),
  > written before the child is torn down. Executable coverage:
  > `test_sbx_2026_026_provider_key_delivery_failure_records_row` in
  > `tests/adversarial/sandbox_escape/test_sbx_boot_handshake.py`, driven from the
  > `sbx_2026_026_provider_key_delivery_failure_records_row.yaml` payload.
- #434 (the `2>/dev/null` five-key collapse + `policy_translate_failed`
  alarm/real conflation), #435 (six launcher refusal paths that emit no
  audit row at all — the issue as filed named four at stale line numbers),
  #436 (the undeclared `sandbox_stub_used` reason field) — sibling
  refinements on the same row family, out of scope here.
- **#434, #435, #436 — closed 2026-07-16.** All three sibling refinements
  named above landed: `sandbox_refused` rows now carry their true reason
  (no more `2>/dev/null` collapse, no more alarm/real conflation on
  `policy_translate_failed`), all six launcher exit-1 paths that previously
  left no audit trail now emit one (charset gate, runuser missing, jq
  missing, bwrap missing, macOS `kind:full`, and an unrecognised sandbox
  kind — including `bwrap_unavailable`), and `sandbox_stub_used`'s `reason`
  field is declared under a closed vocabulary
  (`SANDBOX_STUB_USED_REASONS`) bound by the #432 reason-vocab drift guard.
  That declaration is a schema fix only — the row itself remains
  **deliberately unpersisted**. `sandbox_stub_used` asserts "I am about to
  exec," so a live child then shares the launcher's stderr fd with no
  delimiter; this ADR's interception point is the `read_frame` EOF on a
  refusal candidate that never wrote stdout (Decision B), which fires only
  when the launcher exits *before* exec. A successful exec produces no such
  EOF, so the failure-path drain this ADR built never runs for this row.
  Persisting it for real needs a success-path stderr drain with its own
  out-of-band provenance signal — a new interception point outside this
  ADR's mechanism, and its own ADR.
- **Critically: #440/#441/#442 do not extend to `sandbox_stub_used`.** Those
  issues have the three other launcher-refusal producers (comms-adapter,
  gateway-adapter, foreground-TUI) adopt `SandboxRefusalAuditor` for their
  own `sandbox_refused` rows; adopting that auditor gives those producers
  nothing toward persisting `sandbox_stub_used`, because the gate it wires
  to is an **inverted oracle** for that row: an honest child that execs
  writes stdout and immediately closes the gate (discarding the true
  `sandbox_stub_used` row it might have emitted), while a forging child that
  writes zero stdout before dying *opens* the gate — the gate would admit
  approximately only forgeries. Tracked as a new issue,
  [#447](https://github.com/alfred-os/AlfredOS/issues/447), for the success-path drain + provenance-signal
  design this needs, with its own ADR.

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

## Amendment (#443 PR2 — boot-time handshake)

- **Date**: 2026-07-18
- **Relates to**: issue [#443](https://github.com/alfred-os/AlfredOS/issues/443)
  (the boot-time fail-closed quarantine health-check this amendment records),
  issue [#446](https://github.com/alfred-os/AlfredOS/issues/446) (the forgery
  residual this handshake closes), issue
  [#444](https://github.com/alfred-os/AlfredOS/issues/444) (the reserved
  `provider_key_delivery_failed` writer this amendment's §8.4 distinguishes
  from), epic [#340](https://github.com/alfred-os/AlfredOS/issues/340) PR2b
  (the real-LLM quarantine child go-live this amendment pre-gates)
- **Source**: `docs/superpowers/specs/2026-07-16-443-boot-time-quarantine-health-check-design.md`
  §8, recorded here per that spec's own "Amends: ADR-0051" header

Every claim below was re-verified against the code on this branch (grep/read,
not recollection) before being written — this ADR's Decision 1 already
corrected one falsified premise on this exact drift surface (the fd-3
`writev`), and the spec this amendment records documents two more prose
claims (§8.1, §8.2) wrong in the same ADR. The retraction at Decision 2 and
Consequences above is the load-bearing part of this amendment: without it,
this ADR asserts a proposition (`core-001 is moot for the quarantine-child
call site`) that #443 PR2 makes false, and the document would be internally
self-contradictory.

### §8.1 — the fd-3 `writev`-buffers premise (Decision 1) is a RACE, not structural

Decision 1 (above) records that the fd-3 `writev` "buffers into the pipe and
returns success" on a refusal, so `ProviderKeyDeliveryError` "never fires on
a refusal" — confirmed, it says, on two platforms. **That is only true on
the slow refusal paths Task 0 sampled.** Verified on this branch:
`spawn_quarantine_child_io`'s `finally` block
(`quarantine_child_io.py:931-959`) closes every parent-held read-end copy of
the fd-3 pipe — the lifted alias always, and the pre-lift original whenever a
lift happened — **before** `deliver_provider_key_via_fd3` is called four
lines later (`:963`). Only the child holds a read end by the time the
`writev` (`fd3_key_delivery.py:104`) runs. A launcher that exits before the
child opens that read end therefore closes the only remaining read end
first, the `writev` raises `OSError` (EPIPE), `deliver_provider_key_via_fd3`
re-raises it as `ProviderKeyDeliveryError` (`fd3_key_delivery.py:105-108`),
and `spawn_quarantine_child_io` converts that into `QuarantineChildSpawnError`
(`quarantine_child_io.py:964-972`) — boot already refuses, **nondeterministically**,
via the path Decision 1 says never fires.

The fast `alfred-plugin-launcher.sh` refusal path
(`reason="plugin_id_charset_invalid"`, emitted at `alfred-plugin-launcher.sh:133`,
**before** the first `python3` subprocess spins up at `:216`) exits in the
time it takes the shell to validate an argument — a strong candidate to win
this race — and was never in Task 0's sample (Decision 5 above records "two
platforms," not which refusal reasons). Whether the EPIPE arm or the
`read_frame`-EOF arm (Decision 1's documented path) fires for a given
refusal is a race the parent does not control; §8.4 below records what this
means for that arm's row.

### §8.2 — "four spawn sites drain that stderr" (Context, `:21-24`) is wrong

Only the quarantine child drains its stderr today.
`_SubprocessChildIO._log_child_stderr` (`quarantine_child_io.py:516`, the
executor read at `:568`) is the sole drain in the tree. Verified by grep:
the comms-adapter (`comms_stdio_transport.py:173`,
`stderr=asyncio.subprocess.PIPE`) and the gateway-adapter
(`adapter_child_factory.py:497`, `stderr=subprocess.PIPE`) both **pipe**
stderr and never read it — no `.stderr.read`/`.stderr_reader` call exists in
either file. So #440 (comms-adapter) and #441 (gateway-adapter) are each
"build the drain, **then** attach `SandboxRefusalAuditor`" — materially
larger than "Follow-ups" above implies by describing all three remaining
producers as symmetric adoptions of the same auditor.

Separately — a §7-decomposition finding, not a stderr-draining one, and it
does not touch or contradict this ADR's existing "Follow-ups" note that the
foreground-TUI producer "inherits stderr today rather than piping it" (that
describes real, still-present code: `spawn_plugin_via_launcher`'s
`inherit_stdio` branch). The verified fact is narrower and orthogonal:
`alfred.cli._launcher_spawn.spawn_plugin_via_launcher`
(`_launcher_spawn.py:188`) has **zero production call sites** — `alfred
chat` (`cli/main.py:273`) dials the gateway socket (Spec A G5) instead of
calling it — though the module is still imported elsewhere for `repo_root`
and `PluginLaunchSpec`. #442 (foreground-TUI) should be rescoped to deleting
this dead seam rather than wiring an auditor onto a call site nothing
reaches in production.

### §8.3 — the A-vs-B reversal for the quarantine-child path

The maintainer decision recorded in the spec (2026-07-16, spec §0/§1):
for the quarantine-child call site specifically, option **(A)** — the
spawn-time probe barrier rejected in Decision 2 and "Alternatives
considered" above — is now **adopted**, superseding Decision 2's choice of
**(B)** for that one call site. §5 of this amendment's own PR2 implements it
as a two-frame boot handshake (`_await_boot_handshake`,
`quarantine_child_io.py:753`, invoked from inside `spawn_quarantine_child_io`
at `:984`, before the function returns a child instance to any caller). This
issue, #443, is a hard pre-gate on #340 PR2b (the real-LLM quarantine child
go-live): PR2b must not ship before this handshake closes the forgery
residual on a soon-to-be-untrusted, real-LLM-backed child.

CodeRabbit's #446 🔒 Major — "parser validation cannot establish provenance"
— stands **vindicated**. It was declined on #446 only on the narrow
procedural basis that reversing a recorded ADR decision is the maintainer's
call, never on its technical merits; the maintainer has now made that call
in #443's favour.

### §8.4 — the fast-refusal EPIPE hole (§8.1) is CLOSED by the same zero-stdout-gated drain

On the EPIPE arm identified in §8.1, `deliver_provider_key_via_fd3` raises
`ProviderKeyDeliveryError` (`quarantine_child_io.py`) — the launcher exited
PRE-`exec`, closing its inherited fd-3 read end before the parent's synchronous
`writev`, so no `_SubprocessChildIO` is constructed on the normal path. Its true
`sandbox_refused` row, however, is captured in `process.stderr`
(`subprocess.Popen(stderr=PIPE)`). An **earlier revision of this ADR deferred
this arm** (option (C) / accept), reasoning that draining that stderr would
reopen the forgery bypass §8.3 closes. **That was over-pessimistic — it assumed
a *naive*, ungated drain.** The shipped fix (`_record_fast_launcher_refusal`)
routes the EPIPE arm through the **same sec-001 gate** the handshake uses: one
`read_frame` whose zero-byte-stdout EOF (`refusal_candidate and not
self._child_wrote_stdout`) records the launcher-authored row and fires the
`fail_closed` T0 hookpoint, before the delivery-failure `QuarantineChildSpawnError`
re-raises. So **a genuine fast launcher refusal now produces exactly one
attributed row**, restoring #443's headline promise across BOTH the
handshake-observable and the fast-refusal arms. Boot still refuses fail-closed
either way.

**Why the gate is safe here — even safer than on the slow arm.** The forgery
§8.3 worries about is a live, compromised child triggering EPIPE then forging a
row. But a child cannot *reach* the EPIPE arm without out-racing the parent's
**synchronous** `writev`: `exec` of bwrap→runuser→python takes milliseconds
while the writev is microseconds after `fork` (only the fd-restore `finally`
sits between them), so EPIPE ⟹ the *launcher* (not a child) closed the read end
⟹ a pre-`exec` refusal with launcher-authored stderr. As defence in depth, the
zero-stdout gate additionally discards the drained stderr the instant a child
writes *any* stdout byte, so the only surviving sliver is **identical to §11.5's
already-accepted pre-hello window** (an exec'd child that writes zero stdout
then forges). This fix introduces **no new** forgery path.

Issue #444 remains distinct and separate: its reserved writer fires at the same
`ProviderKeyDeliveryError` arm for a *genuine, non-refusal* delivery failure
(the read end closed for some other reason), writing the fixed
`reason="provider_key_delivery_failed"` (`fd3_key_delivery.py:61`) — a case
where the launcher's stderr carries no `sandbox_refused` row, so this gated
drain records nothing and #444's writer is what would add the row. The two are
complementary: this fix recovers the launcher's *true* reason on a refusal,
while #444 records the *delivery-failure* reason on a non-refusal.
