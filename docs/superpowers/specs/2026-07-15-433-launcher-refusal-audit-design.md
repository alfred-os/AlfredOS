# #433 — persist the `supervisor.plugin.sandbox_refused` audit row (design)

* **Issue:** #433 (split from the #432 review — arch-002, sec-005)
* **Status:** design v2 (scoping session; implementation follows). **v2 supersedes
  v1 after the plan-review fleet found a Critical in v1's interception point** —
  see "Revision history" at the end.
* **Scope decision:** quarantine-child path first, with a shared reusable
  parser + auditor seam the other launcher producers adopt in follow-ups
* **Depends on (both merged):** #432 (closed reason vocabulary bound to the
  launcher) and #437 (`policy_ref` charset guard) — together they guarantee the
  row this design ingests is well-formed and closed-vocab
* **New ADR:** ADR-0051 (launcher→core sandbox-refusal audit path)

## Problem

`bin/alfred-plugin-launcher.sh` is the sole producer of
`supervisor.plugin.sandbox_refused`. It `printf`s the row as JSON to **stderr**
and `exit 1`s. Nothing in `src/alfred/` parses that stderr back into a
structured audit write:

* No `append_schema(fields=SANDBOX_REFUSED_FIELDS, ...)` call exists anywhere.
* The `fail_closed=True` T0 hookpoint registered for the event
  (`supervisor/core.py` `_register_hookpoints`,
  `hooks/_known_hookpoints.py:86`) is never dispatched.

So the row is a fully-specified audit contract — declared field-set
(`SANDBOX_REFUSED_FIELDS`), closed reason vocabulary
(`SANDBOX_REFUSED_REASONS`), registered hookpoint — that **no code writes**. A
refused T3 sandbox launch, a security-relevant event, produces only a stderr
line. This is squarely CLAUDE.md security hard-rule #7 ("no silent failures in
security paths → loud audit entry + alert").

The `NOTE (#433)` comment at `audit_row_schemas.py:1194` and
`docs/subsystems/supervisor.md:362-363` describe a write that does not yet
happen.

## Producer landscape (why this is scoped, not comprehensive)

`bin/alfred-plugin-launcher.sh` is spawned from **four** sites:

| Producer | File | stderr today |
| --- | --- | --- |
| Quarantine child (T3 dual-LLM, `kind="full"`) | `security/quarantine_child_io.py` | `PIPE`, drained to a `child_stderr` log field |
| Foreground TUI (`alfred chat` / discord) | `cli/_launcher_spawn.py` | inherits (`None`) unless piped — cannot capture today |
| Daemon comms adapter | `plugins/comms_stdio_transport.py` | `PIPE` |
| Gateway adapter child | `gateway/adapter_child_factory.py` | `PIPE` |

A refusal from any producer is unpersisted today. This design covers the
**quarantine-child** producer — the highest-security-value path (the T3
dual-LLM boundary, and the path the issue names) — and factors the parsing and
audit-write logic as **shared, reusable units** so the other three producers
adopt them in named follow-ups. The gap stays tracked, never silently dropped.

## The interception point (corrected in v2)

A quarantine-child sandbox refusal is a **pre-`exec`** event: the launcher
`printf`s the row to stderr and `exit 1`s **before `exec`ing the child module**
(every pre-flight refusal — environment, host-OS, `sandbox_block_missing`,
`policy_ref_*`, policy translation, interpreter-prefix — is pre-`exec`). The
question is *where in the host code that refusal becomes observable*.

**It is NOT observable at `deliver_provider_key_via_fd3` (this is the v1 bug).**
`deliver_provider_key_via_fd3` is a single `os.writev` of `4 + len(key)` bytes
(~100 bytes) into a pipe with a ~64KB buffer. The parent runs that `writev`
microseconds after `Popen` returns, while the launcher is still tens of
milliseconds from its `exit 1` (it must resolve environment, read the manifest
via `manifest_reader`, run `jq`, translate the policy). At that instant the
launcher **still holds fd 3's read-end open**, so the small key **buffers and
the write succeeds** — no `BrokenPipeError`, no `ProviderKeyDeliveryError`. The
`writev` reliably wins the race. v1 assumed this arm fires on a refusal; it does
not.

**It IS observable at `read_frame` (EOF).** Because delivery buffers,
`spawn_quarantine_child_io` returns a live `_SubprocessChildIO`. The refusal
surfaces when the transport first drives the child:
`QuarantineStdioTransport.dispatch` → `read_frame` → the launcher has exited
without `exec`ing the child, so the child produced no reply frame → EOF →
`_TruncatedFrameError` → `read_frame_failed` → `QuarantineChildSpawnError`. On
exactly that path, `_SubprocessChildIO._log_child_stderr(failure=True)` **drains
the child's raw stderr** (today only to sanitize it into a `child_stderr` log
field). That raw stderr is the `sandbox_refused` JSON row. **`_log_child_stderr`
on the failure path is the interception point** — which is what issue #433
originally named.

**Deterministic key, not EPIPE.** Following the review's core-003 guidance, the
record is keyed on the deterministic signal — *the child produced no frame and
its stderr carries a `sandbox_refused` row* — never on whether a `writev` raced
into an EPIPE. `read_frame` reaching EOF is that signal.

### Timing / dispatch phase (resolves core-001)

`read_frame` is first called at the **first inbound extraction** (first message
through `QuarantineStdioTransport.dispatch`), which is **after** daemon boot
completes — i.e. after `Supervisor(...)` is constructed and
`_register_hookpoints()` has run (`Supervisor` is built at `_commands.py:783`,
the runner processes messages only after `start()`). So when the auditor
dispatches the `supervisor.plugin.sandbox_refused` hookpoint, it **is
registered**. The review's core-001 hazard (dispatching a hookpoint the
pre-`Supervisor` comms boot graph has not yet declared) does not bite this path,
because the dispatch happens at first-use, not at boot. A test asserts the
hookpoint is declared against the real registry at dispatch time; ADR-0051 also
records the belt-and-suspenders option — declaring the supervisor sandbox
hookpoints via a module-import `declare_hookpoints()` (the
`comms_mcp/hookpoints.py` convention) — as the fix if a future producer ever
dispatches pre-`Supervisor`.

### Security posture is fail-closed at point-of-use, not boot (A-vs-B decision)

Two deterministic interception locations were considered:

* **A — spawn-time probe barrier.** After the fd-3 window closes, wait
  (bounded) for the launcher to either exit (refusal) or stay alive (handed
  off), mirroring `cli/_launcher_spawn.py`'s probe window. Audits at boot and
  can fail the daemon boot closed.
* **B — record at the `read_frame` drain (chosen).** Audit when the refusal is
  first observed (first extraction).

**B is chosen.** The security invariant — *T3 content is never processed by a
dead/absent quarantine child* — holds under both: under B the first message's
T3 content hits the refusal at `read_frame`, the extraction fails closed
(`QuarantineChildSpawnError`), and the row is audited at that moment. B is far
less invasive to the delicate, 100%-gated fd-3 spawn (no new blocking probe, no
change to the spawn's return contract, no boot latency on the success path), and
its dispatch is post-`Supervisor` (sidestepping core-001). A — auditing at boot
and failing boot closed — is a real operability enhancement but a **separate
concern** (a boot-time quarantine health-check) beyond #433's "persist the row"
goal; it is filed as a follow-up. Task 0 empirically confirms the refusal
surfaces at `read_frame` before this is built on.

## Architecture — pure parser + narrow-Protocol recorder

Three single-responsibility units.

### 1. Pure parser — `src/alfred/audit/launcher_refusal.py`

```python
def parse_launcher_refusal_rows(stderr: bytes) -> tuple[SandboxRefusalRow, ...]:
    ...
```

* Frozen `SandboxRefusalRow` (`@dataclass(frozen=True, slots=True)`) carrying
  exactly the `SANDBOX_REFUSED_FIELDS` members, with `as_subject() ->
  dict[str, str]`.
* Scans stderr **line by line**; `json.loads` each; accepts only a `dict` whose
  `event == "supervisor.plugin.sandbox_refused"`.
* **Validates**: keys ⊆ `SANDBOX_REFUSED_FIELDS`; `reason ∈
  SANDBOX_REFUSED_REASONS`; all non-optional fields present. A row failing
  validation is dropped **loudly** (`_log.warning`), never silently.
* **Canonicalizes** to the exact field-set: absent `policy_ref` (omitted by the
  pre-flight refusals) → `""`, because `append_schema` enforces **symmetric**
  keys.
* Pure, no I/O, no audit/hook imports → trivially 100% line+branch testable.

**Location (audit/, not plugins/ — resolves review arch-004/arch-001).** The
parser consumes `SANDBOX_REFUSED_FIELDS`/`SANDBOX_REFUSED_REASONS` from
`alfred.audit.audit_row_schemas` and produces audit-row values; it belongs next
to the schema in `audit/`. This keeps the dependency direction clean
(`security` → `audit`, never `security` → `plugins` for this) and avoids
dragging the heavy `alfred.plugins` package init into the graph.

### 2. Reusable auditor — `src/alfred/security/sandbox_refusal_audit.py`

```python
class SandboxRefusalAuditor:
    def __init__(self, *, audit_writer: AuditWriter) -> None: ...
    async def record(self, rows: tuple[SandboxRefusalRow, ...]) -> None: ...
```

Per row: `append_schema(fields=SANDBOX_REFUSED_FIELDS,
schema_name="SANDBOX_REFUSED_FIELDS", event="supervisor.plugin.sandbox_refused",
actor_user_id=None, actor_persona="supervisor", subject=row.as_subject(),
trust_tier_of_trigger="T0", result="refused", cost_estimate_usd=0.0,
cost_actual_usd=0.0, trace_id=<uuid>)` **then** dispatch the registered
`fail_closed` T0 hookpoint via `invoke(..., kind="post",
subscribable_tiers=SYSTEM_ONLY_TIERS, fail_closed=True)`, mirroring
`cli/daemon/_boot_audit.py:_invoke_boot_failed`. **`alfred.hooks` is imported
lazily (function-local)**, mirroring `_boot_audit.py` and respecting the known
`hooks → security.tiers` back-import (review sec-005).

`record` raising is the caller's contract to handle (see Error handling). This
class is the unit the comms-transport, gateway-adapter, and foreground-TUI
producers adopt in the follow-ups.

### 3. Wiring — recorder on `_SubprocessChildIO`, record in the drain

`spawn_quarantine_child_io(..., refusal_recorder: SandboxRefusalRecorder | None
= None)` — a one-method Protocol (`async def record(self, rows) -> None`),
default `None` = today's behavior byte-for-byte (precursor/dormant posture and
every existing spawn test untouched). The recorder is stored on the returned
`_SubprocessChildIO`.

In `_SubprocessChildIO._log_child_stderr`, after the existing sanitized-field
log, add a **guarded** `await self._record_launcher_refusals(raw)`:

```python
async def _record_launcher_refusals(self, raw: bytes) -> None:
    """Parse launcher refusal rows from raw stderr + record them. Never raises."""
    if self._refusal_recorder is None:
        return
    try:
        rows = parse_launcher_refusal_rows(raw)   # function-local import
        if rows:
            await self._refusal_recorder.record(rows)
    except Exception as exc:
        _log.error(
            "security.quarantine_child.refusal_record_failed",
            error_class=type(exc).__name__,
        )
```

Because `_log_child_stderr` drains at most once (`_stderr_drained` guard), the
record fires at most once. On the clean-teardown (`aclose`, `failure=False`)
path there is no `sandbox_refused` row in stderr (the child ran), so nothing is
recorded — safe to call on both paths.

`daemon_runtime._build_comms_inbound_extractor` (already holds `audit_writer`)
constructs `SandboxRefusalAuditor(audit_writer=...)` and passes it as
`refusal_recorder`. Constructing the auditor is synchronous, so the builder's
"single await = the spawn" fd-3 discipline is preserved.

The parser import in `quarantine_child_io.py` is **function-local** (inside
`_record_launcher_refusals`), not module-top, keeping the adversary-facing IO
module's import surface minimal (review arch-001).

## Error handling / fail-closed posture

* **`record()` failure never masks the refusal and never breaks the drain.** The
  `read_frame` failure arm ALWAYS raises `QuarantineChildSpawnError` (that is how
  the refusal surfaces); `_record_launcher_refusals` is called *before* that
  raise and is fully self-guarding — an `append_schema`/`invoke` failure is
  logged **loud** (`security.quarantine_child.refusal_record_failed` +
  `error_class`, hard rule #7) and swallowed, so it neither preempts the
  contracted `QuarantineChildSpawnError` nor breaks `_log_child_stderr`'s
  best-effort "never raises" contract. This resolves the review's
  record-masks-primary-error High (arch-002/rev-002/core-002/sec-003) — here the
  primary error is guaranteed to surface because the arm raises regardless.
* Malformed / out-of-vocab stderr lines: dropped with a loud `_log.warning`;
  parsing never raises.
* `refusal_recorder is None`: no parse, no record, no behavior change.

## Data flow

```text
launcher refuses (pre-exec) --printf JSON--> child stderr (PIPE); launcher exit 1
                                                     |
first extraction: QuarantineStdioTransport.dispatch -> read_frame
   child produced NO frame (launcher exited pre-exec) -> EOF -> _TruncatedFrameError
                                                     |
   read_frame except arm:  _log.error("read_frame_failed")
                           await _log_child_stderr(failure=True)
                             raw = <drained stderr>            [existing]
                             log sanitized child_stderr        [existing]
                             await _record_launcher_refusals(raw)   [NEW, guarded]
                               rows = parse_launcher_refusal_rows(raw)   [NEW pure]
                               await recorder.record(rows)             [NEW]
                                 -> append_schema(SANDBOX_REFUSED_FIELDS,...)
                                 -> invoke(sandbox_refused, fail_closed=True)  [post-Supervisor]
                           raise QuarantineChildSpawnError          [existing — surfaces the refusal]
```

## Testing (100% line + branch on the trust boundary)

* **Parser (`audit/launcher_refusal`):** single valid row; multiple rows;
  interleaved human + JSON lines; malformed JSON dropped-and-logged; unknown
  `event` ignored; out-of-vocab `reason` dropped-and-logged; absent `policy_ref`
  canonicalized; **missing required field** dropped; **blank-line skip**;
  non-UTF-8 bytes; empty → `()`. (The review flagged the missing-required and
  blank-line branches as coverage gaps — both are covered here.) Assertions are
  on the **returned rows**, not `caplog` (structlog events do not land in
  `caplog.records` — review finding).
* **Auditor (`SandboxRefusalAuditor`):** `record` calls `append_schema` with the
  exact `SANDBOX_REFUSED_FIELDS` subject + correct kwargs; dispatches the
  hookpoint with `fail_closed=True` + `SYSTEM_ONLY_TIERS`; a write/dispatch
  failure **propagates** (the caller guards it); multiple rows each written.
* **Drain wiring (`_SubprocessChildIO`) — via the `_FakePopen` convention
  (`test_quarantine_child_io.py:106`):** a fake with **empty `stdout_frames`
  (EOF) + `stderr_bytes` = a `sandbox_refused` JSON row**, driven through
  `read_frame` → asserts `QuarantineChildSpawnError` **and** the injected
  recorder received the parsed row. Default-`None` recorder → unchanged, no
  record, existing tests green. A `_record_launcher_refusals` test where the
  recorder's `record` **raises** → the drain still completes, logs
  `refusal_record_failed` loud, and the `read_frame_failed`
  `QuarantineChildSpawnError` still surfaces (the record-masking guard).
* **Drain-helper `except` branch (review sec-002):** monkeypatch the raw read to
  raise / time out → assert the guard logs and does not preempt — so the 100%
  line+branch gate on `security/` actually passes.
* **core-001 registry test:** dispatch the auditor against the **real** hook
  registry at the boot phase it actually fires in, asserting
  `supervisor.plugin.sandbox_refused` is declared (proves the post-`Supervisor`
  timing holds).
* **Adversarial (`sbx-2026-018`):** a **real corpus entry under
  `tests/adversarial/sandbox_escape/`** with the mandatory YAML payload
  (category/threat/provenance), NOT a bare pytest module and NOT a duplicate of
  the existing `sbx_2026_008_fd3_partial_write` — asserts a refusal row whose
  values carry injection bytes cannot forge a second audit event (line-oriented
  `json.loads` + canonicalization).
* **Vocab-sync:** confirm `test_sandbox_reason_vocab_sync` still holds (no new
  launcher reason added).

## ADR-0051 outline (launcher→core sandbox-refusal audit path)

* **Context:** the launcher is the sole `sandbox_refused` producer and can only
  `printf` to stderr; four spawn sites drain it; today none persists the row
  (hard-rule-#7 gap).
* **Decision:** pure parser (`audit/launcher_refusal`) + reusable auditor
  (`security/sandbox_refusal_audit`) + narrow-`SandboxRefusalRecorder`-Protocol
  injection into the quarantine spawn; **the deterministic interception point is
  the `read_frame`/`_log_child_stderr` drain, keyed on child-produced-no-frame +
  `sandbox_refused`-in-stderr, NOT on the buffered fd-3 `writev` (the v1 error)
  and NOT on a spawn-time probe barrier (A-vs-B: B chosen for minimal blast
  radius + post-`Supervisor` dispatch)**; parser lives in `audit/` for a clean
  dependency direction; the record is guarded so it can never mask the
  contracted `QuarantineChildSpawnError`.
* **Consequences:** the T3 refusal is persisted at first-use, fail-closed at
  point-of-use; the dispatch is post-`Supervisor` (core-001 moot for this path);
  three producers + a boot-time fail-closed health-check + the
  `provider_key_delivery_failed` synthesized row remain as tracked follow-ups.
* **Alternatives (recorded):** v1's `ProviderKeyDeliveryError`-arm interception
  (rejected — delivery buffers, the arm does not fire); the spawn-time probe
  barrier A (rejected for #433 scope — boot latency + core-001 + larger spawn
  change); all-producers big-bang; parser in `plugins/` (rejected — inverts the
  dependency direction).

## Prose corrections (same PR)

* `src/alfred/supervisor/fd3_key_delivery.py:23-24` — reword the aspirational
  "caller maps this to a `SANDBOX_REFUSED_FIELDS(reason="provider_key_delivery_failed")`
  audit row" claim: that reason stays **reserved / not-yet-written** in this PR
  (the synthesized-row path is a follow-up, not #433 scope). Correct the claim to
  say the delivery-failure reason is reserved for a future writer, so the prose
  matches reality. (Note the correct path is `supervisor/`, not `security/` — the
  v1 plan mis-named it.)
* `docs/subsystems/supervisor.md:362-363` — describe the actual persistence path
  (refusal audited at first-extraction via the drain).
* `src/alfred/audit/audit_row_schemas.py:1194` — update the `NOTE (#433)` block
  (row now persisted on the quarantine path at `read_frame`; three producers +
  the reserved `provider_key_delivery_failed` writer pending).

## Follow-ups to file

* Persist `sandbox_refused` for the **comms-adapter**, **gateway-adapter**, and
  **foreground-TUI** producers via the shared auditor (the TUI needs an
  stderr-capture change — it inherits today).
* **Boot-time fail-closed quarantine health-check** (option A): detect a refusal
  at spawn/boot and refuse boot, rather than at first extraction. Separate
  operability concern.
* **Synthesized `provider_key_delivery_failed` row**: on a genuine fd-3 delivery
  failure (read-end actually closed — rare), write the reserved reason. Deferred
  because its dispatch would be pre-`Supervisor` (needs the `declare_hookpoints()`
  fix) and it is a rare path.

## Out of scope

* #434, #435, #436 — sibling refinements on the same row family.
* Changing *when* a refusal is detected beyond the `read_frame` point (the
  boot-time health-check is a follow-up).

## Revision history

* **v2 (this doc):** the plan-review fleet (test/reviewer/security/core, 4×
  independently + author code-check) found v1's interception point — the
  `ProviderKeyDeliveryError` arm — **does not fire on a refusal**: the ~100-byte
  key `writev` buffers into the 64KB pipe (read-end still open), so delivery
  succeeds and the refusal instead surfaces at `read_frame`. v2 re-anchors the
  interception to the `read_frame`/`_log_child_stderr` drain, relocates the
  parser to `audit/`, makes imports lazy, guards `record()`, drops the
  synthesized `provider_key_delivery_failed` bonus to a follow-up, and adds Task
  0 (empirical spawn check) + the core-001 registry test. Fixed mechanical
  errors: the `fd3_key_delivery.py` path (`supervisor/`, not `security/`).
