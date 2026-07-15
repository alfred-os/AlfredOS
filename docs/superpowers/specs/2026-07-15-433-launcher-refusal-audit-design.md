# #433 — persist the `supervisor.plugin.sandbox_refused` audit row (design)

* **Issue:** #433 (split from the #432 review — arch-002, sec-005)
* **Status:** design (scoping session; implementation follows)
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

The `NOTE (#433)` comment at `audit_row_schemas.py:1194` and the aspirational
prose at `fd3_key_delivery.py:23-24` ("The caller maps this to a
`SANDBOX_REFUSED_FIELDS(reason="provider_key_delivery_failed")` audit row") and
`docs/subsystems/supervisor.md:362-363` all describe a write that does not yet
happen.

## Producer landscape (why this is scoped, not comprehensive)

`bin/alfred-plugin-launcher.sh` is spawned from **four** sites, each draining
stderr differently:

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

## The decisive timing finding

A quarantine-child sandbox refusal surfaces at **spawn time via fd-3 delivery
failure**, not at `read_frame`:

1. On refusal the launcher `printf`s the row to stderr and `exit 1`s **before
   `exec`ing the child module** (every pre-flight refusal — environment,
   host-OS, `sandbox_block_missing`, `policy_ref_*`, policy translation,
   interpreter-prefix — is pre-exec).
2. The child therefore never reads fd 3. `deliver_provider_key_via_fd3()`
   writes the key over the pipe whose read-end went to the (now-exited) child →
   broken pipe / partial write → `ProviderKeyDeliveryError`.
3. `spawn_quarantine_child_io` maps that to `QuarantineChildSpawnError`.

Today the `ProviderKeyDeliveryError` arm reaps the child but **discards its
stderr entirely** — it does not even call `_log_child_stderr`. So the refusal
JSON evaporates. **That arm is the interception point.**

The post-`exec` `read_frame_failed` path (the child started, then the wire
tore) is *not* a sandbox-refusal carrier — a refusing launcher never reaches
`exec`. `sandbox_stub_used` (dev/test) *does* `exec` the child and is a
different-timing, different-issue concern (#436); out of scope here.

## Architecture — pure parser + narrow-Protocol recorder

Three single-responsibility units.

### 1. Pure parser — `src/alfred/plugins/launcher_refusal.py`

```python
def parse_launcher_refusal_rows(stderr: bytes) -> tuple[SandboxRefusalRow, ...]:
    ...
```

* Frozen `SandboxRefusalRow` (Pydantic v2 frozen model / frozen dataclass)
  carrying exactly the `SANDBOX_REFUSED_FIELDS` members.
* Scans stderr **line by line**; attempts `json.loads` on each; accepts only a
  `dict` whose `event == "supervisor.plugin.sandbox_refused"`.
* **Validates** each accepted row: keys ⊆ `SANDBOX_REFUSED_FIELDS`; `reason ∈
  SANDBOX_REFUSED_REASONS`. A row failing validation is **dropped loudly**
  (`_log.warning` with the offending key/reason) — never silently, never
  trusted.
* **Canonicalizes** to the exact field-set: absent optional members (notably
  `policy_ref`, which the pre-flight refusals omit) are filled (`policy_ref =
  ""`). This is load-bearing because `AuditWriter.append_schema` enforces
  **symmetric** keys (subject keys must equal `fields` exactly).
* Pure, no I/O — trivially unit-testable to 100% line+branch.

Trust posture: on the refusal path the child never ran, so stderr is
100%-launcher-authored (T0). Validation is defense-in-depth; #432 + #437 already
guarantee the launcher writes only closed-vocab, charset-safe values.

### 2. Reusable auditor — `src/alfred/security/sandbox_refusal_audit.py`

```python
class SandboxRefusalAuditor:
    def __init__(self, *, audit_writer: _AuditLike) -> None: ...
    async def record(self, rows: tuple[SandboxRefusalRow, ...]) -> None: ...
```

Per row:

1. `await audit_writer.append_schema(fields=SANDBOX_REFUSED_FIELDS,
   schema_name="SANDBOX_REFUSED_FIELDS",
   event="supervisor.plugin.sandbox_refused", actor_user_id=None,
   actor_persona="supervisor", subject={...the five fields...},
   trust_tier_of_trigger="T0", result="refused", cost_estimate_usd=0.0,
   cost_actual_usd=0.0, trace_id=<correlation id>)`.
2. Dispatch the registered `fail_closed` T0 hookpoint via `invoke(...,
   kind="post", subscribable_tiers=SYSTEM_ONLY_TIERS, fail_closed=True)`,
   mirroring `cli/daemon/_boot_audit.py`.

`append_schema` / `invoke` failures are **loud** (hard rule #7) — not swallowed.
This class is the unit the comms-transport, gateway-adapter, and foreground-TUI
producers adopt in the follow-ups.

### 3. Wiring — inject a narrow recorder into the spawn

`spawn_quarantine_child_io(..., refusal_recorder: SandboxRefusalRecorder | None
= None)` where `SandboxRefusalRecorder` is a one-method Protocol
(`async def record(self, rows) -> None`). Default `None` = today's behavior
byte-for-byte (the precursor/dormant posture and every existing spawn test stay
untouched).

On the `ProviderKeyDeliveryError` arm:

1. Drain the reaped child's stderr (reuse `_read_stderr_bytes`, bounded — the
   child is already reaped, so the read cannot block).
2. `rows = parse_launcher_refusal_rows(stderr)`.
3. If `refusal_recorder is not None`: `await refusal_recorder.record(rows)`
   before raising `QuarantineChildSpawnError`.

The `OSError` arm (a `Popen` failure) is **not** an interception point: `Popen`
raising means the launcher binary itself failed to `exec` (missing/permission),
so no child was forked, there is no stderr to drain, and it is not a sandbox
refusal. That arm is left unchanged.

`daemon_runtime._build_comms_inbound_extractor` (which already holds
`audit_writer`) constructs `SandboxRefusalAuditor(audit_writer=...)` and passes
it as `refusal_recorder`.

The IO module gains only a **one-method Protocol** dependency — not
`AuditWriter` / `hooks` concretely — so the most-adversary-facing module and its
per-file 100% gate stay clean.

### Why B1 (write inside the spawn arm) over B2 (attach rows to the exception)

The launcher stderr is only available inside `spawn_quarantine_child_io` (it
owns the `Popen` and reaps the child). B1 keeps the refusal → parse → write
**atomic** at the one point the stderr exists, with the IO module depending only
on the narrow Protocol. B2 (attach `refusal_rows` to `QuarantineChildSpawnError`
and let a boot-audit handler write them) is architecturally purer but spreads a
security-critical write across two modules and risks the rows being lost if the
error is caught/re-raised elsewhere. B1 chosen.

## Bonus: the reserved `provider_key_delivery_failed` reason becomes real

When fd-3 delivery fails but the drained stderr carries **no**
`sandbox_refused` row, it was a genuine delivery failure (not a launcher
refusal). The auditor writes a `sandbox_refused` row with
`reason="provider_key_delivery_failed"` — the reserved reason that
`audit_row_schemas.py:1204-1206` and `fd3_key_delivery.py:23-24` describe but no
code emits today. This turns aspirational prose into a tested path and closes a
second unwired-reason gap for free. (The row is synthesized by the auditor, not
parsed from stderr — the launcher never emits this reason.)

## Data flow

```text
launcher refuses (pre-exec)  --printf JSON-->  child stderr (PIPE)
                                                     |
spawn_quarantine_child_io: deliver_provider_key_via_fd3 -> EPIPE
                                                     |
                              ProviderKeyDeliveryError arm:
                                _terminate_and_reap(child)
                                stderr = _read_stderr_bytes(child)   [NEW]
                                rows   = parse_launcher_refusal_rows(stderr)  [NEW pure]
                                await recorder.record(rows)          [NEW]
                                  -> append_schema(SANDBOX_REFUSED_FIELDS,...)
                                  -> invoke(sandbox_refused, fail_closed=True)
                                raise QuarantineChildSpawnError
```

## Error handling

* Malformed / out-of-vocab stderr lines: dropped with a loud `_log.warning`;
  parsing never raises on bad input (the caller is mid-refusal already).
* `append_schema` / `invoke` failures inside `record`: loud (hard rule #7) —
  they propagate or are logged at error with an explicit `error_class`, never
  swallowed. Exact posture (propagate vs log-and-continue) pinned in the plan;
  the primary `QuarantineChildSpawnError` the caller is raising must still
  surface.
* `refusal_recorder is None`: no write, no behavior change (precursor default).

## Testing (100% line + branch on the trust boundary)

* **Parser (`launcher_refusal`):** single valid row; multiple rows; interleaved
  human + JSON lines; malformed JSON line dropped-and-logged; unknown `event`
  ignored; out-of-vocab `reason` dropped-and-logged; absent `policy_ref`
  canonicalized to `""`; extra/absent required field; non-UTF-8 bytes; empty
  stderr → empty tuple.
* **Auditor (`SandboxRefusalAuditor`):** `record` calls `append_schema` with the
  exact `SANDBOX_REFUSED_FIELDS` subject and correct kwargs; dispatches the
  hookpoint with `fail_closed=True` + `SYSTEM_ONLY_TIERS`; a write/dispatch
  failure is loud, not silent; multiple rows each written; the synthesized
  `provider_key_delivery_failed` row.
* **Spawn wiring:** a fake launcher that refuses (`exit 1` with a
  `sandbox_refused` row) → `spawn_quarantine_child_io` raises
  `QuarantineChildSpawnError` **and** the injected recorder received the parsed
  row; default `None` recorder → no write, existing behavior unchanged.
* **Adversarial:** a refusal row whose values contain injection bytes cannot
  forge a second audit event (guarded upstream by #437; assert the parser
  canonicalizes + validates and the auditor writes exactly one row per input).
* **Vocab-sync interplay:** confirm the #432 `test_sandbox_reason_vocab_sync`
  binding still holds (no new launcher reason added here).

## ADR-0051 outline (launcher→core sandbox-refusal audit path)

* **Context:** the launcher is the sole producer; it can only `printf` to
  stderr (it is a shell script with no DB/audit access); the core must drain,
  parse, and persist.
* **Decision:** pure parser (`plugins/launcher_refusal`) + reusable auditor
  (`security/sandbox_refusal_audit`) + narrow-Protocol injection into the
  spawn; quarantine-first scope; the pre-exec fd-3-delivery-failure interception
  point; the synthesized `provider_key_delivery_failed` path.
* **Consequences:** the row is finally persisted for the T3 path; the reserved
  reason becomes real; three producers remain to adopt the seam (tracked
  follow-ups); the IO module gains one narrow dependency.
* **Alternatives:** B2 (attach-to-exception); all-producers big-bang;
  parse-inside-`_log_child_stderr` (rejected — that path is not the refusal
  carrier and would put the write in a pure-IO drain).

## Prose corrections (same PR)

* `src/alfred/security/fd3_key_delivery.py:23-24` — the "caller maps this to a
  `SANDBOX_REFUSED_FIELDS(...)` audit row" claim becomes true; reword from
  aspirational to descriptive.
* `docs/subsystems/supervisor.md:362-363` — describe the actual persistence
  path.
* `src/alfred/audit/audit_row_schemas.py:1194` — update the `NOTE (#433)` block
  (row now persisted on the quarantine path; three producers pending).

## Follow-ups to file

* Persist `sandbox_refused` for the **comms-adapter** producer
  (`plugins/comms_stdio_transport.py`) via the shared auditor.
* Persist for the **gateway-adapter** producer
  (`gateway/adapter_child_factory.py`).
* Persist for the **foreground-TUI** producer — requires a stderr-capture change
  in `cli/_launcher_spawn.py` (it inherits stderr today), so the operator's
  terminal line is *also* audited.

## Out of scope

* #434 (reason mislabelling round 2), #435 (four no-row refusal paths), #436
  (`sandbox_stub_used` undeclared `reason` field) — sibling refinements on the
  same row family, tracked separately.
* Changing *when* a boot-time refusal is detected (it stays spawn-time via
  fd-3). This design persists the row; it does not alter the fail-closed boot
  semantics.
