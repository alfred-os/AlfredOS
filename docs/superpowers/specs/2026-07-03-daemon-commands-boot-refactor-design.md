# Daemon boot `_commands.py` split — design (#256)

**Status:** design — pending user review
**Date:** 2026-07-03
**Issue:** [#256](https://github.com/MrReasonable/AlfredOS/issues/256) — *CI: add per-file 100% coverage gate for daemon boot-refusal branches*
**Author:** brainstorming session (AI agent), maintainer-directed

## Why this exists

`#256` asked for a per-file 100% coverage gate on the daemon boot-refusal
branches (`_commands.py` / `_failures.py`). The feasibility check on the issue
found that a *whole-file* 100% gate on `_commands.py` is the wrong granularity:
the file is a **2789-line boot orchestrator** doing 5–6 jobs, only some of which
are the fail-closed refuse-boot branches the issue cares about, and it carries
genuinely-unreachable real-infra `finally`/drain lines.

The maintainer reframed the issue: *"clearly we should have full coverage"* +
*"should `_commands.py` be refactored into smaller files? 2400-line spaghetti
ain't fun."* So the plan inverts: **split the file into cohesive modules first**,
because per-file 100% gates are meaningful and feasible on small focused modules,
not on a grab-bag. The refactor is the *enabler* for the coverage `#256` wants.

`_failures.py` is already at 100% (40 stmts, 0 branch) — gating it is the clean,
immediate half and needs no source change.

## Constraints (non-negotiable)

1. **Security-critical fail-closed code.** `_commands.py` holds the audited
   refuse-boot branches (`_refuse_boot`, the `except → _refuse_boot` arms) and the
   resource-reaping `finally` that prevents a leaked bwrap quarantine child
   (CR #255). A careless refactor risks a **fail-OPEN boot regression** or a
   **child/socket/pidfile leak**. Every step must keep the fail-closed direction
   and the reap ordering *byte-exact*.
2. **Incremental, not big-bang.** One cohesive module per PR. After each PR:
   full `tests/unit` green + the release-blocking `tests/adversarial` green +
   a real `/review-pr` pass (security reviewer always) + CodeRabbit.
3. **No behaviour change.** These are pure moves + import fixups. A
   default-empty boot must stay byte-for-byte unchanged
   (`test_default_empty_adapters_boot_unchanged`).
4. **Branch off `main`; never commit to `main` directly.** Editing required CI is
   in scope (adding per-file gate steps) but those steps are *not* new required
   status checks (see §"CI coverage-gate mechanics"), so no `author-gating-workflow`
   gh-api promotion is required.

## Current structure (map)

`_commands.py` — 2789 lines, ~45 top-level symbols. The core problem is
`_start_async` (lines 2073–2619, **546 lines**) threading ~20 shared-state vars
through probes → seed-gate → grant → nonce → comms-graph → supervisor → run-loop
→ a big `try/finally` that reaps resources.

Cohesive clusters (natural module seams):

| Cluster | Lines (approx) | Key symbols |
|---|---|---|
| **comms boot** | 232–1580 (~1350) | `_CommsAdapterWireSpec`, `_RunnerOutboundSender`, `_resolve_comms_adapter_wire_spec`, `_build_sub_payload_promoter`, `_CommsAdapterManifestError`, `_ForwardedInboundRegistryMisconfiguredError`, `_build_forwarded_inbound_registry`, `_is_socket_backed_adapter_kind`, `_resolve_adapter_carrier_kind`, `_emit_durable_intake_ack_loop`, `LifecycleBroadcaster`, `_CommsBootGraph`, `_build_comms_boot_graph`, `_CommsAdapterWiring`, `_build_comms_adapter_wiring`, `_build_comms_runner`, `_spawn_comms_adapter`, `_listen_socket_comms_adapter`, `_make_control_reject_auditor`, `_comms_adapter_failure`, `_comms_adapter_bind_failure` |
| **gate boot** | 1581–1744 (~163) | `_BackingStoreAvailabilityGate`, `_SupervisorBootGate`, `_BootHandshake`, `build_boot_real_gate_for_daemon`, `_first_party_grant_live`, `_install_quarantine_boot_registry`, `build_boot_handshake` |
| **boot audit / lifecycle emit** | 1812–2021 (~210) | `_emit_or_quarantine`, `_emit_ready`, `_emit_going_down`, `_refuse_boot`, `_invoke_boot_failed`, `_invoke_boot_completed`, `_BootRefusedError` (currently defined at line 169; raised only inside this cluster, so it moves with `_refuse_boot`) |
| **settings load** | 2022–2071 | `_load_settings_or_die`, `_EnvironmentNotSetError`, `_environment_refusal_message` |
| **real-infra constructors** | 186–230 | `build_boot_session_scope`, `_build_boot_outbound_dlp` (`# pragma: no cover`, monkeypatched) |
| **orchestrator + CLI entry** | 2073–2789 | `_start_async`, `_current_pid`, `_snapshot_failure`, `start_daemon`, `stop_daemon`, `status_daemon`, `_render_live_adapter_status`, `read_state_git_head_sha`, `wait_for_shutdown` |

## The refactor risk: monkeypatch seams

The unit suite monkeypatches **~33 seams** via `alfred.cli.daemon._commands.X`
(e.g. `_commands.CommsPluginRunner`, `_commands._build_comms_boot_graph`,
`_commands.Supervisor`, `_commands.default_pidfile_path`). Moving a symbol to a
new module changes where a bare-name call resolves. **Python semantics decide the
policy — it is forced, not a free choice:**

- **Seam called by `_start_async` (which stays in `_commands.py`) by bare name.**
  `_commands.py` re-imports the moved symbol (`from ._comms_boot import
  _build_comms_boot_graph`), which binds the name into `_commands`'s namespace.
  `_start_async` reads it from `_commands.__dict__`, so
  `monkeypatch.setattr("...._commands._build_comms_boot_graph", fake)` **still
  works unchanged.** These tests do NOT move.
  Examples: `_build_comms_boot_graph`, `_listen_socket_comms_adapter`,
  `LifecycleBroadcaster`, `Supervisor`, `default_pidfile_path`,
  `build_boot_real_gate_for_daemon`, `wait_for_shutdown`, `_SupervisorBootGate`.

- **Intra-cluster seam (a moved helper calls another moved helper).** The call
  resolves in the *new* module's globals. A test patching `_commands.X` becomes a
  silent no-op → the test breaks. Its patch target **must be repointed** to the
  new module (`_comms_boot.X`).
  Examples (comms cluster): `CommsPluginRunner`, `CommsSocketListener`,
  `CommsStdioTransport` (called by `_build_comms_runner` /
  `_listen_socket_comms_adapter`), `_build_sub_payload_promoter`,
  `_resolve_comms_adapter_wire_spec` (called by wiring/graph helpers).

**Seam-preservation rule (per moved symbol):** grep its test patch-targets; if
the *caller* also moved into the same new module, repoint the test to the new
module path; otherwise keep it in `_commands` via a re-import and leave the test
untouched. The exact repoint list per PR is a plan-level enumeration (a
mechanical `grep -rl '_commands\.<sym>' tests/`), verified by the suite going
green with no `xfail`/skip added.

A re-import that keeps `_start_async`'s seams live does **not** hurt per-file
coverage: coverage is attributed to the file the code *lives in*, not where it is
imported.

## Module split (target end-state)

```
src/alfred/cli/daemon/
├── _commands.py        # thin orchestrator: _start_async, CLI entry (start/stop/status),
│                       #   real-infra constructors, read_state_git_head_sha, wait_for_shutdown
├── _comms_boot.py      # the comms cluster (self-contained: own error types + graph dataclass)
├── _gate_boot.py       # the gate cluster (seed-gate, handshake, grant-assertion, boot registry)
├── _boot_audit.py      # audited refusal + lifecycle emit (_refuse_boot / _emit_* / _invoke_*)
├── _failures.py        # (unchanged) the DaemonBootFailure union — already 100% covered
└── … (existing control-plane / pidfile / probes modules unchanged)
```

Each new module is self-contained: the comms and gate clusters already carry
their own error types and lazy imports (verified by reading the source), so the
move is mechanically *cut symbols → new file → fix imports both ways → repoint the
intra-cluster test seams*.

## CI coverage-gate mechanics

Per-file 100% gates in this repo are named **steps** inside existing jobs, not
new required status checks:

```yaml
- name: <Module> 100% line+branch coverage
  if: steps.check.outputs.has_py == 'true' && hashFiles('<path>') != ''
  run: |
    uv run coverage report --include='<path>' --fail-under=100
```

They follow a **two-gates pattern**: each gated file is named BOTH in the
unit-coverage job (gates on unit-only `.coverage`) AND in the combined
`coverage-gates` / *Trust-boundary files* job (comma-separated `--include` list).
**Both must be updated in the same PR** and kept in sync. Because these are steps,
not new checks, adding one needs no `gh api` required-check promotion.

Gating on unit-only coverage is sound only when the module is fully unit-covered
(no root/Postgres). `# pragma: no cover` on genuinely-unreachable real-infra lines
(e.g. `build_boot_real_gate_for_daemon`, `build_boot_session_scope`) is legitimate
and already present; a per-file 100% gate counts non-pragma lines.

## PR sequence (incremental)

Each PR is independently reviewable, `make check` + `tests/adversarial` green,
one `/review-pr` pass, CodeRabbit, plain `gh pr merge --rebase`.

- **PR-0 (trivial, optional first bank):** add `_failures.py` to the per-file
  100% gate (both jobs). Pure `ci.yml` change, zero source change. The clean half
  of `#256`. Can also fold into PR-1 if the maintainer prefers one fewer PR.
- **PR-1 (highest-value, lowest-risk extraction):** extract `_comms_boot.py`
  (~1350 lines). Move the comms cluster, fix imports both directions, repoint the
  intra-cluster test seams (`CommsPluginRunner`, `CommsSocketListener`,
  `CommsStdioTransport`, `_build_sub_payload_promoter`,
  `_resolve_comms_adapter_wire_spec`, …), add the `_comms_boot.py` per-file 100%
  gate (both jobs). Large diff but mechanically a move.
- **PR-2:** extract `_gate_boot.py` (~163 lines) + its gate.
- **PR-3:** extract `_boot_audit.py` (~210 lines) + its gate. This module holds
  `_refuse_boot` / `_emit_*` / `_BootRefusedError` — the actual fail-closed refusal
  + lifecycle-emit surface `#256` cares about most, so a per-file 100% gate here is
  the core win. `start_daemon` (staying in `_commands.py`) catches
  `_BootRefusedError`, so `_commands.py` re-imports it from `_boot_audit.py`.
- **PR-4 (reassess after PR-1..3 land; separately approved):** the `_start_async`
  decomposition via `BootContext`. See below. Highest risk (the reap `finally`).
  Not pre-committed — decide once `_commands.py` is already much smaller and the
  concrete coverage picture is in hand.

`_commands.py` after PR-3 shrinks from 2789 → ~700 lines (orchestrator + CLI
entry + real-infra constructors), staying under the aggregate 75% gate with
`# pragma: no cover` on the real-infra `finally`/drain lines. Whether it *also*
gets a whole-file gate is the PR-4 question.

## BootContext (designed now, implemented last)

`_start_async` threads ~20 vars. They fall into two kinds:

**Immutable boot identity/config** (established once, read by every phase):
`boot_id`, `audit`, `settings`, `source` (environment_source), `snapshot_ref`,
`session_scope`, `started_at`, `epoch`, `state_git_head_sha`,
`policies_snapshot_hash`.

**Mutable live resources** (accumulated across phases, reaped in the `finally`):
`real_gate`, `gate` (`_SupervisorBootGate`), `t3_nonce`, `outbound_dlp`,
`comms_graph`, `socket_listeners`, `control_server`, `lifecycle_broadcaster`,
`supervisor`, `pidfile_path`, `ready_emitted`.

Proposed shape:

```python
@dataclass(frozen=True, slots=True)
class BootIdentity:
    boot_id: str
    audit: AuditWriter
    settings: Settings
    source: str
    started_at: datetime
    epoch: BootEpoch
    # snapshot_ref / session_scope / derived hashes established during probes

@dataclass(slots=True)
class BootResources:
    """The reapable set. `areap()` IS the current finally body, order-exact."""
    supervisor: _SupervisorType | None = None
    comms_graph: _CommsBootGraph | None = None
    socket_listeners: list[CommsSocketListener] = field(default_factory=list)
    control_server: DaemonControlServer | None = None
    lifecycle_broadcaster: LifecycleBroadcaster = field(default_factory=LifecycleBroadcaster)
    pidfile_path: Path | None = None
    ready_emitted: bool = False

    async def areap(self, *, audit, boot_id, epoch) -> None:
        # EXACT current ordering — load-bearing:
        #   1. if ready_emitted: _emit_going_down (own try; must not skip reap)
        #   2. supervisor.stop()          (isolated)
        #   3. comms_graph.aclose()       (suppressed)
        #   4. each socket_listener.aclose() (suppressed, per-listener isolated)
        #   5. control_server.aclose()    (suppressed)
        #   6. delete_pidfile(pidfile_path)
        ...
```

`_start_async` becomes: build `BootIdentity` → run phase functions
(`_probe_phase`, `_gate_phase`, `_comms_phase`, `_supervise_phase`) that populate
`BootResources` → a single `try/finally` whose `finally` is `await
resources.areap(...)`.

**Load-bearing invariant (PR-4 acceptance):** `areap()` must reproduce the current
`finally` ordering and isolation *exactly* — the `going_down` broadcast strictly
before `supervisor.stop()` (H1 ordering invariant), each reap step isolated so one
failure never skips the rest or the pidfile delete (the exact #255 leak this
`finally` prevents). A characterization test that asserts the reap call-order and
that a raising step does not skip later steps is a prerequisite for PR-4.

## Testing strategy

- **Per PR:** the existing daemon-boot unit suite (`tests/unit/cli/daemon/*`) must
  stay green with seams repointed and *no* `xfail`/skip added. New per-file gate
  proves the extracted module hits 100%.
- **Adversarial (release-blocking):** run `tests/adversarial` after each PR — the
  boot-refusal branches are fail-closed security surface.
- **PR-4 only:** add the `areap()` call-order + isolation characterization test
  *before* decomposing, so the decomposition is proven behaviour-preserving.

## Out of scope

- No behaviour change to the boot sequence, refusal reasons, audit rows, or reap
  ordering.
- No new datastores, no PRD/ADR structural change (this is an internal module
  split; if PR-4's `BootContext` is judged an architectural shift, a short ADR is
  added then).
- The unrelated `# pragma: no cover` real-infra constructors are moved only if
  they belong to an extracted cluster; otherwise they stay with the orchestrator.
```
