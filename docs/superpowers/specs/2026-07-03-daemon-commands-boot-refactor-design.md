# Daemon boot `_commands.py` split — design (#256)

**Status:** IMPLEMENTED (2026-07-04) — PR-1/2/3 merged; PR-4 closed #256 via a whole-file gate (BootContext decomposition assessed and **deferred** — see Closeout).

**Date:** 2026-07-03 (design) · 2026-07-04 (closeout)

**Issue:** [#256](https://github.com/MrReasonable/AlfredOS/issues/256) — *CI: add per-file 100% coverage gate for daemon boot-refusal branches*

**Author:** brainstorming session (AI agent), maintainer-directed

## Closeout (2026-07-04)

Delivered as four PRs: PR-1 `_boot_audit`, PR-2 `_gate_boot`, PR-3 `_comms_boot`
(all pure-move extractions, each per-file 100%-gated), and PR-4 the #256 closeout.

**PR-4 diverged from this design's plan, on purpose.** The plan (below) framed
PR-4 as the `BootContext` decomposition of `_start_async` and called it "required
to fully close #256" — because the refuse-*decision* arms live in `_start_async`
and needed to move into a gated module. But the spec also committed to *reassess
that call after the extractions, with data*. The data: after PR-1..3 shrank
`_commands.py` from 2789 to ~1050 lines, its coverage was **99% with zero missing
statements** — every `await _refuse_boot(...)` decision arm was already covered by
the existing boot tests. The only gaps were two defensive reap-`finally` branch
arcs (one now tested; one an unrecordable exception-exit arc that carries a
`# pragma: no branch`).

So PR-4 closed #256 the **lower-risk** way: a **whole-file 100% line+branch gate on
`_commands.py` + `_failures.py`** (the two files #256 named), with **zero
production-logic movement** — sidestepping the reap-`finally` / bwrap-child-leak
risk the decomposition carried. The whole-file gate delivers the same intent
(gating the refuse-decision arms) that the decomposition existed to achieve. No
ADR (no PRD §5 invariant, CLI, or trust-boundary change). The `BootContext` design
in this doc is retained as a **possible future refactor** for `_start_async`
navigability — it is not required for #256 and was not built.

## Why this exists

`#256` asked for a per-file 100% coverage gate on the daemon boot-refusal
branches (`_commands.py` / `_failures.py`). The feasibility check on the issue
found that a *whole-file* 100% gate on `_commands.py` is the wrong granularity:
the file is a **2789-line boot orchestrator** doing 5–6 jobs, only some of which
are the fail-closed refuse-boot branches the issue cares about, and it carries
genuinely-unreachable real-infra `finally`/drain lines.

The maintainer reframed the issue: *"clearly we should have full coverage"* plus
*"should `_commands.py` be refactored into smaller files? 2400-line spaghetti
ain't fun."* So the plan inverts: **split the file into cohesive modules first**,
because per-file 100% gates are meaningful and feasible on small focused modules,
not on a grab-bag. The refactor is the *enabler* for the coverage `#256` wants.

`_failures.py` is already at 100% (40 stmts, 0 branch) — gating it is the clean,
immediate half and needs no source change.

## What `#256` closure actually requires (scope reframe)

A finding from review (`err-001` / `sec-001`) sharpened the scope: the daemon's
fail-closed *refusal-decision* branches — the `if failure is not None: await
_refuse_boot(...)` guards and the `except X: await _refuse_boot(...)` arms — live
**inside `_start_async`** (source lines 2195 / 2212 / 2240 / 2292 / 2309 / 2358 /
2375 / 2383). The `_boot_audit.py` extraction gates the refusal *mechanism*
(`_refuse_boot` emits the row and raises), but **not** those decision branches.

Consequences, stated plainly:

- The cluster extractions (below) deliver: per-file 100% gating of the refusal
  *mechanism* + the navigability win + a much smaller `_commands.py`.
- The refusal-*decision* arms `#256` most cares about stay in `_start_async` and
  are **not** per-file gated until those arms move into a gated module — which is
  the PR-4 `BootContext` decomposition. So **PR-4 is required to fully close
  `#256`**, not an optional nicety. This is a change from the first draft, which
  framed PR-4 as "reassess / maybe." It remains the last and riskiest PR, but it
  is now on the critical path for closure, and the plan says so.

## Constraints (non-negotiable)

1. **Security-critical fail-closed code.** `_commands.py` holds the audited
   refuse-boot branches and the resource-reaping `finally` that prevents a leaked
   bwrap quarantine child (CR #255). A careless refactor risks a **fail-OPEN boot
   regression** or a **child/socket/pidfile leak**. Every step must keep the
   fail-closed direction and the reap ordering *byte-exact*.
2. **Incremental, not big-bang.** One cohesive module per PR. After each PR:
   full `tests/unit` green + the release-blocking `tests/adversarial` green + a
   real `/review-pr` pass (security reviewer always) + CodeRabbit.
3. **No behaviour change.** These are pure moves + import fixups. The invariants
   held constant, named explicitly so a later PR cannot quietly weaken one: the
   boot sequence, the refusal reasons, the audit-row shapes, the reap ordering,
   **the exit-code contract (2 = refused, 3 = audit-unwritable)**, and the
   `alfred daemon start/stop/status` stdout/stderr. A default-empty boot must stay
   byte-for-byte unchanged (`test_default_empty_adapters_boot_unchanged`).
4. **Branch off `main`; never commit to `main` directly.** Editing required CI is
   in scope (adding per-file gate steps) but those steps are *not* new required
   status checks (see §"CI coverage-gate mechanics"), so no `author-gating-workflow`
   gh-api promotion is required.

## Current structure (map)

`_commands.py` — 2789 lines, ~45 top-level symbols. The core problem is
`_start_async` (lines 2073–2619, **546 lines**) threading ~20 shared-state vars
through probes → seed-gate → grant → nonce → comms-graph → supervisor → run-loop
→ a big `try/finally` that reaps resources.

Cohesive clusters (natural module seams). Line ranges are current locations;
symbols are grouped by target module, so a few (noted) sit elsewhere in the file
today and move to join their cluster.

| Cluster | Lines (approx) | Key symbols |
| ------- | -------------- | ----------- |
| **comms boot** → `_comms_boot.py` | 232–1580 (~1350) | `_CommsAdapterWireSpec`, `_RunnerOutboundSender`, `_resolve_comms_adapter_wire_spec`, `_build_sub_payload_promoter`, `_CommsAdapterManifestError`, `_ForwardedInboundRegistryMisconfiguredError`, `_build_forwarded_inbound_registry`, `_is_socket_backed_adapter_kind`, `_resolve_adapter_carrier_kind`, `_emit_durable_intake_ack_loop`, `_CommsBootGraph`, `_build_comms_boot_graph`, `_CommsAdapterWiring`, `_build_comms_adapter_wiring`, `_build_comms_runner`, `_spawn_comms_adapter`, `_listen_socket_comms_adapter`, `_make_control_reject_auditor`, `_comms_adapter_failure`, `_comms_adapter_bind_failure` |
| **gate boot** → `_gate_boot.py` | 1581–1744 (~163) | `_BackingStoreAvailabilityGate`, `_SupervisorBootGate`, `_BootHandshake`, `build_boot_real_gate_for_daemon`, `_first_party_grant_live`, `_install_quarantine_boot_registry`, `build_boot_handshake` |
| **boot audit / lifecycle emit** → `_boot_audit.py` | 1812–2021 (~210) | `_emit_or_quarantine`, `_emit_ready`, `_emit_going_down`, `_refuse_boot`, `_invoke_boot_failed`, `_invoke_boot_completed`, `_BootRefusedError` (currently at line 169), `LifecycleBroadcaster` (currently at line 587), and the exit-code constants `_EXIT_REFUSED` / `_EXIT_AUDIT_UNWRITABLE` (currently at 151–152) |
| **settings load** (stays in `_commands.py`) | 2022–2071 | `_load_settings_or_die`, `_EnvironmentNotSetError`, `_environment_refusal_message` |
| **real-infra constructors** (stay in `_commands.py`) | 186–230 | `build_boot_session_scope`, `_build_boot_outbound_dlp` (`# pragma: no cover`, monkeypatched) |
| **orchestrator + CLI entry** (stays in `_commands.py`) | 2073–2789 | `_start_async`, `_current_pid`, `_snapshot_failure`, `start_daemon`, `stop_daemon`, `status_daemon`, `_render_live_adapter_status`, `read_state_git_head_sha`, `wait_for_shutdown` |

### Dependency DAG (this drives the PR order)

Review (`arch-001` / `arch-002` / `rev-001` / `err-003`, corroborated by the
performance advisory) established the true dependency direction. The first draft's
claim that "each cluster is self-contained" was **wrong for comms**: comms helpers
`await _refuse_boot(...)` / `_emit_or_quarantine(...)` at source lines ~486, 818,
855, 1049, 1055, 1086, 1137, 1162, 1286, 1324, 1393 — all of which live in the
boot-audit cluster. And `_emit_ready` / `_emit_going_down` (boot-audit) call the
`LifecycleBroadcaster` instance. So:

```
_failures.py  ←  _boot_audit.py  ←  _comms_boot.py
                 (_boot_audit also owns LifecycleBroadcaster + the exit constants)
_gate_boot.py   (independent — depends on neither comms nor boot_audit)
```

Extracting `_comms_boot.py` **before** `_boot_audit.py` would force a top-level
`_comms_boot → _commands` back-import while `_commands → _comms_boot` also holds —
a circular import that fails to load (`_comms_boot` unbuildable). Therefore the
extraction order follows the DAG leaf-first: **`_boot_audit.py` first.**
`LifecycleBroadcaster` is homed in `_boot_audit.py` (its consumers are the emit
functions; the comms socket-carrier only registers via an instance method, never
the constructor). Its type annotation on the boot-audit side is referenced under
`from __future__ import annotations` / `TYPE_CHECKING` where needed so the
end-state stays one-directional.

## The refactor risk: monkeypatch seams

The unit suite monkeypatches **~33 seams** via `alfred.cli.daemon._commands.X`.
Moving a symbol changes where a bare-name call resolves. Python semantics decide
the policy — it is forced, not a free choice:

- **Seam called by `_start_async` (stays in `_commands.py`) by bare name.**
  `_commands.py` re-imports the moved symbol (`from ._boot_audit import
  _refuse_boot`), binding the name into `_commands`'s namespace. `_start_async`
  reads it from `_commands.__dict__`, so `monkeypatch.setattr("...._commands.X",
  fake)` **still works unchanged.** These tests do NOT move. (Empirically
  validated: `build_boot_audit_writer`, the probes, and the pidfile helpers
  already live in sibling modules, are re-imported into `_commands`, and are
  patched at `_commands.` successfully today.)
- **Intra-cluster seam (a moved helper calls another moved helper).** The call
  resolves in the *new* module's globals. A test patching `_commands.X` becomes a
  silent no-op → the test breaks or, worse, silently passes. Its patch target
  **must be repointed** to the new module.

**Seam-preservation rule (per moved symbol):** grep its test patch-targets
(`grep -rl '_commands\.<sym>' tests/`); if the *caller* also moved into the same
new module, repoint the test; otherwise keep it in `_commands` via a re-import and
leave the test untouched.

### Dead-seam verification (hard requirement — `sec-001` / `rev-003`, CRITICAL)

"Suite green + no `xfail`/skip + `grep`" is **necessary but not sufficient**. A
fault-injection seam that silently no-ops after a missed repoint can leave a
test green while the fail-closed branch it was meant to exercise goes untested —
a false-green on a boot refusal. Concrete example: `test_daemon_comms_spawn.py`
patches `_commands._resolve_comms_adapter_wire_spec` to a `_boom` fault-injector
and `_build_sub_payload_promoter` to a benign stand-in; after the comms
extraction both resolve in `_comms_boot.__dict__`, so an un-repointed patch
no-ops — and the `except → _refuse_boot` arm it guards lives in `_start_async`,
which is not per-file gated until PR-4. So each extraction PR MUST additionally:

1. For every repointed **fault-injection** seam, prove it still bites — revert
   the production fix (or perturb the guarded branch) and confirm the test goes
   **red**; and assert the injected fake was actually invoked (call-count / spy),
   not merely present.
2. Enforce a **per-PR coverage-diff floor**: the merged-unit coverage of every
   line the moved code owns must not drop relative to base. A repointed seam that
   silently died shows up as a coverage regression on the branch it guarded.

## Module split (target end-state)

```
src/alfred/cli/daemon/
├── _commands.py        # thin orchestrator: _start_async, CLI entry (start/stop/status),
│                       #   real-infra constructors, read_state_git_head_sha, wait_for_shutdown
├── _boot_audit.py      # audited refusal + lifecycle emit (_refuse_boot / _emit_* / _invoke_* /
│                       #   _BootRefusedError / LifecycleBroadcaster / exit-code constants)
├── _gate_boot.py       # the gate cluster (seed-gate, handshake, grant-assertion, boot registry)
├── _comms_boot.py      # the comms cluster (depends on _boot_audit)
├── _failures.py        # (unchanged) the DaemonBootFailure union — already 100% covered
└── … (existing control-plane / pidfile / probes modules unchanged)
```

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

**Measure before gating (`rev-002`, Medium).** Gating on unit-only coverage is
sound only when the module is fully unit-covered. The comms cluster is **not**
currently 100%: the `#256` feasibility comment located uncovered coverable arms
at source `:295`, `:301`, `:353-355`, `:1048`, `:1086` (manifest-error `raise`
arms + the `_CommsAdapterManifestError` constructor + an `except` arm) — all in
the comms cluster, all reachable by unit tests. So the comms extraction PR must
author those tests to reach per-file 100% — a **second responsibility** riding a
"pure move." Each extraction PR therefore: (a) measures the new module's per-file
coverage first; (b) if `< 100%`, authors the covering tests as a **separate
commit** from the move; (c) only then adds the gate.

**Anti-pragma rule (`sec-003`, High).** `# pragma: no cover` is permitted ONLY on
genuinely-unreachable real-infra constructors (`build_boot_real_gate_for_daemon`,
`build_boot_session_scope`, `_build_boot_outbound_dlp`, `wait_for_shutdown`). A
pragma on a `_refuse_boot` call, an `except → _refuse_boot` arm, or an `_emit_*`
line is forbidden — it would let the 100% gate pass while a fail-closed branch is
un-exercised. Each extraction PR review checks no new pragma lands on a refusal /
emit / decision line.

## PR sequence (incremental, dependency-leaf-first)

Each PR is independently reviewable, `make check` + `tests/adversarial` green,
one `/review-pr` pass (security always), CodeRabbit, plain `gh pr merge --rebase`.

**Per-PR structure (`devex-001`, Medium):** an extraction is committed as two
commits so a fail-closed move stays reviewable — (a) a **pure cut/paste** with
zero edits, verifiable via `git diff --color-moved=zebra` and
lines-added == lines-removed; (b) a separate **import-fixup + test-seam-repoint**
commit. A 1350-line single diff cannot be held in a reviewer's head, and hiding a
content edit inside a move of fail-closed code is the exact fail-OPEN risk this
plan exists to avoid.

**Per-PR i18n step (`i18n-001`, Medium):** moving `t()` call sites shifts the
`#:` location refs in the extracted catalog. CI's `pybabel update --check` runs
without `--no-location`, so each PR must re-run `pybabel extract` + `pybabel
update` (per the repo's i18n-drift flow — never `--omit-header`) and commit the
regenerated `locale/en/LC_MESSAGES/alfred.po`, or the build goes red. The msgids
themselves travel byte-identical with the literal `t("...")` strings (no key
change), and `babel.cfg`'s `**.py` glob under `src/alfred` already scans the new
modules — no `babel.cfg` change.

**Per-PR docs step (`docs-001` / `docs-002`, Medium/Low):** repoint the living
docs that reference relocated symbols by path — `docs/subsystems/comms.md`
(points at `_commands.py` for `_build_comms_boot_graph`, the promoter,
`_CommsBootGraph`) in the comms PR; relocate the relevant module-docstring
paragraphs (`_commands.py` L1–22 documents steps that move out) into the new
modules. ADR references to `_commands.py` are historical and left alone.

The PRs:

- **PR-0 (trivial, optional first bank):** add `_failures.py` to the per-file
  100% gate (both jobs). Pure `ci.yml` change, zero source change. The clean half
  of `#256`. May fold into PR-1 if the maintainer prefers one fewer PR.
- **PR-1 — `_boot_audit.py` (leaf; ~210 lines + moved constants/broadcaster).**
  Extract the refusal + lifecycle-emit mechanism, `_BootRefusedError`,
  `LifecycleBroadcaster`, and the exit-code constants. `start_daemon` (stays in
  `_commands.py`) catches `_BootRefusedError`, so `_commands.py` re-imports it;
  **single definition + a post-move exit-code assertion** (`sec-004`) so the
  class-identity `except` at source 2641 keeps catching. Extracted first so
  every later extraction imports it one-directionally.
- **PR-2 — `_gate_boot.py` (~163 lines).** Independent cluster + its gate.
- **PR-3 — `_comms_boot.py` (~1350 lines).** Depends on `_boot_audit.py` (already
  extracted). Largest move; measure coverage first, author the `:295/:301/:353-355/
  :1048/:1086` tests as a separate commit, repoint the comms fault-injection
  seams with bite-proofs, then gate. Highest value on navigability.
- **PR-4 — `BootContext` decomposition of `_start_async` (on the critical path
  for `#256` closure; separately reviewed).** Moves the refuse-*decision* arms
  into gated phase functions so `#256`'s core intent is actually delivered. See
  below. Highest risk (the reap `finally`).

`_commands.py` after PR-3 shrinks from 2789 → ~1050 lines (the design estimate was ~700; the actual residual is larger) (orchestrator + CLI
entry + real-infra constructors). Whether PR-4 also whole-file-gates the residual
`_commands.py` (pragma-ing the real-infra `finally`/drain lines) is decided in
PR-4.

## BootContext (designed now, implemented in PR-4)

`_start_async` threads ~20 vars in two kinds:

**Immutable boot identity/config** (established once, read by every phase):
`boot_id`, `audit`, `settings`, `source`, `snapshot_ref`, `session_scope`,
`started_at`, `epoch`, `state_git_head_sha`, `policies_snapshot_hash`.

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
    """The reapable set. `areap()` reproduces the current finally body EXACTLY."""
    supervisor: _SupervisorType | None = None
    comms_graph: _CommsBootGraph | None = None
    socket_listeners: list[CommsSocketListener] = field(default_factory=list)
    control_server: DaemonControlServer | None = None
    lifecycle_broadcaster: LifecycleBroadcaster = field(default_factory=LifecycleBroadcaster)
    pidfile_path: Path | None = None
    ready_emitted: bool = False
```

`_start_async` becomes: build `BootIdentity` → run phase functions
(`_probe_phase`, `_gate_phase`, `_comms_phase`, `_supervise_phase`) that populate
`BootResources` and own the refuse-decision arms (now in gated modules) → one
`try/finally` whose `finally` reaps `BootResources`.

### PR-4 acceptance — the reap contract is NOT uniform suppression

The current `finally` (source 2557–2617) mixes propagation and suppression by
design, and the decomposition must preserve **each step's disposition exactly**
(`sec-002` CRITICAL, `arch-003`, `err-002`, `rev-004`):

| Step | Disposition |
| ---- | ----------- |
| `_emit_going_down` (if `ready_emitted`) | own `try`; may raise exit-3, but must NOT skip the reap below |
| `supervisor.stop()` | **propagates** (loud) |
| `comms_graph.aclose()` | `suppress(Exception)` |
| each `socket_listener.aclose()` | `suppress(Exception)`, per-listener isolated |
| `control_server.aclose()` | `suppress(Exception)` |
| `delete_pidfile(pidfile_path)` | **propagates** (loud) |

A symmetric `with suppress(Exception)` `areap()` would pass an "order + no-skip"
test while silently swallowing the loud failures (CLAUDE.md hard rules 7/13).
The **characterization test written before PR-4** must therefore assert: (a) the
call order; (b) that a raising `aclose` does NOT skip later steps or the pidfile
delete; (c) that `supervisor.stop()` and `delete_pidfile` **propagate**; and (d)
exception **precedence** when both `_emit_going_down` (exit-3) and a later loud
step raise — pinning which signal wins (today `supervisor.stop()`'s error would
surface). The H1 ordering invariant (`going_down` broadcast strictly before
`supervisor.stop()`) is part of (a).

## Testing strategy

- **Per PR:** the daemon-boot unit suite (`tests/unit/cli/daemon/*`) stays green
  with seams repointed and *no* `xfail`/skip added; every repointed
  fault-injection seam has a bite-proof (revert → red) and a call-count assertion;
  the per-PR coverage-diff floor holds; the new per-file gate proves the module
  hits 100%.
- **Adversarial (release-blocking):** run `tests/adversarial` after each PR — the
  boot-refusal branches are fail-closed security surface.
- **PR-4 only:** land the `areap()` characterization test (order + per-step
  disposition + precedence, per the table above) *before* decomposing, so the
  decomposition is proven behaviour-preserving.

## Out of scope

- No behaviour change to the boot sequence, refusal reasons, audit rows, exit
  codes, CLI stdout/stderr, or reap ordering.
- No new datastores; no PRD change. A pure symbol-move that preserves the reap
  ordering / H1 invariant byte-exact touches no PRD §5 structural invariant, so no
  ADR is mandatory for PR-1..3. If PR-4's `BootContext` is judged a structural
  shift, a short ADR is added in that PR.
- The `# pragma: no cover` real-infra constructors move only if they belong to an
  extracted cluster; otherwise they stay with the orchestrator.
