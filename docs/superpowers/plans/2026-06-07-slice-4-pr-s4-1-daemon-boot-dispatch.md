# PR-S4-1: daemon-boot-dispatch — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land the `alfred daemon start | stop | status` CLI subcommands and wire the production boot path that constructs `Supervisor(state_git_path=Settings.state_git_path, ...)` so the merged-proposal dispatch loop (ADR-0021 / Slice-3-shipped under `Supervisor._proposal_dispatch_loop`) runs in deployed AlfredOS instances for the first time. The CLI runs three pre-`TaskGroup` probes (launcher policy-resolving, snapshot-ref init, capability-gate handshake) at the CLI layer — **not** inside `Supervisor.start()` (which is TaskGroup-first by current shape; core-007 closure). Each refusal mode emits `DAEMON_BOOT_FAILED_FIELDS` with a typed `failure_reason` `Literal`, prints the operator-translated `t(...)` message to stderr, and exits non-zero. `Settings.environment` becomes mandatory and is dual-sourced (env var precedence over `/etc/alfred/environment`) with a `daemon.boot.environment_source_conflict` audit row on disagreement. Closes **#174**.

**Architecture.** The Slice-3 `Supervisor` already exposes `state_git_path: Path | None` (`src/alfred/supervisor/core.py:177-185`) — when `None` the proposal-dispatch loop is not scheduled; when set, it is. Until Slice 4 no production boot path supplied it; `tests/integration/state/` exercised the loop indirectly. PR-S4-1 closes the gap by adding (a) a new `alfred daemon start` CLI command that constructs the supervisor with the path AND the two new Slice-4 stubs (`policies_ref`, `operator_session_resolver`); (b) a pre-`TaskGroup` probe phase **at the CLI layer** that fails loud-and-early on the five refusal modes spec §3.4 enumerates; (c) `Settings.environment` (mandatory, `Literal["development", "production", "test"]`) dual-sourced via env-var > `/etc/alfred/environment` with conflict-audit; (d) `Settings.state_git_path` (new — Slice-3 hardcoded `/var/lib/alfred/state.git` in `_state_git.py` at the call site). The launcher probe is a no-op stub here (PR-S4-6 fills it in — arch-001 closure). `daemon stop` writes a stop-signal to a PID file the supervisor reads; `daemon status` reads the same PID file + the last `daemon.boot.completed` audit row for the running PID. A smoke test exercises the full boot → mutate-state.git → observe-dispatch loop.

**Tech Stack.** Python 3.12+ · asyncio (Supervisor's existing `TaskGroup`) · Typer (`alfred.cli.daemon`) · pydantic-settings v2 (`Settings.environment`, `Settings.state_git_path`) · `alfred.audit.audit_row_schemas` (PR-S4-0a-shipped Slice-4 constants) · `alfred.audit.AuditWriter` · `alfred.hooks.register_hookpoint` (Slice-3 shipped; new `carrier_tier=` kwarg lands in PR-S4-3 — this PR depends on PR-S4-3 per the index §2 graph) · `alfred.i18n.t()` (Slice-1 shipped; catalog adds in PR-S4-0b) · `alfred.security.RealGate` (Slice-3 shipped, used for capability-gate-handshake probe) · structlog · pytest + testcontainers (for the smoke test).

**PR #205 round-2 review closures** (load-bearing corrections — apply at implementation time):

1. **sec-001 Critical (audit-before-exit)**: `load_settings_or_die()` MUST construct `AuditWriter` BEFORE the environment-missing check. The flow is: (a) construct AuditWriter against an explicit fallback session-scope (in-memory or `/tmp/alfred-boot-audit.log` if Postgres unreachable); (b) check environment; (c) on missing/invalid → emit `DAEMON_BOOT_FAILED_FIELDS(failure_reason="environment_not_set")` THEN print `t(...)` to stderr THEN exit 2. No silent-failure on the most common misconfiguration path. The fallback AuditWriter constructor is a new helper in `src/alfred/cli/daemon/_audit_fallback.py`.

2. **sec-002 Critical (truthy env-var parsing)**: `ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED` MUST be parsed via `_truthy_env(name) -> bool` helper that lowercases, strips whitespace, and accepts `{"1", "true", "yes", "on"}`. NOT `== "1"` strict equality. The same helper is reused by PR-S4-6's launcher policy resolver so the gate and the carrier agree on semantics.

3. **arch-001 High (dead hookpoint surface)**: `_refuse_boot` MUST invoke the `daemon.boot.failed` hookpoint via `await invoke("daemon.boot.failed", stage="error", payload={"failure_reason": ...})` BEFORE the audit emit + exit. Without the invocation the hookpoint registration is dead surface. Task E.2 must include the invoke call alongside the audit emit.

4. **arch-002 High (Pydantic data smuggling)**: `load_settings_or_die()` returns `tuple[Settings, EnvironmentLoadResult]` — NOT `Settings` with `_environment_load_result` smuggled in the model's `data` dict. The Pydantic model has `extra="forbid"`; smuggling violates the constraint at runtime and pollutes serialization. The `EnvironmentLoadResult` carries the conflict-audit metadata (env-var value, file value, resolved value) needed for the conflict-audit emit at the CLI layer.

5. **rev-001 High (per-task preconditions)**: Component A/B tasks have a global gate "PR-S4-0a + PR-S4-0b merged" but Components A and B do NOT consume PR-S4-0a constants. Split: A/B can land any time; D (the probes) and E (the refusals) gate on PR-S4-0a's audit constants. Acceptance criterion 9 is moved to per-task precondition for D/E only.

6. **devex-001 High (actionable error message)**: `t("daemon.boot.launcher_not_policy_resolving")` msgstr says: `"The plugin launcher at /usr/local/bin/alfred-plugin-launcher.sh appears to be the Slice-3 stub (no policy-resolving behaviour). Update alfred to a Slice-4 release ≥ v0.4.0 (which ships the policy-resolving launcher in PR-S4-6). Verify via: \`alfred-plugin-launcher.sh --version\` → expected v4.0+."` NOT "update to PR-S4-6". Concrete path + version check.

7. **devex-002 High (status↔daemon-status cross-ref)**: The `alfred status` help-text catalog (existing Slice-1 key `status.help` in `alfred.po`) MUST be modified by this PR to add the cross-reference line: `"For daemon-specific status (PID, uptime, last boot event), see: alfred daemon status"`. Symmetrically, `daemon.status.help` references back to `alfred status` for full instance status. Both keys ship sample English bodies in the i18n catalog, not just identifiers.

8. **sec-003 Medium (audit-write failure quarantine)**: every `audit.append_schema(...)` call in `_refuse_boot` is wrapped: `try: await audit.append_schema(...); except AuditWriteError: print(t("daemon.boot.audit_log_unwritable"), file=sys.stderr); sys.exit(3)`. CLAUDE.md hard rule 7 demands loud + quarantine on audit failure.

9. **sec-004 Medium (stub launcher refusal in prod)**: the Stage A no-op stub launcher probe MUST refuse in production: when `Settings.environment == "production"` AND the launcher returns the Slice-3 stub signature, refuse with `failure_reason="launcher_not_policy_resolving"`. PR-S4-6 ships the real check; PR-S4-1 ensures no production deploys accidentally succeed without it.

10. **core-eng-001 Medium**: `DaemonBootFailure` discriminated union lives at `src/alfred/cli/daemon/_failures.py` (CLI-layer, NOT `src/alfred/supervisor/protocols.py`) since the daemon refusals are CLI-layer concepts.

11. **core-eng-002 Medium (probe ordering)**: Probe (b) `snapshot-ref init` does file-only ops (Pydantic parse of `config/policies.yaml`). Postgres connectivity is checked separately in probe (c) `capability-gate handshake`. Probe (b) MUST NOT touch Postgres; misattributing a Postgres outage as a snapshot-ref failure leads operators to debug the wrong system.

12. **core-eng-003 Medium (smoke test discipline)**: the smoke test polls `dispatch_loop`'s existing `state.proposal.dispatched` audit-row emits (Slice-3 shipped) instead of `sleep(interval + 5)`. Exercises `alfred daemon stop` via the new `daemon.stop` command, NOT `docker compose down`.

---

## §1 Goal

This PR ships the `alfred daemon` Typer subcommand group and the production boot path that satisfies five spec obligations and closes one carryover issue.

- **Spec §3.1 daemon entry.** `alfred daemon start` is the production entrypoint. `alfred daemon stop` and `alfred daemon status` ship alongside. The Slice-1 `alfred chat` TUI subcommand continues to work; PR-S4-10 rewires it to spawn the TUI MCP plugin via the launcher, but in this PR `alfred chat` is untouched — it remains the in-process TUI per Slice-3 baseline.
- **Spec §3.1 boot-sequence ordering (core-007 closure).** Three probes run in order **at the CLI layer** before `Supervisor` is constructed: `(a) launcher policy-resolving probe`, `(b) snapshot-ref initialisation`, `(c) capability-gate sync handshake`. Failure of any probe raises before the supervisor's `TaskGroup` opens — there is no partial-start state to drain. The probes go in the CLI because `Supervisor.start()` (Slice-3 shape at `src/alfred/supervisor/core.py:227-251`) is TaskGroup-first — it opens `asyncio.TaskGroup()` immediately in `_run()` with no pre-flight phase. PR-S4-1 does NOT change `Supervisor.start()` (the round-2 rev-007 closure spec-wide: runtime-type changes to existing classes belong with the PR that consumes them; this PR adds CLI-side probes, not supervisor-side ones).
- **Spec §3.2 `daemon.boot.completed` audit row.** Emitted once on successful boot with `boot_id` (uuid4), `started_at`, `state_git_head_sha`, `slice_version: Literal["4"]`, `policies_snapshot_hash`. A `daemon.boot.failed` row covers the negative path with a typed `failure_reason: Literal[...]`.
- **Spec §3.4 daemon-boot refusal modes.** Five typed `failure_reason` Literals emit `DAEMON_BOOT_FAILED_FIELDS` and exit non-zero: `environment_not_set`, `unsandboxed_env_in_production`, `launcher_not_policy_resolving`, `snapshot_ref_init_failed`, `capability_gate_handshake_failed`. Each carries an operator-facing `t(...)` message.
- **Spec §7.3 production classification.** `Settings.environment` is **mandatory** (no implicit default) and dual-sourced with deterministic precedence: env var `ALFRED_ENVIRONMENT` wins; `/etc/alfred/environment` is the fallback; disagreement emits `daemon.boot.environment_source_conflict` audit row and uses the env-var value; neither set → daemon refuses with `failure_reason="environment_not_set"`.
- **Issue #174.** Closes the carryover that production never constructed `Supervisor(state_git_path=...)`. Smoke test asserts: daemon boots → mutate state.git → dispatch loop fires → observable side effect.

This PR depends on **PR-S4-0a** (`DAEMON_BOOT_*` constants, `payload_schema.py` additions), **PR-S4-0b** (i18n catalog entries for `daemon.boot.*` messages, Alembic migrations for the daemon-boot audit row schema if new columns are needed), and **PR-S4-3** (`HookpointMeta.carrier_tier` kwarg — required for the three new hookpoints this PR registers). It blocks **PR-S4-2** (`dlp-failure-detail` — that PR threads `OutboundDlpProtocol` through `ProposalContext`, which is reached via the dispatch loop this PR wires in production) and **PR-S4-11** (graduation — runbook references `alfred daemon start`).

---

## §2 Architecture overview

```
alfred daemon start                                  ┐
  │                                                  │  CLI-layer (NEW PR-S4-1)
  ├─ load_settings_or_die()                          │  pre-TaskGroup probe phase
  │    └─ Settings.environment from env-var          │  (core-007 closure)
  │       or /etc/alfred/environment (mandatory)     │
  │                                                  │
  ├─ Probe (a): launcher policy-resolving stub       │
  │    └─ no-op in PR-S4-1; real in PR-S4-6          │
  ├─ Probe (b): snapshot-ref init                    │
  │    └─ stub PoliciesSnapshotRef (real in PR-S4-4) │
  ├─ Probe (c): capability-gate sync handshake       │
  │    └─ RealGate.is_backing_store_available()      │
  │                                                  │
  ├─ Any probe fails:                                 │
  │    ├─ AuditWriter.append_schema(                  │
  │    │     DAEMON_BOOT_FAILED_FIELDS,               │
  │    │     failure_reason=<Literal>, ...)           │
  │    ├─ print(t("daemon.boot.<reason>"), file=err) │
  │    └─ raise typer.Exit(code=2)                    │
  │                                                  │
  └─ All probes pass:                                 ┘
       │
       ▼                                              ┐
    Supervisor(                                       │  Slice-3 surface
      session_scope=session_scope,                    │  (unchanged in this PR)
      gate=real_gate,                                 │
      audit=audit_writer,                             │
      state_git_path=settings.state_git_path,         │
      proposal_dispatch_interval_s=settings.…,        │
      # NEW Slice-4 stub kwargs:                      │
      policies_ref=stub_snapshot_ref,                 │  (added in this PR to
      operator_session_resolver=stub_resolver,        │   Supervisor.__init__;
    ).start()                                         │   real impls in S4-4/S4-5)
       │                                              │
       ▼                                              │
    AuditWriter.append_schema(                        │
      DAEMON_BOOT_FIELDS,                             │
      boot_id=uuid4(),                                │
      started_at=now(),                               │
      state_git_head_sha=...,                         │
      slice_version="4",                              │
      policies_snapshot_hash=...,                     │
    )                                                 │
       │                                              │
       ▼                                              │
    invoke("daemon.boot.completed", ...)              │
       │                                              │
       ▼                                              │
    [Supervisor TaskGroup runs:                       │
       _capability_heartbeat_loop                     │
       _proposal_dispatch_loop  (state.git path set!)│
    ]                                                 ┘


alfred daemon stop
  └─ read PID from ~/.run/alfred/daemon.pid
       └─ os.kill(pid, SIGTERM)
            └─ Supervisor.stop() (existing Slice-3 surface)


alfred daemon status
  ├─ read PID from ~/.run/alfred/daemon.pid (or empty)
  ├─ read last `daemon.boot.completed` audit row (Postgres)
  └─ render: pid, uptime, boot_id, state_git_head_sha,
             policies_snapshot_hash, current task-group state
```

**Why probes live in the CLI, not in `Supervisor.start()` (core-007 closure).**
The Slice-3 `Supervisor.start()` at `src/alfred/supervisor/core.py:227-251` is TaskGroup-first: it spawns `_run()` which immediately opens `async with asyncio.TaskGroup() as tg:` and registers the heartbeat + dispatch loops. There is no pre-flight phase to which probes could be attached without restructuring the start surface — and restructuring would push runtime-type changes onto `Supervisor` that other Slice-4 PRs depend on. The CLI-layer placement keeps `Supervisor.start()` unchanged in this PR. Probes that pass leave the supervisor untouched; probes that fail raise `typer.Exit(2)` before `Supervisor` is constructed.

**The two new Slice-4 stub kwargs.** `Supervisor.__init__` currently takes five kwargs (`session_scope`, `gate`, `audit`, `state_git_path`, `proposal_dispatch_interval_s`). This PR adds **two more**: `policies_ref: PoliciesSnapshotRef | None = None` and `operator_session_resolver: OperatorResolver | None = None`. Both default to `None` so legacy unit tests that construct `Supervisor(session_scope=…, gate=…, audit=…)` keep passing. The real `PoliciesSnapshotRef` ships in PR-S4-4; the real `OperatorResolver` ships in PR-S4-5. PR-S4-1 ships **typed Protocols** for both so this PR's CLI wiring can already pass instances through. The probe (b) constructs a minimal stub `PoliciesSnapshotRef` that loads `config/policies.yaml` once (no watcher, no hot-reload — that's PR-S4-4's job) so the boot-time `policies_snapshot_hash` in the `daemon.boot.completed` row is real, not synthetic.

---

## §3 File structure

| File | Status | Responsibility |
|---|---|---|
| `src/alfred/cli/daemon.py` | **Create** | `daemon_app: typer.Typer`; `start`, `stop`, `status` subcommands; probe orchestration |
| `src/alfred/cli/_daemon_probes.py` | **Create** | The three probe helpers as pure async functions returning `Result[None, DaemonBootFailure]` |
| `src/alfred/cli/_daemon_pidfile.py` | **Create** | PID-file write/read/delete + the small lockfile discipline (mode 0600, hostname-validated) |
| `src/alfred/cli/main.py` | **Modify** | `app.add_typer(daemon_app, name="daemon")` registration alongside the existing groups |
| `src/alfred/config/settings.py` | **Modify** | Add `environment: Literal["development", "production", "test"]` (mandatory, dual-sourced via custom `model_validator`); add `state_git_path: Path` field |
| `src/alfred/config/_environment_loader.py` | **Create** | Dual-source loader for `Settings.environment` — env-var > `/etc/alfred/environment`; emits source-conflict signal for the CLI to audit |
| `src/alfred/supervisor/core.py` | **Modify** | Add `policies_ref` + `operator_session_resolver` kwargs to `Supervisor.__init__` (both default `None`); no change to `start()` |
| `src/alfred/supervisor/__init__.py` | **Modify** | Export `PoliciesSnapshotRefProtocol`, `OperatorResolverProtocol` (typed stubs; real impls land in S4-4/S4-5) |
| `src/alfred/supervisor/protocols.py` | **Create** | `PoliciesSnapshotRefProtocol`, `OperatorResolverProtocol`, `DaemonBootFailure` discriminated union |
| `src/alfred/hooks/registry.py` | (no edits) | PR-S4-3 ships `HookpointMeta.carrier_tier` + `allow_error_substitution`; this PR consumes them via `register_hookpoint(..., carrier_tier="T0")` calls |
| `src/alfred/audit/audit_row_schemas.py` | (no edits) | PR-S4-0a ships `DAEMON_BOOT_FIELDS`, `DAEMON_BOOT_FAILED_FIELDS`, `DAEMON_BOOT_ENVIRONMENT_SOURCE_CONFLICT_FIELDS`; this PR imports them |
| `locale/en/LC_MESSAGES/alfred.po` | **Modify** | Add `daemon.boot.environment_not_set`, `daemon.boot.unsandboxed_env_in_production`, `daemon.boot.launcher_not_policy_resolving`, `daemon.boot.snapshot_ref_init_failed`, `daemon.boot.capability_gate_handshake_failed`, plus `daemon.help.*`, `daemon.start.success`, `daemon.stop.success`, `daemon.status.*`. Catalog skeleton added in PR-S4-0b; this PR fills the daemon-specific keys |
| `tests/unit/cli/daemon/__init__.py` | **Create** | Package marker |
| `tests/unit/cli/daemon/test_daemon_app_registration.py` | **Create** | `alfred --help` lists `daemon`; `alfred daemon --help` lists `start/stop/status` |
| `tests/unit/cli/daemon/test_environment_loader.py` | **Create** | Env-var wins, `/etc/alfred/environment` fallback, conflict signal, both-missing refusal |
| `tests/unit/cli/daemon/test_probe_environment_not_set.py` | **Create** | `Settings.environment` missing → `DAEMON_BOOT_FAILED_FIELDS(failure_reason="environment_not_set")` + exit 2 |
| `tests/unit/cli/daemon/test_probe_unsandboxed_env_in_production.py` | **Create** | `ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED=1` + `environment="production"` → refusal + exit 2 |
| `tests/unit/cli/daemon/test_probe_launcher_not_policy_resolving.py` | **Create** | Stub returns Slice-3 stub signature → refusal + exit 2 (in PR-S4-1 the stub passes; in PR-S4-6 the real probe lands) |
| `tests/unit/cli/daemon/test_probe_snapshot_ref_init_failed.py` | **Create** | Missing/malformed `config/policies.yaml` → refusal + exit 2 |
| `tests/unit/cli/daemon/test_probe_capability_gate_handshake_failed.py` | **Create** | `RealGate.is_backing_store_available()` False → refusal + exit 2 |
| `tests/unit/cli/daemon/test_daemon_boot_completed_emit.py` | **Create** | All probes pass → `DAEMON_BOOT_FIELDS` row with `boot_id`, `state_git_head_sha`, `slice_version="4"`, `policies_snapshot_hash` |
| `tests/unit/cli/daemon/test_daemon_environment_source_conflict.py` | **Create** | env-var + file disagree → `DAEMON_BOOT_ENVIRONMENT_SOURCE_CONFLICT_FIELDS` row; env-var value wins; daemon still boots |
| `tests/unit/cli/daemon/test_daemon_stop_signals_supervisor.py` | **Create** | `alfred daemon stop` reads PID file, sends SIGTERM, supervisor's `_shutdown_event` resolves |
| `tests/unit/cli/daemon/test_daemon_status_renders.py` | **Create** | `alfred daemon status` renders PID, uptime, boot_id, slice_version, snapshot hash |
| `tests/unit/cli/daemon/test_daemon_status_no_daemon.py` | **Create** | `alfred daemon status` with no PID file prints "not running" message, exits 0 (status is read-only, no error) |
| `tests/unit/cli/daemon/test_daemon_pidfile_mode.py` | **Create** | PID file is mode 0600 + owner-current-user; refuses to load a foreign-owned file |
| `tests/unit/cli/daemon/test_daemon_pidfile_stale.py` | **Create** | PID file present but `os.kill(pid, 0)` raises ProcessLookupError → status renders "stale pidfile, no daemon" and `daemon stop` is a no-op exit 0 |
| `tests/unit/cli/daemon/test_daemon_hookpoints_registered.py` | **Create** | `daemon.boot.completed`, `daemon.boot.failed`, `proposal.dispatch.failed` all registered with `carrier_tier="T0"` and `fail_closed=True` |
| `tests/unit/supervisor/test_supervisor_init_new_kwargs.py` | **Create** | `Supervisor(..., policies_ref=..., operator_session_resolver=...)` constructs; legacy positional-arg tests still pass |
| `tests/smoke/test_slice4_daemon_dispatch.py` | **Create** | docker compose up; `alfred daemon start`; queue proposal; observe dispatch loop fires; teardown |
| `tests/unit/config/test_settings_environment_mandatory.py` | **Create** | `Settings()` without `environment` raises; `Settings(environment="production")` constructs |
| `tests/unit/config/test_settings_state_git_path.py` | **Create** | `Settings.state_git_path` defaults to `Path("/var/lib/alfred/state.git")`; override via `ALFRED_STATE_GIT_PATH` works |

---

## §4 Cross-PR contracts (what this PR depends on and emits)

### Depends on (must land first)

| Contract | Owning PR | Verification |
|---|---|---|
| `DAEMON_BOOT_FIELDS` `Final[frozenset[str]]` constant in `alfred.audit.audit_row_schemas` | PR-S4-0a | `from alfred.audit.audit_row_schemas import DAEMON_BOOT_FIELDS` imports cleanly |
| `DAEMON_BOOT_FAILED_FIELDS` constant | PR-S4-0a | Same import test |
| `DAEMON_BOOT_ENVIRONMENT_SOURCE_CONFLICT_FIELDS` constant | PR-S4-0a | Same import test |
| `HookpointMeta.carrier_tier: str` field + `register_hookpoint(carrier_tier=...)` kwarg | PR-S4-3 | `register_hookpoint(name="daemon.boot.completed", carrier_tier="T0", ...)` is accepted |
| `HookpointMeta.allow_error_substitution: bool` field | PR-S4-3 | Defaults `True`; this PR's hookpoints don't override |
| i18n catalog entries for `daemon.help.*`, `daemon.boot.<reason>` | PR-S4-0b (catalog skeleton) + this PR (key bodies) | `pybabel extract` round-trip; `pybabel compile --check` |
| Alembic migration carrying any new `audit_log` columns referenced by `DAEMON_BOOT_FIELDS` | PR-S4-0b | `alembic upgrade head` clean |

### Emits (later PRs may consume)

| Contract | Consuming PR(s) | Shape |
|---|---|---|
| `Settings.environment: Literal["development", "production", "test"]` (mandatory) | PR-S4-6 (launcher reads it), PR-S4-7 (sandbox stub refuses in production), PR-S4-10 (TUI launcher check) | Pydantic field with no default; load fails if neither source set |
| `Settings.state_git_path: Path` (default `/var/lib/alfred/state.git`) | PR-S4-2 (dispatch loop), PR-S4-4 (policy file lives under `config/`, distinct path), PR-S4-11 (graduation runbook) | Pydantic field, dir-checked at probe time |
| `Supervisor.__init__(policies_ref=..., operator_session_resolver=...)` new kwargs | PR-S4-4 (real `PoliciesSnapshotRef`), PR-S4-5 (real `OperatorResolver`) | Both default `None`; legacy tests still pass |
| `PoliciesSnapshotRefProtocol`, `OperatorResolverProtocol` in `alfred.supervisor.protocols` | PR-S4-4, PR-S4-5 | Structural Protocols; real classes in those PRs satisfy them |
| `DaemonBootFailure` typed-discriminated union in `alfred.supervisor.protocols` | PR-S4-6 (extends with launcher-specific failure modes), PR-S4-11 (runbook documentation) | `Literal[...]`-tagged Pydantic models, one per `failure_reason` |
| `~/.run/alfred/daemon.pid` PID-file contract (mode 0600, JSON: `{pid, boot_id, started_at, hostname}`) | PR-S4-11 (runbook) | Documented in `docs/subsystems/supervisor.md` updates in PR-S4-11 |
| Hookpoint `daemon.boot.completed` (post, T0, fail_closed=True) | PR-S4-11 (graduation runbook) | Declared in this PR; no subscribers in-tree |
| Hookpoint `daemon.boot.failed` (**post**, T0, fail_closed=True) | PR-S4-11 | Declared in this PR; no subscribers in-tree. **Contract deviation (arch-222-2, recorded deliberately):** the plan/arch-001 originally prescribed `invoke(stage="error")`; the PR ships `kind="post"`. Rationale: a boot refusal is an OBSERVATION of a refusal that already happened (the `DaemonBootFailure` is the carrier payload), not an error-substitution chain — the error stage's required synthetic `exc` would be fabricated. `kind="post"` mirrors the supervisor's `_invoke_supervisor_hookpoint` shape. PR-S4-2 subscribes `proposal.dispatch.failed` on the error stage and does NOT depend on `daemon.boot.failed`'s stage, so no downstream contract breaks. See `_invoke_boot_failed` in `src/alfred/cli/daemon/_commands.py`. |
| Hookpoint `proposal.dispatch.failed` (error, T0, fail_closed=True) | PR-S4-2 (DLP scan on `processed_proposals.failure_detail`), PR-S4-11 | Declared in this PR; PR-S4-2's emit site subscribes |

### Surfaces this PR explicitly does NOT touch

- **`Supervisor.start()`** — TaskGroup-first; probes go in the CLI per core-007 closure. The body of `start()` is byte-identical pre/post-merge.
- **`Supervisor._proposal_dispatch_loop`** — Slice-3 surface at `src/alfred/supervisor/core.py:317`. This PR wires it into production via `state_git_path`; it does NOT touch the loop body. (PR-S4-2 threads `OutboundDlpProtocol` into the failure-detail write inside this loop.)
- **`alfred chat`** — stays as Slice-3 in-process TUI; PR-S4-10 rewires it to spawn the TUI MCP plugin.
- **`bin/alfred-plugin-launcher.sh`** — the launcher probe is a no-op stub in this PR; PR-S4-6 ships the policy-resolving extension.
- **`config/policies.yaml`** — the snapshot-ref-init probe loads it once if present; PR-S4-4 ships the `PolicyWatcher` and the full `PoliciesV1` model. This PR's stub `PoliciesSnapshotRef` parses the file with `yaml.safe_load` and records the SHA; if the file is missing entirely, it falls back to a built-in default `PoliciesV1` shipped in PR-S4-4 — for this PR we ship a stub `_DefaultPoliciesV1` literal in `src/alfred/cli/_daemon_probes.py` that PR-S4-4 will delete.

---

## §5 Tasks

Tasks follow strict TDD: write the failing test, confirm FAIL, implement, confirm PASS, commit. Every commit references **#174**.

> **Subagent dispatch.** Each task is bite-sized enough to dispatch to a worker. Multiple tasks within a component are sequential because each builds on the prior commit. Tasks across components (A → B → C → D → E → F) are also sequential because each component's surface is consumed by the next. There is no parallelism within this PR — the dependency graph is linear.

---

### Component A — `Settings` field additions (foundation)

The two new Settings fields are the lowest-level dependency. Every other component reads them.

- [ ] **Task A.1 — `Settings.state_git_path` field.**
  Files: Modify `src/alfred/config/settings.py`.

  **Failing test** (`tests/unit/config/test_settings_state_git_path.py`):

  ```python
  """Verify Settings.state_git_path defaults + override behaviour."""
  from __future__ import annotations
  from pathlib import Path
  import os
  import pytest
  from alfred.config.settings import Settings


  def test_state_git_path_default(monkeypatch: pytest.MonkeyPatch) -> None:
      """Default is /var/lib/alfred/state.git per spec §3.1 reference shape."""
      monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-test")
      monkeypatch.setenv("ALFRED_ENVIRONMENT", "development")
      monkeypatch.delenv("ALFRED_STATE_GIT_PATH", raising=False)
      settings = Settings()
      assert settings.state_git_path == Path("/var/lib/alfred/state.git")


  def test_state_git_path_override(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
      """ALFRED_STATE_GIT_PATH env var overrides the default."""
      monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-test")
      monkeypatch.setenv("ALFRED_ENVIRONMENT", "development")
      monkeypatch.setenv("ALFRED_STATE_GIT_PATH", str(tmp_path / "alt-state.git"))
      settings = Settings()
      assert settings.state_git_path == tmp_path / "alt-state.git"
  ```

  Run: `uv run pytest tests/unit/config/test_settings_state_git_path.py -q` → 2 failures (`AttributeError: state_git_path`).

  **Implementation** (append to `Settings` in `src/alfred/config/settings.py`):

  ```python
  # ADR-0021 #174: state.git absolute path. Slice-3 hardcoded
  # /var/lib/alfred/state.git in src/alfred/cli/_state_git.py at the call
  # site; PR-S4-1 promotes it to a Settings field so the daemon boot
  # path and the operator CLI both read from the same source.
  state_git_path: Path = Field(
      default=Path("/var/lib/alfred/state.git"),
      description="Absolute path to the state.git repository. "
                  "Override via ALFRED_STATE_GIT_PATH.",
  )
  ```

  Add the `Path` import at the top of the file. Run the test again → 2 passed.

  Commit:

  ```
  git commit -m "feat(config): Settings.state_git_path field for #174 daemon boot wiring"
  ```

---

- [ ] **Task A.2 — `_environment_loader` module.**
  Files: Create `src/alfred/config/_environment_loader.py`.

  **Failing test** (`tests/unit/cli/daemon/test_environment_loader.py`):

  ```python
  """Verify dual-source loader for Settings.environment per spec §7.3."""
  from __future__ import annotations
  from pathlib import Path
  import pytest
  from alfred.config._environment_loader import (
      EnvironmentLoadResult,
      EnvironmentSource,
      load_environment,
  )


  def test_env_var_wins(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
      """ALFRED_ENVIRONMENT env var takes precedence over /etc/alfred/environment."""
      etc_file = tmp_path / "environment"
      etc_file.write_text("development\n", encoding="utf-8")
      monkeypatch.setenv("ALFRED_ENVIRONMENT", "production")
      result = load_environment(etc_path=etc_file)
      assert result == EnvironmentLoadResult(
          value="production",
          source=EnvironmentSource.ENV_VAR,
          conflict=True,
          conflicting_file_value="development",
      )


  def test_file_fallback(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
      """When env var unset, /etc/alfred/environment is the fallback."""
      etc_file = tmp_path / "environment"
      etc_file.write_text("production\n", encoding="utf-8")
      monkeypatch.delenv("ALFRED_ENVIRONMENT", raising=False)
      result = load_environment(etc_path=etc_file)
      assert result == EnvironmentLoadResult(
          value="production",
          source=EnvironmentSource.ETC_FILE,
          conflict=False,
          conflicting_file_value=None,
      )


  def test_neither_set(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
      """Neither source set → returns None value (probe converts this to refusal)."""
      monkeypatch.delenv("ALFRED_ENVIRONMENT", raising=False)
      missing = tmp_path / "does-not-exist"
      result = load_environment(etc_path=missing)
      assert result.value is None
      assert result.source is EnvironmentSource.NONE


  def test_unrecognised_value(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
      """A value outside the Literal triple is treated as unset (probe refuses)."""
      monkeypatch.setenv("ALFRED_ENVIRONMENT", "staging")  # not in {dev,prod,test}
      result = load_environment(etc_path=tmp_path / "absent")
      assert result.value is None
      assert result.source is EnvironmentSource.UNRECOGNISED
      assert result.unrecognised_value == "staging"


  def test_file_trim_whitespace(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
      """Trailing newlines + surrounding whitespace are stripped per spec §7.3."""
      etc_file = tmp_path / "environment"
      etc_file.write_text("  test  \n", encoding="utf-8")
      monkeypatch.delenv("ALFRED_ENVIRONMENT", raising=False)
      result = load_environment(etc_path=etc_file)
      assert result.value == "test"
  ```

  Run: `uv run pytest tests/unit/cli/daemon/test_environment_loader.py -q` → 5 failures (ImportError).

  **Implementation** (`src/alfred/config/_environment_loader.py`):

  ```python
  """Dual-source loader for Settings.environment.

  Spec §7.3 (sec-003 closure) — Settings.environment is mandatory and
  dual-sourced with deterministic precedence:

  1. ALFRED_ENVIRONMENT env var (primary; wins on conflict).
  2. /etc/alfred/environment file (fallback; trimmed).
  3. Disagreement emits `daemon.boot.environment_source_conflict`
     (caller's responsibility — this loader returns the `conflict` flag).
  4. Neither set → caller refuses to boot with
     `failure_reason="environment_not_set"`.

  This module is isolated so `Settings.__init__` can call it without
  pulling in the audit/typer/cli graph at module-load time (perf-001
  discipline from Slice-3).
  """
  from __future__ import annotations
  import enum
  import os
  from dataclasses import dataclass
  from pathlib import Path
  from typing import Final

  _VALID_VALUES: Final[frozenset[str]] = frozenset({"development", "production", "test"})
  _DEFAULT_ETC_PATH: Final[Path] = Path("/etc/alfred/environment")


  class EnvironmentSource(enum.Enum):
      """Which source produced the final value (or why there is none)."""
      ENV_VAR = "env_var"
      ETC_FILE = "etc_file"
      NONE = "none"
      UNRECOGNISED = "unrecognised"


  @dataclass(frozen=True, slots=True)
  class EnvironmentLoadResult:
      """Outcome of the dual-source environment lookup.

      Attributes:
          value: The resolved environment value, or None if neither
              source supplied a recognised value. Always one of the
              Literal triple when not None.
          source: Which source produced ``value``.
          conflict: True iff both sources are set AND disagree.
          conflicting_file_value: When ``conflict`` is True, the value
              the file held (the env-var value is in ``value``).
          unrecognised_value: When ``source`` is UNRECOGNISED, the raw
              string that failed Literal validation. Carried so the
              caller's refusal message can echo what the operator typed.
      """
      value: str | None
      source: EnvironmentSource
      conflict: bool = False
      conflicting_file_value: str | None = None
      unrecognised_value: str | None = None


  def load_environment(*, etc_path: Path = _DEFAULT_ETC_PATH) -> EnvironmentLoadResult:
      """Resolve Settings.environment via env-var > /etc file precedence.

      Args:
          etc_path: Override for the file source. Tests pass a tmp_path
              so the suite never touches /etc/alfred/environment on a
              developer machine. Production callers pass the default.

      Returns:
          EnvironmentLoadResult describing the resolved value, the source
          that produced it, and any conflict the daemon must audit.
      """
      env_raw = os.environ.get("ALFRED_ENVIRONMENT")
      file_raw: str | None = None
      try:
          file_raw = etc_path.read_text(encoding="utf-8").strip()
      except (FileNotFoundError, PermissionError, IsADirectoryError):
          # Either the file is absent (developer machine) or unreadable
          # (mode-misconfigured /etc — operator concern). The caller's
          # refusal path handles "neither source set"; we just return.
          file_raw = None
      except OSError:
          # Any other filesystem error: treat as unreadable. Loud failure
          # is the caller's job; the loader stays narrow.
          file_raw = None

      # Validate each candidate against the Literal triple.
      env_value = env_raw if env_raw in _VALID_VALUES else None
      file_value = file_raw if file_raw in _VALID_VALUES else None

      if env_value is not None:
          conflict = file_value is not None and file_value != env_value
          return EnvironmentLoadResult(
              value=env_value,
              source=EnvironmentSource.ENV_VAR,
              conflict=conflict,
              conflicting_file_value=file_value if conflict else None,
          )
      if file_value is not None:
          return EnvironmentLoadResult(
              value=file_value,
              source=EnvironmentSource.ETC_FILE,
          )
      # Neither resolved. Distinguish "totally missing" from "set but
      # unrecognised" so the refusal message can echo what the operator
      # typed in the latter case.
      if env_raw is not None and env_raw not in _VALID_VALUES:
          return EnvironmentLoadResult(
              value=None,
              source=EnvironmentSource.UNRECOGNISED,
              unrecognised_value=env_raw,
          )
      if file_raw is not None and file_raw not in _VALID_VALUES:
          return EnvironmentLoadResult(
              value=None,
              source=EnvironmentSource.UNRECOGNISED,
              unrecognised_value=file_raw,
          )
      return EnvironmentLoadResult(value=None, source=EnvironmentSource.NONE)
  ```

  Run: `uv run pytest tests/unit/cli/daemon/test_environment_loader.py -q` → 5 passed.

  Commit:

  ```
  git commit -m "feat(config): dual-source loader for ALFRED_ENVIRONMENT (#174)"
  ```

---

- [ ] **Task A.3 — `Settings.environment` mandatory field.**
  Files: Modify `src/alfred/config/settings.py`.

  **Failing test** (`tests/unit/config/test_settings_environment_mandatory.py`):

  ```python
  """Verify Settings.environment is mandatory per spec §7.3."""
  from __future__ import annotations
  import pytest
  from alfred.config.settings import Settings, SettingsError


  def test_environment_required(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
      """Settings(env=missing) raises SettingsError per sec-003."""
      monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-test")
      monkeypatch.delenv("ALFRED_ENVIRONMENT", raising=False)
      # Override etc path so the test never touches /etc.
      monkeypatch.setattr(
          "alfred.config._environment_loader._DEFAULT_ETC_PATH",
          tmp_path / "no-such-file",
      )
      with pytest.raises(SettingsError):
          Settings()


  def test_environment_production_loads(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
      """Settings(environment='production') constructs cleanly."""
      monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-test")
      monkeypatch.setenv("ALFRED_ENVIRONMENT", "production")
      monkeypatch.setattr(
          "alfred.config._environment_loader._DEFAULT_ETC_PATH",
          tmp_path / "no-such-file",
      )
      settings = Settings()
      assert settings.environment == "production"


  @pytest.mark.parametrize("value", ["development", "production", "test"])
  def test_environment_literal_values(monkeypatch, tmp_path, value) -> None:
      """All three Literal values load."""
      monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-test")
      monkeypatch.setenv("ALFRED_ENVIRONMENT", value)
      monkeypatch.setattr(
          "alfred.config._environment_loader._DEFAULT_ETC_PATH",
          tmp_path / "no-such-file",
      )
      assert Settings().environment == value


  def test_environment_unrecognised_value_refuses(monkeypatch, tmp_path) -> None:
      """A value outside the Literal triple raises SettingsError."""
      monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-test")
      monkeypatch.setenv("ALFRED_ENVIRONMENT", "staging")
      monkeypatch.setattr(
          "alfred.config._environment_loader._DEFAULT_ETC_PATH",
          tmp_path / "no-such-file",
      )
      with pytest.raises(SettingsError):
          Settings()
  ```

  Run: `uv run pytest tests/unit/config/test_settings_environment_mandatory.py -q` → 4 failures.

  **Implementation** (modify `src/alfred/config/settings.py`):

  Add the field + a model-validator (Pydantic v2 idiom) that calls the loader:

  ```python
  from typing import Literal
  from pydantic import model_validator
  from alfred.config._environment_loader import (
      EnvironmentSource,
      load_environment,
  )

  # ... inside class Settings:

  # Spec §7.3 sec-003: mandatory, dual-sourced (env-var > /etc/alfred/environment).
  # Field has NO default — the `_resolve_environment` validator populates it
  # from the dual-source loader at construction time. An explicit kwarg
  # (Settings(environment="...")) still bypasses the loader for tests.
  environment: Literal["development", "production", "test"]

  @model_validator(mode="before")
  @classmethod
  def _resolve_environment(cls, data: object) -> object:
      """Populate ``environment`` from env-var > /etc/alfred/environment.

      Pydantic v2 model-validator (mode='before') runs against the raw
      kwargs dict — when ``environment`` is missing we fall back to the
      dual-source loader. When the loader returns ``None`` we leave the
      field absent and let Pydantic's normal "missing required field"
      error fire, which ``Settings.__init__``'s ``SettingsError`` adapter
      translates to the operator-facing message.
      """
      if not isinstance(data, dict):
          return data
      if "environment" not in data:
          loaded = load_environment()
          if loaded.value is not None:
              data["environment"] = loaded.value
              # Stash the conflict/source for the daemon CLI to audit.
              # We attach via a private attribute on the Settings instance
              # — read-only side channel.
              data["_environment_load_result"] = loaded
          # If loaded.value is None we leave 'environment' absent so
          # Pydantic raises its standard required-field error; the
          # __init__ adapter converts it into SettingsError for the CLI.
      return data
  ```

  Run: `uv run pytest tests/unit/config/test_settings_environment_mandatory.py -q` → 4 passed.

  Commit:

  ```
  git commit -m "feat(config): mandatory Settings.environment dual-sourced (#174)"
  ```

---

### Component B — `Supervisor` kwargs + Protocols (foundation)

The supervisor surface gains two kwargs so the CLI can construct it. Protocols ship with the kwargs so PR-S4-4 / PR-S4-5 can swap in real implementations without re-touching `Supervisor.__init__`.

- [ ] **Task B.1 — `PoliciesSnapshotRefProtocol` + `OperatorResolverProtocol` Protocols.**
  Files: Create `src/alfred/supervisor/protocols.py`.

  **Failing test** (`tests/unit/supervisor/test_supervisor_protocols.py`):

  ```python
  """Verify Slice-4 stub protocols exist and are structurally satisfiable."""
  from __future__ import annotations
  from typing import Protocol, runtime_checkable
  import pytest
  from alfred.supervisor.protocols import (
      OperatorResolverProtocol,
      PoliciesSnapshotRefProtocol,
  )


  def test_policies_snapshot_ref_protocol_is_protocol() -> None:
      assert hasattr(PoliciesSnapshotRefProtocol, "_is_protocol")


  def test_operator_resolver_protocol_is_protocol() -> None:
      assert hasattr(OperatorResolverProtocol, "_is_protocol")


  def test_minimal_stub_satisfies_snapshot_ref() -> None:
      """A minimal class with the right method shape satisfies the Protocol."""
      class _Stub:
          def current(self) -> object: return object()
          def snapshot_hash(self) -> str: return "deadbeef"

      stub: PoliciesSnapshotRefProtocol = _Stub()  # type: ignore[assignment]
      assert stub.snapshot_hash() == "deadbeef"
  ```

  Run: `uv run pytest tests/unit/supervisor/test_supervisor_protocols.py -q` → 3 failures (ImportError).

  **Implementation** (`src/alfred/supervisor/protocols.py`):

  ```python
  """Slice-4 Protocols consumed by Supervisor.__init__.

  Both Protocols default to None in the kwargs so legacy unit tests that
  construct ``Supervisor(session_scope=…, gate=…, audit=…)`` keep passing.
  Real implementations land in:
    - PoliciesSnapshotRefProtocol → PR-S4-4 (PoliciesSnapshotRef)
    - OperatorResolverProtocol → PR-S4-5 (_resolve_operator)
  """
  from __future__ import annotations
  from typing import Protocol, runtime_checkable


  @runtime_checkable
  class PoliciesSnapshotRefProtocol(Protocol):
      """Read-only access to the active PoliciesSnapshot.

      PR-S4-1 ships a minimal stub that loads ``config/policies.yaml`` once
      at boot. PR-S4-4 replaces it with the mtime-polled ``PoliciesSnapshotRef``
      whose ``current()`` is a GIL-atomic single-attribute load (perf-002
      round-2 closure — synchronous, NOT async).
      """
      def current(self) -> object:
          """Return the active snapshot. Type widens to the real
          ``PoliciesSnapshot`` once PR-S4-4 lands."""
          ...

      def snapshot_hash(self) -> str:
          """Return a stable hash of the active snapshot.

          PR-S4-1 uses SHA-256 of the on-disk YAML; PR-S4-4 may switch
          to a content-hash with normalised key ordering.
          """
          ...


  @runtime_checkable
  class OperatorResolverProtocol(Protocol):
      """Resolve the operator UserId from the CLI session file.

      PR-S4-1 ships a no-op stub (returns a synthetic "boot-time" id).
      PR-S4-5 replaces it with the real resolver that reads
      ``~/.config/alfred/session``, validates mode + ownership, queries
      Postgres for the session row, and returns the canonical user id.
      """
      async def resolve(self) -> str:
          """Return the canonical operator UserId.

          PR-S4-1 stub returns a synthetic "_daemon_boot" id so the
          construction surface works; PR-S4-5 raises the typed
          ``OperatorSession*`` exceptions on failure.
          """
          ...
  ```

  Run: `uv run pytest tests/unit/supervisor/test_supervisor_protocols.py -q` → 3 passed.

  Commit:

  ```
  git commit -m "feat(supervisor): protocols for Slice-4 stub kwargs (#174)"
  ```

---

- [ ] **Task B.2 — `Supervisor.__init__` accepts the two new kwargs.**
  Files: Modify `src/alfred/supervisor/core.py`.

  **Failing test** (`tests/unit/supervisor/test_supervisor_init_new_kwargs.py`):

  ```python
  """Verify Supervisor.__init__ accepts the Slice-4 stub kwargs without
  breaking the Slice-3 5-kwarg call sites.
  """
  from __future__ import annotations
  from pathlib import Path
  from unittest.mock import AsyncMock, MagicMock
  import pytest
  from alfred.supervisor.core import Supervisor


  def _make_minimal_session_scope():
      cm = MagicMock()
      cm.__aenter__ = AsyncMock(return_value=MagicMock())
      cm.__aexit__ = AsyncMock(return_value=None)
      return lambda: cm


  def test_legacy_5_kwarg_construction_still_works() -> None:
      """Slice-3 unit tests that pass 5 kwargs must keep passing."""
      sup = Supervisor(
          session_scope=_make_minimal_session_scope(),
          gate=MagicMock(),
          audit=MagicMock(),
          state_git_path=None,
          proposal_dispatch_interval_s=30,
      )
      assert sup is not None


  def test_construction_with_new_slice4_kwargs() -> None:
      """policies_ref + operator_session_resolver accepted as kwargs."""
      class _StubRef:
          def current(self) -> object: return object()
          def snapshot_hash(self) -> str: return "abc"

      class _StubResolver:
          async def resolve(self) -> str: return "_daemon_boot"

      sup = Supervisor(
          session_scope=_make_minimal_session_scope(),
          gate=MagicMock(),
          audit=MagicMock(),
          state_git_path=Path("/tmp/state.git"),
          proposal_dispatch_interval_s=30,
          policies_ref=_StubRef(),
          operator_session_resolver=_StubResolver(),
      )
      assert sup is not None


  def test_both_new_kwargs_default_to_none() -> None:
      """Defaults preserve legacy unit-test construction patterns."""
      sup = Supervisor(
          session_scope=_make_minimal_session_scope(),
          gate=MagicMock(),
          audit=MagicMock(),
      )
      assert sup._policies_ref is None
      assert sup._operator_session_resolver is None
  ```

  Run: `uv run pytest tests/unit/supervisor/test_supervisor_init_new_kwargs.py -q` → 3 failures (kwargs unknown).

  **Implementation** (modify `Supervisor.__init__` at `src/alfred/supervisor/core.py:177-185`):

  ```python
  def __init__(
      self,
      *,
      session_scope: Callable[[], AbstractAsyncContextManager[AsyncSession]],
      gate: _GateLike,
      audit: _AuditLike,
      state_git_path: Path | None = None,
      proposal_dispatch_interval_s: int = 30,
      # Slice-4 stub kwargs (#174). Both default to None so the
      # legacy 5-kwarg construction (unit tests, alfred chat bootstrap)
      # keeps passing unchanged. Real implementations:
      #   policies_ref          → PR-S4-4 (PoliciesSnapshotRef)
      #   operator_session_resolver → PR-S4-5 (_resolve_operator)
      policies_ref: "PoliciesSnapshotRefProtocol | None" = None,
      operator_session_resolver: "OperatorResolverProtocol | None" = None,
  ) -> None:
      # ... existing body ...
      self._policies_ref = policies_ref
      self._operator_session_resolver = operator_session_resolver
  ```

  Import the Protocols at module top via `TYPE_CHECKING` (so the import is free at runtime + mypy sees them):

  ```python
  if TYPE_CHECKING:
      from alfred.supervisor.protocols import (
          OperatorResolverProtocol,
          PoliciesSnapshotRefProtocol,
      )
  ```

  Run: `uv run pytest tests/unit/supervisor/test_supervisor_init_new_kwargs.py -q` → 3 passed. Also run the full Slice-3 supervisor unit suite to verify no regressions: `uv run pytest tests/unit/supervisor -q`.

  Commit:

  ```
  git commit -m "feat(supervisor): stub kwargs policies_ref + operator_session_resolver (#174)"
  ```

---

- [ ] **Task B.3 — `DaemonBootFailure` discriminated union.**
  Files: Modify `src/alfred/supervisor/protocols.py`.

  **Failing test** (`tests/unit/supervisor/test_daemon_boot_failure_union.py`):

  ```python
  """Verify the DaemonBootFailure discriminated union ships the five spec §3.4 modes."""
  from __future__ import annotations
  import pytest
  from alfred.supervisor.protocols import (
      DaemonBootFailure,
      EnvironmentNotSetFailure,
      UnsandboxedEnvInProductionFailure,
      LauncherNotPolicyResolvingFailure,
      SnapshotRefInitFailedFailure,
      CapabilityGateHandshakeFailedFailure,
  )


  @pytest.mark.parametrize("cls,reason", [
      (EnvironmentNotSetFailure, "environment_not_set"),
      (UnsandboxedEnvInProductionFailure, "unsandboxed_env_in_production"),
      (LauncherNotPolicyResolvingFailure, "launcher_not_policy_resolving"),
      (SnapshotRefInitFailedFailure, "snapshot_ref_init_failed"),
      (CapabilityGateHandshakeFailedFailure, "capability_gate_handshake_failed"),
  ])
  def test_failure_carries_literal_reason(cls, reason) -> None:
      instance = cls()
      assert instance.failure_reason == reason


  def test_environment_not_set_carries_no_extra_fields() -> None:
      """Pure refusal — nothing to attach beyond the literal reason."""
      f = EnvironmentNotSetFailure()
      assert f.model_dump() == {"failure_reason": "environment_not_set"}


  def test_snapshot_ref_failed_carries_parse_error() -> None:
      """Failures that need detail carry it on the model."""
      f = SnapshotRefInitFailedFailure(detail_redacted="yaml.scanner.ScannerError")
      d = f.model_dump()
      assert d["failure_reason"] == "snapshot_ref_init_failed"
      assert d["detail_redacted"] == "yaml.scanner.ScannerError"
  ```

  Run → 6 failures (ImportError).

  **Implementation** (append to `src/alfred/supervisor/protocols.py`):

  ```python
  from typing import Literal, Annotated
  from pydantic import BaseModel, ConfigDict, Field


  class _BootFailureBase(BaseModel):
      model_config = ConfigDict(frozen=True, extra="forbid")


  class EnvironmentNotSetFailure(_BootFailureBase):
      failure_reason: Literal["environment_not_set"] = "environment_not_set"


  class UnsandboxedEnvInProductionFailure(_BootFailureBase):
      failure_reason: Literal["unsandboxed_env_in_production"] = "unsandboxed_env_in_production"


  class LauncherNotPolicyResolvingFailure(_BootFailureBase):
      failure_reason: Literal["launcher_not_policy_resolving"] = "launcher_not_policy_resolving"
      probe_response: str = ""  # what the stub launcher returned


  class SnapshotRefInitFailedFailure(_BootFailureBase):
      failure_reason: Literal["snapshot_ref_init_failed"] = "snapshot_ref_init_failed"
      detail_redacted: str = ""  # exception class name; never raw message


  class CapabilityGateHandshakeFailedFailure(_BootFailureBase):
      failure_reason: Literal["capability_gate_handshake_failed"] = "capability_gate_handshake_failed"
      backing_store_kind: Literal["postgres", "state_git", "unknown"] = "unknown"


  DaemonBootFailure = Annotated[
      EnvironmentNotSetFailure
      | UnsandboxedEnvInProductionFailure
      | LauncherNotPolicyResolvingFailure
      | SnapshotRefInitFailedFailure
      | CapabilityGateHandshakeFailedFailure,
      Field(discriminator="failure_reason"),
  ]
  ```

  Run → 6 passed.

  Commit:

  ```
  git commit -m "feat(supervisor): DaemonBootFailure discriminated union for spec §3.4 (#174)"
  ```

---

### Component C — Three probes

The three pre-`TaskGroup` probes spec §3.1 enumerates. Each is a pure async function returning `DaemonBootFailure | None` (None = passed).

- [ ] **Task C.1 — Launcher policy-resolving probe (stub).**
  Files: Create `src/alfred/cli/_daemon_probes.py` (initial scaffold + this probe).

  **Failing test** (`tests/unit/cli/daemon/test_probe_launcher_not_policy_resolving.py`):

  ```python
  """Verify the launcher policy-resolving probe.

  PR-S4-1 ships a no-op stub that always returns None (probe passes);
  PR-S4-6 replaces it with the real probe that calls
  ``bin/alfred-plugin-launcher.sh --self-test``.
  """
  from __future__ import annotations
  import pytest
  from alfred.cli._daemon_probes import probe_launcher_policy_resolving
  from alfred.supervisor.protocols import LauncherNotPolicyResolvingFailure


  @pytest.mark.asyncio
  async def test_probe_stub_passes() -> None:
      """PR-S4-1 stub returns None (no failure)."""
      result = await probe_launcher_policy_resolving()
      assert result is None


  @pytest.mark.asyncio
  async def test_probe_returns_typed_failure_when_signature_mismatch(monkeypatch) -> None:
      """Inject the slice-3 stub signature; probe must return the typed failure."""
      async def _slice3_stub() -> str:
          return "slice-3-stub-signature"  # the response PR-S4-6 will check

      monkeypatch.setattr(
          "alfred.cli._daemon_probes._launcher_self_test_impl",
          _slice3_stub,
      )
      result = await probe_launcher_policy_resolving()
      # In PR-S4-1 the stub above will be wired to return-None; this test
      # locks in the SHAPE the PR-S4-6 implementation must honour.
      # For PR-S4-1 the stub passes; for PR-S4-6 this test will be flipped
      # to assert the failure path. We mark this test xfail until PR-S4-6.
      pytest.xfail("Real launcher probe lands in PR-S4-6 (arch-001 closure)")
  ```

  Run → 1 pass + 1 xfail.

  **Implementation** (`src/alfred/cli/_daemon_probes.py`):

  ```python
  """Pre-TaskGroup probes for the daemon boot path.

  Spec §3.1 (core-007 closure): probes run at the CLI layer, NOT inside
  Supervisor.start(). The supervisor's start() is TaskGroup-first by
  current shape (src/alfred/supervisor/core.py:227-251). PR-S4-1 adds
  these probes to the CLI without touching the supervisor surface.

  Three probes:
    (a) launcher_policy_resolving — no-op stub in PR-S4-1; real in PR-S4-6
    (b) snapshot_ref_init           — load config/policies.yaml once
    (c) capability_gate_handshake  — RealGate.is_backing_store_available()

  Each probe returns ``DaemonBootFailure | None``; ``None`` means passed,
  a discriminated-union instance means refused (caller emits the audit
  row + prints t() message + exits non-zero).
  """
  from __future__ import annotations
  from pathlib import Path
  from typing import TYPE_CHECKING

  if TYPE_CHECKING:
      from alfred.supervisor.protocols import DaemonBootFailure


  async def _launcher_self_test_impl() -> str:
      """PR-S4-1 stub. PR-S4-6 replaces with a real subprocess call to
      ``bin/alfred-plugin-launcher.sh --self-test``.
      """
      return "policy-resolving"  # forward-compat token the PR-S4-6 probe will check


  async def probe_launcher_policy_resolving() -> "DaemonBootFailure | None":
      """Verify the launcher binary supports policy resolution.

      PR-S4-1: stub that always passes.
      PR-S4-6: real probe that runs ``bin/alfred-plugin-launcher.sh --self-test``
      and checks for the policy-resolving signature.
      """
      from alfred.supervisor.protocols import LauncherNotPolicyResolvingFailure

      response = await _launcher_self_test_impl()
      if response != "policy-resolving":
          return LauncherNotPolicyResolvingFailure(probe_response=response)
      return None
  ```

  Run → tests pass. Commit:

  ```
  git commit -m "feat(cli): launcher-policy-resolving probe stub (#174)"
  ```

---

- [ ] **Task C.2 — Snapshot-ref init probe.**
  Files: Modify `src/alfred/cli/_daemon_probes.py`.

  **Failing test** (`tests/unit/cli/daemon/test_probe_snapshot_ref_init_failed.py`):

  ```python
  """Verify the snapshot-ref init probe loads config/policies.yaml or refuses."""
  from __future__ import annotations
  from pathlib import Path
  import pytest
  from alfred.cli._daemon_probes import probe_snapshot_ref_init
  from alfred.supervisor.protocols import SnapshotRefInitFailedFailure


  @pytest.mark.asyncio
  async def test_probe_passes_when_yaml_valid(tmp_path: Path) -> None:
      """Well-formed YAML loads; probe returns None + writes hash."""
      cfg = tmp_path / "policies.yaml"
      cfg.write_text(
          "schema_version: 1\n"
          "rate_limits:\n"
          "  web_fetch_per_user_per_hour: 100\n",
          encoding="utf-8",
      )
      result, snapshot_ref = await probe_snapshot_ref_init(config_path=cfg)
      assert result is None
      assert snapshot_ref is not None
      assert snapshot_ref.snapshot_hash()  # sha256 hex, non-empty


  @pytest.mark.asyncio
  async def test_probe_passes_when_file_missing_uses_default(tmp_path: Path) -> None:
      """Missing file falls back to the PR-S4-1 default policies stub;
      PR-S4-4 may tighten this to require the file once the watcher lands.
      """
      missing = tmp_path / "no-such-policies.yaml"
      result, snapshot_ref = await probe_snapshot_ref_init(config_path=missing)
      assert result is None
      assert snapshot_ref is not None
      # The stub's hash is the literal "default" SHA-256.
      assert snapshot_ref.snapshot_hash() == _default_policies_hash()


  @pytest.mark.asyncio
  async def test_probe_refuses_on_malformed_yaml(tmp_path: Path) -> None:
      """Invalid YAML → typed failure with redacted detail (exception class only)."""
      cfg = tmp_path / "policies.yaml"
      cfg.write_text(":\n:::not valid yaml", encoding="utf-8")
      result, snapshot_ref = await probe_snapshot_ref_init(config_path=cfg)
      assert isinstance(result, SnapshotRefInitFailedFailure)
      assert "ScannerError" in result.detail_redacted or "ParserError" in result.detail_redacted
      assert snapshot_ref is None


  def _default_policies_hash() -> str:
      import hashlib
      return hashlib.sha256(b"_DEFAULT_POLICIES_V1_STUB").hexdigest()
  ```

  Run → 3 failures.

  **Implementation** (append to `src/alfred/cli/_daemon_probes.py`):

  ```python
  import hashlib
  import yaml

  # PR-S4-1 fallback default. PR-S4-4 deletes this once PoliciesV1 ships.
  _DEFAULT_POLICIES_V1_STUB: bytes = b"_DEFAULT_POLICIES_V1_STUB"


  class _StubPoliciesSnapshotRef:
      """Minimal PoliciesSnapshotRef for PR-S4-1.

      Holds the loaded yaml bytes + their sha256. PR-S4-4 replaces with
      the real ``PoliciesSnapshotRef`` that owns the mtime watcher and
      the validated ``PoliciesV1`` Pydantic model.
      """
      def __init__(self, raw_bytes: bytes) -> None:
          self._raw = raw_bytes
          self._hash = hashlib.sha256(raw_bytes).hexdigest()

      def current(self) -> object:
          # PR-S4-1 returns the raw parsed dict; PR-S4-4 returns PoliciesV1.
          return yaml.safe_load(self._raw) if self._raw != _DEFAULT_POLICIES_V1_STUB else None

      def snapshot_hash(self) -> str:
          return self._hash


  async def probe_snapshot_ref_init(
      *,
      config_path: Path = Path("config/policies.yaml"),
  ) -> tuple["DaemonBootFailure | None", "_StubPoliciesSnapshotRef | None"]:
      """Load config/policies.yaml once at boot.

      Returns a 2-tuple: (failure, snapshot_ref). On pass, the failure is
      None and the snapshot_ref is the stub ready to pass into
      ``Supervisor(policies_ref=…)``. On refusal, the snapshot_ref is None
      and the failure carries the redacted exception class.
      """
      from alfred.supervisor.protocols import SnapshotRefInitFailedFailure

      try:
          raw = config_path.read_bytes()
      except FileNotFoundError:
          # Fallback to default stub. PR-S4-4 may require the file.
          return None, _StubPoliciesSnapshotRef(_DEFAULT_POLICIES_V1_STUB)
      except (PermissionError, IsADirectoryError, OSError) as exc:
          return (
              SnapshotRefInitFailedFailure(detail_redacted=type(exc).__qualname__),
              None,
          )

      try:
          yaml.safe_load(raw)  # validate; result discarded for PR-S4-1
      except yaml.YAMLError as exc:
          return (
              SnapshotRefInitFailedFailure(detail_redacted=type(exc).__qualname__),
              None,
          )

      return None, _StubPoliciesSnapshotRef(raw)
  ```

  Run → 3 passed. Commit:

  ```
  git commit -m "feat(cli): snapshot-ref init probe with stub PoliciesSnapshotRef (#174)"
  ```

---

- [ ] **Task C.3 — Capability-gate handshake probe.**
  Files: Modify `src/alfred/cli/_daemon_probes.py`.

  **Failing test** (`tests/unit/cli/daemon/test_probe_capability_gate_handshake_failed.py`):

  ```python
  """Verify the capability-gate sync handshake probe."""
  from __future__ import annotations
  from unittest.mock import AsyncMock, MagicMock
  import pytest
  from alfred.cli._daemon_probes import probe_capability_gate_handshake
  from alfred.supervisor.protocols import CapabilityGateHandshakeFailedFailure


  @pytest.mark.asyncio
  async def test_probe_passes_when_gate_healthy() -> None:
      gate = MagicMock()
      gate.is_backing_store_available = AsyncMock(return_value=True)
      result = await probe_capability_gate_handshake(gate=gate)
      assert result is None


  @pytest.mark.asyncio
  async def test_probe_refuses_when_gate_unavailable() -> None:
      gate = MagicMock()
      gate.is_backing_store_available = AsyncMock(return_value=False)
      result = await probe_capability_gate_handshake(gate=gate)
      assert isinstance(result, CapabilityGateHandshakeFailedFailure)


  @pytest.mark.asyncio
  async def test_probe_refuses_on_gate_exception() -> None:
      gate = MagicMock()
      gate.is_backing_store_available = AsyncMock(side_effect=RuntimeError("pg down"))
      result = await probe_capability_gate_handshake(gate=gate)
      assert isinstance(result, CapabilityGateHandshakeFailedFailure)
      assert result.backing_store_kind in {"postgres", "state_git", "unknown"}
  ```

  Run → 3 failures.

  **Implementation** (append to `src/alfred/cli/_daemon_probes.py`):

  ```python
  async def probe_capability_gate_handshake(
      *,
      gate: object,
  ) -> "DaemonBootFailure | None":
      """Sync handshake with RealGate's backing store.

      Spec §3.4 capability_gate_handshake_failed: RealGate cannot reach
      Postgres or state.git at boot. The probe attempts the
      ``is_backing_store_available()`` call; False or an exception
      both refuse boot.
      """
      from alfred.supervisor.protocols import CapabilityGateHandshakeFailedFailure

      try:
          ok = await gate.is_backing_store_available()  # type: ignore[attr-defined]
      except Exception:  # CLAUDE.md hard rule 7: loud audit on probe failure
          return CapabilityGateHandshakeFailedFailure(backing_store_kind="unknown")
      if not ok:
          return CapabilityGateHandshakeFailedFailure(backing_store_kind="postgres")
      return None
  ```

  Run → 3 passed. Commit:

  ```
  git commit -m "feat(cli): capability-gate handshake probe (#174)"
  ```

---

### Component D — Hookpoint registrations

The three Slice-4 hookpoints this PR owns per spec §10 / index §3 Hookpoint surface table. All carry `carrier_tier="T0"`. PR-S4-3's `HookpointMeta.carrier_tier` kwarg is the consumed surface.

- [ ] **Task D.1 — Register `daemon.boot.completed`, `daemon.boot.failed`, `proposal.dispatch.failed`.**
  Files: Create `src/alfred/cli/daemon.py` (initial skeleton + hookpoint module-level registration).

  **Failing test** (`tests/unit/cli/daemon/test_daemon_hookpoints_registered.py`):

  ```python
  """Verify the three Slice-4 hookpoints this PR owns are registered."""
  from __future__ import annotations
  import pytest
  from alfred.hooks.registry import get_global_registry


  @pytest.fixture(autouse=True)
  def _import_daemon() -> None:
      """Importing the module triggers the module-level register_hookpoint calls."""
      import alfred.cli.daemon  # noqa: F401


  @pytest.mark.parametrize("name", [
      "daemon.boot.completed",
      "daemon.boot.failed",
      "proposal.dispatch.failed",
  ])
  def test_hookpoint_declared(name: str) -> None:
      registry = get_global_registry()
      meta = registry.hookpoint_meta(name)
      assert meta is not None, f"{name} not declared"


  @pytest.mark.parametrize("name", [
      "daemon.boot.completed",
      "daemon.boot.failed",
      "proposal.dispatch.failed",
  ])
  def test_hookpoint_carrier_tier_is_t0(name: str) -> None:
      registry = get_global_registry()
      meta = registry.hookpoint_meta(name)
      assert meta.carrier_tier == "T0"
  ```

  Run → 6 failures (hookpoints not declared).

  **Implementation** (`src/alfred/cli/daemon.py` — initial skeleton):

  ```python
  """alfred daemon CLI — boot/stop/status for the production AlfredOS daemon.

  Spec §3 (issue #174). The daemon entrypoint that constructs
  ``Supervisor(state_git_path=Settings.state_git_path, ...)`` so the
  merged-proposal dispatch loop runs in deployed installs.

  Probes run at the CLI layer pre-TaskGroup (core-007 closure): the
  Slice-3 ``Supervisor.start()`` is TaskGroup-first, so a pre-flight
  phase belongs above the construction site, not inside it.

  Three hookpoints declared at module load:

  * ``daemon.boot.completed`` (post, T0, fail_closed=True) — emitted once
    per successful boot.
  * ``daemon.boot.failed`` (error, T0, fail_closed=True) — emitted on
    every typed refusal mode in DaemonBootFailure.
  * ``proposal.dispatch.failed`` (error, T0, fail_closed=True) — emitted
    by the dispatch loop when a single proposal blob fails. The loop
    itself lives in ``alfred.state.dispatch_loop`` (Slice-3) and PR-S4-2
    will subscribe an OutboundDlp-scan handler; this PR only declares
    the hookpoint.
  """
  from __future__ import annotations

  import typer

  from alfred.hooks.registry import SYSTEM_ONLY_TIERS, get_global_registry
  from alfred.i18n import t


  _registry = get_global_registry()
  # See spec §10 hookpoint table + index §3 — every Slice-4 hookpoint
  # declared by this PR is observation-style at T0 (system-tier carrier).
  _registry.register_hookpoint(
      name="daemon.boot.completed",
      subscribable_tiers=SYSTEM_ONLY_TIERS,
      refusable_tiers=frozenset(),
      fail_closed=True,
      carrier_tier="T0",  # PR-S4-3 added this kwarg to register_hookpoint
  )
  _registry.register_hookpoint(
      name="daemon.boot.failed",
      subscribable_tiers=SYSTEM_ONLY_TIERS,
      refusable_tiers=frozenset(),
      fail_closed=True,
      carrier_tier="T0",
  )
  _registry.register_hookpoint(
      name="proposal.dispatch.failed",
      subscribable_tiers=SYSTEM_ONLY_TIERS,
      refusable_tiers=frozenset(),
      fail_closed=True,
      carrier_tier="T0",
  )


  daemon_app = typer.Typer(help=t("daemon.help.root"), no_args_is_help=True)


  @daemon_app.command("start")
  def start() -> None:
      """Start the AlfredOS daemon (placeholder for Task E.1)."""
      typer.echo("start TBD")  # filled in by Task E.1


  @daemon_app.command("stop")
  def stop() -> None:
      """Stop the AlfredOS daemon (placeholder for Task E.2)."""
      typer.echo("stop TBD")  # filled in by Task E.2


  @daemon_app.command("status")
  def status() -> None:
      """Show daemon status (placeholder for Task E.3)."""
      typer.echo("status TBD")  # filled in by Task E.3
  ```

  Run → 6 passed. Commit:

  ```
  git commit -m "feat(cli): daemon hookpoints registered (#174)"
  ```

---

### Component E — PID file + `start` / `stop` / `status` commands

The body of the three subcommands. `start` does the bulk of the work; `stop` and `status` ride on the PID file `start` writes.

- [ ] **Task E.1 — `_daemon_pidfile` module.**
  Files: Create `src/alfred/cli/_daemon_pidfile.py`.

  **Failing test** (`tests/unit/cli/daemon/test_daemon_pidfile_mode.py` + `test_daemon_pidfile_stale.py`):

  ```python
  # test_daemon_pidfile_mode.py
  from __future__ import annotations
  from pathlib import Path
  import os
  import pytest
  from alfred.cli._daemon_pidfile import (
      PidFileInfo,
      load_pidfile,
      write_pidfile,
      DaemonPidFileError,
  )


  def test_write_pidfile_creates_0600(tmp_path: Path) -> None:
      pf = tmp_path / "daemon.pid"
      write_pidfile(
          path=pf,
          pid=12345,
          boot_id="abc-def",
          started_at="2026-06-07T00:00:00+00:00",
      )
      st = pf.stat()
      assert st.st_mode & 0o777 == 0o600
      assert st.st_uid == os.getuid()


  def test_load_pidfile_refuses_foreign_owner(tmp_path: Path, monkeypatch) -> None:
      pf = tmp_path / "daemon.pid"
      pf.write_text(
          '{"pid":1,"boot_id":"x","started_at":"now","hostname":"h"}',
          encoding="utf-8",
      )
      pf.chmod(0o600)
      # Pretend the file is owned by uid=99999
      orig_stat = Path.stat
      def _fake_stat(self):
          s = orig_stat(self)
          return type(s)((s.st_mode, s.st_ino, s.st_dev, s.st_nlink,
                          99999, s.st_gid, s.st_size, s.st_atime,
                          s.st_mtime, s.st_ctime))
      monkeypatch.setattr(Path, "stat", _fake_stat)
      with pytest.raises(DaemonPidFileError):
          load_pidfile(pf)
  ```

  ```python
  # test_daemon_pidfile_stale.py
  from __future__ import annotations
  from pathlib import Path
  import pytest
  from alfred.cli._daemon_pidfile import (
      load_pidfile,
      write_pidfile,
      is_pid_alive,
  )


  def test_stale_pid_detected(tmp_path: Path) -> None:
      pf = tmp_path / "daemon.pid"
      # Use PID 1 won't be alive for our user; use a definitely-dead pid.
      dead_pid = 999_999
      write_pidfile(pf, pid=dead_pid, boot_id="x", started_at="now")
      info = load_pidfile(pf)
      assert info.pid == dead_pid
      assert is_pid_alive(dead_pid) is False
  ```

  Run → failures (ImportError).

  **Implementation** (`src/alfred/cli/_daemon_pidfile.py`):

  ```python
  """PID file + lockfile discipline for the daemon CLI.

  File at ~/.run/alfred/daemon.pid (mode 0600, owner = current uid).
  JSON contents: {"pid": int, "boot_id": str, "started_at": str (ISO8601),
  "hostname": str}.

  Validation discipline mirrors the operator-session loader (spec §6.2,
  sec-006 closure — open-then-fstat to close the TOCTOU window):
    1. open(path, O_RDONLY | O_NOFOLLOW) — refuse symlinks.
    2. fstat(fd) — validate st_mode == 0600 AND st_uid == os.getuid().
    3. Only then read contents.
  """
  from __future__ import annotations
  import json
  import os
  import signal
  import socket
  from dataclasses import dataclass
  from pathlib import Path
  from typing import Final

  _PIDFILE_DEFAULT_DIR: Final[Path] = Path.home() / ".run" / "alfred"
  _PIDFILE_NAME: Final[str] = "daemon.pid"


  class DaemonPidFileError(Exception):
      """Raised on malformed / foreign-owned / mode-wrong PID file."""


  @dataclass(frozen=True, slots=True)
  class PidFileInfo:
      pid: int
      boot_id: str
      started_at: str
      hostname: str


  def default_pidfile_path() -> Path:
      return _PIDFILE_DEFAULT_DIR / _PIDFILE_NAME


  def write_pidfile(
      path: Path,
      *,
      pid: int,
      boot_id: str,
      started_at: str,
  ) -> None:
      """Write the PID file atomically with mode 0600.

      Creates parent directories if missing (they too are mode 0700).
      """
      path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
      payload = json.dumps({
          "pid": pid,
          "boot_id": boot_id,
          "started_at": started_at,
          "hostname": socket.gethostname(),
      })
      # Atomic write: tempfile + rename. mode is set on the fd before
      # close so the file is never world-readable.
      tmp = path.with_suffix(".pid.tmp")
      fd = os.open(
          str(tmp),
          os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW,
          0o600,
      )
      try:
          os.write(fd, payload.encode("utf-8"))
      finally:
          os.close(fd)
      os.rename(tmp, path)


  def load_pidfile(path: Path) -> PidFileInfo:
      """Open + fstat-validate + read.

      Raises:
          DaemonPidFileError on bad mode, foreign owner, missing file, or
          malformed JSON.
      """
      try:
          fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW)
      except FileNotFoundError as exc:
          raise DaemonPidFileError(f"pidfile_missing:{path}") from exc
      try:
          st = os.fstat(fd)
          if st.st_mode & 0o777 != 0o600:
              raise DaemonPidFileError(f"bad_file_mode:{oct(st.st_mode)}")
          if st.st_uid != os.getuid():
              raise DaemonPidFileError(f"bad_file_owner:{st.st_uid}")
          raw = os.read(fd, 4096)
      finally:
          os.close(fd)
      try:
          data = json.loads(raw.decode("utf-8"))
      except (UnicodeDecodeError, json.JSONDecodeError) as exc:
          raise DaemonPidFileError("malformed_json") from exc
      return PidFileInfo(
          pid=int(data["pid"]),
          boot_id=str(data["boot_id"]),
          started_at=str(data["started_at"]),
          hostname=str(data["hostname"]),
      )


  def is_pid_alive(pid: int) -> bool:
      """Best-effort liveness check via kill(pid, 0).

      Returns True if the process exists and we have permission to
      signal it; False on ProcessLookupError. PermissionError is treated
      as "alive but not ours" — for daemon status that's a "running" answer.
      """
      try:
          os.kill(pid, 0)
      except ProcessLookupError:
          return False
      except PermissionError:
          return True  # exists but owned by another uid
      return True


  def delete_pidfile(path: Path) -> None:
      """Remove the PID file; missing is not an error."""
      try:
          path.unlink()
      except FileNotFoundError:
          pass
  ```

  Run → all pidfile tests passed.

  Commit:

  ```
  git commit -m "feat(cli): daemon PID-file helpers with mode-0600 + open-then-fstat (#174)"
  ```

---

- [ ] **Task E.2 — `alfred daemon start` body.**
  Files: Modify `src/alfred/cli/daemon.py`.

  **Failing test** (`tests/unit/cli/daemon/test_probe_environment_not_set.py`, `test_probe_unsandboxed_env_in_production.py`, `test_daemon_boot_completed_emit.py`, `test_daemon_environment_source_conflict.py`):

  ```python
  # test_probe_environment_not_set.py
  from __future__ import annotations
  import pytest
  from typer.testing import CliRunner
  from alfred.cli.daemon import daemon_app


  def test_environment_not_set_refuses(monkeypatch, tmp_path) -> None:
      monkeypatch.delenv("ALFRED_ENVIRONMENT", raising=False)
      monkeypatch.setattr(
          "alfred.config._environment_loader._DEFAULT_ETC_PATH",
          tmp_path / "absent",
      )
      monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-test")
      runner = CliRunner()
      result = runner.invoke(daemon_app, ["start"])
      assert result.exit_code == 2
      # The operator-facing message routes through t("daemon.boot.environment_not_set")
      assert "ALFRED_ENVIRONMENT" in result.stdout or "environment" in result.stdout.lower()
  ```

  ```python
  # test_probe_unsandboxed_env_in_production.py
  def test_unsandboxed_in_production_refuses(monkeypatch, tmp_path) -> None:
      monkeypatch.setenv("ALFRED_ENVIRONMENT", "production")
      monkeypatch.setenv("ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED", "1")
      monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-test")
      monkeypatch.setattr(
          "alfred.config._environment_loader._DEFAULT_ETC_PATH",
          tmp_path / "absent",
      )
      runner = CliRunner()
      result = runner.invoke(daemon_app, ["start"])
      assert result.exit_code == 2
  ```

  ```python
  # test_daemon_boot_completed_emit.py (sketch)
  # Boot with all probes mocked to pass; assert DAEMON_BOOT_FIELDS row written;
  # PID file present at ~/.run/alfred/daemon.pid; t("daemon.start.success") printed.
  ```

  ```python
  # test_daemon_environment_source_conflict.py
  def test_conflict_emits_audit_and_boots(monkeypatch, tmp_path) -> None:
      monkeypatch.setenv("ALFRED_ENVIRONMENT", "production")
      etc = tmp_path / "environment"
      etc.write_text("development\n", encoding="utf-8")
      monkeypatch.setattr(
          "alfred.config._environment_loader._DEFAULT_ETC_PATH", etc,
      )
      monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-test")
      # Mock the other probes pass + capture audit writer
      # ...
      # Assert DAEMON_BOOT_ENVIRONMENT_SOURCE_CONFLICT_FIELDS row present
      # Assert daemon still boots (Settings.environment == "production")
  ```

  Run → multiple failures (placeholder body).

  **Implementation** (replace the `start` body in `src/alfred/cli/daemon.py`):

  ```python
  import asyncio
  import uuid
  from datetime import datetime, UTC
  from pathlib import Path

  from alfred.audit.audit_row_schemas import (
      DAEMON_BOOT_FIELDS,
      DAEMON_BOOT_FAILED_FIELDS,
      DAEMON_BOOT_ENVIRONMENT_SOURCE_CONFLICT_FIELDS,
  )
  from alfred.cli._daemon_pidfile import default_pidfile_path, write_pidfile
  from alfred.cli._daemon_probes import (
      probe_capability_gate_handshake,
      probe_launcher_policy_resolving,
      probe_snapshot_ref_init,
  )
  from alfred.config._environment_loader import EnvironmentSource


  @daemon_app.command("start")
  def start() -> None:
      """Boot the AlfredOS daemon (spec §3, #174).

      Sequence (core-007 closure):
        1. Load Settings (mandatory environment, dual-source loader).
        2. CLI-layer probes (a) → (b) → (c). Any failure refuses with
           DAEMON_BOOT_FAILED_FIELDS + t() message + exit 2.
        3. Construct Supervisor with state_git_path + the new stub kwargs.
        4. AuditWriter.append_schema(DAEMON_BOOT_FIELDS, ...).
        5. Invoke daemon.boot.completed hookpoint.
        6. Write PID file.
        7. supervisor.start() → asyncio.TaskGroup runs heartbeat +
           proposal dispatch loop until shutdown.
      """
      asyncio.run(_start_async())


  async def _start_async() -> None:
      # Lazy imports — perf-001 discipline; we don't want to pay for
      # the broker + SQLAlchemy + provider graph on alfred --help.
      from alfred.audit.log import AuditWriter
      from alfred.cli._bootstrap import (
          install_identity_factories_for_settings,
          load_settings_or_die,
      )
      from alfred.cli._daemon_pidfile import default_pidfile_path, write_pidfile
      from alfred.security.gate import RealGate
      from alfred.supervisor.core import Supervisor

      try:
          settings = load_settings_or_die()
      except SystemExit:
          raise  # already printed the friendly message

      # The conflict audit (if any) was stashed on the Settings instance by
      # the _resolve_environment validator. Emit it BEFORE the probes so
      # the audit row is present even if a later probe refuses.
      audit_writer = _build_audit_writer(settings)
      load_result = getattr(settings, "_environment_load_result", None)
      if load_result is not None and load_result.conflict:
          await audit_writer.append_schema(
              DAEMON_BOOT_ENVIRONMENT_SOURCE_CONFLICT_FIELDS,
              env_var_value=load_result.value,
              etc_file_value=load_result.conflicting_file_value,
              resolved_value=load_result.value,
              resolved_at=datetime.now(UTC).isoformat(),
          )

      # Refusal 1: unsandboxed env in production. Stronger check than
      # the per-spawn refusal in spec §7.4 — the daemon refuses to even
      # boot if its own env contains the escape hatch and we're in prod.
      if (
          os.environ.get("ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED") == "1"
          and settings.environment == "production"
      ):
          await _refuse_boot(
              audit_writer,
              UnsandboxedEnvInProductionFailure(),
              t("daemon.boot.unsandboxed_env_in_production"),
          )
          raise typer.Exit(code=2)

      # Probe (a): launcher policy-resolving stub.
      result_a = await probe_launcher_policy_resolving()
      if result_a is not None:
          await _refuse_boot(
              audit_writer, result_a, t("daemon.boot.launcher_not_policy_resolving"),
          )
          raise typer.Exit(code=2)

      # Probe (b): snapshot-ref init. Returns the stub ref on pass.
      result_b, snapshot_ref = await probe_snapshot_ref_init()
      if result_b is not None:
          await _refuse_boot(
              audit_writer, result_b, t("daemon.boot.snapshot_ref_init_failed"),
          )
          raise typer.Exit(code=2)

      # Probe (c): capability-gate handshake. Build RealGate against the
      # configured Postgres + state.git path.
      gate = _build_real_gate(settings)
      result_c = await probe_capability_gate_handshake(gate=gate)
      if result_c is not None:
          await _refuse_boot(
              audit_writer, result_c, t("daemon.boot.capability_gate_handshake_failed"),
          )
          raise typer.Exit(code=2)

      # All probes passed. Construct Supervisor + emit completion.
      boot_id = str(uuid.uuid4())
      started_at = datetime.now(UTC)
      state_git_head_sha = _read_state_git_head_sha(settings.state_git_path)
      policies_snapshot_hash = snapshot_ref.snapshot_hash()

      supervisor = Supervisor(
          session_scope=_build_session_scope(settings),
          gate=gate,
          audit=audit_writer,
          state_git_path=settings.state_git_path,
          proposal_dispatch_interval_s=settings.proposal_dispatch_interval_s,
          policies_ref=snapshot_ref,
          operator_session_resolver=_StubOperatorResolver(),  # real in PR-S4-5
      )

      await audit_writer.append_schema(
          DAEMON_BOOT_FIELDS,
          boot_id=boot_id,
          started_at=started_at.isoformat(),
          state_git_head_sha=state_git_head_sha,
          slice_version="4",
          policies_snapshot_hash=policies_snapshot_hash,
      )

      # Invoke daemon.boot.completed hookpoint (no in-tree subscribers yet).
      from alfred.hooks.invoke import invoke
      await invoke(
          "daemon.boot.completed",
          stage="post",
          ctx={"boot_id": boot_id, "state_git_head_sha": state_git_head_sha},
      )

      # Write PID file.
      write_pidfile(
          path=default_pidfile_path(),
          pid=os.getpid(),
          boot_id=boot_id,
          started_at=started_at.isoformat(),
      )

      typer.echo(t("daemon.start.success",
                   boot_id=boot_id,
                   state_git_head_sha=state_git_head_sha))

      # Open the TaskGroup. Blocks until shutdown via daemon stop.
      await supervisor.start()
      try:
          # Park here until something signals shutdown. PR-S4-1 wires a
          # SIGTERM handler that calls supervisor.stop().
          await _wait_for_shutdown(supervisor)
      finally:
          await supervisor.stop()
          from alfred.cli._daemon_pidfile import delete_pidfile
          delete_pidfile(default_pidfile_path())
  ```

  Supporting helpers in the same module (`_refuse_boot`, `_build_audit_writer`, `_build_session_scope`, `_build_real_gate`, `_read_state_git_head_sha`, `_wait_for_shutdown`, `_StubOperatorResolver`) follow standard Slice-3 patterns (lifted from `_bootstrap.py`).

  Run → tests pass.

  Commit:

  ```
  git commit -m "feat(cli): alfred daemon start with pre-TaskGroup probes (#174)"
  ```

---

- [ ] **Task E.3 — `alfred daemon stop` body.**
  Files: Modify `src/alfred/cli/daemon.py`.

  **Failing test** (`tests/unit/cli/daemon/test_daemon_stop_signals_supervisor.py`):

  ```python
  """alfred daemon stop reads PID file, sends SIGTERM."""
  from __future__ import annotations
  import os
  import signal
  from pathlib import Path
  from unittest.mock import patch
  import pytest
  from typer.testing import CliRunner
  from alfred.cli.daemon import daemon_app


  def test_stop_sends_sigterm_to_pid(tmp_path: Path, monkeypatch) -> None:
      pidfile = tmp_path / "daemon.pid"
      from alfred.cli._daemon_pidfile import write_pidfile
      write_pidfile(pidfile, pid=12345, boot_id="b", started_at="now")
      monkeypatch.setattr(
          "alfred.cli._daemon_pidfile.default_pidfile_path", lambda: pidfile,
      )
      with patch("os.kill") as mock_kill:
          runner = CliRunner()
          result = runner.invoke(daemon_app, ["stop"])
          assert result.exit_code == 0
          mock_kill.assert_called_once_with(12345, signal.SIGTERM)


  def test_stop_no_pidfile_exits_zero(tmp_path: Path, monkeypatch) -> None:
      pidfile = tmp_path / "no-pid"
      monkeypatch.setattr(
          "alfred.cli._daemon_pidfile.default_pidfile_path", lambda: pidfile,
      )
      runner = CliRunner()
      result = runner.invoke(daemon_app, ["stop"])
      # Slice-4 spec §3.1 alfred daemon stop is operator-safe — no
      # daemon to stop is success, not error.
      assert result.exit_code == 0
  ```

  Run → 2 failures.

  **Implementation:**

  ```python
  @daemon_app.command("stop")
  def stop() -> None:
      """Stop the AlfredOS daemon by signalling SIGTERM to the PID file's owner."""
      from alfred.cli._daemon_pidfile import (
          DaemonPidFileError, default_pidfile_path, is_pid_alive, load_pidfile,
      )
      path = default_pidfile_path()
      try:
          info = load_pidfile(path)
      except DaemonPidFileError:
          typer.echo(t("daemon.stop.no_daemon"))
          return  # exit 0
      if not is_pid_alive(info.pid):
          typer.echo(t("daemon.stop.stale_pidfile"))
          return  # exit 0; stop is a no-op
      try:
          os.kill(info.pid, signal.SIGTERM)
      except ProcessLookupError:
          typer.echo(t("daemon.stop.stale_pidfile"))
          return
      typer.echo(t("daemon.stop.success", pid=info.pid))
  ```

  Run → 2 passed. Commit:

  ```
  git commit -m "feat(cli): alfred daemon stop signals SIGTERM via PID file (#174)"
  ```

---

- [ ] **Task E.4 — `alfred daemon status` body.**
  Files: Modify `src/alfred/cli/daemon.py`.

  **Failing test** (`tests/unit/cli/daemon/test_daemon_status_renders.py` and `test_daemon_status_no_daemon.py`):

  ```python
  # test_daemon_status_renders.py — sketch
  # Write a PID file pointing at our own pid; pretend audit_writer has a
  # last-boot row; assert status output contains pid + boot_id + slice_version.

  # test_daemon_status_no_daemon.py
  def test_status_no_pidfile(tmp_path, monkeypatch) -> None:
      monkeypatch.setattr(
          "alfred.cli._daemon_pidfile.default_pidfile_path",
          lambda: tmp_path / "no-pid",
      )
      runner = CliRunner()
      result = runner.invoke(daemon_app, ["status"])
      assert result.exit_code == 0
      # Status is read-only — no daemon is not an error
      assert "not running" in result.stdout.lower() or t("daemon.status.not_running") in result.stdout
  ```

  Run → failures.

  **Implementation:**

  ```python
  @daemon_app.command("status")
  def status() -> None:
      """Render daemon boot subset: PID, uptime, boot_id, slice_version, snapshot hash.

      The `alfred status` command is the *general health* overview; this
      `alfred daemon status` is the *boot-process subset*. See spec §3.1
      devex-004 closure. Their --help text cross-references.
      """
      from alfred.cli._daemon_pidfile import (
          DaemonPidFileError, default_pidfile_path, is_pid_alive, load_pidfile,
      )
      path = default_pidfile_path()
      try:
          info = load_pidfile(path)
      except DaemonPidFileError:
          typer.echo(t("daemon.status.not_running"))
          return
      alive = is_pid_alive(info.pid)
      if not alive:
          typer.echo(t("daemon.status.stale_pidfile", pid=info.pid))
          return
      typer.echo(
          t("daemon.status.running",
            pid=info.pid,
            boot_id=info.boot_id,
            started_at=info.started_at)
      )
  ```

  Run → tests pass. Commit:

  ```
  git commit -m "feat(cli): alfred daemon status renders PID + boot info (#174)"
  ```

---

### Component F — `main.py` registration + i18n catalog entries

- [ ] **Task F.1 — Register `daemon_app` in `main.py`.**
  Files: Modify `src/alfred/cli/main.py`.

  **Failing test** (`tests/unit/cli/daemon/test_daemon_app_registration.py`):

  ```python
  """Verify alfred --help lists daemon, and alfred daemon --help lists subcommands."""
  from __future__ import annotations
  from typer.testing import CliRunner
  from alfred.cli.main import app


  def test_daemon_appears_in_root_help() -> None:
      runner = CliRunner()
      result = runner.invoke(app, ["--help"])
      assert result.exit_code == 0
      assert "daemon" in result.stdout


  def test_daemon_subcommands_listed() -> None:
      runner = CliRunner()
      result = runner.invoke(app, ["daemon", "--help"])
      assert result.exit_code == 0
      assert "start" in result.stdout
      assert "stop" in result.stdout
      assert "status" in result.stdout
  ```

  Run → 2 failures.

  **Implementation** (add to `src/alfred/cli/main.py` after the other `add_typer` calls):

  ```python
  from alfred.cli.daemon import daemon_app

  app.add_typer(daemon_app, name="daemon")
  ```

  Run → 2 passed. Commit:

  ```
  git commit -m "feat(cli): register daemon_app in alfred root CLI (#174)"
  ```

---

- [ ] **Task F.2 — i18n catalog entries.**
  Files: Modify `locale/en/LC_MESSAGES/alfred.po`.

  Add msgid entries for every key this PR introduces. CLAUDE.md i18n hard rule 1 — operator-facing strings go through `t()`.

  Keys to land:

  ```
  daemon.help.root
  daemon.help.start
  daemon.help.stop
  daemon.help.status
  daemon.start.success
  daemon.stop.success
  daemon.stop.no_daemon
  daemon.stop.stale_pidfile
  daemon.status.not_running
  daemon.status.running
  daemon.status.stale_pidfile
  daemon.boot.environment_not_set
  daemon.boot.unsandboxed_env_in_production
  daemon.boot.launcher_not_policy_resolving
  daemon.boot.snapshot_ref_init_failed
  daemon.boot.capability_gate_handshake_failed
  ```

  Sample msgstr bodies (operator-facing, actionable):

  ```
  msgid "daemon.boot.environment_not_set"
  msgstr "ALFRED_ENVIRONMENT is not set. Set it to `development`, `production`, or `test` before starting the daemon. You can also write the value into /etc/alfred/environment as a fallback. See docs/runbooks/slice-4-graduation.md."

  msgid "daemon.boot.unsandboxed_env_in_production"
  msgstr "ALFRED_PLUGIN_LAUNCHER_UNSANDBOXED=1 is set, but Settings.environment=\"production\". The dev escape hatch is refused in production. Unset the env var or set ALFRED_ENVIRONMENT=development."

  msgid "daemon.boot.launcher_not_policy_resolving"
  msgstr "bin/alfred-plugin-launcher is missing policy-resolving behaviour. Update to AlfredOS >= Slice 4 PR-S4-6."

  msgid "daemon.boot.snapshot_ref_init_failed"
  msgstr "Failed to parse config/policies.yaml at boot. Validate the file with `python -c 'import yaml; yaml.safe_load(open(\"config/policies.yaml\"))'`."

  msgid "daemon.boot.capability_gate_handshake_failed"
  msgstr "Capability gate cannot reach its backing store (Postgres or state.git). Verify `docker compose ps` shows alfred-pg healthy and that ALFRED_STATE_GIT_PATH exists."
  ```

  **Verification:**

  ```
  uv run pybabel extract -F babel.cfg -o locale/messages.pot src/
  uv run pybabel update -i locale/messages.pot -d locale
  uv run pybabel compile --check -d locale
  ```

  Commit:

  ```
  git commit -m "feat(i18n): daemon.boot.* refusal messages + help strings (#174)"
  ```

---

### Component G — Smoke test

The release-critical end-to-end: docker compose stack up, daemon boots, state.git mutated, dispatch loop observed firing.

- [ ] **Task G.1 — Smoke test.**
  Files: Create `tests/smoke/test_slice4_daemon_dispatch.py`.

  This is the smoke gate spec §3 promises: "boot daemon, mutate state.git, observe dispatch."

  ```python
  """Slice-4 smoke: daemon boot + state.git dispatch loop.

  Closes the #174 acceptance criterion: in deployed AlfredOS, the
  merged-proposal dispatch loop must actually run. This test boots the
  full docker compose stack, runs `alfred daemon start`, queues a
  proposal blob into state.git, and asserts the dispatch loop fires
  within proposal_dispatch_interval_s + 5s grace.

  Marked @pytest.mark.smoke so it only runs when an operator opts in via
  `uv run pytest tests/smoke -m smoke`.
  """
  from __future__ import annotations
  import os
  import subprocess
  import time
  from pathlib import Path
  import pytest


  @pytest.mark.smoke
  @pytest.mark.skipif(
      not Path("docker-compose.yaml").exists(),
      reason="smoke requires docker-compose.yaml present",
  )
  def test_daemon_boots_and_dispatches() -> None:
      """End-to-end: alfred daemon start → mutate state.git → dispatch fires."""
      # 1. docker compose up alfred-pg (Postgres + state.git initdb).
      subprocess.run(
          ["docker", "compose", "up", "-d", "alfred-pg"],
          check=True,
      )
      try:
          # 2. Wait for Postgres ready.
          _wait_for_postgres_ready(timeout_s=30.0)

          # 3. Start daemon in background.
          env = os.environ.copy()
          env["ALFRED_ENVIRONMENT"] = "test"
          env["ALFRED_PROPOSAL_DISPATCH_INTERVAL_S"] = "2"  # snappy test
          daemon = subprocess.Popen(
              ["uv", "run", "alfred", "daemon", "start"],
              env=env,
          )
          try:
              # 4. Wait for daemon.boot.completed audit row.
              _wait_for_boot_completed(timeout_s=10.0)

              # 5. Queue a no-op proposal blob via the operator CLI.
              subprocess.run(
                  ["uv", "run", "alfred", "supervisor", "reset",
                   "noop-component", "--confirm"],
                  env=env, check=True,
              )

              # 6. Wait for the dispatch loop to pick it up. The loop
              # interval is 2s; allow 5s grace.
              _wait_for_proposal_dispatched(timeout_s=10.0)
          finally:
              subprocess.run(
                  ["uv", "run", "alfred", "daemon", "stop"],
                  env=env, check=False,
              )
              daemon.wait(timeout=5.0)
      finally:
          subprocess.run(
              ["docker", "compose", "down"],
              check=False,
          )


  def _wait_for_postgres_ready(timeout_s: float) -> None:
      # Use docker compose exec alfred-pg pg_isready, ~1s cadence.
      deadline = time.monotonic() + timeout_s
      while time.monotonic() < deadline:
          r = subprocess.run(
              ["docker", "compose", "exec", "-T", "alfred-pg",
               "pg_isready", "-U", "alfred"],
              capture_output=True,
          )
          if r.returncode == 0:
              return
          time.sleep(1.0)
      raise TimeoutError("alfred-pg never became ready")


  def _wait_for_boot_completed(timeout_s: float) -> None:
      # Poll audit_log for a row with row_kind='daemon.boot.completed'.
      # ... helper using SQLAlchemy + tiny session_scope to query.
      ...


  def _wait_for_proposal_dispatched(timeout_s: float) -> None:
      # Poll processed_proposals (Slice-3 ADR-0021 table) for a row
      # corresponding to the queued blob.
      ...
  ```

  This test is gated by docker availability + a pytest `smoke` mark. The full helper bodies (`_wait_for_boot_completed`, `_wait_for_proposal_dispatched`) lift from Slice-3 patterns in `tests/integration/state/`.

  Run (only when docker is available): `uv run pytest tests/smoke/test_slice4_daemon_dispatch.py -m smoke -v`.

  Commit:

  ```
  git commit -m "test(smoke): alfred daemon start → state.git dispatch end-to-end (#174)"
  ```

---

### Component H — Quality gates

- [ ] **Task H.1 — `make check` clean.**

  ```
  make check
  ```

  Expect: ruff lint + format + mypy strict + pyright + unit-suite all green.

  If any of the new modules fail mypy strict, fix in-place. Common Slice-4 footguns:

  - `Settings.environment` field needs `Literal["development", "production", "test"]` exactly — `str` widens it.
  - `DaemonBootFailure` discriminated union needs `Annotated[..., Field(discriminator="failure_reason")]`.
  - Each probe's return type is `DaemonBootFailure | None` (not `Optional[DaemonBootFailure]` — PEP 604).

- [ ] **Task H.2 — Adversarial suite clean.**

  This PR doesn't touch `src/alfred/security/`, but it does extend `src/alfred/hooks/` (consuming new fields) and adds a new boot path. Per CLAUDE.md hard rule:

  ```
  uv run pytest tests/adversarial -q
  ```

  Verify all green.

- [ ] **Task H.3 — 100% line + branch coverage on the daemon files.**

  Per CLAUDE.md tests rule:

  ```
  uv run pytest tests/unit/cli/daemon \
    --cov=src/alfred/cli/daemon.py \
    --cov=src/alfred/cli/_daemon_probes.py \
    --cov=src/alfred/cli/_daemon_pidfile.py \
    --cov=src/alfred/config/_environment_loader.py \
    --cov=src/alfred/supervisor/protocols.py \
    --cov-branch \
    --cov-fail-under=100
  ```

  Any miss is a release blocker (the daemon boot path is a security boundary — the operator's first run-time security signal).

- [ ] **Task H.4 — `make docs-check`.**

  Validate any new docs links resolve. PR-S4-1 doesn't touch `docs/` directly (the runbook lands in PR-S4-11), so this should be a no-op pass.

- [ ] **Task H.5 — `pybabel compile --check`.**

  ```
  uv run pybabel compile --check -d locale
  ```

  Catalog drift fails the build per CLAUDE.md i18n hard rule 4.

---

## §6 PR description checklist

- [ ] Title: `feat(daemon): alfred daemon start/stop/status + production dispatch wiring (#174)`
- [ ] Body references **#174**.
- [ ] Body lists every Slice-4 spec section closed: §3.1, §3.2, §3.4, §7.3 (partial — full §7.3 closure spans PR-S4-1 + PR-S4-6 + PR-S4-7).
- [ ] Body lists the `Settings.environment` and `Settings.state_git_path` field additions as part of the operator-visible config surface.
- [ ] Body lists the three new hookpoints: `daemon.boot.completed`, `daemon.boot.failed`, `proposal.dispatch.failed`.
- [ ] Body lists the new `DaemonBootFailure` discriminated union and its five `Literal` failure reasons.
- [ ] Body confirms PR-S4-3 has merged (HookpointMeta.carrier_tier dependency).
- [ ] Body confirms PR-S4-0a has merged (DAEMON_BOOT_* constants dependency).
- [ ] Body confirms PR-S4-0b has merged (i18n catalog skeleton + any migrations).
- [ ] PR description includes the 5-line "what / why / how to verify" summary at top.
- [ ] PR description includes the post-merge promotion plan: add `daemon-boot-smoke` (smoke test) to the required-status-checks list, per index §4.

---

## §7 Out-of-scope (explicit deferrals)

These belong to later Slice-4 PRs; this PR does NOT touch them.

| Surface | Owning PR | Why deferred |
|---|---|---|
| `OutboundDlp.scan` into `processed_proposals.failure_detail` | PR-S4-2 | Different rewrite (DLP threading); separate review surface |
| Real `PolicyWatcher` + `PoliciesV1` Pydantic model | PR-S4-4 | Hot-reload runtime is its own design; this PR ships a parse-once stub |
| Real `_resolve_operator` + `OperatorSession` model | PR-S4-5 | Session-file + Postgres binding is its own design; this PR ships a no-op stub |
| Real `bin/alfred-plugin-launcher.sh --self-test` | PR-S4-6 | Launcher policy-resolution is its own bash rewrite; this PR's probe is a stub that always passes (arch-001 closure) |
| Sandbox policy bytes (Linux bwrap / macOS sandbox-exec / Windows stub) | PR-S4-7 | Policy authoring is separate |
| Comms-MCP wire contract, `process_inbound_message`, `BurstLimiter` | PR-S4-8 | Comms rewrite is its own track |
| Discord adapter as MCP plugin | PR-S4-9 | Comms rewrite track |
| TUI adapter as MCP plugin + `src/alfred/comms/` deletion | PR-S4-10 | Comms rewrite track + atomic flag-day delete |
| `alfred chat` rewire to launcher-spawn | PR-S4-10 | TUI rewrite track |
| Subsystems doc updates + `docs/runbooks/slice-4-graduation.md` | PR-S4-11 | Graduation PR consolidates all subsystem doc deltas |
| ADR-0015 / ADR-0016 Proposed → Accepted flips | PR-S4-11 | Graduation only |

---

## §8 Risk register

| Risk | Severity | Mitigation |
|---|---|---|
| `Settings.environment` mandatory breaks every developer's local `.env` | High | PR-S4-0b's `bin/alfred-setup.sh` update adds `ALFRED_ENVIRONMENT=development` to `.env.example`; runbook calls this out; pre-existing `.env` files get a one-line append by the setup script |
| Probe orchestration in CLI rather than `Supervisor.start()` creates two boot paths (CLI + legacy `alfred chat`) | Medium | Document the probes-CLI-only contract in `docs/subsystems/supervisor.md`; PR-S4-10's `alfred chat` rewrite will go through the same probes via launcher spawn |
| `_StubPoliciesSnapshotRef` returning a parsed dict will break PR-S4-4 consumers that expect `PoliciesV1` | Medium | The Protocol explicitly types `current()` as `object` to widen — PR-S4-4 narrows the Protocol when it ships the real impl; the dispatch loop doesn't dereference `policies_ref.current()` in this PR |
| PID file at `~/.run/alfred/daemon.pid` (XDG-ish) conflicts with operators who run multiple daemons | Low | `Settings.daemon_pidfile_path` deferred to Slice-5 backlog; single-daemon-per-user is the Slice-4 baseline; document in runbook |
| `daemon.boot.environment_source_conflict` audit row written BEFORE probes run could leave a row with no completion if a later probe refuses | Low | Acceptable — the conflict row is informational; the absence of a matching `DAEMON_BOOT_FIELDS` row + presence of `DAEMON_BOOT_FAILED_FIELDS` paints the full picture; forensics-friendly |
| `os.kill(pid, 0)` lies on macOS for foreign-uid processes (returns success even on dead-but-zombie) | Low | Acceptable for the Slice-4 baseline; the smoke test pins the happy path; PR-S4-11 runbook documents the macOS edge |
| Smoke test flakes on slow CI containers (docker compose up takes >30s) | Low | `_wait_for_postgres_ready(timeout_s=30.0)` extendable; promote the smoke gate to required only after a week of stability per ops discipline |
| `register_hookpoint` calls at module load force all three hookpoints visible to test isolation | Low | Slice-3 already established the "register at module load is idempotent" pattern (PR-S3-3b Task 20); this PR follows the precedent |

---

## §9 Verification gate (fabricated-surfaces audit)

Per index §8 backlog "Fabricated-surfaces watchlist for writing-plans," every Slice-3 surface this plan cites was grep-verified at authoring time. The result is recorded here so future plans inherit the discipline.

| Cited surface | Status | Evidence |
|---|---|---|
| `Supervisor.__init__` kwargs | **Verified** | `src/alfred/supervisor/core.py:177-185` — `session_scope, gate, audit, state_git_path, proposal_dispatch_interval_s` confirmed |
| `Supervisor.start()` TaskGroup-first shape | **Verified** | `src/alfred/supervisor/core.py:227-251` — `_run()` opens `async with asyncio.TaskGroup() as tg:` with no pre-flight |
| `Supervisor._proposal_dispatch_loop` (#171 dispatch loop) | **Verified** | `src/alfred/supervisor/core.py:317` |
| `Settings` class | **Verified** | `src/alfred/config/settings.py` — pydantic-settings v2 BaseSettings |
| `Settings.proposal_dispatch_interval_s` | **Verified** | `src/alfred/config/settings.py:85` (default 30, gt=0) |
| `Settings.state_git_path` | **Does NOT exist; new in this PR** | Slice-3 hardcodes `Path("/var/lib/alfred/state.git")` in `src/alfred/cli/_state_git.py:400` and similar call sites |
| `Settings.environment` | **Does NOT exist; new in this PR** | grep confirms absence |
| `DAEMON_BOOT_FIELDS` / `DAEMON_BOOT_FAILED_FIELDS` / `DAEMON_BOOT_ENVIRONMENT_SOURCE_CONFLICT_FIELDS` | **Lands in PR-S4-0a** | Slice-4 index §3 confirms; this PR imports |
| `t()` function | **Verified** | `src/alfred/i18n/translator.py:109 def t(key: str, /, **vars: object) -> str` |
| i18n catalog path | **Verified** | `locale/en/LC_MESSAGES/alfred.po` exists |
| `register_hookpoint(...)` shape | **Verified** | `src/alfred/hooks/registry.py:539` |
| `HookpointMeta` fields (`name`, `subscribable_tiers`, `refusable_tiers`, `fail_closed`) | **Verified** | `src/alfred/hooks/registry.py:176-229` |
| `HookpointMeta.carrier_tier` | **Lands in PR-S4-3** | Slice-4 index §3 confirms; this PR depends on it |
| `HookpointMeta.allow_error_substitution` | **Lands in PR-S4-3** | Same |
| `SYSTEM_ONLY_TIERS` constant | **Verified** | Slice-3 hooks module exports it |
| `AuditWriter.append_schema(...)` shape | **Verified** | `src/alfred/audit/log.py` Slice-3 surface |
| `RealGate.is_backing_store_available()` | **Verified** | Slice-3 capability-gate surface |
| `app.add_typer(name="...")` pattern | **Verified** | `src/alfred/cli/main.py:86-110` — model for this PR's `daemon_app` registration |
| `typer.Exit(code=...)` for refusal-exit | **Verified** | Typer 0.9+ standard surface |

The single new Slice-3 surface this plan **does** invent on top of (`_StubPoliciesSnapshotRef`, `_StubOperatorResolver`) is explicitly marked as PR-S4-1-stub-only, with PR-S4-4 / PR-S4-5 noted as the replacement owner.

---

## §10 Acceptance criteria

This PR is mergeable when:

1. [ ] All 18 new unit-test files green; full unit suite green.
2. [ ] Smoke test green when docker compose is available (CI runner topology: ubuntu-latest merge-blocking with docker-in-docker).
3. [ ] `make check` clean: ruff, format, mypy strict, pyright.
4. [ ] `uv run pytest tests/adversarial -q` clean.
5. [ ] 100% line + branch coverage on `src/alfred/cli/daemon.py`, `src/alfred/cli/_daemon_probes.py`, `src/alfred/cli/_daemon_pidfile.py`, `src/alfred/config/_environment_loader.py`, `src/alfred/supervisor/protocols.py`.
6. [ ] `pybabel compile --check -d locale` clean.
7. [ ] `alfred daemon --help` lists `start`, `stop`, `status`. `alfred --help` lists `daemon`.
8. [ ] Issue #174 closed by this PR.
9. [ ] PR-S4-0a, PR-S4-0b, PR-S4-3 confirmed merged before this PR opens for review.
10. [ ] `daemon-boot-smoke` (smoke-test name) added to the required-status-checks manifest in the same PR.
11. [ ] PR description carries the 5-line summary, references **#174**, and lists the Slice-4 spec sections this PR closes (§3.1, §3.2, §3.4, §7.3 partial).
12. [ ] Conventional-commit `#174` reference gate passes (per index §5 quality gates item 5).
13. [ ] Markdown lint clean for any `.md` files this PR touches.

---

> End of plan. Implementer dispatches Component A → B → C → D → E → F → G → H sequentially; the dependency graph within this PR is linear.
