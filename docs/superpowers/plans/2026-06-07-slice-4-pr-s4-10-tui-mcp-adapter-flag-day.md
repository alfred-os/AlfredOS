# Slice 4 — PR S4-10: TUI MCP Adapter + `src/alfred/comms/` Flag-Day — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `plugins/alfred_tui/` as an MCP comms-adapter plugin (Textual rendering layer preserved verbatim from `src/alfred/comms/tui/textual/`), rewire `alfred chat` at `src/alfred/cli/main.py` to spawn the plugin via `bin/alfred-plugin-launcher.sh` (daemon-required error + 2.5s handshake probe timeout), atomically migrate the five known consumers of the in-process `CommsAdapter` Protocol, delete `src/alfred/comms/` in one shot (no path collision with `src/alfred/comms_mcp/`), narrow the ADR-0009 caveat (removing the "for new adapters" qualifier — NOT a status flip), redirect `bin/alfred-setup.ps1` Windows operators to WSL2, and ship `tests/smoke/test_slice4_graduation.py` as the compose-up + login + chat round-trip merge-blocking gate.

**Architecture:** This is the final pre-graduation PR — the slice closes its irreversible deletion here. The TUI adapter inverts the Slice-1/2 in-process Protocol polarity: instead of the orchestrator calling `adapter.run()` in-process, `alfred chat` spawns a subprocess via `bin/alfred-plugin-launcher.sh`, the subprocess serves the comms-MCP wire contract (ADR-0024) over stdio, and the daemon's `AlfredPluginSession` consumes `inbound.message` notifications and dispatches `outbound.message` requests. Because the wire-format module lives at `src/alfred/comms_mcp/protocol.py` (PR-S4-8) and never at `src/alfred/comms/protocol.py`, the `src/alfred/comms/` deletion is unambiguous — no path collision, no "same path, different contents" git diff. The five known consumers migrate atomically in the same PR; a pre-flight grep on `main` immediately before the deletion absorbs any new consumers added after spec authoring. ADR-0009 was already marked "Superseded by ADR-0016 (for new adapters)" at PR-S3-0a; this PR removes the "for new adapters" qualifier (now that the in-process adapters are also gone) but does NOT flip the status header — that's docs-001 closure in the spec.

**Tech Stack:** Python 3.12+; Textual (preserved at `plugins/alfred_tui/textual/` verbatim from `src/alfred/comms/tui/textual/`); `model_context_protocol` SDK (stdio server side); `mcp.server.stdio` for the plugin's wire surface; `bin/alfred-plugin-launcher.sh` (PR-S4-6 contract); `AlfredPluginSession` + `process_inbound_message` (PR-S4-8); `OperatorSession` + `_resolve_operator` (PR-S4-5); `Supervisor.request_plugin_restart` (PR-S4-8); pytest + pytest-asyncio + testcontainers; AST-walk guards in `tests/unit/comms/`; `uv run pybabel compile --check` for the i18n catalog updates; `make docs-check` for the ADR-0009 caveat narrowing.

**Depends on:** PR-S4-0a (merged — ADR-0024 wire-contract module stubs + `payload_schema.py` Literal additions + audit row constants `COMMS_ADDRESSING_DRIFT_FIELDS`, `COMMS_INBOUND_T3_PROMOTION_FIELDS`, `COMMS_BINDING_REQUESTED_FIELDS`, `COMMS_HANDLER_FAILED_FIELDS`); PR-S4-0b (merged — Alembic 0011–0014, `audit.hash_pepper` bootstrap); PR-S4-3 (merged — recoverable-carrier semantic, `HookpointMeta.allow_error_substitution`); PR-S4-5 (merged — `alfred login` / `alfred logout` / `alfred whoami` + `_resolve_operator` helper); PR-S4-6 (merged — `bin/alfred-plugin-launcher.sh` policy-resolution rewrite, `sandbox.kind` manifest block); PR-S4-8 (merged — host-side `process_inbound_message`, `AlfredPluginSession` notification dispatcher, `REQUIRED_CLASSIFIERS_BY_KIND` + `BODY_FIELD_BY_KIND`, `BurstLimiter` per-`(user_id, persona)`); PR-S4-9 (**must merge first** — `plugins/alfred_discord/` ships, `DiscordSubPayloadClassifier`, `OutboundQueue.pause()` rate-limit honour, idempotency-keyed outbound). PR-S4-10 is the closer for the comms-MCP track before PR-S4-11 graduation per the §2 dependency table in `docs/superpowers/plans/2026-06-07-slice-4-index.md`.

**Blocks:** PR-S4-11 (Slice-4 graduation — `docs/subsystems/comms.md` cannot be authoritative until the in-process Protocol is gone; `tests/smoke/test_slice4_graduation.py` is consumed by graduation; ADR-0015 + ADR-0016 status flip Proposed → Accepted needs the comms-MCP rewrite landed).

---

## §0 Pre-tasks

Before starting Task 1, the implementer **creates a GitHub tracking issue** for PR-S4-10 (or uses the Slice-4 epic issue created in PR-S4-0a) and substitutes the real issue number for every `#TBD-s4-10` token in the commit messages below. The placeholder token must not land in committed history.

The implementer also **runs the pre-flight grep on `main`** (Task 0a below) to capture any consumer of `src/alfred/comms/` added since spec authoring. The output is the canonical "what must migrate before the deletion lands" worksheet; new consumers join Task 4's migration list before Task 5 (the atomic delete) begins.

**PR #205 round-2 review closures** (load-bearing corrections — apply at implementation time):

1. **comms-1 + arch-1 HIGH (TUI PTY hand-off)**: `alfred chat` spawns the TUI plugin with `subprocess.Popen(launcher_cmd, stdin=0, stdout=1, stderr=2)` — direct fd-inheritance of the CLI's PTY, NOT `asyncio.subprocess.PIPE`. The MCP wire uses fd 4/5 (separate pipe pair created via `os.pipe()` and passed to the launcher's bash script as `--mcp-fd-pair 4,5`; bwrap inherits the open, non-CLOEXEC fds 4/5 into the sandbox by DEFAULT — NO bwrap fd flag, exactly as for fd 3 per PR-S4-6 / #218 / ADR-0015; `--sync-fd` is bwrap's internal sync fd and must NOT be used, it would consume the descriptor). The plugin reads MCP frames from fd 4 and writes to fd 5; keystrokes go through stdin (fd 0 inherited); RichLog renders to stdout (fd 1 inherited). After the 2.5s probe succeeds, the CLI EXECs into a long-running `await proc.wait()` with no further IO multiplexing — the plugin owns the TTY. Plan task 4b is REWRITTEN per this model. New `tests/integration/test_alfred_chat_pty_inheritance.py` asserts the Textual plugin can read interactive input from a pty fixture.

2. **comms-2 HIGH (true atomic flag-day)**: §2 sequencing is RESTRUCTURED to a single squash-commit pattern: Task 4 (migrate consumers) + Task 5 (delete `src/alfred/comms/`) are committed AS ONE squash via `git rebase -i` before push. The AST guard `tests/unit/comms/test_no_alfred_comms_imports.py` runs on EVERY commit — there is NEVER a window where `src/alfred/comms/` exists but is unreachable. The xfail-pattern is dropped; the AST guard ships fail-closed from the squash-commit onwards. "Atomic flag-day" is now structurally enforced, not narratively asserted.

3. **arch-2 HIGH (PR-S4-1 daemon-boot integration)**: `alfred chat` MUST verify daemon presence BEFORE launching the TUI plugin. The verification path: (a) read `ALFRED_DAEMON_SOCKET` env var (set by `alfred daemon start`); (b) `os.path.exists(daemon_socket_path)` check; (c) `socket.connect(daemon_socket_path)` test connection with 500ms timeout; (d) send `{"method": "daemon.alive"}` and await `{"alive": true}` response. On any failure: refuse `alfred chat` with `t("chat.refused.daemon_not_running", socket=daemon_socket_path)` and exit code 4 (new, NOT 3). The 2.5s launcher probe is now a sub-step that fires ONLY after daemon presence is confirmed. New `tests/integration/test_alfred_chat_requires_daemon.py` plants a missing daemon and asserts the exit code + message.

4. **devex-1 HIGH (logged-out operator on healthy daemon)**: NEW refusal mode `chat.refused.operator_session_required` with `t()` body: `"You must log in to use \`alfred chat\`. Run: alfred login"`. Triggered when`OperatorSessionResolver.resolve_or_none()` returns None (no session file, expired session, or revoked session). Exit code 5 (new). Distinct from `chat.refused.daemon_not_running`. The CLI checks operator-session presence BEFORE the daemon-socket check (cheaper, and the daemon-socket check requires the operator's audit-row attribution anyway).

5. **devex-2 + comms-4 HIGH (launcher-probe error disambiguation)**: the launcher probe returns a typed `LauncherProbeOutcome` discriminated union with 5 variants: `LauncherSucceeded`, `LauncherMissingBinary` (returncode 127), `LauncherManifestInvalid` (manifest_reader stderr matches), `LauncherSandboxRefused` (bwrap returncode 1 + specific stderr), `LauncherProbeTimeout` (2.5s elapsed with no exit). Each variant maps to a distinct `t()` key:
   - `chat.refused.launcher_missing_binary` (exit 6) — "Plugin launcher not found at /usr/local/bin/alfred-plugin-launcher.sh. Reinstall: `alfred-setup.sh`."
   - `chat.refused.launcher_manifest_invalid` (exit 7) — "TUI plugin manifest at {path} is malformed: {reason}. Check `alfred plugin doctor`."
   - `chat.refused.launcher_sandbox_refused` (exit 8) — "Sandbox refused launch: {reason}. Check `alfred status --sandbox`."
   - `chat.refused.launcher_probe_timeout` (exit 9) — "Plugin did not respond within 2.5s. Try `--no-probe-timeout` or check daemon load."
   The `asyncio.wait_for() + indefinite re-await` pattern is REPLACED with a callback that the launcher's bash script invokes on initialization complete (`echo "ALFRED_LAUNCHER_READY"` on fd 5; the CLI awaits that token with 2.5s timeout). No wall-clock heuristic ambiguity.

6. **devex-3 MEDIUM (exit code disambiguation)**: exit codes documented in spec §8.7 + this plan's §7:
   - 0: success
   - 1: usage error (argparse)
   - 2: argparse fatal
   - 3: REMOVED (was overloaded) — exit code 3 is now unused; legacy script consumers that test `== 3` get a clear migration path (exit 3 never fires from `alfred chat`)
   - 4-9: distinct refusal modes per closure 3, 4, 5 above
   - New `alfred chat --explain-exit-codes` flag prints the full table.

7. **comms-3 MEDIUM (adapter_id trust-tier binding)**: the adapter_id → adapter_kind binding lives in a host-side registry `AdapterRegistry` populated at daemon-boot time from `~/.config/alfred/adapters.toml` (each entry has signed `manifest_sha256`). T1 vs T3 trust classification reads from the registry, NOT from wire-supplied `adapter_id.startswith(...)`. The wire-supplied `adapter_id` is just a key; the registry resolves it to `adapter_kind` and `expected_trust_tier`. An adapter sending a self-claimed `adapter_id` that isn't in the registry is refused at handshake with `COMMS_HANDSHAKE_REFUSED_FIELDS(reason="unknown_adapter_id")`.

8. **arch-3 MEDIUM (deletion grep scope)**: Task 0a expands its grep scope:

   ```bash
   # Python imports + dynamic imports
   rg -t py -g '!tests/**' '(from|import)\s+alfred\.comms|importlib.import_module\s*\(\s*["\']alfred\.comms'
   # YAML/TOML/JSON config references
   rg -t yaml -t toml -t json 'alfred\.comms|alfred_comms'
   # Audit-row component-name strings (case-insensitive, since audit emits often title-case)
   rg -i 'component\s*[=:].*["\']alfred[._]comms'
   # Shell scripts
   rg -t sh 'alfred[._]comms'
   ```

   Output is committed as `docs/superpowers/plans/2026-06-07-slice-4-pr-s4-10-preflight.md` so reviewers can audit the canonical list.

---

## §1 Goal

PR-S4-10 is the flag-day closer for the Slice-4 comms-MCP rewrite. Its spec anchors are §8.7 (TUI adapter + daemon-required error), §8.8 (`src/alfred/comms/` deletion + consumer-break matrix), and §8.9 (ADR-0009 caveat narrowing + #152 closure). It has six distinct jobs:

1. **Ship `plugins/alfred_tui/`** — the new MCP-plugin TUI adapter. Manifest declares `adapter_kind: tui`, `sandbox.kind: none` (operator-facing CLI, PTY required). The Textual rendering layer at `plugins/alfred_tui/textual/` is a verbatim move of `src/alfred/comms/tui/textual/` (largely — wiring at the edges changes; the widgets do not). The plugin serves the four ADR-0024 host→plugin methods (`lifecycle.start`, `lifecycle.stop`, `adapter.health`, `outbound.message`) and emits the four ADR-0024 plugin→host notifications (`inbound.message`, `adapter.binding_request`, `adapter.rate_limit_signal`, `adapter.crashed`).

2. **Rewire `alfred chat`** — at `src/alfred/cli/main.py`. The Slice-2/3 in-process Textual launch is replaced by a thin spawn that hands the TUI plugin a stdio MCP boundary to the daemon (which must already be running per spec §3.1). Daemon-missing path: surface `t("comms.tui.daemon_required_to_chat")` with the exact spec §8.7 message, exit non-zero. Daemon-mid-restart race: 2.5-second handshake probe timeout (devex-003 / core-005 closure) — the launcher's probe fails, the CLI prints the same retry message, the operator retries from the shell (no silent foreground wait inside the plugin process).

3. **Atomic consumer-break migrations** (comms-006-r3 / comms-009-r3 closure) — five known consumers migrate in the same PR as the deletion:
   - `tests/smoke/test_tui_e2e.py` — rewritten to spawn `plugins/alfred_tui/` via the launcher; assertions stay.
   - `tests/smoke/test_discord_gateway_smoke.py` — rewritten against the MCP-plugin Discord shipped by PR-S4-9; assertions stay.
   - `src/alfred/identity/_ingest.py` — `adapter_name: str` argument migrates to `adapter_id: str` sourced from `InboundMessageNotification.adapter_id`.
   - `src/alfred/cli/main.py` — `_chat_main()` rewires to launcher spawn (the Task 2 work above; listed here for the migration matrix).
   - `tests/unit/comms/test_no_direct_adapter_imports.py` — the Slice-2 AST guard rewires to assert the `src/alfred/comms/` package is **absent** rather than not-imported.

4. **Delete `src/alfred/comms/`** in one shot — no file at any path under `src/alfred/comms/` survives. Because `src/alfred/comms_mcp/` is the wire-format owner and the two directory paths are deliberately disjoint, the deletion is unambiguous and there is no path collision.

5. **Narrow ADR-0009 caveat** — at `docs/adr/0009-comms-adapter-protocol-slice2-only.md`. Existing status header reads `Superseded by ADR-0016 (for new adapters); in-process Discord + TUI adapters unchanged through Slice 3`; PR-S4-10 removes the `(for new adapters)` qualifier and updates the body line `Slice 3 ships a CommsAdapterMCP Protocol stub… and a reference test plugin… The existing DiscordAdapter and TuiAdapter remain in-process through Slice 3, untouched.` to "in-process adapters removed in Slice 4 per PR-S4-10". This is **not** a status flip (the `Status: Superseded by ADR-0016` field was already set 2026-05-27 at PR-S3-0a); it is a one-shot caveat narrowing (docs-001 closure).

6. **Ship merge-blocking gates** — `tests/integration/test_tui_round_trip.py` (TUI plugin spawned via launcher, identity-resolver host-side, outbound returns to the rendered RichLog) plus `tests/smoke/test_slice4_graduation.py` (compose-up + `alfred login` + `alfred chat` round-trip; 120s soft / 240s hard runtime budget per perf-007 closure). The graduation smoke ships here, not in PR-S4-9 (ops-006 closure). The AST guard at `tests/unit/comms/test_no_direct_adapter_imports.py` flips from "not-imported" to "package absent" and remains required.

The `bin/alfred-setup.ps1` redirect to WSL2 plus the quarantined-LLM PRD non-compliance note for Windows (ops-003 closure) ships as Task 8.

---

## §2 Architecture overview

### TUI plugin process topology

```
┌──────────────────────────────────────────────────────────────┐
│  Operator shell                                              │
│                                                              │
│  $ alfred chat                                               │
│    │                                                         │
│    └─► CLI _chat_main(): probe daemon (2.5s) ── fail ──► t() │
│            │                                                 │
│            └─► spawn bin/alfred-plugin-launcher.sh \         │
│                        --manifest plugins/alfred_tui/        │
│                        --adapter-id tui-<uuid4>              │
│                                                              │
│            ┌────────────────── stdio ──────────────────────┐ │
│            ▼                                               ▼ │
│  ┌──────────────────────┐                ┌─────────────────┐ │
│  │ plugins/alfred_tui/  │  inbound.msg  │ alfred daemon   │ │
│  │   Textual widget     │ ─────────────► │ AlfredPluginSes │ │
│  │   tree + RichLog     │                │   ↓             │ │
│  │                      │  outbound.msg  │ process_inbound │ │
│  │                      │ ◄───────────── │   _message      │ │
│  └──────────────────────┘                │   ↓             │ │
│                                          │ Orchestrator    │ │
│                                          │ + IdentityResv  │ │
│                                          └─────────────────┘ │
└──────────────────────────────────────────────────────────────┘
```

Two processes; one stdio MCP boundary; identity resolution happens host-side and never crosses the wire (the canonical `user_id` string never appears in any outbound frame — PR-S4-8 adversarial test from §8.2 covers this property for any comms plugin including TUI).

### Consumer-break migration order (load-bearing)

Migrations are sequenced so the test suite stays green at every commit:

1. Ship `plugins/alfred_tui/` (Tasks 1–3). At this commit, `src/alfred/comms/tui/` still exists; the old TUI works; the new plugin is dormant.
2. Migrate `src/alfred/identity/_ingest.py` from `adapter_name` to `adapter_id` (Task 4a). Slice-2 callers still pass `adapter_name`; PR-S4-10 adds a deprecation-narrowing keyword-only alias for one commit-window.
3. Rewire `alfred chat` to launcher spawn (Task 4b). The legacy in-process path stops being reachable; the AST-guard test is *temporarily* xfailed (the guard still flags the now-unused `alfred.comms.tui_adapter` import in `src/alfred/cli/main.py`, which Task 4b removes).
4. Migrate `tests/smoke/test_tui_e2e.py` and `tests/smoke/test_discord_gateway_smoke.py` (Tasks 4c, 4d). These now spawn plugins via the launcher.
5. Pre-flight grep verifies no new consumers added since Task 0a (Task 4e — defensive re-run).
6. Delete `src/alfred/comms/` in one shot (Task 5). The AST guard at `tests/unit/comms/test_no_direct_adapter_imports.py` rewires to assert package absence (Task 5b) and un-xfails.
7. Narrow ADR-0009 caveat (Task 6).
8. Windows redirect + smoke gate + integration gate ship (Tasks 7–9).

Out-of-order execution breaks the test suite at intermediate commits — the migration order above is a hard prerequisite.

### Daemon-required error contract

Spec §8.7 names the exact operator-facing string:

> *"alfred chat needs the daemon. Start it with: `alfred daemon start`. If you expected a daemon to be running, check status with: `alfred daemon status`."*

This becomes `t("comms.tui.daemon_required_to_chat")` in the i18n catalog. Substitutions: none — the string is parameterless. The CLI emits it to stderr, exits with code 3 (the existing `_chat_main` exit code for "Postgres unreachable" + similar startup-failure modes), and never falls back to launching an embedded Textual app.

The 2.5-second handshake probe lives at `bin/alfred-plugin-launcher.sh` per PR-S4-6's contract. PR-S4-10 inherits the probe — it does not modify launcher resolution logic (one-time ownership rule, index §3). The probe's failure shape is "launcher exits non-zero within 2.5s ± slop"; the CLI maps any non-zero launcher exit during the probe window to the same `t()` string.

### ADR-0009 caveat narrowing scope

The diff against `docs/adr/0009-comms-adapter-protocol-slice2-only.md` is small and precise:

```diff
- - **Status**: Superseded by ADR-0016 for new adapters; in-process Discord + TUI adapters unchanged through Slice 3
+ - **Status**: Superseded by ADR-0016; in-process Discord + TUI adapters removed in Slice 4 per PR-S4-10
  - **Date**: 2026-05-27
  - **Slice**: 2 — `docs/superpowers/plans/2026-05-26-slice-2-pr-A-identity.md`
  - **Supersedes**: —
- - **Superseded by**: ADR-0016 (2026-05-31, for new adapters only)
+ - **Superseded by**: ADR-0016 (2026-05-31)
```

…plus a Slice-4 caveat-narrowing paragraph appended to the **Consequences** section that names PR-S4-10 and dates the in-process deletion. The status line stays `Superseded by ADR-0016` — the literal status field on the header is unchanged. The "(for new adapters)" qualifier disappears because there are no longer any "old adapters" for the caveat to be silent about. The body's reference to `CommsAdapterMCP Protocol stub` at the bottom of the file stays accurate as a historical record (the stub shipped in Slice 3; it is no longer a stub in Slice 4 but ADR-0009 documents Slice-2/3 shape and the historical statement remains true).

### `plugins/alfred_tui/` directory layout

```
plugins/alfred_tui/
├── README.md                            # human-facing pointer (operator install hints + sandbox note)
├── manifest.toml                        # adapter_kind=tui, sandbox.kind=none, manifest_version=1, plugin.subscriber_tier=operator
├── pyproject.toml                       # standalone package for out-of-tree consumption + uv lock
├── src/alfred_tui/
│   ├── __init__.py
│   ├── server.py                        # MCP stdio server entry; bind methods + notifications
│   ├── session.py                       # owns connection state to daemon; keystroke-batch debouncer
│   ├── render.py                        # Textual app shell; preserves Slice-1 widget tree
│   ├── outbound.py                      # consumes outbound.message; renders to RichLog
│   ├── _addressing.py                   # always emits addressing_signal="dm" (TUI is 1:1)
│   └── textual/                         # ←── verbatim move from src/alfred/comms/tui/textual/
│       ├── app.py
│       └── widgets/
└── tests/
    ├── test_server_methods.py           # lifecycle.start / lifecycle.stop / adapter.health / outbound.message
    ├── test_inbound_notification.py     # keystroke-batch → inbound.message
    ├── test_render_outbound.py          # outbound.message → RichLog render
    └── test_addressing_signal.py        # all inbound emits addressing_signal="dm"
```

Plugin tests live next to the plugin (`plugins/alfred_tui/tests/`) and run via `uv run pytest plugins/alfred_tui/tests/`; the top-level `tests/integration/test_tui_round_trip.py` exercises the plugin + daemon together.

---

## §3 File structure

| File | Action | Responsibility |
|---|---|---|
| `plugins/alfred_tui/manifest.toml` | Create | `adapter_kind=tui`, `sandbox.kind=none`, `plugin.subscriber_tier=operator`, `manifest_version=1`, `plugin.platform=tui` |
| `plugins/alfred_tui/pyproject.toml` | Create | Standalone uv-managed package; depends on `model_context_protocol`, `textual`, `alfred_comms_protocol` (re-exports `alfred.comms_mcp.protocol`) |
| `plugins/alfred_tui/README.md` | Create | Operator install pointer + sandbox.kind=none rationale + WSL2 note for Windows |
| `plugins/alfred_tui/src/alfred_tui/__init__.py` | Create | Package marker; `__version__` |
| `plugins/alfred_tui/src/alfred_tui/server.py` | Create | MCP stdio server; binds `lifecycle.start`, `lifecycle.stop`, `adapter.health`, `outbound.message` |
| `plugins/alfred_tui/src/alfred_tui/session.py` | Create | Owns wire state; keystroke-batch debouncer; rate-limit pause honour |
| `plugins/alfred_tui/src/alfred_tui/render.py` | Create | Textual app shell; mounts widgets; routes outbound payloads into RichLog |
| `plugins/alfred_tui/src/alfred_tui/outbound.py` | Create | `OutboundMessageRequest` consumer; returns `_OutboundDelivered` on render-success |
| `plugins/alfred_tui/src/alfred_tui/_addressing.py` | Create | Always emits `addressing_signal="dm"`; documents the 1:1 invariant |
| `plugins/alfred_tui/src/alfred_tui/textual/` | Create (move-from `src/alfred/comms/tui/textual/`) | Verbatim widget code from Slice-1 baseline |
| `plugins/alfred_tui/tests/test_server_methods.py` | Create | Happy + error + refusal for the four wire methods |
| `plugins/alfred_tui/tests/test_inbound_notification.py` | Create | Keystroke-batch → `InboundMessageNotification` with `addressing_signal="dm"` |
| `plugins/alfred_tui/tests/test_render_outbound.py` | Create | `outbound.message` → RichLog visible-line render |
| `plugins/alfred_tui/tests/test_addressing_signal.py` | Create | Every inbound emit has `addressing_signal == "dm"` regardless of input |
| `src/alfred/cli/main.py` | Modify | `_chat_main()` rewires to launcher spawn; daemon-required `t()` error; remove `alfred.comms.adapter`/`build_tui_adapter` imports |
| `src/alfred/i18n/locale/en/LC_MESSAGES/alfred.po` | Modify | Add `comms.tui.daemon_required_to_chat` string (exact spec §8.7 prose) |
| `src/alfred/i18n/locale/en/LC_MESSAGES/alfred.mo` | Regenerate | `uv run pybabel compile -d src/alfred/i18n/locale/` |
| `src/alfred/identity/_ingest.py` | Modify | `adapter_name: str` → `adapter_id: str`; update docstring + comments; preserve "tui" sentinel semantics via the adapter-id-prefix lookup |
| `tests/smoke/test_tui_e2e.py` | Modify | Replace in-process `AlfredTuiApp.run_test()` with launcher spawn + plugin handshake + stdio MCP round-trip |
| `tests/smoke/test_discord_gateway_smoke.py` | Modify | Replace in-process `DiscordAdapter` driver with `plugins/alfred_discord/` launcher spawn (PR-S4-9 contract) |
| `tests/smoke/test_slice4_graduation.py` | Create | `docker compose up -d` + `alfred login` + `alfred chat` round-trip; 120s soft / 240s hard budget |
| `tests/integration/test_tui_round_trip.py` | Create | TUI plugin + daemon: spawn via launcher, inbound notification reaches `process_inbound_message`, outbound returns to the rendered RichLog, host-side `IdentityResolver` consulted exactly once |
| `tests/unit/comms/test_no_direct_adapter_imports.py` | Rewrite | Assert `src/alfred/comms/` package is **absent** (path-does-not-exist + import-error sentinels) rather than not-imported |
| `src/alfred/comms/` | Delete | Entire directory; no file survives — `protocol.py`, `adapter.py`, `discord.py`, `discord_types.py`, `markdown_split.py`, `mcp_protocol.py`, `tui.py`, `tui_adapter.py`, `_types.py`, `tui/` |
| `docs/adr/0009-comms-adapter-protocol-slice2-only.md` | Modify | Status line caveat narrowing + Consequences paragraph for Slice-4 deletion (NOT a status flip) |
| `bin/alfred-setup.ps1` | Modify | Direct Windows operators to WSL2; document quarantined-LLM PRD non-compliance on bare Windows (ops-003) |

**Files NOT changed by this PR** (one-time ownership rules, index §3):

- `bin/alfred-plugin-launcher.sh` — PR-S4-6 owns the policy-resolution rewrite; PR-S4-10 only consumes it.
- `docs/adr/0015-slice4-containerised-quarantined-llm.md`, `docs/adr/0016-slice4-discord-tui-comms-mcp-rewrite.md` — status flip Proposed → Accepted is PR-S4-11.
- `CLAUDE.md` command table + filesystem tree — PR-S4-11 owns these updates.
- `src/alfred/comms_mcp/` — the wire-format module shipped by PR-S4-8; PR-S4-10 only consumes it.

---

## §4 Tasks

### Component A: Pre-flight verification + Textual move

- [ ] **Task 0a — Pre-flight grep on `main` (consumer-set verification gate)**

  This task runs *before* any other Task. It is the verification gate that the spec §8.8 consumer-break matrix is still complete at PR-S4-10 implementation time. The output is the canonical worksheet for Tasks 4a–4d.

  Steps:

  1. Pull latest `main`. Run:

     ```bash
     git fetch origin main && git checkout main && git pull --ff-only
     grep -rn 'from alfred.comms\|import alfred.comms' src/ tests/ \
         > /tmp/pr-s4-10-comms-importers.txt
     ```

  2. Compare the output against the spec §8.8 consumer-break matrix (the five known consumers):

     - `tests/smoke/test_discord_gateway_smoke.py`
     - `tests/smoke/test_tui_e2e.py`
     - `src/alfred/identity/_ingest.py`
     - `src/alfred/cli/main.py`
     - `tests/unit/comms/test_no_direct_adapter_imports.py`

     Plus the comms-package-internal imports under `src/alfred/comms/` itself (those are deleted as part of Task 5; they do not need separate migration).

  3. **If new consumers exist**: each new consumer joins Task 4's migration list with a migration-shape note. Update the PR description's consumer-break matrix to include the new entry. Do **not** proceed to Task 5 (deletion) until every grep hit is either inside `src/alfred/comms/` (deleted) or migrated.

  4. **If the grep returns only the five known consumers + the package-internal imports**: proceed to Task 0b. Attach the grep output as a PR artefact so reviewers can verify the worksheet at review time.

  5. Branch off `main` for the PR:

     ```bash
     git checkout -b pr-s4-10-tui-mcp-adapter-flag-day
     ```

  6. Commit the worksheet capture (no code change yet):

     ```
     git commit --allow-empty -m "chore(pr-s4-10): pre-flight grep captures consumer-break worksheet (#TBD-s4-10)"
     ```

- [ ] **Task 0b — Verify the existing `src/alfred/comms/tui/textual/` location for the Textual move**

  Steps:

  1. Confirm the directory exists and is non-empty:

     ```bash
     ls -la src/alfred/comms/tui/textual/ 2>&1 | tee /tmp/pr-s4-10-textual-snapshot.txt
     ```

  2. **If the directory does NOT exist** (the spec §8.8 phrase says Textual code lives at `src/alfred/comms/tui/textual/` — verify this on `main`): widen the search:

     ```bash
     find src/alfred/comms -name "*.py" -path "*textual*" -o -name "app.py" -o -name "widgets*"
     ```

     The Slice-1 TUI shipped as a Textual app; the exact directory shape may be `src/alfred/comms/tui.py` + `src/alfred/comms/tui_adapter.py` + widget modules co-located rather than a dedicated `textual/` subdir. Capture the actual layout in `/tmp/pr-s4-10-textual-snapshot.txt`. The "verbatim move" in Task 3 below reflects whatever the actual on-disk shape is at this point in time; if the spec's directory name does not match reality, the PR description's migration narrative names the actual shape.

  3. Mark Task 0b as `DONE` on the worksheet — no commit (read-only verification).

- [ ] **Task 1 — Create `plugins/alfred_tui/` scaffolding (manifest + pyproject + README)**

  Files: Create `plugins/alfred_tui/manifest.toml`, `plugins/alfred_tui/pyproject.toml`, `plugins/alfred_tui/README.md`, `plugins/alfred_tui/src/alfred_tui/__init__.py`.

  Steps:

  1. Write failing AST guard test (the rewrite of `tests/unit/comms/test_no_direct_adapter_imports.py` lands in Task 5b; for now, write the plugin-scaffolding test): create `plugins/alfred_tui/tests/test_manifest_well_formed.py`:

     ```python
     """Manifest declares adapter_kind=tui, sandbox.kind=none, manifest_version=1."""
     from pathlib import Path
     import tomllib

     def test_manifest_declares_required_fields() -> None:
         path = Path(__file__).parent.parent / "manifest.toml"
         data = tomllib.loads(path.read_text())
         assert data["alfred"]["manifest_version"] == 1
         assert data["plugin"]["subscriber_tier"] == "operator"
         assert data["plugin"]["platform"] == "tui"
         assert data["comms_mcp"]["adapter_kind"] == "tui"
         assert data["sandbox"]["kind"] == "none"
     ```

  2. Run `uv run pytest plugins/alfred_tui/tests/test_manifest_well_formed.py` — must FAIL with "manifest.toml not found".

  3. Create `plugins/alfred_tui/manifest.toml`:

     ```toml
     [alfred]
     manifest_version = 1

     [plugin]
     id = "alfred_tui"
     subscriber_tier = "operator"
     platform = "tui"

     [comms_mcp]
     adapter_kind = "tui"
     classifiers_optional = []                  # TUI has no required classifiers per §8.5

     [sandbox]
     kind = "none"                              # operator-facing CLI; PTY access required
     # rationale: TUI runs in the operator's interactive shell. No sandboxing is
     # applicable because we are the operator's foreground PTY. Acknowledged at
     # the bin/alfred-plugin-launcher.sh policy resolver (PR-S4-6 contract).
     ```

  4. Create `plugins/alfred_tui/pyproject.toml`:

     ```toml
     [project]
     name = "alfred_tui"
     version = "0.1.0"
     description = "AlfredOS TUI comms-MCP adapter (Textual)"
     requires-python = ">=3.12"
     dependencies = [
         "textual>=0.50",
         "model_context_protocol>=0.5",
         "alfred_comms_protocol",               # re-exports alfred.comms_mcp.protocol per spec §8.1
     ]

     [build-system]
     requires = ["hatchling"]
     build-backend = "hatchling.build"

     [tool.hatch.build.targets.wheel]
     packages = ["src/alfred_tui"]
     ```

  5. Create `plugins/alfred_tui/README.md`:

     ```markdown
     # alfred_tui — AlfredOS TUI comms-MCP adapter

     This is the in-tree TUI adapter, rewritten from the Slice-1 in-process
     Textual app as an MCP-stdio plugin. The daemon spawns it via
     `bin/alfred-plugin-launcher.sh` when an operator runs `alfred chat`.

     ## Install

     Bundled with AlfredOS — operators do not install this manually.

     ## Sandbox profile

     `sandbox.kind = none`. The TUI runs in the operator's foreground PTY; no
     sandboxing applies because we *are* the operator's interactive shell.

     ## Windows operators

     On Windows, the launcher requires WSL2. Native Windows hosts do not satisfy
     the PRD §6.7 quarantined-LLM containerisation invariant (ADR-0015); see
     `bin/alfred-setup.ps1` for the WSL2 redirect.
     ```

  6. Create `plugins/alfred_tui/src/alfred_tui/__init__.py`:

     ```python
     """alfred_tui — comms-MCP TUI adapter (Slice 4)."""
     __version__ = "0.1.0"
     ```

  7. Run `uv run pytest plugins/alfred_tui/tests/test_manifest_well_formed.py` — must PASS.

  8. Commit:

     ```
     git commit -m "feat(plugins/alfred_tui): manifest + pyproject scaffolding (#TBD-s4-10)"
     ```

- [ ] **Task 2 — Move Textual rendering layer verbatim**

  Files: `git mv src/alfred/comms/tui/textual/* plugins/alfred_tui/src/alfred_tui/textual/` (the exact source path is whatever Task 0b captured; this Task's mechanics match that).

  Rationale: the widget tree (input area, RichLog, command palette) is preserved one-for-one. Only the *bindings* between widgets and the surrounding adapter change. By moving as a single `git mv` (or `git rm` + `git add` if `git mv` is unavailable for the path shape), the diff stays small and reviewable, and `git log --follow` continues to surface widget history.

  Steps:

  1. From the Task 0b worksheet, determine the actual source directory shape on `main`. If `src/alfred/comms/tui/textual/` exists as a directory:

     ```bash
     mkdir -p plugins/alfred_tui/src/alfred_tui/textual
     git mv src/alfred/comms/tui/textual/* plugins/alfred_tui/src/alfred_tui/textual/
     ```

     If the Textual code is co-located with `src/alfred/comms/tui.py` rather than under a dedicated subdirectory: the move shape is "extract widget classes from `tui.py` into `plugins/alfred_tui/src/alfred_tui/textual/widgets.py`, extract `AlfredTuiApp` subclass into `plugins/alfred_tui/src/alfred_tui/textual/app.py`, leave the old `tui.py` alone for now (Task 5 deletes the whole `src/alfred/comms/` directory anyway)". The PR description names the actual shape.

  2. Replace top-of-file docstrings on every moved widget module to point at `plugins/alfred_tui/`:

     ```python
     """Textual widget code for the AlfredOS TUI MCP-plugin adapter.

     Verbatim move from src/alfred/comms/tui/textual/ (PR-S4-10). Widgets are
     unchanged; only their bindings to the surrounding adapter changed.
     """
     ```

  3. Run `uv run pytest plugins/alfred_tui/tests/` — the manifest test still passes; no other tests added yet.

  4. Run the **full unit suite** (`uv run pytest tests/unit -q`) — should stay green if the move did not break any cross-package imports. If any test fails because it imported a moved symbol, that consumer is an *additional* item not captured by Task 0a's grep; add it to the migration list and surface the discovery in the PR description.

  5. Commit:

     ```
     git commit -m "refactor(plugins/alfred_tui): move Textual rendering layer from src/alfred/comms/ verbatim (#TBD-s4-10)"
     ```

- [ ] **Task 3 — Implement `plugins/alfred_tui/src/alfred_tui/server.py` (four wire methods + handshake)**

  Files: Create `plugins/alfred_tui/src/alfred_tui/server.py`, `plugins/alfred_tui/tests/test_server_methods.py`.

  Steps:

  1. Write failing `plugins/alfred_tui/tests/test_server_methods.py`:

     ```python
     """Server binds the four ADR-0024 host→plugin methods."""
     from alfred_tui.server import build_server

     def test_server_exposes_lifecycle_start() -> None:
         server = build_server()
         assert "lifecycle.start" in server.list_methods()

     def test_server_exposes_lifecycle_stop() -> None:
         assert "lifecycle.stop" in build_server().list_methods()

     def test_server_exposes_adapter_health() -> None:
         assert "adapter.health" in build_server().list_methods()

     def test_server_exposes_outbound_message() -> None:
         assert "outbound.message" in build_server().list_methods()

     def test_server_refuses_unknown_method() -> None:
         # Out-of-scope refusal — manifest-declared method set is closed.
         server = build_server()
         assert "outbound.binary_blob" not in server.list_methods()
     ```

  2. Run `uv run pytest plugins/alfred_tui/tests/test_server_methods.py` — must FAIL with "server.py not found".

  3. Create `plugins/alfred_tui/src/alfred_tui/server.py`:

     ```python
     """MCP stdio server entry for the TUI plugin.

     Binds the four ADR-0024 host→plugin methods. Notification emission lives
     in alfred_tui.session.

     Wire schemas come from alfred_comms_protocol (re-export of
     alfred.comms_mcp.protocol). Plugins must not import from src/alfred/
     directly — the only cross-process boundary is the published
     alfred_comms_protocol package.
     """
     from __future__ import annotations

     from alfred_comms_protocol import (
         AdapterHealthRequest,
         HealthReport,
         LifecycleStartRequest,
         LifecycleStartResult,
         LifecycleStopRequest,
         LifecycleStopResult,
         OutboundMessageRequest,
         OutboundMessageResult,
     )
     from mcp.server import Server

     from alfred_tui import __version__
     from alfred_tui.outbound import handle_outbound_message
     from alfred_tui.session import TuiSession

     def build_server() -> Server:
         """Construct the stdio MCP server with the four wire methods bound."""
         server = Server("alfred_tui")
         session = TuiSession()

         @server.method("lifecycle.start")
         async def _lifecycle_start(req: LifecycleStartRequest) -> LifecycleStartResult:
             await session.start(adapter_id=req.adapter_id)
             return LifecycleStartResult(ok=True, plugin_version=__version__)

         @server.method("lifecycle.stop")
         async def _lifecycle_stop(req: LifecycleStopRequest) -> LifecycleStopResult:
             flushed = await session.stop(reason=req.reason)
             return LifecycleStopResult(ok=True, flushed_messages=flushed)

         @server.method("adapter.health")
         async def _adapter_health(req: AdapterHealthRequest) -> HealthReport:
             snapshot = session.health_snapshot()
             return HealthReport(
                 ok=snapshot.ok,
                 last_inbound_at=snapshot.last_inbound_at,
                 queue_depth=snapshot.queue_depth,
                 error_count=snapshot.error_count,
             )

         @server.method("outbound.message")
         async def _outbound_message(req: OutboundMessageRequest) -> OutboundMessageResult:
             return await handle_outbound_message(req, session=session)

         return server
     ```

  4. Run `uv run pytest plugins/alfred_tui/tests/test_server_methods.py` — must PASS (after stubbing `TuiSession.start/stop/health_snapshot` and `handle_outbound_message` to no-ops sufficient for the method-listing assertions).

  5. Commit:

     ```
     git commit -m "feat(plugins/alfred_tui): server.py binds four ADR-0024 wire methods (#TBD-s4-10)"
     ```

- [ ] **Task 3a — Implement `plugins/alfred_tui/src/alfred_tui/session.py` (keystroke-batch + inbound notification)**

  Files: Create `plugins/alfred_tui/src/alfred_tui/session.py`, `plugins/alfred_tui/tests/test_inbound_notification.py`.

  Steps:

  1. Write failing `plugins/alfred_tui/tests/test_inbound_notification.py`:

     ```python
     """Keystroke-batch → InboundMessageNotification(addressing_signal='dm')."""
     import pytest
     from alfred_comms_protocol import InboundMessageNotification
     from alfred_tui.session import TuiSession

     @pytest.mark.asyncio
     async def test_keystroke_batch_emits_inbound_notification() -> None:
         emitted: list[InboundMessageNotification] = []
         session = TuiSession(notify=emitted.append)
         await session.start(adapter_id="tui-test")
         await session.consume_user_input("hello alfred")
         # batch flushes on enter (or 250ms idle — Task 3b detail)
         await session.flush_keystroke_batch()
         assert len(emitted) == 1
         note = emitted[0]
         assert note.adapter_id == "tui-test"
         assert note.body == "hello alfred"
         assert note.addressing_signal == "dm"
         # platform_user_id for TUI is the OS-level $USER captured at start
         assert note.platform_user_id

     @pytest.mark.asyncio
     async def test_empty_batch_does_not_emit() -> None:
         emitted: list[InboundMessageNotification] = []
         session = TuiSession(notify=emitted.append)
         await session.start(adapter_id="tui-test")
         await session.flush_keystroke_batch()      # nothing to flush
         assert emitted == []
     ```

  2. Run — must FAIL with "TuiSession has no consume_user_input".

  3. Implement `plugins/alfred_tui/src/alfred_tui/session.py`:

     ```python
     """TuiSession owns the connection state and keystroke-batch debouncer.

     A "keystroke-batch" is the unit of inbound emission: a user types into the
     input widget; the widget collects keystrokes until enter is pressed or 250ms
     of idle elapses (whichever first). The session emits one InboundMessageNotification
     per batch with addressing_signal='dm' (TUI is always a 1:1 channel — the
     orchestrator routes by canonical user_id, never by addressing mode within TUI).

     This module does NOT own the Textual app — the app lives in alfred_tui.render
     and feeds the session via consume_user_input(). Keeping them separate means
     the session is testable without an actual terminal.
     """
     from __future__ import annotations

     import os
     import uuid
     from dataclasses import dataclass
     from datetime import datetime, UTC
     from typing import Callable

     from alfred_comms_protocol import InboundMessageNotification

     @dataclass(frozen=True)
     class HealthSnapshot:
         ok: bool
         last_inbound_at: datetime | None
         queue_depth: int
         error_count: int

     class TuiSession:
         def __init__(self, *, notify: Callable[[InboundMessageNotification], None] | None = None) -> None:
             self._adapter_id: str | None = None
             self._buffer: list[str] = []
             self._last_inbound_at: datetime | None = None
             self._error_count: int = 0
             # injected by render.py at runtime; tests inject a list.append spy
             self._notify = notify or (lambda _n: None)

         async def start(self, *, adapter_id: str) -> None:
             self._adapter_id = adapter_id

         async def stop(self, *, reason: str) -> int:
             flushed = len(self._buffer)
             self._buffer.clear()
             return flushed

         async def consume_user_input(self, chunk: str) -> None:
             self._buffer.append(chunk)

         async def flush_keystroke_batch(self) -> None:
             if not self._buffer:
                 return
             body = "".join(self._buffer)
             self._buffer.clear()
             note = InboundMessageNotification(
                 adapter_id=self._adapter_id or "tui-unknown",
                 platform_user_id=os.environ.get("USER", "unknown"),
                 body=body,
                 sub_payload_refs=[],            # TUI has no sub-payloads
                 received_at=datetime.now(UTC),
                 addressing_signal="dm",          # always dm — TUI is 1:1
             )
             self._last_inbound_at = note.received_at
             self._notify(note)

         def health_snapshot(self) -> HealthSnapshot:
             return HealthSnapshot(
                 ok=self._adapter_id is not None,
                 last_inbound_at=self._last_inbound_at,
                 queue_depth=len(self._buffer),
                 error_count=self._error_count,
             )
     ```

  4. Run — must PASS.

  5. Commit:

     ```
     git commit -m "feat(plugins/alfred_tui): session.py + keystroke-batch inbound emission (#TBD-s4-10)"
     ```

- [ ] **Task 3b — Implement `_addressing.py` (always `dm`) + reinforcing test**

  Files: Create `plugins/alfred_tui/src/alfred_tui/_addressing.py`, `plugins/alfred_tui/tests/test_addressing_signal.py`.

  Rationale: the TUI is structurally 1:1 — every inbound is `addressing_signal="dm"`. The spec §8.1 routing-rule table says the host refuses outbound `mention/channel/thread` to TUI with `COMMS_ADDRESSING_DRIFT_FIELDS` + delivery refusal. This task pins the invariant on the plugin side via a single source of truth.

  Steps:

  1. Write failing `plugins/alfred_tui/tests/test_addressing_signal.py`:

     ```python
     """Every inbound emits addressing_signal='dm'."""
     from alfred_tui._addressing import TUI_INBOUND_ADDRESSING_SIGNAL

     def test_tui_inbound_addressing_signal_is_dm() -> None:
         assert TUI_INBOUND_ADDRESSING_SIGNAL == "dm"
     ```

  2. Run — must FAIL.

  3. Create `plugins/alfred_tui/src/alfred_tui/_addressing.py`:

     ```python
     """Addressing-signal invariant for the TUI plugin.

     The TUI is structurally a 1:1 channel — the operator is the only user
     and the persona is the only addressee. Every inbound message therefore
     emits addressing_signal='dm'.

     The host refuses outbound mode=mention/channel/thread to TUI with
     COMMS_ADDRESSING_DRIFT_FIELDS audit row + delivery refusal (spec §8.1
     routing-rule table). This constant pins the invariant on the plugin
     side so the spec's wire-level guarantee has a single source of truth.
     """
     from typing import Literal, Final

     TUI_INBOUND_ADDRESSING_SIGNAL: Final[Literal["dm"]] = "dm"
     ```

  4. Update `session.py` to import and use the constant rather than the inline string.

  5. Run — must PASS.

  6. Commit:

     ```
     git commit -m "feat(plugins/alfred_tui): pin addressing_signal='dm' invariant in _addressing.py (#TBD-s4-10)"
     ```

- [ ] **Task 3c — Implement `outbound.py` + render path**

  Files: Create `plugins/alfred_tui/src/alfred_tui/outbound.py`, `plugins/alfred_tui/src/alfred_tui/render.py`, `plugins/alfred_tui/tests/test_render_outbound.py`.

  Steps:

  1. Write failing `plugins/alfred_tui/tests/test_render_outbound.py`:

     ```python
     """outbound.message → RichLog visible-line render → _OutboundDelivered."""
     import pytest
     from alfred_comms_protocol import OutboundMessageRequest
     from alfred_tui.outbound import handle_outbound_message
     from alfred_tui.session import TuiSession

     @pytest.mark.asyncio
     async def test_outbound_message_returns_delivered_with_id() -> None:
         session = TuiSession()
         await session.start(adapter_id="tui-test")
         req = OutboundMessageRequest(
             adapter_id="tui-test",
             idempotency_key="00000000-0000-0000-0000-000000000001",
             target_platform_id="local-operator",
             body="hello back",
             attachments_refs=[],
             addressing_mode="dm",
         )
         result = await handle_outbound_message(req, session=session)
         assert result.outcome == "delivered"
         assert result.platform_message_id

     @pytest.mark.asyncio
     async def test_outbound_message_refuses_non_dm_mode() -> None:
         # Host-side refusal is the load-bearing layer (spec §8.1 routing-rule
         # table). The plugin defensively returns terminal_failure too so a
         # buggy host that escapes the host-side guard does not silently render.
         session = TuiSession()
         await session.start(adapter_id="tui-test")
         req = OutboundMessageRequest(
             adapter_id="tui-test",
             idempotency_key="00000000-0000-0000-0000-000000000002",
             target_platform_id="local-operator",
             body="x",
             attachments_refs=[],
             addressing_mode="mention",
         )
         result = await handle_outbound_message(req, session=session)
         assert result.outcome == "terminal_failure"
         assert result.error_class == "tui_addressing_mode_not_supported"
     ```

  2. Run — must FAIL.

  3. Implement `plugins/alfred_tui/src/alfred_tui/outbound.py`:

     ```python
     """outbound.message handler.

     The host-side outbound queue refuses mention/channel/thread to TUI per
     spec §8.1 — the plugin's defensive check below is the second layer.
     """
     from __future__ import annotations

     import uuid

     from alfred_comms_protocol import (
         OutboundMessageRequest,
         OutboundMessageResult,
         _OutboundDelivered,
         _OutboundTerminal,
     )

     async def handle_outbound_message(
         req: OutboundMessageRequest,
         *,
         session: "TuiSession",
     ) -> OutboundMessageResult:
         if req.addressing_mode != "dm":
             return _OutboundTerminal(
                 outcome="terminal_failure",
                 error_class="tui_addressing_mode_not_supported",
                 detail_redacted=f"mode={req.addressing_mode} not supported by TUI (1:1 only)",
             )
         # Render path: hand the body to the Textual app via the session.
         await session.render_outbound(req.body)
         return _OutboundDelivered(
             outcome="delivered",
             platform_message_id=str(uuid.uuid4()),
         )
     ```

  4. Add `render_outbound(body: str)` to `TuiSession` (delegates to the Textual app's RichLog write). For the unit test, a no-op stub suffices; the integration test (Task 9) exercises the real render.

  5. Implement `plugins/alfred_tui/src/alfred_tui/render.py`:

     ```python
     """Textual app shell.

     Mounts the widget tree from alfred_tui.textual and routes user input
     into session.consume_user_input. The shell does not own the wire
     contract — the server in alfred_tui.server is the wire-binding layer.
     """
     from __future__ import annotations

     from alfred_tui.session import TuiSession
     from alfred_tui.textual.app import AlfredTuiApp

     def run_tui_render(session: TuiSession) -> None:
         """Synchronous entry; blocks until the Textual app exits."""
         app = AlfredTuiApp(session=session)
         app.run()
     ```

  6. Run — must PASS.

  7. Commit:

     ```
     git commit -m "feat(plugins/alfred_tui): outbound handler + Textual render entry (#TBD-s4-10)"
     ```

### Component B: Consumer-break migrations

- [ ] **Task 4a — Migrate `src/alfred/identity/_ingest.py` from `adapter_name` to `adapter_id`**

  Files: Modify `src/alfred/identity/_ingest.py`.

  Rationale: the in-process Protocol exposed `CommsAdapter.name: str` (`"tui"`, `"discord"`). The comms-MCP wire contract carries `adapter_id: str` (a per-instance UUID-flavoured identifier like `tui-9f3c…` or `discord-bot-prod`). The Slice-2 `_ingest_tier(user, adapter_name)` interface must migrate.

  Slice-2 `_ingest_tier` used the literal string `"tui"` to gate T1: "TUI + operator role → T1". The migration preserves this by checking `adapter_id.startswith("tui")` rather than `adapter_id == "tui"` — a per-instance adapter id like `tui-9f3c2b…` still matches. The adapter-kind prefix is the contract.

  Steps:

  1. Write failing test addition at `tests/unit/identity/test_ingest.py` (extend the existing file):

     ```python
     def test_ingest_tier_recognises_tui_kind_via_adapter_id_prefix() -> None:
         user = _OperatorUser()                     # fixture: authorization=OPERATOR
         tier = _ingest_tier(user, adapter_id="tui-9f3c2b1e")
         assert tier is T1

     def test_ingest_tier_recognises_discord_kind_via_adapter_id_prefix() -> None:
         user = _OperatorUser()
         tier = _ingest_tier(user, adapter_id="discord-bot-prod")
         assert tier is T2                          # Discord is broadcast-shaped → never T1

     def test_ingest_tier_rejects_legacy_adapter_name_kwarg() -> None:
         # Slice-2 callers passed adapter_name=; Slice-4 callers pass adapter_id=.
         # The kwarg rename is a hard break — callers must migrate.
         user = _OperatorUser()
         with pytest.raises(TypeError, match="adapter_id"):
             _ingest_tier(user, adapter_name="tui")  # type: ignore[call-arg]
     ```

  2. Run — must FAIL (the third test passes if the legacy kwarg still works; we want it to NOT still work).

  3. Edit `src/alfred/identity/_ingest.py`:

     ```python
     def _ingest_tier(user: object, adapter_id: str) -> type[TrustTier]:
         """Derive the inbound trust tier from user role + adapter kind.

         adapter_id is the per-instance comms-MCP adapter id (e.g. 'tui-9f3c2b1e',
         'discord-bot-prod'). The adapter-kind prefix is the contract:

         - 'tui*' + operator role  → T1   (operator tier; highest-trust; TUI is 1:1)
         - 'discord*' + any role   → T2   (broadcast-shaped; never T1)
         - anything else           → T2   (safe default)

         Slice-2 used adapter_name=str literal; Slice 4 migrates to adapter_id
         with a prefix lookup so per-instance ids still classify correctly.
         """
         authorization = getattr(user, "authorization", None)
         if adapter_id.startswith("tui") and authorization == Authorization.OPERATOR.value:
             return T1
         return T2
     ```

  4. Update the module docstring's "Rule (spec §3.6)" comment to name `adapter_id` not `adapter_name`.

  5. Run — must PASS.

  6. Run the full identity suite (`uv run pytest tests/unit/identity tests/integration/test_identity*.py`) — must stay green. Any caller of `_ingest_tier(adapter_name=...)` surfaces as a `TypeError`; migrate that caller in the same commit. Expected call sites: `src/alfred/comms/adapter.py` (which is being deleted in Task 5 — no migration needed) and `src/alfred/comms/discord.py` (also being deleted). No call site outside `src/alfred/comms/` calls `_ingest_tier` per the Slice-2 design.

  7. Commit:

     ```
     git commit -m "refactor(identity/_ingest): adapter_name → adapter_id (comms-MCP wire) (#TBD-s4-10)"
     ```

- [ ] **Task 4b — Rewire `alfred chat` to launcher spawn + add `t()` daemon-required string**

  Files: Modify `src/alfred/cli/main.py`, `src/alfred/i18n/locale/en/LC_MESSAGES/alfred.po`, regenerate the `.mo`.

  Steps:

  1. Add the i18n string to `src/alfred/i18n/locale/en/LC_MESSAGES/alfred.po`:

     ```po
     msgid "comms.tui.daemon_required_to_chat"
     msgstr "alfred chat needs the daemon. Start it with: alfred daemon start. If you expected a daemon to be running, check status with: alfred daemon status."
     ```

     The exact string matches spec §8.7 verbatim (no parameter substitution).

  2. Compile the catalog:

     ```bash
     uv run pybabel compile -d src/alfred/i18n/locale/
     ```

  3. Write failing CLI test at `tests/unit/cli/test_chat_daemon_required.py`:

     ```python
     """alfred chat with no daemon prints the daemon-required t() string."""
     from unittest.mock import patch
     import pytest
     import typer
     from typer.testing import CliRunner
     from alfred.cli.main import app

     def test_chat_with_no_daemon_prints_daemon_required_string(monkeypatch) -> None:
         monkeypatch.setenv("ALFRED_DAEMON_SOCKET", "/nonexistent/path")
         # Force the launcher probe to fail by pointing it at a no-op path.
         monkeypatch.setenv("ALFRED_PLUGIN_LAUNCHER", "/bin/false")
         runner = CliRunner()
         result = runner.invoke(app, ["chat"])
         assert result.exit_code == 3
         assert "alfred chat needs the daemon" in result.output
         assert "alfred daemon start" in result.output
         assert "alfred daemon status" in result.output

     def test_chat_with_launcher_timeout_prints_same_string(monkeypatch) -> None:
         # 2.5s probe timeout — point at a script that sleeps forever.
         monkeypatch.setenv("ALFRED_PLUGIN_LAUNCHER", "/bin/sh -c 'sleep 60'")
         runner = CliRunner()
         result = runner.invoke(app, ["chat"])
         assert result.exit_code == 3
         assert "alfred chat needs the daemon" in result.output
     ```

  4. Run — must FAIL.

  5. Rewrite `_chat_main` in `src/alfred/cli/main.py`:

     ```python
     async def _chat_main() -> None:
         """Spawn the TUI MCP plugin via the launcher.

         Slice 4: in-process Textual launch replaced by an MCP-stdio plugin
         spawned via bin/alfred-plugin-launcher.sh. The daemon must already be
         running (spec §3.1); daemon-missing path surfaces a t()-routed
         error and exits non-zero.

         The 2.5s handshake-probe timeout is enforced by the launcher (PR-S4-6
         contract); the CLI maps any non-zero launcher exit within the probe
         window to the same t() string. The TUI plugin does NOT wait-and-retry
         inside its own process — that would create silent foreground-wait UX.
         The operator retries from the shell (core-005 closure).
         """
         import asyncio
         import os
         import shlex
         import uuid

         launcher = os.environ.get(
             "ALFRED_PLUGIN_LAUNCHER",
             "bin/alfred-plugin-launcher.sh",
         )
         adapter_id = f"tui-{uuid.uuid4()}"
         manifest_path = "plugins/alfred_tui/manifest.toml"

         cmd = [
             *shlex.split(launcher),
             "--manifest", manifest_path,
             "--adapter-id", adapter_id,
             "--probe-timeout-seconds", "2.5",
         ]

         try:
             proc = await asyncio.create_subprocess_exec(
                 *cmd,
                 stdin=asyncio.subprocess.PIPE,
                 stdout=asyncio.subprocess.PIPE,
                 stderr=asyncio.subprocess.PIPE,
             )
             # The launcher's handshake probe enforces the 2.5s timeout
             # internally and exits non-zero on failure. Wait for the probe
             # window to elapse.
             try:
                 returncode = await asyncio.wait_for(proc.wait(), timeout=2.5)
             except asyncio.TimeoutError:
                 # Launcher still running after probe window — the probe
                 # succeeded and the TUI is now live. Re-await without timeout.
                 returncode = await proc.wait()

             if returncode != 0:
                 typer.echo(t("comms.tui.daemon_required_to_chat"), err=True)
                 raise typer.Exit(code=3)
         except (FileNotFoundError, OSError):
             typer.echo(t("comms.tui.daemon_required_to_chat"), err=True)
             raise typer.Exit(code=3)
     ```

     Remove all the Slice-2 imports (`build_tui_adapter`, `Orchestrator`, `BudgetGuard`, `WorkingMemoryPool`, `EpisodicMemory`, `OutboundDlp`, `AuditWriter`, `InProcessTokenBucketRateLimiter`, `Platform`, `build_session_scope`, `healthcheck`, `install_identity_factories_for_settings`, `build_adapter_dlp_audit_sink`, `build_broker`, `build_router`, `configure_logging`, `load_settings_or_die`) — the daemon owns the orchestrator graph in Slice 4; the CLI is now just a launcher caller.

     Also remove the `from alfred.comms.adapter import build_tui_adapter` line — this is one of the AST-guard violations that Task 5b will assert is gone.

  6. Run — must PASS (the two CLI tests).

  7. Verify the unit `tests/unit/cli/test_main_lazy_imports.py` still passes — the heavy-import discipline matters even more now (the launcher path is even lighter than the Slice-2 in-process graph).

  8. Commit:

     ```
     git commit -m "feat(cli): alfred chat spawns plugins/alfred_tui via launcher + daemon-required t() (#TBD-s4-10)"
     ```

- [ ] **Task 4c — Rewrite `tests/smoke/test_tui_e2e.py` to spawn plugin via launcher**

  Files: Modify `tests/smoke/test_tui_e2e.py`.

  Rationale: the Slice-1 smoke drove `AlfredTuiApp.run_test()` + `Pilot` in-process. With the plugin shape, the smoke spawns the plugin via the launcher and asserts on the daemon's audit log + the orchestrator's render-back surface. The harness shape changes; the assertions stay (one operator turn → one episode pair + one audit row + one rendered response).

  Steps:

  1. Capture the current shape:

     ```bash
     wc -l tests/smoke/test_tui_e2e.py
     ```

  2. Rewrite the three test functions:

     - `test_tui_mock_provider_round_trip` — `docker compose up -d` the testcontainer; `alfred daemon start` via subprocess; spawn `plugins/alfred_tui/` via the launcher (test-helper utility writes input to the plugin's stdin via the launcher's `--test-input` flag, available behind `ALFRED_ENV=development`); assert the orchestrator received the inbound notification (via audit-log query), the response was rendered (via stdout capture of the plugin's RichLog), the budget guard advanced, the episode pair landed, and the audit row carries the seven-branch shape.

     - `test_tui_real_provider_round_trip` — same harness; gated by `ALFRED_SMOKE_PROVIDER_KEY`; deterministic prompt; assert response includes `"OK"`.

     - `test_tui_rehydrate_cadence_across_invocations` — two consecutive launcher-spawned plugin sessions against the same Postgres; the second session's first inbound triggers rehydrate of the working memory; assertion shape preserved.

  3. Move the spike-outcome docstring at the top of the file: the Slice-1 narrative ("Textual's built-in headless test harness is used directly") becomes "Slice-4: plugin-via-launcher harness; the Slice-1 `Pilot` path lives at `plugins/alfred_tui/tests/` for in-plugin unit coverage."

  4. Run `uv run pytest tests/smoke/test_tui_e2e.py -q` — must PASS against a real docker-compose stack. CI runs this on `ubuntu-latest` per the integration-test-gate table in `docs/superpowers/plans/2026-06-07-slice-4-index.md` §4.

  5. Commit:

     ```
     git commit -m "test(smoke/tui): rewrite to spawn plugins/alfred_tui via launcher (#TBD-s4-10)"
     ```

- [ ] **Task 4d — Rewrite `tests/smoke/test_discord_gateway_smoke.py` against MCP-plugin Discord**

  Files: Modify `tests/smoke/test_discord_gateway_smoke.py`.

  Rationale: PR-S4-9 ships `plugins/alfred_discord/`. The Slice-2 in-process Discord adapter is dormant after PR-S4-9 (still resident in `src/alfred/comms/discord/`, AST-guard forbids imports). PR-S4-10 finishes the migration by repointing the smoke at the plugin.

  Steps:

  1. Rewrite the existing test functions to:
     - Spawn `plugins/alfred_discord/` via the launcher.
     - Connect to the test Discord gateway via the recorded-fixtures harness shipped by PR-S4-9.
     - Drive an inbound message through the plugin's `inbound.message` notification.
     - Assert the orchestrator dispatched the right outbound shape and the gateway received an `outbound.message` matching the spec §8.1 routing-rule table for each addressing mode.

  2. Use the PR-S4-9-shipped Discord plugin fixture (whatever its name turns out to be — check PR-S4-9's PR description; the plan-link is `docs/superpowers/plans/2026-06-07-slice-4-pr-s4-9-discord-mcp-adapter.md`).

  3. Run `uv run pytest tests/smoke/test_discord_gateway_smoke.py -q` — must PASS.

  4. Commit:

     ```
     git commit -m "test(smoke/discord-gateway): repoint at plugins/alfred_discord (PR-S4-9) (#TBD-s4-10)"
     ```

- [ ] **Task 4e — Defensive pre-flight grep re-run before deletion**

  This task is a checkpoint, not a code change. It guards against the case where new consumers landed on `main` between Task 0a and now.

  Steps:

  1. Re-run the Task 0a grep against the current branch (which now has the four migrations of Tasks 4a–4d applied):

     ```bash
     grep -rn 'from alfred.comms\|import alfred.comms' src/ tests/ \
         > /tmp/pr-s4-10-comms-importers-pre-delete.txt
     ```

  2. Every remaining hit must be **inside** `src/alfred/comms/` itself (those files are about to be deleted). If any hit is outside the package, migrate that consumer before proceeding to Task 5.

  3. The Task 4a–4d migrations should leave these expected remaining importers:
     - Files inside `src/alfred/comms/` (deleted in Task 5).
     - `tests/unit/comms/test_no_direct_adapter_imports.py` (rewired in Task 5b — this is the AST guard itself).
     - The two smoke-test rewrites *should not* contain `from alfred.comms` after Task 4c/4d.

  4. **If the grep finds an unexpected outside importer**: STOP. Add it to Task 4 (a new sub-task 4f or amend the existing one); migrate the consumer; commit; only then proceed to Task 5.

  5. **If the grep returns only the expected set**: proceed to Task 5. Attach `/tmp/pr-s4-10-comms-importers-pre-delete.txt` as a PR artefact.

  6. No commit (verification gate).

### Component C: Atomic deletion + AST guard rewire + ADR caveat narrowing

- [ ] **Task 5 — Delete `src/alfred/comms/` in one shot**

  Files: `git rm -r src/alfred/comms/`.

  Rationale: spec §8.8 — every file under `src/alfred/comms/` is removed. The wire-format owner lives at `src/alfred/comms_mcp/protocol.py` (PR-S4-8 shipped); there is no path collision with the deleted directory.

  Steps:

  1. Verify the deletion will not collide with anything under `src/alfred/comms_mcp/`:

     ```bash
     find src/alfred/comms src/alfred/comms_mcp -type f | sort > /tmp/pr-s4-10-paths.txt
     # Inspect /tmp/pr-s4-10-paths.txt — every src/alfred/comms/ path
     # should be unrelated to src/alfred/comms_mcp/ paths.
     ```

  2. Delete the directory:

     ```bash
     git rm -r src/alfred/comms/
     ```

     This removes (verified from the on-disk listing): `src/alfred/comms/__init__.py`, `src/alfred/comms/_types.py`, `src/alfred/comms/adapter.py`, `src/alfred/comms/discord.py`, `src/alfred/comms/discord_types.py`, `src/alfred/comms/markdown_split.py`, `src/alfred/comms/mcp_protocol.py`, `src/alfred/comms/tui.py`, `src/alfred/comms/tui_adapter.py`, plus any subdirectories (`tui/`, `discord/` if present).

  3. Run `uv run pytest tests/unit -q` — must PASS. Any failure here means a consumer was missed at Task 4e; rewind, migrate, re-run.

  4. Run `uv run mypy src/` — must pass. `pyright src/` likewise.

  5. Commit:

     ```
     git commit -m "refactor(comms): delete src/alfred/comms/ — flag-day for in-process adapters (#TBD-s4-10)"
     ```

- [ ] **Task 5b — Rewire `tests/unit/comms/test_no_direct_adapter_imports.py` AST guard to assert package absent**

  Files: Modify `tests/unit/comms/test_no_direct_adapter_imports.py`.

  Rationale: the Slice-2 AST guard scanned the source tree for `from alfred.comms` imports. With the package gone, the guard's job inverts — it asserts the package directory itself does not exist and that `import alfred.comms` raises `ModuleNotFoundError`.

  The test file moves from `tests/unit/comms/` to `tests/unit/_comms_deleted/` (Task 5c) because the original `tests/unit/comms/` directory name is now misleading. The other tests under `tests/unit/comms/` (`test_adapter_protocol.py`, `test_discord*.py`, `test_markdown_split.py`, `test_mcp_identity_boundary.py`, `test_mcp_protocol.py`, `test_tui*.py`) are deleted in Task 5c too — they tested classes that no longer exist.

  Steps:

  1. Write the rewired guard at `tests/unit/_comms_deleted/test_comms_package_absent.py`:

     ```python
     """src/alfred/comms/ is deleted as of PR-S4-10.

     The Slice-2 AST guard (tests/unit/comms/test_no_direct_adapter_imports.py)
     enforced 'import this allowlist only'. PR-S4-10 inverted the guard: the
     package must not exist on disk and must not be importable. Any
     regression that reintroduces the package is caught here.

     See:
       - ADR-0009 (caveat narrowed in PR-S4-10 — the in-process adapters are
         removed in Slice 4, not just superseded for new adapters).
       - ADR-0016 (Slice-4 comms-MCP rewrite).
       - docs/superpowers/specs/2026-06-06-slice-4-design.md §8.8.
     """
     from __future__ import annotations

     import importlib
     import pathlib

     import pytest

     _ROOT = pathlib.Path(__file__).resolve().parents[3]
     _DELETED_DIR = _ROOT / "src" / "alfred" / "comms"

     def test_src_alfred_comms_directory_is_absent() -> None:
         """The directory must not exist on disk."""
         assert not _DELETED_DIR.exists(), (
             f"{_DELETED_DIR} reintroduces the Slice-1/2 in-process comms package "
             "that was deleted in PR-S4-10. The MCP plugins at plugins/alfred_discord/ "
             "and plugins/alfred_tui/ replace it. If a consumer needs comms wire "
             "types, import from alfred_comms_protocol (re-export of "
             "alfred.comms_mcp.protocol). See ADR-0016."
         )

     def test_alfred_comms_is_not_importable() -> None:
         """`import alfred.comms` must raise ModuleNotFoundError."""
         with pytest.raises(ModuleNotFoundError):
             importlib.import_module("alfred.comms")

     def test_alfred_comms_mcp_is_importable() -> None:
         """The replacement wire-format module IS importable.

         Sanity check that PR-S4-10's deletion did not collateral-damage
         the wire-format module shipped by PR-S4-8.
         """
         mod = importlib.import_module("alfred.comms_mcp.protocol")
         assert hasattr(mod, "InboundMessageNotification")
         assert hasattr(mod, "OutboundMessageRequest")
     ```

  2. Run — must PASS.

  3. Commit:

     ```
     git commit -m "test(unit/_comms_deleted): assert src/alfred/comms package absent + replacement importable (#TBD-s4-10)"
     ```

- [ ] **Task 5c — Delete the now-orphaned unit tests at `tests/unit/comms/`**

  Files: `git rm -r tests/unit/comms/` (except the moved AST guard).

  Rationale: the unit tests under `tests/unit/comms/` exercised classes that no longer exist (`TuiAdapter`, `DiscordAdapter`, `CommsAdapter` Protocol, `_split_for_discord`, etc.). With the source classes gone, the tests would fail at import time — they are dead weight.

  The MCP-protocol identity-boundary test at `tests/unit/comms/test_mcp_identity_boundary.py` migrates content to `tests/integration/test_comms_mcp_identity_boundary_real.py` (PR-S4-8 shipped) — the integration variant supersedes the unit stub.

  Steps:

  1. Capture what we are deleting:

     ```bash
     ls tests/unit/comms/ > /tmp/pr-s4-10-deleted-unit-comms.txt
     ```

     Expected entries (from the verified on-disk listing): `__init__.py`, `test_adapter_protocol.py`, `test_discord_allowlist_unchanged_in_slice3.py`, `test_discord_types_protocol.py`, `test_discord.py`, `test_markdown_split.py`, `test_mcp_identity_boundary.py`, `test_mcp_protocol.py`, `test_no_direct_adapter_imports.py`, `test_tui_adapter.py`, `test_tui.py`.

  2. Delete the directory:

     ```bash
     git rm -r tests/unit/comms/
     ```

  3. Run `uv run pytest tests/unit tests/integration -q` — must PASS. The `tests/unit/_comms_deleted/test_comms_package_absent.py` from Task 5b stays green. Any integration test that depended on a unit-tests-side fixture from `tests/unit/comms/` migrates its fixture to a more durable location (typically `tests/conftest.py` or a `tests/_shared/` module).

  4. Commit:

     ```
     git commit -m "test(unit/comms): delete tests of deleted classes — package gone in PR-S4-10 (#TBD-s4-10)"
     ```

- [ ] **Task 6 — Narrow ADR-0009 caveat (NOT a status flip)**

  Files: Modify `docs/adr/0009-comms-adapter-protocol-slice2-only.md`.

  Steps:

  1. Edit the status header. Current text:

     ```markdown
     - **Status**: Superseded by ADR-0016 for new adapters; in-process Discord + TUI adapters unchanged through Slice 3
     - **Date**: 2026-05-27
     - **Slice**: 2 — `docs/superpowers/plans/2026-05-26-slice-2-pr-A-identity.md`
     - **Supersedes**: —
     - **Superseded by**: ADR-0016 (2026-05-31, for new adapters only)
     ```

     Replace with:

     ```markdown
     - **Status**: Superseded by ADR-0016; in-process Discord + TUI adapters removed in Slice 4 per PR-S4-10
     - **Date**: 2026-05-27
     - **Slice**: 2 — `docs/superpowers/plans/2026-05-26-slice-2-pr-A-identity.md`
     - **Supersedes**: —
     - **Superseded by**: ADR-0016 (2026-05-31)
     ```

     **The `Status:` field still reads `Superseded by ADR-0016`. The status word — `Superseded by` — is unchanged. PR-S4-10 narrows the caveat (the parenthetical "for new adapters" qualifier is removed because the in-process adapters are now also gone); it does not flip the status header. ADR-0015/0016 status flips Proposed → Accepted are PR-S4-11 work (docs-001 closure; one-time ownership rule in index §3).**

  2. Append to the bottom of the **Consequences** section, immediately before the **Alternatives considered** heading:

     ```markdown
     ### Slice-4 follow-through

     PR-S4-10 (date: 2026-06-07) deleted `src/alfred/comms/` and shipped the
     in-tree replacements at `plugins/alfred_discord/` (PR-S4-9) and
     `plugins/alfred_tui/` (PR-S4-10). The "in-process adapters unchanged
     through Slice 3" caveat above no longer applies as a forward-looking
     statement — it is preserved as the historical record of what Slice 2
     and Slice 3 carried. The wire-format module at
     `src/alfred/comms_mcp/protocol.py` (shipped PR-S4-8 per ADR-0024) is
     the post-Slice-4 home of the comms-adapter contract. ADR-0016
     status-flips Proposed → Accepted at PR-S4-11 graduation.
     ```

  3. Run `make docs-check` — must PASS. The broken-link gate may complain if any earlier document referenced `src/alfred/comms/`; update those references in the same commit (the PR description names every such update).

  4. Run `uv run pybabel compile --check` — must PASS (no i18n surface touched in this Task).

  5. Commit:

     ```
     git commit -m "docs(adr/0009): narrow caveat — in-process adapters removed in Slice 4 (#TBD-s4-10)"
     ```

### Component D: Windows redirect + smoke + integration gates

- [ ] **Task 7 — Update `bin/alfred-setup.ps1` for WSL2 + quarantined-LLM PRD non-compliance note**

  Files: Modify `bin/alfred-setup.ps1`.

  Rationale: ops-003 closure. Native Windows hosts do not satisfy the PRD §6.7 quarantined-LLM containerisation invariant (ADR-0015 — bwrap on Linux, sandbox-exec on macOS, Windows is stubbed). The setup script's job is to redirect Windows operators to WSL2 and tell them why.

  Steps:

  1. The current `bin/alfred-setup.ps1` is 9 lines and reads:

     ```powershell
     # Slice-1 PowerShell stub. Delegates to WSL until native Windows support lands.
     $ErrorActionPreference = "Stop"

     if (-not (Get-Command wsl -ErrorAction SilentlyContinue)) {
         Write-Error "WSL is required for AlfredOS on Windows in Slice 1. Install with 'wsl --install'."
         exit 1
     }

     wsl bash bin/alfred-setup.sh @args
     ```

  2. Rewrite to:

     ```powershell
     # AlfredOS PowerShell entry — redirects to WSL2.
     #
     # Native Windows hosts cannot satisfy the PRD §6.7 quarantined-LLM
     # containerisation invariant (ADR-0015 — bwrap on Linux, sandbox-exec on
     # macOS, no Windows kernel-level equivalent ships in Slice 4). Running
     # AlfredOS in WSL2 is the supported configuration on Windows; bare
     # Windows is out of scope through Slice 4+.
     #
     # See: ADR-0015, docs/superpowers/specs/2026-06-06-slice-4-design.md §6.6.

     $ErrorActionPreference = "Stop"

     if (-not (Get-Command wsl -ErrorAction SilentlyContinue)) {
         Write-Error @"
     WSL2 is required for AlfredOS on Windows.

     Install with: wsl --install

     Native Windows is not a supported AlfredOS deployment target. The
     quarantined-LLM containerisation invariant (PRD §6.7, ADR-0015) requires
     a kernel-level sandbox primitive (bwrap on Linux, sandbox-exec on
     macOS); no equivalent ships through Slice 4 on bare Windows.
     "@
         exit 1
     }

     wsl bash bin/alfred-setup.sh @args
     ```

  3. No automated test for a PowerShell script — sanity-check by running on a Windows host (or document "no automated coverage; operator-tested" in the PR description).

  4. Commit:

     ```
     git commit -m "build(setup.ps1): direct Windows ops to WSL2; document PRD non-compliance (#TBD-s4-10)"
     ```

- [ ] **Task 8 — Ship `tests/smoke/test_slice4_graduation.py`**

  Files: Create `tests/smoke/test_slice4_graduation.py`.

  Rationale: ops-006 closure. The graduation smoke ships in PR-S4-10, not PR-S4-9 (per index §1 row "PR-S4-10 description"). It is the compose-up + `alfred login` + `alfred chat` round-trip, plus a Discord round-trip for the plugin shipped by PR-S4-9.

  Steps:

  1. Write `tests/smoke/test_slice4_graduation.py`:

     ```python
     """Slice-4 graduation smoke — compose-up + login + chat round-trip.

     This is the merge-blocking gate for the full Slice-4 surface. It runs
     against a clean docker-compose stack: Postgres + Redis + Qdrant +
     the alfred-core daemon + plugins/alfred_tui + plugins/alfred_discord.

     Runtime budget: 120s soft / 240s hard (perf-007 closure). The CI job
     skips the test if any of the prerequisites are missing.

     The TUI round-trip drives one operator turn through the launcher-
     spawned plugin and asserts:
       - Daemon's audit log records inbound + dispatch + outbound rows.
       - The orchestrator's response renders to the plugin's RichLog.
       - The episode pair lands in Postgres.

     The Discord round-trip drives one inbound through the recorded
     Discord-gateway harness (PR-S4-9 fixture) and asserts the four
     addressing-mode outbound shapes.
     """
     from __future__ import annotations

     import asyncio
     import os
     import subprocess
     import time

     import pytest

     # Soft budget — pytest emits a warning if exceeded.
     # Hard budget — pytest fails the test if exceeded.
     SOFT_BUDGET_SECONDS = 120.0
     HARD_BUDGET_SECONDS = 240.0

     pytestmark = pytest.mark.timeout(HARD_BUDGET_SECONDS)

     @pytest.fixture(scope="module")
     def compose_stack():
         """Bring up docker compose for the duration of the module."""
         if os.environ.get("ALFRED_SKIP_GRADUATION_SMOKE") == "1":
             pytest.skip("ALFRED_SKIP_GRADUATION_SMOKE=1")
         subprocess.run(["docker", "compose", "up", "-d", "--wait"], check=True)
         yield
         subprocess.run(["docker", "compose", "down", "-v"], check=False)

     def test_compose_up_then_login_then_tui_chat_round_trip(compose_stack) -> None:
         """End-to-end: stack up → alfred login → alfred chat → response."""
         start = time.monotonic()

         # alfred login (PR-S4-5 shipped — creates session file mode 0600).
         result = subprocess.run(
             ["alfred", "login", "--as", "operator", "--password-stdin"],
             input="test-password\n",
             text=True,
             capture_output=True,
             check=False,
             timeout=10,
         )
         assert result.returncode == 0, result.stderr

         # alfred chat — drive one inbound + assert one outbound.
         # In CI, the harness uses ALFRED_PLUGIN_LAUNCHER_TEST_INPUT
         # (PR-S4-6 dev-only flag) to inject a deterministic prompt and
         # capture the rendered response without an actual PTY.
         chat = subprocess.run(
             ["alfred", "chat"],
             env={
                 **os.environ,
                 "ALFRED_PLUGIN_LAUNCHER_TEST_INPUT": "say OK",
             },
             timeout=60,
             capture_output=True,
             text=True,
         )
         assert chat.returncode == 0, chat.stderr
         assert "OK" in chat.stdout

         elapsed = time.monotonic() - start
         if elapsed > SOFT_BUDGET_SECONDS:
             pytest.warns(UserWarning, match=f"soft budget {SOFT_BUDGET_SECONDS}s exceeded")

     def test_compose_up_then_discord_round_trip(compose_stack) -> None:
         """End-to-end Discord — recorded-gateway harness from PR-S4-9."""
         # Exact harness shape depends on PR-S4-9; this test stub asserts the
         # mere fact that the Discord plugin starts under compose and responds
         # to one recorded inbound. PR-S4-9's harness fills in the body.
         result = subprocess.run(
             ["docker", "compose", "exec", "-T", "alfred-core",
              "python", "-m", "tests.smoke._discord_recorded_harness"],
             timeout=60,
             check=False,
             capture_output=True,
         )
         assert result.returncode == 0, result.stderr
     ```

  2. Add `pytest-timeout` to `pyproject.toml` `[tool.pytest.ini_options]` if not already present.

  3. Run `docker compose up -d` locally; run the smoke; expect PASS (will take 60–120s).

  4. Promote this test to a required-status-check in the workflow that runs `tests/smoke/test_slice4_graduation.py`. The promotion mechanics follow the `author-gating-workflow` skill's pattern (index §4 — "promoted to required-status-check in the PR that ships it"). See `.github/workflows/` for the test-runner job; if a smoke runner does not exist, this Task adds one as `.github/workflows/smoke-slice-4.yml` (a minimal `ubuntu-latest` job that runs `docker compose up -d` + `uv run pytest tests/smoke/test_slice4_graduation.py`).

  5. Commit:

     ```
     git commit -m "test(smoke): ship slice-4 graduation gate — compose+login+chat (#TBD-s4-10)"
     ```

- [ ] **Task 9 — Ship `tests/integration/test_tui_round_trip.py`**

  Files: Create `tests/integration/test_tui_round_trip.py`.

  Steps:

  1. Write the integration test:

     ```python
     """TUI MCP plugin + daemon round-trip integration test.

     Spawns plugins/alfred_tui via bin/alfred-plugin-launcher.sh against a
     real testcontainer Postgres + a real in-process AlfredPluginSession
     (no docker-compose). Drives an inbound notification end-to-end:

       1. Plugin emits inbound.message via stdio.
       2. AlfredPluginSession.process notification → process_inbound_message.
       3. IdentityResolver consulted exactly once host-side (positive
          assertion + adversarial absent-from-wire assertion).
       4. orchestrator.dispatch → outbound.message back to the plugin.
       5. Plugin's render path produces an _OutboundDelivered result.

     Closes spec §8.7 (TUI adapter contract) and reinforces §8.2
     (canonical id never crosses the wire).
     """
     from __future__ import annotations

     import asyncio
     import pytest

     @pytest.mark.asyncio
     async def test_tui_inbound_reaches_process_inbound_message(
         postgres_container, alfred_session_factory, identity_resolver_spy
     ) -> None:
         session = await alfred_session_factory(
             manifest_path="plugins/alfred_tui/manifest.toml",
         )
         await session.send_test_input("hello alfred")
         # process_inbound_message has been awaited exactly once.
         assert identity_resolver_spy.resolve_call_count == 1
         # Canonical id is in the resolved identity but did NOT appear on
         # any captured stdio frame.
         resolved = identity_resolver_spy.last_resolved_identity()
         all_frames = session.captured_stdio_frames()
         assert resolved.canonical_user_id not in (frame for _, frame in all_frames)

     @pytest.mark.asyncio
     async def test_tui_outbound_renders_to_plugin(
         postgres_container, alfred_session_factory
     ) -> None:
         session = await alfred_session_factory(
             manifest_path="plugins/alfred_tui/manifest.toml",
         )
         await session.send_test_input("respond with PONG")
         await asyncio.wait_for(session.wait_for_outbound_rendered("PONG"), timeout=5.0)
         assert "PONG" in session.rendered_buffer()

     @pytest.mark.asyncio
     async def test_tui_outbound_refuses_non_dm_addressing_mode(
         postgres_container, alfred_session_factory
     ) -> None:
         # Force the host to send mode=mention to TUI; assert the host's
         # COMMS_ADDRESSING_DRIFT audit row fires and the plugin's defensive
         # terminal_failure also fires.
         session = await alfred_session_factory(
             manifest_path="plugins/alfred_tui/manifest.toml",
         )
         await session.force_outbound_mode("mention")
         result = await session.last_outbound_result()
         assert result.outcome == "terminal_failure"
         assert result.error_class == "tui_addressing_mode_not_supported"
         assert session.audit_log_has_row("COMMS_ADDRESSING_DRIFT_FIELDS")
     ```

  2. Implement the `alfred_session_factory` fixture in `tests/integration/conftest.py` (or extend it if PR-S4-8 already shipped one). The fixture sets up an in-process `AlfredPluginSession` wired to the testcontainer Postgres, an `IdentityResolverSpy` recording call counts, and a `send_test_input` shim that writes to the launcher subprocess's `--test-input` flag.

  3. Run `uv run pytest tests/integration/test_tui_round_trip.py -q` — must PASS.

  4. Promote `tests/integration/test_tui_round_trip.py` to a required-status-check in `.github/workflows/integration-slice-4.yml` (or whatever workflow runs integration on `ubuntu-latest` per index §4).

  5. Commit:

     ```
     git commit -m "test(integration/tui): ship round-trip gate — plugin + daemon + dispatch (#TBD-s4-10)"
     ```

### Component E: Verification + PR submission

- [ ] **Task 10 — Full quality gate sweep**

  Run all gates from index §5:

  1. `make check` — lint, format, mypy, pyright, unit tests. Must pass.
  2. `uv run pytest tests/adversarial` — required because `_ingest_tier` lives under `src/alfred/identity/` not `src/alfred/security/`, but the comms-MCP wire surface is a trust boundary; the adversarial corpus has comms-injection and inter-persona-forgery payloads that exercise the new path. Must pass.
  3. 100% line + branch coverage on every touched trust-boundary file. The touched files are:
     - `src/alfred/identity/_ingest.py` (adapter_id migration).
     - `src/alfred/cli/main.py` (launcher spawn).
     - `plugins/alfred_tui/src/alfred_tui/session.py`, `outbound.py`, `_addressing.py`.
     Coverage gate enforced by `pytest --cov` with the `fail_under` threshold matching the slice-4 coverage manifest.
  4. `make docs-check` — required for the ADR-0009 caveat narrowing. Must pass; broken links surface here.
  5. `uv run pybabel compile --check` — required for the new `comms.tui.daemon_required_to_chat` string. Must pass.
  6. Conventional-commit `#NNN` reference gate — every commit on the branch carries `(#TBD-s4-10)` until the issue number is substituted at PR-open time.
  7. Markdown lint — `markdownlint-cli2` over the touched `.md` files (ADR-0009, this plan).

- [ ] **Task 11 — Open the PR**

  Steps:

  1. Substitute the real issue number for every `(#TBD-s4-10)` in commit messages (via `git rebase -i` autosquash, or by editing each commit message during a `git rebase -i --autosquash` round).

  2. Push the branch:

     ```bash
     git push -u origin pr-s4-10-tui-mcp-adapter-flag-day
     ```

  3. Open the PR with the title `pr-s4-10: TUI MCP adapter + src/alfred/comms/ flag-day` and a body that includes:

     - **Summary** — three bullets: (a) ships `plugins/alfred_tui/` as the MCP-stdio replacement for the in-process Textual TUI, (b) deletes `src/alfred/comms/` in one shot and migrates the five known consumers atomically, (c) narrows the ADR-0009 caveat — NOT a status flip.

     - **Test plan** — the canonical checklist:
       - [ ] `uv run pytest plugins/alfred_tui/tests/` — plugin-side unit suite passes.
       - [ ] `uv run pytest tests/unit -q` — full unit suite passes (the rewired AST guard at `tests/unit/_comms_deleted/test_comms_package_absent.py` passes).
       - [ ] `uv run pytest tests/integration/test_tui_round_trip.py` — integration gate passes.
       - [ ] `uv run pytest tests/smoke/test_tui_e2e.py tests/smoke/test_discord_gateway_smoke.py tests/smoke/test_slice4_graduation.py` — three smoke gates pass.
       - [ ] `uv run pytest tests/adversarial` — adversarial suite passes.
       - [ ] `make check` and `make docs-check` pass.
       - [ ] `uv run pybabel compile --check` passes.

     - **Consumer-break worksheet** — paste the Task 0a and Task 4e grep outputs as collapsed `<details>` blocks. Note any consumers added between Task 0a and Task 4e.

     - **One-time ownership audit** — confirm:
       - PR-S4-10 deleted `src/alfred/comms/` (index §3 — only PR-S4-10 may do this).
       - PR-S4-10 narrowed ADR-0009's caveat — the `Status:` line was not flipped, only the `(for new adapters)` qualifier was removed (docs-001 closure).
       - PR-S4-10 did NOT modify `bin/alfred-plugin-launcher.sh` policy resolution (PR-S4-6 owns that).
       - PR-S4-10 did NOT flip ADR-0015 or ADR-0016 status (PR-S4-11 owns those flips).
       - PR-S4-10 did NOT update `CLAUDE.md` (PR-S4-11 owns that).

     - **Out-of-scope deferrals** — name explicitly:
       - ADR-0015/0016 status flips → PR-S4-11.
       - CLAUDE.md tree + commands updates → PR-S4-11.
       - `docs/subsystems/comms.md` authoritative rewrite → PR-S4-11.

  4. Apply labels `slice-4`, `comms-mcp`, `flag-day`, `merge-blocking`.

  5. Request review from the agents named in the PR-S4-10 row of index §6 (typically `alfred-comms-adapter-engineer`, `alfred-security-engineer`, `alfred-test-engineer`).

  6. **Promote the new gates to required-status-checks** after the workflow runs at least once successfully on the PR — use `gh api` per the `author-gating-workflow` skill conventions:
     - `tests/integration/test_tui_round_trip.py` (named test job in `.github/workflows/integration-slice-4.yml`).
     - `tests/smoke/test_slice4_graduation.py` (named test job in `.github/workflows/smoke-slice-4.yml`).
     - The AST guard `tests/unit/_comms_deleted/test_comms_package_absent.py` runs inside the existing unit workflow, so promotion happens automatically through the unit-suite required check.

---

## §5 Risk register

| Risk | Mitigation |
|---|---|
| New consumer of `src/alfred/comms/` lands on `main` between Task 0a and Task 4e | Task 4e is a mandatory re-grep checkpoint; if it finds an unexpected importer, STOP and migrate before Task 5. |
| Textual widget code breaks during the move because of an import the spec did not anticipate | Task 2 runs the full unit suite immediately after the move; any failure surfaces the missed import. The move shape preserves `git log --follow` so widget history is recoverable. |
| 2.5s handshake-probe timeout flakes on slow CI runners | The probe lives in `bin/alfred-plugin-launcher.sh` (PR-S4-6 contract). If the integration test flakes on `ubuntu-latest`, raise it as a follow-up issue against PR-S4-6 — PR-S4-10 inherits the contract and does not modify it. |
| ADR-0009 status header accidentally flipped during the narrowing | Task 6 step 1 names the literal status word that must stay (`Superseded by ADR-0016`). The PR description's "one-time ownership audit" checkbox re-confirms at review time. Reviewer rejection criterion: any change to the `Status:` field text beyond removing the parenthetical qualifier. |
| Smoke test `tests/smoke/test_slice4_graduation.py` exceeds 240s hard budget on CI | Soft 120s / hard 240s budget per perf-007. If the CI runner is consistently slow, the harness in `pytest.fixture(scope="module")` for `compose_stack` reuses the stack across tests within the module — both round-trips share one `compose up`. If still slow, escalate to `alfred-test-engineer` for budget review. |
| Pre-flight grep at Task 0a misses a non-import consumer (e.g. dynamic `importlib.import_module("alfred.comms.X")`) | Task 5's full unit + integration + adversarial run catches dynamic-import consumers — `ModuleNotFoundError` surfaces in the suite. The PR description's "consumer-break worksheet" lists any dynamic-import discoveries. |
| The `plugins/alfred_tui/` test suite needs an MCP-server harness that PR-S4-8 did not ship | If `plugins/alfred_tui/tests/test_server_methods.py` requires a method-listing surface PR-S4-8 did not expose, write a thin local helper at `plugins/alfred_tui/tests/_server_helpers.py` — do not extend `src/alfred/comms_mcp/` from PR-S4-10 (one-time ownership). |
| Windows operators running the rewritten `bin/alfred-setup.ps1` hit a WSL2 install path that has shifted in current Windows builds | The script's error message names the canonical `wsl --install` command. If a Windows-version-specific fix is needed, open a follow-up issue — out of Slice 4's scope. |

---

## §6 Out-of-scope items (deferred from this PR)

| Item | Defer to | Rationale |
|---|---|---|
| ADR-0015 status flip Proposed → Accepted | PR-S4-11 (graduation) | One-time ownership rule (index §3). Status flip mirrors the Slice-3 precedent — graduation PR owns it. |
| ADR-0016 status flip Proposed → Accepted | PR-S4-11 (graduation) | Same as above. |
| `CLAUDE.md` filesystem tree update (`src/alfred/comms/` removal) | PR-S4-11 | Tree updates batch at graduation for consistency across all Slice-4 surface changes. |
| `CLAUDE.md` commands table (new `alfred daemon start/stop/status`) | PR-S4-11 | Same as above. |
| `docs/subsystems/comms.md` authoritative deep-doc | PR-S4-11 | Cannot be authoritative until the in-process Protocol is gone — but the deep-doc write itself is graduation work. |
| `docs/runbooks/slice-4-graduation.md` | PR-S4-11 | Operator-facing migration runbook; ships at graduation. |
| Step-up auth via TUI confirmation prompt | Slice 5+ | PRD §7.1 step-up auth depends on the comms-MCP rewrite being in production; out of scope per spec §1.2. |
| `plugins/alfred_telegram/` (Telegram adapter) | Slice 5+ | Post-MVP; spec §8.1 names the wire surface; the adapter ships in a later slice. |
| `alfred sandbox lint <plugin>` CLI | Slice 5+ | Useful once third-party plugins arrive; deferred per spec §1.2. |

---

## §7 References

### Spec

- `docs/superpowers/specs/2026-06-06-slice-4-design.md` §8.7 — TUI adapter spawned via launcher, daemon-required error.
- `docs/superpowers/specs/2026-06-06-slice-4-design.md` §8.8 — `src/alfred/comms/` deletion, consumer-break matrix.
- `docs/superpowers/specs/2026-06-06-slice-4-design.md` §8.9 — ADR-0009 caveat narrowing + #152 closure.
- `docs/superpowers/specs/2026-06-06-slice-4-design.md` §8.1 — wire contract (consumed by `plugins/alfred_tui/server.py`).
- `docs/superpowers/specs/2026-06-06-slice-4-design.md` §8.10 — audit row family (consumed by the integration test).

### Index + sibling PRs

- `docs/superpowers/plans/2026-06-07-slice-4-index.md` §3 — one-time ownership rules.
- `docs/superpowers/plans/2026-06-07-slice-4-index.md` §4 — integration-test gate (`tests/integration/test_tui_round_trip.py` + `tests/smoke/test_slice4_graduation.py` owned by PR-S4-10).
- `docs/superpowers/plans/2026-06-07-slice-4-pr-s4-6-sandbox-launcher.md` — launcher policy-resolution contract (consumed, not modified).
- `docs/superpowers/plans/2026-06-07-slice-4-pr-s4-8-comms-mcp-foundations.md` — host-side `process_inbound_message`, `AlfredPluginSession` notification dispatcher (consumed).
- `docs/superpowers/plans/2026-06-07-slice-4-pr-s4-9-discord-mcp-adapter.md` — `plugins/alfred_discord/` (referenced by Task 4d's smoke rewrite).
- `docs/superpowers/plans/2026-06-07-slice-4-pr-s4-11-docs-glossary-graduation.md` — receives the ADR-0015/0016 status flips + `CLAUDE.md` updates this PR defers.

### ADRs

- `docs/adr/0009-comms-adapter-protocol-slice2-only.md` — caveat narrowed by Task 6 (NOT status flip).
- `docs/adr/0016-slice4-discord-tui-comms-mcp-rewrite.md` — referenced from the narrowed caveat; status flip is PR-S4-11.
- `docs/adr/0024-comms-mcp-wire-contract.md` (shipped PR-S4-0a) — wire contract consumed by `plugins/alfred_tui/server.py`.

### Subagents

- `.rulesync/subagents/alfred-comms-adapter-engineer.md` — owner of this PR.
- `.rulesync/subagents/alfred-security-engineer.md` — review for trust-tier crossing at `src/alfred/identity/_ingest.py`.
- `.rulesync/subagents/alfred-test-engineer.md` — review for smoke + integration gates.

### Glossary

- `docs/glossary.md` — `addressing signal`, `adapter_id`, `comms-MCP`, `CommsAdapter` (deprecated), `inbound notification`, `keystroke-batch`, `MCP plugin transport`, `outbound message`, `Textual`, `trust tier`.
