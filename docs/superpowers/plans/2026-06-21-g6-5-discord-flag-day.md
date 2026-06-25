# G6-5 — Discord flag-day (gateway-hosted Discord adapter) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.
>
> **This plan is LOCAL-ONLY — do NOT `git add` it** (plan docs are markdownlint-gated in CI + kept out of the merge). Commit only code/docs/tests. **i18n commit type = `feat(i18n):` NOT `i18n:`.** Never markdown-link a gitignored file (`CLAUDE.md` / `AGENTS.md`) — plain code-span only.

**Goal:** The flag-day. Replace the standalone `alfred-discord` Compose service + the `_UnspawnedAdapterChildFactory` placeholder with a REAL bwrap-sandboxed, gateway-hosted Discord adapter child whose bot token flows core-vault → `spawn_grant` → fd-3 (never env, never a Compose `secrets.toml` bind-mount). One slice, no dual-mode: delete the service, build the real factory, migrate the test suite, ship the `alfred gateway adapters --wait-ready` verify command + operator runbook + compose-invariant updates.

**Architecture:** The supervisor (`GatewayAdapterSupervisor`), credential client (`GatewayAdapterCredentialClient`), core resolver (`CoreAdapterCredentialResolver`), ingress gate / leg scheduler / per-leg `ReplayBuffer`, and the `_DeliverCredential` fd-3 hook contract are ALL already built and merged (G6-2/G6-3/G6-4). G6-5 supplies the ONE missing collaborator: a real `_AdapterChildFactoryLike` (`GatewayAdapterChildFactory`) that (a) `os.pipe()`s the fd-3 channel, (b) SYNCHRONOUSLY spawns the Discord adapter through `bin/alfred-plugin-launcher.sh` (`kind="full"` → bwrap) using the EXACT dup2→Popen→restore "no-await-while-fd3-clobbered" discipline from `src/alfred/security/quarantine_child_io.py`, (c) invokes the supervisor's `deliver_credential(write_fd)` hook AFTER the clobber window closes and BEFORE the handshake, (d) runs the `CommsPluginRunner` + `CommsStdioTransport` handshake, and (e) returns an `_AdapterChildLike` whose `wait_until_exit()` awaits the child process. The Discord adapter child stops self-brokering its token (`DiscordLifecycle.start`) and reads it from fd-3. The gateway is wired with a non-empty `adapter_ids` set sourced from `settings.comms_enabled_adapters`. The standalone Compose service + the daemon-spawned Discord path are deleted in the same slice.

**Tech Stack:** Python 3.12+, asyncio, Pydantic v2, structlog, the bwrap launcher (`bin/alfred-plugin-launcher.sh`, `sandbox.kind="full"`), `subprocess.Popen` (synchronous spawn-window discipline), `prometheus_client`. The real-spawn + `/proc` negative integration runs on the REQUIRED privileged Linux lane (`integration-privileged`, mirroring `test_daemon_comms_flip_real_spawn.py` / `test_quarantine_child_real_spawn.py`); every wire contract it proves also has a non-root in-process companion test on the required `integration`/`unit` gate (the #245 paper-gate lesson). Adversarial corpus entries (a) cross-adapter cred isolation, (b) no-retained-cred + `/proc` env-absence, (g) per-adapter serial-harvest visibility ship as the Discord-real-child realization of the G6-3 corpus.

---

## Context the implementer MUST hold (verified against `main` @ G6-4 merge)

- **The ONLY placeholder G6-5 replaces** is `_UnspawnedAdapterChildFactory` in `src/alfred/gateway/process.py` (it raises `GatewayAdapterSpawnError` unconditionally). Everything else the factory plugs into is real and merged:
  - `GatewayAdapterSupervisor` (`src/alfred/gateway/adapter_supervisor.py`) — the `_AdapterChildFactoryLike` Protocol is `async def spawn_and_handshake(*, adapter_id: str, epoch: str, deliver_credential: _DeliverCredential) -> _AdapterChildLike`. The G6-5 implementer contract is in that docstring: a `CredentialLegDownError`/`AdapterCredentialError` from `deliver_credential` MUST propagate UNWRAPPED; wrap ONLY a genuine spawn/handshake fault as `GatewayAdapterSpawnError`.
  - `_DeliverCredential = Callable[[int], Awaitable[None]]` — the supervisor hands the factory a closure that runs `acquire_and_deliver(adapter_id, host_restart_seq, write_fd, epoch)`. The factory calls it with the fd-3 WRITE END after the clobber window closes, before handshake.
  - `GatewayAdapterCredentialClient.acquire_and_deliver` (`src/alfred/gateway/adapter_credential_client.py`) — already does the round-trip + grant-verify + `deliver_provider_key_via_fd3(write_fd=…, key=grant.credential_material)` + closes `write_fd` on every path. **The factory does NOT touch the credential; it only creates the pipe and calls the hook.**
  - `CoreAdapterCredentialResolver` (`src/alfred/comms_mcp/adapter_credential_resolver.py`) — `_ADAPTER_SECRET_ALLOWLIST = {"discord": "discord_bot_token"}` is ALREADY present. Wired in `_build_comms_boot_graph`, routed by `CommsPluginRunner._route_spawn_request`. **No core-side credential work needed in G6-5.**
- **The fd-3 + bwrap spawn pattern to MIRROR** is `src/alfred/security/quarantine_child_io.py::spawn_quarantine_child_io`: `os.pipe()` → `os.set_inheritable(read_fd, True)` → save prior fd3 → **`os.dup2(read_fd, 3)` opens the clobber window** → SYNCHRONOUS `subprocess.Popen([launcher, plugin_id, python, "-m", module], stdin/stdout/stderr=PIPE, env=_child_env(), pass_fds=(3,))` (NO `await` inside the window — the loop's selector fd is commonly fd 3; an `await` polls a dead selector → `OSError [Errno 22]`) → `finally` restores fd3 + closes read_fd (window CLOSES) → THEN `deliver_provider_key_via_fd3(write_fd=…, key=…)`. **G6-5 needs an ADAPTER variant** (different plugin_id/module, the credential delivered via the supervisor's hook not inline, wrapped in a `CommsPluginRunner` not a `_SubprocessChildIO`). DO NOT reimplement the dup2 discipline from scratch — factor the shared spawn-window primitive or copy it verbatim with the same comments.
- **`deliver_provider_key_via_fd3`** is `src/alfred/supervisor/fd3_key_delivery.py` — keyword-only `(*, write_fd: int, key: str) -> None`, builds + zeroes its OWN internal bytearray, closes `write_fd` on every path. REUSE (the credential client already does).
- **The Discord child token self-broker to CHANGE** is `plugins/alfred_discord/lifecycle.py::DiscordLifecycle.start` (`token = self._broker.get(_BROKER_KEY)`, `_BROKER_KEY = "discord_bot_token"`). Under core-injects-at-spawn the child reads fd-3 instead. Preserve the `ok=False`-never-raise wire contract + the never-log-the-token discipline.
- **The real runner/transport build to REUSE** is `CommsStdioTransport` (`src/alfred/plugins/comms_stdio_transport.py`) + `CommsPluginRunner` (`src/alfred/plugins/comms_runner.py`) + the daemon's `_build_comms_runner` (`src/alfred/cli/daemon/_commands.py`). NOTE `CommsStdioTransport.spawn()` spawns via the launcher with a SCRUBBED env but names the provider-key fd via env (`ALFRED_PROVIDER_KEY_FD`), it does NOT do literal-fd-3 dup2. The GATEWAY adapter child needs the LITERAL-fd-3 + dup2 discipline (the quarantine pattern), NOT `CommsStdioTransport.spawn()`'s env-named-fd path. **Central foundation seam — see FOUNDATION GAP #2.**
- **The launcher + the Discord sandbox policy bytes EXIST:** `bin/alfred-plugin-launcher.sh`, `config/sandbox/discord-adapter.{linux.bwrap.policy,macos.sb,windows.stub.policy}`. The manifest `plugins/alfred_discord/manifest.toml` declares `[sandbox] kind = "full"`, `id = "alfred.discord"`, `[secrets] discord_bot_token = "*"`, per-OS `policy_refs`. Egress enforcement deferred to #230 (interim-egress posture stands, NOT G6-5 scope).
- **`adapter_ids` is hardcoded EMPTY today:** `GatewayProcess.__init__(adapter_ids=…)` defaults to `[]`; `src/alfred/cli/gateway/_commands.py` constructs `GatewayProcess` WITHOUT passing `adapter_ids`. `supervise_all([])` is a clean no-op. G6-5 sources the set from `settings.comms_enabled_adapters` (`src/alfred/config/settings.py`, env `ALFRED_COMMS_ENABLED_ADAPTERS`).
- **The `alfred gateway adapters` subcommand does NOT exist** (`src/alfred/cli/gateway/__init__.py` has only `start`/`status`/`healthcheck`). The ADR-0038 control router (`src/alfred/cli/daemon/_daemon_control_{client,server,protocol}.py`) is the DAEMON↔CLI socket — see FOUNDATION GAP #3.
- **The K7 restart-survival harness** (`tests/integration/test_gateway_leg_restart_survival.py` + `_gateway_restart_harness.py`) proves the TUI leg with a FAKE child. K7 EXPLICITLY DEFERRED "real supervised child / session held across a core bounce" to G6-5/G6-6. G6-5 ships the real-child restart-survival proof on the privileged lane; the full adversarial restart corpus is G6-6.
- **The adversarial corpus (a/b/e)** exists at `tests/adversarial/comms/test_gateway_credential_corpus.py` (gated required in `ci.yml` via `tests/adversarial/comms`). G6-5 ADDS the real-Discord-child realization of (a)/(b)/(g) on the privileged lane — NOT a rewrite of the in-process corpus.
- **i18n reserve:** `src/alfred/i18n/_spec_b_reserve.py::_register`. New G6-5 operator strings go through `t()` + a reservation here + `alfred.po`/`.mo` (`pybabel update --no-fuzzy-matching`, NEVER `--omit-header`).
- **ci.yml two-gate sites** (per-file 100% coverage): the python-job hashFiles guard + the `coverage-gates` `--include=` list BOTH enumerate every `src/alfred/gateway/*.py`. A new trust-boundary module (the child factory) MUST be added to BOTH. `comms_runner.py`/`comms_stdio_transport.py` are in the plugins gate.

### Scope guards

- **IN:** the real `GatewayAdapterChildFactory` (bwrap spawn + fd-3 dup2 discipline + `deliver_credential` hook sequencing + `CommsPluginRunner` handshake + `wait_until_exit`); wiring it into `GatewayProcess` (replace `_UnspawnedAdapterChildFactory`); sourcing `adapter_ids` from `settings.comms_enabled_adapters`; the Discord child fd-3 token read (stop self-brokering); deleting the `alfred-discord` Compose service; rewiring the secret path (core-side `discord_bot_token`; delete the standalone `secrets.toml` bind-mount); the `alfred gateway adapters --wait-ready` CLI; migrating the ~20-file Discord test suite; setup-script + runbook + compose-invariant updates; per-leg BINDING ingress config for the real Discord leg (replacing the non-binding TUI defaults); the privileged-lane real-spawn + `/proc` negative + non-root companions; adversarial (a)/(b)/(g) real-child realization; ADR-0036/0015 annotations + `docs/subsystems/comms.md` + README + the human-gated `CLAUDE.md` command-row note.
- **OUT (deferred):** real persona-outbound reply (fixed-ack stub, #235). Telegram (#40). Egress chokepoint / connectivity-free core / SCM_RIGHTS core→child fd-pass (Spec C). The full adversarial restart corpus + whole-`adversarial.yml`-to-required promotion (G6-6). The Discord-only egress allowlist enforcement (#230).

---

## File structure

**Created:**

- `src/alfred/gateway/adapter_child_factory.py` — `GatewayAdapterChildFactory` (satisfies `_AdapterChildFactoryLike`): `spawn_and_handshake(*, adapter_id, epoch, deliver_credential)`. Owns `os.pipe()` (read-end → child literal fd 3), the synchronous dup2→Popen→restore spawn window, invokes `deliver_credential(write_fd)` after the window closes / before handshake, builds the `CommsStdioTransport`-over-the-spawned-`Popen` + `CommsPluginRunner`, runs `start_and_handshake`, returns a `_GatewayAdapterChild` whose `wait_until_exit()` awaits the `Popen`. Resolves `adapter_id → (plugin_id, module, policy)` via a closed static map (`discord → alfred.discord / plugins.alfred_discord.server`). Fail-closed: a launcher/handshake fault → `GatewayAdapterSpawnError`; a credential exception from the hook → propagate UNWRAPPED.
- `src/alfred/gateway/_adapter_spawn_window.py` (OPTIONAL — only if the dup2 primitive is factored out of `quarantine_child_io` to share — see GAP-2). Else copy the discipline verbatim into `adapter_child_factory.py` with the same load-bearing comments.
- `src/alfred/cli/gateway/_adapters.py` (or extend `src/alfred/cli/gateway/_commands.py`) — the `alfred gateway adapters [--wait-ready] [--timeout N]` command body: bounded-wait poll of the gateway's per-adapter `up` state, FRIENDLY operator output via `t()`, defined exit-code contract (mirror the deleted Discord-verify 0/1/2/3 remediation-naming), loud failure past the timeout.
- Tests: `tests/unit/gateway/test_adapter_child_factory.py`; `tests/unit/cli/gateway/test_adapters_wait_ready.py`; `tests/unit/discord/test_lifecycle_reads_fd3_token.py`; `tests/integration/test_gateway_discord_real_spawn.py` (PRIVILEGED LANE); `tests/integration/test_gateway_discord_leg_restart_survival.py` (PRIVILEGED LANE) + a non-root in-process companion canary; adversarial (a)/(b)/(g) real-child additions in `tests/adversarial/comms/test_gateway_credential_corpus.py`.

**Modified:**

- `src/alfred/gateway/process.py` — DELETE `_UnspawnedAdapterChildFactory`; `_build_adapter_supervisor` constructs `GatewayAdapterChildFactory(...)` (same `credential_client`); per-leg BINDING ingress gate / `ReplayBuffer` / scheduler registration extended from the single TUI leg to ALSO build one binding-config leg per `adapter_id`; `__all__` drops `_UnspawnedAdapterChildFactory`.
- `src/alfred/cli/gateway/_commands.py` — pass `adapter_ids` from `Settings().comms_enabled_adapters` (gateway-hosted subset; `tui` stays the dial-in leg, not a spawned adapter).
- `src/alfred/cli/gateway/__init__.py` — register the `adapters` subcommand.
- `plugins/alfred_discord/lifecycle.py` — `DiscordLifecycle.start` reads the token from fd 3 (`_fd3_token_source`) instead of the broker; preserve `ok=False`-never-raise + never-log-token.
- `plugins/alfred_discord/server.py` — wire the fd-3 token source into `DiscordLifecycle` construction.
- `docker-compose.yaml` — DELETE the entire `alfred-discord:` service (command/depends_on/mem_limit/env/secrets.toml bind-mount/`ALFRED_SECRETS_FILE`). VERIFY the core-side `discord_bot_token` source exists or ADD it (GAP-4).
- `tests/unit/test_compose_invariants.py` — DELETE the now-vacuous `test_alfred_discord_has_no_setuid` + `test_alfred_discord_has_no_state_git_volume`; ADD `test_alfred_discord_service_is_deleted`; confirm the positive allowed-set tests (`{core, gateway}`) still pass.
- `bin/alfred-setup.sh` + `bin/alfred-setup.ps1` — DELETE the `docker compose run --rm alfred-discord verify` step + the alfred-discord echo; REPLACE with `alfred gateway adapters --wait-ready discord`; add a legacy-config detector; re-point the `discord_bot_token` guidance to the core-vault path.
- `docs/runbooks/g6-5-discord-flag-day-migration.md` (new) — operator migration runbook.
- `docs/subsystems/comms.md`, `docs/adr/0036-...md` (dated annotation), `docs/adr/0015-...md` (gateway as a second bwrap-launcher host), `README.md`.
- `src/alfred/i18n/_spec_b_reserve.py` + `alfred.po` + `.mo` — new `gateway.adapters.*` keys.
- `.github/workflows/ci.yml` — add `adapter_child_factory.py` (+ `_adapter_spawn_window.py` if created) to BOTH gate sites + both hashFiles guards; add the privileged-lane real-spawn + `/proc` negative + adversarial real-child additions to the required `integration-privileged` leg.

---

## Tasks (TDD; each: failing test → RED → minimal impl → GREEN → commit `type(scope): description (Spec B G6-5, #288)` + trailer)

### Task 1 — Discord child reads its token from fd-3 (stop self-brokering)

Add a fd-3 token-source seam to `plugins/alfred_discord/lifecycle.py`: `DiscordLifecycle.start` reads the bot token via an injected `_TokenSource` (default: a length-prefixed `os.read(3)` reader mirroring the child side of `deliver_provider_key_via_fd3`) instead of `self._broker.get("discord_bot_token")`. Preserve `ok=False`-never-raise + never-log-token. RED: `tests/unit/discord/test_lifecycle_reads_fd3_token.py` — start consumes the fd-3 token (fake source) → `connect(token)` called with it; a missing/torn fd-3 read → `ok=False` (never raises); the token never appears in `capture_logs`; the broker is NOT called for the token. Commit `feat(discord): read bot token from fd-3 not the broker (Spec B G6-5, #288)`.

### Task 2 — wire the fd-3 token source into the Discord server construction

In `plugins/alfred_discord/server.py`, construct `DiscordLifecycle` with the fd-3 token source (replacing the broker injection for the token). RED: a server-construction unit test asserts the lifecycle is built with the fd-3 source and no broker-token dependency remains. Commit `feat(discord): wire fd-3 token source into the adapter server (Spec B G6-5, #288)`.

### Task 3 — the synchronous fd-3-clobber spawn window (shared primitive)

Create `src/alfred/gateway/_adapter_spawn_window.py` (or factor `quarantine_child_io`'s window into a shared helper — DECIDE in plan-review, GAP-2): `spawn_child_with_fd3(*, argv, env) -> tuple[subprocess.Popen, int]` returning the live `Popen` + the fd-3 WRITE end, doing the EXACT `os.pipe → set_inheritable → save fd3 → dup2(read_fd,3) → SYNCHRONOUS Popen(pass_fds=(3,)) → finally restore/close` discipline with the load-bearing "NO `await` in the window" comments. RED: `tests/unit/gateway/test_adapter_spawn_window.py` — no `await` in the window; the child inherits fd 3; the parent fd 3 is restored; a `Popen` `OSError` → loud. Commit `feat(gateway): synchronous fd-3-clobber spawn-window primitive for adapter children (Spec B G6-5, #288)`.

### Task 4 — `GatewayAdapterChildFactory`: spawn + fd-3 hook sequencing + handshake (fake launcher)

Create `src/alfred/gateway/adapter_child_factory.py`. `spawn_and_handshake(*, adapter_id, epoch, deliver_credential)`: resolve `adapter_id → (plugin_id, module)` via a CLOSED static map (`discord` only — unknown id → `GatewayAdapterSpawnError`); spawn via Task-3's window; AFTER the window closes / BEFORE handshake call `await deliver_credential(write_fd)`; build `CommsStdioTransport`-over-the-`Popen` + `CommsPluginRunner`; `await runner.start_and_handshake()`; return a `_GatewayAdapterChild` whose `wait_until_exit()` awaits the `Popen`. RED: `tests/unit/gateway/test_adapter_child_factory.py` (fake spawn-window + fake `deliver_credential` + fake runner) — hook called with the write end AFTER the window / BEFORE handshake; a `CredentialLegDownError`/`AdapterCredentialError` from the hook propagates UNWRAPPED; a launcher/handshake fault → `GatewayAdapterSpawnError`; an unknown adapter_id → `GatewayAdapterSpawnError`; `wait_until_exit` awaits the child. Commit `feat(gateway): real bwrap adapter-child factory (Spec B G6-5, #288)`.

### Task 5 — wire the real factory into `GatewayProcess` (delete the placeholder)

In `src/alfred/gateway/process.py`: DELETE `_UnspawnedAdapterChildFactory`; `_build_adapter_supervisor` constructs `GatewayAdapterChildFactory(...)` (same `credential_client`); drop it from `__all__`. RED: `tests/unit/gateway/test_process_supervisor_wiring.py` (extend) — the supervisor is built with the real factory; the placeholder is gone; a non-empty `adapter_ids` no longer fails loud at the placeholder. Commit `refactor(gateway): host the real adapter-child factory, retire the placeholder (Spec B G6-5, #288)`.

### Task 6 — per-leg binding ingress config for the real Discord leg

Extend `GatewayProcess` to build, per `adapter_id`, a BINDING `PerAdapterIngressGate` + `ReplayBuffer` + scheduler registration (real sustained-rate/burst/max_inflight/max_frame_bytes defaults; the TUI leg keeps its non-binding config). Reap per leg on every exit. RED: `tests/unit/gateway/test_process_adapter_legs.py` — a Discord leg gets a binding gate (rate/inflight/size enforced, distinct from the TUI's non-binding sentinels); the TUI leg is unchanged; both legs reaped on shutdown; the K4 forged-`adapter_id` refusal still holds for the multi-leg router. Commit `feat(gateway): binding ingress config per hosted adapter leg (Spec B G6-5, #288)`.

### Task 7 — source `adapter_ids` from settings (gateway boots Discord)

In `src/alfred/cli/gateway/_commands.py`, pass `adapter_ids` from `Settings().comms_enabled_adapters` (gateway-hosted subset; `tui` excluded). RED: `tests/unit/cli/gateway/test_gateway_start_adapter_ids.py` — `comms_enabled_adapters=("discord",)` → `GatewayProcess` constructed with `adapter_ids=["discord"]`; empty/`tui`-only → empty spawned set. Commit `feat(gateway): boot the gateway with the configured hosted adapter set (Spec B G6-5, #288)`.

### Task 8 — `alfred gateway adapters --wait-ready` (ADR-0038 control reuse or gateway surface)

Add the `adapters` subcommand. `--wait-ready [adapter]` polls the gateway's per-adapter `up` state until ready or a bounded `--timeout`, FRIENDLY `t()` output, a defined exit-code contract (0 ready / 1 not-ready-timeout / 2 gateway-unavailable / 3 unknown-adapter), loud on timeout. Reuse the ADR-0038 control router if the gateway exposes adapter state there; ELSE add a minimal gateway-side status read (GAP-3). RED: `tests/unit/cli/gateway/test_adapters_wait_ready.py` — ready → exit 0; timeout → distinct non-zero + loud `t()`; unavailable → exit 2; unknown adapter → exit 3; assertions key on `t()` keys / canonical IDs, never raw English. Commit `feat(gateway): adapters --wait-ready verify command (Spec B G6-5, #288)`.

### Task 9 — i18n for the new operator strings

Reserve `gateway.adapters.*` / `gateway.adapters.wait_ready.*` in `_spec_b_reserve.py::_register`; add msgids to `alfred.po`; `pybabel update --no-fuzzy-matching` (NEVER `--omit-header`) + `pybabel compile`. RED: the i18n-drift check is GREEN; a test asserts each new `t()` key resolves. Commit `feat(i18n): gateway adapters verify + flag-day operator strings (Spec B G6-5, #288)`.

### Task 10 — migrate the Discord test suite (survive / re-point / rewrite per the table below)

Walk EVERY Discord test file; assign each: *survives-unchanged* (wire-contract: message surface, addressing, thread continuity, sub-payload promotion, in-plugin DLP/rate-limit/idempotency units, the prompt-injection corpus), *re-pointed-to-gateway-harness* (lifecycle/health, server-dispatch, the `alfred discord` CLI → `alfred gateway adapters`, sandbox-policy resolution now via the gateway factory), or *rewritten-to-the-new-auth-model* (the capability-grant model: ADR-0027 daemon LOAD-grant → gateway-spawn + core-injected-cred — `test_comms_adapter_grants.py` + `test_daemon_comms_spawn.py`). NO coverage loss — assertions preserved. Delete the dead `src/alfred/cli/discord_cmd.py` + its test IF the `alfred discord` standalone path is retired (VERIFY no other caller). RED→GREEN per migrated file; commit in coherent batches.

### Task 11 — delete the `alfred-discord` Compose service + compose-invariant update

DELETE the `alfred-discord:` service from `docker-compose.yaml`. In `tests/unit/test_compose_invariants.py`: DELETE the now-vacuous Discord-specific negatives; ADD `test_alfred_discord_service_is_deleted`; confirm `test_setuid_allowed_set_is_core_and_gateway` + `test_bwrap_security_opt_set_is_core_and_gateway` still pass. RED: the new deletion test fails first, then passes after deletion. Commit `chore(compose): delete the standalone alfred-discord service (Spec B G6-5, #288)`.

### Task 12 — rewire the secret path (core-vault `discord_bot_token`; delete the bind-mount)

VERIFY the core-side `discord_bot_token` source: the resolver reads it via `SecretBroker.get("discord_bot_token")` on the CORE — confirm the daemon/core mounts a secrets source carrying it (`_PREFER_FILE`). If `secrets.toml` was the only source, ADD a core-side mount/broker entry (GAP-4 — NEW work, not a deletion). Remove the `ALFRED_SECRETS_FILE`/`secrets.toml` bind-mount; ensure NO platform secret is bind-mounted into the gateway. RED: `tests/unit/cli/daemon/test_core_resolves_discord_token.py` — the core resolver reads `discord_bot_token` from the core secret source; the gateway mounts no secret. Commit `feat(secrets): route the Discord token through the core vault for spawn-grant (Spec B G6-5, #288)`.

### Task 13 — setup script + migration runbook

`bin/alfred-setup.sh` + `.ps1`: delete the `docker compose run --rm alfred-discord verify` step + the echo; replace with `alfred gateway adapters --wait-ready discord`; add a legacy-`alfred-discord`-config detector; re-point the `discord_bot_token` guidance to the core-vault path. Write `docs/runbooks/g6-5-discord-flag-day-migration.md`. RED: a shell-grep test — the setup script no longer references `alfred-discord verify`; it references `gateway adapters --wait-ready`. Commit `feat(setup): gateway-adapter verify replaces the alfred-discord verify (Spec B G6-5, #288)` + `docs(runbook): operator migration for the Discord flag-day (Spec B G6-5, #288)`.

### Task 14 — privileged-lane real Discord spawn + `/proc` env-absence negative (REQUIRED gate)

`tests/integration/test_gateway_discord_real_spawn.py` (mirror `test_daemon_comms_flip_real_spawn.py` provisioning — bound interpreter, `skipif` non-Linux/non-root/unprovisioned): the REAL `GatewayAdapterChildFactory` spawns the Discord child via the launcher (`kind="full"` → bwrap) with a real fd-3 token delivery + a MOCK Discord gateway; assert (i) the child receives the token over fd 3 and reaches `up`; (ii) the token is ABSENT from `/proc/<pid>/environ`; (iii) a non-root in-process COMPANION proves the env-dict carries no token / no `*_TOKEN` key on the required lane. Add the privileged test to the `integration-privileged` leg + a collected-and-run non-root canary (#245). RED on the privileged lane (reproduce via `docker run --rm --privileged --platform linux/amd64 debian:bookworm`). Commit `test(gateway): real bwrap Discord spawn + /proc token-absence negative (Spec B G6-5, #288)`.

### Task 15 — real Discord leg restart-survival (the K7-deferred proof) + adversarial (a)/(b)/(g) real-child

`tests/integration/test_gateway_discord_leg_restart_survival.py` (privileged lane): a real Discord leg held across a core bounce, its un-acked inbound replayed EXACTLY ONCE (G0 dedup), two-phase pre-`ready`-refused / post-`ready`-accepted barrier (NOT a sleep). Extend `tests/adversarial/comms/test_gateway_credential_corpus.py` with the privileged-lane real-child (a) cross-adapter `os.read` of another child's fd-3 → refused; (b) `/proc` token-absence + no-retained-cred; (g) per-adapter grant + audited. RED on the privileged lane. Commit `test(gateway): real Discord restart-survival + adversarial real-child corpus (Spec B G6-5, #288)`.

### Task 16 — docs (ADR / comms subsystem / README / CLAUDE.md row note) + full quality bar

Annotate `docs/adr/0036-...md` (dated `> **G6-5 annotation (#288):** …`) + `docs/adr/0015-...md`. Update `docs/subsystems/comms.md`, `README.md`. Add the human-gated `CLAUDE.md` command-table `alfred gateway adapters` row (plain code-span, NO markdown-link to `CLAUDE.md`) — propose, do not self-approve. Add `adapter_child_factory.py` (+ the spawn-window module if created) to BOTH `ci.yml` per-file 100% gate sites. Full quality bar: `uv run ruff check . && uv run ruff format --check .`; `uv run mypy src/ && uv run pyright src/`; the EXACT `coverage-gates` run with the new modules at 100% branch; FULL `uv run pytest tests/unit -q`; the privileged-lane real-spawn integration green; `pybabel update --check` green; markdownlint on the committed docs. Commit `docs(gateway): flag-day docs + ADR annotations + CI gates (Spec B G6-5, #288)`.

---

## Test-migration table (Task 10 — every Discord test file, assigned)

| File | Disposition |
| --- | --- |
| `tests/integration/test_discord_message_surface.py` | survives (wire contract, host-side) |
| `tests/integration/test_discord_addressing_modes.py` | survives (addressing, host-side) |
| `tests/integration/test_discord_thread_continuity.py` | survives (thread continuity, host-side) |
| `tests/integration/test_discord_subpayload_promotion.py` | survives (host-side promotion) |
| `tests/integration/test_discord_rate_limit_pause_resume.py` | survives or re-point (verify the adapter-construction seam) |
| `tests/unit/plugins/alfred_discord/test_lifecycle_health.py` | re-point (fd-3 token; gateway-hosted lifecycle) |
| `tests/unit/plugins/alfred_discord/test_server_dispatch.py` / `test_server_outbound_wired.py` | re-point (server construction with fd-3 source) |
| `tests/unit/plugins/alfred_discord/test_gateway_adapter.py`, `test_*emitter*`, `test_idempotency_store.py`, `test_addressing_inference.py`, `test_manifest_shape.py`, `test_notifications_serialise.py`, `test_outbound_handler.py`, `test_discord_gateway_reconnect.py` | survives (in-plugin units, transport-agnostic) |
| `tests/unit/discord/test_in_plugin_dlp_lite.py`, `test_rate_limit_signal_blocks_outbound.py`, `test_language_field_populated.py`, `test_no_ad_hoc_mocks.py` | survives |
| `tests/unit/plugins/test_discord_adapter_sandbox_policy.py` | survives (policy bytes unchanged; the gateway factory resolves the SAME policy_refs) |
| `tests/unit/cli/test_discord_cmd_launcher.py` + `src/alfred/cli/discord_cmd.py` | rewrite/retire → `alfred gateway adapters` (verify no other caller; delete if dead) |
| `tests/unit/cli/daemon/test_daemon_comms_spawn.py` | rewrite (daemon no longer spawns Discord; the gateway does) — preserve fail-closed assertions against the gateway path |
| `tests/unit/security/capability_gate/test_comms_adapter_grants.py` | rewrite to the gateway-spawn + core-injected-cred model (no coverage loss) |
| `tests/smoke/test_discord_gateway_smoke.py` | re-point to the gateway-hosted smoke (or retire-with-replacement) |
| `tests/adversarial/prompt_injection/pi-2026-005..013-discord-*` + `test_discord_subpayload_injection_executable.py` | survives (host-side T3 extraction unchanged) |
| `tests/adversarial/comms_identity_boundary/*` | survives (host-side identity boundary unchanged) |
| `tests/support/discord_mocks.py` | survives / extend (mock Discord gateway for the real-spawn test) |

---

## Self-review checklist (run before plan-review)

- The factory NEVER touches the credential — it creates the pipe + calls `deliver_credential(write_fd)`; the client owns + delivers + zeroes (DRY on the G6-3 security primitive).
- The fd-3-clobber window has ZERO `await` (the `[Errno 22]` regression guard); the credential crosses ONLY fd 3, never env (HARD rule #6); `/proc/<pid>/environ` token-absence negative on the privileged lane + a non-root env-dict companion (#245 guard).
- Flag-day: the `alfred-discord` deletion + the gateway-hosted path land in the SAME slice; no dual-mode; the compose-invariant set stays `{core, gateway}`.
- Credential exceptions from the hook propagate UNWRAPPED; only a genuine spawn/handshake fault → `GatewayAdapterSpawnError`.
- Payload-blind (#5); fail-loud (#7) on launcher/handshake/cred fail + `--wait-ready` timeout.
- Tests assert via `t()` keys / canonical IDs, never raw English; i18n via `feat(i18n):` + reserve + `--no-fuzzy-matching`.
- New trust-boundary module in BOTH ci.yml per-file 100% gate sites + the privileged-lane real-spawn in the required `integration-privileged` leg.
- No coverage loss in the migrated Discord suite; the capability-grant tests are REWRITTEN to the new model, not retired.

## PRECURSOR / BLOCKED flags (resolve in plan-review before Task-1 RED)

- **GAP-2 (the keystone):** factor the dup2 spawn-window out of `quarantine_child_io` (DRY) vs copy it into the gateway (subsystem separation). Maintainer call.
- **GAP-3:** confirm `--wait-ready` reuses the ADR-0038 daemon-control router vs a gateway-side status read (the gateway has its own socket, not the daemon-control socket).
- **GAP-4:** confirm the core-side `discord_bot_token` secret source exists daemon-side; if the standalone `secrets.toml` was the only source, Task 12 ADDS a core mount/broker entry (NEW work).

---

## Plan-review corrections (MUST apply — architect + security + core-engineer + test-engineer, 2026-06-21)

All 4 returned approve-with-changes. These OVERRIDE conflicting earlier task text. The fleet found a CRITICAL the plan filed as a "reuse" (the runner owns the spawn), a CRITICAL paper-gate (the privileged lane isn't actually required), the GAP-4 cutover ordering, an under-specified child-reaping lifecycle, and test-migration omissions. Resolve C-items before Task-1 RED.

### GAP RULINGS (final)

- **GAP-2 → COPY the ~15-line fd-3 dup2 window verbatim into the factory** (with the identical load-bearing `[Errno 22]`/`pass_fds=(3,)`/save-restore comments) + a SHARED property test (`no await in window`, `child inherits fd3`, `parent fd3 restored`) parametrized over BOTH spawn sites. Do NOT factor it out of `quarantine_child_io.py`. (Security + test ruled copy; architect + core preferred factor — 2-2; resolved to COPY: it keeps the most-adversary-facing merged module + its per-file 100% gate UNTOUCHED, and the shared property test achieves the anti-drift goal without the blast radius. **DROP plan Task 3's separate module; fold the copied window into Task 4.**)
- **GAP-3 → REUSE the ADR-0038 daemon-control `status.query` client (poll loop); STRIKE the "gateway-side read" fallback.** The daemon's `AdapterStatusObserver.all_latest()` holds the gateway-reported per-adapter status (ADR-0036 inversion); ADR-0038 §Consequences names this exact command. The gateway's own socket is single-accept-for-life (undiallable). `alfred gateway adapters --wait-ready` is ergonomically under `gateway` but READS via the daemon-control client. **VERIFY `AdapterStatusObserver`/`status.query` exposes a per-adapter `up`/`ready` field during impl** (if not, add it to the observer's status shape — small precursor).
- **GAP-4 → CRITICAL, NEW work:** the `alfred-core` service has NO `secrets.toml` bind-mount / `ALFRED_SECRETS_FILE` today (only `alfred-discord` does); `discord_bot_token` is `_PREFER_FILE`. Task 12 MUST ADD `ALFRED_SECRETS_FILE=/etc/alfred/secrets.toml` + the `secrets.toml:ro` bind to `alfred-core` (gateway mounts NO secret), and this core-add MUST be a PREREQUISITE of Task 11's service-delete (else the privileged real-spawn proof can't resolve the token + Discord goes dark on merge). One commit, no window; positive test (core mounts it, gateway does NOT) + the core-resolves-token RED.

### CRITICAL

- **C1 (core) — NEW Popen-backed transport, NOT a reuse.** `CommsPluginRunner.start_and_handshake()` calls `transport.spawn()` itself (`comms_runner.py:394`), and `CommsStdioTransport.spawn()` (`comms_stdio_transport.py:142`) creates the child via `create_subprocess_exec` (env-named fd, no literal fd-3). The plan's "build `CommsStdioTransport` over the already-spawned Popen + call `start_and_handshake`" would spawn a SECOND child / error. **Add an explicit task (new Task 4a):** build `GatewayAdapterStdioTransport` implementing `_CommsTransportLike` with a NO-OP `spawn()` and `read_frame`/`send`/`close` over the already-live `subprocess.Popen` pipes using the `run_in_executor` blocking-read pattern (mirror `quarantine_child_io._SubprocessChildIO` — `Popen` gives RAW pipes, NOT an asyncio `StreamReader`; a `StreamReader`/`connect_read_pipe` over Popen fds is the [Errno 22] footgun). The factory spawns via the copied window → `await deliver_credential(write_fd)` → wraps the Popen in `GatewayAdapterStdioTransport` → builds `CommsPluginRunner` → `await runner.start_and_handshake()` (its `spawn()` no-ops, the handshake runs).
- **C2 (test) — the privileged lane is NOT a required check today.** `docs/ci/required-checks.md` lists `integration-privileged` as "Pending required / PROPOSED REQUIRED" — NOT in branch protection. The plan falsely calls it REQUIRED (Tech-Stack, Tasks 14/15, self-review) → Tasks 14/15 would gate NOTHING (#245 paper-gate). **Fix:** (i) the gating PROPERTY for each real-child proof MUST also be proven by a NON-ROOT in-process companion on an ALREADY-required lane (`unit`/`integration`); (ii) Task 16 VERIFIES the actual branch-protection state and either tracks/surfaces the `integration-privileged` promotion as a governance follow-up OR (if already promoted per #250/2b0 — RECONCILE the doc vs reality) corrects the doc. Do NOT claim "required" without verifying `gh api .../branches/main/protection`.
- **C3 (test) — `test_lifecycle_health.py` re-point must PRESERVE the token-never-logged threat assertion against the NEW fd-3 source AND assert the broker is NOT called for the token** (a lingering `broker.get(token)` = a dual-source regression). State this in the Task-10 table entry, not just "re-point".

### HIGH

- **H1 (security+core) — child-reaping lifecycle (under-specified).** The Discord child blocks on `os.read(3)` until delivery; if the factory faults BEFORE the hook (launcher fault), the half-spawned child wedges. AND the supervisor's restart/crash loop does NOT close the returned child today (the fake child just exits) → bwrap children LEAK across crash-loops. Task 4 acceptance MUST: (a) `_terminate_and_reap` the child on ANY pre-handshake fault (mirror `quarantine_child_io`'s terminate-on-fail) before raising `GatewayAdapterSpawnError`; (b) give `_GatewayAdapterChild` a teardown/reap method the supervisor calls on the restart/crash path (add the hook to the supervisor loop if absent); (c) make `wait_until_exit` cancellation-safe (`run_in_executor(None, proc.wait)`; the executor wait keeps running on cancel → the child reaps on its OWN teardown, not the cancelled task). Tests for all three.
- **H2 (test) — `test_comms_adapter_grants.py` rewrite is a coverage-loss trap on a per-file 100% gate** (`src/alfred/security/capability_gate/_comms_adapter_grants.py`, named in BOTH ci.yml gate sites). Task 10 MUST: spell out the post-rewrite branch inventory; re-anchor the builder's coverage on the SURVIVING reference adapter (`alfred_comms_test`) rather than silently dropping the Discord cases; state explicitly whether Discord's ADR-0027 daemon LOAD-grant is REMOVED (gateway-spawn replaces it) or RETAINED-alongside; re-run that module's exact `--include … --fail-under=100` gate as a RED/GREEN checkpoint. (Note `_ADAPTER_SECRET_ALLOWLIST` in the *resolver* is the G6-3 credential path — KEEP it; distinct from the LOAD-grant model.)
- **H3 (test) — Task-10 table OMISSIONS (add every one + a disposition):** `tests/unit/comms_mcp/test_discord_hookpoints_carrier_tier_passed.py`, `tests/unit/comms_mcp/test_discord_sub_payload_classifier.py`, `tests/unit/comms/test_discord_allowlist_unchanged_in_slice3.py`, `tests/unit/comms/test_discord_types_protocol.py`, `tests/unit/comms/test_discord.py`, `tests/integration/test_discord_adapter_integration.py`, and the emitter units (`test_binding_emitter.py`/`test_crash_emitter.py`/`test_rate_limit_emitter.py`/`test_inbound_emitter_normalises.py`). VERIFY the `comms/test_discord*` trio aren't stale dead modules pointing at the deleted `src/alfred/comms/` (delete-if-dead, else assign).
- **H4 (test) — mislabels:** `test_discord_message_surface.py`/`_addressing_modes`/`_thread_continuity` are NOT "host-side" — they pin the `discord.py` 2.x dependency surface; relabel "survives — plugin dependency-surface pin, transport-agnostic" and re-check after the lifecycle change. The smoke `test_discord_gateway_smoke.py` drives the now-DELETED `alfred discord verify` + a standalone `secrets.toml` — COMMIT to re-pointing it to `alfred gateway adapters --wait-ready discord` via the core-vault path (not "re-point OR retire").

### MEDIUM

- **M1 (test) — non-vacuity guards on the negatives:** Task 14 must inject a REAL sentinel Discord token (do NOT inherit the UNSET-placeholder from `test_daemon_comms_flip_real_spawn.py`) and assert in ONE test: (positive control) the sentinel ARRIVES over fd-3 AND (negative) it is ABSENT from `/proc/<pid>/environ` (+ confirm `/proc/<pid>/environ` is actually readable for that pid, else absence is vacuous). Same for the cross-adapter `os.read` negative (a positive control that the token IS on the child's own fd-3).
- **M2 (test) — K7 real-child barrier mechanism:** Task 15 must hold the core leg half-booted via the existing `_HalfBootedCoreTransport.release_ready()` while the real Discord child is LIVE, and reuse `stays`/`settle` — NO child-side sleep. Name this in the task.
- **M3 (security) — fd-3 framing:** the child's fd-3 read (Task 1) MUST be the exact peer of `deliver_provider_key_via_fd3`'s 4-byte length-prefix framing; a short/torn/mis-framed read → `ok=False` (never an unhandled `struct.error`, never partial token bytes into a log). + a negative test that a hook credential error is NOT rewrapped as `GatewayAdapterSpawnError` (preserves the supervisor AWAITING_CORE arm).
- **M4 (architect) — ADR-0036 annotation** must also record the core-vault relocation of the Discord platform credential ("the token moves core-side; gateway/adapter mount no secret").

### LOW

- **L1 (architect) — binding ingress defaults:** the Discord manifest has NO rate fields today; use explicit `Final` constants for the binding leg's rate/burst/inflight/max_frame_bytes and DEFER manifest-sourced caps to a follow-up (state this in Task 6).
- **L2 (test) — CI gate has FOUR edit points** per new module: the `python`-job hashFiles guard + its `--include`, AND the `coverage-gates` hashFiles guard + its `--include`. Task 16 must touch all four (GAP-2=copy means only `adapter_child_factory.py` + the new `GatewayAdapterStdioTransport` module are new gateway files to gate).
- **L3 (security) — verified intact:** the factory never touches the credential (the client owns/delivers/zeroes); keep the `deliver_credential` injection test-only.

### Task-list deltas (apply before execution)

- DROP Task 3 (separate spawn-window module) → copy the window into Task 4 + add the shared property test.
- ADD Task 4a — `GatewayAdapterStdioTransport` (Popen-backed `_CommsTransportLike`, no-op spawn, executor-thread reads).
- Task 4 — add the child-reaping lifecycle (H1) + the framing/propagation tests (M3).
- Task 8 — daemon-control `status.query` poll (GAP-3); strike the gateway-side fallback.
- Task 11/12 — reorder: Task 12's core secret-mount ADD precedes Task 11's service-delete (GAP-4).
- Task 10 — add the omitted files (H3), fix the mislabels (H4), spell out the grant-rewrite coverage inventory (H2), the lifecycle-health threat-assertion carry-over (C3).
- Task 14/15 — non-vacuity sentinel + the observable barrier mechanism (M1/M2); non-root companions for the gating property (C2).
- Task 16 — verify/track the `integration-privileged` required-status reality (C2); four-point CI gate edits (L2); ADR-0036 core-vault annotation (M4).
