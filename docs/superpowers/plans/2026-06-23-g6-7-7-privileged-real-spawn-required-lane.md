# G6-7-7 — Privileged real-spawn forwarded-inbound e2e (packaged probe) + lane promotion — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove the gateway forwarded-inbound bridge end-to-end with a REAL bwrap-sandboxed adapter child for `adapter_id="discord"` (credential delivered via fd-3, provably absent from `/proc/<pid>/environ`) on the `integration-privileged` lane, then set up `integration-privileged` AND the G6-7-6-deferred `Adversarial corpus` for promotion to currently-required merge gates.

**Architecture (Option B + fleet-review corrections):** The hermetic real-spawn test does NOT touch the production Discord adapter (Option A was rejected — its `lifecycle.start`→`bot.login()` HTTP call raises in the hermetic lane → child reaped pre-pump → vacuous, and it weakens a production trust boundary). Instead a dedicated **packaged probe module `src/alfred/gateway/discord_probe.py`** (shipped in the wheel so it is importable inside the `kind=full` bwrap sandbox — a `plugins/` module is NOT bound into the sandbox and would `ModuleNotFoundError`; devops-004) speaks the gateway adapter wire contract: it answers the host's `lifecycle.start` request with `ok=True` FIRST (plain ADR-0025, no seq_ack echo — the runner DROPS any notification emitted before the ack), reads the fd-3 credential (emitting a CONTENT-FREE "fd3-received" ack, never the token bytes), THEN emits ONE scripted `inbound.message`, THEN blocks reading stdin until EOF (so the host can read the live child's `/proc/<pid>/environ` before the child exits), then exits. A small `plugins/alfred_discord_probe/manifest.toml` exists ONLY for bwrap policy resolution (the launcher resolves the policy from the launch-target plugin_id). A **constructor-injected, `ALFRED_ENVIRONMENT`-gated launch-target override** in `GatewayAdapterChildFactory` lets a test redirect the `"discord"` target to the probe; production refuses (no env-supplied module string is ever honored — that would be arbitrary-module exec; the override is a constructor-injected MAP only). The real-spawn test (`_DOCKER_ONLY`) wires the REAL `GatewayAdapterSupervisor` + forward-runner + adapter leg + credential client and asserts the forwarded sentinel lands a `comms.inbound.t3_promoted` row + a committed dispatched-edge `inbound_idempotency` row (keyed on the UNIQUE sentinel id) in real Postgres while the credential marker is absent from the live probe child's `/proc/<pid>/environ`. The non-root wire-contract companion already exists (G6-7-6 A1). Lane promotion is deferred to a post-merge follow-up after a soak window.

**Tech Stack:** Python 3.12+ / pytest / testcontainers (Postgres) / bubblewrap / GitHub Actions / `gh api`.

## Global Constraints

- **Probe is a PACKAGED module (devops-004, Critical).** `src/alfred/gateway/discord_probe.py` ships in the wheel (`wheel.packages=['src/alfred']`) → importable under bwrap via the bound interpreter prefix. The launch-target tuple is `("alfred.discord_probe", "alfred.gateway.discord_probe")` — distinct plugin_id (for a distinct policy) + the packaged module. A `plugins/`-only module would NOT import in a `kind=full` sandbox. The implementer MUST verify import-under-bwrap in the Task-4 docker run.
- **Probe bwrap policy (devops-005/comms-002).** `plugins/alfred_discord_probe/manifest.toml` declares `[sandbox] kind="full"` with `policy_refs` reusing the shipped `config/sandbox/discord-adapter.<os>.*` files (no NEW policy authored — avoids `policy_ref_missing`/`policy_ref_unreadable`). Verify the discord-adapter policy's binds suffice for the packaged module (the interpreter prefix carries `src/alfred`).
- **Override is constructor-injected-map-only + env-gated (sec-102).** `_resolve_launch_target` NEVER reads a `(plugin_id, module)` string from an env var. A test injects an override MAP into the factory/supervisor constructor; `ALFRED_ENVIRONMENT` (read via the sanctioned `load_environment`, manifest_reader.py) only gates whether the injected map is consulted. Default-DENY: any value other than `{"development","test"}` (incl. unset/empty/unknown) refuses (err-003, fail-closed).
- **Audited refusal via the supervisor (err-001/sec-101/arch-102/rev-001).** The factory has no audit writer. `LaunchTargetOverrideRefusedError` SUBCLASSES `GatewayAdapterSpawnError` so the supervisor's existing spawn-error arm (`adapter_supervisor.py:483`, catches `(GatewayAdapterSpawnError, AdapterCredentialError)`) audits it. Unit tests assert the RAISE; the adversarial test asserts the SUPERVISOR's audit ROW. The refusal is CONTENT-FREE (closed-vocab reason + adapter_id + active env; NEVER the rejected module string — sec-003 canary-absence).
- **Probe ships but is production-unreachable (sec-103).** A guard test asserts the production `_ADAPTER_LAUNCH_TARGETS` has NO probe entry and the override is only consulted under the env gate. The fd-3-received ack is content-free.
- **`t()` discipline (i18n-001).** The override refusal is operator-facing → a `t()` catalog key + `locale/en/LC_MESSAGES/alfred.po`/`.mo` + a pybabel-visible callsite, mirroring `src/alfred/plugins/_sandbox_i18n.py` (`supervisor.sandbox.refused.*`); pass `adapter_id`/env as kwargs, not f-string.
- **Fail loud, never skip-in-lane (devops-003/test-004/test-104).** `_DOCKER_ONLY` gates on `_HAS_BWRAP and _IS_LINUX_ROOT(euid==0) and _PROVISIONED(ALFRED_GATEWAY_ADAPTER_CHILD_PYTHON)` — the GATEWAY adapter child-python var (NOT the quarantine one). The `integration-privileged` precondition step asserts that var is set+executable (mirror ci.yml:1114) AND the new test is not-skipped at RUNTIME (not just `--collect-only`).
- **Bounded waits (perf-001).** Every host await in the e2e is deadline-bounded (`_wait_for(..., _TIMEOUT_S=20.0)` + `asyncio.wait_for(task, timeout=...)`) — no raw poll / timeout-less await, so a forward regression fails fast on the required lane.
- **#245 paper-gate rule.** A1 (`tests/integration/cli/daemon/test_forwarded_inbound_gateway_to_core_turn.py`) is the non-root companion — no new one authored.
- **Promotion sequencing (devops-001):** required-checks.md rows STAY Pending in THIS PR; move to Currently-required only in a post-merge follow-up after `gh api .../required_status_checks --jq .contexts` confirms branch protection carries them.
- **Promotion soak (devops-002/sec-004):** N≥3 consecutive green `integration-privileged` PRs before the `gh api POST`; document the `gh api -X DELETE .../contexts` rollback.
- **No `--admin` / `--no-verify`. Conventional Commits** ending `(Spec B G6-7-7, #309)` + MrReasonable trailer (never `i18n` type). `language` tag on stored user-content rows (the refusal row stores only structured fields → no language column needed; the asserted `t3_promoted` row already carries `language`).
- **Real-spawn can't run on darwin** → Task 4 validated via `docker run --privileged --platform linux/amd64`; locally it must cleanly SKIP.

---

## File Structure

- `src/alfred/gateway/discord_probe.py` *(NEW, packaged)* — the probe main (stdin request-loop): answer `lifecycle.start` `ok=True` → read fd-3 cred + emit content-free `fd3-received` ack → emit ONE scripted `inbound.message` (full `InboundMessageNotification`: tz-aware `received_at`, `sub_payload_refs=()`, `body.language`) → block on stdin until EOF → exit. Plain ADR-0025 (no seq_ack echo).
- `plugins/alfred_discord_probe/manifest.toml` *(NEW)* — bwrap-policy resolution only: `[sandbox] kind="full"`, `policy_refs` → the shipped `config/sandbox/discord-adapter.<os>.*`. TEST-ONLY banner in a top comment.
- `src/alfred/gateway/adapter_child_factory.py` *(MODIFY)* — `_resolve_launch_target(adapter_id, *, override_map)` (constructor-injected map, env via `load_environment`, default-deny, `LaunchTargetOverrideRefusedError(GatewayAdapterSpawnError)` + `t()` content-free refusal); call it at `:297`; de-stale the `_ADAPTER_LAUNCH_TARGETS` docstring (`:82-87`).
- `src/alfred/gateway/adapter_supervisor.py` *(VERIFY/MINIMAL)* — confirm the `:483` arm audits `LaunchTargetOverrideRefusedError` via the subclass; if a distinct closed-vocab reason is needed, add it.
- `locale/en/LC_MESSAGES/alfred.po` + the i18n key home (mirror `_sandbox_i18n.py`) *(MODIFY)* — the refusal `t()` key.
- `tests/unit/gateway/test_launch_target_override.py` *(NEW)* — override honored (test env + injected map); refused (raises the `GatewayAdapterSpawnError` subclass) outside allowlist + unset/empty/unknown (fail-closed); no map → production target unchanged; env read via `load_environment`; refusal message content-free.
- `tests/unit/gateway/test_discord_probe.py` *(NEW)* — ack-PRECEDES-inbound; exactly one `inbound.message` with the scripted sentinel + full schema; content-free fd3-ack; blocks until stdin EOF.
- `tests/unit/gateway/test_probe_not_in_production_map.py` *(NEW)* — guard: production `_ADAPTER_LAUNCH_TARGETS` has no probe entry; override only consulted under the env gate (sec-103).
- `tests/adversarial/comms/test_launch_target_override_refusal.py` *(NEW)* — refuses in `{production,staging,"",unset,unknown}`; no probe spawned; the SUPERVISOR writes a loud audit row (assert it); canary-absence in rows AND logs (sec-003).
- `tests/integration/cli/daemon/test_gateway_real_probe_spawn_forwarded_inbound.py` *(NEW)* — the DOCKER-ONLY real-spawn e2e (Task 4).
- `.github/workflows/ci.yml` *(MODIFY)* — thread `ALFRED_GATEWAY_ADAPTER_CHILD_PYTHON` (share the quarantine proto interpreter) through the `integration-privileged` `sudo` run; precondition asserts it set+executable + the new test runtime-not-skipped. `ALFRED_ENVIRONMENT` is set PER-TEST (monkeypatch), NOT job-wide (devops-006).
- `docs/ci/required-checks.md`, `docs/adr/0039-gateway-adapter-inbound-bridge.md`, `docs/subsystems/comms.md`, `docs/glossary.md` *(MODIFY)* — Task 6.

---

## Task 1: Launch-target override (constructor-map-only, env-gated, audited-via-supervisor)

**Files:** Modify `src/alfred/gateway/adapter_child_factory.py` (+ supervisor verify, + i18n key); Test `tests/unit/gateway/test_launch_target_override.py` + `tests/unit/gateway/test_probe_not_in_production_map.py`.

**Interfaces:** Produces `_resolve_launch_target(adapter_id: str, *, override_map: Mapping[str, tuple[str,str]] | None) -> tuple[str,str]`; `LaunchTargetOverrideRefusedError(GatewayAdapterSpawnError)`. Consumes `load_environment` (manifest_reader.py), `_ADAPTER_LAUNCH_TARGETS` (`:88-90`), the supervisor audit arm (`adapter_supervisor.py:483`).

- [ ] **Step 1: Failing unit** — (a) test env + injected `{"discord": ("alfred.discord_probe","alfred.gateway.discord_probe")}` → resolves to the probe; (b) `production`/`staging`/`""`/unset/`"bogus"` + a present override_map → raises `LaunchTargetOverrideRefusedError` (assert it IS a `GatewayAdapterSpawnError`); (c) no override_map → `"discord"` resolves to the production target unchanged; (d) the raised error's message/args contain NO module string (content-free); (e) env is read via `load_environment` (patch it, assert consulted).
- [ ] **Step 2: Run → fail.**
- [ ] **Step 3: Implement** `_resolve_launch_target` + the `LaunchTargetOverrideRefusedError(GatewayAdapterSpawnError)` subclass + the `t()` refusal key (mirror `_sandbox_i18n.py`; kwargs not f-string); call it at `:297`; de-stale the `_ADAPTER_LAUNCH_TARGETS` docstring; thread `override_map` as a factory constructor param (default `None`).
- [ ] **Step 4: Run → pass.**
- [ ] **Step 5: Guard test** (`test_probe_not_in_production_map.py`): assert production `_ADAPTER_LAUNCH_TARGETS` has no `discord_probe`/probe entry; the override is only consulted when `override_map` is injected AND env-allowlisted.
- [ ] **Step 6: `ruff`/`mypy src/`/`pyright src/`; commit** `feat(gateway): env-gated constructor-injected launch-target override + audited refusal (Spec B G6-7-7, #309)`.

## Task 2: Packaged discord probe module + bwrap-policy manifest

**Files:** Create `src/alfred/gateway/discord_probe.py`, `plugins/alfred_discord_probe/manifest.toml`; Test `tests/unit/gateway/test_discord_probe.py`.

**Interfaces:** The probe is exec'd as `python -m alfred.gateway.discord_probe` under bwrap with fd-3 carrying the credential. It speaks the gateway adapter stdio wire (consumes `CommsPluginRunner`'s `lifecycle.start` request; emits via the notification frame the pump reads). The scripted `inbound_id` IS the sentinel asserted by Task 4.

- [ ] **Step 1: Failing unit** — drive the probe main with an in-memory stdio pair + a fake fd-3 cred: assert it (a) replies `ok=True` to `lifecycle.start` (id=0) BEFORE writing any `inbound.message`; (b) emits EXACTLY one `inbound.message` whose params validate against the full `InboundMessageNotification` (tz-aware `received_at`, `sub_payload_refs=()`, `body.language`, the scripted sentinel `inbound_id`/`platform_user_id`/`content`, `addressing_signal="dm"`); (c) the `fd3-received` ack is content-free (the credential bytes never appear in any frame); (d) it blocks reading stdin and exits only on EOF.
- [ ] **Step 2: Run → fail. Step 3: Implement** `discord_probe.py` (stdin request-loop, ack-first, content-free fd3-ack, single emit, block-until-EOF; plain ADR-0025) + `plugins/alfred_discord_probe/manifest.toml` (`kind="full"`, `policy_refs`→`config/sandbox/discord-adapter.<os>.*`, TEST-ONLY banner). **Step 4: Run → pass. Step 5:** `ruff`/`mypy`/`pyright`; **commit** `feat(gateway): packaged discord probe adapter (handshake-first, content-free fd3 ack) for real-spawn proof (Spec B G6-7-7, #309)`.

## Task 3: Adversarial — override refuses outside allowlisted env (supervisor-audited)

**Files:** Test `tests/adversarial/comms/test_launch_target_override_refusal.py`.

- [ ] **Step 1: Failing adversarial** — drive a real `GatewayAdapterSupervisor` with an injected probe override_map under `ALFRED_ENVIRONMENT ∈ {production,staging,"",unset,"unknown"}`: assert `spawn_and_handshake` raises `LaunchTargetOverrideRefusedError`, the supervisor's `:483` arm WRITES a loud audit row (closed-vocab reason, `adapter_id`, env), NO probe is spawned, and a high-entropy canary embedded in the override target module NEVER appears in any audit row OR log line.
- [ ] **Step 2: Run → fail. Step 3: Harden** until green (subclass caught + audited; content-free). **Step 4:** `tests/adversarial/comms -q` green. **Step 5: commit** `test(comms): adversarial — launch-target override refuses + audits outside allowlisted env (Spec B G6-7-7, #309)`.

## Task 4: Privileged real-spawn forwarded-inbound e2e (DOCKER-ONLY, real supervisor wiring)

**Files:** Test `tests/integration/cli/daemon/test_gateway_real_probe_spawn_forwarded_inbound.py`.

**Interfaces:** Consumes the REAL `GatewayAdapterSupervisor` + `_build_forward_runner(forward=core_link.forward_adapter_inbound)` + `build_adapter_leg("discord")` + the real `credential_client` + `GatewayAdapterChildFactory(override_map={"discord": ("alfred.discord_probe","alfred.gateway.discord_probe")})` + the daemon-side gateway-core-leg scaffold (from A1 / `test_chat_gateway_socket_turn.py`) + `process_inbound_message`. NOT A1's direct `core_link.forward_adapter_inbound` injection (test-102).

- [ ] **Step 1: Write the test.** `_DOCKER_ONLY` = `_HAS_BWRAP and _IS_LINUX_ROOT(euid==0) and bool(os.environ.get("ALFRED_GATEWAY_ADAPTER_CHILD_PYTHON"))`. `monkeypatch.setenv("ALFRED_ENVIRONMENT","test")` (per-test, devops-006). Seed a `Platform.DISCORD` bound user (`_seed_discord_bound_user`). Seed a UNIQUE high-entropy **bot-token** marker as the fd-3 credential + a UNIQUE sentinel `inbound_id`. **PRE-SPAWN baseline (err-002):** assert NO `inbound_idempotency` row for `(discord, sentinel_id)` and NO `t3_promoted` row yet. Boot the real comms graph + gateway core leg + register `build_adapter_leg("discord")`; build the supervisor + forward-runner + credential client; spawn via the REAL factory with the override_map → real bwrap probe (verify it IMPORTS — devops-004). **Credential-absence (controls; test-101/test-002/arch-003):** the probe blocks after emit, so the child is ALIVE; positively confirm the probe acked `fd3-received`; assert `/proc/<child.pid>/environ` read is NON-EMPTY; `assert bot_token_marker not in environ_bytes`; MUTATION control: a known-present env var (e.g. `PATH`) IS found in the same read (proving the assertion CAN fire). **Non-vacuity:** await (bounded) the forwarded sentinel → assert ONE `comms.inbound.t3_promoted` row resolved to the seeded user (`result="promoted"`, peppered platform-id hash, `language`) + a committed `inbound_idempotency` row keyed on the UNIQUE `(discord, sentinel_id)` + NO poisoned row. Release the child (close its stdin → EOF → exit). Reap the gateway `_GatewayAdapterChild` (Popen + transport + supervised task) on EVERY exit path (test-005). All awaits deadline-bounded (perf-001).
- [ ] **Step 2: Validate under docker-privileged.** `docker run --rm --privileged --platform linux/amd64` (bwrap + the provisioned `ALFRED_GATEWAY_ADAPTER_CHILD_PYTHON` + per-test `ALFRED_ENVIRONMENT=test`): the test RUNS (not skips) + PASSES; the probe MODULE imports under bwrap; flipping the env to `production` makes the override refuse (probe never spawns). Capture the docker log as PR evidence.
- [ ] **Step 3: Confirm it cleanly SKIPS on darwin** (1 skipped, `_DOCKER_ONLY`).
- [ ] **Step 4: Commit** `test(comms): privileged real-bwrap probe spawn → forwarded inbound → core dispatch e2e (Spec B G6-7-7, #309)`.

## Task 5: CI lane provisioning + precondition hardening

**Files:** Modify `.github/workflows/ci.yml` (`integration-privileged`).

- [ ] **Step 1:** thread `ALFRED_GATEWAY_ADAPTER_CHILD_PYTHON` through the `sudo` pytest run — it SHARES the quarantine proto interpreter (both are ADR-0030 interpreter-prefix twins; no separate provisioning step — devops-006). Do NOT set `ALFRED_ENVIRONMENT` job-wide (the test sets it per-test).
- [ ] **Step 2:** extend the euid-0+bwrap precondition step to also assert `ALFRED_GATEWAY_ADAPTER_CHILD_PYTHON` is set + executable (mirror ci.yml:1114) AND the new real-spawn test is collected-and-not-skipped at RUNTIME (run it with `-rs`/parse the skip, not just `--collect-only` — test-104).
- [ ] **Step 3: commit** `ci(integration-privileged): provision gateway-adapter child python (shared) + assert real-spawn not skipped (Spec B G6-7-7, #309)`.

## Task 6: Manifest (Pending) + ADR amendment + comms.md de-stale + glossary + recipe

**Files:** Modify `docs/ci/required-checks.md`, `docs/adr/0039-gateway-adapter-inbound-bridge.md`, `docs/subsystems/comms.md`, `docs/glossary.md`.

- [ ] **Step 1:** `required-checks.md` — KEEP `Integration (privileged Linux, real spawn)` + `Adversarial corpus` in the **Pending** table (devops-001); update "Promote after" to the soak gate (N≥3 green) + the post-merge `gh api POST` + the `gh api DELETE` rollback.
- [ ] **Step 2: ADR-0039 dated G6-7-7 amendment** — CHAIN explicitly to the 2026-06-23 G6-7-6 amendment (lines 379-430, future-tense "promoted at G6-7-7") with the arch-006-pattern reconciliation paragraph; record: Option-A rejected (sec-001/002), Option-B packaged probe + the env-gated constructor-map override (a new test-only trust seam — amendment, not a new ADR; reads env via `load_environment`), the real-spawn proof on `integration-privileged`, the deferred-promotion soak gate, the A1 companion, leg TEST-ONLY until G6-7-8.
- [ ] **Step 3: comms.md** — SPECIFICALLY de-stale lines 638-664 (the "future G6-7-7" + "not on any currently-required check until G6-7-7" framing — the proof now exists but the lane stays Pending); add the privileged real-spawn proof; land the docker-privileged `ALFRED_GATEWAY_ADAPTER_CHILD_PYTHON` provisioning RECIPE (devex-001) so a lane-flake debugger can reproduce. **glossary.md** — entries for the probe + the launch-target override. markdownlint clean. **commit** `docs(comms): ADR-0039 G6-7-7 amendment (chained) + comms.md de-stale + probe/override glossary + docker recipe (Spec B G6-7-7, #309)`.

## Task 7: Full local gate + evidence

- [ ] `ruff check . && ruff format --check .`; `mypy src/ && pyright src/` (src changed — Tasks 1/2); `pybabel update --check` + `pybabel compile --check` (i18n-002, the new refusal key); `uv run pytest tests/unit/gateway -q`; `uv run pytest tests/adversarial -q` (235 + new); confirm the new integration test SKIPS on darwin; the docker-privileged Task-4 evidence log; markdownlint clean on all shipped docs.
- [ ] New trust-boundary code (the override in `adapter_child_factory.py`): confirm coverage; if it lands a per-file 100% gate, add `adapter_child_factory.py` to BOTH ci.yml gate sites.

---

## POST-MERGE RUNBOOK (record at merge)

1. **Soak:** `integration-privileged` (now RUNNING the real-spawn test for real) green on N≥3 consecutive PRs. **Cost note (perf-002):** the new test joins the EXISTING `pytest tests/integration tests/smoke` invocation (no new pytest run / no new Postgres boot); the probe is a no-login handshake + one frame + immediate exit — negligible vs the quarantine-child real spawn already in this lane. The required-gate cost is the lane's existing ~9min, not a new increment.
2. **Promote:** `gh api -X POST repos/alfred-os/AlfredOS/branches/main/protection/required_status_checks/contexts` adding `Integration (privileged Linux, real spawn)`, then `Adversarial corpus`; verify with `gh api .../required_status_checks --jq .contexts`.
3. **Follow-up PR (only after step 2 confirms — arch-004):** move both rows in `required-checks.md` Pending→Currently; remove the interim `ci.yml` `Comms credential adversarial corpus` step; update `CONTRIBUTING.md` + `.github/PULL_REQUEST_TEMPLATE.md` (devex-001 from G6-7-6). Hard-AFTER both promotions so no required gate is lost and the manifest never drifts.
4. **Rollback:** `gh api -X DELETE .../contexts/...` to de-require a flaking lane while investigating.

G6-7-8 (flag-day) is gated on G6-7-7 green + the privileged lane actually currently-required. The gateway Discord leg stays TEST-ONLY until G6-7-8.
