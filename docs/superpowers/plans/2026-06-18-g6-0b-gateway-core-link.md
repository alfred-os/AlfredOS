# G6-0b — Gateway↔Core Link-Up Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Steps use `- [ ]`.

**Goal:** Make the deployed always-up `alfred-gateway` (shipped in G6-0) actually link to the core, by daemon-ifying `alfred-core` and enabling the socket-backed TUI adapter so the core binds the `comms-tui.sock` the gateway dials — turning the G6-0 "healthy-while-core-down" substrate into a live front door.

**Architecture:** A code investigation (2026-06-18) established there is **no socket-id mismatch**: the daemon binds `comms-{adapter_kind}.sock` keyed on the *manifest* `adapter_kind` (`"tui"` for `plugins/alfred_tui/`), not the enabled-adapter id, so enabling `alfred_tui` binds `comms-tui.sock` — exactly what the gateway's `dial_adapter_id="tui"` dials. The link is already proven by `tests/integration/cli/daemon/test_chat_gateway_socket_turn.py` (real daemon comms graph + socket carrier + real gateway core-link + real cohost). So G6-0b is primarily a **deployment flag-day**: daemon-ify the core, share the socket volume, set the boot-required env, and make the gateway's dial id operator-overridable (closing the implicit-constant coupling the plan-review flagged). Daemon-ifying makes the always-up core spawn the bwrap quarantine child continuously — safe in-container (Linux + bwrap + SETUID present), deterministic-echo, no egress (2c/#230 gates real LLM egress); not human-gated.

**Tech Stack:** Docker Compose, Typer CLI, pytest, PyYAML.

---

## Scope & non-scope

- **In:** daemon-ify `alfred-core` (command/restart/`alfred_run` mount/`ALFRED_ENVIRONMENT`/`ALFRED_COMMS_ENABLED_ADAPTERS=["alfred_tui"]`); make the gateway dial id env-configurable; compose-invariant updates; flag-day docs.
- **Out:** SETUID into the gateway + adapter hosting (G6-1+); Discord/egress (2c/#230); the gateway↔core *link test itself* (already exists — `test_chat_gateway_socket_turn.py`).
- **Provisioning note (verify in-container, not a code change):** the always-up core requires Linux + bwrap + SETUID (present in the `alfred-core` image), `ALFRED_ENVIRONMENT` (hard boot req — `_load_settings_or_die`), and a seeded `audit.hash_pepper` (via `bin/alfred-setup.sh`). `quarantine_provider_api_key` unset → placeholder + loud warn (safe until 2c). A fresh `docker compose up -d` without setup will refuse-boot/crash-loop — documented in §Task 4.

---

## File structure

- Modify: `src/alfred/cli/gateway/_commands.py` — resolve `ALFRED_GATEWAY_DIAL_ADAPTER_ID` (default `"tui"`) and pass it to `GatewayProcess`.
- Test: `tests/unit/cli/test_gateway_cli.py` (or `test_gateway_healthcheck.py`) — assert the dial-id env is honored.
- Modify: `docker-compose.yaml` — daemon-ify `alfred-core`; fix the stale header comment.
- Modify: `tests/unit/test_compose_invariants.py` — core-daemon invariants; widen the `alfred_run` mounter set to `{alfred-core, alfred-gateway}`.
- Modify: `README.md` — flag-day note (long-running core; setup prerequisite).

---

## Task 1: Gateway dial-adapter-id env override (closes arch-002 implicit coupling)

**Files:**

- Modify: `src/alfred/cli/gateway/_commands.py`
- Test: `tests/unit/cli/test_gateway_healthcheck.py`

- [ ] **Step 1: Write the failing test** (append to `tests/unit/cli/test_gateway_healthcheck.py`):

```python
def test_start_honors_dial_adapter_id_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """`alfred gateway start` passes ALFRED_GATEWAY_DIAL_ADAPTER_ID into GatewayProcess
    so the gateway's core-dial target is operator-configurable (not a hidden constant)."""
    import alfred.cli.gateway._commands as cmds

    captured: dict[str, object] = {}

    class _FakeProcess:
        def __init__(self, **kwargs: object) -> None:
            captured.update(kwargs)

        async def run(self) -> None:
            return None

    monkeypatch.setattr("alfred.gateway.process.GatewayProcess", _FakeProcess)
    monkeypatch.setattr(cmds, "start_metrics_server", lambda port: True)
    monkeypatch.setattr(cmds, "resolve_metrics_port", lambda: 9464, raising=False)
    monkeypatch.setenv("ALFRED_GATEWAY_DIAL_ADAPTER_ID", "alfred_tui")
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    CliRunner().invoke(gateway_app, ["start"])
    assert captured.get("dial_adapter_id") == "alfred_tui"
```

NOTE: if `resolve_metrics_port`/`start_metrics_server` are imported lazily inside `start_gateway`, monkeypatch them at their definition module (`alfred.gateway.metrics_server`) instead of `cmds`. Adjust the monkeypatch target to wherever `start_gateway` resolves them so the test exercises the real `start_gateway` body without binding a socket or running the real relay. The load-bearing assertion is `captured["dial_adapter_id"] == "alfred_tui"`.

- [ ] **Step 2: Run → FAIL** (`GatewayProcess` constructed without `dial_adapter_id`). `uv run pytest tests/unit/cli/test_gateway_healthcheck.py -k dial_adapter_id -q`

- [ ] **Step 3: Implement** — in `src/alfred/cli/gateway/_commands.py` `start_gateway()`, where `GatewayProcess(shutdown_event=shutdown_event)` is constructed, resolve and pass the dial id. Add a module constant near the metrics-port one:

```python
_DIAL_ADAPTER_ID_ENV: Final[str] = "ALFRED_GATEWAY_DIAL_ADAPTER_ID"
_DEFAULT_DIAL_ADAPTER_ID: Final[str] = "tui"
```

and at construction:

```python
        dial_adapter_id = os.environ.get(_DIAL_ADAPTER_ID_ENV) or _DEFAULT_DIAL_ADAPTER_ID
        await GatewayProcess(
            shutdown_event=shutdown_event,
            dial_adapter_id=dial_adapter_id,
        ).run()
```

(`os` is already imported in this module. The default `"tui"` preserves current behavior; the constant mirrors `core_link._DEFAULT_DIAL_ADAPTER_ID`.)

- [ ] **Step 4: Run → PASS.** `uv run pytest tests/unit/cli/test_gateway_healthcheck.py tests/unit/cli/test_gateway_cli.py -q`

- [ ] **Step 5: Lint/type.** `uv run ruff check src/alfred/cli/gateway/_commands.py && uv run ruff format --check src/alfred/cli/gateway/_commands.py && uv run mypy src/alfred/cli/gateway/_commands.py`

- [ ] **Step 6: Commit** (explicit paths):

```bash
git add src/alfred/cli/gateway/_commands.py tests/unit/cli/test_gateway_healthcheck.py
git commit -m "feat(gateway): make core-dial adapter id env-configurable (ALFRED_GATEWAY_DIAL_ADAPTER_ID) (#288)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 2: Daemon-ify alfred-core (TDD via compose invariants)

**Files:**

- Test: `tests/unit/test_compose_invariants.py`
- Modify: `docker-compose.yaml`

- [ ] **Step 1: Write the failing/updated invariant tests.** Append:

```python
def test_alfred_core_is_long_running_daemon(compose: dict[str, Any]) -> None:
    """alfred-core runs `daemon start` with a restart policy (Spec B G6-0b)."""
    core = compose.get("services", {}).get("alfred-core", {})
    assert core.get("command") == ["daemon", "start"]
    assert core.get("restart") == "unless-stopped"


def test_alfred_core_shares_alfred_run(compose: dict[str, Any]) -> None:
    """alfred-core mounts alfred_run so the gateway can dial comms-tui.sock."""
    core = compose.get("services", {}).get("alfred-core", {})
    assert "alfred_run:/home/alfred/.run" in _volume_strings(core.get("volumes", []) or [])


def test_alfred_core_enables_tui_adapter(compose: dict[str, Any]) -> None:
    """alfred-core enables the socket-backed alfred_tui adapter (binds comms-tui.sock)."""
    core = compose.get("services", {}).get("alfred-core", {})
    env = core.get("environment", {}) or {}
    assert "alfred_tui" in str(env.get("ALFRED_COMMS_ENABLED_ADAPTERS", ""))


def test_alfred_core_sets_environment(compose: dict[str, Any]) -> None:
    """alfred-core sets ALFRED_ENVIRONMENT (hard boot requirement for the daemon)."""
    core = compose.get("services", {}).get("alfred-core", {})
    env = core.get("environment", {}) or {}
    assert "ALFRED_ENVIRONMENT" in env
```

And **UPDATE** the G6-0 invariant `test_alfred_run_mounted_only_by_gateway` to expect the widened mounter set:

```python
def test_alfred_run_mounted_only_by_core_and_gateway(compose: dict[str, Any]) -> None:
    """G6-0b: alfred_run is shared by exactly {alfred-core, alfred-gateway} (the socket
    dir for the gateway↔core link). No other service may mount it."""
    services = compose.get("services", {})
    mounters = {
        name
        for name, svc in services.items()
        if any("alfred_run" in v for v in _volume_strings(svc.get("volumes", []) or []))
    }
    assert mounters == {"alfred-core", "alfred-gateway"}, (
        f"alfred_run must be mounted only by core+gateway; got {mounters}."
    )
```

(Delete the old `test_alfred_run_mounted_only_by_gateway` — it is superseded. Keep all other G6-0 gateway invariants + the pre-existing core SETUID/state_git + discord/redis invariants unchanged.)

- [ ] **Step 2: Run → new tests FAIL** (core not yet a daemon). `uv run pytest tests/unit/test_compose_invariants.py -q`

- [ ] **Step 3: Edit `docker-compose.yaml`.** In the `alfred-core` service add `command`/`restart`, the `ALFRED_ENVIRONMENT` + `ALFRED_COMMS_ENABLED_ADAPTERS` env, and the `alfred_run` mount (keep `cap_add: [SETUID]`, the existing env block, and the `alfred_state_git` mount):

```yaml
  alfred-core:
    build:
      context: .
      dockerfile: docker/alfred-core.Dockerfile
    # Spec B G6-0b (#288): alfred-core is now the long-running daemon. The always-up
    # gateway dials its comms-tui.sock (bound when the socket-backed alfred_tui adapter
    # is enabled), so the core must stay up and share the alfred_run socket volume.
    # `docker compose run --rm alfred-core <cmd>` still works for one-off subcommands
    # (run overrides command). Requires a seeded audit.hash_pepper (bin/alfred-setup.sh)
    # before `up -d`, or the daemon refuse-boots/crash-loops.
    command: ["daemon", "start"]
    restart: unless-stopped
    depends_on:
      alfred-postgres:
        condition: service_healthy
      alfred-redis:
        condition: service_healthy
    cap_add:
      - SETUID
    environment:
      ALFRED_ENVIRONMENT: ${ALFRED_ENVIRONMENT:-production}
      # SINGLE-QUOTED so the JSON list survives YAML scalar parsing (pydantic parses it to a tuple).
      ALFRED_COMMS_ENABLED_ADAPTERS: '${ALFRED_COMMS_ENABLED_ADAPTERS:-["alfred_tui"]}'
      # ... (keep ALL existing alfred-core env keys: ALFRED_DEEPSEEK_API_KEY,
      #      ALFRED_ANTHROPIC_API_KEY, ALFRED_DATABASE_URL, ALFRED_OPERATOR_*,
      #      ALFRED_DAILY_BUDGET_USD, ALFRED_PER_CALL_MAX_USD, ALFRED_REDIS_URL) ...
    volumes:
      - alfred_state_git:/var/lib/alfred
      - alfred_run:/home/alfred/.run
```

(Preserve every existing env key — only ADD `ALFRED_ENVIRONMENT` + `ALFRED_COMMS_ENABLED_ADAPTERS` and the `command`/`restart`/`alfred_run` lines.)

- [ ] **Step 4: Fix the stale header comment** at `docker-compose.yaml:1-12` — it currently says alfred-core is a "command runner … deliberately carries no `restart:` and no `command:`". Rewrite the alfred-core bullet to describe the long-running daemon (one-off `docker compose run --rm alfred-core <cmd>` still supported).

- [ ] **Step 5: Run invariants + compose validity.** `uv run pytest tests/unit/test_compose_invariants.py -q` (all pass) and `docker compose config --quiet && echo OK`.

- [ ] **Step 6: Commit:**

```bash
git add docker-compose.yaml tests/unit/test_compose_invariants.py
git commit -m "feat(compose): daemon-ify alfred-core + enable alfred_tui so the gateway links to the core (#288)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 3: Docker smoke — the deployed daemon+gateway actually link

**Files:**

- Test: `tests/smoke/test_gateway_core_link_smoke.py` (or extend an existing compose smoke)

- [ ] **Step 1: Determine the smoke approach.** The in-process real-link test already exists (`tests/integration/cli/daemon/test_chat_gateway_socket_turn.py`). G6-0b's *new* risk is the **compose deployment** (does the daemon-ified core boot + bind `comms-tui.sock` + does the gateway reach it, in-container, with the real bwrap child). Check whether `tests/smoke/` already has a docker-compose-driven test (`grep -rl "docker compose" tests/smoke`). If a compose-smoke harness exists, add a case; if not, write a minimal one **gated to run only where Docker + Linux are available** (skip with a clear reason otherwise — do NOT make it a paper gate; mirror how `tests/integration/.../test_daemon_comms_flip_real_spawn.py` gates on docker/root).

- [ ] **Step 2: Write the smoke** (sketch — adapt to the existing smoke harness conventions):
  - `docker compose up -d alfred-postgres alfred-redis`, seed `audit.hash_pepper` (`bin/alfred-setup.sh` path or the seed script), set `ALFRED_ENVIRONMENT=test`, `docker compose up -d alfred-core alfred-gateway`.
  - Assert `alfred-core` reaches a healthy/running state and binds `comms-tui.sock` on the shared `alfred_run` volume.
  - Assert `alfred-gateway`'s healthcheck goes healthy AND its `gateway_core_link_up` metric reads `1` (scrape `alfred-gateway:9464/metrics` from within the compose network, e.g. `docker compose exec alfred-gateway alfred gateway healthcheck` + a metrics curl) — proving the link established (not just buffering).
  - Tear down.
  - If the existing smoke suite is not docker-compose-driven and adding one is disproportionate, instead add an **integration** test that boots the real daemon (as `test_chat_gateway_socket_turn.py` does) with `ALFRED_COMMS_ENABLED_ADAPTERS=["alfred_tui"]` resolved from the daemon Settings and asserts the gateway core-link reports up — and DOCUMENT that the compose-level proof rides the nightly smoke. Record the decision in the test's module docstring.

- [ ] **Step 3: Run it** (where Docker is available) and confirm green; confirm it SKIPS with a clear reason where Docker/Linux is absent (non-paper-gate).

- [ ] **Step 4: Commit:**

```bash
git add tests/smoke/test_gateway_core_link_smoke.py
git commit -m "test(smoke): deployed daemon-core + gateway establish the comms-tui.sock link (#288)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

---

## Task 4: Flag-day docs (README + setup reconciliation)

**Files:**

- Modify: `README.md`

- [ ] **Step 1: Update the README quickstart** to reflect that `docker compose up -d` now starts a **long-running `alfred-core` daemon** (previously a one-shot runner). State the prerequisite: run `bin/alfred-setup.sh` (which seeds `audit.hash_pepper` and provisions secrets) **before** `docker compose up -d`, or the daemon refuse-boots and (under `restart: unless-stopped`) crash-loops. Note that `docker compose run --rm alfred-core <cmd>` still works for one-off subcommands (`migrate`, `user add`, etc.) because `run` overrides `command`. Cross-reference the G6-0 gateway note (the gateway now links to the core, so `gateway_core_link_up` should read 1 once both are up).

- [ ] **Step 2: Check `bin/alfred-setup.sh`** for any line that asserts/depends on `alfred-core` being a one-shot (e.g. the final `Run 'docker compose run --rm -it alfred-core chat'` hint at ~line 361). If the hint is now misleading (chat should go via the gateway), update it minimally; otherwise leave setup's `docker compose run --rm alfred-core <cmd>` calls (they still work). Keep changes surgical — do NOT restructure setup.

- [ ] **Step 3: markdownlint** the touched docs: `npx --yes markdownlint-cli2 README.md 2>&1 | grep -E '^README\.md' | grep -v Finding: || echo CLEAN`.

- [ ] **Step 4: Commit:**

```bash
git add README.md bin/alfred-setup.sh
git commit -m "docs: alfred-core is now a long-running daemon; setup before compose up (Spec B G6-0b) (#288)

MrReasonable <4990954+MrReasonable@users.noreply.github.com>"
```

(If `bin/alfred-setup.sh` needed no change, omit it from the `git add`.)

---

## Task 5: Full local gate

- [ ] **Step 1:** `uv run ruff check . && uv run ruff format --check . && uv run mypy src/ && uv run pytest tests/unit -q` — all green; fix any G6-0b-introduced finding (report unrelated pre-existing failures, don't fix).
- [ ] **Step 2:** `docker compose config --quiet && echo OK`.
- [ ] **Step 3:** Confirm the catalog drift gate is unaffected (no new `t()` keys in G6-0b — if any operator string was added, run the pybabel extract/update/compile + `--check`).
- [ ] **Step 4:** No commit (verification only); the per-task commits stand.

---

## Self-review

**Spec coverage (spec §9 G6-0b row):** daemon-ify alfred-core → Task 2. Enable socket-backed comms adapter → Task 2 (`ALFRED_COMMS_ENABLED_ADAPTERS=["alfred_tui"]`). Couple gateway dial id ↔ core bound id → Task 1 (env-configurable; default already matches via `adapter_kind`). Provisioning invariant + crash-loop mitigation → Task 2 comment + Task 4 docs. Flag-day → Task 4. Real-daemon↔real-gateway test → already exists (`test_chat_gateway_socket_turn.py`); Task 3 adds the deployment-level proof. SETUID/adapter-hosting → NOT here (G6-1+).

**Placeholder scan:** Task 3 leaves the smoke-vs-integration choice to the implementer with explicit criteria (existing-harness-dependent) — that is a bounded decision, not a placeholder; the load-bearing assertion (gateway_core_link_up == 1 on the deployed stack, or the integration analog) is specified.

**Type/name consistency:** `ALFRED_GATEWAY_DIAL_ADAPTER_ID` / `dial_adapter_id` consistent Task 1 ↔ GatewayProcess kwarg. `alfred_run:/home/alfred/.run` identical Task 2 ↔ invariant tests ↔ G6-0. `alfred_tui` enabled-id ↔ `adapter_kind="tui"` ↔ gateway dial `"tui"` (the investigated chain).
