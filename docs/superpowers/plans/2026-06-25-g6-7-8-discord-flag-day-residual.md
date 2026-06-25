# G6-7-8 — Discord flag-day (residual cutover) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.
>
> **This plan is a re-baseline, hardened by review.** The 2026-06-21 plan predates the merged inbound-bridge series (G6-5 #310 + G6-7-1..7-7 #311–#319). A 6-specialist `/review-plan` pass found ~90% already shipped; a 12-specialist `/review-pr` pass (2026-06-25) then hardened this residual. Do NOT re-create merged code.

**Goal:** Close epic #309 — make the gateway literally host the Discord adapter in production and delete the standalone `alfred-discord` Compose service, so the gateway is the sole comms-platform egress (the Spec C connectivity-free-core prerequisite).

**Architecture:** The gateway-hosted Discord spawn chain (factory, supervisor, credential client, fd-3 delivery, inbound forward bridge, `alfred gateway adapters --wait-ready`) is ALREADY built and merged. The residual is a deployment/cutover: (1) give the core the Discord token via env, (2) activate gateway-hosted Discord in compose, (3) delete the standalone service + its secret bind-mount, (4) retire the standalone `alfred discord` CLI + its orphaned i18n keys, (5) migrate setup scripts (+ an unset-token preflight) and write the operator runbook, (6) annotate docs/ADR + retarget every stale operator doc + verify adversarial coverage. No dual-mode: the standalone path dies in the same slice the gateway-hosted path is activated.

**Tech Stack:** Docker Compose, Python 3.12+ (Typer CLI, Pydantic v2 Settings), pytest, the merged gateway adapter-hosting substrate, `prometheus_client`, pybabel. No new runtime modules — this slice is configuration, deletion, and docs over already-merged code.

## Global Constraints

- **Locked decision — GAP-4 token source = Option A (env on core).** The core resolves `discord_bot_token` from `ALFRED_DISCORD_BOT_TOKEN` (the broker's `_PREFER_FILE` env-fallback, `src/alfred/security/secrets.py:421-422`), mirroring `ALFRED_DEEPSEEK_API_KEY` / `ALFRED_ANTHROPIC_API_KEY`. NO broker code change. The token reaches the gateway-hosted Discord child via spawn-grant → fd-3 ONLY; the gateway and the child never hold a vault key and the child never reads it from env (HARD rule #6 holds — #6 forbids secrets in *plugin* env, not the trusted core's). PRD §7.1 encrypted-vault upgrade tracked separately as **#330**.
- **`_PREFER_FILE` precedence is load-bearing.** `discord_bot_token` is file-preferred: a `secrets.toml` carrying it would SILENTLY shadow `ALFRED_DISCORD_BOT_TOKEN`. The deployed core mounts no `secrets.toml` (verified) so env resolves today, but the runbook + the legacy detector MUST warn about file-shadowing, and Task 1 pins both branches.
- **Locked decision — unset-token posture = guardrails-in-slice + tracked fix (#331).** An unset `ALFRED_DISCORD_BOT_TOKEN` makes the core resolver refuse `missing_secret`, which the supervisor re-raises first-attempt → the `supervise_all` TaskGroup aborts → the gateway process dies, taking the TUI relay leg down (loud + audited, but after `compose up` returns 0). This slice ships GUARDRAILS only: a setup preflight that refuses to enable Discord-hosting without the token, a runbook misconfig section, and a deploy-path test pinning the loud-fail posture. The structural fix (a single hosted-adapter cred-failure should PARK, not abort the gateway) is **#331** — out of scope here.
- **Commit trailers = `#309`, NOT `#288`.** #288 (Spec B) is CLOSED. Every commit: `type(scope): description (#309)`. Conventional Commits. End each commit body with the `MrReasonable <…>` + `Claude-Session:` trailer block.
- **No dual-mode flag-day.** Activation (Tasks 1–2) and deletion (Tasks 3–4) land in ONE PR — never a window where Discord is dark or two processes share one bot token.
- **i18n catalog discipline.** The catalog is **repo-root `locale/`** with domain `alfred` (`locale/en/LC_MESSAGES/alfred.po`), NOT `src/alfred/locale`. Deleting `discord_cmd.py` ORPHANS active keys — retire them with `pybabel extract -F babel.cfg -o locale/alfred.pot . && pybabel update -i locale/alfred.pot -d locale -D alfred --no-fuzzy-matching` (NEVER `--omit-header`, NEVER end in `|| true`). `pybabel compile`. Commit type `feat(i18n):`. CI `pybabel update --check` must be green.
- **No paper gates:** the privileged real-spawn lane (`integration-privileged`) was promoted to REQUIRED on 2026-06-24 (#321, `docs/ci/required-checks.md:45`). Any wire contract proven only there also needs a non-root in-process companion (#245).
- **`make check` before every push; never `--no-verify`; never `--admin` merge.** Resolve the real blocker, then plain `gh pr merge --rebase`. CLAUDE.md is a gitignored rulesync OUTPUT — edit `.rulesync/rules/CLAUDE.md` + regenerate, never the mirror; plain code-span, never a markdown-link to it.
- **Markdownlint** gates tracked `.md`. Keep this plan + the runbook markdownlint-clean.

---

## Already merged — DO NOT re-create (verified @ HEAD d6a5d640)

- `src/alfred/gateway/adapter_child_factory.py` (`GatewayAdapterChildFactory` + the copied fd-3 dup2 spawn window + child-reaping + `_ADAPTER_LAUNCH_TARGETS`), `adapter_stdio_transport.py`, `adapter_supervisor.py`, `adapter_credential_client.py`, `inbound_forward_runner.py`.
- `GatewayProcess._build_adapter_supervisor` wires the real factory; the `_UnspawnedAdapterChildFactory` placeholder is GONE.
- The Discord child reads the token from fd-3 (`plugins/alfred_discord/lifecycle.py` `Fd3TokenSource`; `server.py` wires it). It no longer self-brokers.
- `_resolve_hosted_adapter_ids()` maps plugin-package id `alfred_discord` → canonical `discord`, excludes the `tui` dial-in (`src/alfred/cli/gateway/_commands.py`).
- `CoreAdapterCredentialResolver._ADAPTER_SECRET_ALLOWLIST = {"discord": "discord_bot_token"}` resolves via `broker.get` once, cached (`src/alfred/comms_mcp/adapter_credential_resolver.py`).
- `alfred gateway adapters [--wait-ready]` reads per-adapter status via the ADR-0038 daemon-control `status.query` client (`src/alfred/cli/gateway/_adapters.py`), exit-code contract 0/1/2/3, localized via `t()`.
- Daemon treats Discord as gateway-FORWARDED, not daemon-spawned: `_FORWARDED_INBOUND_KINDS = ("discord",)` (`src/alfred/cli/daemon/_commands.py:364`). The forwarded receiver attaches ONLY on the socket/gateway leg (`adapter_kind=="tui"`), independent of the core's enabled set — so the CORE keeps `["alfred_tui"]` (see Task 2).
- The in-process adversarial credential corpus (a/b/e) is merged + required (`tests/adversarial/comms/test_gateway_credential_corpus.py`); the privileged real-spawn probe runs on the required `integration-privileged` lane.

## What remains (this plan)

Production still runs the OLD path: `alfred-discord` is a standalone service (`docker-compose.yaml:177-210`) reading a `secrets.toml` bind-mount; the gateway enables NO hosted adapter; the `alfred discord` CLI (`src/alfred/cli/discord_cmd.py`) still exists with 4 active i18n keys; `bin/alfred-setup.sh:390` still runs `docker compose run --rm alfred-discord verify`; README / `docs/runbooks/slice-2-discord-smoke.md` / `docs/subsystems/comms.md` / `.env.example` still document the standalone path.

### Scope guards

- **IN:** core `ALFRED_DISCORD_BOT_TOKEN` env (Option A); gateway `ALFRED_COMMS_ENABLED_ADAPTERS` activation; the core-stays-TUI-only invariant; the unset-token deploy-path test + setup preflight (guardrails); delete the `alfred-discord` service + bind-mount; compose-invariant test updates; retire the `alfred discord` CLI + retire its 4 orphaned i18n keys; setup-script `.sh`/`.ps1` migration + precedence guidance + legacy detector; operator runbook; ADR-0036/0015/0039 annotations; README + `.env.example` + `docs/subsystems/comms.md` + `docs/runbooks/slice-2-discord-smoke.md` retarget; adversarial post-cutover verification.
- **OUT (deferred):** the supervisor park-not-abort blast-radius fix (#331). Real persona-outbound reply (#235). Telegram (#40). Egress chokepoint / connectivity-free core (Spec C / #230). PRD §7.1 encrypted vault (#330). Any new gateway runtime module (all merged).

---

## File structure

**Modified:**

- `docker-compose.yaml` — alfred-core: ADD `ALFRED_DISCORD_BOT_TOKEN`. alfred-gateway: ADD `ALFRED_COMMS_ENABLED_ADAPTERS` (`alfred_discord`). DELETE the entire `alfred-discord:` service (lines ~158-210).
- `tests/unit/test_compose_invariants.py` — DELETE `test_alfred_discord_has_no_setuid` + `test_alfred_discord_has_no_state_git_volume`; ADD `test_alfred_discord_service_is_deleted`, `test_alfred_core_has_discord_token_env`, `test_alfred_gateway_hosts_discord`, `test_no_secret_env_or_mount_on_gateway`, `test_alfred_core_comms_adapters_stay_tui_only`.
- `src/alfred/cli/main.py` — DELETE the `discord_app` import (line 64) + `app.add_typer(discord_app, name="discord")` (line 107).
- `locale/en/LC_MESSAGES/alfred.po` (+ `.mo`) — retire the 4 orphaned `cli.discord.*` keys (lines ~289-309).
- `bin/alfred-setup.sh` + `bin/alfred-setup.ps1` — `alfred gateway adapters --wait-ready` replaces the standalone verify; an unset-token preflight; precedence guidance; a legacy detector; identical `.sh`/`.ps1` wording.
- `README.md` (lines ~77-124, ~130, ~150-151), `.env.example`, `docs/subsystems/comms.md` (~53-60, ~198-224), `docs/runbooks/slice-2-discord-smoke.md`, `docs/adr/0036-*.md`, `docs/adr/0015-*.md`, `docs/adr/0039-*.md`.

**Created:**

- `docs/runbooks/2026-06-25-discord-flag-day-migration.md`.
- Tests: `tests/unit/security/test_broker_discord_token_precedence.py`; `tests/integration/test_gateway_unset_discord_token_fails_loud.py` (deploy-path posture); `tests/unit/cli/test_discord_cmd_retired.py`; `tests/unit/test_setup_script_gateway_verify.py` (+ a `.ps1` leaf).

**Deleted:**

- `src/alfred/cli/discord_cmd.py` (+ `tests/unit/cli/test_discord_cmd_launcher.py` — verify no surviving caller first).

---

## Tasks (TDD; each: failing test → RED → minimal change → GREEN → commit `type(scope): description (#309)` + trailer)

### Task 1: Core resolves `discord_bot_token` from env, with precedence pinned (GAP-4) — PREREQUISITE

**Files:**

- Modify: `docker-compose.yaml` (alfred-core `environment:`)
- Create: `tests/unit/security/test_broker_discord_token_precedence.py`
- Modify: `tests/unit/test_compose_invariants.py`

**Interfaces:**

- Consumes: `SecretBroker.get("discord_bot_token")` — `_PREFER_FILE` (file wins; env fallback). No broker change.
- Produces: the deployed core resolves `discord_bot_token` so `CoreAdapterCredentialResolver` answers a `gateway.adapter.spawn_request` for `discord`.

- [ ] **Step 1: Write the failing precedence test** (pins BOTH branches — the env-fallback AND the file-shadows-env precedence the reviewers flagged):

```python
# tests/unit/security/test_broker_discord_token_precedence.py
from pathlib import Path

from alfred.security.secrets import SecretBroker


def test_discord_token_resolves_from_env_when_no_file() -> None:
    """Option A (#309): with no secrets file, the broker resolves discord_bot_token
    from ALFRED_DISCORD_BOT_TOKEN (the _PREFER_FILE env-fallback)."""
    broker = SecretBroker(env={"ALFRED_DISCORD_BOT_TOKEN": "tok-env"})
    assert broker.get("discord_bot_token") == "tok-env"


def test_file_shadows_env_for_discord_token(tmp_path: Path) -> None:
    """_PREFER_FILE precedence: a secrets.toml value SHADOWS the env var. Pinned so the
    migration's 'set it in .env' guidance is honest about file-shadowing (#309)."""
    f = tmp_path / "secrets.toml"
    f.write_text('discord_bot_token = "tok-file"\n')
    f.chmod(0o600)
    broker = SecretBroker(env={"ALFRED_DISCORD_BOT_TOKEN": "tok-env"}, settings_default=f)
    assert broker.get("discord_bot_token") == "tok-file"
```

- [ ] **Step 2: Run; verify behavior.** Run: `uv run pytest tests/unit/security/test_broker_discord_token_precedence.py -v`. Expected: BOTH PASS (the broker already behaves this way — these pin the contract). If the precedence test fails, the `_PREFER_FILE` assumption is wrong — STOP and re-read `secrets.py:get()` before any compose change. Adjust the `SecretBroker(...)` constructor kwargs to the real signature if `settings_default` differs (read `secrets.py` `__init__`).

- [ ] **Step 3: Add the compose env passthrough.** In `docker-compose.yaml`, alfred-core `environment:`, after `ALFRED_ANTHROPIC_API_KEY`:

```yaml
      # #309 GAP-4 (Option A): the core resolves discord_bot_token from env and
      # delivers it to the gateway-hosted Discord child via spawn-grant -> fd-3.
      # Mirrors the provider keys; the gateway/child never hold a vault key. NOTE:
      # discord_bot_token is _PREFER_FILE, so a mounted secrets.toml would SHADOW this.
      ALFRED_DISCORD_BOT_TOKEN: ${ALFRED_DISCORD_BOT_TOKEN:-}
```

- [ ] **Step 4: Write the failing compose-invariant test** in `tests/unit/test_compose_invariants.py`:

```python
def test_alfred_core_has_discord_token_env(compose: dict[str, Any]) -> None:
    """#309 GAP-4: alfred-core carries ALFRED_DISCORD_BOT_TOKEN so the core broker
    resolves the Discord credential (env-fallback) for spawn-grant -> fd-3."""
    core = compose.get("services", {}).get("alfred-core", {})
    env = core.get("environment", {}) or {}
    assert "ALFRED_DISCORD_BOT_TOKEN" in env
```

- [ ] **Step 5: Run; verify pass.** Run: `uv run pytest tests/unit/test_compose_invariants.py::test_alfred_core_has_discord_token_env -v`. Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add docker-compose.yaml tests/unit/security/ tests/unit/test_compose_invariants.py
git commit  # feat(compose): route discord_bot_token to the core via env, pin precedence (#309)
```

### Task 2: Activate gateway-hosted Discord; pin core-stays-TUI; pin the unset-token posture — PREREQUISITE

**Files:**

- Modify: `docker-compose.yaml` (alfred-gateway `environment:`)
- Modify: `tests/unit/test_compose_invariants.py`
- Create: `tests/integration/test_gateway_unset_discord_token_fails_loud.py`

**Interfaces:**

- Consumes: `_resolve_hosted_adapter_ids()` (`alfred_discord` → `discord`, excludes `tui`).
- Produces: the deployed gateway spawns + supervises the Discord child.

- [ ] **Step 1: (STATED FACT — do NOT add `alfred_discord` to the core.)** The core's forwarded-inbound receiver is keyed on the hardcoded `_FORWARDED_INBOUND_KINDS = ("discord",)` and attaches ONLY on the socket/gateway leg (`_listen_socket_comms_adapter`, selected for `adapter_kind=="tui"`), independent of the core's `comms_enabled_adapters`. The core therefore keeps `["alfred_tui"]`. Adding `alfred_discord` to the core's set is ACTIVELY WRONG: `len>1` trips `CommsMultiAdapterUnsupportedFailure` (refuse-boot, `src/alfred/cli/daemon/_commands.py:2254`) AND routes Discord to the stdio-spawn branch (`_spawn_comms_adapter`) — a second Discord process, the exact dual-spawn the flag-day forbids. ONLY the gateway service enables `alfred_discord`.

- [ ] **Step 2: Add the gateway hosted-adapter env.** In `docker-compose.yaml`, alfred-gateway `environment:`:

```yaml
      # Spec B G6-7-8 (#309): the gateway HOSTS the Discord adapter as a bwrap child.
      # _resolve_hosted_adapter_ids maps alfred_discord -> canonical "discord" and
      # excludes the tui dial-in. The gateway holds NO secret — the core resolves the
      # token and delivers it over spawn-grant -> fd-3 at each (re)spawn.
      ALFRED_COMMS_ENABLED_ADAPTERS: '${ALFRED_GATEWAY_HOSTED_ADAPTERS:-["alfred_discord"]}'
```

- [ ] **Step 3: Write the failing compose-invariant tests** in `tests/unit/test_compose_invariants.py`:

```python
def test_alfred_gateway_hosts_discord(compose: dict[str, Any]) -> None:
    """Spec B G6-7-8 (#309): the gateway is configured to host the Discord adapter."""
    gw = compose.get("services", {}).get("alfred-gateway", {})
    env = gw.get("environment", {}) or {}
    assert "alfred_discord" in str(env.get("ALFRED_COMMS_ENABLED_ADAPTERS", ""))


def test_no_secret_env_or_mount_on_gateway(compose: dict[str, Any]) -> None:
    """The gateway holds NO platform secret — neither env nor bind-mount (ADR-0036)."""
    gw = compose.get("services", {}).get("alfred-gateway", {})
    env = gw.get("environment", {}) or {}
    assert "ALFRED_DISCORD_BOT_TOKEN" not in env
    assert "ALFRED_SECRETS_FILE" not in env
    assert not any("secrets.toml" in v for v in _volume_strings(gw.get("volumes", []) or []))


def test_alfred_core_comms_adapters_stay_tui_only(compose: dict[str, Any]) -> None:
    """The CORE must NOT host Discord — adding alfred_discord trips
    CommsMultiAdapterUnsupportedFailure + a second stdio-spawned Discord (dual-spawn).
    Discord is gateway-hosted + forwarded; the core stays alfred_tui-only (#309)."""
    core = compose.get("services", {}).get("alfred-core", {})
    enabled = str(core.get("environment", {}).get("ALFRED_COMMS_ENABLED_ADAPTERS", ""))
    assert "alfred_discord" not in enabled
    assert "alfred_tui" in enabled
```

- [ ] **Step 4: Run; verify pass.** Run: `uv run pytest tests/unit/test_compose_invariants.py -k "gateway_hosts_discord or no_secret_env_or_mount or comms_adapters_stay_tui" -v`. Expected: PASS.

- [ ] **Step 5: Pin the unset-token loud-fail posture (deploy-path test).** This is the guardrail decided for #309 (the structural park-not-abort fix is #331). Mirror the privileged real-spawn provisioning (`skipif` non-Linux/non-root/unprovisioned). With the gateway hosting `discord` and the core's `ALFRED_DISCORD_BOT_TOKEN` UNSET, assert the spawn attempt produces a LOUD, AUDITED `missing_secret` refusal (a signed `result=refused` audit row + the `gateway.adapter.credential_refused` / `spawn_aborted` signal) — i.e. NOT silent-dark. Add a non-root in-process companion that drives the resolver with an unset token and asserts `AdapterCredentialError(missing_secret)` is raised + audited (no root needed). Document in the test docstring that the gateway-process-abort blast radius is the known posture tracked by #331.

```python
# tests/integration/test_gateway_unset_discord_token_fails_loud.py (companion, non-root)
import pytest

from alfred.comms_mcp.adapter_credential_resolver import (
    AdapterCredentialError,
    CoreAdapterCredentialResolver,
)


def test_unset_discord_token_refuses_loud_and_audited(make_resolver) -> None:
    """#309 guardrail: an unset discord token yields a LOUD audited missing_secret
    refusal, never silent-dark. The gateway-abort blast radius is tracked by #331.
    `make_resolver` is a fixture wiring a broker with NO discord_bot_token + a
    capturing audit sink (mirror the merged credential-corpus fixtures)."""
    resolver = make_resolver(env={})  # ALFRED_DISCORD_BOT_TOKEN unset
    with pytest.raises(AdapterCredentialError) as exc:
        resolver.resolve(adapter_id="discord", ...)  # match the real resolve signature
    assert exc.value.reason == "missing_secret"
    # assert a signed result=refused audit row was appended (capturing sink)
```

Read `tests/adversarial/comms/test_gateway_credential_corpus.py` for the real resolver-construction + audit-sink fixture to reuse; match the actual `resolve(...)` signature.

- [ ] **Step 6: Run; verify pass.** Run: `uv run pytest tests/integration/test_gateway_unset_discord_token_fails_loud.py -v`. Expected: PASS (companion). The privileged variant runs on `integration-privileged`.

- [ ] **Step 7: Commit**

```bash
git add docker-compose.yaml tests/unit/test_compose_invariants.py tests/integration/test_gateway_unset_discord_token_fails_loud.py
git commit  # feat(compose): activate gateway-hosted Discord; pin core-tui-only + unset-token posture (#309)
```

### Task 3: Delete the standalone `alfred-discord` Compose service

**Files:**

- Modify: `docker-compose.yaml` (delete the `alfred-discord:` service, ~lines 158-210)
- Modify: `tests/unit/test_compose_invariants.py`

- [ ] **Step 1: Write the failing deletion test** in `tests/unit/test_compose_invariants.py`:

```python
def test_alfred_discord_service_is_deleted(compose: dict[str, Any]) -> None:
    """Spec B G6-7-8 (#309): the standalone alfred-discord service is gone — Discord is
    a gateway-hosted bwrap child. No standalone process, no secrets.toml bind-mount."""
    assert "alfred-discord" not in compose.get("services", {})
```

- [ ] **Step 2: Run; expect FAIL.** Run: `uv run pytest tests/unit/test_compose_invariants.py::test_alfred_discord_service_is_deleted -v`. Expected: FAIL.

- [ ] **Step 3: Delete the service.** Remove the entire `alfred-discord:` block + its leading comment from `docker-compose.yaml`.

- [ ] **Step 4: Delete the now-vacuous invariants.** Remove `test_alfred_discord_has_no_setuid` + `test_alfred_discord_has_no_state_git_volume`. Leave `test_setuid_allowed_set_is_core_and_gateway` + `test_bwrap_security_opt_set_is_core_and_gateway` UNCHANGED — they assert the set is exactly `{core, gateway}`, which still holds and is strictly stronger (a re-added discord-with-SETUID fails them).

- [ ] **Step 5: Run the full compose-invariant suite; verify green.** Run: `uv run pytest tests/unit/test_compose_invariants.py -v`. Expected: ALL PASS.

- [ ] **Step 6: Commit**

```bash
git add docker-compose.yaml tests/unit/test_compose_invariants.py
git commit  # chore(compose): delete the standalone alfred-discord service (#309)
```

### Task 4: Retire the `alfred discord` CLI + its orphaned i18n keys

**Files:**

- Delete: `src/alfred/cli/discord_cmd.py` (+ `tests/unit/cli/test_discord_cmd_launcher.py`)
- Modify: `src/alfred/cli/main.py` (remove import line 64 + `add_typer` line 107)
- Modify: `locale/en/LC_MESSAGES/alfred.po` (+ `.mo`) — retire 4 orphaned keys
- Create: `tests/unit/cli/test_discord_cmd_retired.py`

- [ ] **Step 1: Verify dispositions (concrete list; do NOT leave a dangling import).** Run: `grep -rn "discord_cmd\|discord_app\|alfred discord\|discord verify\|cli.discord" src/alfred/ bin/ tests/ locale/ --include=*.py --include=*.sh --include=*.po`. Known sites:
  - `src/alfred/cli/main.py:64,107` → DELETE (Step 5).
  - `src/alfred/cli/discord_cmd.py` → DELETE (Step 5).
  - `tests/unit/cli/test_discord_cmd_launcher.py` → DELETE unless it carries still-relevant launcher assertions (re-point to the gateway factory path if so).
  - `tests/smoke/test_discord_gateway_smoke.py` → already targets `alfred gateway adapters --wait-ready discord` (correct); only its DOCSTRING narrates the standalone path as "STILL EXISTS" — update to past-tense (#309 done). NO functional change.
  - `tests/unit/cli/test_launcher_spawn_handoff.py` → read it; if it exercises the standalone Discord launcher-spawn, re-point/retire with no coverage loss; its docstring (lines ~5/9/64) narrates the retired verify — update. If generic, leave the code, fix the docstring.
  - `locale/en/LC_MESSAGES/alfred.po:~289-309` → the 4 orphaned keys `cli.discord.help.group`, `cli.discord.help.verify.short`, `cli.discord.help.verify.timeout`, `cli.discord.daemon_required` → retire (Step 7).
  - `bin/alfred-setup.sh` → handled in Task 5.

- [ ] **Step 2: Confirm Discord is gateway-forwarded, not daemon-spawned.** Read `tests/unit/cli/daemon/test_daemon_comms_spawn.py`. Confirm no test requires the daemon to STDIO-spawn Discord. If a Discord daemon-spawn case exists, re-point it to `alfred_tui` / a fixture adapter with NO coverage loss; note it here.

- [ ] **Step 3: Write the failing retirement test.**

```python
# tests/unit/cli/test_discord_cmd_retired.py
from typer.testing import CliRunner

from alfred.cli.main import app


def test_alfred_discord_command_is_retired() -> None:
    """Spec B G6-7-8 (#309): the standalone `alfred discord` CLI is gone. Verify via
    `alfred gateway adapters --wait-ready discord`."""
    result = CliRunner().invoke(app, ["discord", "--help"])
    assert result.exit_code != 0
```

- [ ] **Step 4: Run; expect FAIL.** Run: `uv run pytest tests/unit/cli/test_discord_cmd_retired.py -v`. Expected: FAIL (exit_code 0).

- [ ] **Step 5: Remove the registration + delete the module.** In `main.py` delete the `from alfred.cli.discord_cmd import discord_app` import + the `app.add_typer(discord_app, name="discord")` call (+ comment). Delete `src/alfred/cli/discord_cmd.py` and `tests/unit/cli/test_discord_cmd_launcher.py` (if dead). Update the smoke + launcher-handoff docstrings (Step 1).

- [ ] **Step 6: Run; verify pass + clean import.** Run: `uv run pytest tests/unit/cli/test_discord_cmd_retired.py -v && uv run python -c "import alfred.cli.main"`. Expected: PASS + clean.

- [ ] **Step 7: Retire the orphaned i18n keys.** Run (correct catalog path + domain — confirm against `babel.cfg`):

```bash
uv run pybabel extract -F babel.cfg -o locale/alfred.pot .
uv run pybabel update -i locale/alfred.pot -d locale -D alfred --no-fuzzy-matching
uv run pybabel compile -d locale -D alfred
uv run pybabel update -i locale/alfred.pot -d locale -D alfred --no-fuzzy-matching --check  # drift gate must pass
```

Confirm the 4 `cli.discord.*` keys are moved to obsolete (`#~`) and no other source references them. If `babel.cfg` / paths differ from the above, use the actual repo conventions (read `babel.cfg` + an existing i18n commit).

- [ ] **Step 8: Commit** (two commits — code retire, then i18n)

```bash
git add src/alfred/cli/main.py tests/unit/cli/ tests/smoke/test_discord_gateway_smoke.py
git rm src/alfred/cli/discord_cmd.py
git commit  # refactor(cli): retire the standalone `alfred discord` command (#309)
git add locale/
git commit  # feat(i18n): retire the orphaned cli.discord.* catalog keys (#309)
```

### Task 5: Setup-script migration (`.sh` + `.ps1`) + unset-token preflight

**Files:**

- Modify: `bin/alfred-setup.sh`, `bin/alfred-setup.ps1`
- Create: `tests/unit/test_setup_script_gateway_verify.py` (with a `.ps1` leaf)

- [ ] **Step 1: Write the failing grep tests** (cover BOTH scripts):

```python
# tests/unit/test_setup_script_gateway_verify.py
from pathlib import Path

ROOT = Path(__file__).parent.parent.parent
SH = ROOT / "bin" / "alfred-setup.sh"
PS1 = ROOT / "bin" / "alfred-setup.ps1"


def test_sh_uses_gateway_adapters_verify() -> None:
    text = SH.read_text()
    assert "alfred-discord verify" not in text
    assert "gateway adapters --wait-ready" in text
    assert "ALFRED_DISCORD_BOT_TOKEN" in text


def test_ps1_uses_gateway_adapters_verify() -> None:
    text = PS1.read_text()
    assert "alfred-discord verify" not in text
    assert "gateway adapters --wait-ready" in text
    assert "ALFRED_DISCORD_BOT_TOKEN" in text
```

- [ ] **Step 2: Run; expect FAIL.** Run: `uv run pytest tests/unit/test_setup_script_gateway_verify.py -v`. Expected: FAIL.

- [ ] **Step 3: Migrate `bin/alfred-setup.sh`.** Replace the `docker compose run --rm alfred-discord verify` block (~388-396) with a gateway-adapter verify + an unset-token PREFLIGHT (the #309 guardrail) + a legacy detector + a `_PREFER_FILE` precedence note. Remove EVERY stale standalone echo (the token guidance ~195-200, the verify ~388-396, the `up -d alfred-discord` ~407):

```bash
    # #309 preflight: gateway-hosted Discord needs the token core-side, or the gateway
    # ABORTS at first spawn (loud + audited, but it takes the relay down — #331). Refuse
    # to bring Discord up without it rather than ship a green stack with a dead bot.
    if grep -q '^\s*alfred-discord:' docker-compose.yaml 2>/dev/null; then
      warn "Legacy alfred-discord Compose service detected — removed in the #309 flag-day. Pull latest docker-compose.yaml. See docs/runbooks/2026-06-25-discord-flag-day-migration.md."
    fi
    if docker compose ps --services 2>/dev/null | grep -qx alfred-discord; then
      warn "A stale alfred-discord container is running — 'docker compose down' then 'up -d'."
    fi
    if [[ -n "${ALFRED_DISCORD_BOT_TOKEN:-}" ]]; then
      step "Verifying gateway-hosted Discord adapter"
      if alfred gateway adapters --wait-ready discord; then
        echo "Discord adapter is up (gateway-hosted)."
      else
        warn "Discord not ready; inspect 'docker compose logs alfred-gateway' or re-run."
      fi
    else
      warn "ALFRED_DISCORD_BOT_TOKEN is unset — NOT enabling Discord. Set it in .env (NOT secrets.toml, which would shadow env) then 'docker compose up -d alfred-gateway'."
    fi
```

Re-point the token guidance to `ALFRED_DISCORD_BOT_TOKEN` in `.env`; replace the `up -d alfred-discord` echo with `up -d alfred-gateway`.

- [ ] **Step 4: Mirror in `bin/alfred-setup.ps1`** with IDENTICAL wording (same warn/step strings; PowerShell `$env:ALFRED_DISCORD_BOT_TOKEN` + `docker compose` calls). The `.ps1` had no Discord logic — this is an additive, parity path.

- [ ] **Step 5: Run; verify pass.** Run: `uv run pytest tests/unit/test_setup_script_gateway_verify.py -v`. Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add bin/alfred-setup.sh bin/alfred-setup.ps1 tests/unit/test_setup_script_gateway_verify.py
git commit  # feat(setup): gateway-adapter verify + unset-token preflight replace standalone Discord (#309)
```

### Task 6: Operator migration runbook

**Files:**

- Create: `docs/runbooks/2026-06-25-discord-flag-day-migration.md`

- [ ] **Step 1: Write the runbook.** Concretely cover: (a) the token moves from `secrets.toml` `discord_bot_token` (deleted service) → `ALFRED_DISCORD_BOT_TOKEN` in `.env` (core env) — and that a re-mounted `secrets.toml` would SHADOW the env var (`_PREFER_FILE` precedence); (b) `docker compose logs alfred-discord` no longer exists → use `docker compose logs alfred-gateway` + `alfred gateway adapters`; (c) the standalone service is deleted — `docker compose up -d` starts no `alfred-discord`; (d) verify with `alfred gateway adapters --wait-ready discord` and a per-exit-code action table: `0` ready / `1` not-ready-timeout (check token + gateway logs) / `2` control-unavailable (is the daemon up?) / `3` unknown-adapter (typo / not enabled); (e) **MISCONFIG: unset token** — symptom is a green `compose up` then a dead bot; the gateway logs a `missing_secret` refusal and (today) the gateway process aborts and the TUI relay drops (known posture, tracked by #331) → fix: set `ALFRED_DISCORD_BOT_TOKEN` in `.env`, `docker compose up -d alfred-gateway`; (f) rollback: revert the PR (no data migration — the token just moves env vars). Anchor to ADR-0036 (inversion) + ADR-0039 (inbound bridge).

- [ ] **Step 2: Markdownlint the runbook** (use the working-tree glob form to get GFM parsing). Fix any finding.

- [ ] **Step 3: Commit**

```bash
git add docs/runbooks/2026-06-25-discord-flag-day-migration.md
git commit  # docs(runbook): operator migration for the Discord flag-day (#309)
```

### Task 7: Retarget stale docs + adversarial verification + ADR annotations + quality bar

**Files:**

- Modify: `README.md`, `.env.example`, `docs/subsystems/comms.md`, `docs/runbooks/slice-2-discord-smoke.md`, `docs/adr/0036-*.md`, `docs/adr/0015-*.md`, `docs/adr/0039-*.md`
- Possibly modify: `tests/adversarial/comms/test_gateway_credential_corpus.py`

- [ ] **Step 1: Retarget every stale operator doc (enumerated).**
  - `README.md` (~77-124, ~130, ~150-151): replace the `secrets.toml` token guidance with `ALFRED_DISCORD_BOT_TOKEN` in `.env`; replace `docker compose run --rm alfred-discord verify` with `alfred gateway adapters --wait-ready discord`; replace `docker compose up -d alfred-discord` with `up -d alfred-gateway`.
  - `.env.example`: ADD an `ALFRED_DISCORD_BOT_TOKEN=` line with a comment (the canonical template for Option A's "set it in .env" UX).
  - `docs/subsystems/comms.md` (~53-60, ~198-224): retire the `alfred discord verify` probe section + the `src/alfred/cli/discord_cmd.py` reference; replace with the gateway-hosted verify.
  - `docs/runbooks/slice-2-discord-smoke.md`: reconcile (it is the standalone walkthrough CLAUDE.md cites) — either retarget to the gateway-hosted path or add a header superseding it with a pointer to the new migration runbook. Do NOT leave a broken operator path.
  - CLAUDE.md gateway row: confirm `adapters` is present (#329); if it lacks `--wait-ready`, propose the addition via `.rulesync/rules/CLAUDE.md` + `rulesync generate` (human-gated; plain code-span; NEVER edit the gitignored mirror).

- [ ] **Step 2: Verify adversarial coverage holds post-cutover.** Read `tests/adversarial/comms/test_gateway_credential_corpus.py` + the privileged real-spawn probe. Confirm the corpus exercises the gateway-hosted Discord child with the core-env token source (a: cross-adapter cred isolation; b: no-retained-cred + `/proc` env-absence on the child; g: per-adapter serial-harvest). CONFIRM the privileged probe sources the token the way production does (env → spawn-grant → fd-3) — if it injects by fixture/file in a way that diverges from the env path, ADD a minimal env-sourced real-child case on `integration-privileged` WITH a non-root companion. If coverage already holds, record that and add NO test.

- [ ] **Step 3: Annotate the ADRs.** ADR-0036: `> **G6-7-8 annotation (#309):** the Discord flag-day completed — standalone alfred-discord service deleted; the gateway hosts the Discord bwrap child in production; the credential is sourced from the core's ALFRED_DISCORD_BOT_TOKEN env (#309 GAP-4 Option A) and delivered over spawn-grant -> fd-3 (gateway/child hold no vault key). Unset-token blast radius tracked by #331; PRD §7.1 vault by #330.` One-line annotations on ADR-0015 (gateway as a second bwrap host now hosts Discord in production) and ADR-0039 (the inbound bridge this flag-day realizes in production).

- [ ] **Step 4: Full quality bar.** Run, all green:

```bash
uv run ruff check . && uv run ruff format --check .
uv run mypy src/ && uv run pyright src/
uv run pytest tests/unit -q
uv run pytest tests/unit/test_compose_invariants.py -v
uv run pybabel update -i locale/alfred.pot -d locale -D alfred --no-fuzzy-matching --check
```

Markdownlint the committed docs via the working-tree glob. The privileged-lane real-spawn + unset-token posture run on `integration-privileged`; reproduce locally via `docker run --rm --privileged --platform linux/amd64 debian:bookworm` if Step 2 added a case.

- [ ] **Step 5: Commit**

```bash
git add README.md .env.example docs/ tests/adversarial/
git commit  # docs(gateway): close the Discord flag-day — retarget operator docs + ADR annotations (#309)
```

---

## Self-review checklist (run before opening the PR)

- GAP-4 = Option A: `ALFRED_DISCORD_BOT_TOKEN` on alfred-core ONLY; gateway/child carry no secret env/mount; child reads fd-3 (HARD rule #6 holds). No broker code change. `_PREFER_FILE` file-shadows-env precedence pinned (Task 1) + documented (runbook/setup).
- Core stays `["alfred_tui"]` — adding `alfred_discord` would refuse-boot + double-spawn; pinned by `test_alfred_core_comms_adapters_stay_tui_only`.
- Activation (Tasks 1-2) lands BEFORE deletion (Tasks 3-4) in the same PR — no dark window, no two-process token share.
- Unset-token posture: guardrails shipped (setup preflight + deploy-path loud-fail test + runbook misconfig section); the structural park-not-abort fix is deferred to #331 and NOT attempted here.
- i18n: the 4 orphaned `cli.discord.*` keys retired via the CORRECT catalog (`locale/ -D alfred`, `--no-fuzzy-matching`, never `--omit-header`/`|| true`); `pybabel update --check` green; commit `feat(i18n):`.
- The `{core, gateway}` SETUID/bwrap allowed-set invariants stay green; only the two vacuous Discord negatives removed; deletion + activation + tui-only invariants added.
- Discord confirmed gateway-FORWARDED (`_FORWARDED_INBOUND_KINDS`), not daemon-spawned; no dangling `alfred discord` CLI import; smoke + launcher-handoff docstrings refreshed.
- Every stale operator doc retargeted (README, `.env.example`, comms.md, slice-2-discord-smoke.md); ADR-0036/0015/0039 annotated; CLAUDE.md via `.rulesync/` only.
- Adversarial coverage verified against the post-cutover env-sourced-token reality; a real-child case added ONLY if a gap is proven, always with a non-root companion (no paper gate).
- Every commit trailer is `(#309)`, never `(#288)`. `make check` green before push; markdownlint-clean docs.

## PR + close-out

- One PR titled `Spec B G6-7-8: Discord flag-day — gateway-hosted Discord, delete the standalone service (#309)`.
- Run `/review-pr` (security ALWAYS) + CodeRabbit. Resolve every thread. With `enforce_admins=false`, resolving all conversation threads flips the PR to CLEAN/APPROVED → plain `gh pr merge --rebase`. NEVER `--admin`, NEVER dismiss a CR review to force merge.
- On merge: `gh issue close 309` noting the flag-day completed (gateway-hosted Discord; standalone deleted; token via core env per GAP-4 Option A). Open follow-ups: #331 (supervisor park-not-abort), #330 (PRD §7.1 vault). Spec C (G7) is then unblocked.
