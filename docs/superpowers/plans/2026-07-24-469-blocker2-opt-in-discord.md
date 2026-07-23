# #469 Blocker 2 — opt-in Discord Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the stock `docker compose up -d` quickstart boot by defaulting gateway-hosted Discord OFF (opt-in), and make an explicit *missing*-token opt-in fail with a legible refusal instead of a raw-traceback crash-loop.

**Architecture:** Flip the compose `ALFRED_GATEWAY_HOSTED_ADAPTERS` default to `[]` (aligning it with the already-empty code default), thread the setup script to seed the var when a token is present, and add a narrow `GatewayAdapterCredentialError` marker (raised at the supervisor's already-audited credential-refusal arm) that `start_gateway` catches to render a friendly refusal + exit 10 — while genuine bugs and security refusals keep surfacing loud.

**Tech Stack:** Python 3.14+, Typer CLI, pydantic-settings, structlog, pytest, Babel/`pybabel` (domain `alfred`), Docker Compose, Bash + PowerShell setup scripts.

**Spec:** `docs/superpowers/specs/2026-07-23-469-blocker2-gateway-optin-discord-design.md` (v4).

## Global Constraints

- **Never bypass the capability/trust layer; never `--no-verify`; never weaken a security default.** (CLAUDE.md HARD.)
- **No silent failures in security paths** — the new arm must `log.warning(...)` and exit non-zero; bugs/override-refusals must still surface loud (hard rule #7).
- **Audit is non-skippable** — the missing-token path already writes `_audit_spawn_aborted` before the raise; keep it.
- **i18n:** every operator-facing string goes through `t()`; catalog is `locale/en/LC_MESSAGES/alfred.po`, pybabel domain **`alfred`** (use `-D alfred`); re-run `pybabel extract`+`update` after inserting the new key (a mid-function insert stales downstream `#:` refs). Bash/PowerShell strings and structlog event keys are NOT `t()` scope.
- **Coverage:** `cli/gateway/_commands.py` is under the 75% floor (no per-module 100% gate); `adapter_supervisor.py` **is** under a per-module 100% line+branch gate — every new branch there must be covered.
- **Conventional Commits:** every commit subject carries `#469` after the colon.
- **OUT of scope:** invalid-token legibility (#493 — a wrong token stays loud here); #331 park-not-abort; CLAUDE.md/PRD edits (human-gated). Do NOT touch `plugins/alfred_discord/`, `comms_runner.py`, `adapter_child_factory.py`, or `comms_mcp/protocol.py` — those are #493.

---

### Task 1: Compose default flip + comment + invariant tests

**Files:**
- Modify: `docker-compose.yaml:275` (the default) and `:271-274` (the comment)
- Test: `tests/unit/test_compose_invariants.py:363-367` (invert `test_alfred_gateway_hosts_discord`)

**Interfaces:**
- Produces: the stock compose default `ALFRED_GATEWAY_HOSTED_ADAPTERS:-[]`. Nothing else consumes this at the code level (the code default is already `Field(default=())`).

- [ ] **Step 1: Rewrite the failing invariant test** — replace `test_alfred_gateway_hosts_discord` with an opt-in assertion.

```python
def test_alfred_gateway_defaults_to_no_hosted_adapter(compose: dict[str, Any]) -> None:
    """#469 Blocker 2: Discord is opt-in — the shipped default hosts NO adapter, but the
    ALFRED_GATEWAY_HOSTED_ADAPTERS override is still wired so an operator can enable it."""
    gw = compose.get("services", {}).get("alfred-gateway", {})
    raw = str(gw.get("environment", {}).get("ALFRED_COMMS_ENABLED_ADAPTERS", ""))
    assert "alfred_discord" not in raw  # default no longer hosts Discord
    assert "ALFRED_GATEWAY_HOSTED_ADAPTERS" in raw  # opt-in override still wired
    assert ":-[]" in raw or ":- []" in raw  # default fallback is the empty list
```

- [ ] **Step 2: Run it — expect FAIL** (`uv run pytest tests/unit/test_compose_invariants.py::test_alfred_gateway_defaults_to_no_hosted_adapter -v`). Expected: FAIL (current default still `["alfred_discord"]`).

- [ ] **Step 3: Flip the compose default and fix the comment.**

```yaml
      # Gateway-hosted comms adapters (#469 ADR-0054): DEFAULT EMPTY — Discord is opt-in.
      # Enable it by setting BOTH ALFRED_DISCORD_BOT_TOKEN and
      # ALFRED_GATEWAY_HOSTED_ADAPTERS=["alfred_discord"] in .env (bin/alfred-setup.sh
      # seeds the latter when the token is present). _resolve_hosted_adapter_ids maps
      # alfred_discord -> canonical "discord" and excludes the tui dial-in.
      ALFRED_COMMS_ENABLED_ADAPTERS: '${ALFRED_GATEWAY_HOSTED_ADAPTERS:-[]}'
```

- [ ] **Step 4: Add the interpolation test** (devops-003) in the same file.

```python
def test_hosted_adapters_default_and_override_interpolate(tmp_path: Path) -> None:
    """`docker compose config` renders the empty default and an explicit override."""
    # default (no env): ALFRED_COMMS_ENABLED_ADAPTERS resolves to []
    out_default = _compose_config_env(tmp_path, env={})  # helper: runs `docker compose config`
    assert out_default["alfred-gateway"]["ALFRED_COMMS_ENABLED_ADAPTERS"] == "[]"
    out_optin = _compose_config_env(tmp_path, env={"ALFRED_GATEWAY_HOSTED_ADAPTERS": '["alfred_discord"]'})
    assert out_optin["alfred-gateway"]["ALFRED_COMMS_ENABLED_ADAPTERS"] == '["alfred_discord"]'
```

Note: gate this test with the existing docker-availability marker used elsewhere in the suite (grep for `docker compose config` / `requires_docker`); if none exists, `pytest.importorskip`/`shutil.which("docker")` skip. Keep it a unit-fast static check, not a full `up`.

- [ ] **Step 5: Add a positive-boot resolver test** (comms-003) in `tests/unit/cli/gateway/` — an empty `ALFRED_COMMS_ENABLED_ADAPTERS` resolves to `[]`.

```python
def test_resolve_hosted_adapter_ids_empty_is_no_op(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ALFRED_COMMS_ENABLED_ADAPTERS", "[]")
    from alfred.cli.gateway._commands import _resolve_hosted_adapter_ids
    assert _resolve_hosted_adapter_ids() == []
```

- [ ] **Step 6: Update the integration-test docstring** (test-008) — in `tests/integration/test_gateway_unset_discord_token_fails_loud.py`, note that the resolver behaviour is unchanged but the *stock compose default* no longer triggers this path (Discord is now opt-in). Docstring-only; no assertion change.

- [ ] **Step 7: Run the tests — expect PASS** (`uv run pytest tests/unit/test_compose_invariants.py tests/unit/cli/gateway tests/integration/test_gateway_unset_discord_token_fails_loud.py -v`).

- [ ] **Step 8: Commit.**

```bash
git add docker-compose.yaml tests/unit/test_compose_invariants.py tests/unit/cli/gateway tests/integration/test_gateway_unset_discord_token_fails_loud.py
git commit -m "fix(compose): #469 default gateway-hosted adapters to empty (opt-in Discord)"
```

---

### Task 2: `GatewayAdapterCredentialError` marker at the supervisor credential arm

**Files:**
- Modify: `src/alfred/gateway/adapter_supervisor.py` (add the class near `GatewayAdapterSpawnError:109`; change the credential-refusal wrap at `:490-503`)
- Test: `tests/unit/gateway/test_adapter_supervisor_credential.py`

**Interfaces:**
- Produces: `class GatewayAdapterCredentialError(GatewayAdapterSpawnError)` in `alfred.gateway.adapter_supervisor`. Raised (first-attempt) when the credential resolver refuses (`missing_secret`/`grant_mismatch`/`delivery_failed`). Task 3 imports and catches it. **A non-credential first-attempt spawn failure still raises the bare `GatewayAdapterSpawnError`** (unchanged).

- [ ] **Step 1: Write the failing supervisor test** — a first-attempt `missing_secret` refusal raises the marker (a `GatewayAdapterSpawnError` subclass) AND still writes the audit row; a non-credential spawn failure raises the bare base type.

```python
async def test_first_attempt_credential_refusal_raises_marker(...):
    # existing fixture wiring: empty broker -> AdapterCredentialError(missing_secret)
    with pytest.raises(GatewayAdapterCredentialError):   # the marker subclass
        await supervisor._spawn_or_terminal(run)
    assert any(r.get("result") == "refused" for r in audit.rows)  # _audit_spawn_aborted intact

async def test_first_attempt_non_credential_spawn_failure_stays_bare(...):
    # factory raises a plain GatewayAdapterSpawnError (a launcher fault, NOT credential)
    with pytest.raises(GatewayAdapterSpawnError) as ei:
        await supervisor._spawn_or_terminal(run)
    assert type(ei.value) is GatewayAdapterSpawnError  # NOT the credential marker
```

- [ ] **Step 2: Run — expect FAIL** (`GatewayAdapterCredentialError` undefined). `uv run pytest tests/unit/gateway/test_adapter_supervisor_credential.py -v`.

- [ ] **Step 3: Add the marker class** near `adapter_supervisor.py:109`.

```python
class GatewayAdapterCredentialError(GatewayAdapterSpawnError):
    """A first-attempt OPERATOR-CREDENTIAL spawn refusal (missing/mismatched/undeliverable
    secret) — distinct from a bare GatewayAdapterSpawnError (a launcher/handshake fault or a
    programming bug), which stays loud. start_gateway catches ONLY this subclass to render a
    friendly, actionable refusal (#469 [R1]); the base type keeps surfacing as a raw
    traceback so hard rule #7 holds. Carries the closed-vocab credential ``reason``."""

    def __init__(self, message: str, *, reason: str) -> None:
        super().__init__(message)
        self.reason = reason
```

- [ ] **Step 4: Change the credential-refusal wrap** at `adapter_supervisor.py:500-503` — the `isinstance(exc, AdapterCredentialError)` branch already audits via `_audit_spawn_aborted(run, reason=exc.reason)`; change the wrapped error it builds from `GatewayAdapterSpawnError(...)` to the marker:

```python
                await self._audit_spawn_aborted(run, reason=exc.reason)
                spawn_error: GatewayAdapterSpawnError = GatewayAdapterCredentialError(
                    f"credential pipeline aborted the spawn (adapter_id={run.adapter_id!r}, "
                    f"reason={exc.reason!r})",
                    reason=exc.reason,
                )
```

Leave the `else: spawn_error = exc` and the `if first_attempt: ... raise spawn_error from exc` logic unchanged — since `spawn_error` is now the marker (not `exc`), `raise spawn_error from exc` propagates the marker.

- [ ] **Step 5: Run — expect PASS** (both tests). `uv run pytest tests/unit/gateway/test_adapter_supervisor_credential.py -v`.

- [ ] **Step 6: Run the per-module 100% gate for the touched module.**

Run: `uv run pytest tests/unit/gateway -q && uv run coverage run -m pytest tests/unit/gateway && uv run coverage report --include='*/adapter_supervisor.py' --show-missing`
Expected: `adapter_supervisor.py` 100% line+branch (add a test for any new uncovered branch — e.g. the marker `__init__`).

- [ ] **Step 7: Commit.**

```bash
git add src/alfred/gateway/adapter_supervisor.py tests/unit/gateway/test_adapter_supervisor_credential.py
git commit -m "feat(gateway): #469 GatewayAdapterCredentialError marker for credential-refusal spawn aborts"
```

---

### Task 3: `start_gateway` friendly refusal + exit 10 + i18n key

**Files:**
- Modify: `src/alfred/cli/gateway/_commands.py` (new exit constant near `:58-81`; lazy import at `:238-267`; new `except` arm in `:391-439`)
- Modify: `locale/en/LC_MESSAGES/alfred.po` (+ recompile)
- Test: `tests/unit/cli/test_gateway_cli.py`

**Interfaces:**
- Consumes: `GatewayAdapterCredentialError` from Task 2.
- Produces: `_EXIT_ADAPTER_SPAWN_FAILED = 10`; the catalog key `gateway.start.adapter_spawn_failed`.

- [ ] **Step 1: Write the failing handler tests** driving the REAL `_main` TaskGroup unwrap (not a direct raise into the arm).

```python
def test_credential_refusal_renders_friendly_message_and_exit_10(monkeypatch, capsys):
    # patch GatewayProcess.run to raise GatewayAdapterCredentialError inside _run_gateway,
    # so the real TaskGroup + _reraise_first_meaningful unwrap is exercised.
    ...
    with pytest.raises(typer.Exit) as ei:
        start_gateway()
    assert ei.value.exit_code == 10
    out = capsys.readouterr().out
    assert "ALFRED_DISCORD_BOT_TOKEN" in out and "ALFRED_GATEWAY_HOSTED_ADAPTERS" in out
    assert "Traceback" not in out
    # non-vacuity: sibling messages are NOT what rendered
    assert t("gateway.start.bind_failed") not in out

def test_bare_spawn_error_still_surfaces_loud(monkeypatch):
    # a bare GatewayAdapterSpawnError (or LaunchTargetOverrideRefusedError) is NOT caught
    with pytest.raises(GatewayAdapterSpawnError):
        start_gateway()

def test_credential_refusal_logs_before_exit(monkeypatch):
    with capture_logs() as logs:
        with pytest.raises(typer.Exit):
            start_gateway()
    assert any(e["event"] == "gateway.cli.adapter_spawn_failed" for e in logs)
```

- [ ] **Step 2: Run — expect FAIL.** `uv run pytest tests/unit/cli/test_gateway_cli.py -k adapter_spawn -v`.

- [ ] **Step 3: Add the exit constant** (near the other `_EXIT_*` at `:58-81`).

```python
# A friendly "a hosted adapter's credential was refused" refusal (#469 [R1]). Distinct
# non-zero so an operator / healthcheck can tell a credential misconfig apart from the
# egress / bind / config refusals. Fail-closed: the gateway still aborts and crash-loops
# under ``restart: unless-stopped`` — this arm only replaces the raw traceback with a
# legible message (surviving the abort is #331; a wrong token is #493).
_EXIT_ADAPTER_SPAWN_FAILED = 10
```

- [ ] **Step 4: Import the marker** into the lazy block (`:238-267`), alongside `GatewayProcess`:

```python
    from alfred.gateway.adapter_supervisor import GatewayAdapterCredentialError
```

- [ ] **Step 5: Add the `except` arm** in the `asyncio.run(_main())` try (place it among the typed AlfredError arms, e.g. right before `except DaemonUnavailableError`). The message is STATIC (no interpolation — matches sibling keys and i18n-003); the adapter/reason ride the structlog line (err-002/err-004).

```python
    except GatewayAdapterCredentialError as exc:
        # Friendly refusal — a hosted adapter's credential was refused at first spawn
        # (#469 [R1]). Distinct from a bare GatewayAdapterSpawnError (a bug / a
        # LaunchTargetOverrideRefusedError security refusal), which is NOT caught here and
        # surfaces loud (hard rule #7). The supervisor already wrote the audit row before
        # the raise. adapter_id + closed-vocab reason go to the log, never the operator text.
        log.warning(
            "gateway.cli.adapter_spawn_failed", error=repr(exc), reason=exc.reason, exc_info=True
        )
        typer.echo(t("gateway.start.adapter_spawn_failed"))
        raise typer.Exit(code=_EXIT_ADAPTER_SPAWN_FAILED) from exc
```

- [ ] **Step 6: Add the catalog message.** Add the key to `locale/en/LC_MESSAGES/alfred.po`:

```
msgid "gateway.start.adapter_spawn_failed"
msgstr "A hosted comms adapter could not start: its credential was refused. The gateway will not become healthy, so alfred-core and `alfred chat` stay down until this is fixed. Either set the adapter's credential (e.g. ALFRED_DISCORD_BOT_TOKEN) in .env, or remove the adapter from ALFRED_GATEWAY_HOSTED_ADAPTERS. See `docker compose logs alfred-gateway` for the specific adapter and reason."
```

Then regenerate + compile (do NOT hand-edit `.mo`):

Run: `pybabel extract -F babel.cfg -o /tmp/alfred.pot -D alfred src/alfred plugins && pybabel update -D alfred -i /tmp/alfred.pot -d locale --ignore-pot-creation-date && pybabel compile -D alfred -d locale --statistics`
Expected: no drift error; the new key compiled.

- [ ] **Step 7: Run — expect PASS** (`uv run pytest tests/unit/cli/test_gateway_cli.py -k adapter_spawn -v`) and the i18n drift gate green (`uv run pytest -k catalog -q` or the repo's i18n test).

- [ ] **Step 8: Commit.**

```bash
git add src/alfred/cli/gateway/_commands.py locale/en/LC_MESSAGES/alfred.po tests/unit/cli/test_gateway_cli.py
git commit -m "feat(gateway): #469 legible credential-refusal at gateway start (exit 10) instead of raw traceback"
```

---

### Task 4: Widen the config-failed arm for the `["discord"]` opt-in typo

**Files:**
- Modify: `src/alfred/cli/gateway/_commands.py:277-282` (the `_resolve_hosted_adapter_ids()` try)
- Test: `tests/unit/cli/test_gateway_cli.py`

**Interfaces:**
- Consumes: the existing `_EXIT_CONFIG_FAILED = 6` + `t("gateway.start.config_failed")`.

- [ ] **Step 1: Write the failing test** — a canonical `["discord"]` (wrong; the package id is `alfred_discord`) makes `Settings()` raise `SettingsError`/`ValueError`; assert the config-failed refusal + exit 6, not a traceback. Assert an unrelated `ValueError` is NOT swallowed.

```python
def test_canonical_discord_typo_renders_config_failed(monkeypatch):
    monkeypatch.setenv("ALFRED_COMMS_ENABLED_ADAPTERS", '["discord"]')  # wrong id
    with pytest.raises(typer.Exit) as ei:
        start_gateway()
    assert ei.value.exit_code == 6  # _EXIT_CONFIG_FAILED
```

- [ ] **Step 2: Run — expect FAIL** (currently a raw `SettingsError` traceback). `uv run pytest tests/unit/cli/test_gateway_cli.py -k typo -v`.

- [ ] **Step 3: Widen the arm** at `_commands.py:277-282`. Import the settings error type and add it to the caught tuple, scoped to the resolve call only:

```python
    from alfred.config.settings import SettingsError  # or the concrete pydantic error type
    try:
        hosted_adapter_ids = _resolve_hosted_adapter_ids()
    except (OSError, ManifestError, SettingsError) as exc:
        log.warning("gateway.cli.config_failed", error=repr(exc))
        typer.echo(t("gateway.start.config_failed"))
        raise typer.Exit(code=_EXIT_CONFIG_FAILED) from exc
```

Confirm the exact exception type raised by `Settings()` on a bad `comms_enabled_adapters` (a `pydantic.ValidationError` subclass or the repo's `SettingsError`); catch that specific type, not bare `ValueError`, so unrelated `ValueError`s still surface loud.

- [ ] **Step 4: Run — expect PASS.** `uv run pytest tests/unit/cli/test_gateway_cli.py -k typo -v`.

- [ ] **Step 5: Commit.**

```bash
git add src/alfred/cli/gateway/_commands.py tests/unit/cli/test_gateway_cli.py
git commit -m "fix(gateway): #469 render config-failed refusal for a bad comms-adapters id, not a traceback"
```

---

### Task 5: Setup-script opt-in coherence (`.sh` + `.ps1`)

**Files:**
- Modify: `bin/alfred-setup.sh` (new top-level step; the advisory at `:502`)
- Modify: `bin/alfred-setup.ps1` (reconcile the stale advisory at `:45`)
- Test: `tests/unit/test_setup_script_env_seed.py` (reuse `tests/_setup_script_helpers.py`)

**Interfaces:**
- Consumes: `read_env_var` helper (already in the script) and the `umask 077` grep-else-append pattern at `alfred-setup.sh:130-134`.

- [ ] **Step 1: Write the failing test** — token present in `.env` → the script ensures `ALFRED_GATEWAY_HOSTED_ADAPTERS=["alfred_discord"]` (idempotent on re-run); commented/empty/placeholder token → NOT added; an existing `=[]` opt-out preserved.

```python
def test_token_present_seeds_hosted_adapters(tmp_env):  # tmp_env writes a .env with a real token
    run_setup_seed_step(tmp_env)
    assert count_lines(tmp_env, r'^ALFRED_GATEWAY_HOSTED_ADAPTERS=\["alfred_discord"\]$') == 1
    run_setup_seed_step(tmp_env)  # idempotent
    assert count_lines(tmp_env, r'^ALFRED_GATEWAY_HOSTED_ADAPTERS=') == 1

def test_token_absent_leaves_default_empty(tmp_env_no_token):
    run_setup_seed_step(tmp_env_no_token)
    assert count_lines(tmp_env_no_token, r'^ALFRED_GATEWAY_HOSTED_ADAPTERS=') == 0

def test_explicit_opt_out_preserved(tmp_env_optout):  # .env already has =[]
    run_setup_seed_step(tmp_env_optout)
    assert count_lines(tmp_env_optout, r'^ALFRED_GATEWAY_HOSTED_ADAPTERS=\[\]$') == 1
```

- [ ] **Step 2: Run — expect FAIL.** `uv run pytest tests/unit/test_setup_script_env_seed.py -k hosted_adapters -v`.

- [ ] **Step 3: Add the top-level seed step** to `bin/alfred-setup.sh` (OUTSIDE the interactive `$snowflake` branch — a dedicated step keyed on the `.env` token, using `read_env_var`, append-if-absent, token-validity check). Match the existing `umask 077` grep-else-append idiom at `:130-134`.

```bash
# #469: seed the opt-in hosted-adapter set when a real Discord token is present in .env.
# Discord is opt-in (compose default is now []); a present token means the operator wants
# it, so make the opt-in coherent. Idempotent; preserves a deliberate =[] opt-out; a
# commented/empty/placeholder token counts as absent (else we'd re-arm the crash-loop).
_discord_token="$(read_env_var ALFRED_DISCORD_BOT_TOKEN)"
if [[ -n "$_discord_token" && "$_discord_token" != "your-"* ]]; then
  if ! grep -qE '^ALFRED_GATEWAY_HOSTED_ADAPTERS=' "$ENV_FILE"; then
    printf '%s\n' 'ALFRED_GATEWAY_HOSTED_ADAPTERS=["alfred_discord"]' >> "$ENV_FILE"
    info "Discord token detected — enabled gateway-hosted Discord (ALFRED_GATEWAY_HOSTED_ADAPTERS)."
  fi
fi
```

(Match the script's actual `$ENV_FILE`/`read_env_var`/`info` names; do not echo the token.)

- [ ] **Step 4: Update the token-unset advisory** at `:502` (devex-004) so its remedy matches the new posture ("Discord is opt-in; set ALFRED_DISCORD_BOT_TOKEN in .env then re-run setup, or set ALFRED_GATEWAY_HOSTED_ADAPTERS manually").

- [ ] **Step 5: Reconcile `bin/alfred-setup.ps1:45`** — confirm whether `.ps1` delegates `.env` seeding to `alfred-setup.sh`-in-WSL (per the repo's Windows story). If it does, update/remove the stale "NOT enabling Discord" advisory to match. If it seeds standalone, add the parallel append. Record the choice in a comment.

- [ ] **Step 6: Run — expect PASS.** `uv run pytest tests/unit/test_setup_script_env_seed.py -v`.

- [ ] **Step 7: Commit.**

```bash
git add bin/alfred-setup.sh bin/alfred-setup.ps1 tests/unit/test_setup_script_env_seed.py
git commit -m "feat(setup): #469 seed opt-in Discord hosted-adapter set when a token is present"
```

---

### Task 6: Docs (README + runbook + .env.example) + ADR-0054

**Files:**
- Modify: `README.md:140-191` (Enable Discord); `.env.example:52-57` (WARNING block); `docs/runbooks/2026-06-25-discord-flag-day-migration.md:119-165,184`
- Create: `docs/adr/0054-gateway-hosted-adapters-default-empty.md`
- Test: `tests/unit/config/test_env_example_no_downgrade.py` (must stay green); markdownlint

- [ ] **Step 1: Update `README.md:140-191`** — the "Enable Discord" walkthrough must set **both** `ALFRED_DISCORD_BOT_TOKEN` and `ALFRED_GATEWAY_HOSTED_ADAPTERS=["alfred_discord"]` (or re-run `bin/alfred-setup.sh`). Remove any implication that the token alone enables Discord.

- [ ] **Step 2: Invert `.env.example:52-57`** — state the default is empty; enabling Discord needs BOTH the token and the var. Keep the `test_env_example_no_downgrade.py` invariant green (run it).

- [ ] **Step 3: Correct the runbook** `2026-06-25-discord-flag-day-migration.md:119-165,184` — the "unset token aborts the gateway" claim becomes the opt-in posture (an unset token = Discord simply not hosted; the gateway boots healthy). Add a forward-pointer to ADR-0054.

- [ ] **Step 4: Write `docs/adr/0054-gateway-hosted-adapters-default-empty.md`** — Context (the crash-loop + PRD §4 SC-1), Decision (default `[]`, opt-in; capability unchanged), Consequences (opt-in-misconfigured = whole-stack-down accepted until #331; a wrong token loud until #493), Alternatives (park-not-abort = #331; setup-hard-gate). Cite the #309 flag-day runbook as the origin of the on-by-default value; state no prior ADR is superseded; note PRD §5 invariants untouched.

- [ ] **Step 5: Lint + green the doc tests.**

Run: `npx --yes markdownlint-cli2@0.22.1 "docs/**/*.md" && uv run pytest tests/unit/config/test_env_example_no_downgrade.py -v`
Expected: 0 markdown errors; env-example test PASS.

- [ ] **Step 6: Commit.**

```bash
git add README.md .env.example docs/runbooks/2026-06-25-discord-flag-day-migration.md docs/adr/0054-gateway-hosted-adapters-default-empty.md
git commit -m "docs(adr): #469 ADR-0054 opt-in Discord default + reconcile README/runbook/.env.example"
```

---

## Definition of Done

- `uv run pytest tests/unit -q` green; `adapter_supervisor.py` 100% line+branch; `make check` exit 0 (lint + format + mypy + pyright + i18n drift + tests).
- Adversarial suite green (Task 2 touches `src/alfred/gateway/` supervisor code adjacent to the trust boundary; run `uv run pytest tests/adversarial` to be safe).
- The stock quickstart boots (UAT: `cp .env.example .env && docker compose up -d` → gateway healthy → core starts); an explicit missing-token opt-in yields the exit-10 legible refusal, not a traceback; a bad-id typo yields the config-failed refusal; a wrong token stays loud (residual → #493).
- Conventional-commit subjects all carry `#469`.
