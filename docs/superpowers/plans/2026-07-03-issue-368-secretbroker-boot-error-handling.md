# Issue #368 — Route `SecretBrokerConfigError` through clean CLI / boot-refusal handling

> REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Checkbox (`- [ ]`) steps.
>
> **NOT a behaviour change** — `SecretBrokerConfigError` already fails the process closed today; this only changes *how it surfaces* (clean audited refusal / clean CLI exit vs a raw Python traceback). Fail-closed is preserved. Security-adjacent (secret broker) → adversarial suite + security review, but no behaviour-gate / maintainer merge-sign-off needed (unlike #363).

**Goal:** `SecretBrokerConfigError` (+ subclasses `SecretBrokerPermissionsError` / `FileMissingError` / `NotAFileError`) is uncaught on every `build_broker()` path, so a fail-closed secrets error surfaces as a **raw traceback**. #363 widened its reachability to the host-default `~/.config/alfred/secrets.toml` (e.g. a dotfiles-git `$HOME`), but it was already reachable via `ALFRED_SECRETS_FILE` / a bad bind-mount. Wire it into the two established handling patterns so it surfaces cleanly — implementing what `secrets.py:130`'s docstring already says the design intended ("the CLI top-level dispatch catches `SecretBrokerConfigError` once and routes i18n on the concrete subtype").

## Global Constraints

- **No behaviour change to fail-closed.** The process still refuses to start on a bad secrets file; only the surfacing changes (audited refusal / clean exit). Existing `test_secrets.py` fail-closed tests stay green.
- **Two existing patterns (do NOT invent a third):**
  - **CLI clean-exit** — mirror `load_settings_or_die` (`_bootstrap.py:78-108`, `except SettingsError → typer.echo(t(...)) + typer.Exit(2)`). The secrets subtypes already carry a `t()`-rendered message (each raises with `t("secrets.*", ...)`), so the handler echoes `str(exc)` + exits.
  - **Daemon audited-refusal** — `_start_async`'s `except (SQLAlchemyError, HookError, ManifestError, OSError)` arm already maps boot-infra errors to `boot_infra_install_failed` (exit 2 + `daemon.boot.failed` audit row, never a traceback — `_commands.py:1669` docstring). `SecretBrokerConfigError` is an `AlfredError`, NOT in that tuple → add it.
- **i18n:** no NEW strings — the messages exist (`secrets.file_perms_too_open`, `file_in_git_repo`, `path_is_directory`, `file_missing_required`). The handler renders the exception's existing message. (If a top-level "secrets config problem" preamble is wanted, that's ONE new `t()` key — decide in Task 1.)
- **Security subsystem-adjacent.** Adversarial suite (release-blocking) + `alfred-security-engineer` reviewer. `security/*` coverage stays 100%.
- **Commit trailers** (every commit) + Conventional Commits + `#368` in each subject. **Branch:** `368-secretbroker-boot-error-handling`.

## File Structure

- `src/alfred/cli/_bootstrap.py` — **Modify.** Add `build_broker_or_die(settings) -> SecretBroker` (mirrors `load_settings_or_die`); export it. Keep `build_broker` (the raw factory) for callers that want to handle errors themselves / for the daemon path.
- `src/alfred/cli/main.py` (`status`, :183), `src/alfred/cli/supervisor.py` (:87), `src/alfred/cli/operator_session.py` (:456, :519) — **Modify.** Use `build_broker_or_die`.
- `src/alfred/cli/daemon/_commands.py` — **Modify.** Add `SecretBrokerConfigError` to `_start_async`'s boot-infra `except` tuple (+ import). Confirm `_build_boot_outbound_dlp`'s `build_broker` call (:213) is inside that try.
- `tests/unit/cli/…` — **Add.** A CLI clean-exit test (a bad secrets file → `Exit(2)` + the message, NOT a traceback) + a daemon audited-refusal test (`boot_infra_install_failed` row + exit 2). Reuse the `secure_secrets_file`/tmp patterns.

## Tasks (fill in at execution)

- **Task 1 (`feat(cli): build_broker_or_die` + CLI callers):** add the helper; migrate `status`/supervisor/operator-session; CLI clean-exit test. Decide the render (echo `str(exc)` vs a `t()` preamble + subtype message).
- **Task 2 (`fix(daemon): audited refusal for SecretBrokerConfigError`):** add the type to `_start_async`'s except tuple; daemon audited-refusal test (assert the `daemon.boot.failed` / `boot_infra_install_failed` audit row + exit 2). Verify the `build_broker` call is inside the guarded region.
- **Task 3 (gate):** ruff/mypy/pyright, `tests/unit/cli` + `tests/unit/security`, `security/*` 100% coverage, **release-blocking `tests/adversarial`**, then PR → full `/review-pr` fleet (security ALWAYS) + CR → merge (autonomous-OK; no behaviour-gate).

## Self-Review (pre-implementation)

- Both patterns verified present (`load_settings_or_die` except-SettingsError; `_start_async` except-tuple → boot_infra_install_failed). ✓
- No behaviour change — fail-closed preserved; only surfacing changes. ✓
- Implements the `secrets.py:130` intended-but-missing "catch once + route on subtype". ✓
- Fixes the PRE-EXISTING gap (env-var/bind-mount trigger), not only the #363-widened host-default one. ✓
- Excludes the `.git`-walk *narrowing* (that's #366 — an ADR-0012 amendment / genuine design call, held for the maintainer). ✓

## Execution outcome (2026-07-03, PR #369)

- **Daemon mechanism landed as *dedicated* `try/except SecretBrokerConfigError` guards, not an addition to the existing 2188-2205 boot-infra `except` tuple.** Task 1's "Verify the `build_broker` call is inside the guarded region" check found it was NOT — `_build_boot_outbound_dlp` is invoked ~65 lines *after* that tuple closes. So a dedicated guard was wrapped around that call (plus a defense-in-depth guard on the comms-graph call-site, which builds a second broker). Same audited outcome (`_refuse_boot` → exit 2 + `boot_infra_install_failed`), different mechanism than the one-line summary anticipated.
- **CLI renders `str(exc)`** (the subtype's already-`t()`-rendered, actionable message). The daemon arms *also* pass `str(exc)` as the operator-facing refusal message (devex dx-001) so a secrets misconfig is not misdirected to the generic capability-gate/hook-registry boot-infra text — while the audit row keeps the `boot_infra_install_failed` reason. Zero new i18n strings, zero new failure classes, as constrained.
- **Deferred to follow-ups (out of #368 scope):** a dedicated `secrets_config_failed` boot-failure reason + audit-subject detail (new failure class — the plan excluded these); wrapping `tomllib.TOMLDecodeError` / bare `OSError` from `SecretBroker` construction in a typed `SecretBrokerConfigError` subtype (a `src/alfred/security/` change this PR kept out of scope); surfacing the resolved secrets-file path in `alfred status`.
