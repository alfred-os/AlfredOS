# #469 Blocker 1 — Environment Resolution Implementation Plan (v2)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans, task-by-task. Steps use checkbox (`- [ ]`) syntax. Design rationale: `docs/superpowers/specs/2026-07-22-469-blocker1-environment-resolution-design.md` (v2) — read it before Task 1.
>
> **v2** folds a 10-lane `/review-plan` fleet + coordinator (1 Critical, 20 High, …; 63 findings → 31 themes; all disputes resolved). Key changes vs v1: a **new Task 5** closes a launcher `.env`-downgrade the design missed; Task 1 fixes an empty-value regression + fail-closed handling; Task 3/4 corrected against the **real** function/type signatures; Task 8/9 target the **real** coverage + pybabel mechanisms.

**Goal:** Make `alfred daemon start` resolve `Settings.environment` from `.env` (as its own refusal instructs) via one canonical resolver, closing a `production→development` downgrade by construction — at the Settings/gateway paths *and* the bwrap launcher path.

**Architecture:** One `resolve_environment(*, consult_dotenv=True, …)` owns precedence `os.environ["ALFRED_ENVIRONMENT"] > /etc/alfred/environment > .env`. `Settings` delegates via pydantic source-exclusion + a wrap-validator (retiring the ContextVar/dual-validator). In-process security consumers apply a source trust-floor; the **launcher** (stdout→bash, cannot carry the source) instead resolves **trusted-sources-only** (`consult_dotenv=False`) and fails closed to production. Sequenced expand→migrate→contract; each task ends green.

**Tech Stack:** Python 3.14+, pydantic-settings 2.14.2, python-dotenv 1.2.2, pytest, structlog, Babel 2.18/pybabel, uv, ruff, mypy --strict + pyright.

## Global Constraints

- **Precedence (exact):** `os.environ["ALFRED_ENVIRONMENT"] > /etc/alfred/environment > .env`. `.env` lowest, gap-fill only, **never** in a two-source `conflict` (only `UNRECOGNISED` extends).
- **[D3] Short-circuit:** the highest source that is **SET AND NON-EMPTY** decides; if its value ∉ `{development, production, test}` → `UNRECOGNISED`. An **absent OR empty/whitespace** source is skipped — normalize `stripped or None` at all three read sites (a blank `ALFRED_ENVIRONMENT=` must NOT short-circuit to `UNRECOGNISED('')`).
- **[err-01] Fail-closed on an unreadable higher-trust source:** a present-but-unreadable `/etc/alfred/environment` (`PermissionError`/`OSError`/`IsADirectoryError`) must **short-circuit to a distinct audited refusal — never fall through to `.env`** (else hardening `/etc` perms silently triggers the downgrade). `FileNotFoundError` = genuinely absent = skip. `.env` unreadable stays "absent" (its fall-through is `NONE` = fail-closed).
- **[D1]/[launcher] Trust of `.env`:** in-process consumers where dev/test is *permissive* honor dev-mode only when `source ∈ {ENV_VAR, ETC_FILE}`. The launcher path resolves `consult_dotenv=False` (env-var + `/etc` only) and fails closed to production — the stdout→bash interface cannot carry the source.
- **[D2] `.env.example`:** `ALFRED_ENVIRONMENT=production` **uncommented**; comment disambiguates the pre-existing `ALFRED_ENV` capability-gate key.
- **[Db] Post-env `Settings()` failure:** a distinct audited reason `settings_invalid` — and **reuse** `_bootstrap.load_settings_or_die`'s placeholder-key special-case + curated copy (`error.config_invalid`/`hint.copy_env_example`), never raw `str(exc)` (DLP: `str(exc)` can echo a `database_url` DSN password).
- **`.env` parse:** `dotenv_values(path, interpolate=False)`; catch `(FileNotFoundError, PermissionError, IsADirectoryError, OSError, UnicodeDecodeError)` → absent; `.strip()` the value.
- **Deps:** `python-dotenv>=1.2.2` explicit direct dep; `pydantic-settings>=2.14.2,<2.15` (record the cap exception in ADR-0053 — the `_Without` source-state protocol is a 2.14.x internal). All dep edits + a single `uv lock` land in **Task 6**.
- **i18n:** operator strings via `t()`; new keys registered in the `SLICE_4_KEYS` catalog test; `pybabel extract/update --check/compile` with `-D alfred`; commit the `#:` ref churn.
- **Commits:** Conventional Commits with a literal `#469` **after the colon**; end bodies with `MrReasonable <4990954+MrReasonable@users.noreply.github.com>`. Never `--no-verify`. `make check` before push.
- **Coverage:** the resolver + Settings validator get a per-module **`ci.yml`** `coverage report --fail-under=100` gate (NOT `make check` — it runs 0 of 47, #474). `_commands.py`/`_failures.py`/`adapter_child_factory.py`/`manifest_reader.py` are **already** 100%-gated — every new branch must be covered or those gates red. `environment` is security-load-bearing → run the **full adversarial suite** (Task 9).
- **Human-gated doc bugs (flag, do NOT edit here):** `CLAUDE.md:175` (hard-rule #4) and `.github/workflows/pr-validate-python.yml:321` both cite the non-existent `pybabel compile --check`.

## File structure

| Path | Responsibility | Task |
| --- | --- | --- |
| `src/alfred/config/_environment_loader.py` | `resolve_environment(*, consult_dotenv, …)` + `DOTENV`/`UNREADABLE` sources | 1 |
| `src/alfred/config/settings.py` | source-exclusion `_Without` + `mode="wrap"` validator | 2 |
| `src/alfred/cli/daemon/_failures.py` | `SettingsInvalidFailure` + `EnvironmentSourceUnreadableFailure` (union members) | 3 |
| `src/alfred/cli/daemon/_commands.py` | gate: resolve-once, short-circuit, tuple, `settings_invalid` (reuse bootstrap copy), unreadable refusal | 3 |
| `src/alfred/gateway/adapter_child_factory.py` | in-process trust-floor at `_resolve_launch_target` | 4 |
| `src/alfred/plugins/manifest_reader.py`, `bin/alfred-plugin-launcher.sh` | launcher: `consult_dotenv=False` + fail-closed | 5 |
| `.env.example`, `pyproject.toml`, `uv.lock` | `.env.example` entry + direct dep + pin | 6 |
| `docs/adr/0053-*.md` + doc-drift set | ADR + rename/precedence/trust-floor doc updates | 7 |
| `locale/en/LC_MESSAGES/alfred.po` (+`.mo`) | `settings_invalid` + `environment_source_unreadable` keys | 3, 9 |
| `.github/workflows/ci.yml` | per-module coverage gate | 8 |

---

### Task 1: `resolve_environment()` — the 3-layer resolver

**Files:**

- Modify: `src/alfred/config/_environment_loader.py`; import-name-only: `settings.py`, `cli/daemon/_commands.py`, `plugins/manifest_reader.py`, `gateway/adapter_child_factory.py`
- Test: `tests/unit/cli/daemon/test_environment_loader.py`

**Interfaces:**

- Produces: `EnvironmentSource.DOTENV`, `EnvironmentSource.UNREADABLE`; `resolve_environment(*, etc_path: Path | None = None, dotenv_path: Path | None = None, consult_dotenv: bool = True) -> EnvironmentLoadResult`.

- [ ] **Step 1: Failing tests** (cover empty→skip, short-circuit, unreadable-`/etc` fail-closed, UnicodeDecodeError, consult_dotenv, strip, no-`.env`-conflict, and the `/etc`-layer of [D3])

```python
from alfred.config._environment_loader import EnvironmentSource, resolve_environment

def _r(tmp, **kw): return resolve_environment(etc_path=tmp / "absent_etc", dotenv_path=tmp / ".env", **kw)

def test_blank_env_is_skipped_not_unrecognised(monkeypatch, tmp_path):      # core-plan-01
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "")                            # blank -> skip
    (tmp_path / "etc").write_text("production\n", encoding="utf-8")
    r = resolve_environment(etc_path=tmp_path / "etc", dotenv_path=tmp_path / ".env")
    assert (r.value, r.source) == ("production", EnvironmentSource.ETC_FILE)

def test_dotenv_lowest(monkeypatch, tmp_path):
    monkeypatch.delenv("ALFRED_ENVIRONMENT", raising=False)
    (tmp_path / ".env").write_text("ALFRED_ENVIRONMENT=production\n", encoding="utf-8")
    assert _r(tmp_path).source is EnvironmentSource.DOTENV

def test_consult_dotenv_false_ignores_dotenv(monkeypatch, tmp_path):        # launcher path
    monkeypatch.delenv("ALFRED_ENVIRONMENT", raising=False)
    (tmp_path / ".env").write_text("ALFRED_ENVIRONMENT=development\n", encoding="utf-8")
    r = _r(tmp_path, consult_dotenv=False)
    assert r.value is None and r.source is EnvironmentSource.NONE          # fail-closed

def test_etc_typo_short_circuits_over_valid_dotenv(monkeypatch, tmp_path): # [D3] /etc layer
    monkeypatch.delenv("ALFRED_ENVIRONMENT", raising=False)
    (tmp_path / "etc").write_text("staging\n", encoding="utf-8")
    (tmp_path / ".env").write_text("ALFRED_ENVIRONMENT=production\n", encoding="utf-8")
    r = resolve_environment(etc_path=tmp_path / "etc", dotenv_path=tmp_path / ".env")
    assert r.source is EnvironmentSource.UNRECOGNISED and r.unrecognised_value == "staging"

def test_unreadable_etc_is_fail_closed(monkeypatch, tmp_path):             # err-01
    monkeypatch.delenv("ALFRED_ENVIRONMENT", raising=False)
    def _boom(*_a, **_k): raise PermissionError("perm")
    monkeypatch.setattr("alfred.config._environment_loader.Path.read_text", _boom)
    (tmp_path / ".env").write_text("ALFRED_ENVIRONMENT=development\n", encoding="utf-8")
    r = resolve_environment(etc_path=tmp_path / "etc", dotenv_path=tmp_path / ".env")
    assert r.value is None and r.source is EnvironmentSource.UNREADABLE     # NOT development

def test_non_utf8_dotenv_is_absent_not_crash(monkeypatch, tmp_path):       # err-02
    monkeypatch.delenv("ALFRED_ENVIRONMENT", raising=False)
    def _boom(*_a, **_k): raise UnicodeDecodeError("utf-8", b"", 0, 1, "bad")
    monkeypatch.setattr("alfred.config._environment_loader.dotenv_values", _boom, raising=False)
    r = _r(tmp_path)
    assert r.value is None and r.source is EnvironmentSource.NONE
```

- [ ] **Step 2: Run → FAIL.** `uv run pytest tests/unit/cli/daemon/test_environment_loader.py -q`

- [ ] **Step 3: Implement** — add `DOTENV`/`UNREADABLE` to `EnvironmentSource`; a fail-closed `/etc` reader; a guarded `.env` reader; the normalized, short-circuiting loop.

```python
from dotenv import dotenv_values   # direct dep declared in Task 6 (importable now, transitive)

def _norm(raw: str | None) -> str | None:            # core-plan-01: empty/whitespace -> None
    return (raw.strip() or None) if raw is not None else None

class _EtcRead:  # (value_or_None, unreadable)
    __slots__ = ("value", "unreadable")
    def __init__(self, value: str | None, unreadable: bool) -> None:
        self.value, self.unreadable = value, unreadable

def _read_etc(etc_path: Path) -> _EtcRead:
    try:
        return _EtcRead(_norm(etc_path.read_text(encoding="utf-8")), False)
    except FileNotFoundError:
        return _EtcRead(None, False)                 # genuinely absent -> skip
    except (PermissionError, IsADirectoryError, OSError):
        return _EtcRead(None, True)                  # err-01: present-but-unreadable -> fail-closed

def _read_dotenv(dotenv_path: Path) -> str | None:
    try:
        values = dotenv_values(dotenv_path, interpolate=False)   # interpolate=False kills $VAR injection
    except (FileNotFoundError, PermissionError, IsADirectoryError, OSError, UnicodeDecodeError):
        return None
    return _norm(values.get("ALFRED_ENVIRONMENT"))

def resolve_environment(*, etc_path=None, dotenv_path=None, consult_dotenv=True) -> EnvironmentLoadResult:
    etc_path = etc_path or _DEFAULT_ETC_PATH
    dotenv_path = dotenv_path or _DEFAULT_DOTENV_PATH
    env_raw = _norm(os.environ.get("ALFRED_ENVIRONMENT"))
    etc = _read_etc(etc_path)
    if etc.unreadable:                               # err-01: never fall through to a lower source
        return EnvironmentLoadResult(value=None, source=EnvironmentSource.UNREADABLE)
    dotenv_raw = _read_dotenv(dotenv_path) if consult_dotenv else None
    for raw, source in ((env_raw, EnvironmentSource.ENV_VAR),
                        (etc.value, EnvironmentSource.ETC_FILE),
                        (dotenv_raw, EnvironmentSource.DOTENV)):
        if raw is None:
            continue
        if raw not in _VALID_VALUES:
            return EnvironmentLoadResult(value=None, source=EnvironmentSource.UNRECOGNISED, unrecognised_value=raw)
        conflict = source is EnvironmentSource.ENV_VAR and etc.value is not None and etc.value != raw  # validated value, sec finding
        return EnvironmentLoadResult(value=raw, source=source, conflict=conflict,
                                     conflicting_file_value=etc.value if conflict else None)
    return EnvironmentLoadResult(value=None, source=EnvironmentSource.NONE)
```

Update the module docstring (drop "Dual-source"; describe 3 layers + short-circuit + fail-closed — see Task 7). Update the four import sites to `resolve_environment` (name only). Re-point the OLD file tests to `resolve_environment`; give the two "unreadable"/`neither_set` tests an explicit `dotenv_path` so a repo-root `.env` can't leak.

- [ ] **Step 4: Run → PASS.** `uv run pytest tests/unit/cli/daemon/test_environment_loader.py -q`
- [ ] **Step 5: Commit** — `feat(config): #469 three-layer resolve_environment (env>etc>.env) fail-closed + short-circuit`

---

### Task 2: `Settings` delegates via source-exclusion + wrap-validator

**Files:**

- Modify: `src/alfred/config/settings.py`
- Test: `tests/unit/config/test_settings.py`, `tests/unit/config/test_settings_environment_mandatory.py`

**Interfaces:**

- Consumes: `resolve_environment()`. Produces: `Settings.environment_load_result` still populated on a self-resolving `Settings()`.

- [ ] **Step 1: Failing tests** — `.env`-resolves; exclusion airtight (`/etc` beats `.env`); the wrap-validator branch is covered:

```python
def test_settings_resolves_from_dotenv(monkeypatch, tmp_path):
    monkeypatch.delenv("ALFRED_ENVIRONMENT", raising=False); monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-real")
    monkeypatch.chdir(tmp_path); (tmp_path/".env").write_text("ALFRED_ENVIRONMENT=production\n", encoding="utf-8")
    from alfred.config.settings import Settings; assert Settings().environment == "production"

def test_pydantic_cannot_populate_environment_from_dotenv(monkeypatch, tmp_path):
    monkeypatch.delenv("ALFRED_ENVIRONMENT", raising=False); monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-real")
    monkeypatch.setattr("alfred.config._environment_loader._DEFAULT_ETC_PATH", tmp_path/"etc")
    (tmp_path/"etc").write_text("production\n", encoding="utf-8"); monkeypatch.chdir(tmp_path)
    (tmp_path/".env").write_text("ALFRED_ENVIRONMENT=development\n", encoding="utf-8")
    from alfred.config.settings import Settings; assert Settings().environment == "production"   # NOT development
```

- [ ] **Step 2: Run → FAIL.**
- [ ] **Step 3: Implement** — `_Without` source filter + wrap-validator; delete the ContextVar + before/after validators.

```python
from pydantic_settings import PydanticBaseSettingsSource

def _environment_keys(settings_cls) -> tuple[str, ...]:      # core-plan-09: field-name key is the real one; include any validation_alias
    field = settings_cls.model_fields["environment"]
    keys = {"environment"}
    if isinstance(getattr(field, "validation_alias", None), str):
        keys.add(field.validation_alias)
    return tuple(keys)

class _Without(PydanticBaseSettingsSource):
    def __init__(self, inner, keys):
        super().__init__(inner.settings_cls); self._inner, self._keys = inner, keys
    def _set_current_state(self, state): self._inner._set_current_state(state)          # forward 2.14.2 protocol
    def _set_settings_sources_data(self, data): self._inner._set_settings_sources_data(data)
    def get_field_value(self, field, field_name): raise NotImplementedError             # abstract; unused
    def __call__(self):
        d = dict(self._inner());  [d.pop(k, None) for k in self._keys];  return d

# in Settings:
@classmethod
def settings_customise_sources(cls, settings_cls, init_settings, env_settings, dotenv_settings, file_secret_settings):
    k = _environment_keys(settings_cls)
    return (init_settings, _Without(env_settings, k), _Without(dotenv_settings, k), _Without(file_secret_settings, k))

@model_validator(mode="wrap")
@classmethod
def _resolve_environment(cls, data, handler):
    from alfred.config._environment_loader import resolve_environment
    result = None
    if isinstance(data, dict) and "environment" not in data:
        result = resolve_environment()
        if result.value is not None: data = {**data, "environment": result.value}
    inst = handler(data)
    if result is not None and result.value == inst.environment: inst._environment_load_result = result
    return inst
```

- [ ] **Step 4: Run → PASS + migrate `test_settings_environment_mandatory.py`** (its old `mode="before"` direct calls move to constructing `Settings()`; the wrap-validator's inject branch is exercised by a bare `Settings()` so the 100% CI gate on `settings.py` stays green — do NOT leave the branch uncovered, test-010).
- [ ] **Step 5: Commit** — `refactor(config): #469 Settings delegates environment to resolve_environment; retire ContextVar`

---

### Task 3: Daemon gate — tuple, `settings_invalid` (reuse bootstrap copy), unreadable refusal

**Files:**

- Modify: `src/alfred/cli/daemon/_failures.py`, `src/alfred/cli/daemon/_commands.py`, `locale/en/LC_MESSAGES/alfred.po`, `tests/unit/test_catalog_slice_4_keys.py`
- Test: `tests/unit/cli/daemon/test_probe_environment_not_set.py`

**Interfaces:**

- Consumes: `resolve_environment()`, `_bootstrap`'s placeholder detection. Produces: `SettingsInvalidFailure`, `EnvironmentSourceUnreadableFailure` (both `_BootFailureBase` + `DaemonBootFailure` union members); `_load_settings_or_die() -> tuple[Settings, EnvironmentLoadResult]`.

- [ ] **Step 1: Failing tests** — the union members exist + are wired; a post-env `SettingsError` audits `settings_invalid`; an `UNREADABLE` result audits `environment_source_unreadable`; the new keys are in `SLICE_4_KEYS`.

```python
def test_post_env_settings_error_audits_settings_invalid(monkeypatch, tmp_path):
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test"); monkeypatch.chdir(tmp_path)
    appended = []; 
    class _W:
        async def append_schema(self, **kw): appended.append(kw)
    monkeypatch.setattr("alfred.cli.daemon._commands.build_boot_audit_writer", lambda **_: _W())
    from alfred.config.settings import SettingsError
    monkeypatch.setattr("alfred.config.settings.Settings", lambda **_: (_ for _ in ()).throw(SettingsError("boom")))
    r = CliRunner().invoke(daemon_app, ["start"]); assert r.exit_code == 2
    assert appended[0]["subject"]["failure_reason"] == "settings_invalid"
```

- [ ] **Step 2: Run → FAIL.**
- [ ] **Step 3: Implement** — union members (Pydantic `_BootFailureBase`, NOT stdlib dataclass — arch-plan-02/rev-002/core-plan-03) + add both to the `DaemonBootFailure` union + its membership test; the gate:

```python
# _failures.py — mirror the existing _BootFailureBase members
class SettingsInvalidFailure(_BootFailureBase):
    failure_reason: Literal["settings_invalid"] = "settings_invalid"
class EnvironmentSourceUnreadableFailure(_BootFailureBase):
    failure_reason: Literal["environment_source_unreadable"] = "environment_source_unreadable"
# add both to `DaemonBootFailure = <union>` and to the union-membership test.
```

```python
# _commands.py
result = resolve_environment()
if result.source is EnvironmentSource.UNREADABLE:
    raise _EnvironmentSourceUnreadableError(result)     # fail-closed, audited (err-01)
if result.value is None:
    raise _EnvironmentNotSetError(result)               # environment_not_set / UNRECOGNISED echo, .env-aware
from alfred.config.settings import Settings, SettingsError
try:
    settings = Settings(environment=result.value)       # explicit -> single read
except SettingsError as exc:
    raise _SettingsInvalidError(_bootstrap_settings_message(exc), source=result.source.value) from exc
return settings, result
```

`_bootstrap_settings_message(exc)` REUSES `_bootstrap.load_settings_or_die`'s branch (placeholder-key → `t("error.placeholder_api_key")`; else `t("error.config_invalid")` — a curated token, NOT raw `str(exc)`; DLP: `str(exc)` can leak a DSN password — devex-plan-01/arch-plan-03). Both new errors reach `_refuse_boot` with the resolved `environment_source` in the row (err-05). Add catalog msgids `daemon.boot.settings_invalid` (names the fix + `alfred daemon start` / `docker compose up -d` tail, NOT `/etc/alfred` — devex-02) and `daemon.boot.environment_source_unreadable`; register both in `SLICE_4_KEYS` (arch-plan). The `UNRECOGNISED` refusal message must **name the resolved source** (not hardcode ".env" — devex-03).

- [ ] **Step 4: Run → PASS.** `uv run pytest tests/unit/cli/daemon/ tests/unit/test_catalog_slice_4_keys.py -q`; `uv run pybabel compile -D alfred -d locale`. Retire/repoint `test_settings_error_after_valid_env_refuses` to assert `settings_invalid` (err-04/test-005).
- [ ] **Step 5: Commit** — `feat(daemon): #469 settings_invalid + unreadable-source refusals; single-read env gate` (stage `alfred.po` + `alfred.mo` together — i18n-002).

---

### Task 4: In-process trust-floor at `_resolve_launch_target`

**Files:**

- Modify: `src/alfred/gateway/adapter_child_factory.py`
- Test: `tests/unit/gateway/` (+ the release-blocking `tests/adversarial/comms/test_launch_target_override_refusal.py` — keep it green, do NOT change its raise-semantics)

**Interfaces:**

- Real signature (verify): `_resolve_launch_target(adapter_id: str, *, override_map: Mapping[str, tuple[str, str]] | None, ...) -> tuple[str, str]`; refusal **raises** `LaunchTargetOverrideRefusedError` (never returns `None`).

- [ ] **Step 1: Failing test** — a `.env`-sourced dev value must NOT unlock the override (still raises); an `/etc`-sourced dev value does:

```python
def test_dotenv_dev_still_raises(monkeypatch, tmp_path):
    monkeypatch.delenv("ALFRED_ENVIRONMENT", raising=False); monkeypatch.chdir(tmp_path)
    (tmp_path/".env").write_text("ALFRED_ENVIRONMENT=development\n", encoding="utf-8")
    with pytest.raises(LaunchTargetOverrideRefusedError):
        _resolve_launch_target("a", override_map={"a": ("p", "m")}, etc_path=tmp_path/"absent")
```

- [ ] **Step 2: Run → FAIL.**
- [ ] **Step 3: Implement** — gate the **honor** branch on the source-floor; keep the existing `raise` on refusal (do not convert to `return None`). Thread an `etc_path` seam for tests; import `EnvironmentSource`; update the caller at `~:409` and the two "env-not-read on no-override path" unit tests the rename orphans (sec/security).

```python
res = resolve_environment(etc_path=etc_path)
if res.value in ("development", "test") and res.source in (EnvironmentSource.ENV_VAR, EnvironmentSource.ETC_FILE):
    ... existing honor-override branch ...
raise LaunchTargetOverrideRefusedError(adapter_id)   # unchanged fail-closed audited refusal
```

- [ ] **Step 4: Run → PASS.** `uv run pytest tests/unit/gateway/ tests/adversarial/comms/test_launch_target_override_refusal.py -q`
- [ ] **Step 5: Commit** — `fix(gateway): #469 trust-floor: .env cannot unlock the launch-target override`

---

### Task 5: Launcher fail-closed (`.env` cannot un-gate the bwrap sandbox)

> **Critical (sec-001):** `manifest_reader --read-environment` feeds `bin/alfred-plugin-launcher.sh` → `IS_PRODUCTION`, which gates the sandbox refusals + FAKE_UNAME keystone. On the `.env`-only path the launcher child re-resolves from its own app-writable CWD `.env`. Decision: the launcher resolves **trusted-sources-only** and fails closed to production.

**Files:**

- Modify: `src/alfred/plugins/manifest_reader.py` (`_cmd_read_environment`, `:243`)
- Test: new `tests/adversarial/comms/test_launcher_environment_no_dotenv_downgrade.py` (release-blocking); `tests/unit/plugins/test_manifest_reader_cli.py`

- [ ] **Step 1: Failing adversarial test** — a CWD `.env=development` does NOT make `--read-environment` report development:

```python
def test_read_environment_ignores_cwd_dotenv(monkeypatch, tmp_path):
    monkeypatch.delenv("ALFRED_ENVIRONMENT", raising=False); monkeypatch.chdir(tmp_path)
    (tmp_path/".env").write_text("ALFRED_ENVIRONMENT=development\n", encoding="utf-8")
    out = run_manifest_reader(["--read-environment"], etc_path=tmp_path/"absent")  # existing CLI harness
    assert "development" not in out            # fail-closed: emits NONE-equivalent -> launcher treats as production
```

- [ ] **Step 2: Run → FAIL.**
- [ ] **Step 3: Implement** — `_cmd_read_environment` calls `resolve_environment(consult_dotenv=False)`; on `NONE`/`UNREADABLE` it emits the existing no-value token the launcher already treats as production (verify against `bin/alfred-plugin-launcher.sh:231-234` — no bash change needed if the token is unchanged; add a code comment recording that `.env` is deliberately excluded on this stdout→bash interface because it cannot carry the source).
- [ ] **Step 4: Run → PASS** (+ the launcher's own bats/shell test if present).
- [ ] **Step 5: Commit** — `fix(sandbox): #469 launcher resolves env trusted-sources-only; .env cannot downgrade IS_PRODUCTION`

---

### Task 6: `.env.example`, direct dep, pin

**Files:** Modify `.env.example`, `pyproject.toml`, `uv.lock`; Test new `tests/unit/config/test_env_example_no_downgrade.py`

- [ ] **Step 1: Failing test** — `.env.example`'s value is uncommented `production`:

```python
def test_env_example_environment_is_production():
    line = next(l for l in Path(".env.example").read_text().splitlines() if l.strip().startswith("ALFRED_ENVIRONMENT="))
    assert line.strip() == "ALFRED_ENVIRONMENT=production"
```

- [ ] **Step 2: Run → FAIL.**
- [ ] **Step 3: Implement** — add near the existing `ALFRED_ENV` block (uncommented):

```dotenv
# Runtime environment. One of: development, production, test. Gates production
# safety refusals (sec-002). Precedence: ALFRED_ENVIRONMENT env var >
# /etc/alfred/environment > this .env file. DISTINCT from ALFRED_ENV above
# (the capability-gate selector) — different variable, different purpose.
ALFRED_ENVIRONMENT=production
```

Add `python-dotenv>=1.2.2` to `[project].dependencies`; change the existing pin to `pydantic-settings>=2.14.2,<2.15`; run `uv lock` (expect no drift). PR description notes the fourth-party justification + the cap exception.

- [ ] **Step 4: Run → PASS;** `git diff uv.lock` shows no version drift.
- [ ] **Step 5: Commit** — `feat(setup): #469 ship ALFRED_ENVIRONMENT in .env.example; python-dotenv direct dep; pin pydantic-settings`

---

### Task 7: ADR-0053 + doc-drift

**Files:** Create `docs/adr/0053-three-layer-environment-precedence.md`; Modify the loader module + `EnvironmentLoadResult` docstrings, `docs/subsystems/supervisor.md:373-378`, `docs/glossary.md:1645`, `src/alfred/gateway/adapter_child_factory.py:137`, `src/alfred/plugins/manifest_reader.py:16-21,:40`, `src/alfred/cli/daemon/_commands.py:7,:366`, `src/alfred/config/settings.py` (dual-source/ContextVar comment-rot, ~9 refs), `docs/adr/0039-*.md:470`.

- [ ] **Step 1: Write ADR-0053** (next number; highest existing is 0052) — the 3-layer precedence; the single-resolver invariant **scoped to `ALFRED_ENVIRONMENT`**, naming `ALFRED_ENV` as a known divergence; `.env`-lowest + the in-process trust-floor + the launcher trusted-sources-only + err-01 fail-closed; the ContextVar retirement; `DOTENV`/`UNREADABLE` + short-circuit; the `pydantic-settings<2.15` cap exception. Do **not** claim it homes arch-002; it homes the precedence decision. Correct the stale `§7.3`→`§7.1` citation.
- [ ] **Step 2: Update the stale docs** — incl. `adapter_child_factory.py:137` which must reflect the trust-floor (the override unlocks only on `{ENV_VAR, ETC_FILE}` dev/test, not any dev/test — docs-001).
- [ ] **Step 3: Lint** — `npx --yes markdownlint-cli2@0.22.1 "docs/**/*.md"` → 0 errors.
- [ ] **Step 4: Commit** — `docs(adr): #469 ADR-0053 three-layer environment precedence + doc-drift`

---

### Task 8: Per-module coverage gate (CI, not `make check`)

**Files:** Modify `.github/workflows/ci.yml` (mirror the existing hashFiles-guarded `coverage report --include=... --fail-under=100` step pattern — NOT the Makefile; #474/devops-001).

- [ ] **Step 1** — add a hashFiles-guarded step covering `src/alfred/config/_environment_loader.py` (+ the `settings.py` env-resolution surface) at `--fail-under=100 --branch`.
- [ ] **Step 2** — locally prove 100%: `uv run pytest --cov=alfred.config._environment_loader --cov-branch --cov-report=term-missing tests/unit/cli/daemon/test_environment_loader.py tests/unit/config/ -q`. Confirm the 4 already-gated files (`_commands`/`_failures`/`adapter_child_factory`/`manifest_reader`) still hit 100% with their new branches.
- [ ] **Step 3: Commit** — `test(config): #469 CI per-module coverage gate for the env resolver`

---

### Task 9: i18n drift cycle + full quality gates

- [ ] **Step 1: pybabel cycle** (real Babel 2.18 commands — `compile --check` does NOT exist, i18n-001):

```bash
uv run pybabel extract -F babel.cfg -o /tmp/alfred.pot src/alfred plugins
uv run pybabel update -D alfred -i /tmp/alfred.pot -d locale --no-fuzzy-matching
uv run pybabel compile -D alfred -d locale
```

Commit the `#:` ref churn.

- [ ] **Step 2: Full gates** — `make check`; then the release-blocker `uv run pytest tests/adversarial -q` (incl. the two new launcher/override hermeticity tests). Both green.
- [ ] **Step 3: Verify no drift** — `uv run pybabel update -D alfred -i /tmp/alfred.pot -d locale --check --ignore-pot-creation-date`; `uv run pybabel compile -D alfred -d locale --statistics`; `git status` clean.
- [ ] **Step 4: Commit** — `chore(i18n): #469 refresh catalog refs; full-gate + adversarial pass`

---

## Self-Review

**Spec coverage:** resolver + `.env` + short-circuit + empty-skip + err-01 fail-closed + err-02 (T1); Settings delegation + `_Without` + branch coverage (T2); daemon gate + tuple + `settings_invalid` (bootstrap copy) + unreadable refusal + `SLICE_4_KEYS` (T3); in-process trust-floor against the real raising contract (T4); **launcher `.env` downgrade closed** (T5); `.env.example` [D2] + deps + pin (T6); ADR-0053 + full doc-drift incl. trust-floor docs (T7); CI coverage gate + pre-existing gates (T8); pybabel + adversarial (T9). **Out of scope (spec §Scope):** DIP factory consolidation, `ALFRED_ENV`/sec-S3-003 reconciliation, malformed-`.env` friendly message, CI first-run lane. **Human-gated follow-ups flagged, not done here:** `CLAUDE.md:175` + `pr-validate-python.yml:321` (`pybabel compile --check`).

**Placeholder scan:** every code step carries corrected code verified against real signatures (`_resolve_launch_target` raises; `SettingsInvalidFailure` is a `_BootFailureBase` union member; the coverage gate is `ci.yml`; `pybabel compile` has no `--check`). The one audit-and-comment step (T5 Step 3, "verify the launcher's no-value token is unchanged") is a concrete verification with a named fallback (add the token), not a TODO.

**Type consistency:** `resolve_environment(*, etc_path, dotenv_path, consult_dotenv)`, `EnvironmentSource.{DOTENV,UNREADABLE}` (T1) are the names used in T2–T5; `SettingsInvalidFailure`/`EnvironmentSourceUnreadableFailure` are `_BootFailureBase` union members (T3) matching the catalog keys `daemon.boot.settings_invalid`/`daemon.boot.environment_source_unreadable`; `_load_settings_or_die -> tuple[Settings, EnvironmentLoadResult]` (T3) matches the conflict-audit read.
