# #469 Blocker 1 — Environment Resolution Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. The design rationale lives in `docs/superpowers/specs/2026-07-22-469-blocker1-environment-resolution-design.md` (v2) — read it before Task 1.

**Goal:** Make `alfred daemon start` resolve `Settings.environment` from `.env` (as its own refusal message instructs) via one canonical resolver, closing a `production→development` security downgrade by construction.

**Architecture:** One `resolve_environment()` owns a single 3-layer precedence (`os.environ["ALFRED_ENVIRONMENT"] > /etc/alfred/environment > .env`). `Settings` delegates to it (pydantic source-exclusion + a single wrap-validator, retiring the ContextVar/dual-validator). The three composition roots that cannot build `Settings` (daemon gate, launcher subprocess, gateway container) call the resolver directly; the security-sensitive escape-hatch consumer applies a source trust-floor. Sequenced expand→migrate→contract so each task ends green.

**Tech Stack:** Python 3.14+, pydantic v2 / pydantic-settings 2.14.2, python-dotenv 1.2.2, pytest + hypothesis, structlog, Babel/pybabel, uv, ruff, mypy --strict + pyright.

## Global Constraints

- **Precedence (exact):** `os.environ["ALFRED_ENVIRONMENT"] > /etc/alfred/environment > .env`. `.env` is lowest, gap-fill-only, and **never** participates in a two-source `conflict` (only `UNRECOGNISED` extends to it).
- **[D3] Short-circuit:** the highest source that is **SET** decides; if its value is not in `{development, production, test}` → return `UNRECOGNISED` (echo it), do **not** fall through to a valid lower source. An **unset/empty** source is skipped, not a short-circuit.
- **[D1] Trust-floor:** any consumer where dev/test is the *permissive* state honors dev-mode only when `result.source in {EnvironmentSource.ENV_VAR, EnvironmentSource.ETC_FILE}` (never `DOTENV`).
- **[D2] `.env.example`:** ship `ALFRED_ENVIRONMENT=production` **uncommented**; comment must disambiguate the pre-existing `ALFRED_ENV` capability-gate key.
- **[Db] Post-env `Settings()` failure:** distinct audited reason `settings_invalid` (never re-label as `environment_not_set`).
- **`.env` parse:** `dotenv_values(path, interpolate=False)`; catch `PermissionError`/`OSError`/`IsADirectoryError`/`FileNotFoundError` → treat as absent; `.strip()` the value like the other two sources.
- **Deps:** `python-dotenv>=1.2.2` as an explicit **direct** dep; pin the pydantic-settings floor at the installed `2.14.2` (the `_Without` state protocol is an internal API).
- **i18n:** operator strings via `t()`; new key needs `pybabel extract/update/compile` with `-D alfred`; commit the `#:` ref churn (never `--omit-header`).
- **Commits:** Conventional Commits with a literal `#469` **after the colon** in every subject; end every commit body with `MrReasonable <4990954+MrReasonable@users.noreply.github.com>`. Never `--no-verify`. Run `make check` before any push.
- **Security:** `environment` is security-load-bearing → run the **full adversarial suite**; the resolver + Settings validator get a **real per-module coverage gate** (not a paper gate; cf. #474).

## File structure

| Path | Responsibility | Task |
| --- | --- | --- |
| `src/alfred/config/_environment_loader.py` | the one `resolve_environment()` + `EnvironmentSource.DOTENV` | 1 |
| `src/alfred/config/settings.py` | `settings_customise_sources` + `_Without` + `mode="wrap"` validator | 2 |
| `src/alfred/cli/daemon/_failures.py` | `SettingsInvalidFailure` | 3 |
| `src/alfred/cli/daemon/_commands.py` | daemon gate: resolve-once, short-circuit, tuple return, `settings_invalid` | 3 |
| `src/alfred/gateway/adapter_child_factory.py` | trust-floor at the launch-target override | 4 |
| `src/alfred/plugins/manifest_reader.py` | migrate to resolver; trust-floor if permissive-in-dev | 4 |
| `.env.example`, `pyproject.toml`, `uv.lock` | `.env.example` entry + direct dep | 5 |
| `docs/adr/0053-*.md`, `docs/subsystems/supervisor.md`, `docs/glossary.md`, `docs/adr/0039-*.md` | ADR + doc-drift | 6 |
| `locale/en/LC_MESSAGES/alfred.po` (+ `.mo`) | `daemon.boot.settings_invalid` + pybabel | 3, 8 |
| `Makefile` / coverage config | per-module coverage gate | 7 |

---

### Task 1: `resolve_environment()` — the 3-layer resolver

**Files:**

- Modify: `src/alfred/config/_environment_loader.py`
- Modify (import-name only, no logic): `src/alfred/config/settings.py`, `src/alfred/cli/daemon/_commands.py`, `src/alfred/plugins/manifest_reader.py`, `src/alfred/gateway/adapter_child_factory.py`
- Test: `tests/unit/cli/daemon/test_environment_loader.py`

**Interfaces:**

- Produces: `EnvironmentSource.DOTENV` (new enum member); `resolve_environment(*, etc_path: Path | None = None, dotenv_path: Path | None = None) -> EnvironmentLoadResult` (renamed from `load_environment`, now 3-layer). `EnvironmentLoadResult` fields unchanged.
- Consumes: `python-dotenv`'s `dotenv_values` (already resolved transitively; the direct-dep declaration lands in Task 5 — import works now).

- [ ] **Step 1: Write failing tests for the `.env` layer + short-circuit + guard**

```python
# tests/unit/cli/daemon/test_environment_loader.py  (add)
from alfred.config._environment_loader import EnvironmentSource, resolve_environment

def test_dotenv_is_lowest_precedence(monkeypatch, tmp_path):
    monkeypatch.delenv("ALFRED_ENVIRONMENT", raising=False)
    (tmp_path / ".env").write_text("ALFRED_ENVIRONMENT=production\n", encoding="utf-8")
    r = resolve_environment(etc_path=tmp_path / "absent", dotenv_path=tmp_path / ".env")
    assert (r.value, r.source) == ("production", EnvironmentSource.DOTENV)

def test_etc_beats_dotenv(monkeypatch, tmp_path):
    monkeypatch.delenv("ALFRED_ENVIRONMENT", raising=False)
    (tmp_path / "etc").write_text("production\n", encoding="utf-8")
    (tmp_path / ".env").write_text("ALFRED_ENVIRONMENT=development\n", encoding="utf-8")
    r = resolve_environment(etc_path=tmp_path / "etc", dotenv_path=tmp_path / ".env")
    assert (r.value, r.source) == ("production", EnvironmentSource.ETC_FILE)

def test_envvar_beats_dotenv(monkeypatch, tmp_path):
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "production")
    (tmp_path / ".env").write_text("ALFRED_ENVIRONMENT=development\n", encoding="utf-8")
    r = resolve_environment(etc_path=tmp_path / "absent", dotenv_path=tmp_path / ".env")
    assert (r.value, r.source) == ("production", EnvironmentSource.ENV_VAR)

def test_typo_in_higher_source_short_circuits(monkeypatch, tmp_path):
    # [D3]: highest SET source is invalid -> UNRECOGNISED, never masked by a valid lower source
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "staging")
    (tmp_path / ".env").write_text("ALFRED_ENVIRONMENT=production\n", encoding="utf-8")
    r = resolve_environment(etc_path=tmp_path / "absent", dotenv_path=tmp_path / ".env")
    assert r.value is None and r.source is EnvironmentSource.UNRECOGNISED
    assert r.unrecognised_value == "staging"

def test_unreadable_dotenv_is_absent_not_crash(monkeypatch, tmp_path):
    monkeypatch.delenv("ALFRED_ENVIRONMENT", raising=False)
    env = tmp_path / ".env"; env.write_text("ALFRED_ENVIRONMENT=production\n", encoding="utf-8")
    env.chmod(0o000)
    try:
        r = resolve_environment(etc_path=tmp_path / "absent", dotenv_path=env)
    finally:
        env.chmod(0o600)
    assert r.value is None and r.source is EnvironmentSource.NONE  # treated as absent, no raise

def test_dotenv_value_is_stripped(monkeypatch, tmp_path):
    monkeypatch.delenv("ALFRED_ENVIRONMENT", raising=False)
    (tmp_path / ".env").write_text('ALFRED_ENVIRONMENT="  production  "\n', encoding="utf-8")
    r = resolve_environment(etc_path=tmp_path / "absent", dotenv_path=tmp_path / ".env")
    assert r.value == "production"

def test_dotenv_never_conflicts(monkeypatch, tmp_path):
    # .env is gap-fill only; env-var present + .env present -> no conflict recorded for .env
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "production")
    (tmp_path / ".env").write_text("ALFRED_ENVIRONMENT=development\n", encoding="utf-8")
    r = resolve_environment(etc_path=tmp_path / "absent", dotenv_path=tmp_path / ".env")
    assert r.conflict is False
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run pytest tests/unit/cli/daemon/test_environment_loader.py -q`
Expected: FAIL (`resolve_environment` / `DOTENV` undefined).

- [ ] **Step 3: Implement `resolve_environment` in `_environment_loader.py`**

Rename `load_environment` → `resolve_environment`, add `DOTENV` to `EnvironmentSource`, and rewrite the body as a top-down precedence with short-circuit and a guarded `.env` read. Keep the existing `env-var`/`/etc` normalization + the `conflict` computation between those two.

```python
class EnvironmentSource(enum.Enum):
    ENV_VAR = "env_var"
    ETC_FILE = "etc_file"
    DOTENV = "dotenv"          # NEW — lowest precedence, gap-fill only
    NONE = "none"
    UNRECOGNISED = "unrecognised"

_DEFAULT_DOTENV_PATH: Final[Path] = Path(".env")  # CWD-relative, matches pydantic env_file

def _read_dotenv_value(dotenv_path: Path) -> str | None:
    """The `.env` layer's ALFRED_ENVIRONMENT, stripped, or None. Read errors -> None (absent)."""
    from dotenv import dotenv_values  # direct dep declared in pyproject (Task 5)
    try:
        values = dotenv_values(dotenv_path, interpolate=False)  # interpolate=False: kill $VAR injection
    except (FileNotFoundError, PermissionError, IsADirectoryError, OSError):
        return None
    raw = values.get("ALFRED_ENVIRONMENT")
    return raw.strip() if raw is not None else None

def resolve_environment(*, etc_path: Path | None = None, dotenv_path: Path | None = None) -> EnvironmentLoadResult:
    if etc_path is None:
        etc_path = _DEFAULT_ETC_PATH
    if dotenv_path is None:
        dotenv_path = _DEFAULT_DOTENV_PATH

    env_unstripped = os.environ.get("ALFRED_ENVIRONMENT")
    env_raw = env_unstripped.strip() if env_unstripped is not None else None
    file_raw = _read_etc_value(etc_path)      # existing guarded /etc read, factored into a helper
    dotenv_raw = _read_dotenv_value(dotenv_path)

    # [D3] top-down: the highest SET source decides. SET-but-invalid short-circuits to UNRECOGNISED.
    for raw, source in ((env_raw, EnvironmentSource.ENV_VAR), (file_raw, EnvironmentSource.ETC_FILE), (dotenv_raw, EnvironmentSource.DOTENV)):
        if raw is None:
            continue
        if raw not in _VALID_VALUES:
            return EnvironmentLoadResult(value=None, source=EnvironmentSource.UNRECOGNISED, unrecognised_value=raw)
        # valid: this source wins. conflict only ever between env-var and /etc (never .env).
        conflict = source is EnvironmentSource.ENV_VAR and file_raw is not None and file_raw != raw
        return EnvironmentLoadResult(
            value=raw, source=source, conflict=conflict,
            conflicting_file_value=file_raw if conflict else None,
        )
    return EnvironmentLoadResult(value=None, source=EnvironmentSource.NONE)
```

Factor the existing `/etc` read (the `try/except (FileNotFoundError, PermissionError, IsADirectoryError, OSError)` + `.strip()`) into `_read_etc_value(etc_path) -> str | None`. Update the module docstring (remove "Dual-source"; describe the three layers + short-circuit — see Task 6 for the full docstring rewrite). Update the four import sites to `resolve_environment` (name only).

- [ ] **Step 4: Run to verify pass + no regression**

Run: `uv run pytest tests/unit/cli/daemon/test_environment_loader.py -q`
Expected: PASS. Then re-point the file's OLD tests (`test_env_var_wins`, `test_file_fallback`, etc.) at `resolve_environment`; the `test_unrecognised_value` case now asserts short-circuit still returns UNRECOGNISED (unchanged for a lone invalid env-var).

- [ ] **Step 5: Commit**

```bash
git add src/alfred/config/_environment_loader.py src/alfred/config/settings.py \
        src/alfred/cli/daemon/_commands.py src/alfred/plugins/manifest_reader.py \
        src/alfred/gateway/adapter_child_factory.py tests/unit/cli/daemon/test_environment_loader.py
git commit  # subject: "feat(config): #469 three-layer resolve_environment (env>etc>.env) with short-circuit"
```

---

### Task 2: `Settings` delegates via source-exclusion + wrap-validator

**Files:**

- Modify: `src/alfred/config/settings.py`
- Test: `tests/unit/config/test_settings.py`, `tests/unit/config/test_settings_environment_mandatory.py`

**Interfaces:**

- Consumes: `resolve_environment()` (Task 1).
- Produces: `Settings.environment_load_result` property still populated on a self-resolving `Settings()`; a `_Without` source that pops the `environment` field from env/dotenv/secret sources; `Settings(environment=...)` explicit-init still bypasses the resolver.

- [ ] **Step 1: Write failing tests**

```python
# tests/unit/config/test_settings.py  (add)
def test_settings_resolves_environment_from_dotenv(monkeypatch, tmp_path):
    monkeypatch.delenv("ALFRED_ENVIRONMENT", raising=False)
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-real")
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text("ALFRED_ENVIRONMENT=production\n", encoding="utf-8")
    from alfred.config.settings import Settings
    assert Settings().environment == "production"

def test_pydantic_cannot_populate_environment_from_dotenv(monkeypatch, tmp_path):
    # exclusion is airtight: /etc wins over .env even though pydantic *could* read .env
    monkeypatch.delenv("ALFRED_ENVIRONMENT", raising=False)
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-real")
    monkeypatch.setattr("alfred.config._environment_loader._DEFAULT_ETC_PATH", tmp_path / "etc")
    (tmp_path / "etc").write_text("production\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text("ALFRED_ENVIRONMENT=development\n", encoding="utf-8")
    from alfred.config.settings import Settings
    assert Settings().environment == "production"   # NOT development
```

- [ ] **Step 2: Run to verify fail** — `uv run pytest tests/unit/config/test_settings.py -q` → FAIL.

- [ ] **Step 3: Implement the source-exclusion + wrap-validator**

```python
# settings.py
from pydantic_settings import PydanticBaseSettingsSource

def _environment_alias_keys(settings_cls: type) -> tuple[str, ...]:
    """Every key pydantic could map onto the `environment` field (name + any validation_alias)."""
    field = settings_cls.model_fields["environment"]
    keys = {"environment"}
    alias = getattr(field, "validation_alias", None)
    if isinstance(alias, str):
        keys.add(alias)
    # env_prefix'd form so a source keyed by the raw env var is also stripped:
    keys.add(f"{settings_cls.model_config.get('env_prefix', '')}environment".lower())
    return tuple(keys)

class _Without(PydanticBaseSettingsSource):
    def __init__(self, inner: PydanticBaseSettingsSource, keys: tuple[str, ...]) -> None:
        super().__init__(inner.settings_cls)
        self._inner, self._keys = inner, keys
    def _set_current_state(self, state):            # forward per-source state protocol (2.14.2 internal)
        self._inner._set_current_state(state)
    def _set_settings_sources_data(self, data):
        self._inner._set_settings_sources_data(data)
    def get_field_value(self, field, field_name):   # abstractmethod; unused (called via __call__)
        raise NotImplementedError
    def __call__(self) -> dict[str, object]:
        d = dict(self._inner())
        for k in self._keys:
            d.pop(k, None)
        return d

# in Settings:
@classmethod
def settings_customise_sources(cls, settings_cls, init_settings, env_settings, dotenv_settings, file_secret_settings):
    keys = _environment_alias_keys(settings_cls)
    return (init_settings, _Without(env_settings, keys), _Without(dotenv_settings, keys), _Without(file_secret_settings, keys))

@model_validator(mode="wrap")
@classmethod
def _resolve_environment(cls, data, handler):
    from alfred.config._environment_loader import resolve_environment
    result = None
    if isinstance(data, dict) and "environment" not in data:
        result = resolve_environment()
        if result.value is not None:
            data = {**data, "environment": result.value}
    inst = handler(data)
    if result is not None and result.value == inst.environment:
        inst._environment_load_result = result
    return inst
```

Delete: `_ENVIRONMENT_LOAD_RESULT` ContextVar, the old `mode="before"` `_resolve_environment`, and `_capture_environment_load_result`. Keep the `environment_load_result` property + the `_environment_load_result` PrivateAttr.

- [ ] **Step 4: Run to verify pass + migrate the mandatory-field tests**

Run: `uv run pytest tests/unit/config/test_settings.py tests/unit/config/test_settings_environment_mandatory.py -q`
Expected: PASS after updating `test_settings_environment_mandatory.py` — its direct calls to the old `mode="before"` `_resolve_environment` must move to constructing `Settings()` (the `wrap` validator has no standalone-callable signature). Pin the pydantic-settings floor: set `pydantic-settings==2.14.2` (or `>=2.14.2,<2.15`) in `pyproject.toml` with a comment that `_Without` depends on the 2.14.x source-state protocol.

- [ ] **Step 5: Commit** — subject: `refactor(config): #469 Settings delegates environment to resolve_environment; retire ContextVar`

---

### Task 3: Daemon gate — resolve-once, short-circuit, tuple, `settings_invalid`

**Files:**

- Modify: `src/alfred/cli/daemon/_failures.py`, `src/alfred/cli/daemon/_commands.py`
- Modify: `locale/en/LC_MESSAGES/alfred.po` (+ the i18n reserve anchor if `t()` uses an indirection)
- Test: `tests/unit/cli/daemon/test_probe_environment_not_set.py`

**Interfaces:**

- Consumes: `resolve_environment()`; `Settings(environment=...)`.
- Produces: `SettingsInvalidFailure(failure_reason="settings_invalid")`; `_load_settings_or_die() -> tuple[Settings, EnvironmentLoadResult]` (non-optional).

- [ ] **Step 1: Write failing tests** (post-env `SettingsError` → distinct audited `settings_invalid`, exit 2; `.env`-only boot succeeds)

```python
# test_probe_environment_not_set.py  (add / amend)
def test_post_env_settings_error_audits_settings_invalid(monkeypatch, tmp_path):
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")     # env resolves — past the unset gate
    monkeypatch.chdir(tmp_path)                          # no stray .env
    appended: list[dict] = []
    class _W:
        async def append_schema(self, **kw): appended.append(kw)
    monkeypatch.setattr("alfred.cli.daemon._commands.build_boot_audit_writer", lambda **_: _W())
    from alfred.config.settings import SettingsError
    monkeypatch.setattr("alfred.config.settings.Settings",
                        lambda **_: (_ for _ in ()).throw(SettingsError("placeholder_api_key")))
    result = CliRunner().invoke(daemon_app, ["start"])
    assert result.exit_code == 2
    assert appended and appended[0]["subject"]["failure_reason"] == "settings_invalid"

def test_dotenv_only_boot_passes_environment_gate(monkeypatch, tmp_path):
    monkeypatch.delenv("ALFRED_ENVIRONMENT", raising=False)
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text("ALFRED_ENVIRONMENT=production\n", encoding="utf-8")
    from alfred.config._environment_loader import resolve_environment, EnvironmentSource
    r = resolve_environment(etc_path=tmp_path / "absent")
    assert (r.value, r.source) == ("production", EnvironmentSource.DOTENV)  # gate would pass
```

- [ ] **Step 2: Run to verify fail** — `uv run pytest tests/unit/cli/daemon/test_probe_environment_not_set.py -q` → FAIL.

- [ ] **Step 3: Add `SettingsInvalidFailure` + rewrite the gate**

```python
# _failures.py
@dataclass(frozen=True, slots=True)
class SettingsInvalidFailure:
    failure_reason: Literal["settings_invalid"] = "settings_invalid"
```

```python
# _commands.py — _load_settings_or_die + the async refusal wiring
def _load_settings_or_die() -> tuple[Settings, EnvironmentLoadResult]:
    result = resolve_environment()
    if result.value is None:
        raise _EnvironmentNotSetError(result)         # sec-001 audited; UNRECOGNISED echo
    from alfred.config.settings import Settings, SettingsError
    try:
        settings = Settings(environment=result.value)  # explicit -> single read
    except SettingsError as exc:
        raise _SettingsInvalidError(str(exc)) from exc  # [Db] distinct reason, NOT environment_not_set
    return settings, result
```

Add `_SettingsInvalidError`; in `_start_async`, catch it and `await _refuse_boot(audit, SettingsInvalidFailure(), t("daemon.boot.settings_invalid", detail=exc.detail), ...)`. Update the conflict-audit block (`~:542`) and `source` derivation to read the returned non-optional `result`. Add the catalog entry:

```
# locale/en/LC_MESSAGES/alfred.po
msgid "daemon.boot.settings_invalid"
msgstr "Configuration is invalid ({detail}). Refusing to boot. Fix the reported field in your .env or /etc/alfred and re-run `alfred daemon start`."
```

Add a `t("daemon.boot.settings_invalid")` anchor to the i18n reserve file if the daemon uses the key-indirection pattern.

- [ ] **Step 4: Run to verify pass** — `uv run pytest tests/unit/cli/daemon/ -q` → PASS. Run `uv run pybabel compile -D alfred -d locale` so `t()` resolves the new key.

- [ ] **Step 5: Commit** — subject: `feat(daemon): #469 distinct settings_invalid boot refusal; single-read env gate`

---

### Task 4: Trust-floor at the escape-hatch + subprocess-site migration

**Files:**

- Modify: `src/alfred/gateway/adapter_child_factory.py`, `src/alfred/plugins/manifest_reader.py`
- Test: `tests/adversarial/comms/test_launch_target_override_refusal.py`, a new `tests/unit/gateway/test_launch_target_trust_floor.py`

**Interfaces:**

- Consumes: `resolve_environment()` returning `.source`.

- [ ] **Step 1: Write failing tests** (trust-floor + hermeticity)

```python
# tests/unit/gateway/test_launch_target_trust_floor.py
def test_dotenv_development_does_not_unlock_override(monkeypatch, tmp_path):
    monkeypatch.delenv("ALFRED_ENVIRONMENT", raising=False)
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text("ALFRED_ENVIRONMENT=development\n", encoding="utf-8")
    # override map present, but environment came from .env -> must stay refused
    assert _resolve_launch_target(override_map={"x": "y"}, requested="x", etc_path=tmp_path / "absent") is None

def test_etc_development_does_unlock_override(monkeypatch, tmp_path):
    monkeypatch.delenv("ALFRED_ENVIRONMENT", raising=False)
    (tmp_path / "etc").write_text("development\n", encoding="utf-8")
    assert _resolve_launch_target(override_map={"x": "y"}, requested="x", etc_path=tmp_path / "etc") == "y"
```

Also add a positive gateway downgrade oracle: `/etc=production` + `.env=development` + override injected → refused.

- [ ] **Step 2: Run to verify fail** → FAIL.

- [ ] **Step 3: Implement the trust-floor**

In `adapter_child_factory._resolve_launch_target`, replace the bare `resolve_environment().value` dev/test check with a source-gated one:

```python
res = resolve_environment(etc_path=etc_path)  # thread the seam for tests
if res.value in ("development", "test") and res.source in (EnvironmentSource.ENV_VAR, EnvironmentSource.ETC_FILE):
    ...honor override...
return None
```

Audit `manifest_reader._cmd_read_environment` (`:243`): if its consumer treats dev/test as permissive, apply the same floor; otherwise leave it uniformly `.env`-aware (add a comment recording the finding). Then **de-hermeticize-proof the adversarial test**: add `monkeypatch.chdir(tmp_path)` (+ no `.env`) to every case in `test_launch_target_override_refusal.py`, and add a `manifest_reader` `os.environ`-beats-`.env` precedence test.

- [ ] **Step 4: Run to verify pass** — `uv run pytest tests/unit/gateway/test_launch_target_trust_floor.py tests/adversarial/comms/test_launch_target_override_refusal.py -q` → PASS.

- [ ] **Step 5: Commit** — subject: `fix(gateway): #469 trust-floor: .env cannot unlock the launch-target override`

---

### Task 5: `.env.example`, direct dep, compose-downgrade guard

**Files:** Modify `.env.example`, `pyproject.toml`, `uv.lock`; Test `tests/unit/test_compose_invariants.py` (or new `test_env_example_no_downgrade.py`)

- [ ] **Step 1: Failing test** — assert `.env.example`'s `ALFRED_ENVIRONMENT` value is `production` (so `cp` + compose can't downgrade):

```python
def test_env_example_environment_is_production():
    text = Path(".env.example").read_text(encoding="utf-8")
    line = next(l for l in text.splitlines() if l.strip().startswith("ALFRED_ENVIRONMENT="))
    assert line.strip() == "ALFRED_ENVIRONMENT=production"   # uncommented, safe value
```

- [ ] **Step 2: Run → FAIL.**
- [ ] **Step 3: Implement** — add to `.env.example` (near the existing `ALFRED_ENV` block, uncommented):

```dotenv
# Runtime environment for AlfredOS. One of: development, production, test.
# Gates production safety refusals (sec-002). Precedence: ALFRED_ENVIRONMENT env
# var > /etc/alfred/environment > this .env file. NOTE: distinct from ALFRED_ENV
# above (the capability-gate selector) — different variable, different purpose.
ALFRED_ENVIRONMENT=production
```

Add `python-dotenv>=1.2.2` to `[project].dependencies` in `pyproject.toml`; run `uv lock` (expect no version change). PR description must note the (already-present) fourth-party justification.

- [ ] **Step 4: Run** — `uv run pytest tests/unit/test_compose_invariants.py -q` + `uv run python -c "import dotenv"` → PASS; `git diff uv.lock` shows no version drift.
- [ ] **Step 5: Commit** — subject: `feat(setup): #469 ship ALFRED_ENVIRONMENT in .env.example; python-dotenv direct dep`

---

### Task 6: ADR-0053 + doc-drift

**Files:** Create `docs/adr/0053-three-layer-environment-precedence.md`; Modify `src/alfred/config/_environment_loader.py` (module docstring), `docs/subsystems/supervisor.md:373-378`, `docs/glossary.md:1645`, `src/alfred/plugins/manifest_reader.py:40`, `docs/adr/0039-*.md:470`.

- [ ] **Step 1: Write ADR-0053** — Context/Decision/Consequences per spec v2 §Governance: the 3-layer precedence; the single-resolver invariant **scoped to `ALFRED_ENVIRONMENT`** naming `ALFRED_ENV` as a known divergence; `.env`-lowest + the trust-floor; the ContextVar retirement; `DOTENV` + short-circuit. Do **not** claim it "homes arch-002" (mis-attribution) — say it homes the precedence decision no prior ADR does. Correct the loader's stale `§7.3` citation → `§7.1`.
- [ ] **Step 2: Update the stale docs** — rewrite the loader module docstring (drop "Dual-source", describe 3 layers + short-circuit); update `supervisor.md` two-source paragraph; add/refresh the `glossary.md` entry (new symbol + precedence); fix the `manifest_reader.py:40` + `adr/0039` `:func:`/symbol refs to `resolve_environment`.
- [ ] **Step 3: Lint** — `npx --yes markdownlint-cli2@0.22.1 "docs/**/*.md"` → 0 errors (watch MD018 line-start `#NNN`, MD060 tables).
- [ ] **Step 4: Commit** — subject: `docs(adr): #469 ADR-0053 three-layer environment precedence + doc-drift`

---

### Task 7: Per-module coverage gate

**Files:** Modify `Makefile` / coverage config (mirror the `alfred/observability/` per-module gate pattern).

- [ ] **Step 1** — add `src/alfred/config/_environment_loader.py` (and the `settings.py` env-resolution surface) to the per-module 100%-line+branch coverage gate, wired so `make check` actually **runs** it (assert-ran, not a paper gate — cf. #474).
- [ ] **Step 2** — Run: `uv run pytest --cov=alfred.config._environment_loader --cov-branch --cov-report=term-missing tests/unit/cli/daemon/test_environment_loader.py tests/unit/config/ -q`; Expected: 100% line+branch on the resolver.
- [ ] **Step 3: Commit** — subject: `test(config): #469 wire per-module coverage gate for the env resolver`

---

### Task 8: i18n drift cycle + full quality gates

- [ ] **Step 1: pybabel drift cycle** (captures ref churn from Tasks 1–6):

```bash
uv run pybabel extract -F babel.cfg -o /tmp/alfred.pot src/alfred plugins
uv run pybabel update -D alfred -i /tmp/alfred.pot -d locale --no-fuzzy-matching
uv run pybabel compile -D alfred -d locale
```

Commit the `#:` ref churn (never `--omit-header`; msgstrs brace-free).

- [ ] **Step 2: Full gates** — `make check` (ruff + ruff format --check + mypy --strict + pyright + unit); then the release-blocker: `uv run pytest tests/adversarial -q`. Both green.
- [ ] **Step 3: Verify no drift** — `uv run pybabel compile -D alfred -d locale --check`; `git status` clean.
- [ ] **Step 4: Commit** — subject: `chore(i18n): #469 refresh catalog refs; full-gate + adversarial pass`

---

## Self-Review

**Spec coverage:** resolver + `.env` + short-circuit + guard (T1); Settings delegation + `_Without` hardening + ContextVar retirement (T2); daemon gate + tuple + `settings_invalid` [Db] (T3); trust-floor [D1] + adversarial hermeticity (T4); `.env.example` [D2] + dep (T5); ADR-0053 + doc-drift + `ALFRED_ENV` divergence (T6); coverage gate (T7); pybabel + adversarial (T8). The 3-layer-UNRECOGNISED matrix [D3] is covered by T1 Step 1 tests + the short-circuit body. **Out of scope (spec §Scope):** DIP factory consolidation, `ALFRED_ENV`/sec-S3-003 reconciliation, malformed-`.env` friendly message, CI first-run lane — none appear as tasks (correct).

**Placeholder scan:** each code step shows the code; commands have expected output. The one deliberately-open item — whether `manifest_reader` needs the trust-floor — is a T4 Step-3 *audit-and-decide-with-comment*, not a silent TODO.

**Type consistency:** `resolve_environment(*, etc_path, dotenv_path)` and `EnvironmentSource.DOTENV` (T1) are the names used in T2/T3/T4; `_load_settings_or_die -> tuple[Settings, EnvironmentLoadResult]` (T3) matches the conflict-audit read; `SettingsInvalidFailure.failure_reason == "settings_invalid"` (T3) matches the test assertion and the catalog key `daemon.boot.settings_invalid`.
